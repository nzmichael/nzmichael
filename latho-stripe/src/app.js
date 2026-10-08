'use strict';

const crypto = require('node:crypto');
const express = require('express');
const { SERVICES, FREQUENCIES, CURRENCY, TAX_BEHAVIOR, INTEGRATION_IDENTIFIER } = require('./catalog');
const { computeQuote, QuoteError } = require('./pricing');

const ARRIVAL_WINDOWS = ['8am-10am', '10am-12pm', '12pm-2pm', '2pm-4pm'];

function createApp({ stripe, store, config, log = console }) {
  const app = express();

  // The webhook needs the raw body for signature verification, so it is mounted before express.json().
  app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], config.webhookSecret);
    } catch (err) {
      log.warn(`Webhook signature verification failed: ${err.message}`);
      return res.status(400).send('Invalid signature');
    }
    try {
      await handleEvent(event);
      res.json({ received: true });
    } catch (err) {
      // A non-2xx response makes Stripe retry the delivery.
      log.error(`Webhook ${event.type} (${event.id}) failed: ${err.message}`);
      res.status(500).send('Handler error');
    }
  });

  app.use(express.json());

  // ---- Public endpoints -----------------------------------------------------

  app.post('/api/quote', (req, res) => {
    res.json(computeQuote(req.body));
  });

  // Creates the booking and returns a Stripe Checkout URL that saves the customer's
  // payment method. Nothing is charged until the clean is marked complete.
  app.post('/api/bookings', async (req, res) => {
    const { name, email, phone, address, firstVisitAt, arrivalWindow } = req.body;
    const quote = computeQuote(req.body);
    if (!name || !email) throw new QuoteError('name and email are required');
    if (!address?.line1 || !address?.city || !address?.postal_code) {
      throw new QuoteError('address.line1, address.city and address.postal_code are required');
    }
    if (!ARRIVAL_WINDOWS.includes(arrivalWindow)) {
      throw new QuoteError(`arrivalWindow must be one of ${ARRIVAL_WINDOWS.join(', ')}`);
    }
    const visitTime = Date.parse(firstVisitAt);
    if (Number.isNaN(visitTime) || visitTime <= Date.now()) {
      throw new QuoteError('firstVisitAt must be a future ISO date-time');
    }

    const booking = await store.create({
      status: 'awaiting_payment_method',
      quote,
      firstVisitAt: new Date(visitTime).toISOString(),
      arrivalWindow,
    });

    // The service address is the customer address, which is what Stripe Tax uses to place the sale.
    // validate_location rejects an address Stripe Tax can't resolve now, instead of at invoice time.
    const customer = await stripe.customers.create(
      {
        name,
        email,
        phone,
        address: { ...pick(address, ['line1', 'line2', 'city', 'postal_code']), state: address.state || 'ON', country: 'CA' },
        tax: { validate_location: 'immediately' },
        metadata: { booking_id: booking.id },
      },
      { idempotencyKey: `customer-${booking.id}` },
    );

    // Setup mode: saves the payment method for charging after the clean. payment_method_types is
    // omitted so eligible methods are managed in the Dashboard (Settings > Payment methods).
    const session = await stripe.checkout.sessions.create(
      {
        mode: 'setup',
        currency: CURRENCY,
        customer: customer.id,
        success_url: `${config.publicBaseUrl}/booking/confirmed?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${config.publicBaseUrl}/booking/cancelled?booking_id=${booking.id}`,
        metadata: { booking_id: booking.id },
        setup_intent_data: { metadata: { booking_id: booking.id } },
        integration_identifier: INTEGRATION_IDENTIFIER,
      },
      { idempotencyKey: `checkout-${booking.id}` },
    );

    await store.update(booking.id, { customerId: customer.id, checkoutSessionId: session.id });
    res.status(201).json({ bookingId: booking.id, quote, checkoutUrl: session.url });
  });

  // Customer Portal lets recurring customers update their card or cancel.
  // TODO: put this behind real customer authentication; a booking ID alone is not proof of identity.
  app.post('/api/billing-portal', async (req, res) => {
    const booking = await store.get(String(req.body.bookingId || ''));
    if (!booking?.customerId) return res.status(404).json({ error: 'Booking not found' });
    const portal = await stripe.billingPortal.sessions.create({
      customer: booking.customerId,
      return_url: `${config.publicBaseUrl}/account`,
    });
    res.json({ url: portal.url });
  });

  // ---- Office / crew endpoints ----------------------------------------------

  const admin = express.Router();
  admin.use(requireAdmin(config.adminToken));

  admin.get('/bookings/:id', async (req, res) => {
    const booking = await store.get(req.params.id);
    if (!booking) return res.status(404).json({ error: 'Booking not found' });
    res.json(booking);
  });

  // Called once the crew finishes the clean: this is the moment the customer is charged.
  admin.post('/bookings/:id/complete', async (req, res) => {
    const booking = await loadChargeableBooking(req.params.id, res);
    if (!booking) return;
    const invoice = booking.subscriptionId
      ? await heldSubscriptionInvoice(booking)
      : await createVisitInvoice(booking);
    if (!invoice) {
      return res.status(409).json({ error: 'No invoice is waiting for this visit yet. Try again after the visit start time.' });
    }
    res.json(await chargeInvoice(booking, invoice.id));
  });

  // A recurring visit that didn't happen (holiday, customer away): drop that period's charge.
  admin.post('/bookings/:id/skip', async (req, res) => {
    const booking = await loadChargeableBooking(req.params.id, res);
    if (!booking) return;
    if (!booking.subscriptionId) return res.status(400).json({ error: 'Only recurring bookings have visits to skip' });
    const invoice = await heldSubscriptionInvoice(booking);
    if (!invoice) return res.status(409).json({ error: 'No invoice is waiting for this visit' });
    // Draft subscription invoices can't be voided directly: finalize without collecting, then void.
    const current = await stripe.invoices.retrieve(invoice.id);
    if (current.status === 'draft') await stripe.invoices.finalizeInvoice(invoice.id, { auto_advance: false });
    await stripe.invoices.voidInvoice(invoice.id);
    await setVisitStatus(booking, invoice.id, 'skipped');
    res.json({ invoiceId: invoice.id, status: 'skipped' });
  });

  app.use('/api/admin', admin);

  app.use((err, req, res, next) => {
    if (err instanceof QuoteError) return res.status(400).json({ error: err.message });
    if (err?.type === 'StripeInvalidRequestError' && err.param?.startsWith('address')) {
      return res.status(400).json({ error: 'We could not verify that address. Please check it and try again.' });
    }
    log.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  });

  // ---- Helpers ----------------------------------------------------------------

  async function loadChargeableBooking(id, res) {
    const booking = await store.get(id);
    if (!booking) {
      res.status(404).json({ error: 'Booking not found' });
      return null;
    }
    if (booking.status !== 'active') {
      res.status(409).json({ error: `Booking is ${booking.status}` });
      return null;
    }
    return booking;
  }

  async function createVisitInvoice(booking) {
    // A one-time booking has a single visit; a retry after a failed payment reuses its open invoice.
    if (booking.visits.length) return { id: booking.visits[0].invoiceId };

    const { quote } = booking;
    const invoice = await stripe.invoices.create(
      {
        customer: booking.customerId,
        collection_method: 'charge_automatically',
        auto_advance: true,
        automatic_tax: { enabled: true },
        pending_invoice_items_behavior: 'exclude',
        metadata: { booking_id: booking.id },
      },
      { idempotencyKey: `invoice-${booking.id}` },
    );
    await stripe.invoiceItems.create(
      {
        customer: booking.customerId,
        invoice: invoice.id,
        description: describeVisit(booking),
        price_data: {
          currency: CURRENCY,
          product: SERVICES[quote.service].productId,
          unit_amount: quote.amount,
          tax_behavior: TAX_BEHAVIOR,
        },
      },
      { idempotencyKey: `invoice-item-${booking.id}` },
    );
    booking.visits.push({ invoiceId: invoice.id, status: 'awaiting_clean' });
    await store.update(booking.id, { visits: booking.visits });
    return invoice;
  }

  async function heldSubscriptionInvoice(booking) {
    const visit = booking.visits.find((v) => v.status === 'awaiting_clean' || v.status === 'payment_failed');
    return visit ? { id: visit.invoiceId } : null;
  }

  async function chargeInvoice(booking, invoiceId) {
    let invoice = await stripe.invoices.retrieve(invoiceId);
    if (invoice.status === 'draft') {
      invoice = await stripe.invoices.finalizeInvoice(invoiceId, { auto_advance: true });
    }
    if (invoice.status === 'open') {
      try {
        invoice = await stripe.invoices.pay(invoiceId);
      } catch (err) {
        if (err?.type !== 'StripeCardError') throw err;
        // The invoice stays open and Stripe retries it; invoice.payment_failed records the failure.
        invoice = await stripe.invoices.retrieve(invoiceId);
      }
    }
    const status = invoice.status === 'paid' ? 'paid' : 'payment_failed';
    await setVisitStatus(booking, invoiceId, status);
    return {
      invoiceId,
      status,
      amountPaid: invoice.amount_paid,
      tax: invoice.total_taxes?.reduce((sum, t) => sum + t.amount, 0) ?? null,
      hostedInvoiceUrl: invoice.hosted_invoice_url,
    };
  }

  async function setVisitStatus(booking, invoiceId, status) {
    const visit = booking.visits.find((v) => v.invoiceId === invoiceId);
    if (visit) visit.status = status;
    else booking.visits.push({ invoiceId, status });
    await store.update(booking.id, { visits: booking.visits });
  }

  // ---- Webhook handlers -----------------------------------------------------

  async function handleEvent(event) {
    const object = event.data.object;
    switch (event.type) {
      case 'checkout.session.completed':
        if (object.mode === 'setup') await onPaymentMethodSaved(object);
        break;
      case 'invoice.created':
        await onInvoiceCreated(object);
        break;
      case 'invoice.paid':
        await onInvoiceStatus(object, 'paid');
        break;
      case 'invoice.payment_failed':
        // TODO: email the customer object.hosted_invoice_url so they can pay or update their card.
        await onInvoiceStatus(object, 'payment_failed');
        break;
      case 'customer.subscription.deleted': {
        const booking = await store.findBySubscription(object.id);
        if (booking) await store.update(booking.id, { status: 'cancelled' });
        break;
      }
      default:
        break;
    }
  }

  async function onPaymentMethodSaved(session) {
    const booking = await store.get(session.metadata?.booking_id);
    if (!booking || booking.status !== 'awaiting_payment_method') return; // unknown or already handled

    const setupIntent = await stripe.setupIntents.retrieve(session.setup_intent);
    await stripe.customers.update(booking.customerId, {
      invoice_settings: { default_payment_method: setupIntent.payment_method },
    });

    let subscriptionId;
    const recurring = FREQUENCIES[booking.quote.frequency];
    if (recurring) {
      // The billing cycle starts at the first visit, so each period's invoice is created on a visit day.
      // onInvoiceCreated holds it as a draft until the crew marks that clean complete.
      const subscription = await stripe.subscriptions.create(
        {
          customer: booking.customerId,
          collection_method: 'charge_automatically',
          automatic_tax: { enabled: true },
          billing_cycle_anchor: Math.floor(Date.parse(booking.firstVisitAt) / 1000),
          proration_behavior: 'none',
          items: [
            {
              price_data: {
                currency: CURRENCY,
                product: SERVICES[booking.quote.service].productId,
                unit_amount: booking.quote.amount,
                tax_behavior: TAX_BEHAVIOR,
                recurring,
              },
            },
          ],
          metadata: { booking_id: booking.id },
        },
        { idempotencyKey: `subscription-${booking.id}` },
      );
      subscriptionId = subscription.id;
    }
    await store.update(booking.id, { status: 'active', subscriptionId });
  }

  async function onInvoiceCreated(invoice) {
    if (invoice.billing_reason !== 'subscription_cycle' || invoice.status !== 'draft') return;
    const subscriptionId = invoice.parent?.subscription_details?.subscription;
    const booking = subscriptionId && (await store.findBySubscription(subscriptionId));
    if (!booking) return;
    // Stop Stripe from finalizing and charging automatically: customers pay only after the clean.
    await stripe.invoices.update(invoice.id, { auto_advance: false });
    if (!booking.visits.some((v) => v.invoiceId === invoice.id)) {
      booking.visits.push({ invoiceId: invoice.id, status: 'awaiting_clean' });
      await store.update(booking.id, { visits: booking.visits });
    }
  }

  async function onInvoiceStatus(invoice, status) {
    const bookingId = invoice.metadata?.booking_id;
    const subscriptionId = invoice.parent?.subscription_details?.subscription;
    const booking = (bookingId && (await store.get(bookingId))) || (subscriptionId && (await store.findBySubscription(subscriptionId)));
    if (!booking) return;
    const visit = booking.visits.find((v) => v.invoiceId === invoice.id);
    if (visit && visit.status !== 'paid') {
      visit.status = status;
      await store.update(booking.id, { visits: booking.visits });
    }
  }

  return app;
}

function requireAdmin(token) {
  const expected = Buffer.from(`Bearer ${token}`);
  return (req, res, next) => {
    const given = Buffer.from(req.get('authorization') || '');
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
  };
}

function describeVisit(booking) {
  const { quote, firstVisitAt, arrivalWindow } = booking;
  const day = firstVisitAt.slice(0, 10);
  return `${SERVICES[quote.service].name} - ${quote.bedrooms} bed / ${quote.bathrooms} bath - ${day} (${arrivalWindow})`;
}

function pick(obj, keys) {
  return Object.fromEntries(keys.filter((k) => obj[k] != null).map((k) => [k, obj[k]]));
}

module.exports = { createApp, ARRIVAL_WINDOWS };
