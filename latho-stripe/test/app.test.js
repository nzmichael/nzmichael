'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../src/app');
const { createMemoryStore } = require('../src/store');
const { computeQuote } = require('../src/pricing');

const config = { webhookSecret: 'whsec_test', adminToken: 'admin-secret', publicBaseUrl: 'https://lathocleaning.com' };
const ADMIN = { authorization: 'Bearer admin-secret' };

// Records every Stripe call and returns canned objects; no network access.
function fakeStripe({ payFails = false } = {}) {
  const calls = [];
  const invoices = new Map();
  const rec = (name, fn) => async (...args) => {
    calls.push({ name, args });
    return fn(...args);
  };
  const stripe = {
    calls,
    invoices: {
      create: rec('invoices.create', () => {
        const inv = { id: `in_${invoices.size + 1}`, status: 'draft' };
        invoices.set(inv.id, inv);
        return inv;
      }),
      retrieve: rec('invoices.retrieve', (id) => ({ ...invoices.get(id) })),
      update: rec('invoices.update', (id, p) => Object.assign(invoices.get(id), p)),
      finalizeInvoice: rec('invoices.finalizeInvoice', (id) => Object.assign(invoices.get(id), { status: 'open' })),
      pay: rec('invoices.pay', (id) => {
        if (payFails) throw Object.assign(new Error('Your card was declined.'), { type: 'StripeCardError' });
        return Object.assign(invoices.get(id), {
          status: 'paid',
          amount_paid: 18080,
          total_taxes: [{ amount: 2080 }],
          hosted_invoice_url: 'https://invoice.stripe.com/i/x',
        });
      }),
      voidInvoice: rec('invoices.voidInvoice', (id) => Object.assign(invoices.get(id), { status: 'void' })),
    },
    invoiceItems: { create: rec('invoiceItems.create', () => ({ id: 'ii_1' })) },
    customers: {
      create: rec('customers.create', () => ({ id: 'cus_1' })),
      update: rec('customers.update', () => ({ id: 'cus_1' })),
    },
    checkout: { sessions: { create: rec('checkout.sessions.create', () => ({ id: 'cs_1', url: 'https://checkout.stripe.com/c/cs_1' })) } },
    setupIntents: { retrieve: rec('setupIntents.retrieve', () => ({ id: 'seti_1', payment_method: 'pm_1' })) },
    subscriptions: { create: rec('subscriptions.create', () => ({ id: 'sub_1' })) },
    billingPortal: { sessions: { create: rec('billingPortal.sessions.create', () => ({ url: 'https://billing.stripe.com/p/x' })) } },
    webhooks: {
      constructEvent(body, sig) {
        if (sig !== 'valid') throw new Error('bad signature');
        return JSON.parse(body.toString());
      },
    },
  };
  stripe.seedInvoice = (inv) => invoices.set(inv.id, inv);
  return stripe;
}

async function startServer(stripe) {
  const store = createMemoryStore();
  const silent = { warn() {}, error() {} };
  const server = createApp({ stripe, store, config, log: silent }).listen(0);
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body, headers = {}) => {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json', ...headers },
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  };
  const webhook = (event, sig = 'valid') => call('POST', '/webhooks/stripe', JSON.stringify(event), { 'stripe-signature': sig });
  return { server, store, call, webhook };
}

const bookingRequest = (overrides = {}) => ({
  service: 'standard',
  bedrooms: 2,
  bathrooms: 1,
  frequency: 'once',
  name: 'Sam Client',
  email: 'sam@example.com',
  address: { line1: '1 King St W', city: 'Toronto', postal_code: 'M5H 1A1' },
  firstVisitAt: new Date(Date.now() + 3 * 86400e3).toISOString(),
  arrivalWindow: '8am-10am',
  ...overrides,
});

const sessionCompleted = (bookingId) => ({
  id: 'evt_1',
  type: 'checkout.session.completed',
  data: { object: { mode: 'setup', setup_intent: 'seti_1', metadata: { booking_id: bookingId } } },
});

test('quote applies recurring discount and rejects recurring move-out cleans', () => {
  assert.equal(computeQuote({ service: 'standard', bedrooms: 2, bathrooms: 1 }).amount, 18500);
  assert.equal(computeQuote({ service: 'standard', bedrooms: 2, bathrooms: 1, frequency: 'weekly' }).amount, 15725);
  assert.throws(() => computeQuote({ service: 'move', bedrooms: 1, bathrooms: 1, frequency: 'weekly' }));
});

test('one-time booking: card saved at booking, charged with tax only after the clean', async (t) => {
  const stripe = fakeStripe();
  const { server, store, call, webhook } = await startServer(stripe);
  t.after(() => server.close());

  const created = await call('POST', '/api/bookings', bookingRequest());
  assert.equal(created.status, 201);
  assert.equal(created.body.checkoutUrl, 'https://checkout.stripe.com/c/cs_1');

  const customerParams = stripe.calls.find((c) => c.name === 'customers.create').args[0];
  assert.equal(customerParams.address.country, 'CA');
  assert.equal(customerParams.address.state, 'ON');
  assert.deepEqual(customerParams.tax, { validate_location: 'immediately' });

  const sessionParams = stripe.calls.find((c) => c.name === 'checkout.sessions.create').args[0];
  assert.equal(sessionParams.mode, 'setup');
  assert.equal(sessionParams.currency, 'cad');
  assert.equal('payment_method_types' in sessionParams, false);
  assert.ok(!stripe.calls.some((c) => c.name.startsWith('invoices.')), 'nothing charged at booking');

  const id = created.body.bookingId;
  assert.equal((await webhook(sessionCompleted(id), 'bad')).status, 400);
  assert.equal((await webhook(sessionCompleted(id))).status, 200);
  assert.deepEqual(stripe.calls.find((c) => c.name === 'customers.update').args[1], {
    invoice_settings: { default_payment_method: 'pm_1' },
  });
  assert.equal((await store.get(id)).status, 'active');
  assert.ok(!stripe.calls.some((c) => c.name === 'subscriptions.create'));

  assert.equal((await call('POST', `/api/admin/bookings/${id}/complete`)).status, 401);
  const done = await call('POST', `/api/admin/bookings/${id}/complete`, undefined, ADMIN);
  assert.equal(done.status, 200);
  assert.equal(done.body.status, 'paid');
  assert.equal(done.body.tax, 2080);

  const invoiceParams = stripe.calls.find((c) => c.name === 'invoices.create').args[0];
  assert.deepEqual(invoiceParams.automatic_tax, { enabled: true });
  assert.equal(invoiceParams.collection_method, 'charge_automatically');
  const item = stripe.calls.find((c) => c.name === 'invoiceItems.create').args[0];
  assert.deepEqual(item.price_data, { currency: 'cad', product: 'latho_standard_clean', unit_amount: 18500, tax_behavior: 'exclusive' });
});

test('declined card leaves the visit retryable on the same invoice', async (t) => {
  const stripe = fakeStripe({ payFails: true });
  const { server, store, call, webhook } = await startServer(stripe);
  t.after(() => server.close());

  const { body } = await call('POST', '/api/bookings', bookingRequest());
  await webhook(sessionCompleted(body.bookingId));
  const first = await call('POST', `/api/admin/bookings/${body.bookingId}/complete`, undefined, ADMIN);
  assert.equal(first.body.status, 'payment_failed');
  await call('POST', `/api/admin/bookings/${body.bookingId}/complete`, undefined, ADMIN);
  assert.equal(stripe.calls.filter((c) => c.name === 'invoices.create').length, 1);
  assert.equal((await store.get(body.bookingId)).visits.length, 1);
});

test('recurring booking: subscription invoices are held until each clean is done', async (t) => {
  const stripe = fakeStripe();
  const { server, store, call, webhook } = await startServer(stripe);
  t.after(() => server.close());

  const { body } = await call('POST', '/api/bookings', bookingRequest({ frequency: 'biweekly' }));
  await webhook(sessionCompleted(body.bookingId));
  await webhook(sessionCompleted(body.bookingId)); // redelivery is a no-op

  const subs = stripe.calls.filter((c) => c.name === 'subscriptions.create');
  assert.equal(subs.length, 1);
  const subParams = subs[0].args[0];
  assert.deepEqual(subParams.automatic_tax, { enabled: true });
  assert.deepEqual(subParams.items[0].price_data.recurring, { interval: 'week', interval_count: 2 });
  assert.equal(subParams.proration_behavior, 'none');
  assert.equal(subParams.billing_cycle_anchor, Math.floor(Date.parse((await store.get(body.bookingId)).firstVisitAt) / 1000));

  // Before any cycle invoice exists there is nothing to charge.
  assert.equal((await call('POST', `/api/admin/bookings/${body.bookingId}/complete`, undefined, ADMIN)).status, 409);

  stripe.seedInvoice({ id: 'in_cycle1', status: 'draft' });
  const cycleInvoice = {
    id: 'in_cycle1',
    status: 'draft',
    billing_reason: 'subscription_cycle',
    parent: { subscription_details: { subscription: 'sub_1' } },
  };
  await webhook({ id: 'evt_2', type: 'invoice.created', data: { object: cycleInvoice } });
  assert.deepEqual(stripe.calls.find((c) => c.name === 'invoices.update').args, ['in_cycle1', { auto_advance: false }]);

  const done = await call('POST', `/api/admin/bookings/${body.bookingId}/complete`, undefined, ADMIN);
  assert.equal(done.body.status, 'paid');
  assert.equal(done.body.invoiceId, 'in_cycle1');

  // Next cycle: the customer is away, so the office skips it.
  stripe.seedInvoice({ id: 'in_cycle2', status: 'draft' });
  await webhook({ id: 'evt_3', type: 'invoice.created', data: { object: { ...cycleInvoice, id: 'in_cycle2' } } });
  const skipped = await call('POST', `/api/admin/bookings/${body.bookingId}/skip`, undefined, ADMIN);
  assert.equal(skipped.body.status, 'skipped');
  assert.ok(stripe.calls.some((c) => c.name === 'invoices.voidInvoice' && c.args[0] === 'in_cycle2'));

  await webhook({ id: 'evt_4', type: 'customer.subscription.deleted', data: { object: { id: 'sub_1' } } });
  assert.equal((await store.get(body.bookingId)).status, 'cancelled');
});

test('booking validation rejects bad input without calling Stripe', async (t) => {
  const stripe = fakeStripe();
  const { server, call } = await startServer(stripe);
  t.after(() => server.close());

  assert.equal((await call('POST', '/api/bookings', bookingRequest({ firstVisitAt: '2020-01-01T10:00:00Z' }))).status, 400);
  assert.equal((await call('POST', '/api/bookings', bookingRequest({ arrivalWindow: 'midnight' }))).status, 400);
  assert.equal((await call('POST', '/api/bookings', bookingRequest({ service: 'windows' }))).status, 400);
  assert.equal(stripe.calls.length, 0);
});
