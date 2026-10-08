# Latho Cleaning: Stripe integration

Backend (Node 22, Express 5, `stripe@22.6.0`, API version `2026-08-26.dahlia`) for
[lathocleaning.com](https://lathocleaning.com). It covers Payments, Billing, Invoicing and Tax
around one rule from the business: **customers pay only after the clean is done.**

## Integration plan

| Need | Stripe approach |
| --- | --- |
| Instant quote | Computed server-side (`src/pricing.js`; placeholder rates, so swap in real pricing) |
| Secure card at booking, no charge | Checkout Session in `setup` mode saves the payment method to a Customer |
| Charge after a one-time clean | An Invoice with `charge_automatically` is created, finalized and paid when the crew marks the visit complete |
| Weekly / biweekly service (Billing) | Subscription with an inline weekly price (`interval_count` 1 or 2), anchored to the first visit. Each cycle's invoice is **held as a draft** (`auto_advance: false`) until that clean is marked complete, then charged. Skipped visits are voided |
| Receipts / records (Invoicing) | Every charge is an Invoice, so customers get a hosted invoice and PDF |
| HST (Tax) | Stripe Tax with `automatic_tax` on every invoice and subscription. Prices are tax-exclusive and the Customer's address is the service address |
| Card updates / cancel recurring | Stripe Customer Portal |
| Source of truth | Webhooks: `checkout.session.completed`, `invoice.created`, `invoice.paid`, `invoice.payment_failed`, `customer.subscription.deleted` |

```
Book ─▶ Checkout (setup mode) ─▶ webhook: save default card ─┬─ one-time: wait
                                                              └─ recurring: create subscription
Crew marks clean done ─▶ POST /api/admin/bookings/:id/complete ─▶ finalize + pay invoice (HST added)
Recurring cycle ─▶ webhook invoice.created ─▶ hold draft until that visit is completed or skipped
```

## Setup

1. **Keys.** In the Dashboard, create a **restricted key** (`rk_test_…`) rather than using the secret key.
   It needs write access to Customers, Checkout Sessions, Invoices, Invoice Items, Subscriptions,
   Products, Customer Portal and SetupIntents (read is enough), plus read access to Tax Settings and
   Tax Registrations. Copy `.env.example` to `.env` and fill it in. `.env` is gitignored. In
   production, use your host's secrets vault.
2. **Stripe Tax** (Dashboard → Tax):
   - Set your **head office address** in Tax settings. Tax status stays `pending` without it.
   - Add your **GST/HST registration for Ontario**. Without an active registration, `automatic_tax`
     collects **$0 and returns no error**. Stripe only records registrations you already hold with the
     CRA, so check with your accountant whether you are past the small-supplier threshold.
   - Choose a **product tax code** for residential cleaning from the
     [tax code list](https://docs.stripe.com/tax/tax-codes) and set `STRIPE_TAX_CODE`. It is not
     hardcoded so that you and your accountant make that choice.
3. **Products:** `npm install && npm run setup:catalog` creates one Product per service, then checks
   your tax settings and Canadian registrations.
4. **Payment methods:** the code doesn't pass `payment_method_types`. You choose what customers can
   use under Dashboard → Settings → Payment methods. To keep "card only", leave only cards enabled there.
5. **Customer Portal:** turn it on under Dashboard → Settings → Billing → Customer portal.
6. **Webhooks (required):** locally, run `stripe listen --forward-to localhost:4242/webhooks/stripe`
   and put the printed `whsec_…` in `.env`. In production, add an endpoint for the five events above.
7. `npm start`, then `npm test` (tests use a fake Stripe client and make no network calls).
8. Optional: `npm run hooks:install` adds a pre-commit hook that blocks commits containing Stripe keys.

### Testing with Stripe test cards

- `4242 4242 4242 4242` pays successfully. `4000 0000 0000 0341` saves fine but declines when charged
  after the clean.
- Sandbox tax: run a booking with a Toronto address and check that the invoice's
  `total_taxes[].taxability_reason` is not `not_collecting`. If it is, the registration or tax code is missing.

## API

| Method | Path | Who | Purpose |
| --- | --- | --- | --- |
| POST | `/api/quote` | public | `{service: standard\|deep\|move, bedrooms, bathrooms, frequency: once\|weekly\|biweekly}` |
| POST | `/api/bookings` | public | Quote fields + `name, email, phone, address{line1,city,postal_code}, firstVisitAt, arrivalWindow`. Returns `checkoutUrl` |
| POST | `/api/billing-portal` | customer | `{bookingId}`, which returns a portal URL. **Needs real customer auth before launch** |
| GET | `/api/admin/bookings/:id` | office | Booking + visit/payment status |
| POST | `/api/admin/bookings/:id/complete` | crew/office | Charge for the visit just finished (call again to retry a decline) |
| POST | `/api/admin/bookings/:id/skip` | office | Void a recurring visit's charge |

Admin routes need `Authorization: Bearer $ADMIN_TOKEN`.

## Before going live

- Replace the in-memory store (`src/store.js`) with your database.
- Email customers the `hosted_invoice_url` on `invoice.payment_failed` (marked TODO). Turn on
  Smart Retries and failed-payment emails under Billing → Revenue recovery.
- Add customer authentication to the portal endpoint.
- Add a live-mode restricted key, a live webhook endpoint and **live-mode tax registrations**
  (sandbox registrations don't carry over).
- Add a Content-Security-Policy that allows `https://*.stripe.com` on the site.
- Your 24-hour re-clean guarantee needs no Stripe change. If you ever refund instead, refund the
  invoice's payment from the Dashboard so the HST is reversed with it in Stripe Tax reports.
