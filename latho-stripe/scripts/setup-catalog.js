'use strict';

// Creates (or updates) one Stripe Product per cleaning service. Safe to re-run.
const { createStripeClient } = require('../src/stripeClient');
const { SERVICES } = require('../src/catalog');

async function main() {
  const apiKey = process.env.STRIPE_API_KEY;
  const taxCode = process.env.STRIPE_TAX_CODE;
  if (!apiKey) throw new Error('Set STRIPE_API_KEY');
  if (!taxCode) {
    throw new Error('Set STRIPE_TAX_CODE to the product tax code for cleaning services (see https://docs.stripe.com/tax/tax-codes)');
  }
  const stripe = createStripeClient(apiKey);

  for (const { productId, name } of Object.values(SERVICES)) {
    try {
      await stripe.products.update(productId, { name, tax_code: taxCode });
      console.log(`updated ${productId}`);
    } catch (err) {
      if (err?.code !== 'resource_missing') throw err;
      await stripe.products.create({ id: productId, name, tax_code: taxCode });
      console.log(`created ${productId}`);
    }
  }

  const settings = await stripe.tax.settings.retrieve();
  console.log(`Stripe Tax settings status: ${settings.status}`);
  const registrations = await stripe.tax.registrations.list({ status: 'active', limit: 100 });
  const ca = registrations.data.filter((r) => r.country === 'CA');
  if (ca.length === 0) {
    console.warn('No active Canadian tax registration: invoices will collect $0 HST until you add one (Dashboard > Tax > Registrations).');
  } else {
    console.log(`Active Canadian registrations: ${ca.map((r) => JSON.stringify(r.country_options.ca)).join(', ')}`);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
