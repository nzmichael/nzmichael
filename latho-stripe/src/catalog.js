'use strict';

// One Stripe Product per service so invoices show what was cleaned.
// Custom product IDs keep scripts/setup-catalog.js idempotent.
const SERVICES = {
  standard: { productId: 'latho_standard_clean', name: 'Standard House Cleaning' },
  deep: { productId: 'latho_deep_clean', name: 'Deep Cleaning' },
  move: { productId: 'latho_move_clean', name: 'Move-In / Move-Out Cleaning' },
};

const FREQUENCIES = {
  once: null,
  weekly: { interval: 'week', interval_count: 1 },
  biweekly: { interval: 'week', interval_count: 2 },
};

const CURRENCY = 'cad';

// Prices are quoted before HST; Stripe Tax adds HST on the invoice.
const TAX_BEHAVIOR = 'exclusive';

// Labels the Checkout flow in the Dashboard (8 random letter suffix, generated once).
const INTEGRATION_IDENTIFIER = 'latho-booking-card-setup-qvhmtkra';

module.exports = { SERVICES, FREQUENCIES, CURRENCY, TAX_BEHAVIOR, INTEGRATION_IDENTIFIER };
