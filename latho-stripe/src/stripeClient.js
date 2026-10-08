'use strict';

const Stripe = require('stripe');

function createStripeClient(apiKey) {
  return new Stripe(apiKey, { apiVersion: '2026-08-26.dahlia', maxNetworkRetries: 2 });
}

module.exports = { createStripeClient };
