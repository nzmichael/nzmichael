'use strict';

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable ${name}`);
  return value;
}

function loadConfig() {
  return {
    stripeApiKey: required('STRIPE_API_KEY'),
    webhookSecret: required('STRIPE_WEBHOOK_SECRET'),
    adminToken: required('ADMIN_TOKEN'),
    publicBaseUrl: process.env.PUBLIC_BASE_URL || 'http://localhost:4242',
    port: Number(process.env.PORT) || 4242,
  };
}

module.exports = { loadConfig };
