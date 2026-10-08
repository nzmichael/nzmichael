'use strict';

const { loadConfig } = require('./config');
const { createStripeClient } = require('./stripeClient');
const { createMemoryStore } = require('./store');
const { createApp } = require('./app');

const config = loadConfig();
const app = createApp({ stripe: createStripeClient(config.stripeApiKey), store: createMemoryStore(), config });
app.listen(config.port, () => console.log(`Latho Stripe server listening on :${config.port}`));
