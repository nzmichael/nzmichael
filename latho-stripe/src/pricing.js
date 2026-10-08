'use strict';

const { SERVICES, FREQUENCIES } = require('./catalog');

// PLACEHOLDER RATES (CAD cents) - replace with Latho's real pricing.
const BASE = { standard: 12000, deep: 20000, move: 25000 };
const PER_BEDROOM = { standard: 2000, deep: 3500, move: 4000 };
const PER_BATHROOM = { standard: 2500, deep: 4000, move: 4500 };
const RECURRING_DISCOUNT = { once: 0, weekly: 0.15, biweekly: 0.1 };

function computeQuote({ service, bedrooms, bathrooms, frequency = 'once' }) {
  if (!SERVICES[service]) throw new QuoteError(`Unknown service "${service}"`);
  if (!(frequency in FREQUENCIES)) throw new QuoteError(`Unknown frequency "${frequency}"`);
  if (service === 'move' && frequency !== 'once') {
    throw new QuoteError('Move-in/move-out cleaning is a one-time service');
  }
  const beds = toCount(bedrooms, 'bedrooms');
  const baths = toCount(bathrooms, 'bathrooms');

  const subtotal = BASE[service] + beds * PER_BEDROOM[service] + baths * PER_BATHROOM[service];
  const amount = Math.round(subtotal * (1 - RECURRING_DISCOUNT[frequency]));
  return { service, frequency, bedrooms: beds, bathrooms: baths, amount, currency: 'cad', taxExclusive: true };
}

function toCount(value, field) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0 || n > 10) throw new QuoteError(`${field} must be a whole number from 0 to 10`);
  return n;
}

class QuoteError extends Error {}

module.exports = { computeQuote, QuoteError };
