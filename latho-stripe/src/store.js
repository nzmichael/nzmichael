'use strict';

const crypto = require('node:crypto');

// In-memory booking store. Swap for your database before going live:
// bookings are lost on restart, and this does not work across multiple server instances.
function createMemoryStore() {
  const bookings = new Map();
  return {
    async create(data) {
      const booking = { id: crypto.randomUUID(), createdAt: new Date().toISOString(), visits: [], ...data };
      bookings.set(booking.id, booking);
      return booking;
    },
    async get(id) {
      return bookings.get(id) || null;
    },
    async update(id, patch) {
      const booking = bookings.get(id);
      if (!booking) return null;
      Object.assign(booking, patch);
      return booking;
    },
    async findBySubscription(subscriptionId) {
      for (const b of bookings.values()) if (b.subscriptionId === subscriptionId) return b;
      return null;
    },
  };
}

module.exports = { createMemoryStore };
