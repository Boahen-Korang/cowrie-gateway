'use strict';
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'data', 'db.json');

let db = { merchants: [], charges: [], events: [], payouts: [], settlements: [] };

function load() {
  try {
    const raw = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    db = { merchants: [], charges: [], events: [], payouts: [], settlements: [], ...raw };
  } catch {
    db = { merchants: [], charges: [], events: [], payouts: [], settlements: [] };
    persist();
  }
}

function persist() {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function collection(name) {
  return {
    all() { return db[name]; },
    insert(record) { db[name].push(record); persist(); return record; },
    update(record) { persist(); return record; },
    byId(id) { return db[name].find((r) => r.id === id) || null; },
  };
}

const merchants = Object.assign(collection('merchants'), {
  byEmail(email) { return db.merchants.find((m) => m.email === email) || null; },
  byPublicKey(key) { return db.merchants.find((m) => m.publicKey === key) || null; },
  bySecretKey(key) { return db.merchants.find((m) => m.secretKey === key) || null; },
});

const charges = Object.assign(collection('charges'), {
  byReference(ref) { return db.charges.find((c) => c.reference === ref) || null; },
  forMerchant(merchantId) {
    return db.charges.filter((c) => c.merchantId === merchantId).sort((a, b) => b.createdAt - a.createdAt);
  },
});

const events = Object.assign(collection('events'), {
  forMerchant(merchantId) {
    return db.events.filter((e) => e.merchantId === merchantId).sort((a, b) => b.createdAt - a.createdAt);
  },
});

const payouts = Object.assign(collection('payouts'), {
  forMerchant(merchantId) {
    return db.payouts.filter((p) => p.merchantId === merchantId).sort((a, b) => b.createdAt - a.createdAt);
  },
});

const settlements = Object.assign(collection('settlements'), {
  forMerchant(merchantId) {
    return db.settlements.filter((s) => s.merchantId === merchantId).sort((a, b) => b.createdAt - a.createdAt);
  },
});

module.exports = { load, persist, merchants, charges, events, payouts, settlements };
