'use strict';
/*
 * Tiny JSON-file persistence layer. In production swap this single module
 * for Postgres/Prisma — every other file talks to the gateway through here,
 * so nothing else has to change.
 */
const fs = require('fs');
const path = require('path');

const FILE = path.join(__dirname, '..', 'data', 'db.json');
const empty = { merchants: [], charges: [], events: [], idempotency: {} };
let db = JSON.parse(JSON.stringify(empty));

function load() {
  try {
    db = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    for (const k of Object.keys(empty)) if (!db[k]) db[k] = empty[k];
  } catch { save(); }
}
let pending = false;
function save() {
  if (pending) return;
  pending = true;
  process.nextTick(() => {
    pending = false;
    fs.mkdirSync(path.dirname(FILE), { recursive: true });
    fs.writeFileSync(FILE, JSON.stringify(db, null, 2));
  });
}

/* ---------- merchants ---------- */
const merchants = {
  all: () => db.merchants,
  byId: (id) => db.merchants.find((m) => m.id === id),
  byEmail: (e) => db.merchants.find((m) => m.email.toLowerCase() === String(e).toLowerCase()),
  byPublicKey: (k) => db.merchants.find((m) => m.publicKey === k),
  bySecretKey: (k) => db.merchants.find((m) => m.secretKey === k),
  insert: (m) => { db.merchants.push(m); save(); return m; },
  update: (m) => { save(); return m; },
};

/* ---------- charges ---------- */
const charges = {
  byRef: (r) => db.charges.find((c) => c.reference === r),
  forMerchant: (id) => db.charges.filter((c) => c.merchantId === id)
    .sort((a, b) => b.createdAt - a.createdAt),
  insert: (c) => { db.charges.push(c); save(); return c; },
  update: (c) => { c.updatedAt = Date.now(); save(); return c; },
};

/* ---------- webhook events (audit log) ---------- */
const events = {
  forMerchant: (id) => db.events.filter((e) => e.merchantId === id)
    .sort((a, b) => b.createdAt - a.createdAt),
  insert: (e) => { db.events.push(e); save(); return e; },
  update: () => save(),
};

/* ---------- idempotency ---------- */
const idempotency = {
  get: (key) => db.idempotency[key],
  set: (key, reference) => { db.idempotency[key] = { reference, at: Date.now() }; save(); },
};

module.exports = { load, save, merchants, charges, events, idempotency, _db: () => db };
