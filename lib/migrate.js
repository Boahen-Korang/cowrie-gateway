'use strict';
const pool = require('./db');

const SQL = `
CREATE TABLE IF NOT EXISTS merchants (
  id         TEXT PRIMARY KEY,
  email      TEXT UNIQUE NOT NULL,
  public_key TEXT UNIQUE NOT NULL,
  secret_key TEXT UNIQUE NOT NULL,
  data       JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS charges (
  reference   TEXT PRIMARY KEY,
  merchant_id TEXT NOT NULL,
  data        JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS charges_merchant_idx ON charges (merchant_id);

CREATE TABLE IF NOT EXISTS events (
  id          TEXT PRIMARY KEY,
  merchant_id TEXT NOT NULL,
  data        JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_merchant_idx ON events (merchant_id);

CREATE TABLE IF NOT EXISTS payouts (
  id          TEXT PRIMARY KEY,
  merchant_id TEXT NOT NULL,
  data        JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS payouts_merchant_idx ON payouts (merchant_id);

CREATE TABLE IF NOT EXISTS settlements (
  id   TEXT PRIMARY KEY,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_verifications (
  email      TEXT PRIMARY KEY,
  otp        TEXT NOT NULL,
  data       JSONB NOT NULL,
  expires_at BIGINT NOT NULL
);
`;

async function migrate() {
  await pool.query(SQL);
  console.log('  ✓ Database tables ready');
}

module.exports = { migrate };
