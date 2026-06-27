'use strict';
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is not set.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,  // fail fast if DB unreachable
  statement_timeout: 10_000,       // kill queries running > 10 s
});

pool.on('error', (err) => console.error('[pg] Unexpected client error', err));

module.exports = pool;
