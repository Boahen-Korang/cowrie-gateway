'use strict';
const pool = require('./db');

/* ─── result helpers ─── */
const d  = (r) => (r.rows[0] ? r.rows[0].data : null);
const da = (r) => r.rows.map((x) => x.data);

/* ─── merchants ─── */
const merchants = {
  async all()               { return da(await pool.query('SELECT data FROM merchants')); },
  async byId(id)            { return d(await pool.query('SELECT data FROM merchants WHERE id=$1', [id])); },
  async byEmail(email)      { return d(await pool.query('SELECT data FROM merchants WHERE lower(email)=lower($1)', [email])); },
  async byPublicKey(k)      { return d(await pool.query('SELECT data FROM merchants WHERE public_key=$1', [k])); },
  async bySecretKey(k)      { return d(await pool.query('SELECT data FROM merchants WHERE secret_key=$1', [k])); },
  async byLivePublicKey(k)  { return d(await pool.query('SELECT data FROM merchants WHERE live_public_key=$1', [k])); },
  async byLiveSecretKey(k)  { return d(await pool.query('SELECT data FROM merchants WHERE live_secret_key=$1', [k])); },
  async insert(m) {
    await pool.query(
      'INSERT INTO merchants (id,email,public_key,secret_key,live_public_key,live_secret_key,data) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)',
      [m.id, m.email, m.publicKey, m.secretKey, m.livePublicKey || null, m.liveSecretKey || null, JSON.stringify(m)],
    );
    return m;
  },
  async update(m) {
    await pool.query(
      'UPDATE merchants SET data=$1::jsonb, email=$2, public_key=$3, secret_key=$4, live_public_key=$5, live_secret_key=$6 WHERE id=$7',
      [JSON.stringify(m), m.email, m.publicKey, m.secretKey, m.livePublicKey || null, m.liveSecretKey || null, m.id],
    );
    return m;
  },
};

/* ─── charges ─── */
const charges = {
  async all() {
    return da(await pool.query("SELECT data FROM charges ORDER BY (data->>'createdAt')::bigint DESC"));
  },
  async byReference(ref) { return d(await pool.query('SELECT data FROM charges WHERE reference=$1', [ref])); },
  async forMerchant(id) {
    return da(await pool.query(
      "SELECT data FROM charges WHERE merchant_id=$1 ORDER BY (data->>'createdAt')::bigint DESC",
      [id],
    ));
  },
  async insert(c) {
    await pool.query(
      'INSERT INTO charges (reference,merchant_id,data) VALUES ($1,$2,$3::jsonb)',
      [c.reference, c.merchantId, JSON.stringify(c)],
    );
    return c;
  },
  async update(c) {
    await pool.query('UPDATE charges SET data=$1::jsonb WHERE reference=$2', [JSON.stringify(c), c.reference]);
    return c;
  },
};

/* ─── events ─── */
const events = {
  async forMerchant(id) {
    return da(await pool.query(
      "SELECT data FROM events WHERE merchant_id=$1 ORDER BY (data->>'createdAt')::bigint DESC",
      [id],
    ));
  },
  async insert(e) {
    await pool.query(
      'INSERT INTO events (id,merchant_id,data) VALUES ($1,$2,$3::jsonb)',
      [e.id, e.merchantId, JSON.stringify(e)],
    );
    return e;
  },
  async update() { /* no-op */ },
};

/* ─── payouts ─── */
const payouts = {
  async all() {
    return da(await pool.query("SELECT data FROM payouts ORDER BY (data->>'createdAt')::bigint DESC"));
  },
  async byId(id) { return d(await pool.query('SELECT data FROM payouts WHERE id=$1', [id])); },
  async forMerchant(id) {
    return da(await pool.query(
      "SELECT data FROM payouts WHERE merchant_id=$1 ORDER BY (data->>'createdAt')::bigint DESC",
      [id],
    ));
  },
  async insert(p) {
    await pool.query(
      'INSERT INTO payouts (id,merchant_id,data) VALUES ($1,$2,$3::jsonb)',
      [p.id, p.merchantId, JSON.stringify(p)],
    );
    return p;
  },
  async update(p) {
    await pool.query('UPDATE payouts SET data=$1::jsonb WHERE id=$2', [JSON.stringify(p), p.id]);
    return p;
  },
};

/* ─── settlements ─── */
const settlements = {
  async all() {
    return da(await pool.query("SELECT data FROM settlements ORDER BY (data->>'createdAt')::bigint DESC"));
  },
  async insert(s) {
    await pool.query('INSERT INTO settlements (id,data) VALUES ($1,$2::jsonb)', [s.id, JSON.stringify(s)]);
    return s;
  },
  async update(s) {
    await pool.query('UPDATE settlements SET data=$1::jsonb WHERE id=$2', [JSON.stringify(s), s.id]);
    return s;
  },
};

/* ─── pending email verifications ─── */
const verifications = {
  async set(email, otp, data, expiresAt) {
    await pool.query(
      `INSERT INTO pending_verifications (email,otp,data,expires_at) VALUES (lower($1),$2,$3::jsonb,$4)
       ON CONFLICT (email) DO UPDATE SET otp=$2, data=$3::jsonb, expires_at=$4`,
      [email, otp, JSON.stringify(data), expiresAt],
    );
  },
  async get(email) {
    const r = await pool.query('SELECT * FROM pending_verifications WHERE email=lower($1)', [email]);
    return r.rows[0] || null;
  },
  async del(email) {
    await pool.query('DELETE FROM pending_verifications WHERE email=lower($1)', [email]);
  },
};

/* ─── platform settings ─── */
const settings = {
  async get(key) {
    return d(await pool.query('SELECT data FROM platform_settings WHERE key=$1', [key]));
  },
  async set(key, data) {
    await pool.query(
      'INSERT INTO platform_settings (key,data) VALUES ($1,$2::jsonb) ON CONFLICT (key) DO UPDATE SET data=$2::jsonb',
      [key, JSON.stringify(data)],
    );
  },
};

/* backward-compat stubs */
async function persist() {}
async function load() {}

module.exports = { load, persist, merchants, charges, events, payouts, settlements, verifications, settings };
