'use strict';
const cfg = require('./config');

const BASE = 'https://api.paystack.co';

/* Keys loaded from DB at boot (or updated by admin) override env vars */
let _cachedKeys = null;
function configureKeys(keys) { _cachedKeys = keys || null; }

function sk(mode) {
  if (_cachedKeys) {
    const k = mode === 'live' ? _cachedKeys.liveSecretKey : _cachedKeys.testSecretKey;
    if (k) return k;
  }
  return mode === 'live'
    ? (cfg.PAYSTACK_SK_LIVE || cfg.PAYSTACK_SECRET_KEY)
    : (cfg.PAYSTACK_SK_TEST || cfg.PAYSTACK_SECRET_KEY);
}

function authHeaders(mode) {
  return {
    Authorization: `Bearer ${sk(mode)}`,
    'Content-Type': 'application/json',
  };
}

async function initialize({ email, amount, currency, reference, channels, metadata }, mode = 'test') {
  const body = { email, amount, currency, reference, metadata: metadata || {} };
  if (channels && channels.length) body.channels = channels;

  const res = await fetch(`${BASE}/transaction/initialize`, {
    method: 'POST',
    headers: authHeaders(mode),
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!data.status) throw new Error(data.message || 'Paystack initialization failed');
  return data.data; // { authorization_url, access_code, reference }
}

async function verify(reference, mode = 'test') {
  const res = await fetch(`${BASE}/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${sk(mode)}` },
  });
  return res.json();
}

async function charge(body, mode = 'test') {
  const res = await fetch(`${BASE}/charge`, {
    method: 'POST',
    headers: authHeaders(mode),
    body: JSON.stringify(body),
  });
  return res.json();
}

async function submitOtp(reference, otp, mode = 'test') {
  const res = await fetch(`${BASE}/charge/submit_otp`, {
    method: 'POST',
    headers: authHeaders(mode),
    body: JSON.stringify({ reference, otp }),
  });
  return res.json();
}

async function submitPin(reference, pin, mode = 'test') {
  const res = await fetch(`${BASE}/charge/submit_pin`, {
    method: 'POST',
    headers: authHeaders(mode),
    body: JSON.stringify({ reference, pin }),
  });
  return res.json();
}

async function getCharge(reference, mode = 'test') {
  const res = await fetch(`${BASE}/charge/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${sk(mode)}` },
  });
  return res.json();
}

function publicKey(mode = 'test') {
  if (_cachedKeys) {
    const k = mode === 'live' ? _cachedKeys.livePublicKey : _cachedKeys.testPublicKey;
    if (k) return k;
  }
  return mode === 'live'
    ? (cfg.PAYSTACK_PK_LIVE || cfg.PAYSTACK_PUBLIC_KEY)
    : (cfg.PAYSTACK_PK_TEST || cfg.PAYSTACK_PUBLIC_KEY);
}

module.exports = { initialize, verify, charge, submitOtp, submitPin, getCharge, publicKey, configureKeys };
