'use strict';
const cfg = require('./config');

const BASE = 'https://api.paystack.co';

function authHeaders() {
  return {
    Authorization: `Bearer ${cfg.PAYSTACK_SECRET_KEY}`,
    'Content-Type': 'application/json',
  };
}

async function initialize({ email, amount, currency, reference, channels, metadata }) {
  const body = { email, amount, currency, reference, metadata: metadata || {} };
  if (channels && channels.length) body.channels = channels;

  const res = await fetch(`${BASE}/transaction/initialize`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!data.status) throw new Error(data.message || 'Paystack initialization failed');
  return data.data; // { authorization_url, access_code, reference }
}

async function verify(reference) {
  const res = await fetch(`${BASE}/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${cfg.PAYSTACK_SECRET_KEY}` },
  });
  return res.json();
}

// Direct charge — processes payment server-side (no popup)
async function charge(body) {
  const res = await fetch(`${BASE}/charge`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(body),
  });
  return res.json();
}

async function submitOtp(reference, otp) {
  const res = await fetch(`${BASE}/charge/submit_otp`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ reference, otp }),
  });
  return res.json();
}

async function submitPin(reference, pin) {
  const res = await fetch(`${BASE}/charge/submit_pin`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ reference, pin }),
  });
  return res.json();
}

async function getCharge(reference) {
  const res = await fetch(`${BASE}/charge/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${cfg.PAYSTACK_SECRET_KEY}` },
  });
  return res.json();
}

module.exports = { initialize, verify, charge, submitOtp, submitPin, getCharge };
