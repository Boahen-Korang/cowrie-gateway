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

module.exports = { initialize, verify };
