'use strict';
const crypto = require('crypto');

/* ---------- IDs & keys ---------- */
const reference   = () => 'cwr_' + crypto.randomBytes(12).toString('hex');
const merchantId  = () => 'mch_' + crypto.randomBytes(9).toString('hex');
const eventId     = () => 'evt_' + crypto.randomBytes(9).toString('hex');
const apiKey = (type) =>
  (type === 'secret' ? 'sk_test_' : 'pk_test_') + crypto.randomBytes(20).toString('hex');

/* ---------- password hashing (scrypt, no deps) ---------- */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(String(pw), salt, 64);
  return salt.toString('hex') + ':' + dk.toString('hex');
}
function verifyPassword(pw, stored) {
  try {
    const [s, h] = stored.split(':');
    const dk = crypto.scryptSync(String(pw), Buffer.from(s, 'hex'), 64);
    return crypto.timingSafeEqual(dk, Buffer.from(h, 'hex'));
  } catch { return false; }
}

/* ---------- HMAC signing (tokens + webhooks) ---------- */
const hmac = (data, secret) => crypto.createHmac('sha256', secret).update(data).digest('hex');

function makeToken(payload, secret, ttlSec = 86400) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + ttlSec * 1000 })).toString('base64url');
  return body + '.' + hmac(body, secret);
}
function readToken(token, secret) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = hmac(body, secret);
  if (sig.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  let data;
  try { data = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
  if (!data.exp || data.exp < Date.now()) return null;
  return data;
}

/* ---------- card validation ---------- */
function luhnValid(num) {
  const n = String(num).replace(/\D/g, '');
  if (n.length < 12) return false;
  let sum = 0, alt = false;
  for (let i = n.length - 1; i >= 0; i--) {
    let d = +n[i];
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}
function cardBrand(num) {
  const n = String(num).replace(/\D/g, '');
  if (/^4/.test(n)) return 'visa';
  if (/^(5[1-5]|2[2-7])/.test(n)) return 'mastercard';
  if (/^(506[01]|650|5078|6280)/.test(n)) return 'verve';
  return 'unknown';
}

module.exports = {
  reference, merchantId, eventId, apiKey,
  hashPassword, verifyPassword, hmac, makeToken, readToken,
  luhnValid, cardBrand,
};
