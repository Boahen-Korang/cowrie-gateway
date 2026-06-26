'use strict';
const crypto = require('crypto');
const cfg = require('./config');

const randomToken = (bytes = 16) => crypto.randomBytes(bytes).toString('hex');

function reference() {
  return 'cwr_' + randomToken(8);
}

function merchantId() {
  return 'mch_' + randomToken(8);
}

function apiKey(kind) {
  const prefix = kind === 'secret' ? 'sk_live_' : 'pk_live_';
  return prefix + randomToken(16);
}

/* ---- password hashing (scrypt, salted) ---- */
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, 64);
  return salt.toString('hex') + ':' + hash.toString('hex');
}

function verifyPassword(password, stored) {
  const [saltHex, hashHex] = String(stored).split(':');
  if (!saltHex || !hashHex) return false;
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(String(password), salt, 64);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

/* ---- merchant session tokens: base64url(payload).hmac ---- */
function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', cfg.SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyToken(token) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', cfg.SECRET).update(body).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expected);
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
  if (payload.exp && Date.now() > payload.exp) return null;
  return payload;
}

/* ---- webhook signing ---- */
function hmacSign(rawBody, secret) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

/* ---- card helpers ---- */
function genId(prefix) {
  return prefix + randomToken(8);
}

function luhnValid(number) {
  const digits = String(number || '');
  if (!/^\d{12,19}$/.test(digits)) return false;
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = +digits[i];
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function cardBrand(number) {
  const n = String(number || '');
  if (/^4/.test(n)) return 'visa';
  if (/^(5[1-5]|2[2-7])/.test(n)) return 'mastercard';
  if (/^(506[01]|650|5078|6280)/.test(n)) return 'verve';
  return 'unknown';
}

module.exports = {
  reference, merchantId, apiKey, genId,
  hashPassword, verifyPassword,
  signToken, verifyToken,
  hmacSign,
  luhnValid, cardBrand,
};
