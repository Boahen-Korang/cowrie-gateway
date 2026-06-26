'use strict';
const express = require('express');
const store = require('../lib/store');
const pay = require('../lib/payments');
const cfg = require('../lib/config');
const {
  merchantId, apiKey, hashPassword, verifyPassword,
  makeToken, readToken,
} = require('../lib/util');

const router = express.Router();

/* ---------- tiny in-memory rate limiter ---------- */
const hits = new Map();
router.use((req, res, next) => {
  const ip = req.ip; const now = Date.now();
  const w = hits.get(ip) || { n: 0, t: now };
  if (now - w.t > 60000) { w.n = 0; w.t = now; }
  w.n++; hits.set(ip, w);
  if (w.n > 240) return res.status(429).json({ error: 'rate_limited', message: 'Too many requests, slow down.' });
  next();
});

/* ---------- helpers ---------- */
const ok = (res, data, code = 200) => res.status(code).json(data);
const err = (res, code, error, message) => res.status(code).json({ error, message });

function view(c) {
  return {
    reference: c.reference, status: c.status, amount: c.amount, currency: c.currency,
    method: c.method, customer_email: c.customerEmail, metadata: c.metadata,
    next_action: c.nextAction, created_at: c.createdAt, paid_at: c.paidAt || null,
    failure: c.failure || null,
    card: c.method === 'card' && c.auth ? { brand: c.auth.brand, last4: c.auth.last4 } : undefined,
  };
}
function merchantView(m, withSecret = false) {
  return {
    id: m.id, business_name: m.businessName, email: m.email,
    public_key: m.publicKey, webhook_url: m.webhookUrl || null,
    ...(withSecret ? { secret_key: m.secretKey, webhook_secret: m.webhookSecret } : {}),
  };
}

/* ---------- middleware ---------- */
function authMerchant(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  const data = token && readToken(token, cfg.APP_SECRET);
  const merchant = data && store.merchants.byId(data.sub);
  if (!merchant) return err(res, 401, 'unauthorized', 'Invalid or expired session.');
  req.merchant = merchant; next();
}
function merchantFromKey(req, res, next) {
  const key = req.body.public_key || req.headers['x-public-key'] ||
              (req.headers.authorization || '').replace(/^Bearer\s+/, '');
  let merchant = key && (store.merchants.byPublicKey(key) || store.merchants.bySecretKey(key));
  if (!merchant) return err(res, 401, 'unauthorized', 'Missing or invalid API key.');
  req.merchant = merchant; next();
}

/* ================= AUTH ================= */
router.post('/auth/register', (req, res) => {
  const { businessName, email, password } = req.body || {};
  if (!businessName || !email || !password) return err(res, 400, 'invalid_request', 'businessName, email and password are required.');
  if (store.merchants.byEmail(email)) return err(res, 409, 'email_taken', 'An account with this email already exists.');
  const m = store.merchants.insert({
    id: merchantId(), businessName, email,
    passwordHash: hashPassword(password),
    publicKey: apiKey('public'), secretKey: apiKey('secret'),
    webhookSecret: 'whsec_' + apiKey('secret').slice(8), webhookUrl: null,
    createdAt: Date.now(),
  });
  const token = makeToken({ sub: m.id }, cfg.APP_SECRET);
  ok(res, { token, merchant: merchantView(m, true) }, 201);
});

router.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const m = store.merchants.byEmail(email || '');
  if (!m || !verifyPassword(password || '', m.passwordHash))
    return err(res, 401, 'invalid_credentials', 'Email or password is incorrect.');
  const token = makeToken({ sub: m.id }, cfg.APP_SECRET);
  ok(res, { token, merchant: merchantView(m, true) });
});

router.get('/me', authMerchant, (req, res) => ok(res, { merchant: merchantView(req.merchant, true) }));

router.put('/me/webhook', authMerchant, (req, res) => {
  req.merchant.webhookUrl = req.body.url || null;
  store.merchants.update(req.merchant);
  ok(res, { merchant: merchantView(req.merchant, true) });
});

router.get('/transactions', authMerchant, (req, res) =>
  ok(res, { data: store.charges.forMerchant(req.merchant.id).map(view) }));

router.get('/events', authMerchant, (req, res) =>
  ok(res, { data: store.events.forMerchant(req.merchant.id) }));

/* ================= CONFIG (for the demo checkout) ================= */
router.get('/config', (req, res) => {
  const demo = store.merchants.all().find((m) => m.demo) || store.merchants.all()[0];
  ok(res, { public_key: demo ? demo.publicKey : null, currency: cfg.CURRENCY,
            merchant_name: demo ? demo.businessName : 'Demo' });
});

/* ================= CHARGES (the gateway) ================= */
router.post('/charges', merchantFromKey, (req, res, next) => {
  try {
    const idemKey = req.headers['idempotency-key'];
    if (idemKey) {
      const prev = store.idempotency.get(idemKey);
      if (prev) return ok(res, view(store.charges.byRef(prev.reference)));
    }
    const charge = pay.createCharge(req.merchant, {
      amount: req.body.amount, currency: req.body.currency, email: req.body.email,
      metadata: req.body.metadata || {},
    });
    if (idemKey) store.idempotency.set(idemKey, charge.reference);
    ok(res, view(charge), 201);
  } catch (e) { next(e); }
});

function loadCharge(req, res, next) {
  const c = store.charges.byRef(req.params.ref);
  if (!c) return err(res, 404, 'not_found', 'No charge with that reference.');
  req.charge = c; next();
}

router.get('/charges/:ref', loadCharge, (req, res) => ok(res, view(req.charge)));

router.post('/charges/:ref/method', loadCharge, (req, res, next) => {
  try {
    const { method, ...details } = req.body || {};
    const c = pay.submitMethod(req.charge, method, details.details || details);
    ok(res, view(c));
  } catch (e) { next(e); }
});

router.post('/charges/:ref/authorize', loadCharge, async (req, res, next) => {
  try { ok(res, view(await pay.authorizeOtp(req.charge, req.body.otp))); }
  catch (e) { next(e); }
});

router.post('/charges/:ref/confirm', loadCharge, async (req, res, next) => {
  try { ok(res, view(await pay.confirmExternal(req.charge))); }
  catch (e) { next(e); }
});

module.exports = router;
