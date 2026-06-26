'use strict';
const express = require('express');
const store = require('../lib/store');
const cfg = require('../lib/config');
const payments = require('../lib/payments');
const {
  merchantId, apiKey, genId, hashPassword, verifyPassword, signToken, verifyToken,
} = require('../lib/util');

const router = express.Router();

/* ---- tiny in-memory rate limiter ---- */
function rateLimit({ windowMs, max }) {
  const hits = new Map();
  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    const entry = hits.get(key) || { count: 0, reset: now + windowMs };
    if (now > entry.reset) { entry.count = 0; entry.reset = now + windowMs; }
    entry.count += 1;
    hits.set(key, entry);
    if (entry.count > max) {
      const e = new Error('Too many requests, slow down.'); e.status = 429; return next(e);
    }
    next();
  };
}
const authLimiter = rateLimit({ windowMs: 60_000, max: 20 });
const chargeLimiter = rateLimit({ windowMs: 60_000, max: 120 });

const asyncHandler = (fn) => (req, res, next) => fn(req, res, next).catch(next);

function publicMerchant(m) {
  const { passwordHash, ...rest } = m;
  return rest;
}

/* ---- merchant session auth (Bearer token from login/register) ---- */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token && verifyToken(token);
  const merchant = payload && store.merchants.byId(payload.sub);
  if (!merchant) { const e = new Error('Unauthorized'); e.status = 401; return next(e); }
  req.merchant = merchant;
  next();
}

/* ---- API-key auth for charge creation (public or secret key) ---- */
function resolveMerchantByKey(req, res, next) {
  const header = req.headers.authorization || '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : null;
  const key = req.headers['x-public-key'] || (req.body && req.body.public_key) || bearer;
  const merchant = key && (store.merchants.byPublicKey(key) || store.merchants.bySecretKey(key));
  if (!merchant) { const e = new Error('Invalid or missing API key'); e.status = 401; return next(e); }
  req.merchant = merchant;
  next();
}

function loadCharge(req, res, next) {
  const charge = store.charges.byReference(req.params.reference);
  if (!charge) { const e = new Error('Unknown charge reference.'); e.status = 404; return next(e); }
  req.charge = charge;
  next();
}

/* =========================== Auth (merchant) =========================== */

router.post('/auth/register', authLimiter, (req, res, next) => {
  try {
    const { businessName, email, password } = req.body || {};
    if (!businessName || !email || !password) {
      const e = new Error('businessName, email and password are required.'); e.status = 400; throw e;
    }
    if (String(password).length < 8) {
      const e = new Error('password must be at least 8 characters.'); e.status = 400; throw e;
    }
    if (store.merchants.byEmail(email)) {
      const e = new Error('An account with this email already exists.'); e.status = 409; throw e;
    }
    const merchant = store.merchants.insert({
      id: merchantId(),
      businessName,
      email,
      passwordHash: hashPassword(password),
      publicKey: apiKey('public'),
      secretKey: apiKey('secret'),
      webhookSecret: 'whsec_' + apiKey('secret').slice(8),
      webhookUrl: null,
      demo: false,
      createdAt: Date.now(),
    });
    const token = signToken({ sub: merchant.id, exp: Date.now() + cfg.TOKEN_TTL_MS });
    res.status(201).json({ token, merchant: publicMerchant(merchant) });
  } catch (e) { next(e); }
});

router.post('/auth/login', authLimiter, (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    const merchant = email && store.merchants.byEmail(email);
    if (!merchant || !verifyPassword(password || '', merchant.passwordHash)) {
      const e = new Error('Invalid email or password.'); e.status = 401; throw e;
    }
    const token = signToken({ sub: merchant.id, exp: Date.now() + cfg.TOKEN_TTL_MS });
    res.json({ token, merchant: publicMerchant(merchant) });
  } catch (e) { next(e); }
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ merchant: publicMerchant(req.merchant) });
});

router.put('/me/webhook', requireAuth, (req, res, next) => {
  try {
    const { url } = req.body || {};
    if (url) {
      try { new URL(url); } catch { const e = new Error('url must be a valid absolute URL.'); e.status = 400; throw e; }
    }
    req.merchant.webhookUrl = url || null;
    store.merchants.update(req.merchant);
    res.json({ merchant: publicMerchant(req.merchant) });
  } catch (e) { next(e); }
});

router.get('/transactions', requireAuth, (req, res) => {
  res.json({ transactions: store.charges.forMerchant(req.merchant.id) });
});

router.get('/events', requireAuth, (req, res) => {
  res.json({ events: store.events.forMerchant(req.merchant.id) });
});

/* =============================== Charges =============================== */

router.post('/charges', chargeLimiter, resolveMerchantByKey, (req, res, next) => {
  try {
    const idemKey = req.headers['idempotency-key'];
    if (idemKey) {
      const existing = store.charges.forMerchant(req.merchant.id).find((c) => c.idempotencyKey === idemKey);
      if (existing) return res.status(200).json({ charge: existing });
    }
    const charge = payments.createCharge(req.merchant, req.body || {});
    if (idemKey) { charge.idempotencyKey = idemKey; store.charges.update(charge); }
    res.status(201).json({ charge });
  } catch (e) { next(e); }
});

router.get('/charges/:reference', loadCharge, (req, res) => {
  res.json({ charge: req.charge });
});

router.post('/charges/:reference/method', loadCharge, (req, res, next) => {
  try {
    const { method, details } = req.body || {};
    const charge = payments.submitMethod(req.charge, method, details || {});
    res.json({ charge });
  } catch (e) { next(e); }
});

router.post('/charges/:reference/authorize', loadCharge, asyncHandler(async (req, res) => {
  const charge = await payments.authorizeOtp(req.charge, (req.body || {}).otp);
  res.json({ charge });
}));

router.post('/charges/:reference/confirm', loadCharge, asyncHandler(async (req, res) => {
  const charge = await payments.confirmExternal(req.charge);
  res.json({ charge });
}));

/* Test-mode convenience: lets the hosted checkout page start a charge client-side
   the same way a real publishable key would, without exposing the secret key. */
router.get('/demo/public-key', (req, res, next) => {
  const demo = store.merchants.all().find((m) => m.demo);
  if (!demo) { const e = new Error('No demo merchant available.'); e.status = 404; return next(e); }
  res.json({ publicKey: demo.publicKey });
});

/* =========================== Admin (merchant-auth) =========================== */

router.get('/admin/overview', requireAuth, (req, res) => {
  const allCharges = store.charges.forMerchant(req.merchant.id);
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const todayTs = today.getTime();

  const successAll = allCharges.filter((c) => c.status === 'success');
  const collectedToday = successAll
    .filter((c) => c.createdAt >= todayTs)
    .reduce((s, c) => s + c.amount, 0);

  const allPayouts = store.payouts.forMerchant(req.merchant.id);
  const paidOutToday = allPayouts
    .filter((p) => p.createdAt >= todayTs && p.status === 'completed')
    .reduce((s, p) => s + p.amount, 0);

  const total = allCharges.length;
  const successRate = total > 0 ? ((successAll.length / total) * 100).toFixed(1) : '100.0';
  const pendingCount = allCharges.filter((c) => !['success', 'failed'].includes(c.status)).length;

  // 7-day daily totals
  const last7Days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
    const start = d.getTime();
    const end = start + 86_400_000;
    const daySucc = successAll.filter((c) => c.createdAt >= start && c.createdAt < end);
    last7Days.push({
      date: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      amount: daySucc.reduce((s, c) => s + c.amount, 0),
      count: daySucc.length,
    });
  }

  // Method breakdown (by amount)
  const byMethod = {};
  successAll.forEach((c) => {
    const m = c.method || 'unknown';
    byMethod[m] = (byMethod[m] || 0) + c.amount;
  });

  res.json({ overview: { collectedToday, paidOutToday, successRate, pendingCount, last7Days, byMethod } });
});

router.get('/admin/payouts', requireAuth, (req, res) => {
  res.json({ payouts: store.payouts.forMerchant(req.merchant.id) });
});

router.post('/admin/payouts', requireAuth, (req, res, next) => {
  try {
    const { amount, currency, recipient, method, note } = req.body || {};
    if (!amount || Number(amount) <= 0) {
      const e = new Error('amount must be a positive number in minor units.'); e.status = 400; throw e;
    }
    if (!recipient || !String(recipient).trim()) {
      const e = new Error('recipient is required.'); e.status = 400; throw e;
    }
    const payout = store.payouts.insert({
      id: genId('pyt_'),
      merchantId: req.merchant.id,
      amount: Math.round(Number(amount)),
      currency: currency || 'GHS',
      recipient: String(recipient).trim(),
      method: method || 'bank_transfer',
      note: String(note || '').trim(),
      status: 'processing',
      createdAt: Date.now(),
    });
    res.status(201).json({ payout });
  } catch (e) { next(e); }
});

router.post('/admin/payouts/:id/complete', requireAuth, (req, res, next) => {
  try {
    const payout = store.payouts.forMerchant(req.merchant.id).find((p) => p.id === req.params.id);
    if (!payout) { const e = new Error('Payout not found.'); e.status = 404; throw e; }
    if (payout.status === 'completed') { const e = new Error('Payout already completed.'); e.status = 409; throw e; }
    payout.status = 'completed';
    payout.completedAt = Date.now();
    store.persist();
    res.json({ payout });
  } catch (e) { next(e); }
});

router.get('/admin/settlements', requireAuth, (req, res) => {
  res.json({ settlements: store.settlements.forMerchant(req.merchant.id) });
});

router.post('/admin/settlements', requireAuth, (req, res, next) => {
  try {
    const charges = store.charges.forMerchant(req.merchant.id);
    const unsettled = charges.filter((c) => c.status === 'success' && !c.settled);
    if (unsettled.length === 0) {
      const e = new Error('No unsettled successful transactions to settle.'); e.status = 400; throw e;
    }
    const amount = unsettled.reduce((s, c) => s + c.amount, 0);
    unsettled.forEach((c) => { c.settled = true; });
    store.persist();

    const settlement = store.settlements.insert({
      id: genId('stl_'),
      merchantId: req.merchant.id,
      amount,
      currency: 'GHS',
      chargeCount: unsettled.length,
      status: 'completed',
      createdAt: Date.now(),
    });
    res.status(201).json({ settlement });
  } catch (e) { next(e); }
});

router.post('/admin/new-payment', requireAuth, (req, res, next) => {
  try {
    const { amount, currency, email } = req.body || {};
    const charge = payments.createCharge(req.merchant, {
      amount: Number(amount) || 0,
      currency: currency || 'GHS',
      email: String(email || '').trim(),
    });
    const checkoutUrl = `/checkout?reference=${charge.reference}`;
    res.status(201).json({ charge, checkoutUrl });
  } catch (e) { next(e); }
});

module.exports = router;
