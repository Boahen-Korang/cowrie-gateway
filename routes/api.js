'use strict';
const crypto = require('crypto');
const express = require('express');
const store = require('../lib/store');
const cfg = require('../lib/config');
const payments = require('../lib/payments');
const paystack = require('../lib/paystack');
const webhooks = require('../lib/webhooks');
const { sendOtp, sendKycApproved, sendKycRejected, sendPendingTransferAlert } = require('../lib/email');
const fx = require('../lib/fx');
const {
  merchantId, apiKey, genId, hashPassword, verifyPassword, signToken, verifyToken,
} = require('../lib/util');
const { findAdmin } = require('../lib/admins');
const cloudinary = require('../lib/cloudinary');

const router = express.Router();

/* ── rate limiters ── */
function rateLimit({ windowMs, max }) {
  const hits = new Map();
  // Prune expired entries every 5 min to prevent unbounded Map growth
  setInterval(() => {
    const now = Date.now();
    for (const [k, e] of hits) if (now > e.reset) hits.delete(k);
  }, 5 * 60_000).unref();

  return (req, res, next) => {
    const key = req.ip; const now = Date.now();
    const entry = hits.get(key) || { count: 0, reset: now + windowMs };
    if (now > entry.reset) { entry.count = 0; entry.reset = now + windowMs; }
    entry.count += 1; hits.set(key, entry);
    if (entry.count > max) {
      res.setHeader('Retry-After', Math.ceil((entry.reset - now) / 1000));
      const e = new Error('Too many requests, slow down.'); e.status = 429; return next(e);
    }
    next();
  };
}
const globalLimiter = rateLimit({ windowMs: 60_000, max: 200 }); // all routes
const authLimiter   = rateLimit({ windowMs: 60_000, max: 10  }); // login / register
const chargeLimiter = rateLimit({ windowMs: 60_000, max: 60  }); // charge creation
const payLimiter    = rateLimit({ windowMs: 60_000, max: 20  }); // payment actions

router.use(globalLimiter);

const ah = (fn) => (req, res, next) => fn(req, res, next).catch(next);

function publicMerchant(m) {
  const { passwordHash, ...rest } = m;
  return rest;
}

/* ── middleware ── */
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    const payload = token && verifyToken(token);
    const merchant = payload && await store.merchants.byId(payload.sub);
    if (!merchant) { const e = new Error('Unauthorized'); e.status = 401; return next(e); }
    req.merchant = merchant;
    req.mode = (req.headers['x-cowrie-mode'] === 'live') ? 'live' : 'test';
    next();
  } catch (e) { next(e); }
}

async function resolveMerchantByKey(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const bearer = header.startsWith('Bearer ') ? header.slice(7) : null;
    const key = req.headers['x-public-key'] || (req.body && req.body.public_key) || bearer;
    if (!key) { const e = new Error('Invalid or missing API key'); e.status = 401; return next(e); }

    const isLive = key.includes('_live_');
    let merchant;
    if (isLive) {
      merchant = await store.merchants.byLivePublicKey(key) || await store.merchants.byLiveSecretKey(key);
    } else {
      merchant = await store.merchants.byPublicKey(key) || await store.merchants.bySecretKey(key);
    }
    if (!merchant) { const e = new Error('Invalid or missing API key'); e.status = 401; return next(e); }
    req.merchant = merchant;
    req.mode = isLive ? 'live' : 'test';
    next();
  } catch (e) { next(e); }
}

async function loadCharge(req, res, next) {
  try {
    const charge = await store.charges.byReference(req.params.reference);
    if (!charge) { const e = new Error('Unknown charge reference.'); e.status = 404; return next(e); }
    req.charge = charge; next();
  } catch (e) { next(e); }
}

/* ====================== Auth (merchant) ====================== */

/* Step 1 — send OTP */
router.post('/auth/register', authLimiter, ah(async (req, res) => {
  const { businessName, email, password } = req.body || {};
  if (!businessName || !email || !password) {
    const e = new Error('businessName, email and password are required.'); e.status = 400; throw e;
  }
  if (String(password).length < 8) {
    const e = new Error('password must be at least 8 characters.'); e.status = 400; throw e;
  }
  if (await store.merchants.byEmail(email)) {
    const e = new Error('An account with this email already exists.'); e.status = 409; throw e;
  }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 15 * 60 * 1000;

  await store.verifications.set(email, otp, {
    businessName,
    email,
    passwordHash: hashPassword(password),
    publicKey:      apiKey('public',  'test'),
    secretKey:      apiKey('secret',  'test'),
    livePublicKey:  apiKey('public',  'live'),
    liveSecretKey:  apiKey('secret',  'live'),
    webhookSecret: 'whsec_' + apiKey('secret', 'test').slice(16),
  }, expiresAt);

  await sendOtp(email, otp, businessName);

  res.status(202).json({
    status: 'verify_email',
    email,
    message: 'Check your email for a 6-digit verification code.',
  });
}));

/* Step 2 — verify OTP and create account */
router.post('/auth/verify-email', authLimiter, ah(async (req, res) => {
  const { email, otp } = req.body || {};
  if (!email || !otp) {
    const e = new Error('email and otp are required.'); e.status = 400; throw e;
  }

  const pending = await store.verifications.get(email);
  if (!pending) {
    const e = new Error('No pending verification for this email. Please register again.'); e.status = 404; throw e;
  }
  if (Date.now() > pending.expires_at) {
    await store.verifications.del(email);
    const e = new Error('Verification code expired. Please register again.'); e.status = 410; throw e;
  }
  if (pending.otp !== String(otp).replace(/\D/g, '')) {
    const e = new Error('Incorrect verification code.'); e.status = 400; throw e;
  }
  if (await store.merchants.byEmail(email)) {
    await store.verifications.del(email);
    const e = new Error('An account with this email already exists.'); e.status = 409; throw e;
  }

  const pd = pending.data;
  const merchant = await store.merchants.insert({
    id: merchantId(),
    businessName: pd.businessName,
    email: pd.email,
    passwordHash: pd.passwordHash,
    publicKey:     pd.publicKey,
    secretKey:     pd.secretKey,
    livePublicKey: pd.livePublicKey,
    liveSecretKey: pd.liveSecretKey,
    webhookSecret: pd.webhookSecret,
    webhookUrl: null,
    demo: false,
    createdAt: Date.now(),
  });
  await store.verifications.del(email);

  const token = signToken({ sub: merchant.id, exp: Date.now() + cfg.TOKEN_TTL_MS });
  res.status(201).json({ token, merchant: publicMerchant(merchant) });
}));

/* Resend OTP */
router.post('/auth/resend-otp', authLimiter, ah(async (req, res) => {
  const { email } = req.body || {};
  if (!email) { const e = new Error('email is required.'); e.status = 400; throw e; }

  const pending = await store.verifications.get(email);
  if (!pending) { const e = new Error('No pending verification found. Please register again.'); e.status = 404; throw e; }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 15 * 60 * 1000;
  await store.verifications.set(email, otp, pending.data, expiresAt);
  await sendOtp(email, otp, pending.data.businessName);

  res.json({ status: 'verify_email', email, message: 'A new code has been sent to your email.' });
}));

/* Forgot password — step 1: request reset code */
router.post('/auth/forgot-password', authLimiter, ah(async (req, res) => {
  const lc = String(req.body?.email || '').trim().toLowerCase();
  if (!lc || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(lc)) {
    const e = new Error('Enter a valid email address.'); e.status = 400; throw e;
  }
  const merchant = await store.merchants.byEmail(lc);
  if (merchant) {
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const key = '__reset__' + lc;
    await store.verifications.set(key, otp, { type: 'reset', email: lc }, Date.now() + 15 * 60 * 1000);
    await sendOtp(lc, otp, merchant.businessName);
  }
  // Always respond the same way to prevent email enumeration
  res.json({ message: 'If an account exists for that email, a reset code has been sent.' });
}));

/* Forgot password — step 1b: verify OTP only (no password change yet) */
router.post('/auth/verify-reset-otp', authLimiter, ah(async (req, res) => {
  const { email, otp } = req.body || {};
  const lc = String(email || '').trim().toLowerCase();
  if (!lc || !otp) { const e = new Error('email and otp are required.'); e.status = 400; throw e; }
  const key = '__reset__' + lc;
  const pending = await store.verifications.get(key);
  if (!pending || pending.otp !== String(otp).trim() || Date.now() > Number(pending.expires_at)) {
    const e = new Error('Invalid or expired reset code.'); e.status = 400; throw e;
  }
  res.json({ ok: true });
}));

/* Forgot password — step 2: verify code + set new password */
router.post('/auth/reset-password', authLimiter, ah(async (req, res) => {
  const { email, otp, password } = req.body || {};
  const lc = String(email || '').trim().toLowerCase();
  if (!lc || !otp || !password) {
    const e = new Error('email, otp and password are required.'); e.status = 400; throw e;
  }
  if (String(password).length < 8) {
    const e = new Error('Password must be at least 8 characters.'); e.status = 400; throw e;
  }
  const key = '__reset__' + lc;
  const pending = await store.verifications.get(key);
  if (!pending || pending.otp !== String(otp).trim() || Date.now() > Number(pending.expires_at)) {
    const e = new Error('Invalid or expired reset code.'); e.status = 400; throw e;
  }
  const merchant = await store.merchants.byEmail(lc);
  if (!merchant) { const e = new Error('Account not found.'); e.status = 404; throw e; }
  merchant.passwordHash = hashPassword(password);
  await store.merchants.update(merchant);
  await store.verifications.del(key);
  res.json({ message: 'Password updated. Please sign in.' });
}));

/* Login */
router.post('/auth/login', authLimiter, ah(async (req, res) => {
  const { email, password, remember } = req.body || {};
  const merchant = email && await store.merchants.byEmail(email);
  if (!merchant || !verifyPassword(password || '', merchant.passwordHash)) {
    const e = new Error('Invalid email or password.'); e.status = 401; throw e;
  }
  const ttl = remember ? cfg.REMEMBER_TTL_MS : cfg.TOKEN_TTL_MS;
  const token = signToken({ sub: merchant.id, exp: Date.now() + ttl });
  res.json({ token, merchant: publicMerchant(merchant) });
}));

router.get('/me', requireAuth, (req, res) => {
  res.json({ merchant: publicMerchant(req.merchant) });
});

/* Public config — tells the checkout whether we're in live or test mode */
router.get('/info', (req, res) => {
  const key = paystack.secretKey('live') || paystack.secretKey('test') || '';
  res.json({ testMode: !key || key.startsWith('sk_test_') });
});

router.put('/me/webhook', requireAuth, ah(async (req, res) => {
  const { url } = req.body || {};
  if (url) {
    try { new URL(url); } catch { const e = new Error('url must be a valid absolute URL.'); e.status = 400; throw e; }
  }
  req.merchant.webhookUrl = url || null;
  await store.merchants.update(req.merchant);
  res.json({ merchant: publicMerchant(req.merchant) });
}));

router.put('/me/website', requireAuth, ah(async (req, res) => {
  const { url } = req.body || {};
  if (url) {
    try { new URL(url); } catch { const e = new Error('url must be a valid absolute URL.'); e.status = 400; throw e; }
  }
  req.merchant.websiteUrl = url || null;
  await store.merchants.update(req.merchant);
  res.json({ merchant: publicMerchant(req.merchant) });
}));

router.get('/transactions', requireAuth, ah(async (req, res) => {
  const all = await store.charges.forMerchant(req.merchant.id);
  const mode = req.mode || 'test';
  const transactions = all.filter(c => (c.mode || 'test') === mode);
  res.json({ transactions });
}));

router.delete('/transactions', requireAuth, ah(async (req, res) => {
  const { mode } = req.query;
  if (mode === 'live' || mode === 'test') {
    await store.charges.clearForMerchantByMode(req.merchant.id, mode);
  } else {
    await store.charges.clearForMerchant(req.merchant.id);
  }
  res.json({ ok: true });
}));

router.get('/events', requireAuth, ah(async (req, res) => {
  res.json({ events: await store.events.forMerchant(req.merchant.id) });
}));

/* ========================= Payment Links ========================= */

router.get('/payment-links', requireAuth, ah(async (req, res) => {
  const all = await store.charges.forMerchant(req.merchant.id);
  const mode = req.mode || 'test';
  const links = all.filter((c) => c.paymentLink && (c.mode || 'test') === mode);
  res.json({ links });
}));

router.post('/payment-links', requireAuth, chargeLimiter, ah(async (req, res) => {
  const { amount, currency, email, description, openAmount } = req.body || {};
  const isOpen = Boolean(openAmount);
  const amountMinor = isOpen ? 0 : Math.round(Number(amount) * 100);
  if (!isOpen && (!amountMinor || amountMinor < 100)) {
    const e = new Error('Enter a valid amount (minimum 1).'); e.status = 400; throw e;
  }
  const charge = await payments.createCharge(req.merchant, {
    amount: amountMinor,
    currency: String(currency || 'GHS').toUpperCase(),
    email: String(email || '').trim() || null,
    metadata: { description: String(description || '').trim() },
    openAmount: isOpen,
  });
  charge.mode = req.mode || 'test';
  charge.paymentLink = true;
  await store.charges.update(charge);
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const checkoutUrl = `${proto}://${req.get('host')}/checkout?reference=${charge.reference}`;
  res.status(201).json({ charge, checkoutUrl });
}));

router.post('/charges/:reference/set-amount', payLimiter, loadCharge, ah(async (req, res) => {
  const charge = req.charge;
  if (!charge.openAmount) { const e = new Error('This charge has a fixed amount.'); e.status = 400; throw e; }
  if (charge.status !== 'pending') { const e = new Error('Charge is no longer pending.'); e.status = 409; throw e; }
  const amount = Math.round(Number(req.body.amount) * 100);
  if (!amount || amount < 100) { const e = new Error('Enter a valid amount (minimum 1).'); e.status = 400; throw e; }
  charge.amount = amount;
  charge.openAmount = false;
  await store.charges.update(charge);
  res.json({ charge });
}));

/* ========================= Charges ========================= */

router.post('/charges', chargeLimiter, resolveMerchantByKey, ah(async (req, res) => {
  const mode = req.mode || 'test';
  const idemKey = req.headers['idempotency-key'];
  if (idemKey) {
    const existing = (await store.charges.forMerchant(req.merchant.id)).find((c) => c.idempotencyKey === idemKey && (c.mode || 'test') === mode);
    if (existing) return res.status(200).json({ charge: existing });
  }
  const charge = await payments.createCharge(req.merchant, req.body || {});
  charge.mode = mode;
  if (idemKey) charge.idempotencyKey = idemKey;
  await store.charges.update(charge);
  res.status(201).json({ charge });
}));

router.get('/charges/:reference', loadCharge, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.charge.merchantId);
  res.json({ charge: { ...req.charge, merchantName: merchant ? merchant.businessName : 'Cowrie' } });
}));

router.post('/charges/:reference/method', loadCharge, ah(async (req, res) => {
  const { method, details } = req.body || {};
  const charge = await payments.submitMethod(req.charge, method, details || {});
  res.json({ charge });
}));

router.post('/charges/:reference/authorize', loadCharge, ah(async (req, res) => {
  const charge = await payments.authorizeOtp(req.charge, (req.body || {}).otp);
  res.json({ charge });
}));

router.post('/charges/:reference/confirm', loadCharge, ah(async (req, res) => {
  const charge = await payments.confirmExternal(req.charge);
  res.json({ charge });
}));

router.get('/demo/public-key', ah(async (req, res) => {
  const all = await store.merchants.all();
  const demo = all.find((m) => m.demo);
  if (!demo) { const e = new Error('No demo merchant available.'); e.status = 404; throw e; }
  res.json({ publicKey: demo.publicKey });
}));

/* ========================= Admin ========================= */

function requireAdminAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token && verifyToken(token);
  if (!payload || payload.role !== 'admin') {
    const e = new Error('Admin access required.'); e.status = 401; return next(e);
  }
  req.adminEmail = payload.email || null;
  next();
}

router.post('/admin/auth/login', authLimiter, (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    const account = findAdmin(email, password);
    if (!account) {
      const e = new Error('Invalid admin credentials.'); e.status = 401; throw e;
    }
    const token = signToken({ sub: 'admin', email: account.email, role: 'admin', exp: Date.now() + cfg.TOKEN_TTL_MS });
    res.json({ token, admin: { email: account.email, role: 'admin' } });
  } catch (e) { next(e); }
});

router.get('/admin/auth/me', requireAdminAuth, (req, res) => {
  res.json({ admin: { email: req.adminEmail, role: 'admin' } });
});

router.get('/admin/overview', requireAdminAuth, ah(async (req, res) => {
  const allCharges = await store.charges.all();
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const todayTs = today.getTime();

  const rates = await fx.getRates();
  const toGhs = (amount, currency) => fx.toGhsMinor(amount, currency, rates);

  const successAll = allCharges.filter((c) => c.status === 'success');
  const liveSuccess = successAll.filter((c) => (c.mode || 'test') === 'live');
  const testSuccess = successAll.filter((c) => (c.mode || 'test') === 'test');
  const allPayouts = await store.payouts.all();
  const collectedToday = liveSuccess.filter((c) => c.createdAt >= todayTs).reduce((s, c) => s + toGhs(c.amount, c.currency), 0);
  const grossCollected = liveSuccess.reduce((s, c) => s + toGhs(c.amount, c.currency), 0);
  const testCollected  = testSuccess.reduce((s, c) => s + toGhs(c.amount, c.currency), 0);
  const totalPaidOut   = allPayouts.filter((p) => p.status === 'completed').reduce((s, p) => s + p.amount, 0);
  const totalCollected = Math.max(0, grossCollected - totalPaidOut);
  const paidOutToday = allPayouts.filter((p) => p.createdAt >= todayTs && p.status === 'completed').reduce((s, p) => s + p.amount, 0);
  const total = allCharges.length;
  const successRate = total > 0 ? ((successAll.length / total) * 100).toFixed(1) : '100.0';
  const pendingCount = allCharges.filter((c) => !['success', 'failed'].includes(c.status)).length;
  const allMerchants = await store.merchants.all();
  const merchantCount = allMerchants.filter((m) => !m.demo).length;

  const last7Days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
    const start = d.getTime(); const end = start + 86_400_000;
    const daySucc = successAll.filter((c) => c.createdAt >= start && c.createdAt < end);
    last7Days.push({ date: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }), amount: daySucc.reduce((s, c) => s + toGhs(c.amount, c.currency), 0), count: daySucc.length });
  }

  const byMethod = {};
  successAll.forEach((c) => { const m = c.method || 'unknown'; byMethod[m] = (byMethod[m] || 0) + toGhs(c.amount, c.currency); });

  res.json({ overview: { collectedToday, paidOutToday, totalCollected, testCollected, merchantCount, successRate, pendingCount, last7Days, byMethod } });
}));

router.get('/admin/members', requireAdminAuth, ah(async (req, res) => {
  const merchants = (await store.merchants.all()).filter((m) => !m.demo);
  const [allCharges, allPayouts] = await Promise.all([store.charges.all(), store.payouts.all()]);
  const rates = await fx.getRates();
  const toGhs = (amount, currency) => fx.toGhsMinor(amount, currency, rates);
  const members = merchants.map((m) => {
    const charges = allCharges.filter((c) => c.merchantId === m.id);
    const successful = charges.filter((c) => c.status === 'success');
    const liveOk = successful.filter((c) => (c.mode || 'test') === 'live');
    const testOk = successful.filter((c) => (c.mode || 'test') === 'test');
    const livePaidOut = allPayouts
      .filter((p) => p.merchantId === m.id && p.status === 'completed' && (p.mode || 'test') === 'live')
      .reduce((s, p) => s + p.amount, 0);
    const testPaidOut = allPayouts
      .filter((p) => p.merchantId === m.id && p.status === 'completed' && (p.mode || 'test') === 'test')
      .reduce((s, p) => s + p.amount, 0);
    return {
      id: m.id,
      businessName: m.businessName,
      email: m.email,
      websiteUrl: m.websiteUrl || null,
      createdAt: m.createdAt,
      liveCollected: Math.max(0, liveOk.reduce((s, c) => s + toGhs(c.amount, c.currency), 0) - livePaidOut),
      testCollected: Math.max(0, testOk.reduce((s, c) => s + toGhs(c.amount, c.currency), 0) - testPaidOut),
      totalTransactions: charges.length,
      liveTransactions: charges.filter((c) => (c.mode || 'test') === 'live').length,
      successfulTransactions: successful.length,
    };
  });
  res.json({ members });
}));

router.get('/admin/members/:merchantId/transactions', requireAdminAuth, ah(async (req, res) => {
  const charges = await store.charges.forMerchant(req.params.merchantId);
  charges.sort((a, b) => b.createdAt - a.createdAt);
  res.json({ transactions: charges });
}));

router.delete('/admin/transactions', requireAdminAuth, ah(async (req, res) => {
  const { mode } = req.query; // ?mode=live or ?mode=test — omit for all
  if (mode === 'live' || mode === 'test') {
    await store.charges.clearByMode(mode);
  } else {
    await store.charges.clearAll();
  }
  res.json({ ok: true });
}));

router.get('/admin/transactions', requireAdminAuth, ah(async (req, res) => {
  const all = await store.merchants.all();
  const merchantMap = {};
  all.forEach((m) => { merchantMap[m.id] = m.businessName; });
  const transactions = (await store.charges.all())
    .map((c) => ({ ...c, merchantName: merchantMap[c.merchantId] || 'Unknown' }));
  res.json({ transactions });
}));

router.get('/admin/payouts', requireAdminAuth, ah(async (req, res) => {
  const all = await store.merchants.all();
  const merchantMap = {};
  all.forEach((m) => { merchantMap[m.id] = m.businessName; });
  const payouts = (await store.payouts.all())
    .map((p) => ({ ...p, merchantName: merchantMap[p.merchantId] || 'Unknown' }));
  res.json({ payouts });
}));

router.post('/admin/payouts', requireAdminAuth, ah(async (req, res) => {
  const { amount, currency, recipient, method, note } = req.body || {};
  if (!amount || Number(amount) <= 0) { const e = new Error('amount must be a positive number in minor units.'); e.status = 400; throw e; }
  if (!recipient || !String(recipient).trim()) { const e = new Error('recipient is required.'); e.status = 400; throw e; }
  const all = await store.merchants.all();
  const merchant = all.find((m) => m.demo) || all[0];
  if (!merchant) { const e = new Error('No merchant available.'); e.status = 400; throw e; }
  const payout = await store.payouts.insert({
    id: genId('pyt_'), merchantId: merchant.id, amount: Math.round(Number(amount)),
    currency: currency || 'GHS', recipient: String(recipient).trim(),
    method: method || 'bank_transfer', note: String(note || '').trim(),
    status: 'processing', createdAt: Date.now(),
  });
  res.status(201).json({ payout });
}));

router.post('/admin/payouts/:id/complete', requireAdminAuth, ah(async (req, res) => {
  const payout = await store.payouts.byId(req.params.id);
  if (!payout) { const e = new Error('Payout not found.'); e.status = 404; throw e; }
  if (payout.status === 'completed') { const e = new Error('Payout already completed.'); e.status = 409; throw e; }
  payout.status = 'completed'; payout.completedAt = Date.now();
  await store.payouts.update(payout);
  res.json({ payout });
}));

/* ── merchant payout requests ── */
router.get('/payouts', requireAuth, ah(async (req, res) => {
  const all = await store.payouts.forMerchant(req.merchant.id);
  const mode = req.mode || 'test';
  res.json({ payouts: all.filter(p => (p.mode || 'test') === mode) });
}));

router.post('/payouts', requireAuth, ah(async (req, res) => {
  const { amount, method, bank, accountNumber, accountName, mobileProvider, mobileNumber, note } = req.body || {};
  const amt = Math.round(Number(amount));
  if (!amt || amt <= 0) { const e = new Error('Enter a valid amount.'); e.status = 400; throw e; }
  if (method === 'bank' && (!String(accountNumber || '').trim() || !String(accountName || '').trim())) {
    const e = new Error('Account number and account name are required for bank payouts.'); e.status = 400; throw e;
  }
  if (method === 'mobile_money' && !String(mobileNumber || '').trim()) {
    const e = new Error('Mobile money number is required.'); e.status = 400; throw e;
  }
  const payout = await store.payouts.insert({
    id: genId('pyt_'), merchantId: req.merchant.id,
    amount: amt, currency: 'GHS',
    mode: req.mode || 'test',
    method: method || 'bank',
    bank: String(bank || '').trim(),
    accountNumber: String(accountNumber || '').trim(),
    accountName: String(accountName || '').trim(),
    mobileProvider: String(mobileProvider || '').trim(),
    mobileNumber: String(mobileNumber || '').trim(),
    note: String(note || '').trim(),
    status: 'pending', createdAt: Date.now(),
  });
  res.status(201).json({ payout });
}));

router.get('/admin/settlements', requireAdminAuth, ah(async (req, res) => {
  res.json({ settlements: await store.settlements.all() });
}));

router.post('/admin/settlements', requireAdminAuth, ah(async (req, res) => {
  const unsettled = (await store.charges.all()).filter((c) => c.status === 'success' && !c.settled);
  if (!unsettled.length) { const e = new Error('No unsettled successful transactions to settle.'); e.status = 400; throw e; }
  const amount = unsettled.reduce((s, c) => s + c.amount, 0);
  await Promise.all(unsettled.map((c) => { c.settled = true; return store.charges.update(c); }));
  const settlement = await store.settlements.insert({
    id: genId('stl_'), merchantId: 'admin', amount, currency: 'GHS',
    chargeCount: unsettled.length, status: 'completed', createdAt: Date.now(),
  });
  res.status(201).json({ settlement });
}));

router.post('/admin/new-payment', requireAdminAuth, ah(async (req, res) => {
  const { amount, currency, email, mode, openAmount } = req.body || {};
  const isOpen = Boolean(openAmount);
  const all = await store.merchants.all();
  const merchant = all.find((m) => m.demo) || all[0];
  if (!merchant) { const e = new Error('No merchant available.'); e.status = 400; throw e; }
  const charge = await payments.createCharge(merchant, {
    amount: isOpen ? 0 : Number(amount) || 0,
    currency: currency || 'GHS',
    email: String(email || '').trim(),
    openAmount: isOpen,
  });
  charge.mode = (mode === 'live') ? 'live' : 'test';
  await store.charges.update(charge);
  res.status(201).json({ charge, checkoutUrl: `/checkout?reference=${charge.reference}` });
}));

/* ========================= Bank accounts (manual transfer) ========================= */

const NG_BANKS = [
  'Access Bank','Citibank Nigeria','Ecobank Nigeria','Fidelity Bank','First Bank of Nigeria',
  'First City Monument Bank','Globus Bank','Guaranty Trust Bank','Heritage Bank','Keystone Bank',
  'Kuda Bank','Moniepoint Microfinance Bank','OPay','Paga','Palmpay','Polaris Bank','Providus Bank',
  'Stanbic IBTC Bank','Standard Chartered Bank','Sterling Bank','Suntrust Bank','Union Bank',
  'United Bank for Africa','Unity Bank','VFD Microfinance Bank','Wema Bank','Zenith Bank',
];

router.get('/admin/bank-accounts', requireAdminAuth, ah(async (req, res) => {
  const accounts = (await store.settings.get('bank_accounts')) || [];
  res.json({ accounts, banks: NG_BANKS });
}));

router.put('/admin/bank-accounts', requireAdminAuth, ah(async (req, res) => {
  const { accounts } = req.body || {};
  if (!Array.isArray(accounts)) throw Object.assign(new Error('accounts must be an array.'), { status: 400 });
  const cleaned = accounts.slice(0, 5).map(a => ({
    id: a.id || genId('bac_'),
    bankName:      String(a.bankName      || '').trim(),
    accountNumber: String(a.accountNumber || '').trim(),
    accountName:   String(a.accountName   || '').trim(),
    currency:      String(a.currency      || 'NGN').toUpperCase(),
    active:        a.active !== false,
  })).filter(a => a.bankName && a.accountNumber && a.accountName);
  await store.settings.set('bank_accounts', cleaned);
  res.json({ accounts: cleaned });
}));

router.get('/bank-accounts', ah(async (req, res) => {
  const all = (await store.settings.get('bank_accounts')) || [];
  const { currency } = req.query;
  const accounts = all.filter(a => a.active !== false && (!currency || a.currency === currency));
  res.json({ accounts });
}));

/* Called by checkout when customer views static bank details — emails admin once per charge */
router.post('/charges/:reference/notify-transfer', loadCharge, ah(async (req, res) => {
  const charge = req.charge;
  const { payerName } = req.body || {};
  if (payerName && String(payerName).trim() && !charge.payerName) charge.payerName = String(payerName).trim();
  if (charge.transferNotified) { await store.charges.update(charge); return res.json({ ok: true }); }
  charge.transferNotified = true;
  await store.charges.update(charge);
  const adminEmail = process.env.ADMIN_EMAIL || cfg.ADMIN_EMAIL;
  if (adminEmail) {
    const merchant = await store.merchants.byId(charge.merchantId);
    sendPendingTransferAlert(adminEmail, {
      reference: charge.reference,
      amount: charge.amount,
      currency: charge.currency || 'GHS',
      merchantName: merchant ? merchant.businessName : 'Unknown',
    }).catch(err => console.warn('[transfer-alert]', err.message));
  }
  res.json({ ok: true });
}));

router.post('/admin/charges/:reference/mark-paid', requireAdminAuth, ah(async (req, res) => {
  const charge = await store.charges.byReference(req.params.reference);
  if (!charge) throw Object.assign(new Error('Charge not found.'), { status: 404 });
  if (charge.status === 'success') throw Object.assign(new Error('Charge is already marked as paid.'), { status: 409 });
  charge.status = 'success';
  charge.paidAt = Date.now();
  charge.method = charge.method || 'bank_transfer';
  charge.updatedAt = Date.now();
  await store.charges.update(charge);
  const merchant = await store.merchants.byId(charge.merchantId);
  if (merchant) webhooks.emit(merchant, 'charge.success', charge).catch(() => {});
  res.json({ charge });
}));

/* ========================= Paystack integration ========================= */

async function emitWebhookIfTerminal(charge) {
  if (charge.status !== 'success' && charge.status !== 'failed') return;
  const merchant = await store.merchants.byId(charge.merchantId);
  if (!merchant) return;
  const type = charge.status === 'success' ? 'charge.success' : 'charge.failed';
  webhooks.emit(merchant, type, charge).catch(() => {});
}

function normalizePhone(raw) {
  const d = String(raw || '').replace(/\D/g, '');
  if (d.startsWith('233') && d.length >= 12) return d;
  if (d.startsWith('0') && d.length >= 10) return '233' + d.slice(1);
  return d;
}

function resolvePaystackStatus(charge, tx) {
  if (!tx) return { next: 'pending' };
  const CHAN = { mobile_money: 'mobile_money', bank_transfer: 'bank_transfer', ussd: 'ussd' };
  switch (tx.status) {
    case 'success':
      charge.status = 'success'; charge.paidAt = Date.now();
      charge.method = CHAN[tx.channel] || 'card';
      charge.auth = {
        provider: 'paystack', channel: tx.channel,
        last4: tx.authorization && tx.authorization.last4,
        brand: tx.authorization && tx.authorization.card_type,
        expMonth: tx.authorization && tx.authorization.exp_month,
        expYear: tx.authorization && String(tx.authorization.exp_year || '').slice(-2),
        bank: tx.authorization && tx.authorization.bank,
      };
      return { next: 'success' };
    case 'failed':
      charge.status = 'failed';
      charge.failure = { message: tx.gateway_response || 'Payment failed' };
      return { next: 'failed' };
    case 'send_otp': return { next: 'otp' };
    case 'send_pin': return { next: 'pin' };
    case 'open_url': return { next: 'open_url', detail: tx.url };
    case 'pay_offline':
      if (tx.channel === 'ussd') return { next: 'ussd_code', detail: { code: tx.ussd_code, text: tx.display_text } };
      return { next: 'bank_details', detail: tx.data || {} };
    case 'pending': return { next: 'pending', detail: tx.display_text };
    default: return { next: 'pending' };
  }
}

router.post('/charges/:reference/pay', payLimiter, loadCharge, ah(async (req, res) => {
  const charge = req.charge;
  if (charge.status === 'success' || charge.status === 'failed') return res.json({ charge, next: charge.status });

  const { method, email: bodyEmail, phone, provider, number, cvv, expiry_month, expiry_year, ussd_type, payerName } = req.body || {};
  if (payerName && String(payerName).trim()) { charge.payerName = String(payerName).trim(); }
  const email = (bodyEmail && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(bodyEmail) ? bodyEmail : null)
    || charge.customerEmail || 'customer@cowrie.africa';
  const paystackRef = `cwr_${charge.reference}_${Date.now()}`;

  const body = { email, amount: charge.amount, currency: charge.currency || 'GHS', reference: paystackRef, metadata: { cowrie_reference: charge.reference } };

  if (method === 'card') {
    body.card = { number: String(number || '').replace(/\s/g, ''), cvv: String(cvv || ''), expiry_month: String(expiry_month || ''), expiry_year: String(expiry_year || '') };
    const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
    body.callback_url = `${proto}://${req.get('host')}/checkout?reference=${charge.reference}`;
  } else if (method === 'mobile_money') {
    const PROV = { MTN: 'mtn', Vodafone: 'vod', AirtelTigo: 'tgo' };
    body.mobile_money = { phone: normalizePhone(phone), provider: PROV[provider] || provider || 'mtn' };
  } else if (method === 'bank') {
    body.bank_transfer = { account_expires_at: new Date(Date.now() + 3_600_000).toISOString() };
  } else if (method === 'ussd') {
    body.ussd = { type: String(ussd_type || '737') };
  }

  const data = await paystack.charge(body, charge.mode || 'test');
  console.log('[Paystack /charge]', JSON.stringify({ method, mode: charge.mode, status: data.status, message: data.message, data_status: data.data && data.data.status, gateway_response: data.data && data.data.gateway_response }));
  /* Paystack returns status:false both for API errors (no data.data) and for
     legitimate charge failures (data.data.status === 'failed', message === 'Charge attempted').
     Only throw on true API errors — let resolvePaystackStatus handle charge failures. */
  if (!data.status && (!data.data || !data.data.status)) {
    throw Object.assign(new Error(data.message || 'Charge failed'), { status: 400 });
  }

  charge.paystackRef = paystackRef;
  const result = resolvePaystackStatus(charge, data.data);
  if (method === 'card') {
    if (!charge.auth) charge.auth = {};
    if (!charge.auth.last4 && number) charge.auth.last4 = String(number).replace(/\s/g, '').slice(-4);
    if (!charge.auth.expMonth && expiry_month) charge.auth.expMonth = String(expiry_month).padStart(2, '0');
    if (!charge.auth.expYear && expiry_year) charge.auth.expYear = String(expiry_year).slice(-2);
  }
  await store.charges.update(charge);
  await emitWebhookIfTerminal(charge);
  res.json({ charge, next: result.next, detail: result.detail });
}));

router.post('/charges/:reference/submit-otp', payLimiter, loadCharge, ah(async (req, res) => {
  const { otp } = req.body || {};
  if (!req.charge.paystackRef) throw Object.assign(new Error('No pending transaction.'), { status: 400 });
  const data = await paystack.submitOtp(req.charge.paystackRef, String(otp || ''), req.charge.mode || 'test');
  if (!data.status) throw new Error(data.message || 'OTP failed');
  const result = resolvePaystackStatus(req.charge, data.data);
  await store.charges.update(req.charge);
  await emitWebhookIfTerminal(req.charge);
  res.json({ charge: req.charge, next: result.next, detail: result.detail });
}));

router.post('/charges/:reference/submit-pin', payLimiter, loadCharge, ah(async (req, res) => {
  const { pin } = req.body || {};
  if (!req.charge.paystackRef) throw Object.assign(new Error('No pending transaction.'), { status: 400 });
  const data = await paystack.submitPin(req.charge.paystackRef, String(pin || ''), req.charge.mode || 'test');
  if (!data.status) throw new Error(data.message || 'PIN failed');
  const result = resolvePaystackStatus(req.charge, data.data);
  await store.charges.update(req.charge);
  await emitWebhookIfTerminal(req.charge);
  res.json({ charge: req.charge, next: result.next, detail: result.detail });
}));

router.get('/charges/:reference/poll', payLimiter, loadCharge, ah(async (req, res) => {
  const charge = req.charge;
  if (charge.status === 'success' || charge.status === 'failed') return res.json({ charge, next: charge.status });
  if (!charge.paystackRef) return res.json({ charge, next: 'pending' });
  const data = await paystack.getCharge(charge.paystackRef, charge.mode || 'test');
  if (!data.status || !data.data) return res.json({ charge, next: 'pending' });
  const result = resolvePaystackStatus(charge, data.data);
  await store.charges.update(charge);
  await emitWebhookIfTerminal(charge);
  res.json({ charge, next: result.next, detail: result.detail });
}));

router.post('/charges/:reference/paystack-init', payLimiter, loadCharge, ah(async (req, res) => {
  const chargeMode = req.charge.mode || 'test';
  const paystackSk = paystack.secretKey(chargeMode);
  if (!paystackSk) {
    const e = new Error(`Paystack ${chargeMode} key not configured.`); e.status = 503; throw e;
  }
  const charge = req.charge;
  if (charge.status === 'success' || charge.status === 'failed') return res.json({ charge, alreadyComplete: true });
  const email = (req.body.email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(req.body.email) ? req.body.email : null)
    || charge.customerEmail || 'customer@cowrie.africa';
  const channels = Array.isArray(req.body && req.body.channels) ? req.body.channels : undefined;
  const paystackRef = `cwr_${charge.reference}_${Date.now()}`;
  const data = await paystack.initialize({ email, amount: charge.amount, currency: charge.currency || 'GHS', reference: paystackRef, channels, metadata: { cowrie_reference: charge.reference, merchantId: charge.merchantId } }, chargeMode);
  charge.paystackRef = paystackRef;
  await store.charges.update(charge);
  res.json({ accessCode: data.access_code, publicKey: paystack.publicKey(chargeMode), paystackRef });
}));

router.get('/charges/:reference/verify', payLimiter, loadCharge, ah(async (req, res) => {
  const charge = req.charge;
  if (charge.status === 'success' || charge.status === 'failed') return res.json({ charge });
  if (!charge.paystackRef) return res.json({ charge });
  const data = await paystack.verify(charge.paystackRef, charge.mode || 'test');
  if (!data.status) throw new Error(data.message || 'Paystack verification failed');
  const tx = data.data;
  const CHANNEL_MAP = { mobile_money: 'mobile_money', bank_transfer: 'bank_transfer', ussd: 'ussd' };
  if (tx.status === 'success') {
    charge.status = 'success'; charge.paidAt = Date.now();
    charge.method = CHANNEL_MAP[tx.channel] || 'card';
    charge.auth = {
      provider: 'paystack', channel: tx.channel,
      last4: tx.authorization && tx.authorization.last4,
      brand: tx.authorization && tx.authorization.card_type,
      expMonth: tx.authorization && tx.authorization.exp_month,
      expYear: tx.authorization && String(tx.authorization.exp_year || '').slice(-2),
      bank: tx.authorization && tx.authorization.bank,
      phone: tx.customer && tx.customer.phone,
    };
    await store.charges.update(charge);
    await emitWebhookIfTerminal(charge);
  } else if (tx.status === 'failed') {
    charge.status = 'failed';
    charge.failure = { message: tx.gateway_response || 'Payment failed' };
    await store.charges.update(charge);
    await emitWebhookIfTerminal(charge);
  }
  res.json({ charge });
}));

router.post('/webhooks/paystack', (req, res, next) => {
  (async () => {
    const sig = req.headers['x-paystack-signature'];
    const raw = req.rawBody;
    if (!sig || !raw) return res.status(400).json({ error: 'missing_signature' });
    const testKey = cfg.PAYSTACK_SK_TEST || cfg.PAYSTACK_SECRET_KEY;
    const liveKey = cfg.PAYSTACK_SK_LIVE || cfg.PAYSTACK_SECRET_KEY;
    const expectedTest = testKey ? crypto.createHmac('sha512', testKey).update(raw).digest('hex') : null;
    const expectedLive = liveKey ? crypto.createHmac('sha512', liveKey).update(raw).digest('hex') : null;
    if (sig !== expectedTest && sig !== expectedLive) return res.status(400).json({ error: 'invalid_signature' });
    const event = JSON.parse(raw.toString());
    if (event.event === 'charge.success') {
      const cowrieRef = event.data && event.data.metadata && event.data.metadata.cowrie_reference;
      if (cowrieRef) {
        const charge = await store.charges.byReference(cowrieRef);
        if (charge && charge.status !== 'success') {
          const CHANNEL_MAP = { mobile_money: 'mobile_money', bank_transfer: 'bank_transfer', ussd: 'ussd' };
          charge.status = 'success'; charge.paidAt = Date.now();
          charge.method = CHANNEL_MAP[event.data.channel] || 'card';
          charge.auth = {
            provider: 'paystack', channel: event.data.channel,
            last4: event.data.authorization && event.data.authorization.last4,
            brand: event.data.authorization && event.data.authorization.card_type,
            expMonth: event.data.authorization && event.data.authorization.exp_month,
            expYear: event.data.authorization && String(event.data.authorization.exp_year || '').slice(-2),
            bank: event.data.authorization && event.data.authorization.bank,
          };
          await store.charges.update(charge);
          await emitWebhookIfTerminal(charge);
        }
      }
    }
    res.json({ received: true });
  })().catch(next);
});

/* ========================= KYC ========================= */

router.post('/kyc', requireAuth, ah(async (req, res) => {
  const merchant = req.merchant;
  if (merchant.kycStatus === 'approved') {
    const e = new Error('Your account is already verified.'); e.status = 409; throw e;
  }
  const { fullName, phone, idType, idNumber, businessType, businessRegNumber, address, idFront, idBack, certificate } = req.body || {};
  if (!fullName || !phone || !idType || !idNumber || !address) {
    const e = new Error('fullName, phone, idType, idNumber and address are required.'); e.status = 400; throw e;
  }
  if (!idFront || !idBack) {
    const e = new Error('Front and back photos of your ID are required.'); e.status = 400; throw e;
  }
  if (!certificate) {
    const e = new Error('Business certificate or registration document is required.'); e.status = 400; throw e;
  }
  const MAX = 7 * 1024 * 1024; // base64 of a 5 MB file is ~6.7 MB; allow headroom
  for (const [label, val] of [['idFront', idFront], ['idBack', idBack], ['certificate', certificate]]) {
    if (typeof val !== 'string' || !val.startsWith('data:')) {
      const e = new Error(`${label} must be a valid data URL.`); e.status = 400; throw e;
    }
    if (val.length > MAX) {
      const e = new Error(`${label} exceeds the 5 MB limit.`); e.status = 400; throw e;
    }
  }
  /* Upload images to Cloudinary if configured; fall back to storing base64 */
  async function maybeUpload(dataUrl) {
    try {
      const url = await cloudinary.upload(dataUrl);
      return url || dataUrl;
    } catch (err) {
      console.warn('[KYC] Cloudinary upload failed, storing base64:', err.message);
      return dataUrl;
    }
  }
  const [storedFront, storedBack, storedCert] = await Promise.all([
    maybeUpload(idFront),
    maybeUpload(idBack),
    maybeUpload(certificate),
  ]);

  merchant.kycStatus = 'pending';
  merchant.kycData = {
    fullName: String(fullName).trim(),
    phone: String(phone).trim(),
    idType: String(idType).trim(),
    idNumber: String(idNumber).trim(),
    businessType: String(businessType || 'individual').trim(),
    businessRegNumber: String(businessRegNumber || '').trim(),
    address: String(address).trim(),
    idFront: storedFront,
    idBack: storedBack,
    certificate: storedCert,
  };
  merchant.kycSubmittedAt = Date.now();
  merchant.kycRejectionReason = null;
  await store.merchants.update(merchant);
  res.json({ merchant: publicMerchant(merchant) });
}));

router.get('/kyc', requireAuth, (req, res) => {
  const { kycStatus, kycData, kycSubmittedAt, kycReviewedAt, kycRejectionReason } = req.merchant;
  res.json({ kycStatus: kycStatus || 'none', kycData: kycData || null, kycSubmittedAt, kycReviewedAt, kycRejectionReason });
});

router.get('/admin/kyc', requireAdminAuth, ah(async (req, res) => {
  const all = await store.merchants.all();
  const merchants = all.filter(m => !m.demo).map(m => ({
    id: m.id, businessName: m.businessName, email: m.email,
    kycStatus: m.kycStatus || 'none', kycData: m.kycData || null,
    kycSubmittedAt: m.kycSubmittedAt, kycReviewedAt: m.kycReviewedAt,
    kycRejectionReason: m.kycRejectionReason,
  }));
  res.json({ merchants });
}));

router.post('/admin/kyc/:merchantId/approve', requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }
  merchant.kycStatus = 'approved';
  merchant.kycReviewedAt = Date.now();
  merchant.kycRejectionReason = null;
  await store.merchants.update(merchant);
  sendKycApproved(merchant.email, merchant.businessName).catch(() => {});
  res.json({ merchant: publicMerchant(merchant) });
}));

router.post('/admin/kyc/:merchantId/reject', requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }
  const reason = String((req.body || {}).reason || '').trim() || 'Your submission did not meet our requirements.';
  merchant.kycStatus = 'rejected';
  merchant.kycReviewedAt = Date.now();
  merchant.kycRejectionReason = reason;
  await store.merchants.update(merchant);
  sendKycRejected(merchant.email, merchant.businessName, reason).catch(() => {});
  res.json({ merchant: publicMerchant(merchant) });
}));

/* ==================== Gateway Settings (Admin) ==================== */

const SUPPORTED_GATEWAYS = [
  /* ── Fully integrated ─────────────────────────────────────────────── */
  { id: 'paystack',      name: 'Paystack',       status: 'integrated',   website: 'https://paystack.com',           fields: { testPublicKey: 'Test public key (pk_test_…)',        testSecretKey: 'Test secret key (sk_test_…)',         livePublicKey: 'Live public key (pk_live_…)',        liveSecretKey: 'Live secret key (sk_live_…)' } },

  /* ── Global ────────────────────────────────────────────────────────── */
  { id: 'stripe',        name: 'Stripe',          status: 'configurable', website: 'https://stripe.com',             fields: { testPublicKey: 'Test publishable key (pk_test_…)',  testSecretKey: 'Test secret key (sk_test_…)',         livePublicKey: 'Live publishable key (pk_live_…)',   liveSecretKey: 'Live secret key (sk_live_…)' } },
  { id: 'paypal',        name: 'PayPal',          status: 'configurable', website: 'https://developer.paypal.com',   fields: { testPublicKey: 'Sandbox client ID',                 testSecretKey: 'Sandbox client secret',               livePublicKey: 'Live client ID',                     liveSecretKey: 'Live client secret' } },
  { id: 'braintree',     name: 'Braintree',       status: 'configurable', website: 'https://braintreepayments.com',  fields: { testPublicKey: 'Sandbox merchant ID',               testSecretKey: 'Sandbox private key',                 livePublicKey: 'Production merchant ID',              liveSecretKey: 'Production private key' } },
  { id: 'adyen',         name: 'Adyen',           status: 'configurable', website: 'https://adyen.com',              fields: { testPublicKey: 'Test API key',                      testSecretKey: 'Test HMAC key',                       livePublicKey: 'Live API key',                        liveSecretKey: 'Live HMAC key' } },
  { id: 'checkoutcom',   name: 'Checkout.com',    status: 'configurable', website: 'https://checkout.com',           fields: { testPublicKey: 'Test public key (pk_test_…)',       testSecretKey: 'Test secret key (sk_test_…)',         livePublicKey: 'Live public key (pk_…)',              liveSecretKey: 'Live secret key (sk_…)' } },
  { id: 'worldpay',      name: 'Worldpay',        status: 'configurable', website: 'https://worldpay.com',           fields: { testPublicKey: 'Test client key',                   testSecretKey: 'Test service key',                    livePublicKey: 'Live client key',                     liveSecretKey: 'Live service key' } },
  { id: 'authorizenet',  name: 'Authorize.Net',   status: 'configurable', website: 'https://authorize.net',          fields: { testPublicKey: 'Test API login ID',                 testSecretKey: 'Test transaction key',                livePublicKey: 'Live API login ID',                   liveSecretKey: 'Live transaction key' } },
  { id: 'square',        name: 'Square',          status: 'configurable', website: 'https://squareup.com',           fields: { testPublicKey: 'Sandbox application ID',            testSecretKey: 'Sandbox access token',                livePublicKey: 'Production application ID',           liveSecretKey: 'Production access token' } },
  { id: 'twocheckout',   name: '2Checkout',       status: 'configurable', website: 'https://2checkout.com',          fields: { testPublicKey: 'Test merchant code',                testSecretKey: 'Test secret key',                     livePublicKey: 'Live merchant code',                  liveSecretKey: 'Live secret key' } },
  { id: 'klarna',        name: 'Klarna',          status: 'configurable', website: 'https://klarna.com',             fields: { testPublicKey: 'Playground username (UID)',         testSecretKey: 'Playground password',                 livePublicKey: 'Production username (UID)',            liveSecretKey: 'Production password' } },
  { id: 'mollie',        name: 'Mollie',          status: 'configurable', website: 'https://mollie.com',             fields: { testPublicKey: 'Test API key (test_…)',             testSecretKey: 'Test API key (same field)',            livePublicKey: 'Live API key (live_…)',               liveSecretKey: 'Live API key (same field)' } },
  { id: 'nuvei',         name: 'Nuvei',           status: 'configurable', website: 'https://nuvei.com',              fields: { testPublicKey: 'Test merchant ID',                  testSecretKey: 'Test merchant site secret key',       livePublicKey: 'Live merchant ID',                    liveSecretKey: 'Live merchant site secret key' } },
  { id: 'paysafe',       name: 'Paysafe',         status: 'configurable', website: 'https://paysafe.com',            fields: { testPublicKey: 'Test API key',                      testSecretKey: 'Test single-use token API key',       livePublicKey: 'Live API key',                        liveSecretKey: 'Live single-use token API key' } },
  { id: 'aeropay',       name: 'Aeropay',         status: 'configurable', website: 'https://aeropay.com',            fields: { testPublicKey: 'Test client ID',                    testSecretKey: 'Test client secret',                  livePublicKey: 'Live client ID',                      liveSecretKey: 'Live client secret' } },
  { id: 'amazonpay',     name: 'Amazon Pay',      status: 'configurable', website: 'https://pay.amazon.com',         fields: { testPublicKey: 'Sandbox merchant ID',               testSecretKey: 'Sandbox MWS auth token',              livePublicKey: 'Production merchant ID',              liveSecretKey: 'Production MWS auth token' } },

  /* ── Africa ────────────────────────────────────────────────────────── */
  { id: 'flutterwave',   name: 'Flutterwave',     status: 'configurable', website: 'https://flutterwave.com',        fields: { testPublicKey: 'Test public key (FLWPUBK_TEST-…)', testSecretKey: 'Test secret key (FLWSECK_TEST-…)',   livePublicKey: 'Live public key (FLWPUBK-…)',        liveSecretKey: 'Live secret key (FLWSECK-…)' } },
  { id: 'monnify',       name: 'Monnify',         status: 'configurable', website: 'https://monnify.com',            fields: { testPublicKey: 'Test API key',                      testSecretKey: 'Test secret key',                     livePublicKey: 'Live API key',                        liveSecretKey: 'Live secret key' } },
  { id: 'interswitch',   name: 'Interswitch',     status: 'configurable', website: 'https://developer.interswitch.com', fields: { testPublicKey: 'Test client ID',               testSecretKey: 'Test client secret',                  livePublicKey: 'Live client ID',                      liveSecretKey: 'Live client secret' } },
  { id: 'peachpayments', name: 'Peach Payments',  status: 'configurable', website: 'https://peachpayments.com',      fields: { testPublicKey: 'Test entity ID',                    testSecretKey: 'Test API key',                        livePublicKey: 'Live entity ID',                      liveSecretKey: 'Live API key' } },
  { id: 'payfast',       name: 'PayFast',         status: 'configurable', website: 'https://payfast.io',             fields: { testPublicKey: 'Test merchant ID',                  testSecretKey: 'Test merchant key',                   livePublicKey: 'Live merchant ID',                    liveSecretKey: 'Live merchant key' } },
  { id: 'ozow',          name: 'Ozow',            status: 'configurable', website: 'https://ozow.com',               fields: { testPublicKey: 'Test site code',                    testSecretKey: 'Test private key',                    livePublicKey: 'Live site code',                      liveSecretKey: 'Live private key' } },
  { id: 'dpopay',        name: 'DPO Pay',         status: 'configurable', website: 'https://dpopay.com',             fields: { testPublicKey: 'Test company token',                testSecretKey: 'Test service type code',              livePublicKey: 'Live company token',                  liveSecretKey: 'Live service type code' } },
  { id: 'pesapal',       name: 'Pesapal',         status: 'configurable', website: 'https://pesapal.com',            fields: { testPublicKey: 'Sandbox consumer key',              testSecretKey: 'Sandbox consumer secret',             livePublicKey: 'Live consumer key',                   liveSecretKey: 'Live consumer secret' } },
  { id: 'cellulant',     name: 'Cellulant / Tingg', status: 'configurable', website: 'https://cellulant.io',        fields: { testPublicKey: 'Test access key',                   testSecretKey: 'Test secret key',                     livePublicKey: 'Live access key',                     liveSecretKey: 'Live secret key' } },
  { id: 'fawry',         name: 'Fawry',           status: 'configurable', website: 'https://developer.fawrystaging.com', fields: { testPublicKey: 'Test merchant code',           testSecretKey: 'Test security key',                   livePublicKey: 'Live merchant code',                  liveSecretKey: 'Live security key' } },
  { id: 'vodapay',       name: 'VodaPay',         status: 'configurable', website: 'https://vodapay.vodacom.co.za',  fields: { testPublicKey: 'Staging app ID',                    testSecretKey: 'Staging app secret',                  livePublicKey: 'Production app ID',                   liveSecretKey: 'Production app secret' } },
  { id: 'ipay',          name: 'iPay Africa',     status: 'configurable', website: 'https://ipayafrica.com',         fields: { testPublicKey: 'Test vendor ID',                    testSecretKey: 'Test hash key',                       livePublicKey: 'Live vendor ID',                       liveSecretKey: 'Live hash key' } },

  /* ── Middle East ────────────────────────────────────────────────────── */
  { id: 'tap',           name: 'Tap Payments',    status: 'configurable', website: 'https://tap.company',            fields: { testPublicKey: 'Test public key (pk_test_…)',       testSecretKey: 'Test secret key (sk_test_…)',         livePublicKey: 'Live public key (pk_live_…)',        liveSecretKey: 'Live secret key (sk_live_…)' } },
  { id: 'paytabs',       name: 'PayTabs',         status: 'configurable', website: 'https://paytabs.com',            fields: { testPublicKey: 'Test profile ID',                   testSecretKey: 'Test server key',                     livePublicKey: 'Live profile ID',                     liveSecretKey: 'Live server key' } },

  /* ── Asia / India ───────────────────────────────────────────────────── */
  { id: 'razorpay',      name: 'Razorpay',        status: 'configurable', website: 'https://razorpay.com',           fields: { testPublicKey: 'Test key ID (rzp_test_…)',          testSecretKey: 'Test key secret',                     livePublicKey: 'Live key ID (rzp_live_…)',            liveSecretKey: 'Live key secret' } },
  { id: 'payu',          name: 'PayU',            status: 'configurable', website: 'https://payu.com',               fields: { testPublicKey: 'Test merchant key',                 testSecretKey: 'Test merchant salt',                  livePublicKey: 'Live merchant key',                   liveSecretKey: 'Live merchant salt' } },
  { id: 'ccavenue',      name: 'CCAvenue',        status: 'configurable', website: 'https://ccavenue.com',           fields: { testPublicKey: 'Test merchant ID',                  testSecretKey: 'Test working key',                    livePublicKey: 'Live merchant ID',                    liveSecretKey: 'Live working key' } },
  { id: 'cashfree',      name: 'Cashfree',        status: 'configurable', website: 'https://cashfree.com',           fields: { testPublicKey: 'Test app ID',                       testSecretKey: 'Test secret key',                     livePublicKey: 'Live app ID',                         liveSecretKey: 'Live secret key' } },
  { id: 'paymongo',      name: 'PayMongo',        status: 'configurable', website: 'https://paymongo.com',           fields: { testPublicKey: 'Test public key (pk_test_…)',       testSecretKey: 'Test secret key (sk_test_…)',         livePublicKey: 'Live public key (pk_live_…)',        liveSecretKey: 'Live secret key (sk_live_…)' } },
  /* ── Additional Africa ─────────────────────────────────────────────── */
  { id: 'moolre',        name: 'Moolre',          status: 'configurable', website: 'https://moolre.com',             fields: { testPublicKey: 'Test public key',                    testSecretKey: 'Test secret key',                     livePublicKey: 'Live public key',                    liveSecretKey: 'Live secret key' } },
  { id: 'fincra',        name: 'Fincra',          status: 'configurable', website: 'https://fincra.com',             fields: { testPublicKey: 'Test public key',                    testSecretKey: 'Test secret key',                     livePublicKey: 'Live public key',                    liveSecretKey: 'Live secret key' } },
  { id: 'bani',          name: 'Bani',            status: 'configurable', website: 'https://getbani.com',            fields: { testPublicKey: 'Test public key',                    testSecretKey: 'Test secret key',                     livePublicKey: 'Live public key',                    liveSecretKey: 'Live secret key' } },
  { id: 'korapay',       name: 'Korapay',         status: 'configurable', website: 'https://korapay.com',            fields: { testPublicKey: 'Test public key (pk_test_…)',        testSecretKey: 'Test secret key (sk_test_…)',          livePublicKey: 'Live public key (pk_live_…)',         liveSecretKey: 'Live secret key (sk_live_…)' } },
];

function maskSecret(val) {
  if (!val || val.length < 8) return val || '';
  return val.slice(0, 8) + '•'.repeat(Math.min(val.length - 8, 24));
}

router.get('/admin/gateways', requireAdminAuth, ah(async (req, res) => {
  const gs = (await store.settings.get('gateways')) || { activeGateway: null, installed: [], gateways: {} };
  const installed = (gs.installed || []).map(id => {
    const meta = SUPPORTED_GATEWAYS.find(g => g.id === id);
    if (!meta) return null;
    const keys = (gs.gateways && gs.gateways[id]) || {};
    return {
      ...meta,
      active: gs.activeGateway === id,
      keys: {
        testPublicKey: keys.testPublicKey || '',
        testSecretKey: maskSecret(keys.testSecretKey),
        livePublicKey: keys.livePublicKey || '',
        liveSecretKey: maskSecret(keys.liveSecretKey),
      },
    };
  }).filter(Boolean);
  res.json({
    activeGateway: gs.activeGateway || null,
    installed,
    supported: SUPPORTED_GATEWAYS.map(g => ({ id: g.id, name: g.name, fields: g.fields })),
  });
}));

router.put('/admin/gateways/:id', requireAdminAuth, ah(async (req, res) => {
  const { id } = req.params;
  if (!SUPPORTED_GATEWAYS.find(g => g.id === id)) {
    const e = new Error('Unknown gateway.'); e.status = 400; throw e;
  }
  const { testPublicKey = '', testSecretKey = '', livePublicKey = '', liveSecretKey = '' } = req.body || {};
  const gs = (await store.settings.get('gateways')) || { activeGateway: null, installed: [], gateways: {} };
  const existing = (gs.gateways && gs.gateways[id]) || {};

  gs.gateways = gs.gateways || {};
  gs.installed = gs.installed || [];
  if (!gs.installed.includes(id)) gs.installed.push(id);

  gs.gateways[id] = {
    testPublicKey: testPublicKey || existing.testPublicKey || '',
    testSecretKey: testSecretKey && !testSecretKey.includes('•') ? testSecretKey : (existing.testSecretKey || ''),
    livePublicKey: livePublicKey || existing.livePublicKey || '',
    liveSecretKey: liveSecretKey && !liveSecretKey.includes('•') ? liveSecretKey : (existing.liveSecretKey || ''),
  };
  await store.settings.set('gateways', gs);
  if (id === 'paystack') paystack.configureKeys(gs.gateways.paystack);
  res.json({ ok: true });
}));

router.put('/admin/gateways/:id/toggle', requireAdminAuth, ah(async (req, res) => {
  const { id } = req.params;
  if (!SUPPORTED_GATEWAYS.find(g => g.id === id)) {
    const e = new Error('Unknown gateway.'); e.status = 400; throw e;
  }
  const gs = (await store.settings.get('gateways')) || { activeGateway: null, installed: [], gateways: {} };
  gs.activeGateway = gs.activeGateway === id ? null : id;
  await store.settings.set('gateways', gs);
  if (gs.activeGateway === 'paystack') paystack.configureKeys((gs.gateways || {}).paystack || null);
  else if (id === 'paystack') paystack.configureKeys(null);
  res.json({ ok: true, activeGateway: gs.activeGateway });
}));

router.delete('/admin/gateways/:id', requireAdminAuth, ah(async (req, res) => {
  const { id } = req.params;
  const gs = (await store.settings.get('gateways')) || { activeGateway: null, installed: [], gateways: {} };
  gs.installed = (gs.installed || []).filter(x => x !== id);
  if (gs.activeGateway === id) gs.activeGateway = null;
  if (gs.gateways) delete gs.gateways[id];
  await store.settings.set('gateways', gs);
  if (id === 'paystack') paystack.configureKeys(null);
  res.json({ ok: true });
}));

module.exports = router;
