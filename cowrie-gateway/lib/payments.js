'use strict';
/*
 * Core gateway logic — the server-side state machine for a charge.
 *
 * Lifecycle:
 *   pending ──method──▶ requires_otp | requires_approval | awaiting_transfer | awaiting_ussd
 *                                   │            │                  │                │
 *                                authorize     confirm           confirm          confirm
 *                                   └────────────┴──────────────────┴────────────────┴──▶ success
 *                                                                                          (fires webhook)
 *
 * The "bank / network / operator" side is simulated (we can't really call Visa
 * or MTN here) — but the GATEWAY behaviour is real: validation, state, signing,
 * persistence and webhooks all work exactly as a production gateway would.
 */
const store = require('./store');
const webhooks = require('./webhooks');
const { reference, luhnValid, cardBrand } = require('./util');

const TEST_OTP = '123456'; // any 6 digits work in test mode; this one always works

function createCharge(merchant, { amount, currency = 'GHS', email, metadata = {} }) {
  amount = Math.round(Number(amount));
  if (!Number.isFinite(amount) || amount < 100) {
    const e = new Error('amount must be an integer in minor units (>= 100)'); e.status = 400; throw e;
  }
  const charge = {
    reference: reference(),
    merchantId: merchant.id,
    amount,                       // minor units, e.g. 25000 = GHS 250.00
    currency,
    customerEmail: email || null,
    status: 'pending',
    method: null,
    auth: null,                   // transient method details (never the full PAN)
    nextAction: null,
    metadata,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    paidAt: null,
  };
  return store.charges.insert(charge);
}

/* Customer selected a method and submitted its details. */
function submitMethod(charge, method, details = {}) {
  assertActive(charge);
  charge.method = method;

  if (method === 'card') {
    const number = String(details.number || '').replace(/\D/g, '');
    if (!luhnValid(number)) return fail(charge, 'invalid_card', 'Card number failed validation.');
    const mm = +String(details.expiry || '').slice(0, 2);
    if (!(mm >= 1 && mm <= 12)) return fail(charge, 'invalid_expiry', 'Card expiry is invalid.');
    charge.auth = { brand: cardBrand(number), last4: number.slice(-4) };
    charge.status = 'requires_otp';
    charge.nextAction = { type: 'otp', message: 'Enter the 6-digit 3-D Secure code sent to your phone.' };
  } else if (method === 'mobile_money') {
    const phone = String(details.phone || '').replace(/\D/g, '');
    if (phone.length < 10) return fail(charge, 'invalid_phone', 'Mobile money number is invalid.');
    charge.auth = { provider: details.provider || 'MTN', phone: phone.slice(-10) };
    charge.status = 'requires_approval';
    charge.nextAction = { type: 'approve', message: `Approve the prompt on your ${charge.auth.provider} line.` };
  } else if (method === 'bank_transfer') {
    charge.auth = {
      bank: 'Sankofa Bank (via Cowrie)',
      account: '901' + rand(7),
      reference: charge.reference.slice(-8).toUpperCase(),
    };
    charge.status = 'awaiting_transfer';
    charge.nextAction = { type: 'bank_transfer', account: charge.auth };
  } else if (method === 'ussd') {
    charge.auth = { code: '*920*' + rand(3) + '*' + Math.round(charge.amount / 100) + '#' };
    charge.status = 'awaiting_ussd';
    charge.nextAction = { type: 'ussd', code: charge.auth.code };
  } else {
    const e = new Error('unsupported method'); e.status = 400; throw e;
  }
  return store.charges.update(charge);
}

/* Card 3-D Secure step. */
async function authorizeOtp(charge, otp) {
  if (charge.status !== 'requires_otp') { const e = new Error('charge is not awaiting OTP'); e.status = 409; throw e; }
  otp = String(otp || '').replace(/\D/g, '');
  if (otp.length !== 6) { const e = new Error('OTP must be 6 digits'); e.status = 400; throw e; }
  // test mode: accept any 6-digit OTP (TEST_OTP documented as the canonical one)
  return succeed(charge);
}

/* Operator / bank confirmation for momo, bank transfer, ussd. */
async function confirmExternal(charge) {
  if (!['requires_approval', 'awaiting_transfer', 'awaiting_ussd'].includes(charge.status)) {
    const e = new Error('charge is not awaiting external confirmation'); e.status = 409; throw e;
  }
  return succeed(charge);
}

async function succeed(charge) {
  charge.status = 'success';
  charge.paidAt = Date.now();
  charge.nextAction = null;
  store.charges.update(charge);
  const merchant = store.merchants.byId(charge.merchantId);
  await webhooks.emit(merchant, 'charge.success', charge);
  return charge;
}
function fail(charge, code, message) {
  charge.status = 'failed';
  charge.failure = { code, message };
  charge.nextAction = null;
  store.charges.update(charge);
  const merchant = store.merchants.byId(charge.merchantId);
  webhooks.emit(merchant, 'charge.failed', charge).catch(() => {});
  return charge;
}

function assertActive(charge) {
  if (['success', 'failed'].includes(charge.status)) {
    const e = new Error(`charge already ${charge.status}`); e.status = 409; throw e;
  }
}
const rand = (n) => Array.from({ length: n }, () => Math.floor(Math.random() * 10)).join('');

module.exports = { createCharge, submitMethod, authorizeOtp, confirmExternal, TEST_OTP };
