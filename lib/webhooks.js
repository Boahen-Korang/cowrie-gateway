'use strict';
const store = require('./store');
const { hmacSign } = require('./util');

async function emit(merchant, type, charge) {
  const event = {
    id: 'evt_' + require('crypto').randomBytes(6).toString('hex'),
    merchantId: merchant.id,
    type,
    chargeReference: charge.reference,
    createdAt: Date.now(),
    status: 'skipped',
    responseCode: null,
  };

  if (!merchant.webhookUrl) {
    await store.events.insert(event);
    return event;
  }

  if (!merchant.webhookSecret) {
    event.status = 'failed';
    event.error = 'Webhook secret not configured for this merchant.';
    await store.events.insert(event);
    return event;
  }

  const body = JSON.stringify({ id: event.id, type, createdAt: event.createdAt, data: charge });
  const signature = hmacSign(body, merchant.webhookSecret);

  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(merchant.webhookUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cowrie-signature': signature },
      body,
      signal: controller.signal,
    });
    clearTimeout(tid);
    event.status = res.ok ? 'delivered' : 'failed';
    event.responseCode = res.status;
  } catch (err) {
    clearTimeout(tid);
    event.status = err.name === 'AbortError' ? 'timeout' : 'failed';
    event.error = err.name === 'AbortError' ? 'Webhook timed out after 10 s' : err.message;
  }

  await store.events.insert(event);
  return event;
}

module.exports = { emit };
