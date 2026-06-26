'use strict';
const store = require('./store');
const { hmacSign } = require('./util');

/* Deliver a signed webhook for a charge event and log the attempt (or the skip, if the merchant has no webhook configured). */
async function emit(merchant, type, charge) {
  const event = {
    id: 'evt_' + Math.random().toString(36).slice(2, 10),
    merchantId: merchant.id,
    type,
    chargeReference: charge.reference,
    createdAt: Date.now(),
    status: 'skipped',
    responseCode: null,
  };

  if (!merchant.webhookUrl) {
    store.events.insert(event);
    return event;
  }

  const body = JSON.stringify({ id: event.id, type, createdAt: event.createdAt, data: charge });
  const signature = hmacSign(body, merchant.webhookSecret);

  try {
    const res = await fetch(merchant.webhookUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cowrie-signature': signature },
      body,
    });
    event.status = res.ok ? 'delivered' : 'failed';
    event.responseCode = res.status;
  } catch (err) {
    event.status = 'failed';
    event.error = err.message;
  }

  store.events.insert(event);
  return event;
}

module.exports = { emit };
