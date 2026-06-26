'use strict';
/*
 * Webhook dispatcher. On every charge state change we record a signed event
 * and POST it to the merchant's webhook URL (if set). The signature lets the
 * merchant verify the payload really came from Cowrie:
 *   HMAC_SHA256(rawBody, merchant.webhookSecret)  ->  header "cowrie-signature"
 */
const store = require('./store');
const { eventId, hmac } = require('./util');

async function emit(merchant, type, charge) {
  const event = {
    id: eventId(),
    merchantId: merchant.id,
    type,                                  // e.g. "charge.success"
    data: publicCharge(charge),
    createdAt: Date.now(),
    delivery: { status: 'pending', attempts: 0, url: merchant.webhookUrl || null },
  };
  store.events.insert(event);

  if (!merchant.webhookUrl) {
    event.delivery.status = 'skipped';
    store.events.update();
    return event;
  }

  const body = JSON.stringify({ id: event.id, type, data: event.data });
  const signature = hmac(body, merchant.webhookSecret);
  event.delivery.attempts++;
  try {
    const res = await fetch(merchant.webhookUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cowrie-signature': signature },
      body,
    });
    event.delivery.status = res.ok ? 'delivered' : 'failed';
    event.delivery.code = res.status;
  } catch (err) {
    event.delivery.status = 'failed';
    event.delivery.error = err.message;
  }
  store.events.update();
  console.log(`[webhook] ${type} -> ${merchant.webhookUrl} (${event.delivery.status})`);
  return event;
}

function publicCharge(c) {
  return {
    reference: c.reference, status: c.status, amount: c.amount, currency: c.currency,
    method: c.method, customerEmail: c.customerEmail, metadata: c.metadata,
    createdAt: c.createdAt, paidAt: c.paidAt || null,
  };
}

module.exports = { emit, publicCharge };
