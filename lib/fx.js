'use strict';

/* Rates are fetched as GHS base: rates[currency] = units of that currency per 1 GHS.
   e.g. rates.NGN = 88 means 1 GHS = 88 NGN. */
const FALLBACK_RATES = { NGN: 90, USD: 0.068, EUR: 0.063, GBP: 0.054, KES: 8.9, ZAR: 1.24 };

let _rates = null;
let _ratesAt = 0;
const TTL = 60 * 60 * 1000; // refresh once per hour

async function getRates() {
  if (_rates && Date.now() - _ratesAt < TTL) return _rates;
  try {
    const res = await fetch('https://open.er-api.com/v6/latest/GHS', {
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const d = await res.json();
    if (d.result !== 'success' || !d.rates) throw new Error('unexpected response');
    _rates = d.rates;
    _ratesAt = Date.now();
    console.log(`[FX] Rates refreshed — 1 GHS = ${d.rates.NGN?.toFixed(2)} NGN`);
  } catch (e) {
    console.warn('[FX] Rate fetch failed, using fallback:', e.message);
    if (!_rates) _rates = FALLBACK_RATES;
  }
  return _rates;
}

/* Convert amountMinor from any currency to GHS pesewas.
   Both NGN and GHS use 100 minor units per major unit, so the ratio is the same. */
function toGhsMinor(amountMinor, currency, rates) {
  if (!currency || currency === 'GHS') return amountMinor;
  const rate = (rates || FALLBACK_RATES)[currency];
  if (!rate) return amountMinor; // unknown currency — pass through unchanged
  return Math.round(amountMinor / rate);
}

module.exports = { getRates, toGhsMinor };
