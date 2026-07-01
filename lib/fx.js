'use strict';

/* Fixed rates: rates[currency] = units of that currency per 1 GHS.
   e.g. NGN: 140 means 1 GHS = 140 NGN. */
const FIXED_RATES = { NGN: 145, USD: 0.068, EUR: 0.063, GBP: 0.054, KES: 8.9, ZAR: 1.24 };

async function getRates() {
  return FIXED_RATES;
}

/* Convert amountMinor from any currency to GHS pesewas.
   Both NGN and GHS use 100 minor units per major unit, so the ratio is the same. */
function toGhsMinor(amountMinor, currency, rates) {
  if (!currency || currency === 'GHS') return amountMinor;
  const rate = (rates || FIXED_RATES)[currency];
  if (!rate) return amountMinor;
  return Math.round(amountMinor / rate);
}

module.exports = { getRates, toGhsMinor };
