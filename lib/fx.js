'use strict';

/* Fixed rates: rates[currency] = units of that currency per 1 USD.
   e.g. NGN: 1395.625 means 1 USD = 1395.625 NGN, GHS: 12 means 1 USD = 12 GHS. */
const FIXED_RATES = { NGN: 1395.625, GHS: 12, EUR: 0.93, GBP: 0.79, KES: 130, ZAR: 18.5 };

async function getRates() { return FIXED_RATES; }

/* Convert amountMinor from any currency to USD cents (kept for reference). */
function toUsdMinor(amountMinor, currency, rates) {
  if (!currency || currency === 'USD') return amountMinor;
  const rate = (rates || FIXED_RATES)[currency];
  if (!rate) return amountMinor;
  return Math.round(amountMinor / rate);
}

/* Convert amountMinor from any currency to GHS pesewas.
   Via USD as the common base: GHS_pesewas = (amount / src_rate) * GHS_rate */
function toGhsMinor(amountMinor, currency, rates) {
  const r = rates || FIXED_RATES;
  if (!currency || currency === 'GHS') return amountMinor;
  if (currency === 'USD') return Math.round(amountMinor * r.GHS);
  const srcRate = r[currency];
  if (!srcRate) return amountMinor;
  return Math.round((amountMinor / srcRate) * r.GHS);
}

module.exports = { getRates, toUsdMinor, toGhsMinor };
