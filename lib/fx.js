'use strict';

/* Fixed rates: rates[currency] = units of that currency per 1 USD.
   e.g. NGN: 1600 means 1 USD = 1600 NGN. */
const FIXED_RATES = { NGN: 1600, GHS: 12, EUR: 0.93, GBP: 0.79, KES: 130, ZAR: 18.5 };

async function getRates() {
  return FIXED_RATES;
}

/* Convert amountMinor from any currency to USD cents. */
function toUsdMinor(amountMinor, currency, rates) {
  if (!currency || currency === 'USD') return amountMinor;
  const rate = (rates || FIXED_RATES)[currency];
  if (!rate) return amountMinor;
  return Math.round(amountMinor / rate);
}

module.exports = { getRates, toUsdMinor };
