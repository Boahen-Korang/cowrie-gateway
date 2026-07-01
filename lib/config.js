'use strict';

module.exports = {
  PORT: Number(process.env.PORT) || 4000,
  SECRET: process.env.COWRIE_SECRET || 'dev_secret_change_me_in_production',
  DEFAULT_CURRENCY: 'GHS',
  TOKEN_TTL_MS: 24 * 60 * 60 * 1000,
  REMEMBER_TTL_MS: 30 * 24 * 60 * 60 * 1000,
  ADMIN_EMAIL: process.env.ADMIN_EMAIL || 'desmondagrah48@gmail.com,groovyalpha@gmail.com',
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'admin2026',
  PAYSTACK_SECRET_KEY: process.env.PAYSTACK_SECRET_KEY || '',
  PAYSTACK_PUBLIC_KEY: process.env.PAYSTACK_PUBLIC_KEY || '',
  PAYSTACK_SK_TEST: process.env.PAYSTACK_SK_TEST || '',
  PAYSTACK_SK_LIVE: process.env.PAYSTACK_SK_LIVE || process.env.PAYSTACK_SECRET_KEY || '',
  PAYSTACK_PK_TEST: process.env.PAYSTACK_PK_TEST || '',
  PAYSTACK_PK_LIVE: process.env.PAYSTACK_PK_LIVE || process.env.PAYSTACK_PUBLIC_KEY || '',
};
