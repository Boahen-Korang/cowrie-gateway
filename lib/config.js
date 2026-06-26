'use strict';

module.exports = {
  PORT: Number(process.env.PORT) || 4000,
  SECRET: process.env.COWRIE_SECRET || 'dev_secret_change_me_in_production',
  DEFAULT_CURRENCY: 'GHS',
  TOKEN_TTL_MS: 24 * 60 * 60 * 1000,
  ADMIN_EMAIL: process.env.ADMIN_EMAIL || 'admin@cowrie.africa',
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'admin2026',
};
