'use strict';

module.exports = {
  PORT: Number(process.env.PORT) || 4000,
  SECRET: process.env.COWRIE_SECRET || 'dev_secret_change_me_in_production',
  DEFAULT_CURRENCY: 'GHS',
  TOKEN_TTL_MS: 24 * 60 * 60 * 1000, // 24h merchant session tokens
};
