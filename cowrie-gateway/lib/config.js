'use strict';
module.exports = {
  APP_SECRET: process.env.COWRIE_SECRET || 'cowrie_dev_secret_change_me_in_prod',
  PORT: Number(process.env.PORT) || 4000,
  CURRENCY: 'GHS',
};
