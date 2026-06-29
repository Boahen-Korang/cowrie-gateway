'use strict';
const { hashPassword, verifyPassword } = require('./util');

/* Passwords are hashed at startup using scrypt+random-salt.
   The plaintext slots are nulled immediately after so they can be GC'd.

   Primary credentials come from ADMIN_EMAIL + ADMIN_PASSWORD env vars
   (set these in your Render dashboard — never commit real passwords to source).
   The hardcoded list below is the local-dev fallback only. */
const ACCOUNTS = (() => {
  const raw = [
    ['groovyalpha@gmail.com', 'Groovy4!'],
    ['desmondagrah1@gmail.com', '0543201109Agrah@'],
  ];

  /* Inject env-var account at the front if provided */
  const envEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const envPass  = (process.env.ADMIN_PASSWORD || '').trim();
  if (envEmail && envPass && !raw.find(r => r[0] === envEmail)) {
    raw.unshift([envEmail, envPass]);
  } else if (envEmail && envPass) {
    /* Overwrite the password for the matching hardcoded account */
    const idx = raw.findIndex(r => r[0] === envEmail);
    if (idx !== -1) raw[idx][1] = envPass;
  }

  const hashed = raw.map(([email, pw]) => ({ email, passwordHash: hashPassword(pw) }));
  raw.forEach((r) => { r[1] = null; });
  return hashed;
})();

const DUMMY_HASH = ACCOUNTS[0].passwordHash; // used to maintain constant-time on unknown emails

function findAdmin(email, password) {
  const lc = String(email || '').toLowerCase();
  const account = ACCOUNTS.find((a) => a.email === lc);
  // Always run verifyPassword so response time doesn't reveal valid emails
  const valid = verifyPassword(String(password || ''), account ? account.passwordHash : DUMMY_HASH);
  return account && valid ? account : null;
}

module.exports = { findAdmin };
