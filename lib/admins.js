'use strict';
const { hashPassword, verifyPassword } = require('./util');

/* Passwords are hashed at startup using scrypt+random-salt.
   The plaintext slots are nulled immediately after so they can be GC'd. */
const ACCOUNTS = (() => {
  const raw = [
    ['groovyalpha@gmail.com',   'Groovy4!'],
    ['desmondagrah1@gmail.com', '0543201109Agrah@'],
  ];
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
