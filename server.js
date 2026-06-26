'use strict';
const path = require('path');
const express = require('express');
const store = require('./lib/store');
const cfg = require('./lib/config');
const api = require('./routes/api');
const { merchantId, apiKey, hashPassword } = require('./lib/util');

const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true }));

/* ---- API ---- */
app.use('/api', api);

/* ---- pages (linking the front-end pages through one server) ---- */
const pub = path.join(__dirname, 'public');
app.use(express.static(pub));
app.get('/', (_, res) => res.sendFile(path.join(pub, 'index.html')));
app.get('/login', (_, res) => res.sendFile(path.join(pub, 'login.html')));
app.get('/checkout', (_, res) => res.sendFile(path.join(pub, 'checkout.html')));
app.get('/dashboard', (_, res) => res.sendFile(path.join(pub, 'dashboard.html')));
app.get('/register', (_, res) => res.sendFile(path.join(pub, 'register.html')));
app.get('/admin', (_, res) => res.sendFile(path.join(pub, 'admin.html')));

/* ---- JSON 404 + error handler ---- */
app.use('/api', (_, res) => res.status(404).json({ error: 'not_found', message: 'Unknown endpoint.' }));
app.use((e, _req, res, _next) => {
  const status = e.status || 500;
  if (status >= 500) console.error(e);
  res.status(status).json({ error: e.code || 'server_error', message: e.message || 'Something went wrong.' });
});

/* ---- boot ---- */
store.load();
seedDemoMerchant();

app.listen(cfg.PORT, () => {
  const demo = store.merchants.all().find((m) => m.demo);
  console.log('\n  Cowrie gateway running');
  console.log(`  -> http://localhost:${cfg.PORT}`);
  console.log('\n  Pages:');
  console.log(`     /            landing`);
  console.log(`     /login       merchant sign-in   (demo: demo@adom.shop / password123)`);
  console.log(`     /checkout    hosted payment page (test card 4242 4242 4242 4242, OTP 123456)`);
  console.log(`     /dashboard   merchant dashboard`);
  console.log(`     /admin       admin demo UI (static, no backend wiring)`);
  if (demo) console.log(`\n  Demo public key: ${demo.publicKey}\n`);
});

function seedDemoMerchant() {
  if (store.merchants.byEmail('demo@adom.shop')) return;
  store.merchants.insert({
    id: merchantId(),
    businessName: 'Adɔm Stores',
    email: 'demo@adom.shop',
    passwordHash: hashPassword('password123'),
    publicKey: apiKey('public'),
    secretKey: apiKey('secret'),
    webhookSecret: 'whsec_' + apiKey('secret').slice(8),
    webhookUrl: null,
    demo: true,
    createdAt: Date.now(),
  });
  console.log('  Seeded demo merchant: demo@adom.shop / password123');
}
