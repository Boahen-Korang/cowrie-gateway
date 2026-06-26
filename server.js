'use strict';
const path = require('path');
const express = require('express');
const store = require('./lib/store');
const cfg = require('./lib/config');
const api = require('./routes/api');
const { migrate } = require('./lib/migrate');
const { merchantId, apiKey, hashPassword } = require('./lib/util');

const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '20mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(express.urlencoded({ extended: true }));

app.use('/api', api);

const pub = path.join(__dirname, 'public');
app.use(express.static(pub));
app.get('/',           (_, res) => res.sendFile(path.join(pub, 'index.html')));
app.get('/login',      (_, res) => res.sendFile(path.join(pub, 'login.html')));
app.get('/checkout',   (_, res) => res.sendFile(path.join(pub, 'checkout.html')));
app.get('/dashboard',  (_, res) => res.sendFile(path.join(pub, 'dashboard.html')));
app.get('/register',   (_, res) => res.sendFile(path.join(pub, 'register.html')));
app.get('/admin',      (_, res) => res.sendFile(path.join(pub, 'admin.html')));
app.get('/admin-login',(_, res) => res.sendFile(path.join(pub, 'admin-login.html')));

app.use('/api', (_, res) => res.status(404).json({ error: 'not_found', message: 'Unknown endpoint.' }));
app.use((e, _req, res, _next) => {
  const status = e.status || 500;
  if (status >= 500) console.error(e);
  res.status(status).json({ error: e.code || 'server_error', message: e.message || 'Something went wrong.' });
});

async function seedDemoMerchant() {
  const existing = await store.merchants.byEmail('demo@adom.shop');
  if (existing && existing.publicKey.startsWith('cowrie_pk_')) return;
  const merchant = {
    id: existing ? existing.id : merchantId(),
    businessName: 'Adɔm Stores',
    email: 'demo@adom.shop',
    passwordHash: hashPassword('password123'),
    publicKey: apiKey('public'),
    secretKey: apiKey('secret'),
    webhookSecret: 'whsec_' + apiKey('secret').slice(8),
    webhookUrl: null,
    demo: true,
    createdAt: existing ? existing.createdAt : Date.now(),
  };
  if (existing) {
    await store.merchants.update(merchant);
    console.log('  Updated demo merchant API keys to cowrie_pk_ prefix');
  } else {
    await store.merchants.insert(merchant);
    console.log('  Seeded demo merchant: demo@adom.shop / password123');
  }
}

async function connectWithRetry(maxAttempts = 6, delayMs = 3000) {
  for (let i = 1; i <= maxAttempts; i++) {
    try {
      await migrate();
      return;
    } catch (e) {
      if (i === maxAttempts) throw e;
      console.log(`  [DB] Not ready (attempt ${i}/${maxAttempts}), retrying in ${delayMs / 1000}s…`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

async function start() {
  await connectWithRetry();
  await seedDemoMerchant();
  app.listen(cfg.PORT, async () => {
    const all = await store.merchants.all();
    const demo = all.find((m) => m.demo);
    const mode = (cfg.PAYSTACK_SECRET_KEY || '').startsWith('sk_live_') ? 'LIVE' : 'TEST';
    console.log('\n  Cowrie gateway running');
    console.log(`  -> http://localhost:${cfg.PORT}`);
    console.log(`  Paystack mode: ${mode}`);
    if (demo) console.log(`  Demo Cowrie key: ${demo.publicKey}  (not a Paystack key)`);
  });
}

start().catch((e) => { console.error('Failed to start:', e); process.exit(1); });
