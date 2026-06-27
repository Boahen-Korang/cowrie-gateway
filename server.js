'use strict';
const path = require('path');
const express = require('express');
const store = require('./lib/store');
const cfg = require('./lib/config');
const api = require('./routes/api');
const { migrate } = require('./lib/migrate');
const { merchantId, apiKey, hashPassword } = require('./lib/util');
const paystack = require('./lib/paystack');

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
  if (existing && existing.livePublicKey) return; // fully migrated
  const base = existing || {};
  const merchant = {
    id: base.id || merchantId(),
    businessName: 'Adɔm Stores',
    email: 'demo@adom.shop',
    passwordHash: base.passwordHash || hashPassword('password123'),
    publicKey:  base.publicKey  || apiKey('public',  'test'),
    secretKey:  base.secretKey  || apiKey('secret',  'test'),
    livePublicKey:  base.livePublicKey  || apiKey('public',  'live'),
    liveSecretKey:  base.liveSecretKey  || apiKey('secret',  'live'),
    webhookSecret: base.webhookSecret || ('whsec_' + apiKey('secret', 'test').slice(16)),
    webhookUrl: base.webhookUrl || null,
    demo: true,
    createdAt: base.createdAt || Date.now(),
  };
  if (existing) {
    await store.merchants.update(merchant);
    console.log('  Updated demo merchant (added live keys)');
  } else {
    await store.merchants.insert(merchant);
    console.log('  Seeded demo merchant: demo@adom.shop / password123');
  }
}

async function migrateMerchantKeys() {
  const all = await store.merchants.all();
  let count = 0;
  for (const m of all) {
    if (m.livePublicKey) continue;
    m.livePublicKey = apiKey('public', 'live');
    m.liveSecretKey = apiKey('secret', 'live');
    await store.merchants.update(m);
    count++;
  }
  if (count) console.log(`  Provisioned live keys for ${count} existing merchant(s)`);
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

async function loadGatewaySettings() {
  const gs = (await store.settings.get('gateways')) || { activeGateway: null, installed: [], gateways: {} };

  /* Sync Paystack env-var keys into DB so they appear in the admin dashboard.
     We only overwrite a field when the env var is set and the DB slot is empty,
     so manually-saved keys always win. */
  const envKeys = {
    testPublicKey:  process.env.PAYSTACK_PK_TEST  || '',
    testSecretKey:  process.env.PAYSTACK_SK_TEST  || '',
    livePublicKey:  process.env.PAYSTACK_PK_LIVE  || process.env.PAYSTACK_PUBLIC_KEY  || '',
    liveSecretKey:  process.env.PAYSTACK_SK_LIVE  || process.env.PAYSTACK_SECRET_KEY  || '',
  };
  const hasEnvKeys = Object.values(envKeys).some(Boolean);
  if (hasEnvKeys) {
    gs.gateways = gs.gateways || {};
    const existing = gs.gateways.paystack || {};
    gs.gateways.paystack = {
      testPublicKey: existing.testPublicKey || envKeys.testPublicKey,
      testSecretKey: existing.testSecretKey || envKeys.testSecretKey,
      livePublicKey: existing.livePublicKey || envKeys.livePublicKey,
      liveSecretKey: existing.liveSecretKey || envKeys.liveSecretKey,
    };
    gs.installed = gs.installed || [];
    if (!gs.installed.includes('paystack')) gs.installed.push('paystack');
    if (!gs.activeGateway) gs.activeGateway = 'paystack';
    await store.settings.set('gateways', gs);
    console.log('  ✓ Paystack env-var keys synced to dashboard');
  }

  if (gs.gateways && gs.gateways.paystack) {
    paystack.configureKeys(gs.gateways.paystack);
    console.log('  ✓ Gateway keys loaded from database');
  }
}

async function start() {
  await connectWithRetry();
  await seedDemoMerchant();
  await migrateMerchantKeys();
  await loadGatewaySettings();
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
