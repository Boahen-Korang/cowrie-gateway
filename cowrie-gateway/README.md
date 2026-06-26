# Cowrie — a fully functional demo payment gateway

A small but real payment-gateway backend (Node/Express) that links the three
Cowrie front-end pages — **landing → login → checkout** — and makes the gateway
actually work end to end.

The "bank / card network / mobile-money operator" side is *simulated* (you can't
call Visa or MTN from a laptop), but everything the **gateway** itself does is
real: charge creation, a server-side state machine, card validation (Luhn),
3-D Secure / OTP, idempotency, hashed-password auth, API keys, signed webhooks,
and persisted transactions.

## Run it

```bash
npm install      # only dependency is express
npm start        # -> http://localhost:4000
```

Open **http://localhost:4000**.

| Page | URL | Notes |
|------|-----|-------|
| Landing | `/` | links to login + checkout |
| Login | `/login` | demo merchant: `demo@adom.shop` / `password123` |
| Checkout | `/checkout` | the hosted payment page (the gateway) |
| Dashboard | `/dashboard` | payments appear here live after you pay |

Test instruments (test mode): card `4242 4242 4242 4242`, any future expiry, any
CVV, OTP `123456`. Mobile money / bank / USSD auto-confirm to simulate the
operator callback.

## How the pieces link

```
 Landing (/)  ──"Sign in"──▶  Login (/login)  ──POST /api/auth/login──▶  Dashboard (/dashboard)
      │                                                                        ▲
      └──"Try a live payment"──▶  Checkout (/checkout)                         │
                                      │                                        │
                       POST /api/charges            payment succeeds → stored ─┘
                       POST /charges/:ref/method      (and a signed webhook fires)
                       POST /charges/:ref/authorize | confirm
                       GET  /charges/:ref  (poll)
```

## API

All JSON. Amounts are in **minor units** (e.g. `25000` = GHS 250.00).

### Auth (merchant)
- `POST /api/auth/register` `{ businessName, email, password }`
- `POST /api/auth/login` `{ email, password }` → `{ token, merchant }`
- `GET  /api/me` (Bearer token)
- `PUT  /api/me/webhook` `{ url }`
- `GET  /api/transactions` (Bearer token)
- `GET  /api/events` (webhook delivery log)

### Charges (the gateway)
- `POST /api/charges` `{ amount, currency, email }` — auth via `public_key`
  (in body or `X-Public-Key`) or a secret key. Supports `Idempotency-Key` header.
- `GET  /api/charges/:reference` — status (poll this)
- `POST /api/charges/:reference/method` `{ method, details }`
  where method ∈ `card | mobile_money | bank_transfer | ussd`
- `POST /api/charges/:reference/authorize` `{ otp }` — card 3-D Secure
- `POST /api/charges/:reference/confirm` — momo / bank / ussd confirmation

### Webhooks
On `charge.success` / `charge.failed`, Cowrie POSTs a JSON event to the
merchant's `webhook_url` with header `cowrie-signature` =
`HMAC_SHA256(rawBody, webhook_secret)`. Verify it before trusting the payload.

## Server-side example (real integration shape)

```js
// 1. your server creates the charge with your SECRET key
const res = await fetch('http://localhost:4000/api/charges', {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-public-key': SECRET_KEY },
  body: JSON.stringify({ amount: 25000, currency: 'GHS', email: 'ama@adom.shop' }),
});
const { reference } = await res.json();
// 2. redirect the customer to: /checkout?reference=<reference>
// 3. trust the signed webhook (or poll GET /api/charges/<reference>) for success
```

## Project layout

```
server.js            Express app + page routing + demo seed
routes/api.js        all REST endpoints + auth/rate-limit middleware
lib/payments.js      charge state machine (the gateway logic)
lib/webhooks.js      signed webhook dispatch
lib/store.js         JSON persistence (swap for Postgres in prod)
lib/util.js          scrypt hashing, HMAC tokens, Luhn, key/ID generation
lib/config.js        secret + port + currency
public/              index.html · login.html · checkout.html · dashboard.html
data/db.json         created at runtime
```

## Going to production (what to change)
- Replace `lib/store.js` with a real database (Postgres + Prisma).
- Set `COWRIE_SECRET` (token-signing key) via environment, never the default.
- Put it behind HTTPS; serve the checkout from your own domain.
- Integrate real acquiring / card-network and mobile-money operator APIs in
  `lib/payments.js` where the success is currently simulated.
- Add retry/backoff to webhook delivery and store raw events for replay.
