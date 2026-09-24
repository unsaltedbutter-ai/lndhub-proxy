# lndhub-proxy

A minimal, **allow-by-construction** [LNDhub](https://github.com/BlueWallet/LndHub/blob/master/doc/Send-requirements.md) API proxy for a single [LND](https://github.com/lightningnetwork/lnd) node. Pair it with [Zeus](https://zeusln.app/) or BlueWallet on your phone: scan a QR, pay an invoice, done.

No database. No accounts. No sessions. No on-chain endpoints. No build toolchain beyond Node.

## Why this exists

Most LNDhub implementations are multi-user account systems with MongoDB and OAuth2. Most LND remote-access setups expose the raw LND REST API behind a reverse proxy with a *deny-list* of dangerous endpoints. This project takes the opposite position:

**The dangerous endpoints are not filtered out — they are never written.** There is no code path in this repository to `changepassword`, `unlockwallet`, `initwallet`, `genseed`, seed export, macaroon minting, or on-chain `sendcoins`. The single function that talks to LND (`lnd()` in `src/server.js`) is called from a fixed, auditable list of routes. If it's not in the table below, it doesn't exist.

The backing LND macaroon should also be baked narrow (no `signer`, no `macaroon:generate`, no `onchain:write`), so even a fully compromised proxy process cannot sweep the node's on-chain wallet or mint credentials.

## Endpoints (complete list)

| Route | LND call | Purpose |
|---|---|---|
| `POST /api/auth` | *(none)* | verify login+password, issue bearer token |
| `GET /api/getinfo` | `GET /v1/getinfo` | node status |
| `GET /api/balance` | `GET /v1/balance/channels` | Lightning balance (on-chain invisible) |
| `GET /api/getpending` | *(none)* | always `[]` |
| `GET /api/decodeinvoice/:bolt11` | `POST /v1/decodepayreq` | invoice preview |
| `GET /api/checkinvoice/:hash` | `GET /v2/invoices/lookup` | `{paid: bool}` |
| `POST /api/addinvoice` | `POST /v2/invoices` | create invoice |
| `GET /api/getuserinvoices` | `GET /v2/invoices/incoming` | receive history |
| `GET /api/gettxs` | `GET /v2/payments` | payment history |
| `POST /api/payinvoice` | `POST /v1/decodepayreq` + `POST /v2/router/send` | **pay (cap enforced first)** |
| `POST /api/sendcoins` | same as payinvoice | bolt11 only; on-chain refused |

Everything else: `404`.

## Security model

Three independent secrets, all 256-bit:

1. **Secret URL path** — nginx only routes `/<PREFIX><secret>/` to this server; the rest of the world sees a 404 and cannot locate the API.
2. **Login** (UUID) + **password** (64 hex chars) — checked with constant-time comparison; the bearer token is `login:password` per the LNDhub protocol.
3. **Narrow LND macaroon** — server-side only; never sent to the phone.

Defense in depth:

- `MAX_PAYMENT_SATS` — every `payinvoice`/`sendcoins` is decoded and capped **before** LND is asked to route it. Amountless invoices are refused (a cap can't be enforced on them). `0` disables the cap.
- Binds `127.0.0.1` only — refuses to boot on any other interface. TLS and reachability are nginx's job.
- Per-IP sliding-window rate limit (60 req/min) — noise control, not a security control.
- Append-only JSONL payment audit log (`PAYMENT_LOG_PATH`): every attempt, result, and error with amount + hash + destination.

### Kill switch ladder

1. `pm2 stop lndhub-proxy` — API disappears; node and funds untouched.
2. Rotate login/password in the env file + `pm2 restart` — lost-phone response.
3. Remove the nginx location + reload — path gone.
4. Purge macaroons on the LND host — invalidates everything (last resort).

## Configuration (env)

| Var | Default | Notes |
|---|---|---|
| `HOST` | `127.0.0.1` | boot refuses non-loopback |
| `PORT` | `3100` | |
| `LND_REST_URL` | `http://127.0.0.1:8080` | |
| `LNDHUB_MACAROON_HEX` | — | required; narrow macaroon, hex |
| `LNDHUB_LOGIN` | — | required; >= 128 bits |
| `LNDHUB_PASSWORD` | — | required; exactly 256-bit hex enforced |
| `MAX_PAYMENT_SATS` | `250000` | `0` = uncapped |
| `FEE_LIMIT_PCT` | `3` | routing-fee budget, % of amount (floats OK) |
| `FEE_LIMIT_FLOOR_SATS` | `1000` | minimum fee budget in sats |
| `PAYMENT_LOG_PATH` | `./payments.log` | |

Generate credentials:

```bash
openssl rand -hex 32   # path secret  (used in nginx location)
openssl rand -uuid4    # login
openssl rand -hex 32   # password
```

## Deployment sketch (BTCPay-style docker LND + nginx + PM2)

1. Bake the narrow macaroon on the LND host:
   ```bash
   lncli bakemacaroon --save_to=/data/lndhub.macaroon --expiration-days=365 \
     info:read offchain:read offchain:write invoices:read invoices:write addresses:read
   xxd -p -c2000 /data/lndhub.macaroon | tr -d '\n'   # -> LNDHUB_MACAROON_HEX
   ```
2. Env file at `/etc/lndhub-proxy/env`, mode `600`, **not in any backup that leaves the machine** (it is a spend credential).
3. `pm2 start src/server.js --name lndhub-proxy` with the env loaded; confirm `ss -lntp | grep 3100` shows `127.0.0.1` only.
4. One nginx location on an existing HTTPS vhost:
   ```nginx
   location /lh-<PATH-SECRET>/ {
       proxy_pass http://127.0.0.1:3100/api/;
       proxy_set_header Host $host;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   }
   ```
   `nginx -t && systemctl reload nginx` (graceful — no dropped connections).
5. Verify from outside: `POST /lh-<secret>/api/auth` with creds → 200; wrong creds → 401; any unlocker path → 404.
6. Zeus → Connect a node → **LNDHub** → existing account →
   `lndhub://<login>:<password>@https://<host>/lh-<PATH-SECRET>/`
7. First payment: tiny, to your own invoice.

## Development

```bash
npm install
npm test        # 20-check smoke suite against a mock LND; no network, no node needed
```

## Limitations (by design)

- Single user, single node, single channel balance. No accounting DB — the node's
  Lightning balance *is* the wallet balance.
- Receiving via `addinvoice` works, but there's no notification channel; the wallet
  polls `checkinvoice`.
- No on-chain visibility at all (a feature, not a bug).
- Amountless (donation) invoices are refused.

## License

MIT
