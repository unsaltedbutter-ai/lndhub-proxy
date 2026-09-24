// lndhub-proxy — minimal, allow-by-construction LNDhub API proxy for a single LND node.
//
// Security model (see ~/Desktop/next-js-lndhub.md spec):
//  - Binds 127.0.0.1 only. Reachable from the WAN only via an nginx location with a
//    256-bit secret path prefix. Reaching the API still requires login+password (256-bit).
//  - Allow-by-construction: this file contains EVERY LND call the proxy can make.
//    No unlocker endpoints (changepassword/unlockwallet/initwallet/genseed), no on-chain
//    send, no macaroon minting, no seed export — they are absent, not filtered.
//  - The backing LND macaroon excludes signer + macaroon:generate + onchain:write.
//
// Env:
//  PORT (3100), HOST (127.0.0.1)
//  LND_REST_URL (http://127.0.0.1:8080)
//  LNDHUB_MACAROON_HEX   narrow macaroon, hex
//  LNDHUB_LOGIN          opaque login (uuid)
//  LNDHUB_PASSWORD       256-bit hex password
//  MAX_PAYMENT_SATS      per-payment cap, 0 = uncapped
//  PAYMENT_LOG_PATH      append-only JSONL audit log
import Fastify from 'fastify';
import { createHash, timingSafeEqual } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

// ---------------------------------------------------------------- config

const CFG = {
  host: process.env.HOST ?? '127.0.0.1',
  port: Number(process.env.PORT ?? 3100),
  lndUrl: (process.env.LND_REST_URL ?? 'http://127.0.0.1:8080').replace(/\/$/, ''),
  macaroonHex: process.env.LNDHUB_MACAROON_HEX ?? '',
  login: process.env.LNDHUB_LOGIN ?? '',
  password: process.env.LNDHUB_PASSWORD ?? '',
  maxPaymentSats: Number(process.env.MAX_PAYMENT_SATS ?? 250000),
  maxDailySats: Number(process.env.MAX_DAILY_SATS ?? 0),  // 0 = disabled
  logPath: process.env.PAYMENT_LOG_PATH ?? './payments.log',
};

function assertConfig() {
  const fail = (m) => { console.error(`FATAL: ${m}`); process.exit(1); };
  if (CFG.host !== '127.0.0.1' && CFG.host !== 'localhost')
    fail('refusing to bind to a non-loopback address — put nginx in front');
  if (!CFG.macaroonHex) fail('LNDHUB_MACAROON_HEX missing');
  if (CFG.login.length < 32) fail('LNDHUB_LOGIN too short (want >=128 bits)');
  if (CFG.password.length < 64) fail('LNDHUB_PASSWORD too short (want 256-bit hex)');
  if (!Number.isFinite(CFG.maxPaymentSats) || CFG.maxPaymentSats < 0)
    fail('MAX_PAYMENT_SATS must be >= 0');
  if (!Number.isFinite(CFG.maxDailySats) || CFG.maxDailySats < 0)
    fail('MAX_DAILY_SATS must be >= 0');
  if (!CFG.logPath.startsWith('/'))
    console.warn(`WARN: PAYMENT_LOG_PATH is relative (${CFG.logPath}) — it lands in the process cwd; set an absolute path in production.`);
}

// ------------------------------------------------------------- helpers

/** Constant-time string compare via sha256 digest (hides length too). */
function ctEqual(a, b) {
  const ha = createHash('sha256').update(String(a)).digest();
  const hb = createHash('sha256').update(String(b)).digest();
  return timingSafeEqual(ha, hb);
}

const EXPECTED_TOKEN = `${CFG.login}:${CFG.password}`;

/** The ONLY function that talks to LND. Every call site is auditable here. */
async function lnd(method, path, body) {
  const res = await fetch(`${CFG.lndUrl}${path}`, {
    method,
    headers: {
      'Grpc-Metadata-macaroon': CFG.macaroonHex,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30_000),
  });
  const text = await res.text();
  let json;
  try { json = text ? JSON.parse(text) : {}; }
  catch {
    // F1: server-streaming REST endpoints (e.g. /v2/router/send) return NDJSON:
    // one {"result": {...}} per line, final event is authoritative. Take the
    // LAST parseable line. (A single JSON.parse of the whole body throws here —
    // which previously turned SUCCEEDED payments into 502 "not settled".)
    json = {};
    for (const line of (text ?? '').split('\n').reverse()) {
      try { json = JSON.parse(line); if (Object.keys(json).length) break; } catch { /* keep scanning */ }
    }
  }
  if (!res.ok) {
    // LND errors: {error: "..."} (legacy) or {error: {code, message}} (v2) or {message}
    const msg = (typeof json?.error === 'object' ? json.error.message : json?.error)
      ?? json?.message ?? `lnd http ${res.status}`;
    const err = new Error(msg);
    err.status = res.status; err.body = json; throw err;
  }
  // unwrap streaming envelope {result:{...}} -> {...}
  if (json && typeof json === 'object' && 'result' in json && Object.keys(json).length === 1)
    json = json.result;
  return json;
}

/** protojson renders bytes fields as base64; LNDhub wants hex. */
const b64hex = (s) => Buffer.from(s ?? '', 'base64').toString('hex');

function audit(entry) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry });
  try { appendFileSync(CFG.logPath, line + '\n'); }
  catch { try { mkdirSync(dirname(CFG.logPath), { recursive: true }); appendFileSync(CFG.logPath, line + '\n'); } catch (e) { console.error('audit log failed:', e.message); } }
}

// --- F4: rolling 24h aggregate spend window (in-memory; resets on restart)
const spendWindow = [];
function recordSpend(sat) { spendWindow.push({ sat, t: Date.now() }); }
function spentToday() {
  const cutoff = Date.now() - 24 * 3600_000;
  while (spendWindow.length && spendWindow[0].t < cutoff) spendWindow.shift();
  return spendWindow.reduce((s, e) => s + e.sat, 0);
}

/** naive sliding-window limiter: N req / 60s per ip. Noise control, not a security control. */
const buckets = new Map();
function rateLimited(ip, max = 60) {
  const now = Date.now();
  const win = (buckets.get(ip) ?? []).filter((t) => now - t < 60_000);
  if (win.length >= max) { buckets.set(ip, win); return true; }
  win.push(now); buckets.set(ip, win);
  if (buckets.size > 10_000) buckets.clear(); // memory bound; fail-open is fine here
  return false;
}

// ---------------------------------------------------------------- server

// trustProxy: nginx sets X-Forwarded-For; without this every request looks like 127.0.0.1
// and the per-IP limiter would DoS itself. Header is set by OUR nginx on loopback only.
const app = Fastify({ logger: false, bodyLimit: 64 * 1024, trustProxy: true, routerOptions: { maxParamLength: 2000 } });

// --- auth: the LNDhub token IS the credential ("login:password"), no sessions/db.
app.addHook('onRequest', async (req, reply) => {
  if (rateLimited(req.ip)) return reply.code(429).send({ error: true, code: 6, message: 'rate limited' });

  // F6: exact match (query string allowed) — a future /api/anything route must
  // not silently inherit the auth exemption via prefix match.
  if (req.url === '/api/auth' || req.url.startsWith('/api/auth?')) return;

  const hdr = req.headers.authorization ?? '';
  // F3: Authorization header ONLY. The old ?access_token= fallback leaked the
  // bearer credential into nginx access logs (URLs are logged verbatim).
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
  if (!ctEqual(token, EXPECTED_TOKEN))
    return reply.code(401).send({ error: true, code: 1, message: 'Bad auth' });
});

// --- POST /api/auth  (type=auth and refresh_token both just re-issue the same token)
app.post('/api/auth', async (req, reply) => {
  const { login, password } = req.body ?? {};
  const ok = ctEqual(login ?? '', CFG.login) && ctEqual(password ?? '', CFG.password);
  if (!ok) return reply.code(401).send({ error: true, code: 1, message: 'Bad auth' });
  return {
    access_token: EXPECTED_TOKEN,
    token_type: 'Bearer',
    refresh_token: EXPECTED_TOKEN,
    expiry: '0001-01-01T00:00:00Z',
  };
});

// --- GET /api/getinfo  -> LND /v1/getinfo (field names align with LNDhub spec)
app.get('/api/getinfo', async () => {
  const g = await lnd('GET', '/v1/getinfo');
  return {
    fee: 0,
    identity_pubkey: g.identity_pubkey,
    alias: g.alias,
    num_pending_channels: g.num_pending_channels,
    num_active_channels: g.num_active_channels,
    num_inactive_channels: g.num_inactive_channels ?? 0,
    num_peers: g.num_peers,
    block_height: g.block_height,
    block_hash: g.block_hash,
    synced_to_chain: g.synced_to_chain,
    testnet: false,
    chains: g.chains ?? ['bitcoin'],
    uris: g.uris ?? [],
    best_header_timestamp: String(g.best_header_timestamp ?? ''),
    version: g.version,
  };
});

// --- GET /api/balance  -> channel balance only. On-chain is intentionally invisible.
app.get('/api/balance', async () => {
  const b = await lnd('GET', '/v1/balance/channels');
  const sat = Number(b.balance ?? 0);
  return { BTC: { TotalBalance: sat, AvailableBalance: sat, UncomfirmedBalance: 0 } };
});

// --- GET /api/getpending -> always empty: no on-chain endpoints exist here.
app.get('/api/getpending', async () => []);

// --- GET /api/decodeinvoice/:bolt11 -> LND /v1/decodepayreq
app.get('/api/decodeinvoice/:invoice', async (req, reply) => {
  try {
    const d = await lnd('GET', `/v1/payreq/${encodeURIComponent(req.params.invoice)}`);
    return {
      destination: d.destination,
      payment_hash: d.payment_hash,
      num_satoshis: String(d.num_satoshis ?? '0'),
      timestamp: String(d.timestamp ?? ''),
      expiry: String(d.expiry ?? ''),
      description: d.description,
      description_hash: d.description_hash ?? '',
      fallback_addr: d.fallback_addr ?? '',
      cltv_expiry: String(d.cltv_expiry ?? ''),
      route_hints: d.route_hints ?? [],
      payment_addr: d.payment_addr ?? '',
    };
  } catch (e) {
    return reply.code(400).send({ error: true, code: 4, message: `not a valid invoice: ${e.message}` });
  }
});

// --- GET /api/checkinvoice/:hash -> invoice settled?
app.get('/api/checkinvoice/:hash', async (req, reply) => {
  try {
    const b64 = Buffer.from(req.params.hash, 'hex').toString('base64');
    const inv = await lnd('GET', `/v2/invoices/lookup?payment_hash=${encodeURIComponent(b64)}`);
    return { paid: Boolean(inv.settled) };
  } catch {
    return reply.code(404).send({ paid: false });
  }
});

// --- POST /api/addinvoice -> create invoice
app.post('/api/addinvoice', async (req, reply) => {
  const { amt, memo, expiry } = req.body ?? {};
  try {
    const inv = await lnd('POST', '/v1/invoices', {
      memo: String(memo ?? ''),
      value: String(Math.trunc(Number(amt) || 0)),
      expiry: String(expiry ?? 3600),
    });
    return {
      r_hash: b64hex(inv.r_hash),
      pay_req: inv.payment_request,
      add_index: inv.add_index,
      payment_addr: inv.payment_addr,
    };
  } catch (e) {
    return reply.code(500).send({ error: true, code: 7, message: e.message });
  }
});

// --- GET /api/getuserinvoices -> incoming invoices
app.get('/api/getuserinvoices', async () => {
  // LND's v1 reverse=true is unreliable here; fetch and sort by add_index desc in-proxy.
  const { invoices = [] } = await lnd('GET', '/v1/invoices?num_max_invoices=1000');
  return invoices.map((i) => ({
    r_hash: b64hex(i.r_hash),
    payment_request: i.payment_request,
    add_index: i.add_index,
    description: i.memo,
    amt: Number(i.value ?? 0),
    ispaid: Boolean(i.settled),
    expire_date: i.timestamp
      ? new Date((Number(i.timestamp) + 3_600) * 1000).toISOString()
      : undefined,
  })).sort((a, b) => Number(b.add_index) - Number(a.add_index)); // newest first
});

// --- GET /api/gettxs -> outgoing payments
app.get('/api/gettxs', async (req) => {
  const limit = Math.min(Number(req.query.limit ?? 100), 500);
  const offset = Number(req.query.offset ?? 0);
  const all = await lnd('GET', '/v1/payments?max_payments=500');
  const payments = (all.payments ?? []).filter((p) => p.status === 'SUCCEEDED').slice(offset, offset + limit);
  return payments.map((p) => ({
    type: 'paid_invoice',
    ispaid: true,
    payment_hash: p.payment_hash,
    txid: p.payment_hash,
    amt: Number(p.value ?? 0),
    fee: Number(p.fee ?? 0),
    fee_sat: Number(p.fee ?? 0),
    timestamp: Number(p.creation_date ?? 0),
    memo: p.payment_request ? undefined : undefined,
    description: p.payment_request ? undefined : 'payment',
    value: Number(p.value_msat ?? 0),
  })).reverse();
});

// --- shared payment logic (used by payinvoice and sendcoins)
async function payBolt11(bolt11, reply) {
  if (!bolt11 || typeof bolt11 !== 'string')
    return reply.code(400).send({ error: true, code: 4, message: 'missing invoice' });

  let decoded;
  try { decoded = await lnd('GET', `/v1/payreq/${encodeURIComponent(bolt11)}`); }
  catch (e) { return reply.code(400).send({ error: true, code: 4, message: `not a valid invoice: ${e.message}` }); }

  const amtSat = Number(decoded.num_satoshis ?? 0);
  if (amtSat === 0)
    return reply.code(400).send({ error: true, code: 4, message: 'amountless invoices are refused (cap unenforceable)' });
  if (CFG.maxPaymentSats > 0 && amtSat > CFG.maxPaymentSats)
    return reply.code(400).send({ error: true, code: 2, message: `amount ${amtSat} exceeds MAX_PAYMENT_SATS=${CFG.maxPaymentSats}` });

  if (CFG.maxDailySats > 0 && spentToday() + amtSat > CFG.maxDailySats)
    return reply.code(400).send({ error: true, code: 2, message: `daily cap: ${spentToday()} + ${amtSat} exceeds MAX_DAILY_SATS=${CFG.maxDailySats}` });

  audit({ event: 'pay_attempt', amt_sat: amtSat, payment_hash: decoded.payment_hash, destination: decoded.destination });
  try {
    // F2: LND's default routing-fee budget is ~0 sats, so multi-hop payments would
    // fail NO_ROUTE. Allow 1% of amount (floor 1000 sats, ceiling 5000 sats).
    const feeLimitSat = Math.min(5000, Math.max(1000, Math.ceil(amtSat * 0.01)));
    const res = await lnd('POST', '/v2/router/send', {
      payment_request: bolt11,
      timeout_seconds: 120,
      no_inflight_updates: true,   // only the final status event
      fee_limit_msat: String(BigInt(feeLimitSat) * 1000n),
    });
    const succeeded = res.status === 'SUCCEEDED';
    if (succeeded) recordSpend(amtSat);
    audit({ event: 'pay_result', status: res.status, amt_sat: amtSat, payment_hash: res.payment_hash ?? decoded.payment_hash });
    if (!succeeded)
      return reply.code(502).send({
        error: true, code: 7,
        message: res.failure_reason ?? res.status ?? 'payment not settled',
        payment_error: res.failure_reason ?? res.status,
      });
    return {
      payment_error: '',
      payment_preimage: res.payment_preimage ?? '',
      payment_route: res.payment_route ?? {},
      payment_hash: res.payment_hash ?? decoded.payment_hash,
    };
  } catch (e) {
    audit({ event: 'pay_error', message: e.message, amt_sat: amtSat });
    return reply.code(502).send({ error: true, code: 7, message: e.message, payment_error: e.message });
  }
}

// --- POST /api/payinvoice -> THE SPENDING PATH. Cap enforced here, before LND sees anything.
app.post('/api/payinvoice', async (req, reply) => payBolt11(req.body?.invoice, reply));

// --- POST /api/sendcoins -> LNDhub wallets sometimes route bolt11 pays through sendcoins.
//     Same path, same cap. On-chain destinations are REFUSED — only ln-bolt11 is accepted.
app.post('/api/sendcoins', async (req, reply) => {
  const bolt11 = req.body?.invoice ?? req.body?.destination;
  if (typeof bolt11 !== 'string' || !bolt11.toLowerCase().startsWith('ln'))
    return reply.code(400).send({ error: true, code: 4, message: 'only bolt11 invoices accepted (no on-chain sends)' });
  return payBolt11(bolt11, reply);
});

// --- catch-all: 404. No passthrough exists.
app.setNotFoundHandler((req, reply) => {
  reply.code(404).send({ error: true, code: 6, message: 'not found' });
});

// ---------------------------------------------------------------- boot

assertConfig();
app.listen({ host: CFG.host, port: CFG.port }).then(() => {
  console.log(`lndhub-proxy listening on http://${CFG.host}:${CFG.port}/api  (lnd: ${CFG.lndUrl}, cap: ${CFG.maxPaymentSats || 'uncapped'} sats)`);
}).catch((e) => {
  if (e && (e.code === 'EADDRINUSE' || /EADDRINUSE/.test(String(e.message)))) {
    // A live instance already owns the port — that IS the health answer. Exit clean.
    console.log(`lndhub-proxy: port ${CFG.port} already bound by another instance; exiting quietly.`);
    process.exit(0);
  }
  console.error(e); process.exit(1);
});
