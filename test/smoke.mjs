// Smoke test: spins a mock LND REST on 127.0.0.1:18080, boots the proxy against it,
// exercises auth + every endpoint + the payment cap. Run: node test/smoke.mjs
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';

const LOGIN = 'a'.repeat(36);
const PASSWORD = 'b'.repeat(64);
const MAC = 'deadbeef';
let pass = 0, fail = 0, lastSendBody = null;
const ok = (name, cond) => { cond ? pass++ : fail++; console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}`); };

// ---- mock LND
const routes = {
  'GET /v1/getinfo': () => ({ identity_pubkey: '03aa', alias: 'test', num_active_channels: 1, num_peers: 2, num_pending_channels: 0, synced_to_chain: true, block_height: 968000, block_hash: '00', version: '0.21.3', chains: ['bitcoin'], uris: [] }),
  'GET /v1/balance/channels': () => ({ balance: '798976' }),
  'POST /v1/invoices': () => ({ r_hash: '/wAA', payment_request: 'lnbcRECV', add_index: '7', r_preimage: 'aaa' }),
  'GET /v1/invoices': () => ({ invoices: [{ r_hash: '/wAA', payment_request: 'lnbcRECV', add_index: '7', memo: 'hi', value: '5', settled: false, timestamp: 1700000000 }] }),
  'GET /v1/payments': () => ({ payments: [{ payment_hash: 'ff00', value: '20000', fee: '1', creation_date: '1700000000', status: 'SUCCEEDED', payment_request: 'lnbcVALID' }] }),
  'POST /v2/router/send': (b) => {
    lastSendBody = b;
    // F1 regression: real LND streams NDJSON, one {"result":...} per line.
    // Mock returns raw multi-line body; server must parse LAST line + unwrap .result.
    if (b.payment_request === 'lnbcVALID' || b.payment_request === 'lnbcSMALL')
      return { ndjson: [
        { result: { payment_hash: 'ff00', status: 'IN_FLIGHT' } },
        { result: { payment_hash: 'ff00', status: 'SUCCEEDED', payment_preimage: 'aa', payment_route: { total_fees: 1 } } },
      ]};
    return { ndjson: [{ result: { payment_hash: 'ff00', status: 'FAILED', failure_reason: 'FAILURE_REASON_NO_ROUTE' } }] };
  },
};
// dynamic: GET /v1/payreq/<bolt11> and GET /v2/invoices/lookup?payment_hash=<b64>
function dynamic(req) {
  const u = req.url;
  if (u.startsWith('/v1/payreq/')) {
    const bolt = decodeURIComponent(u.slice('/v1/payreq/'.length));
    const amt = bolt === 'lnbcVALID' ? '20000' : bolt === 'lnbcSMALL' ? '5000' : bolt === 'lnbcFAILS' ? '6000' : null;
    if (!amt) return { status: 400, body: { error: 'nope' } };
    return { status: 200, body: { destination: '03bb', payment_hash: 'ff00', num_satoshis: amt, timestamp: '1700000000', expiry: '3600', description: 'test', cltv_expiry: '80' } };
  }
  if (u.startsWith('/v2/invoices/lookup')) {
    const q = new URLSearchParams(u.split('?')[1] ?? '');
    const hex = Buffer.from(q.get('payment_hash') ?? '', 'base64').toString('hex');
    if (hex === 'ff00') return { status: 200, body: { settled: true, payment_request: 'lnbcVALID' } };
    return { status: 404, body: { code: 5, message: 'Not Found' } };
  }
  return null;
}
const mock = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const key = `${req.method} ${req.url}`;
    const dyn = dynamic(req);
    if (dyn) { res.writeHead(dyn.status, { 'content-type': 'application/json' }); res.end(JSON.stringify(dyn.body)); return; }
    const h = routes[key] ?? routes[`${req.method} ${req.url.split('?')[0]}`];
    if (!h) { res.writeHead(404); res.end(JSON.stringify({ error: 'mock: ' + key })); return; }
    try {
      const out = h(body ? JSON.parse(body) : undefined);
      res.writeHead(200, { 'content-type': 'application/json' });
      if (out && out.ndjson) res.end(out.ndjson.map((l) => JSON.stringify(l)).join('\n') + '\n');
      else res.end(JSON.stringify(out));
    } catch (e) { res.writeHead(500); res.end(JSON.stringify({ error: e.message })); }
  });
});
await new Promise((r) => mock.listen(18080, '127.0.0.1', r));

// ---- boot proxy
const env = {
  ...process.env, HOST: '127.0.0.1', PORT: '13100',
  LND_REST_URL: 'http://127.0.0.1:18080',
  LNDHUB_MACAROON_HEX: MAC, LNDHUB_LOGIN: LOGIN, LNDHUB_PASSWORD: PASSWORD,
  MAX_PAYMENT_SATS: '10000', PAYMENT_LOG_PATH: '/tmp/lndhub-smoke.log',
};
const proxy = spawn('node', ['src/server.js'], { env, cwd: new URL('..', import.meta.url).pathname, stdio: 'inherit' });
await new Promise((r) => setTimeout(r, 1500));

const B = 'http://127.0.0.1:13100/api';
const AUTH = `Bearer ${LOGIN}:${PASSWORD}`;
const call = (m, p, opts = {}) => fetch(`${B}${p}`, { method: m, headers: { authorization: AUTH, 'content-type': 'application/json', ...(opts.headers ?? {}) }, body: opts.body ? JSON.stringify(opts.body) : undefined }).then(async (r) => ({ status: r.status, json: await r.json().catch(() => null) }));

try {
  // auth
  let r = await fetch(`${B}/auth?type=auth`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ login: LOGIN, password: PASSWORD }) }).then((x) => x.json());
  ok('auth issues token', r.access_token === `${LOGIN}:${PASSWORD}`);
  r = await fetch(`${B}/auth?type=auth`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ login: LOGIN, password: 'c'.repeat(64) }) });
  ok('auth rejects wrong password', r.status === 401);
  r = await call('GET', '/balance', { headers: { authorization: 'Bearer x:y' } });
  ok('bad bearer rejected', r.status === 401);
  r = await call('GET', '/balance', { headers: { authorization: `Basic ${btoa(LOGIN + ':' + PASSWORD)}` } });
  ok('wrong auth scheme rejected', r.status === 401);

  // data endpoints
  r = await call('GET', '/getinfo');
  ok('getinfo', r.status === 200 && r.json.alias === 'test');
  r = await call('GET', '/balance');
  ok('balance = channel only', r.status === 200 && r.json.BTC.TotalBalance === 798976);
  r = await call('GET', '/getpending');
  ok('getpending empty', r.status === 200 && Array.isArray(r.json) && r.json.length === 0);
  r = await call('GET', '/decodeinvoice/lnbcVALID');
  ok('decodeinvoice', r.status === 200 && r.json.num_satoshis === '20000');
  r = await call('GET', '/checkinvoice/ff00');
  ok('checkinvoice paid', r.status === 200 && r.json.paid === true);
  r = await call('GET', '/checkinvoice/missing');
  ok('checkinvoice unknown -> 404 paid:false', r.status === 404 && r.json.paid === false);
  r = await call('POST', '/addinvoice', { body: { amt: 5, memo: 'hi' } });
  ok('addinvoice + b64->hex', r.status === 200 && r.json.pay_req === 'lnbcRECV' && r.json.r_hash === 'ff0000');
  r = await call('GET', '/getuserinvoices');
  ok('getuserinvoices', r.status === 200 && r.json[0].amt === 5 && r.json[0].ispaid === false);
  r = await call('GET', '/gettxs');
  ok('gettxs', r.status === 200 && r.json[0].type === 'paid_invoice' && r.json[0].amt === 20000);

  // payment paths (cap = 10000 in this test env)
  r = await call('POST', '/payinvoice', { body: { invoice: 'lnbcSMALL' } });   // 5000 < 10000
  ok('payinvoice under cap -> routes', r.status === 200 && r.json.payment_preimage === 'aa');
  r = await call('POST', '/payinvoice', { body: { invoice: 'lnbcVALID' } });    // 20000 > 10000
  ok('payinvoice over cap -> refused before LND', r.status === 400 && /MAX_PAYMENT_SATS/.test(r.json.message));
  r = await call('POST', '/sendcoins', { body: { destination: 'bc1qsomething' } });
  ok('sendcoins refuses on-chain address', r.status === 400);
  r = await call('POST', '/payinvoice', { body: { invoice: 'lnbcBOGUS' } });
  ok('payinvoice invalid bolt11 -> 400', r.status === 400);

  // F1: the under-cap test above only passes if NDJSON (multi-line {"result":...})
  // was parsed and unwrapped — pre-fix it 502'd here.
  // F2: fee_limit_msat (5000 sat payment -> floor 1000 sat -> 1000000 msat) + final-event-only flag
  ok('F2: fee_limit_msat + no_inflight_updates sent', lastSendBody && lastSendBody.fee_limit_msat === '1000000' && lastSendBody.no_inflight_updates === true);
  // F3: query-string token no longer accepted (was a log-leak path)
  r = await fetch(`${B}/balance?access_token=${LOGIN}:${PASSWORD}`);
  ok('F3: query-string token rejected', r.status === 401);

  // F6: prefix-exemption closed — /api/authx must NOT inherit the auth exemption
  r = await fetch(`${B}/authx`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  ok('F6: /api/authx not exempt from auth (401)', r.status === 401);
  // F1: FAILED NDJSON (single result line) -> 502 with real reason
  r = await call('POST', '/payinvoice', { body: { invoice: 'lnbcFAILS' } });
  ok('F1: FAILED stream -> 502 + reason', r.status === 502);

  // allow-by-construction: no passthrough to unlocker or anything else
  r = await call('GET', '/v1/changepassword');
  ok('no passthrough (404)', r.status === 404);
  r = await call('POST', '/initwallet', { body: {} });
  ok('no initwallet (404)', r.status === 404);

  // audit log written
  const log = (await import('node:fs')).readFileSync('/tmp/lndhub-smoke.log', 'utf8');
  ok('payment audit logged', log.includes('pay_attempt') && log.includes('pay_result'));
} finally {
  proxy.kill(); mock.close();
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
