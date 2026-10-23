import test from 'node:test';
import assert from 'node:assert';
import worker from '../src/worker.mjs';

const KEY = 'test-key-123';
const env = { ACCESS_KEY: KEY, ASSETS: { fetch: async () => new Response('<html>shell</html>', { headers: { 'content-type': 'text/html' } }) } };
const call = (path, { key = KEY, e = env, method = 'GET' } = {}) =>
  worker.fetch(new Request('https://app.example' + path, { method, headers: key === null ? {} : { 'x-access-key': key } }), e);

// Stub the outbound fetch the Worker makes to the scanned site.
const realFetch = globalThis.fetch;
function upstream(headers, { body = '<html></html>', status = 200, cookies = [] } = {}) {
  globalThis.fetch = async (url) => {
    const h = new Headers(headers);
    for (const c of cookies) h.append('set-cookie', c);
    const r = new Response(body, { status, headers: h });
    Object.defineProperty(r, 'url', { value: String(url) });
    return r;
  };
}
test.afterEach(() => { globalThis.fetch = realFetch; });

test('serves static assets through ASSETS', async () => {
  const r = await call('/');
  assert.strictEqual(await r.text(), '<html>shell</html>');
});

test('health endpoint needs no key', async () => {
  const r = await call('/api/health', { key: null });
  assert.strictEqual(r.status, 200);
});

test('fails closed when ACCESS_KEY is not configured', async () => {
  const r = await call('/api/scan?url=example.com', { e: { ASSETS: env.ASSETS } });
  assert.strictEqual(r.status, 503);
});

test('rejects missing and wrong keys', async () => {
  assert.strictEqual((await call('/api/scan?url=example.com', { key: null })).status, 401);
  assert.strictEqual((await call('/api/scan?url=example.com', { key: 'nope' })).status, 401);
  assert.strictEqual((await call('/api/scan?url=example.com', { key: KEY + 'x' })).status, 401);
});

test('only GET is allowed', async () => {
  assert.strictEqual((await call('/api/scan?url=example.com', { method: 'POST' })).status, 405);
});

test('blocks internal targets before any outbound request', async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response('x'); };
  for (const t of ['localhost', '127.0.0.1', '169.254.169.254', '10.1.1.1', 'example.com:22', 'ftp://example.com']) {
    const r = await call('/api/scan?url=' + encodeURIComponent(t));
    assert.strictEqual(r.status, 400, t);
  }
  assert.strictEqual(called, false);
});

test('vulnerable result end to end', async () => {
  upstream({ 'x-powered-by': 'PHP/8.3.30', server: 'Apache' }, { cookies: ['PHPSESSID=abc; path=/'] });
  const r = await call('/api/scan?url=client.example');
  assert.strictEqual(r.status, 200);
  const d = await r.json();
  assert.strictEqual(d.verdict, 'vulnerable');
  assert.strictEqual(d.phpVersion, '8.3.30');
  assert.strictEqual(d.host, 'client.example');
  assert.ok(d.evidence.includes('PHPSESSID cookie set'));
  assert.match(d.report.patch[0], /8\.3\.36/);
  assert.strictEqual(r.headers.get('cache-control'), 'no-store');
});

test('patched and hidden results', async () => {
  upstream({ 'x-powered-by': 'PHP/8.5.12' });
  assert.strictEqual((await (await call('/api/scan?url=a.example')).json()).verdict, 'patched');
  upstream({ server: 'nginx' }, { cookies: ['PHPSESSID=1'] });
  assert.strictEqual((await (await call('/api/scan?url=b.example')).json()).verdict, 'unknown');
});

test('upstream failure and timeout map to 502 with a clean message', async () => {
  globalThis.fetch = async () => { throw new TypeError('network down'); };
  const r = await call('/api/scan?url=down.example');
  assert.strictEqual(r.status, 502);
  assert.match((await r.json()).error, /Could not reach/);
  globalThis.fetch = async () => { const e = new Error('t'); e.name = 'TimeoutError'; throw e; };
  assert.match((await (await call('/api/scan?url=slow.example')).json()).error, /too long/);
});

test('large responses are read only up to the limit', async () => {
  upstream({ 'x-powered-by': 'PHP/8.4.27' }, { body: 'x'.repeat(5_000_000) });
  const r = await call('/api/scan?url=big.example');
  assert.strictEqual(r.status, 200);
});

test('unknown API paths 404', async () => {
  assert.strictEqual((await call('/api/nope')).status, 404);
});

// ---- public mode ----
const limiter = (allow = true, seen = []) => ({ limit: async ({ key }) => { seen.push(key); return { success: allow }; } });
const pub = (extra = {}) => ({ ASSETS: env.ASSETS, PUBLIC_MODE: '1', SCAN_LIMITER: limiter(), ...extra });

test('public mode scans with no key and rate limits by client IP', async () => {
  const seen = [];
  upstream({ 'x-powered-by': 'PHP/8.3.30' });
  const req = new Request('https://app.example/api/scan?url=client.example', { headers: { 'cf-connecting-ip': '203.0.113.7' } });
  const r = await worker.fetch(req, pub({ SCAN_LIMITER: limiter(true, seen) }));
  assert.strictEqual(r.status, 200);
  assert.strictEqual((await r.json()).verdict, 'vulnerable');
  assert.deepStrictEqual(seen, ['203.0.113.7']);
});

test('public mode returns 429 when the limiter says no, before any outbound request', async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return new Response('x'); };
  const r = await call('/api/scan?url=client.example', { key: null, e: pub({ SCAN_LIMITER: limiter(false) }) });
  assert.strictEqual(r.status, 429);
  assert.strictEqual(called, false);
});

test('public mode fails closed without a limiter binding', async () => {
  const r = await call('/api/scan?url=client.example', { key: null, e: { ASSETS: env.ASSETS, PUBLIC_MODE: '1' } });
  assert.strictEqual(r.status, 503);
});

test('public mode still blocks internal targets', async () => {
  const r = await call('/api/scan?url=localhost', { key: null, e: pub() });
  assert.strictEqual(r.status, 400);
});

test('PUBLIC_MODE=0 keeps the key requirement', async () => {
  const r = await call('/api/scan?url=client.example', { key: null, e: { ...env, PUBLIC_MODE: '0' } });
  assert.strictEqual(r.status, 401);
});

test('health reports the mode', async () => {
  assert.strictEqual((await (await call('/api/health', { key: null, e: pub() })).json()).mode, 'public');
  assert.strictEqual((await (await call('/api/health', { key: null })).json()).mode, 'private');
});

// ---- redirects ----
function routes(map) {
  globalThis.fetch = async (url, init) => {
    assert.strictEqual(init.redirect, 'manual');
    const [status, headers] = map[String(url)] || [404, {}];
    return new Response(status >= 300 && status < 400 ? null : '<html></html>', { status, headers });
  };
}

test('follows redirects to the final page', async () => {
  routes({
    'https://client.example/': [301, { location: 'https://www.client.example/' }],
    'https://www.client.example/': [200, { 'x-powered-by': 'PHP/8.3.30' }],
  });
  const d = await (await call('/api/scan?url=client.example')).json();
  assert.strictEqual(d.verdict, 'vulnerable');
  assert.strictEqual(d.finalUrl, 'https://www.client.example/');
  assert.deepStrictEqual(d.redirects, ['https://client.example/']);
});

test('refuses a redirect to an internal address', async () => {
  routes({ 'https://client.example/': [302, { location: 'http://169.254.169.254/latest/meta-data/' }] });
  const r = await call('/api/scan?url=client.example');
  assert.strictEqual(r.status, 400);
  assert.match((await r.json()).error, /not allowed/);
});

test('stops after too many redirects', async () => {
  routes({ 'https://a.example/': [302, { location: 'https://b.example/' }], 'https://b.example/': [302, { location: 'https://a.example/' }] });
  const r = await call('/api/scan?url=a.example');
  assert.strictEqual(r.status, 502);
  assert.match((await r.json()).error, /Too many redirects/);
});
