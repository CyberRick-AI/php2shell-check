// Cloudflare Worker: serves the PWA (static assets) and the /api/scan endpoint.
// Passive only: one GET request to the target, headers + first few KB of HTML. No exploit traffic.
//
// Secrets / vars:
//   PUBLIC_MODE   (var)     "1" = anyone can scan with no key, limited per IP by the SCAN_LIMITER binding
//   ACCESS_KEY    (secret)  private mode (default): key the app sends in the x-access-key header
//   SCAN_LIMITER  (binding) Cloudflare rate limiter, required in public mode (see wrangler.toml)
//   ALLOW_PRIVATE (var, tests only)   "1" disables the private-address guard
// Neither mode configured = refuses to scan (fails closed).

import core from './core.js';

const enc = new TextEncoder();

async function sha256(s) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)));
}

// Constant-time comparison (hash both so length differences don't leak).
async function keyMatches(given, expected) {
  const [a, b] = await Promise.all([sha256(given), sha256(expected)]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

async function readLimited(res, maxBytes) {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let out = '';
  let total = 0;
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      out += dec.decode(value, { stream: true });
    }
  } finally {
    try { await reader.cancel(); } catch { /* ignore */ }
  }
  return out.slice(0, maxBytes);
}

async function handleScan(request, env, url) {
  if (request.method !== 'GET') return json({ error: 'Method not allowed' }, 405);

  if (env.PUBLIC_MODE === '1') {
    // Public mode: no login, but every IP is rate limited. No limiter configured = refuse.
    if (!env.SCAN_LIMITER) return json({ error: 'Server not configured: public mode needs the SCAN_LIMITER rate limiter binding' }, 503);
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    const { success } = await env.SCAN_LIMITER.limit({ key: ip });
    if (!success) return json({ error: 'Too many scans from your connection. Wait a minute and try again.' }, 429);
  } else {
    // Private mode. Fail closed: an unconfigured deployment never scans.
    if (!env.ACCESS_KEY) return json({ error: 'Server not configured: set the ACCESS_KEY secret (npx wrangler secret put ACCESS_KEY) or enable PUBLIC_MODE' }, 503);
    const given = request.headers.get('x-access-key') || '';
    if (!(await keyMatches(given, env.ACCESS_KEY))) return json({ error: 'Invalid access key' }, 401);
  }

  let target;
  try { target = core.normalizeTarget(url.searchParams.get('url'), { allowPrivate: env.ALLOW_PRIVATE === '1' }); }
  catch (e) { return json({ error: e.message }, 400); }

  const started = Date.now();
  let res;
  try {
    res = await fetch(target.href, {
      method: 'GET',
      redirect: 'follow',
      headers: { 'user-agent': 'CyberRick-PHP2Shell-Check/1.0', accept: 'text/html,*/*' },
      signal: AbortSignal.timeout(8000),
    });
  } catch (e) {
    const timedOut = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
    return json({ error: timedOut ? 'The site took too long to respond (8s)' : 'Could not reach the site. Check the address, or the site may block scanners.' }, 502);
  }

  const headers = {};
  res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
  const cookies = typeof res.headers.getSetCookie === 'function'
    ? res.headers.getSetCookie().join(';')
    : (res.headers.get('set-cookie') || '');
  const body = await readLimited(res, 8192);

  const analysis = core.analyze({ headers, cookies, body });
  return json({
    url: target.href,
    host: target.hostname,
    finalUrl: res.url || target.href,
    status: res.status,
    ms: Date.now() - started,
    scannedAt: new Date().toISOString(),
    ...analysis,
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/scan') return handleScan(request, env, url);
    if (url.pathname === '/api/health') return json({ ok: true, mode: env.PUBLIC_MODE === '1' ? 'public' : 'private' });
    if (url.pathname.startsWith('/api/')) return json({ error: 'Not found' }, 404);
    return env.ASSETS.fetch(request);
  },
};
