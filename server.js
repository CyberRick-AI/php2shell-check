#!/usr/bin/env node
// Local server + CLI for PHP2Shell Check. Same UI and analysis as the Cloudflare Worker.
//   node server.js              ->  http://localhost:3000   (serves ./public and /api/scan)
//   node server.js example.com  ->  prints the JSON report
// Env: PORT (3000), HOST (127.0.0.1), ACCESS_KEY (optional locally), ALLOW_PRIVATE=1 (LAN testing)
// Zero dependencies. Passive only: one GET, headers + first few KB of HTML. No exploit traffic.

const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const core = require('./src/core');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1';
const ACCESS_KEY = process.env.ACCESS_KEY || '';
const PUBLIC = path.join(__dirname, 'public');

// Constant-time key check (hash both so length differences don't leak).
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const keyMatches = (given) => crypto.timingSafeEqual(sha(given || ''), sha(ACCESS_KEY));

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return core.isPrivateIPv4(ip);
  const l = ip.toLowerCase();
  return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') || l.startsWith('::ffff:');
}

function request(urlObj, ip) {
  return new Promise((resolve, reject) => {
    const lib = urlObj.protocol === 'https:' ? https : http;
    const req = lib.request({
      method: 'GET', host: ip, servername: urlObj.hostname, port: urlObj.port || undefined,
      path: urlObj.pathname + urlObj.search,
      headers: { Host: urlObj.host, 'User-Agent': 'CyberRick-PHP2Shell-Check/1.0', Accept: 'text/html,*/*' },
      timeout: 8000, rejectUnauthorized: false,
    }, (res) => {
      let body = '';
      res.on('data', (c) => { if (body.length < 8192) body += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('timeout', () => req.destroy(new Error('The site took too long to respond (8s)')));
    req.on('error', reject);
    req.end();
  });
}

const MAX_REDIRECTS = 5;

// Resolves one hop, refuses private addresses, then fetches it pinned to the checked IP
// so DNS rebinding cannot swap in an internal address after the check.
async function fetchHop(u, allowPrivate) {
  const addrs = await dns.lookup(u.hostname, { all: true });
  if (!allowPrivate && addrs.some((a) => isPrivateIp(a.address))) throw new Error('Private, internal and local addresses are blocked');
  const ip = addrs[0].address;
  return { ip, res: await request(u, ip) };
}

// Follows redirects (most sites send http->https or apex->www first) and analyzes the final page.
// Every hop goes through the same address checks as the original target.
async function scan(rawUrl, { allowPrivate = ALLOW_PRIVATE } = {}) {
  const target = core.normalizeTarget(rawUrl, { allowPrivate });
  const started = Date.now();
  const redirects = [];
  const hops = [];
  let u = target;
  let ip;
  for (;;) {
    const hop = await fetchHop(u, allowPrivate);
    ip = hop.ip;
    hops.push(hop.res);
    const loc = hop.res.headers.location;
    if (!(hop.res.status >= 300 && hop.res.status < 400 && loc)) break;
    if (redirects.length >= MAX_REDIRECTS) throw new Error(`Too many redirects (more than ${MAX_REDIRECTS})`);
    redirects.push(u.href);
    u = core.normalizeTarget(new URL(loc, u).href, { allowPrivate });
  }

  const res = hops[hops.length - 1];
  const headers = {};
  for (const [k, v] of Object.entries(res.headers)) headers[k.toLowerCase()] = [].concat(v).join(', ');
  // PHP often answers the redirect itself, so keep its version header and cookies if the final page drops them.
  if (!/php/i.test(headers['x-powered-by'] || '')) {
    const php = hops.map((h) => [].concat(h.headers['x-powered-by'] || []).join(', ')).find((v) => /php/i.test(v));
    if (php) headers['x-powered-by'] = php;
  }
  const cookies = hops.flatMap((h) => [].concat(h.headers['set-cookie'] || [])).join(';');

  return {
    url: target.href, host: target.hostname, finalUrl: u.href, redirects, ip, status: res.status, ms: Date.now() - started,
    scannedAt: new Date().toISOString(),
    ...core.analyze({ headers, cookies, body: res.body }),
  };
}

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json',
  '.webmanifest': 'application/manifest+json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
};

function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC + path.sep)) { res.statusCode = 403; return res.end('Forbidden'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.statusCode = 404; return res.end('Not found'); }
    res.setHeader('Content-Type', TYPES[path.extname(file)] || 'application/octet-stream');
    res.end(data);
  });
}

if (require.main === module) {
  if (process.argv[2]) {
    scan(process.argv[2]).then((r) => console.log(JSON.stringify(r, null, 2)))
      .catch((e) => { console.error('Error:', e.message); process.exit(1); });
  } else {
    http.createServer(async (req, res) => {
      const u = new URL(req.url, 'http://x');
      if (u.pathname === '/api/scan') {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Cache-Control', 'no-store');
        if (ACCESS_KEY && !keyMatches(req.headers['x-access-key'])) { res.statusCode = 401; return res.end(JSON.stringify({ error: 'Invalid access key' })); }
        try { res.end(JSON.stringify(await scan(u.searchParams.get('url') || ''))); }
        catch (e) { res.statusCode = e.code === 'ENOTFOUND' ? 502 : 400; res.end(JSON.stringify({ error: e.code === 'ENOTFOUND' ? 'Could not find that site (DNS lookup failed)' : e.message })); }
      } else serveStatic(req, res, u.pathname);
    }).listen(PORT, HOST, () => {
      console.log(`PHP2Shell Check on http://${HOST === '127.0.0.1' ? 'localhost' : HOST}:${PORT}`);
      const loopback = HOST === '127.0.0.1' || HOST === 'localhost' || HOST === '::1';
      if (!loopback && !ACCESS_KEY && !process.env.IN_DOCKER) console.warn('WARNING: listening beyond this machine with no ACCESS_KEY. Anyone on your network can use it to scan. Set ACCESS_KEY=<long random string>.');
    });
  }
}

module.exports = { scan };
