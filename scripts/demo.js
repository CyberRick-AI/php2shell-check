#!/usr/bin/env node
// Demo mode: starts fake "PHP sites" on this machine plus the scanner, so you can see every verdict
// without scanning anyone's real site. Nothing here is PHP; it only sends the headers a PHP site would.
//   npm run demo   ->  open http://localhost:3000 and scan e.g. http://localhost:8081/vulnerable

const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

const TARGET_PORT = Number(process.env.DEMO_PORT || 8081);

const PROFILES = {
  vulnerable: { 'X-Powered-By': 'PHP/8.3.30', Server: 'Apache/2.4.58 (Ubuntu)', 'Set-Cookie': 'PHPSESSID=demo; path=/' },
  patched: { 'X-Powered-By': 'PHP/8.4.27', Server: 'nginx' },
  eol: { 'X-Powered-By': 'PHP/7.4.33', Server: 'Apache/2.4.58 mod_php' },
  hidden: { Server: 'nginx', 'Set-Cookie': 'PHPSESSID=demo; path=/' },
  wordpress: { Server: 'LiteSpeed', body: '<link rel="stylesheet" href="/wp-content/themes/demo/style.css">' },
  nophp: { Server: 'nginx' },
};

function handle(req, res) {
  const name = req.url.replace(/^\/+|\/+$/g, '').split(/[/?]/)[0];
  const p = PROFILES[name];
  if (!p) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end('<h1>Demo targets</h1><ul>' + Object.keys(PROFILES).map((k) => `<li>http://localhost:${TARGET_PORT}/${k}</li>`).join('') + '</ul>');
  }
  const { body = '<html><body>Demo site</body></html>', ...headers } = p;
  res.writeHead(200, { 'Content-Type': 'text/html', ...headers });
  res.end(body);
}

// Loopback only (IPv4 and IPv6, since "localhost" can resolve to either). Never reachable from the network.
http.createServer(handle).listen(TARGET_PORT, '127.0.0.1', () => {
  console.log(`Demo targets (fake headers only, no PHP). Paste one into the scanner:`);
  for (const k of Object.keys(PROFILES)) console.log(`  http://localhost:${TARGET_PORT}/${k}`);
  console.log('');
});
http.createServer(handle).listen(TARGET_PORT, '::1').on('error', () => { /* no IPv6 loopback: IPv4 is enough */ });

// The scanner, with the private-address guard lifted so it can reach the demo targets on localhost.
const scanner = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
  stdio: 'inherit',
  env: { ...process.env, ALLOW_PRIVATE: '1', HOST: '127.0.0.1' },
});
scanner.on('exit', (code) => process.exit(code || 0));
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => scanner.kill(sig));
