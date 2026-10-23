const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { scan } = require('../server');

// A local site whose routes are [status, headers] pairs. allowPrivate lets the scanner reach 127.0.0.1.
function site(routes) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const [status, headers] = routes[req.url] || [404, {}];
      res.writeHead(status, headers);
      res.end('<html></html>');
    }).listen(0, '127.0.0.1', () => resolve({ srv, base: `http://127.0.0.1:${srv.address().port}` }));
  });
}
const opts = { allowPrivate: true };

test('follows redirects and analyzes the final page', async () => {
  const { srv, base } = await site({
    '/': [301, { Location: '/www/' }],
    '/www/': [302, { Location: '/final' }],
    '/final': [200, { 'X-Powered-By': 'PHP/8.3.30' }],
  });
  try {
    const r = await scan(base + '/', opts);
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.verdict, 'vulnerable');
    assert.strictEqual(r.phpVersion, '8.3.30');
    assert.strictEqual(r.finalUrl, base + '/final');
    assert.deepStrictEqual(r.redirects, [base + '/', base + '/www/']);
  } finally { srv.close(); }
});

test('keeps PHP signals seen on redirect hops', async () => {
  const { srv, base } = await site({
    '/': [302, { Location: '/home', 'X-Powered-By': 'PHP/8.2.20', 'Set-Cookie': 'PHPSESSID=a; path=/' }],
    '/home': [200, { Server: 'nginx' }],
  });
  try {
    const r = await scan(base + '/', opts);
    assert.strictEqual(r.phpVersion, '8.2.20');
    assert.ok(r.evidence.includes('PHPSESSID cookie set'));
  } finally { srv.close(); }
});

test('a redirect target goes through the same address checks', async () => {
  const { srv, base } = await site({ '/': [301, { Location: 'ftp://example.com/' }] });
  try {
    await assert.rejects(scan(base + '/', opts), /Only http and https/);
  } finally { srv.close(); }
});

test('stops after too many redirects', async () => {
  const { srv, base } = await site({ '/a': [302, { Location: '/b' }], '/b': [302, { Location: '/a' }] });
  try {
    await assert.rejects(scan(base + '/a', opts), /Too many redirects/);
  } finally { srv.close(); }
});
