const test = require('node:test');
const assert = require('node:assert');
const core = require('../src/core');

const scan = (headers, cookies = '', body = '') => core.analyze({ headers, cookies, body });

test('version boundaries per branch', () => {
  const v = (s) => core.evaluate(core.parseVer(s)).verdict;
  assert.strictEqual(v('8.5.11'), 'vulnerable');
  assert.strictEqual(v('8.5.12'), 'patched');
  assert.strictEqual(v('8.4.26'), 'vulnerable');
  assert.strictEqual(v('8.4.27'), 'patched');
  assert.strictEqual(v('8.3.35'), 'vulnerable');
  assert.strictEqual(v('8.3.36'), 'patched');
  assert.strictEqual(v('8.2.34'), 'vulnerable');
  assert.strictEqual(v('8.2.35'), 'patched');
  assert.strictEqual(v('8.1.30'), 'vulnerable'); // EOL, no upstream fix
  assert.strictEqual(v('7.4.33'), 'vulnerable');
  assert.strictEqual(v('8.6.0'), 'unknown');
  assert.strictEqual(v('5.3.29'), 'unknown');
});

test('vulnerable site: patch target and interim mitigations', () => {
  const r = scan({ 'x-powered-by': 'PHP/8.3.30', server: 'Apache/2.4 (Ubuntu)' });
  assert.strictEqual(r.verdict, 'vulnerable');
  assert.strictEqual(r.phpVersion, '8.3.30');
  assert.match(r.report.patch[0], /8\.3\.36/);
  assert.ok(r.report.disable.some((x) => /session\.upload_progress\.enabled=0/.test(x)));
  assert.ok(r.report.disable.some((x) => /memory_limit=-1/.test(x)));
  assert.ok(r.report.notes.some((x) => /distro/i.test(x)));
});

test('patched site still gets the CVE-2026-115560 setting', () => {
  const r = scan({ 'x-powered-by': 'PHP/8.4.27' });
  assert.strictEqual(r.verdict, 'patched');
  assert.strictEqual(r.report.headline.level, 'ok');
  assert.ok(r.report.disable[0].includes('session.upload_progress.enabled=0'));
  const c = r.report.cves.find((x) => x.id === 'CVE-2026-115560');
  assert.strictEqual(c.status, 'unfixed');
});

test('hidden version is unknown, never a false pass', () => {
  const r = scan({ server: 'nginx' }, 'PHPSESSID=abc; path=/');
  assert.strictEqual(r.verdict, 'unknown');
  assert.strictEqual(r.phpVersion, null);
});

test('no PHP signals', () => {
  const r = scan({ server: 'nginx' });
  assert.strictEqual(r.verdict, 'not-detected');
  assert.strictEqual(r.report.disable.length, 0);
});

test('PHP version in Server header and mod_php note', () => {
  const r = scan({ server: 'Apache/2.4.58 PHP/8.2.30 mod_php' });
  assert.strictEqual(r.verdict, 'vulnerable');
  assert.ok(r.report.notes.some((x) => /mod_php/.test(x)));
});

test('Cloudflare detection', () => {
  assert.ok(scan({ 'x-powered-by': 'PHP/8.3.36', 'cf-ray': 'x' }).report.notes.some((x) => /Cloudflare/.test(x)));
  assert.ok(scan({ 'x-powered-by': 'PHP/8.3.36', server: 'cloudflare' }).report.notes.some((x) => /Cloudflare/.test(x)));
});

test('target validation blocks internal and odd addresses', () => {
  const bad = ['localhost', 'http://127.0.0.1', 'http://10.0.0.5/', 'https://192.168.1.1', 'http://169.254.169.254/latest',
    'http://[::1]/', 'http://2130706433/', 'http://0x7f.1/', 'intranet', 'printer.local', 'http://user:pw@example.com',
    'ftp://example.com', 'example.com:22', 'http://172.16.0.1', 'http://100.64.0.1'];
  for (const b of bad) assert.throws(() => core.normalizeTarget(b), undefined, b);
  assert.throws(() => core.normalizeTarget(''));
  assert.throws(() => core.normalizeTarget('a'.repeat(400)));
});

test('target validation accepts normal sites', () => {
  assert.strictEqual(core.normalizeTarget('example.com').href, 'https://example.com/');
  assert.strictEqual(core.normalizeTarget('http://example.com:8080/x').port, '8080');
  assert.strictEqual(core.normalizeTarget('  Example.COM  ').hostname, 'example.com');
  assert.doesNotThrow(() => core.normalizeTarget('127.0.0.1', { allowPrivate: true }));
});
