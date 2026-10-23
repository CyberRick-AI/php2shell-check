const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const AUDIT = path.join(__dirname, '..', 'local-audit.js');

// A fake `php` binary so the audit can be tested without PHP installed.
function fakePhp(dir, version, ini) {
  const js = path.join(dir, 'php.js');
  fs.writeFileSync(js, `process.stdout.write(process.argv[2] === '-v' ? ${JSON.stringify(`PHP ${version} (cli)\n`)} : ${JSON.stringify(ini)});`);
  const bin = path.join(dir, process.platform === 'win32' ? 'php.cmd' : 'php');
  fs.writeFileSync(bin, process.platform === 'win32' ? `@node "${js}" %*\r\n` : `#!/bin/sh\nexec "${process.execPath}" "${js}" "$@"\n`, { mode: 0o755 });
  return bin;
}

function audit(version, ini, files = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'p2s-audit-'));
  const www = path.join(dir, 'www');
  fs.mkdirSync(www);
  for (const [f, c] of Object.entries(files)) fs.writeFileSync(path.join(www, f), c);
  const r = spawnSync(process.execPath, [AUDIT, www, '--php', fakePhp(dir, version, ini)], { encoding: 'utf8' });
  fs.rmSync(dir, { recursive: true, force: true });
  return r;
}

const ON = 'session.upload_progress.enabled => On => On\nsession.serialize_handler => php => php\n';
const OFF = 'session.upload_progress.enabled => Off => Off\nsession.serialize_handler => php => php\n';

test('vulnerable PHP exits 2 with the fixed target from advisory data', () => {
  const r = audit('8.3.30', ON, { 'i.php': "<?php ini_set('session.serialize_handler', 'php');" });
  assert.strictEqual(r.status, 2);
  assert.match(r.stdout, /\[FAIL\] PHP 8\.3\.30 < 8\.3\.36/);
  assert.match(r.stdout, /\[WARN\] session\.upload_progress\.enabled is ON/);
  assert.match(r.stdout, /Found 1 reference/);
});

test('patched PHP with upload progress off exits 0', () => {
  const r = audit('8.4.27', OFF, { 'i.php': '<?php echo 1;' });
  assert.strictEqual(r.status, 0, r.stdout);
  assert.match(r.stdout, /\[ OK \] PHP 8\.4\.27 >= 8\.4\.27/);
  assert.match(r.stdout, /No references to session\.serialize_handler/);
});

test('end-of-life branch is reported as having no upstream fix', () => {
  const r = audit('7.4.33', OFF);
  assert.strictEqual(r.status, 2);
  assert.match(r.stdout, /PHP 7\.4 is end-of-life upstream/);
});
