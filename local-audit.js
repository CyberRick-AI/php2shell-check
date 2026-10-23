#!/usr/bin/env node
// Local PHP audit for PHP2Shell (CVE-2026-109618 / -109619) and CVE-2026-115560.
// Run ON the server you are authorized to audit:  node local-audit.js [/path/to/webroot] [--php /path/to/php]
// Read-only: runs `php -v` / `php -i` and greps source for ini_set('session.serialize_handler').
// Checks come from advisories/*.json (the same data the scanner uses). Zero dependencies.

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const phpIdx = args.indexOf('--php');
const PHP = phpIdx >= 0 ? args.splice(phpIdx, 2)[1] : 'php';
const webroot = args[0];

const ADVISORIES = require('./advisories');
const fill = (text, vars) => text.replace(/\{(\w+)\}/g, (m, k) => (vars[k] == null ? m : String(vars[k])));
const cmp = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
const parseVer = (s) => s.split('.').map(Number);
const out = [];
const add = (level, msg) => out.push({ level, msg });

function php(a) {
  return execFileSync(PHP, a, { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'ignore'] });
}

let ver = null;
try {
  const m = /PHP (\d+)\.(\d+)\.(\d+)/.exec(php(['-v']));
  ver = m ? [+m[1], +m[2], +m[3]] : null;
} catch { add('WARN', `Could not run "${PHP}". Use --php /path/to/php. Note: CLI PHP can differ from the PHP serving web requests (check php-fpm -v / apache modules too).`); }

// --- version checks (version-compare advisories) ---
if (ver) {
  const branch = `${ver[0]}.${ver[1]}`;
  for (const a of ADVISORIES.filter((x) => x.detection === 'version-compare')) {
    const fixed = a.affected.fixed[branch];
    const vars = { version: ver.join('.'), branch, fixed };
    if (fixed) {
      if (cmp(ver, parseVer(fixed)) >= 0) add('OK', fill(a.localAudit.patched, vars));
      else add('FAIL', fill(a.localAudit.vulnerable, vars));
    } else {
      add('FAIL', fill(a.localAudit.noFix, vars));
    }
  }
}

// --- php.ini settings named by advisories ---
const iniChecks = ADVISORIES.flatMap((a) => (a.localAudit && a.localAudit.ini) || []);
let info = null;
if (iniChecks.length) { try { info = php(['-i']); } catch { /* already warned */ } }
if (info) {
  const g = (k) => { const m = new RegExp('^' + k.replace(/\./g, '\\.') + ' => (.*?) =>', 'm').exec(info); return m ? m[1].trim() : null; };
  for (const c of iniChecks) {
    const value = g(c.key);
    if (value === null) continue;
    if (c.info) add('INFO', fill(c.info, { value }));
    else if (/^(1|on|true|yes)$/i.test(value)) add(c.on, c.onText);
    else add(c.off, c.offText);
  }
  add('INFO', 'CLI php -i may not match the web SAPI config. Compare with the php.ini / pool config actually used by Apache or FPM.');
}

// --- source grep (patterns named by advisories) ---
const greps = ADVISORIES.map((a) => a.localAudit && a.localAudit.sourceGrep).filter(Boolean);
if (webroot && greps.length) {
  const hits = greps.map(() => []);
  const res = greps.map((x) => new RegExp(x.pattern));
  const skip = new Set(['node_modules', '.git', 'vendor']);
  let scanned = 0;
  (function walk(dir, depth) {
    if (depth > 12 || scanned > 50000) return;
    let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (!skip.has(e.name)) walk(p, depth + 1); }
      else if (/\.(php|inc|phtml)$/i.test(e.name)) {
        scanned++;
        let txt; try { if (fs.statSync(p).size > 2e6) continue; txt = fs.readFileSync(p, 'utf8'); } catch { continue; }
        txt.split('\n').forEach((line, i) => { res.forEach((re, j) => { if (re.test(line)) hits[j].push(`${p}:${i + 1}: ${line.trim().slice(0, 140)}`); }); });
      }
    }
  })(webroot, 0);
  // vendor/ is skipped for speed; rerun on vendor dirs if the app is heavily plugin-based
  greps.forEach((x, j) => {
    if (hits[j].length) add('WARN', fill(x.hitText, { count: hits[j].length }) + '\n    ' + hits[j].slice(0, 25).join('\n    '));
    else add('OK', x.cleanText);
  });
} else if (!webroot) {
  add('INFO', 'No webroot given, so app code was not checked. Re-run: node local-audit.js /var/www/site');
}

for (const a of ADVISORIES) for (const n of (a.localAudit && a.localAudit.notes) || []) add('INFO', n);

const tag = { OK: '[ OK ]', WARN: '[WARN]', FAIL: '[FAIL]', INFO: '[INFO]' };
for (const o of out) console.log(`${tag[o.level]} ${o.msg}`);
process.exitCode = out.some((o) => o.level === 'FAIL') ? 2 : out.some((o) => o.level === 'WARN') ? 1 : 0;
