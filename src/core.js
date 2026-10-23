'use strict';
// Shared, dependency-free logic used by the Cloudflare Worker, the local Node server and the tests.
// Passive analysis only: this module never sends network traffic.
// What to check for lives in ../advisories/*.json; this file only knows how to apply it.

const ADVISORIES = require('../advisories');
const { validateAll } = require('./validate');

const problems = validateAll(ADVISORIES);
if (problems.length) throw new Error('Invalid advisory data:\n  ' + problems.join('\n  '));

const VERSIONED = ADVISORIES.filter((a) => a.detection === 'version-compare');

function parseVer(s) {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(s || '');
  return m ? [+m[1], +m[2], +m[3]] : null;
}
const cmp = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
const branchCmp = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); return x[0] - y[0] || x[1] - y[1]; };

// First fixed version per branch of the primary advisory, as arrays (kept for callers and tests).
const FIXED = Object.fromEntries(Object.entries(VERSIONED[0].affected.fixed).map(([b, v]) => [b, parseVer(v)]));

// Replaces {name} placeholders in advisory text.
const fill = (text, vars) => text.replace(/\{(\w+)\}/g, (m, k) => (vars[k] == null ? m : String(vars[k])));

// ---- target validation (SSRF / abuse guards) ----
function isPrivateIPv4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || a >= 224 || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19));
}

function isPrivateHost(host) {
  const h = String(host).toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || /\.(localhost|local|internal|lan|home\.arpa|corp|intranet)$/.test(h)) return true;
  if (h.includes(':')) return true; // block all IPv6 literals
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return isPrivateIPv4(h);
  if (!h.includes('.')) return true; // single-label names like "intranet"
  return false;
}

const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']);

// Returns a URL object or throws Error with a user-facing message.
function normalizeTarget(raw, { allowPrivate = false } = {}) {
  const s = String(raw || '').trim();
  if (!s) throw new Error('Enter a website address');
  if (s.length > 300) throw new Error('Address too long');
  let u;
  try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : 'https://' + s); }
  catch { throw new Error('That does not look like a valid address'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('Only http and https addresses are supported');
  if (u.username || u.password) throw new Error('Remove the username/password from the address');
  if (!allowPrivate && isPrivateHost(u.hostname)) throw new Error('Private, internal and local addresses are blocked');
  if (!allowPrivate && !ALLOWED_PORTS.has(u.port)) throw new Error('Only ports 80, 443, 8080 and 8443 are allowed');
  return u;
}

// Verdict for one version-compare advisory: { verdict, text } or null when no version is known.
function evaluate(version, advisory = VERSIONED[0]) {
  if (!version) return null;
  const { fixed, minBranch, maxBranch } = advisory.affected;
  const branch = `${version[0]}.${version[1]}`;
  const vars = { version: version.join('.'), branch, fixed: fixed[branch], minBranch, maxBranch };
  const t = (k) => fill(advisory.verdictText[k], vars);
  if (fixed[branch]) return cmp(version, parseVer(fixed[branch])) >= 0 ? { verdict: 'patched', text: t('patched') } : { verdict: 'vulnerable', text: t('vulnerable') };
  if (branchCmp(branch, maxBranch) > 0) return { verdict: 'unknown', text: t('newer') };
  if (branchCmp(branch, minBranch) < 0) return { verdict: 'unknown', text: t('older') };
  return { verdict: 'vulnerable', text: t('noFix') };
}

const RANK = { vulnerable: 3, unknown: 2, patched: 1, 'not-detected': 0 };

// A step applies when its `when` matches (verdict, or "php-detected" for any PHP site) and its branch / hasFix filters match.
function applies(step, { verdict, branch, hasFix }) {
  const phpFamily = verdict !== 'not-detected';
  if (step.when && !step.when.some((w) => w === verdict || (w === 'php-detected' && phpFamily))) return false;
  if (step.branch && step.branch !== branch) return false;
  if (step.hasFix !== undefined && step.hasFix !== hasFix) return false;
  return true;
}

const byOrder = (items) => items.map((x, i) => ({ ...x, i })).sort((a, b) => a.order - b.order || a.i - b.i).map((x) => x.text);

// Not tied to one advisory: what a passive header check can and cannot see.
const BASE_COVERED = [
  { order: 20, text: 'Signs the site runs PHP (PHPSESSID cookie, WordPress markers, PHP banners)' },
  { order: 30, text: 'Server hints that raise risk (mod_php) and Cloudflare in front' },
];
const BASE_NOT_COVERED = [
  { order: 10, text: 'Whether the exploit actually works. This is a passive check; it sends no attack traffic' },
  { order: 20, text: 'Sites that hide their version (expose_php=Off or a proxy strips headers). They come back "unknown"' },
  { order: 30, text: 'Distro backports: a fixed package can show an old version number' },
  { order: 50, text: 'session.upload_progress.enabled, memory limits and other settings: not visible from outside' },
  { order: 70, text: 'Other PHP, CMS or plugin vulnerabilities' },
  { order: 80, text: 'Multiple PHP versions behind one domain, or a different PHP on the CLI than on the web' },
];
const NOT_DETECTED = {
  headline: { level: 'neutral', title: 'No PHP detected', sub: 'Nothing here points to PHP. This is not proof the site is safe.' },
  patch: 'No PHP found at this address. If PHP runs on a separate backend or origin, scan that address instead.',
};

// ---- Report builder: turns raw findings into what to patch / what to turn off ----
// results: [{ advisory, verdict }] for every advisory, verdict per advisory.
function buildReport({ version, verdict, results, modPhp, cloudflare, distro }) {
  const branch = version ? `${version[0]}.${version[1]}` : null;
  const phpFamily = verdict !== 'not-detected';
  const lead = results.find((r) => r.advisory.detection === 'version-compare' && r.verdict === verdict);
  const headline = phpFamily ? lead.advisory.headline[verdict] : NOT_DETECTED.headline;

  const cves = [];
  const patch = [];
  const turnOff = [];
  const covered = [...BASE_COVERED];
  const notCovered = [...BASE_NOT_COVERED];
  for (const { advisory: a, verdict: v } of results) {
    const fixed = a.affected.fixed || {};
    const vars = {
      version: version && version.join('.'), branch, fixed: fixed[branch],
      fixedList: Object.values(fixed).join(', '), minBranch: a.affected.minBranch,
    };
    const status = a.detection === 'version-compare' ? v : (phpFamily ? 'unfixed' : 'not-detected');
    for (const c of a.cves) cves.push({ id: c.id, title: c.title, status, detail: (status === 'patched' && c.detail.patched) || c.detail.default });
    const ctx = { verdict: v, branch, hasFix: !!fixed[branch] };
    for (const s of a.patch) if (applies(s, ctx)) patch.push(fill(s.text, vars));
    for (const s of a.turnOff) if (applies(s, ctx)) turnOff.push({ order: s.order, text: fill(s.text, vars) });
    for (const s of a.covered || []) covered.push({ order: s.order, text: fill(s.text, vars) });
    for (const s of a.notCovered || []) notCovered.push({ order: s.order, text: fill(s.text, vars) });
  }
  if (!phpFamily) patch.push(NOT_DETECTED.patch);

  const notes = [];
  if (modPhp) notes.push('Server banner mentions mod_php, the highest-risk setup: a demonstrated exploit triggers before any app code runs.');
  if (cloudflare) notes.push('Behind Cloudflare: its WAF rules help, but attackers are changing payloads to get around them. Treat it as a stopgap, not a fix.');
  if (distro) notes.push('This looks like a distro build. Vendors backport fixes without changing version numbers, so check the package changelog before trusting the version string.');

  return { headline, cves, patch, disable: byOrder(turnOff), notes, covered: byOrder(covered), notCovered: byOrder(notCovered) };
}

// headers: plain object with lowercase keys. cookies: joined Set-Cookie string. body: first few KB of HTML.
function analyze({ headers = {}, cookies = '', body = '' }) {
  const evidence = [];
  const poweredBy = String(headers['x-powered-by'] || '');
  const server = String(headers.server || '');
  let version = /php/i.test(poweredBy) ? parseVer(poweredBy) : null;
  if (version) evidence.push(`X-Powered-By: ${poweredBy.slice(0, 120)}`);
  if (!version && /php\/\d/i.test(server)) { version = parseVer(server.split(/php\//i)[1]); evidence.push(`Server: ${server.slice(0, 120)}`); }

  const looksPhp = !!version || /php/i.test(poweredBy) || /PHPSESSID/.test(cookies) ||
    /wp-content|wp-includes|\/sites\/default\/|Joomla|laravel_session/i.test(body + cookies);
  if (/PHPSESSID/.test(cookies)) evidence.push('PHPSESSID cookie set');
  if (/wp-content|wp-includes/.test(body)) evidence.push('WordPress markers in HTML');
  const modPhp = /mod_php/i.test(server);
  if (modPhp) evidence.push('Server banner mentions mod_php');
  if (/litespeed/i.test(server)) evidence.push('LiteSpeed server');
  const cloudflare = !!headers['cf-ray'] || /^cloudflare$/i.test(server);
  if (cloudflare) evidence.push('Behind Cloudflare');

  const fallback = looksPhp
    ? { verdict: 'unknown', text: 'Site looks like PHP but does not disclose its version.' }
    : { verdict: 'not-detected', text: 'No PHP indicators found.' };
  const results = ADVISORIES.map((advisory) => {
    const r = (advisory.detection === 'version-compare' && evaluate(version, advisory)) || fallback;
    return { advisory, verdict: r.verdict, text: r.text };
  });
  // Overall verdict = the worst result across version-compare advisories (first one wins ties).
  const result = results.filter((r) => r.advisory.detection === 'version-compare')
    .reduce((worst, r) => (RANK[r.verdict] > RANK[worst.verdict] ? r : worst));
  const distro = !!version && /debian|ubuntu|el\d|rhel|centos|alma|rocky/i.test(poweredBy + server);

  return {
    phpVersion: version ? version.join('.') : null,
    evidence,
    verdict: result.verdict,
    text: result.text,
    report: buildReport({ version, verdict: result.verdict, results, modPhp, cloudflare, distro }),
    caveat: 'Passive check: reads response headers only. It does not test the exploit.',
  };
}

module.exports = { ADVISORIES, FIXED, parseVer, evaluate, buildReport, analyze, normalizeTarget, isPrivateHost, isPrivateIPv4 };
