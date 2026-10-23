'use strict';
// Schema check for advisory files. Used at load time by core.js and by the test suite,
// so a pull request that adds a broken advisory fails `npm test` with a clear message.

const DETECTION = ['version-compare', 'not-remotely-detectable'];
const SEVERITY = ['critical', 'high', 'medium', 'low', 'unrated'];
const VERDICTS = ['vulnerable', 'unknown', 'patched', 'php-detected'];
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const BRANCH = /^\d+\.\d+$/;
const VERSION = /^\d+\.\d+\.\d+$/;

const isStr = (s) => typeof s === 'string' && s.trim().length > 0;

function checkSteps(errs, list, name, withOrder) {
  if (!Array.isArray(list)) { errs.push(`${name} must be an array`); return; }
  list.forEach((s, i) => {
    const at = `${name}[${i}]`;
    if (!s || !isStr(s.text)) errs.push(`${at}.text is required`);
    if (s && s.when !== undefined && (!Array.isArray(s.when) || !s.when.every((w) => VERDICTS.includes(w)))) errs.push(`${at}.when must be a list of: ${VERDICTS.join(', ')}`);
    if (s && s.branch !== undefined && !BRANCH.test(s.branch)) errs.push(`${at}.branch must look like "8.3"`);
    if (s && s.hasFix !== undefined && typeof s.hasFix !== 'boolean') errs.push(`${at}.hasFix must be true or false`);
    if (withOrder && s && typeof s.order !== 'number') errs.push(`${at}.order must be a number`);
  });
}

// Returns a list of problems; empty means valid.
function validateAdvisory(a) {
  const errs = [];
  if (!a || typeof a !== 'object') return ['advisory must be a JSON object'];
  if (!/^[a-z0-9-]+$/.test(a.id || '')) errs.push('id must be lowercase letters, digits and dashes');
  if (!isStr(a.name)) errs.push('name is required');
  if (!isStr(a.summary)) errs.push('summary is required');
  if (!SEVERITY.includes(a.severity)) errs.push(`severity must be one of: ${SEVERITY.join(', ')}`);
  if (!DETECTION.includes(a.detection)) errs.push(`detection must be one of: ${DETECTION.join(', ')}`);
  if (!DATE.test(a.dateAdded || '')) errs.push('dateAdded must be YYYY-MM-DD');
  if (!DATE.test(a.dateUpdated || '')) errs.push('dateUpdated must be YYYY-MM-DD');
  if (DATE.test(a.dateAdded || '') && DATE.test(a.dateUpdated || '') && a.dateUpdated < a.dateAdded) errs.push('dateUpdated is before dateAdded');

  if (!Array.isArray(a.sources) || !a.sources.length) errs.push('sources needs at least one link');
  else a.sources.forEach((s, i) => { if (!/^https:\/\/\S+$/.test(s)) errs.push(`sources[${i}] must be an https:// link`); });

  if (!Array.isArray(a.cves) || !a.cves.length) errs.push('cves needs at least one entry');
  else a.cves.forEach((c, i) => {
    if (!/^CVE-\d{4}-\d{4,}$/.test((c && c.id) || '')) errs.push(`cves[${i}].id must look like CVE-2026-12345`);
    if (!c || !isStr(c.title)) errs.push(`cves[${i}].title is required`);
    if (!c || !c.detail || !isStr(c.detail.default)) errs.push(`cves[${i}].detail.default is required`);
  });

  const af = a.affected || {};
  const fixed = af.fixed || {};
  const hasFixed = Object.keys(fixed).length > 0;
  if (!hasFixed && af.unfixed !== true) errs.push('affected needs fixed versions, or "unfixed": true when no fix exists yet');
  if (hasFixed && af.unfixed === true) errs.push('affected cannot have both fixed versions and "unfixed": true');
  for (const [b, v] of Object.entries(fixed)) {
    if (!BRANCH.test(b) || !VERSION.test(v) || !v.startsWith(b + '.')) errs.push(`affected.fixed["${b}"] = "${v}" must map a branch like "8.3" to a release like "8.3.36"`);
  }

  if (a.detection === 'version-compare') {
    if (!hasFixed) errs.push('version-compare advisories need affected.fixed');
    if (!BRANCH.test(af.minBranch || '') || !BRANCH.test(af.maxBranch || '')) errs.push('version-compare advisories need affected.minBranch and affected.maxBranch like "8.1"');
    for (const k of ['patched', 'vulnerable', 'noFix', 'newer', 'older']) if (!a.verdictText || !isStr(a.verdictText[k])) errs.push(`verdictText.${k} is required`);
    for (const k of ['vulnerable', 'unknown', 'patched']) {
      const h = a.headline && a.headline[k];
      if (!h || !isStr(h.title) || !isStr(h.sub) || !['bad', 'warn', 'ok'].includes(h.level)) errs.push(`headline.${k} needs level (bad/warn/ok), title and sub`);
    }
  }

  checkSteps(errs, a.patch, 'patch', false);
  checkSteps(errs, a.turnOff, 'turnOff', true);
  checkSteps(errs, a.covered || [], 'covered', true);
  checkSteps(errs, a.notCovered || [], 'notCovered', true);
  return errs;
}

function validateAll(list) {
  const errs = [];
  const ids = new Set();
  list.forEach((a, i) => {
    const label = (a && a.id) || `#${i}`;
    for (const e of validateAdvisory(a)) errs.push(`${label}: ${e}`);
    if (a && ids.has(a.id)) errs.push(`${label}: duplicate id`);
    if (a) ids.add(a.id);
  });
  if (!list.some((a) => a && a.detection === 'version-compare')) errs.push('at least one version-compare advisory is required');
  return errs;
}

module.exports = { validateAdvisory, validateAll, DETECTION, SEVERITY };
