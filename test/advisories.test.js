const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const ADVISORIES = require('../advisories');
const { validateAdvisory, validateAll } = require('../src/validate');
const core = require('../src/core');

const DIR = path.join(__dirname, '..', 'advisories');
const clone = (o) => JSON.parse(JSON.stringify(o));

test('every advisory file passes the schema', () => {
  for (const a of ADVISORIES) assert.deepStrictEqual(validateAdvisory(a), [], a.id);
  assert.deepStrictEqual(validateAll(ADVISORIES), []);
});

test('every JSON file in advisories/ is listed in advisories/index.js', () => {
  const files = fs.readdirSync(DIR).filter((f) => f.endsWith('.json'));
  const listed = new Set(ADVISORIES.map((a) => a.id));
  for (const f of files) {
    const a = JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8'));
    assert.ok(listed.has(a.id), `${f} is not in advisories/index.js`);
    assert.strictEqual(f, a.id + '.json', `${f}: file name must match its id`);
  }
});

test('schema rejects advisories missing sources, dates or fix status', () => {
  const base = ADVISORIES[0];
  const broken = [
    (a) => { a.sources = []; },
    (a) => { a.sources = ['http://insecure.example']; },
    (a) => { delete a.dateAdded; },
    (a) => { a.dateUpdated = '2020-01-01'; },
    (a) => { a.affected = {}; },
    (a) => { a.affected.fixed['8.3'] = '8.4.1'; },
    (a) => { a.detection = 'active-probe'; },
    (a) => { a.cves[0].id = 'CVE-nope'; },
    (a) => { a.turnOff[0].when = ['sometimes']; },
    (a) => { delete a.headline.patched; },
  ];
  for (const breakIt of broken) {
    const a = clone(base);
    breakIt(a);
    assert.ok(validateAdvisory(a).length > 0, breakIt.toString());
  }
});

test('unfixed advisories must say so explicitly', () => {
  const a = clone(ADVISORIES.find((x) => x.affected.unfixed));
  assert.deepStrictEqual(validateAdvisory(a), []);
  delete a.affected.unfixed;
  assert.ok(validateAdvisory(a).some((e) => /unfixed/.test(e)));
});

test('report output matches the recorded snapshot', () => {
  const cases = require('./fixtures/cases.json');
  const snap = require('./fixtures/snapshot.json');
  for (const c of cases) {
    assert.deepStrictEqual(core.analyze({ headers: c.headers, cookies: c.cookies || '', body: c.body || '' }), snap[c.name], c.name);
  }
});
