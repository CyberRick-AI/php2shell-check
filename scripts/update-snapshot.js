#!/usr/bin/env node
// Re-records test/fixtures/snapshot.json after an intentional change to advisory text or report logic.
// Run `npm run snapshot`, then review the diff in git before committing: every changed line should be on purpose.
const fs = require('fs');
const path = require('path');
const core = require('../src/core');

const dir = path.join(__dirname, '..', 'test', 'fixtures');
const cases = require(path.join(dir, 'cases.json'));
const out = {};
for (const c of cases) out[c.name] = core.analyze({ headers: c.headers, cookies: c.cookies || '', body: c.body || '' });
fs.writeFileSync(path.join(dir, 'snapshot.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`Recorded ${cases.length} cases to test/fixtures/snapshot.json`);
