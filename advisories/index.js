'use strict';
// Every advisory the scanner knows about, in report order.
// Adding one: drop a JSON file in this folder, add it here, run `npm test`.
// (A static list, not a directory read, so the Cloudflare Worker bundler can include them.)
module.exports = [
  require('./php2shell.json'),
  require('./cve-2026-115560.json'),
];
