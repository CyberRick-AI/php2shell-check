# Contributing

Thanks for helping. This project is maintained by CyberRick AI with the AI Builders Guild. Fork it, branch, send a PR.

## Ground rules (read these first)

1. **Passive only.** The scanner sends one ordinary GET and reads headers + the first 8 KB of HTML. PRs that add exploit payloads, crash triggers, fuzzing, path brute-forcing, or any "active probe" will be declined, even if gated behind a flag. A working PHP2Shell probe is a weapon.
2. **Honest verdicts.** Never turn "can't tell" into a pass. Hidden version = `unknown`. An advisory with no fix is `unfixed`, never `patched`.
3. **Sources for every claim.** Each advisory needs at least one https link to a primary or reputable source (vendor advisory, NVD, CERT, a named security firm).
4. **Zero runtime dependencies.** Node built-ins only. Dev tooling is fine if it isn't needed to run.
5. **Keep `npm test` green.** CI runs it on every PR.
6. **Responsible use.** Docs and UI must keep the consent gate and "only scan what you're authorized to" wording.

## Dev setup

```bash
git clone https://github.com/<you>/php2shell-check.git
cd php2shell-check
node server.js        # http://localhost:3000
npm test              # Node 22+
```

## Adding or updating an advisory (the common PR)

Advisories live in [`advisories/`](advisories/). Each is one JSON file; `src/core.js` applies them, and `local-audit.js` reads the same files, so both tools stay in sync.

### 1. Create the file

`advisories/<id>.json`, where `<id>` is lowercase with dashes and **matches the file name**. Start by copying the closest existing file:

- `php2shell.json`: **version-compare**, a bug fixed in specific releases. The scanner compares the disclosed PHP version per branch.
- `cve-2026-115560.json`: **not-remotely-detectable**, no fix or exposure depends on config/code. Reported as "No fix yet" on PHP sites; `local-audit.js` checks it on the server.

### 2. Fields

| Field | Required | Notes |
|---|---|---|
| `id`, `name`, `summary` | yes | |
| `severity` | yes | `critical`, `high`, `medium`, `low`, `unrated` |
| `detection` | yes | `version-compare` or `not-remotely-detectable` |
| `dateAdded`, `dateUpdated` | yes | `YYYY-MM-DD` |
| `sources` | yes | https links, at least one |
| `cves[]` | yes | `id` (CVE-YYYY-NNNN), `title`, `detail.default`, optional `detail.patched` |
| `affected.fixed` | version-compare | `{ "8.3": "8.3.36" }`: first fixed release per branch |
| `affected.minBranch` / `maxBranch` | version-compare | Oldest affected branch / newest branch the advisory covers. Branches in between with no fixed release are reported as "no upstream fix" |
| `affected.unfixed` | if no fix | `true`. You must say this explicitly; it's an error to leave both out |
| `verdictText`, `headline` | version-compare | One-line verdicts and the report banner, see `php2shell.json` |
| `patch[]` | yes (may be empty) | "What needs to be patched" steps, in order |
| `turnOff[]` | yes (may be empty) | "What needs to be turned off or changed", with `order` to interleave across advisories |
| `covered[]`, `notCovered[]` | optional | Extra lines for the coverage lists, with `order` |
| `localAudit` | optional | What `local-audit.js` checks on the server: `patched`/`vulnerable`/`noFix` messages, `ini` settings, `sourceGrep` pattern, `notes` |

Steps (`patch`, `turnOff`) are filtered by:

- `when`: list of verdicts it applies to: `vulnerable`, `unknown`, `patched`, or `php-detected` (any site that looks like PHP)
- `branch`: only for that branch, e.g. `"8.2"`
- `hasFix`: `true` only when the site's branch has a fixed release, `false` only when it doesn't

Text placeholders: `{version}`, `{branch}`, `{fixed}` (fixed release for the site's branch), `{fixedList}`, `{minBranch}`. In `localAudit`: `{value}` (ini value), `{count}` (grep hits).

### 3. Register it

Add a line to [`advisories/index.js`](advisories/index.js). It's a static list so the Cloudflare bundler can include the files. A test fails if a JSON file isn't listed.

### 4. Test

```bash
npm test
```

The schema check (`src/validate.js`) runs at load time and in `test/advisories.test.js`. It rejects missing sources, bad dates, missing fix status, unknown `when` values and so on, with a message naming the field.

Adding an advisory **changes the report**, so the snapshot test will fail. That's expected:

```bash
npm run snapshot      # re-record test/fixtures/snapshot.json
git diff test/fixtures/snapshot.json   # review: every changed line should be on purpose
```

If your advisory has new edge cases (a new branch, an EOL rule), add a case to `test/fixtures/cases.json` and an assertion in `test/core.test.js`.

### Worked example: PHP ships the CVE-2026-115560 fix

Say PHP releases 8.5.13 / 8.4.28 / 8.3.37 with the fix. In `advisories/cve-2026-115560.json`:

```jsonc
"detection": "version-compare",              // now detectable by version
"dateUpdated": "2026-11-05",
"affected": {
  "minBranch": "8.3", "maxBranch": "8.5",     // use the advisory's real affected range
  "fixed": { "8.5": "8.5.13", "8.4": "8.4.28", "8.3": "8.3.37" }
},                                            // and remove "unfixed": true
"verdictText": { ... },                       // copy the shape from php2shell.json
"headline": { ... },
"patch": [
  { "when": ["vulnerable"], "hasFix": true, "text": "Update PHP {branch} from {version} to {fixed} or newer for CVE-2026-115560." }
],
"sources": [ "...", "https://www.php.net/ChangeLog-8.php#..." ]
```

Then `npm test`, `npm run snapshot`, review the diff, and open a PR using the **New advisory / advisory update** template.

## Other contributions

- **Fingerprinting** (new passive signals for PHP or its version): extend `analyze()` in `src/core.js`. Must come from the single GET we already make. Add tests.
- **UI**: `public/index.html` is plain HTML/JS. Keep it dependency-free and working offline (service worker caches the shell).
- **Bugs**: open an issue with the bug template first if it's not obvious.

## PR checklist

- [ ] `npm test` passes locally
- [ ] No active probes, payloads or new outbound requests
- [ ] Advisory changes have sources and an updated `dateUpdated`
- [ ] Snapshot re-recorded only for intentional changes
- [ ] README/CONTRIBUTING updated if behavior changed

Commit style: `feat:`, `fix:`, `docs:`, `test:`, `chore:` prefixes.
