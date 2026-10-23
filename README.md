# PHP2Shell Check

A **passive**, self-hosted PHP vulnerability exposure scanner with a plain-English report: what to patch, what to turn off, and what the scan can and cannot see. Runs on your own machine as an installable app (PWA), a CLI, or a Docker container. **Zero dependencies. No accounts. No one else's cloud.**

Currently checks:

| Advisory | Detection |
|---|---|
| **PHP2Shell**: CVE-2026-109618, CVE-2026-109619 (RCE, CVSS v4 9.2, exploited in the wild) | Disclosed PHP version vs fixed releases 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 |
| **CVE-2026-115560** (session serialize-handler, no fix yet) | Not remotely detectable: reported as "No fix yet", checked on the server by `local-audit.js` |

New advisories are **JSON files** in [`advisories/`](advisories/), not code changes. See [CONTRIBUTING.md](CONTRIBUTING.md).

> **It does not test the exploit.** It sends one normal GET request, reads the response headers and the first 8 KB of HTML, and compares what the site discloses with the advisory data. Only scan sites you own or have written permission to scan.

## Quick start (desktop, 1 minute)

Needs [Node.js 22+](https://nodejs.org). Nothing to `npm install`.

```bash
git clone https://github.com/CyberRick-AI/php2shell-check.git   # or Code > Download ZIP
cd php2shell-check
node server.js
```

Open **http://localhost:3000**. In Chrome or Edge, click the install icon in the address bar to get it as a desktop app.

### Try it without scanning a real site (demo mode)

Most real sites hide their PHP version, so "Can't confirm" or "No PHP detected" is a normal result. To see every verdict, run the built-in fake targets (they only send PHP-style headers; nothing leaves your machine):

```bash
npm run demo
```

Open http://localhost:3000 and scan any of these (include `http://`):

| Address | Expected result |
|---|---|
| `http://localhost:8081/vulnerable` | Vulnerable (PHP 8.3.30) |
| `http://localhost:8081/patched` | Patched (PHP 8.4.27) |
| `http://localhost:8081/eol` | Vulnerable, end-of-life PHP 7.4 with mod_php |
| `http://localhost:8081/hidden` | Can't confirm (PHP session cookie, no version) |
| `http://localhost:8081/wordpress` | Can't confirm (WordPress markers) |
| `http://localhost:8081/nophp` | No PHP detected |

CLI, prints the JSON report:

```bash
node server.js example.com
```

## Docker

```bash
docker compose up -d          # http://localhost:3000
```

The default compose file only listens on `127.0.0.1`. See the comments in [`compose.yaml`](compose.yaml) to open it to your LAN (set `ACCESS_KEY` when you do).

## On your phone

Scanning has to run on a server you control: a phone browser can't read another site's headers on its own. Installing a PWA also needs HTTPS (only `localhost` is exempt). Pick one:

| Option | Install as app? | Effort |
|---|---|---|
| **A. LAN, browser only.** Run `HOST=0.0.0.0 ACCESS_KEY=<long-random> node server.js` on your computer and open `http://<computer-ip>:3000` on the phone (same Wi-Fi). Enter the key in the app's **Access key** box. | No (plain http), works in the browser | Lowest |
| **B. Tailscale Serve.** Run the server on your computer, then `tailscale serve 3000`. Open the `https://<machine>.<tailnet>.ts.net` URL on a phone in your tailnet. | Yes | Low, free Tailscale account |
| **C. Your own free Cloudflare Worker.** Your copy on your own Cloudflare account, see [Host your own copy](#host-your-own-copy-cloudflare-workers-optional). | Yes | Medium |
| **D. Your own reverse proxy** (Caddy, nginx + Let's Encrypt) in front of `node server.js` or the Docker container. Set `ACCESS_KEY`. | Yes | Medium |

To install: **iPhone** Safari, Share, **Add to Home Screen**. **Android** Chrome, **Install app**.

## What the report shows

- Status for each CVE: Patched, Vulnerable, Can't confirm, or No fix yet
- **What needs to be patched**: exact target version, restart steps, EOL guidance
- **What needs to be turned off or changed**: settings and interim mitigations
- **What the scan covers / does NOT cover**, side by side
- Copy report and Print / Save PDF buttons

### Limits you should know

| Limit | What happens |
|---|---|
| Site hides its PHP version (`expose_php=Off`, proxy strips headers) | "Can't confirm". Use `local-audit.js` on the server |
| Distro builds (Debian, Ubuntu, RHEL) backport fixes without changing the version | Version can look old while fixed. Check the package changelog for the CVE |
| CVE-2026-115560 | No fixed PHP release exists yet; exposure depends on server config and app code |
| Workers restarted after patching? | Not visible from outside |

## Server-side audit

On a server you are authorized to audit (copy the repo, or at least `local-audit.js` + `advisories/`):

```bash
node local-audit.js /var/www/site            # add --php /path/to/php if php isn't on PATH
```

Checks the PHP version against every advisory, the php.ini settings advisories name, and greps app code for risky patterns. Read-only. Exit code 0 = clean, 1 = warnings, 2 = vulnerable.

## Layout

```
advisories/         one JSON file per advisory + index.js  <- most contributions go here
src/core.js         analysis + report builder + target validation (applies the advisory data)
src/validate.js     advisory schema check (runs at load and in tests)
src/worker.mjs      optional Cloudflare Worker: /api/scan + serves the PWA
server.js           local server + CLI (same UI, same analysis)
local-audit.js      run ON a server you are authorized to audit
public/             the PWA (index.html, manifest, service worker, icons)
test/               node:test suites + report snapshot fixtures
Dockerfile, compose.yaml
```

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `PORT` | `3000` | Port |
| `HOST` | `127.0.0.1` | Bind address. `0.0.0.0` for LAN/Docker |
| `ACCESS_KEY` | (none) | If set, scans need this key (the app asks once). **Set it whenever the server is reachable by anyone but you** |
| `ALLOW_PRIVATE` | (off) | `1` lifts the private-address guard, for testing your own LAN servers only |

## Safeguards

- Passive only: one GET, no exploit traffic, no probes
- Consent checkbox before every scan
- Blocks localhost, private and link-local ranges, IPv6 literals, single-label hosts, `.local`/`.internal` names, embedded credentials, and ports other than 80/443/8080/8443
- Local server pins the resolved IP so DNS rebinding can't swap in an internal address
- Hidden version = "can't confirm", never a false pass
- Responses are never cached; the service worker never touches `/api/`

## Host your own copy (Cloudflare Workers, optional)

Only if you want an always-on HTTPS instance on **your own** free Cloudflare account. There is no shared public instance.

```bash
npx wrangler login
npx wrangler secret put ACCESS_KEY      # private mode (default): long random key
npx wrangler deploy
```

The Worker **fails closed**: with no `ACCESS_KEY` and `PUBLIC_MODE` off it refuses to scan. `PUBLIC_MODE = "1"` in `wrangler.toml` removes the key and rate-limits each IP to 10 scans/min instead. That turns your Worker into a scanner anyone with the link can use, so think twice.

## Development

```bash
npm test             # all suites, no install needed (Node 22+)
npm run snapshot     # re-record report snapshots after an intentional text change
```

CI runs `npm test` on every pull request.

## Contributing

Pull requests welcome, especially new advisories and updates when PHP ships fixes. Read [CONTRIBUTING.md](CONTRIBUTING.md) first. **No exploit payloads or active probes.** Report security problems in this tool via [SECURITY.md](SECURITY.md).

## Use responsibly

Only scan sites you own or have written permission to scan. Advisory data is a snapshot (see each file's `dateUpdated`); re-check the [PHP security advisories](https://www.php.net/) before telling a client they are covered.

## License

[MIT](LICENSE) © 2026 CyberRick AI. Built with the [AI Builders Guild](https://github.com/ai-builders-guild).
