# Security Policy

## Reporting a problem in this tool

If you find a security issue **in PHP2Shell Check itself** (for example an SSRF bypass of the private-address guard, a way to make it send non-passive traffic, XSS in the report UI, or an access-key bypass), please **do not open a public issue**.

Use GitHub's private reporting: **Security** tab > **Report a vulnerability** on this repository. Include steps to reproduce and the version/commit.

We aim to acknowledge within 3 business days and fix confirmed issues as fast as practical.

## Reporting a new PHP vulnerability

New PHP advisories are public information. Open an issue with the **New advisory / advisory update** template, or send a PR (see [CONTRIBUTING.md](CONTRIBUTING.md)). Never include exploit code or payloads.

## Scope

- In scope: the scanner (`server.js`, `src/`), `local-audit.js`, the PWA in `public/`, the Worker.
- Out of scope: vulnerabilities in sites you scanned with it (report those to the site owner), and anyone's self-hosted deployment config.

## Supported versions

Only the latest `main` is supported.
