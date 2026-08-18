# Contributing to CyberBuddy

Thanks for helping make CyberBuddy more accurate, safe, and useful. The project
is intentionally dependency-light: static HTML/CSS/JavaScript and Python 3.10+
standard-library engines.

## Before opening an issue

- Use the issue templates for reproducible bugs and focused feature requests.
- Do not include live credentials, tokens, private target URLs, or customer
  data. Replace them with minimal synthetic examples.
- Report vulnerabilities in CyberBuddy itself privately as described in
  [SECURITY.md](SECURITY.md), not in a public issue.
- Only test systems you own or have written permission to assess.

## Development setup

```bash
git clone https://github.com/AmitPal-CyberBuddy/CyberBuddy.git
cd CyberBuddy
python3 server.py
# open http://127.0.0.1:8080/
```

No project package installation or production build step is required. The
default server bind is loopback-only. Do not use `--allow-private` unless your
authorized test case requires it and you understand the network exposure.

## Verification

Run the release gate before submitting a pull request:

```bash
python3 tools/verify.py
```

It runs the stdlib unit suite, Python and JavaScript syntax checks, structured
metadata parsing, a clean Pages-shaped assembly, and local link/fragment
validation. The gate expects Git, Python 3.10+, and Node.js (CI uses Node 20);
Node is used only for dependency-free `node --check` validation. Browser
regressions require Chromium plus `puppeteer-core`; setup and commands are
documented in [`tests/browser/README.md`](tests/browser/README.md).

For a focused engine run:

```bash
python3 -m unittest test_engines.py -v
```

## Project conventions

- Keep runtime Python dependency-free unless there is a compelling, documented
  reason to change that contract.
- Treat `security_headers.py`, `cors_validator.py`, `csp_checker.py`, and
  `dns_security.py` as the canonical Python grading engines. Browser graders
  must stay parity-tested against the same fixtures.
- Add or update tests with behavioral changes, especially for scoring, SSRF,
  credential redaction, CORS method coverage, and hostile pasted input.
- Never weaken cloud-metadata/link-local blocking or bypass connect-time DNS
  rebinding validation.
- Escape untrusted values before inserting them into HTML. Generated CSRF/JWT
  artifacts must remain inert inside CyberBuddy.
- Keep public claims precise: network checks are non-destructive, but CORS may
  use HEAD, OPTIONS, and preflight simulation in addition to a GET baseline.
- A new tool must be represented in the shared `TOOLS_MENU` registry, its
  no-JavaScript fallback, guides/docs/metadata, sitemap, PWA manifest, tests,
  and Pages publication surface.

The implementation notes in [`docs/DEV-NOTES.md`](docs/DEV-NOTES.md) capture
important cross-surface and security traps. The public scoring contract is the
[methodology page](https://amitpal-cyberbuddy.github.io/CyberBuddy/methodology/).

## Pull requests

Keep pull requests focused and explain:

1. what changed and why;
2. the security/privacy impact;
3. tests run and their results;
4. screenshots for visible UI changes at desktop and mobile widths; and
5. any hosted Pages versus local-engine behavior differences.

By contributing, you agree that your contribution is licensed under the
project's [Apache-2.0 License](LICENSE) and to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
