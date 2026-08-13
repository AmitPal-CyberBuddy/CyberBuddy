# CyberBuddy

A single web product that hosts multiple browser security checks under one UI.
Light “assessment report” theme — no framework, no build step, no third-party
Python packages. Static HTML/CSS/JS plus Python stdlib.

Requires **Python 3.10+** (`python3 --version`).

**Authorized testing only.** Every tool scans systems you point it at; you are
responsible for having permission to test them. All checks are read-only GETs.

## Tools

| Tool | What it does | Mode |
| --- | --- | --- |
| **Clickjacking Validator** | Live iframe frame-test + PoC overlay; header scoring of X-Frame-Options / CSP frame-ancestors | full with `server.py`, frame-only static |
| **Security Headers** | Grades CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP + cookie flags; score 0–100, grade A–F | needs `server.py` (or CLI) |
| **CORS Validator** | Two-origin engine probe (ACAO reflection vs allowlist, credentials, `Vary: Origin`); cookie-less in-browser fallback | engine for reflection proof; static fallback is single-origin |

More tools slot in later — add one entry to `TOOLS_MENU` in `js/app.js` and it
appears in the nav, footer, and hub grid.

## Quick start (full scans)

```bash
python3 server.py
# open http://127.0.0.1:8080/
```

Binds **127.0.0.1** (loopback only) by default. Cloud-metadata and link-local
targets are always rejected. RFC1918 / loopback targets are allowed when the
server is loopback-bound (the VAPT case).

```bash
# LAN bind — private-IP scans stay off unless you opt in
python3 server.py --host 0.0.0.0
python3 server.py --host 0.0.0.0 --allow-private
```

That serves the hub, all tool pages, and the JSON APIs that make header scans
possible (browsers can't read cross-origin response headers on their own).

## Layout

```
index.html                      # hub
css/app.css                     # shared design system
js/app.js                       # shared helpers (nav, footer, icons, API)
tools/
  clickjacking/index.html       # iframe + PoC overlay + ?url= sharing
  headers/index.html            # header report UI
  cors/index.html               # CORS probe + roadmap
clickjacking_validator.py       # clickjacking engine + shared fetch/URL safety
security_headers.py             # headers engine + CLI
cors_validator.py               # two-origin CORS engine + CLI
server.py                       # local API + static host (stdlib)
test_engines.py                 # stdlib unittest suite
```

## CLI engines

```bash
python3 clickjacking_validator.py https://example.com
python3 clickjacking_validator.py https://a.example https://b.example --json

python3 security_headers.py https://example.com
python3 security_headers.py -f urls.txt --json

python3 cors_validator.py https://example.com/api
```

`--public-only` refuses loopback / RFC1918 targets (metadata is always blocked).

Exit code `1` when any target scores high risk (handy in CI), `2` for usage errors.

```bash
python3 -m unittest test_engines.py
```

## Notes

- Every tool renders results as a self-contained **report card** — target, final
  URL, HTTP status, generated timestamp, verdict, and per-finding evidence —
  ready to screenshot or export via **Export / Print** (print stylesheet included).
- Opening `index.html` straight from disk works for the hub and the frame test;
  header scans need the API, so the pages show a clear static-mode notice and
  instructions instead of failing silently.
- The scan APIs refuse cross-origin browser requests (Origin / Referer check)
  and never fetch cloud-metadata or link-local addresses. Treat a `0.0.0.0`
  bind as an explicit choice, not the default.

## Contact

Ideas, feedback, or collaboration: **amitpal.secure@gmail.com** ·
[LinkedIn](https://www.linkedin.com/in/amitpal-wb/)
