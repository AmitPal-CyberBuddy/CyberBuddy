# CyberBuddy

A single web product that hosts multiple browser security checks under one UI.
Dark, mono-accented, blueprint-styled — no framework, no build step, no third-party
Python packages. Static HTML/CSS/JS plus Python stdlib.

**Authorized testing only.** Every tool scans systems you point it at; you are
responsible for having permission to test them. All checks are read-only GETs.

## Tools

| Tool | What it does | Mode |
| --- | --- | --- |
| **Clickjacking Validator** | Live iframe frame-test + PoC overlay; header scoring of X-Frame-Options / CSP frame-ancestors | full with `server.py`, frame-only static |
| **Security Headers** | Grades CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP + cookie flags; score 0–100, grade A–F | needs `server.py` (or CLI) |
| **CORS Validator** | In-browser CORS probe (origin reflection, credentials, `Vary: Origin`); server-side preflight explorer planned | works static |

More tools slot in later — each is a folder under `tools/` reusing `css/app.css`
and `js/app.js`, and it appears in the nav automatically.

## Quick start (full scans)

```bash
python3 server.py
# open http://127.0.0.1:8080/
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
clickjacking_validator.py       # clickjacking engine + CLI (imported)
security_headers.py             # headers engine + CLI
server.py                       # local API + static host (stdlib)
```

## CLI engines

```bash
python3 clickjacking_validator.py https://example.com
python3 clickjacking_validator.py https://a.example https://b.example --json

python3 security_headers.py https://example.com
python3 security_headers.py -f urls.txt --json
```

Exit code `1` when any target scores high risk (handy in CI), `2` for usage errors.

## Notes

- `clickjacking_validator.py` is imported as-is from the Clickjacking-Validator
  project (same engine, same CLI, same `USER_AGENT`).
- Opening `index.html` straight from disk works for the hub and the frame test;
  header scans need the API, so the pages show a clear static-mode notice and
  instructions instead of failing silently.
- The server binds `0.0.0.0:8080` (LAN reachable) but is stateless and read-only —
  treat it as a local-only tool.
