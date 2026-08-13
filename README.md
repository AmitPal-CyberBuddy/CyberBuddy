# CyberBuddy

A single web product that hosts multiple browser security checks under one UI.
Night-ops console theme — no framework, no build step, no third-party Python
packages. Static HTML/CSS/JS plus Python stdlib. The same graders run in the
browser on GitHub Pages and on `server.py` when you host it yourself.

Requires **Python 3.10+** (`python3 --version`).

**Authorized testing only.** Every tool scans systems you point it at; you are
responsible for having permission to test them. All checks are read-only GETs.

## Tools

| Tool | What it does | Mode |
| --- | --- | --- |
| **Clickjacking Validator** | Live iframe frame-test + PoC overlay; header scoring of X-Frame-Options / CSP frame-ancestors | iframe always; headers via Python API or live lookup |
| **Security Headers** | Grades CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP + cookie flags; score 0–100, grade A–F | Python API when `server.py` is up; live lookup on GitHub Pages |
| **CORS Validator** | Two-origin engine probe (ACAO reflection vs allowlist, credentials, `Vary: Origin`); cookie-less in-browser fallback | Python for reflection proof; hosted site probes from this origin |

More tools slot in later — add one entry to `TOOLS_MENU` in `js/app.js` and it
appears in the nav, footer, and hub grid.

## Quick start (full scans)

```bash
python3 server.py
# open http://127.0.0.1:8080/
# tools: /tools/clickjacking/  /tools/headers/  /tools/cors/
```

Binds **127.0.0.1** (loopback only) by default. Cloud-metadata and link-local
targets are always rejected. RFC1918 / loopback targets are allowed when the
server is loopback-bound (the VAPT case). A `PORT` environment variable (typical
on PaaS) switches the default bind to `0.0.0.0`.

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
404.html                        # hosted 404 + repair for old tool URLs
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
- On GitHub Pages the Python process is not running (Pages is static). The UI
  still grades headers and framing by looking up response headers through a
  public read-only relay, and CORS is probed from the `github.io` origin.
  `server.py` is preferred whenever it is reachable — same scores, no relay.
- The scan APIs refuse cross-origin browser requests (Origin / Referer check)
  and never fetch cloud-metadata or link-local addresses. Treat a `0.0.0.0`
  bind as an explicit choice, not the default.

## Contact

Ideas, feedback, or collaboration: **amitpal.secure@gmail.com** ·
[LinkedIn](https://www.linkedin.com/in/amitpal-wb/)
