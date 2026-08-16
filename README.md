# CyberBuddy

A single web product that hosts multiple browser security checks under one UI.
Night-ops console theme (dark by default, with a sun/moon toggle in the header
that persists per browser) — no framework, no build step, no third-party Python
packages. Static HTML/CSS/JS plus Python stdlib. The same graders run in the
browser on GitHub Pages and on `server.py` when you host it yourself.

Requires **Python 3.10+** (`python3 --version`).

**Authorized testing only.** Every tool scans systems you point it at; you are
responsible for having permission to test them. All checks are read-only GETs.

## Tools

| Tool | What it does | Mode |
| --- | --- | --- |
| **Clickjacking Validator** | Live iframe frame-test + PoC overlay; header scoring of X-Frame-Options / CSP frame-ancestors; analyst visual-confirmation fallback | iframe always; headers via Python API or opt-in lookup |
| **Security Headers** | Grades CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP + cookie flags; score 0–100, grade A–F | Python API when `server.py` is up; opt-in lookup on GitHub Pages |
| **CORS Validator** | Two-origin engine probe (ACAO reflection vs allowlist, credentials, `Vary: Origin`); cookie-less in-browser fallback | Python for reflection proof; hosted site probes from this origin |
| **CSP Policy Auditor** | Audits enforced vs Report-Only CSP, effective script/style sources, object/base/framing/form controls, duplicates, mixed content, Trusted Types, and reporting | Python API/cache when available; identical browser grader with opt-in header lookup on GitHub Pages |
| **CSRF PoC Generator** | Paste a raw Burp request → standalone HTML PoC (GET/POST forms, text/plain, JSON fetch, multipart), labelled READY / LIMITED / NOT DIRECTLY REPRESENTABLE | 100% local in the browser — nothing sent, stored, cached, or relayed; the PoC never executes inside CyberBuddy |
| **JWT Security Workbench** | Decode, inspect, verify and re-sign JWTs locally, get prioritized VAPT suggestions with one-click TEST PAYLOADs and Burp guidance, build test-variant templates, and run bounded HS256/384/512 secret testing — compact JWS parsing, claim timeline, observations, HMAC/RSA-PKCS#1/RSA-PSS/ECDSA verify and sign, a semantic diff and local RSA test-key generation. | 100% local in the browser — no token, key or wordlist is ever sent, stored or placed in the URL |

More tools slot in later — add one entry to the `TOOLS_MENU` registry in
`js/app.js` (with a `category` of `assess` for URL-based target checks or
`local` for generators/analyzers) and it appears in the header menu, the hub
grid, the tools catalog (`/tools/`) and the footer automatically. Add the
tool page under `tools/<slug>/` and its static no-JavaScript card to the hub
and catalog fallbacks.

## Guides

Short, tool-connected notes live under `/guides/` — one per tool. Each guide
covers one weakness, points at the tool that confirms it, and closes with
primary references (OWASP, CWE, MDN, specs) for depth — they are deliberately
concise, not a full article library.

| Guide | Pairs with | Standards |
| --- | --- | --- |
| [`guides/clickjacking/`](guides/clickjacking/) | Clickjacking Validator | OWASP WSTG-CLNT-09 · CWE-1021 |
| [`guides/headers/`](guides/headers/) | Security Headers | OWASP WSTG-CONF-07 · CWE-693 |
| [`guides/cors/`](guides/cors/) | CORS Validator | OWASP WSTG-CLNT-07 · CWE-942 |
| [`guides/csp/`](guides/csp/) | CSP Policy Auditor | OWASP WSTG-CONF-12 · CWE-79 |
| [`guides/csrf/`](guides/csrf/) | CSRF PoC Generator | OWASP WSTG-SESS-05 · CWE-352 |
| [`guides/jwt/`](guides/jwt/) | JWT Security Workbench | RFC 7519 · RFC 7515 · OWASP WSTG-SESS-10 · CWE-347 |

## Documentation page

Operator-facing docs live on the site at the
[Documentation page](https://amitpal-cyberbuddy.github.io/CyberBuddy/documentation/):
quick start, which engine answers a scan, the CLI, export formats, hosted-build
limits, and what leaves the browser. This README stays the contributor
reference — file layout, engine internals, deployment, and the workflow.

## Quick start (full scans)

```bash
python3 server.py
# open http://127.0.0.1:8080/
# catalog: /tools/
# tools: /tools/clickjacking/  /tools/headers/  /tools/cors/  /tools/csp/  /tools/csrf/
# JWT: /tools/jwt/  (decode, inspect, verify, VAPT payloads, edit & generate)
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

The hub suite can run all four URL assessments or any selected subset; the
selection is preserved in share links with the target URL. On GitHub Pages,
a consent-gated A/AAAA lookup through Google Public DNS distinguishes
NXDOMAIN / domains with no web address from ordinary CORS or relay failures.
The Python engine performs its own authoritative system-DNS check locally.

URL fields accept bare public domains (`example.com` becomes
`https://example.com`) and local host/port input (`localhost:8080` becomes
`http://localhost:8080`). Public hostnames need a dot and plausible TLD; IP
addresses and `localhost` remain valid for local work. Only HTTP(S) is accepted.
URLs containing `user:password@` credentials are rejected so secrets are never
burned into a report or evidence card. These browser checks are UX only:
`validate_target()` and the server's SSRF/private-address policy remain the
authoritative security boundary.

## Layout

```
index.html                      # hub (includes #methodology scoring notes)
404.html                        # hosted 404 + repair for old tool URLs
methodology/index.html          # full methodology page (also published to Pages)
documentation/index.html        # operator docs: quick start, engines, CLI, export, limits
guides/
  index.html                    # guides index (short, tool-connected notes)
  clickjacking/index.html       # guide, paired with the Clickjacking Validator
  headers/index.html            # guide, paired with Security Headers
  cors/index.html               # guide, paired with the CORS Validator
  csp/index.html                # guide, paired with the CSP Policy Auditor
  csrf/index.html               # guide, paired with the CSRF PoC Generator
  jwt/index.html                # guide, paired with the JWT Security Workbench
css/app.css                     # shared design system
css/noscript.css                # no-JS fallback (reveal animations off)
css/404.css                     # standalone styles for 404.html
js/app.js                       # shared helpers (nav, footer, icons, API, export)
js/boot.js                      # reads <body data-page/data-init> and boots a page
js/theme-boot.js                # pre-paint theme (no inline script -> strict CSP)
js/hub.js                       # hub-only console animation
js/tool.clickjacking.js         # clickjacking page controller
js/tool.headers.js              # headers page controller
js/tool.cors.js                 # CORS page controller
js/tool.csp.js                  # CSP audit page controller
js/tool.csrf.js                 # CSRF PoC generator (parser + HTML builder + controller)
js/tool.jwt.js                  # JWT Workbench controller (analyze/verify + VAPT suggestions + edit/generate/sign)
js/404-boot.js / js/404.js      # 404 theme + legacy-URL repair
tools/
  index.html                    # tools catalog (every tool in one directory)
  clickjacking/index.html       # iframe + PoC overlay + ?url= sharing
  headers/index.html            # header report UI
  cors/index.html               # CORS probe + roadmap
  csp/index.html                # CSP policy audit report
  csrf/index.html               # CSRF PoC generator (local-only)
  jwt/index.html                # JWT Security Workbench (decode/inspect/verify + VAPT payloads + edit/generate)
  build_cache.py                # pre-scan urls.txt -> cache/<host>.json
LICENSE                         # Apache-2.0
tests/grader_fixtures.json      # shared headers/clickjacking Python<->JS contract
tests/csp_fixtures.json         # shared CSP Python<->JS audit contract
docs/performance.md             # engine performance notes
docs/pages-workflow-patch.md    # REQUIRED manual edit to pages.yml
docs/DEV-NOTES.md               # internal maintainer notes — never deployed, never in shipped files
urls.txt                        # demo targets pre-scanned for the published cache
humans.txt                      # who built it
llms.txt                        # machine-readable project summary
api/                            # optional hosted Python API (Vercel)
apilib.py                       # shared WSGI plumbing for api/ (outside api/)
vercel.json                     # Vercel config for api/
cache/                          # generated by tools/build_cache.py
.well-known/security.txt        # responsible disclosure contact
og-cyberbuddy.png               # Open Graph / Twitter social card
icon-192.png / icon-512.png     # PWA icons (manifest)
manifest.webmanifest            # PWA manifest with tool shortcuts
robots.txt                      # search engine directives
sitemap.xml                     # sitemap for crawlers
clickjacking_validator.py       # clickjacking engine + shared fetch/URL safety
security_headers.py             # headers engine + CLI
cors_validator.py               # two-origin CORS engine + CLI
csp_checker.py                  # dedicated CSP audit engine + CLI
server.py                       # local API + static host (stdlib)
test_engines.py                 # stdlib unittest suite
```

## CLI engines

```bash
python3 clickjacking_validator.py https://example.com
python3 clickjacking_validator.py https://a.example https://b.example --json

python3 security_headers.py https://example.com
python3 security_headers.py -f urls.txt --json
python3 security_headers.py -f urls.txt --workers 8   # parallel batch scan

python3 cors_validator.py https://example.com/api

python3 csp_checker.py https://example.com
python3 csp_checker.py -f urls.txt --json
```

`--public-only` refuses loopback / RFC1918 targets (metadata is always blocked).

The CSP auditor includes the useful baseline checks from the original standalone
checker — missing enforcement, wildcards, `'unsafe-inline'`, `'unsafe-eval'`,
script/object controls, and a secure starting policy — but avoids common false
positives. `default-src` is respected as a real fallback, Report-Only is never
called enforced, nonce/hash + `'strict-dynamic'` compatibility fallbacks are
explained, multiple headers combine restrictively, and duplicate directives use
the browser's first-directive-wins behavior. The suggested policy must be
tailored and tested in Report-Only mode before deployment; applying a generic
policy unchanged can break an application.

Exit code `1` when any target scores high risk (handy in CI), `2` for usage errors.

```bash
python3 -m unittest test_engines.py
```

`tests/grader_fixtures.json` and `tests/csp_fixtures.json` are the **shared
scoring contracts**. CyberBuddy implements the graders twice — stdlib Python
for `server.py`/CLI, and a browser port in `js/app.js` so GitHub Pages can grade
without a server. Both are run against those fixtures, and parity tests compare
the engines directly, so the same target cannot get a different result based on
where it was scanned. Add a case to the relevant JSON and both engines are
checked automatically (node required for the JS side; skipped if absent).

## Making the hosted site full-strength

GitHub Pages is static — no Python, no relays needed for most targets. Three
layers make the hosted site as close to `server.py` as possible:

1. **Cached reports (built-in).** Add your targets to `urls.txt` and build
   the cache — the UI reads `cache/<host>.json` same-origin whenever it is
   present. Two ways to produce it:

   - **Locally (zero workflow changes):** `python3 tools/build_cache.py`,
     then commit the generated `cache/` directory. Your targets get full
     reports — two-origin CORS proof, server-side header reads,
     metadata/private-IP blocking — with **no third-party relays**.
   - **Automatically (one-time workflow edit):** add these two lines to the
     `build` job of `.github/workflows/pages.yml` so every deploy (and a
     `schedule` of your choosing) refreshes the cache before publishing:

     ```yaml
     - name: Build scan cache
       run: python3 tools/build_cache.py
     ```
     and add `test -d cache && cp -a cache _site/ || true` to the
     *Assemble static site* step. (The workflow files are owned by the
     repo maintainer — edit them on your branch.)

   - **Metadata assets:** the workflow also copies `og-cyberbuddy.png`,
     `icon-192.png`, `icon-512.png`, `manifest.webmanifest`, `robots.txt`,
     `sitemap.xml`, `humans.txt`, `llms.txt`, the `methodology/` page, the
     `guides/` section, the `documentation/` page, and
     `.well-known/security.txt` into `_site/`. Use
     `test -f "$f" && cp "$f" _site/ || true` for each file so the build
     never fails if an asset is temporarily missing. Also add
     `test -d .well-known && cp -a .well-known _site/ || true` for the
     security contact file, `test -d methodology && cp -a methodology _site/ || true`
     for the full scoring page, `test -d guides && cp -a guides _site/ || true`
     for the guides section, and
     `test -d documentation && cp -a documentation _site/ || true` for the
     documentation page.

   The UI prefers the cache over the public lookups (fresh within 48h) and
   marks reports `via cached report`. The lookup path is `appBase() + "/cache/"`
   so GitHub Pages resolves `/CyberBuddy/cache/<host>.json`.
2. **Optional hosted API (`api/`).** Deploy the `api/` folder (Vercel free
   tier: `vercel --prod`), then set `API_BASE` in `js/app.js` to the
   deployment URL. The frontend health check finds it and the same Python
   engines run server-side for *any* URL — same quality as `server.py`, and
   the chip shows `python · online`. The endpoint is read-only GET, refuses
   metadata/private targets, and has a per-IP rate limit.
3. **Smarter live fallback.** When neither is available, the browser graders
   run exactly as before — with a dedup + 10-minute lookup cache so repeated
   or suite-wide scans stop hammering the public relays.

The CSP tool uses all three layers. A Pages visitor gets the Python-built CSP
report for configured demo targets, otherwise the browser runs the parity-tested
CSP grader over a direct CORS header read or an explicitly approved relay. It
also derives a CSP result from older cached Security Headers entries, so a cache
built before the dedicated CSP key was added does not break the hosted tool.
Every result keeps its LIVE/CACHED and verified/unverified provenance label.

## CSRF PoC Generator

The fifth tool turns a pasted **Burp-style HTTP request** into a standalone
HTML proof-of-concept for authorized CSRF testing. It is deliberately unlike
the four scanners:

- **Local only.** The request is parsed and the PoC is generated in this
  browser tab. It is never sent, persisted, cached, relayed, or written into
  the URL. The PoC is shown as inert (escaped) text and only leaves the page
  when you download or copy it; CyberBuddy never executes it.
- **Honest mechanics.** Each generated variant is labelled
  `READY` (a simple request — a form, or a CORS-safelisted `fetch()`),
  `LIMITED` (depends on a CORS preflight or server leniency, e.g. exact JSON,
  `PUT/PATCH/DELETE`, custom headers, file fields), or
  `NOT DIRECTLY REPRESENTABLE` (e.g. a GET with a body). There is no numeric
  score and no vulnerability verdict.
- **Never fakes the impossible.** A plain form cannot send an arbitrary exact
  JSON body; CyberBuddy uses `fetch()` and says it needs a preflight. File
  fields are never pre-populated — they become file pickers the victim must
  fill. JSON-as-`text/plain` is offered only when the server might accept that
  type.
- **Hostile-input safe.** Every value is HTML-escaped, and values embedded in
  JavaScript are emitted through a `JSON.stringify`-based literal with `<`
  escaped, so a pasted `</script>` cannot break out. `Cookie`, `Authorization`,
  `Host`, `Content-Length`, `Origin` and `Referer` values are never copied
  into the PoC. Likely CSRF-token fields are detected but never silently
  removed — you choose to include or exclude each one.
- **Auto-submit is opt-in and off by default.** With it off, the PoC has a
  manual submit button; with it on, a minimal fixed auto-submit script is added
  and the UI shows an accidental-state-change warning.

## JWT Security Workbench

The sixth tool, at the [JWT Security Workbench](https://amitpal-cyberbuddy.github.io/CyberBuddy/tools/jwt/),
decodes, inspects, verifies, edits, re-signs and tests JSON Web Tokens
locally in your browser:

- **Decode & inspect (JWT-01, live)** — strict compact-JWS parsing with
  honest errors for malformed input and JWE; pretty-printed header/payload; a
  claim timeline for `iat`/`nbf`/`exp`; contextual observations (missing
  claims, long lifetimes, `jku`/`x5u`/`jwk`/`kid`).
- **Verify (JWT-01, live)** — signature verification via the native Web Crypto
  API for HS256/384/512 (shared secret), RS256/384/512, PS256/384/512 and
  ES256/384, using a PEM public key, JWK or pasted JWKS (key matched by
  `kid`). Expected `iss`/`aud`/`sub` and clock tolerance are validated
  separately. The token's `alg` header is never trusted to choose the
  verifier, and HMAC rejects public keys (algorithm-confusion guard).
- **Edit & generate (JWT-02, live)** — header/payload editors with a
  semantic original-vs-modified diff, standard-claim helpers (`iss`, `sub`,
  `aud`, `exp`, `nbf`, `iat`, `jti`), HMAC and private-key signing (PEM
  PKCS#8 / private JWK) via Web Crypto, local RSA test-key generation,
  explicit **TEST TOKEN** labels, and copy/download that never exports key
  material by accident.
- **VAPT suggestions & payloads** — decoding a token renders prioritized,
  severity-tagged (CRITICAL / HIGH / INFO) test vectors matched to the
  token's algorithm, headers and claims: RS→HS algorithm confusion with a
  pasted public-key PEM, `alg:none` stripping, embedded JWK injection,
  `kid` traversal/SQLi probes that keep the original signature,
  `jku`/`x5u` injection, an offline secret-testing handoff for HS tokens,
  and privilege-claim tampering. Every card builds a one-click **TEST
  PAYLOAD** with "Copy token" and "Copy as Burp Authorization header",
  lists 2–3 Burp Suite steps naming the risky (HTTP 200) versus expected
  (401/403) response, and jumps to the matching workbench tab prefilled.
  Suggestions are test vectors, never findings.
- **Test variants & secret testing (JWT-03, live)** — `alg:none`, claim
  manipulation (tamper and re-sign), algorithm confusion with a pasted
  public key, embedded JWK, JKU/X5U and `kid` mutation templates, every
  one labelled TEST TEMPLATE; bounded HS256/384/512 secret testing in a
  Web Worker with progress, cancel and explicit candidate/time limits.

Everything runs in this browser: no token, key or wordlist is ever sent,
stored or placed in the URL. There is no numeric score; observations are
contextual. The [JWT guide](guides/jwt/) is paired with the tool. See
[`docs/ROADMAP.md`](docs/ROADMAP.md) for the full plan and accuracy rules.

## Evidence and export

Every tool renders a self-contained **report card** — target, final URL, HTTP
status, UTC timestamp, verdict, per-finding evidence, and a provenance strip
naming the tool, engine and time so a cropped screenshot is still
self-identifying.

**Evidence mode** (on by default, toggle under the scan bar) collapses the page
chrome once results render, so the whole card fits one viewport and an OS
snipping tool captures it in a single shot.

The **Export** menu offers:

| Option | What you get | Availability |
| --- | --- | --- |
| Print / Save as PDF | Full card, paper layout, colours and the PoC overlay preserved | everywhere |
| Download evidence card (PNG) | Tool-specific card drawn from the scan data — no live frame | everywhere |
| Copy / download Markdown | Paste-ready metadata, context, findings, evidence and recommendations | everywhere |
| Copy / download JSON | Versioned `cyberbuddy-report/v1` envelope for automation | everywhere |
| Download CSV | Spreadsheet-safe metadata and findings (formula injection neutralized) | everywhere |
| Download standalone HTML | Script-free, printable and portable report | everywhere |

A cross-origin iframe **cannot** be rasterised in JavaScript: canvas pixels would
be tainted, and `html2canvas` does not render iframes. CyberBuddy therefore does
not request screen-capture permission. Use Evidence mode plus your OS screenshot
tool when the live frame matters. The deterministic evidence card records the
clickjacking frame outcome in words; CORS cards foreground probe origins and the
ACAO/ACAC/Vary triple; CSP cards include the enforced policy and directive
findings. No third-party JavaScript is used.

### Clickjacking without header data

When no engine or lookup can supply header values, the frame is still evidence.
CyberBuddy asks what you see and records your answer as **analyst-attested**
(`"confirmation": "manual"` in the JSON, called out in the Markdown and on the
provenance strip) — never as a measured header result. It pre-selects the likely
answer from the frame's load behaviour. The frame runs sandboxed with
`allow-scripts allow-forms allow-same-origin` — the same privileges a real
attacker's frame would have — so a few sites may still render blank for
third-party-storage or frame-busting reasons unrelated to framing headers.
Top-level navigation remains blocked.

## Privacy

- **Scan history is local.** Recent targets and the 10-minute header cache live
  in `localStorage`, expire after 24 hours, and are never uploaded or shared
  between users. *Clear* wipes both the recent list and the cached headers.
- **Published reports are not user scans.** `cache/<host>.json` is built in CI
  from the fixed demo list in `urls.txt`. Nothing a visitor types is written
  there. The UI labels these *via published report*.
- **Third-party relays are opt-in.** Browsers cannot read cross-origin response
  headers, so with no Python engine the hosted site must proxy the request —
  disclosing the target and your IP to the relay operator. CyberBuddy asks
  first, defaults to sending only the **hostname** (not path or query, where
  tokens and tenant IDs live), and flags relayed findings **unverified** in the
  UI and in every export. Relays: `hackertarget.com`, `allorigins.win`,
  `corsproxy.io`, `codetabs.com`.
- A direct same-origin/CORS read is always attempted first — it involves no
  third party. `server.py` avoids relays entirely.

## Notes

- Keyboard: `/` focuses the URL field, `t` toggles theme, `?` opens shortcuts.
  Scoring notes live on the hub under the
  [How CyberBuddy scores](https://amitpal-cyberbuddy.github.io/CyberBuddy/#methodology) section,
  with the full page at the [methodology page](https://amitpal-cyberbuddy.github.io/CyberBuddy/methodology/).
- **CyberBuddy scores A (95/100) against itself.** No page uses inline scripts —
  every controller is a file under `js/`, so `server.py` ships
  `script-src 'self'` with no `'unsafe-inline'`, plus `Permissions-Policy`,
  COOP/COEP/CORP and `frame-ancestors 'self'`. The remaining 5 points are the
  plain-HTTP transport warning on a loopback bind.
- The scan APIs refuse cross-origin browser requests (Origin / Referer check)
  and never fetch cloud-metadata or link-local addresses. Treat a `0.0.0.0`
  bind as an explicit choice, not the default.
- **DNS rebinding is guarded at connect time.** `validate_target()` resolves a
  hostname to decide whether it is allowed, but urllib resolves again when it
  actually connects — a hostile resolver can answer public for the check and
  private for the fetch. The pooled openers therefore re-validate every
  resolved address inside `connect()`, so the policy applies to the address
  the socket really uses.
- The optional hosted `api/` rate limit is **per function instance** and is
  best-effort on serverless (lost on cold start, one counter per concurrent
  instance). Use shared KV storage or the platform WAF if you need a hard
  quota — see the note in `apilib.py`.
- `robots.txt` and `.well-known/security.txt` only take effect at a **domain
  root**. On a project Pages site they live under `/CyberBuddy/`, so crawlers
  will not read them until the project moves to a custom domain.

## Hosted site limitations (GitHub Pages)

Pages serves static files and **cannot send response headers**, which has real
consequences for a tool that grades response headers:

- The policy ships as a `<meta http-equiv="Content-Security-Policy">` on every
  page instead. That covers `script-src`, `object-src`, `base-uri`,
  `frame-src` and friends.
- **`frame-ancestors` and `X-Frame-Options` cannot be set this way** — a meta
  CSP ignores `frame-ancestors` by specification, and XFO is header-only. So
  *the hosted site itself can be framed*, and scanning it with CyberBuddy will
  (correctly) report missing framing protection. `server.py` sets both properly.
  Fixing this on the hosted site requires a host that can send headers
  (Cloudflare Pages `_headers`, Netlify, Vercel) or a custom domain behind a
  proxy.
- HSTS is likewise header-only; `github.io` is HSTS-preloaded at the domain
  level, so this is covered in practice but not by anything in this repo.
- Because of the above, **the hosted site will not score A against itself even
  though `server.py` does.** That is a hosting limit, not a scoring bug — say
  so if anyone asks.
- Only `/tools/clickjacking/` is allowed to frame arbitrary targets
  (`frame-src https: http:`); every other page is `frame-src 'none'`.

- Asset cache-busting (`?v=…`) is stamped with the commit SHA by the Pages
  workflow — do not hand-maintain those strings.

## License

[Apache-2.0](LICENSE) © 2026 Amit Pal. Permissive, with an explicit patent
grant — you may use, modify and redistribute it, including commercially, as
long as you keep the notice and state your changes.

## Contact

Ideas, feedback, or collaboration: **amitpal.secure@gmail.com** ·
[LinkedIn](https://www.linkedin.com/in/amitpal-wb/) ·
[Medium — security write-ups](https://amitpxl.medium.com/)
