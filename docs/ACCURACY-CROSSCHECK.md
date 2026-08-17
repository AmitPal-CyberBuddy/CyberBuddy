# Accuracy cross-check record — 2026-08-17

This is an internal, reproducible verification record for the accuracy sweep.
All network tests used a local, controlled fixture and `curl -D -`; no public
target was scanned. The fixture responses were then fed to the same stdlib
engines that `server.py` uses. Browser ports were compared to the same input
maps by the stdlib/Node parity tests. This separates wire/header collection
from grading and makes every expected outcome reviewable.

## Wire checks and engine results

| Tool | curl/Burp-equivalent controlled input | Expected / observed result | Discrepancy |
| --- | --- | --- | --- |
| Security Headers | Hardened response: CSP, XFO DENY, HSTS `max-age=31536000`, nosniff, strict referrer/permissions and Secure/HttpOnly/SameSite cookie | Header statuses match their values; HTTP transport itself is weak, so this local HTTP fixture scores B/LOW rather than falsely claiming HTTPS/A. Golden cases cover A–F, HSTS `0`/short, cookie flags and every header check. | None |
| Clickjacking | `X-Frame-Options: DENY` plus `frame-ancestors *`; then no framing controls | HIGH for wildcard CSP despite XFO DENY; HIGH when both controls are absent. `frame-ancestors 'none'` / effective XFO cases remain LOW. | **UI wording fixed:** a relay-derived header result was headed “Clickjacking proof (unverified)”. It now reads **Clickjacking assessment** and labels the provenance **relay data**. The relay caveat is retained; it must not be hidden. |
| CSP | `script-src data: 'unsafe-inline'; frame-ancestors *; form-action *; base-uri *` | F/HIGH with weak checks for each permissive control. Golden cases additionally cover mixed content, report-only, duplicate first-directive behavior, nonce/strict-dynamic and multiple policies. | None |
| CORS | **Method-aware:** GET safe (no ACAO), HEAD reflects with creds, OPTIONS direct reflects with creds, preflight POST reflects with creds, per-method `Origin: null` (with/without creds), and unsupported HEAD/OPTIONS (405/501) | Python: GET-only low shows “No risky CORS behavior observed for GET” with coverage matrix; HEAD/OPTIONS/preflight high rolls up to HIGH; per-method null HIGH with creds / MEDIUM without; 405/501 reported as *not assessed* not safe; Vary never drives headline; browser single-origin concrete reflect with creds is MEDIUM never PASS; exports include methods/coverage. | **Extended:** GET baseline + analyst-selected HEAD/OPTIONS/preflight POST (and optional ACRH) — no POST auto-sent; per-method Origin:null; coverage matrix; highest-risk rollup; browser limits explicit; methodology/guide/README updated. |
| DNS | Fixed DNS record maps representing SPF `+all`/`?all`/multiple, DMARC none/quarantine/reject, DKIM hints, DS vs DNSKEY, CAA and RFC 7505 null MX | Python and browser ports agree check-for-check; null MX makes mail-control misses informational. | None |
| CSRF generator | Raw Burp-style URL-encoded form, JSON and multipart/file requests | READY for representable form/safelisted mechanics; LIMITED for JSON and multipart with a file; NOT DIRECTLY REPRESENTABLE where browser mechanics cannot reproduce the request. Parser/generator tests also verify secret-header non-echoing. | None |
| JWT workbench | Locally produced HS256 and asymmetric tokens; correct/incorrect key, signing, variants and bounded secret test | Decode is distinct from verify; correct signature verifies, wrong/missing key does not; re-sign/variant outputs remain labelled test artifacts; secret search is local and bounded. | None |

## Commands and test evidence

The controlled HTTP fixture used the following response families (now with method-aware CORS fixture `tests/cors_fixture.py`):

```text
/hardened      — CSP/XFO/HSTS/nosniff/referrer/permissions/cookie
/framable      — CSP frame-ancestors * + XFO DENY
/csp-risk      — data: + unsafe-inline + permissive framing/form/base
/cors          — ACAO echoes request Origin + ACAC true (GET baseline)
/get-safe      — GET returns no CORS headers (safe)
/head-vuln     — HEAD returns reflected ACAO + ACAC true (vulnerable)
/options-vuln  — OPTIONS direct returns reflected ACAO + ACAC true
/preflight-vuln— OPTIONS + Origin + Access-Control-Request-Method: POST returns reflected ACAO + ACAC true + ACAM/ACAH
/null-reflect  — GET with Origin: null returns ACAO: null (+ ACAC true for HIGH)
/unsupported   — HEAD returns 405 (not assessed)
/echo         — Echoes Origin for any method (generic)
```

The run used `curl -sS -D - -o /dev/null` against each endpoint, including:

```bash
curl -sS -D - -o /dev/null -H "Origin: https://evil.cyberbuddy.test" http://127.0.0.1:9876/echo
curl -sS -D - -o /dev/null -H "Origin: null" http://127.0.0.1:9876/echo
curl -sS -D - -o /dev/null -X HEAD -H "Origin: https://evil.cyberbuddy.test" http://127.0.0.1:9876/head-vuln
curl -sS -D - -o /dev/null -X OPTIONS -H "Origin: https://evil.cyberbuddy.test" http://127.0.0.1:9876/options-vuln
curl -sS -D - -o /dev/null -X OPTIONS -H "Origin: https://evil.cyberbuddy.test" -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: Content-Type" http://127.0.0.1:9876/preflight-vuln
curl -sS -D - -o /dev/null -X HEAD -H "Origin: https://evil.cyberbuddy.test" http://127.0.0.1:9876/unsupported
```

followed by `scan_headers`, `scan_url`, `scan_csp` and `scan_cors` (with `methods`, `preflight_methods`, `preflight_headers`, `allow_private=True`). Observed outputs were:
`B/LOW` for the HTTP hardened fixture (transport appropriately weak), `HIGH`
for framing wildcard, `F/HIGH` for permissive CSP, `HIGH` for credentialed
null-origin CORS reflection, plus method-aware: `GET safe → low with “No risky CORS behavior observed for GET” and coverage matrix`; `GET safe + HEAD reflect → medium`; `GET safe + preflight POST reflect → high`; per-method null HIGH with creds / MEDIUM without; 405/501 → *not assessed* with Vary isolation preserved.

The complete deterministic matrix is enforced by:

```bash
python3 -m unittest test_engines.py
```

It runs `tests/grader_fixtures.json` through both Headers/Clickjacking
implementations; `tests/csp_fixtures.json` through both CSP implementations;
DNS record-map parity; CSRF parser/generator cases; and JWT decode, verify,
sign, variants and secret-test cases. These tests are stdlib/Node only.

## Focused “what else can improve accuracy” review (A-F)

Each tool’s collection, grading, and reporting were re-checked for one session. Only CORS required a behavior change; the others were verified correct and their wording/provenance kept, with regression guards to keep them that way.

**A. Security Headers** — Method/status/redirect: fix confirmed that `fetch_headers` follows redirects and the report shows `final_url` vs `url` with a redirect-info finding that states the grade is for the final response, not the host — not a host-wide claim. Duplicate headers: `headers_from_message` preserves `Set-Cookie` and `Content-Security-Policy` via newline join, and the grader reads the effective directive; HSTS on HTTP is `info` (not missing) with “Only meaningful over HTTPS”; cookie flags are token-checked; wording is response-specific.

**B. Clickjacking** — Relay header result remains an **assessment** with `relay data` provenance, never “proof”. XFO/CSP precedence is correct: permissive `frame-ancestors *` overrides `X-Frame-Options: DENY` → HIGH; restrictive `frame-ancestors` → LOW even when XFO missing (defense-in-depth gap, not medium). Frame evidence is worded as “load event fired — not machine-verifiable” and analyst attestation is explicit; canvas never draws cross-origin pixels.

**C. CSP** — Enforcement vs Report-Only correctly separated (missing enforced → HIGH even when report-only present); multiple enforced policies combine restrictively (intersection) with a note; duplicate directives inside one policy keep the first (browser spec) and are flagged; `default-src` fallback is used only for script/style/object, not for `base-uri`/`frame-ancestors`/`form-action`; reporting gaps are `info` not headline risk.

**D. DNS** — Resolver is system (`/etc/resolv.conf`) locally and `dns.google` (DoH) on Pages after consent, both labelled with provenance; DNSSEC verdict keys on **DS** at the parent (not DNSKEY alone); null MX (`0 .`) makes SPF/DMARC/DKIM informational; DKIM misses are “hints, never proof of absence” on common selectors only; transient lookup/timeout vs NXDOMAIN wording is distinct.

**E. CSRF** — `READY`/`LIMITED`/`NOT DIRECTLY REPRESENTABLE` is **browser-mechanics reproducibility**, never a vulnerability verdict. `application/json` and multipart-with-file correctly produce LIMITED; auto-submit is opt-in and fixed.

**F. JWT** — `decode` is never `verify`; verification and secret-search results remain **test artifacts/local observations** (“TEST TOKEN”/“TEST TEMPLATE”, bounded worker, explicit candidate/time limits) not target acceptance proof; `kid`/`jku`/`x5u`/embedded `jwk`/confusion are surfaces until the target honors them.

For each checked item: no new speculative checks were added, no mutating requests are sent, and where a counterpart exists the Python and JS graders were kept in parity (CORS per-method ladder, CSP duplicate handling, DNS DS vs DKIM, etc.) with matching guide/methodology wording and a stdlib/Node regression test. This record is the controlled verification; public-target claims remain out of scope.

## Browser limitation

The actual Chromium suites still require a Chromium binary. This sandbox has
none, so `responsive.js`, `layout.js`, `dropdown.js` and `overlays.js` are not
claimed as executed. The dropdown/icon and share-control markup is guarded by
stdlib assertions; run the real-browser commands before merge. No Chromium could be installed (apt mirrors and puppeteer download host unreachable).
