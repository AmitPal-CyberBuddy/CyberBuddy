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
| CORS | Arbitrary concrete Origin echo and `Origin: null` echo, both with ACAC true | Python reports HIGH; browser concrete echo is MEDIUM with the explicit single-origin/two-origin-proof limitation. Null without credentials is MEDIUM. | Fixed in this change. |
| DNS | Fixed DNS record maps representing SPF `+all`/`?all`/multiple, DMARC none/quarantine/reject, DKIM hints, DS vs DNSKEY, CAA and RFC 7505 null MX | Python and browser ports agree check-for-check; null MX makes mail-control misses informational. | None |
| CSRF generator | Raw Burp-style URL-encoded form, JSON and multipart/file requests | READY for representable form/safelisted mechanics; LIMITED for JSON and multipart with a file; NOT DIRECTLY REPRESENTABLE where browser mechanics cannot reproduce the request. Parser/generator tests also verify secret-header non-echoing. | None |
| JWT workbench | Locally produced HS256 and asymmetric tokens; correct/incorrect key, signing, variants and bounded secret test | Decode is distinct from verify; correct signature verifies, wrong/missing key does not; re-sign/variant outputs remain labelled test artifacts; secret search is local and bounded. | None |

## Commands and test evidence

The controlled HTTP fixture used the following response families:

```text
/hardened  — CSP/XFO/HSTS/nosniff/referrer/permissions/cookie
/framable  — CSP frame-ancestors * + XFO DENY
/csp-risk  — data: + unsafe-inline + permissive framing/form/base
/cors      — ACAO echoes request Origin + ACAC true
```

The run used `curl -sS -D - -o /dev/null` against each endpoint, including
`curl -H 'Origin: null' …/cors`, followed by `scan_headers`, `scan_url`,
`scan_csp` and `scan_cors` with `allow_private=True`. Observed outputs were:
`B/LOW` for the HTTP hardened fixture (transport appropriately weak), `HIGH`
for framing wildcard, `F/HIGH` for permissive CSP, and `HIGH` for credentialed
null-origin CORS reflection.

The complete deterministic matrix is enforced by:

```bash
python3 -m unittest test_engines.py
```

It runs `tests/grader_fixtures.json` through both Headers/Clickjacking
implementations; `tests/csp_fixtures.json` through both CSP implementations;
DNS record-map parity; CSRF parser/generator cases; and JWT decode, verify,
sign, variants and secret-test cases. These tests are stdlib/Node only.

## Browser limitation

The actual Chromium suites still require a Chromium binary. This sandbox has
none, so `responsive.js`, `layout.js`, `dropdown.js` and `overlays.js` are not
claimed as executed. The dropdown/icon and share-control markup is guarded by
stdlib assertions; run the real-browser commands before merge.
