# CyberBuddy roadmap

Internal planning document. It is intentionally excluded from the published
Pages artifact. Public behavior is documented in `README.md`,
`documentation/`, and `methodology/`; confirmed defects belong in regression
tests rather than promises here.

_Last reconciled: 2026-08-18._

## Product baseline

CyberBuddy currently ships seven live tools:

1. Clickjacking Validator
2. Security Headers
3. CORS Validator
4. CSP Policy Auditor
5. CSRF PoC Generator
6. JWT Security Workbench
7. DNS & Domain Security Analyzer

The first four assess target URLs. DNS queries public records through a
configured resolver. CSRF and JWT are browser-local utilities. JWT is no
longer a roadmap preview: Analyze, Verify, Edit & Generate, Test Variants, and
bounded Secret Test are all live.

## Completed foundations

- Scalable tool registry, global menu, hub groups, catalog and footer.
- One public guide per tool, operator documentation and scoring methodology.
- Python/JavaScript grader parity fixtures for HTTP and DNS scoring.
- Local Python APIs, optional serverless API, static Pages fallback, published
  demo cache and explicit relay/DNS consent.
- CSRF hostile-input handling and local artifact generation.
- JWT compact-JWS parsing, claim analysis, HMAC/RSA/RSA-PSS/ECDSA verification
  and signing, local RSA key generation, VAPT test templates and bounded HMAC
  secret testing.
- Seven-tool PWA/discovery metadata, community files and unified release gate.

## Current release work

### RELEASE-01 — Comprehensive public-launch audit

**Status:** completed on 2026-08-18. See
`docs/RELEASE-AUDIT-2026-08-18.md` for the inventory, defect-to-regression
matrix, release-gate evidence and residual browser limitation.

Completed scope:

- inventory every public page, section, control, tool mode, export and route;
- test each tool's validation, happy paths, errors, hostile input, privacy and
  authorization language, reset/export behavior and hosted/local fallbacks;
- audit keyboard/accessibility, responsive behavior, no-JavaScript navigation,
  consent, recent scans, errors and report rendering;
- review SSRF/rebinding, Host/origin/provenance checks, DNS wire handling,
  credentials, relays, caching, generated artifacts and deployment;
- add a regression for every repaired defect and run `python3 tools/verify.py`;
- record browser/runtime limitations that cannot be exercised locally.

The audit report, traceability matrix and stdlib/Node release gate are complete.
Final browser-backed release approval still requires the manual suites in
`tests/browser/README.md` when Chromium is available.

## Candidate follow-up work

These are backlog candidates, not advertised features or commitments:

- Deterministic two-origin browser fixture/laboratory for offline CORS,
  clickjacking and relay-flow tests.
- Optional CI browser job when a maintained Chromium/Puppeteer dependency
  policy is approved.
- Shared persistent rate limiting for a production multi-instance hosted API.
- Header-capable production hosting so CyberBuddy itself can deliver HSTS,
  X-Frame-Options and `frame-ancestors` instead of relying on meta CSP limits.
- Additional tools such as a TLS analyzer or HAR/traffic inspector only after
  a threat model, privacy model, evidence contract and regression plan exist.

## Planning rules

1. Do not mark a tool live until its controls, evidence, failure states,
   documentation, guide, routes, metadata and tests ship together.
2. Never equate a generated payload with target acceptance or an observation
   with a verified vulnerability.
3. Preserve local/private data boundaries: JWTs, keys, secrets and raw CSRF
   requests are never persisted or sent by CyberBuddy.
4. Hosted fallback disclosures must be opt-in and named; “local” must not be
   described as “no network” when an HTTP target or DNS resolver is contacted.
5. Keep internal planning files out of `_site/`.
6. No release is complete until `python3 tools/verify.py` passes.
