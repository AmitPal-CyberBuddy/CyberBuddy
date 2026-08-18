# Comprehensive public-launch audit — 2026-08-18

This internal record closes `RELEASE-01` in `docs/ROADMAP.md`. It inventories
the CyberBuddy repository, records confirmed defects and repairs, and maps the
requested launch criteria to reproducible evidence. It is intentionally
excluded from the Pages artifact by the deployment leak guard.

## Method and boundaries

- Audited repository: **CyberBuddy** at the active Arena branch baseline.
- Review layers: public HTML and metadata, browser controllers, Python engines,
  local and hosted routes, deployment assembly, tests and operator copy.
- Deterministic fixtures and local loopback targets were used for engine tests;
  no arbitrary public target was scanned for this audit.
- Confirmed defects were repaired and given regressions. Speculative features
  and unverified vulnerability claims were not added.
- A browser binary and Puppeteer were unavailable. The browser-only coverage
  gap and exact rerun procedure are recorded in `tests/browser/README.md`.

## Public-surface inventory

The assembled site contains **20 HTML pages**:

- root hub and custom 404;
- tools catalog and seven tool pages;
- methodology and documentation;
- guides index and one guide for each of the seven tools.

Shared interactive surfaces include the skip link, primary navigation, grouped
Tools dropdown, theme control, scan-engine status/popover, keyboard-shortcut
dialog, recent scans, consent UI, report actions, evidence mode, copy/share and
structured export menus. JavaScript-disabled visitors now receive a status
banner and static links to Home, Tools, Guides, Methodology and Documentation
on every shared-shell page; the 404 retains seven static destinations.

Discovery/deployment surfaces reviewed: `manifest.webmanifest`, `robots.txt`,
`sitemap.xml`, JSON-LD blocks, Open Graph image/icons, `llms.txt`, `humans.txt`,
`.well-known/security.txt`, CI, Pages assembly, Vercel configuration and the
artifact leak guard.

### Tool-function inventory and evidence

| Tool | Functions and states reviewed | Primary deterministic coverage |
| --- | --- | --- |
| Clickjacking Validator | URL validation, target fetch, XFO/CSP interaction, frame observation, analyst attestation, PoC overlay, evidence/export/reset and unreachable state | `ScoreTests`, `MultipleCspFrameAncestorsTests`, `OutcomeRollupTests`, `BrowserUxContractTests` |
| Security Headers | URL/redirect handling, complete header grading, cookies, raw evidence, score/grade, export/reset and hosted/browser provenance | `HeaderCheckTests`, `CookieTests`, `GraderParityTests`, `CredentialRedactionTests` |
| CORS Validator | GET baseline, optional HEAD/OPTIONS, preflight method/headers, two-origin proof, null origin, unsupported methods, coverage export and browser limitation | `CorsMethodAwareTests`, `RelayProvenanceTests`, `GraderParityTests` |
| CSP Policy Auditor | URL scan, pasted enforced/report-only policy, repeated/duplicate directives, fallback semantics, suggestion, score/evidence and reset/export | `CspTests`, `CspAuditorTests`, `CspPastedHeaderTests`, `CspGraderParityTests` |
| CSRF PoC Generator | Raw-request parsing, GET/form/JSON/multipart mechanics, token hints, forbidden headers, escaping, inert preview, auto-submit, copy/download/reset and local-only handling | `CsrfParserTests`, `BrowserUxContractTests` |
| JWT Security Workbench | Decode, claim analysis, HMAC/RSA/RSA-PSS/ECDSA verify/sign, edit/generate, key modes, variants, bounded secret test, claim helpers, local-data boundary and reset/export | `JwtWorkbenchTests`, `JwtVaptTests`, `tests/browser/jwt.js` (pending browser runtime) |
| DNS & Domain Security Analyzer | Domain normalization, UDP/TCP DNS, resolver fallback, A/AAAA/NS/MX/TXT/DS/DNSKEY/CAA, SPF/DMARC/DKIM/null-MX grading, incomplete evidence, CLI, consent/provenance and export | `DnsEngineTests`, `DnsParityTests`, `DnsSiteTests`, `HostedDnsApiTests` |

The local server exposes six GET APIs: `/api/health`, `/api/scan`,
`/api/headers`, `/api/cors`, `/api/csp` and `/api/dns`. The hosted `api/`
functions expose the same six contracts. Static tool aliases, slash
canonicalization, `/CyberBuddy/` project-path forms, root assets, 404 behavior
and all seven tool routes are covered by `ServerRouteTests` and the assembled
site audit.

## Confirmed defects repaired

| Area | Confirmed failure | Repair and regression |
| --- | --- | --- |
| Local API boundary | Loopback service accepted unsafe Host/provenance combinations, a non-loopback bind could trust a rebound Host/Origin pair, and redirects were built without a strict local origin boundary | Normalize/validate Host for every loopback bind address, reject cross-site provenance without trusting forgeable `X-Forwarded-Host`, require the non-simple CyberBuddy request header on every scan API call, and emit local redirects; pinned by `ServerRouteTests` |
| DNS input validation | Python could discard pasted URL credentials, accept unsupported schemes and normalize malformed/quoted input differently from the browser | Both runtimes strip only matching ASCII/smart quotes, accept bare domains or HTTP(S), reject URL userinfo and malformed ports, and extract parsed hostnames; Python/Node parity regressions cover quotes, IDNs, credentials, schemes and ports |
| DNS API status | `scan_dns` converts malformed domains into a result, so catching `ValueError` after calling it could return HTTP 200 | Validate before scanning in both `server.py` and `api/dns.py`; real invalid-input tests now require HTTP 400 and prove the hosted scanner is not called |
| DNS wire trust | Responses were not fully correlated to transaction/question and malformed typed answers could enter evidence | Correlate QR, transaction ID, question name/type/class; bound compression parsing; validate typed RDATA; add malformed packet regressions |
| DNS transport | UDP source selection and TCP reads were insufficiently strict; only the first configured resolver was effectively used | Connected IPv4/IPv6 UDP, exact length-prefixed TCP reads, per-query resolver fallback and disclosure of every contacted resolver; fragmented/fallback regressions added |
| DNS deployment budget | The hosted DNS function was omitted from the explicit scanner timeout configuration | Give `api/dns.py` the same 60-second Vercel budget as the other scanning functions and pin the deployment contract in `DnsSiteTests` |
| DNS grading | NXDOMAIN and resolver/parser failures could be presented as fabricated missing-control grades; either half of DNSSEC deployment could be overstated | Return an ungraded error with evidence and unknown risk for failed queries, and require both parent DS and apex DNSKEY evidence before awarding DNSSEC credit in either grader; parity regressions added |
| DNS email/CAA grading | Qualified/CIDR SPF mechanisms could evade lookup counts, invalid duplicate policies were under-deducted, partial DMARC enforcement earned full credit, revoked DKIM keys could count as active, and inherited or non-restrictive CAA was misgraded | Parse SPF lookup mechanisms and terminal policy conservatively, assess DMARC duplicates/`pct`/`sp`, require a non-empty DKIM public key, walk the RFC 8659 CAA tree and require an `issue` property for full CAA credit, and keep Python/browser deductions aligned |
| DNS CLI | Invalid/non-finite options, file failures and duplicate unnormalized targets had weak failure semantics | Validate timeout/resolvers/files, normalize and deduplicate, serialize errors consistently and return meaningful exit codes |
| JWT accessibility | Key-mode controls lacked complete tab semantics/keyboard behavior; claim helper checkboxes and values shared ambiguous labels | Implement nested ARIA tablists with arrow/Home/End selection and independent accessible names; static plus browser regressions added |
| No-JavaScript UX | Shared navigation was injected only by JavaScript, leaving most public pages without useful navigation/status | Add consistent `<noscript>` status/navigation and hardened responsive styles to all 20 pages; `NoScriptFallbackTests` dynamically inventories pages |
| Test coverage drift | Hosted-CSP coverage used a fixed page list and guide length counted fallback chrome; workflow assertions described an obsolete pending patch | Discover all public HTML dynamically, measure guide content without `<noscript>`, and assert the applied workflow/historical note directly |
| Privacy/provenance copy | Some “local” wording could imply no network activity and DNS resolver disclosure was incomplete | Define local as no CyberBuddy relay/server storage; state that HTTP targets and configured DNS resolvers are still contacted; public-copy regressions added |
| Internal documentation | Roadmap/dev notes and the Pages patch record still described completed features or an unapplied workflow | Reconcile current seven-tool state and retain only an explicit historical workflow note |

The DNS result keeps an additive `error` field because ungraded API/CLI clients
need structured failure detail without parsing prose. A proposed `engine` field
was removed: other Python result schemas do not expose it, and frontend
provenance already uses its dedicated source metadata.

## Security and privacy review

- URL and domain engines reject credentials, unsupported schemes and malformed
  ports, redact userinfo from reports/logs/exports and gate public hosted scans
  against metadata, loopback, private and rebinding destinations.
- Connect-time address pinning and redirect validation cover DNS TOCTOU for
  public hosted URL scans. Local private scanning remains an explicit operator
  mode.
- Local API requests are same-origin/provenance checked and responses use
  no-store plus CSP, frame, MIME, referrer, opener/resource and permissions
  headers.
- Generated CSRF/JWT artifacts escape hostile input, remain labelled test
  artifacts and never claim target acceptance. Spreadsheet exports neutralize
  formula prefixes.
- Relay and DNS-provider use is opt-in and named. JWTs, keys, secrets and raw
  CSRF requests are not persisted or sent by CyberBuddy.
- Pages assembly publishes only the intended surface, rejects internal
  docs/tests/review material, checks root-relative references and audits links
  and fragments.
- Repository secret/exposure checks and community/security-policy files remain
  part of the launch gate established by the preceding launch commit.

## Requirement traceability

| Requested criterion | Evidence |
| --- | --- |
| Inventory every page, section, control, tool mode, export and route | Public-surface and tool-function inventories above; `ToolCatalogTests`, `ServerRouteTests`, `HostedCspTests`, `PagesAssetVerificationTests` |
| Audit all seven tools, including hostile input, scoring, reset/export and fallbacks | Seven-row matrix above; engine, parity, UX contract, credential, relay and tool-specific suites |
| Audit navigation, themes, keyboard, accessibility, responsive/no-JS, recent scans, errors, consent and reports | `NoScriptFallbackTests`, `ThemeContrastTests`, `NavAndScrollContractTests`, `ClearRecentScansTests`, `RelayConsentGateTests`, layout/overlay/responsive contract suites; browser runtime caveat retained |
| Audit content, guides, 404, metadata and every local link/fragment | 20-page dynamic inventory, `GuidesTests`, `DocumentationPageTests`, `ReleaseVerificationTests` and clean assembled-site audit |
| Audit SSRF/rebinding, credentials, CORS/origin, relays, DNS disclosure, injection, caching, APIs and deployment | `ValidateTargetTests`, `SessionPoolTests`, `CredentialRedactionTests`, `ServerRouteTests`, `RelayProvenanceTests`, DNS suites, CSRF/JWT suites and Pages leak checks |
| Add regressions, run complete gate and record local limitations | 428 passing tests, clean release verifier and `tests/browser/README.md` |

## Verification result

Final gate executed successfully on 2026-08-19:

```text
python3 -m unittest -q
Ran 428 tests ... OK

python3 -m py_compile dns_security.py server.py test_engines.py
node --check js/app.js

python3 tools/verify.py
Ran 428 tests ... OK
Python syntax: 21 project files
JavaScript syntax: 23 project files
Structured data: 4 JSON/manifest files, 1 XML file, 19 JSON-LD blocks
Pages artifact: 20 HTML pages, local links passed
PASS — tests, syntax, structured data, and Pages links are clean.
```

## Residual release risks and sign-off

1. **Browser execution remains pending.** Chromium/Puppeteer was unavailable;
   no new claim of computed layout, focus, pointer or visual verification is
   made. Run all seven suites documented in `tests/browser/README.md`.
2. Hosted API rate limiting is per serverless instance and best-effort; use a
   shared store or platform WAF where a hard public quota is required.
3. Static GitHub Pages cannot emit response headers such as HSTS or
   `frame-ancestors`; production header posture depends on the hosting layer.
4. Hosted relays, resolvers and target networks are external dependencies and
   can fail or change independently. Failure states remain ungraded and expose
   provenance rather than inventing evidence.

Subject to the browser rerun above, the repository-level release gate is clean
and every confirmed defect found in this audit has a regression.