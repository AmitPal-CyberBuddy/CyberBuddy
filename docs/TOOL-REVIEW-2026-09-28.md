# Seven-tool results, PoCs and visibility review — 2026-09-28

## Scope and outcome

Reviewed all seven tools, their evidence/result paths, and the generated CSRF
and CORS browser PoCs. Fixed reproducible request-generation, feedback,
contrast and result-display defects. This is a scoped regression review, **not
a claim that every target, browser or deployment produces an accurate verdict**.
No external target received a PoC submission; execution tests used disposable
loopback HTTP receivers and dedicated fixture values.

## Fixes

### CSRF

- Sending buttons now show an immediate busy label and spinner, disable duplicate
  submissions, and recover after completion. Motion respects reduced-motion.
- Outcome panels have readable text, a border and a textual state, with polite
  screen-reader announcements. HTTP error responses are distinguished from
  unreadable responses. Fetch attempts time out after 15 seconds.
- Removed the incorrect claim that every rejected fetch was blocked before
  delivery. The message now says **delivery unknown**, warns about repeated
  state changes on retry, and points to verification notes that actually exist.
- Included browser/network, preflight, SameSite/cookie, origin and server-state
  verification guidance in the downloaded file itself, not just the generator.
- Fixed missing auto-submit status markup, native form submission shadowed by
  an input named `submit`, and the lack of manual-form submission feedback.
  Forms still use top-level navigation: no iframe sandbox is introduced that
  would change cookie/navigation mechanics.
- Preserved raw body line endings; removed phantom empty query/body fields;
  repaired loopback scheme detection and IPv6 URL construction.
- Custom X-* headers now produce a LIMITED fetch variant with preflight instead
  of a READY form that silently dropped them. Raw Content-Type values survive.
- Query, URL-encoded, line-shaped text/plain and multipart token exclusions now
  reach fetch variants, and unchecked selections survive regeneration. Query
  indices no longer accidentally exclude unrelated text/plain fields.
- Rejected malformed multipart delimiters; preserved significant trailing
  field newlines and treated empty filenames as file fields.
- HEAD-with-body is not offered as an executable reproduction. Unsupported or
  invalid requests cannot leave a previous PoC available through export buttons.
- Added visible reproducibility limitations. Cookie delivery is conditional,
  and text/plain JSON alternatives no longer claim byte-exact serialization.

### CORS, DNS and shared UI

- CORS PoCs now have busy/duplicate-click handling, timeout/retry states,
  prominent result panels, accessible announcements, verification notes and
  automatic light/dark styling. Readable HTTP errors are not labelled CORS
  failures. Readability alone does not prove authenticated data exposure.
- CORS scanner wording calls reflected origins + credentials **high risk** and
  asks for browser verification, rather than asserting a proven exploit.
- DNS NXDOMAIN/error results no longer show `0 / 100` beside “not graded”.
- Increased secondary-label contrast on raised surfaces and chips; introduced
  theme-specific D-grade colors; strengthened light-theme severity text and
  input boundaries; corrected dark-console labels and code-on-code styling.
- Busy shared buttons retain readable opacity and expose `aria-busy`.
- Export menus are clamped to the actual viewport so their bottom actions remain
  reachable on phones. JWT tabs wrap on phones; CORS/JWT checkbox labels have
  minimum touch height. Long documentation examples can wrap.

## Verification

Environment: Python, Node 22, Chromium 153.0.8010.0, Puppeteer Core 25.12.0,
axe-core via `@axe-core/puppeteer`. Browser dependencies were installed outside
Git; no runtime/build dependency was added to the application.

| Coverage | Outcome |
| --- | --- |
| `python3 tools/verify.py` | 440 tests; Python/JS syntax, structured data and assembled-site links pass |
| `tool-results.js`, 1366px and 390px, both themes | All seven tool paths pass; no axe text-contrast violations in the exercised initial/result/error/tab states |
| `poc-execution.js` | 30 execution cases pass, including manual/auto fetch, CORS, native forms and both themes |
| `csrf.js` | 22 browser assertions pass, including seven widths, both themes, copying/downloading and inert/local-only generation |
| `jwt.js` | 19 browser assertions pass; corrected the harness to decode a fixture and activate the intended visible tabs before focusing controls |
| `overlays.js` | 48 browser assertions pass, including phone exports |
| Expanded contrast unit matrix | Text on surfaces 1–3, chips/panels and severity/D-grade tints meets 4.5:1 in both themes |

### Per-tool evidence and limits

| Tool | Evidence exercised | Limits |
| --- | --- | --- |
| Clickjacking | Python/browser framing graders, local scan, report/export paths, live frame and PoC overlay | Frame `load` alone does not prove rendered target UI; cross-origin visual confirmation remains analyst-attested |
| Security Headers | Existing grader fixtures/parity tests; real local HTTP scan and grade/export checks | Grades describe measured response headers, not application exploitability |
| CSP | Existing directive/enforcement/parity fixtures; live local scan and policy evidence/export check | No exhaustive browser exploit campaign against every policy combination |
| CORS | Existing method/origin/preflight fixtures; live local scan; actual standalone browser reads and failures | Browser cookie/privacy policies and target-specific authenticated data still need confirmation |
| DNS | Existing resolver/wire/parser/parity tests; real Python grader fixtures rendered in UI, including NXDOMAIN | No fresh public-resolver/live DNS integration verification |
| CSRF | Expanded parser/generator tests; UI state/exclusion/copy/download checks; actual request counts/bodies at local receivers | No PoC establishes a vulnerability without authorized state-change verification; arbitrary binary bodies are not a byte-exact replay facility |
| JWT | Existing crypto/claims/signing/variant tests; real browser HMAC match/mismatch; tab and output contrast checks | Local signature verification never proves a target accepts a generated test token |

## Remaining coverage / follow-up

- Firefox, Safari, OS forced-colors and an authenticated cross-site cookie matrix
  were not exercised. Automated contrast tests cover the stated fixture states,
  not every possible user-supplied value/background or manual overlay opacity.
- The broad **legacy site-wide** dropdown/responsive runs were diagnostic, not
  clean release gates. They reported a stale HAR label assertion, intermittent
  menu-animation visibility checks, and descendants intentionally outside the
  viewport inside horizontal scroll containers. The responsive run also hit
  Puppeteer's unsupported `prefers-contrast` emulation call. Some genuine small
  target/wrapping defects were fixed here, but those entire legacy suites have
  **not** been certified clean by this review. The focused seven-tool and
  overlay suites above are the passing browser evidence.
- The all-route layout and relay-gate suites were not completed in this review.
  Existing static/unit coverage still runs in the release verifier.
- Public hosted relays, provider rate limits and production deployment behavior
  were not exercised. Re-run browser suites in the release browser matrix and
  manually confirm target-specific state changes before reporting findings.


## Follow-up: public landing/reference pages — 2026-09-28

Extended the visibility review to **all 20 public HTML pages**: home, tool
catalog, seven initial tool screens, guides index and seven individual guides,
documentation, methodology and the standalone 404 page. Checked desktop
(1366px) and phone (390px), both themes, real theme switching, expanded
explanatory panels, navigation menus and representative hover/keyboard-focus
states. This follow-up does not change the older layout-suite caveats above.

Additional fixes:

- Kept terminal command text and the homepage's cached-demo badge on a dedicated
  dark-panel palette even when the surrounding page uses light mode. Previously
  the command and badge measured approximately 3.6:1 and 2.8:1 respectively.
- Darkened light-theme explanatory text on tinted note backgrounds (a measured
  4.16:1 case) and regular/hover links, including the JWT guide warning card.
- Changed the blog monogram to theme-aware foreground ink; white lettering on
  the dark theme's bright gradient had measured approximately 1.94:1.
- Corrected the independent 404 light-theme palette: recovery-card links were
  approximately 3.74:1, and the small 404 label approximately 3.42:1. Added explicit
  theme color-schemes, keyboard focus styling and reduced-motion handling there.

Verification: the complete new `site-contrast.js` run passed **80 page/theme/width
combinations**, plus **220 additional interaction/disclosure states**, with
**16,528 text/control samples**. A subsequent focused rerun additionally checks
hover/focus on the tinted JWT guide link. The release verifier now passes
**443 tests**, syntax, structured-data and site-link checks.

Important measurement qualification: axe could not resolve many gradient or
pseudo-element backgrounds (12,596 incomplete observations across repeated
states). These were not treated as passes. A calibrated rendered-background
sampler supplements axe, compares computed foreground colors to screenshot
background pixels and checks 4.5:1 for ordinary text / 3:1 for large text.
Sampling is conservative for gradient text but not exhaustive for every pixel,
opacity, animation frame or overlapping element. This is Chromium regression
coverage, not full WCAG certification; Firefox/Safari and OS forced-color modes
remain unverified.
