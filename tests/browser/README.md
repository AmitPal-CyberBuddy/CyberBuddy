# Real-browser regression suites

These suites exercise behavior that static markup checks and Node-based unit
tests cannot prove: computed layout, focus movement, pointer hit-testing,
overlay stacking, browser navigation, clipboard/download affordances and
responsive rendering.

They are intentionally separate from `python3 tools/verify.py`. The release
gate has no runtime dependency installation, while these suites require a real
Chromium-family executable and `puppeteer-core`.

## Prerequisites

- Python 3.10+
- Node.js 20 or later
- Chromium, Chrome or another Puppeteer-compatible Chromium executable
- `puppeteer-core`, installed outside this repository

A disposable dependency installation keeps generated files out of Git:

```bash
npm install --prefix /tmp/cyberbuddy-browser puppeteer-core @axe-core/puppeteer pngjs
export NODE_PATH=/tmp/cyberbuddy-browser/node_modules
export CB_CHROME=/absolute/path/to/chromium
```

Do not set `CB_CHROME` to a Firefox or WebKit executable; these scripts use
Puppeteer’s Chromium protocol.

## Run the suites

Start CyberBuddy in one terminal. The loopback bind permits the controlled
local target used by scanner tests:

```bash
python3 server.py --port 8080
```

Start a second local target in another terminal:

```bash
python3 server.py --port 8099
```

Then run every suite:

```bash
export CB_BASE=http://127.0.0.1:8080
export CB_TARGET=http://127.0.0.1:8099/
for suite in layout dropdown overlays relay-gate responsive csrf jwt tool-results poc-execution site-contrast; do
  node "tests/browser/${suite}.js" || exit 1
done
```

Each script exits non-zero when an assertion fails. `CB_BASE`, `CB_TARGET` and
`CB_CHROME` may be overridden for another controlled environment. Use only
systems you own or are authorized to test.

For the responsive suite’s hostile long-header case, start its fixture and set
`CB_STRESS`:

```bash
python3 tests/browser/stress_target.py --port 8098
CB_STRESS=http://127.0.0.1:8098/ node tests/browser/responsive.js
```

## Coverage

| Suite | Browser-only evidence |
| --- | --- |
| `layout.js` | All public routes, reveal visibility, report geometry, evidence mode and print layout |
| `dropdown.js` | Tools-menu keyboard/pointer behavior, stacking, containment and project-path links |
| `overlays.js` | Export menu, engine popover, shortcuts dialog, share/copy controls and hit-testing |
| `relay-gate.js` | Relay-consent visibility, focus, choices, disclosure and cancellation |
| `responsive.js` | Seven viewport widths, two themes, all result states, touch targets and hostile long values |
| `csrf.js` | Generate/reset/copy/download flows, auto-submit warning, inert preview and local-data boundary |
| `jwt.js` | Nested key-selector tablists, arrow-key focus/selection and distinct claim-control names |
| `tool-results.js` | All seven tools in both themes: live loopback HTTP scans/exports, offline Python-graded DNS fixtures (including NXDOMAIN), JWT verification, CSRF exclusion persistence and axe text contrast; use `CB_WIDTH=390` for phone coverage |
| `poc-execution.js` | Standalone CSRF/CORS artifacts executed against temporary local HTTP receivers: readable success/error responses, delivered-but-unreadable POST, rejected preflight, timeout, auto-submit, duplicate-click guard, form navigation and contrast in both themes |

| `site-contrast.js` | Discovers all public HTML pages, tests light/dark at 1366px/390px, real theme toggles, initial screens, disclosures and representative hover/focus/menu states; axe plus rendered background sampling (including gradients, placeholders and control values) |

The stdlib suite separately pins the DOM/controller contracts and expected CSS
rules. A browser pass complements those checks; it does not replace
`python3 tools/verify.py`.

## Public-page contrast follow-up — 2026-09-28

`site-contrast.js` requires `pngjs` as well as the browser/axe prerequisites.
It does not submit scans. It discovers the public pages directly from the
repository and fails on contrast regressions. A temporary glyph-free screenshot
samples the rendered gradient/translucent background beneath text; all page
styles are restored. Positive/negative calibration controls prevent an empty
sampler from passing silently. Screenshots are processed in memory, not saved.

```bash
node tests/browser/site-contrast.js
# Optional focused rerun:
CB_WIDTHS=390 CB_ROUTES=/,/404.html,/guides/jwt/ node tests/browser/site-contrast.js
```

Axe's `incomplete` observations are reported, **not counted as passes**. Pixel
sampling complements those observations, but is not exhaustive accessibility
certification: it samples three points per text rectangle, skips disabled/faded
content, and does not evaluate every animation frame, native select popup,
forced-color setting or browser. The normal screen, not print or no-JS mode, is
covered. The scope and findings are recorded in the tool-review document.

## Tool-result / PoC review — 2026-09-28

See `docs/TOOL-REVIEW-2026-09-28.md` for the current scoped review, fixes,
executed tests and remaining coverage gaps. The two new suites additionally
require `@axe-core/puppeteer`. `poc-execution.js` starts and closes its own two
loopback servers; it never submits to an external target. `tool-results.js`
uses `CB_BASE` and `CB_TARGET` as above, and deliberately intercepts DNS API
responses with Python-graded offline fixtures rather than contacting a public
resolver. These fixture checks do **not** claim a live public-DNS integration pass.

```bash
node tests/browser/tool-results.js
CB_WIDTH=390 node tests/browser/tool-results.js
node tests/browser/poc-execution.js
```

## Historical audit limitation — 2026-08-18

The comprehensive launch audit ran all stdlib tests, Node syntax checks,
structured-data parsing and the assembled-site link/fragment audit. These
real-browser suites were **not executed in the audit sandbox** because it had
no Chromium/Chrome executable and no Puppeteer module. Installing a browser
was not possible from the available package/download endpoints.

This is an environmental coverage gap, not a recorded pass. Run the commands
above in a Chromium-equipped environment before release approval, and attach
the suite output to the pull request or release record. No visual,
focus-management, pointer-hit-testing or computed-layout claim in that audit
should be interpreted as newly browser-verified.