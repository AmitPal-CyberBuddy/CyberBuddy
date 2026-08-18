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
npm install --prefix /tmp/cyberbuddy-browser puppeteer-core
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
for suite in layout dropdown overlays relay-gate responsive csrf jwt; do
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

The stdlib suite separately pins the DOM/controller contracts and expected CSS
rules. A browser pass complements those checks; it does not replace
`python3 tools/verify.py`.

## Current audit limitation — 2026-08-18

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