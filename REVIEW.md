# CyberBuddy — project review

> **Status: all recommendations in this review have been implemented** (see
> `git log`). Repo stays **public** under Apache-2.0. This document is kept as
> the rationale record — each section explains *why* the change was made.
> Verified after the work: 78 unit tests pass, all five pages render clean in a
> DOM harness, and CyberBuddy now scores **A (95/100)** against itself, up from
> C (65/100).

Date: 2026-08-14 · Reviewed at commit `ca13040` · Reviewer notes for Amit

> Note: the screenshot you mentioned did not reach my workspace, so the layout
> section below is based on reading the markup/CSS and comparing against your
> earlier `Clickjacking-Validator` repo (`Clickjacking.html`), which I did pull
> and read. If you re-attach the image I can be more specific.

---

## 0. Verdict up front

The engineering is genuinely good: zero dependencies, stdlib-only Python, 68
passing unit tests, a real SSRF guard (`validate_target`), a print stylesheet,
PWA metadata, `security.txt`, OWASP/CWE mapping. It is well above the usual
"pentest tool portfolio project" bar.

The three things you asked about are all real, and two of them are more serious
than you framed them. In priority order:

| # | Issue | Severity | Your Q |
| --- | --- | --- | --- |
| 1 | Target URLs are sent to **4 third-party relays** on the hosted site, undisclosed before the scan | **High (privacy/scope)** | 3 (adjacent) |
| 2 | Print/PDF export **hides the red PoC overlay** — the actual clickjacking evidence | **High (correctness of evidence)** | 1 |
| 3 | "Visual confirmation required + 2 options" flow from the old repo was **lost** in the rewrite | Medium-high (regression) | 1 |
| 4 | Tool pages don't fit one screenshot; hero + toolbar push the report below the fold | Medium | 1 |
| 5 | "Clear" on recent scans **doesn't clear** the header-lookup cache (which holds URLs + response headers) | Medium | 3 |
| 6 | `http_session` opener cache ignores `allow_private` → wrong redirect policy can be reused | Medium (SSRF-adjacent) | — |
| 7 | No LICENSE file | Medium (IP) | 2 |
| 8 | JS graders are a second implementation of the Python graders with **zero tests** | Medium (drift) | — |

---

## 1. Layout, screenshot-ability, and "Download PoC image"

### 1a. Why the old page screenshotted better

`Clickjacking-Validator/Clickjacking.html` is: `h1` + one-line lead + one input
bar + a **2-column grid** (header scan | frame test). Total vertical stack above
the evidence ≈ 180px. Everything lands in one 1080p viewport, so Snipping Tool
gets a complete page in one shot.

`tools/clickjacking/index.html` stacks, before you reach any evidence:

```
site-header (sticky)          ~64px
kicker "Tool 01"              ~30px
h1                            ~55px
lead (2 lines)                ~56px
std-line (OWASP/CWE)          ~28px
.bar with 6 buttons           ~96px  (wraps to 2 rows under ~1100px)
page-hero padding-top 48px    ~48px
                              ------
                              ~380px before .results even starts
```

Then the report card itself is `report-head` → `meta-grid` (4 tiles) →
`verdict-banner` → `poc-grid` (stage is **440px** tall) → findings table →
raw-headers `<details>`. That's ~1100px of card. So the analyst gets roughly
"top of card" or "the frame", never both, in a single snip.

**Recommended fix — an "Evidence mode" that collapses the page after a scan.**
No new dependency needed; it's one class toggled on `<body>` when results
render:

```css
/* Applied after a successful scan */
body.evidence .kicker,
body.evidence .lead,
body.evidence .std-line { display: none; }
body.evidence .page-hero { padding-top: 18px; }
body.evidence h1 { font-size: 1.25rem; margin-bottom: 8px; }
body.evidence .bar { padding: 10px 12px; }          /* keep it — it shows the target */
body.evidence .stage { height: min(52vh, 420px); }
body.evidence .results { margin-top: 14px; }
body.evidence .site-header { position: static; }     /* don't overlap on capture */
```

Plus, on render: `document.getElementById("results").scrollIntoView({block:"start"})`.
That alone gets the whole report card into ~900px and makes the existing
Snipping-Tool workflow work like the old page did.

Also worth doing:
- Move `Copy report` / `Copy JSON` / `Share link` into an overflow "…" menu or a
  second row below the results, so the primary bar is `[URL] [Validate] [PoC
  overlay] [Export]`. Six equal-weight ghost buttons is the main reason the bar
  wraps.
- The report card currently has no visible **branding/timestamp footer**. For a
  VAPT screenshot you want "CyberBuddy · <target> · <UTC timestamp> · source:
  python engine" burned into the card itself, so the screenshot is
  self-authenticating even when cropped. `meta-grid` has the data but the
  timestamp is local-format and the tool name isn't in the card.

### 1b. The print/PDF path has a real bug

`css/app.css:1212-1214`:

```css
@media print {
  ... .overlay ... { display: none !important; }
}
```

`.overlay` is **the red "CLICK HERE — decoy overlay" box**. It is the entire
visual proof of UI redressing. Right now, if an analyst turns on the PoC overlay
and hits Export / Print, the PDF shows the framed site *without* the decoy — i.e.
the exported artefact is strictly weaker than the on-screen one. Remove
`.overlay` from that hide-list (keep `.ambient`, `.aurora`, `.radar` etc.).

Same list hides `.notice`, which is where the "Target not reachable — <reason>"
explanation lives on the headers page. That text should print.

Related: `.stage { height: 300px }` in print will letterbox the frame; consider
`height: 420px` and `-webkit-print-color-adjust: exact; print-color-adjust: exact`
on the report card so the risk colours survive the PDF (right now the browser may
drop the coloured backgrounds and you lose the HIGH/red signal).

### 1c. "Download PoC image" — feasible, but know the constraint

You asked to merge this into Export. It's a good idea, but there is a hard
browser limitation you should design around:

**You cannot rasterise a cross-origin iframe.** `html2canvas` explicitly does not
render iframe content, and any canvas that touched cross-origin pixels is
tainted and `toDataURL()` throws. So there is no pure-JS way to produce a PNG of
"our report card *with* the live target rendered inside it".

Two workable paths:

1. **`getDisplayMedia({ preferCurrentTab: true })` + `ImageCapture`/canvas.**
   This captures actual screen pixels, so the iframe *is* included. Needs HTTPS
   (Pages is fine), one user gesture, and shows the browser's share picker.
   Support: Chrome/Edge desktop full (tab capture), Firefox desktop offers
   window/screen only (no single-tab), Safari 13+ window/screen, **iOS not at
   all**. So: feature-detect, and label the button honestly.

2. **Synthesised evidence card (no live frame).** Build the PNG yourself from the
   scan JSON — draw target/final URL/status/verdict/findings/raw headers onto a
   `<canvas>` (or an SVG `foreignObject` → canvas, same-origin only, no taint).
   Deterministic, works everywhere, no dependency, and it's arguably the better
   *report* artefact. It just can't show the framed site.

**My recommendation:** make Export a small split control —

```
[ Export ▾ ]
   Print / Save as PDF        (existing window.print())
   Download PoC image (PNG)   (getDisplayMedia when available)
   Download evidence card     (canvas-rendered, always available)
   Copy report (Markdown)
   Copy JSON
```

…and when `getDisplayMedia` is unavailable, the PoC-image item is disabled with
a tooltip "Use your OS snipping tool — this browser can't capture the frame".
That is honest and still leaves the improved layout doing the heavy lifting.

Do **not** pull in `html2canvas` for this. It's ~200KB, it would be your first
third-party dependency (killing a genuine selling point), and it cannot do the
one thing you need it for.

### 1d. The lost "visual confirmation required" flow — this is the one to restore

In the current build, when there's no Python engine and no relay data
(`isEngineDown(data)` branch, `tools/clickjacking/index.html`), you get:

```
risk = "FRAME ONLY"
findings row: "Frame test / info / Visual proof only. Header values are not
               available from this host."
```

…and that's terminal. The analyst sees the frame render, knows it's
clickjackable, but the report card still says FRAME ONLY and the exported
Markdown/JSON says `risk: FRAME ONLY`. The evidence and the verdict disagree.

The behaviour you liked — "cannot confirm, visual confirmation required" +
**two buttons**, and picking one updates the verdict — is exactly right and
should come back, better than before:

```html
<div id="visualConfirm" class="confirm-prompt hidden">
  <p>Header values are unavailable from this host. Look at the frame above:</p>
  <button data-verdict="framed">The real site is rendered → framing allowed</button>
  <button data-verdict="blocked">Blank / refused → framing blocked</button>
</div>
```

On click:
- `framed` → risk **HIGH**, protection line "NOT ENABLED", finding row
  `Frame test / missing / Analyst-confirmed: target rendered inside a
  cross-origin frame.`
- `blocked` → risk **LOW**, protection "ENABLED (observed)", finding
  `Frame test / protected / Analyst-confirmed: target refused to render.`

Two things to get right that the old version didn't:
- Stamp the result as **analyst-attested**, not machine-measured — add
  `"confirmation": "manual"` to the JSON and a line in the Markdown export. In a
  VAPT report that distinction matters if the finding is ever challenged.
- Add a cheap automatic hint alongside it: a `load` event that fires with a
  ~0-height/blank document, or no `load` within ~6s, is a strong signal for
  "blocked". Pre-select the likely button rather than leaving it neutral.

Also worth surfacing on that card: with `sandbox="allow-scripts allow-forms"`
(no `allow-same-origin` — a good hardening change vs. the old repo, which used
`allow-same-origin` and shouldn't have), some sites render blank for reasons
*unrelated* to framing headers (they need same-origin storage/cookies). Say so
in the note, otherwise you'll log false "protected" results.

---

## 2. Public vs private repo

Short answer: **keep it public, and add a LICENSE.** Reasoning:

### The security argument for going private doesn't hold

Everything the hosted site actually executes — `index.html`, `js/app.js` (1769
lines, including your full grader port), `css/app.css`, all three tool pages —
is already served to every visitor's browser and trivially saved. GitHub Pages is
static; there is no server-side code running there at all. Making the repo
private would hide only:

- `server.py`, `apilib.py`, `api/*` (not used by the hosted site unless you set
  `API_BASE`)
- the three Python engines and `test_engines.py`
- the workflows and `urls.txt`

…while the frontend, which is 100% of the hosted product, stays public by
necessity. So you'd be trading away credibility (a security portfolio project
with a hidden repo reads oddly) for approximately zero confidentiality.

### The mechanics, if you still want private

- GitHub Pages from a **private repo requires GitHub Pro/Team** — it's not on the
  free plan. The *site* is still public either way; a genuinely private site is
  an Enterprise Cloud feature.
- Free alternatives that serve from a private repo: **Cloudflare Pages,
  Netlify, Vercel**. If you're already considering deploying `api/` to Vercel,
  hosting the static site there too from a private repo is the coherent option.

### What actually protects you: a LICENSE

There is **no LICENSE file** in the repo. Right now the code is "all rights
reserved" by default, which is more restrictive than most people assume — but
it's also ambiguous to anyone who might want to contribute, and it's the first
thing a recruiter or a security team looks for. Pick deliberately:

- `Apache-2.0` — permissive + explicit patent grant, standard for security tools.
- `AGPL-3.0` — if you want anyone hosting a modified copy to publish their changes.
- A source-available licence (e.g. BUSL/PolyForm Noncommercial) — if the real
  worry is someone rebranding it commercially. This is the honest answer to
  "anyone can just download the whole code": you stop them with a licence, not
  with `git`.

### If you do go private — the exact things to change

You asked whether the GitHub link and CLI references would have to go. The link
would 404, so yes. Locations:

| File | Line | What |
| --- | --- | --- |
| `js/app.js` | 266 | footer "Source on GitHub" link |
| `index.html` | 70 | JSON-LD `author.sameAs[]` |
| `llms.txt` | 7 | `- Source: https://github.com/…` |
| `README.md` | many | repo-relative instructions |
| `.github/workflows/pages.yml` | — | still fine, workflows run in private repos |

On the **CLI**: it isn't a leak vector — it's a feature for whoever runs it
locally. But the *hosted* site currently tells anonymous visitors to
`python3 server.py` in three places, which is confusing if they can't get the
code:

- `tools/headers/index.html:147` and `:232` (the "Could not read headers" notice)
- `js/app.js:1408` (`gradeHeadersLive` summary)
- `methodology/index.html:166`

If the repo goes private, rewrite those to "Full header reads aren't available
from the hosted site for this target" and drop the command. If it stays public,
leave them — they're genuinely useful.

---

## 3. Cached responses / search history — is it universal?

You're conflating two different mechanisms. I checked both.

### 3a. Recent scans + lookup cache — per-browser, NOT shared. But under-disclosed.

| Key | Contents | Scope | TTL |
| --- | --- | --- | --- |
| `cb-recent-scans` | last 5 target URLs | this browser profile | **none — forever** |
| `cb-header-lookup-v1` | target URL → full response headers + status | this browser profile | 10 min |
| `cb-theme` | dark/light | this browser profile | none |

All `localStorage`. Never transmitted. So **no cross-user leakage** — your
instinct that it might be a privacy violation doesn't apply *between* users.

But there are two real gaps:

1. **The UI never says so.** The hub renders a bare `Recent:` chip row. An
   analyst on a shared/loaner laptop, or screen-sharing during a debrief, has no
   idea those client URLs are persisted. Add a one-liner under the chips:
   *"Stored only in this browser (localStorage). Never uploaded. Clear removes
   them."* That is a 5-minute change and it's the difference between "fine" and
   "defensible".

2. **`clearRecentScans()` is incomplete** (`js/app.js:1637`). It removes
   `RECENT_KEY` only. `cb-header-lookup-v1` — which holds the target URLs *and*
   their full response headers, i.e. strictly more sensitive than the recent
   list — survives the Clear button for another 10 minutes. Fix:

   ```js
   function clearRecentScans() {
     try {
       localStorage.removeItem(RECENT_KEY);
       localStorage.removeItem(HEADER_CACHE_KEY);
     } catch (_) {}
   }
   ```

   And consider a "Private session" toggle that switches both to `sessionStorage`,
   plus an expiry on recent scans (e.g. 24h) so a laptop that sits idle doesn't
   keep last month's client names.

### 3b. `cache/<host>.json` — this one IS global, but contains no user data

`tools/build_cache.py` pre-scans `urls.txt` in GitHub Actions and publishes
`cache/<host>.json` to Pages. Every visitor reads the same files. But `urls.txt`
contains only `example.com`, `example.org`, `example.net`, and your own Pages
origin — nothing a user typed ever gets written there. So: universal, but not a
leak.

The problem is **wording**. The source chip says `via cached report`, which reads
like "someone else's scan of your target was cached and served to you". Rename it
to `via published report` or `pre-scanned demo` and add one line to the
methodology section: *"Published reports cover only the demo targets in
urls.txt. Your scans are never uploaded, cached server-side, or shared."*
That sentence answers your question for every user who has the same one.

### 3c. The actual privacy problem you didn't ask about — third-party relays

This is the finding I'd fix first. `js/app.js:1362-1369`, `lookupHeadersRemote()`:

```js
const ht = "https://api.hackertarget.com/httpheaders/?q=";
const probes = [
  ht + encoded,                                              // hackertarget.com
  host ? ht + encodeURIComponent(host) : "",
  "https://api.allorigins.win/raw?url=" + …,                 // allorigins.win
  host ? "https://api.allorigins.win/raw?url=" + … : "",
  "https://corsproxy.io/?url=" + …,                          // corsproxy.io
  "https://api.codetabs.com/v1/proxy?quest=" + …             // codetabs.com
];
```

On GitHub Pages with no `API_BASE` configured — **which is the default path for
every single visitor to your hosted site** — the full target URL, including path
and query string, is sent to up to four unrelated third parties, sequentially,
until one answers. Those operators also see the tester's IP and timing.

For an authorised VAPT that is a genuine problem:

- The client's hostname (often an internal-ish or pre-release host, e.g.
  `uat-payments.client.example`) is disclosed outside the engagement.
- Paths and query strings can carry tokens, tenant IDs, or the very endpoint
  under test.
- Many engagement NDAs prohibit exactly this. The footer's "scans run in your
  browser" line is, strictly speaking, misleading — the *grading* runs in the
  browser; the *fetch* is proxied by strangers.

Recommended, in order:

1. **Disclose it before the first scan, not in the footer.** A dismissible banner
   on the hosted site: *"No Python engine detected. Header reads will be proxied
   via public services (hackertarget, allorigins, corsproxy, codetabs) — your
   target URL is disclosed to them. Continue / Use local server.py instead."*
   Ideally make it an explicit opt-in stored per session.
2. **Send the host, not the full URL, by default.** Your probe list already has
   host-only variants — reorder so `ht + host` is tried *first*, and only fall
   back to the full URL if the analyst opts in. Most header checks are
   origin-level anyway.
3. **Mark relay-sourced findings as unverified.** A relay can return anything;
   `parseRawHeaderDump` will happily parse attacker- or operator-controlled text
   into an "evidence-grade" report. The `source-chip` already says `live lookup`
   (good) — make sure that string is prominent in the *screenshot* and in the
   Markdown/JSON export, and add a short "not independently verified" note when
   `_source === "relay"`.
4. Document the relay list in `README.md` and `methodology/`.

If you deploy `api/` to Vercel and set `API_BASE`, all of this goes away for
hosted users — which is a strong argument for doing it. See §4 for the caveats.

---

## 4. Security review (beyond your three questions)

**`http_session.py` opener cache ignores `allow_private` — fix this.** Verified:

```
p.get_opener(insecure=False, allow_private=True)  is
p.get_opener(insecure=False, allow_private=False)   →  True
```

The cache key is `insecure` only, but the opener bakes in a `SafeRedirect`
handler that closes over `allow_private`. So in any process where both values are
used, **the first call wins for the whole process** and a later
`allow_private=False` scan can follow a redirect into RFC1918/loopback. Today
`server.py` sets it once at startup so it's latent, but `tools/build_cache.py`,
the test suite, and any future `api/` variant are exposed. Fix:

```python
def get_opener(self, insecure: bool, allow_private: bool):
    key = (insecure, allow_private)
    with self._lock:
        if key not in self._openers:
            self._openers[key] = self._build_opener(self._make_ssl_context(insecure), allow_private)
        return self._openers[key]
```

Add a regression test asserting the two openers differ.

**DNS TOCTOU.** `validate_target()` resolves via the 300s-TTL cache, then
`urlopen` resolves independently. A hostile DNS server can answer public for the
check and private for the fetch (classic rebinding). Low practical risk for a
scanner an analyst points at their own targets, but the guard advertises more
than it delivers — worth a comment, or pin the resolved IP into the connection.

**The Vercel `api/` is an open proxy.** `apilib.py` rate-limits 30 req/60s in a
module-level dict. On serverless that dict dies with every cold start and each
concurrent instance has its own — so the effective limit is ~unbounded. Before
you publish `API_BASE`, either accept that (it only does read-only GETs, which is
what the relays do anyway) or move the counter to a KV store. Also note
`CB_ALLOW_ORIGIN` defaults to `*`.

**`_api_allowed()` in `server.py`** returns `True` when there's no
Origin/Referer/X-Requested-With. That's deliberate (curl support) and mostly
fine: `fetch` sends Origin, `<img>`/`<script>` send Referer. Good enough for a
loopback service; just don't reuse the pattern if you ever bind publicly.

**iframe sandbox** — dropping `allow-same-origin` (which the old repo had
alongside `allow-scripts`, a known-unsafe combination) is a real improvement.
Keep it. Just document the false-negative caveat noted in §1d.

**Own-site posture is inconsistent with the product.** `server.py` ships
`script-src 'self' 'unsafe-inline'` — required because the tool pages use inline
`<script>` blocks and three `onclick=` attributes each. Run CyberBuddy against
itself and it scores **65/100, grade C, MEDIUM** (I ran it). For a tool whose
whole pitch is header grading, that's the single highest-leverage credibility
fix available: move the per-page scripts to `tools/<name>/tool.js`, replace the
`onclick=` handlers with `addEventListener`, drop `'unsafe-inline'`, and add
`Permissions-Policy` + `Cross-Origin-Resource-Policy`. Then put "CyberBuddy
scores A on itself" on the hub. That's a genuinely good line.

---

## 5. Code quality / maintainability

- **The JS graders are an untested second implementation.** `js/app.js` contains
  a full port of the Python scoring (`WEIGHTS`, `checkCsp`, `checkHsts`,
  `checkXfo`, …). All 68 tests cover the Python side; there is nothing asserting
  the two agree. Two scoring engines that must stay in lockstep, with a test
  suite for one of them, will drift — and when they do, the same target gets
  different grades on Pages vs locally, which is exactly the kind of thing that
  gets a finding disputed. Fix: a golden-file test — a fixture of header maps →
  expected `{score, grade, risk, per-check status}`, consumed by both the Python
  tests and a tiny Node script in CI.
- **Duplicated response-header block** in `server.py._send` and
  `_send_file_streaming` (~20 lines of CSP copy-pasted). Extract
  `_security_headers()`.
- **Manual cache-busting.** `?v=20260814c` is hand-maintained across 5 HTML
  files. One forgotten bump ships a stale CSS/JS to returning users. Either
  generate it in the Pages workflow or hash the filenames.
- **`concurrent_scanner.py`** is only imported by `tools/build_cache.py`, but the
  README implies the CLIs use it. Either wire it into the `-f urls.txt` CLI path
  or correct the docs.
- **`PERFORMANCE.md`** reads as internal notes about a `performance-optimization`
  branch that's already merged. Move to `docs/` or fold the useful parts into the
  README; a root-level file describing a dead branch confuses readers.
- **`.gitignore` has `/cyberbuddy-final/` and `/cyberbuddy-final.zip`** — manual
  upload artefacts. Fine, but if you're building a delivery zip by hand, a
  `make dist` target would be less error-prone.

---

## 6. SEO / metadata / hosting details

- **`robots.txt` and `.well-known/security.txt` are ineffective on a project
  Pages site.** Crawlers read `https://amitpal-cyberbuddy.github.io/robots.txt`
  (domain root), not `/CyberBuddy/robots.txt`. Same for `security.txt` — the spec
  requires domain root. On `user.github.io/project/` you cannot write the root
  unless you also own the `amitpal-cyberbuddy.github.io` repo. If you do, put
  them there; otherwise they're decorative. A custom domain would fix both
  properly.
- Also, `robots.txt` has `Allow:` directives with no `Disallow:` — a no-op.
- **`sitemap.xml` is missing `/methodology/`** (4 URLs listed, methodology isn't
  one) even though the workflow publishes it and it has its own canonical.
- **`manifest.webmanifest` hardcodes `/CyberBuddy/`** for `id`, `start_url`,
  `scope`, and all four shortcuts. Installing the PWA from a local `server.py`
  on `http://127.0.0.1:8080/` will produce a broken scope. Minor, but the
  manifest is linked from every page including local ones.
- `humans.txt` says "Last update: 2026-08-13" and is hand-maintained — it'll rot.
- No `LICENSE` (see §2).

---

## 7. Accessibility / UX (quick pass)

Good: skip link, `aria-live` on verdicts, real `<table>` with `<th scope>`,
`aria-current` on nav, reduced-motion block, keyboard shortcuts with a `?` help
dialog, iframe `title`.

Gaps:
- `--faint: #667084` on `--paper: #07090d` is ≈4.0:1 — under AA for the small
  9-11px uppercase mono labels it's used for (`.meta-label`, `.card-title`,
  `.f-status`). Lift to ~#7d8798.
- The keyboard-help dialog sets `aria-modal` but doesn't trap focus or restore it
  on close.
- `.recent-scans { display: none }` under `prefers-reduced-motion` — that hides
  *functionality*, not motion. Looks like a stray selector in that block.
- Six sibling ghost buttons in `.bar` with no grouping; screen-reader users hear
  a flat list of unlabelled-context actions. Wrap the export/copy/share trio in a
  `<div role="group" aria-label="Export and share">`.

---

## 8. Work completed

All items below shipped in this branch.

**Privacy**
- Relay consent gate — nothing reaches a third party until the analyst agrees;
  hostname-only by default, full URL opt-in, or decline entirely. Verified: with
  target `https://target.example/secret/path?token=abc123`, only
  `target.example` left the browser.
- Relay-sourced findings carry an `unverified` badge in the UI, the provenance
  strip, the Markdown export and the JSON.
- A direct CORS read is attempted first (no third party involved).
- `clearRecentScans()` now also clears `cb-header-lookup-v1`.
- Recent scans expire after 24h and carry an explicit "stored only in this
  browser" note.
- `via cached report` → `via published report`, plus a Privacy section on the
  hub, the methodology page, the README and `llms.txt`.

**Evidence / layout**
- `.overlay` and `.notice` no longer hidden in print; `print-color-adjust: exact`
  keeps risk colours in the PDF; frame height 300px → 420px.
- Evidence mode collapses page chrome after a scan (toggle, remembered).
- Provenance strip burned into every report card (tool, target, UTC, source).
- Export split-menu: Print / PoC image (`getDisplayMedia`) / evidence card
  (canvas) / Copy MD / Copy JSON — with honest capability labelling.
- Visual-confirmation flow restored, recorded as analyst-attested with a
  load-behaviour hint pre-selecting the likely answer.

**Security / quality**
- `http_session` opener cache keyed on `(insecure, allow_private)` + tests.
- **DNS TOCTOU closed** — pooled openers re-validate every resolved address
  inside `connect()`, so rebinding cannot slip a private IP past the
  pre-check. Verified against `localtest.me` (public name -> 127.0.0.1):
  blocked at connect time with the pre-check bypassed, while
  `allow_private=True` still works.
- **Grader parity harness** — `tests/grader_fixtures.json` (15 cases) drives
  both the Python and JS graders, plus a test comparing them directly.
  Verified it catches drift: changing one weight in `js/app.js` fails with
  "score drift". Required extracting pure `grade_headers_from_map()` /
  `grade_clickjacking_from_map()` from both engines.
- **API rate limit** — documented honestly as per-instance/best-effort on
  serverless, now keys on the real client IP via `X-Forwarded-For` and bounds
  its memory.
- All inline scripts externalised → `script-src 'self'` with no
  `'unsafe-inline'`, plus `Permissions-Policy`, CORP/COEP and
  `frame-ancestors 'self'`. **Self-score C (65) → A (95).**
- `server.py` CSP/header block deduplicated into `_security_headers()`.
- LICENSE (Apache-2.0) added.
- Cache-busting stamped from the commit SHA in CI.
- `--workers` wires `concurrent_scanner` into the batch CLI.
- Focus trap + focus restore on the shortcuts dialog; `--faint` contrast
  4.0:1 → 5.49:1; reduced-motion no longer hides Recent scans.
- sitemap includes `/methodology/`; manifest paths made relative; robots.txt and
  security.txt annotated with the domain-root caveat.
- `PERFORMANCE.md` → `docs/performance.md`, rewritten as reference notes.
- `humans.txt` no longer carries a hand-maintained date that would rot.

## 8b. Hosted-site (GitHub Pages) pass

Reviewed specifically as the site behaves on Pages — no Python engine, no
response headers — rather than as it behaves locally.

**Bug: the hub could never grade headers.** `ensureRelayConsent()` calls
`renderRelayGate()`, which no-ops when `#relayGate` is absent — and the hub
never had that element. It failed *closed* (no leak, good) but the consent
prompt could never appear, so on the hosted site the suite silently degraded
to "UNKNOWN / no header data" for every target with no way to opt in. Since
the hub is the landing page, this was the first thing every visitor hit.
Added `#relayGate` to the hub and wired consent into the suite run, with a
useful message on decline. Verified: gate appears, and after consent the
suite returns real grades while only the hostname leaves the browser.

**Fonts were render-blocking.** `css/app.css` pulled Google Fonts via
`@import`, which serializes: the browser must download and parse the whole
stylesheet before it even discovers the font URL, making the `preconnect`
hints in `<head>` nearly useless. Moved to a parallel `<link>` in every page.
(First attempt used `media="print" onload="this.media='all'"` — caught that
the inline `onload` would violate the strict CSP we had just earned, so it
ships as a plain link; `display=swap` already prevents invisible text.)

**The hosted site shipped no security policy at all.** Pages cannot send
response headers, so a header-grading tool was publishing itself with zero
headers. Added a `<meta http-equiv="Content-Security-Policy">` to all six
pages, least-privilege: only `/tools/clickjacking/` may frame arbitrary
targets (`frame-src https: http:`), everything else is `frame-src 'none'`.
Added `img-src blob:` after checking the canvas export path — the
evidence-card and PoC-image downloads would otherwise have been blocked.
`server.py` updated to match so local and hosted stay in sync.

**Documented an honest limitation.** A meta CSP *cannot* set
`frame-ancestors`, and `X-Frame-Options` is header-only, so the hosted site
can still be framed and will not score A against itself even though
`server.py` does. That is a hosting limit, not a scoring bug; README now says
so plainly rather than leaving it as a surprise.

**Copy.** Engine chip `live · browser` -> `browser · no engine` with a
tooltip stating the trust level. Removed the `cached` promise from the demo
chip (it breaks if the cache job fails); "this site" chip now frames the
Pages limits as the teaching moment they are.

6 new tests lock all of this in (89 total).

## 9. Original suggested order of work

**This week (small, high value)**
1. Un-hide `.overlay` (and `.notice`) in the print stylesheet. *One line.*
2. `clearRecentScans()` also clears `cb-header-lookup-v1`. *Two lines.*
3. Disclosure line under the Recent chips + "published report" wording for the
   cache chip. *Copy change.*
4. Key the `http_session` opener cache on `(insecure, allow_private)` + a test.
5. Add a LICENSE.

**Next (the things you actually asked for)**
6. `body.evidence` compact layout + `scrollIntoView` after scan.
7. Restore the visual-confirmation two-button flow, with `confirmation:
   "manual"` in the exports.
8. Export split-menu: Print / PoC image (`getDisplayMedia`) / evidence card
   (canvas) / Copy MD / Copy JSON.

**Then (the one that matters most for professional use)**
9. Relay disclosure + host-only-first probing + "not independently verified" on
   relay-sourced findings — or deploy `api/` and set `API_BASE` so the relays
   are never reached.
10. Externalise inline scripts, drop `'unsafe-inline'`, get CyberBuddy to grade
    A on itself.
11. Golden-file cross-check test between the Python and JS graders.

---

## 10. On the two repos

Keep `Clickjacking-Validator` archived (GitHub's Archive button) with a README
line pointing at CyberBuddy, rather than deleting it. It's dated 2026-08-13, one
day before this repo — a reviewer seeing both will read it as "prototype →
product", which is a good story. Deleting it just loses the history.

---

## 11. Round 2 — productization review (2026-08-14)

A 30-point improvement roadmap was proposed for the hosted site. Each item was
challenged against one question: *does this make the assessment more credible,
or just more decorated?* An evidence-grade security tool must never show data
that did not actually come from a scan — several proposals were rejected or
reshaped for exactly that reason.

**Adopted as proposed**

- **Animated score gauge** — SVG ring that animates to the real 0–100 headers
  score, with the number kept as text (screenshots/AT), grade-band label, and
  full `prefers-reduced-motion` handling. Used on the Headers report and in the
  hub's suite summary.
- **Scan pipeline** — the hub now shows the real stages a run passes through
  (normalize → engine → consent → collect → evaluate → report) with stage-based
  progress, instead of three "Scanning…" skeletons. Stage notes are honest:
  they name the engine that answered and whether consent was needed or skipped.
- **Posture rollup** — missing/weak/OK/info counts under the verdict.
- **Copy finding** — every finding row copies a paste-ready block (status,
  severity, evidence, recommendation, target, UTC stamp) via the existing
  clipboard helper.
- **Scan metadata** — engine, method (GET · read-only), check count, and a
  *measured* duration on every tool report. ("Redirects" was skipped: the
  browser cannot see redirect chains, and faking it would be worse than
  omitting it.)
- **Demo vs live** — results now carry LIVE / CACHED tags (cache =
  CI-published demo reports), the sample console is labelled "demo · cached",
  and the cached-demo line was added to the typed console output.
- **Pages-limits panel** — collapsible "what hosting on GitHub Pages changes"
  block with the browser-engine → CORS → header-visibility chain and the
  `python3 server.py` answer.
- **Scope panel + authorized badge** — "What CyberBuddy does / does not do"
  grid, plus a prominent authorized-testing badge next to the scan bar.
- **Footer architecture** — Tools / Methodology & resources / Connect columns
  plus the engine line under the brand.
- **Scan history with grades** — recent-scan chips show the last headers grade
  (small digest in localStorage, same 24h TTL, cleared by Clear history).
  Clicking a chip still *re-scans*: restoring stale cached reports would
  present old data as fresh evidence.

**Adopted with modifications**

- **Hero (#1)** — the proposed fake "LIVE ASSESSMENT" dashboard was rejected
  (it shows a scan that never happened, 40px above real results). Instead:
  product framing in the kicker, the real console labelled as a cached demo,
  and the real dashboard appears when you actually scan.
- **Tool cards (#3)** — OWASP/CWE badges added (real data). Pre-filled green
  checkmarks rejected: capabilities that look like results.
- **VAPT-style findings (#5)** — severity chip, recommendation, and per-check
  earned-weight bar inside the existing row. Accordions rejected: they hide
  evidence behind clicks and break print (a closed `<details>` cannot be
  force-opened in print CSS).
- **Headers matrix (#15)** — expressed as `8/10 pts` weight bars in the
  findings table rather than a second, redundant PRESENT/VALID/SCORE table.
- **CORS explainer (#13)** — static "how this probe works" (one real fetch,
  drawn honestly) instead of animated fake packets.
- **Methodology/architecture (#8/#28)** — static vertical pipeline diagram and
  an architecture diagram (UI → browser engine / hosted API → engines →
  evidence → score). Interactive/animated versions would be decoration.
- **Suite summary** — worst-case risk across the three tools + per-tool chips,
  with the headers gauge as the *only* numeric score. No invented aggregate
  /100: clickjacking and CORS have no numeric scale.

**Rejected, with reasons**

- **Evidence/Summary/Technical tabs (#6)** — the pages are already
  evidence-forward (raw headers, provenance strip, unverified flags); tabs
  hide evidence behind clicks.
- **HTML report export (#7)** — markdown copy, print/PDF and the PNG evidence
  card already cover VAPT handoff.
- **Clickjacking diagram (#14)** — the page already renders the *real* framed
  target with a PoC overlay; a drawing is strictly worse evidence.
- **Scan comparison (#18)** — persisting full results for comparison conflicts
  with the local-only, 24h, clearable storage promise; retests are served by
  copy/export.
- **Engine popover (#10)** — engine state is already visible in the header
  chip tooltip, the pipeline's engine stage, and the report metadata row.
- **Keyboard modal (#21), engine provenance (#27)** — already shipped.

No scoring code was touched: severity/recommendations are a display layer over
the existing check statuses, so the Python↔JS parity contract is unchanged
(89 tests pass, including parity).

---

## 12. Round 3 — real-browser verification, visitor-first UX, internal-notes policy (2026-08-14)

Verified against a real Chromium build (headless, Python engine online).

**Bug found and fixed**

- **Horizontal page blowout on the Headers report** (and any grid card holding
  a long unbreakable token): the raw-headers JSON line expanded the `.grid-2`
  track to ~2700px because grid items default to `min-width: auto`. Fixed with
  `min-width: 0` on all grid children (`grid-2`, `poc-grid`, `suite-grid`,
  `arch-split`, `scope-grid-2`) + `max-width: 100%` on the raw `<pre>`.
  Verified: overflow 1772px → 0 at 1440px and 390px.

**Blog / tool cards "not showing"**

Reproduced the question in a real browser: both render (4 tool cards, 2 blog
posts; 3 tools + 2 posts even with JavaScript disabled). The likely causes on
the reader's side are a stale Pages deploy or cached HTML — after merging,
wait for the Pages action (~2 min) and hard-refresh. Defense-in-depth added:
the tool grid and blog grid now carry static fallback content in the markup,
so those sections are never empty even if every script fails.

**Visitor-first explanations (the "owner knows, visitor doesn't" pass)**

- The header `engine · …` chip is now a button that opens a proper explainer
  (dialog semantics, Escape/outside-click/scroll close): what the current
  state means, all three engine modes in plain language, and a link to the
  methodology. On phones it renders as a bottom sheet (positioned from
  `<body>` because the header's backdrop-filter traps `position: fixed`).
- A visible `?` button in the header opens the existing keyboard-shortcuts
  dialog (it was only discoverable via a hint in the fine print).
- Tooltips everywhere jargon appears: LIVE/CACHED tags, `via …` source lines,
  the source chip, "analyst-attested", OWASP WSTG / CWE badges (tool cards +
  standards section), every ticker term, the score gauge (band thresholds),
  "Origin tested from", "Final URL", "HTTP status", "Engine", the PoC overlay
  button, and evidence mode (rewritten without the word "chrome").
- "Checked" meta label renamed to "Scanned" (it is a timestamp, not a count).

**Visual structure / space usage (measured, not guessed)**

- Hero: the "does / does not" scope list moved out of the cramped right card
  into its own two-column section — hero card heights now differ by ~43px
  instead of 213px, and the scope gets more prominence.
- Pipeline diagram: 615px → 521px (desktop), 697px → 594px (mobile); the
  architecture diagram 487px → 417px desktop, 589px → 476px mobile.
- Header on mobile: 148px → 122px (compact nav, chip, brand).
- Footer on mobile: 901px → 839px; tap targets bumped (nav links, copy
  finding ≥ 24px); meta grid pinned to 4 columns (2 on mobile) so 8 items
  never land in ragged 5+3 rows; section-head margins tightened.
- Suite summary centres its gauge on phones; the verdict gauge scales down.

**Internal-notes policy**

Notes that used to live in shipped files (visible via view-source) now live
in `docs/DEV-NOTES.md`, which the Pages workflow never deploys. Moved: the
CSP-sync comment from six pages, the robots.txt advisory, the humans.txt
"no last-update line" note, and the CSS font-loading rationale. Shipped files
keep only comments a curious visitor can read without seeing maintainer
notes. Future notes-to-self go in `docs/DEV-NOTES.md`.

**Verification:** 89/89 engine tests (incl. Python↔JS parity), node --check
on all scripts, jsdom boot/smoke of all five pages, Pages-build asset check,
and a 27-point real-browser interaction suite (popover, shortcuts, suite
scan, gauge, tags, no-JS fallbacks, mobile overflow) — all passing.

---

## 13. Round 4 — invisible cards fixed, all three tools validated in a real browser (2026-08-14)

**Root cause of the "empty but clickable" cards (finally found):**

The hub's tool cards and blog cards are injected by `renderToolCards` /
`renderBlog` AFTER `initReveal()` runs. Elements with class `reveal` start
at `opacity: 0` and only become visible when `.in` is added — the injected
cards were never observed, and the 2s fallback only covered elements
captured at init time. Result: cards present in the DOM and clickable, but
invisible (confirmed in Chromium: `opacity: 0`, no `.in`). The bug predates
the Round-2 work (present at `b2372d1`); earlier DOM-level checks counted
elements without checking computed visibility, so it slipped through.

**Fix:** `initReveal()` rewritten to (a) re-query and track every `.reveal`
at call time, (b) watch for late-injected nodes via MutationObserver, and
(c) a re-querying 2s safety net (`querySelectorAll(".reveal:not(.in)")`).
`js/boot.js` now runs `initReveal()` AFTER the page initialisers as
belt-and-braces. Verified in Chromium: all cards `opacity: 1` with `.in`,
including the ghost card and the nav dropdown items.

**All three tools validated end-to-end in real Chromium (51 checks):**

- Setup: a loopback-bound `server.py` (the VAPT configuration) so the
  Python engine path runs for real. Notable: the 0.0.0.0-bound server
  CORRECTLY refuses loopback targets via the SSRF guard — this is intended
  behavior, and the tools then fall back to the browser grader (labelled
  "this browser", as designed).
- Security Headers: real scan → gauge animated to the real score (offset
  5px ≈ 95/100, grade A), 10 findings with severity + recommendation (1/1
  weak rows) + weight bars (9), copy-finding works, raw headers contain
  real values, engine metadata "python engine", measured duration, UTC
  stamp, provenance, zero overflow, zero console errors.
- CORS Validator: probe → RESTRICTIVE verdict, findings + severity +
  posture, the genuine TWO-ORIGIN python proof
  (`https://evil.cyberbuddy.test · https://probe.cyberbuddy.test`), HTTP
  200, engine "python engine", no errors.
- Clickjacking Validator: live frame renders the target, protection line +
  risk chip, both framing-control rows with copy buttons, PoC overlay
  toggles on/off with label updates, no errors.
- Hub suite: all three results "via python engine", all tagged LIVE,
  no overflow, no errors.
- Mobile: headers report fully renders, no overflow, no errors.
- Regression guards added to the browser test harness: computed-opacity
  assertions for tool cards, blog posts, ghost card and nav items (DOM
  presence is not visibility).

**Verification:** 89/89 engine tests (Python↔JS parity), node --check on
all scripts, jsdom boot/smoke, Pages-build asset check, 51-check tool
validation suite, 27+4-check interaction suite.

---

## 14. Round 5 — original POC parity, footer fixes, label fixes (2026-08-14)

The original standalone `Clickjacking-Validator/Clickjacking.html` was
fetched and diffed against the current tool, item by item.

**Adopted from the original POC**

- **`allow-same-origin` on the frame sandbox** (now
  `allow-scripts allow-forms allow-same-origin`). The old tool framed
  targets with the same privileges a real attacker's frame has; the current
  tool's stricter sandbox made sites that need their own storage render
  blank — a false "blocked" verdict on an evidence tool. Top-level
  navigation remains sandbox-blocked, and the only same-origin case is
  scanning CyberBuddy itself (the analyst's own trusted code). The stage
  note, confirm-prompt hint, and README were updated to match.
- **Frame-load "peek" evidence line.** The old tool reported what reading
  `contentDocument` proved. Ported: "Frame loaded — peek: cross-origin
  (document not readable — expected)" or "document readable — <href>" for
  same-origin targets. Verified both paths in Chromium.

**Added for accuracy while there**

- Frame `error` listener (fires on policy blocks such as mixed content;
  verified Chromium instead renders its own error page for refused
  connections and fires `load`).
- When the engine reports the target unreachable, the frame status now says
  so explicitly ("the frame may show the browser's own error page; that is
  not framing evidence") instead of leaving a generic "Frame loaded" line
  next to an UNREACHABLE verdict.

**Skipped (already better here):** the old page's compact single-viewport
layout is covered by Evidence mode; normalize / ?url= / Enter-to-scan /
PoC toggle / auto-scan all exist in stronger form; the header scan the old
page proxied through `/api/scan` is the current Security Headers tool.

**Footer fixes (user-reported)**

- `.footer-legal` was a grid item auto-placed into row 2, column 1 of the
  footer grid — the legal text hugged the left-most column. Fixed with
  `grid-column: 1 / -1`; verified it spans the full footer width and sits
  below all columns at 1440 / 920 / 560 / 390 px.
- Connect column label: "Read the blog · Medium" → "Read My blog · Medium".

**Verification:** 89/89 engine tests, node --check, jsdom smoke, Pages-build
asset check, 51-check tool validation suite, 31-check interaction suite, and
the new footer/CJ checks (footer spans at four widths, same-origin and
cross-origin peeks, unreachable-target path, hub regression) — all passing.
