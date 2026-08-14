# CyberBuddy — internal dev notes

> This file is **repo-internal**: the Pages workflow does not copy `docs/`
> to the deployed site. Notes that used to live as comments inside shipped
> files (where visitors could read them via view-source) now live here.
> If you add a "note to self" while editing, put it here — not in
> `index.html`, the tool pages, `css/app.css`, `js/*.js`, `robots.txt`,
> `humans.txt` or `404.html`.

## CSP between server.py and the static pages

GitHub Pages cannot send response headers, so the site's policy ships as a
`<meta http-equiv="Content-Security-Policy">` tag in every page `<head>`.
**Keep the meta tag in sync with the CSP in `server.py`** — they are the
same policy expressed two ways.

Known trap: `frame-ancestors` / `X-Frame-Options` **cannot** be set through
a meta tag (meta CSP ignores `frame-ancestors`). The clickjacking tool page
is the one place that widens `frame-src` to `https: http:` so its live
iframe proof can load the target; the hub and other tool pages keep
`frame-src 'none'`.

When the CSP changes: update `server.py` (`self.CSP`) and every page
(`index.html`, `404.html`, `tools/*/index.html`, `methodology/index.html`)
in the same commit.

## Font loading

Fonts load from `<link>` tags in each page `<head>`, **not** `@import` in
the stylesheet. An `@import` in `app.css` is serialized: the browser must
download and parse the whole CSS file before it even discovers the font URL,
which delays first paint and wastes the `preconnect` hints in `<head>`.

## robots.txt is advisory on a project Pages site

On a GitHub *project* Pages site this file lives at
`/CyberBuddy/robots.txt`, but crawlers only read the **domain root**
(`https://amitpal-cyberbuddy.github.io/robots.txt`). It only takes effect
under a custom domain, or if the same rules are published from the
`amitpal-cyberbuddy.github.io` repo. The absolute sitemap URL stays correct
either way.

## humans.txt has no "last update" line — on purpose

A hand-maintained date rots the moment someone forgets it. Use the
repository history instead:
<https://github.com/AmitPal-CyberBuddy/CyberBuddy/commits/main>

## Layout regression traps (learned the hard way)

- Grid children need `min-width: 0` — without it, one long unbreakable token
  (a raw header line, the JSON blob in the raw-headers `<pre>`) expands the
  track and blows the page out horizontally. The `.grid-2 > *` rule in
  `css/app.css` is load-bearing; keep it.
- **`.reveal` content injected after boot is invisible until `.in` is
  added** — `html.js .reveal { opacity: 0 }`. The tool cards and blog grid
  are injected by `renderToolCards` / `renderBlog`, so `initReveal()` must
  run AFTER the page initialisers (boot.js order) and must watch for late
  additions (MutationObserver) plus a 2s re-querying safety net. If you
  move the boot order or add a new dynamically injected `.reveal`, re-check
  computed `opacity` in the browser — DOM presence is NOT visibility.
- Reduced-motion CSS must override the more-specific `html.js .reveal`, not
  only `.reveal`. Keep `html.js .reveal, .reveal { opacity: 1 !important;
  animation: none !important; animation-delay: 0s !important; }` inside the
  media query so visitors who disable animation never wait on reveal delays.
- Evidence must stay visible without clicks: never put findings in
  accordions, because a closed `<details>` cannot be force-opened in print
  CSS and breaks the screenshot workflow.
- Anything shown as a score must come from a real scan. The hub shows the
  headers score as the only numeric gauge; clickjacking and CORS have no
  numeric scale, so they are risks, never a fake /100.
- LIVE / CACHED tags are an honesty promise: cached = CI-built demo report
  for a `urls.txt` target, never a fresh scan. Keep them on every result.

## Responsiveness: measure elements, not the document

`body { overflow-x: clip }` is deliberate — decorative blobs must never
cause a scrollbar. The side effect is that **document-level overflow checks
are close to useless**: `documentElement.scrollWidth - clientWidth` stays 0
while an individual panel, menu or table is still spilling off the screen.
`tests/browser/responsive.js` therefore measures every painted element's
rect against `innerWidth`.

Traps found writing it, all of which produce false positives:

- **Closed `<details>` are laid out but not painted.** A closed Tools menu
  reports `clientWidth: 63` vs `scrollWidth: 155` and looks catastrophically
  clipped. Skip anything matching `details:not([open])`, and use
  `el.checkVisibility({ contentVisibilityAuto: true, ... })`.
- **`scrollWidth > clientWidth` does not mean text is cut.** Absolutely
  positioned children (score gauges, chips, the radar) legitimately paint
  outside their parent box. Compare the *text* extent instead: take a
  `Range` over the element's contents and check `range.right > rect.right`.
  On `#grade` the naive check fired while the glyph ended 19px INSIDE.
- **The skip link lives at `left: -9999px`** and the ticker marquee is
  intentionally wider than the viewport. Exclude them explicitly.
- **A mid-animation `.reveal` reads `opacity < 1`.** Poll until it settles.

Genuine issues this found (all fixed): chips and the engine pill at 20-23px
on touch screens; the demo console's fixed-length `─────` divider bleeding
~21px past the card at 360px (box-drawing runs cannot wrap — clip them);
`.method-table` overflowing its card by 3px at 360px; and the evidence
toggle's `<label>` — the real tap target for a 13px checkbox — at 20px.

Also: **do not make `:has()` load-bearing.** The first fix for the
methodology table used `.card:has(> .method-table)`; `display: block` on the
table itself achieves the same scroll container with no support caveat. A
test asserts `:has(` never appears in the stylesheet's real rules.

## Real-browser test suites

`test_engines.py` stays stdlib-only so CI can run it anywhere; it can only
assert that the *rules* are present in the CSS/JS. The things that actually
broke in Round 6 — stacking contexts, panel geometry, pointer interception —
are only observable in a real browser, so they live in `tests/browser/`:

    python3 server.py --port 8080 --allow-private        # shell 1
    npm i puppeteer-core                                 # once
    CB_CHROME=/path/to/chrome node tests/browser/layout.js
    CB_CHROME=/path/to/chrome node tests/browser/dropdown.js
    CB_CHROME=/path/to/chrome node tests/browser/overlays.js

They need a live server and a Chromium binary, so they are not wired into
the Pages workflow (which must stay dependency-free). Run them by hand
before a release, and after ANY change to positioning, z-index, grid
templates or the report markup. Set `CB_TARGET` to point at a scannable
host; the default assumes a throwaway local one on :8099.

Each suite exits non-zero on the first failure. Assert computed values —
`getComputedStyle`, `getBoundingClientRect`, `document.elementFromPoint`,
real navigation — never DOM presence, which is what let the Round 4
invisible-cards bug ship.

## Round 6 traps — stacking contexts and panel balance

- **`position: static` silently disables `z-index`.** Evidence mode used to
  set `body.evidence .site-header { position: static }` to un-stick the
  header for one-shot screenshots. z-index only applies to *positioned*
  elements, so `z-index: 50` stopped applying, the header's
  backdrop-filter stacking context painted in source order, and the open
  Tools menu rendered BEHIND `.report-card` — visible but unclickable.
  Use `position: relative` when you want "not sticky" but still stacked.
  If you ever need static again, verify with `elementFromPoint()` over each
  menu item, not by eye.
- **Equal z-index resolves by source order.** `.container` and
  `.site-footer` were both `z-index: 1`, so the footer painted over an open
  Export panel and ate its clicks. `main.container { z-index: 2 }` breaks
  the tie. Watch for this whenever a new positioned section is added.
- **Absolute panels anchored to small controls escape narrow viewports.**
  A 300px Tools panel on the small `<details>` ran 46px past a 390px
  viewport; the 268px Export panel started at `left: -122px` at 768px once
  its button wrapped to a new flex line. Anchor wide panels to a full-width
  row (`.header-inner`, `.bar`) instead of the button, and re-measure the
  panel rect against `innerWidth` — not just the page's overflow, because a
  clipped ancestor can hide the overflow while the panel is still
  unreachable.
- **Panels only belong side by side when their content lengths are
  comparable.** Findings vs Raw headers measured 2735px vs 236px at 1920px:
  a 2-column grid there is ~2500px of blank gutter. Stack long evidence
  full width. Use a tool-specific class (`.headers-report-stack`) — do NOT
  flatten `.grid-2`, which the CSP evidence row, hub scope grid and
  methodology all depend on. And never force equal heights to "balance" a
  row; that just makes an artificially empty card.
- **Testing traps.** A `.reveal` mid-animation reads `opacity < 1` and is
  not a bug — poll until animations settle before asserting. Likewise
  `scroll-behavior: smooth` means a menu check right after `scrollTo` can
  measure a stale header position. Both cost a false-positive round.

## Blocking prompts must not look like progress

The relay-consent gate blocks a scan on a human decision. Reviewers read it
as "the scan is running, maybe stuck" instead of "answer this". Three
separate causes, all worth remembering for any future blocking prompt:

- **A spinner that keeps spinning is a lie.** The caller had already run
  `setLoading(go, true)`, so the Scan button spun while the gate waited.
  `ensureRelayConsent()` now parks every `.btn.is-loading` into an
  `is-waiting` state reading "Waiting for your choice…", and restores the
  spinner only if the scan actually resumes. If you add another gate, park
  the caller's busy state the same way.
- **A prompt below the fold does not exist.** The gate rendered at
  `top: 681px` in an 844px viewport. It now scrolls itself into view and
  takes focus. Align the **top**, not the centre — the panel is taller than
  a phone viewport, so `block: "center"` pushes the heading off-screen.
  Offset by the sticky header or the title hides behind it.
- **`btn-primary` among sibling choices reads as "already selected".** The
  old row of three buttons looked like hostname-only was preselected and
  the scan was merely slow. All three are now equal-weight option cards;
  the recommendation is an explicit "Recommended" chip, not a colour.

Also: if options differ in ways that matter (privacy, evidence quality),
say so **in** the option. A tooltip nobody hovers is not documentation —
each card states what it sends, what you get back, and why you would pick
it.

## Provenance traps

- **A cache entry inherits the provenance of whatever filled it.** The
  10-minute header lookup cache used to stamp every hit `cache-lookup`,
  including entries originally fetched through a third-party relay — so the
  second scan of a target inside the TTL dropped the `unverified` chip and
  claimed "this browser" read the headers. `relay-cached` keeps the relay
  provenance and the flag. If you add another lookup source, decide what it
  degrades to on a cache hit before you ship it.
- `unverified` is a provenance label, not an error: it means the values came
  from a public relay rather than the Python engine or a first-hand CORS
  read. Never suppress it to make a report look cleaner.

## Parity contract

`tests/grader_fixtures.json` is the shared contract between the Python
graders (`security_headers.py`, `clickjacking_validator.py`) and their
browser port (`js/app.js`); `tests/csp_fixtures.json` does the same for
`csp_checker.py` / `gradeCspFromMap`. The same target must never get a
different grade on Pages than under `server.py`. The Pages workflow runs
`python3 -m unittest test_engines.py` before every deploy — a scoring
regression must never reach the site. Severity chips / recommendations /
weight bars in the UI are display-only layers over the check statuses and
must stay that way.

## CSP auditor traps

- Multiple `Content-Security-Policy` response headers combine restrictively;
  they are preserved newline-separated by both header collectors. Do not
  collapse them to the last value or grade each policy as an independent
  exposure.
- Duplicate directives *inside one policy* are different: browsers use the
  first occurrence and ignore later duplicates. `parse_policy` /
  `parseCspPolicy` deliberately keep the first.
- `default-src` is a real fallback for script/style/object fetch directives,
  but not for `base-uri`, `frame-ancestors`, or `form-action`.
- A nonce/hash plus `'unsafe-inline'` is a legitimate CSP2/CSP3 compatibility
  pattern: modern supporting browsers ignore `'unsafe-inline'`. Do not regress
  it to the standalone checker's unconditional high-risk result.
- GitHub Pages compatibility is the standard header lookup chain: API, fresh
  published cache, direct CORS read, then opt-in relay. Keep `csp` in the cache
  builder and retain the fallback that derives it from older `headers` entries.

## Round 5 traps

- **Grid items with `width:100%` do not span grid rows** — `.footer-legal`
  auto-placed into row 2, column 1 of the footer grid and hugged the left
  column. Any full-width grid row needs `grid-column: 1 / -1`.
- **Iframes: `load` vs `error` is not what you expect.** Chromium renders
  its own error page inside the frame for refused connections and fires
  `load`; the `error` event fires for policy blocks (mixed content) and
  some other browsers' connection failures. When the engine verdict says
  "unreachable", propagate that to the frame status line rather than
  relying on the events.
- **Frame sandbox = attack fidelity.** The frame uses
  `allow-scripts allow-forms allow-same-origin` on purpose — same
  privileges as a real attacker's iframe, so storage-dependent sites render
  instead of false-blanking. Top-level navigation stays blocked. Don't
  "harden" this away; it would turn blank renders into false "protected"
  verdicts.
