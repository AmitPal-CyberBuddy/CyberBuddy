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

## Outcome rollups: primary evidence beats secondary gaps

A headline risk answers the tool's primary question; it is not automatically the
worst colour in the findings table. `X-Frame-Options: DENY` prevents framing even
when modern CSP `frame-ancestors` is absent, so that absence is a
modernisation recommendation on a LOW/protected outcome. Likewise, a two-origin
CORS probe that sees a fixed ACAO remains LOW even when `Vary: Origin` is
missing; the cache finding stays visible but does not rewrite the measured
reflection result. Keep the exception ordering explicit: permissive CSP
`frame-ancestors *` overrides XFO in current browsers, and confirmed CORS
reflection with credentials remains HIGH.

Do not implement an outcome fix in `findingSeverity` or chip CSS. Those are
presentation over status. For any Python grader with a browser twin, change the
Python function, browser function, and golden fixture in the same commit.

The parallel audit found CSP and Security Headers already obey this rule:
Report-Only/reporting gaps are informational and excluded from CSP risk, while
the optional header weights alone leave a protected baseline at B/LOW. Keep
regression cases for those no-change conclusions too.

## URL feedback traps

- Client URL validation is UX, never the security boundary. Server-side
  `validate_target()` plus redirect/connect-time SSRF checks remain
  authoritative.
- A `host:port` string can match the grammar for a URI scheme. Recognise only a
  narrow hostname + **numeric** port shape before rejecting unsupported schemes,
  or `localhost:8080` is mistaken for `localhost:` while loosening the check can
  re-admit `javascript:` and `data:`.
- Error text inserted on input blur can move an adjacent button between
  pointer-down and pointer-up, causing the browser to cancel the click. The URL
  field reserves an absolutely positioned feedback line and gives the sibling
  controls the same bottom margin. Real-browser tests must click the button and
  check the announced message; calling the validator directly misses this bug.
- Reject credential-bearing URLs instead of silently stripping credentials and
  scanning a different target. Export sanitisation is still defense-in-depth:
  Markdown, JSON, provenance and PNG specs remove `user:password@` from imported
  result objects.
- Normalise on blur/paste so scheme insertion is visible. Keep bare public
  domains, localhost and IP workflows, but require a dotted hostname with a
  plausible TLD for public names.

## Clickjacking visual evidence

A real clickjacking target remains at full opacity. The attacker's page is the
layer whose opacity changes; dimming the iframe demonstrates the inverse of the
attack. Keep `pointer-events: none` on the entire attacker subtree and test
`elementFromPoint()` over it, not only the declared CSS.

Cross-origin iframe pixels and DOM are unavailable to the evidence-card canvas.
Record the iframe event, the safe frame-load peek and any analyst attestation in
words. Never draw a fake screenshot or label a `load` event as proof that the
real target UI painted — Chromium may fire `load` for its own connection-error
page. Per-tool card specs should select evidence; the canvas drawing engine
should remain shared.

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

## CSRF PoC Generator traps

- **It must never look like a scanner.** No `/api/` call, no relay gate, no
  LIVE/CACHED tag, no recent-request history, no share link that carries the
  request, no `?url=` param, and no numeric score. The provenance strip says
  "generated locally — nothing transmitted". Do not wire it into the hub
  `initSuite` (that suite is the four scan tools and stays that way).
- **Status is about browser mechanics, not exploitability.** READY = simple
  request (no preflight); LIMITED = preflight- or server-leniency-dependent;
  NOT DIRECTLY REPRESENTABLE = no browser mechanism carries it (GET-with-body,
  CONNECT/TRACE/TRACK). Never derive a "vulnerable" verdict or a score from
  these.
- **Never pretend a form sends exact JSON.** `application/json` goes through
  `fetch()` (preflighted) or, only when the body splits into one `name=value`
  pair and has no newlines, the text/plain trick. `text/plain` bodies are sent
  via `fetch()` (safelisted content type) or a `name=value`-line form.
- **File fields cannot be pre-populated.** Multipart file parts become
  `<input type="file">`; the victim must choose the file. Say so instead of
  faking a value.
- **Escape hostile input three ways.** HTML-attribute/text via `escHtml`;
  JavaScript via `JSON.stringify(...).replace(/</g, "\\u003c")` (never string
  concatenation); the pasted request itself is never echoed as executable code.
  `Cookie`/`Authorization`/`Host`/`Content-Length`/`Origin`/`Referer` values are
  structurally excluded from the generator.
- **Token detection is detection, not silent removal.** `looksLikeToken()`
  flags csrf/xsrf/nonce/authenticity/requestverification/anti-forgery and
  `*token`/`_token*` names. Tokens are included by default; the analyst
  untick-checks to exclude one. A static token value will not match a real
  per-session token — that is expected, and the UI says so.
- **Auto-submit is opt-in and fixed.** OFF = a manual `<button type=submit>`.
  ON = a constant `<script>document.getElementById("csrf-form").submit()</script>`
  (or `window.__send()` for fetch variants) with no interpolated values, plus an
  accidental-state-change warning in the UI. The engine chip (`detectEngine`)
  still pings `/api/health` at load — that is the site's own chrome, never the
  pasted request.
- **Keep the pure engine DOM-free.** `js/tool.csrf.js`'s parser/generator live
  under `CyberBuddyCsrf` and never touch `document`/`window`, so
  `test_engines.py` can run them under Node. `initCsrf` (the controller) is the
  only part that touches the DOM.
- **`tests/browser/stress_target.py`** is a local-only helper that serves the
  400-character header tokens the responsive suite needs when `CB_STRESS` is
  set; it is not shipped to Pages (the workflow only copies `tools/`).

## IA-01 traps — scalable navigation, catalog and footer

- **One registry, four renderers.** `TOOLS_MENU` in `js/app.js` is the only
  source of tool metadata. The header menu (`toolsMenu`), hub cards
  (`renderToolCards`), catalog (`renderToolCatalog`) and footer all read it.
  Add a tool by adding one entry with a `category` of `assess` or `local` —
  never hand-edit four places. If you add a field, add it to every entry or
  the `TOOL_CATEGORIES`/renderer logic will render `undefined`.
- **A generator is not a scanner.** The only thing that separates the two
  categories is `TOOL_CATEGORIES[<category>].suite`. The hub “Run suite”
  (`initSuite`) stays the four scan tools (`apiScan/apiHeaders/apiCors/apiCsp`);
  CSRF is `local` and never joins it, never shows a LIVE/CACHED tag and never
  produces a score. Do not let a future local tool creep into the suite.
- **Dropdown grouping is markup, not behaviour.** The menu groups tools with
  `nav-menu-group` headers inside the existing `details.nav-menu` — the
  active-marker, Escape/outside-click, mobile containment, z-index and
  evidence-mode contracts are untouched. If you ever re-style the menu,
  re-run `tests/browser/dropdown.js` (it hit-tests every `.nav-menu-item`).
- **The footer is category-based on purpose.** It links *All tools / Target
  assessments / Local utilities*, *Learn* and *Project* — never a growing
  per-tool list. A new tool must not re-add a footer link. `tests` assert the
  footer contains no `/tools/<slug>/` links.
- **Catalog path depth differs from tool pages.** `tools/index.html` is one
  level deep (`../css`, `../js`, `../icon-192.png`); tool pages are two levels
  (`../../`). The Pages asset guard catches a wrong depth, but only if the
  catalog is copied — and it is **not** covered by the `cp -a tools/…`
  directory list, so `tools/index.html` must be copied explicitly. That edit
  lives in `docs/pages-workflow-patch.md` (the arena token cannot push
  workflow files).
- **`/tools` vs `/tools/`.** `server.py` serves `/tools/` as the catalog and
  redirects `/tools` (no slash) to it, mirroring `/methodology`. A test pins
  both plus the `/CyberBuddy/tools/` mount. If you add another top-level
  directory page (e.g. `/guides/`), repeat this three-way route coverage.
- **Internal files must never reach Pages.** `docs/ROADMAP.md` is the session
  roadmap and is deliberately excluded like `docs/DEV-NOTES.md`, `tests/` and
  `REVIEW.md`. The CI-side regression guard is stdlib
  `PagesExclusionTests.test_workflow_never_copies_internal_paths` (it fails if
  any future commit starts copying those paths into `_site/`); the equivalent
  in-workflow leak check is carried in `docs/pages-workflow-patch.md` for the
  maintainer. If you add a new internal doc directory, decide its Pages fate
  in the same commit.
- **Catalog static fallback vs JS registry.** `tools/index.html` ships a
  static no-JS fallback *and* `renderToolCatalog()` replaces it from
  `TOOLS_MENU`. This is the same intentional duplication the hub already has;
  the JS registry is still the single JS source. Keep the fallback and the
  registry in sync when tool metadata changes.

## GUIDES traps — the Guides section

- **A guide is only useful if it is connected.** The contract for every guide
  is three links: *up* to `/guides/`, *across* to the tool that confirms the
  finding (`../../tools/<slug>/`), and *out* to the primary references for
  depth. The tool page links back (`../../guides/<slug>/`). Break one of those
  and the guide becomes an orphaned article — which is exactly what the roadmap
  says Guides must not be. `GuidesTests` pins all four directions.
- **“Go deeper” means real references, never the Medium profile root.**
  Superseded rule (do not reinstate): guides used to link
  `https://amitpxl.medium.com/` as the deep-dive for every topic. There are
  only two posts (request smuggling vs pipelining; client-side encryption) and
  neither is about clickjacking, so that link promised a write-up that does not
  exist. Every guide now closes with primary sources — OWASP WSTG, CWE, the
  OWASP cheat sheet, MDN, the W3C spec, PortSwigger. A blog link may appear in
  a guide **only** when a post on that exact topic is published; the CORS
  article (“Understanding CORS — from browser security to real world impact”)
  is in progress, so the CORS guide may add one once it ships, as its own
  subsection separate from the references. `test_guides_never_sell_the_blog_as_
  a_per_tool_deep_dive` asserts no `medium.com` in `guides/`. Never invent a
  topic slug — a dead “read more” is worse than no link. Verify every external
  URL resolves before committing (note MDN moved HTTP headers under
  `/Web/HTTP/Reference/Headers/…`; the pre-`/Reference/` paths only redirect).
- **Write as the author, in first person.** These are Amit's notes, not an
  assistant's description of someone else's site. No “the maintainer's blog”,
  no narrator voice addressing a visitor — the hub's `BLOG_POSTS` excerpts set
  the register (“I walk through how I separate…”).
  `test_guides_are_written_in_first_person_not_as_a_narrator` bans
  “maintainer”/“the author's” in guide prose and requires a first-person “I”.
- **Concise is a tested property, not a wish.** `test_guides_stay_short` caps
  every guide's visible word count at 1200 words. All five copy the pilot's
  shape (attack in one paragraph → the controls / the ways it goes wrong →
  confirm with the tool → the fix → go deeper). Do not let one grow into an
  article.
- **Guide facts must track the engine.** The pilot's risk sentence mirrors
  `clickjacking_validator.py`'s `score()` ladder (permissive/absent
  `frame-ancestors` = High, X-Frame-Options only = Medium, restrictive
  `frame-ancestors` = Low) and the methodology page. If the ladder changes,
  the guide is a third place to update — grep `frame-ancestors` before editing
  the scorer.
- **New top-level section = the same four-part checklist.** `/guides/` needed
  (1) a `STATIC_PREFIXES` entry plus `/guides` → `/guides/` redirect and the
  `/CyberBuddy/guides/…` mount in `server.py`, (2) `sitemap.xml` + `llms.txt` +
  README entries, (3) the CSP meta copied verbatim from `server.py`, and (4) a
  Pages copy line. The workflow copies named directories only, so a new
  directory is invisible on Pages until `cp -a guides _site/` is added —
  carried in `docs/pages-workflow-patch.md` because the arena token cannot
  push `.github/workflows/**`.
- **Guides pages are one and two levels deep.** `guides/index.html` uses
  `../css`, `../js`; `guides/clickjacking/index.html` uses `../../`. Same trap
  as the catalog vs tool pages.
- **`PagesExclusionTests` scans the assemble step only.** The workflow's leak
  *guard* step legitimately names `docs/ROADMAP.md`, `docs/DEV-NOTES.md` and
  `REVIEW.md`, so a whole-file token scan reports a false positive (it did, at
  branch point `17e66e2`). `_assemble_step_body()` slices the YAML from
  `- name: Assemble static site` to the next line indented at or below that
  step's indent; keep new copy lines inside that step or the guard stops
  seeing them.
- **Footer stays category-based.** *Guides* is one entry in the Learn column —
  never one entry per guide. `test_footer_learn_column_links_to_guides`
  asserts the column contains `/guides/` and no `/guides/<slug>/`.
- **`GuidesTests` is table-driven — extend the table, not the tests.** The
  class holds a `GUIDES` dict mapping each slug to `(tool slug, standards,
  reference URLs)`, and every test loops over it. Adding a guide means one new
  entry; adding a *tool* means one new entry too, because
  `test_scope_is_one_guide_per_tool` asserts `sorted(guides/*) ==
  sorted(tools/*)`. That is deliberate: a tool without a guide should fail the
  suite rather than ship silently.
- **Every guide needs the `p.guide-link` backlink on its tool page.** It goes
  immediately after the tool's `p.std-line` (around line 55) as
  `<p class="guide-link reveal" style="--d: .12s;">New to this check? Read the
  <a href="../../guides/<slug>/">N-minute … guide</a> first.</p>`. The
  `.guide-link` rule lives at `css/app.css:1695`; the subsequent `--d` delays
  on that page were left alone on purpose — the stagger is decorative, not
  sequential.
- **CWE-693 is a Pillar and its mapping is DISCOURAGED upstream.** The headers
  and CSP tools already carry it in their standards line for continuity, but a
  guide must present it as thematic context and cite the concrete ID (CWE-79
  for CSP, CWE-1021 for clickjacking, CWE-942 for CORS, CWE-352 for CSRF) as
  the one to put in a report.
- **Guide risk language must mirror the engine, for all five.** CORS:
  reflected `Origin` + credentials = High, reflection alone or wildcard +
  credentials = Medium, everything else Low, and missing `Vary: Origin` is a
  separate finding that never sets headline risk. CSRF: READY / LIMITED / NOT
  DIRECTLY REPRESENTABLE, where `application/json` and multipart-with-file are
  what produce LIMITED. Headers: A≥90 B≥75 C≥60 D≥45 else F, A/B low, C/D
  medium, F high. Change a scorer and the matching guide is a third place to
  update, after the tool page and the methodology page.

---

## DOCS traps — the `/documentation/` page

- **The directory is `documentation/`, never `docs/`.** `docs/` is the
  repo-internal planning tree, and `.github/workflows/pages.yml` has a guard
  step that *fails the build* if `_site/docs` exists
  (`PagesExclusionTests.test_workflow_never_copies_internal_paths` pins the
  same rule). Renaming the published docs page to the obvious `docs/` would
  either break the deploy or silently ship the roadmap. If a future session
  wants a nicer URL, change the redirect, not the directory.
- **It is footer-only, on purpose.** IA-01 settled the header on four items —
  Hub / Guides / Method / Tools — and `renderHeader()` is pinned against
  gaining a `/documentation/` entry by
  `DocumentationPageTests.test_does_not_duplicate_the_header_nav`. Operator
  docs are a reference you go looking for, not a primary destination.
- **Do not restate the scoring rules there.** The score bands and weights
  already exist twice (README + `methodology/`). The page links to
  `../methodology/#hosted-scans` and `../methodology/#privacy` instead, and a
  test asserts that neither the letter bands nor the numeric weights are
  re-typed into it. Three copies of a scoring table is three places to forget.
- **A new top-level section needs four wirings, not one.** `server.py` takes
  *two* edits — the `STATIC_PREFIXES` tuple **and** the redirect/static branch
  (~line 365) — or `/documentation` 404s while `/documentation/` works. Then
  `sitemap.xml`, `llms.txt` and `README.md`. Then the unpushable workflow copy
  line in `docs/pages-workflow-patch.md`. The `/CyberBuddy/…` mount comes free
  via `strip_mount` once the branch clause is right.
- **The page shell is copied from `guides/index.html`, one level deep.** `../`
  asset paths, `theme-boot.js` in the head *without* `defer`, the CSP meta
  verbatim including `frame-src 'none'`, and the `?v=` cache-buster on
  `css/app.css` / `js/app.js` / `js/boot.js`. A prose page frames nothing —
  only the Clickjacking Validator relaxes `frame-src`.
- **The hosted-limits section must stay honest.** It states that the hosted
  build cannot score itself an A because Pages cannot send headers
  (`frame-ancestors` and `X-Frame-Options` are undeliverable via `<meta>`).
  If the site ever moves behind a header-capable host, that section and the
  matching README section both need correcting.

---

## JWT-00 traps (JWT Security Workbench development preview)

The JWT tool shipped first as a **non-operational preview**. These traps keep
it from silently becoming a half-working token processor before JWT-01:

- **"Beta" alone is not enough.** The brief is explicit: visitors read "beta"
  as functional. The page carries the literal strings **BETA ROADMAP PREVIEW**
  and **NOT OPERATIONAL** in the static markup (not injected by JS, not in a
  tooltip, not inside `<details>`), and `JwtPreviewTests` pins both. Do not
  soften the wording when restyling.
- **The controller is tab navigation and nothing else.** `js/tool.jwt.js`
  must not call `fetch`/`XMLHttpRequest`, touch `localStorage`/`sessionStorage`,
  write `history`/`location`, parse JSON, or touch `crypto.subtle`/`atob`.
  `JwtPreviewTests` strips comments then asserts the absence of each. If a
  comment that *says* "does not call fetch()" trips the test, strip comments in
  the assertion — do not weaken the assertion by removing the token.
- **Disabled in markup, disabled by the controller.** Every non-tab
  input/textarea/button/select on the page ships `disabled` +
  `aria-disabled="true"`, and the controller force-disables them again on boot
  (skipping `role="tab"`). A future edit that adds a token input must not
  ship it enabled; the test `test_no_token_processing_action_is_enabled`
  fails loudly if it does.
- **No fake result, score or verdict.** There must be no gauge, `/ 100`,
  `gaugeHtml`, `verdict-banner`, risk label, or pre-filled `"alg":"HS256"`
  JSON on the page. The five tabs explain what *will* exist; none of it is
  computed yet.
- **Noindex, no canonical, no sitemap entry for the tool page.** The preview
  carries `<meta name="robots" content="noindex, nofollow">`, deliberately
  omits `rel="canonical"`, and is absent from `sitemap.xml`. The **guide**
  (`guides/jwt/`) *is* indexed and in the sitemap. When JWT-01 ships and the
  tool becomes functional, remove the noindex, add the canonical, add the
  sitemap URL, and add the PWA shortcut — all four together.
- **It is `status: "preview"`, not `live`, in `TOOLS_MENU`.** That is how the
  menu, hub cards and catalog render a "Preview" badge / "View preview"
  affordance instead of "Run check"/"Launch". Category stays `"local"` (it
  never scans a target and must never join `initSuite`). `TOOLS =
  PAGES.slice(1, 5)` in `tests/browser/responsive.js` must remain the four
  URL-based scan tools — append JWT entries *after* index 4.
- **Preview is one guide per tool, so `guides/jwt/` exists.** `GuidesTests`
  enforces `set(tools/*) == set(guides/*)`; adding the tool without the guide
  (or vice versa) fails the suite. The guide must link to
  `../../methodology/` and `../../tools/jwt/`, stay first-person, cite RFC
  7519/RFC 7515/WSTG-SESS-10/CWE-347, and stay under 1200 words — *including*
  the JSON-LD block, which the word-count test does not strip.
- **The CSP on the JWT page is stricter.** It uses `connect-src 'self'` (no
  `http: https:`) because the preview makes no network calls, and keeps
  `frame-src 'none'`. When JWT-01 adds verification it stays same-origin;
  do not relax `connect-src` to reach a JWKS URL — keys are pasted, never
  fetched by the hosted tool.
- **Workflow copy.** The tool directories are copied by name in
  `.github/workflows/pages.yml` (not a glob), so a new tool needs
  `tools/jwt` on that line. `guides/` is copied whole-tree, so the guide
  needs no named line. If the arena push of the workflow edit is rejected
  (missing `workflows` permission), the same line is carried in
  `docs/pages-workflow-patch.md` for the maintainer — that happened for
  PR #20/#22 and may happen again.
- **Cache-buster consistency.** Every page must use the same `?v=` string;
  the Pages workflow stamps it with the commit SHA at deploy, but the source
  strings must match or `test_cache_buster_is_consistent` fails. New pages
  copy the existing `?v=20260814h` (or whatever is current), not a new date.

---

## JWT-01 traps (decode, inspect & verify)

The functional Analyze & Verify panel builds on the JWT-00 preview. These traps
keep the decode/verify implementation honest:

- **The pure engine is DOM-free and UMD-wrapped.** `js/jwt.engine.js` exposes
  `globalThis.CyberBuddyJwt` with `parseToken`, `tryParseToken`, `observations`,
  `validateClaims` and `verifyToken`, and exports via `module.exports` so the
  same code runs under Node in `JwtWorkbenchTests`. Put token logic in the
  engine, not the controller — the controller only binds DOM.
- **Never trust the token's `alg` header to choose the verifier family.** The
  caller passes `opts.alg` (or the key's `alg` is used); a mismatch with
  `header.alg` fails. HMAC algs only accept a **string** secret and reject
  PEM/JWK objects — that is the algorithm-confusion guard (`HS256 signed with
  the RSA public key`). A JWKS key's `kty` must match the expected alg family,
  and a JWK `alg` that disagrees with the token fails.
- **Decoding is separate from verifying.** The UI shows a "Decoded" state
  immediately; "Verified" only after `verifyToken` resolves valid AND claims
  validate. Observations are contextual (`no-exp`, `long-lifetime`, `jku`,
  `x5u`, `jwk`, `kid`) — there is no numeric score or verdict.
- **JWE is rejected, `alg:none` is rejected, malformed/empty signatures are
  rejected** with specific errors. `parseToken` throws; `tryParseToken` returns
  `{ok:false,error}`. The controller shows the error and never leaves stale
  decoded data on screen.
- **Local-only by construction.** The engine and controller contain no
  `fetch`/`XMLHttpRequest`/storage/history (pinned by tests). The page CSP is
  `connect-src 'self'; frame-src 'none'`. Keys are read from inputs in memory
  and never persisted. JWKS is **pasted**, never fetched from a URL.
- **Web Crypto is async and varies.** `importKey`/`verify` are promises;
  RSA-PSS needs `saltLength` (32/48/64 for SHA-256/384/512); ECDSA uses
  `namedCurve` P-256/P-384 and Web Crypto handles DER conversion. Feature-detect
  `crypto.subtle`; report "unsupported in this browser" rather than crashing.
- **Test tokens are built inside Node with `crypto.createHmac`/`crypto.subtle`**
  — never hand-rolled base64. The HMAC helper must use **base64url** (not
  standard base64) for all three parts, or signatures silently won't verify.
- **No preview panels remain.** JWT-03 completed the set — all four panels
  ship functional, enabled controls; the `..._remain_preview` tests were
  replaced by `test_variants_panel_is_functional` and
  `test_secret_panel_is_functional_and_bounded`.
- **PWA shortcut shipped with JWT-03.** The shortcut was deferred through
  JWT-01/02; once the full workbench was live, `manifest.webmanifest` gained
  the JWT entry and `test_pwa_shortcut_added_now_the_workbench_is_complete`
  pins its presence.

---

## JWT-02 traps (edit & generate)

The Edit & Generate panel is now functional. These traps keep signing honest and
key material from leaking by accident:

- **All crypto stays in the engine.** `signToken`, `generateRsaTestPair`,
  `exportPrivateJwk`/`exportPublicJwk`, `diffClaims` and `randomJti` live in
  `js/jwt.engine.js` next to the verify path; PEM private-key parsing is in
  the engine, never the controller. The controller only binds DOM. The same
  Node tests in `JwtWorkbenchTests` exercise sign→verify round-trips for
  HS256/384/512, RS/PS (generated pair) and ES256 (private JWK).
- **Signing mirrors the verify-side algorithm-confusion guard.** HS* signing
  takes a string secret only and rejects PEM/JWK objects; RS/PS/ES signing
  rejects public keys (JWK without `d`, SPKI PEM, JWKS) and PKCS#1/SEC1 PEM
  (Web Crypto only imports PKCS#8). `header.alg` must agree with `opts.alg`
  and `alg:none` is rejected — the engine neither signs nor produces it.
- **The select and the header editor stay in sync, but the guard stays.**
  Changing the signing algorithm rewrites `alg` in the header editor (when it
  parses); editing the header syncs the select. If the header declares an alg
  the select cannot offer (e.g. ES512), sign fails with a specific mismatch
  error instead of silently signing with the wrong algorithm.
- **A generated RSA pair is bound to one signature family.** Web Crypto
  `generateKey` is per family, so a pair generated for RS256 cannot sign
  PS256. `readEditKey` reports exactly that when the analyst switches the
  algorithm, instead of a confusing import error.
- **No accidental key export.** "Copy token" / "Download token" read only the
  output textarea — `test_copy_download_never_touch_key_material` pins that
  the token handlers never reference key material. Private JWK export is a
  separate, confirmed (`confirm()`) action, and the generated key's public
  JWK is the only key shown by default. Never put the private JWK into the
  result textarea or the clipboard feedback path.
- **TEST TOKEN is a label, not a mitigation.** Every signed output carries
  the TEST TOKEN banner and the honesty line ("not proof of acceptance").
  Keep it visible on success only — an error result must not show the banner
  or a stale token.
- **Diff before sign, always against the analyzed token.** The diff base is
  `lastParsed` (live), so re-analyzing a different token re-bases the diff
  automatically. A blank original (no token pasted) diffs against empty
  objects and says so in the heading.
- **Key sub-tabs are per-tablist.** There are two `.jwt-key-tabs` groups
  (verify + edit) with the same `data-keytype` values; `initKeyTabs` scopes
  panels by `aria-controls` per tablist. Don't select tabs globally — and
  don't match panels by substring (`"jwk"` is a prefix of `"jwks"`), that
  wired the JWK tab to the JWKS panel once.
- **`role="tab"` count is pinned at 4+4+4+3.** Four panel tabs, four verify
  key tabs, four edit key tabs, three variant signing-key tabs. Adding a key
  type means updating `test_accessible_tabs_and_key_subtabs`.
- **The guide is one edit from the 1200-word ceiling.** The visible-word
  count (tags stripped, JSON-LD included) sits at ~1195; every sentence added
  to `guides/jwt/` must trim an equal amount elsewhere.
- **Keep JWT-03 panels disabled.** `test_variants_and_secret_tabs_remain_preview`
  pins that every control in the Test Variants and Secret Test panels ships
  `disabled`; the PWA shortcut stays omitted until the full workbench ships.

---

## JWT-03 traps (test variants & bounded secret testing)

The workbench is now feature-complete. These traps keep the variant builder
and the secret-test worker honest:

- **Variants are templates, never findings.** `buildVariant` in the engine
  is the single entry point (`alg-none`, `tamper`, `claim-resign`,
  `alg-confusion`, `embedded-jwk`, `jku`/`x5u`, `kid`); every result is
  labelled TEST TEMPLATE and carries a per-type note. The UI and the tests
  both pin "not a finding" — do not phrase a variant result as a verdict.
- **`alg:none` exists ONLY as a labelled template.** `parseToken` and
  `signToken` still reject it; `unsignedToken`/`buildVariant("alg-none")`
  is the only producer, and
  `test_variant_alg_none_template_and_guard_intact` pins that the template
  builds while parse keeps rejecting it. Never relax the guards to make
  variants easier.
- **The confusion template deliberately does what the guard blocks.** It
  HMAC-signs with the analyst-pasted public key text via `crypto.subtle`
  directly (not through `signToken`, which must keep rejecting PEM
  secrets). The Node test verifies the signature against an independent
  HMAC computation AND that `verifyToken` still refuses the PEM secret.
- **Re-signed variants go through `signToken`**, so the alg pin, the
  public-key-can't-sign rule and the family checks all apply. The
  controller passes the base token's alg; the generated pair is bound to
  one Web Crypto family, so an RS256 pair can never sign a PS256 variant —
  `readVariantSigningKey` says so instead of failing at import.
- **Embedded JWK needs the public key.** With the generated pair it is
  `pair.publicJwk`; with a pasted private JWK, `publicJwkFromPrivate`
  derives the public subset (RSA n/e, EC x/y). A pasted PEM private key
  cannot provide it — say so, don't guess.
- **Secret testing is HS256/384/512 only, in a worker.** The worker
  (`js/jwt.worker.js`) loads the engine via `importScripts("jwt.engine.js")`
  (same directory, works on Pages), reads the uploaded wordlist with
  `FileReaderSync` inside the worker, and runs `searchHmacSecret` with
  progress every 250 candidates. Bounds are explicit: candidates capped at
  100,000, time at 120 s, both checked between candidates, plus Cancel
  (`{type:"cancel"}` → `shouldContinue` false). No RSA/EC work, no network,
  no storage — `test_worker_references_engine_and_has_no_network_or_storage`
  pins the local-only contract.
- **The worker URL inherits the cache-buster.** `workerUrl()` derives it
  from the engine `<script src>` so the deploy-time `?v=` stamp applies to
  the worker too. Don't hardcode a version string in JS.
- **The built-in list stays small.** `BUILTIN_SECRET_CANDIDATES` is 32
  starter keys; `test_builtin_secret_list_is_small` fails if it grows into
  a bundled wordlist. Real lists are uploaded by the analyst and capped in
  the worker.
- **A secret match is a discovered secret, not a verdict.** The UI states
  the match is for authorized testing and that HS256 is not automatically
  weak. Never present a match as "the target is vulnerable".
- **The worker is tested under Node with a shim.** `_run_worker` defines
  `self`/`postMessage`/`importScripts`/`FileReaderSync` BEFORE evaluating
  the worker source (its top-level `importScripts` call needs the shim
  already in place), then drives `onmessage` and asserts the posted
  messages — found/secret, progress, cancel (tested < total) and deadline.
  The cancel test needs a large enough candidate list (5000) so the run
  cannot finish before the cancel message lands.
- **Engine regex escaping in test harnesses.** Node harness strings write
  base64url helpers as `replace(/\\\\+/g, ...)` in Python source (which
  produces `/\\+/g` in the JS file). Doubling the backslashes produces
  `/\\\\//g`, which Node parses as regex-then-division and throws
  `ReferenceError: g` at runtime — a trap that cost a test round here.
- **All four panels are functional** — nothing on the page ships
  `disabled` anymore, and `test_secret_panel_is_functional_and_bounded`
  asserts the Secret panel has no disabled controls. The PWA shortcut
  shipped with JWT-03 (`test_pwa_shortcut_added_now_the_workbench_is_complete`).

## Cross-surface URL changes (POLISH-01)

- **A URL is never in one file.** Changing where "Methodology" points meant
  editing the header nav and footer in `js/app.js`, `llms.txt`,
  `manifest.webmanifest`, `404.html`, `js/404.js` **and** the published
  `Policy:` line in `.well-known/security.txt`. The last one is easy to
  miss because it is a plain-text RFC 9116 field, not a link. Before
  finishing a URL change, grep the old target across
  `--include=*.html --include=*.js --include=*.txt --include=*.webmanifest`.
- **Deep links need real anchor IDs.** `tools/audit_site.py` resolves
  fragments against the target page's `id` set, so `/methodology/#scoring`
  fails the build unless that `h2` carries `id="scoring"`. Add the id in the
  same commit as the link.
- **`audit_site.py` passes vacuously on a missing directory.** Running it
  with no assembled `_site/` reports "Local link audit passed" and exits 0
  because it globbed zero pages. Assemble the site the way
  `.github/workflows/pages.yml` does (icons included — otherwise every page
  reports a missing `icon-192.png`) and audit *that* directory.
- **Display label vs raw risk.** `reportRiskLabel(data)` in `js/app.js` is
  the only place allowed to translate a raw `risk` into what a human reads.
  CORS + `low` renders `PASS`, because for CORS the headline is a
  pass/fail judgement rather than a severity. It is applied to Markdown,
  standalone HTML, CSV and the evidence-card hero; the
  `cyberbuddy-report/v1` JSON envelope keeps the raw value so automation
  is unaffected. If an export ever disagrees with the on-screen verdict,
  it is because a new export path did not call this helper.
- **Do not assert internal ticket IDs as page copy.** Two tests pinned the
  literal badge text `JWT-02 &middot; Live`, which blocked renaming a
  visitor-facing chip. Assert the structural marker (`jwt-phase-live`) that
  encodes the *state*, and leave the wording free to change.
- **Internal phase IDs stay in the repo.** JWT-0x identifiers belong in
  `docs/`, commit messages and code comments — never in rendered page copy.
  A visitor has no way to resolve "JWT-03".
