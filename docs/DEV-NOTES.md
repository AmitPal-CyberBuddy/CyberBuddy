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
