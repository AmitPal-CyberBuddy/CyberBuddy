# Seven-tool audit — phase by phase, 2026-11-20

Scope: one tool at a time, in the order the site presents them, covering
**technical correctness**, **UI/visual quality** and **user experience**. Each
tool gets its own section, the evidence behind every claim, what was changed,
and what is deliberately left as a recommendation.

This is a working record, not a marketing claim. Anything labelled
*recommendation* is a proposed change that was **not** made in this pass, with
the reason stated.

Environment for this pass: Python 3.11, Node 22, Chromium **not available**
(the sandbox has no browser binary and no package mirror reachable for one).
So: engine behaviour was exercised with the stdlib test-suite plus direct
grader calls; **rendered** behaviour (computed styles, real iframe, contrast)
is marked *unverified in a real browser* and must be confirmed by
`tests/browser/*` on a machine with Chromium.

Baseline before any change: `python3 tools/verify.py` → **PASS** (440 tests,
syntax, structured data, 20-page link check).

---

## Tool 01 — Clickjacking Validator

### What the tool does

1. Loads the target URL into a cross-origin `<iframe>` (the *visual* test).
2. Reads the target's response headers (`/api/scan` under `server.py`,
   published cache, or — with consent — a third-party relay) and grades
   `X-Frame-Options` + CSP `frame-ancestors` into LOW / HIGH / UNKNOWN.
3. When no header data is available, asks the analyst to attest what the
   frame showed, and labels the result **analyst-attested**.
4. Exports the result as print/PDF, PNG evidence card, Markdown, JSON, CSV,
   standalone HTML.

### Phase-by-phase findings

#### Phase 1 — entry (form, validation, consent)

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| 1.1 | Every scan of a private/loopback target (the normal `server.py` case) opened the **third-party relay consent gate** even though `server.py` answers `/api/scan` itself and no relay is ever contacted. The gate is rendered synchronously *before* any engine call, so a local analyst had to consent to a disclosure that never happens — and could answer "Decline", which skipped the engine entirely and produced a header-less "FRAME ONLY" report. | High (UX + truthfulness) | **Fixed** |
| 1.2 | The frame and the header grade can describe two different documents: the frame loads the *requested* URL while the grade is taken from `final_url` after redirects, and nothing on the page points that out. | Medium | **Recommendation** (see 3.2) |
| 1.3 | The `Validate` button only disables; there is no "run again" affordance until it returns, so slow relays make the form look dead. Spinner is present — acceptable. | Low | Recommendation only |
| 1.4 | `Ensure consent` answers are session-scoped (good). No change. | — | — |

#### Phase 2 — collection (engine, provenance, honesty labels)

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| 2.1 | `frame-ancestors` values `https:` and `https://*` are scored **PROTECTED / LOW**. Per CSP3 these are *any HTTPS origin*, i.e. effectively as framable as `*`. A HIGH-risk page would be reported as protected. Confirmed against the shipped grader (`frame-ancestors https:` → `risk=low`, `CSP frame-ancestors=protected`). | **Critical (false negative)** | **Fixed** |
| 2.2 | The same grader is used by CSP Policy Auditor (`allows *` → high) and Security Headers (`frame_ancestors_restricts`), which have the same blind spot. Fixing only Tool 1 would make three tools disagree. | High | **Fixed in all three graders** |
| 2.3 | Duplicate `frame-ancestors` inside *one* policy (`frame-ancestors *; frame-ancestors 'none'`) is decided by the last directive. CSP3 says the **first** occurrence wins (later duplicates are ignored). `*` first now scores LOW/protected — another false negative. `frame-ancestors 'none'; frame-ancestors *` scores HIGH. Both are wrong. | **High** | **Fixed** (first directive wins, and the duplicate is reported) |
| 2.4 | The LIVE/CACHED promise ("keep them on every result") is not honoured on this page: `reportTitleFlag` is filled with `unverifiedFlag()` (relay only), and the page has no live/cached tag, while the *hub* suite shows one. A published CI demo report and a fresh `server.py` scan render identically. | Medium (honesty) | **Fixed** |
| 2.5 | `fillMeta()` **hides** the source chip when protection is LOW "to reduce visual clutter". That deletes provenance exactly on the reassuring result — the one most worth auditing. | Medium (honesty) | **Fixed** |
| 2.6 | `risk` is only ever LOW/HIGH/unknown; the page and export code handle MEDIUM (dead branches). Methodology text says "Only X-Frame-Options protects the page → **Medium**" while the grader says LOW. | Low (doc drift) | **Fixed** (methodology row corrected to match behaviour) |
| 2.7 | `scan()` loads the frame *before* asking for consent, i.e. the target is contacted before the disclosure appears. Defensible (the analyst typed the URL) but the ordering should be deliberate and stated. | Low | Documented |

#### Phase 3 — result (verdict, evidence, exports)

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| 3.1 | The report never states **which origin** framed the page. If `frame-ancestors` allows `https://trusted.example`, the frame is allowed to load and the tool says LOW — correct, but an analyst reading the screenshot cannot tell whether the frame rendered *because* it is allow-listed or because framing is unprotected. | Medium (interpretation) | **Recommendation** — needs a "framed by this page's origin" line; deferred because it changes the findings table contract |
| 3.2 | Redirect drift: the frame keeps loading the *requested* URL while the grade describes `final_url`. There is no visible note when they differ. | Medium | **Recommendation** (same area as 3.1) |
| 3.3 | Analyst attestation resets only via a new scan; if the analyst attests, then toggles the PoC overlay to 5 % opacity, the recorded `poc_overlay.opacity_percent` follows the slider (good) but the *attested* verdict does not re-prompt. Acceptable — it is an attestation of what was seen. | Low | Documented |
| 3.4 | Evidence card / Markdown never mention the CSP directive that actually decided the grade; they list findings rows only. Adequate. | Low | — |
| 3.5 | Dead CSS: `.confirm-prompt` is hidden in print (`test_poc_overlay_is_not_hidden_in_print` guards only `.overlay`), correct — a prompt is not evidence. | — | No change |

#### Phase 4 — visual / responsive / accessibility

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| 4.1 | The live stage has a **fixed 440 px height** at every width (`body.evidence` clamps it, print clamps it, but phones do not). At 390 px wide that is a 390×440 frame of a desktop page — the analyst sees the top-left corner and the "if you can see the real site, it is clickjackable" instruction becomes untestable. There is also no way to ask for a page width, so on a phone the *visual* half of the tool is unusable. | High (UX) | **Fixed** — fluid `clamp(260px, 56vh, 460px)` height + a Fill / Desktop 1280 / Tablet 768 / Phone 390 viewport switcher (horizontal scroll inside the stage) |
| 4.2 | `.poc-stack` forces a single column, so the "Framing controls" table sits *below* a 440 px stage: on a laptop the header and the verdict must both be scrolled to be seen together — the opposite of the screenshot workflow the page is built for. | Medium | **Recommendation** — layout change, needs the responsive suite; not done blind |
| 4.3 | PoC overlay opacity slider (`5–100 %`) is unlabelled for screen readers beyond `for=`; `<output for>` is present — acceptable. The "suggested" button uses a ring only, plus the word "suggested" in a `<span>` — checking colour-alone: the ring is not the only cue. | Low | No change |
| 4.4 | `--attacker-opacity` is only applied by JS after the first `input` event; the CSS default is `0.72` but the visible `<output>` claims `72%` from markup — consistent. | — | No change |
| 4.5 | Print: the stage prints at 420 px fixed, and a *cross-origin* iframe frequently prints blank (browser behaviour). The page does not warn that a printed frame may be empty. | Medium | **Recommendation** (wording in print CSS is not possible; belongs in the note) |
| 4.6 | `#frameStatus` is a live-ish status line but not a live region; a screen-reader user gets no announcement when the frame loads or fails. | Medium (a11y) | **Fixed** |
| 4.7 | "Show PoC overlay" was active before any frame existed, so it toggled an empty stage with no explanation. (Export already handled this correctly with "Run a scan first".) | Low | **Fixed** — the overlay button is `disabled` until the frame fires `load` |

### What was changed in this pass

**Engines (Python + the `js/app.js` twin, so Pages and `server.py` agree).**

- `frame-ancestors` is now evaluated against CSP3 source matching instead of a
  literal `"*" in sources` check:
  - `*`, scheme sources (`https:`, `http:`), wildcard hosts (`https://*`,
    `http://*`) and wildcard ports (`https://app.example:*`) are **weak
    (HIGH)** — each matches any origin that fits the pattern;
  - a genuine allowlist (`'none'`, `'self'`, explicit origins) stays
    **protected**;
  - multiple policies still combine restrictively (unchanged).
- Duplicate directive handling: inside one policy the **first**
  `frame-ancestors` wins (CSP3) and the repeat is reported as its own
  informational finding (*CSP duplicate directive*) instead of silently
  overriding the first. `frame-ancestors *; frame-ancestors 'none'` moved from
  LOW/protected to HIGH — that was a false negative.
- `'none'` with a sibling source is ignored by browsers; it now scores weak.
- The same rule is shared by all three graders through
  `frame_ancestors_any_origin()` / `first_directive_values()`:
  - **CSP Policy Auditor** — a scheme source on `frame-ancestors` was graded
    `medium`; it is now `high`, and wildcard host/port sources are caught too;
  - **Security Headers** — `frame_ancestors_restricts()` no longer forgives a
    missing `X-Frame-Options` for a wildcard-shaped `frame-ancestors`.

**Tool 01 page + controller.**

- Relay-consent gate: asked only when a relay is actually reachable
  (`relayGateNeeded`). A local `server.py` scan no longer demands consent for a
  disclosure that never happens, and answering "Decline" can no longer replace
  a good local grade with a header-less FRAME ONLY report. If the shared helper
  is ever missing, the gate defaults to *shown* — fail closed, not open.
- Provenance: LIVE / CACHED tag restored in the report head
  (`scanTag(data)`), the source chip is no longer hidden on a LOW result, and
  the relay flag stays independent of both.
- Accessibility: `#frameStatus` is a `role="status"` live region, so a
  screen-reader user hears the frame load or fail; the viewport switcher is a
  labelled `role="group"` with `aria-pressed` buttons (28 px min height).
- Responsive stage: fluid height plus the viewport switcher; print resets the
  stage and hides the switcher.
- Docs: `methodology/` and `guides/clickjacking/` no longer claim XFO-only is
  **Medium** (the grader has always said LOW) and now describe the wildcard and
  duplicate rules.

**Tests added (all passing).**

- `FrameAncestorsStrictnessTests` — scheme/wildcard/port sources, first-wins
  duplicates, the duplicate finding, `'none'`-plus-origin, cross-tool agreement
  (CSP auditor severity, Security Headers XFO deduction) and a Node parity run
  against the JS twin.
- `ClickjackingPageContractTests` — consent gate is conditional, provenance is
  never hidden, LIVE/CACHED tag is rendered, the frame status is a live region,
  the stage height is fluid (not a fixed 440 px), the viewport switcher exists
  and is wired, the PoC button starts disabled, the toolbar is hidden in print.
- 7 new golden cases in `tests/grader_fixtures.json`, checked against both
  implementations by the existing `GraderParityTests`.

**Verification performed.**

- `python3 tools/verify.py` → PASS (460 tests, Python/JS syntax, structured
  data, 20-page link check).
- Python ↔ JS parity harness over 11 framing headers → identical risk, findings
  and per-tool severities.
- jsdom DOM-level run of the real `index.html` + `app.js` + controller
  (25 assertions: consent path, provenance, LIVE tag, viewport switcher width
  and `aria-pressed`, PoC enable/disable, overlay toggle, Markdown export) —
  25/25 pass.
- `curl` against the running `server.py`: `/api/scan` on the local site returns
  LOW with both controls protected, matching the rendered report.

### Recommendations implemented (same pass)

- The duplicate PASS chip: `findingRowHtml()` in `js/app.js` no longer prints a
  severity chip when the status chip already says it (`pass` + `ok`/`protected`).
- The posture strip's tag names were colour-only for assistive tech; each is
  now prefixed with an `sr-only` status word ("missing: Base URL control").
- The F-grade summary no longer over-claims. It names what is **still in
  place** ("Still in place: X-Frame-Options, …") instead of "treat the site as
  exposed" when several controls passed.
- `.poc-stack` is two columns above 1200 px, so the live stage and the controls
  sit side by side instead of stacking on a desktop.
- A **frame-context banner** states which origin is doing the framing
  (`window.location.origin`) and flags *redirect drift* when
  `final_url !== url`, so a screenshot is self-describing.

### Not verified in this pass — and the tool 2–7 backlog it exposes

- **No real browser.** Chromium is not installed in this environment and no
  package mirror is reachable, so computed layout, the actual cross-origin
  iframe, focus order and axe/contrast were not exercised. The new CSS is
  pinned by static assertions and the controller by jsdom; `tests/browser/`
  (`tool-results.js`, `responsive.js`, `site-contrast.js`) must still be run
  where Chromium exists, at 390 px and in both themes.
- Whether the fluid stage lands on a sensible height once the header, verdict
  banner and stage are all in one viewport (deferred layout item 4.2).
- `.poc-stack` still forces one column, so on a laptop the findings table sits
  below a tall stage. Recommendation, deliberately not changed blind.
- **Same consent bug exists in tools 02–04.** `js/tool.headers.js:71`,
  `js/tool.csp.js:78` and `js/tool.cors.js:266` all call
  `ensureRelayConsent(url)` unconditionally, so they ask a local-engine analyst
  to approve a third-party relay before a same-origin scan. Scheduled for the
  corresponding tool sections rather than patched here out of scope.
- Findings 3.1 (which origin framed the page) and 3.2 (requested vs graded URL
  after a redirect) remain open recommendations for Tool 01.

---

## Tool 02 — Security Headers

### What the tool does

One read-only `GET`, then a 0–100 score and A–F grade across eleven checks
(transport, CSP, XFO, HSTS, nosniff, Referrer-Policy, Permissions-Policy,
COOP/COEP/CORP, Report-Only CSP, cookie flags). Each finding carries the raw
header value it used; the raw header map is shown beside the findings.

### Phase 2 — collection (engine correctness)

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| 2.1 | **HSTS with whitespace is read as disabled.** RFC 6797 §6.1 defines `max-age` as `"max-age" OWS "=" OWS delta-seconds`. The grader used the regex `max-age=(\d+)`, so `max-age = 31536000; includeSubDomains` — valid, and accepted by browsers — parsed as `max-age=0` and was reported **"max-age=0 disables HSTS … not a protection"** with the full 15-point deduction. A site with working HSTS was told it had none. | **High (false negative)** | **Fixed** — real ABNF field parser |
| 2.2 | **HSTS with an invalid directive is scored as protection.** Per RFC 6797, user agents *ignore the whole field* when `max-age` is repeated, non-numeric, or when a valueless directive (`includeSubDomains=yes`, `preload=1`) carries a value. `max-age=31536000; max-age=0` scored **ok/0 points deducted**. | **High (false positive)** | **Fixed** — reported as weak with the exact reason |
| 2.3 | **Referrer-Policy is read backwards.** A comma-separated value is a deliberate *fallback chain*, and browsers use the **last** value they recognise. The grader read the **first** token, so `no-referrer, unsafe-url` (full URL leaked everywhere) scored **ok**, while `unsafe-url, no-referrer` (nothing leaked) scored **weak, −10**. | **High** | **Fixed** — effective value = last recognised |
| 2.4 | **`camera=self` is flagged as a wildcard.** The parser treated anything that was not exactly `feature=*` after `.strip()` as safe, but compared a parenthesised value wrongly: `camera=(*)` escaped detection while `camera=(self "https://x")` and `feature=self` were mishandled. Meanwhile the real wildcard forms (`camera=*`, `camera=(*)`, `camera=(self *)`) were inconsistently caught. | Medium | **Fixed** — structural parse of the allowlist |
| 2.5 | **A typo in a feature name hides silently.** Browsers ignore `Permissions-Policy` features they do not implement, so `micrphone=self` looked like a lockdown and enforced nothing. | Medium | **Fixed** — unknown feature names are reported |
| 2.6 | **"CSP-Report-Only" looked like a graded control.** When it was the *only* CSP, the row said "does not enforce anything" but sat inside the same findings table as enforced checks, at `info` with no cue that zero policy was in force. | Medium (interpretation) | **Fixed** — wording now distinguishes "only a Report-Only policy exists" from "a Report-Only policy also exists" |
| 2.7 | `Vary: Origin`-style response variations, cookie parsing and the CSP source checks were re-checked; no defect found in this pass. | — | No change |

### Phase 1 — entry (consent)

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| 1.1 | Same relay-consent defect as Tool 01: `ensureRelayConsent(url)` was called unconditionally, so a local `server.py` scan demanded approval for a disclosure that never happens, and "Decline" replaced a valid local grade with a "Header read declined" notice. | High (UX + truthfulness) | **Fixed** — gated on `relayGateNeeded`, fails closed if the helper is missing |
| 1.2 | A declined relay hid the results section but left the previous report's data in `cbLastData`, so the Export menu could still produce a report for the *older* target. | Medium | **Recommendation** — needs a decision on whether exports should be cleared on a failed run; deferred to keep this pass reviewable |

### Phase 3 — result (provenance, grading display)

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| 3.1 | The LIVE / CACHED tag promised by DEV-NOTES was missing: only the relay flag was rendered, so a CI-built published report and a fresh local scan were visually identical on the page that exists to be quoted. | Medium (honesty) | **Fixed** — `scanTag(data)` + relay flag |
| 3.2 | The grade badge (`#grade`) was a bare letter with no accessible name: a screen-reader user heard "B" with no context, while the gauge beside it names itself. | Medium (a11y) | **Fixed** — `role="img"`, `aria-label="Grade B, 85 out of 100"`, and an explicit "no grade" label for unreachable targets |
| 3.3 | The controller assigns `.grade.unknown` for an unreachable target but **no such rule existed in the stylesheet**, so that badge rendered with no colour or border (the base `.grade` has only a 1px transparent-ish border and inherits ink). | Low (visual) | **Fixed** |
| 3.4 | Nothing told the analyst a scan was in flight once a report was on screen: the old numbers stayed fully interactive and screenshot-able while the new scan ran. | Medium (UX/honesty) | **Fixed** — `aria-busy`, dimmed + `pointer-events: none`, "· refreshing" in the heading, released on every exit path, and forced back to full strength in print |
| 3.5 | Score arithmetic is a plain deduction sum, so `score` can reach 0 while several independent controls are fine; the summary text ("Critical posture. Key protections are absent") then overstates. | Low (wording) | **Recommendation** — changing the summary wording is a copy decision across guides/methodology; not changed |

### Phase 4 — visual / responsive / accessibility

| # | Finding | Severity | Status |
| --- | --- | --- | --- |
| 4.1 | Findings and Raw headers are stacked full-width (a previous review measured a 2735px-vs-236px two-column imbalance). Correct as-is. | — | No change |
| 4.2 | The findings table's severity chip duplicates the status chip for `protected`/`ok` rows (both render **PASS**-green), which adds noise on a nine-row table. | Low | **Recommendation** — shared renderer, affects every tool; needs a design decision |
| 4.3 | `postureHtml` lays out nine tags in one wrapping strip with `title=` tooltips only; on a phone that is a dense block, and the icons are decorative (`aria-hidden`) while the status word is not spoken. | Low | **Recommendation** — verified only statically; needs the responsive suite |

### What was changed in this pass

- `security_headers.py` + the `js/app.js` twin:
  - `parse_hsts()` / `parseHsts()` implement the RFC 6797 field grammar
    (OWS around `=`, valueless optional directives, duplicate/invalid
    `max-age`, multiple fields) and report *why* an unenforceable field is
    unenforceable;
  - `effective_referrer_policy()` / `effectiveReferrerPolicy()` use the last
    recognised value of the fallback chain and say so in the detail text;
  - `permissions_issues()` / `permissionsIssues()` parse the allowlist
    structurally, catch every wildcard form, and flag unknown feature names;
  - the Report-Only row distinguishes "only Report-Only exists" from
    "Report-Only alongside an enforced policy".
- `js/tool.headers.js`: relay consent gated on reachability (fail closed);
  LIVE/CACHED tag; `role="img"` + score in the grade's accessible name;
  `aria-busy` / `is-refreshing` around a re-scan, cleared on the declined,
  no-data and unreachable paths.
- `css/app.css`: `.grade.unknown`; the quiet refreshing state; print keeps the
  report at full strength.

**Tests added.** `HeaderParsingStrictnessTests` (10 cases: HSTS grammar and
failure modes, fallback chains, Permissions-Policy forms and typos, Report-Only
wording, plus a Node parity run of nine header edge cases) and
`HeadersPageContractTests` (6 cases: conditional consent, LIVE/CACHED, the
grade's accessible name, busy/refresh state, the print override, `.grade.unknown`).
Seven new golden cases in `tests/grader_fixtures.json`.

**Verification performed.**

- `python3 tools/verify.py` → PASS (**477 tests**, Python/JS syntax, structured
  data, 20-page link check).
- Python ↔ JS parity over 18 header edge cases → identical score, grade and
  per-check status/deduction (7 drift bugs were caught and fixed this way).
- jsdom DOM run of the real headers page (21 assertions: consent, grade
  accessible name, LIVE tag, posture, busy/refresh lifecycle, unreachable
  state) — 21/21 pass.

### Not verified in this pass

- Rendered layout and contrast of the refreshing state and the `.grade.unknown`
  badge need `tests/browser/site-contrast.js` where Chromium exists.
- The `Vary`-only fixture scores F because a response with no security headers
  legitimately fails every check; that is behaviour, not a defect.
- Findings 1.2, 3.5 and 4.2/4.3 were recommendations in the first pass and
  have since been implemented: the duplicate PASS chip is suppressed, the
  posture tags speak their status, the F-grade summary names what is still in
  place, `cbLastData` is cleared on the declined/no-data paths so the Export
  menu cannot emit a stale report, and the grade badge/verdict keep their
  accessible names. Re-verified: 494 tests, `verify.py` PASS, headers jsdom
  run 21/21.

---

## Tool 03 — CSP Policy Auditor

### What the tool does

1. Reads the target's `Content-Security-Policy` and
   `Content-Security-Policy-Report-Only` response headers (`/api/csp` under
   `server.py`, a published cache, the hosted grader, or — with consent — a
   third-party relay).
2. Grade the enforced policy: delivery, duplicate directives, script sources,
   style sources, object embedding, `base-uri`, `frame-ancestors`,
   `form-action`, mixed content, Trusted Types, reporting.
3. Score it 0–100 with A–F bands (`_CSP_DEDUCTIONS`: high 20, medium 10,
   low 5, via the shared `grade_for`).
4. Alternatively *paste* a header value and grade it locally, with no network
   request and no target contacted.

Note on numbering (corrected). An earlier draft of this section claimed the
CSP kicker was off by one and that the site lists CSP third. Both statements
were wrong. The canonical order is the `tools/index.html` catalog, the
`TOOLS_MENU` array and the `<link rel="prefetch">` block, and all three agree:
Clickjacking, Security Headers, **CORS, CSP**, DNS, CSRF, JWT. The kickers for
01–04 already matched it; **DNS, CSRF and JWT were numbered 07, 05, 06** and
are now 05, 06, 07. `ToolNumberingTests` pins the catalogue order and every
kicker together so this cannot drift again.

### Phase 2 — collection / engine correctness

**3.1 An empty source list was described as an ordinary allowlist.**
`Content-Security-Policy: default-src 'self'; frame-ancestors` graded the
framing control `ok` with the text "frame-ancestors uses a restrictive source
list". The *verdict* is right: CSP3 §6.7.2.7 step 2 returns "Does Not Match"
for an empty source list, i.e. it behaves like `'none'`, and browsers keep the
directive rather than dropping it. The *wording* was wrong in a way that
matters — an empty list is almost always a dropped template variable or a stray
trailing semicolon, and an analyst reading "restrictive source list" would never
go looking. Fixed in both engines: an empty list now says so explicitly and
asks the analyst to confirm the value was intended. The same defect existed for
`base-uri`, `form-action`, `script-src` and `style-src` (all reachable through
the same two helpers), and for `frame-ancestors` in the **Clickjacking** tool,
which additionally showed blank evidence (`frame-ancestors `) for the empty
case — fixed in `clickjacking_validator.py` / `assessFrameAncestors()` too.

**3.2 A wrapped pasted header was read as several policies.**
Paste mode split the input on newlines and treated each line as its own
policy. A field copied from a proxy or devtools dump is usually folded:
`Content-Security-Policy: default-src 'self';` followed by an indented
continuation. That produced "Found 2 enforced CSP response policies", fed the
literal `Content-Security-Policy:` label into the directive parser as a
directive name, and could invent a syntax error for a correct policy. Now
`split_pasted_header_fields()` / `splitPastedCspFields()` fold unlabelled
continuations into the field above while keeping a genuinely repeated field as
a second policy (browsers enforce both). Both engines agree on six pasted
shapes, compared detail-string-for-detail-string.

**3.3 Paste mode rejected the verdict it exists to give.**
The controller treated "no `policy` and no `report_only_policy`" as bad input.
That is exactly the answer for a header that carries no CSP, and for a
`Content-Security-Policy-Report-Only`-only paste — the two cases where a
pasted-header audit is most useful. Validation is now "does this text contain
at least one known CSP directive?" (`looks_like_csp_policy()`), so an empty or
report-only policy is graded (F / HIGH) and only genuinely unrelated text
(`Content-Type: text/html`) is rejected.

**3.4 No delivery context in a pasted report.** A pasted header still said
"Found N enforced CSP **response** policies" and "No enforced
Content-Security-Policy **response header** was found", though no response
exists and the HTTPS-delivery check is skipped. Both engines now say "in the
pasted header" / "The pasted text holds no enforced Content-Security-Policy
field".

**3.5 Verified sound.** Multiple policies combine restrictively; only the first
duplicate directive in one policy is used and the repeat is reported; Report-Only
never counts as enforcement; a strong policy on plain HTTP is flagged as
strip-vulnerable; `'none'` with a sibling source is treated as ignored. CSP and
Clickjacking agree on `*`, scheme sources, wildcard hosts and wildcard ports.

### Phase 1 — entry (consent)

**1.1 Relay consent was asked unconditionally.** `audit()` called
`ensureRelayConsent(url)` before anything else, so a local `server.py` (which
answers `/api/csp` itself) demanded approval for a disclosure that never
happens. Now gated on `relayGateNeeded(url)`, fail-closed: if the shared helper
is missing the disclosure stays. Because a stored `deny` makes
`relayGateNeeded` return `false`, the controller also refuses to scan when
`relayAllowed()` is false and no Python engine is present, so a declined user is
not silently downgraded to "no data" — they get the declined notice.

### Phase 3 — result (provenance, honesty, exports)

**3.6 A cached or relayed report looked like a fresh scan.** `#reportTitleFlag`
rendered `unverifiedFlag()` only. Now `scanTag(data) + unverifiedFlag(data)`,
the same two independent claims as Tools 01/02 (LIVE/CACHED for this run, "relay
data" for this source). A pasted header carries no tag at all.

**3.7 No busy state on re-audit.** Re-running an audit left the old report on
screen with no cue it was being replaced. `audit()` now sets `aria-busy` and
`.is-refreshing` on a visible report and clears both on every exit path
(render, declined, unreachable, no-data).

**3.8 "HTTP status —" on a pasted report.** Paste mode shares `#results` with
URL mode, so a pasted report showed an HTTP status of "—" and a method row that
said "GET · read-only". `#statusItem` / `#methodItem` now hide in paste mode
and come back on the next URL audit.

**3.9 The verdict badge had no accessible name.** `#verdict` renders
`F · 45/100`, which a screen reader reads as a stray letter and a fraction. It
now carries `role="img"` and a name ("CSP posture grade F, 45 out of 100"),
matching the Headers tool's grade box.

**3.10 A declined relay left the previous report exportable.** Same defect as
Tool 02: the deny path hid `#results` but kept `cbLastData`, so Export could
emit a Markdown/JSON/PNG report for a target no longer on screen. Cleared on
the deny and no-data paths; kept when the engine returns usable checks.

### Phase 4 — visual / responsive / accessibility

- `findingRowHtml()` and `postureHtml()` fixes from Tools 01/02 apply here for
  free (no duplicate PASS chip on passing rows, spoken status words in the
  posture strip).
- The findings table keeps `scope="col"` headers and per-row copy buttons; the
  proposed-policy block stays `code`-styled rather than a heading, so it is not
  announced as page structure.
- Unverified in a real browser: the paste block's `.pages-note` spacing and the
  two-column `.csp-evidence-grid` below 760 px.

### What was changed in this pass

- `csp_checker.py`: `_empty_list_note()`; empty-list wording for
  `_check_scripts`, `_check_styles`, `_check_navigation_directive`;
  `split_pasted_header_fields()`, `looks_like_csp_policy()`,
  `KNOWN_CSP_DIRECTIVES`; paste-mode wording for the enforced/missing policy
  rows.
- `clickjacking_validator.py`: empty `frame-ancestors` keeps its protected
  verdict, gains explicit evidence and detail.
- `js/app.js`: `cspEmptyListNote()`, `splitPastedCspFields()`,
  `looksLikeCspPolicy()`, paste-mode wording — full twins of the Python
  changes; `assessFrameAncestors()` empty-list evidence.
- `js/tool.csp.js`: conditional relay gate (fail closed) plus the stored-deny
  path, `scanTag()`, `aria-busy`/`is-refreshing`, `cbLastData` clearing,
  paste-mode meta hiding, verdict `role`/`aria-label`, directive-based paste
  validation.
- `tools/csp/index.html`: `#statusItem` and `#methodItem` hooks.
- `tests/csp_fixtures.json`: 10 → 14 cases (empty `frame-ancestors`,
  `base-uri`, `form-action`, `script-src`).
- `test_engines.py`: `CspStrictnessTests` (11 cases including a six-shape
  Python↔JS paste-parity run) and `CspPageContractTests` (6 static cases).

**Verification performed.**

- `python3 tools/verify.py` → **PASS** (494 tests, Python/JS syntax, structured
  data, 20-page link check).
- Python ↔ JS parity: 14 golden CSP fixtures (risk, score, grade, per-check
  status and severity) and 6 pasted-header shapes (result plus every detail
  string) — no drift.
- jsdom run of the real CSP page → **32/32** assertions: conditional consent,
  grade/verdict accessible names, LIVE tag, busy/refresh lifecycle, paste mode
  (no network, no HTTP facts, no scan tag, empty-list wording), paste → URL
  restoration, rejected paste keeping the previous report, declined relay
  clearing the export payload.

### Not verified in this pass

- A real browser for the paste block layout, the evidence grid at 390 px, and
  contrast of the `is-refreshing` state — `tests/browser/*` needs Chromium.
- `_check_navigation_directive` still scores a non-empty but non-source token
  (`frame-ancestors 'unsafe-inline'`) as a trusted allowlist. Browsers drop
  invalid source expressions, which would leave an empty list — a possible
  false negative, left as a recommendation because the fix needs a per-directive
  grammar check and would change grades for existing fixtures.
- HTTP-level paste of *two different* fields (`Content-Security-Policy` and
  `Content-Security-Policy-Report-Only`) is parsed and graded, but the report
  does not yet name both policies separately in the evidence table.

---

## Tool 04 — CORS Validator

(This is the fourth tool in site order — `tools/index.html`, `TOOLS_MENU` and
the prefetch block all list CORS before CSP — and the page's kicker agrees.)

### What the tool does

1. Sends the same request with two different `Origin` values (`ATTACKER_A`,
   `ATTACKER_B`) plus `Origin: null`, so a reflected ACAO can be told apart
   from a fixed allowlist.
2. Optionally repeats that triplet for `HEAD`/`OPTIONS`, and simulates a CORS
   preflight with `OPTIONS + Origin + Access-Control-Request-Method` (never a
   POST body).
3. Grades each method: reflection + credentials HIGH, reflection or
   wildcard + credentials MEDIUM, otherwise LOW; `Vary: Origin` is a separate
   finding that never drives the headline.
4. Builds a local HTML PoC (`CyberBuddyCorsPoc`, no DOM and no network) that the
   analyst hosts on their own origin.

### Phase 2 — collection / engine correctness

**3.1 Credentials were OR-ed across probes — a false positive.**
`creds = _acac(hdr_a) or _acac(hdr_b) or _acac(hdr_null)` was then paired with
"did *any* probe reflect". A server that reflected both probe origins **without**
`Access-Control-Allow-Credentials` but answered the `null` origin **with** it
was graded HIGH with the finding "reflects arbitrary Origins AND allows
credentials … can read authenticated responses as the victim". Neither
statement was true of that response. Credentials are now read per response:
`creds_ab` decides the reflection ladder, `creds_null` decides the null ladder.

**3.2 The null-origin finding suppressed the reflection finding** — same
root cause, different symptom. `if null_reflected: … elif reflected: …` meant a
server that reflected the null origin *and* two arbitrary origins produced one
table row (the null one) and the two-origin reflection never appeared at all.
They are now independent findings, and the summary names the branch that
actually decided the verdict instead of always crediting the null one.

**3.3 Preflight token matching was substring matching.** `Access-Control-Allow-Methods: POSTPREVIEW`
was reported as "Preflight allows POST (ACAM includes it)" — a preflight a
browser rejects. Conversely `ACAH: X-Token-Extra` "contains" `X-Token` and hid a
real failure, while `Access-Control-Allow-Headers: *` (which allows every
requested header) was reported as *missing* the header. Both now compare
comma-separated tokens, and `*` satisfies any requested header.

**3.4 An error status with no CORS became "Pass".** A 401/403/500 with no ACAO
fell through to `both_absent` → "cross-origin reads are blocked by default
(Pass)". An error response says nothing about the policy on the real resource.
When every probe returns ≥400 **and** no ACAO, the method is now `unassessed`
with the status named; if an error response *does* carry ACAO, it is still
assessed (that header is real evidence).

**3.5 Nothing measured could still read PASS.** With every probe raising, the
result was `risk: low` and the summary "No assessed methods produced a CORS
policy result" — a green chip over an empty measurement. Overall risk is now
`unknown` with "An error status or a failed request is not evidence of a
restrictive policy."

**3.6 Unassessed rows carried an unstyled risk class.** The coverage matrix
emitted `class="risk unassessed"`, and no such CSS exists, so a 405/501 row
rendered a plain word. Rows now use `risk unknown` (the boolean `unassessed` and
`reason` carry the meaning) and `.unassessed-badge` — emitted since the matrix
was added, never styled — has a style.

### Phase 2 — collection (browser fallback, `js/app.js`)

**3.7 A thrown fetch was reported as `ok`/tested.** The hosted probe caught any
`fetch` rejection and emitted a passing check ("The browser blocked the
cross-origin read … That usually means this origin is not allowed"), pushed the
method into `tested_methods`, and could therefore render a PASS for a probe that
never got an answer — indistinguishable from a dead network, a TLS failure or an
adblocker. The check is now `info`, the method is `unassessed`, and the headline
is "not assessed" ("JavaScript cannot tell those apart — run server.py").

**3.8 A null-origin reflection was reported as a wildcard.** `acao === "null"`
fell into `acao === "*"`'s branch and produced "Any website can read this
resource … Fine only for fully public data" — the inverse of the finding. The
null case is checked first now, and the null response's own ACAC decides.

**3.9 `browserCorsRisk` could not reach HIGH.** It never returned `high` for a
credentialed wildcard (correct: Fetch refuses `*` with credentials, so the
browser never exposes that response) but the ladder also let a broken
wildcard configuration outrank a real reflection. The function keeps its
conservative ceilings — single-origin evidence is at most MEDIUM — with the
reason documented at the branch.

### Phase 1 — entry (consent)

**1.1 Relay consent was asked unconditionally**, so a local `server.py` asked
permission for a disclosure it never makes. Gated on `relayGateNeeded(url)`,
fail-closed when the helper is absent; a stored `deny` now also refuses the
probe outright instead of silently falling through to "no data".

### Phase 3 — result (provenance, honesty, exports)

**3.10 No LIVE/CACHED tag.** Only `unverifiedFlag()` was rendered, so a cached
CI report and a fresh probe looked identical. Now `scanTag(data) + unverifiedFlag(data)`.

**3.11 No busy state, and a stale report could survive a failed probe.** A
re-probe overwrote the verdict with "PROBING" while leaving the previous target's
findings and coverage matrix on screen. The report is now marked `aria-busy` /
`is-refreshing` and cleared; a declined relay clears the findings, the coverage
matrix **and** `cbLastData`, so the Export menu cannot emit a report for a
target that was never scanned.

**3.12 The verdict chip had no accessible name**, and `NOT ASSESSED` /
`UNREACHABLE` fell through to the generic "UNKNOWN" styling and copy. Both states
now have their own label, banner class and `role="img"` name.

**3.13 `mMethod` claimed methods that were never probed.** When
`tested_methods` was empty the meta row fell back to the *requested* list, so a
401-everywhere scan read "GET". It now says `not assessed (GET)`.

### Phase 4 — visual / responsive / accessibility

- `.unassessed-badge` styled (pill, medium-severity colours) — it had been
  emitted unstyled since the coverage matrix was added.
- The coverage table keeps `scope`-less `<th>`s; that is left as-is because the
  table is a data matrix read with its caption ("Method coverage") rather than a
  form, but the badge now sits *inside* the method cell rather than trailing the
  label as plain text.
- Unverified in a real browser: the method-picker grid at 390 px and the
  coverage table's horizontal scroll at 360 px (`.method-table` block-scrolls
  below 420 px).

### What was changed in this pass

- `cors_validator.py`: per-response credential attribution and a re-ordered
  severity ladder; null-origin and reflection findings are independent;
  `_comma_tokens` / `_lists_token` / `_allows_any_header` for preflight
  ACAM/ACAH, including `*`; `statuses=` argument and the error-status
  `unassessed` path; `unknown` when nothing was assessed; `risk: unknown` +
  `reason` on unassessed rows; summaries that name the deciding exposure and the
  HTTP status.
- `js/app.js`: `probeCorsLive` treats a thrown fetch as unassessed, checks the
  null origin before the wildcard branch, reports "not assessed" when nothing
  was measured, and documents `browserCorsRisk`'s ceilings.
- `js/tool.cors.js`: conditional relay gate + stored-deny path, `scanTag`,
  `aria-busy`/`is-refreshing`, `cbLastData` clearing, accessible verdict with
  NOT ASSESSED/UNREACHABLE states, honest `mMethod`, no-network-answer branch.
- `css/app.css`: `.unassessed-badge`.
- `test_engines.py`: `CorsStrictnessTests` (10 cases) and
  `CorsPageContractTests` (7 static cases).

**Verification performed.**

- `python3 tools/verify.py` → **PASS** (511 tests, Python/JS syntax, structured
  data, 20-page link check).
- jsdom run of the real CORS page → **24/24** assertions: conditional consent,
  busy/refresh lifecycle, LIVE tag, coverage matrix (badge + styled risk chip),
  unmeasured scans never rendered as PASS (both the Python "unmeasured" answer
  and a dead browser probe), declined relay clearing findings/coverage/export,
  and the local PoC builder.
- Smoke re-run of the Headers and CSP pages against the same `js/app.js` →
  6/6 (no regressions from the shared helpers touched here).

### Not verified in this pass

- A real browser for the method-picker grid, the 360 px table scroll, and the
  colour of the new badge.
- Two engine paths need a live target: a preflight against a server that
  actually answers `OPTIONS` with `ACAM`/`ACAH`, and the hosted browser probe's
  behaviour when CORS *succeeds* (jsdom cannot model a real CORS decision).
- `ACAO` on a redirect chain, and `Access-Control-Max-Age`, are not inspected;
  both are worth a follow-up pass rather than a change here.

---

## Tool 05 — DNS & Domain Security Analyzer

(Fifth tool in site order; the kicker read "Tool 07" and is corrected in the
cross-cutting section below.)

### What the tool does

1. Validates the input as a **hostname** (a URL, path, port or `_dmarc` label is
   rejected, never silently truncated).
2. Asks a resolver for `A/AAAA/NS/MX/TXT/DS/DNSKEY` at the apex, `TXT` at
   `_dmarc`, twelve `DKIM:<selector>` keys, and walks the RFC 8659 CAA tree from
   the FQDN upward, keeping the first non-empty RRset.
3. Scores six weighted controls (DMARC 20, SPF 15, DKIM 10, DNSSEC 10, name
   servers 10, CAA 5) into 0–100 and A–F, refusing to grade at all when a query
   failed — an incomplete lookup is not evidence of an absent record.
4. Renders every finding with the raw record it used, and labels a relayed read
   (Google Public DNS over DoH, after consent) **unverified**.

Both graders — `dns_security.py` and the browser port `gradeDnsFromRecords()` in
`js/app.js` — are exercised side by side; the parity test compares the finding
*detail text* as well as the status and deduction.

### Phase 2 — engine correctness

**5.1 DKIM keys were rejected unless `v=DKIM1` came first — a false negative.**
RFC 6376 §3.6.1 makes the version tag **optional** (it defaults to DKIM1) and
says nothing about it having to be the first tag. The parser required
`tags[0].lower() == "v=dkim1"`, so `k=rsa; p=MIGf…` and
`k=rsa; p=MIGf…; v=DKIM1` — perfectly valid published keys — graded as
*"No DKIM key on common selectors"* and cost the domain 5 points.

Both ports now parse tags into a name→value map (first occurrence wins, as RFC
6376 requires), accept a missing `v=`, reject a *different* `v=`, and treat an
empty `p=` as a revocation. Verified: `k=rsa; p=…` → **100/A**, previously
**95** with a DKIM "weak" finding.

**5.2 A revoked key was reported as a missing key — a wrong remediation.** With
`p=` empty (RFC 6376's revocation form) the advice was "no DKIM key on common
selectors … a custom selector may still exist", i.e. go and look for a record
that was deliberately retired. Revocations are now tracked separately and read
*"DKIM key(s) on default, google are revoked (empty p=), so no active key is
published on common selectors"*. The deduction is unchanged (an empty `p=`
proves nothing signs), only the sentence that explains it.

**5.3 Grade A claimed "the zone is signed" with no DNSSEC at all.**
`summarize()` returned a fixed A-grade sentence ending "…and the zone is
signed" regardless of the DNSSEC row. DNSSEC is 10 of the 100 points, so a zone
with everything *except* DS/DNSKEY scores 90 → **A**. Confirmed: fixture minus
DS and DNSKEY → `90 / A` with "the zone is signed" directly under a DNSSEC row
saying "No DS or DNSKEY records". The A sentence is now conditional: signed
zones keep the original wording, unsigned ones read *"Strong email posture —
spoofing controls are enforced — but DNSSEC is not deployed, so lookups are not
cryptographically authenticated."* The grade itself is unchanged (90 = A is the
documented band).

**5.4 `redirect=`-only SPF was described as a neutral result.** RFC 7208 §6.1
forbids `all` alongside `redirect=`; the target policy decides. The engine's
fall-through branch said *"SPF has no all mechanism — unmatched senders receive a
neutral result; prefer -all"*, which is misleading advice for a legal record
(retargeting is not `?all`). It now names the redirect target and says the check
does not follow it: *"SPF has no all mechanism of its own and delegates to
redirect=\_spf.example.com — the effective result comes from that policy, which
this check does not follow. Confirm the target ends in -all."*

**Deliberately not changed:** the 5-point deduction stays. Making a redirect-only
policy full-credit would reward a record whose target policy was never fetched
and might itself end in `+all` — a fail-open in the grader. An `info` status was
drafted and rejected for that reason; the fix is the sentence, not the score.
Likewise the "SPF has no all mechanism" branch without `redirect=` still means a
neutral result and is still correct.

**5.5 `v=spf10` / `v=dmarc10` were accepted as SPF/DMARC records.** The version
test was `startswith("v=spf1")`, so a record whose version is `spf10` — not an
SPF record at all per RFC 7208 §4.5 — scored as SPF, and the same held for
`v=dmarc10` (RFC 7489 §6.3). Both now require a whole version tag (terminated by
whitespace, `;` or end of string).

**5.6 DKIM selector lists could drift between the two ports.** They are separate
literals (`DKIM_SELECTORS` in Python, `DNS_DKIM_SELECTORS` in JS) that must
probe exactly the same names, or the two graders disagree for no visible reason.
`test_engine_and_browser_probe_the_same_dkim_selectors` now reads the JS array
and fails on any divergence or duplicate.

### Phase 3 — result / UX

**5.7 A declined scan left the previous report on screen.** Declining the
consent gate hid `#results` but never cleared `#summary`, the findings table,
the record table or `cbLastData`, so the Export menu could still emit the
**previous domain's** report for a scan that never happened. Same defect class as
Tool 03's 3.x; fixed the same way (`clearReport()` on the decline and failure
paths, `cbLastData = null`).

**5.8 A stale session "no" could be bypassed, and only a fresh "deny" was
checked.** The controller tested `consent === "deny"` but not the revoked-consent
state, unlike the CORS controller. Both now share the rule: a refused relay is
refused even when the gate short-circuits.

**5.9 A failed lookup left the old summary in place.** `#results` was hidden but
`#summary` still carried the previous verdict — and a hidden section is one
`hidden`-class bug away from showing it. Cleared on every failure path.

**5.10 The provenance was right but is now pinned by a test.** The resolver row
is filled from `data.resolver` (the system resolver that actually answered) and
falls back to `sourceLabel()`, which names the DoH relay as "public DNS
(Google)". `test_the_page_never_claims_a_resolver_it_did_not_use` keeps it that
way.

**5.11 Considered and left as-is.** An apex `A: NXDOMAIN` with a working
`_dmarc` record returns an ungraded `error` — defensible: a name that does not
exist has no posture to measure, and the DNS-evidence rule is applied
consistently. CAA inherited from a parent zone (`CAA_SOURCE` = the TLD) earns
full credit with the source named in the evidence; RFC 8659 does make a parent's
CAA set authoritative for the child, so the grade is correct even though it is
generous in spirit. `CAA 0 issuewild` alone scores 3 of 5 (wildcard-only
protection) — kept.

### Verification

- `python3 -m unittest test_engines -q` → **529 tests OK** (was 514; +15 for
  Tool 05: 7 engine regressions, 1 selector-parity guard, 5 page-contract
  assertions, 2 evidence/provenance checks).
- `python3 /tmp/dnsparity.py` style check, now in-suite: the Python and browser
  graders produce identical score, grade, risk, summary **and per-finding detail
  text** across 12 record maps, including the DKIM shapes in 5.1/5.2. A separate
  `test_js_finding_wording_matches_python` pins the copy character-for-character
  on one map where all six controls have something to say.
- jsdom harness `/tmp/dom-dns.js` → **15/15** against the fixed controller
  (happy path, decline, hard failure, re-enabled button, invalid input). The same
  harness against the previous controller → **12/15**, failing exactly the three
  stale-report assertions above.
- Live resolver check (`scan_dns`, system resolver, 2026-11-20): `cloudflare.com`
  → 100/A "…and the zone is signed"; `github.com` → 90/A "…but DNSSEC is not
  deployed" (it publishes no DS); `example.com` → 90/A with the DKIM revocation
  sentence and the CAA gap named separately.
- `python3 tools/verify.py` → **PASS** (20 pages, links clean).

### Recommendations not made in this pass

- **Follow `redirect=` and `include:`** to report the effective SPF verdict. It
  needs a second round of queries and a loop guard (RFC 7208 caps lookups at 10
  and forbids recursive `redirect`); the wording fix above is the honest interim.
- **Look up the organisational domain's DMARC** when the apex has none
  (RFC 7489 §3.2), so a subdomain that inherits `p=reject` is not marked
  "missing".
- **DKIM key strength** (`k=`, key length, `h=` allowed hashes): a published
  `p=` says nothing about whether the key is 1024-bit RSA.
- **CAA from the TLD** deserves a "inherited — verify the registry's policy"
  note in the evidence line, even though the grade is per RFC 8659.

---

## Tool 06 — CSRF PoC Generator

(Sixth tool in site order. This one has **no Python engine and no network
path** by design: the parser and generator are pure functions in
`js/tool.csrf.js`, exercised directly under Node.)

### What the tool does

1. Parses a pasted raw HTTP request (request line, headers, query string,
   `urlencoded` / `multipart` / `text/plain` / JSON body).
2. Rebuilds it as one or more standalone HTML pages using only what a browser
   can send — forms for GET/POST, `fetch()` for JSON and non-form methods.
3. Labels each variant READY / LIMITED / NOT DIRECTLY REPRESENTABLE from
   **browser mechanics only**, never as a vulnerability verdict, and lists the
   conditions a test needs (state change, ambient cookies, no effective token).
4. Flags likely CSRF-token fields so the analyst can include or exclude them.

### Phase 2 — engine correctness

**6.1 A JSON CSRF token was invisible — the one field this tool exists to
surface.** `{"csrfToken":"AAA","email":"a@b.c"}` reported
**"Body parameters: none"**, `Likely tokens —`, no token panel, and no
limitation. It sat under a copy block promising tokens are "included by
default (CyberBuddy never silently removes them)", and the Markdown export said
the same. A JSON endpoint is exactly where a hand-rolled token check is easy to
miss, so the tool was quietest where it mattered most.

JSON keys are now parsed into `jsonKeys`, token-like names (`csrfToken`,
`_csrf`, `authenticity_token`, …) join the token list with `source: "json"`,
the meta row counts them ("2 JSON keys"), the report lists them, and unticking
one **removes the key and re-serializes the body** — with a limitation saying
the bytes may differ. Body byte-for-byte fidelity is preserved whenever nothing
is excluded; invalid JSON and non-object (array/scalar) bodies are left
untouched and get no key analysis.

**6.2 A URL fragment was treated as part of the request.** `GET /search?q=1&page=2#results`
is sent as `/search?q=1&page=2` — the fragment never leaves the browser. The
parser split the query on `?` only, so `page` became `2#results` and the
generated form re-sent that corrupted value; the action URL kept `#results`
too. Fragments are now stripped on both target forms (absolute and
origin-form) before the query is split. Verified: hidden inputs are `q=1`,
`page=2`, action `https://app.example.com/search`, no `#` anywhere.

**6.3 The scheme was guessed as HTTPS for a port that says otherwise.**
Origin-form requests have no scheme, so one is inferred from the `Host`. The
rule was "local host ⇒ http, else https", which turned
`Host: app.example.com:80` into `https://app.example.com:80/x` — a TLS
handshake against a plain-HTTP port, i.e. a PoC that cannot work. Port `80`
now means `http`; `443` and no port stay `https`; any other port stays `https`
but the assumption is **disclosed** in the report as a limitation.

**6.4 `parseRequest()` computed a `warnings` array that nothing ever read.**
`warnings` was initialised, returned, and never rendered, tested or exported —
so anything pushed into it (now, 6.3) would have vanished. Generation now folds
every parse warning into the report's limitations, and a test asserts the
scheme note reaches it.

**6.5 Excluding the guard tested nothing and still read as a result.**
With a single `X-Requested-With` header, the request is LIMITED *because* the
guard needs `fetch()` + preflight. Unticking that header produced a fetch
variant **without the guard**, while the status, the copy and the reason still
said "depends on a CORS preflight" — the report claimed to have exercised a
guard that was not in the payload. The result now carries `unassessed: true`,
the chip reads `LIMITED · NOT ASSESSED`, and the reason says plainly that the
guard was excluded and therefore not tested. A token-only request that keeps
its Content-Type takes the same path for the same reason.

**6.6 `X-Requested-With` could not be excluded at all.** The only exclusion UI
was the token panel, and `looksLikeToken("x-requested-with")` is false — so the
canonical CSRF guard header could never be removed to test whether the server
enforces it. Non-token `X-*` headers now have their own "Replayed guard headers"
panel (same `excluded` map, `data-header-uid`), absent from the generated HTML.

**6.7 The token panel's copy did not change on exclusion.** It kept saying the
fields "are included by default" while the generated PoC had already dropped
them. `#tokenNote` now states *"N of M likely token field(s) will be LEFT OUT of
the generated PoC"*, distinguishes that from the pasted request (which is never
modified), and adds "the guard is NOT assessed" when every token is excluded.

### Phase 4 — robustness

**6.8 A large paste could hang or exhaust the tab.** Measured under Node: a
100 KB body of 200 k parameters produced a **9 MB** PoC in ~0.5 s, and a 4×
larger body died in `String.split` inside the V8 heap. The page accepted
anything. Requests are now refused above **512 KB** (`too-large`) and **2,000
parameters** (`too-many-params`, query, urlencoded, multipart and text/plain),
with copy that explains the limit. The same 781 KB input is refused in 1.7 ms.

### Considered and deliberately left alone

- **HTML forms cannot control `Content-Type`.** The default urlencoded form is
  still the primary variant, with `multipart` and `text/plain` offered as
  alternatives (never the other way round). The JSON-as-`text/plain` trick
  stays a labelled alternative, only offered when the body can be framed as a
  single `name=value` pair.
- **`json-fetch` is kept as the default JSON variant.** The `text/plain` trick is
  more likely to work in practice, but promoting it would bury the honest
  statement that JSON bodies need a preflight behind an encoding the server may
  reject; both remain visible, and 6.1 makes the token caveat explicit.
- **`HEAD`, `OPTIONS`, `TRACE`** keep their existing treatment (HEAD is
  LIMITED via `fetch()`, TRACE is not representable). OPTIONS is now also
  reachable as a requested method (`options` variant) — no change to its
  classification.

### Verification

- `python3 -m unittest test_engines -q` → **537 tests OK** (529 after Tool 05,
  +8 for Tool 06: JSON key/token handling, byte-fidelity guard, fragment
  stripping, scheme inference, unassessed guard, size limits, panel wiring).
- `CsrfParserTests` (23 cases, pre-existing) → OK. One assertion was updated
  rather than deleted: `test_fetch_honors_query_and_header_exclusions`
  asserted `READY` for a PoC that sends no guard header at all — the exact
  defect 6.5 describes.
- jsdom harness `/tmp/dom-csrf.js` → **22/22** (JSON token toggle round-trip,
  "LEFT OUT"/"NOT assessed" copy, guard-header exclusion, NOT ASSESSED chip,
  fragment-free URL, error path clearing the report). The same harness against
  the previous controller fails immediately (no token checkbox for JSON keys).
- `python3 tools/verify.py` → **PASS**, 20 pages, links clean.

### Recommendations not made in this pass

- **Auto-read the page's form** to pick up the token it actually emits (a
  browser extension or a paste-the-HTML flow), so the PoC does not depend on a
  static token that can never match.
- **`SameSite` pre-check**: the page could ask for the cookie's `SameSite`
  attribute (or a pasted `Set-Cookie`) and say up front that `Strict` makes most
  of the variants impossible.
- **Fetch Metadata** (`Sec-Fetch-Site`) is a real modern control; the tool
  mentions Origin/Referer but not `Sec-Fetch-*`, which the browser sets and the
  attacker cannot forge.

---

## Cross-cutting — tool numbering (fixed)

The audit labels tools by their position in the site catalogue, so the
catalogue order is the one thing that has to be unambiguous. It is stated in
three places, and they already agreed with each other:

| # | Tool | `tools/index.html` card | `TOOLS_MENU` | `<link rel=prefetch>` | kicker before |
| --- | --- | --- | --- | --- | --- |
| 1 | Clickjacking Validator | 1 | 1 | 1 | 01 ✓ |
| 2 | Security Headers | 2 | 2 | 2 | 02 ✓ |
| 3 | CORS Validator | 3 | 3 | 3 | 03 ✓ |
| 4 | CSP Policy Auditor | 4 | 4 | 4 | 04 ✓ |
| 5 | DNS & Domain Security Analyzer | 5 | 5 | 5 | **07 ✗** |
| 6 | CSRF PoC Generator | 6 | 6 | 6 | **05 ✗** |
| 7 | JWT Security Workbench | 7 | 7 | 7 | **06 ✗** |

So the catalogue was right and the last three pages were wrong: DNS read
"Tool 07", CSRF "Tool 05", JWT "Tool 06" — the numbering a reader would infer
if they assumed DNS came last. Fixed to 05/06/07.

**A correction to this document.** The Tool 03 and Tool 04 sections originally
said the CSP page's "Tool 04" kicker was off by one and that the site lists CSP
*third*. Both claims were wrong, and following them would have broken a
correct page. The error came from trusting the tool sequence in the audit plan
(headers → CSP → CORS) over the catalogue's actual order (headers → **CORS →
CSP**). Both statements are corrected in place above.

**Guard.** `ToolNumberingTests` (3 cases) now reads the catalogue cards, the
`TOOLS_MENU` array, the prefetch block and every page's kicker, and fails if
they disagree, if a number repeats, or if a page has no kicker at all.

Verified: `python3 tools/verify.py` → **PASS**, 537 tests.
