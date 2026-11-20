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

Note on numbering: the page's kicker says "Tool 04" while the site order is
CSP third (CORS says "Tool 03"). The kickers were left alone in this pass — it
is a copy change across four pages, not a defect in this tool.

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
