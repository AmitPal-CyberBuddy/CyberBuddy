# CyberBuddy — roadmap & session handoff

> **Repo-internal planning document.** The Pages workflow never copies
> `docs/` to the deployed site, so this file (like `docs/DEV-NOTES.md`) is
> not published. It is the **source of truth for future Arena sessions**:
> read it first, update it before you finish.
>
> The repository is **public**, so this file is not secret. Do **not** put
> credentials, private engagement details, customer data or sensitive plans
> here. Everything below is deliberately safe to publish.

---

## 1. Current project state

Recorded at the start of the JWT-00 session (2026-08-15). See §5 “Current
handoff” for the state at the end of that session.

| Item | Value |
| --- | --- |
| Latest merged feature/PR | **JWT-00 preview + JWT-01 decode/inspect/verify** (PR #24, merge commit `b8a9fdc`) — the JWT Security Workbench is live on GitHub Pages. Verified present in `origin/main` (`e2a9a86`, which also applies the `tools/jwt` workflow copy line) before this session; not re-applied. |
| Live tools | 6 live — Clickjacking Validator, Security Headers, CORS Validator, CSP Policy Auditor, CSRF PoC Generator, **JWT Security Workbench (feature-complete: decode/inspect/verify + edit/generate/sign + test variants + bounded secret testing)** |
| Public sections | Hub · Tools catalog (`/tools/`) · Methodology · Guides (`/guides/`, one per tool — 6) · Documentation (`/documentation/`) |
| Python test total | **249** after JWT-00; **245** after JWT-01 (preview tests replaced by functional engine tests); **258** after JWT-02; **274** after JWT-03 (16 variant/secret/worker tests) |
| JavaScript file total | **20** (13 under `js/` incl. `js/jwt.engine.js` + `js/tool.jwt.js`, 7 under `tests/browser/`) — all pass `node --check` |
| Browser suites | layout/dropdown/overlays/relay-gate/responsive/csrf — JWT-00 added the preview page and JWT guide to the `layout`/`dropdown`/`responsive` PAGES arrays; not runnable in the Arena sandbox (no Chromium) |
| Pages assembly result | Hub, 404, methodology, catalog and six tool pages resolve; `docs/`, `tests/` and `REVIEW.md` absent from `_site/`. The JWT tool page (JWT-01) is indexed and in `sitemap.xml`. |
| Release/version state | **Pre-1.0** — no tagged release; `main` carries the live site via GitHub Pages |

Tool categories in force (from IA-01): **Assess targets** (Clickjacking,
Headers, CORS, CSP — the four that join the hub “Run suite”) and **Local
utilities** (CSRF PoC Generator and the JWT Security Workbench — neither scans
a target). JWT is `status: "live"` in `TOOLS_MENU` after JWT-01; it remains
`category: "local"` and excluded from the Run suite.

---

## 2. Status definitions

A task is **not DONE merely because it was committed locally.** Mark it DONE
only after a later session verifies it has merged into `origin/main`.

| Status | Meaning |
| --- | --- |
| `TODO` | Not started. |
| `NEXT` | The next approved work item — the only thing the next session may pick up. |
| `IN PROGRESS` | Being implemented on a branch. |
| `IN REVIEW` | PR open, not merged. |
| `DONE` | Verified present in `origin/main`. |
| `BLOCKED` | Cannot proceed — include the reason. |
| `DEFERRED` | Intentionally postponed. |

---

## 3. Work-item format

Every roadmap item records, in order:

1. **Stable ID** (e.g. `IA-01`).
2. **Status** (from §2).
3. **Goal** — the outcome in one or two sentences.
4. **Scope** — what the work covers.
5. **Explicit non-goals** — what must NOT be done in the same change.
6. **Dependencies** — items that must land first.
7. **Acceptance criteria** — observable conditions for completion.
8. **Required tests** — regression + real-browser coverage where needed.
9. **PR/commit reference** — filled in after completion.
10. **Notes/traps** — anything the next session must know.

---

## 4. Ordered roadmap

Items are ordered; work flows down the list. Only the item marked `NEXT` is
approved for the next session — do **not** implement later items in the same
PR.

### IA-01 — Scalable tool information architecture
- **Status:** `DONE`
- **Goal:** Let the site scale past five tools without a growing nav, footer
  or tool list — two tool categories, a dedicated catalog, and one JS registry.
- **Scope:** Group the Tools menu into *Assess targets* / *Local utilities*;
  add `tools/index.html` (catalog); split the hub cards into the two groups;
  make the footer category-based; publish the catalog (server routes,
  sitemap, `llms.txt`, README, Pages workflow + exclusion guard).
- **Non-goals:** No new security tool; no public Guides/About pages; no
  visual redesign; no broad `app.js` refactor (the registry change is
  behavior-preserving).
- **Dependencies:** CSRF PoC Generator (PR #20) merged.
- **Acceptance criteria:** Catalog at every viewport + both themes; dropdown
  grouping and hit-testing pass; hub category layout and footer layout pass;
  every existing browser suite stays green; `docs/ROADMAP.md`,
  `docs/DEV-NOTES.md`, `tests/` and `REVIEW.md` stay out of `_site/`.
- **Required tests:** stdlib `ToolCatalogTests` + `PagesExclusionTests`;
  catalog page added to `layout`/`responsive`/`dropdown` browser suites;
  new dropdown-grouping and hub-category/footer checks.
- **PR/commit:** PR #22 · branch `arena/01a00217-cyberbuddy` · commit
  `baaea21` · merged into `origin/main` as `2956801` (verified 2026-08-15).

### GUIDES-01 — Public Guides foundation + one Clickjacking pilot guide
- **Status:** `DONE`
- **Goal:** A Guides section with a concise pilot guide (Clickjacking),
  connected to the Clickjacking Validator.
- **Scope:** Guides foundation + the pilot guide. Guides are **concise and
  connected to CyberBuddy tools**, not full articles — depth is delegated to
  primary references (OWASP, CWE, MDN, specs).
- **Non-goals:** No long-form articles.
- **Dependencies:** IA-01 merged.
- **Acceptance criteria:** Pilot guide live, linked from the tool, linking out
  to verified primary references for depth.
- **Required tests:** navigation + content presence checks.
- **PR/commit:** PR #23 · branch `arena/01a003bd-cyberbuddy` (see the PR for
  the final commit).
- **Notes:** Delivered `guides/index.html` (hub) + `guides/clickjacking/`
  (pilot); header nav and footer *Learn* column now carry a single **Guides**
  entry; the 404 page offers a Guides card; the Clickjacking Validator links
  back to the guide. Routes (`/guides`, `/guides/`, `/CyberBuddy/guides/…`),
  `sitemap.xml`, `llms.txt` and README updated. "Go deeper" cites verified
  primary sources (OWASP WSTG-CLNT-09, CWE-1021, the OWASP Clickjacking
  Defense Cheat Sheet, MDN, CSP L3, PortSwigger) — **not** the Medium profile,
  which has no clickjacking post; guide prose is first person throughout. The
  Pages workflow still copies named directories only, so `cp -a guides _site/`
  is carried in `docs/pages-workflow-patch.md` for the maintainer — **without
  it the whole section 404s in production.**
  The original "exactly one pilot guide / no full library" non-goal was lifted
  mid-session by the maintainer; GUIDES-02 and GUIDES-03 were pulled into the
  same PR (see below).

### GUIDES-02 — Concise Security Headers and CSP guides
- **Status:** `DONE`
- **Goal:** Two concise guides for the Headers and CSP tools, same format as
  the pilot.
- **Scope:** Headers guide + CSP guide, each linking to its tool and to
  verified primary references (a blog link only if a post on that topic exists).
- **Non-goals:** No full articles.
- **Dependencies:** GUIDES-01.
- **Acceptance criteria:** Both guides live and linked.
- **Required tests:** content presence.
- **PR/commit:** PR #23 · branch `arena/01a003bd-cyberbuddy` (folded into the
  GUIDES-01 PR at the maintainer's request — all five tools needed a guide
  before merge).
- **Notes:** `guides/headers/` cites the OWASP HTTP Headers Cheat Sheet,
  WSTG-CONF-07, CWE-693 (as thematic context only — the CWE is a Pillar and
  its mapping is DISCOURAGED upstream) and MDN for HSTS/Referrer-Policy/
  Set-Cookie. `guides/csp/` cites WSTG-CONF-12, the OWASP CSP Cheat Sheet,
  CWE-79, MDN and CSP Level 3.

### GUIDES-03 — Concise CORS and CSRF guides
- **Status:** `DONE`
- **Goal:** Two concise guides for the CORS and CSRF tools.
- **Scope:** CORS guide + CSRF guide.
- **Non-goals:** No full articles.
- **Dependencies:** GUIDES-01.
- **Acceptance criteria:** Both guides live and linked.
- **Required tests:** content presence.
- **PR/commit:** PR #23 · branch `arena/01a003bd-cyberbuddy` (folded into the
  GUIDES-01 PR).
- **Notes:** `guides/cors/` cites WSTG-CLNT-07, CWE-942, PortSwigger and MDN
  (CORS guide + `Access-Control-Allow-Origin`). `guides/csrf/` cites
  WSTG-SESS-05, the OWASP CSRF Prevention Cheat Sheet, CWE-352, PortSwigger
  and MDN `Set-Cookie`. Both stay under the 1200-word ceiling `GuidesTests`
  enforces.

### DOCS-01 — In-site documentation page
- **Status:** `DONE`
- **Goal:** Replace the footer's off-site "Documentation" → GitHub `#readme`
  link with a real page in the site shell.
- **Scope:** `documentation/index.html` (quick start, which engine answers, the
  four Python CLIs, evidence/export, hosted-build limits, what leaves the
  browser, then a hand-off to GitHub for contributor material) · footer link
  retarget · `server.py` route pair · `sitemap.xml` / `llms.txt` / `README.md`.
- **Non-goals:** No header nav entry (the four-item budget IA-01 settled on
  stands — this is footer-only). No third copy of the scoring rules or the
  privacy text: the page links to `/methodology/#hosted-scans` and
  `/methodology/#privacy` instead.
- **Dependencies:** IA-01 (footer structure), GUIDES-01 (page-shell template).
- **Acceptance criteria:** `/documentation/`, `/documentation` and
  `/CyberBuddy/documentation/` all resolve; the footer link no longer leaves
  the site; no scoring text duplicated.
- **Required tests:** `DocumentationPageTests` (18) — shell, canonical/OG/
  Twitter, `../` asset paths, external-link hygiene, footer link internal +
  README hop gone, operator-content presence, first person, methodology
  deferral, hosted-limit honesty, header nav unchanged, sitemap/`llms.txt`/
  `README.md`/`server.py` wiring, and the carried workflow copy line.
- **PR/commit:** PR #23 · branch `arena/01a003bd-cyberbuddy` (folded into the
  Guides PR at the maintainer's request — the docs page had to ship before
  merge, not as a follow-up).
- **Notes:** The directory is `documentation/`, **not** `docs/`: the Pages
  leak guard fails the build when `_site/docs` exists, so a `docs/` page would
  never publish. Needs the same kind of unpushable workflow line as `guides/`
  (see `docs/pages-workflow-patch.md`).

### ABOUT-01 — Dedicated About page
- **Status:** `TODO`
- **Goal:** A dedicated About page covering product purpose, scope, privacy,
  architecture, responsible use, maintainer and a roadmap summary.
- **Scope:** One About page + nav/footer wiring.
- **Non-goals:** No marketing rewrite; no redesign.
- **Dependencies:** IA-01 (uses the same scalable nav).
- **Acceptance criteria:** About page live, linked from nav/footer, roadmap
  summary accurate.
- **Required tests:** navigation + content.
- **PR/commit:** —

### DX-01 — Contributor/agent documentation
- **Status:** `TODO`
- **Goal:** First-class contributor and agent docs.
- **Scope:** `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/ADDING-A-TOOL.md`,
  `docs/TESTING.md`, `docs/RELEASE-CHECKLIST.md`.
- **Non-goals:** No tooling rewrite.
- **Dependencies:** IA-01 (documents the registry it introduced).
- **Acceptance criteria:** Each file exists and is accurate.
- **Required tests:** link/consistency checks.
- **PR/commit:** —

### DX-02 — One verification entry point (`tools/verify.py`)
- **Status:** `TODO`
- **Goal:** A single command for Python, JS syntax, JSON/XML, routes and
  Pages assembly checks.
- **Scope:** `tools/verify.py`; real-browser mode may remain optional.
- **Non-goals:** No dependency introduction.
- **Dependencies:** DX-01.
- **Acceptance criteria:** `python3 tools/verify.py` runs the whole gate.
- **Required tests:** the entry point itself.
- **PR/commit:** —

### REFACTOR-01 — Extract pure URL-validation helpers
- **Status:** `TODO`
- **Goal:** Incrementally extract pure URL-validation helpers from the large
  shared `js/app.js` without changing behavior.
- **Scope:** Small, behavior-preserving extraction only.
- **Non-goals:** No broad `app.js` refactor; no behavior change.
- **Dependencies:** IA-01 (registry separation first).
- **Acceptance criteria:** All parity/UX tests stay green.
- **Required tests:** existing URL-validation contracts.
- **PR/commit:** —

### REFACTOR-02 — Extract evidence/export helpers
- **Status:** `TODO`
- **Goal:** Incrementally extract evidence/export helpers out of `js/app.js`.
- **Scope:** Behavior-preserving extraction.
- **Non-goals:** No behavior change.
- **Dependencies:** REFACTOR-01.
- **Acceptance criteria:** Export/evidence tests stay green.
- **Required tests:** evidence-card + export contracts.
- **PR/commit:** —

### REFACTOR-03 — Review grader/module boundaries
- **Status:** `TODO`
- **Goal:** Review grader/module boundaries while preserving all parity
  contracts.
- **Scope:** Boundary review only.
- **Non-goals:** No scoring change.
- **Dependencies:** REFACTOR-01, REFACTOR-02.
- **Acceptance criteria:** Parity fixtures unchanged and green.
- **Required tests:** grader parity suites.
- **PR/commit:** —

### QA-01 — Deterministic local security fixtures/laboratory
- **Status:** `TODO`
- **Goal:** Deterministic local fixtures (victim + attacker origins) for CSRF
  and the existing browser tests.
- **Scope:** Local laboratory harness.
- **Non-goals:** No new scanner.
- **Dependencies:** REFACTOR work (cleaner seams to fixture).
- **Acceptance criteria:** Offline, repeatable browser runs.
- **Required tests:** the fixtures themselves.
- **PR/commit:** —

### RELEASE-01 — Full release audit and v1.0.0 preparation
- **Status:** `TODO`
- **Goal:** Full release audit and v1.0.0 preparation.
- **Scope:** Docs, versioning, changelog, verification pass.
- **Non-goals:** New features.
- **Dependencies:** DX-02, QA-01.
- **Acceptance criteria:** v1.0.0 tagged and documented.
- **Required tests:** full suite + browser suites + Pages guard.
- **PR/commit:** —

### JWT-00 — JWT Security Workbench development preview
- **Status:** `DONE`
- **Goal:** Publish the product structure for a future JWT tool as a
  non-operational roadmap preview, integrated across the whole site, without
  implementing any token processing.
- **Scope:** `tools/jwt/index.html` (five informational preview tabs —
  Analyze, Verify, Edit & Generate, Test Variants, Secret Test),
  `js/tool.jwt.js` (accessible keyboard tab navigation only), `guides/jwt/`,
  registry entry (`status: "preview"`, `category: "local"`), hub/catalog/404
  static cards, server aliases (`/jwt`), `sitemap.xml` (guide only; the tool
  page is `noindex` and absent), `llms.txt`, README, Pages workflow copy line
  + `docs/pages-workflow-patch.md`, and browser page arrays.
- **Non-goals:** No decoding, verification, signing, generation, or secret
  testing; no `fetch`, storage, history/query state, relay gate, share link,
  LIVE/CACHED tag, numeric score, or fake result/verdict; no PWA shortcut
  (added only when JWT-01 ships); no canonical URL on the noindex page.
- **Dependencies:** GUIDES-01/02/03 + DOCS-01 (merged).
- **Acceptance criteria:** The page is visibly labelled **BETA ROADMAP
  PREVIEW · NOT OPERATIONAL** without interaction; every non-tab control is
  disabled; the controller makes no network/storage/history call and contains
  no crypto/parsing; the page is `noindex` and absent from the sitemap while
  the guide is indexed; the JWT entry is labelled "Preview" (not "live") in
  the menu, hub and catalog and is excluded from the Run suite.
- **Required tests:** `JwtPreviewTests` (26 stdlib tests, each mutation-checked
  against the pre-feature tree); route/alias/CSP/cache-buster coverage
  extended; `layout`/`dropdown`/`responsive` browser arrays include the
  preview and guide.
- **PR/commit:** branch `arena/…-cyberbuddy` · PR #24 (open).
- **Accuracy rules (carry into JWT-01/02/03):**
  - HS256 is not automatically weak — a strong shared secret is fine.
  - A missing `exp`/`iss`/`aud` is a *contextual* observation, never an
    automatic verdict or score.
  - Decoding is not verification.
  - Verification with a supplied key proves only a key match, not that the
    key is trusted by the target.
  - A generated/modified variant never proves server acceptance.
  - `kid`/`jku`/`x5u`/embedded `jwk`/algorithm confusion are *surfaces*,
    not exploited findings, until the target accepts the variant.
  - The hosted tool never sends a JWT to a target, a JWKS URL, or a third
    party, and never persists a token, wordlist or discovered secret.
- **Notes/traps:** `test_guides_stay_short` counts the JSON-LD block toward
  the 1200-word ceiling — keep the guide prose tight. The
  `_strip_js_comments` helper in `JwtPreviewTests` exists so a comment that
  *says* the controller does not call `fetch()` cannot trip a "must not
  contain fetch" assertion. The arena token may still lack the `workflows`
  permission; the `tools/jwt` workflow copy line is also recorded in
  `docs/pages-workflow-patch.md`. In `tests/browser/responsive.js` the JWT
  entries stay appended at the end — `TOOLS = PAGES.slice(1, 5)` must remain
  the four scan tools.

### JWT-01 — Decode, inspect and verify
- **Status:** `DONE`
- **Goal:** Decode a compact JWS into its three parts, display header/payload/
  signature and a claim timeline, and verify the signature with a key the
  analyst supplies — entirely in the browser via the Web Crypto API.
- **Scope:** Strict compact-JWS parsing (honest errors for malformed input and
  JWE); header/payload/signature sections; `iat`/`nbf`/`exp` timeline with
  clock-skew; expected `iss`/`aud`/`sub` validation; HMAC (`HS256/384/512`),
  RSA (`RS256/384/512`, `PS256/384/512`) and ECDSA (`ES256/384`) verification
  through `crypto.subtle`; PEM, JWK and pasted JWKS key inputs; three
  distinct UI states (Decoded / Signature verified / Claims validated).
- **Non-goals:** No editing or signing (JWT-02); no test variants or secret
  testing (JWT-03); no network fetch of a JWKS URL (keys are pasted); no
  token persistence or query/share state; no numeric score.
- **Dependencies:** JWT-00.
- **Acceptance criteria:** A token verifies only against a supplied key;
  failures are specific (bad signature, unsupported alg, expired, wrong
  audience); nothing leaves the browser; the page drops `noindex`, gains a
  canonical URL, a PWA shortcut and a sitemap entry only once functional.
- **Required tests:** pure decoder/verifier under Node (DOM-free), stdlib
  content/route tests, real-browser verification matrix.
- **PR/commit:** —
- **Notes:** Web Crypto support varies by algorithm; feature-detect and
  report "unsupported in this browser" honestly. A pasted JWKS must select
  by `kid` and pin the algorithm — never trust the token's `alg` header to
  choose the verifier (the algorithm-confusion trap).

### JWT-02 — Edit and generate
- **Status:** `IN REVIEW`
- **Goal:** Modify header/payload claims and re-sign locally to build
  authorized test tokens.
- **Scope:** Header/payload editors; standard-claim helpers (`iss`, `sub`,
  `aud`, `exp`, `nbf`, `iat`, `jti`); HMAC and private-key signing via Web
  Crypto; local RSA test-key generation; original-vs-modified semantic diff;
  explicit **TEST TOKEN** labels; safe copy/download with no accidental key
  export.
- **Non-goals:** No target requests; no key/secret persistence; no algorithm
  that the browser cannot perform.
- **Dependencies:** JWT-01.
- **Acceptance criteria:** A generated token verifies with the matching key;
  modified claims are shown in a diff before signing; every artifact is
  labelled a test token.
- **Required tests:** pure signer under Node; copy/download and labelling
  tests; real-browser round-trip.
- **PR/commit:** PR #25 · branch `arena/01a004aa-cyberbuddy` · commit
  `27650ff` (open — not merged; do not mark DONE).

### JWT-03 — Test variants and bounded secret testing
- **Status:** `IN REVIEW`
- **Goal:** Build authorized-test variants (`alg:none`, claim manipulation,
  algorithm confusion with an analyst-supplied public key, embedded JWK,
  JKU/X5U and `kid` mutation templates) and bounded HMAC secret testing for
  HS256/384/512 only.
- **Scope:** Variant templates (the tool never sends them); a Web Worker for
  secret testing with progress/cancel and explicit browser resource limits;
  a small built-in candidate list plus an uploaded custom wordlist (read in
  the Worker, never persisted).
- **Non-goals:** No RSA/EC cracking; no target/JWKS fetch; no large bundled
  wordlist; no persistence of the token, wordlist or discovered secret; no
  claim of server acceptance.
- **Dependencies:** JWT-02.
- **Acceptance criteria:** Every variant is labelled a test template, not a
  finding; secret testing is cancellable and bounded; nothing is stored or
  transmitted.
- **Required tests:** variant builder under Node; Worker bounds/cancel;
  real-browser variant + secret-test flow.
- **PR/commit:** PR #25 · branch `arena/01a004aa-cyberbuddy` (folded into
  the JWT-02 PR at the maintainer's request to merge once — see REVIEW
  §28). Not merged; do not mark DONE.

### FUTURE-01 — External payload-corpus integration
- **Status:** `DEFERRED`
- **Goal:** (Mention only) A separately maintained payload corpus may be
  linked later.
- **Scope:** Not designed or implemented now.
- **Non-goals:** No design/implementation in this or the near-term sessions.
- **Dependencies:** —
- **Acceptance criteria:** — (deferred)
- **Required tests:** — (deferred)
- **PR/commit:** —

---

## 5. Current handoff

- **Last verified `origin/main`:** `e2a9a86` — PR #24 (JWT-00 preview +
  JWT-01 decode/inspect/verify) merged as `b8a9fdc` (verified 2026-08-15).
  This session started from `origin/main` with a clean tree.
- **Work in review:** **JWT-02 (edit & generate) + JWT-03 (test variants
  and bounded secret testing)** — branch `arena/01a004aa-cyberbuddy`,
  **PR #25** (open, not merged). JWT-03 was folded into the JWT-02 PR at
  the maintainer's request to merge once.
- **Delivered (JWT-02, REVIEW §27):** functional Edit & Generate —
  header/payload editors, standard-claim helpers, semantic diff,
  HMAC/private-key signing, local RSA test-key generation, TEST TOKEN
  labels, token-only copy/download with confirmed private-key export.
- **Delivered (JWT-03, REVIEW §28):**
  - **Test Variants (functional):** `buildVariant` in the engine —
    `alg:none`, claim tamper (original signature kept) and claim re-sign,
    algorithm confusion (HS256 with the pasted public key as the HMAC
    secret), embedded JWK, `jku`/`x5u`, path/SQL-style `kid` templates.
    Every output is labelled **TEST TEMPLATE**, never a finding; re-signed
    variants go through `signToken` so all JWT-02 guards apply; `alg:none`
    stays rejected by parse/sign and exists only as a template.
  - **Secret Test (functional):** `js/jwt.worker.js` runs the bounded
    HS256/384/512 search off the main thread — `searchHmacSecret` in the
    engine, progress every 250 candidates, cancel, explicit caps
    (100,000 candidates, 120 s) checked between candidates, the uploaded
    wordlist read inside the worker with `FileReaderSync`, a 32-key
    built-in starter list. A match is a discovered secret for authorized
    testing, never a verdict.
  - **PWA shortcut added** (`manifest.webmanifest`) now that the workbench
    is complete (deferred through JWT-01/02); manifest description and
    README/`llms.txt`/guide updated (guide at 1185 of 1200 visible words).
- **Last completed checks:** **274/274** stdlib tests OK
  (`python3 -m unittest test_engines.py`) — 16 new/repurposed
  `JwtWorkbenchTests` covering the Node-driven variant builder (including
  the confusion signature verified against an independent HMAC while the
  verify guard holds), `searchHmacSecret` (found/not-found/progress/stop),
  and the worker message contract under a Node Worker-shim (found +
  cancel with tested < total) · `node --check` clean on all 21 JS files
  (incl. `js/jwt.worker.js`) · `py_compile` clean · JSON (manifest) + XML
  valid · local Pages-assembly dry run green · live `server.py` JWT route
  crawl (covered by the stdlib route tests) · Node DOM-shim smoke tests of
  the full controller (JWT-01/02/03 flows, including the real worker file
  driven through a fake `Worker`, the cache-bustered worker URL, the
  cancel path and the HS-only guard on an RS256 base).
- **Real-browser suites:** not executed (no Chromium in the sandbox). The
  `/tools/jwt/` page now has all four panels functional; run
  `layout`/`dropdown`/`responsive` by hand before merge.
- **Next approved roadmap ID:** none set — the JWT series is complete.
  ABOUT-01 and DX-01 remain `TODO` for the maintainer to approve; the §6
  protocol's "exactly one NEXT" is intentionally not applied until then.
  FUTURE-01 stays `DEFERRED`.
- **Files/traps the next session must read:** `REVIEW.md` §27/§28 ·
  `docs/DEV-NOTES.md` ("JWT-02 traps" + "JWT-03 traps") · `js/jwt.engine.js`
  + `js/tool.jwt.js` + `js/jwt.worker.js` (the engine contract the new
  tests pin) · `docs/pages-workflow-patch.md` (no new entries needed —
  `tools/jwt` is already on the workflow copy line and `js/*.js` is
  copied whole, so the worker needs no line).
- **Known blockers:** none in code. No workflow edit was needed this
  session.

## 6. Future-session protocol

Every future coding session **must**:

1. Start from the latest `origin/main` on its Arena-assigned branch.
2. Read `docs/ROADMAP.md` and `docs/DEV-NOTES.md` first.
3. Verify whether the previous `IN REVIEW` item merged.
4. Mark it `DONE` only if present in `origin/main`.
5. Select only the item marked `NEXT`.
6. Change that item to `IN PROGRESS`.
7. Do not implement later roadmap items in the same PR.
8. Run the baseline before behavior changes.
9. Add regression tests and real-browser coverage where needed.
10. Update `docs/DEV-NOTES.md` with durable traps.
11. Update `docs/ROADMAP.md` status and handoff before finishing.
12. Mark the current item `IN REVIEW` after opening the PR and make exactly
    one following item `NEXT`.
13. Never merge the PR itself.
