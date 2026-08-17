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

> Post-snapshot update (2026-08-16, branch `arena/01a00910-cyberbuddy`,
> not yet merged into `origin/main`): the JWT Security Workbench gained
> prioritized **VAPT Testing Suggestions & Test Payloads** — severity-tagged
> cards derived from the decoded token, one-click TEST PAYLOADs with
> copy-as-Burp-Authorization-header and Burp verification steps, and tab
> prefill hand-offs — plus anchor-precision (`scroll-padding-top`) and
> scroll-to-results fixes across the hub suite and all four assess tools.
> Python tests now **322** (`python3 -m unittest test_engines.py`).

| Item | Value |
| --- | --- |
| Latest merged feature/PR | **JWT-00 preview + JWT-01 decode/inspect/verify** (PR #24, merge commit `b8a9fdc`) — the JWT Security Workbench is live on GitHub Pages. Verified present in `origin/main` (`e2a9a86`, which also applies the `tools/jwt` workflow copy line) before this session; not re-applied. |
| Live tools | 7 live — Clickjacking Validator, Security Headers, CORS Validator, CSP Policy Auditor, CSRF PoC Generator, **JWT Security Workbench (feature-complete: decode/inspect/verify + edit/generate/sign + test variants + bounded secret testing)**, **DNS & Domain Security Analyzer (public-DNS posture: SPF/DMARC/DKIM/DNSSEC/CAA)** |
| Public sections | Hub · Tools catalog (`/tools/`) · Methodology · Guides (`/guides/`, one per tool — 7) · Documentation (`/documentation/`) |
| Python test total | **249** after JWT-00; **245** after JWT-01 (preview tests replaced by functional engine tests); **258** after JWT-02; **274** after JWT-03 (16 variant/secret/worker tests) |
| JavaScript file total | **21** (14 under `js/` incl. `js/jwt.engine.js` + `js/tool.jwt.js` + `js/tool.dns.js`, 7 under `tests/browser/`) — all pass `node --check` |
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

### DNS-01 — DNS & Domain Security Analyzer
- **Status:** `IN REVIEW`
- **Goal:** A seventh live tool that grades a domain's *public DNS* security
  posture — SPF, DMARC, DKIM, DNSSEC, CAA and name-server redundancy — into a
  0–100 score + A–F grade with the raw record behind every finding.
- **Scope:** `dns_security.py` (stdlib DNS wire-format client over UDP with a
  TCP fallback, plus the pure scorer `grade_dns_from_records`); a browser port
  (`gradeDnsFromRecords` + DNS-over-HTTPS collection via `dns.google` in
  `js/app.js`); the `/api/dns?domain=` endpoint in `server.py` and the
  `api/dns.py` Vercel function; `tools/dns/index.html` + `js/tool.dns.js`; a
  DNS guide; registry entry (`category: "assess"`, `suite: false` — standalone,
  not in the hub Run suite); per-tool suite badges in the catalog; and the full
  cross-surface set (hub/catalog/404/guides cards, sitemap, manifest, llms.txt,
  README, methodology, documentation, browser PAGES arrays).
- **Non-goals:** No connection to the target's own servers (resolver only); no
  DNS record *modification* or zone transfer; no subdomain enumeration; no
  joining the hub "Run suite" (that stays the four HTTP tools); no cached
  DNS layer in CI; no third-party relays beyond the consent-gated
  DNS-over-HTTPS fallback.
- **Dependencies:** IA-01 (registry), GUIDES-01/02/03 + DOCS-01 (shell +
  guide template), JWT-03 (the established "new tool" surface).
- **Acceptance criteria:** Python and JS graders agree on a fixed records map;
  an NXDOMAIN domain is reported as unknown, never graded; a no-email domain
  keeps its SPF/DMARC/DKIM checks informational; DKIM misses are phrased as
  hints, never proof of absence; the hosted path is gated behind a
  DNS-specific consent prompt and labelled unverified; every existing stdlib
  and asset/link test stays green.
- **Required tests:** `DnsEngineTests` (pure scorer + input validation),
  `DnsParityTests` (Node JS-vs-Python parity), `DnsSiteTests` (registry,
  engine/gate, exports, sitemap/manifest/llms/route, workflow-patch copy line),
  plus `dns`/`guide-dns` added to the `layout`/`dropdown`/`responsive` browser
  PAGES arrays.
- **PR/commit:** PR #32 · branch `arena/01a00c48-cyberbuddy` · commit
  `c898eb8` (open — not merged; do not mark DONE).
- **Notes/traps:** The arena push token cannot edit `.github/workflows/**`, so
  the `tools/dns` copy line lives in `docs/pages-workflow-patch.md`. DKIM
  probing checks common selectors only. DNSSEC verdict keys on the DS record at
  the parent zone. The tool is `suite: false` — `TOOLS = PAGES.slice(1, 5)` in
  `tests/browser/responsive.js` must stay the four URL scan tools. The DNS
  consent gate is separate from the header relay gate (a domain is all that is
  ever disclosed).

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

> **This session (DNS-01, branch `arena/01a00c48-cyberbuddy`):** the
> **DNS & Domain Security Analyzer** is implemented end-to-end — `dns_security.py`
> (stdlib DNS wire client + pure `grade_dns_from_records`), `/api/dns` in
> `server.py` + `api/dns.py`, `tools/dns/index.html` + `js/tool.dns.js`, the
> `gradeDnsFromRecords` browser port with a consent-gated DNS-over-HTTPS
> fallback, a `guides/dns/` guide, and the full cross-surface set. The tool is
> `category: "assess"` with `suite: false` — it never joins the hub Run suite,
> which stays the four HTTP tools. Registry/category copy was generalized so
> assess membership can be mixed (per-tool suite badges in the catalog). Python
> tests now **355** (`python3 -m unittest test_engines.py`), all green. Open as
> **PR #32**; not merged, do not mark DONE.

- **Last verified `origin/main`:** `e10eb2e` — PR #28 merged, which brought
  the JWT-02/JWT-03 work (previously PR #25) to `main`. The JWT-00 → JWT-03
  series is complete and shipped. This session started from a clean tree.
- **Work in review:** **DNS-01 (this session)** — `IN REVIEW`, branch
  `arena/01a00c48-cyberbuddy`, **PR #32** (open, not merged). Requires the
  maintainer-applied `tools/dns` Pages copy line
  (see `docs/pages-workflow-patch.md`). **POLISH-01 (consistency sweep)** —
  `IN REVIEW`, branch `arena/01a00768-cyberbuddy`, **PR #29** (open, not
  merged).
  Not a numbered roadmap feature: a
  verification pass over the shipped suite plus the drift it exposed. No new
  tool, engine or scoring behaviour.
- **Verified correct, unchanged:** JWT integration on `methodology/`,
  `index.html` (scope, standards card, `06 live`) and `tools/index.html` ·
  CORS PASS verdict in the live UI · `postureHtml` per-name badges + CSS ·
  findings layout · footer social labels · posture strip on all four scan
  tools · clickjacking copy · `.github/workflows/pages.yml` · `sitemap.xml`
  (17 locs) · manifest JWT shortcut · first-person voice across shipped
  pages (zero third-person narrator hits).
- **Fixed this session:**
  - **Methodology is a page, not an anchor.** Header nav now links
    `/methodology/` labelled "Methodology". The same stale `/#methodology`
    target was also corrected in `llms.txt`, `manifest.webmanifest`,
    `404.html`, `js/404.js` and `.well-known/security.txt` (the last was a
    published `Policy:` URL — worth grepping for on any URL change).
  - **Anchor IDs on `methodology/index.html`:** `#tools`, `#scoring`,
    `#csp-risk`, `#clickjacking-risk`, `#jwt`, `#authorized` (joining the
    existing `#hosted-scans`/`#privacy`), so footer and cross-page deep
    links resolve. `tools/audit_site.py` validates fragments, so a deep
    link to a missing id now fails the build.
  - **Footer "Learn" column** no longer ships two rows pointing at the same
    content: Guides / Methodology / Scoring & weights (`#scoring`) / Privacy.
  - **CORS PASS reaches the exports.** New `reportRiskLabel(data)` in
    `js/app.js` is the single place that turns a raw risk into a display
    label; CORS + `low` reads `PASS`. Applied to the Markdown, standalone
    HTML, CSV and evidence-card hero paths. The JSON envelope deliberately
    still carries the raw `risk` for automation.
  - **Internal ticket IDs removed from visitor-facing surfaces.** The
    "Implementation phases" panel on `/tools/jwt/` is now "What the
    Workbench does" (capability cards); panel chips read
    "Local · Web Crypto / templates / Web Worker" instead of
    "JWT-02 · Live". Stale JWT-0x comments in `js/app.js`, `css/app.css`
    and the roadmap phrasing in `guides/jwt/index.html` were corrected too.
  - **Dead CSS deleted:** `.hub-preview-tag` and
    `.jwt-preview-panel .jwt-preview-banner` had no markup referencing them.
  - **`documentation/index.html`** gained a JWT capability table under
    `#engines` ("Tools with no engine behind them") covering decode/inspect,
    verify, edit/sign, test variants and bounded Worker secret testing. It
    sits under an existing `h2` on purpose, so the DEV-NOTES four-part
    checklist for new top-level sections does not apply.
  - **Cache-buster** bumped `?v=20260814h` → `?v=20260816a`, 59 references
    across 17 HTML files, all consistent.
- **Test-suite change:** `test_edit_panel_is_functional` and
  `test_variants_panel_is_functional` asserted the literal badge strings
  `JWT-02 &middot; Live` / `JWT-03 &middot; Live`. They now assert the
  `jwt-phase jwt-phase-live` marker class instead — the intent is "this
  panel is live, not a preview stub", which must not break when
  visitor-facing copy is reworded.
- **Last completed checks:** **291/291** stdlib tests OK
  (`python3 -m unittest test_engines.py`) · `node --check` clean ·
  manifest JSON valid · `tools/audit_site.py` green against a full local
  Pages assembly (an audit run against a missing `_site` passes vacuously —
  always assemble first) · live `server.py --host 0.0.0.0 --port 8080
  --allow-private` smoke test: `/`, `/methodology/`, `/documentation/`,
  `/tools/jwt/`, `/tools/cors/`, `/.well-known/security.txt`, `/llms.txt`,
  `/manifest.webmanifest` all 200, `/api/health` → `{"ok": true}`, empty
  stderr.
- **Real-browser suites:** not executed (no Chromium in the sandbox). The
  header nav label and the rebuilt `/tools/jwt/` capability panel are the
  two visual changes; run `layout`/`dropdown`/`responsive` by hand before
  merge.
- **Next approved roadmap ID:** none set — the JWT series is complete.
  ABOUT-01 and DX-01 remain `TODO` for the maintainer to approve; the §6
  protocol's "exactly one NEXT" is intentionally not applied until then.
  FUTURE-01 stays `DEFERRED`.
- **Files/traps the next session must read:** `docs/DEV-NOTES.md`
  ("Cross-surface URL changes" + the JWT traps) · `reportRiskLabel` in
  `js/app.js` if any tool ever needs a display label that differs from its
  raw risk.
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
