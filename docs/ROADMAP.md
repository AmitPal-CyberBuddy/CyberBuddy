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

Recorded at the start of the GUIDES-01 session (2026-08-15). See §5 “Current
handoff” for the state at the end of that session.

| Item | Value |
| --- | --- |
| Latest merged feature/PR | **IA-01 — scalable tool information architecture** (PR #22, merge commit `2956801`). Verified present in `origin/main` before this session; not re-applied. |
| Live tools | 5 — Clickjacking Validator, Security Headers, CORS Validator, CSP Policy Auditor, CSRF PoC Generator |
| Public sections | Hub · Tools catalog (`/tools/`) · Methodology · **Guides (`/guides/`, new this session)** |
| Python test total | **177** at branch point, of which one failed (see §5 “Fixed en route”); **203** after GUIDES-01 |
| JavaScript file total | **18** (11 under `js/`, 7 under `tests/browser/`) — all pass `node --check` |
| Browser suites | layout 131 · dropdown 132 · overlays 48 · relay-gate 17 · responsive 224 · csrf 22 — **574 checks** (Chromium) plus IA-01's catalog checks; not runnable in the Arena sandbox |
| Pages assembly result | Hub, 404, methodology, catalog and five tool pages resolve; `docs/`, `tests/` and `REVIEW.md` absent from `_site/`. **`guides/` is not copied yet** — see the maintainer follow-up in §5. |
| Release/version state | **Pre-1.0** — no tagged release; `main` carries the live site via GitHub Pages |

Tool categories in force (from IA-01): **Assess targets** (Clickjacking,
Headers, CORS, CSP — the four that join the hub “Run suite”) and **Local
utilities** (CSRF PoC Generator — a generator, never a scanner).

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
- **Status:** `IN REVIEW`
- **Goal:** A Guides section with exactly one concise pilot guide
  (Clickjacking), connected to the Clickjacking Validator.
- **Scope:** Guides foundation + one pilot guide. Guides are **concise and
  connected to CyberBuddy tools**, not full articles — depth is delegated to
  primary references (OWASP, CWE, MDN, specs).
- **Non-goals:** No full Guides library; no long-form articles.
- **Dependencies:** IA-01 merged.
- **Acceptance criteria:** One pilot guide, linked from the tool, linking out
  to verified primary references for depth.
- **Required tests:** navigation + content presence checks.
- **PR/commit:** PR #23 · branch `arena/01a003bd-cyberbuddy` (see the PR for
  the final commit).
- **Notes:** Delivered `guides/index.html` (hub) + `guides/clickjacking/`
  (pilot); header nav and footer *Learn* column now carry a single **Guides**
  entry; the 404 page offers a Guides card; the Clickjacking Validator links
  back to the guide. Routes (`/guides`, `/guides/`, `/CyberBuddy/guides/…`),
  `sitemap.xml`, `llms.txt` and README updated. “Go deeper” cites verified
  primary sources (OWASP WSTG-CLNT-09, CWE-1021, the OWASP Clickjacking
  Defense Cheat Sheet, MDN, CSP L3, PortSwigger) — **not** the Medium profile,
  which has no clickjacking post; guide prose is first person throughout. New
  stdlib `GuidesTests` (23 checks) covers navigation + content presence, pins
  each reference URL, and guards the voice; the pilot's brevity is asserted,
  not assumed. The Pages workflow still copies named
  directories only, so `cp -a guides _site/` is carried in
  `docs/pages-workflow-patch.md` for the maintainer — **without it the whole
  section 404s in production.**

### GUIDES-02 — Concise Security Headers and CSP guides
- **Status:** `NEXT`
- **Goal:** Two concise guides for the Headers and CSP tools, same format as
  the pilot.
- **Scope:** Headers guide + CSP guide, each linking to its tool and to
  verified primary references (a blog link only if a post on that topic exists).
- **Non-goals:** No full articles.
- **Dependencies:** GUIDES-01.
- **Acceptance criteria:** Both guides live and linked.
- **Required tests:** content presence.
- **PR/commit:** —
- **Notes:** Copy the pilot's shape exactly (attack in one paragraph → the
  controls → confirm with the tool → the fix → go deeper) and extend
  `GuidesTests`; do not let a guide grow into an article.

### GUIDES-03 — Concise CORS and CSRF guides
- **Status:** `TODO`
- **Goal:** Two concise guides for the CORS and CSRF tools.
- **Scope:** CORS guide + CSRF guide.
- **Non-goals:** No full articles.
- **Dependencies:** GUIDES-01.
- **Acceptance criteria:** Both guides live and linked.
- **Required tests:** content presence.
- **PR/commit:** —

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

### TOOL-06 — JWT Security Inspector
- **Status:** `DEFERRED`
- **Goal:** Design and implement a JWT Security Inspector.
- **Scope:** New tool.
- **Non-goals:** Starting before the architecture/release work above.
- **Dependencies:** RELEASE-01 (architecture + release first).
- **Acceptance criteria:** — (deferred)
- **Required tests:** — (deferred)
- **PR/commit:** —
- **Notes:** Deferred until the architecture and release work above is
  complete.

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

> Replace this whole section at the end of every session.

- **Last verified `origin/main`:** `17e66e2` (IA-01 merged as `2956801`,
  PR #22).
- **Work currently in review:** GUIDES-01 — branch `arena/01a003bd-cyberbuddy`,
  **PR #23**. Not merged.
- **Last completed checks:** **203/203** stdlib tests
  (`python3 -m unittest test_engines.py`, +26 this session: `GuidesTests` ×23,
  two new `PagesExclusionTests`, one new route test) · `node --check` clean on
  all 18 JS files · live `server.py` route + link crawl over `/guides/`,
  `/guides/clickjacking/`, `/tools/clickjacking/` and the hub (every local
  `href`/`src` resolves 200; `/guides` and `/guides/clickjacking` 301 to their
  slash forms; both `/CyberBuddy/guides/…` mounts 200) · XML/JSON checks.
- **Fixed en route:** the pre-existing failure at branch point
  (`PagesExclusionTests.test_workflow_never_copies_internal_paths` token-scanned
  the whole workflow and tripped over the maintainer's leak-guard step). It now
  scans only the *Assemble static site* step body, and a second test asserts the
  guard step still names the internal paths. The baseline is green again.
- **Maintainer follow-up (required before GUIDES-01 is visible in production):**
  `docs/pages-workflow-patch.md` now asks for one line —
  `test -d guides && cp -a guides _site/ || true` — after the methodology copy
  in *Assemble static site*. The arena token still lacks the `workflows`
  permission. Without it the header/footer Guides links, the 404 card, the tool
  backlink and two `sitemap.xml` URLs all 404 on Pages.
- **Real-browser suites:** `/guides/` and `/guides/clickjacking/` were added to
  the `layout`, `dropdown` and `responsive` PAGES arrays, but the suites were
  **not executed** — this sandbox has no Chromium binary and the browser CDN,
  Debian mirrors and Chrome-for-Testing endpoints are all unreachable. Run them
  by hand (`python3 server.py --port 8080 --allow-private`, then
  `CB_CHROME=… node tests/browser/<suite>.js`) before merging.
- **Next approved roadmap ID:** `GUIDES-02`.
- **Files/traps the next session must read:** `REVIEW.md` §23 (GUIDES-01) ·
  `docs/DEV-NOTES.md` (“GUIDES-01 traps”) · `docs/ROADMAP.md` ·
  `guides/clickjacking/index.html` (the shape GUIDES-02/03 must copy) ·
  `docs/pages-workflow-patch.md` (unapplied).
- **Known blockers:** none in code. One external dependency: the workflow line
  above must be applied by a maintainer.

---

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
