# ACTION REQUIRED — publish the tools catalog & guard internal files

The GitHub App that pushes these arena branches is **not** granted the
`workflows` permission, so any commit that touches `.github/workflows/**` is
rejected by the server. Everything else ships normally. This file carries the
workflow edits that could not be pushed, for a maintainer to apply by hand
(the same mechanism used in PR #20 for the CSRF tool).

This patch is for **IA-01 — scalable tool information architecture**.

## The required edits

Two changes to `.github/workflows/pages.yml`:

### 1. Publish the tools catalog

`tools/index.html` (the catalog) must reach GitHub Pages. In the
*Assemble static site* step, add it after the per-tool directory copy:

```yaml
# before
cp -a tools/clickjacking tools/headers tools/cors tools/csp tools/csrf _site/tools/
# after
cp -a tools/clickjacking tools/headers tools/cors tools/csp tools/csrf _site/tools/
cp tools/index.html _site/tools/
```

Without this the deployed site serves the five tool pages but **not** the
catalog — the “All tools”, “Target assessments” and “Local utilities” links
would 404 on the hosted site. Local `server.py` is unaffected (it serves
everything under `tools/`).

### 2. Guard internal files out of the published site

Add a step immediately after the *Assemble static site* step (before
*Stamp asset versions*) that fails the build if a repo-internal file leaks
into `_site/`:

```yaml
      # Repo-internal files must never reach the public site. docs/ROADMAP.md
      # is the session roadmap (like docs/DEV-NOTES.md); REVIEW.md and tests/
      # are private working artifacts. Fail loudly if any leak into _site/.
      - name: Guard internal files stay out of the published site
        run: |
          set -euo pipefail
          for f in docs/ROADMAP.md docs/DEV-NOTES.md REVIEW.md; do
            if [ -e "_site/$f" ]; then
              echo "::error::Internal file leaked into _site: $f"
              exit 1
            fi
          done
          if [ -d _site/docs ] || [ -d _site/tests ]; then
            echo "::error::Internal directory leaked into _site (docs/ or tests/)"
            exit 1
          fi
          echo "Internal docs, tests and REVIEW.md stay out of the published site."
```

Until this guard is applied, the equivalent protection already runs in CI as
a stdlib test — `test_engines.PagesExclusionTests.test_workflow_never_copies_internal_paths`
— which fails if any future commit starts copying `docs/`, `tests/` or
`REVIEW.md` into `_site/`.

## Why this can't be committed here

`git push` of a branch that modifies `.github/workflows/pages.yml` is refused:

```
! [remote rejected] … -> arena/… (refusing to allow a GitHub App to create
  or update workflow `.github/workflows/pages.yml` without `workflows`
  permission)
```

`gh` authenticates as the same bot, so there is no alternative push path from
this environment.

## Reference — the full workflow with both edits applied

Diff `.github/workflows/pages.yml` against this to confirm the two edits
above. Everything else is unchanged from `main`.

```yaml
# Publish the static hub + tool pages to GitHub Pages.
# One-time: repo Settings → Pages → Source = GitHub Actions.
name: GitHub Pages

on:
  push:
    branches: [main]
  workflow_dispatch:
  schedule:
    - cron: "17 */6 * * *"   # refresh the hosted scan cache every 6 hours (UTC)

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Guard the deploy: the published site runs the same graders as the CLI,
      # so a scoring regression must never reach Pages.
      - name: Run engine tests
        run: python3 -m unittest test_engines.py

      # Pre-scan the URLs in urls.txt with the real Python engines
      # (uses tools/build_cache.py -> cache/<host>.json)
      - name: Build scan cache
        run: python3 tools/build_cache.py

      - name: Assemble static site
        run: |
          set -euo pipefail
          mkdir -p _site/css _site/js _site/tools
          cp index.html _site/
          touch _site/.nojekyll
          test -f 404.html && cp 404.html _site/ || true
          # Copy ALL css/js, not named files. The pages load app.js plus
          # boot.js, theme-boot.js, hub.js and a per-tool controller; naming
          # them individually here is how the build silently drifts out of
          # sync with the site and ships pages with no JavaScript.
          cp css/*.css _site/css/
          cp js/*.js _site/js/
          # Publish every live tool, including the CSP Policy Auditor and the
          # CSRF PoC Generator, plus the tools catalog that indexes them all.
          cp -a tools/clickjacking tools/headers tools/cors tools/csp tools/csrf _site/tools/
          cp tools/index.html _site/tools/
          # Full methodology page (the hub links to the #methodology anchor,
          # but the standalone page has its own canonical URL).
          test -d methodology && cp -a methodology _site/ || true
          # Cached reports for configured targets (skipped if the build step
          # found no targets / network failed).
          test -d cache && cp -a cache _site/ || true
          # Metadata assets: social card, app icons, manifest, robots, sitemap,
          # humans.txt and llms.txt.
          for f in og-cyberbuddy.png icon-192.png icon-512.png manifest.webmanifest robots.txt sitemap.xml humans.txt llms.txt; do
            test -f "$f" && cp "$f" _site/ || true
          done
          # Licence, so the published site carries its own terms.
          test -f LICENSE && cp LICENSE _site/ || true
          # Responsible disclosure contact.
          test -d .well-known && cp -a .well-known _site/ || true

      # Repo-internal files must never reach the public site. docs/ROADMAP.md
      # is the session roadmap (like docs/DEV-NOTES.md); REVIEW.md and tests/
      # are private working artifacts. Fail loudly if any leak into _site/.
      - name: Guard internal files stay out of the published site
        run: |
          set -euo pipefail
          for f in docs/ROADMAP.md docs/DEV-NOTES.md REVIEW.md; do
            if [ -e "_site/$f" ]; then
              echo "::error::Internal file leaked into _site: $f"
              exit 1
            fi
          done
          if [ -d _site/docs ] || [ -d _site/tests ]; then
            echo "::error::Internal directory leaked into _site (docs/ or tests/)"
            exit 1
          fi
          echo "Internal docs, tests and REVIEW.md stay out of the published site."

      # Cache-busting: stamp every ?v=... asset query with the commit SHA so a
      # deploy can never serve stale css/js to returning visitors. Replaces
      # the hand-maintained ?v=YYYYMMDD strings.
      - name: Stamp asset versions
        run: |
          set -euo pipefail
          REV="${GITHUB_SHA::12}"
          find _site -name '*.html' -print0 |
            xargs -0 sed -i -E "s/\?v=[A-Za-z0-9._-]+/?v=${REV}/g"
          echo "Stamped assets with ?v=${REV}"

      # Fail the build if a page references a local css/js/png that was not
      # copied above. This is the check that would have caught tool pages
      # shipping without their controllers.
      - name: Verify referenced assets exist
        run: |
          set -euo pipefail
          bad=$(
            find _site -name '*.html' | while IFS= read -r page; do
              dir=$(dirname "$page")
              # Local href=/src= targets only: skip absolute URLs, data:
              # resources, and #anchors.
              grep -oE '(href|src)="[^"#][^"]*\.(css|js|png|webmanifest)(\?[^"]*)?"' "$page" |
                sed -E 's/^(href|src)="//; s/"$//; s/\?.*$//' |
                while IFS= read -r ref; do
                  case "$ref" in
                    http*|//*|data:*) continue ;;
                  esac
                  [ -f "$dir/$ref" ] || echo "  $page -> $ref"
                done
            done
          )

          if [ -n "$bad" ]; then
            echo "::error::Referenced assets are missing from _site:"
            echo "$bad"
            exit 1
          fi

          echo "All referenced local assets are present."

      - uses: actions/configure-pages@v5

      - uses: actions/upload-pages-artifact@v3
        with:
          path: _site

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - id: deployment
        uses: actions/deploy-pages@v4
```
