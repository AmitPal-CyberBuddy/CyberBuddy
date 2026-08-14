# ACTION REQUIRED — replace `.github/workflows/pages.yml`

I cannot commit this file: the GitHub App I push through is not granted the
`workflows` permission, so any commit touching `.github/workflows/**` is
rejected by the server. Everything else ships normally.

**This is required before the next deploy.** The workflow currently on `main`
copies only `css/app.css` and `js/app.js`. The refactor that removed inline
scripts (so the site can ship a CSP without `'unsafe-inline'`) split the page
logic across nine JS files and three CSS files. Without this change GitHub
Pages publishes tool pages with **no JavaScript** — the scan buttons do
nothing. Local `server.py` is unaffected.

## How to apply

Open `.github/workflows/pages.yml` on GitHub (or locally on `main`), select
all, and replace with the block below. It is the exact file I validated.

## What changed vs. the current version

| Change | Why |
| --- | --- |
| `cp css/*.css` / `cp js/*.js` instead of naming two files | The bug above. Wildcards also cover any file added later, so the build cannot drift out of sync with the site again. |
| New **Run engine tests** step | The published site runs the same graders as the CLI; a scoring regression must not reach Pages. |
| New **Stamp asset versions** step | Rewrites every `?v=…` to the commit SHA, so a deploy can never serve stale css/js. Replaces the hand-maintained `?v=YYYYMMDD` strings. |
| New **Verify referenced assets exist** step | Fails the build if any page references a local css/js/png that was not copied. This is the check that would have caught the missing controllers. |
| `cp LICENSE` | The published site carries its own terms. |
| `set -euo pipefail` in each script | Without it a failing `cp` is silently ignored and a broken site deploys green. |

## Verification I ran

I extracted the `run:` blocks and executed them against this repo:

- Assemble → stamp → verify: **passes**, `_site/` contains all 29 files, every
  `?v=` stamped.
- Served the built `_site/` with a plain static server (what Pages does) and
  loaded all five pages: **all JS returns 200**, no console errors.
- Simulated the *old* workflow (only `app.css`/`app.js`): the verify step
  **fails the build** and lists all 22 missing files, e.g.

```
::error::Referenced assets are missing from _site:
  _site/tools/clickjacking/index.html -> ../../js/tool.clickjacking.js
  _site/index.html -> js/boot.js
  _site/404.html -> js/404-boot.js
  ...
```

## After deploying

1. Hard-reload a tool page; check DevTools → Console for CSP violations
   (should be none) and Network for 404s on `/CyberBuddy/js/*.js`.
2. Run a scan — the button must respond and the relay-consent prompt should
   appear (there is no Python engine on Pages).
3. View source: every `?v=` should be the commit SHA, not `20260814d`.

## The file

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
          cp -a tools/clickjacking tools/headers tools/cors _site/tools/
          # Full methodology page (the hub links to the #methodology anchor,
          # but the standalone page has its own canonical URL)
          test -d methodology && cp -a methodology _site/ || true
          # Cached reports for configured targets (skipped if the build step
          # found no targets / network failed)
          test -d cache && cp -a cache _site/ || true
          # Metadata assets: social card, app icons, manifest, robots, sitemap,
          # humans.txt and llms.txt
          for f in og-cyberbuddy.png icon-192.png icon-512.png manifest.webmanifest robots.txt sitemap.xml humans.txt llms.txt; do
            test -f "$f" && cp "$f" _site/ || true
          done
          # Licence, so the published site carries its own terms
          test -f LICENSE && cp LICENSE _site/ || true
          # Responsible disclosure contact
          test -d .well-known && cp -a .well-known _site/ || true

      # Cache-busting: stamp every ?v=... asset query with the commit SHA so a
      # deploy can never serve a stale css/js to returning visitors. Replaces
      # the hand-maintained ?v=YYYYMMDD strings.
      - name: Stamp asset versions
        run: |
          set -euo pipefail
          REV="${GITHUB_SHA::12}"
          find _site -name '*.html' -print0 |
            xargs -0 sed -i -E "s/\?v=[A-Za-z0-9._-]+/?v=${REV}/g"
          echo "Stamped assets with ?v=${REV}"

      # Fail the build if a page references a local css/js/png that was not
      # copied above. This is the check that would have caught the tool pages
      # shipping without their controllers.
      - name: Verify referenced assets exist
        run: |
          set -euo pipefail
          bad=$(
            find _site -name '*.html' | while IFS= read -r page; do
              dir=$(dirname "$page")
              # Local href=/src= targets only: skip absolute URLs, data: and #anchors.
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
