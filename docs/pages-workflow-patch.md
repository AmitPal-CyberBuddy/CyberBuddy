# ACTION REQUIRED — publish the `guides/` and `documentation/` sections

The GitHub App that pushes these arena branches is **not** granted the
`workflows` permission, so any commit that touches `.github/workflows/**` is
rejected by the server. Everything else ships normally. This file carries the
workflow edit that could not be pushed, for a maintainer to apply by hand
(the same mechanism used in PR #20 for the CSRF tool and PR #22 for IA-01).

This patch originally covered **GUIDES-01/02/03 — the public Guides section,
one guide per tool** — plus the **`/documentation/` page**. It now also
carries the **JWT-00** addition: the `tools/jwt` preview directory must be
copied into `_site/tools/` so `/tools/jwt/` resolves on Pages. (The whole
`guides/` tree is copied, so the new `guides/jwt/` guide needs no separate
line.) The JWT tool page itself is `noindex` and absent from `sitemap.xml`
until JWT-01 ships; the guide is indexed.

## JWT-00 edit (apply if not already present)

In the *Assemble static site* step, add `tools/jwt` to the explicit tool
copy line:

```yaml
# before
          cp -a tools/clickjacking tools/headers tools/cors tools/csp tools/csrf _site/tools/
# after
          cp -a tools/clickjacking tools/headers tools/cors tools/csp tools/csrf tools/jwt _site/tools/
```

Without this, `/tools/jwt/` 404s on the hosted site even though the
header Tools menu, hub card and catalog link to it. Local `server.py` is
unaffected (it serves anything under `tools/` generically).

## DNS-01 edit (apply if not already present)

In the *Assemble static site* step, add `tools/dns` to the explicit tool
copy line (the same mechanism as the JWT preview before it):

```yaml
# before
          cp -a tools/clickjacking tools/headers tools/cors tools/csp tools/csrf tools/jwt _site/tools/
# after
          cp -a tools/clickjacking tools/headers tools/cors tools/csp tools/csrf tools/jwt tools/dns _site/tools/
```

Without this, `/tools/dns/` 404s on the hosted site even though the header
Tools menu, hub card, catalog, manifest shortcut and sitemap all link to it.
Local `server.py` is unaffected (it serves anything under `tools/`
generically). The `guides/` tree is already copied whole, so the new
`guides/dns/` guide needs no separate line.

## The required edits

Two lines in `.github/workflows/pages.yml`, both in the *Assemble static site*
step. `guides/` is a new published top-level section (`/guides/` plus
`/guides/{clickjacking,headers,cors,csp,csrf}/`) and `documentation/` is a new
top-level page; nothing copies either into `_site/` yet:

```yaml
# before
          # Full methodology page (the hub links to the #methodology anchor,
          # but the standalone page has its own canonical URL).
          test -d methodology && cp -a methodology _site/ || true
# after
          # Full methodology page (the hub links to the #methodology anchor,
          # but the standalone page has its own canonical URL).
          test -d methodology && cp -a methodology _site/ || true

          # Guides section: /guides/ index plus one guide directory per topic.
          # Copy the whole tree so future guides need no workflow change.
          test -d guides && cp -a guides _site/ || true

          # Operator documentation page (/documentation/). Deliberately NOT
          # docs/ — the leak guard below fails the build if _site/docs exists.
          test -d documentation && cp -a documentation _site/ || true
```

Without this the deployed site serves the header “Guides” link, the footer
Learn → Guides link, the hub “Short guides on this site →” link, the 404
Guides card and the guide backlink on **all five** tool pages — every one of
them 404s on the hosted site. Local `server.py` is unaffected (it already
routes `/guides/`, `/guides` and `/CyberBuddy/guides/`).

The `documentation/` line matters for the same reason: the footer
“Documentation” link no longer leaves for the GitHub README, it points at
`/documentation/`. Without the copy, every page on the hosted site has a
footer link to a 404.

Note the directory name. `documentation/` is used instead of the obvious
`docs/` because the *Guard internal files stay out of the published site* step
fails the build when `_site/docs` exists (`docs/` is the internal roadmap and
dev notes). Renaming this section to `docs/` would break the deploy.

`sitemap.xml` already lists all six guide URLs (`/guides/` and one per tool)
plus `/documentation/`, so search engines will start requesting them as soon as
the next deploy runs. Apply these edits before merging, or the sitemap
advertises dead URLs.

The *Verify referenced assets exist* step will also catch the mistake in the
other direction: if `guides/` is copied but `css/`/`js/` are not, the build
fails rather than shipping an unstyled guide.

## POST-MERGE FIX — root-relative asset check (apply if not already present)

The nested-404 fix (in the `main` history after the guides/documentation
patch landed) rewrote `404.html` to use **root-relative** asset references —
`/CyberBuddy/js/404.js`, `/CyberBuddy/css/404.css`, `/CyberBuddy/icon-192.png`,
etc. — so the 404 page keeps its styling and icons even when GitHub Pages
serves it from a deeply nested missing URL.

The *Verify referenced assets exist* step only knew how to resolve **relative**
`href`/`src` values (`[ -f "$dir/$ref" ]`), so it reported every one of those
absolute `/CyberBuddy/…` references as missing and **failed the deploy** at
the guard — which is why the live site still serves the old relative-link 404
that breaks under nested paths.

Add a root-relative branch to that step's inner `case` so absolute references
resolve against `_site` after the Pages base is stripped (matching
`tools/audit_site.py`, which already does this):

```yaml
# before
                while IFS= read -r ref; do
                  case "$ref" in
                    http*|//*|data:*) continue ;;
                  esac
                  [ -f "$dir/$ref" ] || echo "  $page -> $ref"
                done
# after
                while IFS= read -r ref; do
                  case "$ref" in
                    http*|//*|data:*) continue ;;
                    /*)
                      # Root-relative references are written against the
                      # GitHub Pages base (/CyberBuddy/). Strip the leading
                      # slash and the repo-name segment, then resolve from
                      # the artifact root, matching tools/audit_site.py.
                      rel="${ref#/}"      # CyberBuddy/js/404.js
                      rel="${rel#*/}"     # js/404.js
                      [ -f "_site/$rel" ] || echo "  $page -> $ref"
                      ;;
                    *)
                      [ -f "$dir/$ref" ] || echo "  $page -> $ref"
                      ;;
                  esac
                done
```

Until this is applied, **every push to `main` fails the Pages build**, so the
post-merge state (the new DNS/HAR roadmap, the JWT workbench completion, the
nested-404 fix, and the per-tool export improvements) never reaches the live
site. The companion guard is
`test_engines.PagesAssetVerificationTests.test_every_local_asset_reference_resolves`,
which fails if any page references an asset that is not copied into the site,
and
`test_workflow_asset_check_handles_root_relative_paths`, which passes once
either the workflow or this patch carries the fix.

## Already applied — no action needed

These IA-01 edits are live in `main` and are listed only so a diff of this
file against the workflow is not confusing:

1. **Publish the tools catalog** — `cp tools/index.html _site/tools/` in the
   *Assemble static site* step.
2. **Guard internal files out of the published site** — the
   *Guard internal files stay out of the published site* step, which fails the
   build if `docs/ROADMAP.md`, `docs/DEV-NOTES.md`, `REVIEW.md`, `_site/docs`
   or `_site/tests` reach `_site/`.

The stdlib companion checks in
`test_engines.PagesExclusionTests` pin both of them:
`test_workflow_never_copies_internal_paths` scans **only the assemble step**
(the guard step legitimately names the internal files it rejects, so a
whole-file token scan gives a false failure), and
`test_workflow_guard_step_names_the_internal_files` pins that the guard keeps
naming them.

## Why this can't be committed here

`git push` of a branch that modifies `.github/workflows/pages.yml` is refused:

```
! [remote rejected] … -> arena/… (refusing to allow a GitHub App to create
  or update workflow `.github/workflows/pages.yml` without `workflows`
  permission)
```

`gh` authenticates as the same bot, so there is no alternative push path from
this environment.

## Reference — the assemble step with the edit applied

Everything else in the workflow is unchanged.

```yaml
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
          # tools/jwt is the JWT-00 DEVELOPMENT PREVIEW (noindex until JWT-01).
          cp -a tools/clickjacking tools/headers tools/cors tools/csp tools/csrf tools/jwt _site/tools/
          cp tools/index.html _site/tools/

          # Full methodology page (the hub links to the #methodology anchor,
          # but the standalone page has its own canonical URL).
          test -d methodology && cp -a methodology _site/ || true

          # Guides section: /guides/ index plus one guide directory per topic.
          # Copy the whole tree so future guides need no workflow change.
          test -d guides && cp -a guides _site/ || true

          # Operator documentation page (/documentation/). Deliberately NOT
          # docs/ — the leak guard fails the build if _site/docs exists.
          test -d documentation && cp -a documentation _site/ || true

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
```
