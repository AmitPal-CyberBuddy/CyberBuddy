# ACTION REQUIRED — publish the `guides/` section

The GitHub App that pushes these arena branches is **not** granted the
`workflows` permission, so any commit that touches `.github/workflows/**` is
rejected by the server. Everything else ships normally. This file carries the
workflow edit that could not be pushed, for a maintainer to apply by hand
(the same mechanism used in PR #20 for the CSRF tool and PR #22 for IA-01).

This patch is for **GUIDES-01 — public Guides foundation + Clickjacking pilot
guide**.

## The required edit

One change to `.github/workflows/pages.yml`, in the *Assemble static site*
step. `guides/` is a new published top-level section (`/guides/` and
`/guides/clickjacking/`) and nothing copies it into `_site/` yet:

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
```

Without this the deployed site serves the header “Guides” link, the footer
Learn → Guides link, the hub “Short guides on this site →” link, the 404
Guides card and the Clickjacking tool's guide backlink — all of them 404 on
the hosted site. Local `server.py` is unaffected (it already routes
`/guides/`, `/guides` and `/CyberBuddy/guides/`).

`sitemap.xml` already lists `/guides/` and `/guides/clickjacking/`, so search
engines will start requesting those URLs as soon as the next deploy runs.
Apply this edit before merging, or the sitemap advertises two dead URLs.

The *Verify referenced assets exist* step will also catch the mistake in the
other direction: if `guides/` is copied but `css/`/`js/` are not, the build
fails rather than shipping an unstyled guide.

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
          cp -a tools/clickjacking tools/headers tools/cors tools/csp tools/csrf _site/tools/
          cp tools/index.html _site/tools/

          # Full methodology page (the hub links to the #methodology anchor,
          # but the standalone page has its own canonical URL).
          test -d methodology && cp -a methodology _site/ || true

          # Guides section: /guides/ index plus one guide directory per topic.
          # Copy the whole tree so future guides need no workflow change.
          test -d guides && cp -a guides _site/ || true

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
