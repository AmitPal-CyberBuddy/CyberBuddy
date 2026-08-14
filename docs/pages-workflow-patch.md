# ACTION REQUIRED — one manual edit to `.github/workflows/pages.yml`

I could not commit this change: the GitHub App I push through is not granted the
`workflows` permission, so any commit touching `.github/workflows/**` is rejected
by the server. Everything else in the review shipped normally.

**This edit is required before the next deploy.** The current workflow copies
only `css/app.css` and `js/app.js`. The refactor that removed inline scripts
(so the site can ship a CSP without `'unsafe-inline'`) split the page logic into
several new files. Without this change GitHub Pages will publish a site whose
tool pages have **no JavaScript** — the scan buttons will do nothing.

Locally (`server.py`) everything already works; this only affects the Pages build.

## The change

In the **`Assemble static site`** step, replace these two lines:

```yaml
          cp css/app.css _site/css/
          cp js/app.js _site/js/
```

with:

```yaml
          cp css/*.css _site/css/
          cp js/*.js _site/js/
```

Then add this, still inside the same `run: |` block, right after the
`cp -a tools/... _site/tools/` line:

```yaml
          test -f LICENSE && cp LICENSE _site/ || true
```

And add a new step immediately after the `Assemble static site` step (same
indentation as the other `- name:` entries):

```yaml
      # Cache-busting: stamp every ?v=... asset query with the commit SHA so a
      # deploy can never serve a stale css/js to returning visitors. This
      # replaces the hand-maintained ?v=YYYYMMDD strings.
      - name: Stamp asset versions
        run: |
          REV="${GITHUB_SHA::12}"
          find _site -name '*.html' -print0 |
            xargs -0 sed -i -E "s/\?v=[A-Za-z0-9._-]+/?v=${REV}/g"
          echo "Stamped assets with ?v=${REV}"
```

## Files that must reach `_site/js/`

| File | Purpose |
| --- | --- |
| `app.js` | shared helpers, graders, export menu |
| `boot.js` | reads `<body data-page/data-init>` and boots the page |
| `theme-boot.js` | pre-paint theme (replaces the inline head script) |
| `hub.js` | hub console animation |
| `tool.clickjacking.js` | clickjacking page controller |
| `tool.headers.js` | headers page controller |
| `tool.cors.js` | CORS page controller |
| `404-boot.js`, `404.js` | 404 theme + legacy-URL repair |

…and `_site/css/`: `app.css`, `noscript.css`, `404.css`.

The wildcard copies above cover all of them, including anything added later.

## Verify after deploying

1. Open a tool page and check DevTools → Console for CSP violations (should be
   none) and Network for 404s on `/CyberBuddy/js/*.js`.
2. Run a scan — the button must respond.
3. View source: every `?v=` should show the commit SHA, not `20260814d`.
