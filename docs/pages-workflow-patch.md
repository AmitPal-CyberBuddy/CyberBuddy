# Historical note — Pages root-relative asset repair

This file is retained as the audit trail for an earlier GitHub App limitation.
The repair is **already applied** in `.github/workflows/pages.yml`; there is no
manual patch left to perform.

The Pages asset verifier originally resolved every `href`/`src` relative to the
HTML file. That broke root-relative 404 assets such as
`/CyberBuddy/js/404.js`. The applied workflow now strips the project mount and
checks from the artifact root:

```sh
rel="${ref#/}"
case "$rel" in
  CyberBuddy/*) rel="${rel#CyberBuddy/}" ;;
esac
[ -f "_site/$rel" ] || echo "  $page -> $ref"
```

The same workflow already:

- publishes all seven tool directories plus the catalog;
- copies methodology, documentation, guides, discovery/PWA assets and the
  responsible-disclosure contact;
- builds the fixed demo cache on deploy and on its six-hour schedule;
- rejects internal docs/tests in the public artifact;
- stamps asset versions with the commit SHA; and
- runs the final local-link and fragment audit.

If the workflow changes, run `python3 tools/verify.py`; do not add a second
manual patch here. GitHub Apps still need `workflows` permission to push any
workflow edit.
