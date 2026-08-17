# DNS-01 — DNS & Domain Security Analyzer: plan & build notes

> Companion to the roadmap entry in `docs/ROADMAP.md` (§4, `DNS-01`). This
> file records the design decisions behind the seventh CyberBuddy tool and
> what was built. Repo-internal: the Pages workflow never publishes `docs/`.

---

## 1. What the tool does

Takes a **domain** (e.g. `example.com`) and grades its *public DNS* security
posture on a 0–100 scale with an A–F band, producing the same evidence-grade
report card as the other assess tools. It reads:

| Check | Weight | What "ok" means |
| --- | --- | --- |
| DMARC | 20 | `_dmarc` TXT with `p=quarantine` or `p=reject` |
| SPF | 15 | one `v=spf1` TXT ending `-all`/`~all`, within the 10-lookup budget |
| DKIM | 10 | a `v=DKIM1` key on a common selector |
| DNSSEC | 10 | DS published at the parent zone |
| Name servers | 10 | at least two authoritative NS |
| CAA | 5 | a certificate-authority authorization record |

Domain resolution (A/AAAA) is reported as a fact; MX is context. A domain that
does not handle email scores SPF/DMARC/DKIM as *informational*, not as
deductions. An NXDOMAIN domain is reported **unknown — never graded**.

## 2. Architecture decisions

1. **Resolver-only.** The tool never connects to the target's own servers; it
   only sends DNS queries to a resolver. No SSRF surface, safe to run against
   domains you do not own.
2. **Two engines, one scoring contract.** `dns_security.grade_dns_from_records`
   (Python) and `gradeDnsFromRecords` (`js/app.js`) grade the same
   `records`/`statuses` shape and are pinned check-for-check by
   `DnsParityTests`. They differ only in *how records are collected*:
   - Python: a stdlib DNS wire-format client (UDP, TCP fallback on
     truncation), querying the system resolver (`/etc/resolv.conf`, public
     fallback only if none is configured).
   - Browser: DNS-over-HTTPS to `dns.google`, gated behind a DNS-specific
     consent prompt and labelled `unverified`.
3. **Standalone, not in the Run suite.** The tool is `category: "assess"` with
   `suite: false`. The hub "Run suite" stays the four HTTP tools
   (clickjacking / headers / CORS / CSP). The catalog now carries per-tool
   suite badges so the mixed membership stays honest.
4. **No cached layer.** CI publishes HTTP scan caches; DNS has no cache layer —
   the Python engine or the consent-gated DoH grader always answers fresh.
5. **Honesty rules** (carried through the UI, guide and tests): a DKIM miss is
   a hint, never proof of absence; DNSSEC verdicts key on DS, not DNSKEY;
   RFC 7505 null MX means "no email", not a missing MX.

## 3. Files

**New**

- `dns_security.py` — engine + CLI (stdlib wire client, scorer, `scan_dns`).
- `api/dns.py` — Vercel file-based function for `/api/dns`.
- `tools/dns/index.html` — the tool page.
- `js/tool.dns.js` — page controller.
- `guides/dns/index.html` — the paired 5-minute guide.

**Modified**

- `server.py` — `/api/dns?domain=`, `/dns` alias, startup banner, docstring.
- `js/app.js` — registry entry, DNS icon, per-tool suite badges, domain
  validation helpers (`initDomainInput`/`validateDomainField`),
  `gradeDnsFromRecords` + DoH collection + `apiDns`, the `dns-relay` source
  label, `renderDnsRelayGate`/`ensureDnsConsent`, DNS weights + `FINDING_FIX`,
  and the `dns` export/evidence-card kind.
- `index.html` · `tools/index.html` · `404.html` · `guides/index.html` — static
  cards + counts (`07 live` / `07 guides` / `seven live tools`).
- `methodology/index.html` — `#dns` scoring section + tool card + privacy note.
- `documentation/index.html` — engine-path note + the 5th CLI.
- `sitemap.xml` · `manifest.webmanifest` · `llms.txt` · `README.md` — wiring.
- `js/404-boot.js` — legacy-URL repair covers `dns`.
- `test_engines.py` — `DnsEngineTests`, `DnsParityTests`, `DnsSiteTests`,
  plus updates to the alias/route/ticker/guide/category tests.
- `tests/browser/{layout,dropdown,responsive}.js` — `dns` + `guide-dns` PAGES.
- `docs/ROADMAP.md` · `docs/DEV-NOTES.md` · `docs/pages-workflow-patch.md` —
  roadmap item, durable traps, and the unpushable workflow copy line.

## 4. Known follow-up for the maintainer

The arena push token cannot edit `.github/workflows/**`. The one-line
`tools/dns` copy-line edit is recorded in `docs/pages-workflow-patch.md`:

```yaml
cp -a tools/clickjacking tools/headers tools/cors tools/csp tools/csrf tools/jwt tools/dns _site/tools/
```

Until that lands, `/tools/dns/` 404s on the hosted Pages site (local
`server.py` is unaffected). The `guides/` tree is copied whole, so
`guides/dns/` needs no separate line.

## 5. Verification

- `python3 -m unittest test_engines.py` → **355 tests OK** (was 333).
- `node --check` on all `js/` and `tests/browser/` scripts → clean.
- `tools/audit_site.py` against a full Pages assembly (icons included) → pass.
- Live `server.py` smoke test: `/tools/dns/` 200, `/dns` 301,
  `/api/dns` → 400 without `domain`, `example.com` → A / 95 / low,
  NXDOMAIN → unknown (not graded), `/api/health` → ok.
