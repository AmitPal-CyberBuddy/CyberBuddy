#!/usr/bin/env python3
"""
Build the hosted scan cache for GitHub Pages.

Reads the targets in urls.txt (one URL per line, '#' comments allowed),
runs the *real* Python engines against each one, and writes one JSON file
per host into cache/<host>.json:

    cache/example.com.json
    {
      "generated_at": "2026-08-13T12:00:00+00:00",
      "urls": {
        "https://example.com/": {
          "url": "https://example.com/",
          "generated_at": "...",
          "clickjacking": { ... ScanResult ... },
          "headers":     { ... HeadersResult ... },
          "cors":        { ... CorsResult ... },
          "csp":         { ... CspResult ... }
        }
      }
    }

The frontend (js/app.js -> cachedReportFor) checks cache/<host>.json before
falling back to public relays, so configured targets get full-strength
results from the GitHub-hosted site: server-side header reads, two-origin
CORS reflection proof, and metadata/private-IP blocking — with no third-
party services involved.

Run locally and commit cache/ (recommended), or wire it into
.github/workflows/pages.yml so every deploy refreshes the cache before the
site is published (see README "Making the hosted site full-strength").
Authorized testing only — read-only GETs.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from clickjacking_validator import scan_url as scan_clickjacking  # noqa: E402
from concurrent_scanner import scan_urls_concurrent  # noqa: E402
from cors_validator import scan_cors  # noqa: E402
from csp_checker import scan_csp  # noqa: E402
from security_headers import scan_headers  # noqa: E402

# Public targets only — a cache on GitHub Pages must never scan private
# addresses. Cloud-metadata hosts are always blocked by the engines.
SCAN_KWARGS = {"timeout": 15.0, "insecure": False, "allow_private": False}


def collect_urls(path: Path) -> list[str]:
    if not path.is_file():
        return []
    urls: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    seen: set[str] = set()
    return [u for u in urls if not (u in seen or seen.add(u))]


def host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or "unknown"
    except ValueError:
        return "unknown"


def scan_all(url: str) -> tuple:
    """Run every engine against one URL (used per worker)."""
    return (
        scan_clickjacking(url, **SCAN_KWARGS),
        scan_headers(url, **SCAN_KWARGS),
        scan_cors(url, **SCAN_KWARGS),
        scan_csp(url, **SCAN_KWARGS),
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--urls", default=str(ROOT / "urls.txt"), help="target file")
    ap.add_argument("--out", default=str(ROOT / "cache"), help="output dir")
    ap.add_argument("--workers", type=int, default=4, help="parallel workers (default 4)")
    args = ap.parse_args(argv)

    urls = collect_urls(Path(args.urls))
    if not urls:
        print("No targets in urls.txt — nothing to cache.")
        return 0

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    by_host: dict[str, dict] = {}

    print(f"[cache] scanning {len(urls)} url(s) with {args.workers} worker(s)…")
    triples = scan_urls_concurrent(urls, scan_all, max_workers=args.workers, show_progress=True)

    for url, triple in zip(urls, triples):
        if triple is None:
            print(f"  ERROR {url}: worker failed")
            continue
        cj, hd, cr, cp = triple
        entry = {
            "url": url,
            "generated_at": stamp,
            "clickjacking": cj.to_dict(),
            "headers": hd.to_dict(),
            "cors": cr.to_dict(),
            "csp": cp.to_dict(),
        }
        host = host_of(url)
        bucket = by_host.setdefault(host, {"generated_at": stamp, "urls": {}})
        bucket["urls"][url] = entry
        print(
            f"  clickjacking={cj.risk}  headers={hd.grade} "
            f"({hd.score}/100)  cors={cr.risk}  csp={cp.risk}"
        )

    for host, bucket in by_host.items():
        target = out_dir / f"{host}.json"
        target.write_text(json.dumps(bucket, indent=2), encoding="utf-8")
        try:
            shown = target.relative_to(ROOT)
        except ValueError:
            shown = target
        print(f"[cache] wrote {shown} ({len(bucket['urls'])} urls)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
