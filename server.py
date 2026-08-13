#!/usr/bin/env python3
"""
CyberBuddy local server — hosts the hub and tool pages plus JSON scan APIs.

Routes
------
GET /                       hub (index.html)
GET /css/app.css            shared styles
GET /js/app.js              shared helpers
GET /tools/<tool>/          each tool page (static)
GET /api/scan?url=…         clickjacking / framing header scan
GET /api/headers?url=…      security headers scan (CSP, HSTS, COOP/COEP, …)
GET /api/cors?url=…         two-origin CORS reflection probe
GET /api/health             {"ok": true}  (alias: /health)
GET /poc?url=…              standalone clickjacking PoC page

Everything is stdlib. Binds 127.0.0.1 by default (loopback only). Pass
--host 0.0.0.0 to reach it from the LAN — that also disables private-IP
scans unless you add --allow-private.

Only test systems you own or have written permission to assess.
"""

from __future__ import annotations

import argparse
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from clickjacking_validator import USER_AGENT, normalize_url, scan_url, validate_target
from cors_validator import scan_cors
from security_headers import scan_headers

HOST = "127.0.0.1"
PORT = 8080
ALLOW_PRIVATE = True
ROOT = Path(__file__).resolve().parent

ALLOWED_STATIC_SUFFIXES = {".html", ".css", ".js"}
STATIC_PREFIXES = ("tools/", "css/", "js/")

POC_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clickjacking PoC — CyberBuddy</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 24px; background: #0a0d13; color: #e9eef5; }}
    h1 {{ font-size: 1.2rem; }}
    p {{ color: #96a2b4; font-size: 0.9rem; }}
    .decoy {{ position: relative; width: 900px; max-width: 100%; height: 600px; }}
    .decoy iframe {{
      position: absolute; inset: 0; width: 100%; height: 100%;
      opacity: 0.3; border: 2px solid #ff5c5c;
    }}
    .hint {{
      position: absolute; top: 40px; left: 40px; z-index: 2;
      background: #ff5c5c; color: #fff; padding: 16px 22px; border-radius: 8px;
      pointer-events: none; font-weight: 700;
    }}
  </style>
</head>
<body>
  <h1>Clickjacking proof of concept</h1>
  <p>If you can see the target UI (even faded) under the decoy, the page is frameable. Authorized testing only.</p>
  <div class="decoy">
    <div class="hint">CLICK HERE — decoy overlay (pointer-events: none)</div>
    <iframe src="{url}" title="Target"></iframe>
  </div>
</body>
</html>
"""


def _under_root(path: Path) -> bool:
    try:
        path.relative_to(ROOT)
        return True
    except ValueError:
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberBuddy"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:
        print("[http] " + fmt % args)

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        # Inline scripts/styles are used by the static pages; frame-src must
        # allow http(s) so the clickjacking iframe can load a target.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "frame-src http: https:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload, indent=2).encode("utf-8"), "application/json; charset=utf-8")

    def _our_origin(self) -> set[str]:
        host = self.headers.get("Host", f"{HOST}:{PORT}")
        return {f"http://{host}", f"https://{host}"}

    def _api_allowed(self) -> bool:
        """Stop drive-by GETs from other sites (img/fetch CSRF).

        Browser fetch from this app sends Origin (and X-Requested-With).
        curl (no Origin, no Referer) is allowed. A third-party page's
        Origin/Referer will not match our Host.
        """
        ours = self._our_origin()
        origin = (self.headers.get("Origin") or "").strip()
        if origin:
            return origin in ours
        referer = (self.headers.get("Referer") or "").strip()
        if referer:
            parsed = urlparse(referer)
            return f"{parsed.scheme}://{parsed.netloc}" in ours
        xrw = (self.headers.get("X-Requested-With") or "").strip()
        if xrw == "CyberBuddy":
            return True
        # No Origin/Referer — curl / address-bar. Allow.
        return True

    def _static(self, rel: str) -> None:
        rel = rel.lstrip("/").replace("\\", "/")
        if ".." in rel.split("/"):
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        if rel not in {"index.html"} and not rel.startswith(STATIC_PREFIXES):
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        path = (ROOT / rel).resolve()
        if not _under_root(path) or not path.is_file():
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        if path.suffix not in ALLOWED_STATIC_SUFFIXES:
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
        }.get(path.suffix, "application/octet-stream")
        self._send(200, path.read_bytes(), ctype)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        url = (qs.get("url") or [""])[0].strip()
        path = parsed.path

        if path in ("/health", "/api/health"):
            self._json(200, {"ok": True})
            return

        if path in ("/api/scan", "/api/headers", "/api/cors"):
            if not self._api_allowed():
                self._json(403, {"error": "cross-origin API access denied"})
                return
            if not url:
                self._json(400, {"error": "url required"})
                return
            kwargs = {"timeout": 15.0, "insecure": False, "allow_private": ALLOW_PRIVATE}
            if path == "/api/scan":
                self._json(200, scan_url(url, **kwargs).to_dict())
            elif path == "/api/headers":
                self._json(200, scan_headers(url, **kwargs).to_dict())
            else:
                self._json(200, scan_cors(url, **kwargs).to_dict())
            return

        if path == "/poc":
            if not url:
                self._send(400, b"url required", "text/plain; charset=utf-8")
                return
            try:
                url = normalize_url(url)
                validate_target(url, allow_private=ALLOW_PRIVATE)
            except ValueError as exc:
                self._send(400, str(exc).encode("utf-8"), "text/plain; charset=utf-8")
                return
            body = POC_HTML.format(url=html.escape(url, quote=True)).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
            return

        if path in ("/", "/index.html"):
            self._static("index.html")
            return

        if path.startswith("/tools/"):
            rel = path.lstrip("/")
            # /tools/clickjacking → /tools/clickjacking/
            if not rel.endswith("/") and "." not in Path(rel).name:
                dest = path.rstrip("/") + "/"
                if parsed.query:
                    dest += "?" + parsed.query
                self.send_response(301)
                self.send_header("Location", dest)
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            if rel.endswith("/"):
                rel += "index.html"
            self._static(rel)
            return

        if path in ("/css/app.css", "/js/app.js"):
            self._static(path.lstrip("/"))
            return

        self._send(404, b"not found", "text/plain; charset=utf-8")


def main(argv: list[str] | None = None) -> None:
    global HOST, PORT, ALLOW_PRIVATE
    p = argparse.ArgumentParser(description="CyberBuddy local hub + scan APIs.")
    p.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1, loopback only)")
    p.add_argument("--port", type=int, default=8080, help="Bind port (default 8080)")
    p.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow RFC1918/loopback scan targets even when bound on a non-loopback address.",
    )
    args = p.parse_args(argv)
    HOST = args.host
    PORT = args.port
    loopback = HOST in {"127.0.0.1", "localhost", "::1"}
    ALLOW_PRIVATE = loopback or args.allow_private

    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"CyberBuddy serving on http://{HOST}:{PORT}")
    print(f"Hub:          http://127.0.0.1:{PORT}/")
    print(f"Clickjacking: http://127.0.0.1:{PORT}/tools/clickjacking/")
    print(f"Headers:      http://127.0.0.1:{PORT}/tools/headers/")
    print(f"CORS:         http://127.0.0.1:{PORT}/tools/cors/")
    print("API:          /api/scan  /api/headers  /api/cors  /api/health")
    if not loopback:
        print("WARNING: bound on a non-loopback address. Private-IP scans are "
              + ("ENABLED (--allow-private)." if ALLOW_PRIVATE else "disabled."))
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
