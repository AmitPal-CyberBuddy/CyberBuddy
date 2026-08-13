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
GET /api/cors?url=…         CORS origin-reflection probe (basic)
GET /poc?url=…              standalone clickjacking PoC page
GET /health                 {"ok": true}

Everything is stdlib. The API intentionally binds to 0.0.0.0 so a phone on
the same LAN can reach it, but it performs only read-only GET scans and holds
no state — treat it as a local-only tool.

Only test systems you own or have written permission to assess.
"""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from clickjacking_validator import USER_AGENT, scan_url
from security_headers import scan_headers

HOST = "0.0.0.0"
PORT = 8080
ROOT = Path(__file__).resolve().parent

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


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberBuddy/" + USER_AGENT.split("/")[-1].split()[0]

    def log_message(self, fmt: str, *args) -> None:
        print("[http] " + fmt % args)

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload, indent=2).encode("utf-8"), "application/json; charset=utf-8")

    def _static(self, rel: str) -> None:
        path = (ROOT / rel).resolve()
        # stay inside the repo root
        if ROOT not in path.parents and path != ROOT:
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        if not path.is_file():
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

        if path == "/health":
            self._json(200, {"ok": True})
            return

        if path == "/api/scan":
            if not url:
                self._json(400, {"error": "url required"})
                return
            self._json(200, scan_url(url, timeout=15.0, insecure=False).to_dict())
            return

        if path == "/api/headers":
            if not url:
                self._json(400, {"error": "url required"})
                return
            self._json(200, scan_headers(url, timeout=15.0, insecure=False).to_dict())
            return

        if path == "/api/cors":
            if not url:
                self._json(400, {"error": "url required"})
                return
            self._json(200, {"url": url, "note": "server-side CORS preflight explorer lands next; use the in-browser probe on the CORS page."})
            return

        if path == "/poc":
            if not url:
                self._send(400, b"url required", "text/plain; charset=utf-8")
                return
            body = POC_HTML.format(url=html.escape(url, quote=True)).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
            return

        # Hub
        if path in ("/", "/index.html"):
            self._static("index.html")
            return

        # Tool pages + assets
        if path.startswith("/tools/"):
            rel = path.lstrip("/")
            if rel.endswith("/"):
                rel += "index.html"
            self._static(rel)
            return

        if path in ("/css/app.css", "/js/app.js"):
            self._static(path.lstrip("/"))
            return

        self._send(404, b"not found", "text/plain; charset=utf-8")


def main() -> None:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"CyberBuddy serving on http://{HOST}:{PORT}")
    print(f"Hub:        http://127.0.0.1:{PORT}/")
    print(f"Clickjacking: http://127.0.0.1:{PORT}/tools/clickjacking/")
    print(f"Headers:    http://127.0.0.1:{PORT}/tools/headers/")
    print(f"CORS:       http://127.0.0.1:{PORT}/tools/cors/")
    print("API:        /api/scan?url=…   /api/headers?url=…   /health")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
