#!/usr/bin/env python3
"""
CyberBuddy local server — hosts the hub and tool pages plus JSON scan APIs.
With performance optimizations: streaming I/O, connection pooling, concurrent scans.

Routes
------
GET /                       hub (index.html)
GET /methodology/           scoring + engine notes
GET /css/app.css            shared styles
GET /js/app.js              shared helpers
GET /tools/<tool>/          each tool page (static)
GET /headers /cors /csp /clickjacking
                            aliases → /tools/<tool>/
GET /api/scan?url=…         clickjacking / framing header scan
GET /api/headers?url=…      security headers scan (CSP, HSTS, COOP/COEP, …)
GET /api/cors?url=…         two-origin CORS reflection probe
GET /api/csp?url=…          dedicated Content-Security-Policy audit
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
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from clickjacking_validator import normalize_url, scan_url, validate_target
from cors_validator import scan_cors
from csp_checker import scan_csp
from security_headers import scan_headers

HOST = "127.0.0.1"
PORT = 8080
ALLOW_PRIVATE = True
ROOT = Path(__file__).resolve().parent

ALLOWED_STATIC_SUFFIXES = {".html", ".css", ".js", ".json", ".png", ".xml", ".webmanifest", ".txt"}
STATIC_PREFIXES = ("tools/", "css/", "js/", "cache/", ".well-known/", "methodology/")
ROOT_STATIC = frozenset({
    "index.html", "404.html",
    "robots.txt", "sitemap.xml", "manifest.webmanifest",
    "og-cyberbuddy.png", "icon-192.png", "icon-512.png",
    "humans.txt", "llms.txt",
})
# GitHub Pages project URL is /CyberBuddy/… — accept the same prefix locally
# so a hosted-style path does not 404 when someone points server.py at it.
MOUNT_PREFIXES = ("/CyberBuddy",)
TOOL_ALIASES = {
    "/headers": "/tools/headers/",
    "/headers/": "/tools/headers/",
    "/cors": "/tools/cors/",
    "/cors/": "/tools/cors/",
    "/csp": "/tools/csp/",
    "/csp/": "/tools/csp/",
    "/clickjacking": "/tools/clickjacking/",
    "/clickjacking/": "/tools/clickjacking/",
}

# Chunk size for streaming file I/O (64KB)
STREAM_CHUNK_SIZE = 65536

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


def strip_mount(path: str) -> str:
    """Drop a known public mount prefix (/CyberBuddy) from the request path."""
    for prefix in MOUNT_PREFIXES:
        if path == prefix:
            return "/"
        if path.startswith(prefix + "/"):
            return path[len(prefix):] or "/"
    return path


def default_bind() -> tuple[str, int]:
    """PaaS hosts set PORT; bind on all interfaces when they do."""
    env_port = (os.environ.get("PORT") or "").strip()
    env_host = (os.environ.get("HOST") or "").strip()
    port = int(env_port) if env_port else 8080
    if env_host:
        host = env_host
    elif env_port:
        host = "0.0.0.0"
    else:
        host = "127.0.0.1"
    return host, port


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberBuddy"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:
        print("[http] " + fmt % args)

    # CyberBuddy grades these headers on other sites, so it ships them itself.
    # script-src has NO 'unsafe-inline': every page script lives in js/*.js.
    # style-src still needs it for the `style="--d: .08s"` animation-delay
    # attributes; style-src-attr scopes that to attributes only, so inline
    # <style> blocks stay blocked. frame-src must allow http(s) so the
    # clickjacking iframe can load a target.
    CSP = (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "style-src-attr 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "script-src 'self'; "
        # blob: — the evidence-card / PoC-image exports build a canvas, call
        # toBlob(), and download it via an object URL.
        "img-src 'self' data: blob:; "
        "connect-src 'self' http: https:; "
        "frame-src http: https:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'self'; "
        "form-action 'self'"
    )

    def _security_headers(self) -> None:
        """Emit the response hardening headers shared by every route."""
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "credentialless")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
            "interest-cohort=()",
        )
        self.send_header("Content-Security-Policy", self.CSP)

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_file_streaming(self, code: int, path: Path, content_type: str) -> None:
        """Send a file using chunked streaming for memory efficiency."""
        try:
            file_size = path.stat().st_size
        except OSError:
            self._not_found()
            return
        
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(file_size))
        self._security_headers()
        self.end_headers()
        
        # Stream file in chunks to avoid loading entire file into memory
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(STREAM_CHUNK_SIZE)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (IOError, OSError):
            pass  # Connection closed or file disappeared

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload, indent=2).encode("utf-8"), "application/json; charset=utf-8")

    def _our_origin(self) -> set[str]:
        hosts: set[str] = set()
        for key in ("Host", "X-Forwarded-Host"):
            raw = (self.headers.get(key) or "").strip()
            if raw:
                hosts.add(raw.split(",")[0].strip())
        if not hosts:
            hosts.add(f"{HOST}:{PORT}")
        proto = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        out: set[str] = set()
        for host in hosts:
            out.add(f"http://{host}")
            out.add(f"https://{host}")
            if proto in {"http", "https"}:
                out.add(f"{proto}://{host}")
        return out

    def _redirect(self, dest: str) -> None:
        self.send_response(301)
        self.send_header("Location", dest)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _not_found(self) -> None:
        page = ROOT / "404.html"
        if page.is_file():
            self._send(404, page.read_bytes(), "text/html; charset=utf-8")
            return
        self._send(404, b"not found", "text/plain; charset=utf-8")

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
            self._not_found()
            return
        if rel not in ROOT_STATIC and not rel.startswith(STATIC_PREFIXES):
            self._not_found()
            return
        path = (ROOT / rel).resolve()
        if not _under_root(path) or not path.is_file():
            self._not_found()
            return
        if path.suffix not in ALLOWED_STATIC_SUFFIXES:
            self._not_found()
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".png": "image/png",
            ".xml": "application/xml; charset=utf-8",
            ".webmanifest": "application/manifest+json; charset=utf-8",
            ".txt": "text/plain; charset=utf-8",
        }.get(path.suffix, "application/octet-stream")
        # Use streaming for potentially large files
        self._send_file_streaming(200, path, ctype)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        url = (qs.get("url") or [""])[0].strip()
        path = strip_mount(parsed.path)

        if path in ("/health", "/api/health"):
            self._json(200, {"ok": True})
            return

        if path in ("/api/scan", "/api/headers", "/api/cors", "/api/csp"):
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
            elif path == "/api/csp":
                self._json(200, scan_csp(url, **kwargs).to_dict())
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

        if path in TOOL_ALIASES:
            dest = TOOL_ALIASES[path]
            if parsed.query:
                dest += "?" + parsed.query
            self._redirect(dest)
            return

        if path in ("/", "/index.html"):
            self._static("index.html")
            return

        if path == "/404.html":
            self._static("404.html")
            return

        if path.startswith("/tools/") or path == "/methodology" or path.startswith("/methodology/"):
            rel = path.lstrip("/")
            # /tools/clickjacking → /tools/clickjacking/
            # /methodology → /methodology/
            if not rel.endswith("/") and "." not in Path(rel).name:
                dest = path.rstrip("/") + "/"
                if parsed.query:
                    dest += "?" + parsed.query
                self._redirect(dest)
                return
            if rel.endswith("/"):
                rel += "index.html"
            self._static(rel)
            return

        if path.startswith("/css/") or path.startswith("/js/") or path.startswith("/cache/"):
            self._static(path.lstrip("/"))
            return

        if path.startswith("/.well-known/"):
            self._static(path.lstrip("/"))
            return

        # Root-level static assets (robots.txt, sitemap.xml, manifest, icons, OG image)
        rel = path.lstrip("/")
        if rel in ROOT_STATIC:
            self._static(rel)
            return

        self._not_found()


def main(argv: list[str] | None = None) -> None:
    global HOST, PORT, ALLOW_PRIVATE
    bind_host, bind_port = default_bind()
    p = argparse.ArgumentParser(description="CyberBuddy local hub + scan APIs.")
    p.add_argument("--host", default=bind_host, help="Bind address (default 127.0.0.1; 0.0.0.0 when PORT is set)")
    p.add_argument("--port", type=int, default=bind_port, help="Bind port (default 8080, or $PORT)")
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
    print(f"CSP:          http://127.0.0.1:{PORT}/tools/csp/")
    print("API:          /api/scan  /api/headers  /api/cors  /api/csp  /api/health")
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
