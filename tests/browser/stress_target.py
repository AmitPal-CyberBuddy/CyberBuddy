#!/usr/bin/env python3
"""Local stress target for tests/browser/responsive.js (CB_STRESS).

Serves one HTML page whose response headers carry 400-character unbreakable
tokens, so the report grids must wrap/clip them without spilling the viewport.

    python3 tests/browser/stress_target.py --port 8098 &
    CB_STRESS=http://127.0.0.1:8098/ node tests/browser/responsive.js
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "x" * 400


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _page(self):
        body = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>stress</title></head><body><h1>stress target</h1>"
            "</body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name in (
            "Server",
            "Set-Cookie",
            "Content-Security-Policy",
            "Access-Control-Allow-Origin",
            "X-Stress-Token",
        ):
            value = TOKEN
            if name == "Content-Security-Policy":
                value = "default-src 'none'; script-src https://" + TOKEN
            elif name == "Set-Cookie":
                value = "stress=" + TOKEN + "; Path=/; SameSite=Lax"
            self.send_header(name, value)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._page()

    def do_HEAD(self):
        self._page()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin") or "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8098)
    args = ap.parse_args()
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()
