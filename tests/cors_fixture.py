#!/usr/bin/env python3
"""Controlled CORS fixture for method-aware verification (curl -D).

Endpoints:
- /get-safe       GET returns no CORS headers (safe)
- /head-vuln      HEAD returns reflected ACAO with credentials (vulnerable)
- /options-vuln   OPTIONS (direct) returns reflected ACAO with credentials
- /preflight-vuln OPTIONS+ACRM:POST returns reflected ACAO with creds
- /null-reflect   GET with Origin:null returns ACAO:null (with/without creds)
- /echo           Echoes Origin for any method (for general testing)
- /unsupported    HEAD returns 405 (to test unassessed)

All endpoints echo Origin if present, with Vary: Origin where appropriate.
For unassessed test, HEAD on /unsupported returns 405.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys

ATTACKER_A = "https://evil.cyberbuddy.test"
ATTACKER_B = "https://probe.cyberbuddy.test"

class Handler(BaseHTTPRequestHandler):
    def _cors_headers(self, origin, with_creds=False):
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            if with_creds:
                self.send_header("Access-Control-Allow-Credentials", "true")

    def do_GET(self):
        origin = self.headers.get("Origin", "")
        if self.path.startswith("/unsupported"):
            # Safe GET, but HEAD unsupported
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/get-safe"):
            # No CORS headers - safe
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"safe")
        elif self.path.startswith("/null-reflect"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            # Reflect null with creds if requested
            if origin == "null":
                self._cors_headers("null", with_creds=True)
            elif origin:
                self._cors_headers(origin, with_creds=False)
            self.end_headers()
            self.wfile.write(b"null test")
        elif self.path.startswith("/echo"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            if origin:
                # echo with creds for high test
                self._cors_headers(origin, with_creds=True)
            self.end_headers()
            self.wfile.write(b"echo")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            if origin:
                self._cors_headers(origin, with_creds=False)
            self.end_headers()
            self.wfile.write(b"ok")

    def do_HEAD(self):
        origin = self.headers.get("Origin", "")
        if self.path.startswith("/unsupported"):
            self.send_response(405)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            return
        if self.path.startswith("/head-vuln"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            if origin:
                self._cors_headers(origin, with_creds=True)
            self.end_headers()
            return
        # Default HEAD echoes
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        if origin:
            self._cors_headers(origin, with_creds=False)
        self.end_headers()

    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "")
        acrm = self.headers.get("Access-Control-Request-Method", "")
        acrh = self.headers.get("Access-Control-Request-Headers", "")
        if self.path.startswith("/options-vuln") and not acrm:
            # Direct OPTIONS vulnerable
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            if origin:
                self._cors_headers(origin, with_creds=True)
                self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS, POST")
            self.end_headers()
            return
        if self.path.startswith("/preflight-vuln") and acrm == "POST":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            if origin:
                self._cors_headers(origin, with_creds=True)
                self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
                if acrh:
                    self.send_header("Access-Control-Allow-Headers", acrh)
                else:
                    self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            return
        if acrm:
            # Generic preflight echo
            self.send_response(200)
            if origin:
                self._cors_headers(origin, with_creds=True)
                self.send_header("Access-Control-Allow-Methods", acrm)
                if acrh:
                    self.send_header("Access-Control-Allow-Headers", acrh)
            self.end_headers()
            return
        # Direct OPTIONS default
        self.send_response(204)
        if origin:
            self._cors_headers(origin, with_creds=False)
            self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        self.end_headers()

    def log_message(self, fmt, *args):
        # Quiet
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9876
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Fixture listening on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
