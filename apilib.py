"""
Shared WSGI plumbing for the optional hosted API.

Deploying this module + the api/ endpoints gives the GitHub Pages site
the same scan quality as a local ``server.py``: server-side header reads,
two-origin CORS reflection proof, and metadata / private-IP blocking —
no public relays, no browser CORS limits, for *arbitrary* URLs.

Platform
--------
Vercel (free hobby tier) auto-detects ``api/*.py`` as file-based Python
functions. This module deliberately lives OUTSIDE api/ (at the repo
root) because every ``.py`` inside api/ becomes its own function and
must define ``app``/``application``/``handler`` — helper modules would
otherwise be deployed as broken endpoints. Vercel bundles all reachable
project files, so the endpoints import it with a sys.path insert.

    vercel --prod

Then set ``API_BASE`` in js/app.js to the deployment URL (or the value
you want, e.g. "https://cyberbuddy-api.vercel.app") and the frontend's
health check will find it and prefer it over the live graders.

Security posture (this endpoint is public by design)
----------------------------------------------------
- Read-only GET only; OPTIONS preflight answered for the browser.
- Cloud-metadata hosts are always refused; private / loopback targets
  are always refused (engines run with ``allow_private=False``) because
  this API is reachable from the internet, unlike loopback ``server.py``.
- Per-IP rate limit, per function instance. On serverless this is
  best-effort ONLY: the counter dies with each cold start and each
  concurrent instance has its own, so the real ceiling is roughly
  CB_RATE_MAX x live instances. Use shared storage (KV/Redis) or the
  platform WAF if you need a hard quota. See _rate_limited().
- CORS is wide open ON PURPOSE so the Pages origin can call it; the
  endpoint only ever performs read-only GETs against URLs the caller
  provides, which is no more dangerous than the public relays it
  replaces. Set ``CB_ALLOW_ORIGIN`` to restrict it if you want.
"""

from __future__ import annotations

import json
import os
import sys
import time
from urllib.parse import parse_qs

# Make the repo root importable (Vercel's working dir is the project base).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

RATE_MAX = int(os.environ.get("CB_RATE_MAX", "30"))
RATE_WINDOW = int(os.environ.get("CB_RATE_WINDOW", "60"))
ALLOW_ORIGIN = os.environ.get("CB_ALLOW_ORIGIN", "*")

# Per-instance rate limit.
#
# IMPORTANT — this is best-effort only on serverless. The dict lives in one
# function instance: it is lost on every cold start, and concurrent instances
# each keep their own counter, so the effective global limit is roughly
# RATE_MAX * (number of live instances). Treat it as protection against a
# single hot caller, NOT as a hard quota.
#
# For a real limit put the counter in shared storage (Vercel KV / Upstash
# Redis / Cloudflare KV) keyed by IP, or front the deployment with the
# platform's own WAF/rate-limiting. Until then the endpoint is deliberately
# read-only GET, refuses private/metadata targets, and caps redirects — the
# blast radius of abuse is a public GET the caller could make anyway.
_hits: dict[str, list[float]] = {}
_HITS_MAX_KEYS = 2048  # bound memory if an instance stays warm under spray


def _rate_limited(environ: dict) -> bool:
    # X-Forwarded-For is set by the platform edge; REMOTE_ADDR alone is the
    # proxy on most PaaS. Take the first hop, which is the real client.
    fwd = (environ.get("HTTP_X_FORWARDED_FOR") or "").split(",")[0].strip()
    ip = fwd or environ.get("REMOTE_ADDR") or "unknown"
    now = time.monotonic()
    if len(_hits) > _HITS_MAX_KEYS:
        for key in [k for k, v in _hits.items() if not v or now - v[-1] > RATE_WINDOW]:
            _hits.pop(key, None)
        if len(_hits) > _HITS_MAX_KEYS:
            _hits.clear()
    bucket = _hits.setdefault(ip, [])
    bucket[:] = [t for t in bucket if now - t < RATE_WINDOW]
    if len(bucket) >= RATE_MAX:
        return True
    bucket.append(now)
    return False


def _cors_headers() -> list[tuple[str, str]]:
    return [
        ("Access-Control-Allow-Origin", ALLOW_ORIGIN),
        ("Access-Control-Allow-Methods", "GET, OPTIONS"),
        ("Access-Control-Allow-Headers", "Content-Type, X-Requested-With"),
        ("Access-Control-Max-Age", "600"),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
    ]


def _json(start_response, status: str, payload: dict) -> list[bytes]:
    body = json.dumps(payload).encode("utf-8")
    headers = [("Content-Type", "application/json; charset=utf-8")] + _cors_headers()
    start_response(status, headers)
    return [body]


def make_app(runner):
    """Wrap an engine callable ``fn(url) -> result with .to_dict()``."""

    def app(environ: dict, start_response) -> list[bytes]:
        if environ.get("REQUEST_METHOD") == "OPTIONS":
            start_response("204 No Content", _cors_headers())
            return [b""]
        if environ.get("REQUEST_METHOD") != "GET":
            return _json(start_response, "405 Method Not Allowed", {"error": "GET only"})
        if _rate_limited(environ):
            return _json(
                start_response,
                "429 Too Many Requests",
                {"error": "rate limit reached — retry in a minute"},
            )

        qs = parse_qs(environ.get("QUERY_STRING", ""))
        url = (qs.get("url") or [""])[0].strip()
        if not url:
            return _json(start_response, "400 Bad Request", {"error": "url required"})

        # Normalize and gate the target *before* scanning: http(s) only,
        # no cloud metadata, no private/loopback IPs, ever.
        try:
            from clickjacking_validator import normalize_url, validate_target

            normalized = normalize_url(url)
            validate_target(normalized, allow_private=False)
        except ValueError as exc:
            return _json(start_response, "400 Bad Request", {"error": str(exc)})

        result = runner(normalized)
        return _json(start_response, "200 OK", result.to_dict())

    return app
