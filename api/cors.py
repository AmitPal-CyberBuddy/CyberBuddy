"""Hosted API: method-aware CORS scan (same engine as server.py).

This is the one check a browser cannot do on its own — it sends crafted
Origins from the server to prove reflection vs allowlist, including
optional HEAD, OPTIONS and preflight probes. The analyst must select
additional methods for an authorized endpoint; the endpoint must exist
and may not support every method.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apilib import _cors_headers, _json, _rate_limited  # noqa: E402
from cors_validator import scan_cors  # noqa: E402
from urllib.parse import parse_qs  # noqa: E402


def _parse_methods(qs):
    methods = None
    if qs.get("methods"):
        raw = qs.get("methods")[0]
        if raw:
            methods = [m.strip() for m in raw.split(",") if m.strip()]
    preflight = None
    if qs.get("preflight"):
        raw = qs.get("preflight")[0]
        if raw:
            preflight = [m.strip() for m in raw.split(",") if m.strip()]
    preflight_headers = None
    if qs.get("preflight_headers"):
        raw = qs.get("preflight_headers")[0]
        if raw:
            preflight_headers = [h.strip() for h in raw.split(",") if h.strip()]
    return methods, preflight, preflight_headers


def app(environ, start_response):
    if environ.get("REQUEST_METHOD") == "OPTIONS":
        start_response("204 No Content", _cors_headers())
        return [b""]
    if environ.get("REQUEST_METHOD") != "GET":
        return _json(start_response, "405 Method Not Allowed", {"error": "GET only"})
    if _rate_limited(environ):
        return _json(start_response, "429 Too Many Requests", {"error": "rate limit reached — retry in a minute"})
    qs = parse_qs(environ.get("QUERY_STRING", ""))
    url = (qs.get("url") or [""])[0].strip()
    if not url:
        return _json(start_response, "400 Bad Request", {"error": "url required"})
    try:
        from clickjacking_validator import normalize_url, validate_target
        normalized = normalize_url(url)
        validate_target(normalized, allow_private=False)
    except ValueError as exc:
        return _json(start_response, "400 Bad Request", {"error": str(exc)})
    methods, preflight, preflight_headers = _parse_methods(qs)
    result = scan_cors(normalized, timeout=15.0, insecure=False, allow_private=False,
                       methods=methods, preflight_methods=preflight, preflight_headers=preflight_headers)
    return _json(start_response, "200 OK", result.to_dict())
