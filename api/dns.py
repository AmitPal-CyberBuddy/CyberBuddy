"""Vercel file-based function: /api/dns — DNS & domain security scan.

Read-only DNS lookups against public resolvers; the target's own servers
are never contacted. The ``domain`` query parameter is validated as a
hostname (never a URL), and the result is the same ``DnsResult`` shape the
local ``server.py`` engine produces.
"""

import os
import sys
from urllib.parse import parse_qs

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apilib import _cors_headers, _json, _rate_limited  # noqa: E402
from dns_security import scan_dns  # noqa: E402


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
    domain = (qs.get("domain") or [""])[0].strip()
    if not domain:
        return _json(start_response, "400 Bad Request", {"error": "domain required"})

    result = scan_dns(domain)
    return _json(start_response, "200 OK", result.to_dict())
