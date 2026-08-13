"""Hosted API: health probe (the frontend uses this to detect the engine)."""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apilib import _json  # noqa: E402


def app(environ, start_response):
    return _json(start_response, "200 OK", {"ok": True})
