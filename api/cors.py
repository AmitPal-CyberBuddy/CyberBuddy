"""Hosted API: two-origin CORS scan (same engine as server.py).

This is the one check a browser cannot do on its own — it sends two
crafted Origins from the server to prove reflection vs allowlist.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apilib import make_app  # noqa: E402
from cors_validator import scan_cors  # noqa: E402

app = make_app(lambda u: scan_cors(u, timeout=15.0, insecure=False, allow_private=False))
