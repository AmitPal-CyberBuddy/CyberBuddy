"""Hosted API: security-headers scan (same engine as server.py)."""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apilib import make_app  # noqa: E402
from security_headers import scan_headers  # noqa: E402

app = make_app(lambda u: scan_headers(u, timeout=15.0, insecure=False, allow_private=False))
