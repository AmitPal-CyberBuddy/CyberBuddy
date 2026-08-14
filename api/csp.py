"""Hosted API: Content-Security-Policy audit (same engine as server.py)."""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from apilib import make_app  # noqa: E402
from csp_checker import scan_csp  # noqa: E402

app = make_app(lambda u: scan_csp(u, timeout=15.0, insecure=False, allow_private=False))
