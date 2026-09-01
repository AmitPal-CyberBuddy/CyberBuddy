#!/usr/bin/env python3
"""Stdlib unit tests for CyberBuddy engines. Run: python3 -m unittest test_engines.py"""

from __future__ import annotations

import http.client
import json
import os
import re
import runpy
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
from unittest.mock import patch
from urllib.parse import quote
from email.message import Message
from http.server import ThreadingHTTPServer
from pathlib import Path

from clickjacking_validator import (
    Finding,
    assess_cookies,
    assess_frame_ancestors,
    assess_xfo,
    cookie_flag_notes,
    headers_from_message,
    normalize_url,
    parse_csp,
    score,
    validate_target,
)
from cors_validator import ATTACKER_A, ATTACKER_B, NULL_ORIGIN, scan_cors
from csp_checker import grade_csp_from_map, parse_policy, split_policies
from security_headers import (
    check_coep,
    check_cookies,
    check_csp,
    check_hsts,
    check_permissions,
    check_referrer,
    check_xfo,
    frame_ancestors_restricts,
    grade_for,
    grade_headers_from_map,
    summarize,
)
from server import ROOT, TOOL_ALIASES, _under_root, default_bind, is_loopback_bind, strip_mount


class NormalizeUrlTests(unittest.TestCase):
    def test_prepends_https(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")

    def test_keeps_http(self):
        self.assertEqual(normalize_url("http://127.0.0.1"), "http://127.0.0.1")

    def test_rejects_javascript(self):
        with self.assertRaises(ValueError):
            normalize_url("javascript:alert(1)")

    def test_rejects_file(self):
        with self.assertRaises(ValueError):
            normalize_url("file:///etc/passwd")

    def test_rejects_data(self):
        with self.assertRaises(ValueError):
            normalize_url("data:text/html,hi")

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            normalize_url("   ")


class CredentialRedactionTests(unittest.TestCase):
    """A credential-bearing URL must be rejected by the Python engine exactly
    as the hosted frontend rejects it, and a credential must never be echoed
    into a report, log or export — not even in the error result for a URL
    that was just rejected for carrying one."""

    def test_normalize_url_rejects_credentials(self):
        with self.assertRaises(ValueError):
            normalize_url("https://user:secret@example.com/")
        with self.assertRaises(ValueError):
            normalize_url("http://alice:password@127.0.0.1:8080/x")

    def test_redact_userinfo_strips_credentials(self):
        from clickjacking_validator import redact_userinfo

        self.assertEqual(
            redact_userinfo("https://user:secret@example.com/private?x=1"),
            "https://example.com/private?x=1",
        )
        self.assertEqual(redact_userinfo("https://example.com/"), "https://example.com/")

    def test_every_scan_rejects_and_redacts_credentials(self):
        """All four engines must neither accept a credential URL nor leak the
        credential in the resulting report (url, final_url, summary, detail)."""
        from clickjacking_validator import redact_userinfo, scan_url
        from cors_validator import scan_cors
        from csp_checker import scan_csp
        from security_headers import scan_headers

        target = "https://alice:hunter2@example.com/private"
        for fn in (scan_url, scan_headers, scan_cors, scan_csp):
            result = fn(target, timeout=5, insecure=False, allow_private=True)
            payload = json.dumps(result.to_dict())
            self.assertNotIn("hunter2", payload, fn.__name__)
            self.assertNotIn("alice", payload, fn.__name__)
            self.assertIn("remove the username and password", payload, fn.__name__)
            # The echoed URL is redacted to the origin, never the credential.
            self.assertIn("https://example.com/private", payload, fn.__name__)

    def test_server_log_redacts_the_url_param(self):
        from server import redact_log_target

        self.assertEqual(
            redact_log_target(
                'GET /api/headers?url=https%3A%2F%2Falice%3Ahunter2%40example.com%2F HTTP/1.1'
            ),
            "GET /api/headers?url=https%3A%2F%2Fexample.com%2F HTTP/1.1",
        )
        # No url param → untouched.
        self.assertEqual(
            redact_log_target("GET /api/health HTTP/1.1"),
            "GET /api/health HTTP/1.1",
        )


class ValidateTargetTests(unittest.TestCase):
    def test_blocks_metadata_ip(self):
        with self.assertRaises(ValueError):
            validate_target("http://169.254.169.254/latest/meta-data/", allow_private=True)

    def test_blocks_metadata_host(self):
        with self.assertRaises(ValueError):
            validate_target("http://metadata.google.internal/", allow_private=True)

    def test_blocks_unspecified(self):
        with self.assertRaises(ValueError):
            validate_target("http://0.0.0.0/", allow_private=True)

    def test_allows_loopback_when_private_ok(self):
        validate_target("http://127.0.0.1/", allow_private=True)

    def test_blocks_loopback_when_public_only(self):
        with self.assertRaises(ValueError):
            validate_target("http://127.0.0.1/", allow_private=False)

    def test_blocks_rfc1918_when_public_only(self):
        with self.assertRaises(ValueError):
            validate_target("http://192.168.1.1/", allow_private=False)

    def test_allows_rfc1918_when_private_ok(self):
        validate_target("http://10.0.0.1/", allow_private=True)


class ScoreTests(unittest.TestCase):
    def test_frame_ancestors_star_beats_xfo_deny(self):
        findings = [
            assess_xfo("DENY"),
            assess_frame_ancestors("frame-ancestors *"),
        ]
        risk, summary = score(findings)
        self.assertEqual(risk, "high")
        self.assertIn("frame-ancestors", summary.lower())

    def test_effective_xfo_is_low_with_csp_gap_as_recommendation(self):
        findings = [
            assess_xfo("DENY"),
            assess_frame_ancestors("default-src 'self'"),
        ]
        risk, summary = score(findings)
        self.assertEqual(risk, "low")
        self.assertIn("defense-in-depth", summary)
        self.assertIn("frame-ancestors", summary)

    def test_fa_none_is_low(self):
        findings = [
            assess_xfo(None),
            assess_frame_ancestors("frame-ancestors 'none'"),
        ]
        risk, _ = score(findings)
        self.assertEqual(risk, "low")

    def test_neither_is_high(self):
        findings = [assess_xfo(None), assess_frame_ancestors(None)]
        risk, _ = score(findings)
        self.assertEqual(risk, "high")


class MultipleCspFrameAncestorsTests(unittest.TestCase):
    def test_multiple_csp_with_restrictive_wins(self):
        # Multiple CSP headers combine restrictively — a restrictive policy in any header still blocks framing
        csp = "frame-ancestors 'none'\nframe-ancestors *"
        result = assess_frame_ancestors(csp)
        self.assertEqual(result.status, "protected")
        # Reverse order also protected
        csp2 = "frame-ancestors *\nframe-ancestors 'none'"
        result2 = assess_frame_ancestors(csp2)
        self.assertEqual(result2.status, "protected")
        # Both permissive -> weak
        csp3 = "frame-ancestors *\nframe-ancestors *"
        result3 = assess_frame_ancestors(csp3)
        self.assertEqual(result3.status, "weak")
        # One missing + one permissive -> weak (no restrictive)
        csp4 = "default-src 'self'\nframe-ancestors *"
        result4 = assess_frame_ancestors(csp4)
        self.assertEqual(result4.status, "weak")
        # Both missing -> missing
        csp5 = "default-src 'self'\nscript-src 'self'"
        result5 = assess_frame_ancestors(csp5)
        self.assertEqual(result5.status, "missing")
        # JS parity check
        import shutil, tempfile, subprocess, json, os
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        script = (
            "const document = { documentElement: { classList: { add() {} } } };\n"
            "const window = { __cbEngine: {}, location: { origin: 'https://example.test', pathname: '/' }, addEventListener() {} };\n"
            "const localStorage = { getItem(){return null;}, setItem(){}, removeItem(){} };\n"
            "const sessionStorage = localStorage;\n"
            + (ROOT / "js" / "app.js").read_text(encoding="utf-8")
            + "\nconsole.log(JSON.stringify({a: assessFrameAncestors('frame-ancestors \\'none\\'' + String.fromCharCode(10) + 'frame-ancestors *').status, b: assessFrameAncestors('frame-ancestors *').status}));\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script); p = fh.name
        try:
            proc = subprocess.run([node, p], capture_output=True, text=True, timeout=15)
        finally:
            os.unlink(p)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(out["a"], "protected")
        self.assertEqual(out["b"], "weak")

class OutcomeRollupTests(unittest.TestCase):
    def _cors_result(self, first_headers, second_headers, null_headers=None):
        responses = [
            (200, "https://api.example.test/data", first_headers),
            (200, "https://api.example.test/data", second_headers),
            (200, "https://api.example.test/data", null_headers or {}),
        ]
        with (
            patch("cors_validator.validate_target"),
            patch("cors_validator.fetch_headers", side_effect=responses),
        ):
            return scan_cors("https://api.example.test/data")

    def test_fixed_cors_allowlist_with_vary_gap_stays_low(self):
        """A Vary recommendation must not outrank the two-origin outcome."""
        fixed = {
            "access-control-allow-origin": "https://trusted.example",
            "access-control-allow-credentials": "true",
        }
        result = self._cors_result(fixed, fixed)
        statuses = {check.name: check.status for check in result.checks}
        self.assertEqual(statuses["Vary: Origin"], "weak")
        self.assertEqual(result.risk, "low")
        self.assertIn("No arbitrary-origin reflection", result.summary)

    def test_cors_absent_headers_indicates_pass(self):
        result = self._cors_result({}, {})
        self.assertEqual(result.risk, "low")
        self.assertIn("Pass", result.summary)

    def test_reflection_outcomes_remain_medium_and_high(self):
        reflected_a = {"access-control-allow-origin": ATTACKER_A, "vary": "Origin"}
        reflected_b = {"access-control-allow-origin": ATTACKER_B, "vary": "Origin"}
        self.assertEqual(self._cors_result(reflected_a, reflected_b).risk, "medium")
        reflected_a["access-control-allow-credentials"] = "true"
        reflected_b["access-control-allow-credentials"] = "true"
        self.assertEqual(self._cors_result(reflected_a, reflected_b).risk, "high")

    def test_null_origin_reflection_is_medium_or_high(self):
        null_only = {"access-control-allow-origin": NULL_ORIGIN, "vary": "Origin"}
        medium = self._cors_result({}, {}, null_only)
        self.assertEqual(medium.risk, "medium")
        self.assertIn("null Origin", medium.summary)
        self.assertIn("Access-Control-Allow-Origin: null", {c.name for c in medium.checks})
        null_only["access-control-allow-credentials"] = "true"
        self.assertEqual(self._cors_result({}, {}, null_only).risk, "high")

    def test_strong_csp_with_reporting_only_gaps_stays_low(self):
        policy = (
            "default-src 'none'; script-src 'nonce-random' 'strict-dynamic'; "
            "style-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        result = grade_csp_from_map(
            "https://example.test", 200, "https://example.test",
            {
                "content-security-policy": policy,
                "content-security-policy-report-only": "default-src 'self'",
            },
        )
        statuses = {check.name: check.status for check in result.checks}
        self.assertEqual(statuses["Report-only policy"], "info")
        self.assertEqual(statuses["Violation reporting"], "info")
        self.assertEqual(result.risk, "low")

    def test_optional_header_gaps_alone_stay_in_low_band(self):
        """Missing best-practice isolation headers cannot push a protected
        baseline below B/low by themselves."""
        result = grade_headers_from_map(
            "https://example.test", 200, "https://example.test",
            {
                "content-security-policy": (
                    "default-src 'self'; script-src 'self'; object-src 'none'; "
                    "frame-ancestors 'none'"
                ),
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
            },
        )
        self.assertEqual(result.score, 75)
        self.assertEqual(result.grade, "B")
        self.assertEqual(result.risk, "low")


class CorsMethodAwareTests(unittest.TestCase):
    """Method-aware CORS: GET baseline, HEAD/OPTIONS, preflight, per-method null, unassessed, rollup, Vary isolation, and export coverage."""

    def _mock_cors(self, method_map, preflight_map=None):
        def _side_effect(url, timeout=15, insecure=False, allow_private=True, extra_headers=None, method="GET"):
            extra_headers = extra_headers or {}
            origin = extra_headers.get("Origin", "")
            acrm = extra_headers.get("Access-Control-Request-Method", "")
            if method == "OPTIONS" and acrm:
                key = acrm.upper()
                if preflight_map and key in preflight_map:
                    hdr_a, hdr_b, hdr_null = preflight_map[key]
                    if origin == ATTACKER_A:
                        return (200, "https://api.example.test/data", hdr_a)
                    elif origin == ATTACKER_B:
                        return (200, "https://api.example.test/data", hdr_b)
                    elif origin == NULL_ORIGIN:
                        return (200, "https://api.example.test/data", hdr_null)
                return (200, "https://api.example.test/data", {})
            else:
                m = method.upper()
                if m in method_map:
                    hdr_a, hdr_b, hdr_null = method_map[m]
                    if origin == ATTACKER_A:
                        return (200, "https://api.example.test/data", hdr_a)
                    elif origin == ATTACKER_B:
                        return (200, "https://api.example.test/data", hdr_b)
                    elif origin == NULL_ORIGIN:
                        return (200, "https://api.example.test/data", hdr_null)
                return (200, "https://api.example.test/data", {})
        return _side_effect

    def test_get_absent_but_preflight_reflects_is_high(self):
        from unittest.mock import patch
        get_map = {"GET": ({}, {}, {})}
        pre_map = {"POST": ({"access-control-allow-origin": ATTACKER_A, "access-control-allow-credentials": "true", "vary": "Origin"},
                            {"access-control-allow-origin": ATTACKER_B, "access-control-allow-credentials": "true", "vary": "Origin"},
                            {"access-control-allow-origin": NULL_ORIGIN, "vary": "Origin"})}
        with patch("cors_validator.validate_target"), patch("cors_validator.fetch_headers", side_effect=self._mock_cors(get_map, pre_map)):
            result = scan_cors("https://api.example.test/data", methods=["GET"], preflight_methods=["POST"])
        self.assertEqual(result.risk, "high")
        self.assertIn("preflight", result.summary.lower())
        self.assertIn("preflight:POST", result.tested_methods)
        found_null = any("null" in (c.name.lower()) for c in result.checks)
        self.assertTrue(found_null)

    def test_get_safe_but_head_vulnerable(self):
        from unittest.mock import patch
        get_map = {"GET": ({}, {}, {})}
        head_map = {"HEAD": ({"access-control-allow-origin": ATTACKER_A, "vary": "Origin"},
                             {"access-control-allow-origin": ATTACKER_B, "vary": "Origin"},
                             {})}
        combined = {**get_map, **head_map}
        with patch("cors_validator.validate_target"), patch("cors_validator.fetch_headers", side_effect=self._mock_cors(combined)):
            result = scan_cors("https://api.example.test/data", methods=["GET", "HEAD"])
        self.assertEqual(result.risk, "medium")
        self.assertIn("HEAD", result.summary)
        self.assertIn("HEAD", result.tested_methods)

    def test_get_safe_but_options_vulnerable_with_credentials(self):
        from unittest.mock import patch
        get_map = {"GET": ({}, {}, {})}
        opt_map = {"OPTIONS": ({"access-control-allow-origin": ATTACKER_A, "access-control-allow-credentials": "true", "vary": "Origin"},
                                {"access-control-allow-origin": ATTACKER_B, "access-control-allow-credentials": "true", "vary": "Origin"},
                                {})}
        combined = {**get_map, **opt_map}
        with patch("cors_validator.validate_target"), patch("cors_validator.fetch_headers", side_effect=self._mock_cors(combined)):
            result = scan_cors("https://api.example.test/data", methods=["GET", "OPTIONS"])
        self.assertEqual(result.risk, "high")

    def test_per_method_null_reflection(self):
        from unittest.mock import patch
        get_map = {"GET": ({}, {}, {"access-control-allow-origin": NULL_ORIGIN, "vary": "Origin"})}
        head_map = {"HEAD": ({}, {}, {"access-control-allow-origin": NULL_ORIGIN, "access-control-allow-credentials": "true", "vary": "Origin"})}
        combined = {**get_map, **head_map}
        with patch("cors_validator.validate_target"), patch("cors_validator.fetch_headers", side_effect=self._mock_cors(combined)):
            result = scan_cors("https://api.example.test/data", methods=["GET", "HEAD"])
        self.assertEqual(result.risk, "high")
        null_checks = [c for c in result.checks if "null" in c.name.lower()]
        self.assertGreaterEqual(len(null_checks), 2)

    def test_unsupported_head_is_unassessed_not_safe(self):
        from unittest.mock import patch
        def side(url, timeout=15, insecure=False, allow_private=True, extra_headers=None, method="GET"):
            if method == "HEAD":
                return (405, "https://api.example.test/data", {})
            return (200, "https://api.example.test/data", {})
        with patch("cors_validator.validate_target"), patch("cors_validator.fetch_headers", side_effect=side):
            result = scan_cors("https://api.example.test/data", methods=["GET", "HEAD"])
        self.assertIn("HEAD", result.unassessed_methods)
        self.assertNotIn("HEAD", result.tested_methods)
        self.assertEqual(result.risk, "low")
        self.assertIn("unassessed", result.summary.lower())

    def test_unsupported_options_is_unassessed(self):
        from unittest.mock import patch
        def side(url, timeout=15, insecure=False, allow_private=True, extra_headers=None, method="GET"):
            if method == "OPTIONS" and not extra_headers.get("Access-Control-Request-Method"):
                return (501, "https://api.example.test/data", {})
            return (200, "https://api.example.test/data", {})
        with patch("cors_validator.validate_target"), patch("cors_validator.fetch_headers", side_effect=side):
            result = scan_cors("https://api.example.test/data", methods=["GET", "OPTIONS"])
        self.assertIn("OPTIONS", result.unassessed_methods)
        self.assertEqual(result.risk, "low")

    def test_one_risky_selected_method_rolls_up(self):
        from unittest.mock import patch
        get_map = {"GET": ({}, {}, {})}
        head_map = {"HEAD": ({"access-control-allow-origin": ATTACKER_A, "access-control-allow-credentials": "true"},
                             {"access-control-allow-origin": ATTACKER_B, "access-control-allow-credentials": "true"},
                             {})}
        opt_map = {"OPTIONS": ({}, {}, {})}
        combined = {**get_map, **head_map, **opt_map}
        with patch("cors_validator.validate_target"), patch("cors_validator.fetch_headers", side_effect=self._mock_cors(combined)):
            result = scan_cors("https://api.example.test/data", methods=["GET", "HEAD", "OPTIONS"])
        self.assertEqual(result.risk, "high")
        self.assertIn("HEAD", result.summary)

    def test_vary_never_drives_headline_risk(self):
        from unittest.mock import patch
        fixed = {"access-control-allow-origin": "https://trusted.example", "access-control-allow-credentials": "true"}
        get_map = {"GET": (fixed, fixed, {})}
        head_map = {"HEAD": (fixed, fixed, {})}
        combined = {**get_map, **head_map}
        with patch("cors_validator.validate_target"), patch("cors_validator.fetch_headers", side_effect=self._mock_cors(combined)):
            result = scan_cors("https://api.example.test/data", methods=["GET", "HEAD"])
        vary_checks = [c for c in result.checks if "Vary" in c.name]
        self.assertTrue(any(c.status == "weak" for c in vary_checks))
        self.assertEqual(result.risk, "low")

    def test_browser_single_origin_concrete_reflection_never_pass(self):
        import shutil, tempfile, subprocess, json, os, pathlib
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        harness = """
const origin = "https://cyberbuddy.example";
console.log(JSON.stringify({
  low: browserCorsRisk("https://trusted.example", "true", origin),
  medium: browserCorsRisk("https://cyberbuddy.example", "true", origin),
  wildcardLow: browserCorsRisk("*", "", origin),
  wildcardMedium: browserCorsRisk("*", "true", origin)
}));
"""
        script = (
            "const document = { documentElement: { classList: { add() {} } } };\n"
            "const window = { __cbEngine: {}, location: { origin: 'https://cyberbuddy.example', pathname: '/' }, addEventListener() {} };\n"
            "const localStorage = { getItem(){return null;}, setItem(){}, removeItem(){} };\n"
            "const sessionStorage = localStorage;\n"
            + pathlib.Path("js/app.js").read_text(encoding="utf-8")
            + harness
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script); p = fh.name
        try:
            proc = subprocess.run([node, p], capture_output=True, text=True, timeout=15)
        finally:
            os.unlink(p)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(result["low"], "low")
        self.assertEqual(result["medium"], "medium")
        self.assertNotEqual(result["medium"], "low")
        self.assertEqual(result["wildcardMedium"], "medium")
        self.assertEqual(result["wildcardLow"], "low")

    def test_exports_include_selected_and_tested_methods(self):
        from unittest.mock import patch
        get_map = {"GET": ({}, {}, {})}
        with patch("cors_validator.validate_target"), patch("cors_validator.fetch_headers", side_effect=self._mock_cors(get_map, {"POST": ({}, {}, {})})):
            result2 = scan_cors("https://api.example.test/data", methods=["GET", "HEAD"], preflight_methods=["POST"], preflight_headers=["Content-Type"])
            d = result2.to_dict()
            self.assertIn("methods", d)
            self.assertIn("preflight_methods", d)
            self.assertIn("preflight_headers", d)
            self.assertIn("tested_methods", d)
            self.assertIn("method_results", d)
            self.assertIn("coverage", d)
            self.assertEqual(d["preflight_headers"], ["Content-Type"])
            self.assertIn("GET", d["methods"])
            self.assertIn("HEAD", d["methods"])
        self.assertIn("preflight:POST", d["tested_methods"])

    def test_no_global_pass_when_only_get(self):
        from unittest.mock import patch
        with patch("cors_validator.validate_target"), patch("cors_validator.fetch_headers", side_effect=lambda *a, **k: (200, "https://api.example.test/data", {})):
            result = scan_cors("https://api.example.test/data", methods=["GET"])
        self.assertEqual(result.risk, "low")
        self.assertIn("No risky CORS behavior observed for GET", result.summary)
        self.assertNotIn("all tested methods", result.summary.lower())
        self.assertIn("GET only", result.summary)


class CorsBrowserPocTests(unittest.TestCase):
    """Local CORS browser HTML PoC — not a scanner feature.

    The generator lives in js/tool.cors.js as CyberBuddyCorsPoc (no DOM, no
    network). A reflected ACAO header is server behaviour; the downloaded
    page is a TEST ARTIFACT the analyst hosts on an origin they control.
    """

    def _run_poc(self, harness: str):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        script = (ROOT / "js" / "tool.cors.js").read_text(encoding="utf-8") + "\n" + harness
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run(
                [node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=30,
            )
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def test_rejects_empty_non_http_and_credentials(self):
        out = self._run_poc(r'''
const C = globalThis.CyberBuddyCorsPoc;
const rows = {};
["", "javascript:alert(1)", "data:text/html,x", "https://user:pass@example.com/"].forEach((url, i) => {
  rows[i] = C.generatePocHtml({ url: url });
});
console.log(JSON.stringify(rows));
''')
        for key, row in out.items():
            self.assertFalse(row["ok"], row)

    def test_generated_html_is_a_manual_test_artifact(self):
        out = self._run_poc(r'''
const C = globalThis.CyberBuddyCorsPoc;
const gen = C.generatePocHtml({ url: "https://api.example.com/account?x=</script><script>alert(1)" });
console.log(JSON.stringify(gen));
''')
        self.assertTrue(out["ok"], out)
        html = out["html"]
        self.assertIn("TEST ARTIFACT", html)
        self.assertIn("not a finding", html.lower())
        self.assertIn("Authorized testing only", html)
        self.assertIn("credentials: \"include\"", html)
        self.assertIn('method: "GET"', html)
        self.assertIn("Run credentialed GET", html)
        self.assertNotIn("</script><script>", html)
        self.assertIn("%3C/script%3E", html)
        self.assertLess(html.index('addEventListener("click"'), html.index("fetch("))
        self.assertNotIn("onload=", html.lower())
        self.assertEqual(out["filename"], "cyberbuddy-cors-poc.html")

    def test_hosted_page_has_local_poc_builder_not_acrh_input(self):
        page = (ROOT / "tools" / "cors" / "index.html").read_text(encoding="utf-8")
        js = (ROOT / "js" / "tool.cors.js").read_text(encoding="utf-8")
        self.assertNotIn("corsPreflightHeaders", page)
        self.assertNotIn("corsPreflightHeaders", js)
        self.assertIn("corsPocBuild", page)
        self.assertIn("TEST ARTIFACT", page)
        self.assertIn("--preflight-headers", page)


class CspTests(unittest.TestCase):
    def test_default_src_star_is_weak(self):
        c = check_csp("default-src *")
        self.assertEqual(c.status, "weak")
        self.assertGreater(c.deduction, 0)

    def test_script_src_elem_unsafe_inline(self):
        c = check_csp("script-src-elem 'unsafe-inline'")
        self.assertEqual(c.status, "weak")

    def test_script_src_overrides_default_unsafe_inline(self):
        c = check_csp("default-src 'unsafe-inline'; script-src 'self'")
        self.assertEqual(c.status, "ok")

    def test_missing_script_and_default(self):
        c = check_csp("style-src 'self'")
        self.assertEqual(c.status, "weak")
        self.assertIn("script-src", c.detail)

    def test_strict_csp_ok(self):
        c = check_csp("default-src 'self'; frame-ancestors 'none'")
        self.assertEqual(c.status, "ok")

    def test_parse_csp(self):
        d = parse_csp("default-src 'self'; FRAME-ANCESTORS 'NONE'")
        self.assertEqual(d["frame-ancestors"], ["'none'"])


class CspAuditorTests(unittest.TestCase):
    def test_missing_enforced_policy_is_high_risk(self):
        result = grade_csp_from_map("https://example.test", 200, "https://example.test", {})
        self.assertEqual(result.risk, "high")
        self.assertEqual(result.checks[0].name, "Enforced response policy")
        self.assertEqual(result.checks[0].status, "missing")

    def test_report_only_policy_does_not_enforce(self):
        result = grade_csp_from_map(
            "https://example.test", 200, "https://example.test",
            {"content-security-policy-report-only": "default-src 'self'"},
        )
        statuses = {check.name: check.status for check in result.checks}
        self.assertEqual(statuses["Enforced response policy"], "missing")
        self.assertEqual(statuses["Report-only policy"], "info")

    def test_nonce_strict_dynamic_legacy_fallback_is_not_false_positive(self):
        result = grade_csp_from_map(
            "https://example.test", 200, "https://example.test",
            {"content-security-policy": (
                "default-src 'none'; script-src 'nonce-random' 'strict-dynamic' 'unsafe-inline'; "
                "style-src 'self'; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'self'"
            )},
        )
        statuses = {check.name: check.status for check in result.checks}
        self.assertEqual(result.risk, "low")
        self.assertEqual(statuses["Script execution"], "info")

    def test_duplicate_directive_uses_first_and_is_reported(self):
        directives, duplicates = parse_policy("script-src 'self'; script-src *")
        self.assertEqual(directives["script-src"], ["'self'"])
        self.assertEqual(duplicates, ["script-src"])

    def test_repeated_policies_remain_separate(self):
        policies = split_policies("default-src *\ndefault-src 'none'")
        self.assertEqual(policies, ["default-src *", "default-src 'none'"])
        result = grade_csp_from_map(
            "https://example.test", 200, "https://example.test",
            {"content-security-policy": (
                "default-src *; script-src * 'unsafe-inline'\n"
                "default-src 'none'; script-src 'none'; style-src 'none'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
            )},
        )
        self.assertEqual(result.risk, "low")


class XfoCspInteractionTests(unittest.TestCase):
    def test_missing_xfo_without_fa_full_deduction(self):
        c = check_xfo(None, False)
        self.assertEqual(c.deduction, 15)
        self.assertNotIn("covers framing", c.detail)

    def test_missing_xfo_with_fa_small_deduction(self):
        c = check_xfo(None, True)
        self.assertEqual(c.deduction, 5)
        self.assertIn("frame-ancestors", c.detail)

    def test_fa_star_does_not_count_as_restricts(self):
        self.assertFalse(frame_ancestors_restricts("frame-ancestors *"))
        self.assertTrue(frame_ancestors_restricts("frame-ancestors 'none'"))
        self.assertFalse(frame_ancestors_restricts("default-src 'self'"))


class HeaderCheckTests(unittest.TestCase):
    def test_hsts_max_age_zero(self):
        c = check_hsts("max-age=0", True)
        self.assertEqual(c.status, "missing")
        self.assertEqual(c.deduction, 15)

    def test_hsts_strong(self):
        c = check_hsts("max-age=31536000; includeSubDomains", True)
        self.assertEqual(c.status, "ok")

    def test_coep_credentialless(self):
        c = check_coep("credentialless")
        self.assertEqual(c.status, "ok")

    def test_coep_unsafe_none(self):
        c = check_coep("unsafe-none")
        self.assertEqual(c.status, "weak")

    def test_referrer_origin_ok(self):
        self.assertEqual(check_referrer("origin").status, "ok")
        self.assertEqual(check_referrer("origin-when-cross-origin").status, "ok")

    def test_referrer_unsafe(self):
        self.assertEqual(check_referrer("unsafe-url").status, "weak")

    def test_permissions_paren_wildcard(self):
        c = check_permissions("geolocation=(*)")
        self.assertEqual(c.status, "weak")

    def test_permissions_bare_wildcard(self):
        c = check_permissions("geolocation=*")
        self.assertEqual(c.status, "weak")

    def test_permissions_self_ok(self):
        c = check_permissions("geolocation=(self)")
        self.assertEqual(c.status, "ok")

    def test_grade_for(self):
        self.assertEqual(grade_for(95), "A")
        self.assertEqual(grade_for(80), "B")
        self.assertEqual(grade_for(10), "F")

    def test_summarize_lists_missing(self):
        text = summarize("C", ["HSTS", "CSP"])
        self.assertIn("HSTS", text)


class CookieTests(unittest.TestCase):
    def test_substring_secure_is_not_a_flag(self):
        notes = cookie_flag_notes("session=securetoken")
        self.assertTrue(any("Secure" in n for n in notes))

    def test_insecure_name_is_not_a_flag(self):
        notes = cookie_flag_notes("insecure=1")
        self.assertTrue(any("Secure" in n for n in notes))

    def test_real_flags_ok(self):
        notes = cookie_flag_notes("sid=abc; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(notes, [])

    def test_multiple_cookies(self):
        notes = cookie_flag_notes("a=1; Secure; HttpOnly; SameSite=Lax\nb=2")
        self.assertTrue(any(n.startswith("b:") for n in notes))

    def test_headers_from_message_keeps_all_set_cookie(self):
        msg = Message()
        msg["Set-Cookie"] = "a=1"
        msg["Set-Cookie"] = "b=2"
        msg["Content-Security-Policy"] = "default-src 'self'"
        msg["Content-Security-Policy"] = "frame-ancestors 'none'"
        msg["X-Frame-Options"] = "DENY"
        hdrs = headers_from_message(msg)
        self.assertIn("a=1", hdrs["set-cookie"])
        self.assertIn("b=2", hdrs["set-cookie"])
        self.assertEqual(
            hdrs["content-security-policy"],
            "default-src 'self'\nframe-ancestors 'none'",
        )
        self.assertEqual(hdrs["x-frame-options"], "DENY")

    def test_assess_cookies_uses_tokens(self):
        f = assess_cookies("session=securetoken")
        self.assertIn("Secure", f.detail)

    def test_check_cookies_ok(self):
        c = check_cookies("sid=x; Secure; HttpOnly; SameSite=Strict")
        self.assertEqual(c.status, "ok")


class StaticPathTests(unittest.TestCase):
    def test_repo_file_is_under_root(self):
        self.assertTrue(_under_root((ROOT / "server.py").resolve()))

    def test_outside_repo_is_not(self):
        self.assertFalse(_under_root((ROOT / ".." / ".." / "etc" / "passwd").resolve()))


class MountAndBindTests(unittest.TestCase):
    def test_strip_mount_github_pages_prefix(self):
        self.assertEqual(strip_mount("/CyberBuddy"), "/")
        self.assertEqual(strip_mount("/CyberBuddy/"), "/")
        self.assertEqual(strip_mount("/CyberBuddy/tools/headers/"), "/tools/headers/")
        self.assertEqual(strip_mount("/CyberBuddy/api/headers"), "/api/headers")
        self.assertEqual(strip_mount("/tools/cors/"), "/tools/cors/")
        self.assertEqual(strip_mount("/CyberBuddy/tools/csp/"), "/tools/csp/")

    def test_tool_aliases_cover_all_tools(self):
        self.assertEqual(TOOL_ALIASES["/headers"], "/tools/headers/")
        self.assertEqual(TOOL_ALIASES["/cors"], "/tools/cors/")
        self.assertEqual(TOOL_ALIASES["/csp"], "/tools/csp/")
        self.assertEqual(TOOL_ALIASES["/clickjacking"], "/tools/clickjacking/")
        self.assertEqual(TOOL_ALIASES["/csrf"], "/tools/csrf/")
        # JWT-00 preview alias.
        self.assertEqual(TOOL_ALIASES["/jwt"], "/tools/jwt/")
        self.assertEqual(TOOL_ALIASES["/jwt/"], "/tools/jwt/")
        # DNS & Domain Security Analyzer alias.
        self.assertEqual(TOOL_ALIASES["/dns"], "/tools/dns/")
        self.assertEqual(TOOL_ALIASES["/dns/"], "/tools/dns/")

    def test_all_loopback_address_forms_are_recognized(self):
        for host in ("localhost", "LOCALHOST.", "127.0.0.1", "127.0.0.2", "::1", "::1%lo0"):
            with self.subTest(host=host):
                self.assertTrue(is_loopback_bind(host))
        for host in ("0.0.0.0", "::", "192.0.2.1", "example.com"):
            with self.subTest(host=host):
                self.assertFalse(is_loopback_bind(host))

    def test_default_bind_loopback_without_port_env(self):
        env = os.environ
        old_port, old_host = env.get("PORT"), env.get("HOST")
        env.pop("PORT", None)
        env.pop("HOST", None)
        try:
            host, port = default_bind()
            self.assertEqual(host, "127.0.0.1")
            self.assertEqual(port, 8080)
        finally:
            if old_port is not None:
                env["PORT"] = old_port
            if old_host is not None:
                env["HOST"] = old_host

    def test_default_bind_paas_port(self):
        env = os.environ
        old_port, old_host = env.get("PORT"), env.get("HOST")
        env["PORT"] = "3000"
        env.pop("HOST", None)
        try:
            host, port = default_bind()
            self.assertEqual(host, "0.0.0.0")
            self.assertEqual(port, 3000)
        finally:
            if old_port is None:
                env.pop("PORT", None)
            else:
                env["PORT"] = old_port
            if old_host is not None:
                env["HOST"] = old_host


class AppBaseJsTests(unittest.TestCase):
    def test_js_uses_pathname_not_full_url_index(self):
        src = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("path.endsWith(marker)", src)
        self.assertNotIn("pathname.slice(0, idx)", src)
        self.assertIn("application/json", src)
        self.assertIn("gradeHeadersFromMap", src)
        self.assertIn("gradeCspFromMap", src)
        self.assertIn("apiCsp", src)
        self.assertIn("lookupHeadersLive", src)
        self.assertIn("probeCorsLive", src)
        # Hosted cache must join appBase() with a leading slash or Pages
        # fetches /CyberBuddycache/... instead of /CyberBuddy/cache/...
        self.assertIn('appBase() + "/cache/"', src)
        self.assertNotIn('appBase() + "cache/"', src)
        self.assertIn("cacheLookupKeys", src)

    def test_tool_pages_exist(self):
        for slug in ("clickjacking", "headers", "cors", "csp", "csrf", "jwt", "dns"):
            page = ROOT / "tools" / slug / "index.html"
            self.assertTrue(page.is_file(), page)
            text = page.read_text(encoding="utf-8")
            self.assertIn("js/app.js", text)
        # The JWT preview also loads its own (non-operational) controller.
        self.assertIn("js/tool.jwt.js", (ROOT / "tools" / "jwt" / "index.html").read_text(encoding="utf-8"))
        # The DNS tool loads its own controller too.
        self.assertIn("js/tool.dns.js", (ROOT / "tools" / "dns" / "index.html").read_text(encoding="utf-8"))

    def test_csp_controller_only_references_existing_elements(self):
        page = (ROOT / "tools" / "csp" / "index.html").read_text(encoding="utf-8")
        controller = (ROOT / "js" / "tool.csp.js").read_text(encoding="utf-8")
        referenced = set(re.findall(r'\$\("([A-Za-z][A-Za-z0-9_-]*)"\)', controller))
        self.assertGreater(len(referenced), 15)
        for element_id in referenced:
            self.assertIn(f'id="{element_id}"', page, element_id)

    def test_four_oh_four_repairs_old_hosted_urls(self):
        # The repair logic lives in js/404-boot.js (externalised so the site
        # can ship a CSP without 'unsafe-inline'); 404.html must load it.
        page = (ROOT / "404.html").read_text(encoding="utf-8")
        self.assertIn("js/404-boot.js", page)
        text = (ROOT / "js" / "404-boot.js").read_text(encoding="utf-8")
        self.assertIn("js\\/app\\.js", text)
        self.assertIn("/tools/$1/", text)
        self.assertIn("headers|cors|csp|csrf|jwt|dns", text)

    def test_js_graders_match_python_scores(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import tempfile
        script = (
            "const document = { documentElement: { classList: { add() {} } } };\n"
            "const window = { __cbEngine: {}, location: { origin: 'https://example.test', pathname: '/' }, addEventListener() {} };\n"
            + (ROOT / "js" / "app.js").read_text(encoding="utf-8")
            + r"""
const hdrs = {
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  "x-frame-options": "DENY",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin"
};
const r = gradeHeadersFromMap("https://example.com", 200, "https://example.com", hdrs, "relay");
const cj = gradeClickjackingFromMap("https://example.com", 200, "https://example.com", hdrs, "relay");
const dump = parseRawHeaderDump("HTTP/1.1 200 OK\nX-Frame-Options: DENY\nContent-Type: text/html\n");
if (r.score < 70) throw new Error("headers score " + r.score);
if (cj.risk !== "low") throw new Error("clickjacking " + cj.risk);
if (dump.headers["x-frame-options"] !== "DENY") throw new Error("dump");
console.log(JSON.stringify({ grade: r.grade, score: r.score, risk: cj.risk }));
"""
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run(
                [node, path],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=15,
            )
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertGreaterEqual(payload["score"], 70)
        self.assertEqual(payload["risk"], "low")


class BrowserUxContractTests(unittest.TestCase):
    def _run_app_js(self, harness: str):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import tempfile

        script = (
            "const document = { documentElement: { classList: { add() {} } } };\n"
            "const window = { __cbEngine: {}, location: { origin: 'https://example.test', "
            "pathname: '/' }, addEventListener() {} };\n"
            "const localStorage = { getItem(){return null;}, setItem(){}, removeItem(){} };\n"
            "const sessionStorage = localStorage;\n"
            + (ROOT / "js" / "app.js").read_text(encoding="utf-8")
            + "\n" + harness
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as handle:
            handle.write(script)
            path = handle.name
        try:
            process = subprocess.run(
                [node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=30,
            )
        finally:
            os.unlink(path)
        self.assertEqual(process.returncode, 0, process.stderr)
        return json.loads(process.stdout.strip().splitlines()[-1])

    def test_url_accept_reject_and_feedback_contract(self):
        rows = self._run_app_js(r'''
const values = [
  "example.com", "localhost:8080", "localhost", "127.0.0.1:8080",
  "192.168.1.20", "  'example.org.'  ",
  "", "https://[bad", "ftp://example.com", "javascript:alert(1)",
  "data:text/html,hi", "httpss://example.com", "search words",
  "example", "a..b", "-.com", "https://user:secret@example.com"
];
console.log(JSON.stringify(values.map((value) => ({ value, ...urlValidation(value) }))));
''')
        by_value = {row["value"]: row for row in rows}
        expected = {
            "example.com": "https://example.com",
            "localhost:8080": "http://localhost:8080",
            "localhost": "http://localhost",
            "127.0.0.1:8080": "http://127.0.0.1:8080",
            "192.168.1.20": "https://192.168.1.20",
            "  'example.org.'  ": "https://example.org",
        }
        for raw, normalized in expected.items():
            with self.subTest(raw=raw):
                self.assertTrue(by_value[raw]["valid"])
                self.assertEqual(by_value[raw]["url"], normalized)
        rejected = {
            "": "empty",
            "https://[bad": "malformed",
            "ftp://example.com": "scheme",
            "javascript:alert(1)": "scheme",
            "data:text/html,hi": "scheme",
            "httpss://example.com": "scheme",
            "search words": "search",
            "example": "public-tld",
            "a..b": "empty-label",
            "-.com": "hyphen",
            "https://user:secret@example.com": "credentials",
        }
        for raw, code in rejected.items():
            with self.subTest(raw=raw):
                self.assertFalse(by_value[raw]["valid"])
                self.assertEqual(by_value[raw]["code"], code)
                self.assertTrue(by_value[raw]["message"])

    def test_dns_domain_validation_matches_idn_and_hostname_rules(self):
        rows = self._run_app_js(r'''
const values = [
  "пример.рф", "xn--e1afmkfd.xn--p1ai", "'example.com'", "“example.com”",
  "https://Example.COM/path", "example.com:443/path", "_dmarc.example.com", "example.c",
  "'example.com\"", "https://user:secret@example.com/path", "https://@example.com/path",
  "ftp://example.com", "https://example.com:not-a-port/path", "https://example.com:99999/path",
  "example.com:99999/path"
];
console.log(JSON.stringify(values.map((value) => ({ value, ...domainValidation(value) }))));
''')
        by_value = {row["value"]: row for row in rows}
        expected = "xn--e1afmkfd.xn--p1ai"
        accepted = {
            "пример.рф": expected,
            expected: expected,
            "'example.com'": "example.com",
            "“example.com”": "example.com",
            "https://Example.COM/path": "example.com",
            "example.com:443/path": "example.com",
        }
        for raw, normalized in accepted.items():
            with self.subTest(raw=raw):
                self.assertTrue(by_value[raw]["valid"])
                self.assertEqual(by_value[raw]["domain"], normalized)
        rejected = {
            "_dmarc.example.com": "hostname",
            "example.c": "public-tld",
            "'example.com\"": "hostname",
            "https://user:secret@example.com/path": "credentials",
            "https://@example.com/path": "credentials",
            "ftp://example.com": "scheme",
            "https://example.com:not-a-port/path": "malformed",
            "https://example.com:99999/path": "malformed",
            "example.com:99999/path": "malformed",
        }
        for raw, code in rejected.items():
            with self.subTest(raw=raw):
                self.assertFalse(by_value[raw]["valid"])
                self.assertEqual(by_value[raw]["code"], code)

    def test_dnskey_without_parent_ds_is_weak_in_browser_grader(self):
        result = self._run_app_js(r'''
const result = gradeDnsFromRecords("example.com", {
  A: ["203.0.113.10"], NS: ["ns1.example.com.", "ns2.example.com."],
  DNSKEY: ["flags=257 protocol=3 algorithm=13 keylen=64"]
}, { A: "NOERROR" }, "browser");
console.log(JSON.stringify(result.checks.find((check) => check.name === "DNSSEC")));
''')
        self.assertEqual(result["status"], "weak")
        self.assertEqual(result["deduction"], 10)
        self.assertIn("chain of trust is not established", result["detail"])

    def test_parent_ds_without_apex_dnskey_is_weak_in_browser_grader(self):
        result = self._run_app_js(r'''
const result = gradeDnsFromRecords("example.com", {
  A: ["203.0.113.10"], NS: ["ns1.example.com.", "ns2.example.com."],
  DS: ["12345 8 2 ABCDEF"]
}, { A: "NOERROR" }, "browser");
console.log(JSON.stringify(result.checks.find((check) => check.name === "DNSSEC")));
''')
        self.assertEqual(result["status"], "weak")
        self.assertEqual(result["deduction"], 10)
        self.assertIn("evidence is incomplete", result["detail"])

    def test_single_origin_browser_cors_ignores_vary_as_headline_risk(self):
        result = self._run_app_js(r'''
console.log(JSON.stringify({
  fixedAllowlist: browserCorsRisk("https://trusted.example", "true", "https://cyberbuddy.example"),
  reflectedCredentialed: browserCorsRisk("https://cyberbuddy.example", "true", "https://cyberbuddy.example"),
  nullCredentialed: browserCorsRisk("null", "true", "null"),
  nullPublic: browserCorsRisk("null", "", "null"),
  wildcardCredentials: browserCorsRisk("*", "true", "https://cyberbuddy.example"),
  wildcardPublic: browserCorsRisk("*", "", "https://cyberbuddy.example")
}));
''')
        self.assertEqual(result["fixedAllowlist"], "low")
        self.assertEqual(result["reflectedCredentialed"], "medium")
        self.assertEqual(result["nullCredentialed"], "high")
        self.assertEqual(result["nullPublic"], "medium")
        self.assertEqual(result["wildcardCredentials"], "medium")
        self.assertEqual(result["wildcardPublic"], "low")

    def test_posture_html_renders_counts_and_header_tags(self):
        html = self._run_app_js(r'''
const checks = [
  { name: "Content-Security-Policy", status: "missing", detail: "Absent" },
  { name: "X-Frame-Options", status: "missing", detail: "Absent" },
  { name: "Referrer-Policy", status: "weak", detail: "unsafe-url" },
  { name: "X-Content-Type-Options", status: "ok", detail: "nosniff" },
  { name: "Reporting", status: "info", detail: "no report-to" }
];
console.log(JSON.stringify({ html: postureHtml(checks) }));
''')["html"]
        self.assertIn('class="posture-counts"', html)
        self.assertIn('Missing · 2', html)
        self.assertIn('Weak · 1', html)
        self.assertIn('OK · 1', html)
        self.assertIn('Info · 1', html)
        self.assertIn('class="posture-tags"', html)
        self.assertIn('class="posture-tag tag-missing"', html)
        self.assertIn('Content-Security-Policy', html)
        self.assertIn('class="posture-tag tag-weak"', html)
        self.assertIn('Referrer-Policy', html)
        self.assertIn('class="posture-tag tag-ok"', html)
        self.assertIn('X-Content-Type-Options', html)
        self.assertIn('class="posture-tag tag-info"', html)

    def test_all_entry_points_use_shared_visible_validation(self):
        pages = [ROOT / "index.html"] + [
            ROOT / "tools" / slug / "index.html"
            for slug in ("clickjacking", "cors", "csp", "headers")
        ]
        for page in pages:
            with self.subTest(page=page):
                text = page.read_text(encoding="utf-8")
                self.assertIn('class="field-error hidden"', text)
                self.assertIn('role="alert"', text)
                self.assertIn("aria-describedby=", text)
        for controller in ("tool.clickjacking.js", "tool.cors.js", "tool.csp.js", "tool.headers.js"):
            text = (ROOT / "js" / controller).read_text(encoding="utf-8")
            self.assertIn('initUrlInput($("url"))', text)
            self.assertIn('validateUrlField($("url"))', text)
            self.assertNotIn("!validUrl", text)
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("initUrlInput(input)", app)
        self.assertIn("showUrlError(input, result.message)", app)
        self.assertIn('input.setAttribute("aria-invalid", "true")', app)

    def test_credential_urls_are_redacted_from_exports(self):
        result = self._run_app_js(r'''
const data = { url: "https://alice:secret@example.com/private", final_url: "https://bob:hunter2@example.net/",
  checks: [{ name: "Redirect", status: "info", detail: "Location: https://carol:password@example.org/next", evidence: "https://dave:key@example.net/" }] };
console.log(JSON.stringify({
  markdown: toMarkdown({ ...data, risk: "low", grade: "A", score: 100 }),
  csv: toCsv(data), html: toStandaloneHtml(data), envelope: reportExportEnvelope(data),
  safe: reportSafeCopy(data), redacted: redactUrlCredentials(data.url)
}));
''')
        serialized = json.dumps(result)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("alice", serialized)
        self.assertNotIn("bob", serialized)
        self.assertNotIn("carol", serialized)
        self.assertNotIn("password", serialized)
        self.assertNotIn("dave", serialized)
        self.assertEqual(result["redacted"], "https://example.com/private")

    def test_all_structured_export_formats_preserve_csp_findings(self):
        result = self._run_app_js(r'''
const data = {
  url: "https://example.com", final_url: "https://example.com/login", status_code: 200,
  risk: "high", summary: "Policy needs attention", _source: "python",
  policy: "default-src 'self'", report_only_policy: "script-src 'none'", directives: {},
  checks: [{ name: "Script execution", status: "weak", severity: "high",
    detail: "Allows broad sources", evidence: "script-src https:", recommendation: "Use a nonce." }]
};
console.log(JSON.stringify({
  markdown: toMarkdown(data), csv: toCsv(data), html: toStandaloneHtml(data),
  envelope: reportExportEnvelope(data)
}));
''')
        self.assertIn("Script execution", result["markdown"])
        self.assertIn("Use a nonce.", result["markdown"])
        self.assertIn("default-src 'self'", result["markdown"])
        self.assertIn("Script execution", result["csv"])
        self.assertIn("Use a nonce.", result["csv"])
        self.assertIn("Script execution", result["html"])
        self.assertIn("Content-Security-Policy", result["html"])
        self.assertNotIn("<script", result["html"].lower())
        self.assertEqual(result["envelope"]["schema_version"], "cyberbuddy-report/v1")
        self.assertEqual(result["envelope"]["tool"], "CSP Policy Auditor")
        self.assertEqual(result["envelope"]["assessment"]["checks"][0]["severity"], "high")

    def test_csv_export_neutralizes_spreadsheet_formulas(self):
        result = self._run_app_js(r'''
const data = { url: "https://example.com", risk: "high", _source: "python",
  checks: [{ name: "Injected", status: "weak", detail: "=HYPERLINK(\"https://evil.test\")", evidence: "+cmd", recommendation: "@payload" }] };
console.log(JSON.stringify({ csv: toCsv(data) }));
''')
        self.assertIn("'=HYPERLINK", result["csv"])
        self.assertIn("'+cmd", result["csv"])
        self.assertIn("'@payload", result["csv"])

    def test_unreachable_evidence_card_is_never_graded(self):
        result = self._run_app_js(r'''
const spec = buildEvidenceCardSpec({ url: "https://missing.example", status_code: null,
  risk: "unknown", _source: "browser", _unreachable: true,
  summary: "DNS reports NXDOMAIN", checks: [{ name: "Target reachability", status: "error", detail: "NXDOMAIN" }] }, "Security Headers");
console.log(JSON.stringify(spec));
''')
        self.assertEqual(result["hero"], "TARGET UNREACHABLE · NOT GRADED")
        self.assertEqual(result["rowsTitle"], "REACHABILITY EVIDENCE")
        self.assertNotIn("/100", result["hero"])

    def test_export_menu_has_no_screen_capture_path(self):
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        css = (ROOT / "css" / "app.css").read_text(encoding="utf-8")
        for removed in ("getDisplayMedia", "downloadPocImage", "canCapturePoc", 'data-act="poc"', "Download PoC image"):
            self.assertNotIn(removed, app)
        self.assertNotIn(".export-menu-item:disabled", css)
        self.assertIn('data-act="card"', app)

    def test_evidence_card_specs_are_tool_specific(self):
        specs = self._run_app_js(r'''
const base = { url: "https://example.com", final_url: "https://example.com", status_code: 200, risk: "low", summary: "Measured outcome", _source: "python" };
const click = buildEvidenceCardSpec({ ...base,
  findings: [{ name: "X-Frame-Options", status: "protected", detail: "DENY", evidence: "DENY" }, { name: "CSP frame-ancestors", status: "missing", detail: "Absent" }],
  frame_observation: { event: "load", rendered: null, peek: "cross-origin (document not readable — expected)" },
  poc_overlay: { visible: true, opacity_percent: 8 }
}, "Clickjacking Validator");
const cors = buildEvidenceCardSpec({ ...base,
  checks: [], origins_tested: ["https://evil.test", "https://probe.test"],
  headers: { "access-control-allow-origin": "(absent)", "access-control-allow-credentials": "(absent)", vary: "Origin" }
}, "CORS Validator");
const csp = buildEvidenceCardSpec({ ...base,
  policy: "default-src 'none'; script-src 'nonce-abc' 'strict-dynamic'", report_only_policy: "default-src 'self'",
  directives: { "default-src": ["'none'"], "script-src": ["'nonce-abc'", "'strict-dynamic'"] },
  checks: [{ name: "Script execution", status: "ok", detail: "Nonce protected" }]
}, "CSP Policy Auditor");
const headers = buildEvidenceCardSpec({ ...base, grade: "A", score: 95, checks: [] }, "Security Headers");
console.log(JSON.stringify({ click, cors, csp, headers }));
''')
        click = specs["click"]
        self.assertIn("PROTECTION ENABLED", click["hero"])
        self.assertEqual(click["rowsTitle"], "FRAMING CONTROLS")
        self.assertEqual(len(click["rows"]), 2)
        self.assertIn("NOT MACHINE-VERIFIABLE", click["context"][0]["detail"])
        self.assertIn("cross-origin", click["context"][1]["detail"])
        self.assertIn("8% opacity", click["context"][2]["evidence"])
        cors = specs["cors"]
        self.assertIn("TWO-ORIGIN REFLECTION PROOF", dict(cors["meta"])["Probe coverage"])
        self.assertEqual([row["name"] for row in cors["context"]], ["ACAO", "ACAC", "Vary"])
        csp = specs["csp"]
        self.assertIn("default-src 'none'", csp["context"][0]["detail"])
        self.assertEqual(csp["rowsTitle"], "DIRECTIVE FINDINGS")
        self.assertEqual(csp["rows"][0]["name"], "Script execution")
        self.assertIn("GRADE A", specs["headers"]["hero"])

    def test_clickjacking_overlay_models_a_transparent_attacker_layer(self):
        css = (ROOT / "css" / "app.css").read_text(encoding="utf-8")
        page = (ROOT / "tools" / "clickjacking" / "index.html").read_text(encoding="utf-8")
        controller = (ROOT / "js" / "tool.clickjacking.js").read_text(encoding="utf-8")
        iframe_rule = css[css.index(".stage.poc iframe"):css.index("}", css.index(".stage.poc iframe"))]
        overlay_rule = css[css.index(".overlay {"):css.index("}", css.index(".overlay {"))]
        self.assertIn("opacity: 1", iframe_rule)
        self.assertIn("inset: 0", overlay_rule)
        self.assertIn("pointer-events: none", overlay_rule)
        self.assertIn("--attacker-opacity", overlay_rule)
        self.assertIn('id="pocOpacity" type="range"', page)
        self.assertIn("Victim view · near-invisible", page)
        self.assertIn("Illustrative click target", page)
        self.assertIn('style.setProperty("--attacker-opacity"', controller)


class HubTickerTests(unittest.TestCase):
    """The streaming checks ticker on the landing page must represent the
    whole suite (headers, clickjacking, CORS, CSP *and* the local CSRF/JWT
    utilities) and keep the exact 2x duplication its translateX(-50%) loop
    relies on."""

    def _track(self):
        text = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertRegex(text, r'<div class="ticker[^"]*"[^>]*aria-hidden="true"',
                         "decorative ticker must stay hidden from assistive tech")
        block = re.search(r'<div class="ticker-track">(.*?)</div>', text, re.S)
        self.assertIsNotNone(block)
        return re.findall(r'<span title="([^"]*)">([^<]+)</span>', block.group(1))

    def test_track_is_the_same_sequence_twice(self):
        spans = self._track()
        self.assertTrue(spans, "ticker must contain items")
        self.assertEqual(len(spans) % 2, 0, "translateX(-50%) needs 2x duplication")
        half = len(spans) // 2
        self.assertEqual(spans[:half], spans[half:],
                         "a mismatched second half makes the loop jump visible")

    def test_every_item_explains_itself_on_hover(self):
        for title, _label in self._track():
            with self.subTest(title=title):
                self.assertTrue(title.strip(), "ticker spans need a title tooltip")

    def test_ticker_covers_all_six_tools(self):
        half = len(self._track()) // 2
        labels = " | ".join(label for _t, label in self._track()[:half])
        for expected in (
            "frame-ancestors",              # clickjacking + CSP
            "Strict-Transport-Security",    # headers
            "Access-Control-Allow-Origin",  # CORS
            "CSRF PoC",                     # CSRF PoC Generator
            "JWT",                          # JWT Security Workbench
            "SPF · DKIM · DMARC",           # DNS & Domain Security Analyzer
            "DNSSEC · CAA",                 # DNS & Domain Security Analyzer
        ):
            with self.subTest(coverage=expected):
                self.assertIn(expected, labels)


class ServerRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import server as srv
        cls.srv = srv
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def _req(self, path: str, method: str = "GET", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            body = resp.read()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, headers, body
        finally:
            conn.close()

    def test_hub(self):
        status, headers, body = self._req("/")
        self.assertEqual(status, 200)
        self.assertIn(b"CyberBuddy", body)
        self.assertIn("text/html", headers.get("content-type", ""))

    def test_all_seven_tool_pages(self):
        expect = {
            "/tools/clickjacking/": b"Clickjacking Validator",
            "/tools/headers/": b"Security Headers",
            "/tools/cors/": b"CORS Validator",
            "/tools/csp/": b"CSP Policy Auditor",
            "/tools/csrf/": b"CSRF PoC Generator",
            "/tools/jwt/": b"JWT Security Workbench",
            "/tools/dns/": b"DNS &amp; Domain Security Analyzer",
        }
        for path, needle in expect.items():
            status, headers, body = self._req(path)
            self.assertEqual(status, 200, path)
            self.assertIn(needle, body, path)
            self.assertIn("text/html", headers.get("content-type", ""))

    def test_jwt_short_alias_redirects(self):
        for short in ("/jwt", "/jwt/"):
            status, headers, _ = self._req(short)
            self.assertEqual(status, 301, short)
            self.assertEqual(headers.get("location"), "/tools/jwt/", short)

    def test_jwt_tool_is_operational(self):
        """JWT-01: the served JWT page is a functional decode/verify tool
        — it has a token input and verify button, is indexable, and no
        longer carries the NOT OPERATIONAL preview banner."""
        status, headers, body = self._req("/tools/jwt/")
        self.assertEqual(status, 200)
        self.assertIn(b"JWT Security Workbench", body)
        self.assertIn(b'id="jwtToken"', body)
        self.assertIn(b'id="jwtVerify"', body)
        self.assertNotIn(b"NOT OPERATIONAL", body)
        self.assertNotIn(b'name="robots" content="noindex', body)

    def test_tool_slash_redirect(self):
        status, headers, _ = self._req("/tools/headers")
        self.assertEqual(status, 301)
        self.assertEqual(headers.get("location"), "/tools/headers/")

    def test_tools_catalog_served(self):
        status, headers, body = self._req("/tools/")
        self.assertEqual(status, 200)
        self.assertIn(b"Tools catalog", body)
        self.assertIn("text/html", headers.get("content-type", ""))
        # /tools (no slash) redirects to the catalog, like /methodology.
        status, headers, _ = self._req("/tools")
        self.assertEqual(status, 301)
        self.assertEqual(headers.get("location"), "/tools/")
        # The GitHub project-path form works too.
        status, _, body = self._req("/CyberBuddy/tools/")
        self.assertEqual(status, 200)
        self.assertIn(b"Tool directory", body)

    def test_short_aliases_redirect(self):
        for short, dest in (
            ("/headers", "/tools/headers/"),
            ("/cors", "/tools/cors/"),
            ("/csp", "/tools/csp/"),
            ("/clickjacking", "/tools/clickjacking/"),
            ("/csrf", "/tools/csrf/"),
            ("/jwt", "/tools/jwt/"),
            ("/dns", "/tools/dns/"),
        ):
            status, headers, _ = self._req(short)
            self.assertEqual(status, 301, short)
            self.assertEqual(headers.get("location"), dest, short)

    def test_github_pages_style_prefix(self):
        status, _, body = self._req("/CyberBuddy/tools/headers/")
        self.assertEqual(status, 200)
        self.assertIn(b"Security Headers", body)
        status, _, body = self._req("/CyberBuddy/tools/cors/")
        self.assertEqual(status, 200)
        self.assertIn(b"CORS Validator", body)
        status, _, body = self._req("/CyberBuddy/tools/csp/")
        self.assertEqual(status, 200)
        self.assertIn(b"CSP Policy Auditor", body)
        status, _, body = self._req("/CyberBuddy/tools/csrf/")
        self.assertEqual(status, 200)
        self.assertIn(b"CSRF PoC Generator", body)
        # JWT tool is reachable under the /CyberBuddy mount (JWT-01).
        status, _, body = self._req("/CyberBuddy/tools/jwt/")
        self.assertEqual(status, 200)
        self.assertIn(b"JWT Security Workbench", body)
        self.assertIn(b'id="jwtVerify"', body)
        # DNS tool is reachable under the /CyberBuddy mount.
        status, _, body = self._req("/CyberBuddy/tools/dns/")
        self.assertEqual(status, 200)
        self.assertIn(b"DNS &amp; Domain Security Analyzer", body)

    def test_static_assets(self):
        status, headers, body = self._req("/css/app.css")
        self.assertEqual(status, 200)
        self.assertIn("text/css", headers.get("content-type", ""))
        self.assertGreater(len(body), 100)
        status, headers, body = self._req("/js/app.js")
        self.assertEqual(status, 200)
        self.assertIn("javascript", headers.get("content-type", ""))
        self.assertIn(b"function appBase", body)
        status, headers, body = self._req("/humans.txt")
        self.assertEqual(status, 200)
        self.assertIn(b"Amit Pal", body)
        status, headers, body = self._req("/llms.txt")
        self.assertEqual(status, 200)
        self.assertIn(b"CyberBuddy", body)

    def test_methodology_page(self):
        status, headers, _ = self._req("/methodology")
        self.assertEqual(status, 301)
        self.assertEqual(headers.get("location"), "/methodology/")
        status, headers, body = self._req("/methodology/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn(b"Methodology", body)
        status, _, body = self._req("/CyberBuddy/methodology/")
        self.assertEqual(status, 200)
        self.assertIn(b"How it scores", body)

    def test_guides_pages(self):
        """A new published top-level section needs all three route forms:
        /guides/, the no-slash redirect, and the GitHub project-path mount."""
        status, headers, _ = self._req("/guides")
        self.assertEqual(status, 301)
        self.assertEqual(headers.get("location"), "/guides/")
        status, headers, body = self._req("/guides/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn(b"Guides", body)

        status, headers, _ = self._req("/guides/clickjacking")
        self.assertEqual(status, 301)
        self.assertEqual(headers.get("location"), "/guides/clickjacking/")
        status, headers, body = self._req("/guides/clickjacking/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn(b"Clickjacking", body)

        status, _, body = self._req("/CyberBuddy/guides/")
        self.assertEqual(status, 200)
        self.assertIn(b"Guides", body)
        status, _, body = self._req("/CyberBuddy/guides/clickjacking/")
        self.assertEqual(status, 200)
        self.assertIn(b"frame-ancestors", body)

    def test_health_and_api_validation(self):
        status, headers, body = self._req("/api/health")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers.get("content-type", ""))
        self.assertTrue(json.loads(body).get("ok"))
        opt_in = {"X-Requested-With": "CyberBuddy"}
        for path in ("/api/scan", "/api/headers", "/api/cors", "/api/csp"):
            status, _, body = self._req(path, headers=opt_in)
            self.assertEqual(status, 400, path)
            self.assertIn("url required", json.loads(body).get("error", ""))
        status, _, body = self._req("/api/dns", headers=opt_in)
        self.assertEqual(status, 400)
        self.assertIn("domain required", json.loads(body).get("error", ""))

    def test_api_requires_explicit_browser_or_cli_opt_in(self):
        status, _, body = self._req("/api/headers?url=https%3A%2F%2Fexample.com")
        self.assertEqual(status, 403)
        self.assertIn("X-Requested-With", json.loads(body).get("error", ""))

        # A forged cross-site Origin is rejected even if the custom header is
        # supplied. Provenance alone is insufficient: a same-origin Referer
        # must also carry the non-simple opt-in header used by the UI.
        status, _, _ = self._req(
            "/api/headers?url=https%3A%2F%2Fexample.com",
            headers={
                "Origin": "https://evil.example",
                "X-Forwarded-Host": "evil.example",
                "X-Requested-With": "CyberBuddy",
            },
        )
        self.assertEqual(status, 403)
        referer = f"http://127.0.0.1:{self.port}/tools/headers/"
        status, _, _ = self._req(
            "/api/headers", headers={"Referer": referer},
        )
        self.assertEqual(status, 403)
        status, _, body = self._req(
            "/api/headers",
            headers={"Referer": referer, "X-Requested-With": "CyberBuddy"},
        )
        self.assertEqual(status, 400)
        self.assertIn("url required", json.loads(body).get("error", ""))

    def test_api_non_simple_header_blocks_non_loopback_rebinding(self):
        original = self.srv.HOST
        self.srv.HOST = "0.0.0.0"
        try:
            status, _, _ = self._req(
                "/api/headers?url=https%3A%2F%2Fexample.com",
                headers={
                    "Host": "attacker.example",
                    "Origin": "http://attacker.example",
                },
            )
            self.assertEqual(status, 403)
        finally:
            self.srv.HOST = original

    def test_api_rejects_dns_rebinding_host_on_loopback(self):
        status, _, _ = self._req(
            "/api/headers?url=https%3A%2F%2Fexample.com",
            headers={"Host": "attacker.example", "X-Requested-With": "CyberBuddy"},
        )
        self.assertEqual(status, 403)

    def test_api_rejects_rebinding_on_any_loopback_bind_address(self):
        original = self.srv.HOST
        self.srv.HOST = "127.0.0.2"
        try:
            status, _, _ = self._req(
                "/api/headers?url=https%3A%2F%2Fexample.com",
                headers={"Host": "attacker.example", "X-Requested-With": "CyberBuddy"},
            )
            self.assertEqual(status, 403)
            status, _, body = self._req(
                "/api/headers",
                headers={"Host": "127.0.0.2", "X-Requested-With": "CyberBuddy"},
            )
            self.assertEqual(status, 400)
            self.assertIn("url required", json.loads(body).get("error", ""))
        finally:
            self.srv.HOST = original

    def test_dns_api_returns_json_for_invalid_domain(self):
        status, headers, body = self._req(
            "/api/dns?domain=localhost",
            headers={"X-Requested-With": "CyberBuddy"},
        )
        self.assertEqual(status, 400)
        self.assertIn("application/json", headers.get("content-type", ""))
        self.assertIn("public domain", json.loads(body).get("error", ""))

    def test_unknown_path_serves_404_page(self):
        status, headers, body = self._req("/does-not-exist")
        self.assertEqual(status, 404)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn(b"404", body)

    def test_four_apis_scan_this_server(self):
        target = quote(f"http://127.0.0.1:{self.port}/", safe="")
        opt_in = {"X-Requested-With": "CyberBuddy"}
        status, _, body = self._req("/api/headers?url=" + target, headers=opt_in)
        self.assertEqual(status, 200)
        headers_data = json.loads(body)
        self.assertIn("grade", headers_data)
        self.assertTrue(headers_data.get("checks"))
        status, _, body = self._req("/api/scan?url=" + target, headers=opt_in)
        self.assertEqual(status, 200)
        scan_data = json.loads(body)
        self.assertTrue(scan_data.get("findings"))
        status, _, body = self._req("/api/cors?url=" + target, headers=opt_in)
        self.assertEqual(status, 200)
        cors_data = json.loads(body)
        self.assertTrue(cors_data.get("checks"))
        status, _, body = self._req("/api/csp?url=" + target, headers=opt_in)
        self.assertEqual(status, 200)
        csp_data = json.loads(body)
        self.assertIn("policy", csp_data)
        self.assertTrue(csp_data.get("checks"))


class HostedDnsApiTests(unittest.TestCase):
    """The deployed DNS function must reject malformed input before it can
    trigger a resolver query, just like the local server route."""

    def test_invalid_domain_returns_400_without_scanning(self):
        import apilib

        apilib._hits.clear()
        namespace = runpy.run_path(str(ROOT / "api" / "dns.py"))
        app = namespace["app"]

        def unexpected_scan(_domain):
            self.fail("scan_dns must not run for an invalid domain")

        app.__globals__["scan_dns"] = unexpected_scan
        response = {}

        def start_response(status, headers):
            response["status"] = status
            response["headers"] = dict(headers)

        body = b"".join(app({
            "REQUEST_METHOD": "GET",
            "QUERY_STRING": "domain=localhost",
            "REMOTE_ADDR": "192.0.2.20",
        }, start_response))
        self.assertEqual(response["status"], "400 Bad Request")
        self.assertIn("application/json", response["headers"]["Content-Type"])
        self.assertIn("public domain", json.loads(body)["error"])


class HostedSiteTests(unittest.TestCase):
    def test_urls_txt_lists_own_site(self):
        text = (ROOT / "urls.txt").read_text(encoding="utf-8")
        self.assertIn("https://example.com", text)
        self.assertIn("https://amitpal-cyberbuddy.github.io/CyberBuddy/", text)

    def test_cache_buster_is_consistent(self):
        pages = [
            ROOT / "index.html",
            ROOT / "methodology" / "index.html",
            ROOT / "guides" / "index.html",
            ROOT / "guides" / "clickjacking" / "index.html",
            ROOT / "tools" / "index.html",
            ROOT / "tools" / "clickjacking" / "index.html",
            ROOT / "tools" / "headers" / "index.html",
            ROOT / "tools" / "cors" / "index.html",
            ROOT / "tools" / "csp" / "index.html",
            ROOT / "tools" / "csrf" / "index.html",
            ROOT / "tools" / "jwt" / "index.html",
            ROOT / "tools" / "dns" / "index.html",
            ROOT / "guides" / "jwt" / "index.html",
            ROOT / "guides" / "dns" / "index.html",
        ]
        versions = set()
        for page in pages:
            text = page.read_text(encoding="utf-8")
            self.assertIn("css/app.css?v=", text, page)
            self.assertIn("js/app.js?v=", text, page)
            css = [part.split('"')[0] for part in text.split("css/app.css?v=")[1:]]
            js = [part.split('"')[0] for part in text.split("js/app.js?v=")[1:]]
            versions.update(css)
            versions.update(js)
        self.assertEqual(len(versions), 1, versions)

    def test_pages_workflow_is_resilient(self):
        text = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
        self.assertIn("test -f \"$f\" && cp \"$f\" _site/ || true", text)
        self.assertIn("test -d .well-known && cp -a .well-known _site/ || true", text)

    def test_hub_has_methodology_anchor(self):
        text = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="methodology"', text)
        sitemap = (ROOT / "sitemap.xml").read_text(encoding="utf-8")
        self.assertIn("/tools/clickjacking/", sitemap)
        self.assertIn("/tools/csp/", sitemap)

    def test_hub_blog_is_a_sample_not_the_full_catalog(self):
        """From the blog is first-person visitor copy. The hub shows the two
        posts that have no matching guide; the CORS write-up lives on the
        CORS guide. Medium is the complete list. No Newest badge — it would
        go stale the moment another post ships."""
        hub = (ROOT / "index.html").read_text(encoding="utf-8")
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        start = app.index("const BLOG_POSTS")
        block = app[start:app.index("];", start)]
        cors = ("https://amitpxl.medium.com/cors-misconfiguration-when-"
                "reflecting-the-origin-is-not-the-whole-story-956e2e6e18bc")
        smuggling = "http-request-smuggling-vs-http-request-pipelining"
        crypto = "how-i-broke-encrypted-requests-by-reading-frontend-javascript"
        self.assertNotIn(cors, block)
        self.assertNotIn(cors, hub)
        self.assertIn(smuggling, block)
        self.assertIn(crypto, block)
        self.assertIn(smuggling, hub)
        self.assertIn(crypto, hub)
        self.assertNotIn("Newest", block)
        self.assertNotIn("blog-badge", hub)
        self.assertIn("write-ups I publish as I find them", hub)
        self.assertNotIn("new posts land here", hub)
        self.assertIn("View all articles on Medium", hub)
        self.assertNotIn("cybersecurity notes", hub.split("From the blog", 1)[1].split("Shape what's next", 1)[0])

    def test_github_pages_first_tools_are_next_up(self):
        hub = (ROOT / "index.html").read_text(encoding="utf-8")
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        soon = app[app.index("const TOOLS_SOON"):app.index("];", app.index("const TOOLS_SOON"))]
        self.assertIn("Next on the bench: HAR Security Analyzer", hub)
        self.assertIn("HAR Security Analyzer", soon)
        self.assertNotIn("DNS & Domain Security Analyzer", soon)
        self.assertNotIn("TLS / SSL Analyzer", soon)
        self.assertNotIn("Subdomain Enumeration", soon)


class GraderParityTests(unittest.TestCase):
    """Python and JS graders must agree, check for check.

    CyberBuddy ships the scoring twice — stdlib Python for server.py/CLI, and
    a browser port in js/app.js so GitHub Pages can grade without a server.
    Two implementations of one spec drift silently, and when they do the same
    target gets a different grade depending on where it was scanned, which is
    exactly the kind of inconsistency that gets a finding disputed. These
    fixtures are the shared contract.
    """

    @classmethod
    def setUpClass(cls):
        path = ROOT / "tests" / "grader_fixtures.json"
        cls.fixtures = json.loads(path.read_text(encoding="utf-8"))["cases"]

    def test_python_grader_matches_fixtures(self):
        from clickjacking_validator import grade_clickjacking_from_map
        from security_headers import grade_headers_from_map

        for case in self.fixtures:
            with self.subTest(case=case["name"]):
                res = grade_headers_from_map(
                    case["url"], case["status_code"], case["final_url"], case["headers"]
                )
                exp = case["expect"]
                if "score" in exp:
                    self.assertEqual(res.score, exp["score"])
                if "grade" in exp:
                    self.assertEqual(res.grade, exp["grade"])
                if "risk" in exp:
                    self.assertEqual(res.risk, exp["risk"])
                by_name = {c.name: c.status for c in res.checks}
                for name, status in exp.get("statuses", {}).items():
                    self.assertIn(name, by_name, f"{name} missing from checks")
                    self.assertEqual(by_name[name], status, f"{name} status")
                if "clickjacking_risk" in exp:
                    cj = grade_clickjacking_from_map(
                        case["url"], case["status_code"], case["final_url"], case["headers"]
                    )
                    self.assertEqual(cj.risk, exp["clickjacking_risk"])

    def test_js_grader_matches_fixtures(self):
        """Run the same fixtures through js/app.js under node."""
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import tempfile

        harness = r"""
const fixtures = JSON.parse(require("fs").readFileSync(process.argv[2], "utf8")).cases;
const out = [];
for (const c of fixtures) {
  const r = gradeHeadersFromMap(c.url, c.status_code, c.final_url, c.headers, "test");
  const cj = gradeClickjackingFromMap(c.url, c.status_code, c.final_url, c.headers, "test");
  const statuses = {};
  r.checks.forEach((x) => { statuses[x.name] = x.status; });
  out.push({ name: c.name, score: r.score, grade: r.grade, risk: r.risk,
             clickjacking_risk: cj.risk, statuses: statuses });
}
console.log(JSON.stringify(out));
"""
        script = (
            "const document = { documentElement: { classList: { add() {} } } };\n"
            "const window = { __cbEngine: {}, location: { origin: 'https://example.test', "
            "pathname: '/' }, addEventListener() {} };\n"
            "const localStorage = { getItem(){return null;}, setItem(){}, removeItem(){} };\n"
            "const sessionStorage = localStorage;\n"
            + (ROOT / "js" / "app.js").read_text(encoding="utf-8")
            + harness
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run(
                [node, path, str(ROOT / "tests" / "grader_fixtures.json")],
                cwd=str(ROOT), capture_output=True, text=True, timeout=30,
            )
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        results = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(len(results), len(self.fixtures))

        for case, got in zip(self.fixtures, results):
            with self.subTest(case=case["name"]):
                exp = case["expect"]
                if "score" in exp:
                    self.assertEqual(got["score"], exp["score"])
                if "grade" in exp:
                    self.assertEqual(got["grade"], exp["grade"])
                if "risk" in exp:
                    self.assertEqual(got["risk"], exp["risk"])
                if "clickjacking_risk" in exp:
                    self.assertEqual(got["clickjacking_risk"], exp["clickjacking_risk"])
                for name, status in exp.get("statuses", {}).items():
                    self.assertIn(name, got["statuses"], f"{name} missing from JS checks")
                    self.assertEqual(got["statuses"][name], status, f"{name} status")

    def test_python_and_js_agree_exactly(self):
        """Belt and braces: compare the two engines directly, not just to expectations."""
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        from clickjacking_validator import grade_clickjacking_from_map
        from security_headers import grade_headers_from_map
        import tempfile

        harness = r"""
const fixtures = JSON.parse(require("fs").readFileSync(process.argv[2], "utf8")).cases;
const out = fixtures.map((c) => {
  const r = gradeHeadersFromMap(c.url, c.status_code, c.final_url, c.headers, "test");
  const cj = gradeClickjackingFromMap(c.url, c.status_code, c.final_url, c.headers, "test");
  const statuses = {};
  r.checks.forEach((x) => { statuses[x.name] = x.status; });
  return { score: r.score, grade: r.grade, risk: r.risk,
           clickjacking_risk: cj.risk, statuses: statuses };
});
console.log(JSON.stringify(out));
"""
        script = (
            "const document = { documentElement: { classList: { add() {} } } };\n"
            "const window = { __cbEngine: {}, location: { origin: 'https://example.test', "
            "pathname: '/' }, addEventListener() {} };\n"
            "const localStorage = { getItem(){return null;}, setItem(){}, removeItem(){} };\n"
            "const sessionStorage = localStorage;\n"
            + (ROOT / "js" / "app.js").read_text(encoding="utf-8")
            + harness
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run(
                [node, path, str(ROOT / "tests" / "grader_fixtures.json")],
                cwd=str(ROOT), capture_output=True, text=True, timeout=30,
            )
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        js_results = json.loads(proc.stdout.strip().splitlines()[-1])

        for case, js in zip(self.fixtures, js_results):
            with self.subTest(case=case["name"]):
                py = grade_headers_from_map(
                    case["url"], case["status_code"], case["final_url"], case["headers"]
                )
                pycj = grade_clickjacking_from_map(
                    case["url"], case["status_code"], case["final_url"], case["headers"]
                )
                self.assertEqual(py.score, js["score"], "score drift")
                self.assertEqual(py.grade, js["grade"], "grade drift")
                self.assertEqual(py.risk, js["risk"], "risk drift")
                self.assertEqual(pycj.risk, js["clickjacking_risk"], "clickjacking drift")
                py_statuses = {c.name: c.status for c in py.checks}
                self.assertEqual(py_statuses, js["statuses"], "per-check status drift")


class CspGraderParityTests(unittest.TestCase):
    """The CSP report must not change between server.py and GitHub Pages."""

    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / "tests" / "csp_fixtures.json"
        cls.fixtures = json.loads(cls.path.read_text(encoding="utf-8"))["cases"]

    def test_python_csp_grader_matches_fixtures(self):
        for case in self.fixtures:
            with self.subTest(case=case["name"]):
                result = grade_csp_from_map(
                    case["url"], case["status_code"], case["final_url"], case["headers"]
                )
                self.assertEqual(result.risk, case["expect"]["risk"])
                statuses = {check.name: check.status for check in result.checks}
                for name, status in case["expect"]["statuses"].items():
                    self.assertEqual(statuses.get(name), status, name)

    def test_python_and_browser_csp_graders_agree(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import tempfile

        harness = r"""
const fixtures = JSON.parse(require("fs").readFileSync(process.argv[2], "utf8")).cases;
const out = fixtures.map((c) => {
  const r = gradeCspFromMap(c.url, c.status_code, c.final_url, c.headers, "test");
  return {
    risk: r.risk,
    checks: r.checks.map((x) => ({ name: x.name, status: x.status, severity: x.severity }))
  };
});
console.log(JSON.stringify(out));
"""
        script = (
            "const document = { documentElement: { classList: { add() {} } } };\n"
            "const window = { __cbEngine: {}, location: { origin: 'https://example.test', "
            "pathname: '/' }, addEventListener() {} };\n"
            "const localStorage = { getItem(){return null;}, setItem(){}, removeItem(){} };\n"
            "const sessionStorage = localStorage;\n"
            + (ROOT / "js" / "app.js").read_text(encoding="utf-8")
            + harness
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as handle:
            handle.write(script)
            script_path = handle.name
        try:
            proc = subprocess.run(
                [node, script_path, str(self.path)],
                cwd=str(ROOT), capture_output=True, text=True, timeout=30,
            )
        finally:
            os.unlink(script_path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        browser = json.loads(proc.stdout.strip().splitlines()[-1])

        for case, js_result in zip(self.fixtures, browser):
            with self.subTest(case=case["name"]):
                py_result = grade_csp_from_map(
                    case["url"], case["status_code"], case["final_url"], case["headers"]
                )
                py_checks = [
                    {"name": check.name, "status": check.status, "severity": check.severity}
                    for check in py_result.checks
                ]
                self.assertEqual(js_result["risk"], py_result.risk)
                self.assertEqual(js_result["checks"], py_checks)


class SessionPoolTests(unittest.TestCase):
    """The opener cache must not leak one caller's allow_private policy.

    Each opener bakes in a SafeRedirect handler that closes over
    allow_private. If the cache key ignores it, the first caller in the
    process decides the redirect policy for everyone — meaning an
    allow_private=False scan could follow a redirect into RFC1918.
    """

    def setUp(self):
        from http_session import get_session_pool

        self.pool = get_session_pool()
        self.pool.clear()

    def tearDown(self):
        self.pool.clear()

    def test_same_key_reuses_opener(self):
        a = self.pool.get_opener(insecure=False, allow_private=True)
        b = self.pool.get_opener(insecure=False, allow_private=True)
        self.assertIs(a, b)

    def test_allow_private_is_part_of_the_cache_key(self):
        public = self.pool.get_opener(insecure=False, allow_private=False)
        private = self.pool.get_opener(insecure=False, allow_private=True)
        self.assertIsNot(public, private)

    def test_insecure_is_part_of_the_cache_key(self):
        secure = self.pool.get_opener(insecure=False, allow_private=False)
        insecure = self.pool.get_opener(insecure=True, allow_private=False)
        self.assertIsNot(secure, insecure)

    def test_public_opener_refuses_private_redirect(self):
        """The allow_private=False opener's redirect guard must reject RFC1918."""
        opener = self.pool.get_opener(insecure=False, allow_private=False)
        handler = next(
            h for h in opener.handlers
            if type(h).__name__ == "SafeRedirect"
        )
        req = urllib.request.Request("https://example.com/")
        msg = Message()
        with self.assertRaises(ValueError):
            handler.redirect_request(
                req, None, 302, "Found", msg, "http://127.0.0.1:8080/"
            )

    def test_connect_time_guard_blocks_private_ip(self):
        """DNS TOCTOU: the guard must apply to the address actually connected to.

        validate_target() resolves once to decide, then urllib resolves again
        independently — a hostile resolver can answer public for the check and
        private for the fetch. Here we bypass the pre-check entirely and
        confirm the connect-time validation still refuses loopback.
        """
        from http_session import _check_connect_ip

        with self.assertRaises(ValueError):
            _check_connect_ip("127.0.0.1", allow_private=False)
        with self.assertRaises(ValueError):
            _check_connect_ip("::1", allow_private=False)
        with self.assertRaises(ValueError):
            _check_connect_ip("10.0.0.5", allow_private=False)
        # Link-local / metadata is refused regardless of allow_private.
        with self.assertRaises(ValueError):
            _check_connect_ip("169.254.169.254", allow_private=True)
        # Loopback is fine when private targets are permitted (the VAPT case).
        _check_connect_ip("127.0.0.1", allow_private=True)
        _check_connect_ip("93.184.216.34", allow_private=False)

    def test_openers_install_pinned_handlers(self):
        from http_session import _PinnedHTTPHandler, _PinnedHTTPSHandler

        opener = self.pool.get_opener(insecure=False, allow_private=False)
        kinds = {type(h) for h in opener.handlers}
        self.assertTrue(any(issubclass(k, _PinnedHTTPHandler) for k in kinds))
        self.assertTrue(any(issubclass(k, _PinnedHTTPSHandler) for k in kinds))

    def test_private_opener_allows_private_redirect(self):
        opener = self.pool.get_opener(insecure=False, allow_private=True)
        handler = next(
            h for h in opener.handlers
            if type(h).__name__ == "SafeRedirect"
        )
        req = urllib.request.Request("http://127.0.0.1:8080/")
        msg = Message()
        # Should not raise — loopback is permitted for this policy.
        handler.redirect_request(
            req, None, 302, "Found", msg, "http://127.0.0.1:8080/next"
        )


class HostedCspTests(unittest.TestCase):
    """GitHub Pages cannot send response headers, so the policy ships as a
    <meta> tag. A header-grading tool that ships no policy on its own hosted
    site is a credibility problem, so keep these locked in."""

    PAGES = [
        str(path.relative_to(ROOT))
        for path in sorted(ROOT.rglob("*.html"))
        if path.relative_to(ROOT).parts[0]
        not in {"_site", "node_modules", ".git", "__pycache__"}
    ]

    def _csp(self, page: str) -> str:
        text = (ROOT / page).read_text(encoding="utf-8")
        m = re.search(
            r'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', text
        )
        self.assertIsNotNone(m, f"{page} has no meta CSP")
        return m.group(1)

    def test_every_page_ships_a_meta_csp(self):
        for page in self.PAGES:
            with self.subTest(page=page):
                csp = self._csp(page)
                self.assertIn("default-src 'self'", csp)
                self.assertIn("object-src 'none'", csp)
                self.assertIn("base-uri 'self'", csp)

    def test_no_unsafe_inline_script_anywhere(self):
        for page in self.PAGES:
            with self.subTest(page=page):
                csp = self._csp(page)
                script = re.search(r"script-src ([^;]+)", csp).group(1)
                self.assertNotIn("unsafe-inline", script)
                self.assertNotIn("unsafe-eval", script)

    def test_only_clickjacking_tool_may_frame_targets(self):
        """Least privilege: the framing capability is the whole point of one
        tool and a liability on every other page."""
        for page in self.PAGES:
            with self.subTest(page=page):
                csp = self._csp(page)
                if page == "tools/clickjacking/index.html":
                    self.assertIn("frame-src https:", csp)
                else:
                    self.assertIn("frame-src 'none'", csp)

    def test_exports_are_not_blocked(self):
        """The evidence-card download builds a canvas blob."""
        for page in self.PAGES:
            with self.subTest(page=page):
                self.assertIn("blob:", re.search(r"img-src ([^;]+)", self._csp(page)).group(1))

    def test_fonts_are_not_render_blocking_imports(self):
        """@import inside app.css serializes the font fetch behind the CSS
        download+parse, which defeats the preconnect hints."""
        css = (ROOT / "css" / "app.css").read_text(encoding="utf-8")
        self.assertNotIn("@import url(", css)
        for page in ["index.html", "tools/headers/index.html"]:
            text = (ROOT / page).read_text(encoding="utf-8")
            self.assertIn("fonts.googleapis.com/css2", text)

    def test_reduced_motion_never_leaves_reveals_invisible(self):
        css = (ROOT / "css" / "app.css").read_text(encoding="utf-8")
        block = css[css.index("@media (prefers-reduced-motion: reduce)"):]
        self.assertIn("html.js .reveal, .reveal", block)
        self.assertIn("opacity: 1 !important", block)
        self.assertIn("animation-delay: 0s !important", block)

    def test_hub_can_offer_relay_consent(self):
        """Without #relayGate the hub silently degrades to 'no header data'
        on the hosted site with no way for the analyst to opt in."""
        self.assertIn('id="relayGate"', (ROOT / "index.html").read_text(encoding="utf-8"))


class NoScriptFallbackTests(unittest.TestCase):
    """Every page remains navigable and honest when client JavaScript fails."""

    SHELL_PAGES = [page for page in HostedCspTests.PAGES if page != "404.html"]

    def test_shell_pages_offer_static_global_navigation(self):
        for page in self.SHELL_PAGES:
            text = (ROOT / page).read_text(encoding="utf-8")
            with self.subTest(page=page):
                self.assertIn('<noscript><link rel="stylesheet"', text)
                self.assertIn('class="noscript-banner"', text)
                self.assertIn('aria-label="No-JavaScript navigation"', text)
                self.assertIn(">Home</a>", text)
                self.assertIn(">Tools</a>", text)
                self.assertIn(">Guides</a>", text)
                self.assertIn(">Methodology</a>", text)
                self.assertIn(">Documentation</a>", text)
                self.assertIn("interactive scanners", text)

    def test_no_script_styles_keep_content_visible_and_controls_honest(self):
        css = (ROOT / "css" / "noscript.css").read_text(encoding="utf-8")
        self.assertIn(".reveal { opacity: 1 !important", css)
        self.assertIn("body[data-init] main button", css)
        self.assertIn("pointer-events: none", css)

    def test_404_keeps_static_navigation_and_hides_its_script_only_theme_control(self):
        page = (ROOT / "404.html").read_text(encoding="utf-8")
        self.assertIn('<noscript><link rel="stylesheet"', page)
        self.assertEqual(7, len(re.findall(r'data-slug="[^"]+"', page)))
        self.assertIn('id="guidesLink"', page)
        self.assertIn('id="methodLink"', page)
        css = (ROOT / "css" / "noscript.css").read_text(encoding="utf-8")
        self.assertIn("#themeToggle { display: none !important", css)


class ClearRecentScansTests(unittest.TestCase):
    """Clearing scan history must also drop the cached response headers."""

    def test_clear_removes_header_lookup_cache(self):
        text = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        start = text.index("function clearRecentScans()")
        body = text[start:start + 400]
        self.assertIn("RECENT_KEY", body)
        self.assertIn("HEADER_CACHE_KEY", body)


class PrintStylesheetTests(unittest.TestCase):
    """The exported PDF must keep the evidence the screen shows."""

    def _print_block(self) -> str:
        """The @media print body, with /* comments */ stripped."""
        text = (ROOT / "css" / "app.css").read_text(encoding="utf-8")
        start = text.index("@media print")
        block = text[start:text.index("@media (max-width: 760px)", start)]
        return re.sub(r"/\*.*?\*/", "", block, flags=re.S)

    def _print_hide_rule(self) -> str:
        """Just the selector list of the `display: none !important` rule."""
        block = self._print_block()
        end = block.index("display: none !important")
        # Back up to the start of that rule's selector list.
        return block[block.rindex("}", 0, end) + 1:end]

    def test_poc_overlay_is_not_hidden_in_print(self):
        # .overlay is the attacker layer — it IS the clickjacking evidence.
        self.assertNotIn(".overlay", self._print_hide_rule())

    def test_notice_is_not_hidden_in_print(self):
        self.assertNotIn(".notice", self._print_hide_rule())

    def test_chrome_is_still_hidden_in_print(self):
        rule = self._print_hide_rule()
        for sel in (".site-header", ".site-footer", ".btn", ".aurora"):
            self.assertIn(sel, rule)

    def test_print_forces_colour_adjust(self):
        block = self._print_block()
        self.assertIn("print-color-adjust: exact", block)


class HeadersReportLayoutTests(unittest.TestCase):
    """Round 6: the Security Headers report stacks Findings above Raw headers.

    Findings runs several times taller than Raw headers, so a 2-column split
    left a large blank right column (measured 2735px vs 236px at 1920px).
    """

    def setUp(self) -> None:
        self.page = (ROOT / "tools" / "headers" / "index.html").read_text(encoding="utf-8")
        self.css = (ROOT / "css" / "app.css").read_text(encoding="utf-8")

    def _rule(self, selector: str) -> str:
        start = self.css.index(selector)
        return self.css[start:self.css.index("}", start)]

    def _stack_rule(self) -> str:
        return self._rule(".headers-report-stack {")

    def test_report_uses_the_tool_specific_stack_not_grid_2(self):
        body = self.page[self.page.index('id="results"'):]
        self.assertIn('class="headers-report-stack"', body)
        # .grid-2 is load-bearing elsewhere; the headers report must not use
        # it, and must not be "fixed" by changing it globally.
        self.assertNotIn('class="grid-2"', body)

    def test_stack_is_single_column(self):
        rule = self._stack_rule()
        self.assertIn("grid-template-columns: 1fr", rule)

    def test_findings_come_first_then_raw_headers(self):
        body = self.page[self.page.index("headers-report-stack"):]
        self.assertLess(body.index("Findings"), body.index("Raw headers"))

    def test_shared_grid_2_still_has_two_columns(self):
        """Other sections depend on .grid-2 — it must not be flattened."""
        start = self.css.index(".grid-2 {")
        self.assertIn("1.15fr 1fr", self.css[start:self.css.index("}", start)])

    def test_stack_children_can_shrink(self):
        """Without min-width: 0 a long raw-header token expands the track."""
        rule = self._rule(".headers-report-stack > * {")
        self.assertIn("min-width: 0", rule)
        # Full-width rows in a grid need an explicit span, not width: 100%.
        self.assertIn("grid-column: 1 / -1", rule)

    def test_raw_headers_wrap_long_unbreakable_tokens(self):
        start = self.css.index(".raw-headers {")
        rule = self.css[start:self.css.index("}", start)]
        self.assertIn("overflow-wrap: anywhere", rule)
        self.assertIn("max-width: 100%", rule)
        self.assertIn("overflow: auto", rule)

    def test_findings_are_not_hidden_behind_a_disclosure(self):
        """Evidence must stay visible: a closed <details> cannot be forced
        open by print CSS and breaks the screenshot workflow."""
        start = self.page.index("headers-report-stack")
        block = self.page[start:self.page.index("reportProvenance", start)]
        self.assertNotIn("<details", block)

    def test_print_still_flattens_report_grids(self):
        start = self.css.index("@media print")
        block = self.css[start:self.css.index("@media (max-width: 760px)", start)]
        self.assertIn("grid-template-columns: 1fr", block)
        self.assertIn(".raw-headers { max-height: none; }", block)


class OverlayStackingTests(unittest.TestCase):
    """Round 6: dropdowns/menus must render above the report and stay
    inside the viewport. Reproduced in Chromium before fixing."""

    def setUp(self) -> None:
        self.css = (ROOT / "css" / "app.css").read_text(encoding="utf-8")

    def test_evidence_mode_keeps_the_header_positioned(self):
        """`position: static` drops the header out of the z-index game, so
        its z-index: 50 stopped applying and the Tools menu painted behind
        the report card. Evidence mode must un-stick it without un-position
        -ing it."""
        start = self.css.index("body.evidence .site-header")
        rule = self.css[start:self.css.index("}", start)]
        self.assertIn("position: relative", rule)
        self.assertNotIn("position: static", rule)
        self.assertNotIn("position: sticky", rule)

    def test_site_header_still_declares_a_stacking_order(self):
        start = self.css.index(".site-header {")
        self.assertIn("z-index: 50", self.css[start:self.css.index("}", start)])

    def test_main_content_outranks_the_footer(self):
        """`.container` and `.site-footer` were both z-index: 1, so the
        footer painted over an open Export panel and swallowed its clicks."""
        self.assertIn("main.container { z-index: 2; }", self.css)
        start = self.css.index(".site-footer {")
        self.assertIn("z-index: 1", self.css[start:self.css.index("}", start)])

    def test_narrow_tools_menu_anchors_to_the_header_row(self):
        """A 300px panel anchored to the small Tools <details> ran past the
        right edge at 390px (measured 46px of horizontal overflow)."""
        self.assertIn("position: relative", self._rule(".header-inner {"))
        self.assertIn(".header-inner .nav-menu { position: static; }", self.css)
        panel = self._rule(".header-inner .nav-menu-panel {")
        self.assertIn("left: 0; right: 0", panel)
        self.assertIn("overflow-y: auto", panel)

    def test_export_panel_anchors_to_the_scan_bar(self):
        """The Export button wraps to its own line on narrow screens; a
        right-anchored 268px panel then started at a negative x."""
        self.assertIn(".bar, .suite-bar {", self.css)
        self.assertIn("position: relative", self._rule(".bar, .suite-bar {"))
        self.assertIn(".bar .export-menu, .suite-bar .export-menu { position: static; }", self.css)

    def test_export_panel_outranks_report_content(self):
        start = self.css.index(".export-menu-panel {")
        self.assertIn("z-index: 70", self.css[start:self.css.index("}", start)])

    def _rule(self, selector: str) -> str:
        start = self.css.index(selector)
        return self.css[start:self.css.index("}", start)]


class RelayProvenanceTests(unittest.TestCase):
    """Round 6: relayed header values keep their `unverified` flag even when
    they are re-served from the 10-minute local lookup cache."""

    def setUp(self) -> None:
        self.js = (ROOT / "js" / "app.js").read_text(encoding="utf-8")

    def test_cached_relay_reads_keep_a_relay_source(self):
        start = self.js.index("async function lookupHeadersLive")
        body = self.js[start:start + 700]
        self.assertIn('"relay-cached"', body)
        self.assertIn('cached.source === "relay"', body)

    def test_relay_cached_counts_as_unverified(self):
        start = self.js.index("function isUnverified(")
        body = self.js[start:self.js.index("}", start)]
        self.assertIn('"relay"', body)
        self.assertIn('"relay-cached"', body)

    def test_relay_cached_is_not_labelled_as_this_browser(self):
        """Calling relayed data 'this browser' overstates the provenance."""
        start = self.js.index("function sourceLabel(")
        body = self.js[start:self.js.index("\n}", start)]
        line = [l for l in body.splitlines() if "relay-cached" in l][0]
        self.assertIn("relay", line)
        self.assertNotIn("this browser", line)

    def test_every_source_has_an_explanation(self):
        start = self.js.index("const SOURCE_EXPLAIN")
        block = self.js[start:self.js.index("};", start)]
        for src in ("python", "cache", "relay", "relay-cached", "browser", "cache-lookup", "none"):
            self.assertIn(src, block)


class RelayConsentGateTests(unittest.TestCase):
    """Round 6b: the relay gate blocks a scan on a human decision, so it must
    read as a question — not as a status panel beside a running spinner."""

    def setUp(self) -> None:
        self.js = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        self.css = (ROOT / "css" / "app.css").read_text(encoding="utf-8")
        start = self.js.index("function renderRelayGate()")
        self.gate = self.js[start:self.js.index("\n/* Call before any scan", start)]
        # Strip comments: they discuss the OLD markup (btn-primary, tooltips)
        # and would otherwise satisfy assertions about the rendered output.
        self.markup = re.sub(r"//.*", "", self.gate)

    def test_gate_states_the_scan_is_paused(self):
        """Reviewers read the gate as 'the scan is running, maybe stuck'."""
        self.assertIn("scan is paused until you pick", self.markup)
        self.assertIn("Action needed", self.markup)

    def test_no_option_is_preselected(self):
        """A btn-primary among three choices reads as 'already answered'."""
        self.assertNotIn("btn-primary", self.markup)
        # Exactly three calls to the shared option() builder, one per choice.
        self.assertEqual(re.findall(r'\boption\("(\w+)"', self.markup),
                         ["host", "full", "deny"])
        self.assertIn('class="relay-option"', self.markup)

    def test_exactly_one_option_is_recommended(self):
        # The "Recommended" chip must actually be rendered…
        self.assertIn(">Recommended<", self.markup)
        self.assertIn("relay-option-rec", self.markup)
        # …and exactly one option passes rec=true — the privacy-preserving one.
        host = self.markup[self.markup.index('option("host"'):self.markup.index('option("full"')]
        self.assertIn("true", host)
        full = self.markup[self.markup.index('option("full"'):self.markup.index('option("deny"')]
        self.assertIn("false", full)
        deny = self.markup[self.markup.index('option("deny"'):]
        self.assertIn("false", deny)

    def test_each_option_explains_what_it_sends_and_returns(self):
        """The difference must be readable without hovering a tooltip."""
        # One shared builder emits both lines for every option.
        self.assertIn("<strong>Sends:</strong>", self.markup)
        self.assertIn("<strong>You get:</strong>", self.markup)
        for mode in ('option("host"', 'option("full"', 'option("deny"'):
            self.assertIn(mode, self.markup)

    def test_gate_is_scrolled_into_view_and_focused(self):
        """It rendered below the fold on a phone and went unnoticed."""
        # The scroll must actually run, not sit behind a dead guard.
        self.assertRegex(self.markup, r"\n\s*window\.scrollTo\(\{ top:")
        self.assertRegex(self.markup, r"\n\s*try \{ panel\.focus\(")
        # Top-aligned, not centred: the panel is taller than a phone viewport.
        self.assertNotIn('block: "center"', self.markup)

    def test_escape_declines_rather_than_relaying(self):
        self.assertIn('choose("deny")', self.markup)

    def test_spinner_stops_while_the_gate_waits(self):
        """A spinning Scan button makes the gate look like a slow scan."""
        start = self.js.index("async function ensureRelayConsent")
        body = self.js[start:self.js.index("\n}", start)]
        self.assertIn("is-waiting", body)
        self.assertIn("setLoading(btn, false)", body)
        self.assertIn("Waiting for your choice", body)
        # …and the spinner comes back when the scan actually resumes.
        self.assertIn("setLoading(btn, true)", body)

    def test_waiting_button_is_styled(self):
        self.assertIn(".btn.is-waiting", self.css)

    def test_options_stack_on_narrow_screens(self):
        start = self.css.index(".relay-consent-actions {")
        self.assertIn("repeat(3, 1fr)", self.css[start:self.css.index("}", start)])
        self.assertIn(".relay-consent-actions { grid-template-columns: 1fr; }", self.css)

    def test_gate_still_names_every_relay_host(self):
        """The disclosure must keep listing who would see the target."""
        self.assertIn("RELAY_HOSTS.join(", self.markup)
        start = self.js.index("const RELAY_HOSTS")
        for host in ("hackertarget.com", "allorigins.win", "corsproxy.io", "codetabs.com"):
            self.assertIn(host, self.js[start:start + 300])

    def test_gate_keeps_the_local_server_escape_hatch(self):
        self.assertIn("python3 server.py", self.markup)

    def test_consent_stays_session_scoped(self):
        """Consent must not silently persist across days."""
        start = self.js.index("function setRelayConsent")
        self.assertIn("sessionStorage", self.js[start:self.js.index("}", start)])


class ResponsiveLayoutTests(unittest.TestCase):
    """Round 6c: per-element responsiveness fixes, found by measuring painted
    elements against the viewport at seven widths (2560 down to 360)."""

    def setUp(self) -> None:
        self.css = (ROOT / "css" / "app.css").read_text(encoding="utf-8")
        # Comments discuss the rules (and name :has()); assert on real CSS.
        self.rules = re.sub(r"/\*.*?\*/", "", self.css, flags=re.S)

    def _rule(self, selector: str) -> str:
        start = self.css.index(selector)
        return self.css[start:self.css.index("}", start)]

    def test_touch_targets_meet_24px(self):
        """Measured at 390px these rendered 20-23px tall — under the touch
        minimum, and the controls a phone user most often mis-taps."""
        start = self.css.index("/* Touch tap targets.")
        block = self.css[start:self.css.index("@media (max-width: 760px)", start)]
        self.assertIn("min-height: 24px", block)
        for sel in (".engine-chip", ".recent-chip", ".recent-clear", ".copy-finding"):
            self.assertIn(sel, block)

    def test_evidence_toggle_label_is_the_tap_target(self):
        """The checkbox is 13px; its <label> wrapper carries the minimum."""
        self.assertIn("min-height: 24px", self._rule(".evidence-toggle {"))

    def test_recent_chip_cannot_span_the_row(self):
        """A chip holding a long URL must stay tappable without filling the
        width of a phone screen."""
        start = self.css.index("/* Touch tap targets.")
        block = self.css[start:self.css.index("@media (max-width: 760px)", start)]
        self.assertIn("max-width: min(260px, calc(100vw - 72px))", block)

    def test_console_dividers_cannot_bleed_past_the_card(self):
        """The demo console's divider lines are fixed-length box-drawing runs
        that cannot wrap; at 360px they painted ~21px past the edge."""
        rules = [r for r in self.css.split("\n") if ".console .c-dim" in r]
        self.assertTrue(any("overflow: hidden" in r for r in rules), rules)

    def test_method_tables_scroll_on_tiny_screens(self):
        """At 360px the scoring tables overflowed their card by a few px."""
        start = self.rules.index("@media (max-width: 420px)")
        block = self.rules[start:self.rules.index("}", self.rules.index(".method-table", start))]
        self.assertIn("overflow-x: auto", block)

    def test_no_has_selector_dependency_for_layout(self):
        """:has() is progressive enhancement only — never load-bearing."""
        self.assertNotIn(":has(", self.rules)

    def test_pipeline_diagram_spans_the_container_in_columns(self):
        """Pre-launch review: the 6-step pipeline was a min(560px) vertical
        stack — 300px+ of dead gutter either side on a 1160px container.
        It is a responsive flow grid now: 3 cols desktop, 2 tablet, 1 phone."""
        body = self._rule(".pipeline-diagram {")
        self.assertIn("display: grid", body)
        self.assertIn("repeat(3, 1fr)", body)
        self.assertNotIn("flex-direction: column", body)
        node = self._rule(".pd-node {")
        self.assertIn("width: 100%", node)
        self.assertIn("@media (max-width: 1060px) { .pipeline-diagram { grid-template-columns: repeat(2, 1fr); } }",
                      self.rules)
        start = self.rules.index("@media (max-width: 760px)", self.rules.index(".pd-arrow"))
        block = self.rules[start:self.rules.index("\n}", start)]
        self.assertIn(".pipeline-diagram { grid-template-columns: 1fr; }", block)
        # The numbered 01–06 steps carry the sequence in the grid; the ↓
        # glyphs only make sense in the single-column phone stack.
        self.assertIn(".pd-arrow { display: none; }", self.rules)
        self.assertIn(".pd-arrow { display: block; text-align: center; }", block)
        # No rule may reintroduce the narrow centered-column cap that used
        # to pinch both the pipeline and the (now-removed) architecture diagram.
        self.assertNotIn("min(560px", self.rules)

    def test_pipeline_arrows_are_decorative(self):
        """The ↓ glyphs duplicate the numbered steps, so they must not be
        announced by screen readers."""
        hub = (ROOT / "index.html").read_text(encoding="utf-8")
        glyphs = hub.count('<div class="pd-arrow" aria-hidden="true">↓')
        bare = hub.count('<div class="pd-arrow">↓')
        self.assertGreater(glyphs, 0)
        self.assertEqual(bare, 0)


class FluidResponsiveSystemTests(unittest.TestCase):
    """RESP-01: the multi-device, standards-first layout system.

    The responsive rework replaced the ad-hoc breakpoints with a small,
    documented device ladder plus a fluid type/spacing scale (`clamp()` +
    custom-property tokens) and `auto-fit`/`minmax()` card grids, and added a
    large-monitor tier so a 2560px panel uses its width instead of leaving
    huge gutters. Media queries cannot read custom properties (a CSS
    limitation), so the *breakpoint values* are literals re-stated against the
    documented ladder while every *layout dimension* they drive is a token.
    These stdlib tests gate the rules in CI — the browser suites verify the
    rendered result (see tests/browser/responsive.js).
    """

    def setUp(self) -> None:
        self.css = (ROOT / "css" / "app.css").read_text(encoding="utf-8")
        # Comments discuss the system (and name :has()); assert on real CSS.
        self.rules = re.sub(r"/\*.*?\*/", "", self.css, flags=re.S)

    def _rule(self, selector: str) -> str:
        start = self.css.index(selector)
        return self.css[start:self.css.index("}", start)]

    def test_fluid_type_scale_is_tokenized_with_clamp(self):
        """Type must scale continuously (clamp) via tokens, not hardcoded px."""
        root = self._rule(":root {")
        for token in ("--fs-h1", "--fs-h2", "--fs-h3", "--fs-lead"):
            with self.subTest(token=token):
                self.assertIn(token, root, token)
                self.assertIn("clamp(", root[0:root.index(token) + 120], token)
        # The heading/lead rules consume the tokens, not literal sizes.
        self.assertIn("font-size: var(--fs-h1)", self._rule("h1 {"))
        self.assertIn("font-size: var(--fs-h2)", self._rule("h2 {"))
        self.assertIn("font-size: var(--fs-lead)", self._rule(".lead {"))

    def test_container_width_is_tokenized(self):
        """The column width reads --container-max, so wide tiers only have to
        re-define the token — never touch .container itself."""
        self.assertIn("var(--container-max)", self._rule(".container {"))

    def test_large_monitors_widen_the_column_via_the_token(self):
        """A 2560px monitor must widen the readable column, not sit at 1160px
        with giant gutters. Each tier re-defines --container-max upward."""
        # The default column caps at 1160px…
        self.assertIn("--container-max: 1160px", self._rule(":root {"))
        # …and the wide tiers push it out in order.
        tiers = [
            ("1440px", "1320px"),
            ("1920px", "1480px"),
            ("2560px", "1560px"),
        ]
        for width, expected in tiers:
            with self.subTest(tier=width):
                block = self.rules[
                    self.rules.index("@media (min-width: %s)" % width):
                    self.rules.index("}", self.rules.index("@media (min-width: %s)" % width))
                ]
                self.assertIn("--container-max: %s" % expected, block)

    def test_card_grids_are_autofit_minmax(self):
        """Card grids must reflow to fill their container (1-up phone, N-up
        monitor) instead of being pinned to a fixed column count."""
        for selector, needle in (
            (".tool-grid {", "repeat(auto-fit, minmax(min(100%"),
            (".suite-grid {", "repeat(auto-fit, minmax(min(100%"),
            (".blog-grid {", "repeat(auto-fit, minmax(min(100%"),
            (".tool-catalog-grid {", "repeat(auto-fit, minmax(min(100%"),
        ):
            with self.subTest(selector=selector):
                self.assertIn(needle, self._rule(selector))

    def test_prefers_contrast_is_supported(self):
        """Visitors who need more contrast get stronger borders and more
        opaque surfaces in both themes, via the tokens only."""
        start = self.css.index("@media (prefers-contrast: more)")
        block = self.css[start:]
        self.assertIn("--line", block)
        self.assertIn("--surface", block)
        # Both themes are handled.
        self.assertIn('html[data-theme="light"]', block)
        self.assertIn(":focus-visible", block)

    def test_no_container_query_or_has_dependency_for_layout(self):
        """The reflow relies on auto-fit/minmax, not on container queries
        (whose inline-size containment would clip the score gauges / radar
        that intentionally paint outside their card) or on :has()."""
        self.assertNotIn(":has(", self.rules)
        self.assertNotIn("@container", self.rules)
        self.assertNotIn("container-type", self.rules)


class ThemeContrastTests(unittest.TestCase):
    """WCAG AA (4.5:1) for every text/background token pairing in BOTH
    themes, computed from the real css/app.css variables with translucent
    surfaces composited over the page gradient. The pre-launch audit found
    light-theme --faint (3.0), --brand (3.7) and --accent-2 (4.3) failing AA;
    this test keeps every pairing above the floor forever."""

    @staticmethod
    def _parse_color(value):
        value = value.strip()
        if value.startswith("#"):
            h = value[1:]
            if len(h) == 3:
                h = "".join(x * 2 for x in h)
            return ((int(h[0:2], 16) / 255, int(h[2:4], 16) / 255,
                     int(h[4:6], 16) / 255), 1.0)
        match = re.match(r"rgba?\(([^)]+)\)", value)
        parts = [x for x in re.split(r"[,\s/]+", match.group(1).strip())
                 if x and x != "/"]
        rgb = tuple(float(x) / 255 for x in parts[:3])
        return rgb, (float(parts[3]) if len(parts) == 4 else 1.0)

    @staticmethod
    def _composite(color, alpha, backdrop):
        return tuple(c * alpha + b * (1 - alpha) for c, b in zip(color, backdrop))

    @staticmethod
    def _luminance(rgb):
        def channel(x):
            return x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4
        return (0.2126 * channel(rgb[0]) + 0.7152 * channel(rgb[1])
                + 0.0722 * channel(rgb[2]))

    @classmethod
    def _ratio(cls, fg, bg):
        lf, lb = cls._luminance(fg), cls._luminance(bg)
        return (max(lf, lb) + 0.05) / (min(lf, lb) + 0.05)

    def _themes(self):
        import re as _re
        css = (ROOT / "css" / "app.css").read_text(encoding="utf-8")

        def block(pattern):
            match = _re.search(pattern + r"\s*\{(.*?)\n\}", css, _re.S)
            self.assertIsNotNone(match, pattern)
            vars_ = dict(_re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", match.group(1)))
            for key, value in list(vars_.items()):
                ref = _re.match(r"var\((--[\w-]+)\)", value.strip())
                if ref and ref.group(1) in vars_:
                    vars_[key] = vars_[ref.group(1)]
            return vars_

        dark = block(r":root")
        light = {**dark, **block(_re.escape('html[data-theme="light"]'))}
        return {"dark": dark, "light": light}

    def test_every_text_pairing_meets_aa_in_both_themes(self):
        for name, theme in self._themes().items():
            bg_top = self._parse_color(theme["--bg-top"])[0]
            bg_bottom = self._parse_color(theme["--bg-bottom"])[0]
            backdrop = tuple((a + b) / 2 for a, b in zip(bg_top, bg_bottom))
            surface_fx, surface_a = self._parse_color(theme["--surface"])
            surface = self._composite(surface_fx, surface_a, backdrop)
            soft_fx, soft_a = self._parse_color(theme["--brand-soft"])
            brand_soft = self._composite(soft_fx, soft_a, surface)
            pairs = [
                ("--ink", surface), ("--muted", surface), ("--faint", surface),
                ("--brand", surface), ("--accent-2", surface),
                ("--high", surface), ("--med", surface), ("--low", surface),
                ("--brand", brand_soft), ("--ink", brand_soft),
                ("--on-brand", self._parse_color(theme["--brand"])[0]),
            ]
            for fg, bgc in pairs:
                with self.subTest(theme=name, foreground=fg):
                    ratio = self._ratio(self._parse_color(theme[fg])[0], bgc)
                    self.assertGreaterEqual(ratio, 4.5,
                                            "%s %s contrast %.2f" % (name, fg, ratio))

    def test_on_brand_token_drives_every_brand_background(self):
        """Text painted on --brand backgrounds must track the --on-brand
        token so theme swaps keep button/skip-link/icon text legible."""
        css = (ROOT / "css" / "app.css").read_text(encoding="utf-8")
        rules = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        brand_bg_rules = re.findall(r"[^{}]+\{[^}]*background: var\(--brand\)[^}]*\}", rules)
        self.assertTrue(brand_bg_rules)
        for rule in brand_bg_rules:
            if "::" in rule.split("{")[0]:
                continue  # ::after/::before paint dots and underlines, not text
            color = re.search(r"(?<![-\w])color:\s*([^;]+);", rule)
            with self.subTest(rule=rule[:60]):
                self.assertIsNotNone(color)
                self.assertEqual(color.group(1).strip(), "var(--on-brand)")


class CsrfParserTests(unittest.TestCase):
    """CSRF PoC Generator: parser + generator + escaping (pure JS, no DOM).

    Loads js/tool.csrf.js under Node (its pure engine is intentionally free of
    `document`/`window`) and asserts the browser-mechanics contract: body-type
    parsing, honest variant generation, HTML/JS escaping, forbidden-header
    redaction, token include/exclude and auto-submit behaviour.
    """

    def _run_csrf(self, harness: str):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import tempfile

        script = (
            (ROOT / "js" / "tool.csrf.js").read_text(encoding="utf-8")
            + "\n" + harness
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run(
                [node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=30,
            )
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def test_parses_crlf_lf_absolute_and_relative(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const rows = {};
const crlf = "POST /p?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\na=1";
const lf = "GET /p HTTP/1.1\nHost: localhost:8080\n\n";
const abs = "PUT https://api.example.com:8443/v1/a HTTP/1.1\nContent-Type: application/json\n\n{}";
const rel = "GET /x HTTP/1.1\nHost: example.com\n\n";
[["crlf", crlf], ["lf", lf], ["abs", abs], ["rel", rel]].forEach(([k, raw]) => {
  const p = C.parseRequest(raw);
  rows[k] = { ok: p.ok, method: p.method, host: p.host, port: p.port, scheme: p.scheme, path: p.path, url: p.url };
});
console.log(JSON.stringify(rows));
''')
        self.assertTrue(out["crlf"]["ok"])
        self.assertEqual(out["crlf"]["method"], "POST")
        self.assertEqual(out["crlf"]["host"], "example.com")
        self.assertEqual(out["crlf"]["url"], "https://example.com/p?x=1")
        self.assertTrue(out["lf"]["ok"])
        self.assertEqual(out["lf"]["host"], "localhost")
        self.assertEqual(out["lf"]["port"], "8080")
        self.assertEqual(out["lf"]["scheme"], "http")
        self.assertTrue(out["abs"]["ok"])
        self.assertEqual(out["abs"]["host"], "api.example.com")
        self.assertEqual(out["abs"]["port"], "8443")
        self.assertEqual(out["abs"]["path"], "/v1/a")
        self.assertTrue(out["rel"]["ok"])
        self.assertEqual(out["rel"]["url"], "https://example.com/x")

    def test_get_post_forms_and_query_params(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const get = C.generatePoc(C.parseRequest("GET /s?q=1&q=2&blank= HTTP/1.1\r\nHost: e.com\r\n\r\n"), {autoSubmit:false, excluded:{}});
const post = C.generatePoc(C.parseRequest("POST /login HTTP/1.1\r\nHost: e.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&pass=p%40ss"), {autoSubmit:false, excluded:{}});
console.log(JSON.stringify({
  getStatus: get.status,
  getHtml: get.variants[0].html,
  postStatus: post.status,
  postHtml: post.variants[0].html,
  postFields: (post.variants[0].html.match(/type="hidden"/g) || []).length
}));
''')
        self.assertEqual(out["getStatus"], "READY")
        self.assertIn('method="GET"', out["getHtml"])
        self.assertIn('name="q"', out["getHtml"])
        self.assertIn('value="p@ss"', out["postHtml"])  # %40 is decoded before building the hidden input
        self.assertEqual(out["postStatus"], "READY")

    def test_urlencoded_value_is_decoded_for_form(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const p = C.parseRequest("POST /l HTTP/1.1\r\nHost: e.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nmail=a%40b.com&plain=hello+world");
const g = C.generatePoc(p, {autoSubmit:false, excluded:{}});
console.log(JSON.stringify(g.variants[0].html));
''')
        self.assertIn('value="a@b.com"', out)
        self.assertIn('value="hello world"', out)

    def test_multipart_text_and_file_fields(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const raw = "POST /u HTTP/1.1\r\nHost: e.com\r\nContent-Type: multipart/form-data; boundary=----x\r\n\r\n------x\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhi\r\n------x\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nDATA\r\n------x--\r\n";
const p = C.parseRequest(raw);
const g = C.generatePoc(p, {autoSubmit:false, excluded:{}});
const html = g.variants[0].html;
console.log(JSON.stringify({ status: g.status, hasFileInput: /type="file"/.test(html), hasTitle: /name="title"/.test(html), hasFileField: p.hasFileFields }));
''')
        self.assertEqual(out["status"], "LIMITED")
        self.assertTrue(out["hasFileField"])
        self.assertTrue(out["hasFileInput"])
        self.assertTrue(out["hasTitle"])

    def test_text_plain_exact_body_and_form(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const p = C.parseRequest("POST /t HTTP/1.1\r\nHost: e.com\r\nContent-Type: text/plain\r\n\r\na=b\nc=d");
const g = C.generatePoc(p, {autoSubmit:false, excluded:{}});
console.log(JSON.stringify({
  status: g.status,
  ids: g.variants.map(v => v.id),
  fetchHtml: g.variants.find(v => v.id === "textplain-fetch").html
}));
''')
        self.assertEqual(out["status"], "READY")
        self.assertIn("textplain-fetch", out["ids"])
        self.assertIn("textplain-form", out["ids"])
        self.assertIn("a=b", out["fetchHtml"])

    def test_json_is_fetch_and_never_pretends_to_be_a_form(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const p = C.parseRequest("POST /api HTTP/1.1\r\nHost: e.com\r\nContent-Type: application/json\r\n\r\n{\"a\":1}");
const g = C.generatePoc(p, {autoSubmit:false, excluded:{}});
console.log(JSON.stringify({ status: g.status, ids: g.variants.map(v => v.id), html: g.variants[0].html }));
''')
        self.assertEqual(out["status"], "LIMITED")
        self.assertIn("json-fetch", out["ids"])
        self.assertIn('method: "POST"', out["html"])
        self.assertIn('"Content-Type": "application/json"', out["html"])

    def test_duplicate_and_blank_params_preserved(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const p = C.parseRequest("POST /f HTTP/1.1\r\nHost: e.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ndup=1&dup=2&blank=&noparam");
const g = C.generatePoc(p, {autoSubmit:false, excluded:{}});
const html = g.variants[0].html;
console.log(JSON.stringify({ names: (html.match(/type="hidden"/g) || []).length, dup1: html.includes('name="dup" value="1"'), dup2: html.includes('name="dup" value="2"'), blank: html.includes('name="blank" value=""'), noparam: html.includes('name="noparam" value=""') }));
''')
        self.assertEqual(out["names"], 4)
        self.assertTrue(out["dup1"] and out["dup2"] and out["blank"] and out["noparam"])

    def test_malformed_requests_have_clear_errors(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const cases = {
  empty: "",
  noRequestLine: "Host: e.com\r\n\r\n",
  noHost: "POST /x HTTP/1.1\r\n\r\na=1",
  badScheme: "POST ftp://e.com/x HTTP/1.1\r\n\r\n",
  badRequestLine: "garbage line here"
};
const rows = {};
Object.keys(cases).forEach(k => { const p = C.parseRequest(cases[k]); rows[k] = { ok: p.ok, errors: p.errors.map(e => e.message) }; });
console.log(JSON.stringify(rows));
''')
        for key in ("empty", "noRequestLine", "noHost", "badScheme", "badRequestLine"):
            self.assertFalse(out[key]["ok"], key)
            self.assertTrue(out[key]["errors"], key)
            self.assertTrue(out[key]["errors"][0], key)

    def test_forbidden_headers_never_reach_generated_html(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const raw = "POST /x HTTP/1.1\r\nHost: victim.example\r\nCookie: session=TOP-SECRET-COOKIE\r\nAuthorization: Bearer TOP-SECRET-AUTH\r\nContent-Length: 123\r\nOrigin: https://attacker.example\r\nReferer: https://attacker.example/ref\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1";
const p = C.parseRequest(raw);
const g = C.generatePoc(p, {autoSubmit:false, excluded:{}});
const all = g.variants.map(v => v.html).join("\n");
console.log(JSON.stringify({
  hasCookie: /TOP-SECRET-COOKIE/.test(all),
  hasAuth: /TOP-SECRET-AUTH/.test(all) || /Bearer/.test(all),
  hasAttackerOrigin: /attacker\.example/.test(all),
  hasVictimHost: /victim\.example/.test(all),
  headerNames: ["Cookie:", "Authorization:", "Origin:", "Referer:", "Content-Length:", "Host:"].filter(h => all.includes(h))
}));
''')
        self.assertFalse(out["hasCookie"])
        self.assertFalse(out["hasAuth"])
        self.assertFalse(out["hasAttackerOrigin"])
        self.assertTrue(out["hasVictimHost"])  # the target host is the one thing that must survive
        self.assertEqual(out["headerNames"], [])

    def test_escaping_protects_attributes_and_scripts(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const p = C.parseRequest("POST /e HTTP/1.1\r\nHost: e.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nx=</script><img src=x onerror=1>&q=\"quoted\"<tag>");
const g = C.generatePoc(p, {autoSubmit:false, excluded:{}});
const formHtml = g.variants[0].html;
const jp = C.parseRequest("POST /j HTTP/1.1\r\nHost: e.com\r\nContent-Type: application/json\r\n\r\n{\"p\":\"</script><script>alert(1)</script>\"}");
const jg = C.generatePoc(jp, {autoSubmit:false, excluded:{}});
const jsonHtml = jg.variants[0].html;
console.log(JSON.stringify({
  rawScriptInForm: formHtml.includes("</script><img"),
  escapedLt: formHtml.includes("&lt;/script&gt;"),
  rawScriptInJson: jsonHtml.includes("</script><script>"),
  unicodeEsc: jsonHtml.includes("\\u003c/script")
}));
''')
        self.assertFalse(out["rawScriptInForm"])
        self.assertTrue(out["escapedLt"])
        self.assertFalse(out["rawScriptInJson"])
        self.assertTrue(out["unicodeEsc"])

    def test_token_detection_and_exclusion(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const p = C.parseRequest("POST /s HTTP/1.1\r\nHost: e.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncsrf_token=ABC&name=joe");
const tokens = p.tokens.map(t => t.name);
const included = C.generatePoc(p, {autoSubmit:false, excluded:{}});
const excluded = C.generatePoc(p, {autoSubmit:false, excluded:{ "b:0": true }});
console.log(JSON.stringify({
  tokens,
  includedHasToken: /name="csrf_token"/.test(included.variants[0].html),
  excludedHasToken: /name="csrf_token"/.test(excluded.variants[0].html)
}));
''')
        self.assertEqual(out["tokens"], ["csrf_token"])
        self.assertTrue(out["includedHasToken"])
        self.assertFalse(out["excludedHasToken"])

    def test_auto_submit_off_and_on(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const p = C.parseRequest("POST /s HTTP/1.1\r\nHost: e.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1");
const off = C.generatePoc(p, {autoSubmit:false, excluded:{}});
const on = C.generatePoc(p, {autoSubmit:true, excluded:{}});
console.log(JSON.stringify({
  offHtml: off.variants[0].html,
  onHtml: on.variants[0].html
}));
''')
        self.assertIn("Send request", out["offHtml"])
        self.assertNotIn("AUTO-SUBMIT ENABLED", out["offHtml"])
        self.assertIn("AUTO-SUBMIT ENABLED", out["onHtml"])
        self.assertIn('document.getElementById("csrf-form").submit();', out["onHtml"])
        # The auto-submit script is fixed text — no request value concatenated in.
        self.assertNotIn("a=1", out["onHtml"].split("AUTO-SUBMIT ENABLED")[1])

    def test_statuses_read_limited_not_representable(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const urlenc = C.generatePoc(C.parseRequest("POST /a HTTP/1.1\r\nHost: e.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1"), {autoSubmit:false, excluded:{}});
const put = C.generatePoc(C.parseRequest("PUT /b HTTP/1.1\r\nHost: e.com\r\nContent-Type: application/json\r\n\r\n{}"), {autoSubmit:false, excluded:{}});
const getBody = C.generatePoc(C.parseRequest("GET /c HTTP/1.1\r\nHost: e.com\r\n\r\nbody"), {autoSubmit:false, excluded:{}});
const trace = C.generatePoc(C.parseRequest("TRACE /d HTTP/1.1\r\nHost: e.com\r\n\r\n"), {autoSubmit:false, excluded:{}});
console.log(JSON.stringify({ urlenc: urlenc.status, put: put.status, getBody: getBody.status, trace: trace.status }));
''')
        self.assertEqual(out["urlenc"], "READY")
        self.assertEqual(out["put"], "LIMITED")
        self.assertEqual(out["getBody"], "NOT DIRECTLY REPRESENTABLE")
        self.assertEqual(out["trace"], "NOT DIRECTLY REPRESENTABLE")

    def test_json_as_text_plain_alternative_only_when_applicable(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
const withEq = C.generatePoc(C.parseRequest("POST /j HTTP/1.1\r\nHost: e.com\r\nContent-Type: application/json\r\n\r\n{\"a\":\"x=y\"}"), {autoSubmit:false, excluded:{}});
const noEq = C.generatePoc(C.parseRequest("POST /j HTTP/1.1\r\nHost: e.com\r\nContent-Type: application/json\r\n\r\n{\"novalue\"}"), {autoSubmit:false, excluded:{}});
console.log(JSON.stringify({ withEq: withEq.variants.map(v => v.id), noEq: noEq.variants.map(v => v.id) }));
''')
        self.assertIn("json-textplain", out["withEq"])
        self.assertNotIn("json-textplain", out["noEq"])

    def test_safe_filename_is_hostname_based(self):
        out = self._run_csrf(r'''
const C = globalThis.CyberBuddyCsrf;
console.log(JSON.stringify({
  a: C.safeFilename({ host: "Victim.Example.com", method: "POST" }),
  b: C.safeFilename({ host: "a b/c.com", method: "GET" })
}));
''')
        self.assertEqual(out["a"], "csrf-post-victim.example.com.html")
        self.assertEqual(out["b"], "csrf-get-a-b-c.com.html")


class VerdictContractTests(unittest.TestCase):
    """B3: every result-producing tool shares one verdict DOM contract.

    The five tools that emit a verdict had drifted into two incompatible
    shapes. `#verdict` meant the *banner* on headers/clickjacking but the
    *risk chip* on csp/cors/csrf, so the same id selected different kinds of
    element depending on the page. Headers additionally nested its chip
    inside the banner instead of the report actions.

    The agreed contract, asserted here so it cannot silently drift again:
      * `#verdict`       -- the terse risk chip, in `.report-actions`
      * `#verdictBanner` -- the full verdict block, the single live region
    """

    TOOLS = ("headers", "clickjacking", "csp", "cors", "csrf")

    def _page(self, tool: str) -> str:
        return (ROOT / "tools" / tool / "index.html").read_text(encoding="utf-8")

    def test_every_tool_defines_both_ids_exactly_once(self):
        for tool in self.TOOLS:
            with self.subTest(tool=tool):
                page = self._page(tool)
                self.assertEqual(page.count('id="verdict"'), 1)
                self.assertEqual(page.count('id="verdictBanner"'), 1)

    def test_risk_chip_lives_in_report_actions(self):
        for tool in self.TOOLS:
            with self.subTest(tool=tool):
                page = self._page(tool)
                actions = page[page.index('class="report-actions"'):]
                actions = actions[:actions.index("</div>")]
                self.assertIn('id="verdict"', actions)
                self.assertIn('class="risk unknown"', actions)

    def test_banner_is_the_only_live_region(self):
        # Two nested live regions made screen readers announce the verdict
        # twice on headers/clickjacking; announcing only the chip on the
        # others dropped the summary prose entirely.
        for tool in self.TOOLS:
            with self.subTest(tool=tool):
                page = self._page(tool)
                banner = page[page.index('id="verdictBanner"'):]
                banner = banner[:banner.index(">")]
                self.assertIn('role="status"', banner)
                self.assertIn('aria-live="polite"', banner)

                chip = page[page.index('id="verdict"'):]
                chip = chip[:chip.index(">")]
                self.assertNotIn("aria-live", chip)
                self.assertNotIn('role="status"', chip)

    def test_controllers_target_the_contract_ids(self):
        # The chip carries `.risk`, the banner carries `.verdict-banner`.
        # Swapping them would silently strip one of the two of its styling.
        for tool in self.TOOLS:
            with self.subTest(tool=tool):
                js = (ROOT / "js" / f"tool.{tool}.js").read_text(encoding="utf-8")
                # The pre-convergence chip id must be gone everywhere.
                self.assertNotIn('$("risk")', js)
                # The banner must be reached by its contract id and be given
                # the banner class. Controllers may assign directly or via a
                # guarded local, so assert both facts rather than one spelling.
                self.assertIn('$("verdictBanner")', js)
                self.assertIn('"verdict-banner "', js)

    def test_every_id_a_controller_touches_exists_on_its_page(self):
        for tool in self.TOOLS:
            with self.subTest(tool=tool):
                js = (ROOT / "js" / f"tool.{tool}.js").read_text(encoding="utf-8")
                page = self._page(tool)
                for ident in sorted(set(re.findall(r'\$\("([A-Za-z0-9_]+)"\)', js))):
                    self.assertIn(f'id="{ident}"', page, f"{tool}: no #{ident} on page")


class ToolCatalogTests(unittest.TestCase):
    """IA-01: scalable tool information architecture.

    The TOOLS_MENU registry in js/app.js is the single source of tool
    metadata; the header menu, hub grid, footer and the new /tools/ catalog
    all read from it. Scan tools are category "assess" (part of the hub
    suite), the CSRF PoC Generator is category "local" (never a scanner).
    """

    def _app(self) -> str:
        return (ROOT / "js" / "app.js").read_text(encoding="utf-8")

    def test_registry_has_exactly_two_categories(self):
        app = self._app()
        self.assertIn('category: "assess"', app)
        self.assertIn('category: "local"', app)
        # Five target tools assess (the four HTTP tools + the DNS analyzer,
        # which the hub suite feeds from the URL hostname); local utilities
        # are the CSRF PoC Generator and the JWT Security Workbench.
        self.assertEqual(app.count('category: "assess"'), 5)
        self.assertEqual(app.count('category: "local"'), 2)

    def test_categories_define_suite_membership(self):
        app = self._app()
        start = app.index("const TOOL_CATEGORIES")
        block = app[start:app.index("const TOOLS_MENU", start)]
        self.assertIn("suite: true", block)
        self.assertIn("suite: false", block)
        self.assertIn("Assess targets", block)
        self.assertIn("Local utilities", block)

    def test_tools_menu_groups_by_category(self):
        """The dropdown must not be one flat list — it groups tools under
        category labels so it can scale past five tools."""
        app = self._app()
        start = app.index("function toolsMenu(")
        body = app[start:app.index("\nfunction navLink(", start)]
        self.assertIn("nav-menu-group", body)
        self.assertIn('["assess", "local"]', body)
        # The catalog is reachable from the menu itself.
        self.assertIn('"/tools/"', body)
        self.assertIn("All tools", body)

    def test_catalog_page_exists_and_loads_shared_js(self):
        page = ROOT / "tools" / "index.html"
        self.assertTrue(page.is_file(), page)
        text = page.read_text(encoding="utf-8")
        self.assertIn("js/app.js", text)
        self.assertIn("renderToolCatalog", text)
        self.assertIn('id="assess-targets"', text)
        self.assertIn('id="local-utilities"', text)
        # The catalog must not widen the framing policy (it needs no iframe).
        self.assertIn("frame-src 'none'", text)

    def test_catalog_renderer_reads_the_single_registry(self):
        app = self._app()
        self.assertIn("function renderToolCatalog()", app)
        self.assertIn("TOOLS_MENU.filter((t) => t.category", app)
        self.assertIn("TOOL_CATEGORIES[t.category]", app)

    def test_footer_is_scalable_not_a_tool_list(self):
        """The footer lists categories, not every tool — adding a tool must
        not require a footer edit."""
        app = self._app()
        start = app.index("function renderFooter()")
        body = app[start:app.index("\n/* ---------- Blog", start)]
        self.assertIn("All tools", body)
        self.assertIn("Target assessments", body)
        self.assertIn("Local utilities", body)
        self.assertIn("Security policy", body)
        # No per-tool links remain in the footer.
        self.assertNotIn("/tools/clickjacking/", body)
        self.assertNotIn("/tools/headers/", body)
        self.assertNotIn("/tools/csrf/", body)

    def test_sitemap_lists_the_catalog(self):
        sitemap = (ROOT / "sitemap.xml").read_text(encoding="utf-8")
        self.assertIn("/CyberBuddy/tools/", sitemap)

    def test_llms_txt_lists_the_catalog(self):
        text = (ROOT / "llms.txt").read_text(encoding="utf-8")
        self.assertIn("/tools/", text)

    def test_hub_links_to_the_catalog(self):
        hub = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn('class="catalog-link"', hub)
        self.assertIn('href="tools/"', hub)
        self.assertIn('id="assess-targets"', hub)
        self.assertIn('id="local-utilities"', hub)

    def test_hub_cards_are_split_into_two_grids(self):
        hub = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="assessGrid"', hub)
        self.assertIn('id="localGrid"', hub)
        # The CSRF card sits under Local utilities, not the scan group.
        local = hub[hub.index('id="localGrid"'):hub.index('id="localGrid"') + 2000]
        self.assertIn("CSRF PoC Generator", local)

    def test_csrf_is_local_and_not_in_the_scan_suite(self):
        """The generator never joins the hub suite — that stays the five
        target tools (apiScan / apiHeaders / apiCors / apiCsp / apiDns)."""
        app = self._app()
        start = app.index("function initSuite()")
        body = app[start:app.index("/* ---------- Scan pipeline", start)]
        self.assertIn("apiScan", body)
        self.assertIn("apiCsp", body)
        self.assertIn("apiDns", body)
        self.assertNotIn("csrf", body.lower())

    def test_clickjacking_relay_result_is_an_assessment_not_a_proof(self):
        page = (ROOT / "tools" / "clickjacking" / "index.html").read_text(encoding="utf-8")
        app = self._app()
        self.assertIn("Clickjacking assessment", page)
        self.assertNotIn("Clickjacking proof", page)
        self.assertIn("relay data", app)
        # Provenance remains visible; a relay is not first-hand evidence.
        self.assertIn("isUnverified(data)", app)

    def test_suite_exports_and_menu_icons_are_report_artifacts(self):
        app = self._app()
        self.assertIn("suiteExportEnvelope", app)
        self.assertIn("suiteMarkdown", app)
        self.assertIn("suiteCsv", app)
        self.assertIn("suiteStandaloneHtml", app)
        self.assertIn("ICONS[t.icon]", app)
        dropdown = (ROOT / "tests" / "browser" / "dropdown.js").read_text(encoding="utf-8")
        self.assertIn("hasIcon", dropdown)
        self.assertIn("missing icon", dropdown)
        self.assertNotIn("initShareButton", app)
        hub = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn("Download suite report", hub)
        for format_name in ("Markdown", "JSON", "CSV", "HTML"):
            self.assertIn("Download " + format_name, hub)
        for slug in ("clickjacking", "headers", "cors", "csp", "dns"):
            self.assertNotIn("shareLink", (ROOT / "tools" / slug / "index.html").read_text(encoding="utf-8"))

    def test_catalog_page_uses_established_shell(self):
        """The catalog keeps the shared theme/meta CSP contract like every
        other page (checked in HostedCspTests)."""
        page = (ROOT / "tools" / "index.html").read_text(encoding="utf-8")
        self.assertIn("theme-boot.js", page)
        self.assertIn("boot.js", page)


class GuidesTests(unittest.TestCase):
    """The public Guides section: one guide per tool.

    The point of a guide is that it is *connected*: reachable from the global
    nav, paired with the tool that confirms the finding, and honest about
    where the depth comes from (primary references, not a blog that has no
    post on the topic). Guides stay deliberately concise — five short notes,
    not an article library.
    """

    INDEX = ROOT / "guides" / "index.html"

    #: slug -> (tool slug, standards that must appear, primary references)
    GUIDES = {
        "clickjacking": (
            "clickjacking",
            ("WSTG-CLNT-09", "CWE-1021"),
            (
                "https://owasp.org/www-project-web-security-testing-guide/latest"
                "/4-Web_Application_Security_Testing/11-Client-side_Testing"
                "/09-Testing_for_Clickjacking",
                "https://cwe.mitre.org/data/definitions/1021.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/"
                "Clickjacking_Defense_Cheat_Sheet.html",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference"
                "/Headers/Content-Security-Policy/frame-ancestors",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference"
                "/Headers/X-Frame-Options",
                "https://w3c.github.io/webappsec-csp/",
                "https://portswigger.net/web-security/clickjacking",
            ),
        ),
        "headers": (
            "headers",
            ("WSTG-CONF-07", "CWE-693"),
            (
                "https://cheatsheetseries.owasp.org/cheatsheets/"
                "HTTP_Headers_Cheat_Sheet.html",
                "https://owasp.org/www-project-web-security-testing-guide/latest"
                "/4-Web_Application_Security_Testing"
                "/02-Configuration_and_Deployment_Management_Testing"
                "/07-Test_HTTP_Strict_Transport_Security",
                "https://cwe.mitre.org/data/definitions/693.html",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference"
                "/Headers/Strict-Transport-Security",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference"
                "/Headers/Referrer-Policy",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference"
                "/Headers/Set-Cookie",
            ),
        ),
        "cors": (
            "cors",
            ("WSTG-CLNT-07", "CWE-942"),
            (
                "https://owasp.org/www-project-web-security-testing-guide/latest"
                "/4-Web_Application_Security_Testing/11-Client-side_Testing"
                "/07-Testing_Cross_Origin_Resource_Sharing",
                "https://cwe.mitre.org/data/definitions/942.html",
                "https://portswigger.net/web-security/cors",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference"
                "/Headers/Access-Control-Allow-Origin",
            ),
        ),
        "csp": (
            "csp",
            ("WSTG-CONF-12", "CWE-79"),
            (
                "https://owasp.org/www-project-web-security-testing-guide/latest"
                "/4-Web_Application_Security_Testing"
                "/02-Configuration_and_Deployment_Management_Testing"
                "/12-Test_for_Content_Security_Policy",
                "https://cheatsheetseries.owasp.org/cheatsheets/"
                "Content_Security_Policy_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/79.html",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference"
                "/Headers/Content-Security-Policy",
                "https://w3c.github.io/webappsec-csp/",
            ),
        ),
        "csrf": (
            "csrf",
            ("WSTG-SESS-05", "CWE-352"),
            (
                "https://owasp.org/www-project-web-security-testing-guide/latest"
                "/4-Web_Application_Security_Testing/06-Session_Management_Testing"
                "/05-Testing_for_Cross_Site_Request_Forgery",
                "https://cheatsheetseries.owasp.org/cheatsheets/"
                "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/352.html",
                "https://portswigger.net/web-security/csrf",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference"
                "/Headers/Set-Cookie",
            ),
        ),
        "jwt": (
            "jwt",
            ("RFC 7519", "RFC 7515", "WSTG-SESS-10", "CWE-347"),
            (
                "https://www.rfc-editor.org/rfc/rfc7519",
                "https://www.rfc-editor.org/rfc/rfc7515",
                "https://owasp.org/www-project-web-security-testing-guide/latest"
                "/4-Web_Application_Security_Testing/06-Session_Management_Testing"
                "/10-Testing_JSON_Web_Tokens",
                "https://cwe.mitre.org/data/definitions/347.html",
                "https://portswigger.net/web-security/jwt",
            ),
        ),
        "dns": (
            "dns",
            ("RFC 7489", "RFC 7208", "RFC 6376", "RFC 4033", "CWE-290"),
            (
                "https://datatracker.ietf.org/doc/html/rfc7489",
                "https://datatracker.ietf.org/doc/html/rfc7208",
                "https://datatracker.ietf.org/doc/html/rfc6376",
                "https://datatracker.ietf.org/doc/html/rfc4033",
                "https://datatracker.ietf.org/doc/html/rfc8659",
                "https://cwe.mitre.org/data/definitions/290.html",
            ),
        ),
    }

    def _index(self) -> str:
        return self.INDEX.read_text(encoding="utf-8")

    def _guide(self, slug: str) -> str:
        return (ROOT / "guides" / slug / "index.html").read_text(encoding="utf-8")

    def _pages(self):
        """(name, html) for the index and every guide."""
        yield "index", self._index()
        for slug in sorted(self.GUIDES):
            yield slug, self._guide(slug)

    def _app(self) -> str:
        return (ROOT / "js" / "app.js").read_text(encoding="utf-8")

    # --- navigation -----------------------------------------------------

    def test_header_nav_links_to_guides(self):
        app = self._app()
        start = app.index("function renderHeader(")
        body = app[start:app.index("\nfunction renderFooter(", start)]
        self.assertIn('"/guides/"', body)
        self.assertIn('"Guides"', body)

    def test_footer_learn_column_links_to_guides(self):
        """Guides is a section link in the Learn column — one entry, not one
        per guide, so adding guides never needs a footer edit."""
        app = self._app()
        start = app.index("function renderFooter()")
        body = app[start:app.index("\n/* ---------- Blog", start)]
        learn = body[body.index('aria-label="Learn"'):]
        self.assertIn("/guides/", learn)
        # Still a section link only: no per-guide entries.
        for slug in self.GUIDES:
            self.assertNotIn("/guides/%s/" % slug, learn)

    def test_hub_links_to_guides(self):
        hub = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="guides/"', hub)

    def test_404_offers_a_guides_card(self):
        page = (ROOT / "404.html").read_text(encoding="utf-8")
        self.assertIn('id="guidesLink"', page)
        js = (ROOT / "js" / "404.js").read_text(encoding="utf-8")
        # Base-aware rewrite, so /CyberBuddy/ hosting resolves correctly.
        self.assertIn('base + "/guides/"', js)

    # --- pages exist and use the shared shell ---------------------------

    def test_every_page_exists(self):
        self.assertTrue(self.INDEX.is_file(), self.INDEX)
        for slug in self.GUIDES:
            path = ROOT / "guides" / slug / "index.html"
            with self.subTest(guide=slug):
                self.assertTrue(path.is_file(), path)

    def test_pages_use_the_established_shell(self):
        for name, page in self._pages():
            data_page = "/guides/" if name == "index" else "/guides/%s/" % name
            with self.subTest(page=data_page):
                self.assertIn('data-page="%s"' % data_page, page)
                self.assertIn("theme-boot.js", page)
                self.assertIn("boot.js", page)
                self.assertIn('id="main"', page)
                # Guides never frame anything — least privilege stays.
                self.assertIn("frame-src 'none'", page)

    def test_pages_have_canonical_and_social_metadata(self):
        for name, page in self._pages():
            url = "/CyberBuddy/guides/" if name == "index" \
                else "/CyberBuddy/guides/%s/" % name
            with self.subTest(url=url):
                self.assertIn('rel="canonical" href="https://amitpal-cyberbuddy.github.io'
                              + url + '"', page)
                self.assertIn('property="og:title"', page)
                self.assertIn('name="twitter:card"', page)

    # --- content presence ------------------------------------------------

    def test_index_lists_every_guide(self):
        index = self._index()
        for slug in self.GUIDES:
            with self.subTest(guide=slug):
                self.assertIn('href="%s/"' % slug, index)

    def test_scope_is_one_guide_per_tool(self):
        """Every tool has a guide, and no guide exists without a tool."""

        def page_dirs(parent):
            """Directories that are actual pages.

            `tools/` also holds Python helpers (audit_site.py, build_cache.py),
            so running them leaves a `__pycache__` directory behind. Ignore
            build artifacts and anything without an index.html so a developer
            who ran the helpers before the suite does not see a false failure.
            """
            return sorted(
                p.name for p in (ROOT / parent).iterdir()
                if p.is_dir() and not p.name.startswith((".", "__"))
                and (p / "index.html").is_file()
            )

        dirs = page_dirs("guides")
        self.assertEqual(dirs, sorted(self.GUIDES))
        self.assertEqual(dirs, page_dirs("tools"))

    def test_clickjacking_guide_covers_both_framing_controls(self):
        page = self._guide("clickjacking")
        for needle in (
            "X-Frame-Options",
            "frame-ancestors",
            "'none'",
            "SAMEORIGIN",
            "DENY",
        ):
            self.assertIn(needle, page, needle)

    def test_every_guide_carries_its_standards_line(self):
        """Same standards identity the tool uses, so the guide and the report
        cite one thing."""
        for slug, (_tool, standards, _refs) in self.GUIDES.items():
            page = self._guide(slug)
            for std in standards:
                with self.subTest(guide=slug, standard=std):
                    self.assertIn(std, page)

    def test_pages_state_the_authorization_boundary(self):
        for name, page in self._pages():
            with self.subTest(page=name):
                self.assertIn("Authorized testing only", page)

    def test_guides_stay_short(self):
        """Concise by design: a guide is a few minutes of reading, not a
        long-form article."""
        for slug in self.GUIDES:
            page = re.sub(r"<noscript\b[^>]*>.*?</noscript>", " ", self._guide(slug), flags=re.S)
            text = re.sub(r"<[^>]+>", " ", page)
            words = len(text.split())
            with self.subTest(guide=slug, words=words):
                self.assertLess(words, 1200, words)

    # --- the connections that make a guide useful ------------------------

    def test_guide_links_to_the_matching_tool(self):
        for slug, (tool, _standards, _refs) in self.GUIDES.items():
            with self.subTest(guide=slug):
                self.assertIn('href="../../tools/%s/"' % tool, self._guide(slug))

    def test_tool_links_back_to_the_guide(self):
        for slug, (tool, _standards, _refs) in self.GUIDES.items():
            page = (ROOT / "tools" / tool / "index.html").read_text(encoding="utf-8")
            with self.subTest(tool=tool):
                self.assertIn('href="../../guides/%s/"' % slug, page)

    def test_guides_never_sell_the_blog_as_a_per_tool_deep_dive(self):
        """A blog link belongs in a guide only when a post on that exact
        topic exists, and never as a substitute for the primary Go deeper
        references. The CORS write-up has shipped; it may appear in its own
        subsection. Every other guide still has no matching post."""
        cors_post = (
            "https://amitpxl.medium.com/cors-misconfiguration-when-reflecting-"
            "the-origin-is-not-the-whole-story-956e2e6e18bc"
        )
        for name, page in self._pages():
            with self.subTest(page=name):
                if name == "cors":
                    self.assertIn(cors_post, page)
                    deeper = page[page.index("Go deeper"):]
                    self.assertNotIn("medium.com", deeper)
                else:
                    self.assertNotIn("medium.com", page)

    def test_guides_go_deeper_via_real_primary_references(self):
        """The "Go deeper" block must cite sources that actually document the
        weakness, each opened safely in a new tab."""
        for slug, (_tool, _standards, refs) in self.GUIDES.items():
            page = self._guide(slug)
            for url in refs:
                with self.subTest(guide=slug, url=url):
                    self.assertIn(url, page)
            for external in re.findall(r'<a href="(https?://[^"]+)"[^>]*>', page):
                with self.subTest(guide=slug, link=external):
                    self.assertIn('href="' + external + '" target="_blank" '
                                  'rel="noopener noreferrer"', page)

    def test_guides_are_written_in_first_person_not_as_a_narrator(self):
        """These are my own notes. Copy that refers to "the maintainer" reads
        like an assistant describing someone else's site."""
        for name, page in self._pages():
            prose = re.sub(r"<[^>]+>", " ", page)
            with self.subTest(page=name):
                for tell in ("maintainer", "the author's", "this website's owner"):
                    self.assertNotIn(tell, prose.lower(), tell)
                self.assertRegex(prose, r"\bI\b")

    def test_guides_point_at_the_scoring_methodology(self):
        for slug in self.GUIDES:
            with self.subTest(guide=slug):
                self.assertIn('href="../../methodology/"', self._guide(slug))

    # --- discoverability --------------------------------------------------

    def test_sitemap_lists_every_guide_url(self):
        sitemap = (ROOT / "sitemap.xml").read_text(encoding="utf-8")
        self.assertIn("/CyberBuddy/guides/</loc>", sitemap)
        for slug in self.GUIDES:
            with self.subTest(guide=slug):
                self.assertIn("/CyberBuddy/guides/%s/</loc>" % slug, sitemap)

    def test_llms_txt_describes_the_guides_section(self):
        text = (ROOT / "llms.txt").read_text(encoding="utf-8")
        self.assertIn("/guides/", text)
        for slug in self.GUIDES:
            with self.subTest(guide=slug):
                self.assertIn("/guides/%s/" % slug, text)

    def test_readme_documents_the_section(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("guides/", text)
        for slug in self.GUIDES:
            with self.subTest(guide=slug):
                self.assertIn("guides/%s/" % slug, text)

    def test_server_serves_the_section(self):
        text = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn('"guides/"', text)          # STATIC_PREFIXES
        self.assertIn('path == "/guides"', text)  # no-slash redirect
        self.assertIn('path.startswith("/guides/")', text)


class DocumentationPageTests(unittest.TestCase):
    """The in-site documentation page.

    The footer's "Documentation" link used to eject the visitor to the GitHub
    README — the only off-site link in that column, landing them in 390 lines
    that are two-thirds contributor material (file tree, engine internals,
    deployment). `/documentation/` is the operator-facing half of that: how to
    run the suite, which engine answers, the CLI, export, and the honest limits
    of the static build.

    Deliberately *not* a docs/ directory: the Pages workflow refuses to publish
    docs/ (see PagesExclusionTests), so a page named that way would 404 hosted.
    """

    PAGE = ROOT / "documentation" / "index.html"

    def _page(self) -> str:
        return self.PAGE.read_text(encoding="utf-8")

    # --- exists and uses the shared shell --------------------------------

    def test_page_exists(self):
        self.assertTrue(self.PAGE.is_file(), self.PAGE)

    def test_page_uses_the_established_shell(self):
        page = self._page()
        self.assertIn('data-page="/documentation/"', page)
        self.assertIn("theme-boot.js", page)
        self.assertIn("boot.js", page)
        self.assertIn('id="main"', page)
        # A prose page frames nothing — least privilege stays.
        self.assertIn("frame-src 'none'", page)

    def test_page_has_canonical_and_social_metadata(self):
        page = self._page()
        self.assertIn(
            'rel="canonical" href="https://amitpal-cyberbuddy.github.io'
            '/CyberBuddy/documentation/"',
            page,
        )
        self.assertIn('property="og:title"', page)
        self.assertIn('name="twitter:card"', page)

    def test_assets_resolve_one_level_up(self):
        """Top-level section page: assets are ../, never absolute paths that
        would break under the /CyberBuddy/ project-pages mount."""
        page = self._page()
        self.assertIn('href="../css/app.css', page)
        self.assertIn('src="../js/app.js', page)
        self.assertNotIn('href="/css/', page)
        self.assertNotIn('src="/js/', page)

    def test_external_links_open_safely(self):
        page = self._page()
        for external in re.findall(r'<a href="(https?://[^"]+)"[^>]*>', page):
            with self.subTest(link=external):
                self.assertIn(
                    'href="' + external + '" target="_blank" '
                    'rel="noopener noreferrer"',
                    page,
                )

    # --- the footer link now stays on the site ---------------------------

    def test_footer_documentation_link_is_internal(self):
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        start = app.index("function renderFooter()")
        body = app[start:app.index("\n/* ---------- Blog", start)]
        self.assertIn("""base + '/documentation/">Documentation</a>'""", body)
        # The README hop is what this replaced.
        self.assertNotIn("CyberBuddy#readme", body)
        # GitHub itself is still linked — only the docs entry changed.
        self.assertIn("github.com/AmitPal-CyberBuddy/CyberBuddy", body)

    # --- content: operator scope, not a third copy of the scoring rules ---

    def test_covers_the_operator_essentials(self):
        page = self._page()
        for needle in (
            "python3 server.py",       # quick start
            "--allow-private",         # private-target opt-in
            "127.0.0.1",               # default bind
            "clickjacking_validator.py",
            "security_headers.py",
            "cors_validator.py",
            "csp_checker.py",
            "--public-only",
            "Markdown",                # export formats
            "provenance",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, page)

    def test_states_the_authorization_boundary(self):
        self.assertIn("Authorized testing only", self._page())

    def test_is_written_in_first_person(self):
        prose = re.sub(r"<[^>]+>", " ", self._page())
        for tell in ("maintainer", "the author's", "this website's owner"):
            self.assertNotIn(tell, prose.lower(), tell)
        self.assertRegex(prose, r"\bI\b")

    def test_defers_scoring_to_the_methodology_page(self):
        """Scoring rules already exist twice (README + methodology). This page
        links to methodology instead of becoming a third copy."""
        page = self._page()
        self.assertIn('href="../methodology/"', page)
        self.assertIn('href="../methodology/#hosted-scans"', page)
        self.assertIn('href="../methodology/#privacy"', page)
        # No re-statement of the letter bands or the numeric weights.
        for band in ("A ≥ 90", "A>=90", "score of 25", "25 points"):
            with self.subTest(band=band):
                self.assertNotIn(band, page)

    def test_explains_why_the_hosted_build_cannot_score_itself_an_a(self):
        page = self._page()
        for needle in ("frame-ancestors", "X-Frame-Options", "GitHub Pages"):
            with self.subTest(needle=needle):
                self.assertIn(needle, page)

    def test_does_not_duplicate_the_header_nav(self):
        """Footer-only by design: the header stays Hub / Guides / Method /
        Tools, which is the four-item budget the IA work settled on."""
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        start = app.index("function renderHeader(")
        body = app[start:app.index("\nfunction renderFooter(", start)]
        self.assertNotIn("/documentation/", body)

    # --- discoverability --------------------------------------------------

    def test_sitemap_lists_the_page(self):
        sitemap = (ROOT / "sitemap.xml").read_text(encoding="utf-8")
        self.assertIn("/CyberBuddy/documentation/</loc>", sitemap)

    def test_llms_txt_describes_the_page(self):
        self.assertIn("/documentation/", (ROOT / "llms.txt").read_text(encoding="utf-8"))

    def test_readme_points_at_the_page(self):
        self.assertIn("documentation/", (ROOT / "README.md").read_text(encoding="utf-8"))

    def test_server_serves_the_page(self):
        text = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn('"documentation/"', text)          # STATIC_PREFIXES
        self.assertIn('path == "/documentation"', text)  # no-slash redirect
        self.assertIn('path.startswith("/documentation/")', text)

    def test_page_is_not_under_the_unpublishable_docs_dir(self):
        """docs/ is blocked by the Pages leak guard; a docs page living there
        would silently 404 on the hosted site."""
        self.assertFalse((ROOT / "docs" / "index.html").exists())

    def test_workflow_publishes_the_documentation_directory(self):
        workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
        self.assertIn("cp -a documentation _site/", workflow)


class JwtWorkbenchTests(unittest.TestCase):
    """JWT-01/02/03: the JWT Security Workbench decodes, inspects, verifies,
    edits, generates and re-signs compact JWS tokens locally, builds
    authorized-test variant templates and runs a bounded HMAC secret search
    in a Web Worker. The pure engine lives in js/jwt.engine.js (DOM-free,
    run under Node here, including the worker message contract under a
    Node Worker-shim); the controller wires the DOM and the worker.

    Accuracy rules pinned here: HS256 is not automatically weak; missing
    claims are contextual observations, not a score; decoding is separate
    from signature/claim verification; we never trust the token's alg header
    to choose a key family (algorithm-confusion guard, in both verify and
    sign directions); a signed token is a TEST TOKEN and a variant is a
    TEST TEMPLATE until the target honors them; secret testing is HS-only,
    bounded, cancellable and never persists anything; key export is explicit
    and confirmed, never accidental; and nothing leaves the browser (no
    network/storage in the controller or the worker).
    """

    PAGE = ROOT / "tools" / "jwt" / "index.html"
    CONTROLLER = ROOT / "js" / "tool.jwt.js"
    ENGINE = ROOT / "js" / "jwt.engine.js"
    GUIDE = ROOT / "guides" / "jwt" / "index.html"

    def _page(self) -> str:
        return self.PAGE.read_text(encoding="utf-8")

    def _controller(self) -> str:
        return self.CONTROLLER.read_text(encoding="utf-8")

    def _engine(self) -> str:
        return self.ENGINE.read_text(encoding="utf-8")

    @staticmethod
    def _strip_js_comments(js: str) -> str:
        js = re.sub(r"/\*.*?\*/", " ", js, flags=re.S)
        js = re.sub(r"//[^\n]*", " ", js)
        return js

    # --- engine under Node ---------------------------------------------

    def _run_engine(self, harness: str):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import tempfile
        engine = self.ENGINE.read_text(encoding="utf-8")
        script = engine + "\n" + harness
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run(
                [node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=30,
            )
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def _jwt(self, header: dict, payload: dict, secret: str) -> str:
        """Build an HS256-signed JWT inside Node (mirrors what an issuer
        would produce) and return the compact serialization."""
        import tempfile
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        harness = """
const h = %s;
const p = %s;
const secret = %s;
const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
const b64 = (o) => b64url(Buffer.from(JSON.stringify(o)));
const data = b64(h) + '.' + b64(p);
const sig = require('crypto').createHmac('sha256', secret).update(data).digest();
console.log(JSON.stringify({ token: data + '.' + b64url(sig) }));
""" % (json.dumps(header), json.dumps(payload), json.dumps(secret))
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(harness); path = fh.name
        try:
            proc = subprocess.run([node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=15)
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])["token"]

    # --- files, routes, wiring ----------------------------------------

    def test_route_controller_and_engine_exist(self):
        for f in (self.PAGE, self.CONTROLLER, self.ENGINE):
            self.assertTrue(f.is_file(), f)
        page = self._page()
        self.assertIn("js/jwt.engine.js", page)
        self.assertIn("js/tool.jwt.js", page)
        self.assertIn('data-init="initJwt"', page)
        # JWT-01 is now indexable (no more noindex preview).
        self.assertNotIn('name="robots" content="noindex', page)
        self.assertIn('rel="canonical"', page)

    def test_server_aliases_jwt(self):
        text = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn('"/jwt": "/tools/jwt/"', text)
        self.assertIn('"/jwt/": "/tools/jwt/"', text)

    def test_engine_has_no_network_or_storage(self):
        js = self._strip_js_comments(self._engine())
        for needle in ("fetch(", "XMLHttpRequest", "localStorage", "sessionStorage",
                       "history.", "location."):
            self.assertNotIn(needle, js, "engine must be local-only: " + needle)

    def test_controller_has_no_network_or_storage(self):
        js = self._strip_js_comments(self._controller())
        for needle in ("fetch(", "XMLHttpRequest", "localStorage", "sessionStorage",
                       "history.", "URLSearchParams"):
            self.assertNotIn(needle, js, "controller must be local-only: " + needle)

    # --- decode --------------------------------------------------------

    def test_engine_parses_valid_hs256(self):
        token = self._jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "k1"},
            {"sub": "alice", "iss": "https://iss.example", "aud": "app",
             "iat": 1700000000, "exp": 1900000000},
            "topsecret",
        )
        out = self._run_engine("""
const r = CyberBuddyJwt.tryParseToken(%s);
console.log(JSON.stringify({ ok: r.ok, alg: r.token && r.token.header.alg,
  sub: r.token && r.token.payload.sub, obs: r.token && CyberBuddyJwt.observations(r.token).map(o=>o.code) }));
""" % json.dumps(token))
        self.assertTrue(out["ok"])
        self.assertEqual(out["alg"], "HS256")
        self.assertEqual(out["sub"], "alice")
        self.assertIn("hmac", out["obs"])

    def test_engine_rejects_malformed_and_jwe(self):
        cases = {
            "empty": "",
            "two parts": "a.b",
            "bad base64": "!!!.!!!.!!!",
            "bad json": "aaaa.bbbb.cccc",
            "no alg": self._jwt({"typ": "JWT"}, {"x": 1}, "s"),
            "jwe": "a.b.c.d.e",
        }
        for name, tok in cases.items():
            out = self._run_engine(
                "const r = CyberBuddyJwt.tryParseToken(%s); console.log(JSON.stringify({ok:r.ok, err:r.error}));"
                % json.dumps(tok))
            self.assertFalse(out["ok"], name + " should not parse")
            self.assertTrue(out["err"], name)

    def test_engine_rejects_noncanonical_compact_jws_and_critical_headers(self):
        """JWT parsing is strict: compact JWS uses unpadded base64url, JSON
        objects for both header/payload, and no unimplemented crit extension."""
        cases = {
            "standard-base64": "eyJhbGciOiJIUzI1NiJ9+.eyJzdWIiOiJhIn0.sig",
            "padded": "eyJhbGciOiJIUzI1NiJ9=.eyJzdWIiOiJhIn0.sig",
            "payload-array": "eyJhbGciOiJIUzI1NiJ9.W10.sig",
            "critical": "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiZXhwIl19.eyJzdWIiOiJhIn0.sig",
        }
        for name, token in cases.items():
            out = self._run_engine(
                "const r=CyberBuddyJwt.tryParseToken(%s); console.log(JSON.stringify({ok:r.ok,error:r.error}));"
                % json.dumps(token))
            self.assertFalse(out["ok"], name)
            self.assertTrue(out["error"], name)

    def test_claim_validation_rejects_malformed_registered_claims(self):
        out = self._run_engine("""
const r = CyberBuddyJwt.validateClaims({exp:'4102444800', nbf:20, iat:30,
  iss:7, sub:[], aud:['api', 7], jti:9});
console.log(JSON.stringify({valid:r.valid, codes:r.errors.map(e=>e.code), messages:r.errors.map(e=>e.message)}));
""")
        self.assertFalse(out["valid"])
        for code in ("exp", "iss", "sub", "aud", "jti"):
            self.assertIn(code, out["codes"])

    def test_engine_rejects_alg_none_even_with_signature(self):
        # A token that declares alg:none must not verify.
        out = self._run_engine("""
const r = CyberBuddyJwt.tryParseToken('eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.');
console.log(JSON.stringify({ ok: r.ok, err: r.error }));
""")
        self.assertFalse(out["ok"])
        self.assertIn("none", out["err"].lower())

    # --- Markdown analysis export --------------------------------------

    def _markdown(self, header: dict, payload: dict, verification=None) -> str:
        """Render the Markdown analysis for a token inside Node."""
        token = self._jwt(header, payload, "secret")
        out = self._run_engine(
            "const p = CyberBuddyJwt.parseToken(%s);\n"
            "const md = CyberBuddyJwt.buildMarkdown(p, %s);\n"
            "console.log(JSON.stringify({ md: md }));"
            % (json.dumps(token), json.dumps({"verification": verification} if verification else None))
        )
        return out["md"]

    def test_markdown_export_never_leaks_credentials(self):
        """The Workbench handles live credentials, so the export must carry
        the token's shape and never material that could authenticate: no raw
        token, no signature, and no values for identifying claims."""
        md = self._markdown(
            {"alg": "HS256", "typ": "JWT", "kid": "key-7"},
            {
                "iss": "https://issuer.example",
                "sub": "user-4711-SECRET",
                "jti": "UNIQUE-ID-SECRET",
                "email": "victim@example.com",
                "role": "admin",
                "exp": 4102444800,
            },
        )
        for secret in ("user-4711-SECRET", "UNIQUE-ID-SECRET", "victim@example.com"):
            self.assertNotIn(secret, md, "leaked claim value: " + secret)
        # Sensitive claims are still reported by name, so the reader knows
        # they exist without the report carrying the value.
        for name in ("`sub`", "`jti`", "`email`"):
            self.assertIn(name, md)
        self.assertIn("(present, value withheld)", md)
        # Non-identifying claims stay readable — that is the useful content.
        self.assertIn("admin", md)
        self.assertIn("https://issuer.example", md)

    def test_markdown_export_states_verification_status(self):
        """Decoding is not verification. With no verify run the report must
        say so rather than letting silence imply the token checked out."""
        claims = {"iss": "https://issuer.example", "exp": 4102444800}
        md = self._markdown({"alg": "HS256", "typ": "JWT"}, claims)
        self.assertIn("## Verification", md)
        self.assertIn("Not run.", md)
        self.assertIn("Decoding is not verification", md)

        signed = self._markdown(
            {"alg": "HS256", "typ": "JWT"}, claims,
            verification={"valid": False, "lines": ["Signature does not match"]},
        )
        self.assertIn("not verified", signed)
        self.assertIn("Signature does not match", signed)
        self.assertNotIn("Not run.", signed)

    def test_markdown_export_has_no_score_or_verdict(self):
        """Parity with the page itself: observations are contextual, so the
        export must not invent a grade the tool does not produce."""
        md = self._markdown(
            {"alg": "HS256", "typ": "JWT"},
            {"iss": "https://issuer.example", "exp": 4102444800},
        )
        self.assertIn("## Observations", md)
        self.assertIn("not a score or a verdict", md)
        for banned in ("/ 100", "Grade:", "Score:"):
            self.assertNotIn(banned, md)

    def test_page_offers_markdown_export(self):
        """Report parity: every other tool leaves with a shareable artifact."""
        page = self._page()
        self.assertIn('id="jwtCopyMd"', page)
        self.assertIn('id="jwtDownloadMd"', page)
        controller = self._controller()
        self.assertIn("buildMarkdown", controller)
        self.assertIn("cyberbuddy-jwt-analysis.md", controller)

    # --- verification: HMAC -------------------------------------------

    def test_verify_hmac_correct_and_wrong_secret(self):
        token = self._jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "alice", "exp": 4102444800},
            "correct horse battery staple",
        )
        good = self._run_engine(
            "CyberBuddyJwt.verifyToken(%s,'correct horse battery staple',{alg:'HS256'}).then(r=>console.log(JSON.stringify(r)));"
            % json.dumps(token))
        self.assertTrue(good["valid"], good)
        self.assertEqual(good["alg"], "HS256")
        bad = self._run_engine(
            "CyberBuddyJwt.verifyToken(%s,'wrong',{alg:'HS256'}).then(r=>console.log(JSON.stringify(r)));"
            % json.dumps(token))
        self.assertFalse(bad["valid"])
        self.assertIn("Signature", bad["error"])

    def test_algorithm_confusion_hmac_rejects_public_key(self):
        """HS* must reject a PEM/JWK public key — the classic confusion."""
        token = self._jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "a"}, "s")
        pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n-----END PUBLIC KEY-----"
        out = self._run_engine(
            "CyberBuddyJwt.verifyToken(%s,%s,{alg:'HS256'}).then(r=>console.log(JSON.stringify(r)));"
            % (json.dumps(token), json.dumps(pem)))
        self.assertFalse(out["valid"])
        self.assertIn("shared secret", out["error"])

    def test_verify_rejects_wrong_alg_pin(self):
        token = self._jwt({"alg": "HS256", "typ": "JWT"}, {"x": 1}, "s")
        out = self._run_engine(
            "CyberBuddyJwt.verifyToken(%s,'s',{alg:'RS256'}).then(r=>console.log(JSON.stringify(r)));"
            % json.dumps(token))
        self.assertFalse(out["valid"])
        self.assertIn("Algorithm mismatch", out["error"])

    # --- verification: RSA and ECDSA ----------------------------------

    def _asymmetric_token(self, alg: str):
        """Return (token, public_jwk) generated with Web Crypto in Node."""
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import tempfile
        if alg.startswith("ES"):
            gen = "{name:'ECDSA',namedCurve:'%s'}" % ("P-256" if alg == "ES256" else "P-384")
            sign_alg = "{name:'ECDSA',hash:{name:'%s'},namedCurve:'%s'}" % (
                "SHA-256" if alg.endswith("256") else "SHA-384",
                "P-256" if alg == "ES256" else "P-384")
        else:
            gen = "{name:'%s',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'}" % (
                "RSA-PSS" if alg.startswith("PS") else "RSASSA-PKCS1-v1_5")
            sign_alg = "{name:'%s',hash:{name:'SHA-256'}%s}" % (
                "RSA-PSS" if alg.startswith("PS") else "RSASSA-PKCS1-v1_5",
                ",saltLength:32" if alg.startswith("PS") else "")
        harness = """
const crypto = globalThis.crypto;
const b64 = (buf) => Buffer.from(buf).toString('base64').replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
(async () => {
  const pair = await crypto.subtle.generateKey(%s, true, ['sign','verify']);
  const header = {alg:%s, typ:'JWT', kid:'k1'};
  const payload = {sub:'bob', aud:'app', exp:4102444800, iat:1700000000};
  const data = b64(JSON.stringify(header)) + '.' + b64(JSON.stringify(payload));
  const sig = await crypto.subtle.sign(%s, pair.privateKey, new TextEncoder().encode(data));
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  jwk.kid = 'k1';
  console.log(JSON.stringify({ token: data + '.' + b64(Buffer.from(sig)), jwk: jwk }));
})();
""" % (gen, json.dumps(alg), sign_alg)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(harness); path = fh.name
        try:
            proc = subprocess.run([node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=30)
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def test_verify_rsa_and_ecdsa_with_jwk(self):
        for alg in ("RS256", "PS256", "ES256"):
            data = self._asymmetric_token(alg)
            out = self._run_engine(
                "CyberBuddyJwt.verifyToken(%s,%s,{alg:%s}).then(r=>console.log(JSON.stringify(r)));"
                % (json.dumps(data["token"]), json.dumps(data["jwk"]), json.dumps(alg)))
            self.assertTrue(out["valid"], "%s: %s" % (alg, out.get("error")))
            self.assertEqual(out["alg"], alg)

    def test_jwks_selects_key_by_kid(self):
        data = self._asymmetric_token("ES256")
        jwks = {"keys": [
            {"kty": "RSA", "n": "aaa", "e": "AQAB", "kid": "other", "alg": "RS256"},
            data["jwk"],
        ]}
        out = self._run_engine(
            "CyberBuddyJwt.verifyToken(%s,%s,{}).then(r=>console.log(JSON.stringify(r)));"
            % (json.dumps(data["token"]), json.dumps(jwks)))
        self.assertTrue(out["valid"], out.get("error"))

    # --- claims validation --------------------------------------------

    def test_validate_claims_exp_nbf_iss_aud_sub(self):
        now = int(__import__("time").time())
        valid = {"iss": "me", "aud": "app", "sub": "u1", "exp": now + 3600, "nbf": now - 10}
        out = self._run_engine(
            "console.log(JSON.stringify(CyberBuddyJwt.validateClaims(%s,{iss:'me',aud:'app',sub:'u1'})));"
            % json.dumps(valid))
        self.assertTrue(out["valid"], out)

        expired = dict(valid, exp=now - 10)
        out = self._run_engine(
            "console.log(JSON.stringify(CyberBuddyJwt.validateClaims(%s,{})));" % json.dumps(expired))
        self.assertFalse(out["valid"])
        self.assertIn("exp", [e["code"] for e in out["errors"]])

        future = dict(valid, nbf=now + 3600)
        out = self._run_engine(
            "console.log(JSON.stringify(CyberBuddyJwt.validateClaims(%s,{})));" % json.dumps(future))
        self.assertFalse(out["valid"])
        self.assertIn("nbf", [e["code"] for e in out["errors"]])

        mismatch = dict(valid)
        out = self._run_engine(
            "console.log(JSON.stringify(CyberBuddyJwt.validateClaims(%s,{iss:'other',aud:'x',sub:'z'})));"
            % json.dumps(mismatch))
        codes = {e["code"] for e in out["errors"]}
        self.assertEqual(codes, {"iss", "aud", "sub"})

    def test_skew_applies_to_exp_and_nbf(self):
        now = int(__import__("time").time())
        out = self._run_engine(
            "console.log(JSON.stringify(CyberBuddyJwt.validateClaims({exp:%d},{clockTolerance:120})));"
            % (now - 60))
        self.assertTrue(out["valid"], out)  # expired 60s ago but within 120s skew

    # --- JWT-02: signing under Node ------------------------------------

    def test_sign_hs256_roundtrip_and_wrong_secret(self):
        out = self._run_engine("""
CyberBuddyJwt.signToken({alg:'HS256',typ:'JWT'},{sub:'alice',exp:4102444800},
  'correct horse battery staple',{alg:'HS256'}).then(async r => {
  if (r.error) { console.log(JSON.stringify(r)); return; }
  const good = await CyberBuddyJwt.verifyToken(r.token,'correct horse battery staple',{alg:'HS256'});
  const bad = await CyberBuddyJwt.verifyToken(r.token,'wrong',{alg:'HS256'});
  console.log(JSON.stringify({token:r.token, parts:r.token.split('.').length,
    good:good.valid, bad:bad.valid, badErr:bad.error}));
});
""")
        self.assertTrue(out["token"], out)
        self.assertEqual(out["parts"], 3)
        self.assertTrue(out["good"], out)
        self.assertFalse(out["bad"])
        self.assertIn("Signature", out["badErr"])

    def test_sign_hs384_and_hs512_roundtrip(self):
        for alg in ("HS384", "HS512"):
            out = self._run_engine("""
CyberBuddyJwt.signToken({alg:%s},{sub:'bob'},'s3cret',{alg:%s}).then(async r => {
  if (r.error) { console.log(JSON.stringify(r)); return; }
  const v = await CyberBuddyJwt.verifyToken(r.token,'s3cret',{alg:%s});
  console.log(JSON.stringify({ok:v.valid, alg:v.alg}));
});
""" % (json.dumps(alg), json.dumps(alg), json.dumps(alg)))
            self.assertTrue(out["ok"], "%s: %s" % (alg, out))
            self.assertEqual(out["alg"], alg)

    def test_sign_rejects_alg_none_missing_and_unsupported(self):
        out = self._run_engine("""
(async () => {
  const a = await CyberBuddyJwt.signToken({alg:'none'},{sub:'a'},'s');
  const b = await CyberBuddyJwt.signToken({typ:'JWT'},{sub:'a'},'s');
  const c = await CyberBuddyJwt.signToken({alg:'HS999'},{sub:'a'},'s');
  console.log(JSON.stringify({none:a.error, missing:b.error, unsupported:c.error}));
})();
""")
        self.assertIn("none", out["none"].lower())
        self.assertIn("alg", out["missing"].lower())
        self.assertIn("Unsupported", out["unsupported"])

    def test_sign_hmac_rejects_public_key_pem(self):
        """Signing HS* with a pasted public key is algorithm confusion."""
        out = self._run_engine("""
CyberBuddyJwt.signToken({alg:'HS256'},{sub:'a'},
  '-----BEGIN PUBLIC KEY-----\\nabc\\n-----END PUBLIC KEY-----').then(r=>console.log(JSON.stringify(r)));
""")
        self.assertIn("error", out)
        self.assertIn("secret", out["error"])

    def test_sign_rejects_wrong_alg_pin(self):
        out = self._run_engine("""
CyberBuddyJwt.signToken({alg:'HS256'},{sub:'a'},'s',{alg:'RS256'}).then(r=>console.log(JSON.stringify(r)));
""")
        self.assertIn("Algorithm mismatch", out["error"])

    def test_sign_rsa_roundtrip_with_generated_pair(self):
        """The local RSA test-key pair signs a token that verifies with the
        matching public JWK — for both RSA signature families."""
        for alg in ("RS256", "PS256"):
            out = self._run_engine("""
(async () => {
  const pair = await CyberBuddyJwt.generateRsaTestPair(%s);
  if (pair.error) { console.log(JSON.stringify(pair)); return; }
  const s = await CyberBuddyJwt.signToken({alg:%s,typ:'JWT'},{sub:'bob',exp:4102444800},
    pair.privateKey,{alg:%s});
  if (s.error) { console.log(JSON.stringify(s)); return; }
  const v = await CyberBuddyJwt.verifyToken(s.token, pair.publicJwk, {alg:%s});
  const priv = await CyberBuddyJwt.exportPrivateJwk(pair.privateKey);
  console.log(JSON.stringify({ok:v.valid, alg:v.alg, pubKty:pair.publicJwk.kty,
    hasD:!!priv.d, hasN:!!pair.publicJwk.n}));
})();
""" % (json.dumps(alg), json.dumps(alg), json.dumps(alg), json.dumps(alg)))
            self.assertTrue(out["ok"], "%s: %s" % (alg, out))
            self.assertEqual(out["alg"], alg)
            self.assertEqual(out["pubKty"], "RSA")
            self.assertTrue(out["hasD"] and out["hasN"], out)

    def test_sign_es256_roundtrip_with_private_jwk(self):
        """A pasted EC private JWK signs a token that verifies with its
        public JWK."""
        out = self._run_engine("""
(async () => {
  const pair = await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'}, true, ['sign','verify']);
  const priv = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const s = await CyberBuddyJwt.signToken({alg:'ES256'},{sub:'bob',exp:4102444800},priv,{alg:'ES256'});
  if (s.error) { console.log(JSON.stringify(s)); return; }
  const v = await CyberBuddyJwt.verifyToken(s.token, pub, {alg:'ES256'});
  console.log(JSON.stringify({ok:v.valid, alg:v.alg}));
})();
""")
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["alg"], "ES256")

    def test_sign_rejects_public_key_material(self):
        """Public keys (JWK without d, SPKI PEM, JWKS) and PKCS#1 private
        PEM can never sign."""
        out = self._run_engine("""
(async () => {
  const noD = await CyberBuddyJwt.signToken({alg:'RS256'},{sub:'a'},{kty:'RSA',n:'aaa',e:'AQAB'});
  const spki = await CyberBuddyJwt.signToken({alg:'RS256'},{sub:'a'},
    '-----BEGIN PUBLIC KEY-----\\nabc\\n-----END PUBLIC KEY-----');
  const pkcs1 = await CyberBuddyJwt.signToken({alg:'RS256'},{sub:'a'},
    '-----BEGIN RSA PRIVATE KEY-----\\nabc\\n-----END RSA PRIVATE KEY-----');
  const jwks = await CyberBuddyJwt.signToken({alg:'RS256'},{sub:'a'},{keys:[]});
  console.log(JSON.stringify({noD:noD.error, spki:spki.error, pkcs1:pkcs1.error, jwks:jwks.error}));
})();
""")
        self.assertIn("private", out["noD"])
        self.assertIn("private", out["spki"].lower())
        self.assertIn("PKCS#8", out["pkcs1"])
        self.assertIn("JWKS", out["jwks"])

    def test_diff_claims_semantics(self):
        out = self._run_engine("""
console.log(JSON.stringify(CyberBuddyJwt.diffClaims({a:1,b:2,d:'x'},{b:3,c:4,d:'x'})));
""")
        by = {r["claim"]: r for r in out}
        self.assertEqual(by["a"]["kind"], "removed")
        self.assertEqual(by["b"]["kind"], "changed")
        self.assertEqual(by["b"]["from"], 2)
        self.assertEqual(by["b"]["to"], 3)
        self.assertEqual(by["c"]["kind"], "added")
        self.assertEqual(by["d"]["kind"], "unchanged")

    def test_random_jti_is_unique_and_shaped(self):
        out = self._run_engine("""
const a = CyberBuddyJwt.randomJti(), b = CyberBuddyJwt.randomJti();
console.log(JSON.stringify({a:a, b:b, shape:/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(a)}));
""")
        self.assertTrue(out["shape"], out)
        self.assertNotEqual(out["a"], out["b"])

    # --- JWT-03: variant templates under Node --------------------------

    def _variant_base(self):
        """A parsed RS256 base token plus its key pair, built in Node."""
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import tempfile
        harness = """
const crypto = globalThis.crypto;
const b64 = (buf) => Buffer.from(buf).toString('base64').replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
(async () => {
  const pair = await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'}, true, ['sign','verify']);
  const header = {alg:'RS256', typ:'JWT', kid:'k1'};
  const payload = {sub:'alice', role:'user', exp:4102444800};
  const data = b64(JSON.stringify(header)) + '.' + b64(JSON.stringify(payload));
  const sig = await crypto.subtle.sign({name:'RSASSA-PKCS1-v1_5',hash:{name:'SHA-256'}}, pair.privateKey, new TextEncoder().encode(data));
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const priv = await crypto.subtle.exportKey('jwk', pair.privateKey);
  console.log(JSON.stringify({token: data + '.' + b64(Buffer.from(sig)), publicJwk: pub, privateJwk: priv}));
})();
"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(harness); path = fh.name
        try:
            proc = subprocess.run([node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=30)
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def test_variant_alg_none_template_and_guard_intact(self):
        data = self._variant_base()
        out = self._run_engine("""
(async () => {
  const parsed = CyberBuddyJwt.parseToken(%s);
  const v = await CyberBuddyJwt.buildVariant(parsed, 'alg-none');
  console.log(JSON.stringify({token:v.token, alg:v.header.alg, emptySig:v.token.endsWith('.'),
    parseRejects:!CyberBuddyJwt.tryParseToken(v.token).ok}));
})();
""" % json.dumps(data["token"]))
        self.assertTrue(out["emptySig"], out)
        self.assertEqual(out["alg"], "none")
        # The template exists, but parse/verify guards stay intact.
        self.assertTrue(out["parseRejects"])

    def test_variant_tamper_keeps_original_signature(self):
        data = self._variant_base()
        out = self._run_engine("""
(async () => {
  const parsed = CyberBuddyJwt.parseToken(%s);
  const v = await CyberBuddyJwt.buildVariant(parsed, 'tamper', {claim:'role', value:'admin'});
  const payload = JSON.parse(new TextDecoder().decode(CyberBuddyJwt.b64urlDecode(v.token.split('.')[1])));
  console.log(JSON.stringify({sameSig: v.token.split('.')[2] === parsed.raw.split('.')[2],
    role: payload.role, note: v.note}));
})();
""" % json.dumps(data["token"]))
        self.assertTrue(out["sameSig"], out)
        self.assertEqual(out["role"], "admin")
        self.assertTrue(out["note"])

    def test_variant_claim_resign_roundtrip(self):
        data = self._variant_base()
        out = self._run_engine("""
(async () => {
  const parsed = CyberBuddyJwt.parseToken(%s);
  const pair = await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'}, true, ['sign','verify']);
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const v = await CyberBuddyJwt.buildVariant(parsed, 'claim-resign', {claim:'role', value:'admin', alg:'RS256', key:pair.privateKey});
  if (v.error) { console.log(JSON.stringify(v)); return; }
  const check = await CyberBuddyJwt.verifyToken(v.token, pub, {alg:'RS256'});
  const payload = JSON.parse(new TextDecoder().decode(CyberBuddyJwt.b64urlDecode(v.token.split('.')[1])));
  console.log(JSON.stringify({ok:check.valid, role:payload.role, type:v.type}));
})();
""" % json.dumps(data["token"]))
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["role"], "admin")
        self.assertEqual(out["type"], "claim-resign")

    def test_variant_algorithm_confusion_signs_with_public_key(self):
        """The confusion template HMAC-signs with the public key text; the
        verify-side guard still rejects PEM secrets (both coexist)."""
        data = self._variant_base()
        out = self._run_engine("""
const crypto2 = require('crypto');
(async () => {
  const parsed = CyberBuddyJwt.parseToken(%s);
  const pem = '-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\\n-----END PUBLIC KEY-----';
  const v = await CyberBuddyJwt.buildVariant(parsed, 'alg-confusion', {publicKeyPem: pem});
  if (v.error) { console.log(JSON.stringify(v)); return; }
  const parts = v.token.split('.');
  const header = JSON.parse(new TextDecoder().decode(CyberBuddyJwt.b64urlDecode(parts[0])));
  const expected = crypto2.createHmac('sha256', pem).update(parts[0] + '.' + parts[1]).digest();
  const got = Buffer.from(CyberBuddyJwt.b64urlDecode(parts[2]));
  const verifyRejects = await CyberBuddyJwt.verifyToken(v.token, pem, {alg:'HS256'});
  console.log(JSON.stringify({alg:header.alg, sigOk: expected.equals(Buffer.from(got)), verifyRejected: !verifyRejects.valid}));
})();
""" % json.dumps(data["token"]))
        self.assertEqual(out["alg"], "HS256")
        self.assertTrue(out["sigOk"], out)
        self.assertTrue(out["verifyRejected"])

    def test_variant_embedded_jwk_verifies_with_embedded_key(self):
        data = self._variant_base()
        out = self._run_engine("""
(async () => {
  const parsed = CyberBuddyJwt.parseToken(%s);
  const pair = await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'}, true, ['sign','verify']);
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const v = await CyberBuddyJwt.buildVariant(parsed, 'embedded-jwk', {publicJwk: pub, alg:'RS256', key: pair.privateKey});
  if (v.error) { console.log(JSON.stringify(v)); return; }
  const header = JSON.parse(new TextDecoder().decode(CyberBuddyJwt.b64urlDecode(v.token.split('.')[0])));
  const check = await CyberBuddyJwt.verifyToken(v.token, header.jwk, {alg:'RS256'});
  console.log(JSON.stringify({hasJwk: !!header.jwk, ok: check.valid}));
})();
""" % json.dumps(data["token"]))
        self.assertTrue(out["hasJwk"], out)
        self.assertTrue(out["ok"], out)

    def test_variant_jku_x5u_and_kid_headers(self):
        data = self._variant_base()
        out = self._run_engine("""
(async () => {
  const parsed = CyberBuddyJwt.parseToken(%s);
  const pair = await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'}, true, ['sign','verify']);
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const dec = (t) => JSON.parse(new TextDecoder().decode(CyberBuddyJwt.b64urlDecode(t.split('.')[0])));
  const jku = await CyberBuddyJwt.buildVariant(parsed, 'jku', {url:'https://attacker.example/jwks.json', alg:'RS256', key:pair.privateKey});
  const x5u = await CyberBuddyJwt.buildVariant(parsed, 'x5u', {url:'https://attacker.example/cert.pem', alg:'RS256', key:pair.privateKey});
  const kid = await CyberBuddyJwt.buildVariant(parsed, 'kid', {kid:\"1' OR 1=1--\", alg:'RS256', key:pair.privateKey});
  const check = await CyberBuddyJwt.verifyToken(kid.token, pub, {alg:'RS256'});
  console.log(JSON.stringify({jku:dec(jku.token).jku, x5u:dec(x5u.token).x5u,
    kid:dec(kid.token).kid, verifies:check.valid}));
})();
""" % json.dumps(data["token"]))
        self.assertEqual(out["jku"], "https://attacker.example/jwks.json")
        self.assertEqual(out["x5u"], "https://attacker.example/cert.pem")
        self.assertIn("OR 1=1", out["kid"])
        self.assertTrue(out["verifies"])

    def test_variant_requires_base_token(self):
        out = self._run_engine("""
CyberBuddyJwt.buildVariant(null, 'alg-none').then(r=>console.log(JSON.stringify(r)));
""")
        self.assertIn("error", out)
        self.assertIn("base token", out["error"].lower())

    def test_public_jwk_from_private_rsa_and_ec(self):
        out = self._run_engine("""
(async () => {
  const rsa = await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'}, true, ['sign','verify']);
  const ec = await crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, true, ['sign','verify']);
  const rsaPriv = await crypto.subtle.exportKey('jwk', rsa.privateKey);
  const ecPriv = await crypto.subtle.exportKey('jwk', ec.privateKey);
  const rsaPub = CyberBuddyJwt.publicJwkFromPrivate(rsaPriv);
  const ecPub = CyberBuddyJwt.publicJwkFromPrivate(ecPriv);
  console.log(JSON.stringify({rsaKty:rsaPub.kty, rsaHasN:!!rsaPub.n, rsaNoD:!rsaPub.d,
    ecCrv:ecPub.crv, ecHasX:!!ecPub.x, ecNoD:!ecPub.d}));
})();
""")
        self.assertEqual(out["rsaKty"], "RSA")
        self.assertTrue(out["rsaHasN"] and out["rsaNoD"])
        self.assertEqual(out["ecCrv"], "P-256")
        self.assertTrue(out["ecHasX"] and out["ecNoD"])

    # --- JWT-03: bounded secret search under Node ----------------------

    def test_builtin_secret_list_is_small(self):
        out = self._run_engine("""
const l = CyberBuddyJwt.BUILTIN_SECRET_CANDIDATES;
console.log(JSON.stringify({n:l.length, hasSecret:l.indexOf('secret')!==-1, hasJwt:l.indexOf('jwt-secret')!==-1}));
""")
        self.assertLess(out["n"], 100, "built-in list stays small")
        self.assertTrue(out["hasSecret"] and out["hasJwt"])

    def test_search_hmac_secret_found_and_not_found(self):
        out = self._run_engine("""
(async () => {
  const s = await CyberBuddyJwt.signToken({alg:'HS256'},{sub:'x'},'topsecret',{alg:'HS256'});
  const parsed = CyberBuddyJwt.parseToken(s.token);
  const found = await CyberBuddyJwt.searchHmacSecret({alg:'HS256', signingInput:parsed.signingInput,
    signature:parsed.signature, candidates:['aaaa','bbbb','topsecret','cccc']});
  const miss = await CyberBuddyJwt.searchHmacSecret({alg:'HS256', signingInput:parsed.signingInput,
    signature:parsed.signature, candidates:['nope1','nope2']});
  console.log(JSON.stringify({found:found.found, secret:found.secret, tested:found.tested,
    miss:!miss.found, missTested:miss.tested}));
})();
""")
        self.assertTrue(out["found"], out)
        self.assertEqual(out["secret"], "topsecret")
        self.assertEqual(out["tested"], 3)  # stops at the match
        self.assertTrue(out["miss"])
        self.assertEqual(out["missTested"], 2)

    def test_search_hmac_secret_reports_progress_and_stops(self):
        out = self._run_engine("""
(async () => {
  const s = await CyberBuddyJwt.signToken({alg:'HS512'},{sub:'x'},'zz',{alg:'HS512'});
  const parsed = CyberBuddyJwt.parseToken(s.token);
  let stops = 0;
  const r = await CyberBuddyJwt.searchHmacSecret({alg:'HS512', signingInput:parsed.signingInput,
    signature:parsed.signature, candidates:['a','b','c','d','e'],
    shouldContinue: () => (stops++, stops < 2)});
  console.log(JSON.stringify({tested:r.tested, total:r.total, found:r.found, stops:stops}));
})();
""")
        self.assertEqual(out["tested"], 1, out)   # stopped before the 2nd candidate
        self.assertEqual(out["total"], 5)
        self.assertFalse(out["found"])

    def test_search_hmac_secret_rejects_non_hs(self):
        out = self._run_engine("""
CyberBuddyJwt.searchHmacSecret({alg:'RS256', signingInput:'x', signature:new Uint8Array(1),
  candidates:['a']}).catch(e=>console.log(JSON.stringify({err:e.message})));
""")
        self.assertIn("HS256/384/512", out["err"])

    def _run_worker(self, harness: str):
        """Run js/jwt.worker.js under Node with a Worker-environment shim
        (self / importScripts / postMessage / FileReaderSync). The shim is
        defined BEFORE the worker source so its top-level importScripts
        call can load the engine."""
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import tempfile
        engine = self.ENGINE.read_text(encoding="utf-8")
        worker = (ROOT / "js" / "jwt.worker.js").read_text(encoding="utf-8")
        preamble = """
global.self = global;
const messages = [];
global.postMessage = (m) => messages.push(m);
const ENGINE_SRC = %s;
global.importScripts = (p) => { if (String(p).indexOf('jwt.engine.js') !== -1) (0, eval)(ENGINE_SRC); };
global.FileReaderSync = class { readAsText() { return ''; } };
""" % json.dumps(engine)
        script = preamble + "\n" + worker + "\n" + harness
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run([node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=60)
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def test_worker_finds_secret_and_posts_progress(self):
        harness = """
(async () => {
  const s = await globalThis.CyberBuddyJwt.signToken({alg:'HS256'},{sub:'x'},'topsecret',{alg:'HS256'});
  const parsed = globalThis.CyberBuddyJwt.parseToken(s.token);
  self.onmessage({data:{type:'run', alg:'HS256', signingInput:parsed.signingInput,
    signature:parsed.signature, builtin:false,
    candidates:['aaaa','bbbb','topsecret'], maxCandidates:10, deadline:Date.now()+5000}});
  await new Promise(r=>setTimeout(r,300));
  const done = messages.find(m=>m.type==='done');
  console.log(JSON.stringify({found:done.found, secret:done.secret, tested:done.tested, total:done.total}));
})();
"""
        out = self._run_worker(harness)
        self.assertTrue(out["found"], out)
        self.assertEqual(out["secret"], "topsecret")
        self.assertEqual(out["tested"], 3)

    def test_worker_cancel_stops_early(self):
        harness = """
(async () => {
  const s = await globalThis.CyberBuddyJwt.signToken({alg:'HS256'},{sub:'x'},'zz',{alg:'HS256'});
  const parsed = globalThis.CyberBuddyJwt.parseToken(s.token);
  const cands = Array.from({length:5000}, (_, i) => 'cand' + i);
  self.onmessage({data:{type:'run', alg:'HS256', signingInput:parsed.signingInput,
    signature:parsed.signature, builtin:false, candidates:cands, maxCandidates:10000, deadline:0}});
  await new Promise(r=>setTimeout(r,10));
  self.onmessage({data:{type:'cancel'}});
  await new Promise(r=>setTimeout(r,500));
  const done = messages.find(m=>m.type==='done');
  console.log(JSON.stringify({cancelled:done.cancelled, tested:done.tested, total:done.total}));
})();
"""
        out = self._run_worker(harness)
        self.assertTrue(out["cancelled"], out)
        self.assertLess(out["tested"], out["total"])

    # --- UI wiring -----------------------------------------------------

    def test_analyze_and_verify_panel_is_functional(self):
        page = self._page()
        self.assertIn('id="jwtToken"', page)
        self.assertIn('id="jwtVerify"', page)
        for kid in ("jwtHeader", "jwtPayload", "jwtTimeline", "jwtClaims",
                    "jwtObservations", "jwtSecret", "jwtPem", "jwtJwk", "jwtJwks",
                    "jwtExpIss", "jwtExpAud", "jwtExpSub", "jwtSkew", "jwtExpectedAlg"):
            self.assertIn('id="%s"' % kid, page, kid)
        self.assertIn("Expected algorithm", page)
        self.assertNotIn('id="jwtPinAlg"', page)
        # The verify button is enabled (not a preview).
        self.assertNotIn('id="jwtVerify" disabled', page)

    def test_key_type_tabs_have_complete_keyboard_and_aria_contract(self):
        page = self._page()
        tab_to_panel = {
            "jwt-key-secret-tab": "jwt-key-secret", "jwt-key-pem-tab": "jwt-key-pem",
            "jwt-key-jwk-tab": "jwt-key-jwk", "jwt-key-jwks-tab": "jwt-key-jwks",
            "jwt-edit-key-secret-tab": "jwt-edit-key-secret", "jwt-edit-key-pem-tab": "jwt-edit-key-pem",
            "jwt-edit-key-jwk-tab": "jwt-edit-key-jwk", "jwt-edit-key-generated-tab": "jwt-edit-key-generated",
            "jwt-var-key-secret-tab": "jwt-var-key-secret", "jwt-var-key-private-tab": "jwt-var-key-private",
            "jwt-var-key-generated-tab": "jwt-var-key-generated",
        }
        for tab_id, panel_id in tab_to_panel.items():
            tab = re.search(r'<button\b(?=[^>]*\bid="%s")[^>]*>' % re.escape(tab_id), page)
            panel = re.search(r'<div\b(?=[^>]*\bid="%s")[^>]*>' % re.escape(panel_id), page)
            self.assertIsNotNone(tab, tab_id)
            self.assertIsNotNone(panel, panel_id)
            self.assertIn('aria-controls="%s"' % panel_id, tab.group(0))
            self.assertRegex(tab.group(0), r'tabindex="(?:0|-1)"')
            self.assertIn('aria-labelledby="%s"' % tab_id, panel.group(0))
        ctrl = self._controller()
        for key in ("ArrowRight", "ArrowLeft", "ArrowDown", "ArrowUp", "Home", "End"):
            self.assertIn(key, ctrl)
        self.assertIn('setAttribute("tabindex", on ? "0" : "-1")', ctrl)

    def test_claim_helpers_label_checkbox_and_value_separately(self):
        page = self._page()
        claims = ("Iss", "Sub", "Aud", "Exp", "Nbf", "Iat", "Jti")
        self.assertNotIn('<label class="jwt-help-row">', page)
        for claim in claims:
            use = re.search(r'<input\b(?=[^>]*\bid="jwtHelp%sUse")[^>]*>' % claim, page)
            value_label = re.search(r'<label\b(?=[^>]*\bfor="jwtHelp%s")[^>]*>' % claim, page)
            self.assertIsNotNone(use, claim)
            self.assertIn("aria-label=", use.group(0))
            self.assertIsNotNone(value_label, claim)

    def test_edit_panel_is_functional(self):
        """JWT-02: the Edit & Generate panel is a working editor/signer."""
        page = self._page()
        for kid in ("jwtEditHeader", "jwtEditPayload", "jwtEditLoad", "jwtEditReset",
                    "jwtHelpApply", "jwtHelpIss", "jwtHelpSub", "jwtHelpAud",
                    "jwtHelpExp", "jwtHelpNbf", "jwtHelpIat", "jwtHelpJti",
                    "jwtEditDiffList", "jwtSignAlg", "jwtSign",
                    "jwtEditSecret", "jwtEditPem", "jwtEditJwk", "jwtGenKey",
                    "jwtEditToken", "jwtCopyToken", "jwtDlToken",
                    "jwtCopyPub", "jwtCopyPriv", "jwtDlPriv"):
            self.assertIn('id="%s"' % kid, page, kid)
        # The sign button and both editors are enabled (not a preview).
        self.assertNotIn('id="jwtSign" disabled', page)
        self.assertNotIn('id="jwtEditHeader" disabled', page)
        self.assertNotIn('id="jwtEditPayload" disabled', page)
        block = page[page.index('id="jwt-panel-edit"'):page.index("</section>", page.index('id="jwt-panel-edit"'))]
        self.assertNotIn("Coming in JWT-02", block)
        # The panel carries the live badge. Assert the marker class, not the
        # internal ticket ID: badge wording is visitor-facing copy and may be
        # reworded, but a preview panel must never get jwt-phase-live.
        self.assertIn("jwt-phase jwt-phase-live", block)

    def test_variants_panel_is_functional(self):
        """JWT-03: the Test Variants panel builds labelled templates."""
        page = self._page()
        for kid in ("jwtVarNone", "jwtVarClaim", "jwtVarValue", "jwtVarTamper",
                    "jwtVarResign", "jwtVarPubPem", "jwtVarConfusion",
                    "jwtVarEmbed", "jwtVarJkuX5u", "jwtVarUrl", "jwtVarJku",
                    "jwtVarKidStyle", "jwtVarKid", "jwtVarKidBuild",
                    "jwtVarSecret", "jwtVarPrivate", "jwtVarGenKey",
                    "jwtVarGenPub", "jwtVarToken", "jwtVarCopy", "jwtVarDl",
                    "jwtVarResult", "jwtVarNote"):
            self.assertIn('id="%s"' % kid, page, kid)
        self.assertNotIn('id="jwtVarNone" disabled', page)
        block = page[page.index('id="jwt-panel-variants"'):page.index("</section>", page.index('id="jwt-panel-variants"'))]
        self.assertNotIn("Coming in JWT-03", block)
        self.assertIn("jwt-phase jwt-phase-live", block)
        self.assertIn("TEST TEMPLATE", block)
        self.assertIn("not a finding", block)

    def test_secret_panel_is_functional_and_bounded(self):
        """JWT-03: the Secret Test panel is functional, bounded and local."""
        page = self._page()
        for kid in ("jwtSecretBuiltin", "jwtWordlist", "jwtMaxCand", "jwtMaxSec",
                    "jwtSecretStart", "jwtSecretCancel", "jwtSecretProgress",
                    "jwtSecretBar", "jwtSecretResult", "jwtSecretFound",
                    "jwtSecretCopy"):
            self.assertIn('id="%s"' % kid, page, kid)
        block = page[page.index('id="jwt-panel-secret"'):page.index("</section>", page.index('id="jwt-panel-secret"'))]
        self.assertNotIn("Coming in JWT-03", block)
        self.assertNotIn("disabled", block)
        # Explicit bounds on candidates and time.
        self.assertIn('max="100000"', page)
        self.assertIn('max="120"', page)
        # Honesty: HS-only, worker-based, nothing stored/transmitted.
        for needle in ("HS256/384/512 only", "Web Worker", "never persisted",
                       "not a verdict", "cancel"):
            self.assertIn(needle, re.sub(r"\s+", " ", block))
        ctrl = self._controller()
        self.assertIn("new Worker", ctrl)
        self.assertIn("terminate", ctrl)
        self.assertIn("postMessage", ctrl)

    def test_worker_references_engine_and_has_no_network_or_storage(self):
        worker = (ROOT / "js" / "jwt.worker.js").read_text(encoding="utf-8")
        self.assertIn('importScripts("jwt.engine.js")', worker)
        js = self._strip_js_comments(worker)
        for needle in ("fetch(", "XMLHttpRequest", "localStorage", "sessionStorage",
                       "history.", "location."):
            self.assertNotIn(needle, js, "worker must be local-only: " + needle)

    def test_test_token_labels_and_honesty(self):
        page = re.sub(r"\s+", " ", self._page())
        self.assertIn("TEST TOKEN", page)
        self.assertIn("TEST TEMPLATE", page)
        for needle in ("proves nothing until", "not proof of acceptance",
                       "throwaway", "stays in memory", "algorithm confusion",
                       "not a finding", "never sends"):
            self.assertIn(needle, page, "missing statement: " + needle)
        ctrl = self._controller()
        self.assertIn("TEST TOKEN", ctrl)
        # Private-key export must be behind an explicit confirmation.
        self.assertIn("confirm(", ctrl)

    def test_copy_download_never_touch_key_material(self):
        """Copy/download token handlers export the token alone; private-key
        export is a separate, confirmed path."""
        ctrl = self._controller()

        def fn_body(name):
            m = re.search(r"function %s\(\) \{(.*?)\n  \}" % name, ctrl, flags=re.S)
            self.assertTrue(m, name + " not found in controller")
            return m.group(1)

        for name in ("copyToken", "downloadToken"):
            body = fn_body(name)
            self.assertNotIn("exportPrivateJwk", body, name)
            self.assertNotIn("private", body, name)
            self.assertNotIn("confirm", body, name)
        for name in ("copyPrivateKey", "downloadPrivateKey"):
            body = fn_body(name)
            self.assertIn("confirm", body, name)
            self.assertIn("exportPrivateJwk", body, name)

    def test_accessible_tabs_and_key_subtabs(self):
        page = self._page()
        # Four panel tabs (Analyze&Verify, Edit/Generate, Test Variants,
        # Secret Test), four verify key-type sub-tabs, four signing key-type
        # sub-tabs and three variant signing-key sub-tabs.
        self.assertEqual(page.count('role="tab"'), 4 + 4 + 4 + 3)
        self.assertIn("ArrowRight", self._controller())
        self.assertIn("Home", self._controller())
        self.assertIn("End", self._controller())

    def test_privacy_and_accuracy_statements_present(self):
        page = re.sub(r"\s+", " ", self._page())
        for needle in (
            "JWTs can be credentials",
            "Fully local",
            "Decoding is not verification",
            "proves only a match with that key",
            "TEST TOKEN and a variant is a TEST TEMPLATE — not proof of acceptance",
            "Live target testing is not part",
            "Authorized testing only",
        ):
            self.assertIn(needle, page, "missing statement: " + needle)

    def test_no_numeric_score_or_fake_verdict(self):
        page = self._page()
        for needle in ("score-gauge", "/ 100", "gaugeHtml", 'class="risk high"',
                       'class="risk medium"', 'class="risk low"'):
            self.assertNotIn(needle, page)

    def test_guide_tracks_the_live_workbench(self):
        """The guide reflects the shipped tool: every panel is functional, so
        it must not describe any capability as a future preview.

        The guide describes capabilities in the reader's terms; internal phase
        numbering is a repo concern and deliberately stays out of the copy.
        """
        guide = self.GUIDE.read_text(encoding="utf-8")
        self.assertIn("Every panel is fully functional", guide)
        self.assertIn("decode", guide.lower())
        self.assertIn("verif", guide.lower())
        self.assertIn("secret testing", guide.lower())
        self.assertNotIn("still in development", guide)

    def test_sitemap_lists_the_tool_now_that_it_is_functional(self):
        sitemap = (ROOT / "sitemap.xml").read_text(encoding="utf-8")
        self.assertIn("/CyberBuddy/tools/jwt/</loc>", sitemap)
        self.assertIn("/CyberBuddy/guides/jwt/</loc>", sitemap)

    def test_pwa_shortcut_added_now_the_workbench_is_complete(self):
        """JWT-03 completes the phased workbench, so the JWT tool earns its
        home-screen shortcut (deliberately deferred through JWT-00/01/02)."""
        manifest = json.loads((ROOT / "manifest.webmanifest").read_text(encoding="utf-8"))
        urls = [s.get("url", "") for s in manifest.get("shortcuts", [])]
        self.assertTrue(any("jwt" in u for u in urls), urls)
        names = [s.get("name", "") for s in manifest.get("shortcuts", [])]
        self.assertTrue(any("JWT" in n for n in names), names)

    def test_methodology_and_landing_page_mention_jwt(self):
        methodology = (ROOT / "methodology" / "index.html").read_text(encoding="utf-8")
        landing = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn("JWT Security Workbench", methodology)
        self.assertIn("JWT verification", methodology)
        # Landing page: the workbench card and the checks ticker keep the JWT
        # promise visible (the scope section is key-point copy, not per-tool).
        self.assertIn("JWT Security Workbench", landing)
        self.assertIn("JWT decode &amp; verify", landing)


class JwtVaptTests(unittest.TestCase):
    """VAPT Testing Suggestions & Test Payloads: the Analyze & Verify panel
    derives prioritized authorized-test vectors from the decoded token
    (engine: J.vaptRecommendations — pure rules, Node-tested here), builds
    one-click TEST PAYLOADs locally (J.buildVaptPayload), and routes to the
    matching workbench tab with the same values prefilled.

    Accuracy rules pinned here: everything stays client-side; suggestions are
    test vectors, never findings; severities come from a fixed vocabulary;
    the alg:none suggestion keeps parse/verify guards intact; RS→HS
    confusion requires the pasted public key (never fetched); kid probes
    keep the original signature so they never need a key; self-signed probes
    (embedded-JWK, jku/x5u) re-declare the signing algorithm in the header
    because the alg switch is part of the test.
    """

    PAGE = ROOT / "tools" / "jwt" / "index.html"
    CONTROLLER = ROOT / "js" / "tool.jwt.js"
    ENGINE = ROOT / "js" / "jwt.engine.js"

    def _page(self) -> str:
        return self.PAGE.read_text(encoding="utf-8")

    def _controller(self) -> str:
        return self.CONTROLLER.read_text(encoding="utf-8")

    def _engine(self) -> str:
        return self.ENGINE.read_text(encoding="utf-8")

    def _run_engine(self, harness: str):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import tempfile
        engine = self.ENGINE.read_text(encoding="utf-8")
        script = engine + "\n" + harness
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run(
                [node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=30,
            )
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])

    @staticmethod
    def _hs_token(payload: dict, header_extra: dict | None = None) -> str:
        """Sign an HS256 token through the engine itself (inside Node)."""
        import tempfile
        node = shutil.which("node")
        if not node:
            return ""
        header = {"alg": "HS256", "typ": "JWT"}
        header.update(header_extra or {})
        harness = (
            "CyberBuddyJwt.signToken(%s,%s,'secret',{alg:'HS256'})"
            ".then(r=>console.log(JSON.stringify({token:r.token})));"
            % (json.dumps(header), json.dumps(payload))
        )
        engine = (ROOT / "js" / "jwt.engine.js").read_text(encoding="utf-8")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(engine + "\n" + harness)
            path = fh.name
        try:
            proc = subprocess.run([node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=30)
        finally:
            os.unlink(path)
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout.strip().splitlines()[-1])["token"]

    def _recs(self, token: str):
        out = self._run_engine(
            "const p = CyberBuddyJwt.parseToken(%s);\n"
            "console.log(JSON.stringify(CyberBuddyJwt.vaptRecommendations(p)));"
            % json.dumps(token)
        )
        return out

    # --- suggestion rules ----------------------------------------------

    def test_hs_token_offers_secret_test_but_no_confusion(self):
        token = self._hs_token({"sub": "alice", "exp": 4102444800, "iat": 4102444800 - 3600})
        recs = self._recs(token)
        ids = [r["id"] for r in recs]
        self.assertIn("hmac-secret", ids)
        self.assertIn("alg-none", ids)
        self.assertNotIn("alg-confusion", ids)
        secret = next(r for r in recs if r["id"] == "hmac-secret")
        self.assertEqual(secret["action"], "secret")
        self.assertEqual(secret["tab"], "secret")
        self.assertEqual(secret["actionLabel"], "Launch secret test")

    def test_rs_token_offers_confusion_as_critical(self):
        token = self._hs_token({"sub": "a"})  # header alg rewritten below
        out = self._run_engine("""
(async () => {
  const pair = await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'}, true, ['sign','verify']);
  const s = await CyberBuddyJwt.signToken({alg:'RS256',typ:'JWT'}, {sub:'a', exp:4102444800, iat:4102444800-3600}, pair.privateKey, {alg:'RS256'});
  const recs = CyberBuddyJwt.vaptRecommendations(CyberBuddyJwt.parseToken(s.token));
  const conf = recs.filter(r=>r.id==='alg-confusion')[0];
  console.log(JSON.stringify({ids: recs.map(r=>r.id), confSev: conf && conf.severity,
    confNeedsPem: !!(conf && conf.needsPem), confLabel: conf && conf.actionLabel,
    hasSecretTest: recs.some(r=>r.id==='hmac-secret')}));
})();
""")
        self.assertIn("alg-confusion", out["ids"])
        self.assertEqual(out["confSev"], "critical")
        self.assertTrue(out["confNeedsPem"])
        self.assertIn("RS-to-HMAC", out["confLabel"])
        self.assertFalse(out["hasSecretTest"])

    def test_ps_token_also_offers_rsa_to_hmac_confusion_vector(self):
        """PS* uses an RSA public key; header-driven fallback to HMAC is the
        same class of verifier mistake as RS* → HS* confusion."""
        out = self._run_engine("""
(async () => {
  const pair = await CyberBuddyJwt.generateRsaTestPair('PS256');
  const s = await CyberBuddyJwt.signToken({alg:'PS256',typ:'JWT'}, {sub:'a'}, pair.privateKey, {alg:'PS256'});
  const recs = CyberBuddyJwt.vaptRecommendations(CyberBuddyJwt.parseToken(s.token));
  const c = recs.find(r => r.id === 'alg-confusion');
  console.log(JSON.stringify({has:!!c, severity:c && c.severity, title:c && c.title}));
})();
""")
        self.assertTrue(out["has"], out)
        self.assertEqual(out["severity"], "critical")
        self.assertIn("PS256", out["title"])

    def test_alg_none_suggested_for_every_signed_token(self):
        for payload in ({"sub": "a"}, {"x": 1}):
            recs = self._recs(self._hs_token(payload))
            none = next(r for r in recs if r["id"] == "alg-none")
            self.assertEqual(none["severity"], "critical")
            self.assertEqual(none["payload"], "alg-none")
            self.assertIn("alg:none", none["actionLabel"])

    def test_kid_severity_depends_on_presence_and_offers_vectors(self):
        with_kid = self._recs(self._hs_token({"sub": "a"}, {"kid": "key-7"}))
        kid = next(r for r in with_kid if r["id"] == "kid")
        self.assertEqual(kid["severity"], "high")
        self.assertIn("key-7", kid["why"])  # reasons cite the token's own kid
        without_kid = self._recs(self._hs_token({"sub": "a"}))
        kid2 = next(r for r in without_kid if r["id"] == "kid")
        self.assertEqual(kid2["severity"], "info")  # defense-in-depth
        for recs in (with_kid, without_kid):
            k = next(r for r in recs if r["id"] == "kid")
            joined = " ".join(k["howTo"])
            self.assertIn("dev/null", joined)
            self.assertIn("OR 1=1", joined)

    def test_jku_x5u_always_suggested_and_reflects_existing_header(self):
        recs = self._recs(self._hs_token({"sub": "a"}))
        jku = next(r for r in recs if r["id"] == "jku-x5u")
        self.assertEqual(jku["severity"], "high")
        self.assertTrue(jku["needsUrl"])
        self.assertIn("no jku/x5u", jku["why"])
        recs2 = self._recs(self._hs_token({"sub": "a"}, {"jku": "https://keys.example/jwks.json"}))
        jku2 = next(r for r in recs2 if r["id"] == "jku-x5u")
        self.assertIn("already declares", jku2["why"])

    def test_claim_tamper_only_when_authorization_claims_exist(self):
        recs = self._recs(self._hs_token({"sub": "a", "role": "user", "scopes": ["read"]}))
        ids = [r["id"] for r in recs]
        self.assertIn("claim-tamper", ids)
        tamper = next(r for r in recs if r["id"] == "claim-tamper")
        self.assertEqual(tamper["action"], "edit")
        self.assertEqual(tamper["tab"], "edit")
        self.assertIn("role", tamper["claims"])
        self.assertIn("scopes", tamper["claims"])
        bare = self._recs(self._hs_token({"sub": "a", "name": "Alice"}))
        self.assertNotIn("claim-tamper", [r["id"] for r in bare])

    def test_lifetime_suggestion_for_long_lived_or_never_expiring(self):
        long_lived = self._recs(self._hs_token(
            {"exp": 4102444800, "iat": 4102444800 - 86400 * 30}))
        self.assertIn("lifetime", [r["id"] for r in long_lived])
        no_exp = self._recs(self._hs_token({"sub": "a"}))
        self.assertIn("lifetime", [r["id"] for r in no_exp])
        normal = self._recs(self._hs_token(
            {"exp": 4102444800, "iat": 4102444800 - 900}))
        self.assertNotIn("lifetime", [r["id"] for r in normal])

    def test_every_suggestion_is_well_formed(self):
        token = self._hs_token({"sub": "a", "role": "user", "kid-free": 1}, {"kid": "k"})
        recs = self._recs(token)
        self.assertTrue(len(recs) >= 5)
        for r in recs:
            self.assertIn(r["severity"], ("critical", "high", "info"), r["id"])
            self.assertTrue(r["title"], r["id"])
            self.assertTrue(r["why"], r["id"])
            self.assertIn(r["action"], ("build", "edit", "secret"), r["id"])
            self.assertTrue(r["actionLabel"], r["id"])
            self.assertIn(r["tab"], ("variants", "edit", "secret"), r["id"])
            self.assertGreaterEqual(len(r["howTo"]), 2, r["id"])
            self.assertLessEqual(len(r["howTo"]), 3, r["id"])
            joined = " ".join(r["howTo"]).lower()
            self.assertIn("burp", joined, r["id"])
            # Each how-to names the vulnerable signal, not just the action.
            self.assertTrue("401" in joined or "403" in joined or "vulnerable" in joined, r["id"])

    # --- one-click payload generation -----------------------------------

    def test_payload_alg_none_is_unsigned_and_still_rejected_by_parse(self):
        token = self._hs_token({"sub": "alice", "role": "user"})
        out = self._run_engine("""
(async () => {
  const parsed = CyberBuddyJwt.parseToken(%s);
  const v = await CyberBuddyJwt.buildVaptPayload(parsed, 'alg-none');
  const header = JSON.parse(new TextDecoder().decode(CyberBuddyJwt.b64urlDecode(v.token.split('.')[0])));
  console.log(JSON.stringify({alg: header.alg, emptySig: v.token.endsWith('.'),
    parseRejects: !CyberBuddyJwt.tryParseToken(v.token).ok, type: v.type, note: !!v.note}));
})();
""" % json.dumps(token))
        self.assertEqual(out["alg"], "none")
        self.assertTrue(out["emptySig"])
        self.assertTrue(out["parseRejects"])
        self.assertEqual(out["type"], "alg-none")
        self.assertTrue(out["note"])

    def test_payload_kid_keeps_original_signature(self):
        token = self._hs_token({"sub": "alice"})
        out = self._run_engine("""
(async () => {
  const parsed = CyberBuddyJwt.parseToken(%s);
  const path = await CyberBuddyJwt.buildVaptPayload(parsed, 'kid', {kid:'../../../dev/null'});
  const sql = await CyberBuddyJwt.buildVaptPayload(parsed, 'kid', {kid:"1' OR 1=1--"});
  const dflt = await CyberBuddyJwt.buildVaptPayload(parsed, 'kid', {});
  const kidOf = (t) => JSON.parse(new TextDecoder().decode(CyberBuddyJwt.b64urlDecode(t.split('.')[0]))).kid;
  console.log(JSON.stringify({
    pathKeepsSig: path.token.split('.')[2] === parsed.raw.split('.')[2],
    pathKid: kidOf(path.token), sqlKid: kidOf(sql.token), dfltKid: kidOf(dflt.token)}));
})();
""" % json.dumps(token))
        self.assertTrue(out["pathKeepsSig"])  # needs no key at all
        self.assertEqual(out["pathKid"], "../../../dev/null")
        self.assertIn("OR 1=1", out["sqlKid"])
        self.assertEqual(out["dfltKid"], "../../../dev/null")

    def test_payload_alg_confusion_signs_with_pasted_public_key(self):
        token = self._hs_token({"sub": "alice"})
        out = self._run_engine("""
const crypto2 = require('crypto');
(async () => {
  const parsed = CyberBuddyJwt.parseToken(%s);
  const pem = '-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAA\\n-----END PUBLIC KEY-----';
  const v = await CyberBuddyJwt.buildVaptPayload(parsed, 'alg-confusion', {publicKeyPem: pem});
  const parts = v.token.split('.');
  const header = JSON.parse(new TextDecoder().decode(CyberBuddyJwt.b64urlDecode(parts[0])));
  const expected = crypto2.createHmac('sha256', pem).update(parts[0] + '.' + parts[1]).digest();
  console.log(JSON.stringify({alg: header.alg,
    sigOk: expected.equals(Buffer.from(CyberBuddyJwt.b64urlDecode(parts[2]))),
    needsPem: (await CyberBuddyJwt.buildVaptPayload(parsed, 'alg-confusion', {})).error}));
})();
""" % json.dumps(token))
        self.assertEqual(out["alg"], "HS256")
        self.assertTrue(out["sigOk"])
        self.assertTrue(out["needsPem"])  # refused without the pasted PEM

    def test_payload_embedded_jwk_flips_alg_and_verifies_with_own_key(self):
        token = self._hs_token({"sub": "alice"})
        out = self._run_engine("""
(async () => {
  const parsed = CyberBuddyJwt.parseToken(%s);
  const pair = await CyberBuddyJwt.generateRsaTestPair('RS256');
  const v = await CyberBuddyJwt.buildVaptPayload(parsed, 'embedded-jwk',
    {publicJwk: pair.publicJwk, alg:'RS256', key: pair.privateKey});
  const header = JSON.parse(new TextDecoder().decode(CyberBuddyJwt.b64urlDecode(v.token.split('.')[0])));
  const check = await CyberBuddyJwt.verifyToken(v.token, header.jwk, {alg:'RS256'});
  console.log(JSON.stringify({alg: header.alg, hasJwk: !!header.jwk, ok: check.valid}));
})();
""" % json.dumps(token))
        # HS256 base: the self-signed probe re-declares its signing alg — the
        # switch is part of the embedded-JWK test.
        self.assertEqual(out["alg"], "RS256")
        self.assertTrue(out["hasJwk"])
        self.assertTrue(out["ok"])

    def test_payload_jku_x5u_carry_the_url_and_verify(self):
        token = self._hs_token({"sub": "alice"})
        out = self._run_engine("""
(async () => {
  const parsed = CyberBuddyJwt.parseToken(%s);
  const pair = await CyberBuddyJwt.generateRsaTestPair('RS256');
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const jku = await CyberBuddyJwt.buildVaptPayload(parsed, 'jku',
    {url:'https://attacker.example/jwks.json', alg:'RS256', key: pair.privateKey, kid:'test-jwks-key'});
  const x5u = await CyberBuddyJwt.buildVaptPayload(parsed, 'x5u',
    {url:'https://attacker.example/c.pem', alg:'RS256', key: pair.privateKey, kid:'test-cert-key'});
  const dec = (t) => JSON.parse(new TextDecoder().decode(CyberBuddyJwt.b64urlDecode(t.split('.')[0])));
  const check = await CyberBuddyJwt.verifyToken(jku.token, pub, {alg:'RS256'});
  console.log(JSON.stringify({jku: dec(jku.token).jku, x5u: dec(x5u.token).x5u,
    jkuKid: dec(jku.token).kid, x5uKid: dec(x5u.token).kid,
    alg: dec(jku.token).alg, verifies: check.valid}));
})();
""" % json.dumps(token))
        self.assertEqual(out["jku"], "https://attacker.example/jwks.json")
        self.assertEqual(out["x5u"], "https://attacker.example/c.pem")
        self.assertEqual(out["jkuKid"], "test-jwks-key")
        self.assertEqual(out["x5uKid"], "test-cert-key")
        self.assertEqual(out["alg"], "RS256")
        self.assertTrue(out["verifies"])

    def test_url_header_payloads_require_absolute_http_urls(self):
        token = self._hs_token({"sub": "alice"})
        out = self._run_engine("""
(async () => {
  const parsed = CyberBuddyJwt.parseToken(%s);
  const bad = await CyberBuddyJwt.buildVaptPayload(parsed, 'jku', {url:'javascript:alert(1)', alg:'RS256', key:{}});
  const relative = await CyberBuddyJwt.buildVariant(parsed, 'x5u', {url:'/cert.pem', alg:'HS256', key:'secret'});
  console.log(JSON.stringify({bad:bad.error, relative:relative.error}));
})();
""" % json.dumps(token))
        self.assertIn("http or https", out["bad"])
        self.assertIn("absolute HTTP(S) URL", out["relative"])

    def test_payload_requires_base_token_and_known_kind(self):
        out = self._run_engine("""
(async () => {
  const noBase = await CyberBuddyJwt.buildVaptPayload(null, 'alg-none');
  const s = await CyberBuddyJwt.signToken({alg:'HS256'},{x:1},'s',{alg:'HS256'});
  const badKind = await CyberBuddyJwt.buildVaptPayload(CyberBuddyJwt.parseToken(s.token), 'wipe-server');
  console.log(JSON.stringify({noBase: noBase.error, badKind: badKind.error}));
})();
""")
        self.assertIn("base token", out["noBase"].lower())
        self.assertIn("Unknown VAPT payload kind", out["badKind"])

    # --- UI wiring -------------------------------------------------------

    def test_vapt_section_present_in_analyze_panel(self):
        page = self._page()
        for kid in ("jwtVapt", "jwtVaptList", "jwtVaptStatus", "jwtVaptOut",
                    "jwtVaptOutNote", "jwtVaptOutLabel", "jwtVaptToken",
                    "jwtVaptCopy", "jwtVaptCopyBurp", "jwtVaptRefine",
                    "jwtVaptCopyStatus", "jwtVaptHowTo"):
            self.assertIn('id="%s"' % kid, page, kid)
        self.assertIn("VAPT Testing Suggestions", page)
        self.assertIn("TEST PAYLOAD", page)
        # Sits inside the Analyze & Verify panel, below the claims analysis.
        analyze = page[page.index('id="jwt-panel-analyze"'):page.index('id="jwt-panel-edit"')]
        self.assertIn('id="jwtVapt"', analyze)
        self.assertLess(analyze.index('id="jwtClaims"'), analyze.index('id="jwtVapt"'))
        # Copy affordances contract: raw token and a Burp-ready header.
        self.assertIn("Copy as Burp Authorization header", page)
        self.assertIn("authorized testing only", analyze.replace("&middot;", "·"))

    def test_vapt_controller_wiring(self):
        ctrl = self._controller()
        self.assertIn("vaptRecommendations(", ctrl)
        self.assertIn("buildVaptPayload(", ctrl)
        self.assertIn("initVaptPanel", ctrl)
        self.assertIn("renderVapt(parsed)", ctrl)
        self.assertIn("renderVapt(null)", ctrl)
        # The Burp-ready copy composes the Authorization header locally.
        self.assertIn('"Authorization: Bearer "', ctrl)
        # Refine routes cover all three workbench tabs.
        for tab in ("jwt-tab-edit", "jwt-tab-variants", "jwt-tab-secret"):
            self.assertIn(tab, ctrl)
        # Secret test can launch straight from the suggestion card.
        self.assertIn("startSecretTest();", ctrl)

    def test_vapt_styles_cover_severity_tags_and_layout(self):
        css = (ROOT / "css" / "app.css").read_text(encoding="utf-8")
        for needle in (".jwt-vapt-list", ".jwt-vapt-item", ".jwt-vapt-tag",
                       ".jwt-vapt-tag-critical", ".jwt-vapt-tag-high",
                       ".jwt-vapt-tag-info", ".jwt-vapt-out",
                       ".jwt-vapt-howto", ".jwt-vapt-inline"):
            self.assertIn(needle, css, needle)
        # The tags reuse the theme variables, so light/dark stay in sync.
        start = css.index(".jwt-vapt-tag-critical")
        block = css[start:start + 300]
        self.assertIn("var(--high", block)


class NavAndScrollContractTests(unittest.TestCase):
    """Site-chrome contracts behind three reported UX regressions:

    1. Header/footer "Methodology" must always point at the dedicated
       /methodology/ page — never back at the hub's #methodology summary
       section.
    2. Fragment links (/tools/#assess-targets, /methodology/#scoring, …)
       must land with the target heading visible below the sticky header —
       html{scroll-padding-top} + the load-time re-snap guarantee it.
    3. After a scan — cached demo answers included — the page must move to
       the results region, for every tool and for the hub suite, so a fast
       run never reads as "the tool didn't run".
    """

    def _app(self) -> str:
        return (ROOT / "js" / "app.js").read_text(encoding="utf-8")

    def _css(self) -> str:
        return (ROOT / "css" / "app.css").read_text(encoding="utf-8")

    @staticmethod
    def _strip_js_comments(js: str) -> str:
        js = re.sub(r"/\*.*?\*/", " ", js, flags=re.S)
        js = re.sub(r"//[^\n]*", " ", js)
        return js

    def test_nav_methodology_points_to_the_page_not_the_hub_section(self):
        app = self._app()
        # Header nav → the dedicated methodology page.
        self.assertIn('navLink(base, "/methodology/", "Methodology", current)', app)
        # Footer "Learn" column → the same page (one Methodology entry).
        self.assertIn("'/methodology/\">Methodology</a>'", app)
        # No chrome link may target the hub's #methodology summary section.
        stripped = self._strip_js_comments(app)
        self.assertNotIn("/#methodology", stripped)
        self.assertNotIn('"#methodology"', stripped)
        # The hub section keeps its anchor id — it is the footer/section
        # target, just never the nav destination.
        hub = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="methodology"', hub)

    def test_fragment_links_clear_the_sticky_header(self):
        css = self._css()
        self.assertIn("scroll-padding-top", css)
        # The html rule consumes the --scroll-offset token (a smaller phone
        # override re-defines the token inside the 760px media query).
        html_rule = re.search(
            r"html \{[^}]*scroll-padding-top:\s*var\(--scroll-offset\)", css, flags=re.S
        )
        self.assertTrue(html_rule, "html rule must carry scroll-padding-top")
        # Header is ~60px tall; the token's base value must exceed it.
        token = re.search(r"--scroll-offset:\s*(\d+)px", css)
        self.assertTrue(token, "--scroll-offset token must be defined in px")
        self.assertGreaterEqual(int(token.group(1)), 61)
        # Result regions that are programmatically scrolled to get margins.
        self.assertRegex(css, r"#results,\s*#suiteResults\s*\{\s*scroll-margin-top:")

    def test_anchor_resnap_runs_once_after_load(self):
        app = self._app()
        self.assertIn("function initAnchorResnap()", app)
        self.assertIn('addEventListener("load"', app)
        self.assertIn("scrollIntoView", app)
        # Never fights a deliberate user scroll.
        self.assertIn("the user already took over", app)

    def test_hub_suite_scrolls_to_results_on_run(self):
        app = self._app()
        start = app.index("async function run()")
        body = app[start:start + 4000]
        self.assertIn("scrollResultsIntoView(out)", body)
        self.assertIn('out.innerHTML = pipelineHtml(url)', body)

    def test_every_tool_scrolls_to_results_after_a_scan(self):
        app = self._app()
        self.assertIn("function scrollResultsIntoView(el)", app)
        # Evidence mode no longer gates the navigation itself — only the
        # page-collapse it was designed for.
        start = app.index("function enterEvidenceMode()")
        body = app[start:app.index("}", app.index("scrollResultsIntoView", start))]
        self.assertIn("evidenceEnabled()", body)
        self.assertIn('scrollResultsIntoView(document.getElementById("results"))', body)
        # Reduced-motion users still get the jump, minus the animation.
        helper = app[app.index("function scrollResultsIntoView(el)"):]
        helper = helper[:helper.index("\n}\n") + 2]
        self.assertIn('prefersReduced() ? "auto" : "smooth"', helper)
        # All four scan tools route through enterEvidenceMode on completion.
        for tool in ("clickjacking", "headers", "cors", "csp"):
            ctrl = (ROOT / "js" / ("tool.%s.js" % tool)).read_text(encoding="utf-8")
            self.assertIn("enterEvidenceMode();", ctrl, tool)



class CspPastedHeaderTests(unittest.TestCase):
    """The CSP Policy Auditor must accept a pasted Content-Security-Policy
    header value (with or without the header name) and grade it with no
    network request, and the 0-100 score / A-F grade must agree between the
    Python and browser engines."""

    PASTED = (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "frame-ancestors 'none'"
    )

    def test_python_grades_pasted_header_without_delivery_false_positive(self):
        from csp_checker import grade_csp_from_header

        result = grade_csp_from_header("Content-Security-Policy: " + self.PASTED)
        # A pasted header has no URL/status and must not claim the page is
        # delivered over HTTP.
        self.assertEqual(result.url, "")
        self.assertEqual(result.final_url, "")
        self.assertIsNone(result.status_code)
        mixed = next(c for c in result.checks if c.name == "Mixed-content control")
        self.assertEqual(mixed.status, "ok")
        self.assertNotIn("delivered over HTTP", mixed.detail)
        # The enforced policy is present, so it is not reported as missing.
        self.assertNotEqual(
            next(c for c in result.checks if c.name == "Enforced response policy").status,
            "missing",
        )
        self.assertIsNotNone(result.score)
        self.assertIn(result.grade, "ABCDF")

    def test_python_pasted_header_label_and_report_only(self):
        from csp_checker import grade_csp_from_header

        labeled = grade_csp_from_header("Content-Security-Policy: default-src 'none'")
        self.assertEqual(labeled.policy, "default-src 'none'")
        self.assertEqual(labeled.report_only_policy, "")

        report_only = grade_csp_from_header(
            "Content-Security-Policy-Report-Only: default-src 'self'"
        )
        self.assertEqual(report_only.report_only_policy, "default-src 'self'")
        self.assertEqual(report_only.policy, "")
        # Report-only does not enforce: enforced policy is missing.
        self.assertEqual(
            next(c for c in report_only.checks if c.name == "Enforced response policy").status,
            "missing",
        )

    def test_score_and_grade_agree_between_python_and_browser(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import tempfile

        from csp_checker import grade_csp_from_header

        cases = [
            self.PASTED,
            "default-src *; script-src * 'unsafe-inline'",
            "Content-Security-Policy-Report-Only: default-src 'self'",
            "Content-Security-Policy: default-src 'none'; script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ]
        py = [grade_csp_from_header(case) for case in cases]

        harness = r"""
const cases = JSON.parse(process.argv[2]);
const out = cases.map((c) => {
  const r = gradeCspFromHeader(c);
  return { risk: r.risk, score: r.score, grade: r.grade, policy: r.policy,
           report_only: r.report_only_policy, pasted: !!r._pasted,
           source: r._source, tag: scanTag(r) };
});
console.log(JSON.stringify(out));
"""
        script = (
            "const document = { documentElement: { classList: { add() {} } } };\n"
            "const window = { __cbEngine: {}, location: { origin: 'https://example.test', "
            "pathname: '/' }, addEventListener() {} };\n"
            "const localStorage = { getItem(){return null;}, setItem(){}, removeItem(){} };\n"
            "const sessionStorage = localStorage;\n"
            + (ROOT / "js" / "app.js").read_text(encoding="utf-8")
            + harness
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run(
                [node, path, json.dumps(cases)],
                cwd=str(ROOT), capture_output=True, text=True, timeout=30,
            )
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        js = json.loads(proc.stdout.strip().splitlines()[-1])

        self.assertEqual(len(js), len(py))
        for case, python, browser in zip(cases, py, js):
            with self.subTest(case=case):
                self.assertEqual(browser["risk"], python.risk)
                self.assertEqual(browser["score"], python.score)
                self.assertEqual(browser["grade"], python.grade)
                self.assertEqual(browser["policy"], python.policy)
                self.assertEqual(browser["report_only"], python.report_only_policy)
                self.assertTrue(browser["pasted"])
                self.assertEqual(browser["source"], "pasted")
                self.assertEqual(browser["tag"], "")  # no LIVE/CACHED tag for pasted

    def test_pasted_header_has_no_scan_tag_and_local_source(self):
        """A pasted header is local, not a scan — it must not read as LIVE/CACHED."""
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        start = app.index("function scanTag(")
        body = app[start:app.index("function parseCsp(", start)]
        self.assertIn('data._source === "pasted"', body)
        self.assertIn('"pasted header (local)"', app)
        self.assertIn("gradeCspFromHeader", app)

    def test_csp_page_offers_the_paste_affordance(self):
        page = (ROOT / "tools" / "csp" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="cspHeaderInput"', page)
        self.assertIn('id="cspHeaderGo"', page)
        self.assertIn('id="cspHeaderError"', page)
        controller = (ROOT / "js" / "tool.csp.js").read_text(encoding="utf-8")
        self.assertIn("gradeCspFromHeader", controller)
        self.assertIn("_pasted", controller)


class ReleaseVerificationTests(unittest.TestCase):
    """Launch-facing copy, metadata, and quality gates must not drift."""

    def test_audit_site_rejects_missing_or_empty_artifacts(self):
        script = ROOT / "tools" / "audit_site.py"
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / "missing"
            proc = subprocess.run(
                [sys.executable, str(script), str(missing)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("directory does not exist", proc.stderr)

            empty = Path(temp) / "empty"
            empty.mkdir()
            proc = subprocess.run(
                [sys.executable, str(script), str(empty)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("no HTML pages", proc.stderr)

    def test_audit_site_accepts_a_minimal_valid_artifact(self):
        script = ROOT / "tools" / "audit_site.py"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "index.html").write_text(
                '<!doctype html><a href="#ready">Ready</a><h1 id="ready">Ready</h1>',
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(script), str(root)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("1 HTML page", proc.stdout)

    def test_public_copy_describes_non_destructive_method_coverage(self):
        surfaces = (
            ROOT / "index.html",
            ROOT / "tools" / "index.html",
            ROOT / "documentation" / "index.html",
            ROOT / "README.md",
            ROOT / "llms.txt",
            ROOT / "js" / "app.js",
        )
        stale = (
            "All scans are read-only GETs",
            "all scans are read-only GETs",
            "All checks are read-only GETs",
            "Destructive requests</strong> — GET only",
            "POST / PUT / DELETE testing",
        )
        for path in surfaces:
            text = path.read_text(encoding="utf-8")
            for phrase in stale:
                with self.subTest(path=path.relative_to(ROOT), phrase=phrase):
                    self.assertNotIn(phrase, text)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for phrase in ("GET baseline", "HEAD/OPTIONS", "preflight", "POST, PUT, PATCH, or DELETE"):
            self.assertIn(phrase, readme)

    def test_launch_metadata_lists_all_seven_tools(self):
        hub = (ROOT / "index.html").read_text(encoding="utf-8")
        catalog = (ROOT / "tools" / "index.html").read_text(encoding="utf-8")
        self.assertIn("clickjacking, headers, CSP, CORS, DNS, CSRF, and JWT", hub)
        self.assertIn('"numberOfItems": 7', catalog)
        for slug in ("clickjacking", "headers", "cors", "csp", "dns", "csrf", "jwt"):
            self.assertIn(f'/CyberBuddy/tools/{slug}/', catalog)
        self.assertIn('data-count="7" data-pad="2">07</span>', hub)
        self.assertIn('data-count="5">5</span>', hub)

    def test_ci_runs_the_complete_release_verifier(self):
        verifier = (ROOT / "tools" / "verify.py").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("check_javascript_syntax", verifier)
        self.assertIn("check_structured_data", verifier)
        self.assertIn("check_pages_artifact", verifier)
        self.assertIn('"--others"', verifier)
        self.assertIn('"--exclude-standard"', verifier)
        self.assertIn("python tools/verify.py", workflow)


class PagesAssetVerificationTests(unittest.TestCase):
    """The Pages workflow's "Verify referenced assets exist" step must accept
    root-relative references (404.html points at /CyberBuddy/… assets so it
    still works from a deeply nested missing URL), and every local asset
    reference in the published tree must resolve to a real file.

    This is the regression guard for the deploy that failed on
    "Referenced assets are missing from _site" because the step only knew how
    to resolve relative hrefs and reported 404.html's absolute
    /CyberBuddy/js/404.js (etc.) as missing.
    """

    ASSET_RE = re.compile(r'(?:href|src)="([^"#][^"]*\.(?:css|js|png|webmanifest)(?:\?[^"]*)?)"')
    SKIP_TOP = {"_site", "node_modules", ".git", "__pycache__"}

    def _html_files(self):
        for path in sorted(ROOT.rglob("*.html")):
            rel = path.relative_to(ROOT)
            if rel.parts and rel.parts[0] in self.SKIP_TOP:
                continue
            yield path

    def test_every_local_asset_reference_resolves(self):
        """Mirror the workflow's asset check over the source tree (the same
        files the assemble step copies into _site/), covering both relative
        and root-relative /CyberBuddy/ references."""
        for page in self._html_files():
            text = page.read_text(encoding="utf-8", errors="replace")
            for m in self.ASSET_RE.finditer(text):
                ref = m.group(1).split("?", 1)[0]
                if ref.startswith(("http:", "https:", "//", "data:")):
                    continue
                if ref.startswith("/"):
                    # Root-relative: drop the leading slash and the GitHub
                    # Pages repo-name segment, then resolve from the root.
                    rel = ref.lstrip("/")
                    parts = rel.split("/", 1)
                    if parts[0] == "CyberBuddy":
                        rel = parts[1] if len(parts) > 1 else ""
                    target = ROOT / rel
                else:
                    target = page.parent / ref
                self.assertTrue(
                    target.is_file(),
                    f"{page.relative_to(ROOT)} -> {ref}",
                )

    def test_workflow_asset_check_handles_root_relative_paths(self):
        """The applied workflow resolves /CyberBuddy/… references from the
        artifact root; otherwise 404.html fails every deployment."""
        workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
        self.assertIn('rel="${ref#/}"', workflow)
        self.assertIn('[ -f "_site/$rel" ]', workflow)


class PagesExclusionTests(unittest.TestCase):
    """The published site must never carry repo-internal planning docs.

    docs/ROADMAP.md is the session roadmap; docs/DEV-NOTES.md is internal
    maintainer notes; docs/ and tests/ are working artifacts. The Pages
    workflow copies only the public surface, and a regression guard (here,
    run by CI via `python3 -m unittest test_engines.py`) pins that the
    assemble step never copies them into _site/.
    """

    def test_roadmap_doc_exists(self):
        self.assertTrue((ROOT / "docs" / "ROADMAP.md").is_file())

    @staticmethod
    def _assemble_step_body() -> str:
        """Return just the `run:` body of the *Assemble static site* step.

        Scanning the whole workflow for internal-path tokens is wrong: the
        leak-guard step legitimately *names* docs/ROADMAP.md and
        docs/DEV-NOTES.md in order to reject them. Only the assemble step
        decides what gets copied, so only the assemble step is scanned here.
        """
        text = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
        lines = text.splitlines()
        start = next(
            (i for i, ln in enumerate(lines) if ln.strip().startswith("- name: Assemble static site")),
            None,
        )
        assert start is not None, "Assemble static site step not found in pages.yml"
        indent = len(lines[start]) - len(lines[start].lstrip())
        body = []
        for ln in lines[start + 1:]:
            # Anything back at the step's own indentation (the next `- name:`
            # entry, or a comment introducing it) ends this step's body.
            if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
                break
            body.append(ln)
        return "\n".join(body)

    def test_workflow_never_copies_internal_paths(self):
        """The assemble step must not reference docs/ or tests/ as copy
        sources. This is the regression guard: CI runs it on every push, so a
        future commit that starts copying internal files into _site/ fails
        here."""
        text = self._assemble_step_body()
        for token in (
            "cp -a docs", "cp docs", "cp -r docs",
            "cp -a tests", "cp tests", "cp -r tests",
            "docs/ROADMAP.md", "docs/DEV-NOTES.md",
        ):
            self.assertNotIn(token, text, token)

    def test_workflow_guard_step_names_the_internal_files(self):
        """The leak guard itself must keep naming the internal files, which is
        exactly why the scan above is scoped to the assemble step."""
        text = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
        self.assertIn("Guard internal files stay out of the published site", text)
        guard = text.split("Guard internal files stay out of the published site", 1)[1]
        for name in ("docs/ROADMAP.md", "docs/DEV-NOTES.md"):
            self.assertIn(name, guard, name)

    def test_workflow_publishes_catalog_guides_and_dns(self):
        workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
        self.assertIn("cp tools/index.html _site/tools/", workflow)
        self.assertIn("cp -a guides _site/", workflow)
        self.assertIn("tools/dns", workflow)


class LinkLabelTests(unittest.TestCase):
    """Link labels name the destination — they never echo the path or URL.

    A visible label of ``/tools/jwt/`` or ``https://…`` turns a link into a
    raw location instead of a readable destination, and it leaks the site's
    internal layout into prose. Every link must say what it points at
    ("JWT Workbench"), not where it lives. Three deliberate exceptions are
    pinned by the tests below so the rule cannot silently spread to them:
    README table rows (reference tables may carry repo paths as row
    content), llms.txt's bare-URL bullets (a machine index where the URL is
    the payload), and the methodology page's security.txt disclosure link
    (the filename is the point of the link, per RFC 9116).
    """

    #: label forms that echo the destination: root-relative paths, bare
    #: fragments, and URL schemes. A leading-dot filename like
    #: ``.well-known/security.txt`` is a name, not a path form.
    PATH_OR_URL = re.compile(r"^(?:/|\.{1,2}/|#|//|[a-z][a-z0-9+.-]*://)")

    #: the one HTML link whose label is deliberately the filename: the
    #: disclosure link must say where reports go (RFC 9116).
    DISCLOSURE_HREF = "../.well-known/security.txt"

    SKIP_TOP = {"_site", "node_modules", ".git", "__pycache__"}

    def _html_files(self):
        for path in sorted(ROOT.rglob("*.html")):
            rel = path.relative_to(ROOT)
            if rel.parts and rel.parts[0] in self.SKIP_TOP:
                continue
            yield path

    def test_html_links_name_the_destination(self):
        """No published page labels a link with a path, fragment or URL."""
        link_re = re.compile(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.S)
        for page in self._html_files():
            text = page.read_text(encoding="utf-8", errors="replace")
            for href, inner in link_re.findall(text):
                if href == self.DISCLOSURE_HREF:
                    continue
                label = " ".join(re.sub(r"<[^>]+>", " ", inner).split())
                with self.subTest(page=page.relative_to(ROOT), label=label):
                    self.assertIsNone(
                        self.PATH_OR_URL.match(label),
                        "link label %r echoes its destination" % label,
                    )

    def test_readme_links_name_the_destination(self):
        """README links (outside table rows) do the same."""
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        text = re.sub(r"```.*?```", "", text, flags=re.S)  # fenced code blocks
        link_re = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
        for line in text.splitlines():
            if line.lstrip().startswith("|"):
                continue  # reference table rows may be repo paths by design
            for label, _url in link_re.findall(line):
                label = label.replace("`", "").strip()
                with self.subTest(label=label):
                    self.assertIsNone(
                        self.PATH_OR_URL.match(label),
                        "README link label %r echoes its destination" % label,
                    )

    def test_llms_txt_url_bullets_are_intentional(self):
        """llms.txt is exempt: a machine index labels entries with their
        bare URL, so the label rule does not apply there. Pin the exception
        so a cleanup never rewrites the URL bullets into something else."""
        text = (ROOT / "llms.txt").read_text(encoding="utf-8")
        for name in ("Hub", "Tools catalog", "Guides", "Documentation", "Methodology"):
            line = next(l for l in text.splitlines() if l.startswith("- %s: " % name))
            with self.subTest(bullet=name):
                self.assertRegex(
                    line,
                    r"^- %s: https?://\S+$" % re.escape(name),
                    "llms.txt %s bullet must keep its bare-URL label" % name,
                )


class DnsEngineTests(unittest.TestCase):
    """DNS & Domain Security Analyzer — pure engine tests (no network).

    The scoring contract ``grade_dns_from_records`` is exercised against
    synthetic record maps, so the suite never depends on a live resolver."""

    def _grade(self, records, statuses=None, domain="example.com"):
        from dns_security import grade_dns_from_records
        return grade_dns_from_records(domain, records, statuses or {})

    def test_normalize_domain_strips_url_path_dot_and_valid_port(self):
        from dns_security import normalize_domain
        self.assertEqual(normalize_domain("https://Example.COM/path?q=1"), "example.com")
        self.assertEqual(normalize_domain("example.com:443/path"), "example.com")
        self.assertEqual(normalize_domain("example.com."), "example.com")
        self.assertEqual(normalize_domain("  sub.example.com  "), "sub.example.com")

    def test_normalize_domain_accepts_internationalized_tlds(self):
        from dns_security import normalize_domain
        expected = "xn--e1afmkfd.xn--p1ai"
        self.assertEqual(normalize_domain("пример.рф"), expected)
        self.assertEqual(normalize_domain(expected), expected)

    def test_normalize_domain_accepts_matching_quoted_values(self):
        from dns_security import normalize_domain
        for raw in ('"example.com"', "'example.com'", "“example.com”", "‘example.com’"):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_domain(raw), "example.com")
        with self.assertRaises(ValueError):
            normalize_domain("'example.com\"")

    def test_normalize_domain_rejects_url_credentials_schemes_and_ports(self):
        from dns_security import normalize_domain
        for bad in (
            "https://user:secret@example.com/path",
            "https://@example.com/path",
            "ftp://example.com",
            "https://example.com:not-a-port/path",
            "https://example.com:99999/path",
            "example.com:99999/path",
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_domain(bad)

    def test_normalize_domain_rejects_ips_and_localhost(self):
        from dns_security import normalize_domain
        for bad in ("127.0.0.1", "::1", "localhost", "example", "no_tld", "a..b"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    normalize_domain(bad)

    def test_nxdomain_is_reported_not_graded(self):
        result = self._grade({}, statuses={"A": "NXDOMAIN"})
        self.assertEqual(result.status, "error")
        self.assertEqual(result.risk, "unknown")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.checks[0].name, "Domain resolution")
        self.assertEqual(result.checks[0].status, "error")

    def test_resolver_or_parser_failure_is_not_scored_as_missing_records(self):
        result = self._grade(
            {"A": ["203.0.113.10"]},
            statuses={"A": "NOERROR", "NS": "ERROR"},
        )
        self.assertEqual(result.status, "error")
        self.assertEqual(result.grade, "—")
        self.assertEqual(result.risk, "unknown")
        self.assertIn("NS", result.error)
        self.assertIn("no posture grade", result.summary.lower())

    def test_strong_domain_scores_high(self):
        result = self._grade({
            "A": ["203.0.113.10"],
            "NS": ["ns1.example.com.", "ns2.example.com."],
            "DS": ["12345 8 2 ABCDEF"],
            "DNSKEY": ["flags=257 protocol=3 algorithm=13 keylen=64"],
            "MX": ["10 mail.example.com."],
            "TXT": ["v=spf1 include:_spf.example.com -all"],
            "DMARC": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            "DKIM:default": ["v=DKIM1; k=rsa; p=MIGfMA0G"],
            "CAA": ['0 issue "letsencrypt.org"'],
        })
        self.assertEqual(result.grade, "A")
        self.assertGreaterEqual(result.score, 90)
        self.assertEqual(result.risk, "low")

    def test_spf_plus_all_is_a_weak_finding(self):
        result = self._grade({
            "A": ["203.0.113.10"], "NS": ["ns1.example.com.", "ns2.example.com."],
            "MX": ["10 mail.example.com."],
            "TXT": ["v=spf1 +all"],
            "DMARC": ["v=DMARC1; p=reject"],
            "DKIM:default": ["v=DKIM1; k=rsa; p=MIGfMA0G"],
            "CAA": ['0 issue "letsencrypt.org"'],
        })
        spf = next(c for c in result.checks if c.name == "SPF")
        self.assertEqual(spf.status, "weak")
        self.assertEqual(spf.deduction, 15)

    def test_spf_without_all_is_neutral_not_safe(self):
        result = self._grade({
            "MX": ["10 mail.example.com."],
            "TXT": ["v=spf1 ip4:203.0.113.0/24"],
        })
        spf = next(c for c in result.checks if c.name == "SPF")
        self.assertEqual(spf.status, "weak")
        self.assertEqual(spf.deduction, 5)
        self.assertIn("neutral", spf.detail)

    def test_spf_lookup_budget_counts_qualified_and_cidr_mechanisms(self):
        from dns_security import _spf_lookup_count
        policy = (
            "v=spf1 -include:a.example +a/24 ~mx:mail.example/24 "
            "?exists:%{i}.one.example ptr:two.example "
            "include:3.example include:4.example include:5.example "
            "include:6.example include:7.example redirect=8.example"
        )
        self.assertEqual(_spf_lookup_count(policy), 11)
        result = self._grade({"TXT": [policy]})
        spf = next(c for c in result.checks if c.name == "SPF")
        self.assertEqual(spf.deduction, 15)
        self.assertIn("11", spf.detail)

    def test_dmarc_none_is_a_weak_finding(self):
        result = self._grade({
            "A": ["203.0.113.10"], "NS": ["ns1.example.com.", "ns2.example.com."],
            "MX": ["10 mail.example.com."],
            "TXT": ["v=spf1 -all"],
            "DMARC": ["v=DMARC1; p=none"],
            "DKIM:default": ["v=DKIM1; k=rsa; p=MIGfMA0G"],
            "CAA": ['0 issue "letsencrypt.org"'],
        })
        dmarc = next(c for c in result.checks if c.name == "DMARC")
        self.assertEqual(dmarc.status, "weak")
        self.assertEqual(dmarc.deduction, 10)

    def test_dmarc_partial_and_subdomain_monitoring_do_not_earn_full_credit(self):
        cases = (
            ("v=DMARC1; p=reject; pct=0", 10, "pct=0%"),
            ("v=DMARC1; p=reject; pct=25", 5, "pct=25%"),
            ("v=DMARC1; p=reject; sp=none", 5, "sp=none"),
            ("v=DMARC1; p=reject; pct=invalid", 10, "invalid pct"),
        )
        for policy, deduction, detail in cases:
            with self.subTest(policy=policy):
                result = self._grade({"MX": ["10 mail.example.com."], "DMARC": [policy]})
                dmarc = next(c for c in result.checks if c.name == "DMARC")
                self.assertEqual(dmarc.status, "weak")
                self.assertEqual(dmarc.deduction, deduction)
                self.assertIn(detail, dmarc.detail)

    def test_duplicate_email_policies_and_revoked_dkim_are_not_protected(self):
        result = self._grade({
            "MX": ["10 mail.example.com."],
            "TXT": ["v=spf1 -all", "v=spf1 ~all"],
            "DMARC": ["v=DMARC1; p=reject", "v=DMARC1; p=quarantine"],
            "DKIM:default": ["v=DKIM1; k=rsa; p="],
        })
        checks = {check.name: check for check in result.checks}
        self.assertEqual(checks["SPF"].deduction, 15)
        self.assertEqual(checks["DMARC"].deduction, 20)
        self.assertEqual(checks["DKIM"].status, "weak")
        self.assertNotEqual(checks["DKIM"].deduction, 0)

    def test_null_mx_keeps_email_checks_informational(self):
        # RFC 7505 null MX: the domain explicitly has no email, so a missing
        # SPF/DMARC/DKIM is not a finding.
        result = self._grade({
            "A": ["203.0.113.10"], "NS": ["ns1.example.com.", "ns2.example.com."],
            "MX": ["0 ."],
            "DS": ["12345 8 2 ABCDEF"],
            "DNSKEY": ["flags=257 protocol=3 algorithm=13 keylen=64"],
        })
        for name in ("MX", "SPF", "DMARC", "DKIM"):
            check = next(c for c in result.checks if c.name == name)
            self.assertIn(check.status, ("info", "ok"), (name, check.status))
        self.assertEqual(result.grade, "A")

    def test_missing_email_controls_deduct_when_mail_present(self):
        result = self._grade({
            "A": ["203.0.113.10"], "NS": ["ns1.example.com.", "ns2.example.com."],
            "MX": ["10 mail.example.com."],
        })
        by_name = {c.name: c for c in result.checks}
        self.assertEqual(by_name["SPF"].status, "missing")
        self.assertEqual(by_name["DMARC"].status, "missing")
        self.assertEqual(by_name["DKIM"].status, "weak")
        self.assertLess(result.score, 60)

    def test_caa_absence_is_weak(self):
        result = self._grade({
            "A": ["203.0.113.10"], "NS": ["ns1.example.com.", "ns2.example.com."],
            "MX": ["10 mail.example.com."], "TXT": ["v=spf1 -all"],
            "DMARC": ["v=DMARC1; p=reject"], "DKIM:default": ["v=DKIM1; k=rsa; p=MIGfMA0G"],
            "DS": ["12345 8 2 ABCDEF"],
            "DNSKEY": ["flags=257 protocol=3 algorithm=13 keylen=64"],
        })
        caa = next(c for c in result.checks if c.name == "CAA")
        self.assertEqual(caa.status, "weak")
        self.assertEqual(caa.deduction, 5)
        self.assertIn("parent labels", caa.detail)

    def test_caa_requires_an_issue_property_and_reports_inheritance(self):
        cases = (
            ({"CAA": ['0 iodef "mailto:security@example.com"']}, 5, "no issue property"),
            ({"CAA": ['0 issuewild "letsencrypt.org"']}, 3, "wildcard issuance only"),
            ({
                "CAA": ['0 issue "letsencrypt.org"'],
                "CAA_SOURCE": ["example.com"],
            }, 0, "inherited from example.com"),
        )
        for records, deduction, detail in cases:
            with self.subTest(records=records):
                result = self._grade(records, domain="www.example.com")
                caa = next(c for c in result.checks if c.name == "CAA")
                self.assertEqual(caa.deduction, deduction)
                self.assertIn(detail, caa.detail)

    def test_dnskey_without_parent_ds_does_not_claim_dnssec(self):
        result = self._grade({
            "A": ["203.0.113.10"],
            "NS": ["ns1.example.com.", "ns2.example.com."],
            "DNSKEY": ["flags=257 protocol=3 algorithm=13 keylen=64"],
        })
        dnssec = next(c for c in result.checks if c.name == "DNSSEC")
        self.assertEqual(dnssec.status, "weak")
        self.assertEqual(dnssec.deduction, 10)
        self.assertIn("chain of trust is not established", dnssec.detail)

    def test_parent_ds_without_apex_dnskey_does_not_claim_dnssec(self):
        result = self._grade({
            "A": ["203.0.113.10"],
            "NS": ["ns1.example.com.", "ns2.example.com."],
            "DS": ["12345 8 2 ABCDEF"],
        })
        dnssec = next(c for c in result.checks if c.name == "DNSSEC")
        self.assertEqual(dnssec.status, "weak")
        self.assertEqual(dnssec.deduction, 10)
        self.assertIn("evidence is incomplete", dnssec.detail)

    def test_single_ns_is_weak(self):
        result = self._grade({"A": ["203.0.113.10"], "NS": ["ns1.example.com."]})
        ns = next(c for c in result.checks if c.name == "Name servers")
        self.assertEqual(ns.status, "weak")

    def test_to_dict_serializes(self):
        import json
        result = self._grade({"A": ["203.0.113.10"], "NS": ["ns1.example.com.", "ns2.example.com."]})
        payload = json.loads(json.dumps(result.to_dict()))
        self.assertEqual(payload["domain"], "example.com")
        self.assertIn("checks", payload)
        self.assertIn("grade", payload)

    def test_wire_helpers_roundtrip(self):
        from dns_security import _encode_name, _read_name
        raw = _encode_name("www.example.com")
        name, end = _read_name(raw, 0)
        self.assertEqual(name, "www.example.com")
        self.assertEqual(end, len(raw))

    def test_normalize_domain_rejects_non_hostname_dns_labels(self):
        from dns_security import normalize_domain
        for bad in ("foo_bar.example", "_dmarc.example.com", "-bad.example", "bad-.example"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                normalize_domain(bad)

    def test_read_name_rejects_cycles_forward_pointers_and_bad_lengths(self):
        from dns_security import _read_name
        malformed = (
            b"\xc0\x00",                  # self-cycle
            b"\xc0\x02\x00",            # forward pointer
            b"\xc0\xff",                  # out-of-bounds pointer
            b"\x40" + b"A" * 64 + b"\x00",  # reserved label type / >63
            b"\x04ab",                    # declared label runs off packet
            (b"\x3f" + b"a" * 63) * 4 + b"\x00",  # expanded name >255
        )
        for packet in malformed:
            with self.subTest(packet=packet[:8]), self.assertRaises(ValueError):
                _read_name(packet, 0)

    def test_parse_response_correlates_id_question_and_response_flag(self):
        import struct
        from dns_security import QTYPE_A, QTYPE_TXT, _encode_name, _parse_response
        name = "example.com"
        question = _encode_name(name) + struct.pack("!HH", QTYPE_A, 1)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_A, 1, 60, 4) + b"\xcb\x00\x71\x09"
        packet = struct.pack("!HHHHHH", 0xCAFE, 0x8180, 1, 1, 0, 0) + question + answer
        header, answers = _parse_response(
            packet, expected_id=0xCAFE, expected_name=name, expected_qtype=QTYPE_A
        )
        self.assertEqual(header["rcode_name"], "NOERROR")
        self.assertEqual(answers, [("A", QTYPE_A, "203.0.113.9")])
        for kwargs in (
            {"expected_id": 0xBEEF},
            {"expected_name": "other.example"},
            {"expected_qtype": QTYPE_TXT},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                _parse_response(packet, **kwargs)
        not_response = packet[:2] + struct.pack("!H", 0x0100) + packet[4:]
        with self.assertRaisesRegex(ValueError, "not a response"):
            _parse_response(not_response)

    def test_udp_query_connects_resolver_and_ignores_wrong_transaction(self):
        import struct
        import dns_security

        query = struct.pack("!H", 0x1234) + b"query"
        wrong = struct.pack("!H", 0x9999) + b"wrong"
        right = struct.pack("!H", 0x1234) + b"right"

        class FakeSocket:
            def __init__(self):
                self.connected = None
                self.sent = b""
                self.replies = [wrong, right]
            def settimeout(self, _timeout): pass
            def connect(self, address): self.connected = address
            def send(self, payload): self.sent = payload; return len(payload)
            def recv(self, _size): return self.replies.pop(0)
            def close(self): pass

        fake = FakeSocket()
        addresses = [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", ("1.1.1.1", 53))]
        with patch.object(dns_security, "_socket_addresses", return_value=addresses), \
             patch.object(dns_security.socket, "socket", return_value=fake):
            self.assertEqual(dns_security._query_udp(query, "1.1.1.1"), right)
        self.assertEqual(fake.connected, ("1.1.1.1", 53))
        self.assertEqual(fake.sent, query)

    def test_tcp_query_reads_fragmented_length_and_body_exactly(self):
        import struct
        import dns_security

        query = struct.pack("!H", 0x1234) + b"query"
        body = struct.pack("!H", 0x1234) + b"response-body"
        prefix = struct.pack("!H", len(body))

        class FakeSocket:
            def __init__(self):
                self.replies = [prefix[:1], prefix[1:], body[:3], body[3:8], body[8:]]
                self.sent = b""
            def settimeout(self, _timeout): pass
            def connect(self, _address): pass
            def sendall(self, payload): self.sent = payload
            def recv(self, size):
                chunk = self.replies.pop(0)
                self.assertion = len(chunk) <= size
                return chunk
            def close(self): pass

        fake = FakeSocket()
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", 53))]
        with patch.object(dns_security, "_socket_addresses", return_value=addresses), \
             patch.object(dns_security.socket, "socket", return_value=fake):
            self.assertEqual(dns_security._query_tcp(query, "1.1.1.1"), body)
        self.assertTrue(fake.assertion)
        self.assertEqual(fake.sent, struct.pack("!H", len(query)) + query)

    def test_parse_response_rejects_malformed_typed_rdata(self):
        import struct
        from dns_security import QTYPE_A, _encode_name, _parse_response
        question = _encode_name("example.com") + struct.pack("!HH", QTYPE_A, 1)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_A, 1, 60, 3) + b"bad"
        packet = struct.pack("!HHHHHH", 9, 0x8180, 1, 1, 0, 0) + question + answer
        with self.assertRaisesRegex(ValueError, "A record length"):
            _parse_response(
                packet, expected_id=9, expected_name="example.com", expected_qtype=QTYPE_A
            )

    def test_resolve_domain_falls_back_and_reports_every_contacted_resolver(self):
        import dns_security
        error = {"rcode_name": "TIMEOUT"}
        success = {"rcode_name": "NOERROR"}

        def fake_query(resolver, _name, _qtype, _timeout):
            return (error, []) if resolver == "192.0.2.1" else (success, [])

        with patch.object(dns_security, "_query", side_effect=fake_query) as query:
            _records, statuses, used = dns_security.resolve_domain(
                "example.com", resolvers=["192.0.2.1", "192.0.2.2"]
            )
        self.assertTrue(all(status == "NOERROR" for status in statuses.values()))
        self.assertEqual(used, "192.0.2.1, 192.0.2.2")
        self.assertEqual(query.call_args_list[0].args[0], "192.0.2.1")
        self.assertEqual(query.call_args_list[1].args[0], "192.0.2.2")
        self.assertTrue(all(call.args[0] == "192.0.2.2" for call in query.call_args_list[2:]))

    def test_resolve_domain_uses_nearest_inherited_caa_rrset(self):
        import dns_security
        success = {"rcode_name": "NOERROR"}
        queried_caa = []

        def fake_query(_resolver, name, qtype, _timeout):
            if qtype == dns_security.QTYPE_CAA:
                queried_caa.append(name)
                if name == "example.com":
                    return success, [("CAA", qtype, '0 issue "letsencrypt.org"')]
            return success, []

        with patch.object(dns_security, "_query", side_effect=fake_query), \
             patch.object(dns_security, "DKIM_SELECTORS", ()):
            records, statuses, _used = dns_security.resolve_domain(
                "app.eu.example.com", resolvers=["192.0.2.53"]
            )
        self.assertEqual(
            queried_caa,
            ["app.eu.example.com", "eu.example.com", "example.com"],
        )
        self.assertEqual(records["CAA_SOURCE"], ["example.com"])
        self.assertEqual(records["CAA"], ['0 issue "letsencrypt.org"'])
        self.assertEqual(statuses["CAA@example.com"], "NOERROR")

    def test_query_does_not_mix_cname_into_requested_values(self):
        import struct
        import dns_security
        query = struct.pack("!H", 7) + b"query"
        answers = [("CNAME", dns_security.QTYPE_CNAME, "alias.example."),
                   ("A", dns_security.QTYPE_A, "203.0.113.10")]
        header = {"rcode_name": "NOERROR", "truncated": False}
        with patch.object(dns_security, "_build_query", return_value=query), \
             patch.object(dns_security, "_query_udp", return_value=b"\x00\x07\x81\x80"), \
             patch.object(dns_security, "_parse_response", return_value=(header, answers)):
            status, values = dns_security._query(
                "1.1.1.1", "example.com", dns_security.QTYPE_A, 8.0
            )
        self.assertEqual(status["rcode_name"], "NOERROR")
        self.assertEqual(values, [("A", dns_security.QTYPE_A, "203.0.113.10")])

    def test_cli_json_serializes_one_result_and_returns_risk_exit_code(self):
        import io
        import dns_security
        result = dns_security.grade_dns_from_records(
            "example.com",
            {"A": ["203.0.113.10"], "NS": ["ns1.example.com."],
             "MX": ["10 mail.example.com."]},
        )
        with patch.object(dns_security, "scan_dns", return_value=result), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            code = dns_security.main(["example.com", "--json"])
        self.assertEqual(code, 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["domain"], "example.com")
        self.assertEqual(payload[0]["error"], "")

    def test_cli_rejects_an_invalid_domain_as_usage_error(self):
        import io
        import dns_security
        with patch("sys.stderr", new_callable=io.StringIO) as output:
            code = dns_security.main(["localhost"])
        self.assertEqual(code, 2)
        self.assertIn("Invalid domain", output.getvalue())

    def test_cli_rejects_invalid_timeout_resolver_and_input_file(self):
        import io
        import dns_security
        cases = (
            (["example.com", "--timeout", "0"], "Invalid timeout"),
            (["example.com", "--resolver", "resolver.example"], "Invalid resolver"),
            (["--file", "/definitely/missing/cyberbuddy-domains.txt"], "Could not read"),
        )
        for argv, message in cases:
            with self.subTest(argv=argv), \
                 patch("sys.stderr", new_callable=io.StringIO) as output:
                self.assertEqual(dns_security.main(argv), 2)
                self.assertIn(message, output.getvalue())

    def test_cli_normalizes_and_deduplicates_inputs_before_scanning(self):
        import io
        import dns_security
        result = dns_security.grade_dns_from_records("example.com", {})
        with patch.object(dns_security, "scan_dns", return_value=result) as scan, \
             patch("sys.stdout", new_callable=io.StringIO):
            dns_security.main(["Example.com", "https://example.com/path"])
        scan.assert_called_once()
        self.assertEqual(scan.call_args.args[0], "example.com")


class DnsParityTests(unittest.TestCase):
    """The JS grader must agree with the Python engine, record map for record
    map. Exercised under Node against a fixed records/statuses shape."""

    RECORDS = {
        "A": ["203.0.113.10"],
        "AAAA": ["2001:db8::10"],
        "NS": ["ns1.example.com.", "ns2.example.com."],
        "MX": ["10 mail.example.com."],
        "TXT": ["v=spf1 include:_spf.example.com -all"],
        "DMARC": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
        "DKIM:default": ["v=DKIM1; k=rsa; p=MIGfMA0G"],
        "CAA": ['0 issue "letsencrypt.org"'],
        "DS": ["12345 8 2 ABCDEF"],
        "DNSKEY": ["flags=257 protocol=3 algorithm=13 keylen=64"],
    }

    def _python_grade(self):
        import json
        from dns_security import grade_dns_from_records
        result = grade_dns_from_records("example.com", self.RECORDS, {"A": "NOERROR"})
        return json.loads(json.dumps(result.to_dict()))

    def test_js_grader_matches_python(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import tempfile
        import json as _json
        from dns_security import grade_dns_from_records
        py = grade_dns_from_records("example.com", self.RECORDS, {"A": "NOERROR"})
        records_json = _json.dumps(self.RECORDS)
        script = (
            "const document = { documentElement: { classList: { add() {} } } };\n"
            "const window = { __cbEngine: {}, location: { origin: 'https://example.test', pathname: '/' }, addEventListener() {} };\n"
            + (ROOT / "js" / "app.js").read_text(encoding="utf-8")
            + "\n"
            + "const r = gradeDnsFromRecords('example.com', " + records_json + ", { A: 'NOERROR' }, 'python');\n"
            + "console.log(JSON.stringify({ score: r.score, grade: r.grade, risk: r.risk, checks: r.checks.map(function(c){return [c.name, c.status, c.deduction || 0];}) }));\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run([node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=30)
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(payload["score"], py.score)
        self.assertEqual(payload["grade"], py.grade)
        self.assertEqual(payload["risk"], py.risk)
        js_checks = {name: (status, ded) for name, status, ded in payload["checks"]}
        for check in py.checks:
            self.assertIn(check.name, js_checks)
            self.assertEqual(js_checks[check.name][0], check.status, check.name)
            self.assertEqual(js_checks[check.name][1], check.deduction, check.name)

    def test_js_grader_matches_python_for_email_policy_edges(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        import json as _json
        from dns_security import grade_dns_from_records
        scenarios = [
            {
                "MX": ["10 mail.example.com."],
                "TXT": ["v=spf1 ip4:203.0.113.0/24"],
                "DMARC": ["v=DMARC1; p=reject; pct=0"],
                "DKIM:default": ["v=DKIM1; p="],
            },
            {
                "TXT": [
                    "v=spf1 -include:a +a/24 ~mx:m/24 ?exists:%{i}.x ptr:y "
                    "include:3 include:4 include:5 include:6 include:7 redirect=8"
                ],
                "DMARC": ["v=DMARC1; p=reject; sp=none"],
                "DKIM:default": ["v=DKIM1; p=active"],
            },
            {
                "TXT": ["v=spf1 -all", "v=spf1 ~all"],
                "DMARC": ["v=DMARC1; p=reject", "v=DMARC1; p=quarantine"],
            },
        ]
        expected = []
        for records in scenarios:
            result = grade_dns_from_records("example.com", records, {"A": "NOERROR"})
            expected.append({
                check.name: (check.status, check.deduction)
                for check in result.checks
            })
        script = (
            "const document = { documentElement: { classList: { add() {} } } };\n"
            "const window = { __cbEngine: {}, location: { origin: 'https://example.test', pathname: '/' }, addEventListener() {} };\n"
            + (ROOT / "js" / "app.js").read_text(encoding="utf-8")
            + "\nconst scenarios = " + _json.dumps(scenarios) + ";\n"
            + "console.log(JSON.stringify(scenarios.map((records) => {"
            + " const r=gradeDnsFromRecords('example.com',records,{A:'NOERROR'},'browser');"
            + " return Object.fromEntries(r.checks.map((c)=>[c.name,[c.status,c.deduction||0]]));"
            + "})));\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run(
                [node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=30
            )
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        actual = _json.loads(proc.stdout.strip().splitlines()[-1])
        normalized_expected = [
            {name: list(value) for name, value in checks.items()}
            for checks in expected
        ]
        self.assertEqual(actual, normalized_expected)

    def test_browser_doh_filters_answer_types_and_walks_inherited_caa(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        script = (
            "const document = { documentElement: { classList: { add() {} } } };\n"
            "const window = { __cbEngine: {}, location: { origin: 'https://example.test', pathname: '/' }, addEventListener() {} };\n"
            + (ROOT / "js" / "app.js").read_text(encoding="utf-8")
            + "\n(async function(){\n"
            + "global.fetch = async function(){ return {ok:true,json:async function(){return {Status:0,Answer:[{type:5,data:'alias.example.'},{type:16,data:'\\\"v=spf1 \\\" \\\"-all\\\"'}]};}};};\n"
            + "const txt = await dohResolve('app.example.com','TXT');\n"
            + "const calls=[]; dohResolve=async function(name,type){calls.push([name,type]); return {status:'NOERROR',answers:name==='example.com' ? ['0 issue \\\"letsencrypt.org\\\"'] : []};};\n"
            + "const records={}, statuses={}; await collectRelevantCaa('app.eu.example.com',records,statuses);\n"
            + "console.log(JSON.stringify({txt:txt.answers,calls:calls,records:records,statuses:statuses}));\n"
            + "})().catch(function(error){console.error(error);process.exit(1);});\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run(
                [node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=30
            )
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(payload["txt"], ["v=spf1 -all"])
        self.assertEqual(
            payload["calls"],
            [["app.eu.example.com", "CAA"], ["eu.example.com", "CAA"], ["example.com", "CAA"]],
        )
        self.assertEqual(payload["records"]["CAA_SOURCE"], ["example.com"])
        self.assertEqual(payload["statuses"]["CAA@example.com"], "NOERROR")

    def test_js_grader_refuses_to_score_incomplete_dns_evidence(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node not available")
        script = (
            "const document = { documentElement: { classList: { add() {} } } };\n"
            "const window = { __cbEngine: {}, location: { origin: 'https://example.test', pathname: '/' }, addEventListener() {} };\n"
            + (ROOT / "js" / "app.js").read_text(encoding="utf-8")
            + "\nconst r = gradeDnsFromRecords('example.com', {A:['203.0.113.10']}, {A:'NOERROR',NS:'error'}, 'dns-relay');\n"
            + "console.log(JSON.stringify({status:r.status,grade:r.grade,risk:r.risk,error:r.error,checks:r.checks}));\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run(
                [node, path], cwd=str(ROOT), capture_output=True, text=True, timeout=30
            )
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["grade"], "—")
        self.assertEqual(payload["risk"], "unknown")
        self.assertIn("NS", payload["error"])
        self.assertEqual(payload["checks"][0]["name"], "DNS queries")


class DnsSiteTests(unittest.TestCase):
    """The DNS tool is wired through the registry, menu, catalog, sitemap,
    manifest, llms.txt and the applied Pages workflow."""

    def test_dns_tool_joins_the_hub_suite(self):
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        start = app.index("const TOOLS_MENU")
        end = app.index("const TOOLS_SOON", start)
        menu = app[start:end]
        self.assertIn('href: "/tools/dns/"', menu)
        self.assertIn('category: "assess"', menu)
        # The DNS analyzer is part of the hub "Run suite": the suite derives
        # the domain from the URL hostname and feeds it to the DNS grader.
        self.assertIn("suite: true", menu)

    def test_dns_suite_wiring_derives_domain_from_url(self):
        """Hub suite contract: the DNS checkbox exists, the button counts five
        tools, and initSuite derives the hostname (skipping IP literals) before
        the consent-gated apiDns call."""
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        hub = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn('value="dns"', hub)
        self.assertIn("Run 5 tools", hub)
        start = app.index("function initSuite()")
        body = app[start:app.index("/* ---------- Scan pipeline", start)]
        self.assertIn("dnsHost", body)
        self.assertIn("ensureDnsConsent", body)
        self.assertIn("apiDns", body)
        self.assertIn('"DNS & domain"', body)
        # The summary, worst-case verdict and stored digest include DNS.
        self.assertIn('["DNS & domain", s.dns]', app)
        self.assertIn('suiteToolChip("DNS", s.dns, true)', app)

    def test_dns_removed_from_soon_and_har_remains(self):
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        soon = app[app.index("const TOOLS_SOON"):app.index("];", app.index("const TOOLS_SOON"))]
        self.assertNotIn("DNS", soon)
        self.assertIn("HAR Security Analyzer", soon)

    def test_dns_engine_and_consent_gate_present(self):
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("function gradeDnsFromRecords", app)
        self.assertIn("async function apiDns", app)
        self.assertIn("function renderDnsRelayGate", app)
        self.assertIn("async function ensureDnsConsent", app)
        self.assertIn('"dns-relay"', app)
        self.assertIn("pushDomainParam", app)
        self.assertIn("initDomainInput", app)

    def test_dns_exports_are_wired(self):
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn('return "dns"', app)
        self.assertIn('"DNS & Domain Security Analyzer"', app)
        self.assertIn('title: "DNS & DOMAIN SECURITY"', app)

    def test_sitemap_lists_the_dns_tool_and_guide(self):
        sitemap = (ROOT / "sitemap.xml").read_text(encoding="utf-8")
        self.assertIn("/CyberBuddy/tools/dns/</loc>", sitemap)
        self.assertIn("/CyberBuddy/guides/dns/</loc>", sitemap)

    def test_manifest_has_a_dns_shortcut(self):
        manifest = json.loads((ROOT / "manifest.webmanifest").read_text(encoding="utf-8"))
        urls = [s.get("url", "") for s in manifest.get("shortcuts", [])]
        self.assertTrue(any("dns" in u for u in urls), urls)

    def test_llms_txt_describes_the_dns_tool_and_guide(self):
        text = (ROOT / "llms.txt").read_text(encoding="utf-8")
        self.assertIn("/tools/dns/", text)
        self.assertIn("/guides/dns/", text)

    def test_dns_api_route_is_served_by_server(self):
        src = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn('path == "/api/dns"', src)
        self.assertIn('qs.get("domain")', src)
        self.assertIn('"/dns": "/tools/dns/"', src)

    def test_hosted_dns_function_has_scanner_timeout_budget(self):
        config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(config["functions"]["api/dns.py"]["maxDuration"], 60)

    def test_pages_workflow_publishes_the_dns_tool(self):
        workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
        self.assertIn("tools/dns", workflow)


if __name__ == "__main__":
    unittest.main()
