#!/usr/bin/env python3
"""Stdlib unit tests for CyberBuddy engines. Run: python3 -m unittest test_engines.py"""

from __future__ import annotations

import http.client
import json
import os
import re
import shutil
import subprocess
import threading
import unittest
import urllib.request
from unittest.mock import patch
from urllib.parse import quote
from email.message import Message
from http.server import ThreadingHTTPServer

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
from cors_validator import ATTACKER_A, ATTACKER_B, scan_cors
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
from server import ROOT, TOOL_ALIASES, _under_root, default_bind, strip_mount


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


class OutcomeRollupTests(unittest.TestCase):
    def _cors_result(self, first_headers, second_headers):
        responses = [
            (200, "https://api.example.test/data", first_headers),
            (200, "https://api.example.test/data", second_headers),
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

    def test_reflection_outcomes_remain_medium_and_high(self):
        reflected_a = {"access-control-allow-origin": ATTACKER_A, "vary": "Origin"}
        reflected_b = {"access-control-allow-origin": ATTACKER_B, "vary": "Origin"}
        self.assertEqual(self._cors_result(reflected_a, reflected_b).risk, "medium")
        reflected_a["access-control-allow-credentials"] = "true"
        reflected_b["access-control-allow-credentials"] = "true"
        self.assertEqual(self._cors_result(reflected_a, reflected_b).risk, "high")

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
        for slug in ("clickjacking", "headers", "cors", "csp", "csrf", "jwt"):
            page = ROOT / "tools" / slug / "index.html"
            self.assertTrue(page.is_file(), page)
            text = page.read_text(encoding="utf-8")
            self.assertIn("js/app.js", text)
        # The JWT preview also loads its own (non-operational) controller.
        self.assertIn("js/tool.jwt.js", (ROOT / "tools" / "jwt" / "index.html").read_text(encoding="utf-8"))

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
        self.assertIn("headers|cors|csp|csrf|jwt", text)

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

    def test_single_origin_browser_cors_ignores_vary_as_headline_risk(self):
        result = self._run_app_js(r'''
console.log(JSON.stringify({
  fixedAllowlist: browserCorsRisk("https://trusted.example", "true"),
  wildcardCredentials: browserCorsRisk("*", "true"),
  wildcardPublic: browserCorsRisk("*", "")
}));
''')
        self.assertEqual(result["fixedAllowlist"], "low")
        self.assertEqual(result["wildcardCredentials"], "medium")
        self.assertEqual(result["wildcardPublic"], "low")

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


class ServerRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import server as srv
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def _req(self, path: str, method: str = "GET"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path)
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

    def test_six_tool_pages(self):
        expect = {
            "/tools/clickjacking/": b"Clickjacking Validator",
            "/tools/headers/": b"Security Headers",
            "/tools/cors/": b"CORS Validator",
            "/tools/csp/": b"CSP Policy Auditor",
            "/tools/csrf/": b"CSRF PoC Generator",
            # JWT-00: the development preview page resolves and is labelled.
            "/tools/jwt/": b"JWT Security Workbench",
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
        for path in ("/api/scan", "/api/headers", "/api/cors", "/api/csp"):
            status, _, body = self._req(path)
            self.assertEqual(status, 400, path)
            self.assertIn("url required", json.loads(body).get("error", ""))

    def test_unknown_path_serves_404_page(self):
        status, headers, body = self._req("/does-not-exist")
        self.assertEqual(status, 404)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn(b"404", body)

    def test_four_apis_scan_this_server(self):
        target = quote(f"http://127.0.0.1:{self.port}/", safe="")
        status, _, body = self._req("/api/headers?url=" + target)
        self.assertEqual(status, 200)
        headers_data = json.loads(body)
        self.assertIn("grade", headers_data)
        self.assertTrue(headers_data.get("checks"))
        status, _, body = self._req("/api/scan?url=" + target)
        self.assertEqual(status, 200)
        scan_data = json.loads(body)
        self.assertTrue(scan_data.get("findings"))
        status, _, body = self._req("/api/cors?url=" + target)
        self.assertEqual(status, 200)
        cors_data = json.loads(body)
        self.assertTrue(cors_data.get("checks"))
        status, _, body = self._req("/api/csp?url=" + target)
        self.assertEqual(status, 200)
        csp_data = json.loads(body)
        self.assertIn("policy", csp_data)
        self.assertTrue(csp_data.get("checks"))


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
            ROOT / "guides" / "jwt" / "index.html",
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

    def test_github_pages_first_tools_are_next_up(self):
        hub = (ROOT / "index.html").read_text(encoding="utf-8")
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        soon = app[app.index("const TOOLS_SOON"):app.index("];", app.index("const TOOLS_SOON"))]
        self.assertIn("Next on the bench: DNS &amp; Domain Security Analyzer", hub)
        self.assertIn("HAR Security Analyzer", hub)
        self.assertIn("DNS & Domain Security Analyzer", soon)
        self.assertIn("HAR Security Analyzer", soon)
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
        "index.html",
        "404.html",
        "methodology/index.html",
        "guides/index.html",
        "guides/clickjacking/index.html",
        "tools/index.html",
        "tools/clickjacking/index.html",
        "tools/headers/index.html",
        "tools/cors/index.html",
        "tools/csp/index.html",
        "tools/csrf/index.html",
        # JWT-00 preview: it is a non-framing, non-network page, so it
        # must carry the same strict meta CSP as every other tool page.
        "tools/jwt/index.html",
        "guides/jwt/index.html",
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
        # Four scan tools assess; local utilities are the CSRF PoC Generator
        # and the JWT Security Workbench (a development preview).
        self.assertEqual(app.count('category: "assess"'), 4)
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
        """The generator never joins the hub suite — that stays the four
        scan tools (apiScan / apiHeaders / apiCors / apiCsp)."""
        app = self._app()
        start = app.index("function initSuite()")
        body = app[start:app.index("/* ---------- Scan pipeline", start)]
        self.assertIn("apiScan", body)
        self.assertIn("apiCsp", body)
        self.assertNotIn("csrf", body.lower())

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
        dirs = sorted(p.name for p in (ROOT / "guides").iterdir() if p.is_dir())
        self.assertEqual(dirs, sorted(self.GUIDES))
        tools = sorted(p.name for p in (ROOT / "tools").iterdir() if p.is_dir())
        self.assertEqual(dirs, tools)

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
            text = re.sub(r"<[^>]+>", " ", self._guide(slug))
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
        """Only two Medium posts exist (request smuggling vs pipelining, and
        client-side encryption). Neither matches a guide topic, so pointing a
        guide's "Go deeper" at the profile root promises a write-up that is
        not there. A blog link belongs in a guide only when a post on that
        exact topic exists."""
        for name, page in self._pages():
            with self.subTest(page=name):
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

    def test_workflow_patch_carries_the_copy_line(self):
        """The arena token cannot push .github/workflows/**, so the one-line
        workflow edit is carried for the maintainer. Without it the directory
        is never copied into _site/ and the page 404s when hosted."""
        patch = (ROOT / "docs" / "pages-workflow-patch.md").read_text(encoding="utf-8")
        self.assertIn("cp -a documentation _site/", patch)


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

    def test_engine_rejects_alg_none_even_with_signature(self):
        # A token that declares alg:none must not verify.
        out = self._run_engine("""
const r = CyberBuddyJwt.tryParseToken('eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.');
console.log(JSON.stringify({ ok: r.ok, err: r.error }));
""")
        self.assertFalse(out["ok"])
        self.assertIn("none", out["err"].lower())

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
                    "jwtExpIss", "jwtExpAud", "jwtExpSub", "jwtSkew"):
            self.assertIn('id="%s"' % kid, page, kid)
        # The verify button is enabled (not a preview).
        self.assertNotIn('id="jwtVerify" disabled', page)

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
        self.assertIn("JWT-02 &middot; Live", block)

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
        self.assertIn("JWT-03 &middot; Live", block)
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
        """The guide reflects the current phase: after JWT-03 every panel is
        functional, so it must not describe any phase as a future preview."""
        guide = self.GUIDE.read_text(encoding="utf-8")
        self.assertIn("All three phases are live", guide)
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


class PagesExclusionTests(unittest.TestCase):
    """The published site must never carry repo-internal planning docs.

    docs/ROADMAP.md is the session roadmap; docs/DEV-NOTES.md is internal
    maintainer notes; REVIEW.md and tests/ are working artifacts. The Pages
    workflow copies only the public surface, and a regression guard (here,
    run by CI via `python3 -m unittest test_engines.py`) pins that the
    assemble step never copies them into _site/.

    Note: the arena push token is not granted the `workflows` permission, so
    the *catalog publish + leak-guard* workflow edit itself cannot be
    committed here — it is carried in docs/pages-workflow-patch.md for the
    maintainer to apply (the same mechanism as PR #20).
    """

    def test_roadmap_doc_exists(self):
        self.assertTrue((ROOT / "docs" / "ROADMAP.md").is_file())

    @staticmethod
    def _assemble_step_body() -> str:
        """Return just the `run:` body of the *Assemble static site* step.

        Scanning the whole workflow for internal-path tokens is wrong: the
        leak-guard step legitimately *names* docs/ROADMAP.md, docs/DEV-NOTES.md
        and REVIEW.md in order to reject them. Only the assemble step decides
        what gets copied, so only the assemble step is scanned here.
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
        """The assemble step must not reference docs/, tests/ or REVIEW.md
        as copy sources. This is the regression guard: CI runs it on every
        push, so a future commit that starts copying internal files into
        _site/ fails here."""
        text = self._assemble_step_body()
        for token in (
            "cp -a docs", "cp docs", "cp -r docs",
            "cp -a tests", "cp tests", "cp -r tests",
            "cp REVIEW.md", "cp -a REVIEW.md",
            "docs/ROADMAP.md", "docs/DEV-NOTES.md",
        ):
            self.assertNotIn(token, text, token)

    def test_workflow_guard_step_names_the_internal_files(self):
        """The leak guard itself must keep naming the internal files, which is
        exactly why the scan above is scoped to the assemble step."""
        text = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
        self.assertIn("Guard internal files stay out of the published site", text)
        guard = text.split("Guard internal files stay out of the published site", 1)[1]
        for name in ("docs/ROADMAP.md", "docs/DEV-NOTES.md", "REVIEW.md"):
            self.assertIn(name, guard, name)

    def test_patch_doc_documents_the_catalog_and_guard(self):
        """The workflow edit that cannot be pushed (catalog copy + internal
        -file guard) must stay recorded for the maintainer."""
        patch = (ROOT / "docs" / "pages-workflow-patch.md").read_text(encoding="utf-8")
        self.assertIn("cp tools/index.html _site/tools/", patch)
        self.assertIn("docs/ROADMAP.md", patch)
        self.assertIn("docs/DEV-NOTES.md", patch)
        self.assertIn("REVIEW.md", patch)

    def test_patch_doc_documents_the_guides_copy(self):
        """A new published top-level section must have its Pages fate decided
        in the same commit. guides/ cannot be added to pages.yml from here, so
        the copy line lives in the patch doc for the maintainer."""
        patch = (ROOT / "docs" / "pages-workflow-patch.md").read_text(encoding="utf-8")
        self.assertIn("cp -a guides _site/", patch)


if __name__ == "__main__":
    unittest.main()
