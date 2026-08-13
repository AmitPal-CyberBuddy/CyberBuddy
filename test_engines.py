#!/usr/bin/env python3
"""Stdlib unit tests for CyberBuddy engines. Run: python3 -m unittest test_engines.py"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess
import threading
import unittest
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

    def test_xfo_only_is_medium(self):
        findings = [
            assess_xfo("DENY"),
            assess_frame_ancestors(None),
        ]
        risk, _ = score(findings)
        self.assertEqual(risk, "medium")

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
        msg["X-Frame-Options"] = "DENY"
        hdrs = headers_from_message(msg)
        self.assertIn("a=1", hdrs["set-cookie"])
        self.assertIn("b=2", hdrs["set-cookie"])
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

    def test_tool_aliases_cover_all_three(self):
        self.assertEqual(TOOL_ALIASES["/headers"], "/tools/headers/")
        self.assertEqual(TOOL_ALIASES["/cors"], "/tools/cors/")
        self.assertEqual(TOOL_ALIASES["/clickjacking"], "/tools/clickjacking/")

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
        self.assertIn("lookupHeadersLive", src)
        self.assertIn("probeCorsLive", src)

    def test_tool_pages_exist(self):
        for slug in ("clickjacking", "headers", "cors"):
            page = ROOT / "tools" / slug / "index.html"
            self.assertTrue(page.is_file(), page)
            text = page.read_text(encoding="utf-8")
            self.assertIn("js/app.js", text)

    def test_four_oh_four_repairs_old_hosted_urls(self):
        text = (ROOT / "404.html").read_text(encoding="utf-8")
        self.assertIn("js\\/app\\.js", text)
        self.assertIn("/tools/$1/", text)

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

    def test_three_tool_pages(self):
        expect = {
            "/tools/clickjacking/": b"Clickjacking Validator",
            "/tools/headers/": b"Security Headers",
            "/tools/cors/": b"CORS Validator",
        }
        for path, needle in expect.items():
            status, headers, body = self._req(path)
            self.assertEqual(status, 200, path)
            self.assertIn(needle, body, path)
            self.assertIn("text/html", headers.get("content-type", ""))

    def test_tool_slash_redirect(self):
        status, headers, _ = self._req("/tools/headers")
        self.assertEqual(status, 301)
        self.assertEqual(headers.get("location"), "/tools/headers/")

    def test_short_aliases_redirect(self):
        for short, dest in (
            ("/headers", "/tools/headers/"),
            ("/cors", "/tools/cors/"),
            ("/clickjacking", "/tools/clickjacking/"),
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

    def test_static_assets(self):
        status, headers, body = self._req("/css/app.css")
        self.assertEqual(status, 200)
        self.assertIn("text/css", headers.get("content-type", ""))
        self.assertGreater(len(body), 100)
        status, headers, body = self._req("/js/app.js")
        self.assertEqual(status, 200)
        self.assertIn("javascript", headers.get("content-type", ""))
        self.assertIn(b"function appBase", body)

    def test_health_and_api_validation(self):
        status, headers, body = self._req("/api/health")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers.get("content-type", ""))
        self.assertTrue(json.loads(body).get("ok"))
        for path in ("/api/scan", "/api/headers", "/api/cors"):
            status, _, body = self._req(path)
            self.assertEqual(status, 400, path)
            self.assertIn("url required", json.loads(body).get("error", ""))

    def test_unknown_path_serves_404_page(self):
        status, headers, body = self._req("/does-not-exist")
        self.assertEqual(status, 404)
        self.assertIn("text/html", headers.get("content-type", ""))
        self.assertIn(b"404", body)

    def test_three_apis_scan_this_server(self):
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


if __name__ == "__main__":
    unittest.main()
