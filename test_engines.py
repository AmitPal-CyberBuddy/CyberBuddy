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

    def test_tool_aliases_cover_all_four(self):
        self.assertEqual(TOOL_ALIASES["/headers"], "/tools/headers/")
        self.assertEqual(TOOL_ALIASES["/cors"], "/tools/cors/")
        self.assertEqual(TOOL_ALIASES["/csp"], "/tools/csp/")
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
        for slug in ("clickjacking", "headers", "cors", "csp"):
            page = ROOT / "tools" / slug / "index.html"
            self.assertTrue(page.is_file(), page)
            text = page.read_text(encoding="utf-8")
            self.assertIn("js/app.js", text)

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
        self.assertIn("headers|cors|csp", text)

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

    def test_four_tool_pages(self):
        expect = {
            "/tools/clickjacking/": b"Clickjacking Validator",
            "/tools/headers/": b"Security Headers",
            "/tools/cors/": b"CORS Validator",
            "/tools/csp/": b"CSP Policy Auditor",
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
            ("/csp", "/tools/csp/"),
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
        status, _, body = self._req("/CyberBuddy/tools/csp/")
        self.assertEqual(status, 200)
        self.assertIn(b"CSP Policy Auditor", body)

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
            ROOT / "tools" / "clickjacking" / "index.html",
            ROOT / "tools" / "headers" / "index.html",
            ROOT / "tools" / "cors" / "index.html",
            ROOT / "tools" / "csp" / "index.html",
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

    def test_upcoming_csrf_generator_is_visible(self):
        hub = (ROOT / "index.html").read_text(encoding="utf-8")
        app = (ROOT / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("Next on the bench: CSRF PoC Generator", hub)
        self.assertIn('"CSRF PoC Generator"', app)


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
        "tools/clickjacking/index.html",
        "tools/headers/index.html",
        "tools/cors/index.html",
        "tools/csp/index.html",
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
        """The evidence-card / PoC-image download builds a canvas blob."""
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
        # .overlay is the red decoy — it IS the clickjacking evidence.
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


if __name__ == "__main__":
    unittest.main()
