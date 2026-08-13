#!/usr/bin/env python3
"""
Clickjacking Validator
Checks framing protections on one or more URLs and reports residual risk.
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Iterable
from urllib.parse import urlparse


USER_AGENT = "Clickjacking-Validator/1.1 (+https://github.com/AmitPal-CyberBuddy/Clickjacking-Validator)"


@dataclass
class Finding:
    name: str
    status: str  # protected | weak | missing | info | error
    detail: str
    evidence: str = ""


@dataclass
class ScanResult:
    url: str
    final_url: str
    status_code: int | None
    findings: list[Finding] = field(default_factory=list)
    risk: str = "unknown"
    summary: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = asdict(self)
        return data


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty URL")
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError(f"invalid URL: {raw}")
    return raw


def fetch_headers(url: str, timeout: float, insecure: bool) -> tuple[int, str, dict[str, str]]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.getcode(), resp.geturl(), headers
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return exc.code, exc.geturl() or url, headers


def parse_csp(csp: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        directives[name] = [t.lower() for t in tokens[1:]]
    return directives


def assess_xfo(value: str | None) -> Finding:
    if not value:
        return Finding(
            name="X-Frame-Options",
            status="missing",
            detail="Header not present. Browsers may allow framing unless CSP frame-ancestors is set.",
        )
    raw = value.strip()
    token = raw.split(",")[0].strip().upper()
    if token == "DENY":
        return Finding(
            name="X-Frame-Options",
            status="protected",
            detail="DENY blocks framing from any origin, including the site itself.",
            evidence=raw,
        )
    if token == "SAMEORIGIN":
        return Finding(
            name="X-Frame-Options",
            status="protected",
            detail="SAMEORIGIN allows framing only by the same origin.",
            evidence=raw,
        )
    if token.startswith("ALLOW-FROM"):
        return Finding(
            name="X-Frame-Options",
            status="weak",
            detail="ALLOW-FROM is obsolete and ignored by modern browsers. Use CSP frame-ancestors.",
            evidence=raw,
        )
    return Finding(
        name="X-Frame-Options",
        status="weak",
        detail="Unrecognized X-Frame-Options value; treat as ineffective.",
        evidence=raw,
    )


def assess_frame_ancestors(csp_value: str | None) -> Finding:
    if not csp_value:
        return Finding(
            name="CSP frame-ancestors",
            status="missing",
            detail="No Content-Security-Policy header. frame-ancestors is the modern clickjacking control.",
        )
    directives = parse_csp(csp_value)
    # Report if only Report-Only is present (caller may pass that separately)
    if "frame-ancestors" not in directives:
        return Finding(
            name="CSP frame-ancestors",
            status="missing",
            detail="CSP is present but frame-ancestors is not set. Other CSP directives do not stop framing.",
            evidence=csp_value[:300],
        )
    sources = directives["frame-ancestors"]
    if not sources or sources == ["'none'"]:
        return Finding(
            name="CSP frame-ancestors",
            status="protected",
            detail="frame-ancestors 'none' forbids all framing (strongest modern control).",
            evidence="frame-ancestors " + " ".join(sources),
        )
    if sources == ["'self'"]:
        return Finding(
            name="CSP frame-ancestors",
            status="protected",
            detail="frame-ancestors 'self' allows only same-origin frames.",
            evidence="frame-ancestors " + " ".join(sources),
        )
    if "*" in sources:
        return Finding(
            name="CSP frame-ancestors",
            status="weak",
            detail="frame-ancestors * allows any origin to frame the page.",
            evidence="frame-ancestors " + " ".join(sources),
        )
    return Finding(
        name="CSP frame-ancestors",
        status="protected",
        detail="frame-ancestors allowlist is set. Confirm every listed origin is trusted.",
        evidence="frame-ancestors " + " ".join(sources),
    )


def assess_csp_report_only(value: str | None) -> Finding | None:
    if not value:
        return None
    directives = parse_csp(value)
    if "frame-ancestors" in directives:
        return Finding(
            name="CSP-Report-Only frame-ancestors",
            status="info",
            detail="frame-ancestors exists only on Content-Security-Policy-Report-Only and does not block framing.",
            evidence=value[:300],
        )
    return Finding(
        name="CSP-Report-Only",
        status="info",
        detail="Report-Only CSP is present but does not enforce framing restrictions.",
        evidence=value[:200],
    )


def assess_permissions_policy(value: str | None) -> Finding:
    if not value:
        return Finding(
            name="Permissions-Policy",
            status="info",
            detail="No Permissions-Policy header. Optional extra hardening (not a substitute for frame-ancestors).",
        )
    lower = value.lower()
    extra = []
    if "display-capture" in lower:
        extra.append("display-capture mentioned")
    return Finding(
        name="Permissions-Policy",
        status="info",
        detail="Header present. Useful for feature lockdown, not a clickjacking primary control.",
        evidence=value[:250] + (("; " + ", ".join(extra)) if extra else ""),
    )


def assess_cookies(set_cookie: str | None) -> Finding:
    if not set_cookie:
        return Finding(
            name="Set-Cookie",
            status="info",
            detail="No Set-Cookie on this response. Session cookies should use SameSite and Secure.",
        )
    parts = set_cookie.lower()
    notes = []
    if "samesite=none" in parts and "secure" not in parts:
        notes.append("SameSite=None without Secure is invalid in modern browsers.")
    if "samesite" not in parts:
        notes.append("SameSite not set (defaults vary; prefer Lax or Strict for session cookies).")
    if "secure" not in parts:
        notes.append("Secure flag missing.")
    if "httponly" not in parts:
        notes.append("HttpOnly missing (XSS impact, not clickjacking).")
    if not notes:
        return Finding(
            name="Set-Cookie",
            status="info",
            detail="Cookie flags look reasonable. SameSite does not stop clickjacking of logged-in UI.",
            evidence=set_cookie[:250],
        )
    return Finding(
        name="Set-Cookie",
        status="info",
        detail=" ".join(notes) + " Cookie flags complement, but do not replace, framing protections.",
        evidence=set_cookie[:250],
    )


def assess_https(url: str) -> Finding:
    if urlparse(url).scheme == "https":
        return Finding(
            name="Transport",
            status="info",
            detail="HTTPS in use. Framing headers must still be set on every sensitive response.",
        )
    return Finding(
        name="Transport",
        status="weak",
        detail="HTTP URL. Headers can be stripped or injected on the network. Prefer HTTPS.",
    )


def score(findings: Iterable[Finding]) -> tuple[str, str]:
    findings = list(findings)
    xfo = next((f for f in findings if f.name == "X-Frame-Options"), None)
    csp = next((f for f in findings if f.name == "CSP frame-ancestors"), None)

    xfo_ok = xfo is not None and xfo.status == "protected"
    csp_ok = csp is not None and csp.status == "protected"
    csp_weak = csp is not None and csp.status == "weak"

    if csp_ok:
        return "low", "Modern CSP frame-ancestors is in force. Residual risk is low for standard browsers."
    if xfo_ok and not csp_ok:
        return (
            "medium",
            "Only X-Frame-Options protects the page. Add CSP frame-ancestors for modern, consistent coverage.",
        )
    if csp_weak:
        return "high", "frame-ancestors is too permissive (e.g. *). The page can be framed by untrusted origins."
    return "high", "No effective framing protection detected. The page is likely clickjackable."


def scan_url(url: str, timeout: float, insecure: bool) -> ScanResult:
    try:
        url = normalize_url(url)
    except ValueError as exc:
        return ScanResult(url=url, final_url=url, status_code=None, findings=[
            Finding(name="request", status="error", detail=str(exc))
        ], risk="unknown", summary=str(exc))

    try:
        code, final_url, headers = fetch_headers(url, timeout=timeout, insecure=insecure)
    except Exception as exc:  # noqa: BLE001 — surface network errors to the user
        return ScanResult(
            url=url,
            final_url=url,
            status_code=None,
            findings=[Finding(name="request", status="error", detail=f"Request failed: {exc}")],
            risk="unknown",
            summary=f"Request failed: {exc}",
        )

    findings = [
        assess_https(final_url),
        assess_xfo(headers.get("x-frame-options")),
        assess_frame_ancestors(headers.get("content-security-policy")),
    ]
    ro = assess_csp_report_only(headers.get("content-security-policy-report-only"))
    if ro:
        findings.append(ro)
    findings.append(assess_permissions_policy(headers.get("permissions-policy") or headers.get("feature-policy")))
    findings.append(assess_cookies(headers.get("set-cookie")))

    risk, summary = score(findings)
    interesting = {
        k: headers[k]
        for k in (
            "x-frame-options",
            "content-security-policy",
            "content-security-policy-report-only",
            "permissions-policy",
            "feature-policy",
            "set-cookie",
            "strict-transport-security",
        )
        if k in headers
    }
    return ScanResult(
        url=url,
        final_url=final_url,
        status_code=code,
        findings=findings,
        risk=risk,
        summary=summary,
        headers=interesting,
    )


def print_human(result: ScanResult) -> None:
    print(f"\nTarget:      {result.url}")
    print(f"Final URL:   {result.final_url}")
    print(f"HTTP status: {result.status_code}")
    print(f"Risk:        {result.risk.upper()}")
    print(f"Summary:     {result.summary}")
    print("-" * 72)
    for f in result.findings:
        print(f"[{f.status.upper():9}] {f.name}: {f.detail}")
        if f.evidence:
            print(f"{'':13}evidence: {f.evidence}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Validate clickjacking (framing) protections on one or more URLs.",
    )
    p.add_argument("urls", nargs="*", help="Target URLs (https://example.com)")
    p.add_argument("-f", "--file", help="File with one URL per line")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--timeout", type=float, default=15.0, help="Request timeout in seconds")
    p.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    return p.parse_args(argv)


def collect_urls(args: argparse.Namespace) -> list[str]:
    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            urls.extend(line.strip() for line in fh if line.strip() and not line.lstrip().startswith("#"))
    # de-dupe, keep order
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    urls = collect_urls(args)
    if not urls:
        print("Provide at least one URL or --file.", file=sys.stderr)
        return 2

    results = [scan_url(u, timeout=args.timeout, insecure=args.insecure) for u in urls]
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            print_human(r)
        print()

    # exit 1 if any high risk (useful in CI)
    if any(r.risk == "high" for r in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

