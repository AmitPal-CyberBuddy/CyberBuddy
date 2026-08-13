#!/usr/bin/env python3
"""
Clickjacking Validator with performance optimizations.

Optimizations:
- DNS caching via http_session module
- HTTP connection pooling and SSL context reuse
- Faster URL validation using cached DNS lookups
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Iterable
from urllib.parse import urlparse

from http_session import dns_resolve, get_session_pool

USER_AGENT = "CyberBuddy/1.2 (+https://github.com/AmitPal-CyberBuddy/CyberBuddy)"

# Hostnames that are never legitimate VAPT targets for this tool.
METADATA_HOSTS = frozenset({
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
})

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_HTTP_RE = re.compile(r"^https?://", re.I)


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
        return asdict(self)


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty URL")
    # Reject javascript:, data:, file:, ftp:, etc. before we prepend https://
    if _SCHEME_RE.match(raw) and not _HTTP_RE.match(raw):
        raise ValueError(f"only http(s) URLs are allowed: {raw}")
    if not _HTTP_RE.match(raw):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc or not parsed.hostname:
        raise ValueError(f"invalid URL: {raw}")
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"only http(s) URLs are allowed: {raw}")
    return raw


def _ip_block_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool) -> str | None:
    if ip.version == 6 and getattr(ip, "ipv4_mapped", None):
        return _ip_block_reason(ip.ipv4_mapped, allow_private)  # type: ignore[arg-type]

    if ip.version == 4:
        if ip in ipaddress.ip_network("169.254.0.0/16"):
            return "link-local/metadata"
        if ip in ipaddress.ip_network("0.0.0.0/8"):
            return "unspecified"
        if ip in ipaddress.ip_network("224.0.0.0/4"):
            return "multicast"
        if ip == ipaddress.ip_address("255.255.255.255"):
            return "broadcast"
    else:
        if ip in ipaddress.ip_network("fe80::/10"):
            return "link-local"
        if ip in ipaddress.ip_network("ff00::/8"):
            return "multicast"
        if ip == ipaddress.ip_address("::"):
            return "unspecified"
        if ip == ipaddress.ip_address("fd00:ec2::254"):
            return "cloud metadata"

    if not allow_private:
        if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_link_local:
            return "private/loopback"
    return None


def _resolve_ips(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve hostname to IPs using cached DNS lookups."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    
    try:
        ips_str = dns_resolve(host)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve host: {host}") from exc
    
    return [ipaddress.ip_address(ip) for ip in ips_str]


def validate_target(url: str, allow_private: bool = True) -> None:
    """Raise ValueError if the URL is not a safe scan target.

    Always blocked: non-http(s), link-local, multicast, unspecified,
    cloud-metadata hostnames/IPs. RFC1918 / loopback are allowed when
    allow_private=True (CLI and localhost-bound server — the VAPT case).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http(s) URLs are allowed")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("invalid URL host")
    if host in METADATA_HOSTS or host.endswith(".metadata.google.internal"):
        raise ValueError(f"blocked scan target: {host}")
    for ip in _resolve_ips(host):
        reason = _ip_block_reason(ip, allow_private=allow_private)
        if reason:
            raise ValueError(f"blocked scan target ({reason}): {host} -> {ip}")


def headers_from_message(msg) -> dict[str, str]:
    """Flatten an email/http header map, preserving every Set-Cookie."""
    out: dict[str, str] = {}
    cookies: list[str] = []
    if msg is None:
        return out
    for key, value in msg.items():
        lk = key.lower()
        if lk == "set-cookie":
            cookies.append(value)
        else:
            out[lk] = value
    if cookies:
        out["set-cookie"] = "\n".join(cookies)
    return out


def fetch_headers(
    url: str,
    timeout: float,
    insecure: bool,
    allow_private: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, str, dict[str, str]]:
    """Fetch HTTP headers using the session pool for connection reuse."""
    validate_target(url, allow_private=allow_private)
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, method="GET", headers=headers)
    
    # Use session pool for opener reuse
    pool = get_session_pool()
    opener = pool.get_opener(insecure=insecure, allow_private=allow_private)
    
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.getcode(), resp.geturl(), headers_from_message(resp.headers)
    except urllib.error.HTTPError as exc:
        hdrs = headers_from_message(exc.headers) if exc.headers else {}
        return exc.code, exc.geturl() or url, hdrs


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


def cookie_flag_notes(set_cookie: str) -> list[str]:
    """Inspect each Set-Cookie by attribute token, not substring."""
    notes: list[str] = []
    for raw in set_cookie.split("\n"):
        raw = raw.strip()
        if not raw:
            continue
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip() or "cookie"
        attrs = [p.lower() for p in parts[1:]]
        flags = {a.split("=", 1)[0].strip() for a in attrs}
        samesite = ""
        for a in attrs:
            if a.startswith("samesite="):
                samesite = a.split("=", 1)[1].strip()
        missing: list[str] = []
        if "secure" not in flags:
            missing.append("Secure")
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "samesite" not in flags:
            missing.append("SameSite")
        elif samesite == "none" and "secure" not in flags:
            missing.append("SameSite=None requires Secure")
        if missing:
            notes.append(f"{name}: {', '.join(missing)} missing")
    return notes


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
    evidence = value[:250]
    if extra:
        evidence += "; " + ", ".join(extra)
    return Finding(
        name="Permissions-Policy",
        status="info",
        detail="Header present. Useful for feature lockdown, not a clickjacking primary control.",
        evidence=evidence,
    )


def assess_cookies(set_cookie: str | None) -> Finding:
    if not set_cookie:
        return Finding(
            name="Set-Cookie",
            status="info",
            detail="No Set-Cookie on this response. Session cookies should use SameSite and Secure.",
        )
    notes = cookie_flag_notes(set_cookie)
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
        detail=" ".join(notes) + ". Cookie flags complement, but do not replace, framing protections.",
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

    # frame-ancestors overrides X-Frame-Options in modern browsers — check
    # a permissive FA before treating XFO as sufficient.
    if csp_weak:
        return "high", "frame-ancestors is too permissive (e.g. *). Modern browsers honour CSP over X-Frame-Options, so the page can be framed by untrusted origins."
    if csp_ok:
        return "low", "Modern CSP frame-ancestors is in force. Residual risk is low for standard browsers."
    if xfo_ok:
        return (
            "medium",
            "Only X-Frame-Options protects the page. Add CSP frame-ancestors for modern, consistent coverage.",
        )
    return "high", "No effective framing protection detected. The page is likely clickjackable."


def scan_url(
    url: str,
    timeout: float,
    insecure: bool,
    allow_private: bool = True,
) -> ScanResult:
    try:
        url = normalize_url(url)
        validate_target(url, allow_private=allow_private)
    except ValueError as exc:
        return ScanResult(url=url, final_url=url, status_code=None, findings=[
            Finding(name="request", status="error", detail=str(exc))
        ], risk="unknown", summary=str(exc))

    try:
        code, final_url, headers = fetch_headers(
            url, timeout=timeout, insecure=insecure, allow_private=allow_private,
        )
    except Exception as exc:  # noqa: BLE001 — surface network errors to the user
        return ScanResult(
            url=url,
            final_url=url,
            status_code=None,
            findings=[Finding(name="request", status="error", detail=f"Request failed: {exc}")],
            risk="unknown",
            summary=f"Request failed: {exc}",
        )

    # Clickjacking is specifically about *framing*. Keep the findings table to
    # the two framing controls (X-Frame-Options + CSP frame-ancestors) rather
    # than mixing in Transport / cookies / Permissions-Policy, which belong to
    # the Security Headers tool.
    findings = [
        assess_xfo(headers.get("x-frame-options")),
        assess_frame_ancestors(headers.get("content-security-policy")),
    ]

    risk, summary = score(findings)
    interesting = {
        k: headers[k]
        for k in (
            "x-frame-options",
            "content-security-policy",
            "content-security-policy-report-only",
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
    p.add_argument(
        "--public-only",
        action="store_true",
        help="Refuse loopback / RFC1918 / link-local targets (default: allow private, block metadata).",
    )
    return p.parse_args(argv)


def collect_urls(args: argparse.Namespace) -> list[str]:
    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            urls.extend(line.strip() for line in fh if line.strip() and not line.lstrip().startswith("#"))
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

    allow_private = not args.public_only
    results = [
        scan_url(u, timeout=args.timeout, insecure=args.insecure, allow_private=allow_private)
        for u in urls
    ]
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            print_human(r)
        print()

    if any(r.risk == "high" for r in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
