#!/usr/bin/env python3
"""
Security Headers Checker with performance optimizations.

Optimizations:
- HTTP connection pooling via http_session module
- Efficient header parsing and validation
- Reduced memory footprint
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

from clickjacking_validator import (
    cookie_flag_notes,
    fetch_headers,
    normalize_url,
    parse_csp,
    validate_target,
)

# Score weights. 100 is a perfect baseline; each finding deducts.
WEIGHTS = {
    "Content-Security-Policy": 25,
    "X-Frame-Options": 15,
    "Strict-Transport-Security": 15,
    "X-Content-Type-Options": 10,
    "Referrer-Policy": 10,
    "Permissions-Policy": 5,
    "Cross-Origin-Opener-Policy": 5,
    "Cross-Origin-Embedder-Policy": 5,
    "Cross-Origin-Resource-Policy": 5,
}

# If CSP frame-ancestors already blocks framing, a missing X-Frame-Options
# is a smaller deal (modern browsers honor CSP first).
XFO_MISSING_WITH_CSP_DEDUCTION = 5


@dataclass
class Check:
    name: str
    status: str  # ok | weak | missing | info | error
    detail: str
    evidence: str = ""
    deduction: int = 0


@dataclass
class HeadersResult:
    url: str
    final_url: str
    status_code: int | None
    checks: list[Check] = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    risk: str = "unknown"
    summary: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def check_transport(url: str) -> Check:
    if urlparse(url).scheme == "https":
        return Check(
            "Transport", "ok", "HTTPS in use — headers cannot be stripped on the wire.",
            deduction=0,
        )
    return Check(
        "Transport", "weak",
        "HTTP URL. Response headers can be stripped or injected on the network. Prefer HTTPS.",
        evidence=url, deduction=5,
    )


def _src_issues(name: str, tokens: list[str]) -> list[tuple[str, int]]:
    issues: list[tuple[str, int]] = []
    if "*" in tokens:
        issues.append((f"{name} allows * (any origin can load this type)", 15))
    if "'unsafe-inline'" in tokens:
        issues.append((f"{name} allows 'unsafe-inline' (weakens XSS protections)", 15))
    if "'unsafe-eval'" in tokens:
        issues.append((f"{name} allows 'unsafe-eval'", 10))
    if any(t == "data:" or t.startswith("data:") for t in tokens):
        issues.append((f"{name} allows data: URIs", 10))
    if "http:" in tokens:
        issues.append((f"{name} allows http: (mixed content)", 10))
    return issues


def check_csp(value: str | None) -> Check:
    if not value:
        return Check(
            "Content-Security-Policy", "missing",
            "Header not present. CSP is the modern defense-in-depth header: restrict "
            "script sources, block mixed content, and set frame-ancestors.",
            deduction=WEIGHTS["Content-Security-Policy"],
        )
    directives = parse_csp(value)
    notes: list[str] = []
    deduction = 0

    has_script = "script-src" in directives or "script-src-elem" in directives
    has_default = "default-src" in directives
    if not has_script and not has_default:
        notes.append("no script-src or default-src (scripts are unrestricted)")
        deduction = max(deduction, 15)

    # script-src overrides default-src for scripts; only score the effective one.
    if "script-src" in directives:
        for msg, ded in _src_issues("script-src", directives["script-src"]):
            notes.append(msg)
            deduction = max(deduction, ded)
        if "script-src-elem" in directives:
            for msg, ded in _src_issues("script-src-elem", directives["script-src-elem"]):
                notes.append(msg)
                deduction = max(deduction, ded)
    elif "script-src-elem" in directives:
        for msg, ded in _src_issues("script-src-elem", directives["script-src-elem"]):
            notes.append(msg)
            deduction = max(deduction, ded)
    elif has_default:
        for msg, ded in _src_issues("default-src", directives["default-src"]):
            notes.append(msg)
            deduction = max(deduction, ded)

    if notes:
        return Check(
            "Content-Security-Policy", "weak",
            "Header present but " + "; ".join(notes) + ".",
            evidence=value[:300], deduction=deduction,
        )
    detail = "Header present with no obvious weak directives."
    if "frame-ancestors" in directives:
        detail += " Includes frame-ancestors (clickjacking control)."
    return Check(
        "Content-Security-Policy", "ok",
        detail,
        evidence=value[:300], deduction=0,
    )


def frame_ancestors_restricts(csp_value: str | None) -> bool:
    """True when CSP frame-ancestors is present and not a wildcard."""
    if not csp_value:
        return False
    sources = parse_csp(csp_value).get("frame-ancestors")
    if sources is None:
        return False
    return "*" not in sources


def check_xfo(value: str | None, frame_ancestors_ok: bool) -> Check:
    if not value:
        ded = XFO_MISSING_WITH_CSP_DEDUCTION if frame_ancestors_ok else WEIGHTS["X-Frame-Options"]
        note = (
            "CSP frame-ancestors covers framing; X-Frame-Options is optional when present."
            if frame_ancestors_ok else
            "Browsers may allow framing unless CSP frame-ancestors is also set."
        )
        return Check("X-Frame-Options", "missing", f"Header not present. {note}", deduction=ded)
    token = value.strip().split(",")[0].strip().upper()
    if token in ("DENY", "SAMEORIGIN"):
        return Check(
            "X-Frame-Options", "ok",
            f"{token} blocks cross-origin framing.",
            evidence=value.strip(), deduction=0,
        )
    if token.startswith("ALLOW-FROM"):
        return Check(
            "X-Frame-Options", "weak",
            "ALLOW-FROM is obsolete and ignored by modern browsers. Use CSP frame-ancestors.",
            evidence=value.strip(), deduction=WEIGHTS["X-Frame-Options"],
        )
    return Check(
        "X-Frame-Options", "weak",
        "Unrecognized value; treat as ineffective.",
        evidence=value.strip(), deduction=WEIGHTS["X-Frame-Options"],
    )


def check_hsts(value: str | None, is_https: bool) -> Check:
    if not is_https:
        return Check(
            "Strict-Transport-Security", "info",
            "Only meaningful over HTTPS — no HSTS check on an HTTP target.",
            deduction=0,
        )
    if not value:
        return Check(
            "Strict-Transport-Security", "missing",
            "Header not present. HSTS forces HTTPS and prevents SSL-stripping for returning visitors.",
            deduction=WEIGHTS["Strict-Transport-Security"],
        )
    m = re.search(r"max-age=(\d+)", value, re.I)
    max_age = int(m.group(1)) if m else 0
    if max_age == 0:
        return Check(
            "Strict-Transport-Security", "missing",
            "max-age=0 disables HSTS (browsers forget the policy). This is not a protection.",
            evidence=value.strip(), deduction=WEIGHTS["Strict-Transport-Security"],
        )
    if max_age < 180 * 86400:
        return Check(
            "Strict-Transport-Security", "weak",
            f"max-age={max_age}s is short; browsers need ≥ 15552000s (180 days) for meaningful protection.",
            evidence=value.strip(), deduction=5,
        )
    if "includesubdomains" not in value.lower():
        return Check(
            "Strict-Transport-Security", "weak",
            "Max-age is fine but includeSubDomains is missing.",
            evidence=value.strip(), deduction=5,
        )
    return Check(
        "Strict-Transport-Security", "ok",
        "HSTS present with a strong max-age (and includeSubDomains).",
        evidence=value.strip(), deduction=0,
    )


def check_nosniff(value: str | None) -> Check:
    if not value:
        return Check(
            "X-Content-Type-Options", "missing",
            "Header not present. Set 'nosniff' to stop MIME-sniffing attacks.",
            deduction=WEIGHTS["X-Content-Type-Options"],
        )
    if value.strip().lower() == "nosniff":
        return Check(
            "X-Content-Type-Options", "ok",
            "nosniff set — browsers will not MIME-sniff responses.",
            evidence=value.strip(), deduction=0,
        )
    return Check(
        "X-Content-Type-Options", "weak",
        "Only 'nosniff' is meaningful.",
        evidence=value.strip(), deduction=WEIGHTS["X-Content-Type-Options"],
    )


REFERRER_OK = {
    "no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin",
    "origin", "origin-when-cross-origin",
}


def check_referrer(value: str | None) -> Check:
    if not value:
        return Check(
            "Referrer-Policy", "missing",
            "Header not present. Browsers fall back to 'strict-origin-when-cross-origin', "
            "but an explicit policy is clearer and more consistent.",
            deduction=WEIGHTS["Referrer-Policy"],
        )
    token = value.strip().split(",")[0].strip().lower()
    if token in REFERRER_OK:
        return Check(
            "Referrer-Policy", "ok",
            f"{token} — referrer leakage is limited.",
            evidence=value.strip(), deduction=0,
        )
    if token in ("unsafe-url", "no-referrer-when-downgrade"):
        return Check(
            "Referrer-Policy", "weak",
            f"'{token}' can leak full URLs (including query strings) to other origins.",
            evidence=value.strip(), deduction=WEIGHTS["Referrer-Policy"],
        )
    return Check(
        "Referrer-Policy", "weak",
        "Unrecognized policy value.",
        evidence=value.strip(), deduction=5,
    )


def check_permissions(value: str | None) -> Check:
    if not value:
        return Check(
            "Permissions-Policy", "missing",
            "Header not present. Recommended for locking down powerful features "
            "(camera, microphone, geolocation). Optional hardening.",
            deduction=WEIGHTS["Permissions-Policy"],
        )
    wildcarded = []
    for tok in value.split(","):
        if "=" not in tok:
            continue
        feature, allow = tok.split("=", 1)
        allow = allow.strip().lower()
        if allow in ("*", "(*)"):
            wildcarded.append(feature.strip())
    if wildcarded:
        return Check(
            "Permissions-Policy", "weak",
            "Feature(s) allowlisted as bare wildcard: "
            + ", ".join(wildcarded)
            + ". Restrict them to 'self' or an origin allowlist.",
            evidence=value[:300], deduction=5,
        )
    return Check(
        "Permissions-Policy", "ok",
        "Header present.",
        evidence=value[:300], deduction=0,
    )


def check_coop(value: str | None) -> Check:
    if not value:
        return Check(
            "Cross-Origin-Opener-Policy", "missing",
            "Header not present. 'same-origin' isolates the browsing context from "
            "cross-origin popups (mitigates some Spectre-era attacks).",
            deduction=WEIGHTS["Cross-Origin-Opener-Policy"],
        )
    token = value.strip().split(";")[0].strip().lower()
    if token in ("same-origin", "same-origin-allow-popups"):
        return Check(
            "Cross-Origin-Opener-Policy", "ok",
            f"{token} — cross-origin popup isolation active.",
            evidence=value.strip(), deduction=0,
        )
    return Check(
        "Cross-Origin-Opener-Policy", "weak",
        "'unsafe-none' provides no cross-origin isolation.",
        evidence=value.strip(), deduction=WEIGHTS["Cross-Origin-Opener-Policy"],
    )


def check_coep(value: str | None) -> Check:
    if not value:
        return Check(
            "Cross-Origin-Embedder-Policy", "missing",
            "Header not present. 'require-corp' forces CORP/CORS on all subresources "
            "(needed for cross-origin isolation).",
            deduction=WEIGHTS["Cross-Origin-Embedder-Policy"],
        )
    token = value.strip().split(";")[0].strip().lower()
    if token == "require-corp":
        return Check(
            "Cross-Origin-Embedder-Policy", "ok",
            "require-corp — subresources must opt in via CORP or CORS.",
            evidence=value.strip(), deduction=0,
        )
    if token == "credentialless":
        return Check(
            "Cross-Origin-Embedder-Policy", "ok",
            "credentialless — cross-origin subresources load without credentials.",
            evidence=value.strip(), deduction=0,
        )
    return Check(
        "Cross-Origin-Embedder-Policy", "weak",
        "'unsafe-none' does not restrict cross-origin subresources.",
        evidence=value.strip(), deduction=WEIGHTS["Cross-Origin-Embedder-Policy"],
    )


def check_corp(value: str | None) -> Check:
    if not value:
        return Check(
            "Cross-Origin-Resource-Policy", "missing",
            "Header not present. Restricts which origins may load this resource "
            "('same-origin' / 'same-site' / 'cross-origin').",
            deduction=WEIGHTS["Cross-Origin-Resource-Policy"],
        )
    token = value.strip().lower()
    if token in ("same-origin", "same-site", "cross-origin"):
        return Check(
            "Cross-Origin-Resource-Policy", "ok",
            f"{token} — resource loading policy explicit.",
            evidence=value.strip(), deduction=0,
        )
    return Check(
        "Cross-Origin-Resource-Policy", "weak",
        "Unrecognized value.",
        evidence=value.strip(), deduction=5,
    )


def check_csp_report_only(value: str | None) -> Check | None:
    if not value:
        return None
    return Check(
        "CSP-Report-Only", "info",
        "Report-Only CSP is present and does not enforce anything — it only reports violations.",
        evidence=value[:300], deduction=0,
    )


def check_cookies(value: str | None) -> Check | None:
    if not value:
        return None
    notes = cookie_flag_notes(value)
    if notes:
        return Check(
            "Set-Cookie flags", "weak",
            "; ".join(notes) + ".",
            evidence=value[:250], deduction=5,
        )
    return Check(
        "Set-Cookie flags", "ok",
        "Secure, HttpOnly and SameSite are set on the response cookies.",
        evidence=value[:250], deduction=0,
    )


def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"


def risk_for(grade: str) -> str:
    return {"A": "low", "B": "low", "C": "medium", "D": "medium", "F": "high"}[grade]


def summarize(grade: str, missing: list[str]) -> str:
    extra = ""
    if missing and grade != "A":
        preview = ", ".join(missing[:4])
        extra = f" Missing: {preview}" + ("…" if len(missing) > 4 else "") + "."
    if grade == "A":
        return "Strong header posture. Keep it this way — and re-test after any deployment change."
    if grade == "B":
        return "Good posture with a few gaps. Close them for a bulletproof baseline." + extra
    if grade == "C":
        return "Notable gaps — attackers get signal here. Prioritize the missing headers." + extra
    if grade == "D":
        return "Weak posture. Multiple important headers missing or misconfigured." + extra
    return "Critical posture. Key protections are absent — treat the site as exposed until fixed." + extra


def scan_headers(
    url: str,
    timeout: float = 15.0,
    insecure: bool = False,
    allow_private: bool = True,
) -> HeadersResult:
    try:
        url = normalize_url(url)
        validate_target(url, allow_private=allow_private)
    except ValueError as exc:
        return HeadersResult(
            url=url, final_url=url, status_code=None,
            checks=[Check("request", "error", str(exc))],
            grade="F", risk="unknown", summary=str(exc),
        )

    try:
        code, final_url, headers = fetch_headers(
            url, timeout=timeout, insecure=insecure, allow_private=allow_private,
        )
    except Exception as exc:  # noqa: BLE001 — surface network errors
        return HeadersResult(
            url=url, final_url=url, status_code=None,
            checks=[Check("request", "error", f"Request failed: {exc}")],
            grade="F", risk="unknown", summary=f"Request failed: {exc}",
        )

    is_https = urlparse(final_url).scheme == "https"
    csp_value = headers.get("content-security-policy")
    fa_ok = frame_ancestors_restricts(csp_value)

    checks: list[Check] = [
        check_transport(final_url),
        check_csp(csp_value),
        check_xfo(headers.get("x-frame-options"), fa_ok),
        check_hsts(headers.get("strict-transport-security"), is_https),
        check_nosniff(headers.get("x-content-type-options")),
        check_referrer(headers.get("referrer-policy")),
        check_permissions(headers.get("permissions-policy") or headers.get("feature-policy")),
        check_coop(headers.get("cross-origin-opener-policy")),
        check_coep(headers.get("cross-origin-embedder-policy")),
        check_corp(headers.get("cross-origin-resource-policy")),
    ]
    ro = check_csp_report_only(headers.get("content-security-policy-report-only"))
    if ro:
        checks.append(ro)
    cookie_check = check_cookies(headers.get("set-cookie"))
    if cookie_check:
        checks.append(cookie_check)

    score = max(0, 100 - sum(c.deduction for c in checks))
    grade = grade_for(score)
    missing = [c.name for c in checks if c.status == "missing"]

    interesting = {
        k: headers[k]
        for k in (
            "content-security-policy",
            "content-security-policy-report-only",
            "x-frame-options",
            "strict-transport-security",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "feature-policy",
            "cross-origin-opener-policy",
            "cross-origin-embedder-policy",
            "cross-origin-resource-policy",
            "set-cookie",
        )
        if k in headers
    }
    return HeadersResult(
        url=url,
        final_url=final_url,
        status_code=code,
        checks=checks,
        score=score,
        grade=grade,
        risk=risk_for(grade),
        summary=summarize(grade, missing),
        headers=interesting,
    )


def print_human(result: HeadersResult) -> None:
    print(f"\nTarget:      {result.url}")
    print(f"Final URL:   {result.final_url}")
    print(f"HTTP status: {result.status_code}")
    print(f"Score:       {result.score}/100  Grade: {result.grade}  Risk: {result.risk.upper()}")
    print("-" * 72)
    for c in result.checks:
        print(f"[{c.status.upper():7}] {c.name}: {c.detail}")
        if c.evidence:
            print(f"{'':10}evidence: {c.evidence}")
    print(f"Summary: {result.summary}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Grade the security headers of one or more URLs.",
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
        scan_headers(u, timeout=args.timeout, insecure=args.insecure, allow_private=allow_private)
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
