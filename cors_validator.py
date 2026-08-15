#!/usr/bin/env python3
"""
CyberBuddy — CORS posture probe with performance optimizations.

Sends two GETs with distinct Origin values so we can tell a reflected
ACAO from a fixed allowlist. Pure stdlib with connection pooling.

Optimizations:
- HTTP connection reuse via http_session module
- Efficient header validation
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field

from clickjacking_validator import fetch_headers, normalize_url, redact_userinfo, validate_target

ATTACKER_A = "https://evil.cyberbuddy.test"
ATTACKER_B = "https://probe.cyberbuddy.test"


@dataclass
class Check:
    name: str
    status: str  # ok | weak | missing | info | error
    detail: str
    evidence: str = ""


@dataclass
class CorsResult:
    url: str
    final_url: str
    status_code: int | None
    checks: list[Check] = field(default_factory=list)
    risk: str = "unknown"
    summary: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    origins_tested: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _acao(headers: dict[str, str]) -> str | None:
    value = headers.get("access-control-allow-origin")
    return value.strip() if value else None


def _acac(headers: dict[str, str]) -> bool:
    value = (headers.get("access-control-allow-credentials") or "").strip().lower()
    return value == "true"


def _vary(headers: dict[str, str]) -> str:
    return headers.get("vary") or ""


def scan_cors(
    url: str,
    timeout: float = 15.0,
    insecure: bool = False,
    allow_private: bool = True,
) -> CorsResult:
    safe_url = redact_userinfo(url)
    try:
        url = normalize_url(url)
        validate_target(url, allow_private=allow_private)
    except ValueError as exc:
        return CorsResult(
            url=safe_url, final_url=safe_url, status_code=None,
            checks=[Check("request", "error", str(exc))],
            risk="unknown", summary=str(exc),
        )

    try:
        code_a, final_a, hdr_a = fetch_headers(
            url, timeout=timeout, insecure=insecure, allow_private=allow_private,
            extra_headers={"Origin": ATTACKER_A},
        )
        _code_b, _final_b, hdr_b = fetch_headers(
            url, timeout=timeout, insecure=insecure, allow_private=allow_private,
            extra_headers={"Origin": ATTACKER_B},
        )
    except Exception as exc:  # noqa: BLE001
        return CorsResult(
            url=safe_url, final_url=safe_url, status_code=None,
            checks=[Check("request", "error", f"Request failed: {exc}")],
            risk="unknown", summary=f"Request failed: {exc}",
        )

    acao_a = _acao(hdr_a)
    acao_b = _acao(hdr_b)
    creds = _acac(hdr_a) or _acac(hdr_b)
    vary = _vary(hdr_a) or _vary(hdr_b)
    checks: list[Check] = []

    reflected = acao_a == ATTACKER_A and acao_b == ATTACKER_B
    wildcard = acao_a == "*" and acao_b == "*"
    both_absent = acao_a is None and acao_b is None

    if both_absent:
        checks.append(Check(
            "Access-Control-Allow-Origin", "ok",
            "No ACAO for either probe origin — cross-origin reads are blocked. Restrictive and safe.",
            evidence=f"Origin {ATTACKER_A} → (absent); Origin {ATTACKER_B} → (absent)",
        ))
    elif reflected:
        if creds:
            checks.append(Check(
                "Access-Control-Allow-Origin", "weak",
                "The server reflects arbitrary Origins AND allows credentials. A malicious site "
                "can read authenticated responses as the victim.",
                evidence=f"ACAO: {acao_a} / {acao_b}   ACAC: true",
            ))
        else:
            checks.append(Check(
                "Access-Control-Allow-Origin", "weak",
                "The server reflects arbitrary Origins (two distinct probe origins were echoed). "
                "Safe only for fully public data; dangerous if cookies are ever added.",
                evidence=f"ACAO: {acao_a} / {acao_b}",
            ))
    elif wildcard:
        if creds:
            checks.append(Check(
                "Access-Control-Allow-Origin", "weak",
                "Wildcard ACAO combined with Allow-Credentials: true. Browsers refuse this for "
                "credentialed requests, but the configuration is broken.",
                evidence="ACAO: *   ACAC: true",
            ))
        else:
            checks.append(Check(
                "Access-Control-Allow-Origin", "info",
                "Wildcard ACAO, no credentials. Any site can read this resource — acceptable "
                "only for fully public data.",
                evidence="ACAO: *",
            ))
    else:
        checks.append(Check(
            "Access-Control-Allow-Origin", "ok",
            "ACAO is not a per-request reflection of arbitrary origins. Treat this as a "
            "fixed allowlist (or no CORS for these probe origins).",
            evidence=f"Origin {ATTACKER_A} → {acao_a or '(absent)'}; Origin {ATTACKER_B} → {acao_b or '(absent)'}",
        ))

    if creds and not wildcard:
        checks.append(Check(
            "Allow-Credentials", "info",
            "Credentials explicitly allowed on at least one probe response.",
            evidence="ACAC: true",
        ))

    origin_specific = (acao_a not in (None, "*")) or (acao_b not in (None, "*"))
    if origin_specific and not re_origin_in_vary(vary):
        checks.append(Check(
            "Vary: Origin", "weak",
            "Origin-specific CORS headers without Vary: Origin. Shared caches / CDNs can "
            "serve one caller's ACAO to everyone.",
            evidence=f"Vary: {vary or '(absent)'}",
        ))
    elif re_origin_in_vary(vary):
        checks.append(Check(
            "Vary: Origin", "ok",
            "Vary: Origin present — cached responses will be partitioned by caller origin.",
            evidence=f"Vary: {vary}",
        ))
    elif not both_absent:
        checks.append(Check(
            "Vary: Origin", "info",
            "No origin-specific ACAO observed; Vary: Origin is still recommended.",
            evidence=f"Vary: {vary or '(absent)'}",
        ))

    # Headline risk follows the observed access outcome, not a secondary
    # cache-hardening finding. A fixed ACAO without Vary: Origin still needs
    # remediation, but two different attacker Origins were *not* reflected;
    # that recommendation must not turn a restrictive result into MEDIUM.
    if reflected and creds:
        risk = "high"
        summary = "Arbitrary Origin reflection with credentials was confirmed across two probe Origins."
    elif reflected:
        risk = "medium"
        summary = "Arbitrary Origin reflection was confirmed across two probe Origins. Safe only for intentionally public data."
    elif wildcard:
        risk = "medium" if creds else "low"
        summary = (
            "Wildcard ACAO with credentials is misconfigured (browsers reject credentialed wildcard reads)."
            if creds else
            "Wildcard ACAO allows unauthenticated cross-origin reads. Confirm this resource is intentionally public."
        )
    elif both_absent:
        risk = "low"
        summary = "No CORS headers found for the probe origins. Cross-origin reads are blocked by default (Pass)."
    else:
        risk = "low"
        summary = "No arbitrary-origin reflection detected across two probe Origins. Review any cache-hardening recommendation separately."

    interesting = {}
    for key in (
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "vary",
    ):
        if key in hdr_a:
            interesting[key] = hdr_a[key]
        elif key in hdr_b:
            interesting[key] = hdr_b[key]

    return CorsResult(
        url=url,
        final_url=final_a,
        status_code=code_a,
        checks=checks,
        risk=risk,
        summary=summary,
        headers=interesting,
        origins_tested=[ATTACKER_A, ATTACKER_B],
    )


def re_origin_in_vary(vary: str) -> bool:
    return any(part.strip().lower() == "origin" for part in vary.split(",")) if vary else False


def print_human(result: CorsResult) -> None:
    print(f"\nTarget:      {result.url}")
    print(f"Final URL:   {result.final_url}")
    print(f"HTTP status: {result.status_code}")
    print(f"Risk:        {result.risk.upper()}")
    print(f"Summary:     {result.summary}")
    if result.origins_tested:
        print(f"Origins:     {', '.join(result.origins_tested)}")
    print("-" * 72)
    for c in result.checks:
        print(f"[{c.status.upper():7}] {c.name}: {c.detail}")
        if c.evidence:
            print(f"{'':10}evidence: {c.evidence}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Probe CORS origin-reflection and credential posture on one or more URLs.",
    )
    p.add_argument("urls", nargs="*", help="Target URLs (https://example.com/api)")
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
        scan_cors(u, timeout=args.timeout, insecure=args.insecure, allow_private=allow_private)
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
