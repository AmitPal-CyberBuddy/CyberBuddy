#!/usr/bin/env python3
"""Content-Security-Policy auditor for CyberBuddy.

The engine is deliberately stdlib-only and can grade an already-fetched header
map.  ``server.py``/the CLI use it directly; ``js/app.js`` contains the browser
port used by GitHub Pages when no Python engine is available.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

from clickjacking_validator import fetch_headers, normalize_url, redact_userinfo, validate_target


SUGGESTED_POLICY = (
    "default-src 'self'; "
    "base-uri 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "upgrade-insecure-requests"
)


@dataclass
class CspCheck:
    name: str
    status: str  # ok | weak | missing | info | error
    detail: str
    evidence: str = ""
    severity: str = "info"  # pass | low | medium | high | info
    recommendation: str = ""


@dataclass
class CspResult:
    url: str
    final_url: str
    status_code: int | None
    checks: list[CspCheck] = field(default_factory=list)
    risk: str = "unknown"
    summary: str = ""
    policy: str = ""
    report_only_policy: str = ""
    directives: dict[str, list[str]] = field(default_factory=dict)
    suggested_policy: str = SUGGESTED_POLICY
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def split_policies(value: str | None) -> list[str]:
    """Return separately delivered policies preserved by the HTTP collector.

    ``headers_from_message`` joins repeated CSP fields with newlines. Multiple
    enforced policies are conjunctive in browsers, so retaining the boundary
    matters; treating the last field as the whole policy can create a false
    positive.
    """
    return [line.strip() for line in (value or "").splitlines() if line.strip()]


def parse_policy(value: str) -> tuple[dict[str, list[str]], list[str]]:
    """Parse one serialized policy, keeping the first duplicate directive.

    CSP requires browsers to ignore later duplicates in the same policy. This
    differs intentionally from the older generic parser, which is retained for
    backwards-compatible Security Headers scoring.
    """
    directives: dict[str, list[str]] = {}
    duplicates: list[str] = []
    for raw in value.split(";"):
        raw = raw.strip()
        if not raw:
            continue
        tokens = raw.split()
        name = tokens[0].lower()
        if name in directives:
            duplicates.append(name)
            continue
        directives[name] = [token.lower() for token in tokens[1:]]
    return directives, duplicates


def _effective(
    directives: dict[str, list[str]],
    name: str,
    *fallbacks: str,
) -> tuple[list[str] | None, str]:
    for candidate in (name, *fallbacks):
        if candidate in directives:
            return directives[candidate], candidate
    return None, ""


def _is_nonce_or_hash(token: str) -> bool:
    return token.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))


def _source_label(name: str, tokens: list[str] | None) -> str:
    if tokens is None:
        return "not set"
    return name + (" " + " ".join(tokens) if tokens else " (empty source list)")


def _issue_check(
    name: str,
    issues: list[tuple[str, str]],
    evidence: str,
    recommendation: str,
    ok_detail: str,
    info: list[str] | None = None,
) -> CspCheck:
    if issues:
        level = max((severity for _, severity in issues), key={"low": 1, "medium": 2, "high": 3}.get)
        return CspCheck(
            name,
            "weak",
            "; ".join(message for message, _ in issues) + ".",
            evidence=evidence,
            severity=level,
            recommendation=recommendation,
        )
    if info:
        return CspCheck(
            name,
            "info",
            ok_detail + " " + " ".join(info),
            evidence=evidence,
            severity="info",
        )
    return CspCheck(name, "ok", ok_detail, evidence=evidence, severity="pass")


def _check_scripts(directives: dict[str, list[str]]) -> CspCheck:
    element, element_from = _effective(directives, "script-src-elem", "script-src", "default-src")
    evaluation, eval_from = _effective(directives, "script-src", "default-src")
    attributes, attr_from = _effective(directives, "script-src-attr", "script-src", "default-src")
    recommendation = (
        "Restrict script-src to trusted hosts or, preferably, per-response nonces/hashes. "
        "Remove wildcards, data:, 'unsafe-eval', and unprotected 'unsafe-inline'."
    )
    if element is None:
        return CspCheck(
            "Script execution",
            "missing",
            "No script-src, script-src-elem, or default-src fallback; script loading is unrestricted.",
            severity="high",
            recommendation=recommendation,
        )

    issues: list[tuple[str, str]] = []
    info: list[str] = []
    trust_tokens = set(element or [])
    has_trust_anchor = any(_is_nonce_or_hash(token) for token in trust_tokens)

    if "*" in trust_tokens:
        issues.append(("the effective script source allows * (any matching origin)", "high"))
    if "data:" in trust_tokens:
        issues.append(("the effective script source allows data: scripts", "high"))
    if "http:" in trust_tokens or any(token.startswith("http://") for token in trust_tokens):
        issues.append(("the effective script source allows cleartext HTTP", "high"))
    if "https:" in trust_tokens:
        issues.append(("the effective script source allows scripts from any HTTPS origin", "medium"))
    if any(token.startswith("*.") or "://*." in token for token in trust_tokens):
        issues.append(("the effective script source trusts a wildcard subdomain", "medium"))
    elif any("://*" in token for token in trust_tokens):
        issues.append(("the effective script source trusts a wildcard host", "medium"))

    if "'unsafe-inline'" in trust_tokens:
        if has_trust_anchor:
            info.append("'unsafe-inline' is ignored by modern nonce/hash-aware browsers and acts only as a legacy fallback.")
        else:
            issues.append(("'unsafe-inline' permits inline script execution", "high"))

    eval_tokens = set(evaluation or [])
    if "'unsafe-eval'" in eval_tokens:
        issues.append(("'unsafe-eval' permits string-to-code execution", "high"))
    if "'wasm-unsafe-eval'" in eval_tokens:
        issues.append(("'wasm-unsafe-eval' permits WebAssembly compilation from bytes", "medium"))

    attr_tokens = set(attributes or [])
    if attr_from == "script-src-attr" and "'unsafe-inline'" in attr_tokens:
        issues.append(("script-src-attr 'unsafe-inline' permits inline event handlers", "high"))

    if "'strict-dynamic'" in trust_tokens and not has_trust_anchor:
        issues.append(("'strict-dynamic' has no nonce or hash trust anchor", "medium"))
    if "'none'" in trust_tokens and len(trust_tokens) > 1:
        issues.append(("'none' is mixed with other script sources and is ignored", "medium"))

    evidence_parts = [_source_label(element_from, element)]
    if eval_from and eval_from != element_from:
        evidence_parts.append(_source_label(eval_from, evaluation))
    if attr_from and attr_from not in {element_from, eval_from}:
        evidence_parts.append(_source_label(attr_from, attributes))
    return _issue_check(
        "Script execution",
        issues,
        " · ".join(evidence_parts),
        recommendation,
        "Script execution has an explicit restrictive source list.",
        info,
    )


def _check_object(directives: dict[str, list[str]]) -> CspCheck:
    tokens, inherited = _effective(directives, "object-src", "default-src")
    recommendation = "Set object-src 'none' to disable legacy plugin/object embedding."
    if tokens is None:
        return CspCheck(
            "Object embedding", "missing",
            "No object-src or default-src fallback; object/embed content is unrestricted.",
            severity="medium", recommendation=recommendation,
        )
    evidence = _source_label(inherited, tokens)
    if not tokens or tokens == ["'none'"]:
        return CspCheck(
            "Object embedding", "ok", "Object/embed loading is blocked.",
            evidence=evidence, severity="pass",
        )
    return CspCheck(
        "Object embedding", "weak",
        "Object/embed content is still allowed. CSP hardening guidance recommends blocking it.",
        evidence=evidence, severity="medium", recommendation=recommendation,
    )


def _check_navigation_directive(
    directives: dict[str, list[str]],
    name: str,
    label: str,
    missing_severity: str,
    recommendation: str,
) -> CspCheck:
    tokens = directives.get(name)
    if tokens is None:
        return CspCheck(
            label, "missing",
            f"{name} is absent and is not inherited from default-src.",
            severity=missing_severity, recommendation=recommendation,
        )
    evidence = _source_label(name, tokens)
    if not tokens or tokens == ["'none'"] or tokens == ["'self'"]:
        return CspCheck(
            label, "ok", f"{name} uses a restrictive source list.",
            evidence=evidence, severity="pass",
        )
    issues: list[tuple[str, str]] = []
    if "*" in tokens:
        issues.append((f"{name} allows *", "high" if name == "frame-ancestors" else "medium"))
    if any(token in {"http:", "https:"} for token in tokens):
        issues.append((f"{name} allows every origin on a URL scheme", "medium"))
    if "'none'" in tokens and len(tokens) > 1:
        issues.append((f"{name} mixes 'none' with other sources, so 'none' is ignored", "medium"))
    if issues:
        return _issue_check(label, issues, evidence, recommendation, "")
    return CspCheck(
        label, "ok", f"{name} has an explicit allowlist; verify each origin is required and trusted.",
        evidence=evidence, severity="pass",
    )


def _check_styles(directives: dict[str, list[str]]) -> CspCheck:
    tokens, inherited = _effective(directives, "style-src", "default-src")
    recommendation = (
        "Set style-src to required origins only. Prefer nonces or hashes for inline styles; "
        "remove *, data:, cleartext HTTP, and 'unsafe-inline' where the application permits."
    )
    if tokens is None:
        return CspCheck(
            "Style sources", "missing",
            "No style-src or default-src fallback; stylesheet loading is unrestricted.",
            severity="medium", recommendation=recommendation,
        )
    sources = set(tokens)
    issues: list[tuple[str, str]] = []
    if "*" in sources:
        issues.append(("the effective style source allows *", "medium"))
    if "data:" in sources:
        issues.append(("the effective style source allows data:", "low"))
    if "http:" in sources or any(token.startswith("http://") for token in sources):
        issues.append(("the effective style source allows cleartext HTTP", "medium"))
    if "'unsafe-inline'" in sources and not any(_is_nonce_or_hash(token) for token in sources):
        issues.append(("'unsafe-inline' permits arbitrary inline CSS", "medium"))
    if "'none'" in sources and len(sources) > 1:
        issues.append(("'none' is mixed with other style sources and is ignored", "low"))
    return _issue_check(
        "Style sources", issues, _source_label(inherited, tokens), recommendation,
        "Stylesheets have an explicit restrictive source list.",
    )


def _check_mixed_content(directives: dict[str, list[str]], final_url: str) -> CspCheck:
    if urlparse(final_url).scheme != "https":
        return CspCheck(
            "Mixed-content control", "weak",
            "The final page is delivered over HTTP, so the CSP itself can be stripped or modified in transit.",
            evidence=final_url, severity="high",
            recommendation="Serve the page over HTTPS, then use upgrade-insecure-requests while migrating legacy HTTP resources.",
        )
    if "upgrade-insecure-requests" in directives or "block-all-mixed-content" in directives:
        name = "upgrade-insecure-requests" if "upgrade-insecure-requests" in directives else "block-all-mixed-content"
        return CspCheck(
            "Mixed-content control", "ok",
            f"{name} is present.", evidence=name, severity="pass",
        )
    insecure: list[str] = []
    for name, tokens in directives.items():
        if name in {"report-uri", "report-to"}:
            continue
        if "http:" in tokens or any(token.startswith("http://") for token in tokens):
            insecure.append(name)
    if insecure:
        return CspCheck(
            "Mixed-content control", "weak",
            "Cleartext HTTP sources appear in: " + ", ".join(sorted(insecure)) + ".",
            evidence="; ".join(insecure), severity="medium",
            recommendation="Remove HTTP source expressions or add upgrade-insecure-requests during migration.",
        )
    return CspCheck(
        "Mixed-content control", "ok",
        "No explicit cleartext HTTP sources were found.", severity="pass",
    )


def _audit_one_policy(directives: dict[str, list[str]], final_url: str) -> list[CspCheck]:
    checks = [
        _check_scripts(directives),
        _check_styles(directives),
        _check_object(directives),
        _check_navigation_directive(
            directives, "base-uri", "Base URL control", "medium",
            "Set base-uri 'self' (or 'none') to prevent injected <base> tags from rewriting relative URLs.",
        ),
        _check_navigation_directive(
            directives, "frame-ancestors", "Framing control", "medium",
            "Set frame-ancestors 'none' or 'self' in the response header. This directive does not work in a meta CSP.",
        ),
        _check_navigation_directive(
            directives, "form-action", "Form submissions", "low",
            "Set form-action 'self' or a narrow allowlist so injected forms cannot submit to arbitrary origins.",
        ),
        _check_mixed_content(directives, final_url),
    ]
    if "require-trusted-types-for" in directives and "'script'" in directives["require-trusted-types-for"]:
        checks.append(CspCheck(
            "Trusted Types", "ok", "DOM XSS sinks require Trusted Types.",
            evidence="require-trusted-types-for 'script'", severity="pass",
        ))
    else:
        checks.append(CspCheck(
            "Trusted Types", "info",
            "Trusted Types is not required. This is optional defense-in-depth for DOM XSS sinks.",
            severity="info",
        ))
    return checks


def _issue_rank(check: CspCheck) -> tuple[int, int]:
    if check.status not in {"missing", "weak", "error"}:
        return (0, 0 if check.status == "ok" else 1)
    return ({"low": 1, "medium": 2, "high": 3}.get(check.severity, 1), 0)


def _combine_policy_checks(per_policy: list[list[CspCheck]]) -> list[CspCheck]:
    """Combine checks using CSP's conjunctive multiple-policy semantics.

    A resource/navigation must pass every enforced policy. Therefore one
    restrictive policy can supply a control even if another policy omits it.
    The syntax check remains separate because duplicate directives are a
    maintenance error regardless of compensating policies.
    """
    if len(per_policy) == 1:
        return per_policy[0]
    combined: list[CspCheck] = []
    names = [check.name for check in per_policy[0]]
    for name in names:
        candidates = [next(check for check in checks if check.name == name) for checks in per_policy]
        best = min(candidates, key=_issue_rank)
        clone = CspCheck(**asdict(best))
        if any(_issue_rank(candidate) > _issue_rank(best) for candidate in candidates):
            clone.detail += " Multiple enforced policies combine; another policy supplies this restriction."
        combined.append(clone)
    return combined


def grade_csp_from_map(
    url: str,
    status_code: int | None,
    final_url: str,
    headers: dict[str, str],
) -> CspResult:
    """Audit CSP response headers without making a network request."""
    normalized = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    policy = normalized.get("content-security-policy", "").strip()
    report_only = normalized.get("content-security-policy-report-only", "").strip()
    policies = split_policies(policy)
    final = final_url or url
    checks: list[CspCheck] = []

    if not policies:
        detail = "No enforced Content-Security-Policy response header was found."
        if report_only:
            detail += " A Report-Only policy records violations but does not block them."
        checks.append(CspCheck(
            "Enforced response policy", "missing", detail,
            severity="high",
            recommendation="Serve an enforced Content-Security-Policy HTTP response header. Start with the suggested policy and tailor sources before deployment.",
        ))
        directives: dict[str, list[str]] = {}
        per_policy = [_audit_one_policy(directives, final)]
    else:
        parsed = [parse_policy(item) for item in policies]
        directives = parsed[0][0]
        delivery_status = "ok" if urlparse(final).scheme == "https" else "weak"
        checks.append(CspCheck(
            "Enforced response policy",
            delivery_status,
            f"Found {len(policies)} enforced CSP response polic" + ("y." if len(policies) == 1 else "ies. Multiple policies combine restrictively."),
            evidence=policy[:500],
            severity="pass" if delivery_status == "ok" else "high",
            recommendation="Serve the page and its CSP over HTTPS so the policy cannot be stripped in transit." if delivery_status == "weak" else "",
        ))
        duplicates = sorted({name for _, dupes in parsed for name in dupes})
        if duplicates:
            checks.append(CspCheck(
                "Policy syntax", "weak",
                "Duplicate directives found; browsers use the first occurrence and ignore later ones: " + ", ".join(duplicates) + ".",
                evidence=", ".join(duplicates), severity="medium",
                recommendation="Remove duplicate directives and merge intended source lists into the first occurrence.",
            ))
        else:
            checks.append(CspCheck(
                "Policy syntax", "ok", "No duplicate directives were found.", severity="pass",
            ))
        per_policy = [_audit_one_policy(item[0], final) for item in parsed]

    checks.extend(_combine_policy_checks(per_policy))

    if report_only:
        checks.append(CspCheck(
            "Report-only policy", "info",
            "A Report-Only policy is present. It reports violations but does not enforce restrictions.",
            evidence=report_only[:500], severity="info",
        ))

    reporting = directives.get("report-to") or directives.get("report-uri")
    if reporting is not None:
        checks.append(CspCheck(
            "Violation reporting", "ok",
            "The policy declares a violation reporting destination. Confirm the endpoint is monitored and does not receive sensitive URL data.",
            evidence=("report-to " if "report-to" in directives else "report-uri ") + " ".join(reporting),
            severity="pass",
        ))
    else:
        checks.append(CspCheck(
            "Violation reporting", "info",
            "No CSP reporting destination is configured. Reporting is optional but helps detect breakage and attacks.",
            severity="info",
        ))

    issue_levels = [
        {"low": 1, "medium": 2, "high": 3}.get(check.severity, 0)
        for check in checks
        if check.status in {"missing", "weak", "error"}
    ]
    worst = max(issue_levels, default=0)
    risk = "high" if worst >= 3 else "medium" if worst == 2 else "low"
    actionable = sum(check.status in {"missing", "weak", "error"} for check in checks)
    if risk == "high":
        summary = f"High-risk CSP gaps found ({actionable} actionable finding{'s' if actionable != 1 else ''}). Prioritize script execution and policy delivery."
    elif risk == "medium":
        summary = f"CSP is enforced but has {actionable} hardening gap{'s' if actionable != 1 else ''}. Review the findings before relying on it for XSS defense-in-depth."
    else:
        summary = "No obvious exploitable CSP source pattern was found. Validate the policy in report-only mode against real application flows before tightening it further."

    interesting = {
        key: normalized[key]
        for key in ("content-security-policy", "content-security-policy-report-only")
        if key in normalized
    }
    return CspResult(
        url=url,
        final_url=final,
        status_code=status_code,
        checks=checks,
        risk=risk,
        summary=summary,
        policy=policy,
        report_only_policy=report_only,
        directives=directives,
        headers=interesting,
    )


def scan_csp(
    url: str,
    timeout: float = 15.0,
    insecure: bool = False,
    allow_private: bool = True,
) -> CspResult:
    safe_url = redact_userinfo(url)
    try:
        url = normalize_url(url)
        validate_target(url, allow_private=allow_private)
    except ValueError as exc:
        return CspResult(
            url=safe_url, final_url=safe_url, status_code=None,
            checks=[CspCheck("request", "error", str(exc), severity="high")],
            risk="unknown", summary=str(exc),
        )
    try:
        code, final_url, headers = fetch_headers(
            url, timeout=timeout, insecure=insecure, allow_private=allow_private,
        )
    except Exception as exc:  # noqa: BLE001 — network errors belong in the report
        return CspResult(
            url=safe_url, final_url=safe_url, status_code=None,
            checks=[CspCheck("request", "error", f"Request failed: {exc}", severity="high")],
            risk="unknown", summary=f"Request failed: {exc}",
        )
    return grade_csp_from_map(url, code, final_url, headers)


def print_human(result: CspResult) -> None:
    print(f"\nTarget:      {result.url}")
    print(f"Final URL:   {result.final_url}")
    print(f"HTTP status: {result.status_code}")
    print(f"Risk:        {result.risk.upper()}")
    print(f"Summary:     {result.summary}")
    print("-" * 72)
    for check in result.checks:
        print(f"[{check.status.upper():9}] {check.name}: {check.detail}")
        if check.evidence:
            print(f"{'':13}evidence: {check.evidence}")
    if result.risk != "low":
        print("\nSuggested starting policy (tailor before deployment):")
        print("Content-Security-Policy: " + result.suggested_policy)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit Content-Security-Policy response headers.")
    parser.add_argument("urls", nargs="*", help="Target URLs (https://example.com)")
    parser.add_argument("-f", "--file", help="File with one URL per line")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--timeout", type=float, default=15.0, help="Request timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    parser.add_argument(
        "--public-only", action="store_true",
        help="Refuse loopback / RFC1918 targets (metadata and link-local are always blocked).",
    )
    return parser.parse_args(argv)


def collect_urls(args: argparse.Namespace) -> list[str]:
    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            urls.extend(
                line.strip() for line in handle
                if line.strip() and not line.lstrip().startswith("#")
            )
    seen: set[str] = set()
    return [url for url in urls if not (url in seen or seen.add(url))]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    urls = collect_urls(args)
    if not urls:
        print("No URLs supplied. Use --help for usage.", file=sys.stderr)
        return 2
    results = [
        scan_csp(
            url,
            timeout=args.timeout,
            insecure=args.insecure,
            allow_private=not args.public_only,
        )
        for url in urls
    ]
    if args.json:
        payload = [result.to_dict() for result in results]
        print(json.dumps(payload[0] if len(payload) == 1 else payload, indent=2))
    else:
        for result in results:
            print_human(result)
    return 1 if any(result.risk in {"high", "unknown"} for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
