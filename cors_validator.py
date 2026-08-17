#!/usr/bin/env python3
"""
CyberBuddy — CORS posture probe with method-aware coverage.

Sends two GETs with distinct Origin values so we can tell a reflected
ACAO from a fixed allowlist, plus optional HEAD, OPTIONS and preflight
probes. Pure stdlib with connection pooling.

Primary risk ladder (per method):
- reflected Origin + credentials = High;
- reflection alone OR wildcard + credentials = Medium;
- otherwise Low;
- missing Vary: Origin is a separate finding, never headline risk.
The overall risk is the highest observed primary risk across all
successfully assessed methods.

We never automatically send POST — it can mutate state. The analyst
explicitly selects additional coverage (HEAD, OPTIONS, preflight POST
etc.) for an authorized endpoint. Unsupported methods (405/501) are
reported as unassessed, not safe.

Optimizations:
- HTTP connection reuse via http_session module
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field

from clickjacking_validator import fetch_headers, normalize_url, redact_userinfo, validate_target

ATTACKER_A = "https://evil.cyberbuddy.test"
ATTACKER_B = "https://probe.cyberbuddy.test"
NULL_ORIGIN = "null"

# HTTP status codes that mean the method is not supported — report as
# unassessed rather than safe. 405 Method Not Allowed and 501 Not
# Implemented are the standard signals; we also treat 501 variants.
UNSUPPORTED_METHOD_STATUSES = {405, 501}


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
    # Method-aware coverage (new)
    methods: list[str] = field(default_factory=list)  # direct methods selected (GET, HEAD, OPTIONS)
    preflight_methods: list[str] = field(default_factory=list)  # preflight ACRM values (POST etc.)
    preflight_headers: list[str] = field(default_factory=list)  # ACRH values
    tested_methods: list[str] = field(default_factory=list)  # successfully assessed
    unassessed_methods: list[str] = field(default_factory=list)  # 405/501 etc.
    method_results: list[dict] = field(default_factory=list)  # per-probe detail
    coverage: list[dict] = field(default_factory=list)  # alias for method_results (export convenience)

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


def re_origin_in_vary(vary: str) -> bool:
    return any(part.strip().lower() == "origin" for part in vary.split(",")) if vary else False


def _assess_triplet(
    label: str | None,
    hdr_a: dict[str, str],
    hdr_b: dict[str, str],
    hdr_null: dict[str, str],
    is_preflight: bool = False,
    preflight_method: str | None = None,
    preflight_headers: list[str] | None = None,
) -> tuple[list[Check], str, str]:
    """Assess one method/preflight triplet and return (checks, risk, summary)."""
    prefix = f"{label}: " if label else ""
    # For preflight the label already includes "Preflight POST"
    acao_a = _acao(hdr_a)
    acao_b = _acao(hdr_b)
    acao_null = _acao(hdr_null)
    creds = _acac(hdr_a) or _acac(hdr_b) or _acac(hdr_null)
    vary = _vary(hdr_a) or _vary(hdr_b) or _vary(hdr_null)
    checks: list[Check] = []

    reflected = acao_a == ATTACKER_A and acao_b == ATTACKER_B
    wildcard = acao_a == "*" and acao_b == "*"
    null_reflected = acao_null == NULL_ORIGIN
    both_absent = acao_a is None and acao_b is None and acao_null is None

    if null_reflected:
        checks.append(Check(
            f"{prefix}Access-Control-Allow-Origin: null" if label else "Access-Control-Allow-Origin: null", "weak",
            "The server allows the opaque null Origin. Sandboxed documents and data URLs can use it to read responses" +
            (" with credentials." if creds else "."),
            evidence=f"Origin null → ACAO: {acao_null}   ACAC: {'true' if creds else '(absent)'}",
        ))
    elif both_absent:
        checks.append(Check(
            f"{prefix}Access-Control-Allow-Origin", "ok",
            "No ACAO for either probe origin — cross-origin reads are blocked. Restrictive and safe.",
            evidence=f"Origin {ATTACKER_A} → (absent); Origin {ATTACKER_B} → (absent)",
        ))
    elif reflected:
        if creds:
            checks.append(Check(
                f"{prefix}Access-Control-Allow-Origin", "weak",
                "The server reflects arbitrary Origins AND allows credentials. A malicious site "
                "can read authenticated responses as the victim.",
                evidence=f"ACAO: {acao_a} / {acao_b}   ACAC: true",
            ))
        else:
            checks.append(Check(
                f"{prefix}Access-Control-Allow-Origin", "weak",
                "The server reflects arbitrary Origins (two distinct probe origins were echoed). "
                "Safe only for fully public data; dangerous if cookies are ever added.",
                evidence=f"ACAO: {acao_a} / {acao_b}",
            ))
    elif wildcard:
        if creds:
            checks.append(Check(
                f"{prefix}Access-Control-Allow-Origin", "weak",
                "Wildcard ACAO combined with Allow-Credentials: true. Browsers refuse this for "
                "credentialed requests, but the configuration is broken.",
                evidence="ACAO: *   ACAC: true",
            ))
        else:
            checks.append(Check(
                f"{prefix}Access-Control-Allow-Origin", "info",
                "Wildcard ACAO, no credentials. Any site can read this resource — acceptable "
                "only for fully public data.",
                evidence="ACAO: *",
            ))
    else:
        checks.append(Check(
            f"{prefix}Access-Control-Allow-Origin", "ok",
            "ACAO is not a per-request reflection of arbitrary origins. Treat this as a "
            "fixed allowlist (or no CORS for these probe origins).",
            evidence=f"Origin {ATTACKER_A} → {acao_a or '(absent)'}; Origin {ATTACKER_B} → {acao_b or '(absent)'}",
        ))

    if creds and not wildcard:
        checks.append(Check(
            f"{prefix}Allow-Credentials", "info",
            "Credentials explicitly allowed on at least one probe response.",
            evidence="ACAC: true",
        ))

    # Preflight-specific checks for Allow-Methods / Allow-Headers
    if is_preflight and preflight_method:
        acam = (hdr_a.get("access-control-allow-methods") or hdr_b.get("access-control-allow-methods") or hdr_null.get("access-control-allow-methods") or "").strip()
        if acam:
            if preflight_method.lower() in acam.lower():
                checks.append(Check(
                    f"{prefix}Access-Control-Allow-Methods", "info",
                    f"Preflight allows {preflight_method} (ACAM includes it).",
                    evidence=f"ACAM: {acam}",
                ))
            else:
                checks.append(Check(
                    f"{prefix}Access-Control-Allow-Methods", "weak",
                    f"Preflight does not list {preflight_method} in Access-Control-Allow-Methods.",
                    evidence=f"ACAM: {acam or '(absent)'}",
                ))
        else:
            checks.append(Check(
                f"{prefix}Access-Control-Allow-Methods", "info",
                "No Access-Control-Allow-Methods in preflight response.",
                evidence="ACAM: (absent)",
            ))
        if preflight_headers:
            acah = (hdr_a.get("access-control-allow-headers") or hdr_b.get("access-control-allow-headers") or hdr_null.get("access-control-allow-headers") or "").strip()
            wanted = ", ".join(preflight_headers)
            if acah:
                # Check that all requested headers are allowed (case-insensitive)
                missing = [h for h in preflight_headers if h.lower() not in acah.lower()]
                if not missing:
                    checks.append(Check(
                        f"{prefix}Access-Control-Allow-Headers", "info",
                        f"Preflight allows requested headers: {wanted}.",
                        evidence=f"ACAH: {acah}",
                    ))
                else:
                    checks.append(Check(
                        f"{prefix}Access-Control-Allow-Headers", "weak",
                        f"Preflight missing requested header(s): {', '.join(missing)}.",
                        evidence=f"ACAH: {acah} ; requested: {wanted}",
                    ))
            else:
                checks.append(Check(
                    f"{prefix}Access-Control-Allow-Headers", "info",
                    f"No Access-Control-Allow-Headers in preflight; requested {wanted}.",
                    evidence="ACAH: (absent)",
                ))

    origin_specific = (acao_a not in (None, "*")) or (acao_b not in (None, "*")) or (acao_null == NULL_ORIGIN)
    if origin_specific and not re_origin_in_vary(vary):
        checks.append(Check(
            f"{prefix}Vary: Origin", "weak",
            "Origin-specific CORS headers without Vary: Origin. Shared caches / CDNs can "
            "serve one caller's ACAO to everyone.",
            evidence=f"Vary: {vary or '(absent)'}",
        ))
    elif re_origin_in_vary(vary):
        checks.append(Check(
            f"{prefix}Vary: Origin", "ok",
            "Vary: Origin present — cached responses will be partitioned by caller origin.",
            evidence=f"Vary: {vary}",
        ))
    elif not both_absent:
        checks.append(Check(
            f"{prefix}Vary: Origin", "info",
            "No origin-specific ACAO observed; Vary: Origin is still recommended.",
            evidence=f"Vary: {vary or '(absent)'}",
        ))

    # Headline risk follows the observed access outcome, not a secondary
    # cache-hardening finding.
    if null_reflected and creds:
        risk = "high"
        summary = "The server reflects the null Origin and allows credentials; opaque-origin documents can read authenticated responses."
    elif null_reflected:
        risk = "medium"
        summary = "The server reflects the null Origin; opaque-origin documents can read this response."
    elif reflected and creds:
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

    # Prefix summary with label for multi-method clarity
    if label:
        summary = f"[{label}] {summary}"

    return checks, risk, summary


def scan_cors(
    url: str,
    timeout: float = 15.0,
    insecure: bool = False,
    allow_private: bool = True,
    methods: list[str] | None = None,
    preflight_methods: list[str] | None = None,
    preflight_headers: list[str] | None = None,
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
            methods=methods or ["GET"],
            preflight_methods=preflight_methods or [],
            preflight_headers=preflight_headers or [],
            tested_methods=[],
            unassessed_methods=[],
            method_results=[],
            coverage=[],
        )

    # Normalize direct methods
    if methods is None:
        methods = ["GET"]
    else:
        if isinstance(methods, str):  # type: ignore[arg-type]
            methods = [m.strip() for m in str(methods).split(",") if m.strip()]
        normalized = []
        for m in methods:
            m = str(m).strip().upper()
            if m:
                normalized.append(m)
        methods = normalized
        # Keep GET as baseline
        if "GET" not in methods:
            methods = ["GET"] + methods
        # Deduplicate preserving order, keep only GET/HEAD/OPTIONS
        seen: set[str] = set()
        uniq: list[str] = []
        for m in methods:
            if m not in seen:
                seen.add(m)
                uniq.append(m)
        allowed = {"GET", "HEAD", "OPTIONS"}
        methods = [m for m in uniq if m in allowed]
        if not methods:
            methods = ["GET"]

    # Normalize preflight
    if preflight_methods is None:
        preflight_methods = []
    else:
        if isinstance(preflight_methods, str):  # type: ignore[arg-type]
            preflight_methods = [m.strip() for m in str(preflight_methods).split(",") if m.strip()]
        normalized = []
        for m in preflight_methods:
            m = str(m).strip().upper()
            if m:
                normalized.append(m)
        # deduplicate
        seen = set()
        uniq = []
        for m in normalized:
            if m not in seen:
                seen.add(m)
                uniq.append(m)
        preflight_methods = uniq

    if preflight_headers is None:
        preflight_headers = []
    else:
        if isinstance(preflight_headers, str):  # type: ignore[arg-type]
            preflight_headers = [h.strip() for h in str(preflight_headers).split(",") if h.strip()]
        else:
            preflight_headers = [str(h).strip() for h in preflight_headers if str(h).strip()]

    all_checks: list[Check] = []
    method_results: list[dict] = []
    tested_methods: list[str] = []
    unassessed_methods: list[str] = []
    max_risk = "low"
    risk_order = {"low": 0, "medium": 1, "high": 2, "unknown": 0, "unassessed": 0}
    final_url_overall: str | None = None
    status_code_overall: int | None = None
    headers_overall: dict[str, str] = {}
    origins_tested_overall = [ATTACKER_A, ATTACKER_B, NULL_ORIGIN]

    def _update_max(r: str) -> None:
        nonlocal max_risk
        if risk_order.get(r, 0) > risk_order.get(max_risk, 0):
            max_risk = r

    # Direct methods
    for method in methods:
        # For each method, probe three origins
        try:
            code_a, final_a, hdr_a = fetch_headers(
                url, timeout=timeout, insecure=insecure, allow_private=allow_private,
                extra_headers={"Origin": ATTACKER_A}, method=method,
            )
            code_b, _final_b, hdr_b = fetch_headers(
                url, timeout=timeout, insecure=insecure, allow_private=allow_private,
                extra_headers={"Origin": ATTACKER_B}, method=method,
            )
            code_null, _final_null, hdr_null = fetch_headers(
                url, timeout=timeout, insecure=insecure, allow_private=allow_private,
                extra_headers={"Origin": NULL_ORIGIN}, method=method,
            )
        except Exception as exc:  # noqa: BLE001
            err_check = Check(
                f"{method}: request" if method != "GET" else "request",
                "error", f"Request failed for {method}: {exc}",
            )
            method_results.append({
                "method": method,
                "kind": "direct",
                "status_code": None,
                "risk": "unknown",
                "checks": [asdict(err_check)],
                "headers": {},
                "origins": [ATTACKER_A, ATTACKER_B, NULL_ORIGIN],
                "unassessed": False,
                "error": str(exc),
                "evidence": f"{method} request failed",
            })
            all_checks.append(err_check)
            # Do not update max risk for unknown error; keep existing
            continue

        # Check for unsupported method (405/501)
        if code_a in UNSUPPORTED_METHOD_STATUSES:
            label = method
            info_check = Check(
                f"{label}: CORS probe" if method != "GET" else "CORS probe",
                "info",
                f"{method} not supported by endpoint (HTTP {code_a}) — CORS for {method} was not assessed.",
                evidence=f"HTTP {code_a} for {method}",
            )
            method_results.append({
                "method": method,
                "kind": "direct",
                "status_code": code_a,
                "risk": "unassessed",
                "checks": [asdict(info_check)],
                "headers": {k: hdr_a.get(k, "") for k in ("access-control-allow-origin", "access-control-allow-credentials", "vary") if k in hdr_a},
                "origins": [ATTACKER_A, ATTACKER_B, NULL_ORIGIN],
                "unassessed": True,
                "reason": f"HTTP {code_a}",
                "evidence": f"{method} → HTTP {code_a}",
            })
            unassessed_methods.append(method)
            all_checks.append(info_check)
            continue

        # Assess triplet
        label = method if method != "GET" else None
        checks, risk, summary = _assess_triplet(label, hdr_a, hdr_b, hdr_null)
        method_results.append({
            "method": method,
            "kind": "direct",
            "status_code": code_a,
            "risk": risk,
            "summary": summary,
            "checks": [asdict(c) for c in checks],
            "headers": {k: hdr_a.get(k, "") for k in ("access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods", "access-control-allow-headers", "vary") if k in hdr_a or k in hdr_b or k in hdr_null},
            "origins": [ATTACKER_A, ATTACKER_B, NULL_ORIGIN],
            "unassessed": False,
            "evidence": f"{method} Origin {ATTACKER_A} → {hdr_a.get('access-control-allow-origin') or '(absent)'}; {ATTACKER_B} → {hdr_b.get('access-control-allow-origin') or '(absent)'}; null → {hdr_null.get('access-control-allow-origin') or '(absent)'}",
        })
        tested_methods.append(method)
        for c in checks:
            all_checks.append(c)
        _update_max(risk)
        if final_url_overall is None:
            final_url_overall = final_a
            status_code_overall = code_a
            # Prefer hdr_a but fallback
            interesting = {}
            for key in ("access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods", "access-control-allow-headers", "vary"):
                if key in hdr_a:
                    interesting[key] = hdr_a[key]
                elif key in hdr_b:
                    interesting[key] = hdr_b[key]
                elif key in hdr_null:
                    interesting[key] = hdr_null[key]
            headers_overall = interesting

    # Preflight probes (OPTIONS with ACRM)
    for pre_m in preflight_methods:
        extra_a = {"Origin": ATTACKER_A, "Access-Control-Request-Method": pre_m}
        extra_b = {"Origin": ATTACKER_B, "Access-Control-Request-Method": pre_m}
        extra_null = {"Origin": NULL_ORIGIN, "Access-Control-Request-Method": pre_m}
        if preflight_headers:
            hdr_val = ", ".join(preflight_headers)
            extra_a["Access-Control-Request-Headers"] = hdr_val
            extra_b["Access-Control-Request-Headers"] = hdr_val
            extra_null["Access-Control-Request-Headers"] = hdr_val
        try:
            code_a, final_a, hdr_a = fetch_headers(
                url, timeout=timeout, insecure=insecure, allow_private=allow_private,
                extra_headers=extra_a, method="OPTIONS",
            )
            code_b, _final_b, hdr_b = fetch_headers(
                url, timeout=timeout, insecure=insecure, allow_private=allow_private,
                extra_headers=extra_b, method="OPTIONS",
            )
            code_null, _final_null, hdr_null = fetch_headers(
                url, timeout=timeout, insecure=insecure, allow_private=allow_private,
                extra_headers=extra_null, method="OPTIONS",
            )
        except Exception as exc:  # noqa: BLE001
            label = f"Preflight {pre_m}"
            err_check = Check(f"{label}: request", "error", f"Preflight request failed for {pre_m}: {exc}")
            method_results.append({
                "method": "OPTIONS",
                "kind": "preflight",
                "request_method": pre_m,
                "request_headers": preflight_headers,
                "status_code": None,
                "risk": "unknown",
                "checks": [asdict(err_check)],
                "headers": {},
                "origins": [ATTACKER_A, ATTACKER_B, NULL_ORIGIN],
                "unassessed": False,
                "error": str(exc),
            })
            all_checks.append(err_check)
            continue
        if code_a in UNSUPPORTED_METHOD_STATUSES:
            label = f"Preflight {pre_m}"
            info_check = Check(f"{label}: CORS probe", "info", f"Preflight for {pre_m} not supported (HTTP {code_a}) — not assessed.", evidence=f"HTTP {code_a}")
            method_results.append({
                "method": "OPTIONS",
                "kind": "preflight",
                "request_method": pre_m,
                "request_headers": preflight_headers,
                "status_code": code_a,
                "risk": "unassessed",
                "checks": [asdict(info_check)],
                "headers": {},
                "origins": [ATTACKER_A, ATTACKER_B, NULL_ORIGIN],
                "unassessed": True,
                "reason": f"HTTP {code_a}",
            })
            unassessed_methods.append(f"preflight:{pre_m}")
            all_checks.append(info_check)
            continue
        label = f"Preflight {pre_m}"
        checks, risk, summary = _assess_triplet(label, hdr_a, hdr_b, hdr_null, is_preflight=True, preflight_method=pre_m, preflight_headers=preflight_headers)
        method_results.append({
            "method": "OPTIONS",
            "kind": "preflight",
            "request_method": pre_m,
            "request_headers": preflight_headers,
            "status_code": code_a,
            "risk": risk,
            "summary": summary,
            "checks": [asdict(c) for c in checks],
            "headers": {k: hdr_a.get(k, "") for k in ("access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods", "access-control-allow-headers", "vary") if k in hdr_a or k in hdr_b or k in hdr_null},
            "origins": [ATTACKER_A, ATTACKER_B, NULL_ORIGIN],
            "unassessed": False,
            "evidence": f"Preflight {pre_m} Origin {ATTACKER_A} → {hdr_a.get('access-control-allow-origin') or '(absent)'}; {ATTACKER_B} → {hdr_b.get('access-control-allow-origin') or '(absent)'}; null → {hdr_null.get('access-control-allow-origin') or '(absent)'}",
        })
        # Record tested as preflight:POST etc.
        tested_methods.append(f"preflight:{pre_m}")
        for c in checks:
            all_checks.append(c)
        _update_max(risk)
        if final_url_overall is None:
            final_url_overall = final_a
            status_code_overall = code_a
            interesting = {}
            for key in ("access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods", "access-control-allow-headers", "vary"):
                if key in hdr_a:
                    interesting[key] = hdr_a[key]
                elif key in hdr_b:
                    interesting[key] = hdr_b[key]
                elif key in hdr_null:
                    interesting[key] = hdr_null[key]
            headers_overall = interesting

    # If no method succeeded (all unassessed or error), fallback values
    if final_url_overall is None:
        # Use url as final, status unknown, keep headers empty
        final_url_overall = url
        status_code_overall = None
        headers_overall = {}

    # Determine overall risk: highest among tested (assessed) methods
    # If no tested methods but some unassessed, risk remains low? But we should report unknown if no successful assessment
    if not tested_methods and unassessed_methods:
        # Only unassessed methods were requested beyond GET? But GET should have been tested. If GET also unassessed, then unknown.
        # Check if any method_results have risk high/medium/low; else unknown
        assessed_risks = [r["risk"] for r in method_results if not r.get("unassessed") and r.get("risk") not in ("unknown", "unassessed")]
        if not assessed_risks:
            overall_risk = "unknown"
            overall_summary = f"All selected methods were unassessed (unsupported). No CORS posture could be determined. Coverage: {', '.join(methods + [f'preflight:{m}' for m in preflight_methods])}."
        else:
            overall_risk = max_risk
            overall_summary = f"No risky CORS behavior observed for tested methods ({', '.join(tested_methods)})."
    else:
        overall_risk = max_risk
        # Build summary with method awareness
        if overall_risk == "high":
            risky = [r for r in method_results if r.get("risk") == "high" and not r.get("unassessed")]
            risky_labels = []
            for r in risky:
                if r["kind"] == "preflight":
                    risky_labels.append(f"preflight {r['request_method']}")
                else:
                    risky_labels.append(r["method"])
            overall_summary = f"High-risk CORS behavior observed for {', '.join(risky_labels)} — reflected Origin + credentials confirmed."
            if len(tested_methods) > len(risky_labels):
                overall_summary += f" Other tested methods were not vulnerable."
            overall_summary += f" Coverage: {', '.join(tested_methods)}."
            if unassessed_methods:
                overall_summary += f" Unassessed: {', '.join(unassessed_methods)}."
        elif overall_risk == "medium":
            risky = [r for r in method_results if r.get("risk") == "medium" and not r.get("unassessed")]
            risky_labels = []
            for r in risky:
                if r["kind"] == "preflight":
                    risky_labels.append(f"preflight {r['request_method']}")
                else:
                    risky_labels.append(r["method"])
            # Distinguish null vs reflection vs wildcard
            overall_summary = f"Medium-risk CORS behavior observed for {', '.join(risky_labels)}."
            # Use first risky summary detail?
            if risky:
                # Take first risky's summary without label prefix
                overall_summary += f" {risky[0].get('summary','')}"
            overall_summary += f" Coverage: {', '.join(tested_methods)}."
            if unassessed_methods:
                overall_summary += f" Unassessed: {', '.join(unassessed_methods)}."
        else:  # low
            if len(tested_methods) == 1 and tested_methods[0] == "GET" and not preflight_methods and len(methods) == 1:
                # Preserve original per-method summary wording for backward compat
                # while also satisfying the method-aware "No risky ... for GET" requirement.
                per_summary = ""
                if method_results and method_results[0].get("summary"):
                    per_summary = method_results[0]["summary"]
                    if per_summary.startswith("["):
                        idx = per_summary.find("] ")
                        if idx != -1:
                            per_summary = per_summary[idx+2:]
                # Ensure Pass / No arbitrary-origin substrings remain for existing tests
                overall_summary = f"No risky CORS behavior observed for GET — {per_summary} Coverage: GET only; other methods (HEAD, OPTIONS, preflight) were not tested — select them for authorized testing if the endpoint supports them."
                if unassessed_methods:
                    overall_summary += f" Unassessed: {', '.join(unassessed_methods)}."
            elif not tested_methods:
                overall_summary = "No assessed methods produced a CORS policy result."
            else:
                overall_summary = f"No risky CORS behavior observed for all tested methods ({', '.join(tested_methods)})."
                if unassessed_methods:
                    overall_summary += f" Unassessed: {', '.join(unassessed_methods)}."
                # For low but with no reflection, keep mention of PASS for GET? But avoid global PASS when only GET
                # For multi-method low, it's okay to say all tested methods PASS
                if len(tested_methods) == 1:
                    overall_summary += f" Coverage: {tested_methods[0]} only."
                else:
                    overall_summary += f" Coverage: {', '.join(tested_methods)}."

    # If overall checks are empty (should not happen), fallback to all_checks
    # For backward compat, if only GET was requested, keep original summary style for low cases where appropriate?
    # But new summary already covers.

    # Build interesting headers overall (keep GET's)
    # Ensure coverage alias
    coverage = method_results

    return CorsResult(
        url=url,
        final_url=final_url_overall,
        status_code=status_code_overall,
        checks=all_checks if all_checks else [Check("request", "error", "No checks produced")],
        risk=overall_risk,
        summary=overall_summary,
        headers=headers_overall,
        origins_tested=origins_tested_overall,
        methods=methods,
        preflight_methods=preflight_methods,
        preflight_headers=preflight_headers,
        tested_methods=tested_methods,
        unassessed_methods=unassessed_methods,
        method_results=method_results,
        coverage=coverage,
    )


def print_human(result: CorsResult) -> None:
    print(f"\nTarget:      {result.url}")
    print(f"Final URL:   {result.final_url}")
    print(f"HTTP status: {result.status_code}")
    print(f"Risk:        {result.risk.upper()}")
    print(f"Summary:     {result.summary}")
    if result.origins_tested:
        print(f"Origins:     {', '.join(result.origins_tested)}")
    if result.methods or result.preflight_methods:
        print(f"Methods:     {', '.join(result.methods)}")
        if result.preflight_methods:
            print(f"Preflight:   {', '.join(result.preflight_methods)}" + (f" headers={','.join(result.preflight_headers)}" if result.preflight_headers else ""))
        print(f"Tested:      {', '.join(result.tested_methods) if result.tested_methods else '(none)'}")
        if result.unassessed_methods:
            print(f"Unassessed:  {', '.join(result.unassessed_methods)}")
    print("-" * 72)
    for c in result.checks:
        print(f"[{c.status.upper():7}] {c.name}: {c.detail}")
        if c.evidence:
            print(f"{'':10}evidence: {c.evidence}")
    if result.method_results:
        print("\nCoverage matrix:")
        for mr in result.method_results:
            label = mr["method"]
            if mr.get("kind") == "preflight":
                label = f"Preflight {mr.get('request_method')}"
            print(f"  {label}: {mr.get('risk','')} (HTTP {mr.get('status_code')})")


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
    p.add_argument(
        "--methods",
        help="Comma-separated direct methods to probe in addition to GET (e.g., GET,HEAD,OPTIONS). GET is always included as baseline.",
    )
    p.add_argument(
        "--preflight",
        help="Comma-separated methods to simulate preflight for via OPTIONS + Access-Control-Request-Method (e.g., POST). Requires authorized endpoint.",
    )
    p.add_argument(
        "--preflight-headers",
        help="Comma-separated request headers to simulate via Access-Control-Request-Headers for preflight (e.g., Content-Type,X-Custom).",
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
    methods = None
    if args.methods:
        methods = [m.strip() for m in args.methods.split(",") if m.strip()]
    preflight_methods = None
    if args.preflight:
        preflight_methods = [m.strip() for m in args.preflight.split(",") if m.strip()]
    preflight_headers = None
    if args.preflight_headers:
        preflight_headers = [h.strip() for h in args.preflight_headers.split(",") if h.strip()]
    results = [
        scan_cors(u, timeout=args.timeout, insecure=args.insecure, allow_private=allow_private,
                  methods=methods, preflight_methods=preflight_methods, preflight_headers=preflight_headers)
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
