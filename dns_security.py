#!/usr/bin/env python3
"""
DNS & Domain Security Analyzer — stdlib-only engine.

Grades the *public DNS* security posture of a domain without ever
connecting to the domain itself. All traffic goes to a DNS resolver
(the system's, or an explicit override); the target's own servers are
never contacted, so this is safe to run against domains the analyst
does not own — and it still asks only for authorized testing.

Checks
------
- Domain resolution     A/AAAA present? NXDOMAIN is reported honestly.
- Name servers (NS)     present and at least two for redundancy.
- DNSSEC                DS published at the parent zone (chain-of-trust
                        evidence) plus the apex DNSKEY.
- MX                    inbound mail delivery (context for the email checks).
- SPF                   v=spf1 TXT, its qualifier (+all/?all/~all/-all) and
                        the 10-lookup budget from RFC 7208.
- DMARC                 _dmarc TXT, its p= policy and subdomain policy.
- DKIM                  v=DKIM1 TXT on common selectors (never a proof of
                        absence — a custom selector may still exist).
- CAA                   Certificate Authority Authorization for issuance.

Everything is stdlib: the engine speaks the DNS wire format directly over
UDP (with a TCP fallback on truncation) using ``socket`` + ``struct``.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import socket
import struct
import sys
from dataclasses import asdict, dataclass, field
from typing import Callable
from urllib.parse import urlparse

# Score weights. 100 is a perfect baseline; each finding deducts.
WEIGHTS = {
    "DMARC": 20,
    "SPF": 15,
    "DKIM": 10,
    "DNSSEC": 10,
    "Name servers": 10,
    "CAA": 5,
}

# DKIM selectors we probe. A miss is explicitly NOT proof of absence.
DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2",
    "mail", "smtp", "dkim", "mandrill", "s1", "s2",
)

# Record types the engine understands.
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_PTR = 12
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28
QTYPE_DNSKEY = 48
QTYPE_DS = 43
QTYPE_CAA = 257

QTYPE_NAMES = {
    QTYPE_A: "A", QTYPE_NS: "NS", QTYPE_CNAME: "CNAME", QTYPE_SOA: "SOA",
    QTYPE_PTR: "PTR", QTYPE_MX: "MX", QTYPE_TXT: "TXT", QTYPE_AAAA: "AAAA",
    QTYPE_DNSKEY: "DNSKEY", QTYPE_DS: "DS", QTYPE_CAA: "CAA",
}

RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}

DEFAULT_PUBLIC_RESOLVERS = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")


def rcode_name(code: int) -> str:
    return RCODE_NAMES.get(code, f"RCODE{code}")


@dataclass
class Check:
    name: str
    status: str  # ok | weak | missing | info | error
    detail: str
    evidence: str = ""
    deduction: int = 0


@dataclass
class DnsResult:
    domain: str
    url: str
    status: str  # ok | error
    resolver: str
    records: dict[str, list[str]] = field(default_factory=dict)
    statuses: dict[str, str] = field(default_factory=dict)
    checks: list[Check] = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    risk: str = "unknown"
    summary: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Domain input handling
# ---------------------------------------------------------------------------

def normalize_domain(raw: str) -> str:
    """Turn pasted input (URL, trailing dot, whitespace) into a lowercase
    FQDN without a trailing dot. Raises ValueError with a human message."""
    value = (raw or "").strip()
    if not value:
        raise ValueError("Enter a domain to analyze.")
    # Strip a URL scheme/path/query if someone pastes a full URL.
    if "://" in value:
        value = urlparse(value).netloc or urlparse(value).path
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    value = value.strip().rstrip(".")
    if not value:
        raise ValueError("Enter a domain to analyze.")
    # Bracketed IPv6 -> reject below as an IP.
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    # Port suffix? Strip it — a host:port paste should still resolve.
    if ":" in value and value.count(":") == 1:
        maybe_host, maybe_port = value.rsplit(":", 1)
        if maybe_port.isdigit():
            value = maybe_host

    try:
        ipaddress.ip_address(value)
        raise ValueError("IP addresses cannot be analyzed as domains — enter a hostname such as example.com.")
    except ValueError as exc:
        if "cannot be analyzed" in str(exc):
            raise
        # Not an IP — fall through to hostname validation.

    if value.lower() == "localhost":
        raise ValueError("localhost is not a public domain — enter a hostname such as example.com.")

    # Punycode-encode internationalized domains (stdlib idna codec).
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        pass  # keep the raw value; label validation below will reject it.

    if len(value) > 253:
        raise ValueError("The domain is longer than 253 characters.")
    labels = value.split(".")
    if len(labels) < 2:
        raise ValueError("Public domains need a dot and a TLD (for example, example.com).")
    for label in labels:
        if not label or len(label) > 63:
            raise ValueError("The domain contains an empty or over-long label.")
        if not label.replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"Invalid characters in label '{label}'.")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("Domain labels cannot start or end with a hyphen.")
    tld = labels[-1]
    if not tld.replace("_", "").isalpha():
        raise ValueError("The domain needs a plausible TLD, such as .com or .org.")
    return value


def validate_domain(raw: str) -> str:
    """Validate + normalize; the single entry point for every caller."""
    return normalize_domain(raw)


# ---------------------------------------------------------------------------
# Resolvers
# ---------------------------------------------------------------------------

def system_resolvers() -> list[str]:
    """Return the system's configured resolvers, else a public fallback.

    ``server.py`` (the private local path) prefers the OS resolver so a
    scan never has to disclose the target to a third party. If none is
    configured, public resolvers are used and the report says so."""
    resolvers: list[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                if parts and parts[0] == "nameserver" and len(parts) > 1:
                    resolvers.append(parts[1])
                    if len(resolvers) >= 2:
                        break
    except OSError:
        pass
    return resolvers or list(DEFAULT_PUBLIC_RESOLVERS[:2])


# ---------------------------------------------------------------------------
# DNS wire format (UDP + TCP fallback)
# ---------------------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii", "ignore")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _build_query(name: str, qtype: int) -> bytes:
    ident = random.randint(0, 0xFFFF)
    flags = 0x0100  # RD=1 (recursion desired)
    header = struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", qtype, 1)
    return header + question


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    next_offset = offset
    jumped = False
    end = offset
    while True:
        if offset >= len(packet):
            break
        length = packet[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(packet):
                break
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(packet[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), end


def _parse_txt(rdata: bytes) -> str:
    out: list[str] = []
    i = 0
    while i < len(rdata):
        ln = rdata[i]
        i += 1
        out.append(rdata[i:i + ln].decode("utf-8", "replace"))
        i += ln
    return "".join(out)


def _parse_rdata(qtype: int, packet: bytes, rdata_off: int, rdlength: int) -> str:
    rdata = packet[rdata_off:rdata_off + rdlength]
    # Names inside rdata may be compression pointers into the full packet,
    # so they are read from ``packet`` at their true offsets — never from
    # the rdata slice.
    if qtype == QTYPE_A:
        return socket.inet_ntop(socket.AF_INET, rdata)
    if qtype == QTYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if qtype in (QTYPE_NS, QTYPE_CNAME, QTYPE_PTR):
        return _read_name(packet, rdata_off)[0]
    if qtype == QTYPE_MX:
        pref = struct.unpack("!H", rdata[:2])[0]
        exchange = _read_name(packet, rdata_off + 2)[0]
        return f"{pref} {exchange or '.'}"
    if qtype == QTYPE_TXT:
        return _parse_txt(rdata)
    if qtype == QTYPE_SOA:
        mname, off = _read_name(packet, rdata_off)
        rname, off = _read_name(packet, off)
        serial, _refresh, _retry, _expire, _minimum = struct.unpack("!IIIII", packet[off:off + 20])
        return f"{mname} {rname} {serial}"
    if qtype == QTYPE_CAA:
        flags = rdata[0]
        tag_len = rdata[1]
        tag = rdata[2:2 + tag_len].decode("ascii", "replace")
        value = rdata[2 + tag_len:].decode("utf-8", "replace")
        return f'{flags} {tag} "{value}"'
    if qtype == QTYPE_DS:
        keytag, algorithm, digest_type = struct.unpack("!HBB", rdata[:4])
        digest = rdata[4:].hex().upper()
        return f"{keytag} {algorithm} {digest_type} {digest}"
    if qtype == QTYPE_DNSKEY:
        flags, protocol, algorithm = struct.unpack("!HBB", rdata[:4])
        keylen = len(rdata) - 4
        return f"flags={flags} protocol={protocol} algorithm={algorithm} keylen={keylen}"
    return rdata.hex()


def _parse_response(packet: bytes) -> tuple[dict, list[tuple[str, int, str]]]:
    """Return (header, answers) where answers is a list of
    (qtype_name, qtype, rdata_string)."""
    if len(packet) < 12:
        raise ValueError("short DNS response")
    ident, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)
    header = {
        "rcode": rcode,
        "rcode_name": rcode_name(rcode),
        "truncated": truncated,
        "ancount": ancount,
    }
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(packet, offset)
        offset += 4
    answers: list[tuple[str, int, str]] = []
    for _ in range(ancount):
        try:
            _, offset = _read_name(packet, offset)
            if offset + 10 > len(packet):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
            offset += 10
            rdata_off = offset
            offset += rdlength
        except (struct.error, IndexError):
            break
        answers.append((QTYPE_NAMES.get(rtype, str(rtype)), rtype,
                        _parse_rdata(rtype, packet, rdata_off, rdlength)))
    return header, answers


def _query_udp(resolver: str, name: str, qtype: int, timeout: float) -> bytes:
    query = _build_query(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (resolver, 53))
        data, _addr = sock.recvfrom(4096)
    return data


def _query_tcp(resolver: str, name: str, qtype: int, timeout: float) -> bytes:
    query = _build_query(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((resolver, 53))
        sock.sendall(struct.pack("!H", len(query)) + query)
        length_bytes = sock.recv(2)
        if len(length_bytes) < 2:
            raise socket.timeout("no length prefix")
        length = struct.unpack("!H", length_bytes)[0]
        chunks = bytearray()
        while len(chunks) < length:
            chunk = sock.recv(min(4096, length - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        return bytes(chunks)


def _query(resolver: str, name: str, qtype: int, timeout: float) -> tuple[dict, list[tuple[str, int, str]]]:
    try:
        packet = _query_udp(resolver, name, qtype, timeout)
        header, answers = _parse_response(packet)
        if header["truncated"]:
            packet = _query_tcp(resolver, name, qtype, timeout)
            header, answers = _parse_response(packet)
        return header, answers
    except socket.timeout:
        return {"rcode": -1, "rcode_name": "timeout", "truncated": False, "ancount": 0}, []
    except OSError as exc:
        return {"rcode": -1, "rcode_name": f"error: {exc}", "truncated": False, "ancount": 0}, []


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def resolve_domain(
    domain: str,
    timeout: float = 8.0,
    resolvers: list[str] | None = None,
) -> tuple[dict[str, list[str]], dict[str, str], str]:
    """Collect DNS records for ``domain``.

    Returns ``(records, statuses, resolver)``. ``records`` maps logical keys
    (``"A"``, ``"MX"``, ``"TXT"``, ``"DMARC"``, ``"DKIM:<selector>"``, …)
    to lists of string values; ``statuses`` maps the same keys to a status
    string (``NOERROR`` / ``NXDOMAIN`` / ``timeout`` / …).
    """
    resolvers = resolvers or system_resolvers()
    resolver = resolvers[0]
    records: dict[str, list[str]] = {}
    statuses: dict[str, str] = {}

    def collect(key: str, qname: str, qtype: int) -> None:
        header, answers = _query(resolver, qname, qtype, timeout)
        statuses[key] = header["rcode_name"]
        vals = [rdata for rtype_name, _rtype, rdata in answers]
        if vals:
            records[key] = vals

    apex_types = {
        "A": QTYPE_A,
        "AAAA": QTYPE_AAAA,
        "NS": QTYPE_NS,
        "MX": QTYPE_MX,
        "TXT": QTYPE_TXT,
        "CAA": QTYPE_CAA,
        "DS": QTYPE_DS,
        "DNSKEY": QTYPE_DNSKEY,
    }
    for key, qtype in apex_types.items():
        collect(key, domain, qtype)

    # DMARC lives at the reserved _dmarc subdomain.
    collect("DMARC", f"_dmarc.{domain}", QTYPE_TXT)

    # DKIM: probe the usual selector subdomains. A miss is never proof of
    # absence — it only means the common selectors are not used.
    for selector in DKIM_SELECTORS:
        collect(f"DKIM:{selector}", f"{selector}._domainkey.{domain}", QTYPE_TXT)

    return records, statuses, resolver


# ---------------------------------------------------------------------------
# Scoring (pure — no network)
# ---------------------------------------------------------------------------

def _mx_pairs(records: dict[str, list[str]]) -> list[tuple[int, str]]:
    pairs: list[tuple[int, str]] = []
    for value in records.get("MX", []):
        parts = value.split(None, 1)
        if not parts:
            continue
        try:
            pref = int(parts[0])
        except ValueError:
            pref = 0
        exchange = parts[1].strip() if len(parts) > 1 else ""
        pairs.append((pref, exchange))
    return pairs


def _is_null_mx(pairs: list[tuple[int, str]]) -> bool:
    """RFC 7505 null MX: ``MX 0 .`` — the domain explicitly has no email."""
    return bool(pairs) and all(exchange in (".", "") for _pref, exchange in pairs)


def _spf_records(records: dict[str, list[str]]) -> list[str]:
    return [t for t in records.get("TXT", []) if t.lstrip().lower().startswith("v=spf1")]


def _dmarc_records(records: dict[str, list[str]]) -> list[str]:
    return [t for t in records.get("DMARC", []) if t.lstrip().lower().startswith("v=dmarc1")]


def _dkim_records(records: dict[str, list[str]]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for key, values in records.items():
        if key.startswith("DKIM:") and any("v=dkim1" in v.lower() for v in values):
            selector = key.split(":", 1)[1]
            found.append((selector, next(v for v in values if "v=dkim1" in v.lower())))
    return found


def _spf_qualifier(spf: str) -> str:
    terms = spf.lower().split()
    for term in reversed(terms):
        if term in ("all", "+all", "-all", "~all", "?all"):
            return term
        if term.endswith("all") and term[:-3] in ("+", "-", "~", "?"):
            return term
    return ""


def _spf_lookup_count(spf: str) -> int:
    terms = spf.lower().split()
    count = 0
    for term in terms:
        if term in ("all", "ip4", "ip6", "a", "mx", "ptr", "include", "exists", "redirect", "exp"):
            if term != "all":
                count += 1
        elif term.startswith(("a:", "mx:", "ptr:", "include:", "exists:", "redirect=")):
            count += 1
    return count


def grade_dns_from_records(
    domain: str,
    records: dict[str, list[str]],
    statuses: dict[str, str],
    resolver: str = "",
) -> DnsResult:
    """Score an already-collected record map. Pure function — no network.

    This is the shared scoring contract with the browser port
    (``gradeDnsFromRecords`` in js/app.js), which feeds the same
    ``records``/``statuses`` shape from DNS-over-HTTPS."""
    checks: list[Check] = []
    records = records or {}
    statuses = statuses or {}

    apex_status = statuses.get("A", "NOERROR")
    if apex_status == "NXDOMAIN":
        return DnsResult(
            domain=domain, url=domain, status="error", resolver=resolver,
            records=records, statuses=statuses,
            checks=[Check("Domain resolution", "error",
                          "NXDOMAIN — the domain does not exist in public DNS.", "DNS", 0)],
            score=0, grade="F", risk="unknown",
            summary="NXDOMAIN — the domain does not exist. No security posture can be measured.",
        )

    has_web = bool(records.get("A") or records.get("AAAA") or records.get("CNAME"))
    if has_web:
        ips = ", ".join((records.get("A") or [])[:4] + (records.get("AAAA") or [])[:4])
        checks.append(Check("Domain resolution", "ok",
                            "The domain resolves to a web address (A/AAAA).",
                            ips or "A/AAAA present", 0))
    else:
        checks.append(Check("Domain resolution", "info",
                            "No A/AAAA web address published — the domain may be mail-only or parked.",
                            "DNS", 0))

    # Name servers
    ns = records.get("NS", [])
    if not ns:
        checks.append(Check("Name servers", "missing",
                            "No NS records returned — the domain has no published delegation.",
                            "NS: (none)", WEIGHTS["Name servers"]))
    elif len(ns) < 2:
        checks.append(Check("Name servers", "weak",
                            "A single authoritative name server — no redundancy if it fails.",
                            "NS: " + ", ".join(ns), 5))
    else:
        checks.append(Check("Name servers", "ok",
                            f"{len(ns)} name servers published — delegation is redundant.",
                            "NS: " + ", ".join(ns[:6]), 0))

    # DNSSEC — DS at the parent is the chain-of-trust signal.
    ds = records.get("DS", [])
    dnskey = records.get("DNSKEY", [])
    if ds:
        checks.append(Check("DNSSEC", "ok",
                            "DS records are published at the parent zone — the domain is DNSSEC-signed.",
                            "DS: " + ", ".join(ds[:3]), 0))
    elif dnskey:
        checks.append(Check("DNSSEC", "ok",
                            "DNSKEY is published at the apex, but no DS was returned — confirm the parent delegation.",
                            "DNSKEY: " + ", ".join(dnskey[:3]), 0))
    else:
        checks.append(Check("DNSSEC", "weak",
                            "No DS or DNSKEY records — DNSSEC is not deployed for this zone.",
                            "DNS", WEIGHTS["DNSSEC"]))

    # MX — context for the email checks. RFC 7505 null MX is handled.
    mx_pairs = _mx_pairs(records)
    null_mx = _is_null_mx(mx_pairs)
    receives_email = bool(mx_pairs) and not null_mx
    if null_mx:
        checks.append(Check("MX", "info",
                            "Null MX (RFC 7505) — the domain explicitly does not accept email.",
                            "MX: 0 .", 0))
    elif mx_pairs:
        checks.append(Check("MX", "ok",
                            f"{len(mx_pairs)} mail exchanger(s) published — the domain receives email.",
                            "MX: " + ", ".join(records["MX"][:4]), 0))
    else:
        checks.append(Check("MX", "info",
                            "No MX records — the domain does not receive email, so the email checks below are informational only.",
                            "MX: (none)", 0))

    # SPF
    spf = _spf_records(records)
    if spf:
        if len(spf) > 1:
            checks.append(Check("SPF", "weak",
                                "Multiple SPF records — RFC 7208 allows exactly one; receivers may treat this as PermError.",
                                "SPF: " + " | ".join(spf[:3]), 5))
        else:
            text = spf[0]
            qualifier = _spf_qualifier(text)
            lookups = _spf_lookup_count(text)
            if qualifier in ("-all", "~all") and lookups == 0 and not receives_email:
                checks.append(Check("SPF", "ok",
                                    "SPF present with a null policy (" + qualifier + ") — appropriate for a domain that sends no mail.",
                                    text[:180], 0))
            elif qualifier == "+all":
                checks.append(Check("SPF", "weak",
                                    "SPF ends in +all — any host is authorized to send as this domain.",
                                    text[:180], WEIGHTS["SPF"]))
            elif qualifier == "?all":
                checks.append(Check("SPF", "weak",
                                    "SPF ends in ?all (neutral) — permissive and easily spoofed; prefer -all.",
                                    text[:180], 5))
            elif lookups > 10:
                checks.append(Check("SPF", "weak",
                                    f"SPF exceeds the RFC 7208 limit of 10 DNS lookups ({lookups}) — receivers may reject it.",
                                    text[:180], 5))
            else:
                checks.append(Check("SPF", "ok",
                                    "SPF present with a safe qualifier (" + (qualifier or "none") + ").",
                                    text[:180], 0))
    elif receives_email:
        checks.append(Check("SPF", "missing",
                            "Email is accepted (MX present) but no SPF record exists — the domain can be spoofed.",
                            "SPF: (none)", WEIGHTS["SPF"]))
    else:
        checks.append(Check("SPF", "info",
                            "No SPF record — not required when the domain does not send or receive email.",
                            "SPF: (none)", 0))

    # DMARC
    dmarc = _dmarc_records(records)
    if dmarc:
        if len(dmarc) > 1:
            checks.append(Check("DMARC", "weak",
                                "Multiple DMARC records — receivers treat this as invalid; keep exactly one.",
                                "DMARC: " + " | ".join(dmarc[:2]), 5))
        else:
            text = dmarc[0]
            policy = ""
            for token in text.lower().split(";"):
                token = token.strip()
                if token.startswith("p="):
                    policy = token[2:].strip()
            if policy == "none":
                checks.append(Check("DMARC", "weak",
                                    "DMARC present but p=none (monitor only) — spoofed mail is delivered; move to quarantine or reject.",
                                    text[:180], 10))
            elif policy in ("quarantine", "reject"):
                checks.append(Check("DMARC", "ok",
                                    f"DMARC present with an enforcement policy (p={policy}).",
                                    text[:180], 0))
            else:
                checks.append(Check("DMARC", "weak",
                                    "DMARC record present but no clear enforcement policy (p=) was found.",
                                    text[:180], 10))
    elif receives_email or spf:
        checks.append(Check("DMARC", "missing",
                            "No DMARC record — spoofed email is delivered without a reported policy.",
                            "_dmarc TXT: (none)", WEIGHTS["DMARC"]))
    else:
        checks.append(Check("DMARC", "info",
                            "No DMARC record — not required when the domain does not handle email.",
                            "_dmarc TXT: (none)", 0))

    # DKIM
    dkim = _dkim_records(records)
    if dkim:
        selectors = ", ".join(s for s, _v in dkim[:5])
        checks.append(Check("DKIM", "ok",
                            f"DKIM keys published on {len(dkim)} common selector(s).",
                            "selectors: " + selectors, 0))
    elif receives_email or spf or dmarc:
        checks.append(Check("DKIM", "weak",
                            "No DKIM key on common selectors. This is not proof of absence — a custom selector may still exist.",
                            "common selectors: (none)", 5))
    else:
        checks.append(Check("DKIM", "info",
                            "No DKIM on common selectors — not required when the domain does not sign email.",
                            "common selectors: (none)", 0))

    # CAA
    caa = records.get("CAA", [])
    if caa:
        restrictive = any('issue ";"' in c for c in caa)
        detail = ("CAA restricts issuance" + (" (issue \";\" — no CA may issue)" if restrictive else "."))
        checks.append(Check("CAA", "ok", detail, "CAA: " + ", ".join(caa[:3]), 0))
    else:
        checks.append(Check("CAA", "weak",
                            "No CAA record — any public CA may issue certificates for this domain.",
                            "CAA: (none)", WEIGHTS["CAA"]))

    score = max(0, 100 - sum(c.deduction for c in checks))
    grade = grade_for(score)
    missing = [c.name for c in checks if c.status == "missing"]
    return DnsResult(
        domain=domain,
        url=domain,
        status="ok",
        resolver=resolver,
        records=records,
        statuses=statuses,
        checks=checks,
        score=score,
        grade=grade,
        risk=risk_for(grade),
        summary=summarize(grade, missing),
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
        return "Strong DNS posture — email-spoofing controls are enforced and the zone is signed."
    if grade == "B":
        return "Good posture with a few gaps. Close the remaining DNS controls." + extra
    if grade == "C":
        return "Notable gaps — attackers get signal here. Prioritize the missing records." + extra
    if grade == "D":
        return "Weak DNS posture. Several anti-spoofing and integrity controls are missing." + extra
    return "Critical DNS posture. Key email and integrity controls are absent." + extra


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def scan_dns(
    domain: str,
    timeout: float = 8.0,
    resolvers: list[str] | None = None,
    allow_private: bool = True,
) -> DnsResult:
    """Validate + scan a domain. ``allow_private`` is accepted for API
    symmetry with the other engines; DNS analysis never connects to the
    target, so it has no private-IP SSRF surface."""
    del allow_private  # no private connection is ever made
    try:
        domain = validate_domain(domain)
    except ValueError as exc:
        return DnsResult(
            domain=domain or "", url=domain or "", status="error", resolver="",
            checks=[Check("domain", "error", str(exc))],
            grade="F", risk="unknown", summary=str(exc),
        )
    try:
        records, statuses, resolver = resolve_domain(domain, timeout=timeout, resolvers=resolvers)
    except Exception as exc:  # noqa: BLE001 — surface resolver failures
        return DnsResult(
            domain=domain, url=domain, status="error", resolver="",
            checks=[Check("domain", "error", f"DNS query failed: {exc}")],
            grade="F", risk="unknown", summary=f"DNS query failed: {exc}",
        )
    return grade_dns_from_records(domain, records, statuses, resolver)


def print_human(result: DnsResult) -> None:
    print(f"\nDomain:      {result.domain}")
    print(f"Resolver:    {result.resolver or '—'}")
    print(f"Score:       {result.score}/100  Grade: {result.grade}  Risk: {result.risk.upper()}")
    print("-" * 72)
    for c in result.checks:
        print(f"[{c.status.upper():7}] {c.name}: {c.detail}")
        if c.evidence:
            print(f"{'':10}evidence: {c.evidence}")
    print(f"Summary: {result.summary}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Grade the DNS security posture of a domain.")
    p.add_argument("domains", nargs="*", help="Target domains (example.com)")
    p.add_argument("-f", "--file", help="File with one domain per line")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--timeout", type=float, default=8.0, help="Per-query timeout in seconds")
    p.add_argument("--resolver", action="append", help="Resolver IP to use (repeatable; default: system)")
    return p.parse_args(argv)


def collect_domains(args: argparse.Namespace) -> list[str]:
    domains = list(args.domains)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            domains.extend(line.strip() for line in fh if line.strip() and not line.lstrip().startswith("#"))
    seen: set[str] = set()
    out: list[str] = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    domains = collect_domains(args)
    if not domains:
        print("Provide at least one domain or --file.", file=sys.stderr)
        return 2
    resolvers = args.resolver or None
    results = [scan_dns(d, timeout=args.timeout, resolvers=resolvers) for d in domains]
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
