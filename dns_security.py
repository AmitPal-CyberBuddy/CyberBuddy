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
import math
import secrets
import socket
import struct
import sys
from dataclasses import asdict, dataclass, field
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
    # Machine-readable failure detail for ungraded results. This mirrors the
    # browser grader and avoids forcing API/CLI consumers to parse `summary`.
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Domain input handling
# ---------------------------------------------------------------------------

def normalize_domain(raw: str) -> str:
    """Turn pasted input (URL, trailing dot, whitespace) into a lowercase
    FQDN without a trailing dot. Raises ValueError with a human message."""
    value = (raw or "").strip()
    quote_pairs = {'"': '"', "'": "'", "“": "”", "‘": "’"}
    if len(value) >= 2 and quote_pairs.get(value[0]) == value[-1]:
        value = value[1:-1].strip()
    if not value:
        raise ValueError("Enter a domain to analyze.")
    # Strip an HTTP(S) URL only after rejecting credentials and malformed
    # ports. Silently accepting another scheme or dropping userinfo would make
    # the CLI disagree with the browser validator and could conceal a secret.
    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Enter a bare domain or an http(s) URL, such as example.com.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Remove username/password credentials before analyzing the domain.")
        try:
            host, _port = parsed.hostname, parsed.port
        except ValueError as exc:
            raise ValueError("Enter a valid domain, such as example.com.") from exc
        if not host:
            raise ValueError("Enter a valid domain, such as example.com.")
        value = host
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    value = value.strip().rstrip(".")
    if not value:
        raise ValueError("Enter a domain to analyze.")
    # Bracketed IPv6 -> reject below as an IP.
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    # Port suffix? Strip a syntactically valid port — a host:port paste should
    # still resolve, but an out-of-range value must not be silently discarded.
    if ":" in value and value.count(":") == 1:
        maybe_host, maybe_port = value.rsplit(":", 1)
        if maybe_port.isdigit():
            if int(maybe_port) > 65535:
                raise ValueError("Enter a valid domain and port (0-65535).")
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
        if not label.isascii() or not label.replace("-", "").isalnum():
            raise ValueError(f"Invalid characters in label '{label}'.")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("Domain labels cannot start or end with a hyphen.")
    tld = labels[-1]
    if not (
        (2 <= len(tld) <= 63 and tld.isalpha())
        or (tld.startswith("xn--") and 6 <= len(tld) <= 63)
    ):
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
    """Encode a DNS name without silently discarding malformed bytes."""
    labels = name.rstrip(".").split(".")
    out = bytearray()
    wire_length = 1
    for label in labels:
        try:
            raw = label.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("DNS labels must be ASCII after IDNA normalization") from exc
        if not raw or len(raw) > 63:
            raise ValueError("DNS labels must contain between 1 and 63 bytes")
        wire_length += len(raw) + 1
        if wire_length > 255:
            raise ValueError("encoded DNS name exceeds 255 bytes")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _build_query(name: str, qtype: int, ident: int | None = None) -> bytes:
    ident = secrets.randbits(16) if ident is None else ident
    flags = 0x0100  # RD=1 (recursion desired)
    header = struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", qtype, 1)
    return header + question


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode one DNS name and reject malformed compression structures.

    Compression pointers must point backwards. Besides preventing cycles, this
    avoids following attacker-controlled forward pointers into unrelated
    bytes. ``end`` is the first byte after the name in the original stream.
    """
    if offset < 0 or offset >= len(packet):
        raise ValueError("DNS name offset is outside the packet")

    labels: list[str] = []
    cursor = offset
    end: int | None = None
    seen: set[int] = set()
    expanded_length = 1  # terminating root label

    while True:
        if cursor >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[cursor]
        label_kind = length & 0xC0

        if label_kind == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= cursor:
                raise ValueError("DNS compression pointer must point backwards")
            if pointer in seen:
                raise ValueError("cyclic DNS compression pointer")
            if pointer >= len(packet):
                raise ValueError("DNS compression pointer is outside the packet")
            seen.add(pointer)
            if end is None:
                end = cursor + 2
            cursor = pointer
            continue

        if label_kind:
            raise ValueError("reserved DNS label encoding")
        if length == 0:
            if end is None:
                end = cursor + 1
            break
        if length > 63:
            raise ValueError("DNS label exceeds 63 bytes")

        label_start = cursor + 1
        label_end = label_start + length
        if label_end > len(packet):
            raise ValueError("truncated DNS label")
        try:
            label = packet[label_start:label_end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("non-ASCII DNS label") from exc
        labels.append(label)
        expanded_length += length + 1
        if expanded_length > 255:
            raise ValueError("expanded DNS name exceeds 255 bytes")
        cursor = label_end

    return ".".join(labels), end


def _parse_txt(rdata: bytes) -> str:
    out: list[str] = []
    offset = 0
    while offset < len(rdata):
        length = rdata[offset]
        offset += 1
        if offset + length > len(rdata):
            raise ValueError("truncated DNS TXT segment")
        out.append(rdata[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return "".join(out)


def _parse_rdata(qtype: int, packet: bytes, rdata_off: int, rdlength: int) -> str:
    rdata_end = rdata_off + rdlength
    if rdata_off < 0 or rdlength < 0 or rdata_end > len(packet):
        raise ValueError("DNS RDATA extends beyond the packet")
    rdata = packet[rdata_off:rdata_end]

    if qtype == QTYPE_A:
        if rdlength != 4:
            raise ValueError("invalid A record length")
        return socket.inet_ntop(socket.AF_INET, rdata)
    if qtype == QTYPE_AAAA:
        if rdlength != 16:
            raise ValueError("invalid AAAA record length")
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if qtype in (QTYPE_NS, QTYPE_CNAME, QTYPE_PTR):
        value, end = _read_name(packet, rdata_off)
        if end != rdata_end:
            raise ValueError("invalid compressed-name RDATA length")
        return value
    if qtype == QTYPE_MX:
        if rdlength < 3:
            raise ValueError("invalid MX record length")
        pref = struct.unpack("!H", rdata[:2])[0]
        exchange, end = _read_name(packet, rdata_off + 2)
        if end != rdata_end:
            raise ValueError("invalid MX exchange length")
        return f"{pref} {exchange or '.'}"
    if qtype == QTYPE_TXT:
        return _parse_txt(rdata)
    if qtype == QTYPE_SOA:
        mname, cursor = _read_name(packet, rdata_off)
        rname, cursor = _read_name(packet, cursor)
        if cursor + 20 != rdata_end:
            raise ValueError("invalid SOA record length")
        serial, _refresh, _retry, _expire, _minimum = struct.unpack(
            "!IIIII", packet[cursor:cursor + 20]
        )
        return f"{mname} {rname} {serial}"
    if qtype == QTYPE_CAA:
        if rdlength < 2:
            raise ValueError("invalid CAA record length")
        flags = rdata[0]
        tag_len = rdata[1]
        if 2 + tag_len > rdlength:
            raise ValueError("invalid CAA tag length")
        tag = rdata[2:2 + tag_len].decode("ascii", "strict")
        value = rdata[2 + tag_len:].decode("utf-8", "replace")
        return f'{flags} {tag} "{value}"'
    if qtype == QTYPE_DS:
        if rdlength < 4:
            raise ValueError("invalid DS record length")
        keytag, algorithm, digest_type = struct.unpack("!HBB", rdata[:4])
        return f"{keytag} {algorithm} {digest_type} {rdata[4:].hex().upper()}"
    if qtype == QTYPE_DNSKEY:
        if rdlength < 4:
            raise ValueError("invalid DNSKEY record length")
        flags, protocol, algorithm = struct.unpack("!HBB", rdata[:4])
        return f"flags={flags} protocol={protocol} algorithm={algorithm} keylen={rdlength - 4}"
    return rdata.hex()


def _parse_response(
    packet: bytes,
    *,
    expected_id: int | None = None,
    expected_name: str | None = None,
    expected_qtype: int | None = None,
) -> tuple[dict, list[tuple[str, int, str]]]:
    """Parse and correlate a DNS response with its exact request."""
    if len(packet) < 12:
        raise ValueError("short DNS response")
    ident, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", packet[:12]
    )
    if expected_id is not None and ident != expected_id:
        raise ValueError("DNS transaction ID mismatch")
    if not flags & 0x8000:
        raise ValueError("DNS packet is not a response")
    if (flags >> 11) & 0xF:
        raise ValueError("unexpected DNS opcode")
    if qdcount != 1:
        raise ValueError("DNS response must contain exactly one question")

    offset = 12
    question_name, offset = _read_name(packet, offset)
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    question_type, question_class = struct.unpack("!HH", packet[offset:offset + 4])
    offset += 4
    if question_class != 1:
        raise ValueError("unexpected DNS question class")
    if expected_name is not None and question_name.rstrip(".").lower() != expected_name.rstrip(".").lower():
        raise ValueError("DNS question name mismatch")
    if expected_qtype is not None and question_type != expected_qtype:
        raise ValueError("DNS question type mismatch")

    rcode = flags & 0x000F
    header = {
        "id": ident,
        "rcode": rcode,
        "rcode_name": rcode_name(rcode),
        "truncated": bool(flags & 0x0200),
        "ancount": ancount,
    }
    answers: list[tuple[str, int, str]] = []
    for _ in range(ancount):
        _owner, offset = _read_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS answer header")
        rtype, rclass, _ttl, rdlength = struct.unpack(
            "!HHIH", packet[offset:offset + 10]
        )
        offset += 10
        rdata_off = offset
        offset += rdlength
        if offset > len(packet):
            raise ValueError("truncated DNS answer data")
        if rclass != 1:
            continue
        answers.append((
            QTYPE_NAMES.get(rtype, str(rtype)),
            rtype,
            _parse_rdata(rtype, packet, rdata_off, rdlength),
        ))
    return header, answers


def _socket_addresses(resolver: str, socktype: int) -> list[tuple]:
    """Resolve an IP-literal resolver into IPv4/IPv6 socket addresses."""
    try:
        ipaddress.ip_address(resolver.split("%", 1)[0])
    except ValueError as exc:
        raise ValueError("resolver must be an IP address") from exc
    return socket.getaddrinfo(resolver, 53, socket.AF_UNSPEC, socktype)


def _query_udp(query: bytes, resolver: str, timeout: float = 8.0) -> bytes:
    """Send one connected UDP query and ignore unrelated transaction IDs."""
    expected_id = struct.unpack("!H", query[:2])[0]
    last_error: Exception | None = None
    for family, socktype, proto, _canonname, address in _socket_addresses(
        resolver, socket.SOCK_DGRAM
    ):
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(address)
            sock.send(query)
            for _ in range(16):
                packet = sock.recv(65535)
                if len(packet) >= 2 and struct.unpack("!H", packet[:2])[0] == expected_id:
                    return packet
            raise ValueError("too many unrelated DNS responses")
        except (OSError, ValueError) as exc:
            last_error = exc
        finally:
            sock.close()
    if last_error is not None:
        raise last_error
    raise OSError("no usable resolver address")


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise OSError("DNS TCP connection closed early")
        data.extend(chunk)
    return bytes(data)


def _query_tcp(query: bytes, resolver: str, timeout: float = 8.0) -> bytes:
    last_error: Exception | None = None
    for family, socktype, proto, _canonname, address in _socket_addresses(
        resolver, socket.SOCK_STREAM
    ):
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(address)
            sock.sendall(struct.pack("!H", len(query)) + query)
            length = struct.unpack("!H", _recv_exact(sock, 2))[0]
            if length < 12:
                raise ValueError("short DNS TCP response")
            return _recv_exact(sock, length)
        except (OSError, ValueError) as exc:
            last_error = exc
        finally:
            sock.close()
    if last_error is not None:
        raise last_error
    raise OSError("no usable resolver address")


def _query(
    resolver: str,
    name: str,
    qtype: int,
    timeout: float,
) -> tuple[dict, list[tuple[str, int, str]]]:
    query = _build_query(name, qtype)
    expected_id = struct.unpack("!H", query[:2])[0]
    try:
        packet = _query_udp(query, resolver, timeout)
        if len(packet) < 4:
            raise ValueError("short DNS response")
        if struct.unpack("!H", packet[2:4])[0] & 0x0200:
            packet = _query_tcp(query, resolver, timeout)
        header, answers = _parse_response(
            packet,
            expected_id=expected_id,
            expected_name=name,
            expected_qtype=qtype,
        )
        # A CNAME can legitimately accompany the requested RRset, but it must
        # never be exposed as an A/TXT/etc value in the logical record map.
        answers = [answer for answer in answers if answer[1] == qtype]
        return header, answers
    except socket.timeout:
        return {"rcode": -1, "rcode_name": "TIMEOUT", "truncated": False, "ancount": 0}, []
    except (OSError, ValueError, struct.error) as exc:
        return {
            "rcode": -1,
            "rcode_name": f"ERROR: {exc}",
            "truncated": False,
            "ancount": 0,
        }, []


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
    if timeout <= 0:
        raise ValueError("DNS timeout must be greater than zero")
    configured = list(resolvers or system_resolvers())
    if not configured:
        raise ValueError("at least one DNS resolver is required")
    for resolver in configured:
        try:
            ipaddress.ip_address(resolver.split("%", 1)[0])
        except ValueError as exc:
            raise ValueError(f"resolver must be an IP address: {resolver}") from exc

    records: dict[str, list[str]] = {}
    statuses: dict[str, str] = {}
    contacted: list[str] = []

    def collect(key: str, qname: str, qtype: int) -> list[str]:
        nonlocal configured
        last_header = {"rcode_name": "ERROR: no resolver response"}
        answers: list[tuple[str, int, str]] = []
        for resolver in configured:
            if resolver not in contacted:
                contacted.append(resolver)
            header, candidate_answers = _query(resolver, qname, qtype, timeout)
            last_header, answers = header, candidate_answers
            if header["rcode_name"] in {"NOERROR", "NXDOMAIN"}:
                # Keep a healthy fallback first for the remaining queries.
                configured = [resolver] + [item for item in configured if item != resolver]
                break
        statuses[key] = last_header["rcode_name"]
        vals = [rdata for _rtype_name, _rtype, rdata in answers]
        if vals:
            records[key] = vals
        return vals

    apex_types = {
        "A": QTYPE_A,
        "AAAA": QTYPE_AAAA,
        "NS": QTYPE_NS,
        "MX": QTYPE_MX,
        "TXT": QTYPE_TXT,
        "DS": QTYPE_DS,
        "DNSKEY": QTYPE_DNSKEY,
    }
    for key, qtype in apex_types.items():
        collect(key, domain, qtype)

    # RFC 8659's RelevantCAASet walks from the requested FQDN toward (but not
    # including) the DNS root and uses the first non-empty CAA RRset. Preserve
    # each attempted status so a failed lookup cannot be misreported as an
    # absent policy, and expose the effective owner for report evidence.
    labels = domain.split(".")
    for index in range(len(labels)):
        owner = ".".join(labels[index:])
        key = "CAA" if index == 0 else f"CAA@{owner}"
        values = collect(key, owner, QTYPE_CAA)
        if values:
            if key != "CAA":
                records.pop(key, None)
            records["CAA"] = values
            records["CAA_SOURCE"] = [owner]
            break
        if statuses[key] not in {"NOERROR", "NXDOMAIN"}:
            break

    # DMARC lives at the reserved _dmarc subdomain.
    collect("DMARC", f"_dmarc.{domain}", QTYPE_TXT)

    # DKIM: probe the usual selector subdomains. A miss is never proof of
    # absence — it only means the common selectors are not used.
    for selector in DKIM_SELECTORS:
        collect(f"DKIM:{selector}", f"{selector}._domainkey.{domain}", QTYPE_TXT)

    return records, statuses, ", ".join(contacted)


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
    """Return syntactically recognizable, non-revoked DKIM key records."""
    found: list[tuple[str, str]] = []
    for key, values in records.items():
        if not key.startswith("DKIM:"):
            continue
        for value in values:
            tags = [token.strip() for token in value.split(";") if token.strip()]
            if not tags or tags[0].lower() != "v=dkim1":
                continue
            public_keys = [token[2:].strip() for token in tags if token.lower().startswith("p=")]
            if public_keys and public_keys[-1]:
                found.append((key.split(":", 1)[1], value))
                break
    return found


def _caa_properties(records: dict[str, list[str]]) -> list[tuple[int, str, str]]:
    """Parse the presentation form emitted by the wire decoder.

    Unknown or malformed properties remain non-restrictive rather than earning
    credit merely because some CAA-shaped bytes were returned.
    """
    parsed: list[tuple[int, str, str]] = []
    for record in records.get("CAA", []):
        parts = record.strip().split(None, 2)
        if len(parts) != 3:
            continue
        try:
            flags = int(parts[0], 10)
        except ValueError:
            continue
        if not 0 <= flags <= 255:
            continue
        tag = parts[1].lower()
        value = parts[2].strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        parsed.append((flags, tag, value))
    return parsed


def _spf_qualifier(spf: str) -> str:
    terms = spf.lower().split()
    for term in reversed(terms):
        if term in ("all", "+all", "-all", "~all", "?all"):
            return term
        if term.endswith("all") and term[:-3] in ("+", "-", "~", "?"):
            return term
    return ""


def _spf_lookup_count(spf: str) -> int:
    """Count RFC 7208 section 4.6.4 DNS-interactive terms.

    Qualifiers may prefix any mechanism, while ``a``/``mx`` can carry a CIDR
    suffix. Strip those syntactic parts before classifying the mechanism so a
    hostile record cannot hide lookups behind ``-include`` or ``a/24``.
    """
    count = 0
    for raw_term in spf.lower().split():
        term = raw_term.lstrip("+-~?")
        if term.startswith("redirect="):
            count += 1
            continue
        mechanism = term.split(":", 1)[0].split("/", 1)[0]
        if mechanism in {"a", "mx", "ptr"}:
            count += 1
        elif mechanism in {"include", "exists"} and ":" in term:
            count += 1
    return count


def grade_dns_from_records(
    domain: str,
    records: dict[str, list[str]],
    statuses: dict[str, str] | None = None,
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
        message = "NXDOMAIN — the domain does not exist. No security posture can be measured."
        return DnsResult(
            domain=domain, url=domain, status="error", resolver=resolver,
            records=records, statuses=statuses,
            checks=[Check("Domain resolution", "error",
                          "NXDOMAIN — the domain does not exist in public DNS.", "DNS", 0)],
            score=0, grade="—", risk="unknown", summary=message, error=message,
        )

    # An absent RRset is evidence only when the resolver completed the query.
    # Never turn transport, parser, SERVFAIL or REFUSED failures into scored
    # "missing" records; that would manufacture a posture grade from partial
    # evidence. Missing status keys remain valid for pure fixture callers.
    failed = {
        key: value for key, value in statuses.items()
        if str(value).upper() not in {"NOERROR", "NXDOMAIN"}
    }
    if failed:
        evidence = "; ".join(f"{key}: {value}" for key, value in sorted(failed.items()))
        message = (
            "DNS evidence is incomplete because one or more queries failed; "
            "no posture grade was assigned."
        )
        return DnsResult(
            domain=domain, url=domain, status="error", resolver=resolver,
            records=records, statuses=statuses,
            checks=[Check("DNS queries", "error", message, evidence, 0)],
            score=0, grade="—", risk="unknown", summary=message, error=evidence,
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

    # DNSSEC — a parent DS is the delegation signal, while the apex DNSKEY is
    # the key material it delegates to. Require evidence of both record sets
    # before awarding credit; either one alone is an incomplete deployment.
    ds = records.get("DS", [])
    dnskey = records.get("DNSKEY", [])
    if ds and dnskey:
        checks.append(Check("DNSSEC", "ok",
                            "DS is published at the parent and DNSKEY at the apex — delegation evidence for DNSSEC is present.",
                            "DS: " + ", ".join(ds[:3]) + "; DNSKEY: " + ", ".join(dnskey[:3]), 0))
    elif ds:
        checks.append(Check("DNSSEC", "weak",
                            "DS is published at the parent, but no apex DNSKEY was returned — DNSSEC deployment evidence is incomplete.",
                            "DS: " + ", ".join(ds[:3]), WEIGHTS["DNSSEC"]))
    elif dnskey:
        checks.append(Check("DNSSEC", "weak",
                            "DNSKEY is published at the apex, but no parent DS was returned — the chain of trust is not established.",
                            "DNSKEY: " + ", ".join(dnskey[:3]), WEIGHTS["DNSSEC"]))
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
                                "Multiple SPF records cause a PermError — publish exactly one SPF policy.",
                                "SPF: " + " | ".join(spf[:3]), WEIGHTS["SPF"]))
        else:
            text = spf[0]
            qualifier = _spf_qualifier(text)
            lookups = _spf_lookup_count(text)
            if qualifier == "+all":
                checks.append(Check("SPF", "weak",
                                    "SPF ends in +all — any host is authorized to send as this domain.",
                                    text[:180], WEIGHTS["SPF"]))
            elif lookups > 10:
                checks.append(Check("SPF", "weak",
                                    f"SPF exceeds the RFC 7208 limit of 10 DNS lookups ({lookups}) and can produce PermError.",
                                    text[:180], WEIGHTS["SPF"]))
            elif qualifier == "?all":
                checks.append(Check("SPF", "weak",
                                    "SPF ends in ?all (neutral) — permissive and easily spoofed; prefer -all.",
                                    text[:180], 5))
            elif not qualifier:
                checks.append(Check("SPF", "weak",
                                    "SPF has no all mechanism — unmatched senders receive a neutral result; prefer -all.",
                                    text[:180], 5))
            else:
                checks.append(Check("SPF", "ok",
                                    "SPF present with a restrictive qualifier (" + qualifier + ").",
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
                                "Multiple DMARC records are invalid — publish exactly one policy.",
                                "DMARC: " + " | ".join(dmarc[:2]), WEIGHTS["DMARC"]))
        else:
            text = dmarc[0]
            tags: dict[str, str] = {}
            duplicate_tags: set[str] = set()
            for token in text.lower().split(";"):
                token = token.strip()
                if "=" not in token:
                    continue
                name, value = (part.strip() for part in token.split("=", 1))
                if name in tags:
                    duplicate_tags.add(name)
                tags[name] = value
            policy = tags.get("p", "")
            subdomain_policy = tags.get("sp", "")
            pct_raw = tags.get("pct", "100")
            pct_valid = pct_raw.isascii() and pct_raw.isdigit()
            pct = int(pct_raw) if pct_valid else 0
            pct_valid = pct_valid and 0 <= pct <= 100
            if duplicate_tags:
                checks.append(Check("DMARC", "weak",
                                    "DMARC repeats policy tags and may be rejected as invalid.",
                                    text[:180], 10))
            elif policy == "none":
                checks.append(Check("DMARC", "weak",
                                    "DMARC present but p=none (monitor only) — spoofed mail is delivered; move to quarantine or reject.",
                                    text[:180], 10))
            elif policy not in ("quarantine", "reject"):
                checks.append(Check("DMARC", "weak",
                                    "DMARC record present but no clear enforcement policy (p=) was found.",
                                    text[:180], 10))
            elif not pct_valid:
                checks.append(Check("DMARC", "weak",
                                    "DMARC has an invalid pct value, so enforcement coverage is unclear.",
                                    text[:180], 10))
            elif pct < 100:
                checks.append(Check("DMARC", "weak",
                                    f"DMARC enforces p={policy} for only pct={pct}% of failing mail.",
                                    text[:180], 10 if pct == 0 else 5))
            elif subdomain_policy == "none":
                checks.append(Check("DMARC", "weak",
                                    "DMARC enforces the organizational domain but sp=none leaves subdomains in monitoring mode.",
                                    text[:180], 5))
            else:
                checks.append(Check("DMARC", "ok",
                                    f"DMARC present with an enforcement policy (p={policy}, pct=100).",
                                    text[:180], 0))
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

    # CAA — score the first non-empty RRset from RFC 8659 tree climbing. A
    # record containing only iodef/unknown properties does not restrict
    # issuance; issuewild alone protects wildcard issuance, not ordinary
    # certificates, so neither case can earn full credit.
    caa = records.get("CAA", [])
    caa_source = (records.get("CAA_SOURCE") or [domain])[0]
    caa_properties = _caa_properties(records)
    issue = [prop for prop in caa_properties if prop[1] == "issue"]
    issuewild = [prop for prop in caa_properties if prop[1] == "issuewild"]
    location = " at " + caa_source
    inherited = caa_source.rstrip(".").lower() != domain.rstrip(".").lower()
    if issue:
        deny_all = all(not value.split(";", 1)[0].strip() for _flags, _tag, value in issue)
        detail = "CAA" + (" inherited from " + caa_source if inherited else "") + " restricts certificate issuance"
        if deny_all:
            detail += " (empty issue issuer — no CA may issue)"
        checks.append(Check("CAA", "ok", detail + ".",
                            "CAA" + location + ": " + ", ".join(caa[:3]), 0))
    elif issuewild:
        checks.append(Check("CAA", "weak",
                            "CAA" + (" inherited from " + caa_source if inherited else "") +
                            " restricts wildcard issuance only; ordinary certificate issuance remains unrestricted.",
                            "CAA" + location + ": " + ", ".join(caa[:3]), 3))
    elif caa:
        checks.append(Check("CAA", "weak",
                            "CAA records are present but contain no issue property, so ordinary certificate issuance is unrestricted.",
                            "CAA" + location + ": " + ", ".join(caa[:3]), WEIGHTS["CAA"]))
    else:
        checks.append(Check("CAA", "weak",
                            "No CAA record was found on the domain or its parent labels — any public CA may issue certificates for it.",
                            "CAA tree: (none)", WEIGHTS["CAA"]))

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
            grade="—", risk="unknown", summary=str(exc), error=str(exc),
        )
    try:
        records, statuses, resolver = resolve_domain(domain, timeout=timeout, resolvers=resolvers)
    except Exception as exc:  # noqa: BLE001 — surface resolver failures
        message = f"DNS query failed: {exc}"
        return DnsResult(
            domain=domain, url=domain, status="error", resolver="",
            checks=[Check("domain", "error", message)],
            grade="—", risk="unknown", summary=message, error=message,
        )
    return grade_dns_from_records(domain, records, statuses, resolver)


def print_human(result: DnsResult) -> None:
    print(f"\nDomain:      {result.domain}")
    print(f"Resolver:    {result.resolver or '—'}")
    score = f"{result.score}/100" if result.status == "ok" else "—"
    print(f"Score:       {score}  Grade: {result.grade}  Risk: {result.risk.upper()}")
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
            domains.extend(
                line.strip() for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            )
    seen: set[str] = set()
    normalized: list[str] = []
    for raw in domains:
        domain = validate_domain(raw)
        if domain not in seen:
            seen.add(domain)
            normalized.append(domain)
    return normalized


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        print("Invalid timeout: use a finite value greater than zero.", file=sys.stderr)
        return 2
    if args.resolver:
        try:
            for resolver in args.resolver:
                ipaddress.ip_address(resolver.split("%", 1)[0])
        except ValueError:
            print(f"Invalid resolver: {resolver} is not an IP address.", file=sys.stderr)
            return 2
    try:
        domains = collect_domains(args)
    except (OSError, UnicodeError) as exc:
        print(f"Could not read domain file: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Invalid domain: {exc}", file=sys.stderr)
        return 2
    if not domains:
        print("Provide at least one domain or --file.", file=sys.stderr)
        return 2

    results = [
        scan_dns(domain, timeout=args.timeout, resolvers=args.resolver or None)
        for domain in domains
    ]
    if args.json:
        print(json.dumps([result.to_dict() for result in results], indent=2))
    else:
        for result in results:
            print_human(result)
        print()
    if any(result.status != "ok" or result.risk == "high" for result in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
