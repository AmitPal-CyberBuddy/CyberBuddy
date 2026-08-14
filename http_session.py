#!/usr/bin/env python3
"""
HTTP Session Pool for CyberBuddy — Connection pooling, DNS caching, and reuse.

This module provides:
- Persistent HTTP/HTTPS connections via a global session pool
- DNS result caching with TTL (default 300s)
- SSL context reuse across requests
- Thread-safe singleton pattern
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
import urllib.request
from threading import Lock
from typing import NamedTuple


class _DNSCacheEntry(NamedTuple):
    """DNS lookup result with expiration."""
    ips: list[str]
    expires_at: float


# DNS cache: hostname → _DNSCacheEntry
_dns_cache: dict[str, _DNSCacheEntry] = {}
_dns_lock = Lock()
DNS_TTL = 300  # seconds


def dns_resolve(host: str) -> list[str]:
    """
    Resolve a hostname to IPs with caching.
    
    Returns a list of IP addresses. Cached results are reused for DNS_TTL seconds.
    Raises socket.gaierror if resolution fails.
    """
    now = time.time()
    
    # Check cache
    with _dns_lock:
        if host in _dns_cache:
            entry = _dns_cache[host]
            if now < entry.expires_at:
                return entry.ips
    
    # Resolve (blocking, but called infrequently due to cache)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = list({info[4][0] for info in infos})
        if not ips:
            raise socket.gaierror(f"cannot resolve {host}")
    except socket.gaierror:
        raise
    
    # Cache result
    with _dns_lock:
        _dns_cache[host] = _DNSCacheEntry(ips, now + DNS_TTL)
    
    return ips


def clear_dns_cache() -> None:
    """Clear the DNS cache. Useful for testing."""
    with _dns_lock:
        _dns_cache.clear()


def _check_connect_ip(ip: str, allow_private: bool) -> None:
    """Re-validate the address we are actually about to connect to.

    Closes the DNS TOCTOU window: validate_target() resolves the hostname to
    decide whether a target is allowed, but urllib then resolves it again
    independently. A hostile resolver can answer public for the check and
    private for the fetch (classic DNS rebinding). Checking here means the
    guard applies to the address the socket really uses.
    """
    import ipaddress

    from clickjacking_validator import _ip_block_reason

    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return
    reason = _ip_block_reason(parsed, allow_private=allow_private)
    if reason:
        raise ValueError(f"blocked scan target ({reason}): {ip}")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that validates each resolved address before connecting."""

    allow_private = True

    def connect(self):  # noqa: D102
        for info in socket.getaddrinfo(self.host, self.port, proto=socket.IPPROTO_TCP):
            _check_connect_ip(info[4][0], self.allow_private)
        super().connect()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection with the same connect-time address validation."""

    allow_private = True

    def connect(self):  # noqa: D102
        for info in socket.getaddrinfo(self.host, self.port, proto=socket.IPPROTO_TCP):
            _check_connect_ip(info[4][0], self.allow_private)
        super().connect()


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, allow_private: bool):
        super().__init__()
        self._allow_private = allow_private

    def http_open(self, req):  # noqa: D102
        allow_private = self._allow_private

        class _Conn(_PinnedHTTPConnection):
            pass

        _Conn.allow_private = allow_private
        return self.do_open(_Conn, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, ctx: ssl.SSLContext, allow_private: bool):
        super().__init__(context=ctx)
        self._allow_private = allow_private
        self._ctx = ctx

    def https_open(self, req):  # noqa: D102
        allow_private = self._allow_private
        ctx = self._ctx

        class _Conn(_PinnedHTTPSConnection):
            pass

        _Conn.allow_private = allow_private
        return self.do_open(_Conn, req, context=ctx)


class _SessionPool:
    """
    Global HTTP session pool with connection reuse.

    Maintains one SSL context per ``insecure`` setting and one opener per
    ``(insecure, allow_private)`` pair, avoiding repeated SSL context
    creation.

    Why the opener key includes ``allow_private``
    ---------------------------------------------
    Each opener bakes in a ``SafeRedirect`` handler that closes over
    ``allow_private``. Keying the cache on ``insecure`` alone meant the
    FIRST caller in a process decided the redirect policy for every later
    caller — so a scan requesting ``allow_private=False`` could be handed
    an opener that happily follows a redirect into RFC1918/loopback.
    Keep both values in the key.
    """

    def __init__(self):
        self._openers: dict[tuple[bool, bool], urllib.request.OpenerDirector] = {}
        self._contexts: dict[bool, ssl.SSLContext] = {}
        self._lock = Lock()

    def _make_ssl_context(self, insecure: bool) -> ssl.SSLContext:
        """Create or return a cached SSL context."""
        ctx = self._contexts.get(insecure)
        if ctx is None:
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._contexts[insecure] = ctx
        return ctx

    def get_opener(self, insecure: bool, allow_private: bool) -> urllib.request.OpenerDirector:
        """
        Get an opener (handler set) for HTTP requests.

        Reuses SSL contexts and handlers across calls to minimize
        initialization overhead. Openers are cached per
        ``(insecure, allow_private)`` so the redirect guard always matches
        the policy the caller asked for.
        """
        key = (bool(insecure), bool(allow_private))
        with self._lock:
            opener = self._openers.get(key)
            if opener is None:
                ctx = self._make_ssl_context(key[0])
                opener = self._build_opener(ctx, key[1])
                self._openers[key] = opener
            return opener
    
    @staticmethod
    def _build_opener(ctx: ssl.SSLContext, allow_private: bool) -> urllib.request.OpenerDirector:
        """Build an opener with redirect validation and connect-time IP checks."""
        # Import here to avoid circular dependency
        from clickjacking_validator import validate_target

        class SafeRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                validate_target(newurl, allow_private=allow_private)
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        return urllib.request.build_opener(
            SafeRedirect,
            _PinnedHTTPHandler(allow_private),
            _PinnedHTTPSHandler(ctx, allow_private),
        )
    
    def clear(self) -> None:
        """Clear cached openers and contexts. Useful for testing."""
        with self._lock:
            self._openers.clear()
            self._contexts.clear()


# Global singleton
_session_pool = _SessionPool()


def get_session_pool() -> _SessionPool:
    """Get the global HTTP session pool."""
    return _session_pool


if __name__ == "__main__":
    # Quick test
    print("Testing DNS cache...")
    ips1 = dns_resolve("github.com")
    print(f"First resolve:  {ips1}")
    
    ips2 = dns_resolve("github.com")
    print(f"Cached resolve: {ips2}")
    print(f"Same result: {ips1 == ips2}")
    
    print("\nTesting session pool...")
    pool = get_session_pool()
    opener_a = pool.get_opener(False, True)
    opener_b = pool.get_opener(False, True)
    print(f"Openers are same object: {opener_a is opener_b}")

    opener_c = pool.get_opener(False, False)
    print(f"allow_private=False gets its own opener: {opener_a is not opener_c}")
