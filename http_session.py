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

import socket
import ssl
import time
import urllib.request
from functools import lru_cache
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


class _SessionPool:
    """
    Global HTTP session pool with connection reuse.
    
    Maintains a single SSL context and opener per insecure setting,
    avoiding repeated SSL context creation.
    """
    
    def __init__(self):
        self._secure_opener = None
        self._insecure_opener = None
        self._secure_ctx = None
        self._insecure_ctx = None
        self._lock = Lock()
    
    def _make_ssl_context(self, insecure: bool) -> ssl.SSLContext:
        """Create or return a cached SSL context."""
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx
    
    def get_opener(self, insecure: bool, allow_private: bool) -> urllib.request.OpenerDirector:
        """
        Get an opener (handler set) for HTTP requests.
        
        Reuses SSL contexts and handlers across calls to minimize
        initialization overhead.
        """
        with self._lock:
            if insecure:
                if self._insecure_opener is None:
                    self._insecure_ctx = self._make_ssl_context(True)
                    self._insecure_opener = self._build_opener(self._insecure_ctx, allow_private)
                return self._insecure_opener
            else:
                if self._secure_opener is None:
                    self._secure_ctx = self._make_ssl_context(False)
                    self._secure_opener = self._build_opener(self._secure_ctx, allow_private)
                return self._secure_opener
    
    @staticmethod
    def _build_opener(ctx: ssl.SSLContext, allow_private: bool) -> urllib.request.OpenerDirector:
        """Build an opener with redirect validation."""
        # Import here to avoid circular dependency
        from clickjacking_validator import validate_target
        
        class SafeRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                validate_target(newurl, allow_private=allow_private)
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        
        return urllib.request.build_opener(
            SafeRedirect,
            urllib.request.HTTPSHandler(context=ctx),
        )
    
    def clear(self) -> None:
        """Clear cached openers and contexts. Useful for testing."""
        with self._lock:
            self._secure_opener = None
            self._insecure_opener = None
            self._secure_ctx = None
            self._insecure_ctx = None


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
