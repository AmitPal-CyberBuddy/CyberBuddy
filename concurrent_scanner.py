#!/usr/bin/env python3
"""
Concurrent URL scanning — Process multiple URLs in parallel.

Provides ThreadPoolExecutor-based scanning with configurable worker count.
Used by CLI tools to speed up batch operations.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable
import sys


def scan_urls_concurrent(
    urls: list[str],
    scan_func: Callable[[str], Any],
    max_workers: int = 4,
    show_progress: bool = False,
) -> list[Any]:
    """
    Scan multiple URLs concurrently.
    
    Args:
        urls: List of URLs to scan
        scan_func: Function that takes a URL and returns a result
        max_workers: Maximum number of threads (default: 4)
        show_progress: Whether to print progress updates
    
    Returns:
        List of results in the same order as input URLs
    """
    if not urls:
        return []
    
    # Limit workers to number of URLs
    workers = min(max_workers, len(urls))
    results = [None] * len(urls)
    completed = 0
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Submit all tasks with their indices
        futures = {
            executor.submit(scan_func, url): idx
            for idx, url in enumerate(urls)
        }
        
        for future in as_completed(futures):
            idx = futures[future]
            try:
                results[idx] = future.result()
                completed += 1
                if show_progress:
                    pct = (completed / len(urls)) * 100
                    print(f"  [{completed}/{len(urls)}] {pct:.0f}% — {urls[idx]}", file=sys.stderr)
            except Exception as exc:
                if show_progress:
                    print(f"  ERROR [{idx}] {urls[idx]}: {exc}", file=sys.stderr)
                # Leave as None or store error
                results[idx] = None
    
    return results


if __name__ == "__main__":
    # Quick test
    def slow_func(x: str) -> str:
        import time
        time.sleep(0.5)
        return f"processed {x}"
    
    urls = ["url1", "url2", "url3", "url4"]
    print("Testing concurrent scanning...")
    results = scan_urls_concurrent(urls, slow_func, max_workers=2, show_progress=True)
    print(f"Results: {results}")
