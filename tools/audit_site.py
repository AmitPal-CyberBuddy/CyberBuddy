#!/usr/bin/env python3
"""Fail when a published HTML page contains a broken local link or fragment."""

from __future__ import annotations

import argparse
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references: list[str] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        identifier = values.get("id")
        if identifier:
            self.ids.add(identifier)
        for name in ("href", "src"):
            value = values.get(name)
            if value:
                self.references.append(value)


def audit(root: Path) -> list[str]:
    root = root.resolve()
    pages: dict[Path, PageParser] = {}
    for path in root.rglob("*.html"):
        parser = PageParser()
        parser.feed(path.read_text(encoding="utf-8", errors="replace"))
        pages[path.resolve()] = parser

    failures: list[str] = []
    for page, parser in pages.items():
        for raw in parser.references:
            if raw.startswith(("https:", "http:", "mailto:", "data:", "//")):
                continue
            parts = urlsplit(raw)
            path_text = unquote(parts.path)
            if path_text.startswith("/"):
                # Published pages are mounted at /CyberBuddy/. Strip that
                # known project prefix, then resolve from the artifact root.
                path_text = path_text.removeprefix("/CyberBuddy/").lstrip("/")
                target = root / path_text
            else:
                target = page.parent / path_text if path_text else page
            target = target.resolve()
            try:
                target.relative_to(root)
            except ValueError:
                failures.append(f"{page.relative_to(root)} -> {raw} (escapes site root)")
                continue
            if path_text.endswith("/") or (target.exists() and target.is_dir()):
                target /= "index.html"
            if not target.is_file():
                failures.append(f"{page.relative_to(root)} -> {raw} (missing target)")
                continue
            if parts.fragment and target.suffix.lower() == ".html":
                target_parser = pages.get(target.resolve())
                if target_parser and parts.fragment not in target_parser.ids:
                    failures.append(f"{page.relative_to(root)} -> {raw} (missing fragment)")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default="_site", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        print(f"Site audit failed: directory does not exist: {root}", file=sys.stderr)
        return 2
    pages = list(root.rglob("*.html"))
    if not pages:
        print(f"Site audit failed: no HTML pages found in {root}", file=sys.stderr)
        return 2
    if not (root / "index.html").is_file():
        print(f"Site audit failed: root index.html is missing from {root}", file=sys.stderr)
        return 2

    failures = audit(root)
    if failures:
        print("Broken local links:")
        print("\n".join(f"  {item}" for item in failures))
        return 1
    print(f"Local link audit passed for {root} ({len(pages)} HTML pages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
