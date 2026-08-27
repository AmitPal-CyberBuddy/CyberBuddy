#!/usr/bin/env python3
"""Run CyberBuddy's complete dependency-free release verification.

This command is the local counterpart to the CI and Pages quality gates. It
runs the stdlib test suite, checks Python and JavaScript syntax, parses project
JSON/XML and JSON-LD metadata, assembles a clean Pages-shaped artifact in a
temporary directory, and audits every local link and fragment.

A Node.js executable is required for JavaScript syntax checking. Real-browser
regression suites remain separate because they require Chromium and
``puppeteer-core``; see ``tests/browser/README.md``.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from audit_site import audit

ROOT = Path(__file__).resolve().parent.parent
TOOL_SLUGS = ("clickjacking", "headers", "cors", "csp", "csrf", "jwt", "dns")
PUBLIC_DIRS = ("methodology", "documentation", "guides", ".well-known")
PUBLIC_FILES = (
    "index.html",
    "404.html",
    "og-cyberbuddy.png",
    "icon-192.png",
    "icon-512.png",
    "manifest.webmanifest",
    "robots.txt",
    "sitemap.xml",
    "humans.txt",
    "llms.txt",
    "LICENSE",
)
JSON_LD_RE = re.compile(
    r'<script\s+type="application/ld\+json"[^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)


def project_files(*patterns: str) -> list[Path]:
    """Return tracked and untracked, non-ignored files matching pathspecs."""
    proc = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--", *patterns],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [ROOT / line for line in proc.stdout.splitlines() if line]


def run(label: str, command: list[str]) -> None:
    print(f"\n[verify] {label}")
    subprocess.run(command, cwd=ROOT, check=True)


def check_python_syntax() -> None:
    paths = project_files("*.py", "**/*.py")
    for path in paths:
        source = path.read_text(encoding="utf-8")
        compile(source, str(path.relative_to(ROOT)), "exec")
    print(f"[verify] Python syntax: {len(paths)} project files")


def check_javascript_syntax() -> None:
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js is required for JavaScript syntax checks")
    paths = project_files("js/*.js", "tests/browser/*.js")
    for path in paths:
        subprocess.run(
            [node, "--check", str(path.relative_to(ROOT))],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )
    print(f"[verify] JavaScript syntax: {len(paths)} project files")


def check_structured_data() -> None:
    json_paths = project_files("*.json", "**/*.json", "*.webmanifest")
    for path in json_paths:
        json.loads(path.read_text(encoding="utf-8"))

    xml_paths = project_files("*.xml", "**/*.xml")
    for path in xml_paths:
        ET.parse(path)

    blocks = 0
    for path in project_files("*.html", "**/*.html"):
        text = path.read_text(encoding="utf-8")
        for index, raw in enumerate(JSON_LD_RE.findall(text), start=1):
            try:
                json.loads(raw)
            except json.JSONDecodeError as exc:
                rel = path.relative_to(ROOT)
                raise ValueError(f"invalid JSON-LD in {rel}, block {index}: {exc}") from exc
            blocks += 1
    print(
        f"[verify] Structured data: {len(json_paths)} JSON/manifest files, "
        f"{len(xml_paths)} XML files, {blocks} JSON-LD blocks"
    )


def copy_tree(source: Path, destination: Path) -> None:
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True)


def assemble_site(destination: Path) -> None:
    """Assemble the same public surface as the Pages workflow, without cache I/O."""
    destination.mkdir(parents=True, exist_ok=True)
    (destination / ".nojekyll").touch()

    for name in PUBLIC_FILES:
        source = ROOT / name
        if source.is_file():
            shutil.copy2(source, destination / name)

    copy_tree(ROOT / "css", destination / "css")
    copy_tree(ROOT / "js", destination / "js")
    (destination / "tools").mkdir(exist_ok=True)
    shutil.copy2(ROOT / "tools" / "index.html", destination / "tools" / "index.html")
    for slug in TOOL_SLUGS:
        copy_tree(ROOT / "tools" / slug, destination / "tools" / slug)
    for name in PUBLIC_DIRS:
        copy_tree(ROOT / name, destination / name)
    copy_tree(ROOT / "cache", destination / "cache")


def check_pages_artifact() -> None:
    with tempfile.TemporaryDirectory(prefix="cyberbuddy-site-") as temp:
        site = Path(temp)
        assemble_site(site)
        failures = audit(site)
        if failures:
            detail = "\n".join(f"  {item}" for item in failures)
            raise RuntimeError(f"assembled-site link audit failed:\n{detail}")
        pages = list(site.rglob("*.html"))
        if not (site / "index.html").is_file() or not pages:
            raise RuntimeError("assembled site is missing its root page")
        for forbidden in ("docs", "tests"):
            if (site / forbidden).exists():
                raise RuntimeError(f"internal path leaked into assembled site: {forbidden}")
        print(f"[verify] Pages artifact: {len(pages)} HTML pages, local links passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="skip the unittest suite (useful only when tests already ran in the same job)",
    )
    args = parser.parse_args()

    try:
        if not args.skip_tests:
            run("stdlib unit tests", [sys.executable, "-m", "unittest", "test_engines.py", "-v"])
        check_python_syntax()
        check_javascript_syntax()
        check_structured_data()
        check_pages_artifact()
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"\n[verify] FAILED: {exc}", file=sys.stderr)
        return 1

    print("\n[verify] PASS — tests, syntax, structured data, and Pages links are clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
