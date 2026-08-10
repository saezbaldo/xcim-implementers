#!/usr/bin/env python3
"""Fail closed when obvious credentials or private keys enter the source drop."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".eml",
    ".json",
    ".md",
    ".mjs",
    ".py",
    ".txt",
    ".yml",
    ".yaml",
}
FORBIDDEN_PATTERNS = (
    ("private-key-block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)\b(?:client_secret|access_token|refresh_token|api[_-]?key|password)\b\s*[:=]\s*[\"'][^\"'\r\n]{8,}[\"']"
        ),
    ),
)


def iter_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        if path.suffix.lower() in TEXT_SUFFIXES:
            yield path


def main() -> int:
    findings: list[tuple[Path, int, str, str]] = []
    scanned = 0
    for path in iter_files():
        scanned += 1
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            findings.append((path, 0, "binary-or-non-utf8", "text artifact is not UTF-8"))
            continue
        for line_number, line in enumerate(lines, start=1):
            for label, pattern in FORBIDDEN_PATTERNS:
                if pattern.search(line):
                    findings.append((path, line_number, label, "credential-like material"))

    if findings:
        print("Public artifact security scan failed:", file=sys.stderr)
        for path, line_number, label, detail in findings:
            relative = path.relative_to(ROOT).as_posix()
            print(f"- {relative}:{line_number}: {label}: {detail}", file=sys.stderr)
        return 1

    print(f"Public artifact security scan passed: {scanned} UTF-8 text files checked")
    print("Test-only fixture seeds remain allowed only when explicitly marked *_TEST_ONLY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
