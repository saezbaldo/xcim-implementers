#!/usr/bin/env python3
"""Run the published XCIM draft checks from one reproducible command."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
VALIDATOR = TOOLS / "validate_protocol_schemas.py"


def run(label: str, command: list[str]) -> int:
    print(f"\n[xcim-check] {label}")
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode:
        print(f"[xcim-check] FAILED ({completed.returncode}): {label}", file=sys.stderr)
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate XCIM draft schemas and run every published Node vector verifier."
    )
    parser.add_argument(
        "--python-only", action="store_true", help="run schema/fixture validation only"
    )
    parser.add_argument(
        "--node-only", action="store_true", help="run Node vector verifiers only"
    )
    parser.add_argument(
        "--list", action="store_true", help="list checks without executing them"
    )
    args = parser.parse_args()
    if args.python_only and args.node_only:
        parser.error("--python-only and --node-only cannot be combined")

    runners = sorted(TOOLS.glob("verify*.mjs"))
    checks: list[tuple[str, list[str]]] = []
    if not args.node_only:
        checks.append(
            (
                "Python shadow-mode adapter tests",
                [sys.executable, "-m", "unittest", "tools.test_shadow_mode_adapter"],
            )
        )
        checks.append(("Python schema and fixture validator", [sys.executable, str(VALIDATOR)]))
    if not args.python_only:
        checks.extend((f"Node verifier: {path.name}", ["node", str(path)]) for path in runners)

    if args.list:
        for label, command in checks:
            print(f"{label}: {' '.join(command)}")
        return 0

    failures = 0
    for label, command in checks:
        failures += run(label, command) != 0
    if failures:
        print(f"\n[xcim-check] {failures} check(s) failed", file=sys.stderr)
        return 1
    print(f"\n[xcim-check] passed {len(checks)} check(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
