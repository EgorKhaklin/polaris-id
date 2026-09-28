# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""
run.py — the check runner. One command, no apparatus.

    python3 -m polaris_checks.run            # human-readable; exit 1 on any FAIL
    python3 -m polaris_checks.run --json     # machine-readable

One entry point for the invariant layer: it runs every check
in polaris_checks.checks and reports. Exit code is non-zero iff any check FAILs,
so it gates CI directly.
"""

from __future__ import annotations

import json
import pathlib
import sys

from .checks import run_all

# The repo root is two levels up from this file (polaris_checks/run.py).
_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def main(argv: list[str]) -> int:
    as_json = "--json" in argv[1:]
    findings = run_all(_REPO_ROOT)
    fails = [f for f in findings if f.level == "FAIL"]
    warns = [f for f in findings if f.level == "WARN"]

    if as_json:
        print(json.dumps({
            "findings": [{"level": f.level, "check": f.check, "message": f.message} for f in findings],
            "fail": len(fails), "warn": len(warns), "ok": len(findings) - len(fails) - len(warns),
        }, indent=2))
    else:
        print("polaris-checks")
        for f in findings:
            print(f)
        print(f"\n  {len(findings) - len(fails) - len(warns)} ok · {len(warns)} warn · {len(fails)} fail")
        print("  READY" if not fails else "  BLOCKED — resolve the failures above")

    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
