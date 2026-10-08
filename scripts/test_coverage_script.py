# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The coverage gate fails when it cannot read its numbers.

From 2026-09-30 to 2026-10-08 polaris-coverage.sh's `coverage json` failed in CI, its totals came
out empty, the floor comparison crashed, and the empty answer read as "nothing below the floor", so
the step passed without measuring. These tests run a copy of the script in an empty tree against a
stub interpreter that answers every suite with success and plays coverage.py's last steps as each
case needs, and require the script to fail on each way its numbers can go missing. No database,
no suites, no coverage.py.

    python3 -m unittest test_coverage_script      (from scripts/)
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "polaris-coverage.sh"

# `-c` snippets (the totals, the comparison) run on the real interpreter; `import coverage`, every
# suite and the ship tool succeed; combine and json do what STUB_COMBINE and STUB_JSON say.
STUB = """#!/bin/bash
if [ "$1" = "-c" ]; then
    [ "$2" = "import coverage" ] && exit 0
    exec "%(python)s" -I "$@"
fi
if [ "$1 $2" = "-m coverage" ]; then
    case "$3" in
        combine) [ "${STUB_COMBINE:-ok}" = ok ] || { echo "No data to combine" >&2; exit 1; } ;;
        json)
            if [ "${STUB_JSON:-fail}" = fail ]; then
                echo "No source for code: '/tmp/polaris-cli-pkg-x/site/polaris_cli/__init__.py'" >&2
                exit 1
            fi
            printf '%%s' "$STUB_JSON" > "$6" ;;
    esac
fi
exit 0
"""


def totals(lines, statements, branches, num_branches):
    return json.dumps({"totals": {"covered_lines": lines, "num_statements": statements,
                                  "covered_branches": branches, "num_branches": num_branches}})


class TheGateFailsClosed(unittest.TestCase):

    def setUp(self):
        self.tree = pathlib.Path(tempfile.mkdtemp(prefix="polaris-coverage-gate-"))
        self.addCleanup(shutil.rmtree, self.tree, ignore_errors=True)
        for d in ("scripts", "polaris_web", "polaris_cli", "sdk/python", "packages/polaris-oid4vp"):
            (self.tree / d).mkdir(parents=True)
        shutil.copy(SCRIPT, self.tree / "scripts" / "polaris-coverage.sh")
        self.stub = self.tree / "python-stub"
        self.stub.write_text(STUB % {"python": sys.executable})
        self.stub.chmod(0o755)

    def gate(self, **env):
        # Without GITHUB_STEP_SUMMARY: run inside CI's coverage step, the copy would publish its
        # stub numbers in that step's summary.
        clean = {k: v for k, v in os.environ.items()
                 if not k.startswith(("COVERAGE_", "GITHUB_")) and k != "PYTHONPATH"}
        clean.update(POLARIS_TEST_PYTHON=str(self.stub), COVERAGE_FLOOR="86", BRANCH_FLOOR="84")
        clean.update(env)
        return subprocess.run(["bash", str(self.tree / "scripts" / "polaris-coverage.sh")], env=clean,
                              capture_output=True, text=True, timeout=120)

    def test_numbers_over_both_floors_pass(self):
        r = self.gate(STUB_JSON=totals(90, 100, 88, 100))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("statements 90.00% (floor 86%), branches 88.00% (floor 84%)", r.stdout)

    def test_a_number_under_its_floor_fails(self):
        r = self.gate(STUB_JSON=totals(90, 100, 80, 100))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("below its floor (branches)", r.stderr)

    def test_a_failed_json_export_fails(self):
        r = self.gate(STUB_JSON="fail")      # what CI did for eight days
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("coverage json failed", r.stderr)
        self.assertNotIn("== statements", r.stdout)

    def test_a_failed_combine_fails(self):
        r = self.gate(STUB_COMBINE="fail", STUB_JSON=totals(90, 100, 88, 100))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("coverage combine failed", r.stderr)

    def test_a_report_without_totals_fails(self):
        r = self.gate(STUB_JSON="{}")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("totals could not be read", r.stderr)

    def test_a_floor_that_is_not_a_number_fails(self):
        r = self.gate(STUB_JSON=totals(90, 100, 88, 100), BRANCH_FLOOR="eighty-four")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("floors could not be compared", r.stderr)


if __name__ == "__main__":
    unittest.main()
