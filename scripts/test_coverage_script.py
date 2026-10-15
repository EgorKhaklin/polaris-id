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
# suite and the ship tool succeed; combine and json do what STUB_COMBINE and STUB_JSON say. With
# STUB_LOG set, every invocation is logged there, and with STUB_DATA set, every suite leaves a data
# file the way `coverage run -p` does (the shard cases).
STUB = """#!/bin/bash
[ -n "${STUB_LOG:-}" ] && echo "$*" | tr '\\n' ' ' >> "$STUB_LOG" && echo >> "$STUB_LOG"
if [ "$1" = "-c" ]; then
    [ "$2" = "import coverage" ] && exit 0
    exec "%(python)s" -I "$@"
fi
if [ -n "${STUB_DATA:-}" ] && [ "$1 $2 $3" != "-m coverage erase" ] && [ "$1 $2 $3" != "-m coverage combine" ]; then
    echo data > "${COVERAGE_FILE}.stub.$$.$RANDOM"
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

    def gate(self, *args, **env):
        # Without GITHUB_STEP_SUMMARY: run inside CI's coverage step, the copy would publish its
        # stub numbers in that step's summary.
        clean = {k: v for k, v in os.environ.items()
                 if not k.startswith(("COVERAGE_", "GITHUB_")) and k != "PYTHONPATH"}
        clean.update(POLARIS_TEST_PYTHON=str(self.stub), COVERAGE_FLOOR="86", BRANCH_FLOOR="84")
        clean.update(env)
        return subprocess.run(["bash", str(self.tree / "scripts" / "polaris-coverage.sh"), *args], env=clean,
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



class TheShards(TheGateFailsClosed):
    """2026-10-15: CI runs the suites as three shards (--shard I/3) and combines their data in
    a job of its own (--combine DIR --of 3). The shards must divide the work without losing or
    repeating a suite, and the combination must refuse to measure without every shard."""

    def shard(self, i, n, **env):
        log = self.tree / ("log-%d-%d" % (i, n))
        env.setdefault("STUB_JSON", totals(90, 100, 88, 100))    # 1/1 is the whole run, and gates
        r = self.gate("--shard", "%d/%d" % (i, n), STUB_LOG=str(log), STUB_DATA="1", **env)
        calls = log.read_text().splitlines() if log.exists() else []
        return r, calls

    @staticmethod
    def suites(calls):
        """The suites a run started: everything but coverage's own housekeeping and the -c snippets."""
        return [c for c in calls if not c.startswith(("-c ", "-m coverage erase", "-m coverage combine",
                                                      "-m coverage report", "-m coverage xml",
                                                      "-m coverage json"))]

    def test_the_shards_divide_the_suites_without_losing_or_repeating_one(self):
        r, whole = self.shard(1, 1)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        whole = self.suites(whole)
        ship = [c for c in whole if "polaris-ship.py" in c]
        self.assertEqual(len(ship), 1)
        self.assertNotIn("--part", ship[0])
        parts = []
        for i in (1, 2, 3):
            for f in self.tree.glob(".coverage*"):
                f.unlink()
            r, calls = self.shard(i, 3)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual((self.tree / "coverage-shard.txt").read_text().strip(), "%d/3" % i)
            self.assertNotIn("== combining", r.stdout)
            calls = self.suites(calls)
            ship = [c for c in calls if "polaris-ship.py" in c]
            self.assertEqual(len(ship), 1, "every shard runs its part of the sharded suites")
            self.assertIn("--no-unsharded --part %d/3" % i, ship[0])
            parts += [c for c in calls if "polaris-ship.py" not in c]
        self.assertEqual(sorted(parts), sorted(c for c in whole if "polaris-ship.py" not in c))

    def test_a_shard_with_a_failed_suite_fails(self):
        # The stub fails the one suite shard 1 of 3 starts first, polaris_checks/test_checks.py.
        self.stub.write_text(self.stub.read_text().replace(
            'if [ "$1" = "-c" ]; then', 'case "$*" in *test_checks*) exit 1 ;; esac\nif [ "$1" = "-c" ]; then', 1))
        r, _ = self.shard(1, 3)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("suite failed", r.stderr)
        self.assertFalse((self.tree / "coverage-shard.txt").exists())

    def test_a_shard_that_wrote_no_data_fails(self):
        log = self.tree / "log"
        r = self.gate("--shard", "2/3", STUB_LOG=str(log))     # no STUB_DATA: no data file
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("wrote no data", r.stderr)

    def test_bad_arguments_are_refused(self):
        for args in (["--shard", "0/3"], ["--shard", "4/3"], ["--shard", "x"], ["--combine", "d"],
                     ["--of", "3"] + ["--combine"], ["--combine", "d", "--of", "0"], ["--frob"],
                     ["--combine", "d", "--of", "3", "--shard", "1/3"]):
            r = self.gate(*args)
            self.assertEqual(r.returncode, 2, (args, r.stdout + r.stderr))

    def shards_dir(self, n=3, skip=(), empty=(), marker=None, nodata=()):
        d = pathlib.Path(tempfile.mkdtemp(prefix="shards-", dir=self.tree))
        for i in range(1, n + 1):
            if i in skip:
                continue
            s = d / ("coverage-data-shard-%d" % i)
            s.mkdir(parents=True)
            (s / "coverage-shard.txt").write_text("%s\n" % (marker.get(i) if marker and i in marker else "%d/%d" % (i, n)))
            if i not in nodata:
                (s / (".coverage.host%d.1.2" % i)).write_text("" if i in empty else "data")
        return d

    def combine(self, d, n=3, **env):
        return self.gate("--combine", str(d), "--of", str(n), STUB_JSON=totals(90, 100, 88, 100), **env)

    def test_all_shards_present_combines_and_gates(self):
        r = self.combine(self.shards_dir())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("shard 3/3: 1 data file(s)", r.stdout)
        self.assertIn("statements 90.00% (floor 86%), branches 88.00% (floor 84%)", r.stdout)
        self.assertEqual(sorted(p.name for p in self.tree.glob(".coverage.host*")),
                         [".coverage.host1.1.2", ".coverage.host2.1.2", ".coverage.host3.1.2"])

    def test_the_floors_still_apply_after_combining(self):
        r = self.gate("--combine", str(self.shards_dir()), "--of", "3", STUB_JSON=totals(80, 100, 88, 100))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("below its floor (statements)", r.stderr)

    def test_a_missing_shard_fails(self):
        r = self.combine(self.shards_dir(skip=(2,)))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("coverage shard 2 of 3 is missing", r.stderr)
        self.assertNotIn("== statements", r.stdout)

    def test_a_shard_without_data_fails(self):
        r = self.combine(self.shards_dir(nodata=(3,)))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("coverage shard 3 of 3 holds no data file", r.stderr)

    def test_an_empty_data_file_fails(self):
        r = self.combine(self.shards_dir(empty=(1,)))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("is empty", r.stderr)

    def test_a_shard_from_another_split_fails(self):
        r = self.combine(self.shards_dir(marker={2: "2/4"}))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("carries the marker '2/4'", r.stderr)
        r = self.combine(self.shards_dir(n=2), n=3)
        self.assertEqual(r.returncode, 1)

    def test_a_failed_combine_still_fails(self):
        r = self.combine(self.shards_dir(), STUB_COMBINE="fail")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("coverage combine failed", r.stderr)


if __name__ == "__main__":
    unittest.main()
