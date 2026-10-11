# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""A harness that stops early must not exit 0, on bash 3.2 as on bash 5.2.

Every lab/interop/*/run.sh runs under `set -euo pipefail` with an EXIT trap whose last command
succeeds. After a `set -u` failure, macOS /bin/bash 3.2.57 exits with the trap's own status, and
`$?` inside the trap is already 0, so the run exited 0; Linux bash 5.2 exits 1. The harnesses now
hand their status to exit_trap, which fails any run that did not reach the line before its final
`exit "$fail"` (finished=1).

The skeleton runs under /bin/bash: 3.2.57 on macOS, 5.2 on the Linux CI runners. The static half
holds each harness to the same code, so one that drops it fails here on either.
"""
import pathlib
import re
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent

HEADER = '''# A run that stops before its last line fails, whatever its EXIT trap's last command returns:
# after a set -u failure, bash 3.2 (macOS /bin/bash) exits with the trap's own status, and $? in
# the trap is already 0. Every trap below hands its status to exit_trap.
finished=0
exit_trap() {  # $1 the run's exit status: kept, unless the run stopped early with 0
  local rc="$1"
  if [ "$finished" != 1 ] && [ "$rc" = 0 ]; then rc=1; fi
  exit "$rc"
}
'''

# Harness-shaped: the header, a cleanup whose last command succeeds, the body, the sentinel, and
# the final exit "$fail".
SKELETON = '''#!/bin/bash
set -euo pipefail
''' + HEADER + '''cleanup() { echo "cleanup ran"; false || true; }
trap 'exit_rc=$?; cleanup; echo "done"; exit_trap "$exit_rc"' EXIT
fail=0
%s
finished=1
exit "$fail"
'''

TRAP = re.compile(r"^\s*trap (.+) EXIT\s*$", re.M)
WRAPPED = re.compile(r"""^'exit_rc=\$\?; [^']+; exit_trap "\$exit_rc"'$""")


def harnesses():
    return sorted(p for p in HERE.glob("*/run.sh") if TRAP.search(p.read_text()))


class SkeletonExits(unittest.TestCase):
    def run_body(self, body):
        with tempfile.TemporaryDirectory() as d:
            script = pathlib.Path(d) / "run.sh"
            script.write_text(SKELETON % body)
            r = subprocess.run(["/bin/bash", str(script)], capture_output=True, text=True,
                               env={"PATH": "/usr/bin:/bin"}, timeout=30)
        self.assertIn("done", r.stdout, "the EXIT trap did not run: %r" % (r.stdout + r.stderr))
        return r.returncode

    def test_unset_variable_exits_1(self):
        self.assertEqual(self.run_body('echo "$UNSET_VAR"'), 1)

    def test_failing_command_exits_1(self):
        self.assertEqual(self.run_body("false"), 1)

    def test_a_failed_control_exits_1(self):
        self.assertEqual(self.run_body("fail=1"), 1)

    def test_an_explicit_status_is_kept(self):
        self.assertEqual(self.run_body("exit 2"), 2)

    def test_a_clean_run_exits_0(self):
        self.assertEqual(self.run_body("echo ok"), 0)


class EveryHarnessCarriesIt(unittest.TestCase):
    def test_the_sixteen_are_found(self):
        self.assertEqual(len(harnesses()), 16, [p.parent.name for p in harnesses()])

    def test_each_harness(self):
        for p in harnesses():
            with self.subTest(harness=p.parent.name):
                s = p.read_text()
                self.assertIn("set -euo pipefail\n" + HEADER, s,
                              "the exit_trap block, verbatim, right after set -euo pipefail")
                for cmd in TRAP.findall(s):
                    self.assertRegex(cmd, WRAPPED, "an EXIT trap that does not end in exit_trap")
                tail = [ln for ln in s.splitlines() if ln.strip()][-2:]
                self.assertEqual(tail, ["finished=1", 'exit "$fail"'])
                self.assertEqual(s.count("finished=1"), 1)


if __name__ == "__main__":
    unittest.main()
