# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The trigger refusal drill credits a catch reported inside a subTest.

The drill confirms a catch by running the failed tests again, alone. From 2026-10-05 to 2026-10-08
it read the failed tests' names only from lines ending in ")", and unittest ends a subTest
failure with "[the subtest's message]". When an unrelated flaky test failed in the same run, only
that test ran again, it passed, and a refusal its own test had caught was reported UNTESTED,
failing CI on a different refusal each time. These tests run real unittest on a throwaway suite
shaped like that run. No database.

    python3 -m unittest test_trigger_drill      (from scripts/)
"""
import contextlib
import importlib.util
import io
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location("trigger_drill", HERE / "polaris-trigger-mutation-drill.py")
drill = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drill)

# A refusal deleted, so its subTest goes red on every run; a test that goes red on its first run
# only, as the C1 privilege-boundary tests did beside it; and one that passes.
SUITE = '''
import os, unittest
MARK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flaked")

class Refusals(unittest.TestCase):
    def test_a_revocation_cannot_be_backdated(self):
        for message in ("cannot be un-set", "cannot be moved earlier"):
            with self.subTest(message):
                self.assertNotEqual(message, os.environ.get("DELETED_REFUSAL"))

class Boundary(unittest.TestCase):
    def test_counts(self):
        if os.environ.get("FLAKY") and not os.path.exists(MARK):
            open(MARK, "w").close()
            self.fail("red once")

    def test_passes(self):
        pass
'''


def _env(**extra):
    """The child's environment, without coverage's subprocess hook: the throwaway suite lives in a
    temporary directory, and data recorded for it outlives the directory, which makes CI's
    `coverage json` fail with "No source for code" (and polaris-coverage.sh fail closed)."""
    env = {k: v for k, v in os.environ.items() if k != "COVERAGE_PROCESS_START"}
    env.update(extra)
    return env


class TheDrillReadsSubtestFailures(unittest.TestCase):

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="polaris-trigger-drill-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        (self.root / "polaris_web").mkdir()
        (self.root / "polaris_web" / "fake_suite.py").write_text(SUITE)
        real_root = drill.ROOT
        drill.ROOT = self.root               # the drill runs suites from ROOT/polaris_web
        self.addCleanup(setattr, drill, "ROOT", real_root)

    def catches(self, **env):
        with contextlib.redirect_stdout(io.StringIO()):     # its "(flaky: ...)" note
            return drill._suite_catches("fake_suite", _env(**env))

    def test_a_subtest_failure_is_named(self):
        r = drill.polaris_bounded_run.run(
            [sys.executable, "-m", "unittest", "fake_suite"], cwd=str(self.root / "polaris_web"),
            env=_env(DELETED_REFUSAL="cannot be moved earlier", FLAKY="1"),
            capture_output=True, text=True)
        expected = ["fake_suite.Boundary.test_counts",
                    "fake_suite.Refusals.test_a_revocation_cannot_be_backdated"]
        if sys.version_info < (3, 11):       # unittest named the class alone before 3.11
            expected = [e.rsplit(".", 1)[0] for e in expected]
        self.assertEqual(drill._failed_tests(r.stderr), expected, r.stderr)

    def test_a_catch_beside_a_flaky_failure_is_credited(self):
        # What CI met: the subTest catch and the flaky test fail together, the flaky one alone
        # passes. Only the catch running again, and failing again, settles it.
        self.assertTrue(self.catches(DELETED_REFUSAL="cannot be moved earlier", FLAKY="1"))

    def test_a_catch_alone_is_credited(self):
        self.assertTrue(self.catches(DELETED_REFUSAL="cannot be moved earlier"))

    def test_a_flaky_failure_alone_is_not_credited(self):
        self.assertFalse(self.catches(FLAKY="1"))

    def test_a_green_suite_catches_nothing(self):
        self.assertFalse(self.catches())


if __name__ == "__main__":
    unittest.main()
