# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The mdoc mutation drill finds the verifier's refusals, keeps the certificate path out, and its
shards switch off every refusal exactly once.

The partition is proved on verify_mdoc.py itself; main() then runs per shard with the suites
replaced by a function that knows which refusal is off, and what the shards did is compared with
what one run does. The checkout is never written.

    python3 -m unittest test_mdoc_drill      (from scripts/)
"""
import contextlib
import importlib.util
import io
import pathlib
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("mdoc_drill", HERE / "polaris-mdoc-mutation-drill.py")
drill = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drill)

ORIGINAL = (drill.ROOT / drill.SOURCE).read_text()


class SiteTests(unittest.TestCase):

    def test_the_verifier_has_refusals_in_scope_and_on_the_certificate_path(self):
        found, skipped = drill.sites(ORIGINAL)
        self.assertGreaterEqual(len(found), 60)
        self.assertGreaterEqual(skipped, 5)
        self.assertEqual(len({s["key"] for s in found}), len(found))
        self.assertFalse({s["function"] for s in found} & set(drill.OUT_OF_SCOPE))
        self.assertNotIn("issuer chain", {s["check"] for s in found})
        # Each site is one `raise Refused(` statement, at the line it names.
        lines = ORIGINAL.splitlines()
        for s in found:
            self.assertIn("raise Refused(", lines[s["line"] - 1], s)

    def test_out_of_scope_reaches_nested_functions_and_identical_statements_get_their_own_keys(self):
        src = ("def chain_to_root(x):\n    def inner():\n        raise Refused('a', 'b')\n    return inner\n\n"
               "def verify(x):\n    if x:\n        raise Refused('cbor', 'same')\n    if not x:\n"
               "        raise Refused('cbor', 'same')\n    raise Refused('issuer chain', 'c')\n")
        found, skipped = drill.sites(src)
        self.assertEqual(skipped, 2)
        self.assertEqual([s["line"] for s in found], [8, 10])
        self.assertEqual(found[1]["key"], found[0]["key"] + "~2")

    def test_switching_off_changes_only_the_chosen_statements(self):
        found, _ = drill.sites(ORIGINAL)
        one = drill.switch_off(ORIGINAL, [found[5]])
        before, after = ORIGINAL.splitlines(), one.splitlines()
        span = found[5]["end"] - found[5]["line"] + 1
        self.assertEqual(len(before) - len(after), span - 1)
        self.assertEqual(after[found[5]["line"] - 1].strip(), "pass")
        self.assertEqual(before[:found[5]["line"] - 1], after[:found[5]["line"] - 1])
        self.assertEqual(before[found[5]["end"]:], after[found[5]["line"]:])
        everything = drill.switch_off(ORIGINAL, found)
        compile(everything, drill.SOURCE, "exec")
        # All of them off: no in-scope refusal is left, and the certificate path is untouched.
        self.assertEqual(drill.sites(everything), ([], drill.sites(ORIGINAL)[1]))
        self.assertEqual(drill.switch_off(ORIGINAL, []), ORIGINAL)

    def test_the_shards_switch_off_every_refusal_exactly_once(self):
        found, _ = drill.sites(ORIGINAL)
        for n in (1, 2, 3, 4, 7, 100):
            taken = [s["key"] for i in range(1, n + 1) for s in drill.shard_sites(found, (i, n))]
            with self.subTest(n=n):
                self.assertEqual(sorted(taken), sorted(s["key"] for s in found))
        self.assertEqual(drill.shard_sites(found, (1, 1)), found)

    def test_each_declaration_is_answered_by_its_shard_or_by_every_shard(self):
        found, _ = drill.sites(ORIGINAL)
        declared = {found[3]["key"]: "x", "verify:cbor:000000": "names nothing"}
        for n in (2, 3, 5):
            answers = {k: [i for i in range(1, n + 1)
                           if k in drill.declarations_answered(found, drill.shard_sites(found, (i, n)), declared)]
                       for k in declared}
            with self.subTest(n=n):
                self.assertEqual(len(answers[found[3]["key"]]), 1)
                self.assertEqual(answers["verify:cbor:000000"], list(range(1, n + 1)))

    def test_parse_shard(self):
        self.assertEqual(drill.parse_shard("2/3"), (2, 3))
        for bad in ("0/3", "4/3", "3", "a/b", "1/0", ""):
            with self.subTest(bad=bad), self.assertRaises(Exception):
                drill.parse_shard(bad)


class ShardedRunTests(unittest.TestCase):
    """main() per shard, the suites replaced: red exactly when a refusal that is not a survivor is
    off, or when more than one is off."""

    def run_drill(self, shard, survivors, declared, baseline_green=True, control_red=True):
        found, _ = drill.sites(ORIGINAL)
        by_text = {drill.switch_off(ORIGINAL, [s]): s["key"] for s in found}
        off = []

        def suites(copy):
            text = (copy / drill.SOURCE).read_text()
            if text == ORIGINAL:
                return baseline_green, "" if baseline_green else "test_x"
            key = by_text.get(text)
            if key is None:            # the negative control: every refusal off
                return (not control_red), "test_control"
            off.append(key)
            return key in survivors, "test_y"

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(drill, "run_suites", side_effect=suites), \
                mock.patch.object(drill, "DECLARED_SURVIVORS", declared), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = drill.main(["--shard", shard])
        self.assertEqual((drill.ROOT / drill.SOURCE).read_text(), ORIGINAL)
        return code, off, out.getvalue() + err.getvalue()

    def test_the_shards_together_switch_off_what_one_run_switches_off(self):
        code, one_run, _ = self.run_drill("1/1", set(), {})
        self.assertEqual(code, 0)
        found, _ = drill.sites(ORIGINAL)
        self.assertEqual(sorted(one_run), sorted(s["key"] for s in found))
        together = [k for i in range(1, 4) for k in self.run_drill("%d/3" % i, set(), {})[1]]
        self.assertEqual(sorted(together), sorted(one_run))

    def test_an_undeclared_survivor_and_a_stale_declaration_fail_the_shard_that_holds_them(self):
        found, _ = drill.sites(ORIGINAL)
        survivor, caught = found[4]["key"], found[9]["key"]
        for i in range(1, 4):
            code, off, text = self.run_drill("%d/3" % i, {survivor}, {caught: "caught now"})
            with self.subTest(i=i):
                expect = 1 if (survivor in off or caught in off) else 0
                self.assertEqual(code, expect, text)
                self.assertEqual("UNDECLARED SURVIVOR " + survivor in text, survivor in off)
                self.assertEqual("STALE DECLARATION " + caught in text, caught in off)
        code, _, text = self.run_drill("1/1", {survivor}, {survivor: "declared"})
        self.assertEqual(code, 0, text)

    def test_a_declaration_naming_no_refusal_fails_every_shard(self):
        for i in range(1, 4):
            code, _, text = self.run_drill("%d/3" % i, set(), {"verify:cbor:000000": "rewritten"})
            with self.subTest(i=i):
                self.assertEqual(code, 1, text)
                self.assertIn("STALE DECLARATION verify:cbor:000000", text)

    def test_a_red_baseline_and_a_green_negative_control_void_the_run(self):
        code, off, text = self.run_drill("1/1", set(), {}, baseline_green=False)
        self.assertEqual((code, off), (2, []), text)
        self.assertIn("VOID", text)
        code, off, text = self.run_drill("1/1", set(), {}, control_red=False)
        self.assertEqual((code, off), (2, []), text)
        self.assertIn("VOID", text)


    def test_an_empty_share_passes_only_when_the_refusals_run_out(self):
        code, off, text = self.run_drill("80/80", set(), {})
        self.assertEqual((code, off), (0, []), text)
        with mock.patch.object(drill, "shard_sites", return_value=[]):
            code, off, text = self.run_drill("2/3", set(), {})
        self.assertEqual((code, off), (1, []), text)
        self.assertIn("received no refusal", text)


class RunnerTests(unittest.TestCase):
    """The suites run without STRUCTURAL, and the runner leaves out only the tests it is given."""

    def test_the_suites_are_run_without_the_structural_test(self):
        done = mock.Mock(returncode=0, stderr="")
        with mock.patch.object(drill.subprocess, "run", return_value=done) as run:
            self.assertEqual(drill.run_suites(pathlib.Path("/nonexistent")), (True, ""))
        self.assertEqual(run.call_count, len(drill.SUITES))
        for call, (_, module) in zip(run.call_args_list, drill.SUITES):
            argv = call.args[0]
            self.assertEqual(argv[argv.index(drill._RUNNER) + 1:], [module] + list(drill.STRUCTURAL))
            self.assertNotIn("GIT_DIR", call.kwargs["env"])

    def test_the_runner_leaves_out_exactly_the_named_tests_and_refuses_to_run_none(self):
        import subprocess
        import sys
        import tempfile
        # The prefix is on .coveragerc's omit list: the coverage shards record the child's run.
        with tempfile.TemporaryDirectory(prefix="polaris-runner-test-") as d:
            pathlib.Path(d, "t_two.py").write_text(
                "import unittest\n"
                "class T(unittest.TestCase):\n"
                "    def test_kept(self): pass\n"
                "    def test_structural(self): self.fail('ran')\n")

            def runner(*left_out):
                return subprocess.run([sys.executable, "-B", "-c", drill._RUNNER, "t_two"] + list(left_out),
                                      cwd=d, capture_output=True, text=True, timeout=120)
            self.assertEqual(runner().returncode, 1)
            kept = runner("test_structural")
            self.assertEqual(kept.returncode, 0, kept.stderr)
            self.assertIn("Ran 1 test", kept.stderr)
            none = runner("test_structural", "test_kept")
            self.assertNotEqual(none.returncode, 0)
            self.assertIn("no test left in t_two", none.stderr)


if __name__ == "__main__":
    unittest.main()
