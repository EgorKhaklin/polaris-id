# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The application mutation drill's shards cover every refusal exactly once.

The weekly sweep runs the drill as N parallel shards (`--shard I/N`): unsharded, its 145 refusals
passed the job's two hours. Sharding must lose nothing: the N shards together switch off exactly
the refusals one run switches off, none twice; a declared entry's refusals stay in one shard, so
that shard can tell a live declaration from a stale one. These tests prove the partition on the
application's own refusals, then run main() over two small modules in a temporary directory, with
the suite replaced by a function that knows which refusal is off, and compare what the shards did
with what one run does. No database, and the application's files are never written.

    python3 -m unittest test_app_drill      (from scripts/)
"""
import contextlib
import importlib.util
import io
import pathlib
import random
import sys
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location("app_drill", HERE / "polaris-app-mutation-drill.py")
drill = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drill)

SHARD_COUNTS = (1, 2, 3, 4, 5, 6, 7, 8, 13)


def _application_refusals():
    """Every refusal the drill finds in polaris_web, read, never written."""
    found = []
    for m in drill.modules():
        for r in drill.refusals(m.read_text()):
            r["file"] = m
            found.append(r)
    return found


def _key(case):
    return (case["file"].name, case["line"])


class PartitionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cases = _application_refusals()

    def test_the_application_has_refusals_and_declared_entries_to_deal(self):
        self.assertGreaterEqual(len(self.cases), 100)
        self.assertGreaterEqual(len(drill.DECLARED), 10)

    def test_the_shards_cover_every_refusal_exactly_once(self):
        for n in SHARD_COUNTS:
            with self.subTest(n=n):
                taken = [_key(c) for i in range(1, n + 1) for c in drill.shard_cases(self.cases, (i, n))]
                self.assertEqual(sorted(taken), sorted(_key(c) for c in self.cases))
                self.assertEqual(len(taken), len(set(taken)))

    def test_a_declared_entrys_refusals_are_in_one_shard(self):
        for n in SHARD_COUNTS:
            for key in drill.DECLARED:
                holders = {i for i in range(1, n + 1)
                           if any(drill.matches(key, c) for c in drill.shard_cases(self.cases, (i, n)))}
                with self.subTest(n=n, key=key):
                    self.assertLessEqual(len(holders), 1)

    def test_each_declaration_is_answered_by_one_shard_or_by_every_shard(self):
        nowhere = ("no_such_view", "no such condition")
        declared = {**drill.DECLARED, nowhere: "matches no refusal"}
        for n in SHARD_COUNTS:
            answers = {k: [i for i in range(1, n + 1)
                           if k in drill.declarations_answered(self.cases, drill.shard_cases(self.cases, (i, n), declared),
                                                               declared)]
                       for k in declared}
            with self.subTest(n=n):
                self.assertEqual(answers[nowhere], list(range(1, n + 1)))
                for k, shards in answers.items():
                    if k != nowhere and any(drill.matches(k, c) for c in self.cases):
                        self.assertEqual(len(shards), 1, k)
        self.assertEqual(drill.declarations_answered(self.cases, self.cases), set(drill.DECLARED))

    def test_the_deal_does_not_depend_on_the_order_found(self):
        shuffled = self.cases[:]
        random.Random(7).shuffle(shuffled)
        for n in (3, 6):
            for i in range(1, n + 1):
                self.assertEqual([_key(c) for c in drill.shard_cases(shuffled, (i, n))],
                                 [_key(c) for c in drill.shard_cases(self.cases, (i, n))])

    def test_one_shard_is_the_unsharded_run_and_the_shards_are_even(self):
        self.assertEqual([_key(c) for c in drill.shard_cases(self.cases, (1, 1))], sorted(_key(c) for c in self.cases))
        sizes = [len(drill.shard_cases(self.cases, (i, 6))) for i in range(1, 7)]
        biggest = max(len(u) for u in drill.shard_units(self.cases))
        self.assertLessEqual(max(sizes) - min(sizes), biggest, sizes)

    def test_more_shards_than_units_leaves_empty_shards(self):
        two = self.cases[:2]
        units = drill.shard_units(two, {})
        self.assertEqual(len(units), 2)
        self.assertEqual([len(drill.shard_cases(two, (i, 4), {})) for i in range(1, 5)], [1, 1, 0, 0])
        self.assertEqual(drill.shard_cases([], (2, 3)), [])

    def test_parse_shard(self):
        self.assertEqual(drill.parse_shard("2/6"), (2, 6))
        self.assertEqual(drill.parse_shard("1/1"), (1, 1))
        for bad in ("0/6", "7/6", "6", "a/b", "1/0", "", "-1/3"):
            with self.subTest(bad=bad), self.assertRaises(Exception):
                drill.parse_shard(bad)


# Two modules of routes the drill parses as it parses polaris_web. The control is the refusal on
# /api/v1/auth/authorize whose condition reads `not ok`, as in the drill's CONTROL. One declared
# entry, ("view_a", "a_shared"), matches two refusals.
MODULE_A = """
@app.route("/api/v1/auth/authorize")
def authorize():
    if not ok:
        return err, 403
    return 1


@app.route("/a")
def view_a():
    if a_one:
        return err, 400
    if a_shared and first:
        return err, 404
    if a_two:
        return err, 400
    if a_shared and second:
        return err, 404
    return 1
"""
MODULE_B = """
@app.route("/b")
def view_b():
    if b_one:
        return err, 400
    if b_survives:
        return err, 400
    return 1


@app.route("/c")
def view_c():
    if c_covered_now:
        return err, 409
    return 1
"""
DECLARED = {("view_a", "a_shared"): "masked", ("view_b", "b_survives"): "masked"}


class ShardedRunTests(unittest.TestCase):
    """main() per shard, against the two modules: the suite is red exactly when a refusal that
    is not a survivor is off."""

    def run_drill(self, shard, survivors, declared=DECLARED, sharder=None):
        """(exit code, the refusals switched off as cases, the output). The negative control's
        own switch-off, always the first, is not a case; the control refusal as a case is."""
        with tempfile.TemporaryDirectory() as d:
            files = [pathlib.Path(d) / "a_routes.py", pathlib.Path(d) / "b_routes.py"]
            files[0].write_text(MODULE_A)
            files[1].write_text(MODULE_B)
            originals = {f: f.read_text() for f in files}
            cases = {f: drill.refusals(originals[f]) for f in files}
            switched_off = []

            def suite(targets, env):
                off = [c["source"] for f in files for c in cases[f]
                       if f.read_text() != originals[f] and f.read_text() == drill.mutate(originals[f], c["span"])]
                switched_off.extend(off)
                if not off:
                    return True, "OK"
                return (off[0] in survivors), "one off"

            done = mock.Mock(stdout=b"")
            with mock.patch.object(drill, "modules", return_value=files), \
                    mock.patch.object(drill, "run_tests", side_effect=suite), \
                    mock.patch.object(drill, "classes_exercising", return_value=["T"]), \
                    mock.patch.object(drill, "DECLARED", declared), \
                    mock.patch.object(drill, "CONTROL", ("/api/v1/auth/authorize", "not ok")), \
                    mock.patch.object(drill, "MIN_REFUSALS", 1), \
                    mock.patch.object(drill.subprocess, "run", return_value=done), \
                    mock.patch.object(drill, "shard_cases", sharder or drill.shard_cases), \
                    mock.patch.object(sys, "argv", ["drill", "--all", "--shard", shard]):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = drill.main()
                self.assertEqual({f: f.read_text() for f in files}, originals)
        self.assertEqual(switched_off[:1], ["not ok"])
        return code, switched_off[1:], out.getvalue() + err.getvalue()

    def test_the_shards_together_switch_off_what_one_run_switches_off(self):
        code, one_run, text = self.run_drill("1/1", {"b_survives"})
        self.assertEqual(code, 1, text)    # the two a_shared refusals no longer survive: stale
        self.assertEqual(len(one_run), 8)  # every refusal, the control's as a case included
        for n in (2, 3, 5, 9):
            with self.subTest(n=n):
                together = [m for i in range(1, n + 1)
                            for m in self.run_drill("%d/%d" % (i, n), {"b_survives"})[1]]
                self.assertEqual(sorted(together), sorted(one_run))

    def test_an_undeclared_survivor_fails_exactly_the_shard_that_holds_it(self):
        holders = [i for i in range(1, 4) if "c_covered_now" in self.run_drill("%d/3" % i, set())[1]]
        self.assertEqual(len(holders), 1)
        survivors = {"b_survives", "c_covered_now", "a_shared and first"}
        for i in range(1, 4):
            code, _, text = self.run_drill("%d/3" % i, survivors)
            with self.subTest(i=i):
                self.assertEqual(code, 1 if i == holders[0] else 0, text)
                self.assertEqual("REFUSAL(S) NOTHING NOTICES" in text, i == holders[0])

    def test_a_declaration_one_of_whose_refusals_survives_is_live_in_every_shard(self):
        # ("view_a", "a_shared") matches two refusals; only the first survives. A deal that split
        # them would hand the second to a shard that sees the entry matched by no survivor and
        # calls it stale.
        for n in (2, 3, 4):
            for i in range(1, n + 1):
                code, _, text = self.run_drill("%d/%d" % (i, n), {"b_survives", "a_shared and first"})
                with self.subTest(n=n, i=i):
                    self.assertEqual(code, 0, text)
                    self.assertNotIn("STALE", text)

    def test_a_stale_declaration_fails_the_shard_holding_its_refusals_and_one_matching_nothing_fails_every_shard(self):
        declared = {**DECLARED, ("view_c", "c_covered_now"): "covered now"}
        survivors = {"b_survives", "a_shared and first"}
        results = [self.run_drill("%d/3" % i, survivors, declared) for i in range(1, 4)]
        failing = [i for i, (code, _, _) in enumerate(results, 1) if code == 1]
        self.assertEqual(len(failing), 1)
        self.assertIn("STALE DECLARATIONS (1)", results[failing[0] - 1][2])
        gone = {**declared, ("view_gone", "rewritten"): "its refusal was rewritten"}
        for i in range(1, 4):
            code, _, text = self.run_drill("%d/3" % i, survivors | {"c_covered_now"}, gone)
            with self.subTest(i=i):
                self.assertEqual(code, 1, text)
                self.assertIn("STALE DECLARATIONS (1)", text)
                self.assertIn("view_gone(rewritten)", text)

    def test_an_empty_share_passes_only_when_the_units_run_out(self):
        survivors = {"b_survives", "a_shared and first"}
        code, cases, text = self.run_drill("8/8", survivors)  # 7 units: two refusals share an entry
        self.assertEqual((code, cases), (0, []), text)
        self.assertIn("in 0 of 7 unit(s)", text)
        code, cases, text = self.run_drill("2/3", survivors, sharder=lambda cases, shard, declared=None: [])
        self.assertEqual((code, cases), (1, []), text)
        self.assertIn("the partition has dropped work", text)


if __name__ == "__main__":
    unittest.main()
