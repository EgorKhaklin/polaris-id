# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The OID4VP mutation drill's shards make every mutation exactly once (2026-10-15).

CI runs the drill as three shards (`--shard I/3`) rather than one step of 34 minutes. Sharding
must lose nothing: the shards together make exactly the mutations one unsharded run makes, none
twice, and each shard answers for the declared survivors it mutated while a declaration that
names no refusal fails every shard. These tests prove the partition on the real package, then
run the drill's main() for each shard with the package's suites replaced by a stand-in that
fails on every mutation except the declared survivors. No suite runs.

    python3 -m unittest test_oid4vp_drill      (from scripts/)
"""
import contextlib
import importlib.util
import io
import pathlib
import subprocess
import sys
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location("oid4vp_drill", HERE / "polaris-oid4vp-mutation-drill.py")
drill = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drill)

SHARD_COUNTS = (1, 2, 3, 5)        # 3 is what CI runs


def _originals():
    return {source: (drill.PKG / source).read_text(encoding="utf-8") for source in drill.SOURCES}


class ThePartition(unittest.TestCase):

    def setUp(self):
        self.units = drill.mutation_units(_originals())

    def test_there_is_work_to_divide(self):
        self.assertGreater(sum(1 for u in self.units if u[0] == "site"), 100)
        self.assertEqual(sum(1 for u in self.units if u[0] == "named"), len(drill.NAMED_MUTANTS))

    def test_the_shards_cover_every_mutation_exactly_once(self):
        keys = [(u[0], u[1]) for u in self.units]
        self.assertEqual(len(keys), len(set(keys)), "two mutations share a label")
        for n in SHARD_COUNTS:
            shards = [[(u[0], u[1]) for u in drill.shard_of(self.units, (i, n))] for i in range(1, n + 1)]
            flat = [k for shard in shards for k in shard]
            self.assertEqual(sorted(flat), sorted(keys), "shards of %d drop or repeat a mutation" % n)
            sizes = [len(x) for x in shards]
            self.assertLessEqual(max(sizes) - min(sizes), 1, "uneven shards %r" % sizes)

    def test_each_file_is_dealt_across_the_shards(self):
        for source in drill.SOURCES:
            holders = {i for i in (1, 2, 3)
                       if any(u[2] == source for u in drill.shard_of(self.units, (i, 3)))}
            self.assertEqual(holders, {1, 2, 3}, source)

    def test_parse_shard(self):
        self.assertEqual(drill.parse_shard("2/3"), (2, 3))
        self.assertEqual(drill.parse_shard("1/1"), (1, 1))
        for bad in ("", "3", "0/3", "4/3", "1/0", "a/b"):
            with self.assertRaises(Exception):
                drill.parse_shard(bad)


class TheShardsAgreeWithOneRun(unittest.TestCase):
    """main() per shard, with the suites stood in for: the package as copied, unmutated, passes;
    a declared survivor's mutation passes; every other mutation fails."""

    def setUp(self):
        originals = _originals()
        self.units = drill.mutation_units(originals)
        # Every mutated file text the drill can write, mapped to the mutation's label.
        self.by_text = {}
        for u in self.units:
            if u[0] == "site":
                lines = originals[u[2]].splitlines(keepends=True)
                lines[u[3]] = u[4]
                self.by_text["".join(lines)] = u[1]
            else:
                _kind, label, source, old, new = u
                text = originals.get(source) or (drill.PKG / source).read_text(encoding="utf-8")
                self.by_text[text.replace(old, new)] = label

    def run_shard(self, shard, survive):
        made = []

        def suite(work):
            for source in drill.SOURCES + ("polaris_oid4vp/serve.py",):
                label = self.by_text.get((work / source).read_text(encoding="utf-8"))
                if label is not None:
                    made.append(label)
                    return subprocess.CompletedProcess([], 0 if label in survive else 1, "", "")
            if any("# MUTANT" in (work / s).read_text(encoding="utf-8") for s in drill.SOURCES):
                return subprocess.CompletedProcess([], 1, "", "")     # the negative control
            return subprocess.CompletedProcess([], 0, "", "")         # unmutated

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(drill, "_run_suite", side_effect=suite), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = drill.main(["--shard", "%d/%d" % shard])
        return code, made, out.getvalue() + err.getvalue()

    def test_three_shards_make_what_one_run_makes_and_pass(self):
        survive = set(drill.DECLARED_SURVIVORS)
        code, one, text = self.run_shard((1, 1), survive)
        self.assertEqual(code, 0, text)
        made = []
        for i in (1, 2, 3):
            code, part, text = self.run_shard((i, 3), survive)
            self.assertEqual(code, 0, text)
            made += part
        # A survivor is run twice (the confirmation), so compare the sets and the single runs.
        self.assertEqual(sorted(set(made)), sorted(set(one)))
        self.assertEqual(sorted(set(made)), sorted(u[1] for u in self.units))

    def test_a_closed_gap_fails_only_the_shard_that_holds_it(self):
        declared = sorted(drill.DECLARED_SURVIVORS)[0]
        holder = next(i for i in (1, 2, 3)
                      if any(u[1] == declared for u in drill.shard_of(self.units, (i, 3))))
        survive = set(drill.DECLARED_SURVIVORS) - {declared}
        for i in (1, 2, 3):
            code, _, text = self.run_shard((i, 3), survive)
            self.assertEqual(code, 1 if i == holder else 0, (i, text[-400:]))

    def test_a_declaration_naming_no_refusal_fails_every_shard(self):
        with mock.patch.dict(drill.DECLARED_SURVIVORS, {"sdjwt:nowhere:000000": "stale"}):
            survive = set(drill.DECLARED_SURVIVORS)
            for i in (1, 2, 3):
                code, _, text = self.run_shard((i, 3), survive)
                self.assertEqual(code, 1, i)
                self.assertIn("sdjwt:nowhere:000000", text)

    def test_an_undeclared_survivor_fails_its_shard(self):
        extra = next(u[1] for u in self.units if u[0] == "site" and u[1] not in drill.DECLARED_SURVIVORS)
        holder = next(i for i in (1, 2, 3) if any(u[1] == extra for u in drill.shard_of(self.units, (i, 3))))
        code, _, text = self.run_shard((holder, 3), set(drill.DECLARED_SURVIVORS) | {extra})
        self.assertEqual(code, 1, text[-400:])

    def test_a_shard_past_the_end_of_the_list_claims_nothing_and_passes(self):
        n = len(self.units) + 1
        code, made, text = self.run_shard((n, n), set(drill.DECLARED_SURVIVORS))
        self.assertEqual((code, made), (0, []), text[-400:])


if __name__ == "__main__":
    unittest.main()
