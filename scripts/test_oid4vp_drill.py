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
import re
import subprocess
import sys
import tempfile
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


def _modules():
    return sorted("polaris_oid4vp/" + f.name for f in (drill.PKG / "polaris_oid4vp").glob("*.py"))


def _sited():
    return {u[2] for u in drill.mutation_units(_originals()) if u[0] == "site"}


class TheModulesThatRaise(unittest.TestCase):
    """cbor.py, cose.py and mdoc.py refuse by raising, and the mutant puts the raise behind
    `if False:` (2026-11-16)."""

    def test_every_raise_in_them_is_a_site_and_every_mutant_compiles(self):
        originals = _originals()
        for source in drill._RAISING:
            lines = originals[source].splitlines(keepends=True)
            sites = [i for i, line in enumerate(lines) if drill._invert(line, source) is not None]
            raises = [i for i, line in enumerate(lines) if re.match(r"\s*raise\b", line)]
            self.assertTrue(sites, source)
            self.assertEqual(sites, raises, "%s raises something no pattern inverts" % source)
            for i in sites:
                mutated = lines[:]
                mutated[i] = drill._invert(lines[i], source)
                # A mutant that does not compile fails every test and reads as caught.
                compile("".join(mutated), source, "exec")

    def test_the_mutated_guard_does_not_fire(self):
        for raised in ('raise _Refused("code", "why")\n', 'raise _Refused("code", "why") from None\n',
                       'raise _Refused("code",\n                   "why") from None\n'):
            first, _, rest = raised.partition("\n")
            mutant = drill._invert("    " + first + "\n", "polaris_oid4vp/mdoc.py") + rest + ("\n" if rest else "")
            scope = {}
            exec("class _Refused(Exception):\n    pass\n\n\ndef judge():\n" + mutant + "    return 'accepted'\n", scope)
            self.assertEqual(scope["judge"](), "accepted", raised)

    def test_the_other_modules_keep_their_own_patterns(self):
        line = '    raise ValueError("no")\n'
        self.assertIsNone(drill._invert(line, "polaris_oid4vp/sdjwt.py"))
        self.assertIsNotNone(drill._invert(line, "polaris_oid4vp/mdoc.py"))


class TheLists(unittest.TestCase):
    """Every module of the package is a source with a refusal or is declared to have none."""

    def test_the_package_as_it_is_has_no_problem(self):
        self.assertEqual(drill.module_problems(_modules(), _sited()), [])
        self.assertEqual(set(_modules()), set(drill.SOURCES) | set(drill.NO_REFUSALS))

    def test_a_module_in_neither_list_is_a_problem(self):
        # mdoc.py as it stood before it joined SOURCES, and a module added tomorrow.
        mdoc = "polaris_oid4vp/mdoc.py"
        with mock.patch.object(drill, "SOURCES", tuple(s for s in drill.SOURCES if s != mdoc)):
            problems = drill.module_problems(_modules(), _sited() - {mdoc})
        self.assertEqual(len(problems), 1, problems)
        self.assertIn(mdoc + " is in neither SOURCES nor NO_REFUSALS", problems[0])
        problems = drill.module_problems(_modules() + ["polaris_oid4vp/new.py"], _sited())
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("polaris_oid4vp/new.py is in neither", problems[0])

    def test_a_source_in_which_no_refusal_matched_is_a_problem(self):
        problems = drill.module_problems(_modules(), _sited() - {"polaris_oid4vp/cose.py"})
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("polaris_oid4vp/cose.py is in SOURCES and no refusal in it matched", problems[0])

    def test_a_listed_module_that_is_gone_is_a_problem(self):
        for gone in ("polaris_oid4vp/serve.py", "polaris_oid4vp/jwe.py"):
            problems = drill.module_problems([m for m in _modules() if m != gone], _sited() - {gone})
            self.assertEqual(len(problems), 1, problems)
            self.assertIn(gone + " is listed and is not a module of the package", problems[0])

    def test_a_module_in_both_lists_is_a_problem(self):
        with mock.patch.dict(drill.NO_REFUSALS, {"polaris_oid4vp/jwe.py": "no"}):
            problems = drill.module_problems(_modules(), _sited())
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("polaris_oid4vp/jwe.py is in SOURCES and in NO_REFUSALS", problems[0])


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

    def test_a_module_outside_both_lists_stops_the_drill_before_any_mutation(self):
        kept = {k: v for k, v in drill.NO_REFUSALS.items() if k != "polaris_oid4vp/cli.py"}
        with mock.patch.object(drill, "NO_REFUSALS", kept):
            code, made, text = self.run_shard((1, 1), set(drill.DECLARED_SURVIVORS))
        self.assertEqual((code, made), (1, []), text[-400:])
        self.assertIn("polaris_oid4vp/cli.py is in neither SOURCES nor NO_REFUSALS", text)

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


class TheSuiteRun(unittest.TestCase):
    """One suite run: every suite, the slow one last, stopped by the first failing test, with the
    exit status a full run gives."""

    def test_a_run_names_every_suite_once_and_the_slow_one_last(self):
        command = drill.unittest_command()
        self.assertEqual(command[1:4], ["-m", "unittest", "--failfast"])
        self.assertEqual(sorted(command[4:]), sorted(drill.SUITES))
        self.assertTrue(drill.SLOW_SUITES)
        self.assertEqual(tuple(command[-len(drill.SLOW_SUITES):]), drill.SLOW_SUITES)
        self.assertLessEqual(set(drill.SLOW_SUITES), set(drill.SUITES))

    def run_in(self, quick_passes):
        """Two suites of one test each in a scratch package: the quick one passes or fails, the
        slow one leaves a file when it runs. Returns (exit status, whether the slow one ran)."""
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp)
            (work / "test_quick.py").write_text(
                "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
                "        self.assertTrue(%r)\n" % quick_passes)
            (work / "test_slow.py").write_text(
                "import pathlib\nimport unittest\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
                "        pathlib.Path('ran').write_text('x')\n")
            # Listed slow first, so that only the ordering puts it after the quick one.
            with mock.patch.object(drill, "SUITES", ("test_slow", "test_quick")), \
                    mock.patch.object(drill, "SLOW_SUITES", ("test_slow",)):
                done = drill._run_suite(work)
            return done.returncode, (work / "ran").exists()

    def test_a_failing_test_ends_the_run_before_the_slow_suite_and_fails_it(self):
        code, slow_ran = self.run_in(quick_passes=False)
        self.assertNotEqual(code, 0)
        self.assertFalse(slow_ran)

    def test_a_passing_run_ran_every_suite(self):
        code, slow_ran = self.run_in(quick_passes=True)
        self.assertEqual(code, 0)
        self.assertTrue(slow_ran)


if __name__ == "__main__":
    unittest.main()
