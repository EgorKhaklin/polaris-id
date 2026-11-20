# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The OID4VP mutation drill's shards make every mutation exactly once (2026-10-15).

CI runs the drill as eight shards (`--shard I/8`) rather than one step of 34 minutes. Sharding
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
import os
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

SHARD_COUNTS = (1, 2, 3, 5, 6)     # 6 is what CI runs

#: What every scratch directory this file makes is named with. CI's coverage step measures the
#: child interpreters these tests start, and combines its shards on another runner, where the
#: directory never existed: code run from it is a "No source for code" error in `coverage json`,
#: and the floor gate cannot read its numbers (PR 579, 2026-11-18). .coveragerc omits this name.
SCRATCH_PREFIX = "polaris-runner-test-"

# What unittest prints for a run, as the drill reads it: green; red with a failure; red by ERROR only.
PASSED = subprocess.CompletedProcess([], 0, "", "Ran 3 tests in 0.1s\n\nOK\n")
FAILED_ONE = subprocess.CompletedProcess([], 1, "", "Ran 3 tests in 0.1s\n\nFAILED (failures=1)\n")
CRASHED = subprocess.CompletedProcess([], 1, "", "Ran 3 tests in 0.1s\n\nFAILED (errors=1)\n")


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
                self.by_text[drill.mutated_text(originals[u[2]], u[2], [(u[3], u[4])])] = u[1]
            else:
                _kind, label, source, old, new = u
                text = originals.get(source) or (drill.PKG / source).read_text(encoding="utf-8")
                self.by_text[text.replace(old, new)] = label
        # The files a mutation can be in: SOURCES, and any other module a named mutant changes
        # (cli.py, 2026-11-18), which the drill reads from the package it copied.
        self.mutable = list(drill.SOURCES) + sorted(
            {u[2] for u in self.units if u[0] == "named"} - set(drill.SOURCES))

    #: What the stand-in prints for a failing run, in the form unittest gives a failing test.
    FAILED = "FAIL: test_stand_in (suite.T.test_stand_in)\nAssertionError\n\nFAILED (failures=1)\n"

    def run_shard(self, shard, survive, fails_once=(), fails_rerun=(), crash=(), crash_fast=(),
                  control=None):
        """main() for one shard: (exit status, the labels run in order, everything printed). A
        label in `survive` passes; every other mutation fails a test. One in `fails_once` fails
        its first run and passes after it; one in `fails_rerun` passes its first run and fails its
        second. One in `crash` is red by ERROR alone; one in `crash_fast` is red by ERROR alone
        under --failfast and fails a test in the full run. `control` replaces the negative
        control's result."""
        made = []

        def suite(work, failfast=True):
            for source in self.mutable:
                label = self.by_text.get((work / source).read_text(encoding="utf-8"))
                if label is not None:
                    made.append(label)
                    run = made.count(label)
                    if label in crash or (label in crash_fast and failfast):
                        return CRASHED
                    passes = label in survive and not (label in fails_once and run == 1) \
                        and not (label in fails_rerun and run == 2)
                    return subprocess.CompletedProcess([], 0 if passes else 1, "", "" if passes else self.FAILED)
            if any("# MUTANT" in (work / s).read_text(encoding="utf-8") for s in drill.SOURCES):
                return control or FAILED_ONE                          # the negative control
            return PASSED                                             # unmutated

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
            code, made, text = self.run_shard((i, 3), survive)
            self.assertEqual(code, 1 if i == holder else 0, (i, text[-400:]))
            if i == holder:
                # It failed twice before the list was called stale, and the run's words are shown.
                self.assertEqual(made.count(declared), 2)
                self.assertIn("%s is declared a survivor and its suite run failed twice" % declared, text)
                self.assertIn("FAIL: test_stand_in (suite.T.test_stand_in)", text)
                self.assertIn("no longer survive", text)

    def test_a_declared_survivor_that_fails_one_run_and_passes_the_next_still_survives(self):
        declared = sorted(drill.DECLARED_SURVIVORS)[0]
        holder = next(i for i in (1, 2, 3)
                      if any(u[1] == declared for u in drill.shard_of(self.units, (i, 3))))
        code, made, text = self.run_shard((holder, 3), set(drill.DECLARED_SURVIVORS), fails_once={declared})
        self.assertEqual(code, 0, text[-600:])
        self.assertEqual(made.count(declared), 2)
        self.assertIn("%s is declared a survivor and its suite run failed, then passed on the re-run"
                      % declared, text)
        self.assertIn("FAIL: test_stand_in (suite.T.test_stand_in)", text)
        self.assertIn("1 declared survivor(s) failed one of their two runs", text)
        self.assertNotIn("no longer survive", text)

    def test_a_declared_survivor_that_passes_one_run_and_fails_the_next_still_survives(self):
        """The same rule in the other order: the failing run is the second."""
        declared = sorted(drill.DECLARED_SURVIVORS)[0]
        holder = next(i for i in (1, 2, 3)
                      if any(u[1] == declared for u in drill.shard_of(self.units, (i, 3))))
        code, made, text = self.run_shard((holder, 3), set(drill.DECLARED_SURVIVORS), fails_rerun={declared})
        self.assertEqual(code, 0, text[-600:])
        self.assertEqual(made.count(declared), 2)
        self.assertIn("%s is declared a survivor and its suite run passed, then failed on the re-run"
                      % declared, text)
        self.assertIn("FAIL: test_stand_in (suite.T.test_stand_in)", text)
        self.assertIn("1 declared survivor(s) failed one of their two runs", text)
        self.assertNotIn("no longer survive", text)
        self.assertNotIn("so they are CAUGHT", text)

    def test_an_undeclared_mutation_that_passes_one_run_and_fails_the_next_is_caught(self):
        """The second run of a mutation nobody declared is still what it was: a confirmation."""
        undeclared = next(u[1] for u in self.units if u[0] == "site" and u[1] not in drill.DECLARED_SURVIVORS)
        holder = next(i for i in (1, 2, 3)
                      if any(u[1] == undeclared for u in drill.shard_of(self.units, (i, 3))))
        code, made, text = self.run_shard((holder, 3), set(drill.DECLARED_SURVIVORS) | {undeclared},
                                          fails_rerun={undeclared})
        self.assertEqual(code, 0, text[-600:])
        self.assertEqual(made.count(undeclared), 2)
        self.assertIn("1 mutation(s) passed once and failed on the re-run, so they are CAUGHT: %s" % undeclared, text)

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

    def test_a_mutant_that_only_crashes_is_not_caught_and_one_that_fails_is(self):
        # 2026-11-18: a red made of ERRORs alone asserted nothing. One mutation, both ways.
        extra = next(u[1] for u in self.units if u[0] == "site" and u[1] not in drill.DECLARED_SURVIVORS)
        holder = next(i for i in (1, 2, 3) if any(u[1] == extra for u in drill.shard_of(self.units, (i, 3))))
        survive = set(drill.DECLARED_SURVIVORS)
        code, _, text = self.run_shard((holder, 3), survive, crash={extra})
        self.assertEqual(code, 1, text[-400:])
        self.assertIn("red only by ERROR", text)
        self.assertIn(extra, text)
        code, _, text = self.run_shard((holder, 3), survive)
        self.assertEqual(code, 0, text[-400:])

    def test_a_named_mutation_that_only_crashes_is_not_caught(self):
        label = drill.NAMED_MUTANTS[0][0]
        holder = next(i for i in (1, 2, 3) if any(u[1] == label for u in drill.shard_of(self.units, (i, 3))))
        code, _, text = self.run_shard((holder, 3), set(drill.DECLARED_SURVIVORS), crash={label})
        self.assertEqual(code, 1, text[-400:])
        self.assertIn("%s [crashed]" % label, text)

    def test_a_mutant_red_by_error_under_failfast_and_failing_a_test_in_the_full_run_is_caught(self):
        # --failfast stops at the first ERROR, and a test later in the run may fail on the same
        # mutant: the full run decides, once, and that mutation is caught, not reported crashed.
        extra = next(u[1] for u in self.units if u[0] == "site" and u[1] not in drill.DECLARED_SURVIVORS)
        holder = next(i for i in (1, 2, 3) if any(u[1] == extra for u in drill.shard_of(self.units, (i, 3))))
        code, made, text = self.run_shard((holder, 3), set(drill.DECLARED_SURVIVORS), crash_fast={extra})
        self.assertEqual(code, 0, text[-600:])
        self.assertEqual(made.count(extra), 2)         # the run under --failfast, then the full run
        self.assertNotIn("red only by ERROR when", text)

    def test_a_negative_control_red_only_by_error_voids_the_run(self):
        code, _, text = self.run_shard((1, 3), set(drill.DECLARED_SURVIVORS), control=CRASHED)
        self.assertEqual(code, 1, text[-400:])
        self.assertIn("red only by ERROR, so no test failed on it", text)

    def test_a_passthrough_naming_a_function_with_no_refusal_stops_every_shard(self):
        with mock.patch.dict(drill._PASSTHROUGH, {("polaris_oid4vp/jwe.py", "_open_response"): "_open_compact"}):
            for i in (1, 2, 3):
                code, made, text = self.run_shard((i, 3), set(drill.DECLARED_SURVIVORS))
                self.assertEqual((code, made), (1, []), i)
                self.assertIn("_open_response holds no refusal", text)


class TheVerdictReadsWhatTheSuiteSaid(unittest.TestCase):
    """drill.verdict on real unittest runs: a failure is a catch; ERRORs alone, a module that does
    not import, or a red with nothing to read are crashes."""

    BODIES = {
        "green": "def test_a(self):\n        self.assertTrue(True)\n",
        "fails": "def test_a(self):\n        self.assertEqual(1, 2)\n",
        "raises": "def test_a(self):\n        {}['x']\n",
        "both": "def test_a(self):\n        self.assertEqual(1, 2)\n\n    def test_b(self):\n        {}['x']\n",
    }

    def run_module(self, body):
        import tempfile
        with tempfile.TemporaryDirectory(prefix=SCRATCH_PREFIX) as d:
            text = "import unittest\n\n\nclass T(unittest.TestCase):\n    " + body if body else "import nowhere_at_all\n"
            pathlib.Path(d, "test_m.py").write_text(text, encoding="utf-8")
            return subprocess.run([sys.executable, "-m", "unittest", "test_m"], cwd=d,
                                  capture_output=True, text=True, timeout=60)

    def test_each_kind_of_run(self):
        for name, expected in (("green", "passed"), ("fails", "caught"), ("raises", "crashed"),
                               ("both", "caught"), (None, "crashed")):
            with self.subTest(name=name):
                self.assertEqual(drill.verdict(self.run_module(self.BODIES.get(name))), expected)

    def test_a_red_with_nothing_to_read_is_a_crash(self):
        self.assertEqual(drill.verdict(subprocess.CompletedProcess([], 1, "", "")), "crashed")

    def test_two_mutants_of_one_size_and_one_second_each_get_their_own_verdict(self):
        # 2026-11-18: same mtime, same size, and the second ran the first one's .pyc.
        import os
        import tempfile
        with tempfile.TemporaryDirectory(prefix=SCRATCH_PREFIX) as d:
            work = pathlib.Path(d)
            (work / "test_m.py").write_text(
                "import unittest\nimport m\n\n\nclass T(unittest.TestCase):\n"
                "    def test_a(self):\n        self.assertEqual(m.VALUE, 1)\n", encoding="utf-8")
            verdicts = []
            with mock.patch.object(drill, "SUITES", ("test_m",)):
                for value in ("1", "2"):
                    (work / "m.py").write_text("VALUE = %s\n" % value, encoding="utf-8")
                    os.utime(work / "m.py", (1700000000, 1700000000))
                    verdicts.append(drill.verdict(drill._run_suite(work)))
        self.assertEqual(verdicts, ["passed", "caught"])


class AReadRefusalInvertedIsAForgedPlaintext(unittest.TestCase):
    """2026-11-18, decode-once: a refusal in _read_compact inverted to `return b'{}'` must reach
    the verifier as a plaintext, as it did before the split, through the passthrough the mutant
    copy gives _open_compact. Without it the same mutant only raises AttributeError."""

    JWE = "polaris_oid4vp/jwe.py"

    def setUp(self):
        self.originals = _originals()
        self.lines = self.originals[self.JWE].splitlines(keepends=True)
        self.sites = [u for u in drill.mutation_units(self.originals) if u[0] == "site"]

    def site(self, function, text):
        (u,) = [u for u in self.sites if u[2] == self.JWE and text in self.lines[u[3]]
                and drill._function_of(self.lines, u[3]) == function]
        return u

    def test_only_a_read_refusal_gets_the_passthrough_first_in_open_compact(self):
        marker = "    if isinstance(compact, bytes):  # MUTANT\n        return compact  # MUTANT\n"
        read = self.site("_read_compact", "is not a JSON object")
        text = drill.mutated_text(self.originals[self.JWE], self.JWE, [(read[3], read[4])])
        self.assertEqual(text.count(marker), 1)
        head = text.split(marker)[0].splitlines()
        self.assertTrue(head[-1].startswith("def _open_compact("), head[-1])
        for u in self.sites:
            if u[2] == self.JWE and drill._function_of(self.lines, u[3]) != "_read_compact":
                text = drill.mutated_text(self.originals[self.JWE], self.JWE, [(u[3], u[4])])
                self.assertNotIn(marker, text, u[1])

    def test_the_passthroughs_describe_the_code(self):
        found = [(u[2], u[3], u[4], u[1]) for u in self.sites]
        self.assertEqual(drill.passthrough_drift(self.originals, found), [])
        moved = dict(self.originals)
        moved[self.JWE] = moved[self.JWE].replace("def _open_compact(", "def _opened_compact(")
        self.assertIn("polaris_oid4vp/jwe.py:_open_compact is defined 0 time(s), not once",
                      drill.passthrough_drift(moved, found))

    def test_in_the_real_package_the_mutant_accepts_with_the_passthrough_and_crashes_without(self):
        # Read off the mutated package itself: four parts where five are required, a refusal of
        # _read_compact, inverted. With the passthrough decrypt_compact hands the forged b"{}"
        # on, and test_jwe fails on it; without, the same mutant raises AttributeError, which
        # says nothing about acceptance. A suite's verdict alone no longer tells the two apart,
        # because test_jwe also fails, not errors, on any exception other than JweError.
        import shutil
        import tempfile
        read = self.site("_read_compact", "five dot-separated parts")
        probe = ("from cryptography.hazmat.primitives.asymmetric import ec\n"
                 "from polaris_oid4vp.jwe import decrypt_compact\n"
                 "try:\n"
                 "    print(repr(decrypt_compact('a.b.c.d', ec.generate_private_key(ec.SECP256R1()))))\n"
                 "except Exception as exc:\n"
                 "    print(type(exc).__name__)\n")
        seen, verdicts = {}, {}
        with tempfile.TemporaryDirectory(prefix=SCRATCH_PREFIX) as d:
            pkg = pathlib.Path(d) / "pkg"
            shutil.copytree(drill.PKG, pkg, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", "build"))
            for passthrough in (True, False):
                with mock.patch.dict(drill._PASSTHROUGH, {}, clear=not passthrough):
                    (pkg / self.JWE).write_text(
                        drill.mutated_text(self.originals[self.JWE], self.JWE, [(read[3], read[4])]),
                        encoding="utf-8")
                proc = subprocess.run([sys.executable, "-B", "-c", probe], cwd=str(pkg),
                                      capture_output=True, text=True, timeout=120)
                seen[passthrough] = proc.stdout.strip() or proc.stderr.strip()[-300:]
                if passthrough:
                    with mock.patch.object(drill, "SUITES", ("test_jwe",)):
                        verdicts[passthrough] = drill.verdict(drill._run_suite(pkg))
        self.assertEqual(seen, {True: "b'{}'", False: "AttributeError"})
        self.assertEqual(verdicts, {True: "caught"})


class ItsScratchDirectoriesAreOnesTheCoverageMeasureLeavesOut(unittest.TestCase):
    """2026-11-18: two tests here ran code from a plain TemporaryDirectory, and CI's coverage step
    failed on it (SCRATCH_PREFIX's comment says how). Every scratch directory this file makes is
    found by reading the file, so one added later without the prefix fails here, not in CI."""

    def test_every_scratch_directory_here_is_named_with_the_prefix(self):
        import ast
        names = ("TemporaryDirectory", "mkdtemp", "mkstemp", "NamedTemporaryFile")
        tree = ast.parse((HERE / "test_oid4vp_drill.py").read_text(encoding="utf-8"))
        # tempfile.TemporaryDirectory(...), and TemporaryDirectory(...) imported from tempfile.
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and ((isinstance(node.func, ast.Attribute) and node.func.attr in names)
                      or (isinstance(node.func, ast.Name) and node.func.id in names))]
        self.assertGreaterEqual(len(calls), 3, "the three scratch directories were not found")
        for call in calls:
            with self.subTest(line=call.lineno):
                prefix = [k.value for k in call.keywords if k.arg == "prefix"]
                self.assertEqual(len(prefix), 1, "a scratch directory without a prefix")
                self.assertIsInstance(prefix[0], ast.Name)
                self.assertEqual(prefix[0].id, "SCRATCH_PREFIX")

    def test_the_prefix_is_one_the_coverage_measure_leaves_out(self):
        import configparser
        config = configparser.ConfigParser(interpolation=None)
        config.read_string((HERE.parent / ".coveragerc").read_text(encoding="utf-8"))
        omitted = [line.strip() for line in config.get("run", "omit").splitlines()]
        self.assertIn("*/%s*/*" % SCRATCH_PREFIX, omitted)


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
        # The full run a crash falls back to: the same suites in the same order, not stopped.
        self.assertEqual(drill.unittest_command(failfast=False), command[:3] + command[4:])

    def run_in(self, quick_passes):
        """Two suites of one test each in a scratch package: the quick one passes or fails, the
        slow one leaves a file when it runs. Returns (exit status, whether the slow one ran)."""
        with tempfile.TemporaryDirectory(prefix=SCRATCH_PREFIX) as tmp:
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


class NoStaleBytecode(unittest.TestCase):
    """A mutant is one file rewritten, often to the size of the mutant before it and within the same
    second, which is all a bytecode file is keyed by. A suite run that leaves bytecode behind hands
    the next mutant the previous one's code (2026-11-16: in CI a mutant in a branch nothing reaches
    was reported caught). So a suite run leaves none, whichever interpreter imports the module."""

    #: Two versions of one module, the same length. The suite fails on A and passes on B.
    A = "def f():\n    return 1\n"
    B = "def f():\n    return 2\n"
    #: The module imported by the suite's own interpreter.
    DIRECT = ("import unittest\n\nimport m\n\n\nclass T(unittest.TestCase):\n    def test_f(self):\n"
              "        self.assertEqual(m.f(), 2)\n")
    #: The module imported first by an interpreter the test starts, as test_cli and test_serve start
    #: theirs, then by the suite's own.
    THROUGH_A_CHILD = ("import subprocess\nimport sys\nimport unittest\n\n\nclass T(unittest.TestCase):\n"
                       "    def test_f(self):\n"
                       "        subprocess.run([sys.executable, '-c', 'import m'], check=True)\n"
                       "        import m\n        self.assertEqual(m.f(), 2)\n")

    #: What the scratch package's directory name starts with. The coverage shards record the suite
    #: runs' interpreters too, and their data is combined on another runner, where the scratch
    #: module never existed: measured, it is a "No source for code" report error there.
    #: .coveragerc omits this name.
    SCRATCH = SCRATCH_PREFIX

    def two_versions(self, suite):
        """A, one suite run, then B written at A's size and mtime, and a second run: (the first exit
        status, the second, the bytecode files left behind, the scratch directory's name)."""
        self.assertEqual(len(self.A), len(self.B))
        with tempfile.TemporaryDirectory(prefix=SCRATCH_PREFIX) as tmp:
            work = pathlib.Path(tmp)
            (work / "test_m.py").write_text(suite)
            module = work / "m.py"
            module.write_text(self.A)
            stamp = module.stat()
            with mock.patch.object(drill, "SUITES", ("test_m",)), mock.patch.object(drill, "SLOW_SUITES", ()), \
                    mock.patch.dict(os.environ):
                # Whatever the caller of these tests set, the drill's own setting is what is tested.
                os.environ.pop("PYTHONDONTWRITEBYTECODE", None)
                first = drill._run_suite(work).returncode
                module.write_text(self.B)
                os.utime(module, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
                second = drill._run_suite(work).returncode
            return first, second, sorted(p.name for p in work.rglob("*.pyc")), work.name

    def test_a_rewrite_of_the_same_size_and_time_runs_its_own_code(self):
        for name, suite in (("direct", self.DIRECT), ("through a child", self.THROUGH_A_CHILD)):
            with self.subTest(imported=name):
                first, second, left, where = self.two_versions(suite)
                self.assertNotEqual(first, 0)
                self.assertEqual(second, 0)
                self.assertEqual(left, [])
                self.assertTrue(where.startswith(self.SCRATCH), where)

    def test_the_scratch_name_is_one_the_coverage_measure_leaves_out(self):
        omitted = [line.strip() for line in (HERE.parent / ".coveragerc").read_text().splitlines()]
        self.assertIn("*/%s*/*" % self.SCRATCH, omitted)


if __name__ == "__main__":
    unittest.main()
