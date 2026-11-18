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

    def run_shard(self, shard, survive, crash=(), control=None):
        """main() on one shard. A label in `survive` passes; one in `crash` is red by ERROR alone;
        every other mutation fails a test. `control` replaces the negative control's result."""
        made = []

        def suite(work):
            for source in drill.SOURCES + ("polaris_oid4vp/serve.py",):
                label = self.by_text.get((work / source).read_text(encoding="utf-8"))
                if label is not None:
                    made.append(label)
                    if label in survive:
                        return PASSED
                    return CRASHED if label in crash else FAILED_ONE
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
        with tempfile.TemporaryDirectory() as d:
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
        with tempfile.TemporaryDirectory() as d:
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
        with tempfile.TemporaryDirectory() as d:
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


if __name__ == "__main__":
    unittest.main()
