# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The procedure mutation drill's shards cover every refusal exactly once.

CI runs the drill as N parallel shards (`--shard I/N`) rather than one job of 1h45m. Sharding
must lose nothing: the N shards together mutate exactly the refusals one unsharded run mutates,
no refusal twice, and each shard's survivor comparison answers for what that shard mutated.
These tests prove the partition, then run the drill's main() against an in-memory catalog with
every shard count and compare what the shards did with what one run does. No database.

    python3 -m unittest test_procedure_drill      (from scripts/)
"""
import contextlib
import importlib.util
import io
import random
import re
import sys
import pathlib
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location("procedure_drill", HERE / "polaris-procedure-mutation-drill.py")
drill = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drill)

#: Refusals per procedure as CI measured them on 2026-10-10 (103 across 21 procedures).
CI_COUNTS = {
    "close_anchor_batch": 3, "uc_apply_retention_template": 4, "uc_archive_purge": 10,
    "uc_bulk_issue": 6, "uc_ensure_event_partitions": 1, "uc_issue_credential_copy": 6,
    "uc_pseudonymize_individual": 6, "uc_record_holder_key_event": 5, "uc_set_retention_policy": 3,
    "uc1_issue_and_activate": 2, "uc10_attest_trust": 5, "uc10_revoke_attestation": 5,
    "uc11_close_epoch": 6, "uc12_record_duress": 1, "uc4_activate_reserve": 7, "uc5_bind_device": 3,
    "uc6_migrate_algorithm": 2, "uc8_revoke_token": 5, "uc9_complete_recovery": 10,
    "uc9_initiate_recovery": 2, "uc9_record_recovery_channel": 11,
}
SHARD_COUNTS = (1, 2, 3, 5, 6)      # 6 is what CI runs


def _cases(counts):
    return [(name, idx, 0, 0, "text") for name, n in counts.items() for idx in range(n)]


def _units(cases):
    return {"%s#%d" % (c[0], c[1]) for c in cases}


class PartitionTests(unittest.TestCase):

    def assert_partition(self, cases, n):
        full = _units(cases)
        shards = [_units(drill.shard_cases(cases, (i, n))) for i in range(1, n + 1)]
        self.assertEqual(set().union(*shards), full, "shards of %d miss a refusal" % n)
        for a in range(n):
            for b in range(a + 1, n):
                self.assertFalse(shards[a] & shards[b], "shards %d and %d of %d overlap"
                                 % (a + 1, b + 1, n))
        self.assertEqual(sum(len(s) for s in shards), len(cases))
        sizes = [len(s) for s in shards]
        self.assertLessEqual(max(sizes) - min(sizes), 1, "uneven shards %r" % sizes)
        return shards

    def test_the_shards_cover_the_ci_set_exactly_once(self):
        cases = _cases(CI_COUNTS)
        self.assertEqual(len(cases), 103)
        for n in SHARD_COUNTS:
            with self.subTest(n=n):
                self.assert_partition(cases, n)

    def test_more_shards_than_refusals_leaves_empty_shards_and_still_covers_all(self):
        cases = _cases({"uc12_record_duress": 1, "uc5_bind_device": 2})
        shards = self.assert_partition(cases, 5)
        self.assertEqual([len(s) for s in shards], [1, 1, 1, 0, 0])
        self.assertEqual(drill.shard_cases([], (2, 3)), [])

    def test_the_deal_does_not_depend_on_the_catalog_order(self):
        cases = _cases(CI_COUNTS)
        shuffled = cases[:]
        random.Random(7).shuffle(shuffled)
        for n in SHARD_COUNTS:
            for i in range(1, n + 1):
                self.assertEqual(drill.shard_cases(shuffled, (i, n)), drill.shard_cases(cases, (i, n)))

    def test_one_shard_is_the_unsharded_run(self):
        cases = _cases(CI_COUNTS)
        self.assertEqual(drill.shard_cases(cases, (1, 1)), sorted(cases, key=lambda c: (c[0], c[1])))

    def test_a_procedures_refusals_are_dealt_across_shards(self):
        # Round-robin, not blocks: the eleven cheap uc9_record_recovery_channel refusals must not
        # all land on one shard while another gets every uc8_revoke_token one.
        cases = _cases(CI_COUNTS)
        holders = {i for i in range(1, 7)
                   if any(c[0] == "uc9_record_recovery_channel" for c in drill.shard_cases(cases, (i, 6)))}
        self.assertEqual(holders, set(range(1, 7)))

    def test_parse_shard(self):
        self.assertEqual(drill.parse_shard("2/6"), (2, 6))
        self.assertEqual(drill.parse_shard("1/1"), (1, 1))
        for bad in ("0/6", "7/6", "6", "a/b", "1/0", "", "-1/3"):
            with self.subTest(bad=bad), self.assertRaises(Exception):
                drill.parse_shard(bad)


class DeclaredSurvivorTests(unittest.TestCase):
    EXPECTED = {"p1#1": "x", "p1#9": "a stale index: p1 has three refusals", "p2#0": "y",
                "p4#0": "p4 is measured by nothing"}

    def test_the_shards_answer_for_what_one_run_answers_for(self):
        counts = {"p1": 3, "p2": 2, "p3": 4, "p4": 1}
        cases = _cases(counts)
        full = _units(cases)
        measured_procs = {"p1", "p2", "p3"}            # no test class names p4
        unmeasurable = {u for u in full if u.startswith("p4#")}
        with mock.patch.object(drill, "SURVIVORS_EXPECTED", self.EXPECTED):
            # Unsharded, the result is the procedure-level filter the drill always applied.
            one = drill.declared_survivors(full - unmeasurable, full, measured_procs)
            self.assertEqual(one, {k for k in self.EXPECTED if k.split("#")[0] in measured_procs})
            for n in SHARD_COUNTS:
                per = [drill.declared_survivors(_units(drill.shard_cases(cases, (i, n))) - unmeasurable,
                                                full, measured_procs) for i in range(1, n + 1)]
                self.assertEqual(set().union(*per), one, "n=%d" % n)
                # The stale entry belongs to no shard, so every shard reports it.
                self.assertTrue(all("p1#9" in d for d in per), "n=%d" % n)
                # A live entry is answered for by exactly the one shard that mutated it.
                self.assertEqual(sum("p1#1" in d for d in per), 1, "n=%d" % n)


class FakeCatalog:
    """The drill's database, in memory: bodies by name, and a test suite that goes red when a
    mutated refusal is not one of `survivors`."""

    def __init__(self, counts, survivors=()):
        self.orig = {
            name: "CREATE OR REPLACE FUNCTION public.%s()\n AS $$ BEGIN\n%s END $$;\n" % (
                name, "".join("  IF x THEN RAISE EXCEPTION '%s r%d'; END IF;\n" % (name, i)
                              for i in range(n)))
            for name, n in counts.items()}
        self.now = dict(self.orig)
        self.survivors = set(survivors)
        self.mutated = []

    def install(self, _conn, sql):
        name = re.search(r"FUNCTION public\.(\w+)", sql).group(1)
        self.now[name] = sql
        if drill.MUTATION_MARK in sql:
            gone = [m for m in re.findall(r"'(\w+ r\d+)'", self.orig[name]) if m not in sql]
            self.mutated.append(gone[0].replace(" r", "#"))
        return ""

    def definitions(self, _conn):
        return dict(self.now)

    def red(self, _env, targets, show=False):
        if not targets:
            return False
        for name, body in self.now.items():
            if drill.MUTATION_MARK in body:
                gone = [m for m in re.findall(r"'(\w+ r\d+)'", self.orig[name]) if m not in body]
                return gone[0].replace(" r", "#") not in self.survivors
        return False


class MainTests(unittest.TestCase):
    COUNTS = {"p%02d" % i: n for i, n in enumerate((3, 1, 0, 5, 2, 7, 1, 4, 0, 2, 6, 3))}  # 34

    def run_main(self, argv, survivors=("p05#2",), expected=None):
        db = FakeCatalog(self.COUNTS, survivors)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(drill, "_interpreter_can_run_the_suite", lambda *a: ""), \
                mock.patch.object(drill, "_connect", lambda env: mock.Mock()), \
                mock.patch.object(drill, "_left_mutated", lambda conn: []), \
                mock.patch.object(drill, "_definitions", db.definitions), \
                mock.patch.object(drill, "_install", db.install), \
                mock.patch.object(drill, "_suites_red", db.red), \
                mock.patch.object(drill, "_classes_exercising", lambda name: ["test_app.T"]), \
                mock.patch.object(drill, "CONTROL", ("p00", "'p00 r0'")), \
                mock.patch.object(drill, "SURVIVORS_EXPECTED",
                                  expected if expected is not None else {"p05#2": "declared"}), \
                mock.patch.dict("os.environ", {"POLARIS_DB_NAME": "polaris_test"}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = drill.main(argv)
        # The negative control is mutated first in every run that is not --only; it is not a case.
        cases = db.mutated[1:] if "--only" not in argv else db.mutated
        return rc, cases, out.getvalue() + err.getvalue()

    def test_the_shards_together_mutate_what_one_run_mutates(self):
        rc, one, _ = self.run_main([])
        self.assertEqual(rc, 0)
        full = {"%s#%d" % (n, i) for n, c in self.COUNTS.items() for i in range(c)}
        self.assertEqual(sorted(one), sorted(full))
        for n in SHARD_COUNTS:
            seen = []
            for i in range(1, n + 1):
                rc, mutated, text = self.run_main(["--shard", "%d/%d" % (i, n)])
                self.assertEqual(rc, 0, "shard %d/%d: %s" % (i, n, text))
                seen += mutated
            self.assertEqual(sorted(seen), sorted(one), "n=%d mutates a different set" % n)

    def test_an_undeclared_survivor_fails_exactly_the_shard_that_holds_it(self):
        for n in (1, 3, 5):
            failed = [i for i in range(1, n + 1)
                      if self.run_main(["--shard", "%d/%d" % (i, n)], survivors=("p05#2", "p10#4"))[0]]
            self.assertEqual(len(failed), 1, "n=%d: failed shards %r" % (n, failed))

    def test_a_stale_declaration_fails_every_shard(self):
        stale = {"p05#2": "declared", "p05#40": "p05 has no refusal 40"}
        for n in (1, 3, 5):
            for i in range(1, n + 1):
                rc, _, text = self.run_main(["--shard", "%d/%d" % (i, n)], expected=stale)
                self.assertEqual(rc, 1, "shard %d/%d" % (i, n))
                self.assertIn("strike them: p05#40", text)

    def test_a_shard_with_no_refusal_says_so_and_touches_nothing(self):
        # p01 has one refusal; of three shards, two get nothing.
        results = [self.run_main(["--only", "p01", "--shard", "%d/3" % i]) for i in (1, 2, 3)]
        self.assertEqual([r[0] for r in results], [0, 0, 0])
        self.assertEqual([len(r[1]) for r in results], [1, 0, 0])
        for _rc, _m, text in results[1:]:
            self.assertIn("has no refusal to mutate", text)
            self.assertIn("nothing is claimed here", text)
            self.assertNotIn("OK:", text)

    def test_an_empty_shard_that_should_hold_work_fails(self):
        # A partition bug: shard_cases hands a shard nothing although the set reaches it.
        with mock.patch.object(drill, "shard_cases", lambda cases, shard: []):
            rc, mutated, text = self.run_main(["--shard", "2/3"])
        self.assertEqual(rc, 1)
        self.assertEqual(mutated, [])
        self.assertIn("partition has dropped work", text)
        # Shard 3 of 3 over a one-refusal set is the legitimate empty share, and still passes.
        with mock.patch.object(drill, "shard_cases", lambda cases, shard: []):
            rc, _, text = self.run_main(["--only", "p01", "--shard", "3/3"])
        self.assertEqual(rc, 0, text)
        self.assertIn("has no refusal to mutate", text)

    def test_an_empty_full_set_still_fails_in_every_shard(self):
        for i in (1, 2, 3):
            rc, mutated, text = self.run_main(["--only", "nonexistent", "--shard", "%d/3" % i])
            self.assertEqual(rc, 1)
            self.assertEqual(mutated, [])
            self.assertIn("no refusal was found to mutate", text)

    def test_the_negative_control_runs_in_a_shard_that_does_not_hold_it(self):
        # p00#0 is the control; with five shards it falls to shard 1 only.
        db_runs = self.run_main(["--shard", "2/5"])
        self.assertEqual(db_runs[0], 0)
        self.assertIn("negative control: deleting a tested refusal", db_runs[2])
        self.assertNotIn("p00#0", db_runs[1])


if __name__ == "__main__":
    unittest.main()
