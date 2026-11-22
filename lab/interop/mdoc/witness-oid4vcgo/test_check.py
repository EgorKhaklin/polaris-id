#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_check.py -- check.py passes the row shape the vectors call for, and fails on each broken case made here.

The rows are made here from the tree's mdoc-vectors.json, the shape main.go writes when OID4VCgo judges
every vector as the vector says; no witness run, no network. mdoc-witness.yml runs this before the witness.

    python3 -I lab/interop/mdoc/witness-oid4vcgo/test_check.py
"""
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "..", "negative-vectors", "mdoc-vectors.json")
_spec = importlib.util.spec_from_file_location("witness_check", os.path.join(HERE, "check.py"))
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)


def verdict(outcome, inputs):
    if check.runs_verify_response(inputs):
        return {"outcome": outcome}
    return {"outcome": "", "not_run": "a redirect-flow Verifier's client_id is derived from its own certificate"}


def rows_as_the_vectors_say(vectors):
    rows = []
    for v in vectors:
        want = check.WANT[v["expected"]]
        rows.append({"name": v["id"], "variant": "case", "composed": {"outcome": want},
                     "verify_response": verdict(want, v["inputs"])})
        if "repaired" in v:
            rows.append({"name": v["id"], "variant": "repaired", "composed": {"outcome": "accepted"},
                         "verify_response": verdict("accepted", v["repaired"]["inputs"])})
    return rows


class CheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VECTORS, encoding="utf-8") as f:
            cls.vectors = json.load(f)["vectors"]
        cls.good = rows_as_the_vectors_say(cls.vectors)
        cls.dc_api = [r for r in cls.good if "not_run" not in r["verify_response"]]

    def problems(self, rows, vectors=None):
        return check.problems_of(rows, self.vectors if vectors is None else vectors)[0]

    def test_the_rows_the_vectors_call_for_pass(self):
        self.assertTrue(self.vectors and self.dc_api)
        self.assertEqual(self.problems(self.good), [])

    def test_verify_response_run_on_no_row_fails_once_per_dc_api_row(self):
        rows = copy.deepcopy(self.good)
        for r in rows:
            r["verify_response"] = {"outcome": "", "not_run": "stopped"}
        got = self.problems(rows)
        self.assertEqual(len(got), len(self.dc_api), got)
        self.assertTrue(all("not run, though its inputs say dc_api.jwt" in p for p in got), got)

    def test_a_dc_api_control_refused_on_verify_response_fails(self):
        rows = copy.deepcopy(self.good)
        accepted = [r for r in rows if r["verify_response"].get("outcome") == "accepted"]
        self.assertTrue(accepted)
        accepted[0]["verify_response"] = {"outcome": "refused", "error": "x"}
        got = self.problems(rows)
        self.assertEqual(len(got), 1, got)
        self.assertIn("on verify_response: refused, the vector says accepted", got[0])

    def test_a_case_accepted_on_the_composed_path_against_its_vector_fails(self):
        rows = copy.deepcopy(self.good)
        rejected = [r for r in rows if r["composed"]["outcome"] == "refused"]
        self.assertTrue(rejected)
        rejected[0]["composed"] = {"outcome": "accepted"}
        self.assertEqual(len(self.problems(rows)), 1)

    def test_a_missing_outcome_fails(self):
        rows = copy.deepcopy(self.good)
        rows[0]["composed"] = {}
        self.assertIn("no outcome", " ".join(self.problems(rows)))

    def test_no_rows_fail(self):
        self.assertIn("the witness wrote no rows", self.problems([]))

    def test_a_missing_row_fails(self):
        self.assertIn("0 rows, not 1", " ".join(self.problems(self.good[1:])))

    def test_a_duplicated_row_fails(self):
        self.assertIn("2 rows, not 1", " ".join(self.problems(self.good + self.good[:1])))

    def test_a_row_for_no_vector_fails(self):
        extra = dict(self.good[0], name="md-no-such-vector")
        self.assertIn("no such vector in the file", " ".join(self.problems(self.good + [extra])))

    def test_no_vectors_fail(self):
        self.assertIn("the vectors file holds no vectors", self.problems(self.good, []))

    def test_vectors_with_no_dc_api_inputs_fail(self):
        vectors = copy.deepcopy(self.vectors)
        for v in vectors:
            v["inputs"]["response_mode"] = "direct_post.jwt"
            if "repaired" in v:
                v["repaired"]["inputs"]["response_mode"] = "direct_post.jwt"
        rows = rows_as_the_vectors_say(vectors)
        self.assertIn("VerifyResponse is held to no row", " ".join(self.problems(rows, vectors)))

    def test_an_unknown_expected_fails(self):
        vectors = copy.deepcopy(self.vectors)
        vectors[0]["expected"] = "maybe"
        self.assertTrue(self.problems(self.good, vectors))

    def test_the_command_exits_0_on_the_good_rows_and_1_on_none(self):
        with tempfile.TemporaryDirectory() as d:
            good, empty = os.path.join(d, "good.jsonl"), os.path.join(d, "empty.jsonl")
            with open(good, "w", encoding="utf-8") as f:
                f.write("".join(json.dumps(r) + "\n" for r in self.good))
            open(empty, "w", encoding="utf-8").close()
            run = [sys.executable, "-I", os.path.join(HERE, "check.py")]
            self.assertEqual(subprocess.run(run + [good, VECTORS], capture_output=True).returncode, 0)
            self.assertEqual(subprocess.run(run + [empty, VECTORS], capture_output=True).returncode, 1)
            self.assertEqual(subprocess.run(run + [good], capture_output=True).returncode, 2)


if __name__ == "__main__":
    unittest.main()
