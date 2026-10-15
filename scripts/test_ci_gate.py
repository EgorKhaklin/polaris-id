# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""scripts/polaris-ci-gate.py: a gate passes a part that succeeded, or that was skipped with the
changes job's "false" behind the skip, and nothing else.

GitHub reports a skipped required check as passing, so the one thing a gate must never do is
read "skipped" as "passed". Each case here is a result the gate can be handed: every way a part
can end, every way the changes job's outputs can be wrong, and every way the results can fail to
be there at all. The last class reads the gate's invocation out of ci.yml, so the workflow and
these cases cannot drift apart. No network, no database.

    python3 -m unittest test_ci_gate      (from scripts/)
"""
import importlib.util
import io
import json
import os
import pathlib
import shlex
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
_spec = importlib.util.spec_from_file_location("polaris_ci_gate", HERE / "polaris-ci-gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

WHEN = {"full": ["test-app-role", "test-zk"], "oid4vp": ["test-oid4vp-drill"]}
ALWAYS = ["test-core"]


def results(changes="success", full="true", oid4vp="true", **parts):
    """A toJSON(needs) document: every part successful unless named otherwise."""
    out = {"changes": {"result": changes, "outputs": {"full": full, "oid4vp": oid4vp}}}
    for job in ("test-core", "test-app-role", "test-zk", "test-oid4vp-drill"):
        out[job] = {"result": parts.pop(job.replace("-", "_"), "success"), "outputs": {}}
    assert not parts, parts
    return json.dumps(out)


def judge(text, changes="changes", when=None, always=None):
    return gate.judge(text, changes, WHEN if when is None else when, ALWAYS if always is None else always)


class EachPartIsJudged(unittest.TestCase):

    def test_every_part_succeeding_passes(self):
        ok, lines = judge(results())
        self.assertTrue(ok, lines)

    def test_a_skip_the_changes_job_explains_passes(self):
        ok, lines = judge(results(full="false", oid4vp="false", test_app_role="skipped",
                                  test_zk="skipped", test_oid4vp_drill="skipped"))
        self.assertTrue(ok, lines)
        self.assertIn("ok   test-zk: skipped, and full=false says this change does not need it", lines)

    def test_a_skip_while_the_output_says_needed_fails(self):
        ok, lines = judge(results(full="true", test_zk="skipped"))
        self.assertFalse(ok)
        self.assertIn("FAIL test-zk: skipped, but full=true says this change needs it", lines)

    def test_a_skip_under_the_wrong_output_fails(self):
        # oid4vp=false explains the OID4VP drill, never a job full governs.
        ok, _ = judge(results(full="true", oid4vp="false", test_app_role="skipped"))
        self.assertFalse(ok)

    def test_a_skipped_part_no_output_governs_fails(self):
        ok, lines = judge(results(full="false", test_core="skipped"))
        self.assertFalse(ok)
        self.assertIn("FAIL test-core: skipped, and no output of the changes job governs it", lines)

    def test_a_failure_fails(self):
        for job in ("test_core", "test_zk", "test_oid4vp_drill"):
            ok, _ = judge(results(**{job: "failure"}))
            self.assertFalse(ok, job)

    def test_a_cancellation_fails(self):
        for job in ("test_core", "test_app_role"):
            ok, _ = judge(results(**{job: "cancelled"}))
            self.assertFalse(ok, job)

    def test_a_failure_is_not_excused_by_a_false_output(self):
        ok, _ = judge(results(full="false", test_zk="failure"))
        self.assertFalse(ok)


class TheChangesJobMustSpeak(unittest.TestCase):

    def test_a_failed_changes_job_fails_even_with_every_part_green(self):
        ok, lines = judge(results(changes="failure"))
        self.assertFalse(ok)
        self.assertTrue(any(line.startswith("FAIL changes: failure") for line in lines), lines)

    def test_a_skipped_or_cancelled_changes_job_fails(self):
        for r in ("skipped", "cancelled"):
            ok, _ = judge(results(changes=r))
            self.assertFalse(ok, r)

    def test_an_output_that_is_not_true_or_false_fails(self):
        for v in ("", "True", "yes", "0", None):
            doc = json.loads(results(full="false", test_zk="skipped", test_app_role="skipped"))
            doc["changes"]["outputs"]["full"] = v
            ok, _ = judge(json.dumps(doc))
            self.assertFalse(ok, repr(v))

    def test_a_missing_output_fails(self):
        doc = json.loads(results())
        del doc["changes"]["outputs"]["oid4vp"]
        ok, _ = judge(json.dumps(doc))
        self.assertFalse(ok)
        doc["changes"].pop("outputs")
        ok, _ = judge(json.dumps(doc))
        self.assertFalse(ok)

    def test_outputs_named_without_a_changes_job_fail(self):
        ok, _ = judge(results(), changes=None)
        self.assertFalse(ok)


class TheResultsMustBeThere(unittest.TestCase):

    def test_a_missing_need_fails(self):
        doc = json.loads(results())
        del doc["test-zk"]
        ok, lines = judge(json.dumps(doc))
        self.assertFalse(ok)
        self.assertIn("FAIL the results do not mention test-zk, which this gate needs", lines)

    def test_a_result_the_gate_was_not_told_about_fails(self):
        doc = json.loads(results())
        doc["test-new"] = {"result": "skipped", "outputs": {}}
        ok, _ = judge(json.dumps(doc))
        self.assertFalse(ok)

    def test_empty_or_unparseable_results_fail(self):
        for text in ("", "   ", "null", "[]", "{}", "not json", '{"test-core": "success"', "42", '"success"'):
            ok, _ = judge(text)
            self.assertFalse(ok, repr(text))

    def test_a_result_that_is_not_a_string_fails(self):
        doc = json.loads(results())
        doc["test-core"] = {"result": None}
        self.assertFalse(judge(json.dumps(doc))[0])
        doc["test-core"] = "success"
        self.assertFalse(judge(json.dumps(doc))[0])

    def test_a_gate_told_about_nothing_fails(self):
        ok, _ = gate.judge(json.dumps({"x": {"result": "success"}}), None, {}, [])
        self.assertFalse(ok)

    def test_a_job_under_two_outputs_or_also_always_fails(self):
        self.assertFalse(judge(results(), when={"full": ["test-zk"], "oid4vp": ["test-zk"]})[0])
        self.assertFalse(judge(results(), when={"full": ["test-zk", "test-app-role"],
                                                "oid4vp": ["test-oid4vp-drill"]},
                               always=["test-core", "test-zk"])[0])

    def test_a_gate_with_no_outputs_requires_success(self):
        text = json.dumps({"test-coverage-shard": {"result": "success", "outputs": {}}})
        self.assertTrue(gate.judge(text, None, {}, ["test-coverage-shard"])[0])
        for r in ("skipped", "failure", "cancelled"):
            text = json.dumps({"test-coverage-shard": {"result": r, "outputs": {}}})
            self.assertFalse(gate.judge(text, None, {}, ["test-coverage-shard"])[0], r)


class TheCommandLine(unittest.TestCase):

    def run_main(self, argv, text):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"RESULTS": text}), redirect_stdout(out):
            code = gate.main(argv)
        return code, out.getvalue()

    def test_exit_codes(self):
        argv = ["--changes", "changes", "--always", "test-core",
                "--when", "full=test-app-role,test-zk", "--when", "oid4vp=test-oid4vp-drill"]
        code, out = self.run_main(argv, results())
        self.assertEqual(code, 0, out)
        self.assertIn("gate: PASSED", out)
        code, out = self.run_main(argv, results(test_zk="failure"))
        self.assertEqual(code, 1, out)
        self.assertIn("gate: FAILED", out)
        code, _ = self.run_main(argv, "")
        self.assertEqual(code, 1)

    def test_a_malformed_when_fails(self):
        for bad in ("full", "full=", "=test-zk", "full=,"):
            code, _ = self.run_main(["--changes", "changes", "--when", bad], results())
            self.assertEqual(code, 1, bad)


class TheWorkflowsGate(unittest.TestCase):
    """The required gate as ci.yml invokes it, against results shaped like its own needs."""

    @classmethod
    def setUpClass(cls):
        import yaml
        jobs = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"]
        cls.jobs = jobs
        gate_job = next(j for j in jobs.values() if j.get("name") == "Polaris product test suite")
        cls.needs = gate_job["needs"]
        cmd = next(s["run"] for s in gate_job["steps"] if "polaris-ci-gate.py" in s.get("run", ""))
        cls.argv = shlex.split(cmd)[2:]
        cls.condition = gate_job.get("if")

    def doc(self, overrides=None, outputs=None):
        d = {j: {"result": "success", "outputs": {}} for j in self.needs}
        d["changes"]["outputs"] = dict({"full": "true", "oid4vp": "true", "sdk": "true"}, **(outputs or {}))
        for j, r in (overrides or {}).items():
            d[j]["result"] = r
        return json.dumps(d)

    def governed(self, output):
        return [j for j in self.needs
                if self.jobs[j].get("if") == "needs.changes.outputs.%s == 'true'" % output]

    def run_gate(self, text):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"RESULTS": text}), redirect_stdout(out):
            return gate.main(self.argv), out.getvalue()

    def test_the_gate_runs_always(self):
        self.assertEqual(self.condition, "always()")

    def test_all_green_passes(self):
        code, out = self.run_gate(self.doc())
        self.assertEqual(code, 0, out)

    def test_every_job_the_outputs_can_skip_is_judged_by_its_own_output(self):
        for output in ("full", "oid4vp", "sdk"):
            jobs = self.governed(output)
            self.assertTrue(jobs, output)
            skipped = {j: "skipped" for j in jobs}
            code, out = self.run_gate(self.doc(skipped, {output: "false"}))
            self.assertEqual(code, 0, out)
            code, out = self.run_gate(self.doc(skipped, {output: "true"}))
            self.assertEqual(code, 1, out)

    def test_a_docs_only_change_passes_with_everything_skippable_skipped(self):
        skipped = {j: "skipped" for o in ("full", "oid4vp", "sdk") for j in self.governed(o)}
        code, out = self.run_gate(self.doc(skipped, {"full": "false", "oid4vp": "false", "sdk": "false"}))
        self.assertEqual(code, 0, out)

    def test_each_need_failing_or_skipped_without_cause_fails_the_gate(self):
        for job in self.needs:
            for r in ("failure", "cancelled"):
                code, _ = self.run_gate(self.doc({job: r}))
                self.assertEqual(code, 1, (job, r))
            if job != "changes":
                code, _ = self.run_gate(self.doc({job: "skipped"}))
                self.assertEqual(code, 1, (job, "skipped while needed"))


if __name__ == "__main__":
    unittest.main()
