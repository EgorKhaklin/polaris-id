"""test_conformance_runner.py -- the conformance runner, held to scoring a WRONG verifier as wrong.

`conformance/run_conformance.py` is how an outside team certifies its own verifier: point the
runner at it and read the exit code. Every instrument in the tree ran the runner against a
verifier that is RIGHT (the Python SDK, the TypeScript SDK, the detached verifier), and a
runner that passes everything passes all of those. On 2026-09-23 a held-out round mutated the
runner itself: a case scored as conforming when ANY expected key matched rather than every
one, `authentic` not compared at all, a key the verifier omits counted as a match, one
failure treated as not fatal, the VOID rule switched off, the last case skipped. Every
instrument stayed green.

So these tests drive the runner against verifiers that are wrong on purpose, one defect
each, and assert the exit code the runner documents: 0 iff every case matches, 1 on any
mismatch, 2 if a case could not be run or the run is VOID. The fake verifier answers from
the case's own expected verdict, looked up by the payload the runner sends, and then corrupts
exactly one thing, so each test isolates one scoring rule.

Run: python3 -m unittest test_conformance_runner   (from scripts/)
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shlex
import sys
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

_spec = importlib.util.spec_from_file_location(
    "run_conformance", os.path.join(_ROOT, "conformance", "run_conformance.py"))
R = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R)

_FAKE = r'''
import hashlib, json, os, sys
payload = sys.stdin.read()
key = hashlib.sha256(json.dumps(json.loads(payload), sort_keys=True).encode()).hexdigest()
with open(os.environ["FAKE_ORACLE"]) as f:
    oracle = json.load(f)
entry = oracle[key]
verdict, mode = dict(entry["expect"]), os.environ.get("FAKE_MODE", "faithful")
if mode == "flip_last" and entry["last"]:
    verdict["authentic"] = not verdict["authentic"]
elif mode == "accept_all":
    verdict["authentic"] = True
elif mode == "reject_all":
    verdict["authentic"] = False
elif mode == "drop_other":
    verdict = {k: v for k, v in verdict.items() if k == "authentic"}
elif mode == "wrong_other_once" and entry["other"]:
    k = entry["other"]
    verdict[k] = not verdict[k]
print(json.dumps(verdict))
if mode == "exit_1" and entry["last"]:
    sys.exit(1)
'''


def _key(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _subset():
    """A genuine case, a tampered one, and a case constraining a second key; the case with
    the second key is last, so "the last case" and "a second key" are both exercised."""
    cases = R._load_cases()
    genuine = next(c for c in cases if c[2] == {"authentic": True})
    tampered = next(c for c in cases if c[2] == {"authentic": False})
    two_keys = next(c for c in cases if set(c[2]) == {"authentic", "fresh"}
                    and c[2]["authentic"] is True and isinstance(c[2]["fresh"], bool))
    return [genuine, tampered, two_keys]


class TheRunnerScoresWrongVerifiersAsWrong(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="polaris-runner-test-")
        cls.cases = _subset()
        oracle = {}
        for i, (_name, payload, expect) in enumerate(cls.cases):
            other = next((k for k in expect if k != "authentic"), None)
            oracle[_key(payload)] = {"expect": expect, "last": i == len(cls.cases) - 1,
                                     "other": other}
        cls.oracle = os.path.join(cls.tmp, "oracle.json")
        with open(cls.oracle, "w") as f:
            json.dump(oracle, f)
        cls.fake = os.path.join(cls.tmp, "fake_verifier.py")
        with open(cls.fake, "w") as f:
            f.write(_FAKE)

    def run_with(self, mode):
        cmd = "%s %s" % (shlex.quote(sys.executable), shlex.quote(self.fake))
        env = {"FAKE_ORACLE": self.oracle, "FAKE_MODE": mode}
        with mock.patch.object(R, "_load_cases", return_value=self.cases), \
                mock.patch.dict(os.environ, env), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return R.main(["--verifier", cmd])

    def test_a_faithful_verifier_conforms(self):
        """The positive control: without it every test below could pass on a runner that
        fails everything."""
        self.assertEqual(self.run_with("faithful"), 0)

    def test_one_wrong_verdict_on_the_last_case_fails_the_run(self):
        self.assertEqual(self.run_with("flip_last"), 1,
                         "one mismatch is a failure, and the last case is scored like the rest")

    def test_a_verifier_that_accepts_tampered_material_fails(self):
        self.assertEqual(self.run_with("accept_all"), 1, "authentic must be compared")

    def test_a_verifier_that_omits_a_constrained_key_fails(self):
        self.assertEqual(self.run_with("drop_other"), 1,
                         "a key the case constrains and the verdict lacks is a mismatch, not a pass")

    def test_every_constrained_key_must_match_not_any(self):
        self.assertEqual(self.run_with("wrong_other_once"), 1,
                         "authentic right and fresh wrong is a mismatch")

    def test_a_verifier_that_refuses_everything_is_void_not_conformant_or_merely_failing(self):
        self.assertEqual(self.run_with("reject_all"), 2,
                         "no positive control passed, so the refusals prove nothing: VOID")

    def test_a_verifier_that_exits_non_zero_could_not_be_run(self):
        """It prints a CORRECT verdict and then exits 1. Written first as an exit with no
        output, and the runner's JSON parse refused that, so the exit-code check could be
        deleted with this test green: a different mechanism satisfied it."""
        self.assertEqual(self.run_with("exit_1"), 2)


if __name__ == "__main__":
    unittest.main()
