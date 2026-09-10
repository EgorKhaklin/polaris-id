"""test_ship_tool.py — the triage tool's flake classifier (roadmap P1.16, v9.377).

`triage` exists so a red CI run gets one of two answers quickly: this is a known flake, rerun
it; or this is real, here are the first failing lines. Both answers are load-bearing, and the
expensive failure is the third one it used to give by accident, which is a confident
"investigate" over a log it never actually read.

These are unit tests over the pure classifier, so a new signature is verified against the log
line it was written for rather than by pushing and waiting twenty minutes to find out.
"""
import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        "polaris_ship_tool", os.path.join(_HERE, "polaris-ship.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ship = _load()

# The real line, from the run that prompted the signature. Kept verbatim: a signature tested
# against a paraphrase of its log is a signature tested against nothing.
ALPINE_PIP = (
    'Docker image build\t\t2026-09-10T22:17:12.4862682Z ERROR: failed to build: failed to '
    'solve: process "/bin/sh -c apk add --no-cache python3     && apk add --no-cache '
    '--virtual .pip py3-pip     && pip3 install --no-cache-dir --break-system-packages -r '
    '/tmp/requirements-patroni.txt     && apk del .pip     && rm -f '
    '/tmp/requirements-patroni.txt     && patroni --version" did not complete successfully: '
    'exit code: 1')


class FlakeClassifierTests(unittest.TestCase):
    def test_the_alpine_pip_layer_is_a_known_flake(self):
        verdict, name, advice = ship.classify_failure_log(ALPINE_PIP)
        self.assertEqual((verdict, name), ("flake", "alpine-pip-layer"))
        self.assertIn("docker build --no-cache", advice,
                      "the advice must say how to CONFIRM it is a flake, not just assert it")

    def test_the_apt_index_flake_still_classifies(self):
        for line in ("E: Failed to fetch http://azure.archive.ubuntu.com",
                     "Hash Sum mismatch",
                     "Some index files failed to download"):
            with self.subTest(line=line[:30]):
                self.assertEqual(ship.classify_failure_log(line)[1], "apt-index")

    def test_the_caddy_module_proxy_flake_still_classifies(self):
        self.assertEqual(
            ship.classify_failure_log("verifying sum.golang.org: stream error")[1],
            "caddy-module-proxy")

    def test_a_real_failure_is_not_excused_as_a_flake(self):
        # The direction that matters most. A classifier that called real failures flakes
        # would turn a red build into a rerun loop, and the defect would ship.
        for line in ("AssertionError: the drill found a defect",
                     "✗ [some_check] the tree does not hold",
                     "FAIL: at least one case did not hold",
                     "psycopg2.errors.CheckViolation: token has zero active signatures",
                     "ModuleNotFoundError: No module named 'cbor2'"):
            with self.subTest(line=line[:30]):
                self.assertEqual(ship.classify_failure_log(line)[0], "investigate")

    def test_an_empty_log_is_not_a_flake(self):
        self.assertEqual(ship.classify_failure_log("")[0], "investigate")

    def test_every_signature_carries_advice(self):
        for name, pattern, advice in ship.FLAKE_SIGNATURES:
            with self.subTest(name=name):
                self.assertTrue(pattern, "%s has no pattern" % name)
                self.assertGreater(len(advice), 30,
                                   "%s: advice must say what to DO, not name the flake" % name)
                self.assertIn("rerun", advice.lower(),
                              "%s: a flake's advice is to rerun; say so" % name)


class TriageHonestyTests(unittest.TestCase):
    """The verdict a tool gives when it could not look at anything."""

    def test_triage_distinguishes_no_log_from_nothing_found(self):
        # gh refuses --log-failed while any job in the run is still going, so a run whose
        # failure has already landed returns a refusal string rather than a log. Reporting
        # "investigate (no known flake signature matched)" over that reads as a considered
        # verdict about evidence nobody saw.
        with open(os.path.join(_HERE, "polaris-ship.py")) as fh:
            source = fh.read()
        self.assertIn("still in progress", source,
                      "triage must recognise gh's refusal to hand over a log")
        self.assertIn("UNKNOWN, no log to read yet", source,
                      "and say so, rather than reporting a conclusion it did not reach")
        triage = source.split("def triage")[1]
        unknown_at = triage.find("UNKNOWN, no log to read yet")
        classify_at = triage.find("classify_failure_log(log)")
        self.assertGreater(classify_at, 0)
        self.assertLess(unknown_at, classify_at,
                        "the no-log case must be handled BEFORE classification, or the "
                        "classifier runs over a refusal string and reports on it")


if __name__ == "__main__":
    unittest.main()
