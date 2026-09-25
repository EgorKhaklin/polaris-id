#!/usr/bin/env python3
"""polaris-real-signer-suite.py - the web application's suite, signing with real ML-DSA-65.

WHY THIS EXISTS. The main CI job and the local gate run test_app with the development
placeholder signer (POLARIS_PQC_PROFILE=placeholder): SHA3-256 of the token value, no key. The
real signer ran only in its own CI job, over test_pqc_signing and a handful of drills, so every
route that issues, migrates, packs or displays a signature had been exercised end to end under
the placeholder alone. An outside reviewer asked on 2026-09-25 which tests had never run under
real cryptography. Run that day under POLARIS_USE_REAL_PQC=1, test_app had five failures, and
all five were tests asserting the placeholder's bytes or wording rather than the effect: no
route misbehaved, but nothing had shown that before. Those tests now assert the effect in
either mode (a real signature stores its key and both witnesses accept it; a flipped byte is
refused by every witness), and this runs the whole module under the real signer.

    POLARIS_DB_HOST=localhost POLARIS_DB_USER=<owner> python3 scripts/polaris-real-signer-suite.py

Exit 0 when every test passes under real ML-DSA-65, 1 otherwise, 3 when liboqs is not
importable here (outside CI; in CI that is a failure, since a skip is a pass nobody reads).
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(os.path.dirname(HERE), "polaris_web")


def main():
    # Set before the application module is imported: pqc_signing reads the flag per call, but
    # app.py prints its placeholder warning, and picks its profile, at import.
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    os.environ.pop("POLARIS_PQC_PROFILE", None)
    os.chdir(WEB)
    sys.path.insert(0, WEB)
    import pqc_signing
    if not pqc_signing.is_enabled():
        print("real-signer suite: liboqs is not importable here, so the real signer cannot run")
        return 1 if os.environ.get("CI") else 3
    import test_app as T

    suite = unittest.defaultTestLoader.loadTestsFromModule(T)
    with open(os.devnull, "w") as sink:
        result = unittest.TextTestRunner(verbosity=0, stream=sink).run(suite)
    bad = result.failures + result.errors
    print("real-signer suite: %d tests under ML-DSA-65, %d failed, %d skipped"
          % (result.testsRun, len(bad), len(result.skipped)))
    if result.testsRun < 500:
        print("real-signer suite: fewer tests ran than test_app holds; the loader found the wrong module")
        return 1
    # The flag must still be on after the run: a test that switched the signer off and left it
    # off would turn the rest of this run into another placeholder run.
    if not pqc_signing.is_enabled():
        print("real-signer suite: the real signer was switched off during the run")
        return 1
    for test, tb in bad:
        last = [line for line in tb.strip().splitlines() if line.strip()][-1]
        print("  FAIL %s\n       %s" % (test.id().split(".", 1)[-1], last[:200]))
    if bad:
        print("\nEach is a route that misbehaves under the real signer, or a test that asserts "
              "the placeholder's bytes rather than the effect.")
        return 1
    print("OK: every test_app test passes with issuance signing under real ML-DSA-65 (%d)."
          % result.testsRun)
    return 0


if __name__ == "__main__":
    sys.exit(main())
