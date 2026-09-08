#!/usr/bin/env python3
"""
attacks/ — adversaries that MUST fail. Run every release; CI goes red if any SUCCEEDS.

Not greps: each attack actively tries to break a real security property against the
REAL code (the detached verifier's `verify_pack`, the app's ML-DSA-65 verify, the
verify-at-use route's authorization verdict). An attack "SUCCEEDS" when the defense
FAILS to stop it, and if any attack succeeds this runner exits non-zero. A suite you
asked for that cannot run (missing liboqs, no database) is a hard error, never a
silent skip, so a green run always means the defenses actually held.

    python3 attacks/run_attacks.py --suite crypto   # needs liboqs (real ML-DSA-65)
    python3 attacks/run_attacks.py --suite db        # needs the app + Postgres
    python3 attacks/run_attacks.py                   # both

Exit 0: every attack failed to break its defense (good).
Exit 1: at least one attack SUCCEEDED (a defense is broken).
Exit 3: a requested suite could not run, or an attack raised unexpectedly.
"""
import argparse
import importlib
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

_SUITES = ("crypto", "db")


def _run_suite(name):
    """Returns (results, hard_error). results is a list of (name, succeeded, note)."""
    try:
        mod = importlib.import_module("attack_%s" % name)
    except Exception as e:
        print("  [ERROR ] %s: could not import the attack module: %s" % (name, e))
        return [], True
    ok, reason = mod.available()
    if not ok:
        print("  [ERROR ] %s: suite cannot run (%s)" % (name, reason))
        return [], True
    results = []
    hard_error = False
    for attack_name, fn in mod.ATTACKS:
        try:
            succeeded, note = fn()
        except Exception as e:
            # An attack that crashes is not a pass: we cannot conclude the defense
            # held, so treat it as a hard error rather than a silent green.
            print("  [ERROR ] %s:%s raised %s: %s" % (name, attack_name, type(e).__name__, e))
            hard_error = True
            continue
        results.append((attack_name, succeeded, note))
    return results, hard_error


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the Polaris attack suite (adversaries that must fail).")
    ap.add_argument("--suite", choices=_SUITES + ("all",), default="all")
    args = ap.parse_args(argv)
    suites = _SUITES if args.suite == "all" else (args.suite,)

    all_results = []
    hard_error = False
    for suite in suites:
        print("== suite: %s ==" % suite)
        results, he = _run_suite(suite)
        hard_error = hard_error or he
        for attack_name, succeeded, note in results:
            tag = "BROKEN" if succeeded else "held"
            print("  [%-6s] %s:%s — %s" % (tag, suite, attack_name, note))
        all_results.extend((suite,) + r for r in results)

    broken = [r for r in all_results if r[2]]
    print()
    if broken:
        print("FAIL: %d attack(s) SUCCEEDED — a defense is broken:" % len(broken))
        for suite, attack_name, _s, note in broken:
            print("  - %s:%s — %s" % (suite, attack_name, note))
        return 1
    if hard_error:
        print("ERROR: an attack suite could not run or an attack crashed; cannot certify the defenses.")
        return 3
    print("OK: all %d attacks failed to break their defense." % len(all_results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
