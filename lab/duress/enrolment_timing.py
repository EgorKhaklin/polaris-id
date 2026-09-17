#!/usr/bin/env python3
"""enrolment_timing.py -- can the front of house tell who has a duress code?

THE CLAIM UNDER TEST, from docs/design/duress-codes.md:

    "Where it settles. The front of house cannot distinguish, so the attacker must attack
     the back: an admin or auditor session, or the database directly. Both need a privilege
     escalation the verification surface does not provide."

and the safeguard it rests on:

    "Three safeguards hold this up: the constant-time comparison with matched work on both
     paths, the omission of the events from every operator surface, and the role gate on
     the queue."

"Matched work on both paths" was true of MATCH versus NO-MATCH. It was never true of
ENROLLED versus NOT-ENROLLED. `_check_and_record_duress` used to read:

    row = query("SELECT duress_code_hash ...")
    if not row or not row['duress_code_hash']:
        return                                     # <- no hash, no work
    if not check_password_hash(row['duress_code_hash'], duress_input):
        return                                     # <- a hash, and the full scrypt cost

The enrolled hashes are scrypt:32768:8:1. So typing anything at all into the duress field
and timing the response separated "this holder enrolled a duress code" from "this holder
did not", using the verification surface and no privilege of any kind.

WHY IT MATTERS, and what it does NOT show. It does not reveal a code, and it does not
reveal that a duress signal fired. It reveals ENROLMENT, which is the fact that makes the
signal usable. lab/duress/README.md already records that enrolment is opt-in, so "I have no
duress code" is a claim a coercer can press on and the holder cannot disprove; an opt-in
defence makes its absence interrogable. A coercer who can MEASURE it does not have to press.
And the README's own unmeasured list names "the operator as coercer": an operator who is the
coercer types the field and reads the latency off their own screen.

This is not a laboratory-grade side channel. It is roughly a third of a second.

THE FIX this measures: the comparison now runs against `_DURESS_TIMING_BALLAST`, a real
scrypt hash at the same parameters, when nothing is enrolled. Both paths pay the same cost
and the result is discarded on the ballast path.

Run: python3 lab/duress/enrolment_timing.py [--samples N]
"""
import argparse
import pathlib
import re
import statistics
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
APP = ROOT / "polaris_web" / "app.py"
AUTH_SQL = ROOT / "polaris_sql" / "10_auth.sql"


def _scrypt_params(h):
    """(N, r, p, salt) out of a werkzeug scrypt hash string, or None."""
    m = re.match(r"scrypt:(\d+):(\d+):(\d+)\$([^$]*)\$([0-9a-f]+)$", h)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)) if m else None


def _shipped_enrolled_hash():
    """A real enrolled duress hash, read out of the tree rather than invented, so the cost
    measured below is the cost the deployment actually pays."""
    m = re.search(r"duress_code_hash = '(scrypt:[^']+)'", AUTH_SQL.read_text(encoding="utf-8"))
    return m.group(1) if m else None


def _ballast():
    src = APP.read_text(encoding="utf-8")
    m = re.search(r'_DURESS_TIMING_BALLAST = \(\s*((?:\s*"[^"]*"\s*)+)\)', src)
    return "".join(re.findall(r'"([^"]*)"', m.group(1))) if m else None


def _cost_ms(params, samples):
    """What one check_password_hash costs at these parameters, on this machine."""
    try:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except Exception:
        return None
    n, r, p, salt = params
    Scrypt(salt=salt.encode(), length=64, n=n, r=r, p=p).derive(b"warm")
    out = []
    for _ in range(samples):
        t0 = time.perf_counter()
        Scrypt(salt=salt.encode(), length=64, n=n, r=r, p=p).derive(b"whatever-was-typed")
        out.append((time.perf_counter() - t0) * 1000)
    return sorted(out)


def _branch_structure():
    """Does the NOT-ENROLLED path reach the comparison, or return before it?

    Read off the source rather than asserted, because this is exactly the kind of property
    that a comment can claim after the code has stopped doing it.
    """
    # Parsed, not grepped. The first version of this function split the source on the text
    # "check_password_hash" and searched what came before it. The comment ABOVE the
    # comparison explains the defect and names the function, so the split landed inside the
    # comment and the check saw none of the code: it reported the channel CLOSED against the
    # pre-fix source, which is an instrument that cannot register the effect it exists for.
    # Caught by mutating the fix away and watching the harness not notice. An AST sees code.
    import ast
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "_check_and_record_duress"),
              None)
    if fn is None:
        return None

    compare_lines = [n.lineno for n in ast.walk(fn)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                     and n.func.id == "check_password_hash"]
    if not compare_lines:
        # No comparison at all: neither path pays, which is a different and worse shape.
        return {"returns_before_the_hash_when_not_enrolled": True,
                "compares_against_ballast_when_not_enrolled": False}
    first_compare = min(compare_lines)

    # A bare `return` reached on the strength of the hash being absent, standing before the
    # comparison, is the channel: that path pays nothing.
    returns_when_absent = False
    for node in ast.walk(fn):
        if not isinstance(node, ast.If) or node.lineno >= first_compare:
            continue
        test_src = ast.dump(node.test)
        if "duress_code_hash" not in test_src:
            continue
        if any(isinstance(s, ast.Return) and s.value is None for s in node.body):
            returns_when_absent = True

    ballast_used = any(isinstance(n, ast.Name) and n.id == "_DURESS_TIMING_BALLAST"
                       for n in ast.walk(fn))
    return {"returns_before_the_hash_when_not_enrolled": returns_when_absent,
            "compares_against_ballast_when_not_enrolled": ballast_used}


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--samples", type=int, default=9)
    args = ap.parse_args()

    enrolled = _shipped_enrolled_hash()
    ballast = _ballast()
    if not enrolled:
        print("VOID: no enrolled duress hash found in polaris_sql/10_auth.sql, so there is "
              "nothing to measure the cost of", file=sys.stderr)
        return 1
    ep = _scrypt_params(enrolled)
    if not ep:
        print("VOID: the enrolled hash is not a werkzeug scrypt hash; this study assumes it "
              "is and would otherwise measure the wrong primitive", file=sys.stderr)
        return 1

    print("the claim: docs/design/duress-codes.md, 'the front of house cannot distinguish'")
    print("the axis:  a token WITH an enrolled duress code vs one WITHOUT, timed from the")
    print("           verification surface, with anything at all typed into the field\n")

    print("enrolled hash in the tree: scrypt:%d:%d:%d" % ep[:3])
    cost = _cost_ms(ep, args.samples)
    if cost is None:
        print("VOID: no scrypt implementation available here, so the cost of the comparison "
              "cannot be measured and no conclusion follows", file=sys.stderr)
        return 1
    median = statistics.median(cost)
    print("   one comparison costs   min %.1f ms   median %.1f ms   max %.1f ms  (n=%d)\n"
          % (cost[0], median, cost[-1], len(cost)))

    struct = _branch_structure()
    if struct is None:
        print("VOID: _check_and_record_duress could not be located in polaris_web/app.py",
              file=sys.stderr)
        return 1
    print("_check_and_record_duress, the not-enrolled path:")
    print("   returns before the comparison   %s" % struct["returns_before_the_hash_when_not_enrolled"])
    print("   compares against the ballast    %s\n" % struct["compares_against_ballast_when_not_enrolled"])

    if struct["returns_before_the_hash_when_not_enrolled"]:
        print("== FINDING: the not-enrolled path returns before check_password_hash, so a "
              "token with no duress code answers ~%.0f ms sooner than one with a code. That "
              "is enrolment, readable from the verification surface, with no privilege of "
              "any kind ==" % median, file=sys.stderr)
        return 2

    if not struct["compares_against_ballast_when_not_enrolled"]:
        print("== INCONCLUSIVE: the early return is gone, but nothing stands in for the "
              "comparison on the not-enrolled path either. Read the function: if it does no "
              "hashing work there, the channel is open and this script cannot see it ==",
              file=sys.stderr)
        return 3

    if not ballast:
        print("== FINDING: the code names _DURESS_TIMING_BALLAST but no such constant was "
              "found in polaris_web/app.py ==", file=sys.stderr)
        return 2
    bp = _scrypt_params(ballast)
    if not bp:
        print("== FINDING: the ballast is not a well-formed werkzeug scrypt hash, so "
              "check_password_hash may refuse it cheaply and pay nothing ==", file=sys.stderr)
        return 2
    if bp[:3] != ep[:3]:
        print("== FINDING: the ballast is scrypt:%d:%d:%d and the enrolled hashes are "
              "scrypt:%d:%d:%d. It no longer costs what it stands in for, and the difference "
              "is the channel reopening ==" % (bp[:3] + ep[:3]), file=sys.stderr)
        return 2

    bcost = _cost_ms(bp, args.samples)
    if bcost is None:
        print("VOID: the ballast's cost could not be measured", file=sys.stderr)
        return 1
    bmed = statistics.median(bcost)
    print("ballast: scrypt:%d:%d:%d, median %.1f ms against the enrolled hash's %.1f ms"
          % (bp[0], bp[1], bp[2], bmed, median))
    print("   difference %.1f ms\n" % abs(bmed - median))

    print("== CLOSED on this axis. Both paths run one comparison at the same parameters, so "
          "the response no longer says whether a duress code is enrolled.")
    print("   WHAT THIS DOES NOT SAY. It is a measurement of the comparison COST, not of a "
          "live request: the surrounding query, template render and network dominate the "
          "variance and are not modelled here. It says nothing about the other two coercers "
          "in README.md, nothing about an operator who watches the code being typed, and "
          "nothing about long-run frequency analysis or enrolment-rate inference, which "
          "remain unmeasured. It closes one channel that was open by 0.3 seconds. ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
