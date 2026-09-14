#!/usr/bin/env python3
"""polaris-sdk-agreement-drill.py -- do the two reference SDKs give the SAME answer?

`conformance/SPEC.md` publishes two reference implementations, Python and TypeScript, and CI
runs each of them against all 118 published cases. Both pass. **That is weaker than it
sounds**, because a case constrains only the keys it names: `authentic`, sometimes
`issuer_trusted`, `fresh`, `audience_matches`. A verifier may report more, and on every key
the case does not name, the two SDKs can disagree with nothing noticing.

An integrator reads one SDK and deploys the other. A field that means "yes" in one and "no"
in the other is a decision made differently by two implementations both certified against the
same contract, and the contract cannot see it.

  disagreement = the same case, the same key, two different values

WHAT A DISAGREEMENT MEANS depends on the key. On a key the case CONSTRAINS, one of the two is
non-conformant and the published suite should have caught it; that is a hard failure here. On
a key the case does not constrain, neither is wrong by the contract, and the finding is about
the contract: it should either name the key or the SDKs should stop reporting it.

NEGATIVE CONTROL, and the run is VOID without it. A drill that compares nothing reports
perfect agreement. So `--prove-control` puts a shim in front of one verifier that flips a
single boolean in every verdict, and REQUIRES the disagreement to be found. Without that leg,
"0 disagreements" and "the comparison never ran" are the same sentence.

  python3 scripts/polaris-sdk-agreement-drill.py
  python3 scripts/polaris-sdk-agreement-drill.py --prove-control
"""
import argparse
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The shim the control runs instead of the real TypeScript verifier: it calls the real one
#: and inverts `authentic`. A flip on a CONSTRAINED key, so a control that fails to fire
#: means the comparison is not happening at all rather than being merely insensitive.
CONTROL_SHIM = """
import json, subprocess, sys
raw = sys.stdin.read()
p = subprocess.run(["node", "sdk/typescript/src/conformance.ts"], input=raw,
                   capture_output=True, text=True, cwd=sys.argv[1])
verdict = json.loads(p.stdout.strip().splitlines()[-1])
if "authentic" in verdict:
    verdict["authentic"] = not verdict["authentic"]
print(json.dumps(verdict))
"""


def load_cases():
    spec = importlib.util.spec_from_file_location("rc", ROOT / "conformance" / "run_conformance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._load_cases()


def verdict(cmd, payload, env=None):
    """Run one verifier on one case. Returns (verdict, error)."""
    try:
        proc = subprocess.run(cmd, input=json.dumps(payload), capture_output=True, text=True,
                              cwd=str(ROOT), env=env, timeout=120)
    except Exception as exc:  # noqa: BLE001
        return None, "could not run: %s" % exc
    if proc.returncode != 0:
        return None, "exited %d: %s" % (proc.returncode, proc.stderr.strip()[:160])
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1]), None
    except Exception as exc:  # noqa: BLE001
        return None, "output was not a verdict (%s): %r" % (exc, proc.stdout[:120])


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--prove-control", action="store_true",
                    help="flip a key in one verifier; the drill must find the disagreement")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    python_cmd = [sys.executable, "-m", "polaris_verify.conformance"]
    python_env = dict(os.environ, PYTHONPATH=str(ROOT / "sdk" / "python"))
    ts_cmd = ["node", "sdk/typescript/src/conformance.ts"]

    tmp = None
    if args.prove_control:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-agreement-control-"))
        shim = tmp / "shim.py"
        shim.write_text(CONTROL_SHIM)
        ts_cmd = [sys.executable, str(shim), str(ROOT)]

    cases = load_cases()
    constrained_disagreements, free_disagreements, asymmetric, errors = [], [], [], []
    compared = 0

    for name, payload, expect in cases:
        py, py_err = verdict(python_cmd, payload, python_env)
        ts, ts_err = verdict(ts_cmd, payload)
        if py is None or ts is None:
            errors.append("%s: python=%s typescript=%s" % (name, py_err or "ok", ts_err or "ok"))
            continue
        compared += 1
        for key in sorted(set(py) | set(ts)):
            if key not in py or key not in ts:
                asymmetric.append((name, key, "python" if key in py else "typescript"))
                continue
            if py[key] == ts[key]:
                continue
            row = (name, key, py[key], ts[key])
            (constrained_disagreements if key in expect else free_disagreements).append(row)

    if args.prove_control:
        found = len(constrained_disagreements) + len(free_disagreements)
        if found:
            print("control holds: a verifier with one key flipped produced %d disagreement(s) "
                  "and this drill found them" % found)
            return 0
        print("== the control FAILED: one verifier was returning the OPPOSITE answer on every "
              "case and this drill reported agreement, so it is comparing nothing ==",
              file=sys.stderr)
        return 3

    print("compared %d of %d published cases across both reference SDKs" % (compared, len(cases)))
    if errors:
        print("  %d case(s) could not be compared:" % len(errors))
        for line in errors[:5]:
            print("      %s" % line)
    print("  keys where they disagree, and the case constrains it:   %d"
          % len(constrained_disagreements))
    print("  keys where they disagree, and the case does not:        %d"
          % len(free_disagreements))
    print("  keys one reports and the other does not:                %d" % len(asymmetric))

    for name, key, py_value, ts_value in constrained_disagreements[:10]:
        print("      CONSTRAINED  %-28s %-22s python=%r typescript=%r"
              % (name, key, py_value, ts_value))
    for name, key, py_value, ts_value in free_disagreements[:10]:
        print("      unconstrained %-27s %-22s python=%r typescript=%r"
              % (name, key, py_value, ts_value))
    if args.verbose:
        for name, key, which in asymmetric[:40]:
            print("      only %-10s %-28s %s" % (which, name, key))

    if not compared:
        print("\n== VOID: no case was compared, so the agreement below is a statement about "
              "this drill ==", file=sys.stderr)
        return 3
    if errors:
        print("\n== %d case(s) could not be run through both SDKs. A case that did not run "
              "agrees with everything ==" % len(errors), file=sys.stderr)
        return 2
    if constrained_disagreements:
        print("\n== %d disagreement(s) on a key the contract CONSTRAINS: one of the two "
              "reference implementations is not conformant, and the published suite did not "
              "catch it ==" % len(constrained_disagreements), file=sys.stderr)
        return 1
    if free_disagreements or asymmetric:
        print("\n== the two reference SDKs agree on every constrained key, and differ on %d "
              "unconstrained value(s) and %d key(s) only one of them reports. Neither is "
              "wrong by the contract, which is the finding: an integrator reading one and "
              "deploying the other sees a different verdict on a field nothing checks =="
              % (len(free_disagreements), len(asymmetric)))
        return 0
    print("\n== the two reference SDKs return identical verdicts on every published case, key "
          "for key, including the keys no case constrains ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
