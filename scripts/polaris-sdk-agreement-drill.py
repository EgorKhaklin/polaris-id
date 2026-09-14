#!/usr/bin/env python3
"""polaris-sdk-agreement-drill.py -- do the implementations give the SAME answer?

This repository ships THREE verifiers of the same artifacts: the detached verifier a relying
party installs (`packages/polaris-verify`), and the two reference SDKs `conformance/SPEC.md`
publishes, Python and TypeScript. CI runs each against all 118 published cases. All three
pass. **That is weaker than it sounds**, because a case constrains only the keys it names:
`authentic`, sometimes `issuer_trusted`, `fresh`, `audience_matches`. A verifier may report
more, and on every key the case does not name, the three can disagree with nothing noticing.

An integrator reads one and deploys another. A field that means "yes" in one and "no" in the
next is a decision made differently by implementations all certified against the same
contract, and the contract cannot see it.

  disagreement = the same case, the same key, two implementations, two values

ON KEYS ONLY ONE REPORTS. The detached verifier is driven through the adapter in
`scripts/test_verify_conformance.py`, which deliberately projects each artifact onto the keys
the contract compares. So a key it does not report is a fact about that adapter, not about
the verifier, and this drill compares only keys present in BOTH members of a pair. Counting
adapter shape as disagreement would bury the real finding in noise.

WHAT A DISAGREEMENT MEANS depends on the key. On a key the case CONSTRAINS, one of the two is
non-conformant and the published suite should have caught it; that is a hard failure here. On
a key the case does not constrain, neither is wrong by the contract, and the finding is about
the contract: it should either name the key or the implementations should stop reporting it.

WHAT THIS FOUND, and it is a ratchet rather than a to-do list. Thirty-six unconstrained
divergences, every one of them between the detached verifier and an SDK, on two keys and for
two reasons, both accounted for in ACCOUNTED below. The two SDKs agree with each other
everywhere. Anything OUTSIDE that accounting fails the run, so a new divergence is caught
while the known ones stay visible instead of being suppressed by a count nobody reads.

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


def accounted(name, key, a, b, expect):
    """Is this divergence one of the two known, explained ones?

    Both are between the detached verifier and the SDKs, and neither is a defect in either:
    they are two defensible conventions that the published contract does not choose between.
    Harmonising them would be a product behaviour change justified by nothing but tidiness,
    so they are recorded here and the drill guards the boundary instead.
    """
    pair = {a, b}
    if "detached" not in pair:
        return None

    # 1. `fresh` on an artifact that failed authentication. The detached verifier RETURNS at
    #    the failure, so the window is never evaluated and `fresh` stays null, meaning "not
    #    asked". The SDKs fall through to a common tail that answers the window regardless,
    #    so `fresh` means "the interval holds", which is separately true of a forgery. A
    #    relying party gating on `fresh is not False` cannot tell the difference; one gating
    #    on `fresh is True` can, and in every one of these cases `authentic` is already false,
    #    so the authenticity gate refuses first either way.
    if key == "fresh" and expect.get("authentic") is False:
        return "detached stops at the failure; the SDKs answer the window anyway"

    # 2. `issuer_trusted` on the cross-authority cases. On the detached side this key is not
    #    reported by the verifier at all: the conformance adapter DERIVES it from key_status,
    #    which answers "is this key revoked or unknown" rather than "is it in the anchor set
    #    the caller supplied". Two different questions wearing one name, and the difference
    #    belongs to the adapter rather than to either verifier.
    if key == "issuer_trusted" and name.startswith("cross-authority"):
        return "the detached adapter derives this from key_status, a different question"

    return None


def load_cases():
    spec = importlib.util.spec_from_file_location("rc", ROOT / "conformance" / "run_conformance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._load_cases()


def load_detached_adapter():
    """The detached verifier, driven through the adapter its own conformance test uses.

    Reusing that adapter rather than writing a second one is deliberate: a fresh adapter
    would be a third opinion about what each artifact's verdict means, and this drill would
    then be comparing adapters rather than verifiers.
    """
    spec = importlib.util.spec_from_file_location(
        "tvc", ROOT / "scripts" / "test_verify_conformance.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["tvc"] = module
    spec.loader.exec_module(module)
    raw = json.loads((ROOT / "conformance" / "cases.json").read_text())["cases"]
    return module._verdict_for, {c["name"]: c for c in raw}


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
    detached_verdict, raw_cases = load_detached_adapter()

    def run_all(name, payload):
        """Every implementation's verdict for one case, keyed by implementation name."""
        out, errs = {}, {}
        py, err = verdict(python_cmd, payload, python_env)
        (out if py is not None else errs)["python-sdk"] = py if py is not None else err
        ts, err = verdict(ts_cmd, payload)
        (out if ts is not None else errs)["typescript-sdk"] = ts if ts is not None else err
        if not args.prove_control:
            # The control shims the TypeScript SDK only; running the detached verifier under
            # it would compare a flipped verdict against two unflipped ones and inflate the
            # count without testing anything more.
            try:
                out["detached"] = detached_verdict(raw_cases[name])
            except Exception as exc:  # noqa: BLE001
                errs["detached"] = "adapter raised: %s" % exc
        return out, errs

    constrained, free, unaccounted, errors = [], [], [], []
    compared = 0

    for name, payload, expect in cases:
        verdicts, errs = run_all(name, payload)
        for impl, why in errs.items():
            errors.append("%s: %s %s" % (name, impl, why))
        if len(verdicts) < 2:
            continue
        compared += 1
        names = sorted(verdicts)
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                # Only keys BOTH report: a key one adapter projects away is a fact about the
                # adapter, not a disagreement between verifiers.
                for key in sorted(set(verdicts[a]) & set(verdicts[b])):
                    if verdicts[a][key] == verdicts[b][key]:
                        continue
                    row = (name, key, a, verdicts[a][key], b, verdicts[b][key])
                    if key in expect:
                        constrained.append(row)
                    elif accounted(name, key, a, b, expect):
                        free.append(row)
                    else:
                        unaccounted.append(row)

    if args.prove_control:
        found = len(constrained) + len(free) + len(unaccounted)
        if found:
            print("control holds: a verifier with one key flipped produced %d disagreement(s) "
                  "and this drill found them" % found)
            return 0
        print("== the control FAILED: one verifier was returning the OPPOSITE answer on every "
              "case and this drill reported agreement, so it is comparing nothing ==",
              file=sys.stderr)
        return 3

    print("compared %d of %d published cases across %d implementations"
          % (compared, len(cases), 3))
    if errors:
        print("  %d verdict(s) could not be obtained:" % len(errors))
        for line in errors[:5]:
            print("      %s" % line)
    print("  disagreements on a key the case CONSTRAINS:  %d" % len(constrained))
    print("  unconstrained and accounted for:             %d" % len(free))
    print("  unconstrained and NOT accounted for:         %d" % len(unaccounted))
    for name, key, a, av, b, bv in unaccounted[:10]:
        print("      UNACCOUNTED %-26s %-20s %s=%r  %s=%r" % (name, key, a, av, b, bv))

    for name, key, a, av, b, bv in constrained[:10]:
        print("      CONSTRAINED %-26s %-20s %s=%r  %s=%r" % (name, key, a, av, b, bv))
    shown = free if args.verbose else free[:12]
    for name, key, a, av, b, bv in shown:
        print("      %-38s %-20s %s=%r  %s=%r" % (name, key, a, av, b, bv))
    if not args.verbose and len(free) > 12:
        print("      ... %d more, --verbose for all" % (len(free) - 12))

    if not compared:
        print("\n== VOID: no case was compared, so the agreement below is a statement about "
              "this drill ==", file=sys.stderr)
        return 3
    if errors:
        print("\n== %d verdict(s) could not be obtained. An implementation that did not run "
              "agrees with everything ==" % len(errors), file=sys.stderr)
        return 2
    if unaccounted:
        print("\n== %d divergence(s) this drill does not account for. Either the "
              "implementations should agree, or ACCOUNTED should say why they do not =="
              % len(unaccounted), file=sys.stderr)
        return 1
    if constrained:
        print("\n== %d disagreement(s) on a key the contract CONSTRAINS: one of the "
              "implementations is not conformant, and the published suite did not catch it =="
              % len(constrained), file=sys.stderr)
        return 1
    if free:
        print("\n== every implementation agrees on every constrained key. They differ on %d "
              "unconstrained value(s), all of them between the detached verifier and an SDK, "
              "all accounted for. The two SDKs agree with each other everywhere ==" % len(free))
        return 0
    print("\n== every implementation returns the same value for every key they both report, "
          "on every published case, including the keys no case constrains ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
