#!/usr/bin/env python3
"""
run_conformance.py -- the Polaris verification conformance runner (P3.5).

Drives ANY verifier implementation over the published authenticity cases and
checks every verdict. Passing this suite is the integration contract (ROADMAP
P3.5): an external team certifies its own verifier, in any language, by pointing
this runner at it.

A verifier is a command that reads ONE case as JSON on stdin --
`{"pack": {...}, "anchors": ["<hex>", ...]}` (anchors present only when the case
supplies them) -- and prints `{"authentic": bool, "issuer_trusted": bool|null}`
on stdout. See SPEC.md.

    python3 conformance/run_conformance.py --self                 # the bundled Python SDK
    python3 conformance/run_conformance.py --verifier "node my_verifier.js"

Exit 0 iff every case matches; 1 on any mismatch; 2 if a case could not be run.
"""
import argparse
import json
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load_cases():
    with open(os.path.join(_HERE, "cases.json")) as f:
        manifest = json.load(f)
    cases = []
    for c in manifest["cases"]:
        with open(os.path.join(_ROOT, c["pack_file"])) as pf:
            pack = json.load(pf)
        anchors = c.get("anchors")
        if anchors == "self":
            anchors = [pack["public_key_hex"]]
        payload = {"pack": pack}
        if anchors is not None:
            payload["anchors"] = anchors
        cases.append((c["name"], payload, c["expect"]))
    return cases


def _self_verifier_cmd():
    # Run the bundled Python SDK's conformance CLI with the SDK on the path.
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(_ROOT, "sdk", "python") + os.pathsep + env.get("PYTHONPATH", "")
    return [sys.executable, "-m", "polaris_verify.conformance"], env


def main(argv=None):
    ap = argparse.ArgumentParser(description="Polaris verification conformance runner")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--self", action="store_true", dest="use_self",
                   help="run the bundled Python reference SDK")
    g.add_argument("--verifier", help="a verifier command (reads a case on stdin, prints a verdict)")
    ap.add_argument("--json", action="store_true", help="machine-readable summary")
    args = ap.parse_args(argv)

    if args.use_self:
        cmd, env = _self_verifier_cmd()
        shell = False
    else:
        cmd, env, shell = args.verifier, None, True

    cases = _load_cases()
    results, failures = [], 0
    for name, payload, expect in cases:
        try:
            proc = subprocess.run(cmd, input=json.dumps(payload), capture_output=True,
                                  text=True, env=env, shell=shell, timeout=120)
        except Exception as e:
            print("  [ERROR] %-24s could not run the verifier: %s" % (name, e), file=sys.stderr)
            return 2
        if proc.returncode != 0:
            print("  [ERROR] %-24s verifier exited %d: %s" % (name, proc.returncode, proc.stderr.strip()[:200]),
                  file=sys.stderr)
            return 2
        try:
            got = json.loads(proc.stdout.strip().splitlines()[-1])
        except Exception as e:
            print("  [ERROR] %-24s verifier output not JSON: %r (%s)" % (name, proc.stdout[:120], e), file=sys.stderr)
            return 2
        ok = (bool(got.get("authentic")) == expect["authentic"]
              and got.get("issuer_trusted") == expect["issuer_trusted"])
        results.append({"name": name, "expect": expect, "got": got, "pass": ok})
        if not ok:
            failures += 1
        print("  [%s] %-24s authentic=%s issuer_trusted=%s (expected authentic=%s issuer_trusted=%s)"
              % ("PASS" if ok else "FAIL", name, got.get("authentic"), got.get("issuer_trusted"),
                 expect["authentic"], expect["issuer_trusted"]))

    if args.json:
        print(json.dumps({"total": len(cases), "failures": failures, "results": results}))
    if failures:
        print("\nFAIL: %d/%d conformance cases did not match." % (failures, len(cases)), file=sys.stderr)
        return 1
    print("\nOK: all %d conformance cases passed -- the verifier is conformant." % len(cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
