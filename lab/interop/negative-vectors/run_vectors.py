#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/interop/negative-vectors/run_vectors.py: run vectors.json against a verifier and print, for each
vector, the verdict it should reach and the one it reached.

    python3 run_vectors.py vectors.json --adapter polaris-oid4vp [--json results.json]

An adapter is one function: (vector, settings) -> ("accept" | "reject", a short reason). The run fails
(exit 1) when a control is refused, because then every refusal it reports measured nothing, and when a
negative vector is accepted. Exit 2: the adapter could not run.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def polaris_oid4vp(vector, settings):
    sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "packages", "polaris-oid4vp"))
    from cryptography import x509
    from polaris_oid4vp.sdjwt import verify_presentation
    kw = {"expected_nonce": settings["nonce"], "expected_audience": settings["audience"], "now": settings["now"],
          "max_skew_seconds": settings["max_skew_seconds"], "expected_vct": settings["vct"]}
    if vector["trust"] == "jwks":
        kw["issuer_jwks"] = settings["issuer_jwks"]
    else:
        kw["trust_anchors"] = [x509.load_pem_x509_certificate(p.encode()) for p in settings["trust_anchors_pem"]]
    verdict = verify_presentation(vector["presentation"], **kw)
    return ("accept" if verdict.authentic else "reject"), "%s: %s" % (verdict.code, verdict.reason)


ADAPTERS = {"polaris-oid4vp": polaris_oid4vp}


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    ap.add_argument("vectors")
    ap.add_argument("--adapter", choices=sorted(ADAPTERS), required=True)
    ap.add_argument("--json", help="write the results here")
    args = ap.parse_args(argv)
    doc = json.load(open(args.vectors))
    run = ADAPTERS[args.adapter]
    results, wrong = [], []
    for vector in doc["vectors"]:
        try:
            got, why = run(vector, doc["settings"])
        except Exception as e:  # noqa: BLE001: an adapter that cannot judge a vector stops the run
            print("could not run %s: %s: %s" % (vector["id"], type(e).__name__, e), file=sys.stderr)
            return 2
        ok = got == vector["expected"]
        results.append({"id": vector["id"], "expected": vector["expected"], "got": got, "ok": ok, "reason": why})
        print("%-4s %-26s expected %-6s got %-6s %s" % ("ok" if ok else "FAIL", vector["id"], vector["expected"], got,
                                                       why[:90]))
        if not ok:
            wrong.append(vector["id"])
    controls = [r for r in results if r["id"].startswith("accept-")]
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"adapter": args.adapter, "vectors_version": doc["version"], "results": results}, fh, indent=1)
    if any(not r["ok"] for r in controls):
        print("a control was refused: the refusals above measured nothing", file=sys.stderr)
        return 1
    print("%d of %d as expected" % (len(results) - len(wrong), len(results)))
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
