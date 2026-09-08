#!/usr/bin/env python3
"""
polaris-fetch-kat.py — (re)generate the committed ML-DSA-65 conformance vectors.

Downloads Project Wycheproof's ML-DSA-65 *verify* test vectors at a PINNED commit
and curates a compact, comprehensive subset into vectors/kat/mldsa_65_verify.json:
the empty-context tests (which the standard verify handles), capped per distinct
Wycheproof flag-set so every edge case it exercises is represented without carrying
the full 1.6 MB file. The committed file is what CI checks; this script exists so
that file is auditable and regenerable, not hand-made.

    python3 scripts/polaris-fetch-kat.py            # refresh vectors/kat/mldsa_65_verify.json

Wycheproof is Apache-2.0; its vectors are redistributed here with attribution.
"""
import argparse
import json
import os
import sys
import urllib.request
from collections import defaultdict

# Pinned so the committed vectors reference an exact, reproducible source.
_REPO = "C2SP/wycheproof"
_PATH = "testvectors_v1/mldsa_65_verify_test.json"
_COMMIT = "613a2e44cb645a9890e49f8d8798cd59ef38379b"
_URL = f"https://raw.githubusercontent.com/{_REPO}/{_COMMIT}/{_PATH}"
_OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "vectors", "kat", "mldsa_65_verify.json")
_PER_FLAGSET = 5  # keep up to this many tests per distinct flag-set


def main(argv=None):
    ap = argparse.ArgumentParser(description="Regenerate the committed ML-DSA-65 conformance vectors.")
    ap.add_argument("--out", default=_OUT)
    ap.add_argument("--per-flagset", type=int, default=_PER_FLAGSET)
    args = ap.parse_args(argv)

    with urllib.request.urlopen(_URL, timeout=60) as r:
        src = json.load(r)
    if src.get("algorithm") != "ML-DSA-65":
        sys.exit("unexpected algorithm: %r" % src.get("algorithm"))

    kept_by_flags = defaultdict(int)
    groups_out = []
    n_tests = 0
    n_ctx = 0
    for g in src["testGroups"]:
        tests = []
        for t in g["tests"]:
            ctx = t.get("ctx") or ""
            has_ctx = ctx != ""
            key = tuple(t.get("flags", []))
            # Cap the empty-context tests per flag-set; ALWAYS keep the rare
            # context-string tests (only a handful, and they exercise a distinct
            # verify path — the ML-DSA context domain separation and its 255-byte cap).
            if not has_ctx and kept_by_flags[key] >= args.per_flagset:
                continue
            kept_by_flags[key] += 1
            entry = {"tcId": t["tcId"], "comment": t.get("comment", ""),
                     "flags": t.get("flags", []), "result": t["result"],
                     "msg": t["msg"], "sig": t["sig"]}
            if has_ctx:
                entry["ctx"] = ctx
                n_ctx += 1
            tests.append(entry)
            n_tests += 1
        if tests:
            groups_out.append({"publicKey": g["publicKey"], "tests": tests})

    out = {
        "algorithm": "ML-DSA-65",
        "provenance": {
            "source": f"{_REPO} {_PATH}",
            "commit": _COMMIT,
            "url": _URL,
            "license": "Apache-2.0",
            "note": ("Project Wycheproof ML-DSA-65 verify vectors: empty-context tests curated to "
                     "<=%d per flag-set, PLUS every context-string test (a `ctx` field, verified with "
                     "the ML-DSA context domain separation). Regenerate with scripts/polaris-fetch-kat.py."
                     % args.per_flagset),
        },
        "flag_sets_covered": [list(k) for k in sorted(kept_by_flags)],
        "testGroups": groups_out,
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(out, f, indent=1, sort_keys=False)
        f.write("\n")
    valid = sum(1 for g in groups_out for t in g["tests"] if t["result"] == "valid")
    print("wrote %s: %d tests (%d valid / %d invalid; %d with a context string) across %d groups, "
          "%d flag-sets, %d bytes"
          % (args.out, n_tests, valid, n_tests - valid, n_ctx, len(groups_out),
             len(kept_by_flags), os.path.getsize(args.out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
