#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""check.py -- does OID4VCgo judge every mdoc vector as the vector says?

Reads the witness's oid4vcgo.jsonl (run.sh writes it) and the mdoc-vectors.json it ran over. Every
case must come out as its `expected` says (accept: accepted, reject: refused) and every repaired
twin accepted: on the composed path always, and on VerifyResponse wherever it ran (a row whose
VerifyResponse carries `not_run` and no outcome is skipped on that path only). VerifyResponse must
have run on every row whose inputs (a twin's own repaired inputs) say response_mode dc_api.jwt,
the rows main.go runs it on, and at least one vector must say so. It also requires exactly one row
per case and per twin, nothing else, and at least one row.

    python3 -I check.py OUT/oid4vcgo.jsonl lab/interop/negative-vectors/mdoc-vectors.json

Exits 0 and prints the counts when every row agrees; exits 1 naming each row that does not.
"""
import collections
import json
import sys

WANT = {"accept": "accepted", "reject": "refused"}


def runs_verify_response(inputs):
    """main.go runs VerifyResponse exactly when the inputs say response_mode dc_api.jwt."""
    return (inputs or {}).get("response_mode") == "dc_api.jwt"


def problems_of(rows, vectors):
    want, must_run = {}, set()
    for v in vectors:
        want[(v["id"], "case")] = WANT.get(v["expected"], "expected %r" % v["expected"])
        if runs_verify_response(v.get("inputs")):
            must_run.add((v["id"], "case"))
        if "repaired" in v:
            want[(v["id"], "repaired")] = "accepted"
            if runs_verify_response(v["repaired"].get("inputs")):
                must_run.add((v["id"], "repaired"))
    problems, seen, counts = [], collections.Counter(), collections.Counter()
    if not rows:
        problems.append("the witness wrote no rows")
    if not want:
        problems.append("the vectors file holds no vectors")
    if want and not must_run:
        problems.append("no vector's inputs say response_mode dc_api.jwt, so VerifyResponse is held to no row")
    for row in rows:
        key = (row.get("name"), row.get("variant"))
        seen[key] += 1
        if key not in want:
            problems.append("%s (%s): no such vector in the file" % key)
            continue
        for path in ("composed", "verify_response"):
            got = (row.get(path) or {}).get("outcome", "")
            if path == "verify_response" and got == "" and (row.get(path) or {}).get("not_run"):
                counts[path, "not run"] += 1
                if key in must_run:
                    problems.append("%s (%s) on verify_response: not run, though its inputs say dc_api.jwt"
                                    % key)
                continue
            counts[path, got or "no outcome"] += 1
            if got != want[key]:
                problems.append("%s (%s) on %s: %s, the vector says %s"
                                % (key[0], key[1], path, got or "no outcome", want[key]))
    for key in sorted(want):
        if seen[key] != 1:
            problems.append("%s (%s): %d rows, not 1" % (key[0], key[1], seen[key]))
    return problems, counts


def main(argv):
    if len(argv) != 3:
        print("usage: check.py OID4VCGO_JSONL MDOC_VECTORS_JSON", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]
    with open(argv[2], encoding="utf-8") as f:
        vectors = json.load(f)["vectors"]
    problems, counts = problems_of(rows, vectors)
    for p in problems:
        print("DISAGREES " + p)
    print("%d rows; composed: %s; verify_response: %s"
          % (len(rows), ", ".join("%d %s" % (n, o) for (path, o), n in sorted(counts.items()) if path == "composed"),
             ", ".join("%d %s" % (n, o) for (path, o), n in sorted(counts.items()) if path == "verify_response")))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
