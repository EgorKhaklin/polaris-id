#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the stranger-head timestamp-anchor vector and its two cases (1.1.0).

A timestamp is anchored only under the log key the relying party names (conformance/SPEC.md,
the timestamp anchor). The vector is the published timestamp-anchor-variants-base anchor with
one change: its head is re-signed by a fresh key that no case names. The head is authentic
under its own key, the proof and the cosignatures are the base's, and only the signer differs.

    timestamp-anchor-stranger-head-no-log-key          no log_key: not anchored
    timestamp-anchor-stranger-head-authority-log-key   the base's log_key: not anchored

timestamp-anchor-variants-base, the same anchor under the log's own head and key, is their
positive control. The generator checks every expected value against the detached verifier and
the Python SDK, and the controls, before anything is written. Never modifies a published vector.

    python3 conformance/make_stranger_head_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.1.0"
VEC = "conformance/vectors/"
NAME = "timestamp-anchor-stranger-head"
PROVENANCE = "real ML-DSA-65 (liboqs); conformance/make_stranger_head_vectors.py"


def main():
    try:
        import oqs  # type: ignore
    except Exception as e:  # noqa: BLE001
        print("needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    sys.path.insert(0, str(ROOT / "sdk" / "python"))
    import polaris_verify as P  # noqa: E402

    doc = json.loads(CASES.read_text(encoding="utf-8"))
    base_case = next(c for c in doc["cases"] if c["name"] == "timestamp-anchor-variants-base")
    base = json.loads((OUT / "timestamp-anchor-variants-base.json").read_text(encoding="utf-8"))
    log_key = base_case["log_key"]
    if log_key != base["anchor"]["sth"]["public_key_hex"]:
        print("the base case does not name its own head's log key", file=sys.stderr)
        return 1
    witnesses = sorted({c["public_key_hex"] for c in base["anchor"]["cosignatures"]})

    with oqs.Signature("ML-DSA-65") as s:
        stranger_pk = bytes(s.generate_keypair())
        stranger_sk = bytes(s.export_secret_key())
    head = {k: v for k, v in base["anchor"]["sth"].items() if k != "signature_hex"}
    head["public_key_hex"] = stranger_pk.hex()
    with oqs.Signature("ML-DSA-65", secret_key=stranger_sk) as s:
        head["signature_hex"] = bytes(s.sign(hashlib.sha3_256(V._sth_canonical(head)).digest())).hex()
    ts = json.loads(json.dumps(base))
    ts["anchor"]["sth"] = head
    ts["_vector"] = {"expect": "not anchored", "name": NAME, "provenance": PROVENANCE,
                     "note": "timestamp-anchor-variants-base with its head re-signed by a key no case names"}

    def anchored(obj, key):
        d = V.verify_timestamp_anchor(obj, log_key=key, trusted_witnesses=witnesses, threshold=2)["anchored"]
        p = P.verify_timestamp_anchor(obj, log_key=key, trusted_witnesses=witnesses, threshold=2).anchored
        return bool(d), bool(p)

    # Every expected value, before anything is written, under both verifiers. The controls: the
    # base anchors under its log key, and the new head is authentic and anchors under its own
    # signer's key, so in each case below only the named key can refuse it.
    if not V.verify_sth(head)["sth_authentic"] or not P.verify_signed_artifact(head).authentic:
        print("control: the re-signed head is not authentic, so a refusal would be the signature's",
              file=sys.stderr)
        return 1
    for label, obj, key, want in (("control: the base under its log key", base, log_key, (True, True)),
                                  ("control: the re-signed head under its signer's key", ts,
                                   stranger_pk.hex(), (True, True)),
                                  (NAME + "-no-log-key", ts, None, (False, False)),
                                  (NAME + "-authority-log-key", ts, log_key, (False, False))):
        got = anchored(obj, key)
        if got != want:
            print("%s: (detached, sdk) = %s, want %s" % (label, got, want), file=sys.stderr)
            return 1

    cases = [
        {"name": NAME + "-no-log-key", "artifact": "timestamp-anchor", "timestamp_file": VEC + NAME + ".json",
         "trusted_witnesses": "cosigners", "threshold": 2, "expect": {"anchored": False}, "since": SINCE,
         "note": "A head of the timestamp log signed by a key the relying party did not name, and no "
                 "log_key: not anchored. A head anchors only under the log key the relying party names. "
                 "timestamp-anchor-variants-base, the same anchor under the log's own head and key, is "
                 "the positive control."},
        {"name": NAME + "-authority-log-key", "artifact": "timestamp-anchor", "timestamp_file": VEC + NAME + ".json",
         "log_key": log_key, "trusted_witnesses": "cosigners", "threshold": 2, "expect": {"anchored": False},
         "since": SINCE,
         "note": "The same head under the log key of timestamp-anchor-variants-base, which did not sign "
                 "it: not anchored. timestamp-anchor-variants-base is the positive control."},
    ]
    (OUT / (NAME + ".json")).write_text(json.dumps(ts, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    mine = {c["name"] for c in cases}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote 1 vector and %d cases (total %d)" % (len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
