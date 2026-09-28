#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the timestamp-anchor variant conformance vectors: one genuinely signed, twice-
witnessed one-entry log over the published conformance timestamp, and variants that differ in
exactly one signed fact.

2026-09-23 a held-out round removed rules from both SDKs' verify_timestamp_anchor, and three
survived every test: a head genuinely signed for ANOTHER log anchored the timestamp, and a
cosignature over another tree size, or over another root, counted toward the witness quorum.
The code was right and its tests were missing; sdk/testdata/anchor-variants.json added them to
the SDK suites. The published contract never carried those inputs, so a verifier written
against it could skip all three checks and still conform. These cases publish them.

The base anchor is published too, as the positive control for these keys: without it a verifier
that never anchors, or never counts a witness, would pass every variant.

Each vector is decided by the detached verifier before it is written. Keys are fresh per run.

    python3 conformance/make_anchor_variant_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.0.0-rc.66"
LOG_ID = "polaris-timestamp-log"
PROVENANCE = "real ML-DSA-65 (liboqs); conformance/make_anchor_variant_vectors.py"


def main():
    try:
        import oqs  # type: ignore
    except Exception as e:  # noqa: BLE001
        print("needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)

    def keypair():
        with oqs.Signature("ML-DSA-65") as s:
            return bytes(s.generate_keypair()), bytes(s.export_secret_key())

    def sign(sk, digest):
        with oqs.Signature("ML-DSA-65", secret_key=sk) as s:
            return bytes(s.sign(digest))

    # verify_timestamp_anchor checks the timestamp's HASH, not its signature, so the published
    # conformance timestamp is the entry, exactly as the SDK fixture does it.
    ts = json.loads((OUT / "timestamp-valid.json").read_text(encoding="utf-8"))
    ts.pop("anchor", None)
    ts.pop("_vector", None)
    entry = V.timestamp_hash(ts)
    root = V._lh(entry).hex()
    log_pk, log_sk = keypair()
    w1_pk, w1_sk = keypair()
    w2_pk, w2_sk = keypair()

    def sth(log_id=LOG_ID):
        head = {"format": "polaris-transparency-sth/1", "algorithm": "ML-DSA-65", "log_id": log_id,
                "tree_size": 1, "root_hash_hex": root, "timestamp": "2026-05-01T00:00:10Z",
                "public_key_hex": log_pk.hex()}
        head["signature_hex"] = sign(log_sk, hashlib.sha3_256(V._sth_canonical(head)).digest()).hex()
        return head

    def cosig(sk, pk, tree_size=1, root_hex=root):
        c = {"format": "polaris-transparency-cosignature/1", "algorithm": "ML-DSA-65", "log_id": LOG_ID,
             "tree_size": tree_size, "root_hash_hex": root_hex, "public_key_hex": pk.hex()}
        c["signature_hex"] = sign(sk, hashlib.sha3_256(V._cosignature_canonical(c)).digest()).hex()
        return c

    def anchored(name, note, head, cosignatures):
        out = dict(ts)
        out["anchor"] = {"log_id": head["log_id"], "timestamp_hash": entry, "sth": head,
                         "proof": {"log_id": LOG_ID, "entry_hex": entry, "index": 0, "tree_size": 1,
                                   "root_hash_hex": root, "proof_hex": []},
                         "cosignatures": cosignatures}
        out["_vector"] = {"name": name, "note": note, "provenance": PROVENANCE}
        return out

    good = [cosig(w1_sk, w1_pk), cosig(w2_sk, w2_pk)]
    variants = (
        ("base", sth(), good, {"anchored": True, "witnessed": True},
         "The positive control: this log's genuine head, the inclusion proof, and two distinct "
         "trusted witnesses cosigning exactly that head."),
        ("other-log", sth("some-other-log"), good, {"anchored": False},
         "A head genuinely signed by the log's key but for ANOTHER log does not anchor an entry "
         "of this one."),
        ("cosignature-other-size", sth(), [good[0], cosig(w2_sk, w2_pk, tree_size=2)],
         {"anchored": True, "witnessed": False},
         "The second cosignature is genuine but over another tree size, so it is not a cosignature "
         "of this head and the threshold of two is not met."),
        ("cosignature-other-root", sth(), [good[0], cosig(w2_sk, w2_pk, root_hex="00" * 32)],
         {"anchored": True, "witnessed": False},
         "The second cosignature is genuine but over another root, so it witnesses a different "
         "log state and the threshold of two is not met."),
    )
    files, new = {}, []
    for label, head, cosigs, want, note in variants:
        name = "timestamp-anchor-variants-%s" % label
        obj = anchored(name, note, head, cosigs)
        got = V.verify_timestamp_anchor(obj, log_key=log_pk.hex(),
                                        trusted_witnesses=[w1_pk.hex(), w2_pk.hex()], threshold=2)
        for key, value in want.items():
            assert got[key] == value, (name, key, got)
        files[name + ".json"] = obj
        new.append({"name": name, "artifact": "timestamp-anchor",
                    "timestamp_file": "conformance/vectors/%s.json" % name, "log_key": "sth",
                    "trusted_witnesses": "cosigners", "threshold": 2, "expect": want,
                    "since": SINCE, "note": note})

    for fname, obj in files.items():
        (OUT / fname).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    names = {c["name"] for c in doc["cases"]}
    doc["cases"].extend(c for c in new if c["name"] not in names)
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors, %d cases (total %d)" % (len(files), len(new), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
