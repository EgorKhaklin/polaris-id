#!/usr/bin/env python3
"""Generate the timestamp-anchor conformance vectors (P9.6, was P8.5c): the evidence that a
timestamp is an entry in a witnessed append-only log, which is what makes long-term validation
survive a stolen timestamp key. Every vector is verified by the detached verifier before it is
written, and the cases assert the same verdicts the SDKs must reach. Keys are fresh per run.

    python3 conformance/make_anchor_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"


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

    tsa_pk, tsa_sk = keypair()          # the timestamp authority
    log_pk, log_sk = keypair()          # the timestamp log's head signer
    w1_pk, w1_sk = keypair()            # witness one
    w2_pk, w2_sk = keypair()            # witness two
    other_pk, _ = keypair()             # a key nobody trusts

    ts = {"format": "polaris-timestamp/1", "authority": {"agency_id": 1, "name": "Conformance Authority"},
          "digest_hex": hashlib.sha3_256(b"a notional document").hexdigest(), "digest_algorithm": "SHA3-256",
          "nonce": "c0ffee00c0ffee00", "issued_at": "2026-05-01T00:00:00Z", "algorithm": "ML-DSA-65"}
    ts["public_key_hex"] = tsa_pk.hex()
    ts["signature_hex"] = sign(tsa_sk, hashlib.sha3_256(V._timestamp_canonical(ts)).digest()).hex()
    assert V.verify_timestamp(ts)["timestamp_authentic"] is True

    # The log holds four entries; ours is the third, so the proof has real siblings.
    h = V.timestamp_hash(ts)
    entries = [hashlib.sha3_256(b"earlier-0").hexdigest(), hashlib.sha3_256(b"earlier-1").hexdigest(),
               h, hashlib.sha3_256(b"later-3").hexdigest()]
    idx = entries.index(h)
    root = V.merkle_tree_head(entries)
    path = V.inclusion_proof(idx, entries)

    sth = {"format": "polaris-transparency-sth/1", "log_id": "polaris-timestamp-log",
           "tree_size": len(entries), "root_hash_hex": root.hex(), "timestamp": "2026-05-01T00:00:10Z",
           "algorithm": "ML-DSA-65", "public_key_hex": log_pk.hex()}
    sth["signature_hex"] = sign(log_sk, hashlib.sha3_256(V._sth_canonical(sth)).digest()).hex()

    def cosign(pk, sk):
        c = {"format": "polaris-transparency-cosignature/1", "log_id": sth["log_id"],
             "tree_size": sth["tree_size"], "root_hash_hex": sth["root_hash_hex"],
             "algorithm": "ML-DSA-65", "public_key_hex": pk.hex()}
        c["signature_hex"] = sign(sk, hashlib.sha3_256(V._cosignature_canonical(c)).digest()).hex()
        return c

    proof = {"log_id": sth["log_id"], "entry_hex": h, "index": idx, "tree_size": len(entries),
             "root_hash_hex": root.hex(), "proof_hex": [p.hex() for p in path]}

    anchored = dict(ts, anchor={"log_id": sth["log_id"], "timestamp_hash": h, "proof": proof, "sth": sth})
    witnessed = dict(ts, anchor={"log_id": sth["log_id"], "timestamp_hash": h, "proof": proof, "sth": sth,
                                 "cosignatures": [cosign(w1_pk, w1_sk), cosign(w2_pk, w2_sk)]})
    # A forged anchor: a fabricated head signed by a stolen log key, with no witness on it.
    f_entries = [h]
    f_root = V.merkle_tree_head(f_entries)
    f_sth = {"format": "polaris-transparency-sth/1", "log_id": sth["log_id"], "tree_size": 1,
             "root_hash_hex": f_root.hex(), "timestamp": "2026-05-01T00:00:10Z",
             "algorithm": "ML-DSA-65", "public_key_hex": log_pk.hex()}
    f_sth["signature_hex"] = sign(log_sk, hashlib.sha3_256(V._sth_canonical(f_sth)).digest()).hex()
    forged = dict(ts, anchor={"log_id": sth["log_id"], "timestamp_hash": h,
                              "proof": {"log_id": sth["log_id"], "entry_hex": h, "index": 0, "tree_size": 1,
                                        "root_hash_hex": f_root.hex(), "proof_hex": []},
                              "sth": f_sth, "cosignatures": [cosign(w1_pk, w1_sk)]})
    # A broken proof: the right head, a path that cannot reconstruct it.
    broken = dict(ts, anchor={"log_id": sth["log_id"], "timestamp_hash": h,
                              "proof": dict(proof, proof_hex=[("11" * 32)] * len(path)), "sth": sth})

    tw = sorted({w1_pk.hex(), w2_pk.hex()})
    for name, obj, want in (("timestamp-anchor-valid.json", anchored, (True, None)),
                            ("timestamp-anchor-witnessed.json", witnessed, (True, True)),
                            ("timestamp-anchor-unwitnessed.json", anchored, (True, False)),
                            ("timestamp-anchor-forged.json", forged, (True, False)),
                            ("timestamp-anchor-broken-proof.json", broken, (False, None))):
        wl = tw if want[1] is not None else None
        v = V.verify_timestamp_anchor(obj, log_key=log_pk.hex(), trusted_witnesses=wl, threshold=1)
        assert bool(v["anchored"]) is want[0], (name, v)
        if want[1] is not None:
            assert bool(v["witnessed"]) is want[1], (name, v)
        if name != "timestamp-anchor-unwitnessed.json":
            (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    doc = json.loads(CASES.read_text(encoding="utf-8"))
    new = [
        {"name": "timestamp-anchor-valid", "artifact": "timestamp-anchor",
         "timestamp_file": "conformance/vectors/timestamp-anchor-valid.json", "log_key": "sth",
         "expect": {"anchored": True, "witnessed": None}, "since": "9.346",
         "note": "P9.6: the inclusion proof reconstructs a head the expected log key signed."},
        {"name": "timestamp-anchor-witnessed", "artifact": "timestamp-anchor",
         "timestamp_file": "conformance/vectors/timestamp-anchor-witnessed.json", "log_key": "sth",
         "trusted_witnesses": "cosigners", "threshold": 2,
         "expect": {"anchored": True, "witnessed": True}, "since": "9.346",
         "note": "P9.6: two distinct trusted witnesses have cosigned this exact head."},
        {"name": "timestamp-anchor-unwitnessed", "artifact": "timestamp-anchor",
         "timestamp_file": "conformance/vectors/timestamp-anchor-valid.json", "log_key": "sth",
         "trusted_witnesses": [], "threshold": 1,
         "expect": {"anchored": True, "witnessed": False}, "since": "9.346",
         "note": "P9.6: anchored, but nobody the verifier trusts has cosigned the head."},
        {"name": "timestamp-anchor-forged-head", "artifact": "timestamp-anchor",
         "timestamp_file": "conformance/vectors/timestamp-anchor-forged.json", "log_key": "sth",
         "trusted_witnesses": [], "threshold": 1,
         "expect": {"anchored": True, "witnessed": False}, "since": "9.346",
         "note": "P9.6: a stolen log key can sign a fabricated head; it cannot make a trusted witness cosign it."},
        {"name": "timestamp-anchor-broken-proof", "artifact": "timestamp-anchor",
         "timestamp_file": "conformance/vectors/timestamp-anchor-broken-proof.json", "log_key": "sth",
         "expect": {"anchored": False, "witnessed": None}, "since": "9.346",
         "note": "P9.6: the path does not reconstruct the head."},
    ]
    names = {c["name"] for c in doc["cases"]}
    doc["cases"].extend(c for c in new if c["name"] not in names)
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote 4 vectors and %d cases (total %d)" % (len(new), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
