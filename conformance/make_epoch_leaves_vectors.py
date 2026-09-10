#!/usr/bin/env python3
"""Generate the epoch-leaves conformance vectors (P9.2): the published anonymity set a holder
proves membership against on their OWN device. Until v9.350 no endpoint published the set, so
a holder had to be handed it out of band, which in practice meant the issuer proving for them.

The leaves ride outside the signed statement and are committed to by leaves_root_hex, so any
verifier checks the set with SHA3-256 alone and never needs the proving library.

    python3 conformance/make_epoch_leaves_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
NOW = datetime(2026, 5, 1, tzinfo=timezone.utc)


def main():
    try:
        import oqs  # type: ignore
    except Exception as e:  # noqa: BLE001
        print("needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)

    with oqs.Signature("ML-DSA-65") as s:
        pk, sk = bytes(s.generate_keypair()), bytes(s.export_secret_key())

    def sign(d):
        with oqs.Signature("ML-DSA-65", secret_key=sk) as s:
            return bytes(s.sign(d))

    iso = lambda d: d.isoformat().replace("+00:00", "Z")
    leaves = [hashlib.sha3_256(("member-%d" % i).encode()).hexdigest() for i in range(8)]
    body = {"format": "polaris-epoch-leaves/1",
            "authority": {"agency_id": 1, "name": "Conformance Authority"},
            "epoch_id": 7, "context_id": 1, "merkle_root": "ab" * 32,
            "leaf_count": len(leaves), "leaves_root_hex": V._leaves_root(leaves),
            "issued_at": iso(NOW), "expires_at": iso(NOW + timedelta(hours=24)),
            "algorithm": "ML-DSA-65"}
    body["signature_hex"] = sign(hashlib.sha3_256(V._epoch_leaves_canonical(body)).digest()).hex()
    body["public_key_hex"] = pk.hex()
    body["all_leaves_hex"] = leaves

    at = iso(NOW + timedelta(seconds=30))
    v = V.verify_epoch_leaves(body, now=V._parse_iso(at))
    assert v["leaves_authentic"] and v["commitment_matches"] and v["count_matches"], v
    # A member finds themselves; a non-member does not.
    assert V.member_index(body, leaves[3]) == 3
    assert V.member_index(body, "ff" * 32) is None
    # A set with one leaf swapped no longer matches the commitment the authority signed.
    swapped = dict(body, all_leaves_hex=leaves[:-1] + [hashlib.sha3_256(b"intruder").hexdigest()])
    assert V.verify_epoch_leaves(swapped, now=V._parse_iso(at))["commitment_matches"] is False

    (OUT / "epoch-leaves-valid.json").write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (OUT / "epoch-leaves-swapped.json").write_text(json.dumps(swapped, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    doc = json.loads(CASES.read_text(encoding="utf-8"))
    new = [
        {"name": "epoch-leaves-valid", "artifact": "epoch-leaves",
         "object_file": "conformance/vectors/epoch-leaves-valid.json", "now": at,
         "expect": {"authentic": True, "fresh": True}, "since": "9.350",
         "note": "P9.2: the published anonymity set, signed, with the leaves committed by leaves_root_hex."},
        {"name": "epoch-leaves-swapped", "artifact": "epoch-leaves",
         "object_file": "conformance/vectors/epoch-leaves-swapped.json", "now": at,
         "expect": {"authentic": False}, "since": "9.350",
         "note": "P9.2: a member swapped after signing; the commitment no longer matches the set."},
    ]
    names = {c["name"] for c in doc["cases"]}
    doc["cases"].extend(c for c in new if c["name"] not in names)
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote 2 vectors and %d cases (total %d)" % (len(new), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
