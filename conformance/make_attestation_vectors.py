#!/usr/bin/env python3
"""Generate the trust-attestation conformance vectors (P9.5): the attesting agency's own
signature over a federation trust edge. Before v9.348 the edge was a row an operator
recorded, and the manifest that published it signed whatever the table held; a row inserted
straight into a database was indistinguishable from one made through the ceremony.

Each vector is verified by the detached verifier before it is written. Keys are fresh per run.

    python3 conformance/make_attestation_vectors.py
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

    att_pk, att_sk = keypair()     # the ATTESTING authority (B), which signs the edge
    sub_pk, _ = keypair()          # the ATTESTED authority (A), whose key the edge names

    att = {"format": "polaris-trust-attestation/1", "attesting_agency_id": 2,
           "attested_agency_id": 1, "attested_public_key_hex": sub_pk.hex(), "context_id": 3,
           "attested_date": "2026-05-01T00:00:00", "valid_until": "2027-05-01",
           "algorithm": "ML-DSA-65"}
    att["public_key_hex"] = att_pk.hex()
    att["signature_hex"] = sign(att_sk, hashlib.sha3_256(V._attestation_canonical(att)).digest()).hex()
    assert V.verify_attestation(att)["attestation_authentic"] is True
    # The edge is bound to the ATTESTED KEY, so re-pointing it at another key breaks it:
    # an attestation naming an agency alone would keep meaning what the operator meant
    # after that agency rotated to a key the attester never saw.
    other_pk, _ = keypair()
    rekeyed = dict(att, attested_public_key_hex=other_pk.hex())
    assert V.verify_attestation(rekeyed)["attestation_authentic"] is False
    # And widening the context after signing breaks it.
    widened = dict(att, context_id=1)
    assert V.verify_attestation(widened)["attestation_authentic"] is False

    for name, obj in (("trust-attestation-valid.json", att),
                      ("trust-attestation-rekeyed.json", rekeyed),
                      ("trust-attestation-widened.json", widened)):
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    doc = json.loads(CASES.read_text(encoding="utf-8"))
    new = [
        {"name": "trust-attestation-valid", "artifact": "trust-attestation",
         "object_file": "conformance/vectors/trust-attestation-valid.json",
         "expect": {"authentic": True}, "since": "9.348",
         "note": "P9.5: the attesting agency signed this edge itself; it is not the operator's word."},
        {"name": "trust-attestation-rekeyed", "artifact": "trust-attestation",
         "object_file": "conformance/vectors/trust-attestation-rekeyed.json",
         "expect": {"authentic": False}, "since": "9.348",
         "note": "P9.5: the edge is bound to the attested KEY, so re-pointing it at another key breaks it."},
        {"name": "trust-attestation-widened", "artifact": "trust-attestation",
         "object_file": "conformance/vectors/trust-attestation-widened.json",
         "expect": {"authentic": False}, "since": "9.348",
         "note": "P9.5: the context is signed, so an edge cannot be widened after the fact."},
    ]
    names = {c["name"] for c in doc["cases"]}
    doc["cases"].extend(c for c in new if c["name"] not in names)
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote 3 vectors, %d cases (total %d)" % (len(new), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
