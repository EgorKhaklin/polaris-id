#!/usr/bin/env python3
"""Generate the algorithm-agility conformance vectors (P8.8a, v9.329).

The artifacts the suite already certifies, signed under ML-DSA-87; a genuine ML-DSA-44 pack
that every conformant verifier MUST refuse (below the floor); and a trust list that records a
migration: a retired ML-DSA-65 key beside the active ML-DSA-87 key that signs the list. Each
vector is verified by the detached verifier before it is written, and the ML-DSA-87 pack is
cross-checked under dilithium-py (an independent FIPS 204 implementation) when it is present.
Keys are fresh per run; the written vectors are committed, so the suite is deterministic.

    python3 conformance/make_algorithm_vectors.py        # rewrites the five vectors + cases
"""
import hashlib
import importlib.util
from datetime import datetime, timezone
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"


def _load_verifier():
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _at(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc)


def main():
    try:
        import oqs  # type: ignore
    except Exception as e:
        print("needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    V = _load_verifier()

    def keypair(alg):
        with oqs.Signature(alg) as s:
            pk = bytes(s.generate_keypair())
            return pk, bytes(s.export_secret_key())

    def sign(alg, sk, digest):
        with oqs.Signature(alg, secret_key=sk) as s:
            return bytes(s.sign(digest))

    pk87, sk87 = keypair("ML-DSA-87")
    pk65, sk65 = keypair("ML-DSA-65")
    pk44, sk44 = keypair("ML-DSA-44")
    written = {}

    def write(name, obj):
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written[name] = obj

    # 1. The authenticity pack under ML-DSA-87 (valid, tampered) and a genuine ML-DSA-44 pack.
    tok = "POLARIS-CONFORMANCE-MLDSA87-0001"
    pack = {"format": "polaris-authenticity-pack/1", "token_value": tok, "algorithm": "ML-DSA-87",
            "signature_hex": sign("ML-DSA-87", sk87, V._digest(tok)).hex(), "public_key_hex": pk87.hex()}
    assert V.verify_pack(pack)["signature_valid"] is True
    bad = bytearray(bytes.fromhex(pack["signature_hex"])); bad[0] ^= 0x01
    tampered = dict(pack, signature_hex=bytes(bad).hex())
    assert V.verify_pack(tampered)["signature_valid"] is False
    pack44 = {"format": "polaris-authenticity-pack/1", "token_value": tok, "algorithm": "ML-DSA-44",
              "signature_hex": sign("ML-DSA-44", sk44, V._digest(tok)).hex(), "public_key_hex": pk44.hex()}
    with oqs.Signature("ML-DSA-44") as s44:  # genuine under ML-DSA-44: the refusal is policy, not a bad signature
        assert s44.verify(V._digest(tok), bytes.fromhex(pack44["signature_hex"]), pk44)
    assert V.verify_pack(pack44)["signature_valid"] is False
    write("pack-mldsa87-valid.json", pack)
    write("pack-mldsa87-tampered.json", tampered)
    write("pack-mldsa44-unaccepted.json", pack44)
    try:
        from dilithium_py.ml_dsa import ML_DSA_87  # type: ignore
        assert ML_DSA_87.verify(pk87, V._digest(tok), bytes.fromhex(pack["signature_hex"]))
        print("  cross-check: dilithium-py (independent FIPS 204) verifies the ML-DSA-87 pack")
    except ImportError:
        print("  cross-check: dilithium-py not installed (skipped)")

    # 2. The status assertion under ML-DSA-87 (the published valid vector's body, re-signed).
    sa = json.loads((OUT / "status-assertion-valid.json").read_text(encoding="utf-8"))
    sa["algorithm"] = "ML-DSA-87"
    sa["public_key_hex"] = pk87.hex()
    sa["signature_hex"] = sign("ML-DSA-87", sk87, hashlib.sha3_256(V._status_assertion_canonical(sa)).digest()).hex()
    v = V.verify_status_assertion(sa, now=_at("2026-06-01T00:00:00Z"))
    assert v["status_authentic"] is True and v["fresh"] is True, v
    write("status-assertion-mldsa87-valid.json", sa)

    # 3. A trust list recording a migration: the ML-DSA-65 key retired, the ML-DSA-87 key active
    #    and signing. Verifiers require the signer key ACTIVE for the publisher; the retired key
    #    stays listed so evidence signed before its retirement can still be judged.
    tl = json.loads((OUT / "trust-list-valid.json").read_text(encoding="utf-8"))
    template = dict(tl["keys"][0])
    old_key = dict(template, public_key_hex=pk65.hex(), algorithm="ML-DSA-65", status="retired",
                   registered_at="2026-01-01T00:00:00Z", retired_at="2026-04-01T00:00:00Z", compromised_at=None)
    new_key = dict(template, public_key_hex=pk87.hex(), algorithm="ML-DSA-87", status="active",
                   registered_at="2026-04-01T00:00:00Z", retired_at=None, compromised_at=None)
    tl["keys"] = [old_key, new_key]
    tl["algorithm"] = "ML-DSA-87"
    tl["public_key_hex"] = pk87.hex()
    tl["signature_hex"] = sign("ML-DSA-87", sk87, hashlib.sha3_256(V._trust_list_canonical(tl)).digest()).hex()
    v = V.verify_trust_list(tl, now=_at("2026-05-01T12:00:00Z"))
    assert v["trust_list_authentic"] is True and v["fresh"] is True, v
    assert V.key_status_at(tl, pk65.hex(), _at("2026-03-01T00:00:00Z")) == "active"
    assert V.key_status_at(tl, pk65.hex(), _at("2026-05-01T00:00:00Z")) == "retired"
    assert V.key_status_at(tl, pk87.hex(), _at("2026-05-01T00:00:00Z")) == "active"
    # the list signed by the RETIRED ML-DSA-65 key must be refused (a publisher cannot sign under a retired key)
    tl_retired = dict(tl, algorithm="ML-DSA-65", public_key_hex=pk65.hex())
    tl_retired["signature_hex"] = sign("ML-DSA-65", sk65, hashlib.sha3_256(V._trust_list_canonical(tl_retired)).digest()).hex()
    assert V.verify_trust_list(tl_retired, now=_at("2026-05-01T12:00:00Z"))["trust_list_authentic"] is False
    write("trust-list-migration.json", tl)
    write("trust-list-migration-retired-signer.json", tl_retired)

    # 4. The cases.
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    pack_case = next(c for c in doc["cases"] if c.get("artifact", "authenticity-pack") == "authenticity-pack" and any(k.endswith("_file") for k in c))
    pack_key = next(k for k in pack_case if k.endswith("_file"))
    new_cases = [
        {"name": "pack-mldsa87-valid", "artifact": "authenticity-pack", pack_key: "conformance/vectors/pack-mldsa87-valid.json",
         "expect": {"authentic": True},
         "note": "P8.8a: a genuine ML-DSA-87 pack verifies; an accepted parameter set beside the default."},
        {"name": "pack-mldsa87-tampered", "artifact": "authenticity-pack", pack_key: "conformance/vectors/pack-mldsa87-tampered.json",
         "expect": {"authentic": False}, "note": "P8.8a: one flipped signature byte under ML-DSA-87."},
        {"name": "pack-mldsa44-unaccepted", "artifact": "authenticity-pack", pack_key: "conformance/vectors/pack-mldsa44-unaccepted.json",
         "expect": {"authentic": False},
         "note": "P8.8a: a GENUINE ML-DSA-44 signature MUST be refused: the parameter set is below the floor (wire spec section 6)."},
        {"name": "status-assertion-mldsa87-active", "artifact": "status-assertion",
         "assertion_file": "conformance/vectors/status-assertion-mldsa87-valid.json", "now": "2026-06-01T00:00:00Z",
         "expect": {"authentic": True, "fresh": True, "active": True}, "note": "P8.8a: the status assertion under ML-DSA-87."},
        {"name": "trust-list-migration", "artifact": "trust-list", "object_file": "conformance/vectors/trust-list-migration.json",
         "now": "2026-05-01T12:00:00Z", "expect": {"authentic": True, "fresh": True},
         "note": "P8.8a: an algorithm migration recorded in a trust list: the ML-DSA-65 key retired, the ML-DSA-87 key active and signing."},
        {"name": "trust-list-migration-retired-signer", "artifact": "trust-list",
         "object_file": "conformance/vectors/trust-list-migration-retired-signer.json", "now": "2026-05-01T12:00:00Z",
         "expect": {"authentic": False},
         "note": "P8.8a: the same list signed by the RETIRED ML-DSA-65 key is refused: a publisher signs only under a key it lists active."},
    ]
    names = {c["name"] for c in doc["cases"]}
    doc["cases"] = [c for c in doc["cases"] if c["name"] not in {n["name"] for n in new_cases}] + new_cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("  wrote %d vectors, cases now %d (added %d)" % (len(written), len(doc["cases"]), len([n for n in new_cases if n["name"] not in names])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
