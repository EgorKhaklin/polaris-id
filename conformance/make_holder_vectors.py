#!/usr/bin/env python3
"""Generate the holder-key conformance vectors (P9.1): the chain issuer anchor -> binding ->
holder key -> proof. Polaris was issuer-centric until v9.349, so presenting the credential
file was the whole of the proof; a holder proof answers whether the party presenting it holds
the key the issuer bound to that credential.

Every vector is verified by the detached verifier before it is written; the proof deliberately
does not cover the presented code, so a coerced presentation stays byte-indistinguishable.

    python3 conformance/make_holder_vectors.py
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

    def kp():
        with oqs.Signature("ML-DSA-65") as s:
            return bytes(s.generate_keypair()), bytes(s.export_secret_key())

    def sign(sk, d):
        with oqs.Signature("ML-DSA-65", secret_key=sk) as s:
            return bytes(s.sign(d))

    iso = lambda d: d.isoformat().replace("+00:00", "Z")
    iss_pk, iss_sk = kp()          # the issuing authority
    hol_pk, hol_sk = kp()          # the HOLDER's key, which never reaches Polaris
    oth_pk, oth_sk = kp()          # somebody else's key
    tv = "CONFORMANCE-HOLDER-0001"

    cred = {"format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": "ML-DSA-65",
            "public_key_hex": iss_pk.hex(),
            "signature_hex": sign(iss_sk, hashlib.sha3_256(tv.encode("utf-8")).digest()).hex()}

    def binding(key, status="active"):
        b = {"format": "polaris-holder-binding/1", "token_value": tv,
             "holder_public_key_hex": key.hex(), "holder_algorithm": "ML-DSA-65",
             "bound_at": iso(NOW - timedelta(days=1)), "status": status,
             "issued_at": iso(NOW), "expires_at": iso(NOW + timedelta(hours=24)),
             "algorithm": "ML-DSA-65"}
        b["signature_hex"] = sign(iss_sk, hashlib.sha3_256(V._holder_binding_canonical(b)).digest()).hex()
        b["public_key_hex"] = iss_pk.hex()
        return b

    def proof(sk, pk, nonce="rp-nonce-1", ctx=1):
        pr = {"format": "polaris-holder-proof/1", "token_value": tv, "context_id": ctx,
              "verifier_nonce": nonce, "issued_at": iso(NOW), "algorithm": "ML-DSA-65"}
        pr["signature_hex"] = sign(sk, hashlib.sha3_256(V._holder_proof_canonical(pr)).digest()).hex()
        pr["public_key_hex"] = pk.hex()
        return pr

    good_b, good_p = binding(hol_pk), proof(hol_sk, hol_pk)
    revoked_b = binding(hol_pk, "revoked")
    stranger_p = proof(oth_sk, oth_pk)
    replayed_p = proof(hol_sk, hol_pk, nonce="a-nonce-another-verifier-issued")
    tampered_b = dict(good_b, holder_public_key_hex=oth_pk.hex())

    for name, obj in (("holder-credential.json", cred), ("holder-binding-valid.json", good_b),
                      ("holder-binding-revoked.json", revoked_b), ("holder-binding-tampered.json", tampered_b),
                      ("holder-proof-valid.json", good_p), ("holder-proof-stranger.json", stranger_p),
                      ("holder-proof-replayed.json", replayed_p)):
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Pre-verify every verdict the cases will assert, with the detached verifier.
    at = iso(NOW + timedelta(seconds=30))
    assert V.verify_holder_binding(good_b, credential=cred, now=V._parse_iso(at))["binding_authentic"] is True
    assert V.verify_holder_binding(tampered_b, credential=cred, now=V._parse_iso(at))["binding_authentic"] is False
    assert V.verify_holder_proof(good_p, binding=good_b, expected_nonce="rp-nonce-1",
                                 now=V._parse_iso(at))["key_matches_binding"] is True
    assert V.verify_holder_proof(good_p, binding=revoked_b, now=V._parse_iso(at))["key_matches_binding"] is False

    doc = json.loads(CASES.read_text(encoding="utf-8"))
    chain = lambda name, b, pr, want, note: {
        "name": name, "artifact": "holder-chain",
        "credential_file": "conformance/vectors/holder-credential.json",
        "binding_file": "conformance/vectors/%s" % b, "proof_file": "conformance/vectors/%s" % pr,
        "expected_nonce": "rp-nonce-1", "expected_context": 1, "now": at,
        "expect": {"proved": want}, "since": "9.349", "note": note}
    new = [
        {"name": "holder-binding-valid", "artifact": "holder-binding",
         "object_file": "conformance/vectors/holder-binding-valid.json", "now": at,
         "expect": {"authentic": True, "fresh": True}, "since": "9.349",
         "note": "P9.1: the issuer's signed statement that this holder key belongs to this credential."},
        {"name": "holder-binding-tampered", "artifact": "holder-binding",
         "object_file": "conformance/vectors/holder-binding-tampered.json", "now": at,
         "expect": {"authentic": False}, "since": "9.349",
         "note": "P9.1: the bound key was swapped after signing."},
        {"name": "holder-proof-valid", "artifact": "holder-proof",
         "object_file": "conformance/vectors/holder-proof-valid.json", "now": at,
         "expect": {"authentic": True}, "since": "9.349",
         "note": "P9.1: the holder's own signature over the credential, context, nonce and instant."},
        chain("holder-chain-proved", "holder-binding-valid.json", "holder-proof-valid.json", True,
              "P9.1: the party presenting the credential holds the key its issuer bound to it."),
        chain("holder-chain-stranger", "holder-binding-valid.json", "holder-proof-stranger.json", False,
              "P9.1: a genuine proof by a key the issuer never bound proves nothing about this credential."),
        chain("holder-chain-replayed", "holder-binding-valid.json", "holder-proof-replayed.json", False,
              "P9.1: a proof naming another verifier's nonce is a replay of one made for somebody else."),
        chain("holder-chain-revoked", "holder-binding-revoked.json", "holder-proof-valid.json", False,
              "P9.1: a revoked binding means the holder has no usable key until a new one is bound."),
    ]
    names = {c["name"] for c in doc["cases"]}
    doc["cases"].extend(c for c in new if c["name"] not in names)
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote 7 vectors and %d cases (total %d)" % (len(new), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
