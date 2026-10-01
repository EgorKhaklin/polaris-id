#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the holder-proof credential vectors and cases (1.0.0-rc.68).

A holder proof names the credential it is about: `token_value` is inside the statement the
holder signs (WIRE-SPEC section 3.15). Until 2026-09-30 no verifier here compared it with the
credential presented, only the proof's key with the binding's, so a proof a holder made for
one credential passed with another credential bound to the same holder key.

The vectors are a fresh chain, generated here: an ISSUER signs a credential and binds a HOLDER
key to it; the holder signs two proofs, one naming this credential and one naming another.

    holder-chain-proof-for-another-credential   the proof names another token -> not proved
    holder-chain-proof-for-this-credential      the positive control: the same chain and holder
        key, the proof naming this credential -> proved, so the refusal above is the token's

Every expected value is checked against the detached verifier and the Python SDK before
anything is written. Never modifies a published vector: every file here is new.

    python3 conformance/make_holder_token_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.0.0-rc.68"
VEC = "conformance/vectors/"
NOW = "2026-05-01T00:00:30Z"
NONCE, CONTEXT = "rp-nonce-1", 1


def main():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as e:
        print("needs cryptography with ML-DSA (>=48): %s" % e, file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    sys.path.insert(0, str(ROOT / "sdk" / "python"))
    import polaris_verify as P  # noqa: E402

    def key():
        sk = mldsa.MLDSA65PrivateKey.generate()
        return sk, sk.public_key().public_bytes_raw().hex()

    iss_sk, iss = key()
    hol_sk, hol = key()
    tv = "CONFORMANCE-HOLDER-TOKEN-0001"
    cred = {"format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": "ML-DSA-65",
            "public_key_hex": iss, "signature_hex": iss_sk.sign(hashlib.sha3_256(tv.encode("utf-8")).digest()).hex()}
    binding = {"format": "polaris-holder-binding/1", "token_value": tv, "holder_public_key_hex": hol,
               "holder_algorithm": "ML-DSA-65", "bound_at": "2026-04-30T00:00:00Z", "status": "active",
               "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-05-02T00:00:00Z", "algorithm": "ML-DSA-65"}
    binding["signature_hex"] = iss_sk.sign(hashlib.sha3_256(V._holder_binding_canonical(binding)).digest()).hex()
    binding["public_key_hex"] = iss

    def proof(token):
        pr = {"format": "polaris-holder-proof/1", "token_value": token, "context_id": CONTEXT,
              "verifier_nonce": NONCE, "issued_at": "2026-05-01T00:00:00Z", "algorithm": "ML-DSA-65"}
        pr["signature_hex"] = hol_sk.sign(hashlib.sha3_256(V._holder_proof_canonical(pr)).digest()).hex()
        pr["public_key_hex"] = hol
        return pr

    files = {"holder-token-credential.json": cred, "holder-token-binding.json": binding,
             "holder-token-proof-this.json": proof(tv),
             "holder-token-proof-other.json": proof("CONFORMANCE-HOLDER-TOKEN-0002")}
    cases = []
    for name, proof_file, proved, why in (
            ("holder-chain-proof-for-another-credential", "holder-token-proof-other.json", False,
             "The holder's genuine signature over a proof naming ANOTHER credential, presented with this one. "
             "`token_value` is inside what the holder signs (WIRE-SPEC 3.15), so the proof is about the other "
             "credential. Before this case every verifier here compared only the proof's key with the binding's."),
            ("holder-chain-proof-for-this-credential", "holder-token-proof-this.json", True,
             "The positive control: the same chain and holder key, with the proof naming this credential.")):
        cases.append({"name": name, "artifact": "holder-chain", "credential_file": VEC + "holder-token-credential.json",
                      "binding_file": VEC + "holder-token-binding.json", "proof_file": VEC + proof_file,
                      "expected_nonce": NONCE, "expected_context": CONTEXT, "now": NOW,
                      "expect": {"proved": proved}, "since": SINCE, "note": why})

    for c in cases:
        pr = files[c["proof_file"][len(VEC):]]
        s = P.verify_holder(cred, binding, pr, expected_nonce=NONCE, expected_context=CONTEXT, now=NOW).proved
        bv = V.verify_holder_binding(binding, credential=cred, now=NOW)
        pv = V.verify_holder_proof(pr, binding=binding, expected_nonce=NONCE, expected_context=CONTEXT, now=NOW)
        d = bool(bv["binding_authentic"] and bv["bound_to_credential"] and pv["proof_authentic"]
                 and pv["key_matches_binding"] and pv["nonce_matches"] is not False
                 and pv["context_matches"] is not False and pv["fresh"] is not False)
        if (d, bool(s)) != (c["expect"]["proved"],) * 2:
            print("a verifier disagrees with %s: detached=%s sdk=%s" % (c["name"], d, s), file=sys.stderr)
            return 1

    for name, obj in files.items():
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    mine = {c["name"] for c in cases}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
