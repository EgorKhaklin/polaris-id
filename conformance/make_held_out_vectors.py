#!/usr/bin/env python3
"""Generate the last two held-out fixtures as published conformance cases: a holder proof's
exact window, and a revoked leaf written in upper case.

Both inputs were found on 2026-09-23 by removing or loosening a rule in both SDKs and watching
every test stay green; the code was right and the tests were missing, and sdk/testdata added
them to the SDK suites only. The published contract never carried them, so a verifier written
against it could loosen either rule and still conform.

HOLDER PROOF WINDOW. The published holder chain issues its binding and its proof at the same
instant, so a proof dated inside the one-minute skew is also before its binding opens, and the
skew cannot be told apart from the binding's freshness: doubling the skew survived. Here the
binding opens a day before the proof, so only the proof's own window decides, at its four
edges: five minutes after the proof and one second more, one minute before it and one second
more.

UPPER-CASE LEAF. The issuer's own feed, genuinely signed, lists the credential's leaf in upper-
case hex. The feed's commitment is computed over lower-cased leaves (wire spec), so the feed is
authentic, and a membership test that compares case-sensitively misses the listing and accepts
a revoked credential. The same credential with no feed is the positive control.

Every case is decided through the detached verifier's conformance harness before it is
published; on any disagreement the vectors are removed and nothing is published. Keys are
fresh per run.

    python3 conformance/make_held_out_vectors.py
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
PROVENANCE = "real ML-DSA-65 (liboqs); conformance/make_held_out_vectors.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def main():
    try:
        import oqs  # type: ignore
    except Exception as e:  # noqa: BLE001
        print("needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    V = _load("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    sys.path.insert(0, str(ROOT / "scripts"))
    harness = _load("polaris_conformance_harness", ROOT / "scripts" / "test_verify_conformance.py")

    def keypair():
        with oqs.Signature("ML-DSA-65") as s:
            return bytes(s.generate_keypair()), bytes(s.export_secret_key())

    def sign(sk, digest):
        with oqs.Signature("ML-DSA-65", secret_key=sk) as s:
            return bytes(s.sign(digest))

    def pack_for(token, pk, sk, name):
        return {"format": "polaris-authenticity-pack/1", "algorithm": "ML-DSA-65", "token_value": token,
                "public_key_hex": pk.hex(),
                "signature_hex": sign(sk, hashlib.sha3_256(token.encode("utf-8")).digest()).hex(),
                "_vector": {"name": name, "provenance": PROVENANCE}}

    files, new = {}, []

    # --- the holder proof's window ------------------------------------------------------------
    issuer_pk, issuer_sk = keypair()
    holder_pk, holder_sk = keypair()
    token = "TKN-HOLDER-WINDOW-1"
    files["holder-window-credential.json"] = pack_for(token, issuer_pk, issuer_sk, "holder-window-credential")
    binding = {"format": "polaris-holder-binding/1", "algorithm": "ML-DSA-65", "token_value": token,
               "holder_public_key_hex": holder_pk.hex(), "holder_algorithm": "ML-DSA-65",
               "bound_at": "2026-04-29T00:00:00Z", "status": "active",
               "issued_at": "2026-04-30T00:00:00Z", "expires_at": "2026-05-02T00:00:00Z",
               "public_key_hex": issuer_pk.hex()}
    binding["signature_hex"] = sign(issuer_sk, hashlib.sha3_256(V._holder_binding_canonical(binding)).digest()).hex()
    binding["_vector"] = {"name": "holder-window-binding", "provenance": PROVENANCE,
                          "note": "valid from a day before the proof until a day after it"}
    proof = {"format": "polaris-holder-proof/1", "algorithm": "ML-DSA-65", "token_value": token,
             "context_id": 1, "verifier_nonce": "rp-nonce-window", "issued_at": "2026-05-01T00:00:00Z",
             "public_key_hex": holder_pk.hex()}
    proof["signature_hex"] = sign(holder_sk, hashlib.sha3_256(V._holder_proof_canonical(proof)).digest()).hex()
    proof["_vector"] = {"name": "holder-window-proof", "provenance": PROVENANCE,
                        "note": "issued 2026-05-01T00:00:00Z; fresh for five minutes, a minute of skew before"}
    files["holder-window-binding.json"] = binding
    files["holder-window-proof.json"] = proof
    for label, now, want, note in (
            ("late-edge", "2026-05-01T00:05:00Z", True, "five minutes after the proof: the last instant it is fresh"),
            ("late-past", "2026-05-01T00:05:01Z", False, "one second past the five-minute window"),
            ("early-edge", "2026-04-30T23:59:00Z", True, "one minute before the proof: the clock skew allowed"),
            ("early-past", "2026-04-30T23:58:59Z", False, "one second more skew than is allowed")):
        new.append({"name": "holder-chain-proof-window-%s" % label, "artifact": "holder-chain",
                    "credential_file": "conformance/vectors/holder-window-credential.json",
                    "binding_file": "conformance/vectors/holder-window-binding.json",
                    "proof_file": "conformance/vectors/holder-window-proof.json",
                    "expected_nonce": "rp-nonce-window", "expected_context": 1, "now": now,
                    "expect": {"proved": want}, "since": SINCE,
                    "note": "The binding is valid throughout, so only the proof's own window decides: %s." % note})

    # --- the upper-case revoked leaf ------------------------------------------------------------
    a_pk, a_sk = keypair()    # authority A: issued the credential, publishes its feed
    b_pk, b_sk = keypair()    # authority B: attests A's key
    token2 = "TKN-XA-UPPERCASE-LEAF-1"
    files["cross-authority-uppercase-leaf-pack.json"] = pack_for(token2, a_pk, a_sk, "cross-authority-uppercase-leaf-pack")
    m = {"format": "polaris-federation-manifest/1", "algorithm": "ML-DSA-65",
         "authority": {"agency_id": 2, "name": "Authority B"},
         "anchors": [{"public_key_hex": b_pk.hex(), "algorithm": "ML-DSA-65", "status": "active"}],
         "attestations": [{"attested_agency_id": 1, "attested_public_key_hex": a_pk.hex(), "context_id": 1}],
         "epoch": {"number": 1, "root_hex": "bb" * 32}, "revocation": {"as_of": "2026-05-31T00:00:00Z"},
         "issued_at": "2026-05-31T00:00:00Z", "expires_at": "2026-06-30T00:00:00Z", "public_key_hex": b_pk.hex()}
    m["signature_hex"] = sign(b_sk, hashlib.sha3_256(V._manifest_canonical(m)).digest()).hex()
    m["_vector"] = {"name": "cross-authority-uppercase-leaf-manifest", "provenance": PROVENANCE}
    leaf = V.revocation_leaf(token2)
    feed = {"format": "polaris-revocation-feed/1", "algorithm": "ML-DSA-65",
            "authority": {"agency_id": 1, "name": "Authority A"}, "epoch_number": 1,
            "as_of": "2026-05-31T00:00:00Z", "revoked_root_hex": V.revoked_root([leaf.upper()]),
            "revoked_count": 1, "revoked_leaves": [leaf.upper()],
            "issued_at": "2026-05-31T00:00:00Z", "expires_at": "2026-06-30T00:00:00Z",
            "public_key_hex": a_pk.hex()}
    feed["signature_hex"] = sign(a_sk, hashlib.sha3_256(V._revocation_feed_canonical(feed)).digest()).hex()
    feed["_vector"] = {"name": "cross-authority-uppercase-leaf-feed", "provenance": PROVENANCE,
                       "note": "the issuer's own feed lists this credential's leaf in upper-case hex"}
    files["cross-authority-uppercase-leaf-manifest.json"] = m
    files["cross-authority-uppercase-leaf-feed.json"] = feed
    base = {"artifact": "cross-authority",
            "pack_file": "conformance/vectors/cross-authority-uppercase-leaf-pack.json",
            "manifest_files": ["conformance/vectors/cross-authority-uppercase-leaf-manifest.json"],
            "trusted_anchors": "manifest", "context_id": 1, "now": "2026-06-01T00:00:00Z", "since": SINCE}
    new.append(dict(base, name="cross-authority-uppercase-leaf-no-feed", expect={"decision": "accept"},
                    note="The positive control: the same credential, with no feed supplied, is accepted."))
    new.append(dict(base, name="cross-authority-uppercase-leaf-revoked", expect={"decision": "reject"},
                    feed_file="conformance/vectors/cross-authority-uppercase-leaf-feed.json",
                    note="The issuer's authentic feed lists the leaf in upper-case hex. Leaves are hex "
                         "and compared without regard to case, as the feed's own commitment is."))

    for fname, obj in files.items():
        (OUT / fname).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    wrong = []
    for c in new:
        got = harness._verdict_for(c)
        wrong += ["%s: %s != %s" % (c["name"], got.get(k), v) for k, v in c["expect"].items() if got.get(k) != v]
    if wrong:
        for fname in files:
            (OUT / fname).unlink()
        print("NOT PUBLISHED, the detached verifier disagrees:\n  " + "\n  ".join(wrong), file=sys.stderr)
        return 1
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    names = {c["name"] for c in doc["cases"]}
    doc["cases"].extend(c for c in new if c["name"] not in names)
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors, %d cases (total %d)" % (len(files), len(new), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
