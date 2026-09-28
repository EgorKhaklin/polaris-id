#!/usr/bin/env python3
"""Generate the require-signed-attestation conformance vectors: a relying party that requires
signed edges is not satisfied by a legacy one.

Wire spec section 3.14: an attestation with no signature is LEGACY, a verifier MAY accept it for
one major, and a relying party that requires signed edges says so (`require_signed_attestation`).
On 2026-09-23 a held-out round removed that option's rule from both SDKs and every test stayed
green; sdk/testdata/federation-variants.json added the input to the SDK suites. It was the one
held-out input the published contract could not carry, because the case format had no field for
the option. Cases may now set `require_signed_attestation`.

One credential and two manifests, fresh at `now`, differing only in whether the edge is signed:
- the unsigned edge, the option on: reject;
- the signed edge, the option on: accept (the positive control: the option refuses legacy edges,
  not every edge);
- the unsigned edge, the option off: accept (the control that the option, not the manifest,
  decides).

Each case is decided through the detached verifier's conformance harness before it is
published; on any disagreement the vectors are removed and nothing is published. Keys are fresh
per run.

    python3 conformance/make_signed_edge_vectors.py
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
NOW = "2026-06-01T00:00:00Z"
PROVENANCE = "real ML-DSA-65 (liboqs); conformance/make_signed_edge_vectors.py"


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

    a_pk, a_sk = keypair()   # authority A: issued the credential
    b_pk, b_sk = keypair()   # authority B: attests A's key and publishes the manifest
    token = "TKN-XA-SIGNED-EDGE-1"
    pack = {"format": "polaris-authenticity-pack/1", "algorithm": "ML-DSA-65", "token_value": token,
            "public_key_hex": a_pk.hex(),
            "signature_hex": sign(a_sk, hashlib.sha3_256(token.encode("utf-8")).digest()).hex(),
            "_vector": {"name": "cross-authority-signed-edge-pack", "provenance": PROVENANCE}}

    def manifest(name, signed):
        att = {"attesting_agency_id": 2, "attested_agency_id": 1, "attested_public_key_hex": a_pk.hex(),
               "context_id": 1, "attested_date": "2026-01-01T00:00:00", "valid_until": "2026-12-31"}
        if signed:
            att.update(format="polaris-trust-attestation/1", algorithm="ML-DSA-65", public_key_hex=b_pk.hex())
            att["signature_hex"] = sign(b_sk, hashlib.sha3_256(V._attestation_canonical(att)).digest()).hex()
        m = {"format": "polaris-federation-manifest/1", "algorithm": "ML-DSA-65",
             "authority": {"agency_id": 2, "name": "Authority B"},
             "anchors": [{"public_key_hex": b_pk.hex(), "algorithm": "ML-DSA-65", "status": "active"}],
             "attestations": [att], "epoch": {"number": 1, "root_hex": "bb" * 32},
             "revocation": {"as_of": "2026-05-31T00:00:00Z"},
             "issued_at": "2026-05-31T00:00:00Z", "expires_at": "2026-06-30T00:00:00Z",
             "public_key_hex": b_pk.hex()}
        m["signature_hex"] = sign(b_sk, hashlib.sha3_256(V._manifest_canonical(m)).digest()).hex()
        m["_vector"] = {"name": name, "provenance": PROVENANCE,
                        "note": "B's edge to A's key is %s" % ("signed by B itself" if signed else
                                                               "unsigned: legacy, the manifest's word")}
        return m

    files = {"cross-authority-signed-edge-pack.json": pack,
             "cross-authority-signed-edge-manifest-unsigned.json": manifest("cross-authority-signed-edge-manifest-unsigned", False),
             "cross-authority-signed-edge-manifest-signed.json": manifest("cross-authority-signed-edge-manifest-signed", True)}

    def case(name, manifest_file, required, want, note):
        c = {"name": name, "artifact": "cross-authority",
             "pack_file": "conformance/vectors/cross-authority-signed-edge-pack.json",
             "manifest_files": ["conformance/vectors/%s" % manifest_file],
             "trusted_anchors": "manifest", "context_id": 1, "now": NOW,
             "expect": {"decision": want}, "since": SINCE, "note": note}
        if required is not None:
            c["require_signed_attestation"] = required
        return c

    new = [
        case("cross-authority-require-signed-unsigned-edge", "cross-authority-signed-edge-manifest-unsigned.json",
             True, "reject", "The relying party requires signed edges and this one is legacy (wire spec 3.14)."),
        case("cross-authority-require-signed-signed-edge", "cross-authority-signed-edge-manifest-signed.json",
             True, "accept", "The positive control: under the same requirement a signed edge is accepted."),
        case("cross-authority-unsigned-edge-not-required", "cross-authority-signed-edge-manifest-unsigned.json",
             None, "accept", "The same legacy edge with the option off is accepted: the option decides."),
    ]

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
