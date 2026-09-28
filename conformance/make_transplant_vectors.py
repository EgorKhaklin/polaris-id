#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the signature-transplant conformance vectors and cases (1.0.0-rc.64).

An authenticity pack (WIRE-SPEC 3.7) is signed over SHA3-256(token_value). Every other signed
artifact is signed over SHA3-256 of its canonical JSON statement. Until 1.0.0-rc.64 nothing
kept the two apart, so an authority's signature on any artifact it publishes (here, a
federation manifest) could be re-wrapped as a pack whose token_value is the manifest's
canonical statement, and every shipped verifier reported it as an authentic credential from a
trusted issuer. A verifier MUST now refuse a pack whose token_value is not a credential serial.

The vectors are a fresh key set:

    the AUTHORITY   signs a federation manifest (a genuine artifact, published as such),
                    and a credential with a serial token value (the control)

and three cases:

    transplant-manifest-genuine          the manifest verifies: the signature being moved is real
    pack-transplanted-artifact-signature that signature and statement, wrapped as a pack under
                                         the same trusted key: NOT authentic
    pack-transplant-control-valid        a genuine pack by the same key, a serial token value:
                                         authentic and trusted (so the refusal above is the rule's)

Every expected value is checked against the detached verifier before anything is written.
Never modifies a published vector: every file here is new.

    python3 conformance/make_transplant_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.0.0-rc.64"
VEC = "conformance/vectors/"
NOW = "2026-05-01T00:00:30Z"


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
        auth_pk = bytes(s.generate_keypair())
        auth_sk = bytes(s.export_secret_key())

    def sign(digest):
        with oqs.Signature("ML-DSA-65", secret_key=auth_sk) as s:
            return bytes(s.sign(digest))

    manifest = {"format": "polaris-federation-manifest/1",
                "authority": {"agency_id": 21, "name": "Transplant Authority"},
                "anchors": [{"public_key_hex": auth_pk.hex(), "algorithm": "ML-DSA-65", "status": "active"}],
                "attestations": [], "epoch": None, "revocation": None,
                "issued_at": "2026-04-30T00:00:00Z", "expires_at": "2026-05-02T00:00:00Z",
                "algorithm": "ML-DSA-65"}
    statement = V._manifest_canonical(manifest)
    manifest["signature_hex"] = sign(hashlib.sha3_256(statement).digest()).hex()
    manifest["public_key_hex"] = auth_pk.hex()

    transplanted = {
        "_vector": {"expect": "invalid", "name": "pack-transplanted-artifact-signature",
                    "note": "a genuine federation-manifest signature and its canonical statement, re-wrapped as "
                            "a pack; the token_value is not a credential serial, so it MUST NOT verify"},
        "format": "polaris-authenticity-pack/1", "token_value": statement.decode("utf-8"),
        "algorithm": "ML-DSA-65", "signature_hex": manifest["signature_hex"],
        "public_key_hex": auth_pk.hex()}
    serial = "POLARIS-TRANSPLANT-CONTROL-0001"
    control = {
        "_vector": {"expect": "valid", "name": "pack-transplant-control-valid",
                    "note": "a genuine pack by the transplant authority's key, over a credential serial"},
        "format": "polaris-authenticity-pack/1", "token_value": serial, "algorithm": "ML-DSA-65",
        "signature_hex": sign(hashlib.sha3_256(serial.encode("utf-8")).digest()).hex(),
        "public_key_hex": auth_pk.hex()}

    files = {
        "transplant-manifest.json": manifest,
        "pack-transplanted-artifact-signature.json": transplanted,
        "pack-transplant-control-valid.json": control,
    }
    cases = [
        {"name": "transplant-manifest-genuine", "artifact": "federation-manifest",
         "object_file": VEC + "transplant-manifest.json", "now": NOW,
         "expect": {"authentic": True}, "since": SINCE,
         "note": "The artifact whose signature the next case moves: a genuine manifest by the transplant "
                 "authority."},
        {"name": "pack-transplanted-artifact-signature", "artifact": "authenticity-pack",
         "pack_file": VEC + "pack-transplanted-artifact-signature.json", "anchors": "self",
         "expect": {"authentic": False}, "since": SINCE,
         "note": "The manifest's genuine signature and canonical statement, wrapped as a pack, with its key "
                 "trusted. A pack's token_value MUST be a credential serial (WIRE-SPEC 3.7): every other "
                 "artifact signs a JSON statement, which begins with '{'. Before 1.0.0-rc.64 every shipped "
                 "verifier reported this authentic and its issuer trusted."},
        {"name": "pack-transplant-control-valid", "artifact": "authenticity-pack",
         "pack_file": VEC + "pack-transplant-control-valid.json", "anchors": "self",
         "expect": {"authentic": True, "issuer_trusted": True}, "since": SINCE,
         "note": "Control: the same authority's key over a credential serial verifies and is trusted, so the "
                 "refusal above is the serial rule's and not the key's."},
    ]

    # Every expected value, against the detached verifier, before anything is written.
    m = V.verify_manifest(manifest, now=NOW)
    got = {"transplant-manifest-genuine": {"authentic": m["manifest_authentic"]}}
    for name, pack in (("pack-transplanted-artifact-signature", transplanted),
                       ("pack-transplant-control-valid", control)):
        v = V.verify_pack(pack, [auth_pk.hex()])
        got[name] = {"authentic": v["signature_valid"], "issuer_trusted": v["issuer_trusted"]}
    # And the signature being moved really is genuine over the statement, by both witnesses.
    ok, ran, _note = V._two_witness_verify(hashlib.sha3_256(statement).digest(),
                                           bytes.fromhex(manifest["signature_hex"]), auth_pk, "ML-DSA-65")
    if not ok or len(ran) < 2:
        print("the manifest signature did not verify under both witnesses: %s" % ran, file=sys.stderr)
        return 1
    for c in cases:
        wrong = {k: (got[c["name"]].get(k), e) for k, e in c["expect"].items() if got[c["name"]].get(k) != e}
        if wrong:
            print("the detached verifier disagrees with %s: %s" % (c["name"], wrong), file=sys.stderr)
            return 1

    for name, obj in files.items():
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    # These cases are this generator's own, so a rerun replaces them in place.
    mine = {c["name"] for c in cases}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
