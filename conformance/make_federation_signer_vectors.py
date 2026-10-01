#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the manifest-signer conformance vectors and cases (1.0.0-rc.68).

A federation manifest is trusted when the key that SIGNED it is one the relying party trusts
(WIRE-SPEC section 4: "signed by a trusted anchor"; section 3.1). Until 2026-09-30 all three
verifiers here trusted a manifest when any key it merely LISTED was trusted, so an attacker who
signed a manifest with a root of their own and listed the relying party's anchor beside it was a
trusted authority, and its attestation of the attacker's own credential key was honoured.

The vectors are a fresh attacker chain, generated here:

    the ATTACKER root   signs the manifest, which lists it AND the published anchor of
                        conformance/vectors/cross-authority-manifest.json as active
    the CREDENTIAL key  signs the pack, and the manifest attests it in context 1

    cross-authority-manifest-lists-trusted-anchor   the relying party trusts the published
        anchor only: its private key signed nothing here, so the manifest is not trusted -> reject
    cross-authority-manifest-signer-trusted         the positive control: the relying party trusts
        the attacker's root, which did sign the manifest -> accept, so the refusal above is the
        trust rule's and not a broken vector

The same holds one level down, for a SIGNED trust edge (WIRE-SPEC 3.14: "signed by the agency
that made it"): until 2026-09-30 any key's valid signature on an edge naming the authority's
agency id counted as the authority's, so `require_signed_attestation` was met by a stranger.
A fresh authority root signs two manifests that differ only in who signed their one edge:

    cross-authority-edge-signed-by-a-stranger       a key that is none of the authority's
        anchors signed the edge -> reject, with a signed edge required
    cross-authority-edge-signed-by-its-authority    the positive control: the authority's own
        root signed it -> accept, with a signed edge required

Every expected value is checked against the detached verifier and the Python SDK before
anything is written. Never modifies a published vector: every file here is new.

    python3 conformance/make_federation_signer_vectors.py
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
NOW = "2026-06-01T00:00:00Z"


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

    published = json.loads((OUT / "cross-authority-manifest.json").read_text(encoding="utf-8"))
    trusted = published["public_key_hex"]            # the published anchor: its secret signs nothing here
    root_sk, root = key()
    cred_sk, cred = key()
    tv = "CONFORMANCE-FEDERATION-SIGNER-0001"
    pack = {"format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": "ML-DSA-65",
            "public_key_hex": cred, "signature_hex": cred_sk.sign(hashlib.sha3_256(tv.encode("utf-8")).digest()).hex(),
            "_vector": {"expect": "valid", "name": "federation-signer-pack",
                        "note": "a genuine pack under the attacker's credential key"}}
    edge = dict(published["attestations"][0], attested_public_key_hex=cred, context_id=1)
    manifest = {"format": "polaris-federation-manifest/1",
                "authority": {"agency_id": 990, "name": "Conformance attacker authority"},
                "anchors": [{"public_key_hex": root, "status": "active"},
                            {"public_key_hex": trusted, "status": "active"}],
                "attestations": [edge], "epoch": published.get("epoch"), "revocation": published.get("revocation"),
                "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-12-31T00:00:00Z", "algorithm": "ML-DSA-65"}
    manifest["signature_hex"] = root_sk.sign(hashlib.sha3_256(V._manifest_canonical(manifest)).digest()).hex()
    manifest["public_key_hex"] = root
    manifest["_vector"] = {"expect": "authentic, trusted only by a party that trusts its signer",
                           "name": "federation-signer-manifest",
                           "note": "signed by the attacker's root; lists the published anchor as active too"}

    cases = []
    for name, anchors, decision, why in (
            ("cross-authority-manifest-lists-trusted-anchor", [trusted], "reject",
             "The manifest is signed by the attacker's root and LISTS the published anchor, whose private key "
             "signed nothing here, beside it. WIRE-SPEC section 4: a manifest the relying party trusts is "
             "\"signed by a trusted anchor\". Before this case all three verifiers here trusted a manifest when "
             "any key it listed was trusted, and accepted the attacker's credential."),
            ("cross-authority-manifest-signer-trusted", [root], "accept",
             "The positive control: the same pack and manifest, with the relying party trusting the key that "
             "signed the manifest. The refusal in cross-authority-manifest-lists-trusted-anchor is the trust "
             "rule's, not a broken vector's.")):
        cases.append({"name": name, "artifact": "cross-authority", "pack_file": VEC + "federation-signer-pack.json",
                      "manifest_files": [VEC + "federation-signer-manifest.json"], "trusted_anchors": anchors,
                      "context_id": 1, "now": NOW, "expect": {"decision": decision}, "since": SINCE, "note": why})

    files = {"federation-signer-pack.json": pack, "federation-signer-manifest.json": manifest}
    objects = {VEC + k: v for k, v in files.items()}

    # The signed edge, signed by a stranger and by the authority's own root.
    auth_sk, auth = key()
    stranger_sk, stranger = key()
    k2_sk, k2 = key()
    tv2 = "CONFORMANCE-FEDERATION-EDGE-0001"
    pack2 = {"format": "polaris-authenticity-pack/1", "token_value": tv2, "algorithm": "ML-DSA-65",
             "public_key_hex": k2, "signature_hex": k2_sk.sign(hashlib.sha3_256(tv2.encode("utf-8")).digest()).hex(),
             "_vector": {"expect": "valid", "name": "federation-edge-pack",
                         "note": "a genuine pack under the key the edges attest"}}

    def edge_manifest(edge_sk, edge_pk, who):
        att = {"format": "polaris-trust-attestation/1", "attesting_agency_id": 991, "attested_agency_id": 992,
               "attested_public_key_hex": k2, "context_id": 1, "attested_date": "2026-01-01T00:00:00",
               "valid_until": "2026-12-31", "algorithm": "ML-DSA-65", "public_key_hex": edge_pk}
        att["signature_hex"] = edge_sk.sign(hashlib.sha3_256(V._attestation_canonical(att)).digest()).hex()
        mm = {"format": "polaris-federation-manifest/1", "authority": {"agency_id": 991, "name": "Conformance authority"},
              "anchors": [{"public_key_hex": auth, "status": "active"}], "attestations": [att],
              "epoch": published.get("epoch"), "revocation": published.get("revocation"),
              "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-12-31T00:00:00Z", "algorithm": "ML-DSA-65"}
        mm["signature_hex"] = auth_sk.sign(hashlib.sha3_256(V._manifest_canonical(mm)).digest()).hex()
        mm["public_key_hex"] = auth
        mm["_vector"] = {"expect": "authentic", "name": "federation-edge-manifest-" + who,
                         "note": "signed by the authority's root; its one edge is signed by " + who}
        return mm

    for who, esk, epk, decision, why in (
            ("stranger", stranger_sk, stranger, "reject",
             "A trusted authority's manifest whose one edge carries a valid signature by a key that is none of "
             "the authority's anchors, with a signed edge required. WIRE-SPEC 3.14: an edge is \"signed by the "
             "agency that made it\". Before this case every verifier here counted any key's signature."),
            ("authority", auth_sk, auth, "accept",
             "The positive control: the same edge signed by the authority's own root, with a signed edge "
             "required.")):
        fname = "federation-edge-manifest-%s.json" % who
        files[fname] = edge_manifest(esk, epk, who)
        objects[VEC + fname] = files[fname]
        cases.append({"name": "cross-authority-edge-signed-by-" + ("a-stranger" if who == "stranger" else "its-authority"),
                      "artifact": "cross-authority", "pack_file": VEC + "federation-edge-pack.json",
                      "manifest_files": [VEC + fname], "trusted_anchors": [auth], "context_id": 1, "now": NOW,
                      "require_signed_attestation": True, "expect": {"decision": decision}, "since": SINCE,
                      "note": why})
    files["federation-edge-pack.json"] = pack2
    objects[VEC + "federation-edge-pack.json"] = pack2

    for c in cases:
        cp, cm = objects[c["pack_file"]], [objects[f] for f in c["manifest_files"]]
        req = c.get("require_signed_attestation") is True
        d = V.verify_cross_authority(cp, 1, cm, trusted_anchors=c["trusted_anchors"], now=NOW,
                                     require_signed_attestation=req)["decision"]
        s = P.verify_cross_authority(cp, 1, cm, trusted_anchors=c["trusted_anchors"], now=NOW,
                                     require_signed_attestation=req).decision
        if (d, s) != (c["expect"]["decision"],) * 2:
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
