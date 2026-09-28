#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the edge-window conformance vectors: a trust edge counts only inside its own window,
signed or not (wire spec section 4).

Until 2026-09-28 the published contract held no case in which an edge's own `valid_until`
decides, so a verifier that never read it conformed. Both SDKs ignored it for a signed edge until
1.0.0-rc.65, and all three verifiers ignored it for an unsigned (legacy) edge until 2026-09-28,
while every published case passed.

One pack and four manifests, each authentic and fresh at the cases' `now` and differing only in
the edge: signed and open, signed and closed, unsigned and open, unsigned and closed. The open
ones are the positive controls: without them a verifier that refuses every edge would pass the
closed ones. An unsigned edge that states NO window stays legacy and is accepted; the existing
`cross-authority-accept` case already publishes exactly that edge.

Each vector is decided by the detached verifier before it is written. Keys are fresh per run.

    python3 conformance/make_edge_window_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"

#: The instant every cross-authority case is decided at; the manifests are fresh at it.
NOW = "2026-06-01T00:00:00Z"
SINCE = "1.0.0-rc.66"


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

    issuer_pk, issuer_sk = keypair()      # authority A, which issued the credential
    authority_pk, authority_sk = keypair()  # authority B, which attests A's key and publishes

    token = "TKN-XA-EDGE-WINDOW-1"
    pack = {"format": "polaris-authenticity-pack/1", "algorithm": "ML-DSA-65", "token_value": token,
            "public_key_hex": issuer_pk.hex(),
            "signature_hex": sign(issuer_sk, hashlib.sha3_256(token.encode("utf-8")).digest()).hex(),
            "_vector": {"name": "cross-authority-edge-window-pack",
                        "note": "A's authenticity pack; every edge-window manifest attests A's key",
                        "provenance": "real ML-DSA-65 (liboqs); conformance/make_edge_window_vectors.py"}}

    def edge(valid_until, signed):
        att = {"attesting_agency_id": 2, "attested_agency_id": 1,
               "attested_public_key_hex": issuer_pk.hex(), "context_id": 1,
               "attested_date": "2026-01-01T00:00:00", "valid_until": valid_until}
        if signed:
            att.update(format="polaris-trust-attestation/1", algorithm="ML-DSA-65",
                       public_key_hex=authority_pk.hex())
            att["signature_hex"] = sign(authority_sk, hashlib.sha3_256(
                V._attestation_canonical(att)).digest()).hex()
        return att

    def manifest(name, att, note):
        m = {"format": "polaris-federation-manifest/1", "algorithm": "ML-DSA-65",
             "authority": {"agency_id": 2, "name": "Authority B"},
             "anchors": [{"public_key_hex": authority_pk.hex(), "algorithm": "ML-DSA-65",
                          "status": "active"}],
             "attestations": [att], "epoch": {"number": 1, "root_hex": "bb" * 32},
             "revocation": {"as_of": "2026-05-31T00:00:00Z"},
             "issued_at": "2026-05-31T00:00:00Z", "expires_at": "2026-06-30T00:00:00Z",
             "public_key_hex": authority_pk.hex()}
        m["signature_hex"] = sign(authority_sk, hashlib.sha3_256(V._manifest_canonical(m)).digest()).hex()
        m["_vector"] = {"name": name, "note": note,
                        "provenance": "real ML-DSA-65 (liboqs); conformance/make_edge_window_vectors.py"}
        return m

    variants = (
        ("signed-open", True, "2026-12-31", "accept",
         "the edge is signed and its own window is open at now: the positive control"),
        ("signed-closed", True, "2026-05-01", "reject",
         "the edge is signed and its own window closed a month before now; the manifest is fresh"),
        ("unsigned-open", False, "2026-12-31", "accept",
         "a legacy edge states a window that is open at now: the positive control"),
        ("unsigned-closed", False, "2026-05-01", "reject",
         "a legacy edge states a window that closed before now: the manifest's authority signed "
         "that window, and a fresh manifest does not extend an edge its authority has ended"),
    )
    written = {"cross-authority-edge-window-pack.json": pack}
    new = []
    for label, signed, until, want, note in variants:
        name = "cross-authority-edge-window-%s" % label
        m = manifest(name, edge(until, signed), note)
        got = V.verify_cross_authority(pack, 1, [m], now=NOW, trusted_anchors=[authority_pk.hex()])
        assert got["decision"] == want, (name, got)
        written[name + ".json"] = m
        new.append({"name": name, "artifact": "cross-authority",
                    "pack_file": "conformance/vectors/cross-authority-edge-window-pack.json",
                    "manifest_files": ["conformance/vectors/%s.json" % name],
                    "trusted_anchors": "manifest", "context_id": 1, "now": NOW,
                    "expect": {"decision": want}, "since": SINCE,
                    "note": "Wire spec section 4: %s." % note})

    for fname, obj in written.items():
        (OUT / fname).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    names = {c["name"] for c in doc["cases"]}
    doc["cases"].extend(c for c in new if c["name"] not in names)
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors, %d cases (total %d)" % (len(written), len(new), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
