#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the hex-text vectors and cases (1.0.0-rc.70).

A key or a digest is a hex string. JavaScript's String() reads a one-element list as its element,
where Python's str() writes the brackets, so a signed field holding [K] matched K in the TypeScript
SDK and in neither Python verifier: a manifest whose anchor key, a grant whose agent key, a holder
binding whose key, an attestation whose attested key or a feed whose root was such a list verified
in one language only. All three verifiers now read a hex field as hex text (a non-empty string, in
any case) and nothing else.

Each case is a genuine signature over bytes whose hex field is a list; the published valid cases
of each artifact are the controls, and one control here is the same manifest with a string key.
Every expected value is checked against the detached verifier and the Python SDK before anything
is written. Never modifies a published vector: every file here is new.

    python3 conformance/make_hex_text_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.0.0-rc.70"
VEC = "conformance/vectors/"
NOW = "2026-05-01T00:00:30Z"


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

    def sign(obj, sk, pk, canonical):
        obj["public_key_hex"] = pk
        obj["signature_hex"] = sk.sign(hashlib.sha3_256(canonical(obj)).digest()).hex()
        return obj

    files, cases = {}, []

    def case(name, artifact, expect, note, **fields):
        c = {"name": name, "artifact": artifact}
        c.update(fields)
        c.update({"expect": expect, "since": SINCE, "note": note})
        cases.append(c)

    rule = ("A key or a digest is a hex string; JavaScript's String() read the one-element list as its "
            "element, so the TypeScript SDK accepted this and both Python verifiers did not.")
    published = json.loads((OUT / "cross-authority-manifest.json").read_text(encoding="utf-8"))

    # --- a manifest's anchor key -----------------------------------------------------------------
    for label, anchor_key, ok in (("control", None, True), ("a-list", "list", False)):
        sk, pk = key()
        m = {"format": "polaris-federation-manifest/1",
             "authority": {"agency_id": 998, "name": "Conformance hex authority"},
             "anchors": [{"public_key_hex": [pk] if anchor_key == "list" else pk, "status": "active"}],
             "attestations": [], "epoch": published.get("epoch"), "revocation": published.get("revocation"),
             "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-12-31T00:00:00Z", "algorithm": "ML-DSA-65"}
        fname = "hex-text-manifest-anchor-%s.json" % label
        files[fname] = sign(m, sk, pk, V._manifest_canonical)
        case("manifest-anchor-key-" + label, "federation-manifest",
             {"authentic": True, "fresh": True} if ok else {"authentic": False},
             "The positive control: a manifest signed by the one anchor it lists." if ok else
             "A manifest signed by K whose one anchor lists its key as [K]. " + rule,
             object_file=VEC + fname, now=NOW)

    # --- a grant's agent key ----------------------------------------------------------------------
    hol_sk, hol_pk = key()
    agt_sk, agt_pk = key()
    grant = {"format": "polaris-agent-grant/1", "grant_id": "conformance-hex-text-grant", "agent_public_key_hex": [agt_pk],
             "agent_algorithm": "ML-DSA-65", "actions": ["read:status"], "limits": {"max_uses": 3},
             "context_id": 1, "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-05-01T06:00:00Z",
             "algorithm": "ML-DSA-65"}
    files["hex-text-agent-grant-key-a-list.json"] = sign(grant, hol_sk, hol_pk, V._agent_grant_canonical)
    proof = {"format": "polaris-agent-proof/1", "grant_id": "conformance-hex-text-grant", "action": "read:status",
             "service_nonce": "svc-hex-text-1", "issued_at": "2026-05-01T00:00:00Z", "algorithm": "ML-DSA-65"}
    files["hex-text-agent-proof.json"] = sign(proof, agt_sk, agt_pk, V._agent_proof_canonical)
    case("agent-grant-use-agent-key-a-list", "agent-grant-use",
         {"authentic": True, "action_in_scope": True, "agent_proved": False},
         "A grant naming its agent key as [AK], and a proof signed by AK. " + rule,
         grant_file=VEC + "hex-text-agent-grant-key-a-list.json", now=NOW,
         proof_file=VEC + "hex-text-agent-proof.json", requested_action="read:status",
         expected_nonce="svc-hex-text-1")

    # --- a holder binding's key -------------------------------------------------------------------
    iss_sk, iss_pk = key()
    h_sk, h_pk = key()
    tv = "CONFORMANCE-HEX-TEXT-0001"
    files["hex-text-holder-credential.json"] = {
        "format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": "ML-DSA-65", "public_key_hex": iss_pk,
        "signature_hex": iss_sk.sign(hashlib.sha3_256(tv.encode("utf-8")).digest()).hex()}
    b = {"format": "polaris-holder-binding/1", "token_value": tv, "holder_public_key_hex": [h_pk],
         "holder_algorithm": "ML-DSA-65", "bound_at": "2026-04-30T00:00:00Z", "status": "active",
         "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-05-02T00:00:00Z", "algorithm": "ML-DSA-65"}
    files["hex-text-holder-binding-key-a-list.json"] = sign(b, iss_sk, iss_pk, V._holder_binding_canonical)
    pr = {"format": "polaris-holder-proof/1", "token_value": tv, "context_id": 1, "verifier_nonce": "hex-text-nonce-1",
          "issued_at": "2026-05-01T00:00:00Z", "algorithm": "ML-DSA-65"}
    files["hex-text-holder-proof.json"] = sign(pr, h_sk, h_pk, V._holder_proof_canonical)
    case("holder-chain-binding-key-a-list", "holder-chain", {"proved": False},
         "A binding the issuer signed naming the holder key as [HK], and a proof signed by HK. " + rule,
         credential_file=VEC + "hex-text-holder-credential.json",
         binding_file=VEC + "hex-text-holder-binding-key-a-list.json", proof_file=VEC + "hex-text-holder-proof.json",
         expected_nonce="hex-text-nonce-1", expected_context=1, now=NOW)

    # --- an attestation's attested key ------------------------------------------------------------
    auth_sk, auth = key()
    edge_sk, edge_pk = key()
    k2_sk, k2 = key()
    tv2 = "CONFORMANCE-HEX-TEXT-EDGE-0001"
    files["hex-text-edge-pack.json"] = {
        "format": "polaris-authenticity-pack/1", "token_value": tv2, "algorithm": "ML-DSA-65", "public_key_hex": k2,
        "signature_hex": k2_sk.sign(hashlib.sha3_256(tv2.encode("utf-8")).digest()).hex()}
    att = {"format": "polaris-trust-attestation/1", "attesting_agency_id": 998, "attested_agency_id": 999,
           "attested_public_key_hex": [k2], "context_id": 1, "attested_date": "2026-01-01T00:00:00",
           "valid_until": "2026-12-31", "algorithm": "ML-DSA-65"}
    sign(att, edge_sk, edge_pk, V._attestation_canonical)
    mm = {"format": "polaris-federation-manifest/1", "authority": {"agency_id": 998, "name": "Conformance hex authority"},
          "anchors": [{"public_key_hex": auth, "status": "active"}, {"public_key_hex": edge_pk, "status": "active"}],
          "attestations": [att], "epoch": published.get("epoch"), "revocation": published.get("revocation"),
          "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-12-31T00:00:00Z", "algorithm": "ML-DSA-65"}
    files["hex-text-edge-manifest-key-a-list.json"] = sign(mm, auth_sk, auth, V._manifest_canonical)
    case("cross-authority-attested-key-a-list", "cross-authority", {"decision": "reject"},
         "A signed edge naming the attested key as [K], presented by a credential signed by K. " + rule,
         pack_file=VEC + "hex-text-edge-pack.json", manifest_files=[VEC + "hex-text-edge-manifest-key-a-list.json"],
         trusted_anchors=[auth], context_id=1, now=NOW, require_signed_attestation=True)

    # --- a feed's root ----------------------------------------------------------------------------
    feed = json.loads((OUT / "revocation-feed-valid.json").read_text(encoding="utf-8"))
    for k in ("signature_hex", "public_key_hex", "_vector"):
        feed.pop(k, None)
    leaf = feed["revoked_leaves"][0]
    feed.update(revoked_leaves=[leaf], revoked_root_hex=[V.revoked_root([leaf])], revoked_count=1)
    f_sk, f_pk = key()
    files["hex-text-revocation-feed-root-a-list.json"] = sign(feed, f_sk, f_pk, V._revocation_feed_canonical)
    case("revocation-feed-root-a-list", "revocation-feed", {"authentic": False},
         "A feed whose signed revoked_root_hex is [R], R being the root of its one leaf. " + rule,
         object_file=VEC + "hex-text-revocation-feed-root-a-list.json", now="2026-06-01T00:00:00Z")

    # Every expected value, against the detached verifier and the Python SDK, before writing.
    def obj(path):
        return files[path[len(VEC):]]

    for c in cases:
        e, a = c["expect"], c["artifact"]
        if a in ("federation-manifest", "revocation-feed"):
            o = obj(c["object_file"])
            d = (V.verify_manifest(o, now=c["now"])["manifest_authentic"] if a == "federation-manifest"
                 else V.verify_revocation_feed(o, now=c["now"])["feed_authentic"])
            got, want = (bool(d), P.verify_signed_artifact(o, now=c["now"]).authentic), (e["authentic"],) * 2
        elif a == "agent-grant-use":
            g, p = obj(c["grant_file"]), obj(c["proof_file"])
            dv = V.verify_agent_grant(g, now=c["now"], requested_action=c["requested_action"], agent_proof=p,
                                      expected_nonce=c["expected_nonce"])
            s = bool(P.verify_signed_artifact(p, now=c["now"]).authentic
                     and P.agent_proof_proves(p, g, c["requested_action"], c["expected_nonce"]))
            got, want = (dv["agent_proved"] is True, s), (e["agent_proved"],) * 2
        elif a == "holder-chain":
            s = P.verify_holder(obj(c["credential_file"]), obj(c["binding_file"]), obj(c["proof_file"]),
                                expected_nonce=c["expected_nonce"], expected_context=c["expected_context"],
                                now=c["now"]).proved
            bv = V.verify_holder_binding(obj(c["binding_file"]), credential=obj(c["credential_file"]), now=c["now"])
            pv = V.verify_holder_proof(obj(c["proof_file"]), binding=obj(c["binding_file"]),
                                       expected_nonce=c["expected_nonce"], expected_context=c["expected_context"],
                                       now=c["now"])
            d = bool(V.verify_pack(obj(c["credential_file"]))["signature_valid"]
                     and bv["binding_authentic"] and bv["fresh"] is True and bv["bound_to_credential"]
                     and pv["proof_authentic"] and pv["key_matches_binding"] and pv["nonce_matches"] is True
                     and pv["context_matches"] is not False and pv["fresh"] is not False)
            got, want = (d, s), (e["proved"],) * 2
        else:
            cp, cm = obj(c["pack_file"]), [obj(f) for f in c["manifest_files"]]
            d = V.verify_cross_authority(cp, c["context_id"], cm, trusted_anchors=c["trusted_anchors"], now=c["now"],
                                         require_signed_attestation=True)["decision"]
            s = P.verify_cross_authority(cp, c["context_id"], cm, trusted_anchors=c["trusted_anchors"], now=c["now"],
                                         require_signed_attestation=True).decision
            got, want = (d, s), (e["decision"],) * 2
        if got != want:
            print("a verifier disagrees with %s: detached, sdk = %r, expected %r" % (c["name"], got, want),
                  file=sys.stderr)
            return 1

    for name, o in files.items():
        (OUT / name).write_text(json.dumps(o, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    mine = {c["name"] for c in cases}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
