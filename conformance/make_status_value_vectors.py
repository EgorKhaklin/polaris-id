#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the status-value conformance vectors and cases (1.0.0-rc.69).

An anchor in a federation manifest, an authority in a registry and a holder binding each carry
a signed `status`. A status that is absent means active; `active` means active. Until
2026-10-01 the Python SDK and the detached verifier read the field as `status or "active"`, so
a signed `false` or `""` was active there, while the TypeScript SDK read it as stated and
refused: three verifiers, two answers, on the same signed bytes. Nothing pinned the rule.

These cases pin it at every place a status decides: a manifest's own signer, a registry's
publisher, a holder binding in a chain, the binding behind a grant in use, and the anchor that
signed a trust edge. Each refusal sits beside a control that differs from it in the status
alone. Every expected value is checked against the detached verifier and the Python SDK before
anything is written. Never modifies a published vector: every file here is new.

    python3 conformance/make_status_value_vectors.py
"""
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
SINCE = "1.0.0-rc.69"
VEC = "conformance/vectors/"
NOW = "2026-05-01T00:00:30Z"
STATUSES = (("active", "active"), ("empty", ""), ("false", False))


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
        obj["signature_hex"] = sk.sign(hashlib.sha3_256(canonical(obj)).digest()).hex()
        obj["public_key_hex"] = pk
        return obj

    def load(name):
        return json.loads((OUT / name).read_text(encoding="utf-8"))

    files, cases = {}, []
    why_rule = ("A status that is absent means active; any other value has to BE \"active\". Before this "
                "case the Python SDK and the detached verifier read a signed %s as active and the "
                "TypeScript SDK did not.")

    # --- a federation manifest must be signed by one of its own ACTIVE anchors ----------------
    published = load("cross-authority-manifest.json")
    for label, status in STATUSES:
        root_sk, root = key()
        m = {"format": "polaris-federation-manifest/1",
             "authority": {"agency_id": 993, "name": "Conformance status authority"},
             "anchors": [{"public_key_hex": root, "status": status}], "attestations": [],
             "epoch": published.get("epoch"), "revocation": published.get("revocation"),
             "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-12-31T00:00:00Z", "algorithm": "ML-DSA-65"}
        sign(m, root_sk, root, V._manifest_canonical)
        fname = "status-value-manifest-signer-%s.json" % label
        files[fname] = m
        ok = label == "active"
        cases.append({"name": "manifest-signer-status-" + label, "artifact": "federation-manifest",
                      "object_file": VEC + fname, "now": NOW,
                      "expect": {"authentic": ok, "fresh": True} if ok else {"authentic": False},
                      "since": SINCE,
                      "note": ("The positive control: a manifest signed by its one anchor, listed active."
                               if ok else "The same manifest with its signer's anchor entry signed as %r. "
                               % status + why_rule % repr(status))})

    # --- a registry must be signed by the key it lists, ACTIVE, for its own publisher ---------
    reg_pub = load("registry-valid.json")
    for label, status in STATUSES[:2]:
        sk, pk = key()
        r = copy.deepcopy(reg_pub)
        for k in ("signature_hex", "public_key_hex", "_vector"):
            r.pop(k, None)
        mine = [a for a in r["authorities"] if a.get("agency_id") == r["publisher"]["agency_id"]]
        assert mine, "the published registry lists its publisher"
        mine[0]["public_key_hex"] = pk
        mine[0]["status"] = status
        mine[0].pop("keys", None)
        sign(r, sk, pk, V._registry_canonical)
        fname = "status-value-registry-publisher-%s.json" % label
        files[fname] = r
        ok = label == "active"
        cases.append({"name": "registry-publisher-status-" + label, "artifact": "registry",
                      "object_file": VEC + fname, "now": "2026-05-01T12:00:00Z",
                      "expect": {"authentic": ok, "fresh": True} if ok else {"authentic": False},
                      "since": SINCE,
                      "note": ("The positive control: the published registry re-signed by a fresh "
                               "publisher key it lists as active." if ok else
                               "The same registry with its publisher's entry signed as %r. " % status
                               + why_rule % repr(status))})

    # --- a holder chain, and a grant in use, rest on an ACTIVE holder binding -----------------
    iss_sk, iss_pk = key()
    hol_sk, hol_pk = key()
    _agt_sk, agt_pk = key()
    tv = "CONFORMANCE-STATUS-VALUE-0001"
    cred = {"format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": "ML-DSA-65",
            "public_key_hex": iss_pk,
            "signature_hex": iss_sk.sign(hashlib.sha3_256(tv.encode("utf-8")).digest()).hex()}
    files["status-value-credential.json"] = cred
    nonce = "status-value-nonce-1"
    proof = {"format": "polaris-holder-proof/1", "token_value": tv, "context_id": 1,
             "verifier_nonce": nonce, "issued_at": "2026-05-01T00:00:00Z", "algorithm": "ML-DSA-65"}
    files["status-value-holder-proof.json"] = sign(proof, hol_sk, hol_pk, V._holder_proof_canonical)
    grant = {"format": "polaris-agent-grant/1", "grant_id": "conformance-status-value-grant-0001",
             "agent_public_key_hex": agt_pk, "agent_algorithm": "ML-DSA-65", "actions": ["read:status"],
             "limits": {"max_uses": 3}, "context_id": 1, "issued_at": "2026-05-01T00:00:00Z",
             "expires_at": "2026-05-01T06:00:00Z", "algorithm": "ML-DSA-65"}
    files["status-value-grant.json"] = sign(grant, hol_sk, hol_pk, V._agent_grant_canonical)
    for label, status in STATUSES:
        b = {"format": "polaris-holder-binding/1", "token_value": tv, "holder_public_key_hex": hol_pk,
             "holder_algorithm": "ML-DSA-65", "bound_at": "2026-04-30T00:00:00Z", "status": status,
             "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-05-02T00:00:00Z", "algorithm": "ML-DSA-65"}
        fname = "status-value-binding-%s.json" % label
        files[fname] = sign(b, iss_sk, iss_pk, V._holder_binding_canonical)
        ok = label == "active"
        note = ("The positive control: an active binding inside its window." if ok else
                "The same chain under a binding the issuer signed with status %r. " % status
                + why_rule % repr(status))
        cases.append({"name": "holder-chain-binding-status-" + label, "artifact": "holder-chain",
                      "credential_file": VEC + "status-value-credential.json", "binding_file": VEC + fname,
                      "proof_file": VEC + "status-value-holder-proof.json", "expected_nonce": nonce,
                      "expected_context": 1, "now": NOW, "expect": {"proved": ok}, "since": SINCE,
                      "note": note})
        cases.append({"name": "agent-grant-use-binding-status-" + label, "artifact": "agent-grant-use",
                      "grant_file": VEC + "status-value-grant.json", "binding_file": VEC + fname,
                      "credential_file": VEC + "status-value-credential.json", "now": NOW,
                      "expect": {"authentic": True, "principal_bound": ok}, "since": SINCE,
                      "note": note.replace("chain", "grant")})

    # --- a signed trust edge counts only under an ACTIVE anchor of its authority --------------
    auth_sk, auth = key()
    edge_sk, edge_pk = key()
    k2_sk, k2 = key()
    tv2 = "CONFORMANCE-STATUS-VALUE-EDGE-0001"
    pack2 = {"format": "polaris-authenticity-pack/1", "token_value": tv2, "algorithm": "ML-DSA-65",
             "public_key_hex": k2, "signature_hex": k2_sk.sign(hashlib.sha3_256(tv2.encode("utf-8")).digest()).hex()}
    files["status-value-edge-pack.json"] = pack2
    att = {"format": "polaris-trust-attestation/1", "attesting_agency_id": 994, "attested_agency_id": 995,
           "attested_public_key_hex": k2, "context_id": 1, "attested_date": "2026-01-01T00:00:00",
           "valid_until": "2026-12-31", "algorithm": "ML-DSA-65", "public_key_hex": edge_pk}
    att["signature_hex"] = edge_sk.sign(hashlib.sha3_256(V._attestation_canonical(att)).digest()).hex()
    for label, status in STATUSES[:2]:
        mm = {"format": "polaris-federation-manifest/1", "authority": {"agency_id": 994, "name": "Conformance authority"},
              "anchors": [{"public_key_hex": auth, "status": "active"},
                          {"public_key_hex": edge_pk, "status": status}],
              "attestations": [att], "epoch": published.get("epoch"), "revocation": published.get("revocation"),
              "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-12-31T00:00:00Z", "algorithm": "ML-DSA-65"}
        fname = "status-value-edge-manifest-%s.json" % label
        files[fname] = sign(mm, auth_sk, auth, V._manifest_canonical)
        ok = label == "active"
        cases.append({"name": "cross-authority-edge-anchor-status-" + label, "artifact": "cross-authority",
                      "pack_file": VEC + "status-value-edge-pack.json", "manifest_files": [VEC + fname],
                      "trusted_anchors": [auth], "context_id": 1, "now": NOW,
                      "require_signed_attestation": True, "expect": {"decision": "accept" if ok else "reject"},
                      "since": SINCE,
                      "note": ("The positive control: the edge is signed by an anchor its authority lists "
                               "as active, with a signed edge required." if ok else
                               "The same edge, its signer listed by the authority with status %r, with a "
                               "signed edge required. " % status + why_rule % repr(status))})

    # Every expected value, against the detached verifier and the Python SDK, before writing.
    def obj(path):
        return files[path[len(VEC):]]

    for c in cases:
        e, a = c["expect"], c["artifact"]
        if a in ("federation-manifest", "registry"):
            o = obj(c["object_file"])
            d = (V.verify_manifest(o, now=c["now"]) if a == "federation-manifest"
                 else V.verify_registry(o, now=c["now"]))
            d_auth = d["manifest_authentic"] if a == "federation-manifest" else d["registry_authentic"]
            s_auth = P.verify_signed_artifact(o, now=c["now"]).authentic
            got = (d_auth, s_auth)
            want = (e["authentic"],) * 2
        elif a == "holder-chain":
            s = P.verify_holder(obj(c["credential_file"]), obj(c["binding_file"]), obj(c["proof_file"]),
                                expected_nonce=c["expected_nonce"], expected_context=c["expected_context"],
                                now=c["now"]).proved
            # The detached verifier's contract composition (scripts/test_verify_conformance.py):
            # the binding's status is read where the proof is matched to it.
            bv = V.verify_holder_binding(obj(c["binding_file"]), credential=obj(c["credential_file"]), now=c["now"])
            pv = V.verify_holder_proof(obj(c["proof_file"]), binding=obj(c["binding_file"]),
                                       expected_nonce=c["expected_nonce"], expected_context=c["expected_context"],
                                       now=c["now"])
            d = bool(V.verify_pack(obj(c["credential_file"]))["signature_valid"]
                     and bv["binding_authentic"] and bv["fresh"] is True and bv["bound_to_credential"]
                     and pv["proof_authentic"] and pv["key_matches_binding"] and pv["nonce_matches"] is True
                     and pv["context_matches"] is not False and pv["fresh"] is not False)
            got, want = (d, s), (e["proved"],) * 2
        elif a == "agent-grant-use":
            s = P.grant_principal_bound(obj(c["grant_file"]), obj(c["binding_file"]), obj(c["credential_file"]),
                                        now=c["now"])
            dv = V.verify_agent_grant(obj(c["grant_file"]), binding=obj(c["binding_file"]),
                                      credential=obj(c["credential_file"]), now=c["now"])
            got, want = (dv["principal_bound"] is True, s), (e["principal_bound"],) * 2
        else:
            cp, cm = obj(c["pack_file"]), [obj(f) for f in c["manifest_files"]]
            d = V.verify_cross_authority(cp, 1, cm, trusted_anchors=c["trusted_anchors"], now=c["now"],
                                         require_signed_attestation=True)["decision"]
            s = P.verify_cross_authority(cp, 1, cm, trusted_anchors=c["trusted_anchors"], now=c["now"],
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
