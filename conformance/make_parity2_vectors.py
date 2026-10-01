#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the second set of SDK parity vectors and cases (1.0.0-rc.70).

A hostile review of the first parity fix (make_parity_vectors.py) found signed inputs on which
the three verifiers still answered differently, and one the fix itself had opened:

  nonces      a holder proof's verifier_nonce went through str() in Python and String() in
              JavaScript, which spell true "True" and "true" and 1e-05 "1e-05" and "0.00001";
  contexts    Python's == read a context_id of true as context 1, JavaScript's === did not, in
              a holder proof and in a signed trust edge;
  agencies    the same for an attestation's attesting_agency_id;
  wire text   compared bare, a proof that names no nonce matched an expected nonce with no wire
              text (None == None in Python, null === null in JavaScript): the first fix opened
              this, and the published packages refuse it;
  integers    beyond 2**53 Python reads the exact integer and JavaScript the nearest double, so a
              grant id there named two grants in one language and one in the other.

Each refusal sits beside a control. Every expected value is checked against the detached
verifier and the Python SDK before anything is written; the TypeScript SDK is held to the same
cases by the conformance run. Never modifies a published vector: every file here is new.

    python3 conformance/make_parity2_vectors.py
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

    # --- holder chains: the proof's nonce and context, read one way ----------------------------
    iss_sk, iss_pk = key()
    hol_sk, hol_pk = key()
    tv = "CONFORMANCE-PARITY-2-0001"
    files["parity2-holder-credential.json"] = {
        "format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": "ML-DSA-65",
        "public_key_hex": iss_pk, "signature_hex": iss_sk.sign(hashlib.sha3_256(tv.encode("utf-8")).digest()).hex()}
    files["parity2-holder-binding.json"] = sign(
        {"format": "polaris-holder-binding/1", "token_value": tv, "holder_public_key_hex": hol_pk,
         "holder_algorithm": "ML-DSA-65", "bound_at": "2026-04-30T00:00:00Z", "status": "active",
         "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-05-02T00:00:00Z", "algorithm": "ML-DSA-65"},
        iss_sk, iss_pk, V._holder_binding_canonical)
    nonce = "parity-2-nonce-1"
    for label, verifier_nonce, context, expected_nonce, ok, note in (
            ("verifier-nonce-control", nonce, 1, nonce, True,
             "The positive control: a proof naming the relying party's nonce, as text, in context 1."),
            ("verifier-nonce-boolean", True, 1, "true", False,
             "A proof whose signed verifier_nonce is the boolean true, checked against the nonce "
             "\"true\". A nonce is text; true is not. The TypeScript SDK's String() spelled it "
             "\"true\" and proved the chain; Python's str() spelled it \"True\" and did not."),
            ("verifier-nonce-small-number", 0.00001, 1, "0.00001", False,
             "A proof whose signed verifier_nonce is the number 0.00001 (signed as 1e-05), checked "
             "against the nonce \"0.00001\". The TypeScript SDK's String() wrote \"0.00001\" and "
             "proved the chain; Python's str() wrote \"1e-05\" and did not."),
            ("context-boolean", nonce, True, nonce, False,
             "A proof whose signed context_id is the boolean true, checked in context 1. Python's == "
             "read true as 1 and proved the chain; the TypeScript SDK's === did not. A context is an "
             "id, and true is not one.")):
        proof = {"format": "polaris-holder-proof/1", "token_value": tv, "context_id": context,
                 "verifier_nonce": verifier_nonce, "issued_at": "2026-05-01T00:00:00Z", "algorithm": "ML-DSA-65"}
        fname = "parity2-holder-proof-%s.json" % label
        files[fname] = sign(proof, hol_sk, hol_pk, V._holder_proof_canonical)
        case("holder-chain-" + label, "holder-chain", {"proved": ok}, note,
             credential_file=VEC + "parity2-holder-credential.json",
             binding_file=VEC + "parity2-holder-binding.json", proof_file=VEC + fname,
             expected_nonce=expected_nonce, expected_context=1, now=NOW)

    # --- an attestation names its attesting agency by id ---------------------------------------
    for label, attesting, ok, note in (
            ("control", 1, True, "The positive control: an attestation by agency 1, checked for agency 1."),
            ("boolean", True, False,
             "An attestation whose signed attesting_agency_id is the boolean true, checked for agency "
             "1. Python's == read true as 1 and relied on it; the TypeScript SDK's === did not.")):
        a_sk, a_pk = key()
        att = {"format": "polaris-trust-attestation/1", "attesting_agency_id": attesting,
               "attested_agency_id": 2, "attested_public_key_hex": "ab" * 32, "context_id": 1,
               "attested_date": "2026-05-01T00:00:00", "valid_until": "2026-12-31", "algorithm": "ML-DSA-65"}
        fname = "parity2-attestation-attesting-agency-%s.json" % label
        files[fname] = sign(att, a_sk, a_pk, V._attestation_canonical)
        case("trust-attestation-attesting-agency-" + label, "trust-attestation", {"authentic": ok}, note,
             object_file=VEC + fname, attesting_agency_id=1)

    # --- a signed trust edge counts in its own context, an id ----------------------------------
    published = json.loads((OUT / "cross-authority-manifest.json").read_text(encoding="utf-8"))
    auth_sk, auth = key()
    edge_sk, edge_pk = key()
    k2_sk, k2 = key()
    tv2 = "CONFORMANCE-PARITY-2-EDGE-0001"
    files["parity2-edge-pack.json"] = {
        "format": "polaris-authenticity-pack/1", "token_value": tv2, "algorithm": "ML-DSA-65",
        "public_key_hex": k2, "signature_hex": k2_sk.sign(hashlib.sha3_256(tv2.encode("utf-8")).digest()).hex()}
    for label, context, decision, note in (
            ("control", 1, "accept",
             "The positive control: a signed edge in context 1, presented in context 1."),
            ("boolean", True, "reject",
             "The same edge signed with context_id true, presented in context 1. Python's == read "
             "true as 1 and accepted it; the TypeScript SDK's === did not.")):
        att = {"format": "polaris-trust-attestation/1", "attesting_agency_id": 996, "attested_agency_id": 997,
               "attested_public_key_hex": k2, "context_id": context, "attested_date": "2026-01-01T00:00:00",
               "valid_until": "2026-12-31", "algorithm": "ML-DSA-65"}
        sign(att, edge_sk, edge_pk, V._attestation_canonical)
        mm = {"format": "polaris-federation-manifest/1",
              "authority": {"agency_id": 996, "name": "Conformance parity authority"},
              "anchors": [{"public_key_hex": auth, "status": "active"},
                          {"public_key_hex": edge_pk, "status": "active"}],
              "attestations": [att], "epoch": published.get("epoch"), "revocation": published.get("revocation"),
              "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-12-31T00:00:00Z", "algorithm": "ML-DSA-65"}
        fname = "parity2-edge-manifest-context-%s.json" % label
        files[fname] = sign(mm, auth_sk, auth, V._manifest_canonical)
        case("cross-authority-edge-context-" + label, "cross-authority", {"decision": decision}, note,
             pack_file=VEC + "parity2-edge-pack.json", manifest_files=[VEC + fname], trusted_anchors=[auth],
             context_id=1, now=NOW, require_signed_attestation=True)

    # --- an agent proof's nonce and grant id, as wire text on both sides -----------------------
    hol2_sk, hol2_pk = key()
    agt_sk, agt_pk = key()
    grant = {"format": "polaris-agent-grant/1", "grant_id": "conformance-parity-2-grant", "agent_public_key_hex": agt_pk,
             "agent_algorithm": "ML-DSA-65", "actions": ["read:status"], "limits": {"max_uses": 3},
             "context_id": 1, "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-05-01T06:00:00Z",
             "algorithm": "ML-DSA-65"}
    files["parity2-agent-grant.json"] = sign(grant, hol2_sk, hol2_pk, V._agent_grant_canonical)
    big = 2 ** 53 + 1
    big_grant = dict(grant, grant_id=str(big))
    for k in ("signature_hex", "public_key_hex"):
        big_grant.pop(k, None)
    files["parity2-agent-grant-large-id.json"] = sign(big_grant, hol2_sk, hol2_pk, V._agent_grant_canonical)
    svc = "svc-parity-2-1"
    for label, grant_file, proof_fields, expected_nonce, ok, note in (
            ("proof-nonce-control", "parity2-agent-grant.json", {"service_nonce": svc}, svc, True,
             "The positive control: a proof naming the grant and the service's nonce, as text."),
            ("proof-names-no-nonce", "parity2-agent-grant.json", {}, True, False,
             "A proof that names no service nonce, checked against an expected nonce of true, which "
             "has no wire text. Neither side names a nonce, so nothing matches. The first parity "
             "fix compared the two readings bare (None == None, null === null) and proved it in "
             "all three verifiers; the published packages refuse it."),
            ("grant-id-beyond-safe-integer", "parity2-agent-grant-large-id.json",
             {"service_nonce": svc, "grant_id": big}, svc, False,
             "A proof whose signed grant_id is the integer 2**53 + 1, for a grant whose id is that "
             "number written as text. Python read the exact integer and matched it; JavaScript reads "
             "the nearest double, 2**53. An id beyond 2**53 is not one both languages can read.")):
        proof = {"format": "polaris-agent-proof/1", "grant_id": "conformance-parity-2-grant", "action": "read:status",
                 "issued_at": "2026-05-01T00:00:00Z", "algorithm": "ML-DSA-65"}
        proof.update(proof_fields)
        fname = "parity2-agent-proof-%s.json" % label
        files[fname] = sign(proof, agt_sk, agt_pk, V._agent_proof_canonical)
        case("agent-grant-use-" + label, "agent-grant-use",
             {"authentic": True, "action_in_scope": True, "agent_proved": ok}, note,
             grant_file=VEC + grant_file, now=NOW, proof_file=VEC + fname,
             requested_action="read:status", expected_nonce=expected_nonce)

    # --- a grant names itself, and a revocation names a grant, as text ------------------------
    for label, grant_id, ok, note in (
            ("names-itself-control", "conformance-parity-2-grant", True,
             "The positive control: a grant whose grant_id, its revocation handle, is text."),
            ("without-grant-id", None, False,
             "A grant signed with grant_id null. WIRE-SPEC 3.17: grant_id is the revocation handle "
             "and names this grant alone; a grant without one could never be revoked, so it is not a "
             "grant. Every verifier here read it as authentic."),
            ("grant-id-boolean", True, False,
             "A grant signed with grant_id true, which is not text, so it names no grant and no "
             "revocation can name it. Every verifier here read it as authentic.")):
        g = dict(grant, grant_id=grant_id)
        for k in ("signature_hex", "public_key_hex"):
            g.pop(k, None)
        fname = "parity2-agent-grant-%s.json" % label
        files[fname] = sign(g, hol2_sk, hol2_pk, V._agent_grant_canonical)
        case("agent-grant-" + label, "agent-grant", {"authentic": ok}, note, object_file=VEC + fname, now=NOW)
    named = dict(grant, grant_id="True")
    for k in ("signature_hex", "public_key_hex"):
        named.pop(k, None)
    files["parity2-agent-grant-named-true.json"] = sign(named, hol2_sk, hol2_pk, V._agent_grant_canonical)
    for label, rev_id, revoked, note in (
            ("revocation-names-grant-control", "True", True,
             "The positive control: the holder revokes the grant named \"True\", by that text."),
            ("revocation-grant-id-boolean", True, False,
             "A revocation naming the boolean true, for the grant named \"True\". Python's str() "
             "spelled true \"True\" and revoked it; the TypeScript SDK's String() spelled it \"true\" "
             "and did not. true is not text, so it names no grant.")):
        rev = {"format": "polaris-grant-revocation/1", "grant_id": rev_id, "revoked_at": "2026-05-01T00:00:10Z",
               "algorithm": "ML-DSA-65"}
        fname = "parity2-%s.json" % label
        files[fname] = sign(rev, hol2_sk, hol2_pk, V._grant_revocation_canonical)
        case("agent-grant-use-" + label, "agent-grant-use", {"authentic": True, "revoked": revoked}, note,
             grant_file=VEC + "parity2-agent-grant-named-true.json", now=NOW, revocation_file=VEC + fname)

    # --- a grant's actions are text --------------------------------------------------------------
    for label, actions, action, note in (
            ("action-nested-list", [["read:status"]], "read:status",
             "A grant whose signed actions list holds the list [\"read:status\"]. The TypeScript SDK's "
             "String() read it as \"read:status\" and found the action in scope; Python's str() did "
             "not. An action is text, and a list is not."),
            ("action-boolean", [True], "true",
             "A grant whose signed actions list holds the boolean true, asked for the action \"true\". "
             "The TypeScript SDK's String() spelled it \"true\" and found it in scope; Python's str() "
             "spelled it \"True\"."),
            ("action-null", [None], "None",
             "A grant whose signed actions list holds null, asked for the action \"None\". Python's "
             "str() spelled null \"None\" and found it in scope; the TypeScript SDK's String() spelled "
             "it \"null\".")):
        g = dict(grant, actions=actions, grant_id="conformance-parity-2-grant-" + label)
        for k in ("signature_hex", "public_key_hex"):
            g.pop(k, None)
        fname = "parity2-agent-grant-%s.json" % label
        files[fname] = sign(g, hol2_sk, hol2_pk, V._agent_grant_canonical)
        case("agent-grant-use-" + label, "agent-grant-use", {"authentic": True, "action_in_scope": False}, note,
             grant_file=VEC + fname, now=NOW, requested_action=action)

    # --- a principal binding names the credential as text -------------------------------------
    iss3_sk, iss3_pk = key()
    for label, cred_token, bind_token, bound, note in (
            ("principal-token-text-control", "CONFORMANCE-PARITY-2-PRINCIPAL", "CONFORMANCE-PARITY-2-PRINCIPAL", True,
             "The positive control: the issuer binds the grant's signing key to this credential, by "
             "its token value."),
            ("principal-token-boolean-javascript", "true", True, False,
             "A binding the issuer signed with token_value true, beside the credential \"true\". The "
             "TypeScript SDK's String() spelled it \"true\" and bound the grant; Python did not."),
            ("principal-token-boolean-python", "True", True, False,
             "The same binding beside the credential \"True\". Python's str() spelled true \"True\" and "
             "bound the grant; the TypeScript SDK did not. true is not text and names no credential.")):
        cred = {"format": "polaris-authenticity-pack/1", "token_value": cred_token, "algorithm": "ML-DSA-65",
                "public_key_hex": iss3_pk,
                "signature_hex": iss3_sk.sign(hashlib.sha3_256(cred_token.encode("utf-8")).digest()).hex()}
        files["parity2-%s-credential.json" % label] = cred
        b = {"format": "polaris-holder-binding/1", "token_value": bind_token, "holder_public_key_hex": hol2_pk,
             "holder_algorithm": "ML-DSA-65", "bound_at": "2026-04-30T00:00:00Z", "status": "active",
             "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-05-02T00:00:00Z", "algorithm": "ML-DSA-65"}
        files["parity2-%s-binding.json" % label] = sign(b, iss3_sk, iss3_pk, V._holder_binding_canonical)
        case("agent-grant-use-" + label, "agent-grant-use", {"authentic": True, "principal_bound": bound}, note,
             grant_file=VEC + "parity2-agent-grant.json", now=NOW,
             binding_file=VEC + "parity2-%s-binding.json" % label,
             credential_file=VEC + "parity2-%s-credential.json" % label)

    # Every expected value, against the detached verifier and the Python SDK, before writing.
    def obj(path):
        return files[path[len(VEC):]]

    for c in cases:
        e, a = c["expect"], c["artifact"]
        if a == "holder-chain":
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
        elif a == "trust-attestation":
            o = obj(c["object_file"])
            dv = V.verify_attestation(o, attesting_agency_id=c["attesting_agency_id"])
            d = bool(dv["attestation_authentic"]) and dv.get("attester_matches") is not False
            s = P.verify_attestation(o, attesting_agency_id=c["attesting_agency_id"]).authentic
            got, want = (d, s), (e["authentic"],) * 2
        elif a == "cross-authority":
            cp, cm = obj(c["pack_file"]), [obj(f) for f in c["manifest_files"]]
            d = V.verify_cross_authority(cp, c["context_id"], cm, trusted_anchors=c["trusted_anchors"], now=c["now"],
                                         require_signed_attestation=True)["decision"]
            s = P.verify_cross_authority(cp, c["context_id"], cm, trusted_anchors=c["trusted_anchors"], now=c["now"],
                                         require_signed_attestation=True).decision
            got, want = (d, s), (e["decision"],) * 2
        elif a == "agent-grant":
            o = obj(c["object_file"])
            got = (bool(V.verify_agent_grant(o, now=c["now"])["grant_authentic"]),
                   P.verify_signed_artifact(o, now=c["now"]).authentic)
            want = (e["authentic"],) * 2
        elif "revocation_file" in c:
            g, rev = obj(c["grant_file"]), obj(c["revocation_file"])
            dv = V.verify_agent_grant(g, now=c["now"], revocation=rev)
            s = bool(P.verify_signed_artifact(rev, now=c["now"]).authentic and P.revocation_ends_grant(rev, g))
            got, want = (dv["revoked"] is True, s), (e["revoked"],) * 2
        elif "proof_file" not in c and "requested_action" in c:
            g = obj(c["grant_file"])
            dv = V.verify_agent_grant(g, now=c["now"], requested_action=c["requested_action"])
            s = bool(P.verify_signed_artifact(g, now=c["now"]).authentic and P.grant_covers(g, c["requested_action"]))
            got, want = (dv["action_in_scope"] is True, s), (e["action_in_scope"],) * 2
        elif "binding_file" in c:
            g, b, cr = obj(c["grant_file"]), obj(c["binding_file"]), obj(c["credential_file"])
            dv = V.verify_agent_grant(g, binding=b, credential=cr, now=c["now"])
            got = (dv["principal_bound"] is True, P.grant_principal_bound(g, b, cr, now=c["now"]))
            want = (e["principal_bound"],) * 2
        else:
            g, pr = obj(c["grant_file"]), obj(c["proof_file"])
            dv = V.verify_agent_grant(g, now=c["now"], requested_action=c["requested_action"], agent_proof=pr,
                                      expected_nonce=c["expected_nonce"])
            s = bool(P.verify_signed_artifact(pr, now=c["now"]).authentic
                     and P.agent_proof_proves(pr, g, c["requested_action"], c["expected_nonce"]))
            got, want = (dv["agent_proved"] is True, s), (e["agent_proved"],) * 2
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
