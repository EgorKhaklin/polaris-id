# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""python -m polaris_verify.conformance -- the verifier CLI the conformance suite drives.

Reads ONE conformance case as JSON on stdin and prints a verdict as JSON on stdout. The case
names the artifact it is about; a verifier dispatches on it:

    {"artifact": "authenticity-pack", "pack": {...}, "anchors": ["<hex>", ...]}
        -> {"authentic": bool, "issuer_trusted": bool|null}
    {"artifact": "status-assertion", "assertion": {...}, "now": "<iso8601>"}
        -> {"authentic": bool, "fresh": bool|null, "active": bool|null}
    {"artifact": "<epoch-checkpoint|revocation-feed|federation-manifest|
                  federation-status-bundle|transparency-sth>", "object": {...}, "now": "<iso8601>"}
        -> {"authentic": bool, "fresh": bool|null}
    {"artifact": "timestamp-anchor", "timestamp": {...}, "log_key": "<hex>"|null,
     "trusted_witnesses": ["<hex>", ...]|null, "threshold": int}
        -> {"anchored": bool, "witnessed": bool|null}

For backward compatibility a case with no `artifact` is an authenticity pack. A conformant
verifier in any language implements this same stdin->stdout contract; conformance/run_conformance.py
drives it over the published cases and checks every verdict. See conformance/SPEC.md.
"""
import json
import sys

from . import (agent_proof_proves, verify_exchange_mint, verify_exchange_receipt, verify_exchange_request, grant_covers, grant_principal_bound, pairwise_handle, revocation_ends_grant, verify_attestation, verify_authenticity, verify_cross_authority, verify_holder,
               verify_id_token,
               verify_signed_artifact, verify_status_assertion, verify_timestamp_anchor)

_SIGNED_ARTIFACTS = {"epoch-checkpoint", "revocation-feed", "federation-manifest",
                     "federation-status-bundle", "transparency-sth", "timestamp", "registry", "exchange-request", "signed-document", "id-token", "trust-list", "exchange-receipt", "exchange-mint", "holder-binding", "holder-proof", "epoch-leaves",
                     "agent-grant", "grant-revocation", "agent-proof"}


def main(argv=None):
    try:
        case = json.load(sys.stdin)
    except Exception as e:
        print(json.dumps({"error": "could not read case: %s" % e}))
        return 2
    if not isinstance(case, dict):
        case = {"pack": case}
    artifact = case.get("artifact", "authenticity-pack")
    if artifact == "authenticity-pack":
        pack = case.get("pack") if "pack" in case else case
        v = verify_authenticity(pack or {}, case.get("anchors"))
        print(json.dumps({"authentic": v.authentic, "issuer_trusted": v.issuer_trusted}))
        return 0
    if artifact == "status-assertion":
        v = verify_status_assertion(case.get("assertion") or {}, now=case.get("now"))
        print(json.dumps({"authentic": v.authentic, "fresh": v.fresh, "active": v.active}))
        return 0
    if artifact == "trust-attestation":
        v = verify_attestation(case.get("object") or {},
                               attesting_agency_id=case.get("attesting_agency_id"),
                               expected_key=case.get("expected_key"))
        print(json.dumps({"authentic": v.authentic, "fresh": v.fresh}))
        return 0
    if artifact == "id-token":
        # v9.420: an ID token verified as a generic signed artifact is verified for
        # its SIGNATURE only, and a token minted for one relying party carries a
        # perfectly good signature at another. Audience confusion and nonce replay
        # are the two attacks this artifact exists to stop, so the contract asks
        # about them.
        anchors = case.get("anchors")
        if anchors == "self":
            anchors = [(case.get("object") or {}).get("public_key_hex")]
        v = verify_id_token(case.get("object") or {}, audience=case.get("audience"),
                            nonce=case.get("nonce"), now=case.get("now"), anchors=anchors)
        print(json.dumps({"authentic": v.authentic, "audience_matches": v.audience_matches,
                          "nonce_matches": v.nonce_matches, "fresh": v.fresh,
                          "issuer_trusted": v.issuer_trusted}))
        return 0
    if artifact in _SIGNED_ARTIFACTS:
        anchors = case.get("anchors")
        if anchors == "self":
            anchors = [(case.get("object") or {}).get("public_key_hex")]
        v = verify_signed_artifact(case.get("object") or {}, now=case.get("now"),
                                   anchors=anchors)
        print(json.dumps({"authentic": v.authentic, "fresh": v.fresh,
                          "issuer_trusted": v.issuer_trusted}))
        return 0
    if artifact == "agent-grant-use":
        # 2026-09-27: a grant IN USE. The signed-artifact cases ask only whether each of the
        # three objects is genuine; a service must also ask whether the action is in scope,
        # whether the revocation is the holder's and names this grant, and whether the proof
        # binds this grant, action and nonce. A verifier answering only the first question
        # conformed while honouring anybody's revocation and any copied grant.
        grant = case.get("grant") or {}
        now = case.get("now")
        g = verify_signed_artifact(grant, now=now, anchors=None)
        action = case.get("requested_action")
        # `fresh` is the grant's own window (WIRE-SPEC 2.2): an expired grant grants nothing. The
        # contract asked only whether each object was genuine, so an expired grant with a proof
        # a year old came back in scope and proved (2026-09-30).
        verdict = {"authentic": g.authentic, "fresh": g.fresh, "action_in_scope": None, "revoked": None,
                   "agent_proved": None, "principal_bound": None, "pairwise_handle": None,
                   "correlation": None}
        if not g.authentic:
            # A grant the holder did not sign grants nothing, so no later question is answered:
            # reading the scope of a forged grant would honour the forger's own actions.
            print(json.dumps(verdict))
            return 0
        if action is not None:
            verdict["action_in_scope"] = grant_covers(grant, action)
        binding = case.get("binding")
        if binding is not None:
            verdict["principal_bound"] = grant_principal_bound(grant, binding, case.get("credential") or {}, now)
            if case.get("verifier_scope") is not None:
                # A binding is the holder's to send; one that is not an object has no key,
                # so no handle, as in the TypeScript adapter (it raised AttributeError here).
                key = binding.get("holder_public_key_hex") if isinstance(binding, dict) else None
                verdict["pairwise_handle"] = pairwise_handle(key, case["verifier_scope"])
                verdict["correlation"] = "exposed"
        rev = case.get("revocation")
        if rev is not None:
            verdict["revoked"] = bool(verify_signed_artifact(rev, now=now, anchors=None).authentic
                                      and revocation_ends_grant(rev, grant))
        proof = case.get("agent_proof")
        if proof is not None:
            verdict["agent_proved"] = bool(verify_signed_artifact(proof, now=now, anchors=None).authentic
                                           and agent_proof_proves(proof, grant, action,
                                                                  case.get("expected_nonce")))
        print(json.dumps(verdict))
        return 0
    if artifact == "exchange-use":
        # 1.0.0-rc.64: an exchange artifact IN USE. The signed-artifact cases ask only whether
        # it is genuine; a party holding one must also ask whether it is by the requester or
        # responder expected, whether the requester was attested in its context by an
        # authority trusted at `now`, and whether the bodies it holds are the ones committed.
        obj = case.get("object") or {}
        fmt = obj.get("format") if isinstance(obj, dict) else None
        now = case.get("now")
        if fmt == "polaris-exchange-receipt/1":
            r = verify_exchange_receipt(obj, now=now, trusted_manifests=case.get("manifests"),
                                        responder_key=case.get("responder_key"),
                                        request_body=case.get("request_body"),
                                        response_body=case.get("response_body"))
            print(json.dumps({"authentic": r.authentic, "responder_matches": r.responder_matches,
                              "requester_authorized": r.requester_authorized, "via": r.via,
                              "request_bound": r.request_bound, "response_bound": r.response_bound,
                              "responder": r.responder}))
        elif fmt == "polaris-exchange-mint/1":
            m = verify_exchange_mint(obj, responder_key=case.get("responder_key"))
            print(json.dumps({"authentic": m.authentic, "responder_matches": m.responder_matches}))
        else:
            q = verify_exchange_request(obj, requester_key=case.get("requester_key"),
                                        trusted_manifests=case.get("manifests"),
                                        body=case.get("body"), now=now)
            print(json.dumps({"authentic": q.authentic, "requester_matches": q.requester_matches,
                              "requester_authorized": q.requester_authorized,
                              "body_bound": q.body_bound}))
        return 0
    if artifact == "timestamp-anchor":
        v = verify_timestamp_anchor(case.get("timestamp") or {}, log_key=case.get("log_key"),
                                    trusted_witnesses=case.get("trusted_witnesses"),
                                    threshold=int(case.get("threshold") or 1))
        print(json.dumps({"anchored": v.anchored, "witnessed": v.witnessed}))
        return 0
    if artifact == "holder-chain":
        v = verify_holder(case.get("credential") or {}, case.get("binding") or {}, case.get("proof") or {},
                          expected_nonce=case.get("expected_nonce"), expected_context=case.get("expected_context"),
                          now=case.get("now"))
        print(json.dumps({"proved": v.proved}))
        return 0
    if artifact == "cross-authority":
        v = verify_cross_authority(case.get("pack") or {}, case.get("context_id"),
                                   case.get("manifests") or [], trusted_anchors=case.get("trusted_anchors"),
                                   revocation_feed=case.get("revocation_feed"), now=case.get("now"),
                                   require_signed_attestation=case.get("require_signed_attestation") is True)
        print(json.dumps({"decision": v.decision, "authentic": v.authentic, "issuer_trusted": v.issuer_trusted}))
        return 0
    print(json.dumps({"error": "unknown artifact: %s" % artifact}))
    return 2


if __name__ == "__main__":
    sys.exit(main())
