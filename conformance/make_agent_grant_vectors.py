#!/usr/bin/env python3
"""Generate the delegated agent-grant conformance vectors (P9.8).

A person authorising an agent should not have to hand over their credential, and an outside
implementation must be able to check the alternative. These vectors carry the three signed
artifacts of that chain, each in a genuine form and in the exact broken form a service has to
catch:

    the GRANT           genuine, and one whose actions were widened after signing
    the REVOCATION      genuine, and one signed by somebody who is not the holder
    the AGENT PROOF     genuine, and one signed by a key the grant does not name

Every vector is verified by the detached verifier before it is written, so a case that ships
is one this implementation already agrees with.

    python3 conformance/make_agent_grant_vectors.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
NOW = datetime(2026, 5, 1, tzinfo=timezone.utc)


def main():
    try:
        import oqs  # type: ignore
    except Exception as e:  # noqa: BLE001
        print("needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)

    def kp():
        with oqs.Signature("ML-DSA-65") as s:
            return bytes(s.generate_keypair()), bytes(s.export_secret_key())

    def sign(sk, d):
        with oqs.Signature("ML-DSA-65", secret_key=sk) as s:
            return bytes(s.sign(d))

    iso = lambda d: d.isoformat().replace("+00:00", "Z")
    hol_pk, hol_sk = kp()      # the human's holder key: it signs the grant and any revocation
    agt_pk, agt_sk = kp()      # the agent's key: it signs each action
    imp_pk, imp_sk = kp()      # somebody who is neither
    GID = "conformance-grant-0001"

    grant = {"format": "polaris-agent-grant/1", "grant_id": GID,
             "agent_public_key_hex": agt_pk.hex(), "agent_algorithm": "ML-DSA-65",
             "actions": ["read:status"], "limits": {"max_uses": 3}, "context_id": 1,
             "issued_at": iso(NOW), "expires_at": iso(NOW + timedelta(hours=6)),
             "algorithm": "ML-DSA-65"}
    grant["signature_hex"] = sign(hol_sk, hashlib.sha3_256(V._agent_grant_canonical(grant)).digest()).hex()
    grant["public_key_hex"] = hol_pk.hex()

    # The attack the grant exists to stop: an action added after signing. The signature no
    # longer covers the statement, so this must not verify.
    widened = dict(grant, actions=["read:status", "transfer:funds"])

    def revocation(sk, pk, gid=GID):
        r = {"format": "polaris-grant-revocation/1", "grant_id": gid,
             "revoked_at": iso(NOW + timedelta(hours=1)), "algorithm": "ML-DSA-65"}
        r["signature_hex"] = sign(sk, hashlib.sha3_256(V._grant_revocation_canonical(r)).digest()).hex()
        r["public_key_hex"] = pk.hex()
        return r

    def proof(sk, pk, action="read:status", nonce="svc-nonce-1"):
        p = {"format": "polaris-agent-proof/1", "grant_id": GID, "action": action,
             "service_nonce": nonce, "issued_at": iso(NOW), "algorithm": "ML-DSA-65"}
        p["signature_hex"] = sign(sk, hashlib.sha3_256(V._agent_proof_canonical(p)).digest()).hex()
        p["public_key_hex"] = pk.hex()
        return p

    rev_holder, rev_impostor = revocation(hol_sk, hol_pk), revocation(imp_sk, imp_pk)
    proof_agent, proof_impostor = proof(agt_sk, agt_pk), proof(imp_sk, imp_pk)

    at = iso(NOW + timedelta(seconds=30))
    now = V._parse_iso(at)

    # Pre-verify every verdict the cases below assert.
    assert V.verify_agent_grant(grant, now=now)["grant_authentic"] is True
    assert V.verify_agent_grant(widened, now=now)["grant_authentic"] is False
    assert V.verify_agent_grant(grant, now=now, requested_action="read:status")["action_in_scope"] is True
    assert V.verify_agent_grant(grant, now=now, requested_action="transfer:funds")["action_in_scope"] is False
    assert V.verify_agent_grant(grant, now=now, revocation=rev_holder)["revoked"] is True
    assert V.verify_agent_grant(grant, now=now, revocation=rev_impostor)["revoked"] is False
    assert V.verify_agent_grant(grant, now=now, agent_proof=proof_agent,
                                requested_action="read:status",
                                expected_nonce="svc-nonce-1")["agent_proved"] is True
    assert V.verify_agent_grant(grant, now=now, agent_proof=proof_impostor,
                                requested_action="read:status",
                                expected_nonce="svc-nonce-1")["agent_proved"] is False

    for name, obj in (("agent-grant-valid.json", grant),
                      ("agent-grant-widened.json", widened),
                      ("grant-revocation-valid.json", rev_holder),
                      ("grant-revocation-impostor.json", rev_impostor),
                      ("agent-proof-valid.json", proof_agent),
                      ("agent-proof-impostor.json", proof_impostor)):
        (OUT / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    doc = json.loads(CASES.read_text(encoding="utf-8"))
    new = [
        {"name": "agent-grant-valid", "artifact": "agent-grant",
         "object_file": "conformance/vectors/agent-grant-valid.json", "now": at,
         "expect": {"authentic": True}, "since": "9.354",
         "note": "P9.8: a holder-signed grant naming its actions, limits and expiry."},
        {"name": "agent-grant-widened", "artifact": "agent-grant",
         "object_file": "conformance/vectors/agent-grant-widened.json", "now": at,
         "expect": {"authentic": False}, "since": "9.354",
         "note": "P9.8: an action was added after signing. actions is inside the signed "
                 "statement precisely so this fails."},
        {"name": "grant-revocation-valid", "artifact": "grant-revocation",
         "object_file": "conformance/vectors/grant-revocation-valid.json", "now": at,
         "expect": {"authentic": True}, "since": "9.354",
         "note": "P9.8: the holder ends the grant with the same key that signed it. The issuer "
                 "is not contacted and the human's credential is untouched."},
        {"name": "grant-revocation-impostor", "artifact": "grant-revocation",
         "object_file": "conformance/vectors/grant-revocation-impostor.json", "now": at,
         "expect": {"authentic": True}, "since": "9.354",
         "note": "P9.8: the SIGNATURE is genuine, but by a key that is not the grant's holder. A "
                 "verifier must check that binding separately: authenticity alone does not end a "
                 "grant, or anyone able to publish bytes could revoke somebody else's."},
        {"name": "agent-proof-valid", "artifact": "agent-proof",
         "object_file": "conformance/vectors/agent-proof-valid.json", "now": at,
         "expect": {"authentic": True}, "since": "9.354",
         "note": "P9.8: the agent's signature over the grant, the action and the service's nonce."},
        {"name": "agent-proof-impostor", "artifact": "agent-proof",
         "object_file": "conformance/vectors/agent-proof-impostor.json", "now": at,
         "expect": {"authentic": True}, "since": "9.354",
         "note": "P9.8: genuinely signed, by a key the grant does not name. Without the "
                 "key-matches-grant check a copied grant would be a bearer token."},
    ]
    names = {c["name"] for c in doc["cases"]}
    doc["cases"].extend(c for c in new if c["name"] not in names)
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote 6 vectors and %d cases (total %d)" % (len(new), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
