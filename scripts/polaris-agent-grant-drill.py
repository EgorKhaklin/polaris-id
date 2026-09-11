#!/usr/bin/env python3
"""polaris-agent-grant-drill.py - a person delegates to an agent without handing over their
credential (roadmap P9.8).

Under real ML-DSA-65, no mocking. The whole chain is five signatures deep:

    issuer -> credential
    issuer -> holder-key binding
    holder key -> the GRANT            (actions, limits, expiry, a revocation handle)
    holder key -> a REVOCATION         (optional, and the issuer never hears about it)
    agent key -> a PROOF of the action (against the service's own nonce)

The point is what a grant is NOT. Handing an agent your credential gives it everything you
can do, forever, with no way to take it back short of revoking yourself. A grant names the
actions, states the limits, expires on its own, and can be ended by the holder alone.

Three properties this drill exists to hold:

  BOUNDED       An action outside the named list is refused, and a limit the service does
                not understand is refused rather than ignored (case 6). A grant that
                silently widened would be the hand-over it replaces.

  REVOCABLE     The holder ends the grant with their own key. The credential stays ACTIVE
                and usable throughout, and the ISSUER is never contacted (cases 9-11). A
                person can end their agent's authority without asking permission from, or
                being seen by, the authority that issued their identity.

  NOT A BEARER  A copied grant is useless without the agent's key. Case 12 steals the grant
  TOKEN         and fails; case 13 replays a genuine proof at a second service and fails.

And the bound, asserted rather than glossed (case 14): under a plain binding the service
still sees the credential's token value, so the verdict says `correlation: "exposed"`. A
grant hides the human from the agent's ACTIONS, not the credential from the service.

Run: python3 scripts/polaris-agent-grant-drill.py
Exit 0 iff every case holds.
"""
import hashlib
import importlib.util
import os
import sys
from datetime import datetime, timedelta, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_ROOT, "scripts", rel))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


#: Cases this drill actually recorded. A drill whose cases are removed or
#: short-circuited in a refactor prints its whole summary and exits 0 anyway,
#: which is a guarantee reported by something that tested nothing (v9.403).
_cases_recorded = 0


def _row(label, got, want):
    global _cases_recorded
    _cases_recorded += 1
    ok = got == want
    print("  %-66s %-8s %-8s %s" % (label[:66], str(got)[:8], str(want)[:8], "OK" if ok else "FAIL"))
    return ok


def main():
    try:
        import oqs  # type: ignore
    except Exception as e:  # noqa: BLE001
        print("agent-grant drill needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    V = _load("polaris_verify", "polaris-verify.py")

    def kp():
        with oqs.Signature("ML-DSA-65") as s:
            return bytes(s.generate_keypair()), bytes(s.export_secret_key())

    def sign(sk, d):
        with oqs.Signature("ML-DSA-65", secret_key=sk) as s:
            return bytes(s.sign(d))

    iso = lambda d: d.isoformat().replace("+00:00", "Z")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    iss_pk, iss_sk = kp()      # the issuing authority
    hol_pk, hol_sk = kp()      # the human's holder key
    agt_pk, agt_sk = kp()      # the agent's own key
    imp_pk, imp_sk = kp()      # an impostor: a thief, or a second agent
    tv = "DRILL-AGENT-GRANT-0001"
    SERVICE = "rp_service_000000000000001"

    cred = {"format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": "ML-DSA-65",
            "public_key_hex": iss_pk.hex(),
            "signature_hex": sign(iss_sk, hashlib.sha3_256(tv.encode("utf-8")).digest()).hex()}
    binding = {"format": "polaris-holder-binding/1", "token_value": tv,
               "holder_public_key_hex": hol_pk.hex(), "holder_algorithm": "ML-DSA-65",
               "bound_at": iso(now - timedelta(days=1)), "status": "active",
               "issued_at": iso(now), "expires_at": iso(now + timedelta(hours=24)),
               "algorithm": "ML-DSA-65"}
    binding["signature_hex"] = sign(iss_sk, hashlib.sha3_256(
        V._holder_binding_canonical(binding)).digest()).hex()
    binding["public_key_hex"] = iss_pk.hex()

    def grant(sk=hol_sk, pk=hol_pk, gid="grant-0001", actions=("read:status", "present:age-over-18"),
              limits=None, hours=6):
        g = {"format": "polaris-agent-grant/1", "grant_id": gid,
             "agent_public_key_hex": agt_pk.hex(), "agent_algorithm": "ML-DSA-65",
             "actions": list(actions), "limits": dict(limits or {"max_uses": 3}),
             "context_id": 1, "issued_at": iso(now - timedelta(minutes=1)),
             "expires_at": iso(now + timedelta(hours=hours)), "algorithm": "ML-DSA-65"}
        g["signature_hex"] = sign(sk, hashlib.sha3_256(V._agent_grant_canonical(g)).digest()).hex()
        g["public_key_hex"] = pk.hex()
        return g

    def revocation(gid="grant-0001", sk=hol_sk, pk=hol_pk):
        r = {"format": "polaris-grant-revocation/1", "grant_id": gid,
             "revoked_at": iso(now), "algorithm": "ML-DSA-65"}
        r["signature_hex"] = sign(sk, hashlib.sha3_256(V._grant_revocation_canonical(r)).digest()).hex()
        r["public_key_hex"] = pk.hex()
        return r

    def agent_proof(gid="grant-0001", action="read:status", nonce="svc-nonce-1",
                    sk=agt_sk, pk=agt_pk):
        pr = {"format": "polaris-agent-proof/1", "grant_id": gid, "action": action,
              "service_nonce": nonce, "issued_at": iso(now), "algorithm": "ML-DSA-65"}
        pr["signature_hex"] = sign(sk, hashlib.sha3_256(V._agent_proof_canonical(pr)).digest()).hex()
        pr["public_key_hex"] = pk.hex()
        return pr

    good = grant()
    common = dict(binding=binding, credential=cred, anchor_keys=[iss_pk.hex()])

    print("a human delegates to an agent, under real ML-DSA-65")
    print()
    print("  %-66s %-8s %-8s %s" % ("case", "got", "expect", "ok"))
    ok = True

    # 1-3. The happy path, and the chain reported link by link.
    v = V.verify_agent_grant(good, requested_action="read:status",
                             agent_proof=agent_proof(), expected_nonce="svc-nonce-1", **common)
    ok &= _row("a genuine grant, in scope, with the agent's proof: USABLE", v["usable"], True)
    ok &= _row("...the grant chains to an issuer-bound holder key", v["principal_bound"], True)
    ok &= _row("...and the agent proved it holds the key the grant names", v["agent_proved"], True)

    # 4-6. BOUNDED.
    v = V.verify_agent_grant(good, requested_action="transfer:funds",
                             agent_proof=agent_proof(action="transfer:funds"),
                             expected_nonce="svc-nonce-1", **common)
    ok &= _row("an action outside the grant's list is REFUSED", v["usable"], False)
    ok &= _row("...and the verdict says which action and which scope",
               "not in the grant's scope" in (v["note"] or ""), True)
    ok &= _row("a limit the service does not understand is refused, not ignored",
               V.grant_within_limits({"limits": {"max_transfers": 3}})[0], False)

    # 7-8. Expiry is the grant's own, and it does not touch the credential.
    v = V.verify_agent_grant(grant(hours=-1), requested_action="read:status", **common)
    ok &= _row("an expired grant is refused", v["usable"], False)
    ok &= _row("...while the credential itself is still authentic",
               V.verify_pack(cred, [iss_pk.hex()])["signature_valid"], True)

    # 9-11. REVOCABLE, by the holder, without the issuer.
    v = V.verify_agent_grant(good, requested_action="read:status", revocation=revocation(),
                             agent_proof=agent_proof(), expected_nonce="svc-nonce-1", **common)
    ok &= _row("the holder revokes the grant: REFUSED", v["usable"], False)
    ok &= _row("...and the verdict names it a revocation, not a broken signature",
               v["revoked"], True)
    ok &= _row("...while the human's credential is untouched and still authentic",
               V.verify_pack(cred, [iss_pk.hex()])["signature_valid"], True)
    v = V.verify_agent_grant(good, requested_action="read:status",
                             revocation=revocation(sk=imp_sk, pk=imp_pk), **common)
    ok &= _row("a stranger cannot revoke someone else's grant", v["revoked"], False)
    v = V.verify_agent_grant(good, requested_action="read:status",
                             revocation=revocation(gid="grant-9999"), **common)
    ok &= _row("a revocation naming another grant does not end this one", v["revoked"], False)

    # 12-13. NOT A BEARER TOKEN.
    v = V.verify_agent_grant(good, requested_action="read:status",
                             agent_proof=agent_proof(sk=imp_sk, pk=imp_pk),
                             expected_nonce="svc-nonce-1", **common)
    ok &= _row("a stolen grant is useless without the agent's key", v["usable"], False)
    v = V.verify_agent_grant(good, requested_action="read:status", agent_proof=agent_proof(),
                             expected_nonce="svc-nonce-2", **common)
    ok &= _row("a proof captured at one service does not replay at another", v["usable"], False)
    v = V.verify_agent_grant(good, requested_action="read:status",
                             agent_proof=agent_proof(action="present:age-over-18"),
                             expected_nonce="svc-nonce-1", **common)
    ok &= _row("a proof for one action does not authorise another", v["usable"], False)

    # 14. A grant signed by a key no issuer bound speaks for nobody.
    v = V.verify_agent_grant(grant(sk=imp_sk, pk=imp_pk), requested_action="read:status", **common)
    ok &= _row("a grant signed by an unbound key is refused", v["principal_bound"], False)

    # 15. An empty action list grants nothing, rather than everything.
    v = V.verify_agent_grant(grant(actions=()), requested_action="read:status", **common)
    ok &= _row("a grant naming no actions grants NOTHING", v["action_in_scope"], False)

    # 16. The limits are inside the signed statement, so editing them breaks the signature.
    widened = dict(good, limits={"max_uses": 9999})
    ok &= _row("editing the limits after signing breaks the grant",
               V.verify_agent_grant(widened, requested_action="read:status", **common)["grant_authentic"],
               False)
    widened_actions = dict(good, actions=["read:status", "transfer:funds"])
    ok &= _row("...and so does adding an action after signing",
               V.verify_agent_grant(widened_actions, requested_action="transfer:funds",
                                    **common)["grant_authentic"], False)

    # 17. THE BOUND, ASSERTED.
    v = V.verify_agent_grant(good, requested_action="read:status", agent_proof=agent_proof(),
                             expected_nonce="svc-nonce-1", verifier_scope=SERVICE, **common)
    ok &= _row("the service is given a per-service handle to key its records by",
               v["pairwise_handle"] == V.pairwise_handle(hol_pk.hex(), SERVICE), True)
    ok &= _row("...and the verdict calls the correlation EXPOSED, not unlinkable",
               v["correlation"], "exposed")

    # 18. The revocation says nothing about WHY, so it cannot be read for duress.
    ok &= _row("a revocation's signed statement carries no reason field",
               sorted(__import__("json").loads(
                   V._grant_revocation_canonical(revocation()).decode())),
               ["algorithm", "format", "grant_id", "revoked_at"])

    # 19. Totality: a service is fed hostile bytes and must return a verdict.
    ok &= _row("hostile input returns a verdict, never an exception",
               all(isinstance(V.verify_agent_grant(x), dict)
                   for x in (None, 0, "", [], {}, {"format": None}, {"format": "x", "actions": 7})),
               True)

    print()
    if ok:
        if not _cases_recorded:
            print("FAIL: this drill recorded NO cases. It tested nothing and would "
                  "have printed its summary regardless.", file=sys.stderr)
            return 1
        print("OK: a person delegates to an agent without handing over their credential. The grant "
              "names its actions, states its limits inside the signed statement so widening it "
              "breaks the signature, expires on its own, and is ended by the holder's own key "
              "without the issuer being contacted or the human's credential being touched. It is "
              "not a bearer token: a stolen grant fails without the agent's key, and a genuine "
              "proof does not replay to a second service or to a second action. The bound is "
              "stated: under a plain binding the service still sees the credential, so the verdict "
              "reports the correlation as exposed rather than claiming the agent acts unseen.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
