#!/usr/bin/env python3
"""Add the grant-in-use conformance cases (2026-09-27).

The agent-grant cases published at 9.354 ask one question of each object: is its signature
genuine. A service using a grant must ask three more, and until these cases a verifier that
never asked them conformed:

    is the requested action in the grant's signed scope?
    does this revocation END this grant (the holder's key, naming this grant)?
    does this agent proof bind this grant, this action and this service's nonce?

No new vectors: every case reuses the frozen 9.354 files, and the answers each case expects
are first checked against the detached verifier, so a case that ships is one this
implementation already agrees with.

    python3 conformance/make_agent_grant_use_cases.py
"""
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = ROOT / "conformance" / "cases.json"
VEC = "conformance/vectors/"
NOW = "2026-05-01T00:00:30Z"
SINCE = "1.0.0-rc.63"


def main():
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    load = lambda f: json.loads((ROOT / VEC / f).read_text(encoding="utf-8"))

    grant = VEC + "agent-grant-valid.json"
    cases = [
        ("agent-grant-use-widened-grant", {"grant_file": VEC + "agent-grant-widened.json",
                                           "requested_action": "transfer:funds"},
         {"authentic": False, "action_in_scope": None},
         "An action added to the grant after signing. A grant the holder did not sign grants "
         "nothing, so its scope is not read at all: answering from the forged list would "
         "honour the forger's own action."),
        ("agent-grant-use-action-in-scope", {"requested_action": "read:status"},
         {"authentic": True, "action_in_scope": True},
         "The requested action is in the grant's signed scope."),
        ("agent-grant-use-action-out-of-scope", {"requested_action": "transfer:funds"},
         {"authentic": True, "action_in_scope": False},
         "A genuine grant used for an action it does not name. Authenticity is not permission."),
        ("agent-grant-use-revoked-by-holder", {"revocation_file": VEC + "grant-revocation-valid.json"},
         {"authentic": True, "revoked": True},
         "The holder's own revocation of this grant ends it."),
        ("agent-grant-use-revocation-by-impostor", {"revocation_file": VEC + "grant-revocation-impostor.json"},
         {"authentic": True, "revoked": False},
         "A genuinely signed revocation by a key that is not the grant's holder ends nothing; "
         "otherwise anyone able to publish bytes could revoke somebody else's grant."),
        ("agent-grant-use-agent-proved", {"proof_file": VEC + "agent-proof-valid.json",
                                          "requested_action": "read:status", "expected_nonce": "svc-nonce-1"},
         {"authentic": True, "action_in_scope": True, "agent_proved": True},
         "The agent proves it holds the key the grant names, for this action and this nonce."),
        ("agent-grant-use-proof-by-impostor", {"proof_file": VEC + "agent-proof-impostor.json",
                                               "requested_action": "read:status", "expected_nonce": "svc-nonce-1"},
         {"authentic": True, "agent_proved": False},
         "A genuine proof by a key the grant does not name: a copied grant is not a bearer token."),
        ("agent-grant-use-proof-replayed", {"proof_file": VEC + "agent-proof-valid.json",
                                            "requested_action": "read:status", "expected_nonce": "svc-nonce-2"},
         {"authentic": True, "agent_proved": False},
         "The agent's genuine proof, presented to a service that issued a different nonce: a replay."),
    ]
    new = []
    for name, extra, expect, note in cases:
        c = {"name": name, "artifact": "agent-grant-use", "grant_file": grant, "now": NOW}
        c.update(extra)
        gfile = c["grant_file"][len(VEC):]
        c.update({"expect": expect, "since": SINCE, "note": note})
        v = V.verify_agent_grant(
            load(gfile), now=V._parse_iso(NOW),
            requested_action=c.get("requested_action"),
            revocation=load(c["revocation_file"][len(VEC):]) if "revocation_file" in c else None,
            agent_proof=load(c["proof_file"][len(VEC):]) if "proof_file" in c else None,
            expected_nonce=c.get("expected_nonce"))
        got = {"authentic": v["grant_authentic"], "action_in_scope": v["action_in_scope"],
               "revoked": v["revoked"], "agent_proved": v["agent_proved"]}
        wrong = {k: (got[k], e) for k, e in expect.items() if got[k] != e}
        if wrong:
            print("the detached verifier disagrees with %s: %s" % (name, wrong), file=sys.stderr)
            return 1
        new.append(c)
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    # These cases are this generator's own, so a rerun replaces them in place.
    mine = {c["name"] for c in new}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + new
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("%d grant-in-use cases (total %d)" % (len(new), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
