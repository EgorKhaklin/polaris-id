#!/usr/bin/env python3
"""scenario-2-agent.py -- a holder authorises an AI agent to perform ONE scoped action.

The second required benchmark scenario. Privado's documented product surface has NO DIRECT
EQUIVALENT: its "Agent API" is an issuer-node transport endpoint, and the human-to-agent
delegation material found publicly is research literature rather than that system's feature.
So this scenario is not a comparison. It is a critical evaluation of Polaris's own
delegation, which the directive asks for explicitly: having the feature earns nothing, and
the question is whether it is useful and UNDERSTANDABLE.

The measurement that matters is therefore the trap. A verifier integrates against the
published conformance contract. What does that contract let it get wrong?

Run: python3 lab/benchmark/scenario-2-agent.py
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "sdk" / "python"))

import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "polaris_detached", ROOT / "packages" / "polaris-verify" / "polaris_verify_cli" / "verifier.py")
V = importlib.util.module_from_spec(_spec)
sys.modules["polaris_detached"] = V
_spec.loader.exec_module(V)

from polaris_verify import grant_covers, grant_within_limits, revocation_ends_grant  # noqa: E402

VEC = ROOT / "conformance" / "vectors"


def vec(name):
    return json.loads((VEC / ("%s.json" % name)).read_text())


def main() -> int:
    grant = vec("agent-grant-valid")

    # A backend check FIRST. Without a real ML-DSA implementation every signature reports
    # `None`, meaning "could not run", and the trap below then counts zero artifacts that
    # are authentic-but-unbound because NOTHING is authentic. That zero is a fact about this
    # machine and would read as a fact about the contract. Refuse instead of reporting it.
    probe = V.verify_agent_grant(grant, requested_action=(grant.get("actions") or [None])[0])
    if probe.get("grant_authentic") is not True:
        print("VOID: the published grant does not verify here (grant_authentic=%r). With no "
              "real ML-DSA backend every signature reports 'could not run', and the trap "
              "below would report zero because nothing verified rather than because nothing "
              "is wrong. Install cryptography>=48 or liboqs and re-run."
              % probe.get("grant_authentic"), file=sys.stderr)
        return 2

    print("== the grant, as a verifier receives it ==")
    print("  actions            %s" % grant.get("actions"))
    print("  limits             %s" % grant.get("limits"))
    print("  expires_at         %s" % grant.get("expires_at"))
    print("  agent key          %s..." % str(grant.get("agent_public_key_hex"))[:24])

    print("\n== the full verdict: how many things must a verifier understand? ==")
    verdict = V.verify_agent_grant(grant, requested_action=(grant.get("actions") or [None])[0])
    for k in sorted(verdict):
        if k not in ("witnesses", "note"):
            print("  %-18s %s" % (k, verdict[k]))
    print("  fields a verifier is handed: %d" % len([k for k in verdict if k != "witnesses"]))

    print("\n== scope: the grant covers what it names, and nothing else ==")
    named = (grant.get("actions") or ["?"])[0]
    print("  grant_covers(%-22r) %s" % (named, grant_covers(grant, named)))
    print("  grant_covers(%-22r) %s" % ("transfer.unlimited", grant_covers(grant, "transfer.unlimited")))
    print("  grant_covers on a grant with no actions list: %s"
          % grant_covers({"actions": []}, named))
    ok, note = grant_within_limits(grant, uses_so_far=0)
    print("  grant_within_limits(fresh)          %s %s" % (ok, note or ""))
    ok, note = grant_within_limits(dict(grant, limits={"max_tranfers": 3}), uses_so_far=0)
    print("  a limit key the verifier misreads   %s  %s" % (ok, note))

    print("\n== THE TRAP: what the published contract lets a conformant verifier get wrong ==")
    failures = 0

    # The artifact's OWN verifier, never a hasattr fallback. An earlier version of this
    # harness fell back to {"authentic": None} when a function was missing, which produced a
    # clean zero below from a silent default: the same fabricated null this repository spends
    # its time hunting, written into the instrument measuring for it.
    revocation = vec("grant-revocation-impostor")
    rv = V.verify_grant_revocation(revocation)
    bound = revocation_ends_grant(revocation, grant)
    print("\n  grant-revocation-impostor")
    print("    the contract constrains:  authentic = %s" % rv.get("authentic"))
    print("    revocation_ends_grant:    %s" % bound)
    if rv.get("authentic") and not bound:
        failures += 1
        print("    ^ AUTHENTIC and NOT BOUND. A verifier reading only what the contract")
        print("      constrains would treat this as ending the grant. Anyone may sign bytes")
        print("      naming a grant_id; only the holder who signed the grant may end it.")

    proof = vec("agent-proof-impostor")
    pv = V.verify_agent_proof(proof)
    key_matches = (str(proof.get("public_key_hex") or "").lower()
                   == str(grant.get("agent_public_key_hex") or "").lower())
    print("\n  agent-proof-impostor")
    print("    the contract constrains:  authentic = %s" % pv.get("authentic"))
    print("    proof key == grant's agent key: %s" % key_matches)
    if pv.get("authentic") and not key_matches:
        failures += 1
        print("    ^ AUTHENTIC and BY THE WRONG KEY. A genuine signature proving agency for")
        print("      an agent this grant never named.")

    print("\n== result ==")
    print("  artifacts that are AUTHENTIC and must still be refused: %d" % failures)
    print("  the checks that refuse them (grant_covers, grant_within_limits,")
    print("  revocation_ends_grant) are entered by NO published case, measured by")
    print("  scripts/polaris-contract-reach-drill.py.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
