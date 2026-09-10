#!/usr/bin/env python3
"""polaris-scoped-nullifier-drill.py - one human, once per scope (roadmap P9.3).

Proves the two opposite-facing properties of the scoped nullifier end to end,
against the REAL Plonky2 circuit and the real Poseidon commitments, with no
mocking anywhere:

  ONE PERSON ONCE   A relying party sees the same nullifier when the same member
                    proves a second time in its own scope and epoch, under a
                    fresh nonce and a different proof. It refuses the repeat
                    while learning nothing about who was refused.

  NO CORRELATION    The same member at a SECOND relying party presents a value
                    the first could not have predicted and cannot recognise. Two
                    verifiers pooling their ledgers learn nothing.

The construction that makes both possible is the leaf: since P9.3 the epoch
publishes Poseidon(secret || context_id), a commitment the circuit OPENS, rather
than an opaque SHA3-256 seed. Opening it in-circuit is what binds the nullifier
to the same secret as the leaf. Case 8 is the one that shows why it matters: a
prover holding somebody else's leaf and their own secret is refused, because the
leaf no longer opens.

Bounds honestly stated, and case 9 asserts one of them:
  - The nullifier does NOT hide the holder from the ISSUER, which derives every
    member's secret to build the epoch tree. The property is between RELYING
    PARTIES.
  - It resets each epoch. A relying party's one-person-once rule holds within an
    epoch, not forever, which is what keeps membership from becoming a permanent
    identifier.

Run: python3 scripts/polaris-scoped-nullifier-drill.py
Exit 0 iff every case holds.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "polaris_web"))
sys.path.insert(0, os.path.join(ROOT, "polaris_zk"))

import zk  # noqa: E402
from witness2.commitment import leaf_commitment as witness_leaf  # noqa: E402
from witness2.commitment import links, nullifier as witness_nullifier  # noqa: E402

CONTEXT = 4
EPOCH = 21
# Two relying parties. A scope is any u64 a verifier picks for itself; a
# deployment derives it from its own identifier so that no two verifiers share
# one by accident, which would collapse the no-correlation property between them.
SCOPE_CLINIC = 0x9A17_C11C
SCOPE_LIBRARY = 0x11B2_A2E5


def _row(label, got, want):
    ok = got == want
    print("  %-62s %-10s %-10s %s" % (label[:62], str(got)[:10], str(want)[:10], "OK" if ok else "FAIL"))
    return ok


def main():
    if not os.path.exists(zk._binary_path()):
        print("polaris-zk binary not built; run `cargo build --release` in polaris_zk/", file=sys.stderr)
        return 3

    members = [(tid, "TKN-SN-%03d" % tid) for tid in range(1, 13)]
    secrets = [zk.derive_holder_secret(tid, val, CONTEXT) for tid, val in members]
    leaves = [zk.derive_leaf_commitment(s, CONTEXT) for s in secrets]
    root_hex, _ = zk.compute_epoch_leaves(leaves)
    me = 5  # the member who proves throughout

    print("epoch %d, context %d: %d members, root %s" % (EPOCH, CONTEXT, len(leaves), root_hex[:16]))
    print()
    print("  %-62s %-10s %-10s %s" % ("case", "got", "expected", "ok"))
    ok = True

    # 1. The published leaf is a commitment, not the secret.
    ok &= _row("the published leaf is not the holder's secret", leaves[me] != secrets[me], True)

    # 2. The commitment agrees with the independent Python witness.
    ok &= _row("leaf agrees with the independent second witness",
               leaves[me] == witness_leaf(secrets[me], CONTEXT), True)

    # 3. An honest proof verifies, and carries a nullifier.
    at_clinic = zk.generate_proof(secrets[me], me, leaves, EPOCH, CONTEXT, nonce=1, scope=SCOPE_CLINIC)
    n_clinic = at_clinic["public_inputs"]["nullifier_hex"]
    ok &= _row("an honest proof verifies against the epoch root",
               zk.verify_proof_against_epoch(at_clinic, root_hex, EPOCH, CONTEXT, 1), True)
    ok &= _row("the proof carries a nullifier", bool(n_clinic), True)
    ok &= _row("the nullifier agrees with the independent second witness",
               n_clinic == witness_nullifier(secrets[me], SCOPE_CLINIC, EPOCH), True)

    # 4. ONE PERSON ONCE: a second visit to the same verifier is recognisable.
    again = zk.generate_proof(secrets[me], me, leaves, EPOCH, CONTEXT, nonce=2, scope=SCOPE_CLINIC)
    ok &= _row("a second visit is a DIFFERENT proof",
               again["proof_hex"] != at_clinic["proof_hex"], True)
    ok &= _row("...but the SAME nullifier, so the verifier can refuse it",
               links(again["public_inputs"]["nullifier_hex"], n_clinic), True)

    # 5. NO CORRELATION: the same person at another verifier is unrecognisable.
    at_library = zk.generate_proof(secrets[me], me, leaves, EPOCH, CONTEXT, nonce=1, scope=SCOPE_LIBRARY)
    n_library = at_library["public_inputs"]["nullifier_hex"]
    ok &= _row("the same person at a second verifier verifies there too",
               zk.verify_proof_against_epoch(at_library, root_hex, EPOCH, CONTEXT, 1), True)
    ok &= _row("the two verifiers' nullifiers do not correlate", links(n_clinic, n_library), False)

    # 6. Within one scope, no two members collide.
    seen = set()
    collided = False
    for i, s in enumerate(secrets):
        n = zk.derive_nullifier(s, SCOPE_CLINIC, EPOCH)
        if n in seen:
            collided = True
        seen.add(n)
    ok &= _row("no two members share a nullifier in one scope", collided, False)
    ok &= _row("every member has one", len(seen), len(secrets))

    # 7. A proof cannot be relabelled into another verifier's scope.
    verifier = _load_detached_verifier()
    rescoped = {"proof_hex": at_clinic["proof_hex"],
                "public_inputs": dict(at_clinic["public_inputs"], scope=SCOPE_LIBRARY)}
    v = verifier.verify_zk_against_root(rescoped, root_hex, EPOCH, CONTEXT,
                                        expected_scope=SCOPE_LIBRARY)
    ok &= _row("a proof relabelled into another scope does not verify",
               bool(v["bound"] and v["proof_verified"]), False)

    # 8. THE CONSTRUCTION: a stranger's secret cannot open a member's leaf.
    refused = False
    try:
        zk.generate_proof(secrets[me], me - 1, leaves, EPOCH, CONTEXT, nonce=1, scope=SCOPE_CLINIC)
    except Exception as e:  # noqa: BLE001
        refused = "does not open leaf" in str(e)
    ok &= _row("a member cannot prove against ANOTHER member's leaf", refused, True)

    # 9. The rule resets with the epoch: membership is not a permanent identifier.
    ok &= _row("a new epoch rotates the nullifier",
               links(zk.derive_nullifier(secrets[me], SCOPE_CLINIC, EPOCH),
                     zk.derive_nullifier(secrets[me], SCOPE_CLINIC, EPOCH + 1)), False)

    # 10. The verifier's own ledger: the first proof is fresh, the second is not.
    ledger = set()
    first = verifier.verify_zk_against_root(at_clinic, root_hex, EPOCH, CONTEXT, expected_nonce=1,
                                            expected_scope=SCOPE_CLINIC, seen_nullifiers=ledger)
    ok &= _row("the first proof is accepted and its nullifier is fresh",
               bool(first["bound"] and first["fresh_nullifier"]), True)
    ledger.add(first["nullifier"])
    second = verifier.verify_zk_against_root(again, root_hex, EPOCH, CONTEXT, expected_nonce=2,
                                             expected_scope=SCOPE_CLINIC, seen_nullifiers=ledger)
    ok &= _row("the second proof is REFUSED as a repeat", second["fresh_nullifier"], False)

    # 11. The other verifier's ledger is unaffected: it has never seen this person.
    other_ledger = set(ledger)
    at_other = verifier.verify_zk_against_root(at_library, root_hex, EPOCH, CONTEXT,
                                               expected_nonce=1, expected_scope=SCOPE_LIBRARY,
                                               seen_nullifiers=other_ledger)
    ok &= _row("the second verifier still sees a first visit", at_other["fresh_nullifier"], True)

    # 12. The verdict says nothing about who proved.
    leaked = [k for k, val in first.items()
              if isinstance(val, str) and any(m[1] in val for m in members)]
    ok &= _row("the verdict carries no token value (zero-knowledge)", leaked, [])

    print()
    if ok:
        print("OK: one human, once per scope. A relying party recognises a second proof from the "
              "same person in its own scope and epoch and refuses it, while a second relying party "
              "sees a value it cannot correlate with the first -- because the epoch leaf is a "
              "Poseidon commitment the circuit OPENS, binding the nullifier to the same secret as "
              "the leaf. A member cannot prove against another member's leaf, a proof cannot be "
              "relabelled into another verifier's scope, and the rule resets each epoch so "
              "membership never becomes a permanent identifier.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


def _load_detached_verifier():
    import importlib.util
    spec = importlib.util.spec_from_file_location("polaris_verify_detached",
                                                  os.path.join(HERE, "polaris-verify.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


if __name__ == "__main__":
    sys.exit(main())
