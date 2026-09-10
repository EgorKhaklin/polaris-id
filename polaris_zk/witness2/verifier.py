"""
witness2.py - the second witness for Polaris's zero-knowledge verdict.

Polaris's ZK trust today rests on a single Rust verifier (polaris_zk verify()).
A verdict only one program can check is a promise, not a proof. This is the
second program: an independent re-derivation, in a different language and number
representation, that must agree with the Rust verifier ACCEPT/REJECT on every
honest and adversarial case. The discipline is Glass's Pentecost pattern, scoped
to what a statement-level witness can honestly model.

WHAT THIS TWO-WITNESSES (and what it does not)
----------------------------------------------
The Rust verify() returns true iff BOTH:
  (1) the Plonky2 proof is cryptographically valid - the prover really knew a
      leaf + path hashing to the committed root, and
  (2) the bundle's public inputs equal the public inputs the proof committed to.

This witness independently re-establishes the FACT behind (1) - that the leaf is
a real member of the tree at the committed root, recomputed with our own
Poseidon/Merkle (merkle.py) - and checks (2) directly. It does NOT parse the
Plonky2 proof bytes; cryptographic soundness of the FRI proof object is outside
its model and it ABSTAINS on proof-byte integrity by construction. That axis is
left to the Rust decoder. See docs/design/zk-soundness.md for the honest ledger.

So: agreement here means a second, independent implementation of the same field,
hash, and Merkle semantics confirms the verifier's verdict on the underlying
claim. It is an additive sanity check, not an audit and not a re-prover of the
proof artifact.
"""

from __future__ import annotations

import json
import sys

from .commitment import leaf_commitment, nullifier as derive_nullifier
from .merkle import build_root, membership_holds

# The public inputs the circuit commits to, in registration order. P9.3 added
# `scope` and `nullifier_hex`: a witness that ignored them would call a re-scoped
# or nullifier-edited bundle ACCEPT while the Rust verifier rejected it, and the
# two witnesses would disagree for a reason that is not about the proof.
_PI_FIELDS = ("epoch_root_hex", "epoch_id", "context_id", "nonce", "scope", "nullifier_hex")


def recompute_root(leaves_hex: list[str]) -> str:
    """Independently recompute the epoch Merkle root. Mirrors the Rust
    compute-root subcommand; must agree bit-for-bit."""
    return build_root(leaves_hex)


def _normalize_pi(pi: dict) -> tuple:
    """Canonicalize a public-inputs dict for exact comparison."""
    return (
        str(pi["epoch_root_hex"]).lower(),
        int(pi["epoch_id"]),
        int(pi["context_id"]),
        int(pi["nonce"]),
        int(pi.get("scope", 0)),
        str(pi.get("nullifier_hex", "")).lower(),
    )


def check_claim(witness: dict, committed: dict, claimed: dict) -> dict:
    """Predict the verifier verdict for a statement-level claim.

    witness   - the inclusion witness the proof attests:
                {"leaf_hash", "leaf_index", "proof_path": [hex x TREE_DEPTH]}
    committed - the public inputs the proof was actually built with (ground
                truth the prover committed to): the four _PI_FIELDS.
    claimed   - the public inputs the verifier is being asked to accept (the
                bundle's public_inputs; may be tampered relative to committed).

    Returns {"verdict": "ACCEPT"|"REJECT", "membership": bool, "binding": bool,
             "opens": bool|None, "nullifier_derived": bool|None, "reasons": [...]}.
    ACCEPT iff the membership fact holds AND the claimed public inputs match the
    committed ones AND, when the witness carries the secret, that secret really
    opens the leaf and really derives the committed nullifier.

    The last two are P9.3's contribution and they are what the circuit added. The
    Rust verifier establishes them by verifying the proof; this witness
    establishes them by RE-DERIVING both values from the secret. A witness that
    only re-checked membership would have gone on agreeing with a Rust verifier
    that had quietly stopped constraining the nullifier to the leaf's secret,
    which is the exact failure the second witness exists to catch.
    """
    reasons: list[str] = []

    membership = membership_holds(
        witness["leaf_hash"],
        int(witness["leaf_index"]),
        list(witness["proof_path"]),
        committed["epoch_root_hex"],
    )
    if not membership:
        reasons.append("leaf does not hash to the committed root (not a member)")

    binding = _normalize_pi(claimed) == _normalize_pi(committed)
    if not binding:
        diffs = [
            f"{f}: claimed={claimed.get(f)!r} != committed={committed.get(f)!r}"
            for f in _PI_FIELDS
            if str(claimed.get(f)).lower() != str(committed.get(f)).lower()
            and claimed.get(f) != committed.get(f)
        ]
        reasons.append("public-input binding broken: " + "; ".join(diffs))

    # P9.3: when the witness carries the secret, re-derive both commitments.
    opens = None
    nullifier_ok = None
    secret_hex = witness.get("secret_hex")
    if secret_hex:
        expected_leaf = leaf_commitment(secret_hex, int(committed["context_id"]))
        opens = expected_leaf == str(witness["leaf_hash"]).lower()
        if not opens:
            reasons.append(
                "the secret does not open the claimed leaf: Poseidon(secret || context_id) is "
                f"{expected_leaf}, the leaf is {str(witness['leaf_hash']).lower()}")
        if "nullifier_hex" in committed:
            expected_nullifier = derive_nullifier(
                secret_hex, int(committed.get("scope", 0)), int(committed["epoch_id"]))
            nullifier_ok = expected_nullifier == str(committed["nullifier_hex"]).lower()
            if not nullifier_ok:
                reasons.append(
                    "the committed nullifier is not the one this secret derives: expected "
                    f"{expected_nullifier}, committed {str(committed['nullifier_hex']).lower()}")

    accept = membership and binding and opens is not False and nullifier_ok is not False
    verdict = "ACCEPT" if accept else "REJECT"
    return {"verdict": verdict, "membership": membership, "binding": binding,
            "opens": opens, "nullifier_derived": nullifier_ok, "reasons": reasons}


# ---------------------------------------------------------------------------
# CLI - mirrors the shape of the Rust binary so the witness can run standalone.
#   python3 -m witness2.verifier recompute-root   < {"leaves_hex":[...]}
#   python3 -m witness2.verifier check-claim       < {"witness":..,"committed":..,"claimed":..}
#   python3 -m witness2.verifier self-test
# ---------------------------------------------------------------------------

def _main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: witness2 <recompute-root|check-claim|self-test>\n")
        return 2
    sub = argv[1]

    if sub == "self-test":
        from .poseidon import self_test
        self_test()
        print("witness2: Poseidon anchored to Plonky2 vectors; OK")
        return 0

    payload = json.loads(sys.stdin.read())
    if sub == "recompute-root":
        print(json.dumps({"epoch_root_hex": recompute_root(payload["leaves_hex"])}))
        return 0
    if sub == "check-claim":
        result = check_claim(payload["witness"], payload["committed"], payload["claimed"])
        print(json.dumps(result))
        return 0
    sys.stderr.write(f"unknown subcommand: {sub}\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
