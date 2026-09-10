"""
zk.py — Python wrapper around the polaris_zk Rust binary (R10-1 / M2-1 / v8.23).

The Rust binary lives at `polaris_zk/target/release/polaris-zk` (configurable
via the POLARIS_ZK_BINARY env var). We talk to it via subprocess + JSON over
stdin/stdout. The binary is small; all proof state stays in the pipe.

This is the C3+A4+B3 ship picked in the M2-1 alignment-exploration Sanctum:
  C3 — transparent setup (no ceremony; Plonky2 is FRI-based)
  A4 — Plonky2 SNARK family
  B3 — hybrid-Merkle circuit reusing R10-2 AnchorBatch infrastructure

The schema-level commitment (`TokenStateEpoch.merkle_root`) is the Poseidon
root produced by Plonky2 over the per-token leaf hashes. This is different
from R10-2's SHA3-256 anchoring — two distinct cryptographic commitments
for two distinct primitives. See docs/design/zk-snark.md.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess


def _binary_path() -> str:
    """Locate the polaris-zk Rust binary. POLARIS_ZK_BINARY env var wins;
    otherwise default to ../polaris_zk/target/release/polaris-zk."""
    explicit = os.environ.get("POLARIS_ZK_BINARY")
    if explicit:
        return explicit
    here = pathlib.Path(__file__).resolve().parent
    return str(here.parent / "polaris_zk" / "target" / "release" / "polaris-zk")


def _run_subcommand(subcommand: str, payload: dict) -> dict:
    """Invoke the Rust binary's <subcommand> with <payload> on stdin.
    Returns parsed JSON output. Raises RuntimeError with stderr context on
    non-zero exit."""
    binary = _binary_path()
    if not os.path.isfile(binary):
        raise RuntimeError(
            f"polaris-zk binary not found at {binary}. "
            f"Build with `cargo build --release` in polaris_zk/. "
            f"Or override via POLARIS_ZK_BINARY env var."
        )
    proc = subprocess.run(
        [binary, subcommand],
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"polaris-zk {subcommand} failed (exit={proc.returncode}): "
            f"stderr={proc.stderr.decode('utf-8', errors='replace')[:500]}"
        )
    return json.loads(proc.stdout.decode("utf-8"))


# ---------------------------------------------------------------------------
# Leaf derivation, in two steps since P9.3.
#
#   secret = SHA3-256(token_id || token_value || context_id)   (holder-derivable)
#   leaf   = Poseidon(secret || context_id)                    (published)
#
# Before P9.3 the leaf WAS the SHA3-256 digest, handed to the circuit as an
# opaque private value. That is why the scoped nullifier could not be added: a
# circuit that never opens the leaf cannot constrain a nullifier to the same
# secret, so the nullifier would have proved "I know some number" rather than "I
# am the person behind this leaf". Poseidon is the circuit's native hash, so the
# commitment is cheap to open in-circuit where a SHA3-256 preimage would not be.
#
# The change is NOT backward compatible: an epoch closed before P9.3 holds
# SHA3-256 leaves that the current circuit cannot open, and its proofs do not
# verify against the current verifier. Epochs are re-closed rather than migrated.
#
# The secret stays holder-derivable from the credential the holder holds. The
# ISSUER can derive it too, since it must build the epoch tree; the nullifier's
# unlinkability is between RELYING PARTIES, not against the issuer. Stated in
# full in witness2/commitment.py.
# ---------------------------------------------------------------------------

def derive_holder_secret(token_id: int, token_value: str, context_id: int) -> str:
    """The holder's per-context secret: SHA3-256(token_id || token_value || context_id).

    Derivable by anyone holding the credential, and by the issuer at issuance.
    Never published: the epoch publishes its COMMITMENT, and the holder opens it
    inside the circuit.
    """
    h = hashlib.sha3_256()
    h.update(f"{token_id}|{token_value}|{context_id}".encode("utf-8"))
    return h.hexdigest()


def derive_leaf_commitment(secret_hex: str, context_id: int) -> str:
    """The published epoch leaf: Poseidon(secret || context_id).

    Shells into the Rust binary, which computes it with the same Poseidon the
    circuit uses. `polaris_zk.witness2.commitment.leaf_commitment` is the
    independent Python re-derivation and must agree byte for byte.
    """
    return _run_subcommand("leaf", {"secret_hex": secret_hex,
                                    "context_id": int(context_id)})["leaf_hex"]


def derive_leaf_seed(token_id: int, token_value: str, context_id: int) -> str:
    """The epoch leaf for a member, end to end: commit to the derived secret.

    Kept under its original name because every caller means "the leaf this member
    contributes to the epoch tree", which is still exactly what it returns. What
    changed underneath is that the value is now a Poseidon commitment the circuit
    can open, not a bare SHA3-256 digest.
    """
    return derive_leaf_commitment(derive_holder_secret(token_id, token_value, context_id),
                                  context_id)


def derive_nullifier(secret_hex: str, scope: int, epoch_id: int) -> str:
    """The scoped nullifier: Poseidon(secret || scope || epoch_id).

    A relying party records these to refuse the same person a second time in its
    own scope. Two relying parties with different scopes cannot correlate theirs.
    """
    return _run_subcommand("nullifier", {"secret_hex": secret_hex, "scope": int(scope),
                                         "epoch_id": int(epoch_id)})["nullifier_hex"]


# ---------------------------------------------------------------------------
# Public API. Polaris callers (Flask routes, sample data, tests) use these.
# ---------------------------------------------------------------------------

def compute_epoch_root(leaves_hex: list[str]) -> str:
    """Compute the Poseidon Merkle root for a set of leaf hashes.
    Each leaf must be 64 hex chars (32 bytes). Returns root as hex."""
    result = _run_subcommand("compute-root", {"leaves_hex": leaves_hex})
    return result["epoch_root_hex"]


def compute_epoch_leaves(leaves_hex: list[str]) -> tuple[str, list[dict]]:
    """Compute root + per-leaf inclusion proofs.
    Returns (root_hex, [{index, leaf_hash, proof_path}...]).
    Used by uc11_close_epoch path to populate TokenStateEpochLeaf rows."""
    result = _run_subcommand("compute-leaves", {"leaves_hex": leaves_hex})
    return result["epoch_root_hex"], result["leaves"]


def generate_proof(
    secret_hex: str,
    leaf_index: int,
    all_leaves_hex: list[str],
    epoch_id: int,
    context_id: int,
    nonce: int,
    scope: int = 0,
) -> dict:
    """Generate a ZK-SNARK proof that the prover holds the secret opening
    leaves[leaf_index] in a tree whose root is computed over all_leaves_hex.
    The proof is bound to (epoch_id, context_id, nonce, scope) — see R1, R2, R9
    audit refinements — and carries the scoped nullifier as a public input.

    `scope` is the relying party's domain separator. Left at 0 every member's
    nullifier lands in one global space, which is a real choice a deployment can
    make but not the private one: a per-verifier scope is what keeps two relying
    parties from correlating a person.

    Returns the ProofBundle: {"proof_hex": ..., "public_inputs": {...}}.
    """
    return _run_subcommand(
        "prove",
        {
            "secret_hex": secret_hex,
            "leaf_index": leaf_index,
            "all_leaves_hex": all_leaves_hex,
            "epoch_id": epoch_id,
            "context_id": context_id,
            "nonce": nonce,
            "scope": int(scope),
        },
    )


def verify_proof(proof_bundle: dict) -> bool:
    """Verify a ProofBundle. Returns True if cryptographically valid AND
    the public inputs match the proof's commitment to them."""
    result = _run_subcommand("verify", proof_bundle)
    return bool(result["verified"])


def verify_proof_against_epoch(
    proof_bundle: dict,
    expected_root_hex: str,
    expected_epoch_id: int,
    expected_context_id: int,
    expected_nonce: int,
) -> bool:
    """Verify a proof AND check that the proof's public inputs match the
    epoch we expect. This is the verifier-side entry point for the Flask
    route — it cross-checks the proof's bound (epoch, context, nonce)
    against what the verifier expects, then runs the SNARK verification.

    Returns True only if BOTH the proof verifies AND its public inputs
    match. This is where R1/R2/R9 binding takes effect at the API layer.
    """
    pi = proof_bundle.get("public_inputs", {})
    if pi.get("epoch_root_hex") != expected_root_hex:
        return False
    if int(pi.get("epoch_id", -1)) != int(expected_epoch_id):
        return False
    if int(pi.get("context_id", -1)) != int(expected_context_id):
        return False
    if int(pi.get("nonce", -1)) != int(expected_nonce):
        return False
    return verify_proof(proof_bundle)
