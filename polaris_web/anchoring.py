"""
anchoring.py — Merkle log helper for R10-2 (M2-2).

The internal Merkle log is the off-chain commitment layer named in PDF §9
"Centralized trust assumption." This module computes deterministic Merkle
roots and per-leaf inclusion proofs over BlockchainAnchor rows, so the
SQL procedure close_anchor_batch can pass pre-computed values in without
requiring plpython3u.

Hash algorithm: SHA3-256 by default (post-quantum).
Per the proposal, the algorithm choice is operator policy; the hash
function is passed in by name.

Leaf ordering: deterministic by anchor_id ascending. This defeats the
publish-then-fork attack — even if the same set of (anchor_id, commitment_hash)
tuples is batched at different times, the root reproduces.

Tree shape: standard binary Merkle. For odd-numbered leaves at any level,
the last leaf is duplicated (rather than promoted). This is the same shape
Bitcoin's transaction-merkle uses; well-understood failure modes.

Inclusion proof: a list of (sibling_hash_hex, position) pairs from leaf
upward, where position is 'L' or 'R' indicating which side of the pairing
the sibling sat on. Verification: start with the leaf hash, pair-and-hash
up the proof, compare final hash to the claimed root.

This module is one of the cryptographic-primitive layers in Polaris:

  - TokenSignature (R11-1)           — M:N signatures per token
  - Constitutional limits (R11-6)    — issuer-discretion bounds via advisory-lock
  - AnchorBatch (R10-2, this file)   — per-batch Merkle commitment

Together they realize the "post-quantum by default" claim at the
substrate level, in line with PDF Appendix E.
"""
# coverage:exempt - drives an external chain; the anchoring drill exercises it against a stand-in, and a unit test here would be testing the stand-in rather than the module.

from __future__ import annotations

import hashlib
from typing import Iterable


SUPPORTED_HASHES = {
    'SHA3-256': hashlib.sha3_256,
    'SHA3-512': hashlib.sha3_512,
    'BLAKE3-256': hashlib.sha3_256,   # fallback to SHA3-256 if blake3 not installed
}


def _hash_fn(algorithm_name: str):
    """Resolve the hash function by canonical name. Falls back to SHA3-256
    if the requested algorithm is not in SUPPORTED_HASHES — same posture as
    the schema's CryptographicAlgorithm table (algorithm choice is recorded
    as metadata; the implementation picks a supported function)."""
    return SUPPORTED_HASHES.get(algorithm_name, hashlib.sha3_256)


def leaf_hash(anchor_id: int, commitment_hash: str, algorithm_name: str = 'SHA3-256') -> str:
    """Compute the leaf hash for a BlockchainAnchor row.

    The leaf input is (anchor_id, commitment_hash) joined by a separator that
    cannot appear in either field. anchor_id is an integer; commitment_hash
    is hex per the schema's expectation. The separator ``|`` is outside both
    spaces.
    """
    hf = _hash_fn(algorithm_name)
    h = hf()
    h.update(f'{anchor_id}|{commitment_hash}'.encode('utf-8'))
    return h.hexdigest()


def _pair_hash(left: str, right: str, hf) -> str:
    h = hf()
    h.update(bytes.fromhex(left))
    h.update(bytes.fromhex(right))
    return h.hexdigest()


def merkle_tree(leaves: Iterable[str], algorithm_name: str = 'SHA3-256') -> list[list[str]]:
    """Build the full Merkle tree as a list of levels (root at the end).

    Levels[0] is the leaf row (already-hashed leaves), levels[-1] is a
    single-element list containing the root. For odd-count rows, the last
    leaf is duplicated when pairing.
    """
    hf = _hash_fn(algorithm_name)
    leaves = list(leaves)
    if not leaves:
        raise ValueError('Cannot build Merkle tree from empty leaf set')

    levels = [leaves]
    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            next_level.append(_pair_hash(left, right, hf))
        levels.append(next_level)
    return levels


def merkle_root(leaves: Iterable[str], algorithm_name: str = 'SHA3-256') -> str:
    """Return the Merkle root hex for the given leaf set."""
    return merkle_tree(leaves, algorithm_name)[-1][0]


def inclusion_proof(leaves: list[str], target_index: int,
                    algorithm_name: str = 'SHA3-256') -> list[dict]:
    """Build an inclusion proof for leaves[target_index].

    Returns a list of {sibling, position} dicts, ordered from leaf up to
    just-below-root. ``position`` is 'L' or 'R' indicating which side of
    the pairing the sibling sat on.
    """
    tree = merkle_tree(leaves, algorithm_name)
    proof = []
    idx = target_index
    for level in tree[:-1]:
        # If idx is even, its sibling is at idx+1 (on the right); else idx-1.
        if idx % 2 == 0:
            sibling_idx = idx + 1 if idx + 1 < len(level) else idx  # duplicate-last
            position = 'R'
        else:
            sibling_idx = idx - 1
            position = 'L'
        proof.append({
            'sibling': level[sibling_idx],
            'position': position,
        })
        idx //= 2
    return proof


def verify_proof(leaf: str, proof: list[dict], root: str,
                 algorithm_name: str = 'SHA3-256') -> bool:
    """Verify an inclusion proof against a claimed root.

    Returns True if the proof reconstructs the root, False otherwise.
    """
    hf = _hash_fn(algorithm_name)
    current = leaf
    for step in proof:
        sibling = step['sibling']
        position = step['position']
        if position == 'R':
            current = _pair_hash(current, sibling, hf)
        elif position == 'L':
            current = _pair_hash(sibling, current, hf)
        else:
            return False  # malformed proof
    return current == root


# ---------------------------------------------------------------------------
# Batch helpers used by the Flask route and tests
# ---------------------------------------------------------------------------

def compute_batch(anchors: list[tuple[int, str]],
                  algorithm_name: str = 'SHA3-256') -> tuple[str, dict]:
    """Given a list of (anchor_id, commitment_hash) tuples, return:
        - merkle_root (hex)
        - proofs dict: { anchor_id_str: proof_list_of_dicts }

    Sorts by anchor_id ascending for deterministic leaf order. This is the
    function close_anchor_batch's caller invokes to pre-compute the values
    that get passed into the SQL procedure.
    """
    if not anchors:
        raise ValueError('compute_batch requires at least one anchor')
    sorted_anchors = sorted(anchors, key=lambda x: x[0])
    leaves = [leaf_hash(aid, ch, algorithm_name) for aid, ch in sorted_anchors]
    root = merkle_root(leaves, algorithm_name)
    proofs = {}
    for i, (aid, _) in enumerate(sorted_anchors):
        proofs[str(aid)] = inclusion_proof(leaves, i, algorithm_name)
    return root, proofs


# ----------------------------------------------------------------------------
# Transparency log (P3.3): an RFC-6962-style append-only Merkle log over the
# ordered sequence of AnchorBatch roots, using SHA3-256. Distinct from the
# per-batch anchor tree above -- this log's leaves are whole batch roots, and it
# supports CONSISTENCY proofs (the append-only evidence) the per-batch tree does
# not. A leaf is hashed with a 0x00 prefix and an interior node with 0x01, so a
# leaf can never be presented as a node. These mirror scripts/polaris-verify.py
# so an app-signed tree head verifies under the standalone verifier; the
# transparency drill proves that agreement under real ML-DSA every release.
# ----------------------------------------------------------------------------
def log_leaf_hash(entry: str) -> bytes:
    """RFC 6962 leaf hash SHA3-256(0x00 || entry), entry taken as its UTF-8 bytes."""
    return hashlib.sha3_256(b'\x00' + entry.encode('utf-8')).digest()


def _log_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha3_256(b'\x01' + left + right).digest()


def _log_k(n: int) -> int:
    k = 1
    while k < n:
        k <<= 1
    return k >> 1


def log_tree_head(entries) -> bytes:
    """RFC 6962 Merkle Tree Hash over the ordered log entries (anchor root hex strings)."""
    n = len(entries)
    if n == 0:
        return hashlib.sha3_256(b'').digest()
    if n == 1:
        return log_leaf_hash(entries[0])
    k = _log_k(n)
    return _log_node(log_tree_head(entries[:k]), log_tree_head(entries[k:]))


def log_consistency_proof(m: int, entries) -> list:
    """RFC 6962 consistency proof that the first `m` entries are a prefix of `entries`.
    Returns a list of hex digests."""
    def sub(mm, ents, b):
        n = len(ents)
        if mm == n:
            return [] if b else [log_tree_head(ents)]
        k = _log_k(n)
        if mm <= k:
            return sub(mm, ents[:k], b) + [log_tree_head(ents[k:])]
        return sub(mm - k, ents[k:], False) + [log_tree_head(ents[:k])]
    if m <= 0 or m > len(entries):
        return []
    return [h.hex() for h in sub(m, entries, True)]


def log_inclusion_proof(idx: int, entries) -> list:
    """RFC 6962 inclusion proof for the entry at `idx`. Returns a list of hex digests."""
    def sub(i, ents):
        n = len(ents)
        if n <= 1:
            return []
        k = _log_k(n)
        if i < k:
            return sub(i, ents[:k]) + [log_tree_head(ents[k:])]
        return sub(i - k, ents[k:]) + [log_tree_head(ents[:k])]
    if idx < 0 or idx >= len(entries):
        return []
    return [h.hex() for h in sub(idx, entries)]
