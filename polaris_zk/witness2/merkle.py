"""
merkle.py - the Plonky2 Merkle-tree semantics Polaris's circuit proves, re-done
independently in Python.

What the Polaris circuit proves (polaris_zk/src/lib.rs):
  "I know a leaf L at index i, and a sibling path P, such that hashing L up the
   tree along P produces the public root R."

This module recomputes R two ways:
  - build_root(leaves)          - the full tree, matching `compute-root`
  - root_from_path(leaf, path)  - the inclusion check, matching the in-circuit
                                  verify_merkle_proof_to_cap gadget

Both must agree, bit-for-bit, with the Rust crate. The hashing primitive is the
independent Poseidon in poseidon.py. Encoding conventions are copied from the
Rust crate's hex_to_hash_elements / hash_elements_to_hex so the byte layout
lines up exactly (little-endian, 8 bytes per Goldilocks lane, 4 lanes = 32 bytes
= 64 hex chars).
"""

from __future__ import annotations

import os

from .poseidon import HASH_OUT_ELEMENTS, hash_or_noop, two_to_one
from .poseidon_constants import P

# Must match polaris_zk/src/lib.rs tree_depth(). Both read POLARIS_ZK_TREE_DEPTH
# (default 14: 16,384 leaves, covering the schema's 10,000-leaf epoch cap), so
# the second witness and the Rust prover stay on the same circuit shape when a
# deployment reprofiles the tree (P0.7). The differential test fails loudly if
# the two ever diverge; check_zk_tree_depth_synced pins the two defaults.
DEFAULT_TREE_DEPTH = 14


def _tree_depth() -> int:
    raw = os.environ.get("POLARIS_ZK_TREE_DEPTH")
    if raw is None:
        return DEFAULT_TREE_DEPTH
    d = int(raw)
    if not (4 <= d <= 32):
        raise ValueError(f"POLARIS_ZK_TREE_DEPTH must be in 4..=32, got {d}")
    return d


TREE_DEPTH = _tree_depth()
ZERO_LEAF_HEX = "0" * 64


def hex_to_elements(hex_str: str) -> list[int]:
    """Decode 64 hex chars (32 bytes) into 4 Goldilocks lanes.

    Matches lib.rs hex_to_hash_elements: little-endian u64 per 8 bytes, then
    reduced mod P (Rust uses from_noncanonical_u64, i.e. reduce, not panic)."""
    raw = bytes.fromhex(hex_str)
    if len(raw) != 32:
        raise ValueError(f"hash must be 32 bytes / 64 hex chars, got {len(raw)} bytes")
    return [
        int.from_bytes(raw[i * 8 : (i + 1) * 8], "little") % P
        for i in range(HASH_OUT_ELEMENTS)
    ]


def elements_to_hex(elements: list[int]) -> str:
    """Encode 4 Goldilocks lanes into 64 hex chars.

    Matches lib.rs hash_elements_to_hex: canonical u64 per lane, little-endian."""
    if len(elements) != HASH_OUT_ELEMENTS:
        raise ValueError("expected 4 elements")
    out = bytearray()
    for e in elements:
        out += (e % P).to_bytes(8, "little")
    return out.hex()


def _check_population(leaves_hex: list[str]) -> int:
    """Validate a leaf set against the tree's capacity; return the capacity."""
    cap = 1 << TREE_DEPTH
    if not leaves_hex:
        raise ValueError("cannot build a Merkle tree from an empty leaf set")
    if len(leaves_hex) > cap:
        raise ValueError(f"too many leaves ({len(leaves_hex)}); depth {TREE_DEPTH} caps at {cap}")
    return cap


def zero_hashes(depth: int = None) -> list[list[int]]:
    """`z[k]` is the digest of an all-zero subtree of height k.

    The padding is one repeated value, so every subtree above the real leaves is an all-zero
    subtree and has exactly one hash per level. Precomputing them is what lets this witness
    reach production depth at all: at depth 24 the padded form is 16.7 million entries of
    pure-Python Poseidon, which is not a computation anyone waits for. Mirrors lib.rs's
    `zero_hashes`, and `test_zero_hashes_match_the_rust_witness` pins the pair.
    """
    d = TREE_DEPTH if depth is None else depth
    z = [[0] * HASH_OUT_ELEMENTS]
    for _ in range(d):
        z.append(two_to_one(z[-1], z[-1]))
    return z


def _levels(leaves_hex: list[str]) -> tuple[list[list[list[int]]], list[list[int]]]:
    """The real prefix of every level, bottom-up, plus the zero-subtree hashes.

    Returns (levels, zero) where levels[0] is the real leaf digests and levels[TREE_DEPTH]
    is exactly the root. Cost is O(real leaves + depth), not O(2^depth).
    """
    _check_population(leaves_hex)
    z = zero_hashes()
    cur = [hash_or_noop(hex_to_elements(h)) for h in leaves_hex]
    levels = []
    for k in range(TREE_DEPTH):
        levels.append(cur)
        nxt = []
        for i in range(0, len(cur), 2):
            right = cur[i + 1] if i + 1 < len(cur) else z[k]
            nxt.append(two_to_one(cur[i], right))
        cur = nxt
    levels.append(cur)
    return levels, z


def build_root(leaves_hex: list[str]) -> str:
    """Compute the epoch Merkle root over a leaf set. Mirrors compute_epoch_root.

    Leaf digest = hash_or_noop(leaf) (a no-op pad for 4-element leaves).
    Internal node = two_to_one(left, right). Pairs adjacent siblings
    (even index = left, odd index = right), bottom up, for cap_height = 0.

    Sparse since v9.357: the zero padding is folded into precomputed per-level hashes rather
    than materialised. The value is bit-identical to the padded construction, which
    `parity_with_the_padded_construction` asserts on both sides of the language boundary.
    """
    levels, _z = _levels(leaves_hex)
    return elements_to_hex(levels[TREE_DEPTH][0])


def inclusion_path(leaves_hex: list[str], leaf_index: int) -> list[str]:
    """The sibling path for one leaf, bottom-up, exactly TREE_DEPTH entries.

    The witness's own derivation of what the Rust `compute-leaves` publishes, so a published
    path can be checked rather than trusted.
    """
    levels, z = _levels(leaves_hex)
    if not 0 <= leaf_index < len(leaves_hex):
        raise ValueError(f"leaf_index {leaf_index} out of range (only {len(leaves_hex)} leaves)")
    path, i = [], leaf_index
    for k in range(TREE_DEPTH):
        sibling = i ^ 1
        node = levels[k][sibling] if sibling < len(levels[k]) else z[k]
        path.append(elements_to_hex(node))
        i >>= 1
    return path


def root_from_path(leaf_hex: str, leaf_index: int, sibling_path_hex: list[str]) -> str:
    """Recompute the root from a single leaf and its inclusion path.

    Mirrors Plonky2's verify_merkle_proof_to_cap: walk the index bits least
    significant first; bit 0 means current is the left child, bit 1 the right."""
    if len(sibling_path_hex) != TREE_DEPTH:
        raise ValueError(f"inclusion path must have {TREE_DEPTH} siblings, got {len(sibling_path_hex)}")
    current = hash_or_noop(hex_to_elements(leaf_hex))
    for i in range(TREE_DEPTH):
        sibling = hex_to_elements(sibling_path_hex[i])
        bit = (leaf_index >> i) & 1
        if bit:
            current = two_to_one(sibling, current)
        else:
            current = two_to_one(current, sibling)
    return elements_to_hex(current)


def membership_holds(
    leaf_hex: str, leaf_index: int, sibling_path_hex: list[str], claimed_root_hex: str
) -> bool:
    """True iff the leaf hashes up its path to the claimed root."""
    return root_from_path(leaf_hex, leaf_index, sibling_path_hex) == claimed_root_hex.lower()
