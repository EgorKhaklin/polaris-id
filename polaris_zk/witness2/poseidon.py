"""
poseidon.py - an independent, from-scratch Poseidon-Goldilocks permutation.

This is the "second witness" half of Polaris's ZK verdict. It shares NO code
with the Rust crate (polaris_zk) or with Glass; it is a deliberately separate
re-implementation in a different language and a different number representation
(plain Python int mod p, not Rust's base-2^64 limbs). The Pentecost discipline:
a proof you cannot independently check is just a promise.

The permutation is the textbook reference Poseidon (no FAST_PARTIAL_ROUND
optimization): for each round, add round constants, apply the x^7 S-box
(all lanes on full rounds, lane 0 only on partial rounds), then multiply by
the MDS layer. Plonky2's optimized permutation is mathematically identical and
its published test vectors anchor this file (see poseidon_constants.py).

Width 12, 8 full rounds (4 + 4), 22 partial rounds, S-box x^7.
"""

from __future__ import annotations

from .poseidon_constants import (
    ALL_ROUND_CONSTANTS,
    HALF_N_FULL_ROUNDS,
    MDS_MATRIX_CIRC,
    MDS_MATRIX_DIAG,
    N_PARTIAL_ROUNDS,
    P,
    WIDTH,
)

# Number of Goldilocks field elements in a hash digest (HashOut). Plonky2's
# NUM_HASH_OUT_ELTS. A digest is 4 elements = 32 bytes.
HASH_OUT_ELEMENTS = 4

# Plonky2's SPONGE_RATE: how many input elements are absorbed per permutation.
# WIDTH is 12 lanes and the capacity is the 4 that hold the digest, so the rate
# is 8.
SPONGE_RATE = WIDTH - HASH_OUT_ELEMENTS


def _sbox_monomial(x: int) -> int:
    """The Poseidon S-box, x^7 over Goldilocks."""
    return pow(x, 7, P)


def _constant_layer(state: list[int], round_ctr: int) -> None:
    """Add this round's 12 round constants to the state, in place."""
    base = WIDTH * round_ctr
    for i in range(WIDTH):
        state[i] = (state[i] + ALL_ROUND_CONSTANTS[base + i]) % P


def _mds_row(r: int, v: list[int]) -> int:
    """One MDS output lane, matching Plonky2's mds_row_shf.

    result[r] = sum_i v[(i + r) mod 12] * CIRC[i]  +  v[r] * DIAG[r]
    """
    res = 0
    for i in range(WIDTH):
        res += v[(i + r) % WIDTH] * MDS_MATRIX_CIRC[i]
    res += v[r] * MDS_MATRIX_DIAG[r]
    return res % P


def _mds_layer(state: list[int]) -> list[int]:
    """Apply the circulant+diagonal MDS matrix."""
    return [_mds_row(r, state) for r in range(WIDTH)]


def permute(state: list[int]) -> list[int]:
    """The full Poseidon permutation over a 12-element Goldilocks state.

    Input/output are lists of 12 ints already reduced mod P. Does not mutate
    the caller's list.
    """
    if len(state) != WIDTH:
        raise ValueError(f"Poseidon state must be {WIDTH} elements, got {len(state)}")
    s = [x % P for x in state]
    round_ctr = 0

    # First half of the full rounds.
    for _ in range(HALF_N_FULL_ROUNDS):
        _constant_layer(s, round_ctr)
        s = [_sbox_monomial(x) for x in s]
        s = _mds_layer(s)
        round_ctr += 1

    # Partial rounds: S-box on lane 0 only.
    for _ in range(N_PARTIAL_ROUNDS):
        _constant_layer(s, round_ctr)
        s[0] = _sbox_monomial(s[0])
        s = _mds_layer(s)
        round_ctr += 1

    # Second half of the full rounds.
    for _ in range(HALF_N_FULL_ROUNDS):
        _constant_layer(s, round_ctr)
        s = [_sbox_monomial(x) for x in s]
        s = _mds_layer(s)
        round_ctr += 1

    return s


def two_to_one(left: list[int], right: list[int]) -> list[int]:
    """Compress two 4-element digests into one, matching Plonky2's compress().

    State = [left(4), right(4), 0, 0, 0, 0]; permute; take the first 4 lanes.
    This is exactly the internal-node hash of a Plonky2 Merkle tree.
    """
    if len(left) != HASH_OUT_ELEMENTS or len(right) != HASH_OUT_ELEMENTS:
        raise ValueError("two_to_one operands must be 4-element digests")
    state = list(left) + list(right) + [0] * (WIDTH - 2 * HASH_OUT_ELEMENTS)
    out = permute(state)
    return out[:HASH_OUT_ELEMENTS]


def hash_no_pad(elements: list[int]) -> list[int]:
    """Plonky2's `hash_n_to_hash_no_pad`: the sponge with NO padding.

    Absorb the input in RATE-element chunks into a WIDTH-lane state that starts
    at zero, permuting after each chunk, then squeeze the first HASH_OUT_ELEMENTS
    lanes. A short final chunk sets only its own lanes and leaves the rest of the
    state as the previous permutation left them, which is exactly what Plonky2's
    `set_from_slice` does; padding the chunk with zeros instead would produce a
    different digest for the same input, so it is not done here.

    This is the hash behind the P9.3 leaf commitment and scoped nullifier
    (witness2.commitment), and it must agree with the in-circuit
    `builder.hash_n_to_hash_no_pad::<PoseidonHash>` element for element.
    """
    state = [0] * WIDTH
    absorbed = [x % P for x in elements]
    for start in range(0, len(absorbed), SPONGE_RATE):
        chunk = absorbed[start : start + SPONGE_RATE]
        for i, c in enumerate(chunk):
            state[i] = c
        state = permute(state)
    return state[:HASH_OUT_ELEMENTS]


def hash_or_noop(elements: list[int]) -> list[int]:
    """Plonky2's leaf digest: for <= 4 elements, the leaf IS the digest
    (zero-padded to 4); for more, it would be a sponge hash. Polaris leaves
    are exactly 4 elements, so this is a no-op pad."""
    if len(elements) <= HASH_OUT_ELEMENTS:
        padded = list(elements) + [0] * (HASH_OUT_ELEMENTS - len(elements))
        return [x % P for x in padded]
    # Sponge path (not used by Polaris's 4-element leaves, included for
    # completeness so the witness never silently mis-handles a wide leaf).
    state = [0] * WIDTH
    rate = WIDTH - HASH_OUT_ELEMENTS  # 8
    padded = list(elements)
    for start in range(0, len(padded), rate):
        chunk = padded[start : start + rate]
        for i, c in enumerate(chunk):
            state[i] = c % P
        state = permute(state)
    return state[:HASH_OUT_ELEMENTS]


def self_test() -> None:
    """Anchor the permutation to Plonky2's published test vectors. Raises
    AssertionError on any mismatch. Independent of the Polaris Rust binary."""
    from .poseidon_constants import POSEIDON_TEST_VECTORS

    for idx, (inp, expected) in enumerate(POSEIDON_TEST_VECTORS):
        got = permute(inp)
        assert got == [e % P for e in expected], (
            f"Poseidon test vector {idx} mismatch:\n  got={[hex(x) for x in got]}\n"
            f"  exp={[hex(e) for e in expected]}"
        )


if __name__ == "__main__":
    self_test()
    print("poseidon: all Plonky2 test vectors pass")
