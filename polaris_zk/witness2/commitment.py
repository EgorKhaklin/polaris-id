"""witness2.commitment - the leaf commitment and the scoped nullifier, re-derived.

The independent half of P9.3. `polaris_zk`'s Rust circuit computes both of these
INSIDE the proof, and `leaf_commitment` / `nullifier` in `src/lib.rs` compute them
outside it for the issuer and the wallet. This module is the third implementation,
in a different language and number representation, and it must agree with both to
the byte.

Why a third: the leaf commitment is what makes the whole construction mean
anything. If the issuer's out-of-circuit derivation ever drifted from the
in-circuit one, the issuer would publish an epoch of leaves that no holder could
open, and the failure would surface as "proving is broken" rather than as a
commitment mismatch. And if the nullifier drifted, a relying party's
one-person-once rule would silently stop matching the same person to themselves.
Two implementations can share a mistake when one was written from the other. This
one is written from the specification:

    leaf       = Poseidon_no_pad(secret[0..4] || context_id)
    nullifier  = Poseidon_no_pad(secret[0..4] || scope || epoch_id)

where Poseidon_no_pad is Plonky2's `hash_n_to_hash_no_pad`: absorb the input in
8-element chunks into a 12-lane state that starts at zero, permuting after each,
then take the first 4 lanes. No padding, no domain tag. `poseidon.hash_no_pad`
implements it and is anchored to Plonky2's published permutation vectors.

What the nullifier does NOT do, stated here because this is where someone will
read it: it does not hide the holder from the ISSUER. The issuer derives the
secret at issuance in order to build the epoch tree, so it can compute any
member's nullifier in any scope. The property is between RELYING PARTIES: one
cannot correlate its nullifiers with another's, and each can refuse the same
person twice within its own scope. Issuer-blind derivation is a different
construction and is not claimed.
"""
from __future__ import annotations

from .merkle import elements_to_hex, hex_to_elements
from .poseidon import hash_no_pad


def leaf_commitment(secret_hex: str, context_id: int) -> str:
    """The epoch leaf for a member: `Poseidon(secret || context_id)`.

    context_id rides inside the commitment, so a leaf minted for one context
    cannot be opened in another even by the member who owns it.
    """
    elements = hex_to_elements(secret_hex)
    return elements_to_hex(hash_no_pad(elements + [int(context_id)]))


def nullifier(secret_hex: str, scope: int, epoch_id: int) -> str:
    """The scoped nullifier: `Poseidon(secret || scope || epoch_id)`.

    Same secret as the leaf, which is what lets a verifier conclude the value
    belongs to the member who owns that leaf rather than to anyone at all.
    """
    elements = hex_to_elements(secret_hex)
    return elements_to_hex(hash_no_pad(elements + [int(scope), int(epoch_id)]))


def links(nullifier_a: str, nullifier_b: str) -> bool:
    """Do two nullifiers name the same person in the same scope and epoch?

    A relying party keeps the nullifiers it has seen and calls this. Comparison
    is case-insensitive hex; it is deliberately NOT a similarity test, because
    the only honest answer about two nullifiers from different scopes is "no
    information", and any partial comparison would invent some.
    """
    return str(nullifier_a).lower() == str(nullifier_b).lower()
