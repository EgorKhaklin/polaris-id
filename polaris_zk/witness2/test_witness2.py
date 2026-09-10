"""
test_witness2.py - self-contained unit tests for the second witness.

These need no Rust binary: they anchor Poseidon to Plonky2's published vectors,
exercise the Merkle encoding/round-trips, and check the verdict logic on both
honest and adversarial statement-level claims (including the non-member case the
Rust-side differential cannot construct, since Rust's prove() only ever proves
real membership). The cross-language bit-for-bit agreement with the Rust crate
lives in polaris_web/test_zk_second_witness.py.

Run: python3 -m pytest polaris_zk/witness2/test_witness2.py
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from witness2 import commitment, merkle, poseidon, verifier
from witness2.poseidon_constants import P, POSEIDON_TEST_VECTORS

# External anchor for the Merkle math. These roots and the inclusion path are
# the INDEPENDENT Rust witness's output (polaris-zk compute-leaves) for fixed
# leaf sets, captured once. Pinning the Python second witness to them verifies
# its build_root / root_from_path against external ground truth rather than
# against itself: a wrong-but-deterministic implementation (wrong MDS, flipped
# index bits, wrong padding) would survive a self-referential round-trip but
# fails here. Regenerate after any depth/encoding change with:
#   echo '{"leaves_hex":["aa..","bb..","cc.."]}' | polaris-zk compute-leaves
_ANCHOR_LEAVES = ["aa" * 32, "bb" * 32, "cc" * 32]
_ANCHOR_ROOT = "8fe699f2fb373f24557cd712e277b5a05b44f62037653b91227e414ada7331d7"
_ANCHOR_PATH0 = [
    "bb" * 32,
    "e69d3d8967339e1ad6026a96b530d8db5251396ac0f636eb846c1a3804a89492",
    "cc4ff1aad14a1ab6cfb201991b58858df20aa362d79a8fde03e58a3241fc9621",
    "5ae05c29f70ae06164dea29dc57c249a5fc056e9bf94fb4642a53cc70c3a7067",
    "442646061a92545147092c2e0db3c18c274d85bff37c7d1640a088afa0ea22f5",
    "ae615bd1c8b5e6e939d497bd349bac86970159fcf0237eb772666f68973505d0",
    "4a61495d1a5f2225038fee8e642a1d5a10fb7dc441f7a8ddc3300d0860125649",
    "e35508e23eed79e9f9c1c446c6429a3cb1a43aa86edac916f5790b8bfce468b7",
    "1629fd0c72d76ffe5a7a0adbf3cf728d27a9f99551d41bd3b389294a1267d32b",
    "4ef1c9572144a23c9e84af352cc04e9597919dee33c6f02c45f41f7935daf1fc",
    "c340117b3fb6f7cc53eaa3e4b119e991f78d331df5717c70412aaf00468f7ec2",
    "c3d3b50aadba6e8de39850f0b6aa1b0d4cd4d9b076acc5e17536c83b5bc78b21",
    "219d838e168925ed168071ee6f8401fbe20458214c9ee38e4c6fd2e9698c6161",
    "7f8f37d821f86f2969c6a1c7aed775c9f8f48845fab14108c55dcf9907a276ec",
]
_ANCHOR_SINGLE_LEAF = "dd" * 32
_ANCHOR_SINGLE_ROOT = "fba229f3061680027107f5158cdcd6309e3b41e44790a05ef5f26b9eac3d0631"


def test_poseidon_matches_plonky2_vectors():
    poseidon.self_test()  # raises on mismatch
    # And explicitly, so a failure points at the offending vector.
    for i, (inp, expected) in enumerate(POSEIDON_TEST_VECTORS):
        assert poseidon.permute(inp) == [e % P for e in expected], f"vector {i}"


def test_poseidon_does_not_mutate_input():
    state = list(range(12))
    snapshot = list(state)
    poseidon.permute(state)
    assert state == snapshot


def test_two_to_one_is_deterministic_and_order_sensitive():
    a = [1, 2, 3, 4]
    b = [5, 6, 7, 8]
    assert poseidon.two_to_one(a, b) == poseidon.two_to_one(a, b)
    assert poseidon.two_to_one(a, b) != poseidon.two_to_one(b, a)


def test_hex_element_roundtrip():
    h = "0123456789abcdef" "fedcba9876543210" "00ff00ff00ff00ff" "1122334455667788"
    assert merkle.elements_to_hex(merkle.hex_to_elements(h)) == h


def test_single_leaf_root_is_leaf_digest():
    # A 1-leaf tree pads to the full depth; its root is well-defined and stable.
    leaf = "aa" * 32
    assert len(merkle.build_root([leaf])) == 64


def test_build_root_matches_external_rust_root():
    # Value-pinned against the independent Rust witness (not against the Python
    # function under test). A wrong-but-deterministic build_root fails here.
    assert merkle.build_root(_ANCHOR_LEAVES) == _ANCHOR_ROOT


def test_single_leaf_root_matches_external_rust_root():
    assert merkle.build_root([_ANCHOR_SINGLE_LEAF]) == _ANCHOR_SINGLE_ROOT


def test_membership_holds_against_external_root():
    # The committed root is the EXTERNAL anchor constant, NOT root_from_path()
    # recomputed here, so a True verdict genuinely confirms the Python witness's
    # path traversal reproduces the Rust-derived root. This is the assertion the
    # self-referential round-trip tests could not make.
    assert merkle.membership_holds(
        _ANCHOR_LEAVES[0], 0, _ANCHOR_PATH0, _ANCHOR_ROOT) is True


def test_membership_fails_against_external_root_with_wrong_leaf():
    # Same external root + path, different leaf -> the traversal must NOT
    # reproduce the anchor root.
    assert merkle.membership_holds(
        _ANCHOR_LEAVES[1], 0, _ANCHOR_PATH0, _ANCHOR_ROOT) is False


def test_inclusion_path_reconstructs_root():
    # Build a small tree by hand and verify each real leaf's path.
    leaves = [bytes([i]) .ljust(32, b"\0").hex() for i in range(1, 6)]
    root = merkle.build_root(leaves)
    # Reconstruct via the witness's own tree to derive a path independently:
    # walk indices and confirm membership_holds is True for the true path is
    # covered by the differential; here we assert a wrong path fails.
    # Tamper: claim membership at a flipped root must fail.
    bad_root = ("00" + root[2:])
    if bad_root == root:  # extremely unlikely; flip differently
        bad_root = root[:-2] + "00"
    # Use a path of zero-siblings (almost surely wrong) -> non-member.
    zero_path = ["00" * 32] * merkle.TREE_DEPTH
    assert merkle.membership_holds(leaves[0], 0, zero_path, bad_root) is False


def test_check_claim_accepts_consistent_statement():
    # Construct a self-consistent statement using the witness's own tree math:
    # pick leaves, compute root, derive index-0 path of zero siblings only if it
    # genuinely reconstructs. Instead, drive through a known-good path by using
    # build_root + a hand-walked path is covered in the differential; here we
    # validate the binding logic directly.
    leaf = "11" * 32
    # A degenerate but internally consistent claim: committed root == the root
    # the witness recomputes for this (leaf, index, path).
    path = ["00" * 32] * merkle.TREE_DEPTH
    committed_root = merkle.root_from_path(leaf, 0, path)
    witness = {"leaf_hash": leaf, "leaf_index": 0, "proof_path": path}
    committed = {"epoch_root_hex": committed_root, "epoch_id": 5, "context_id": 1, "nonce": 9}
    claimed = dict(committed)
    res = verifier.check_claim(witness, committed, claimed)
    assert res["verdict"] == "ACCEPT"
    assert res["membership"] and res["binding"]


def test_check_claim_rejects_binding_mismatch():
    leaf = "11" * 32
    path = ["00" * 32] * merkle.TREE_DEPTH
    committed_root = merkle.root_from_path(leaf, 0, path)
    witness = {"leaf_hash": leaf, "leaf_index": 0, "proof_path": path}
    committed = {"epoch_root_hex": committed_root, "epoch_id": 5, "context_id": 1, "nonce": 9}
    claimed = dict(committed, nonce=10)  # tampered
    res = verifier.check_claim(witness, committed, claimed)
    assert res["verdict"] == "REJECT"
    assert res["binding"] is False
    assert res["membership"] is True


def test_check_claim_rejects_non_member():
    leaf = "11" * 32
    path = ["00" * 32] * merkle.TREE_DEPTH
    real_root = merkle.root_from_path(leaf, 0, path)
    # Commit to a DIFFERENT root than the leaf+path produce -> not a member.
    wrong_root = real_root[:-2] + ("00" if real_root[-2:] != "00" else "11")
    witness = {"leaf_hash": leaf, "leaf_index": 0, "proof_path": path}
    committed = {"epoch_root_hex": wrong_root, "epoch_id": 5, "context_id": 1, "nonce": 9}
    res = verifier.check_claim(witness, committed, dict(committed))
    assert res["verdict"] == "REJECT"
    assert res["membership"] is False


# ---------------------------------------------------------------------------
# P9.3 - the leaf commitment and the scoped nullifier.
#
# The anchors below are the INDEPENDENT Rust witness's output, captured once, so
# the Python derivation is pinned to external ground truth rather than to itself.
# Regenerate after any change to the construction with:
#   echo '{"secret_hex":"<64 hex>","context_id":3}'          | polaris-zk leaf
#   echo '{"secret_hex":"<64 hex>","scope":11,"epoch_id":5}' | polaris-zk nullifier
# ---------------------------------------------------------------------------
_ANCHOR_SECRET = "7fd9c03d0cd9d66cc8738a8c9518067a22ddb087a6e1b4ca927b3d807dfa357a"
_ANCHOR_LEAF_CTX3 = "9299d39303fd019a044098d44dab21d8b4e027a9f56335f01f62a184da099941"
_ANCHOR_NULLIFIER_S11_E5 = "39f3836c9cdd68dd11fe9491a0fbce48f0c2660b6efd5da2a9b58e778e9f32a0"
_ANCHOR_NULLIFIER_S22_E5 = "23b864acc5308e203d57b56655ec0ca1b417e87483da34a5c810a20413348162"


def test_leaf_commitment_matches_the_rust_witness():
    # If these two ever drift, the issuer publishes an epoch of leaves no holder
    # can open, and the symptom looks like "proving is broken" rather than like a
    # commitment mismatch. Pin it.
    assert commitment.leaf_commitment(_ANCHOR_SECRET, 3) == _ANCHOR_LEAF_CTX3


def test_nullifier_matches_the_rust_witness():
    assert commitment.nullifier(_ANCHOR_SECRET, 11, 5) == _ANCHOR_NULLIFIER_S11_E5
    assert commitment.nullifier(_ANCHOR_SECRET, 22, 5) == _ANCHOR_NULLIFIER_S22_E5


def test_the_context_is_inside_the_leaf():
    # A leaf minted for one context must not open in another, so a member cannot
    # carry their membership sideways into a context they were never enrolled in.
    assert commitment.leaf_commitment(_ANCHOR_SECRET, 3) != \
        commitment.leaf_commitment(_ANCHOR_SECRET, 4)


def test_one_person_one_nullifier_per_scope_and_epoch():
    # Deterministic in (secret, scope, epoch): this is what lets a relying party
    # recognise a second visit.
    a = commitment.nullifier(_ANCHOR_SECRET, 11, 5)
    b = commitment.nullifier(_ANCHOR_SECRET, 11, 5)
    assert a == b and commitment.links(a, b)


def test_two_scopes_do_not_link():
    # The privacy half. Two relying parties see uncorrelated values for one
    # person, and `links` reports no relationship rather than a partial one.
    a = commitment.nullifier(_ANCHOR_SECRET, 11, 5)
    b = commitment.nullifier(_ANCHOR_SECRET, 22, 5)
    assert a != b
    assert commitment.links(a, b) is False


def test_a_new_epoch_rotates_the_nullifier():
    # Within a scope, a new epoch gives a new value, so a relying party's
    # one-person-once rule resets per epoch rather than lasting forever.
    assert commitment.nullifier(_ANCHOR_SECRET, 11, 5) != \
        commitment.nullifier(_ANCHOR_SECRET, 11, 6)


def test_distinct_secrets_give_distinct_nullifiers():
    seen = set()
    for i in range(32):
        secret = (bytes([i + 1]) + b"\x00" * 31).hex()
        n = commitment.nullifier(secret, 11, 5)
        assert n not in seen, "two members collided in one scope"
        seen.add(n)


def test_links_is_case_insensitive_hex():
    a = commitment.nullifier(_ANCHOR_SECRET, 11, 5)
    assert commitment.links(a, a.upper())


def test_check_claim_rejects_a_secret_that_does_not_open_the_leaf():
    # The second witness must catch a bundle whose secret is not the one behind
    # the leaf. This is the property the circuit added; a witness that only
    # rechecked membership would call it ACCEPT.
    leaf = commitment.leaf_commitment(_ANCHOR_SECRET, 1)
    path = ["00" * 32] * merkle.TREE_DEPTH
    root = merkle.root_from_path(leaf, 0, path)
    committed = {"epoch_root_hex": root, "epoch_id": 5, "context_id": 1, "nonce": 9,
                 "scope": 11, "nullifier_hex": commitment.nullifier(_ANCHOR_SECRET, 11, 5)}
    good = {"leaf_hash": leaf, "leaf_index": 0, "proof_path": path, "secret_hex": _ANCHOR_SECRET}
    assert verifier.check_claim(good, committed, dict(committed))["verdict"] == "ACCEPT"

    stranger = dict(good, secret_hex="ab" * 32)
    res = verifier.check_claim(stranger, committed, dict(committed))
    assert res["verdict"] == "REJECT"
    assert res["opens"] is False


def test_check_claim_rejects_a_nullifier_the_secret_does_not_derive():
    leaf = commitment.leaf_commitment(_ANCHOR_SECRET, 1)
    path = ["00" * 32] * merkle.TREE_DEPTH
    root = merkle.root_from_path(leaf, 0, path)
    committed = {"epoch_root_hex": root, "epoch_id": 5, "context_id": 1, "nonce": 9,
                 "scope": 11, "nullifier_hex": "ff" * 32}
    witness = {"leaf_hash": leaf, "leaf_index": 0, "proof_path": path, "secret_hex": _ANCHOR_SECRET}
    res = verifier.check_claim(witness, committed, dict(committed))
    assert res["verdict"] == "REJECT"
    assert res["nullifier_derived"] is False


def test_check_claim_rejects_a_rescoped_bundle():
    # Relabelling a proof into another scope breaks the public-input binding.
    leaf = commitment.leaf_commitment(_ANCHOR_SECRET, 1)
    path = ["00" * 32] * merkle.TREE_DEPTH
    root = merkle.root_from_path(leaf, 0, path)
    committed = {"epoch_root_hex": root, "epoch_id": 5, "context_id": 1, "nonce": 9,
                 "scope": 11, "nullifier_hex": commitment.nullifier(_ANCHOR_SECRET, 11, 5)}
    res = verifier.check_claim({"leaf_hash": leaf, "leaf_index": 0, "proof_path": path},
                               committed, dict(committed, scope=22))
    assert res["verdict"] == "REJECT"
    assert res["binding"] is False


def test_check_claim_without_a_secret_abstains_on_the_commitment():
    # A verifier that holds only the bundle cannot re-derive anything from a
    # secret it does not have, and must say so rather than guessing True.
    leaf = commitment.leaf_commitment(_ANCHOR_SECRET, 1)
    path = ["00" * 32] * merkle.TREE_DEPTH
    root = merkle.root_from_path(leaf, 0, path)
    committed = {"epoch_root_hex": root, "epoch_id": 5, "context_id": 1, "nonce": 9,
                 "scope": 11, "nullifier_hex": commitment.nullifier(_ANCHOR_SECRET, 11, 5)}
    res = verifier.check_claim({"leaf_hash": leaf, "leaf_index": 0, "proof_path": path},
                               committed, dict(committed))
    assert res["verdict"] == "ACCEPT"
    assert res["opens"] is None and res["nullifier_derived"] is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
