"""
test_zk_second_witness.py - the differential that two-witnesses Polaris's ZK
verdict (v9.44, Glass bounded-integration).

For every honest and adversarial scenario, the Rust verifier (polaris_zk) and
the independent Python witness (polaris_zk/witness2) must agree ACCEPT/REJECT.
The witness shares no code with the Rust crate or with Glass; it re-derives the
Goldilocks+Poseidon+Merkle membership fact and the public-input binding in a
different language and number representation.

Honest scope (see docs/design/zk-soundness.md):
  - Statement-level surface (membership + public-input binding) is two-witnessed.
  - Proof-byte integrity (the FRI object) is checked by the Rust decoder alone;
    the witness ABSTAINS on that axis by construction. The proof-byte-tamper
    case below asserts the Rust side rejects and records the abstention.

Skips cleanly if the Rust binary is not built (cargo build --release in
polaris_zk/, or set POLARIS_ZK_BINARY).
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess

import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_ZK_DIR = _HERE.parent / "polaris_zk"

# Make the witness2 package importable.
import sys

if str(_ZK_DIR) not in sys.path:
    sys.path.insert(0, str(_ZK_DIR))

from witness2 import verifier as w2  # noqa: E402


def _binary() -> str | None:
    explicit = os.environ.get("POLARIS_ZK_BINARY")
    if explicit and os.path.isfile(explicit):
        return explicit
    default = _ZK_DIR / "target" / "release" / "polaris-zk"
    return str(default) if default.is_file() else None


_BIN = _binary()
_NEED_BIN = pytest.mark.skipif(_BIN is None, reason="polaris-zk binary not built")


def _rust(sub: str, payload: dict) -> tuple[int, dict | None, str]:
    """Run a Rust subcommand. Returns (returncode, parsed_json_or_None, stderr)."""
    assert _BIN is not None  # callers are guarded by _NEED_BIN
    proc = subprocess.run(
        [_BIN, sub], input=json.dumps(payload).encode(), capture_output=True, timeout=120
    )
    out = None
    if proc.returncode == 0 and proc.stdout.strip():
        out = json.loads(proc.stdout)
    return proc.returncode, out, proc.stderr.decode("utf-8", "replace")


def _rust_verify(bundle: dict) -> bool:
    """Rust verdict: True iff the binary returns {"verified": true}. A non-zero
    exit (e.g. undecodable proof bytes) counts as a reject."""
    rc, out, _ = _rust("verify", bundle)
    if rc != 0 or out is None:
        return False
    return bool(out["verified"])


def _make_secrets(n: int, salt: int = 0) -> list[str]:
    """n distinct holder secrets. Since P9.3 a test cannot invent leaves directly:
    a leaf is Poseidon(secret || context_id) and the circuit opens it, so the
    secret is the thing a prover actually holds."""
    secrets = []
    for i in range(n):
        b = bytearray(32)
        b[0:8] = ((i + 1) * 0x1001 + salt).to_bytes(8, "little")
        b[8:16] = (salt * 7 + 3).to_bytes(8, "little")
        secrets.append(b.hex())
    return secrets


def _make_leaves(secrets: list[str], ctx: int) -> list[str]:
    """The published epoch leaves for those secrets, via the Rust binary."""
    leaves = []
    for s in secrets:
        rc, out, err = _rust("leaf", {"secret_hex": s, "context_id": ctx})
        assert rc == 0 and out is not None, f"leaf failed: {err}"
        leaves.append(out["leaf_hex"])
    return leaves


def _honest_case(n: int, leaf_index: int, epoch: int, ctx: int, nonce: int,
                 scope: int = 0) -> dict:
    """Produce an honest proof + the ground-truth witness needed by the Python
    second witness (the inclusion path and the committed public inputs)."""
    secrets = _make_secrets(n, salt=epoch)
    leaves = _make_leaves(secrets, ctx)
    rc, bundle, err = _rust(
        "prove",
        {
            "secret_hex": secrets[leaf_index],
            "leaf_index": leaf_index,
            "all_leaves_hex": leaves,
            "epoch_id": epoch,
            "context_id": ctx,
            "nonce": nonce,
            "scope": scope,
        },
    )
    assert rc == 0 and bundle is not None, f"prove failed: {err}"

    rc, cl, err = _rust("compute-leaves", {"leaves_hex": leaves})
    assert rc == 0 and cl is not None, f"compute-leaves failed: {err}"
    entry = next(e for e in cl["leaves"] if e["index"] == leaf_index)

    return {
        "bundle": bundle,
        "witness": {
            "leaf_hash": entry["leaf_hash"],
            "leaf_index": leaf_index,
            "proof_path": entry["proof_path"],
            # P9.3: the secret lets the second witness RE-DERIVE the leaf and the
            # nullifier instead of taking the bundle's word for either.
            "secret_hex": secrets[leaf_index],
        },
        "committed": dict(bundle["public_inputs"]),  # the proof's true public inputs
    }


# Scenarios: (label, n, index, epoch, ctx, nonce)
_SCENARIOS = [
    ("mid-tree", 8, 3, 42, 1, 99),
    ("first-leaf", 8, 0, 7, 2, 1),
    ("last-real-leaf", 5, 4, 100, 9, 12345),
    ("single-leaf", 1, 0, 1, 1, 1),
    ("full-cohort", 16, 15, 55, 3, 777),
]


@_NEED_BIN
@pytest.mark.parametrize("label,n,idx,epoch,ctx,nonce", _SCENARIOS)
def test_honest_proof_both_accept(label, n, idx, epoch, ctx, nonce):
    case = _honest_case(n, idx, epoch, ctx, nonce)
    assert _rust_verify(case["bundle"]) is True, f"[{label}] Rust should ACCEPT honest proof"
    pred = w2.check_claim(case["witness"], case["committed"], case["bundle"]["public_inputs"])
    assert pred["verdict"] == "ACCEPT", f"[{label}] witness should ACCEPT: {pred['reasons']}"
    assert pred["membership"] is True
    assert pred["binding"] is True


@_NEED_BIN
@pytest.mark.parametrize(
    "field,mutate",
    [
        ("nonce", lambda v: v + 1),
        ("epoch_id", lambda v: v + 1),
        ("context_id", lambda v: v + 1),
    ],
)
def test_public_input_tamper_both_reject(field, mutate):
    case = _honest_case(8, 3, 42, 1, 99)
    tampered = json.loads(json.dumps(case["bundle"]))
    tampered["public_inputs"][field] = mutate(tampered["public_inputs"][field])

    assert _rust_verify(tampered) is False, f"Rust must REJECT tampered {field}"
    pred = w2.check_claim(case["witness"], case["committed"], tampered["public_inputs"])
    assert pred["verdict"] == "REJECT", f"witness must REJECT tampered {field}"
    assert pred["binding"] is False


@_NEED_BIN
def test_tampered_merkle_root_both_reject():
    case = _honest_case(8, 3, 42, 1, 99)
    tampered = json.loads(json.dumps(case["bundle"]))
    root = bytearray.fromhex(tampered["public_inputs"]["epoch_root_hex"])
    root[0] ^= 0x01
    tampered["public_inputs"]["epoch_root_hex"] = root.hex()

    assert _rust_verify(tampered) is False, "Rust must REJECT tampered root"
    pred = w2.check_claim(case["witness"], case["committed"], tampered["public_inputs"])
    assert pred["verdict"] == "REJECT", "witness must REJECT tampered root"


@_NEED_BIN
def test_multi_field_replay_both_reject():
    case = _honest_case(8, 3, 42, 1, 99)
    tampered = json.loads(json.dumps(case["bundle"]))
    tampered["public_inputs"]["epoch_id"] = 43
    tampered["public_inputs"]["context_id"] = 2
    tampered["public_inputs"]["nonce"] = 100

    assert _rust_verify(tampered) is False, "Rust must REJECT multi-field replay"
    pred = w2.check_claim(case["witness"], case["committed"], tampered["public_inputs"])
    assert pred["verdict"] == "REJECT"


@_NEED_BIN
def test_proof_byte_tamper_rust_rejects_witness_abstains():
    """Proof-byte integrity is outside the statement-level witness's model: it
    ABSTAINS by construction and the Rust decoder is the sole witness on that
    axis. We assert the Rust side does not accept a corrupted proof object."""
    case = _honest_case(8, 3, 42, 1, 99)
    tampered = json.loads(json.dumps(case["bundle"]))
    pb = bytearray.fromhex(tampered["proof_hex"])
    pb[len(pb) // 2] ^= 0xFF
    tampered["proof_hex"] = pb.hex()

    assert _rust_verify(tampered) is False, "Rust must REJECT a corrupted proof object"
    # Witness abstention recorded: the statement is unchanged (membership +
    # binding still hold), so the witness alone cannot detect proof-byte rot.
    pred = w2.check_claim(case["witness"], case["committed"], tampered["public_inputs"])
    assert pred["verdict"] == "ACCEPT", (
        "by design the statement-level witness ABSTAINS on proof-byte integrity "
        "(it sees an intact statement); the Rust decoder catches the corruption"
    )


@_NEED_BIN
@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13, 16])
def test_root_agreement_bit_identical(n):
    """The core cryptographic computation (Goldilocks+Poseidon+Merkle root) is
    two-witnessed bit-for-bit across cohort sizes."""
    leaves = _make_leaves(_make_secrets(n, salt=n * 11), 1)
    rc, out, err = _rust("compute-root", {"leaves_hex": leaves})
    assert rc == 0 and out is not None, err
    assert out["epoch_root_hex"] == w2.recompute_root(leaves), f"root mismatch at n={n}"


@_NEED_BIN
@pytest.mark.parametrize("ctx", [1, 2, 9, 4294967296])
def test_leaf_commitment_agreement_bit_identical(ctx):
    """P9.3: the leaf commitment is two-witnessed. If the Rust and Python
    derivations ever drift, the issuer publishes an epoch of leaves no holder can
    open, and the failure looks like broken proving rather than like a mismatch."""
    from witness2.commitment import leaf_commitment
    for secret in _make_secrets(6, salt=ctx % 1000):
        rc, out, err = _rust("leaf", {"secret_hex": secret, "context_id": ctx})
        assert rc == 0 and out is not None, err
        assert out["leaf_hex"] == leaf_commitment(secret, ctx), \
            f"leaf mismatch for context {ctx}"


@_NEED_BIN
@pytest.mark.parametrize("scope", [0, 7, 1001, 2**63])
def test_nullifier_agreement_bit_identical(scope):
    """P9.3: the scoped nullifier is two-witnessed. A drift here would silently
    stop a relying party recognising the same person on a second visit."""
    from witness2.commitment import nullifier
    for epoch in (1, 42, 999):
        for secret in _make_secrets(4, salt=epoch):
            rc, out, err = _rust("nullifier", {"secret_hex": secret, "scope": scope,
                                               "epoch_id": epoch})
            assert rc == 0 and out is not None, err
            assert out["nullifier_hex"] == nullifier(secret, scope, epoch), \
                f"nullifier mismatch at scope={scope} epoch={epoch}"


@_NEED_BIN
def test_the_second_witness_catches_an_unconstrained_nullifier():
    """The failure the second witness exists for.

    Suppose the circuit stopped constraining the nullifier to the leaf's secret.
    Every proof would still verify in Rust, and a membership-only witness would
    still say ACCEPT. The witness catches it by RE-DERIVING the nullifier from
    the secret: a bundle carrying any other value is REJECT.
    """
    case = _honest_case(8, 3, 42, 1, 99, scope=1001)
    pred = w2.check_claim(case["witness"], case["committed"], case["bundle"]["public_inputs"])
    assert pred["verdict"] == "ACCEPT" and pred["nullifier_derived"] is True

    forged = dict(case["committed"], nullifier_hex="ff" * 32)
    pred = w2.check_claim(case["witness"], forged, dict(forged))
    assert pred["verdict"] == "REJECT"
    assert pred["nullifier_derived"] is False


@_NEED_BIN
def test_the_second_witness_catches_a_secret_that_does_not_open_the_leaf():
    """A prover pairing someone else's leaf with their own secret must be caught
    by the witness as well as by the circuit."""
    case = _honest_case(8, 3, 42, 1, 99, scope=1001)
    stranger = dict(case["witness"], secret_hex="ab" * 32)
    pred = w2.check_claim(stranger, case["committed"], case["bundle"]["public_inputs"])
    assert pred["verdict"] == "REJECT"
    assert pred["opens"] is False


@_NEED_BIN
def test_one_person_once_per_scope_across_both_witnesses():
    """Same member, same scope, two proofs: one nullifier, agreed by both."""
    from witness2.commitment import links, nullifier
    a = _honest_case(8, 3, 42, 1, 99, scope=1001)
    b = _honest_case(8, 3, 42, 1, 12345, scope=1001)
    na = a["bundle"]["public_inputs"]["nullifier_hex"]
    nb = b["bundle"]["public_inputs"]["nullifier_hex"]
    assert links(na, nb), "a relying party must recognise the second visit"
    assert na == nullifier(a["witness"]["secret_hex"], 1001, 42)

    elsewhere = _honest_case(8, 3, 42, 1, 99, scope=2002)
    assert not links(na, elsewhere["bundle"]["public_inputs"]["nullifier_hex"]), \
        "another relying party must not be able to correlate the same person"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
