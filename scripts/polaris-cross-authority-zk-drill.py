#!/usr/bin/env python3
"""
polaris-cross-authority-zk-drill.py — offline cross-authority epoch-bound ZK, run (P3.2d).

A holder proves, in ZERO KNOWLEDGE, that its credential is included in an issuing
authority's epoch tree, without revealing which credential. The Plonky2 circuit binds the
proof to that epoch's Merkle ROOT (a public input), and the same root is what the authority
publishes SIGNED in its epoch checkpoint. P3.2d composes the two OFFLINE: a relying party
that trusts authority B accepts a holder's proof against a FOREIGN authority A's epoch iff
A's signed checkpoint is authentic, fresh, and attested by B in the presented context (so
the epoch root is trusted, non-transitively), the proof's public inputs BIND to that trusted
root/epoch/context, and the Plonky2 proof verifies (via the local polaris-zk binary).

Because generating a proof needs the Rust prover and signing a checkpoint needs liboqs, the
end-to-end artifacts are generated ONCE (`--generate`, needs both) and committed as a
fixture, exactly like the ML-DSA vectors/. The drill then VERIFIES the fixture, which needs
only the polaris-zk binary (to check the proof) and a ML-DSA verifier (liboqs OR the
cryptography/OpenSSL witness) -- both present in the CI test job. It FAILS (exit 1) on any
wrong decision: an active foreign proof must be accepted, and an untrusted issuer, a wrong
context, a forged checkpoint, a wrong-root proof, and a tampered proof must all be rejected;
with the binary absent the decision must ABSTAIN, never falsely accept.

    python3 scripts/polaris-cross-authority-zk-drill.py --generate   # local, needs liboqs + binary
    python3 scripts/polaris-cross-authority-zk-drill.py              # verify the fixture (CI)
"""
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FIXTURE = os.path.join(_ROOT, "polaris_zk", "fixtures", "cross-authority-zk.json")
sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _iso(dt):
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


CONTEXT_ID = 1
EPOCH_ID = 7
NONCE = 4242


def generate(path):
    """Build a real epoch tree, a real inclusion proof, A's signed epoch checkpoint, and B's
    manifest attesting A. Needs liboqs (checkpoint/manifest signatures) and the polaris-zk
    prover binary. Writes the fixture the verify path re-checks."""
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    import pqc_signing
    import zk
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("--generate needs real ML-DSA (liboqs + cryptography)", file=sys.stderr)
        return 3
    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-ca-zk-gen-")
    now = datetime.now(timezone.utc)

    def keypair(name):
        kp = pqc_signing.generate_keypair()
        kf = os.path.join(tmp, "%s.json" % name)
        with open(kf, "w") as f:
            json.dump(kp, f)
        return kf, kp["public_key_hex"]

    key_a, pub_a = keypair("A")
    key_b, pub_b = keypair("B")

    def sign_with(key_file, message):
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
        sig, _alg, pk = pqc_signing.signature_over_message(message)
        return sig, pk

    # A's epoch tree, and a holder's inclusion proof for one leaf.
    secrets = [zk.derive_holder_secret(tid, "TKN-CA-%d" % tid, CONTEXT_ID) for tid in range(1, 6)]
    leaves = [zk.derive_leaf_commitment(s, CONTEXT_ID) for s in secrets]
    root_hex, _ = zk.compute_epoch_leaves(leaves)
    proof = zk.generate_proof(secrets[2], 2, leaves, EPOCH_ID, CONTEXT_ID, NONCE)
    assert proof["public_inputs"]["epoch_root_hex"] == root_hex, "prover root must equal the epoch root"

    # A proof for a DIFFERENT tree (a different root): valid on its own, but not for A's epoch.
    other_secrets = [zk.derive_holder_secret(tid, "TKN-OTHER-%d" % tid, CONTEXT_ID) for tid in range(1, 6)]
    other = [zk.derive_leaf_commitment(s, CONTEXT_ID) for s in other_secrets]
    proof_wrong_root = zk.generate_proof(other_secrets[1], 1, other, EPOCH_ID, CONTEXT_ID, NONCE)

    # A signs an epoch checkpoint committing exactly {EPOCH_ID, root_hex}.
    cp = {
        "format": "polaris-epoch-checkpoint/1",
        "authority": {"agency_id": "A", "name": "Authority A"},
        "epoch": {"number": EPOCH_ID, "root_hex": root_hex, "committed_count": len(leaves),
                  "valid_until": _iso(now + timedelta(days=30))},
        "prev": {"number": EPOCH_ID - 1, "root_hex": "aa" * 16},
        "as_of": _iso(now), "issued_at": _iso(now),
        "expires_at": _iso(now + timedelta(days=1)), "algorithm": "ML-DSA-65",
    }
    sig, pk = sign_with(key_a, V._epoch_checkpoint_canonical(cp))
    cp["signature_hex"], cp["public_key_hex"] = sig.hex(), pk

    # B's manifest attesting A's key in CONTEXT_ID.
    mf = {
        "format": "polaris-federation-manifest/1",
        "authority": {"agency_id": "B", "name": "Authority B"},
        "anchors": [{"public_key_hex": pub_b, "algorithm": "ML-DSA-65", "status": "active"}],
        "attestations": [{"attested_agency_id": "A", "attested_public_key_hex": pub_a, "context_id": CONTEXT_ID}],
        "epoch": {"number": EPOCH_ID, "root_hex": root_hex},
        "revocation": {"as_of": _iso(now)},
        "issued_at": _iso(now), "expires_at": _iso(now + timedelta(days=1)), "algorithm": "ML-DSA-65",
    }
    sig, pk = sign_with(key_b, V._manifest_canonical(mf))
    mf["signature_hex"], mf["public_key_hex"] = sig.hex(), pk

    fixture = {
        "note": "P3.2d cross-authority epoch-bound ZK fixture. Regenerate with --generate "
                "(needs liboqs + the polaris-zk prover). issued_at fields are refreshed at "
                "verify time so the checkpoint/manifest stay fresh.",
        "context_id": CONTEXT_ID, "epoch_id": EPOCH_ID, "nonce": NONCE,
        "pub_a": pub_a, "pub_b": pub_b,
        "proof": proof, "proof_wrong_root": proof_wrong_root,
        "epoch_checkpoint": cp, "manifest": mf,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(fixture, f, indent=2, sort_keys=True)
    print("wrote fixture: %s" % path)
    return 0


def run(path, zk_binary=None):
    V = _load_verifier()
    with open(path) as f:
        fx = json.load(f)
    # Pin `now` inside the fixture's validity window so the committed artifacts stay fresh
    # regardless of the wall clock, and check the ZK proof cryptographically via the binary.
    now = V._parse_iso(fx["epoch_checkpoint"]["issued_at"]) + timedelta(seconds=1)
    ctx, nonce = fx["context_id"], fx["nonce"]
    cp, mf = fx["epoch_checkpoint"], fx["manifest"]
    trust = [mf]
    anchors = [fx["pub_b"]]

    def decide(proof, checkpoint, context=ctx, manifests=trust, zk_bin=zk_binary):
        return V.verify_cross_authority_zk(proof, checkpoint, context, manifests, now=now,
                                           max_window_seconds=None, trusted_anchors=anchors,
                                           expected_nonce=nonce, zk_binary=zk_bin)

    forged_cp = json.loads(json.dumps(cp))
    _b = bytearray.fromhex(forged_cp["signature_hex"]); _b[0] ^= 0x01
    forged_cp["signature_hex"] = _b.hex()

    tampered_proof = json.loads(json.dumps(fx["proof"]))
    _p = bytearray.fromhex(tampered_proof["proof_hex"]); _p[0] ^= 0x01
    tampered_proof["proof_hex"] = _p.hex()

    checks = [
        ("active foreign credential, real proof against A's trusted epoch: ACCEPT",
         decide(fx["proof"], cp)["decision"], "accept"),
        ("issuer not attested by anyone trusted: REJECT",
         decide(fx["proof"], cp, manifests=[])["decision"], "reject"),
        ("attested in context 1 but presented in context 2: REJECT",
         decide(fx["proof"], cp, context=2)["decision"], "reject"),
        ("forged epoch checkpoint (bad signature): REJECT",
         decide(fx["proof"], forged_cp)["decision"], "reject"),
        ("proof for a DIFFERENT epoch tree (wrong root): REJECT",
         decide(fx["proof_wrong_root"], cp)["decision"], "reject"),
        ("tampered proof bytes (binding intact, crypto fails): REJECT",
         decide(tampered_proof, cp)["decision"], "reject"),
        ("no polaris-zk binary: ABSTAIN (trust holds, proof unverifiable here), never accept",
         decide(fx["proof"], cp, zk_bin="/nonexistent/polaris-zk")["decision"], "abstain"),
        ("the verdict carries no token_value (zero-knowledge)",
         "token_value" not in json.dumps(decide(fx["proof"], cp)).lower(), True),
    ]

    print("case                                                                    got        expected   ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-69s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: a holder's zero-knowledge inclusion proof is decided against a FOREIGN authority's "
              "epoch OFFLINE -- accepted only when the authority's signed checkpoint is trusted in-context "
              "AND the proof binds to its committed root AND the Plonky2 proof verifies; a wrong root, a "
              "forged checkpoint, an untrusted issuer, and a tampered proof all reject, and with no verifier "
              "binary the decision abstains rather than false-accepts.")
        return 0
    print("\nFAIL: a cross-authority ZK decision was wrong.", file=sys.stderr)
    return 1


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if "--generate" in argv:
        return generate(_FIXTURE)
    if not os.path.isfile(_FIXTURE):
        print("fixture %s is missing; regenerate with --generate (needs liboqs + the polaris-zk "
              "prover)" % _FIXTURE, file=sys.stderr)
        return 3
    # Verifying the proof needs the polaris-zk binary; verifying the checkpoint needs a ML-DSA
    # verifier (liboqs OR the cryptography/OpenSSL witness, which ships in requirements). Skip
    # cleanly when the binary is absent -- without it the accept case would only ever abstain.
    V = _load_verifier()
    if not os.path.isfile(V._zk_binary_path()):
        print("cross-authority ZK drill needs the polaris-zk binary (build in polaris_zk/); skipping",
              file=sys.stderr)
        return 3
    return run(_FIXTURE)


if __name__ == "__main__":
    sys.exit(main())
