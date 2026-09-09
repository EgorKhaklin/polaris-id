# Offline cross-authority epoch-bound ZK (P3.2d)

**Reader:** an engineer or an assessor who understands the Plonky2 inclusion proof
(a holder proving membership in an epoch tree) and the P3.2 federation trust
decision, and wants to know how the two compose so a relying party accepts a
holder's proof against a **foreign** authority's epoch, offline.

**Status:** shipped v9.312. `verify_cross_authority_zk` in
`scripts/polaris-verify.py`, driven every release by
`scripts/polaris-cross-authority-zk-drill.py`; `check_cross_authority_zk` pins it.

## What composes

Two things already exist, and P3.2d joins them:

1. **The proof is already epoch-bound.** The Plonky2 circuit proves a leaf is
   included in a Merkle tree and registers the tree **root** as a public input,
   alongside the epoch number, a context, and a nonce. That root is exactly the
   Poseidon root Polaris commits as `TokenStateEpoch.merkle_root`. So a holder's
   proof already carries, in the clear, *which epoch root it is a proof against* --
   while revealing nothing about which leaf (which credential) it is.
2. **The root already travels the federation graph, signed.** An authority
   publishes that same root in its signed epoch checkpoint
   (`polaris-epoch-checkpoint/1`), and P3.2/P3.2b already let a relying party
   decide, offline, whether to **trust** a foreign authority's checkpoint: it must
   be authentic, fresh, and attested by an authority the relying party trusts, in
   the presented context, non-transitively.

P3.2d is the join: trust the foreign checkpoint to obtain a **trusted epoch root**,
require the holder's proof to **bind** to that root (and epoch number and context),
and then **verify** the proof cryptographically. A holder thereby proves, in zero
knowledge, that its credential is in a foreign authority's epoch, and a relying
party that trusts that authority (through the graph) accepts it, learning nothing
about which credential.

## The decision, and why the binary

`verify_cross_authority_zk(proof_bundle, epoch_checkpoint, context_id,
trusted_manifests, ...)` decides in three steps:

1. **Trust** (pure Python): `verify_epoch_checkpoint` establishes the checkpoint is
   authentic and fresh; then, exactly as `verify_cross_authority` does, some trusted
   manifest must attest the checkpoint's signing key in the presented context. This
   yields the trusted epoch root and number. No trust, no decision.
2. **Binding** (pure Python): the proof's public inputs must match that root, that
   epoch number, and the context (and a nonce, if the relying party issued a
   challenge). A proof for a different epoch, or a different context, is not a proof
   about this authority's population here.
3. **Proof** (`polaris-zk` binary): the Plonky2 FRI proof is checked. This is the one
   thing the standalone verifier cannot do in pure Python, so it shells to the
   `polaris-zk` binary as a **local subprocess**. There is no network: the proof is
   checked entirely on the verifier's own machine, so the decision is still offline.

If the binary is absent, step 3 cannot run, and the decision is **abstain**: trust
and binding are established, but the proof is unverifiable *here*. Abstain is never
a false accept; a relying party without the binary fetches it, or verifies online.
This mirrors the verifier's existing "no ML-DSA verifier available" abstention: the
verifier states what it could not check rather than guessing.

The verdict carries **no credential**. The proof is zero-knowledge, and the decision
dict names an authority (`via`) and a decision, never a token.

## Standalone, still

The detached verifier stays import-standalone: it imports no Polaris code, and
shelling out to a separate binary is not an import. The `polaris-zk` binary is a
dependency **for the ZK path only** -- every other verification (signatures,
manifests, feeds, bundles, status assertions, transparency heads) remains pure
Python with no external binary. `check_cross_authority_zk` pins both the subprocess
invocation and the standalone constraint.

## What runs

Generating a proof needs the Rust prover and signing a checkpoint needs liboqs, so
the end-to-end artifacts are generated **once** and committed as a fixture, exactly
like the ML-DSA `vectors/`: `polaris_zk/fixtures/cross-authority-zk.json` holds a
real inclusion proof, a real ML-DSA-signed epoch checkpoint, a manifest, and a proof
against a different tree. The drill then **verifies** the fixture, which needs only
the `polaris-zk` binary (to check the proof) and a ML-DSA verifier (liboqs or the
cryptography/OpenSSL witness) -- both present in the CI `test` job. It runs the full
matrix every release and is red on any wrong decision: accept the genuine foreign
proof; reject a wrong root, a forged checkpoint, an untrusted issuer, a wrong
context, and a tampered proof; abstain with no binary. Regenerate the fixture with
`--generate` (which needs liboqs and the prover). A relying party can run the
decision from the command line with `polaris-verify.py --zk-proof ...
--epoch-checkpoint ... --trusted-manifest ...`.

## Boundaries

- **Freshness and replay.** The proof binds a nonce, which stops proof
  *substitution*. Single-use *replay* protection across presentations is stateful,
  and this offline decision keeps no state; a relying party that needs it issues a
  challenge nonce (passed as the expected nonce) or verifies online, where the
  single-use `ZkVerificationNonce` store applies.
- **Issuer identity is bound by the root, not inside the circuit.** The circuit does
  not carry an `authority_id`; cross-authority uniqueness rests on the epoch root
  (globally unique per authority-epoch) and the signed checkpoint that ties that
  root to the issuing authority. Binding the issuer identity *inside* the proof would
  require a circuit change and is out of scope here.
- **The offline verifier needs the binary for the proof.** This is deliberate: the
  alternative, a from-scratch pure-Python Plonky2 verifier, is a separate and much
  larger undertaking. The binary runs locally, so the offline guarantee holds.
