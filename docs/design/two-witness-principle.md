# The two-witness principle

**Reader:** an engineer or an assessor. **Job:** Why no cryptographic verdict is trusted from one implementation.

> Any cryptographic verdict Polaris ships must be checkable by a second,
> independent implementation. A verdict only one program can produce is a
> promise, not a proof.

A verifier that agrees with itself has established nothing. The rule below is
the standing obligation that follows from that, and the table at the end is its
current state: every verdict Polaris renders, the implementation that renders
it, and the independent one that checks it.

## The rule

A component that renders a cryptographic verdict, valid or invalid, member or
non-member, accept or reject, must have that verdict reproduced by a second
witness meeting all four conditions:

1. **Independently implemented.** Written separately from the primary, ideally
   in another language.
2. **Differently represented.** Not the same number model: plain integers
   modulo p against the primary's limb arithmetic, for instance. A shared
   representation hides shared bugs.
3. **Sharing no code** with the primary, nor with any third system the pair is
   meant to cross-check.
4. **Agreeing on the verdict** across the honest and adversarial corpus, or
   abstaining explicitly on any axis it cannot model faithfully. Silent
   non-coverage is forbidden: an abstention is recorded, not hidden.

## What it catches

It catches implementation divergence: a bug in one verifier that the other does
not share. It is a differential check. Every document that claims a two-witness
result states its coverage, as [zk-soundness.md](zk-soundness.md) does.

## Why it belongs here

Polaris already refuses to assert what it can test. C9 requires concurrency
hazards to be exercised with real threads rather than asserted in prose. The
two-witness rule is the same discipline applied to cryptographic verdicts,
which were the one place it was missing: the ZK verdict rested on a single Rust
verifier, and the signature verdict on a single liboqs call.

## Current instances

| Verdict | Primary witness | Second witness | Coverage |
|---|---|---|---|
| ZK Merkle inclusion (membership and binding) | the `polaris_zk` Rust crate's `verify` | `polaris_zk/witness2/`, in Python | Statement level. It abstains on proof-byte integrity, which [zk-soundness.md](zk-soundness.md) states in full. |
| ML-DSA-65 signature (`pqc_signing.verify_both`) | liboqs, through the `oqs` bindings | `cryptography`'s `MLDSA65PublicKey`, an independent FIPS 204 implementation | Full. The two must agree; where the installed `cryptography` is too old to provide ML-DSA the verdict degrades to the primary alone, so the witness can never weaken the path. `check_pqc_second_witness` pins both functions. |

The signature row was an explicit abstention until an independent
implementation existed, which is rule 4 working as intended: a lone verifier is
recorded as one, in the open, until it is not one.

## The standing obligation

Any verifier Polaris adds later, a wider-tree SNARK, a recursive proof, a
different signature scheme, inherits this rule. Shipping a lone verifier is a
finding, not a feature.
