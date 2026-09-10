# The ZK-SNARK

**Reader:** an engineer or an assessor. **Job:** What the Plonky2 circuit proves, and the second witness that checks it.

A zero-knowledge verification has to answer one question, that a valid token
exists, without revealing which one. The proof object that does it, and the
choices behind that object, are what this record covers.
[zk-soundness.md](zk-soundness.md) is the companion: it states which of the
claims here are rigorous and which are limited, and it should be read with
this one.

## The three choices

The design space was a proof system, a circuit shape, and a setup posture.
What was chosen, and why:

- **Transparent setup.** No ceremony at all, rather than a ceremony documented
  or outsourced. It removes a trust assumption instead of managing one.
- **Plonky2.** FRI-based, hash-only commitments, comfortable in a
  post-quantum threat model. It is the family that matches a system whose
  signing is already post-quantum.
- **Merkle membership over a per-epoch root.** The issuer publishes a Merkle
  root over the active-token set for an epoch, and the proof shows membership
  in that root, bound to the epoch, the context and a nonce.

The trade-offs were taken with open eyes. Plonky2 is the youngest of the
families considered, so breaking changes are a live risk; the epoch-bounded
architecture means the proof system could be replaced without touching the
schema. A proof is tens of kilobytes and verification is milliseconds, which
the measured numbers in the soundness ledger set out precisely. The default
tree depth of fourteen covers the schema's ten-thousand-leaf epoch cap, and
because the setup is transparent, changing the depth is configuration rather
than a ceremony.

## What the circuit proves

```
Public inputs, which the verifier sees:
  epoch_root  four field elements: the Poseidon Merkle root
  epoch_id    one field element
  context_id  one field element
  nonce       one field element
  scope       one field element: the relying party's domain separator
  nullifier   four field elements: Poseidon(secret || scope || epoch_id)

Private inputs, which only the prover holds:
  secret      four field elements: the holder's per-context secret
  proof_path  the sibling hashes, one per level
  index_bits  the leaf's position, as booleans

The constraints:
  1. leaf = Poseidon(secret || context_id)
  2. hashing that leaf up the path, in the order the index bits give,
     must produce the public root
  3. nullifier = Poseidon(secret || scope || epoch_id), the SAME secret
```

The epoch, context, nonce and scope are registered as public inputs rather than
constrained arithmetically. That binds the proof to them by commitment: a
proof made for one tuple cannot be presented under another, because the
verifier checks the proof's public inputs against what it expected.

## The leaf is a commitment the circuit opens

Constraint 1 is newer than the rest and it is what makes constraint 3 mean
anything. The leaf used to be `SHA3-256(token_id | token_value | context_id)`,
computed outside the circuit and handed in as an opaque private value. A
nullifier beside an opaque leaf proves only that the prover knows some number:
nothing ties the two to one secret, so a prover could pair any member's leaf
with a nullifier of their own choosing.

Verifying a SHA3-256 preimage inside a circuit costs thousands of constraints.
Poseidon costs about a hundred. So the leaf moved to Poseidon and the circuit
opens it, which is what lets constraint 3 name the same secret as constraint 1.

The SHA3-256 derivation did not disappear; it became the **secret**, which the
holder derives from the credential they hold and the issuer derives at
issuance. The epoch publishes the commitment.

The change is not backward compatible. An epoch closed under the old derivation
holds leaves the current circuit cannot open, and its proofs do not verify
against the current verifier. Epochs are re-closed rather than migrated.

## One person, once per scope

The nullifier answers a question a relying party asks constantly and a
credential system usually answers badly: *has this person already claimed
here?* The usual answer is an account, which is an identifier, which is a
lifelong correlation handle. The nullifier answers it without one.

Within one relying party's scope and one epoch, a member's nullifier is
constant, so a second proof is recognisable as a repeat and can be refused.
Across two relying parties, the values are uncorrelated: distinguishing them
needs the secret, which neither has. So each can enforce its own rule and the
two learn nothing by pooling their ledgers.

Two bounds, stated because they are easy to overclaim:

- **It does not hide the holder from the issuer.** The issuer derives every
  member's secret in order to build the epoch tree, so it could compute any
  member's nullifier in any scope. The property is between relying parties.
  Issuer-blind derivation is a different construction and is not claimed.
- **It resets each epoch.** That is deliberate. A nullifier that persisted
  across epochs would be a permanent pseudonym, which is the thing being
  avoided. A relying party's ledger should be keyed by (its scope, epoch) and
  should not outlive the epoch.

Both SDKs carry the comparison rule (`nullifiers_link` / `nullifiersLink`)
because it is easy to get wrong by hand: exact hex only, never across scopes,
never across epochs.

That prevents substituting a captured proof into a different context. It does
not by itself prevent replaying the identical request, because the verification
route neither issues nor consumes nonces: the prover chooses one and carries
it. Closing that needs a single-use nonce store, which
[threat-model.md](threat-model.md) tracks as an open item. Until then,
anti-replay rests on context-side enforcement and the freshness window.

## Why Poseidon here and SHA3 elsewhere

The anchoring layer uses SHA3-256 because it is a commitment published
off-chain, where a standard, widely implemented hash is the right choice. The
epoch root uses Poseidon because it is hashed *inside* a circuit, where SHA3
would cost thousands of constraints per hash and Poseidon costs roughly a
hundred.

Two commitments, two jobs, two hashes.
[substrate.md](substrate.md) carries a row for each so the dependency manifest
shows both.

## A Rust subprocess, not a binding

Plonky2 is Rust-native and the Python bindings are not mature, so the boundary
is a process rather than a foreign function interface:

- `polaris_zk/` is the crate, built against a pinned nightly toolchain, and
  produces one binary.
- `polaris_web/zk.py` shells out to it with JSON on stdin and stdout.
- The subcommands are `compute-root`, `compute-leaves`, `leaf`, `nullifier`,
  `prove` and `verify`.

The cost is process spawn per call and a build step in deployment; the
production image compiles the binary once and ships it. The benefit is that no
Rust runtime lives inside the Python process, and the two sides can be tested
independently, which is what makes the second witness possible.

## What holds the proof together

**Zero-knowledge is the proof system's property, not an API rule.** The
verifier sees the proof bytes and the public inputs and cannot recover the
leaf. Nothing at the route layer has to enforce that.

**An expired epoch is refused distinctly.** The verification route checks
`valid_until` before invoking the verifier and rejects with a reason that says
the epoch expired, which is not the same event as a failed verification, and
the audit trail keeps them apart.

**Epoch closure is an operator action.** `uc11_close_epoch` requires the admin
role and nothing schedules it. The schema records the epoch; an operator
decides when it closes, under a per-procedure advisory lock so the prover is
never racing a changing leaf set.

**The epoch is immutable once closed.** `enforce_epoch_immutability` makes
`TokenStateEpoch` append-only, and the leaf table is append-only too. Every
proof issued against a root depends on that root not moving.

**The two cryptographic gates do not overlap.** Disclosure level decides which
one applies: a zero-knowledge verification runs the proof check and no
federation check, because no issuer is disclosed; a selective or full
verification runs the federation check and submits no proof. No path runs both.

## Where an adversary ends up

- **The claim.** A zero-knowledge verification proves a valid token exists in
  the named epoch without revealing which. Soundness rests on Plonky2 and on
  Poseidon over the Goldilocks field.
- **The direct attack.** Forge a proof. That reduces to the cryptographic
  assumptions the substrate manifest documents, and it is not where this gets
  attacked.
- **So the attack moves outside the proof.** The timing of a request, the
  co-occurrence of zero-knowledge events with disclosed ones for the same
  person, or the composition of the epoch leaf set, which is closer to the
  database than to the circuit.
- **The strongest of those.** Correlate zero-knowledge events with selective
  or full ones across contexts and timestamps to reconstruct the graph the
  proof was hiding. The SNARK does not answer that. What answers it is
  everything around it: the redaction proof, the absence of the verification
  graph from operator surfaces, and the bounded result sets on every read
  path.
- **What it costs.** Proof generation is expensive relative to a signature
  check, and it is paid at epoch boundaries and amortised across every
  verification in the window.

The substitutability principle holds throughout: circuit, prover and verifier
could be replaced by any system satisfying the same public-input contract
without amending the schema. Keeping the circuit to membership alone, with the
validity predicates checked when the epoch is composed, is what keeps it small
enough to be fast.

## What is not built

- **No independent cryptographic audit.** The crate is used as published; the
  circuit over it has had no external review.
- **No prover on the holder's device.** Proof generation runs on the Polaris
  host. Moving it to the holder is the architecture a production deployment
  would want, and it is a different system.
- **No witness encryption.** The stored leaf paths are plaintext.
- **No scheduled epochs.** Closure is a deliberate operator action.
- **No validity predicates in the circuit.** Whether a token is active,
  permitted for a context and unrevoked is decided when the epoch is
  composed, not proved inside it.

## Reading the code

- `polaris_zk/src/lib.rs` for the circuit, the prover and the verifier;
  `src/main.rs` for the four subcommands.
- `polaris_zk/witness2/` for the independent Python implementation that checks
  the verdict, under [two-witness-principle.md](two-witness-principle.md).
- `polaris_web/zk.py` for the subprocess wrapper.
- `polaris_sql/01_schema.sql` for `TokenStateEpoch` and its leaf table;
  `05_procedures.sql` for `uc11_close_epoch`; `06_triggers.sql` for
  `enforce_epoch_immutability`.
- `polaris_web/test_app.py` for `ZKSnarkTests` and the epoch-closure
  concurrency tests.
