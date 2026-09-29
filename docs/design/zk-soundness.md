# ZK soundness

**Reader:** an engineer or an assessor. **Job:** What the words proof and zero-knowledge mean here, precisely.

The `polaris_zk` crate uses the words proof, zero-knowledge and post-quantum.
This is the ledger that says which of those claims are rigorous, which are
limited, and exactly where the edges are. A layer that cannot state its own
limits precisely should not be trusted with the thing it protects.

The short version, up front:

> **The ZK layer is a Merkle-inclusion SNARK built on the audited
> `plonky2` 1.x crate (Merkle roots were verified bit-identical across the
> major-version bump). The membership statement and its verdict are
> two-witnessed by an independent implementation. The tree depth is
> runtime-parameterized (`POLARIS_ZK_TREE_DEPTH`, default 14 = 16,384 leaves),
> which covers the schema's 10,000-leaf epoch cap, so the default anonymity set
> is a full epoch; prove, verify and proof size are measured below. None of
> this has had an external cryptographic audit. Do not protect real identities
> with it as shipped.**

There are two different kinds of guarantee here, and conflating them is the
main way to be misled by this layer.

---

## 1. The differential / consistency guarantee: strong and real

This is the guarantee Polaris now delivers rigorously, and it is not itself a
cryptographic claim. It is a correctness claim about the implementation.

The verdict of the Rust verifier (`polaris_zk::verify`) is **two-witnessed**: an
independent, from-scratch re-implementation of the same field, hash and Merkle
semantics (`polaris_zk/witness2/`, pure Python, plain `int mod p` rather than the
Rust crate's limbs, sharing no code with it) re-derives the membership fact and
the public-input binding, and must agree on ACCEPT or REJECT in every honest and
adversarial case.

What is checked:

- **Root computation** is bit-for-bit identical between the Rust crate
  (`compute-root`) and the Python witness across every cohort size 1..16
  (`test_root_agreement_bit_identical`). A wrong Poseidon, MDS, encoding, or tree
  ordering could not survive this.
- **The Python Poseidon is anchored independently** of Polaris: it reproduces
  Plonky2's own published permutation test vectors (all-zeros, `0..11`, all `-1`)
  in `poseidon_constants.py::POSEIDON_TEST_VECTORS`, so the second witness has its
  own ground truth, not just "agrees with the Rust binary."
- **The verdict differential** (`polaris_web/test_zk_second_witness.py`) runs
  honest proofs and every public-input tamper (nonce, epoch, context, root, and a
  multi-field replay) through both verifiers; both ACCEPT the honest case and both
  REJECT every tamper.

This is the strongest claim in the document. The membership statement Polaris's
verifier accepts is the statement an independent implementation also accepts,
and the bindings it rejects are the ones that implementation also rejects.

---

## 2. The cryptographic guarantee: demo-scale, with specific caveats

The soundness of the *proof object itself* (the FRI / Plonky2 proof, that a
cheating prover cannot forge membership) rests entirely on the upstream
`plonky2` 1.x crate. Polaris does not re-implement or audit that; it depends on
it. The honest caveats:

| Component | What is real | The honest caveat |
|---|---|---|
| **Proof system** | The audited, widely used `plonky2` 1.x crate: transparent setup, FRI-based, no trusted ceremony, no elliptic-curve assumption. The major-version bump was taken with roots verified bit-identical and the two-witness differential re-passing. | Polaris ships a thin circuit over it. The crate is mature; Polaris's use of it has had no external review. |
| **Statement** | "I know a leaf `L` and a path `P` such that `L` hashes up to the public root `R`, bound to `(epoch_id, context_id, nonce)`." Correct and now two-witnessed. | The binding fields are registered as public inputs but not otherwise constrained (see the public-input registration in `lib.rs`); they prevent proof *substitution* by commitment, not by an in-circuit predicate, and do not by themselves prevent bundle replay (the single-use nonce store is deferred, threat-model T-T2). |
| **Tree size** | Depth is runtime-parameterized (P0.7): `POLARIS_ZK_TREE_DEPTH`, default 14 (16,384 leaves), settable 4..=32. | The default covers the schema's 10,000-leaf epoch cap, so the anonymity set is a full epoch, not a 16-leaf demo. Plonky2 is transparent, so a depth change is a config change, not a ceremony. Larger anonymity sets are viable for verify/size but bounded by prover cost (see benchmarks). |
| **Hash** | Poseidon over Goldilocks, Plonky2-native, vector-matched. | Standard primitive, but the in-circuit security margin is Plonky2's default config, not a parameter set audited for this deployment. |
| **FRI parameters** | `CircuitConfig::standard_recursion_config()` defaults. | The concrete bit-security of the shipped config is **still not independently derived here** (it depends on the FRI rate + query count, which this ledger does not re-derive); treat any specific bit number as aspirational. What IS now measured is the *performance* profile below. |
| **Token-signing PQC** | Real ML-DSA-65 through liboqs (`pqc_signing.py`, `POLARIS_USE_REAL_PQC`), two-witnessed on the verify path, and set by both shipped production paths. | The code default is off, so a development run signs a labelled deterministic placeholder and property tests stay reproducible. This is a separate primitive from the Merkle SNARK above; the two are often conflated and should not be. |

### Measured performance (P0.7, v9.169)

Benchmarked on the reference dev machine (Apple Silicon, `--release`), 64 real
leaves, averaged over repeated runs; each timing includes process start and a
full circuit rebuild, so it is an upper bound on the compute.

| depth | max leaves | prove | verify | proof size |
|------:|-----------:|------:|-------:|-----------:|
| 10 (demo) | 1,024 | ~24 ms | ~9 ms | 72 KB |
| **14 (default)** | **16,384** | **~36 ms** | **~10 ms** | **76 KB** |
| 20 | 1,048,576 | ~580 ms | ~10 ms | 76 KB |
| 24 (national) | 16,777,216 | ~11 s | ~11 ms | 76 KB |

Two facts fall straight out of the numbers, and they set the production profile:

- **Verify and proof size are effectively constant** across depth (~10 ms,
  ~76 KB). That is the FRI succinctness property doing exactly what it should: a
  verifier's cost does not grow with the anonymity set. Verification is
  production-viable at any depth.
- **Prove cost grows superlinearly** and is dominated NOT by the SNARK (which is
  `O(depth)` hashes in-circuit) but by `pad_leaves_to_full_depth` +
  `build_merkle_tree` reconstructing and hashing the entire `2^depth`-leaf tree
  on every proof. `lib.rs` already flags this as a v1 shortcut ("in a production
  deployment only the leaf's siblings would be needed"). So depth 14 is
  comfortably production-ready (36 ms), and larger anonymity sets are gated on a
  sibling-path-only witness, not on the proof system.

**Production profile:** depth 14 is the shipped default and is production-ready
for the per-epoch anonymity model the schema already enforces (10k-leaf epoch
cap). Depths up to ~20 are usable today at a sub-second prove cost. A
national-scale single-tree anonymity set (depth 24+) is verify- and
size-viable but needs the sibling-path witness optimization before its prover
cost is practical; that optimization is the named next step for this layer.

---

## What the second witness covers, and what it does not

The second witness is a **statement-level** check, by design. It re-establishes:

- **membership**: the leaf really hashes up its path to the committed root, and
- **binding**: the bundle's public inputs equal the ones the proof committed to.

It deliberately **ABSTAINS** on one axis: the integrity of the Plonky2 proof
*bytes*. It does not parse or re-run the FRI object, so it cannot detect a
corrupted proof blob; that axis is witnessed by the Rust decoder alone. The
differential records this explicitly
(`test_proof_byte_tamper_rust_rejects_witness_abstains`): on proof-byte
corruption the Rust side rejects and the witness, seeing an intact statement,
abstains rather than bluffs.

That is the boundary every two-witness claim has: it catches implementation
divergence on the statement, not a shared misreading of the specification, and
it never substitutes for an external audit.

---

## Bottom line for an operator

The constitutional invariants, C1 to C10, are enforced in PostgreSQL and are
not what this ledger is about. This is only the optional ZK layer, and for
that layer the position is:

- The membership proof is transparent-setup, post-quantum-comfortable, and its
  verdict is independently two-witnessed. That part is solid, and it is good
  tooling to learn from and to build on.
- It is not audited cryptography. The concrete bit-security of the shipped FRI
  configuration is not derived here, and Polaris's circuit over `plonky2` has
  had no external review.
- The README's framing of the whole system as notional is the correct one, and
  this layer is a reason for it rather than an exception to it.

| Question | Read |
|---|---|
| The independent witness | `polaris_zk/witness2/`, with `test_witness2.py` |
| The verdict differential | `polaris_web/test_zk_second_witness.py` |
| The two-witness principle | [two-witness-principle.md](two-witness-principle.md) |
| What the circuit proves | [zk-snark.md](zk-snark.md) |
