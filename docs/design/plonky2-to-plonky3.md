# Plonky2 to Plonky3: an evaluation, and the decision

**Reader:** whoever next asks whether the proof library should be replaced. **Job:** record
what was measured, what was reasoned, what was not verified, and the decision, so the question
is re-opened by evidence rather than by mood.

**Decision: KEEP Plonky2.** Re-evaluate when one of the triggers at the end fires. This is a
spike with a decision record, not a migration, which is what roadmap P2.12 asked for.

## Why the question exists at all

It is not performance. It is supply chain. Plonky2 is pinned at `1.1.0` and has been stable
for a long time; a dependency that does not move is either finished or unmaintained, and from
the outside those look identical. Plonky3 is where the same authors' momentum went. For a
system that expects to outlive its dependencies, "the library we depend on has stopped
receiving releases" is a real long-term risk even when nothing is broken today.

So the question is honest. The answer is still no, for now, and the reasons are below in the
order they actually weighed.

## What was measured

On this machine, release build, through the CLI (so the numbers include process start and
circuit construction, which is how the application actually pays them):

| | Depth 14 (demo) | Depth 24 (national) |
|---|---|---|
| Prove, median of 5 | 20 ms | 33 ms |
| Verify, median of 5 | 12 ms | 12 ms |
| Proof size | 77,840 bytes | 77,840 bytes |

Two things follow. Proving is barely sensitive to tree depth, because the circuit is dominated
by fixed FRI parameters rather than by the twenty-four Merkle levels. And the proof size does
not move at all: 77,840 bytes is a property of the proof system's configuration, not of the
statement.

**There is no performance case for a rewrite.** A holder proves in 33 milliseconds on their
own device at national depth. [../reference/COST-MODEL.md](../reference/COST-MODEL.md) found
separately that verification throughput is not the cost driver at any realistic national
scale. Nothing in the measured behaviour is asking to be faster.

The one number a migration might improve is proof size, and 77 KB is already small enough to
staple to a presentation and to move as QR frames.

## What was reasoned, from the code rather than from a blog post

**A migration is not a version bump.** Plonky2 ships a ready-made recursive-SNARK
`CircuitBuilder`: `build_circuit` in `polaris_zk/src/lib.rs` declares targets, calls
`verify_merkle_proof_to_cap` and `hash_n_to_hash_no_pad`, and registers public inputs. Plonky3
ships modular `p3-*` component crates, a STARK/AIR toolkit rather than a drop-in. The circuit
would be re-expressed as an algebraic intermediate representation with its own trace layout,
its own constraint polynomials, and its own commitment configuration. That is a rewrite of the
soundness core, by whoever understands both the old circuit and the new toolkit.

**Every published epoch would be invalidated.** The epoch root is a Poseidon Merkle root under
Plonky2's specific parameters. A different hash or tree construction changes every root, every
holder's leaf, and every conformance vector, exactly as the P9.3 leaf change did at a smaller
scale. That cost is now known concretely rather than guessed: it is re-closing every epoch and
regenerating every published artifact.

**The two-witness model would largely survive, which was the surprise.** The second witness
(`polaris_zk/witness2/`) is deliberately a *statement-level* witness: it re-derives the
membership fact and checks the public-input binding, and it abstains on proof-byte integrity
by construction. Nothing in it parses a Plonky2 proof. What it does depend on is the hash and
the Merkle construction, and `poseidon.py` is anchored to Plonky2's published permutation
vectors. So a migration would need `witness2` re-anchored to whatever hash the new
construction uses, but the *shape* of the second witness, and the differential that pins it
against the Rust, carries over. The two-witness discipline is not an obstacle to migrating; it
is one more thing to re-anchor.

That is a genuinely useful finding for the eventual decision, and it came from reading the
witness rather than from assuming.

## What was NOT verified, and must be before any decision to move

This spike did not re-check the external facts, and a future decision must not inherit them:

- **Plonky3's current version and release status.** The roadmap row recorded `0.7.0-rc.1` when
  it was written. Whether that is still a release candidate is the single most decision-
  relevant fact here and it has a shelf life measured in months.
- **Audit status of either library.** Neither the Plonky2 circuit nor its proof library has had
  an external cryptographic audit *in this repository's use of it*, which
  [zk-soundness.md](zk-soundness.md) already says in its own words. Whether either project has
  been audited independently was not established here, and asserting it either way would be
  worse than leaving it open.
- **Maintenance trajectory.** "Stable" and "abandoned" look the same from a version number.
  Commit activity, issue response and a stated support policy are the evidence, and they were
  not gathered.

Recording these as unverified is the point. A decision record that quietly presents unchecked
claims as findings is how a rewrite gets justified by a paragraph nobody sourced.

## The decision

**Keep Plonky2.** Three reasons, in weight order:

1. **A release candidate is not a soundness core.** A system that models national identity does
   not put its zero-knowledge proofs on a pre-release toolkit. This alone defers the question
   until Plonky3 is stable, whatever the other columns say.
2. **There is no problem to solve.** Proving is 33 ms at national depth, verification is not
   the cost driver, and the proof fits in a QR presentation. A rewrite of the soundness core
   with no measured deficiency to fix is risk without return.
3. **The cost is a rewrite plus a re-anchor plus an invalidation of every published epoch**, and
   it is now measured rather than feared. That is a price worth paying for a real problem and
   not for a version number.

## What would change the decision

Any one of these re-opens it, and the first is the only one likely soon:

- **Plonky3 reaches a stable release** with a stated support policy, and Plonky2 has still had
  no release. That is the staleness risk becoming concrete rather than theoretical.
- **A soundness or implementation defect is found in Plonky2** that its maintainers do not fix.
- **A scale requirement appears that the measurements above cannot meet**, which today would
  mean an epoch pipeline needing recursive aggregation across shards rather than one proof per
  holder.
- **Proof size becomes a constraint**, for instance a transport that cannot carry 77 KB.

Absent one of those, the nearer-term ZK work is the sibling-path witness optimisation named in
roadmap P0.7, not a change of proof system.

## Proven by

`check_plonky3_evaluation` pins that this record exists, states a decision, separates what was
measured from what was not verified, and carries re-evaluation triggers. It cannot check
whether the decision is right; it can check that the next person is told what it rested on.
