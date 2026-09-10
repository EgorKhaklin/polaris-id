# Epoch cadence: how often to close, and what the choice costs

**Reader:** an operator deciding an authority's epoch schedule, or an assessor asking what
that number does. **Job:** state the trade-off the cadence controls, give the measured cost
of closing one, and record what an epoch stores and deliberately does not.

An epoch is a committed snapshot of an authority's valid credentials: a Merkle root over one
leaf per member, published and signed. A holder proves membership against it. The cadence is
how often that snapshot is retaken, and it is the single number that sets three unrelated
properties at once, which is why it deserves a document rather than a default.

## The three things the cadence sets

**Revocation freshness.** A revoked credential drops out of the *next* epoch, not this one.
Until then it can still produce a valid membership proof. The epoch length is therefore an
upper bound on how long a revoked member remains provable, and it is the same shape of trade
as the offline status window: a deployment picks the number, and the number is policy, not
law. A verifier that cannot accept that bound should be checking status online rather than
accepting a membership proof.

**The size of the crowd.** The anonymity set *is* the epoch. A membership proof hides which
member is proving among everyone in that snapshot, so a shorter cadence over a growing
population is not automatically better: an epoch closed hourly for a small context can produce
a crowd small enough to identify someone by elimination. The floor is a population question,
not a schedule question, and an authority with few members in a context should lengthen the
cadence rather than publish a crowd of eleven.

**How often a relying party's ledger resets.** The scoped nullifier (P9.3) is keyed by the
epoch, deliberately, so that membership never becomes a permanent pseudonym. A relying party
enforcing *one human, once* holds its ledger for exactly one epoch. A short cadence weakens
that rule; a long one strengthens it and weakens revocation freshness. These two pull in
opposite directions and no cadence satisfies both.

## Recommended cadence

| Deployment shape | Cadence | Why |
|---|---|---|
| Demo, teaching, CI | On demand | The set is tiny and nothing depends on freshness. |
| Single authority, thousands of members | Daily | A day-long revocation bound is comparable to the status-assertion window most verifiers already accept, and a day's crowd is large. |
| National, millions of members | Hourly to daily, per context | Closing is cheap (below); the binding constraint is the anonymity floor per context, not the compute. |
| A context with fewer than a few thousand members | Lengthen until the crowd is large enough, or do not offer membership proofs in that context | A small crowd is not anonymity, and a schedule cannot fix that. |

An authority should publish its cadence, because a relying party's freshness reasoning
depends on it and cannot be inferred from the artifacts.

## What closing an epoch costs

Measured on the reference machine (Apple silicon, release build) at the national tree depth
of 24, capacity 16,777,216:

| Members | Root | Peak memory |
|---|---|---|
| 1,000 | 0.01s | 27 MB |
| 100,000 | 0.24s | tens of MB |
| 1,000,000 | 2.10s | tens of MB |

Before v9.357 the same thousand-member root took **10.8 seconds and 2.9 GB**, and the number
did not depend on the population: a fixed-depth tree was padded to 2^depth and every one of
the sixteen million leaves was materialised. The padding is one repeated value, so every
subtree above the real members is an all-zero subtree with exactly one hash per level.
Precomputing those makes a root cost O(members + depth).

Two properties keep that from being a shortcut. The sparse root is element for element the
root the padded construction produced, so no epoch already published becomes unverifiable;
the crate asserts it across the shapes that break naive implementations, including a full
tree with no padding. And the independent Python witness computes the same value at depth 24,
where before it could not run at all.

Repairing a single member is O(depth) rather than a rebuild, which is what makes a revocation
between epochs a twenty-four-node operation instead of a sixteen-million-leaf one.

## What an epoch stores, and what it does not

An epoch stores the root, the committed count, the window, and one leaf hash per member. It
does **not** store an inclusion path per member, and since v9.357 it does not compute one.

That was not always true. The path was written on every close and read by nothing: every
query in the application selects `leaf_hash`, the published anonymity set serves leaf hashes,
and since P9.2 the holder derives their own path on their own device from the set the
authority already publishes. The cost of keeping it was 1,718 bytes per member, which is
roughly 17 GB of JSON to close a ten-million-member epoch, and the schema's own comment
flagged it as plaintext at rest that a later version would have to encrypt under the holder's
key. Data that nothing reads is the easiest kind to stop holding.

The column survives, nullable, so epochs closed before v9.357 keep the paths they recorded.
Migration `011-epoch-leaf-path-optional` makes the change and its down-migration backfills an
empty array rather than inventing a path.

## The cap, and where it will have to move

`uc11_close_epoch` refuses an epoch above 10,000 members, and `/api/v1/epoch/<id>/leaves`
bounds the published set (C8). Both numbers are sized for the default tree depth of 14 and are
the binding constraint on a national deployment, not the hashing. Raising them is a schema and
bounded-read decision that belongs with the deployment that needs it: the published set is a
public body, so its ceiling is a resource-exhaustion question as much as a capacity one, and
the honest answer at national scale is paging or a per-context split rather than one larger
number. Nothing here raises them.

## Proven by

`scripts/polaris-epoch-scale-drill.py`, on every push: parity between the sparse and padded
roots across awkward shapes, agreement between the two witnesses at depth 24, a member
rebuilding the root from a path they derived themselves, and wall-clock and memory ceilings
that a return of the padded construction would breach. `check_epoch_pipeline_scale` pins the
construction, the drill and this document.

The circuit and the leaf commitment are in [zk-snark.md](zk-snark.md); the holder-side
consequences, including why the leaf had to become a Poseidon commitment, are in
[holder-side-keys.md](holder-side-keys.md).
