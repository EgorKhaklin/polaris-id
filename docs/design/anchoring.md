# Blockchain anchoring

**Reader:** an engineer or an assessor. **Job:** How a batch of audit rows is committed to an external anchor, and what that proves.

An audit trail held by one operator asks everyone to trust that operator not
to rewrite it. Anchoring answers that without moving the system onto a ledger:
the schema stays the audit of record, and a periodic Merkle commitment fixes
each batch of anchors under a root. Outside verification goes through the
[transparency log](transparency-log.md): every batch root is an entry of that
RFC 6962 log, which binds each root and lets a monitor prove the sequence of
roots only grew. The proofs under a root are checked by the verify route
(`/api/anchor/verify/<token_id>`);
[What a batch proof binds](#what-a-batch-proof-binds) says what they prove.

The commitment is what leaves; the data does not.

## How a batch closes

1. Each `BlockchainAnchor` row carries a per-token identifier and a commitment
   hash.
2. `close_anchor_batch(algorithm_id, root, proofs)` groups the pending anchors
   by signature algorithm, records a new `AnchorBatch` row with the Merkle
   root, and writes each leaf's inclusion proof back to its anchor row.
3. The root is published: every batch root is an entry of the public
   transparency log. The per-leaf proofs are served to signed-in users
   (`/api/anchor/<token_id>`, the token export
   `/api/tokens/<token_id>/export`, and the read-only SQL console (admin,
   auditor)) and checked there by `/api/anchor/verify/<token_id>`. Committing
   the logs' heads to a public chain is the operator's decision, and the schema
   records that it happened (`ChainAnchor`, below).

## The Merkle maths runs in Python, not in the database

`polaris_web/anchoring.py` computes the root and the proofs, and the procedure
takes them as parameters. That keeps the schema portable: requiring
`plpython3u` would tie every deployment to a PostgreSQL build with the trusted
language installed, which many managed providers do not offer.

The cost is that a compromised helper could hand the procedure a root that
does not match its leaves. The verify route (`/api/anchor/verify/<token_id>`)
recomputes one anchor's leaf from its row and walks that anchor's stored proof
to the stored root, so a root or a proof that does not fit an anchor shows at
that anchor's next verification. Whoever holds the batch's rows can rebuild
the root with `compute_batch` and compare.

## Leaves are ordered, and the order is part of the defence

The helper sorts leaves by anchor identifier before hashing, and the procedure
selects them in the same order. Without a deterministic order an attacker can
produce two different roots from one leaf set, show each to a different
auditor, and call both canonical. One order means one root.

## The hash is operator policy

`SUPPORTED_HASHES` offers SHA3-256, which is the default and FIPS 202, and
SHA3-512 for a higher target. Any other name is refused, never mapped to one
of these.

The `CryptographicAlgorithm` table records signature algorithms, not hash
functions, so the hash used for a batch is a property of the helper at batch
time rather than a column. Changing it later is a new entry in
`SUPPORTED_HASHES` and an operator policy decision, not a schema migration.

## One batch at a time, per algorithm

`close_anchor_batch` takes a transaction-scoped advisory lock keyed on the
algorithm. Two calls for the same algorithm serialise; two calls for different
algorithms do not. It is the same shape as the per-agency lock on revocation,
the per-individual lock on recovery and the per-token lock on migration, and
[concurrency.md](concurrency.md) holds the catalogue.

Without it, two callers can see the same pending leaves, both insert a batch,
and split or duplicate the leaves between them, breaking the property that a
leaf belongs to exactly one batch.
`ConcurrencyTests.test_close_anchor_batch_concurrent` races them.

## Design choices

- **It does not mark a batch as committed.** `committed_to_chain` exists and
  no trigger sets it. Publishing to a ledger is an operator action, and the
  schema records the fact rather than performing it.
- **It does not record the publication on the batch.** The batch is audit of
  record, so its columns cannot change after it closes. Since decision 013
  (2026-10-04) a publication is recorded beside it instead: a checkpoint over
  the transparency logs' heads, which include the anchor log's root over every
  batch, is committed to Bitcoin and recorded in `ChainAnchor`
  ([transparency-log.md](transparency-log.md#public-chain-anchoring-decision-013)).
- **It does not store the hash function.** Which function closed a given batch
  is answered by this document and by the proof geometry, not by a column.

The three future fields, `committed_to_chain`, `external_chain` and
`external_chain_tx`, move together under the `batch_chain_consistency` check,
so a transaction identifier cannot appear while the flag is false. Nothing
writes them, and nothing will: an append-only row cannot be marked after it
closes, and `external_chain` admits no public chain. They remain as the
record of the first design; `ChainAnchor` holds what they were reserved for.

## The ten-thousand-leaf cap

`close_anchor_batch` refuses a larger batch. A SHA3-256 tree over ten thousand
leaves is fourteen levels deep, so an inclusion proof is fourteen sibling
hashes, a few hundred bytes, which is a reasonable thing to hand a verifier.
Ten thousand anchors an hour is a population-scale rate. Beyond that, proofs
grow into the kilobytes and the verifier's client pays for it.

The cap is an engineering bound, not a security one. Raising it is fine if a
deployment needs it, since proof size grows logarithmically.

## Where an adversary ends up

- **The claim.** A closed batch fixes a Merkle root. When the verifier
  recomputes the leaf from an anchor's row, as the verify route does, a proof
  that places that anchor under the root cannot be forged without breaking
  SHA3-256 ([What a batch proof binds](#what-a-batch-proof-binds)).
- **The direct attack.** Find a pre-image that hashes into an existing root.
  SHA3-256 offers 256-bit pre-image resistance against a classical attacker
  and half of that against Grover, which is still out of reach. The
  cryptographic layer is not where this gets attacked.
- **So the attack moves up.** The remaining targets are the batch-closing
  procedure, the lock that decides which leaves are eligible, and the
  immutability trigger on the batch row.
- **The best of those.** Race two closes against the same algorithm to compose
  a leaf set before the lock is taken. The advisory lock defeats it: the
  second caller waits, then finds the first caller's rows already assigned to
  a batch and no eligible leaves left.
- **What it costs.** Per-algorithm scoping means one tree cannot mix
  algorithms. A global anchor would need a differently scoped lock. That is
  accepted, because algorithm scoping is what keeps a signature algorithm
  substitutable rather than load-bearing for the whole history.

## What a batch proof binds

- **The leaf comes from the row.** A leaf is SHA3-256 of the text
  `anchor_id|commitment_hash`, an interior node SHA3-256 of its two
  children's bytes. The verify route recomputes the leaf from the anchor's
  row, so a proof it accepts is bound to that row. No row can spell a node:
  a node's input is the 64 bytes of two SHA3-256 outputs; a row's is a serial
  `anchor_id`, `|` and a `commitment_hash` that a CHECK holds to hex
  (`01_schema.sql`).
- **Outside verification goes through the transparency log.** Its entries are
  the batch roots, hashed as RFC 6962 prescribes, with `0x00` and `0x01`, so
  the log binds each root at its position, and a monitor proves the sequence
  only grew ([transparency-log.md](transparency-log.md)).

## Reading the code

- `polaris_web/anchoring.py`: `compute_batch`, `leaf_hash`, `merkle_root`,
  `inclusion_proof`, `verify_proof`.
- `polaris_sql/01_schema.sql`: `AnchorBatch`, and `BlockchainAnchor` with its
  batch reference and proof column.
- `polaris_sql/05_procedures.sql`: `close_anchor_batch`.
- `polaris_sql/06_triggers.sql`: `trg_anchor_batch_append_only`.
- `polaris_web/test_app.py`: `AnchorBatchTests`, the concurrency tests named
  above, and `TransparencyProofBoundsTests`, which pins the login on the two
  routes built to serve a proof, and that no GET route answering without login
  serves a stored proof's hashes.
- [audit-of-record.md](audit-of-record.md): `AnchorBatch` is one of the
  thirteen instances of the principle.
