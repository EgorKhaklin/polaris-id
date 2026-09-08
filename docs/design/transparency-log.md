# The transparency log (P3.3)

**Reader:** an engineer or an assessor, or anyone who wants to run a monitor.
**Job:** how the audit anchor log is turned into a public, append-only, independently
verifiable log, and what a monitor can and cannot prove by watching it.

[anchoring.md](anchoring.md) explains the audit anchor: a periodic Merkle commitment
over audit rows, recorded in the append-only `AnchorBatch` table, so an outside verifier
can prove the history at that point has not been revised. That leaves one gap. A single
`AnchorBatch` root proves the audit rows under *it*; it does not, on its own, prove that
the operator did not later throw away a root and publish a different one in its place. An
append-only transparency log closes that gap: it commits to the whole *sequence* of
anchor roots, and lets anyone prove that the sequence only ever grew.

## The log is a signed view over AnchorBatch

The log's entries are the `AnchorBatch` Merkle roots, in append order (`batch_id`).
`AnchorBatch` is already append-only at the database (an audit-of-record instance), so
the log inherits that property; nothing new is stored. Over those entries the app builds
a Merkle tree in the style of RFC 6962 (Certificate Transparency), using SHA3-256 to
match the rest of Polaris: a leaf is hashed as `SHA3-256(0x00 || entry)` and an interior
node as `SHA3-256(0x01 || left || right)`, so a leaf can never be presented as an
interior node.

The math lives in two places that must agree: `polaris_web/anchoring.py` (`log_tree_head`,
`log_consistency_proof`, `log_inclusion_proof`) for the app, and `scripts/polaris-verify.py`
(`merkle_tree_head`, `verify_consistency`, `verify_inclusion`) for the standalone verifier.
The transparency drill proves they agree under real ML-DSA every release, and the
canonical-signing oracle proves the signed tree head is byte-identical across the two.

## What the log publishes

- `GET /api/v1/transparency/sth` — a **Signed Tree Head**: `{log_id, tree_size, root_hash,
  timestamp}`, signed with the instance's own ML-DSA key over `SHA3-256(canonical)`. It is
  the log's commitment to its entire history at a size.
- `GET /api/v1/transparency/consistency/<m>/<n>` — a **consistency proof** that the size-m
  tree is a prefix of the size-n tree. This is the append-only evidence: it exists only if
  the first m entries were never reordered, rewritten, or dropped.
- `GET /api/v1/transparency/proof/<index>` — an **inclusion proof** that a given entry is in
  the log at a size.
- `GET /api/v1/transparency/entries` — the entries themselves (bounded per call), so a
  monitor or a mirror can replicate the log and recompute everything independently.

There is no personal data in any of it: the entries are anchor roots, and the heads and
proofs are hashes.

## What a monitor proves, and what it does not

`scripts/polaris-transparency-monitor.py` is the auditor's side, and anyone can run it. It
is standalone (only the standard library and the detached verifier), read-only, and it
keeps one piece of state: the last Signed Tree Head it accepted. Each cycle it fetches the
current STH, verifies the signature against a trust anchor it was given out of band, and
fetches a consistency proof from its last head to the new one. If the proof verifies, the
log only appended, and the monitor records the new head. If it does not -- a rewritten
entry, a **fork** (two different roots at one size), a **shrunk** tree, an STH signed by
the wrong key, or a timestamp that goes backwards -- the monitor prints the finding and
exits non-zero.

What this proves is **consistency**: the operator cannot rewrite history without every
monitor that saw the old head detecting it, because the old head will not be a prefix of
the new one. What it does not prove on its own is that two monitors were shown the *same*
head at the same size; catching that split-view requires the monitors to compare notes.
Gossip between monitors, and publishing the heads to an external ledger, are the
distribution layer (deferred to P3.3b); the append-only guarantee above does not depend on
them.

## How this is tested

`scripts/polaris-transparency-drill.py` proves the guarantee end to end under real
ML-DSA-65, two ways. First the detection engine: `verify_log_consistency` accepts an
append-only extension and rejects a rewrite, a fork, a shrink, and a stranger-signed head.
Then the productized monitor: a minimal log server serves signed heads and proofs over
HTTP, and the actual monitor daemon is run against it -- it exits 0 while the log only
appends, and alerts the moment the log is tampered. It runs every release in the
`pqc-real` CI job. Pinned by `check_transparency_log`; the RFC-6962 math is additionally
self-tested exhaustively across tree sizes with inclusion and consistency proofs and their
tamper-rejection.
