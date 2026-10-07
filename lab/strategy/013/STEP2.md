# 013 step 2: the product record, published and checked

Built 2026-10-04 for section 7, step 2 of
[013-public-chain-anchoring.md](../013-public-chain-anchoring.md), and reported against its
falsifiers in section 6.

## What was built

| Piece | Where |
| --- | --- |
| The record: append-only, digest derived from the checkpoint bytes, written only by the schema owner | `ChainAnchor` (01_schema.sql, migration 2026-10-04-001) |
| The verifier: the proof format read with the standard library, raw headers hashed and their work checked, two sources that must agree | `verify_chain_anchor` (packages/polaris-verify) |
| Recording, after deciding the anchor again | `polaris-id anchor-record` / `anchor-list` |
| Publication beside the heads | `GET /api/v1/transparency/anchors` |
| Building, deciding and monitoring | `scripts/polaris-chain-anchor.py checkpoint / verify / check` |

## Measured end to end

A copy of the test database step 1 anchored (its timestamp log at 194 entries, root
`75d95f79...`), with the migration applied and a local instance on it:

```
$ polaris-chain-anchor.py verify step1/checkpoint.json step1/checkpoint.json.ots --out anchor.json
ANCHORED: in Bitcoin block 969876, read from 2 source(s)
$ polaris-id anchor-record anchor.json
Recorded chain anchor #1: Bitcoin block 969876 (000000000000000000012d19498c55fdb7b676947e449b3cdb17dcc63e214d14)
$ polaris-id anchor-record anchor.json                         -> exit 1, already recorded
$ POLARIS_DB_USER=polaris_app polaris-id anchor-record anchor.json   -> exit 3, schema owner only
$ polaris-chain-anchor.py check --url http://127.0.0.1:5078      -> exit 0
  polaris-timestamp-log: size 194 extends the anchored 194
```

Then the log was changed twice, as its owner could:

| Change | `check` |
| --- | --- |
| One entry appended (195) | exit 0: "size 195 extends the anchored 194", by the consistency proof the instance served |
| One old entry rewritten, the owner disabling the append-only trigger to do it | exit 2: "size 195 does NOT extend the anchored size 194 (root 75d95f79...)" |

The second is the property: a history rewritten after its checkpoint went into a block is
caught by anyone holding that checkpoint, against a root that is in Bitcoin.

## Against the falsifiers

1. **One source is not a witness: held.** Two sources must return the same 80-byte header,
   which the verifier hashes and checks against its declared work; sources that disagree are a
   refusal. A caller's own node may stand alone only when the caller says so.
2. **The record is not evidence: held.** The verifier reads the checkpoint and the proof and
   nothing else the record carries; `test_the_record_s_own_block_fields_are_never_read` gives an
   anchor a false block height and header and gets the true block back.
3. **An outsider, or it stays in the lab: open until 2027-01-04.**
4. **No new door: held.** The application role reads `ChainAnchor` and cannot insert, update or
   delete (`TestChainAnchorRecord`, the C1 privilege test, the CLI's app-role refusal); the
   table is audit of record, attacked by the append-only and uniqueness sweeps like the others.
