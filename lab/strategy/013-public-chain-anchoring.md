# 013: Anchoring the transparency logs on a public chain

**Opened 2026-10-04.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md),
on the owner's direction of 2026-10-04: an interest in blockchain integration, choosing "anchor the
audit log on-chain" over trusting chain-based issuers by DID and a bridge to another identity
network's zero-knowledge stack. State: OPEN. The falsifiers in section 6 were written before the build.
Step 1 passed on 2026-10-04 ([013/STEP1.md](013/STEP1.md)): Bitcoin block 969876. Step 2, the
product record, built the same day ([013/STEP2.md](013/STEP2.md)); falsifiers 1, 2 and 4 held.

---

## The finding that started it

[anchoring.md](../../docs/design/anchoring.md) closes audit rows into `AnchorBatch` Merkle roots and
says the operator "publishes the root, with per-leaf proofs, to whatever external ledger they have
chosen", reserves `committed_to_chain`, `external_chain` and `external_chain_tx` for the record, and
adds: "Nothing writes them yet ... Until an operator has chosen a ledger there is nothing to design it
against." [transparency-log.md](../../docs/design/transparency-log.md) publishes three RFC 6962 logs
(audit anchors, exchange receipts, timestamps) as signed tree heads and has witnesses cosign them,
K of N, against a split view.

Two walls, read from the schema on 2026-10-04:

- `AnchorBatch` is an audit-of-record table: its rows are append-only at the database, so the three
  reserved columns can never be set after a batch closes. They cannot hold the record.
- `external_chain` admits only `ALGORAND_PQ`, `HYPERLEDGER_INDY` and `CUSTOM_LATTICE`; no public chain
  an outsider can read without an account is among them.

- **Kept:** the schema is the audit of record; only commitments leave, never data; publishing is an
  operator action that the schema records rather than performs; the witnesses.
- **Dropped:** "nothing to design against"; the reserved `AnchorBatch` columns as the place to record
  a publication.
- **New position:** at the operator's cadence, one checkpoint over the three logs' signed tree heads
  is committed to a public chain as a single hash. The proof of that commitment is kept in a new
  append-only record and published beside the heads, and anyone can check it with a script and a
  public source of block headers. The chain witnesses the log; it holds nothing about anyone.

## 1. What capability is being considered?

- **The checkpoint.** A canonical JSON object listing each log's canonical tree-head statement
  (`format`, `log_id`, `tree_size`, `root_hash_hex`, `timestamp`, the statement the head's signature
  covers), hashed with SHA-256.
- **Bitcoin, through OpenTimestamps.** The digest goes to public OpenTimestamps calendars, which
  aggregate many digests into one Bitcoin transaction. It needs no key, account or fee. The proof is
  pending until a Bitcoin block includes the calendar's commitment, usually within hours, and is then
  upgraded to a path from the digest to that block's Merkle root.
- **Optionally an EVM chain** (Polygon PoS, Base, Ethereum): a transaction whose calldata is the
  digest, from a key the operator holds and funds. Gas is the operator's expense, outside the system.
- **The record.** A new append-only table of anchors (tree sizes, the digest, the chain, the block or
  transaction reference, the proof bytes), written by an operator-only procedure the application
  role cannot call.
- **The verifier.** A script that takes a published head, or any leaf with its inclusion proof, and the
  anchor proof. It recomputes the digest and the path to the block, and compares the block header from
  a local node or from two independent public sources that must agree. It never reads the database
  record as evidence.

## 2. What problem would it solve?

Today an outsider can check that the logs only grew, but only between heads they themselves saw, or
through cosignatures from witnesses who have to be recruited and trusted. Once a checkpoint's digest
is in a Bitcoin block, the operator cannot later present a different history for that moment without
the conflict being provable by anyone holding the earlier head and its anchor. A public chain is a
witness nobody has to recruit.

It does not establish that what was logged is true, and it adds nothing to verifying a credential,
which stays offline against published keys. No chain enters a credential's trust path.

## 3. Who needs it?

The owner's direction, and the class it serves: an auditor, regulator or relying party who must
check an operator's audit history without trusting the operator or the witnesses the operator chose.
No outside party has asked for it. That is recorded here, not assumed away.

## 4. What already solves it?

- RFC 3161 time-stamping authorities: a signed timestamp that requires trusting the authority.
- Sigstore Rekor: a transparency log run by a foundation, which is another log to trust.
- Witness cosigning, which Polaris already has: it requires recruiting independent witnesses.
- OpenTimestamps: the established, open way to put a hash into Bitcoin without keys or fees. It is
  what this record would use, not reinvent.

## 5. Constraints this must keep

- **No personal data on any chain.** Only the checkpoint digest leaves, and it reveals nothing beyond
  the log sizes and roots the heads already publish.
- **C10, identity is not money.** No balance, fee, token or price enters the schema; an EVM anchor's
  gas is an operator expense outside it.
- **Algorithm honesty.** The digest is SHA-256 because OpenTimestamps operates on SHA-256; the heads
  themselves stay SHA3-256 under the instance's signature. What secures the commitment is the chain's
  accumulated history, not its transaction signatures, and the record says so rather than claiming a
  quantum property it does not have.
- **The application role gains no write.** A compromised application must not be able to record an
  anchor; the verifier must not need the record to be honest.

## 6. Falsifiers, written before the build

1. **One source is not a witness.** If an anchor cannot be verified without trusting a single calendar
   or a single block explorer, the property is not delivered. The verifier must succeed from a local
   node or from two independent header sources that agree, and must refuse a tampered head, a tampered
   proof and a proof pointing at the wrong block.
2. **The record is not evidence.** If a database row can make the verifier report an anchor the chain
   does not hold, the design fails.
3. **An outsider, or it stays in the lab.** If no party other than the author verifies a published
   Polaris anchor by 2027-01-04, the product wiring is frozen and the capability returns to lab/.
4. **No new door.** If the new table breaks an audit-of-record invariant or gives the application role
   a write it lacked, stop.

## 7. Plan

1. **Lab (now).** `lab/strategy/013/`: build a checkpoint over the three heads of a running instance,
   stamp it through OpenTimestamps, upgrade it once Bitcoin confirms, and verify it against two
   independent block-header sources, with the falsifier 1 controls. Recorded in `013/STEP1.md`.
2. **Product.** The append-only anchor table with its migration pair, append-only trigger, grants,
   checks and detection tests; the operator-only recording procedure; an operator script to stamp,
   upgrade and record; the verifier script; an endpoint publishing anchor proofs beside the heads; and
   updates to anchoring.md and transparency-log.md.
3. **An EVM chain (optional).** Needs an operator-funded key. Testnets need faucet tokens, which are
   the owner's to obtain.
