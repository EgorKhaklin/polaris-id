# 013 step 3: the checkpoint on an EVM chain (lab)

**2026-10-05.** Record [013](../013-public-chain-anchoring.md), plan item 3: the same checkpoint,
committed to an EVM chain as one transaction's calldata. Lab code; nothing in the product changes.

## What it is

[`evm_anchor.py`](evm_anchor.py), standard library only:

- `calldata`: the four bytes `PLRS` and the checkpoint's SHA-256, the only thing that leaves.
- The operator sends it in a transaction from a key they hold, with a wallet of their choosing
  (`cast send --account ...`, a keystore or a hardware wallet). No key passes through Polaris code,
  and gas is the operator's expense outside the system: no fee, balance or token enters the schema
  (C10).
- `record`: reads the transaction back from one source and refuses one whose calldata is not this
  checkpoint's; writes `polaris-evm-anchor/1` (chain id, transaction, block, digest).
- `verify`: two independent RPC sources must each return the transaction with exactly this
  calldata, a successful receipt in the block it names, the same block hash at that height, and at
  least `--confirmations` blocks on top (12 by default). The record is compared, never trusted.
- `controls`: the genuine anchor first (a verifier that refuses everything fails), then six cases
  that must each be refused.

## What it is not

The Bitcoin path recomputes a Merkle path from the digest to a block header and only takes the
header from outside. Here inclusion is **attested by the sources**: the verifier does not rebuild
the block's transactions trie. Two independent providers would have to lie the same way. That is a
weaker property than step 1's, written down rather than hidden. A local node removes the trust in
providers, as it does for Bitcoin.

## Run, 2026-10-05, on local chains (no money, no network)

Foundry's `anvil`: chain A; B, an independent node forked from A's history; C, a fresh chain with
the same chain id. The checkpoint is step 1's (`step1/checkpoint.json`, digest
`07f61b18…537747c3b2d`).

```
recorded: chain 31337, block 1
VERIFIED: chain 31337 block 1 (0xebeb3204…ad53f5245), 13 confirmations, agreed by 2 sources
  ok    the genuine anchor verifies
  ok    refused a tampered checkpoint
  ok    refused another transaction
  ok    refused another chain id
  ok    refused another block in the record
  ok    refused a single source
  ok    refused a source on a different history
RESULT: all 6 controls refused
```

The controls were mutated once: with the calldata comparison deleted, the tampered checkpoint was
accepted and `controls` reported `1 control(s) accepted`.

## Falsifiers (record 013, section 6), for this path

1. **One source is not a witness:** held on the local chains (a repeated source and a source on
   another history are refused). On a public chain it is held only by giving two providers that are
   in fact independent, or a local node.
2. **The record is not evidence:** held; every field is re-read from the sources.
3. **An outsider:** open, as for Bitcoin, and the stronger test here, because the first public EVM
   anchor needs a funded key.
4. **No new door:** held; nothing in the product changed.

## Next, and whose it is

A public testnet (Polygon Amoy or Ethereum Sepolia) needs faucet tokens in an address the owner
controls; a mainnet anchor on Polygon PoS costs a fraction of a cent of gas per checkpoint, paid
from that key. Both are the owner's decision. Until then the path is proven only on local chains.
