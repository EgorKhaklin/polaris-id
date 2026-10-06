# 013 step 1: a checkpoint of the transparency logs in a Bitcoin block

Measured 2026-10-04 for section 7, step 1 of
[013-public-chain-anchoring.md](../013-public-chain-anchoring.md), and reported against its
falsifiers in section 6. No product file was changed.

## Result

The checkpoint over a test instance's three signed tree heads is in **Bitcoin block 969876**
(hash `000000000000000000012d19498c55fdb7b676947e449b3cdb17dcc63e214d14`, block time
2026-10-04T17:01:00Z). The proof path runs through the alice.btc.calendar.opentimestamps.org
calendar's transaction `c851874e01ea6091f1aef411acb35ccf7397787efc0ab86c279363ffb64f1268`.

```
$ python anchor.py verify step1/checkpoint.json step1/checkpoint.json.ots
ANCHORED: in Bitcoin block 969876 (000000000000000000012d19498c55fdb7b676947e449b3cdb17dcc63e214d14, time 1791133260), read from 2 independent sources
$ python anchor.py controls step1/checkpoint.json step1/checkpoint.json.ots
  ok     a checkpoint with one byte changed: the proof does not open: the proof is for digest 07f61b18..., not this checkpoint's 3cb82789...
  ok     the proof with one operation changed: block 969876's Merkle root is 970129be..., and the proof computes c89807c7...
  ok     the next block instead of the attested one: block 969877's Merkle root is bfa2daa3..., and the proof computes 970129be...
controls: every one refused
```

## Files

| File | What it is |
| --- | --- |
| `step1/heads.json` | The three signed tree heads as the instance served them at 2026-10-04T16:30:22Z. |
| `step1/checkpoint.json` | The checkpoint: the canonical JSON of the three statements those signatures cover (676 bytes, SHA-256 `07f61b18cb2b4e8367637f5a2cc1756500da1d7ea64806c98818c537747c3b2d`). |
| `step1/checkpoint.json.ots` | The OpenTimestamps proof, upgraded: an 80-operation path from that digest to block 969876's Merkle root, plus the pending branches of the three other calendars. |

## Timeline

| Time (UTC) | Event |
| --- | --- |
| 16:30:22 | The three heads are read from the instance; the checkpoint is built. |
| 16:32 | `ots stamp`: the digest goes to four public calendars, with no key, account or fee. |
| 17:01:00 | Block 969876 includes the alice calendar's transaction. |
| 17:43 | Two calendars report their transactions, waiting for 6 confirmations. |
| 17:53 | `ots upgrade` completes the proof; `verify` and `controls` pass on the first complete proof. |

From stamp to a proof anyone can check took 81 minutes, most of it the calendar's wait for six
confirmations.

## Against the falsifiers

1. **One source is not a witness: held.** `verify` does not use the OpenTimestamps client's
   verdict. It replays every operation of the path itself and reads the block from
   blockstream.info and mempool.space, which agreed on the block hash and Merkle root. It
   refused a checkpoint with one byte changed, a proof with one operation changed and the
   block after the attested one. Before our own stamp confirmed, the same verifier confirmed
   OpenTimestamps' published example proof (`hello-world.txt.ots`, block 358391) from both
   sources.
2. **The record is not evidence: not yet tested.** There is no record yet; that is step 2.
3. **An outsider, or it stays in the lab: open until 2027-01-04.** This anchor is the first one
   an outsider can check: `pip install -r requirements.txt`, then the two commands above.
4. **No new door: not yet tested.** Step 2.

## What this does not show

- **The heads are from a test instance.** It ran on this machine with the development signer,
  so `heads.json` carries placeholder signatures that authenticate nothing. The step tests the
  anchoring, not the instance's key.
- **Two public explorers are two sources, not a node.** A verifier with its own Bitcoin node
  should compare against it; the step-2 verifier takes block headers from a node or from
  sources the caller names.
- **The explorers' JSON is trusted for the Merkle root.** Step 2 reads the raw 80-byte header
  instead, computes the block hash and checks its proof of work itself.
