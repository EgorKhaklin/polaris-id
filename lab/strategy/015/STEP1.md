# 015 step 1: the two witnesses agree (lab)

**2026-10-05**, Apple M3, liboqs 0.15.0 (liboqs-python 0.16.0), `@noble/post-quantum` 0.7.1 (the
version the TS SDK's lockfile pins), Node 24.

[`witness_agreement.py`](witness_agreement.py) runs liboqs in Python and `@noble/post-quantum` in
Node ([`noble_witness.mjs`](noble_witness.mjs)), on random 32-byte digests (the shape Polaris signs:
SHA3-256 of a token value), with a fresh key per message.

| liboqs | noble | liboqs signs, noble verifies | noble signs, liboqs verifies | flipped byte refused by both | other side's key refused by both |
|---|---|---:|---:|---:|---:|
| Falcon-512 | falcon512 | 20/20 | 20/20 | 20/20 | 20/20 |
| Falcon-1024 | falcon1024 | 20/20 | 20/20 | 20/20 | 20/20 |
| Falcon-padded-512 | falcon512padded | 20/20 | 20/20 | 20/20 | 20/20 |
| Falcon-padded-1024 | falcon1024padded | 20/20 | 20/20 | 20/20 | 20/20 |
| SLH-DSA-SHA2-128f | slh_dsa_sha2_128f | 20/20 | 20/20 | 20/20 | 20/20 |
| SLH-DSA-SHA2-128s | slh_dsa_sha2_128s | 2/2 | 2/2 | 2/2 | 2/2 |
| SLH-DSA-SHA2-192f | slh_dsa_sha2_192f | 20/20 | 20/20 | 20/20 | 20/20 |
| SLH-DSA-SHA2-256f | slh_dsa_sha2_256f | 20/20 | 20/20 | 20/20 | 20/20 |
| SLH-DSA-SHA2-256s | slh_dsa_sha2_256s | 2/2 | 2/2 | 2/2 | 2/2 |
| SLH-DSA-SHAKE-128f | slh_dsa_shake_128f | 20/20 | 20/20 | 20/20 | 20/20 |
| SLH-DSA-SHAKE-256f | slh_dsa_shake_256f | 20/20 | 20/20 | 20/20 | 20/20 |

**Falsifier 1 held:** no disagreement on any variant. The slow "s" sets ran two messages each, about
a second per SLH-DSA signature in each library. **Mutation:** with Falcon-512 paired against
noble's Falcon-1024, every count fell to 0 and the run reported the variant as not to be wired.

## What this does not establish

- **Two implementations agreeing is not either being correct.** They are independent (C and
  TypeScript, different authors), which is why agreement is evidence; a published known-answer set
  for each standard is the next check, as ML-DSA has Wycheproof.
- **FN-DSA here is Falcon as both libraries ship it, ahead of FIPS 206's final text.** Falsifier 4
  (draft drift) stays open until the standard is final and both libraries track it.
- **Nothing about timing.** Falsifier 2 (FN-DSA's signing path shown constant-time on the
  deployment's platforms) is the next lab step, and FN-DSA is not wired until it holds.
