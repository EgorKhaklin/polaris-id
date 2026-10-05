# One population, seven signature families

**Measured 2026-10-05** with [`candidate_chain.py`](candidate_chain.py) on an Apple M3, liboqs
0.15.0 (liboqs-python 0.16.0), PostgreSQL 16, 200 credentials.

**The question:** does the migration path (`uc6_migrate_algorithm`, its one-way deprecation and
the rule that a credential always keeps a signature in force) survive algorithms whose shapes
differ by orders of magnitude? This is lab work. The product's accepted signers are code and stay
ML-DSA; nothing here admits a candidate, and most of these are candidates in NIST's
additional-signature process that could still be broken.

**The answer:** yes. The same 200 credentials moved through every family below, each hop signed
with a fresh authority key and the previous signature deprecated. After every hop no credential
stood without a signature in force, every signature in force verified under liboqs from the
stored bytes and key alone, and a signature with one flipped byte was refused.

| Algorithm | Family | Standing | Public key | Signature | Sign | Verify | Database per credential | Result |
|---|---|---|---:|---:|---:|---:|---:|---|
| ML-DSA-87 | ML-DSA | FIPS 204 | 2,592 B | 4,627 B | 0.49 ms | 0.19 ms | 1.08 ms | OK |
| Falcon-1024 | FN-DSA | FIPS 206 (draft) | 1,793 B | 1,277 B | 0.41 ms | 0.10 ms | 0.93 ms | OK |
| SLH-DSA-SHA2-256s | SLH-DSA | FIPS 205 | 64 B | 29,792 B | 814 ms | 1.13 ms | 4.07 ms | OK |
| MAYO-5 | MAYO | additional signatures, round 2 | 5,554 B | 964 B | 0.99 ms | 0.38 ms | 1.27 ms | OK |
| OV-V-pkc | UOV | additional signatures, round 2 | 446,992 B | 260 B | 0.59 ms | 1.13 ms | 27.92 ms | OK |
| SNOVA-56-25-2 | SNOVA | additional signatures, round 2 | 31,266 B | 178 B | 3.06 ms | 1.63 ms | 4.80 ms | OK |
| CROSS-RSDP-256-balanced | CROSS | additional signatures, round 2 | 153 B | 53,527 B | 4.05 ms | 1.88 ms | 2.05 ms | OK |

Times are medians per credential, at NIST security category 5 for every family.

## What it found

**1. The storage layout does not survive large keys.** Every signature row stores the signing
public key beside the signature (as hex), so verification is self-contained and survives the
retirement of a key. For ML-DSA that costs about 9.8 KB per credential per signature, or 3.4 TB
at 350 million credentials. For UOV, whose public key is 447 KB, it is 894 KB per credential:
**313 TB**. SNOVA reaches 22 TB, CROSS 19 TB and SLH-DSA 10.5 TB. The fix keeps the property and
drops the copy. The authority key is already recorded once, append-only, in the key register
(`AuthorityKeyEvent`), so a signature row can name the key it was made with instead of carrying
it. Verification still needs nothing that can change. That change belongs with record 014
(Precession), which reworks the signature row anyway.

**2. FN-DSA is the most compact standardized family.** It has the smallest signature (1,277 B),
the smallest stored footprint (4.9 KB per credential, 1.7 TB at 350 million) and the fastest
verification of all seven: the case for adopting it, opt-in while FIPS 206 is a draft, in a
decision record of its own.

**3. SLH-DSA's cost is signing time, not database time.** At 814 ms per signature, one runner
re-signs about 1.2 credentials per second, where ML-DSA-87 does about 310. A hash-based migration
has to be planned in parallel runners, or with the faster `f` parameter sets, which trade
signature size for signing speed.

**4. Returning is refused.** Moving back to ML-DSA-87 after leaving it fails on
`one_signature_per_algorithm_per_token`: the reason for record 014.

## Not measured here

- **FAEST, SQIsign, MQOM, SDitH, QR-UOV, HAWK, LESS, Mirath, PERK and RYDE** are candidates that
  liboqs 0.15.0 does not carry. Building their reference implementations means running unvetted
  code, which belongs in a pinned, isolated container; until then they are unmeasured, not
  passed.
- **What is not stated:** these numbers say nothing about any candidate's security, nothing about
  side channels (FN-DSA's floating-point signing in particular), and nothing about an
  implementation outside liboqs.
