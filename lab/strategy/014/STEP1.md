# 014 step 1: continuous re-signing as generations (lab)

**2026-10-05**, Apple M3, PostgreSQL 16, liboqs 0.15.0. [`precession.sql`](precession.sql) applied to a
lab database built the way CI builds one; [`precession_drill.py`](precession_drill.py) drives it.

## What was built (lab only)

- `TokenSignature` rows are identified by `(token_id, generation)`, not `(token_id, algorithm_id)`.
  Each row names its parent (the head it forked from) and its key, by reference, in an append-only
  key table indexed by the key's SHA-256.
- The existing rows become generation 1, and each credential that had already moved has its rows
  linked in signing order. The first run refused exactly this: the sample data holds credentials
  with two signatures, and "only a genesis has no parent" refused the second until it was linked.
- `precession_fork` is the one door. Under the per-credential lock it forks the next generation
  from the head, then retires every older generation after a grace period. The new row exists
  before anything is retired.
- Triggers keep the lineage and the key reference immutable, refuse a fork from anything but the
  head, and keep the key table append-only. The existing triggers (one-way deprecation, at least one
  signature with no deprecation, no DELETE) are unchanged.

## The churn

The run used 2,200 credentials and 8 passes, moving the whole population back and forth between
ML-DSA-65 and ML-DSA-87, each pass under a new key, with real signatures.

```
pass 1: ML-DSA-65 new key #1, 2.23s      pass 5: ML-DSA-65 new key #5, 2.32s
pass 2: ML-DSA-87 new key #2, 2.51s      pass 6: ML-DSA-87 new key #6, 2.57s
pass 3: ML-DSA-65 new key #3, 2.25s      pass 7: ML-DSA-65 new key #7, 2.31s
pass 4: ML-DSA-87 new key #4, 2.57s      pass 8: ML-DSA-87 new key #8, 2.57s
```

17,600 re-signings in 19.3 s: **952 per second on one runner** (signing 9.2 s, database 9.3 s),
generation 9 reached, 3,968 bytes per row with the key referenced rather than copied (about
9,800 bytes today, with the copy).

| Falsifier (014, section 6) | Result |
|---|---|
| 1. Nobody goes dark: the most credentials without a signature in force after any batch | **0** |
| ...and sampled heads verified by liboqs from the stored bytes and the referenced key | all |
| 2. History cannot be rewritten: edit a signature, a generation, a parent, a key reference; un-retire; delete | **6 of 6 refused** |
| ...fork from a generation that is not the head | refused |
| ...edit a registered key | refused |
| 3. Every head walks back to its genesis | **all**; none broken |
| 4. Not slower: at least 250 per second per runner | **952** |

**Mutation:** with the lineage trigger removed, editing a generation and a key reference were
accepted and the drill reported FAIL. Three earlier runs failed on the drill's own target choice
(a credential never churned, which made two "edits" no-ops); the target is now a churned
credential's retired generation, which makes each attempt a real change.

## Two findings beside the result

- **A key is identified by its fingerprint.** A unique index on the key itself fails for ML-DSA:
  1,952 bytes is 3,904 as hex, past the 2,704 bytes PostgreSQL indexes. The register indexes the
  SHA-256, which is also what a verifier quotes.
- **Re-signing is faster this way.** Today's quantum-event drill measures 310 per second per
  runner for one migration, and 952 here, partly because a row no longer carries the key.

## What this does not establish

- Lab only: no product route, CLI or verifier reads `generation` yet.
- The application role's grants are not measured here; #254 (TokenSignature written by the owner
  only) is the boundary this design keeps.
- One runner, and no issuance load alongside it.
- Falsifier 6 (an outside operator asking for rotation or rollback by 2027-03-12) is open.
