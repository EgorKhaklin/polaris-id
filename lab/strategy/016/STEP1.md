# 016 step 1: what verifiers can link, measured (lab)

**2026-10-05.** [`linkage.py`](linkage.py) builds real wallet copies with
`polaris_web/wallet_copy.py` and the test PKI, and gives each of eight verifiers one presentation
disclosing only `age_over_18`: the smallest request there is.

| Observable a verifier keeps | A: one copy (today) | B: a batch, one copy per verifier |
|---|---|---|
| Holder key (`cnf`) | same at every verifier | differs |
| Status index | same at every verifier | differs |
| Signature | same at every verifier | differs |
| `iat` | same (to the second) | same (rounded to the day) |
| `exp` | same | same (the day's policy) |
| Disclosed value | same | same |
| Issuer | same | same |

**Today**, the eight verifiers can join their records on five values (holder key, status index,
signature, and the exact `iat` and `exp`) while having learned nothing but "over 18". **With a
batch**, they share only the issuer, the day and the answer, which every holder issued that day
with the same answer shares.

**Falsifier 1 held:** no two copies in the batch share a key, an index or a signature, and no
timestamp is finer than the day. **Mutation:** with one holder key reused across the batch, the
run reports falsifier 1 FAILED.

## What this does not establish

- **Only what the copy carries.** A verifier that also logs IP addresses, times or device
  fingerprints links by those; that is outside the credential.
- **The crowd's size.** A day-rounded `iat` hides a holder among the copies issued that day, so the
  privacy depends on how many there are. That is measured when there is a population, not here.
- **Revocation across a batch (falsifier 2) and the mapping's confinement (falsifier 3)** need the
  product path; they are step 2.
