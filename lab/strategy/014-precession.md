# 014: Precession, re-signing a credential as often as it has to move

**Opened 2026-10-05.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md),
on the owner's direction of 2026-10-05: algorithm migration must work "perfectly, securely and
without problems" across many migrations between many algorithms, continuously if need be. State:
OPEN. The falsifiers in section 6 were written before the build.
Step 1 (lab) passed on 2026-10-05 ([014/STEP1.md](014/STEP1.md)): 2,200 credentials moved back and
forth between ML-DSA-65 and ML-DSA-87 eight times, a new key each pass, nobody dark, history
immutable, every lineage whole, 952 re-signings per second per runner.

The name: the celestial pole is not fixed. Precession moves it from star to star, which is why
Polaris is the pole star now and will not always be. A credential's signature has to be able to
move the same way, as often as the cryptography under it changes, without the holder ever standing
on nothing. Each re-signing is a **genesis fork**: a new generation of the credential's signature,
whose lineage runs back to the signature it was issued with (its genesis).

---

## The finding that started it

Measured on 2026-10-05 (`MigrationChainPropertyTests` in `polaris_web/test_app.py`, and the
quantum-event drill):

- **Migration works, once per algorithm.** Random sequences of per-credential and population
  migrations, grace windows and refusals keep every promise of QUANTUM-EVENT.md under real
  ML-DSA, and the drill re-signs 2,000 credentials at 310 per second on one runner with nobody
  ever unverifiable.
- **It cannot happen twice under one algorithm.** `TokenSignature` is append-only and unique on
  `(token_id, algorithm_id)`. A credential that moved from ML-DSA-65 to ML-DSA-87 can never return
  to 65, and with two signers wired today it can move at most once.
- **So three operations are impossible today:**
  - **Rollback.** If the target turns out to be the weaker choice, the credentials that left
    cannot go back.
  - **Key rotation for existing credentials.** A compromised authority key under ML-DSA-65 cannot
    be replaced by a new 65 key on the credentials it signed. KEY-CEREMONY.md removes the anchor,
    and those credentials read invalid until they are re-issued.
  - **Continuous migration.** Moving a population again and again ("migrate, migrate, migrate")
    is refused after the first move.

## 1. Thesis, antithesis, synthesis

- **Thesis (today).** One signature per algorithm, append-only. The audit is simple, a
  signature never changes, and a duplicate is a constraint violation, not a judgment call.
- **Antithesis.** Cryptography does not move once. Keys are rotated, and compromised keys are
  replaced. A migration may need to be undone. A design that allows one move per algorithm turns
  the second event into a mass re-issuance, which is the outcome migration exists to avoid.
- **Synthesis.** Keep everything the thesis gets right: append-only rows, one-way deprecation,
  at least one signature in force at every instant, the window that cannot close early. Change
  only the identity of a signature, from *(credential, algorithm)* to
  *(credential, algorithm, generation)*. A generation is minted by a fork from the credential's
  current generation and is never edited or reused, so any number of moves is possible,
  including back to an algorithm used before and under a new key for the same algorithm. Every
  generation names its parent, so the lineage back to genesis is a query, not a reconstruction.

## 2. Who needs it

The operator class QUANTUM-EVENT.md and KEY-CEREMONY.md are written for: an authority that has to
move its population when an algorithm weakens, rotate a key on schedule, and replace a
compromised key without re-issuing every credential it signed. No outside party has asked for it
yet. That is recorded here, not assumed away.

## 3. What already solves it

- **Re-issuance.** It works, and it costs every holder a new credential and the authority an
  enrolment-scale operation. Precession leaves it as the path for a credential that must change
  for reasons other than its signature.
- **Certificate renewal in PKI.** Renewal mints a new certificate and keeps the old one valid
  until expiry. A genesis fork is the same pattern, applied to the credential's signature, with
  an append-only lineage that a renewal chain does not keep.

## The ten questions, briefly

1. **Capability:** re-signing a credential any number of times, under any algorithm and key, as
   append-only generations (section 1).
2. **Problem:** rollback, key rotation and replacement of a compromised key for existing
   credentials, and repeated migration, are impossible today (the finding).
3. **Who:** an authority's operators (section 2).
4. **Existing systems:** re-issuance; certificate renewal (section 3).
5. **Interoperate instead?** Nothing outside changes: a wallet still presents one signature, and a
   verifier still checks one signature against a published key. The change is inside the issuer.
6. **Advantage:** a credential whose signature can follow the cryptography for its whole life,
   with a lineage anyone can audit back to issuance. That is the system's central claim made
   operable rather than one-shot.
7. **If not built:** the second cryptographic event in a credential's life (a key rotation, a
   compromise, a reversed migration) means re-issuing the population.
8. **Delayed:** the SLH-DSA signer and OID4VCI batch issuance (both in the proposed-items list).
   Precession goes first because both of them add algorithms or signatures that it lets a
   credential move between.
9. **Cheap lab test first?** Yes: section 5, step 1, on a scratch database.
10. **What proves it wrong:** section 6.

## 4. Constraints it must keep

- C1: `TokenSignature` stays append-only. A fork adds a row; deprecation stays one-way.
- At least one generation in force at every instant: the existing trigger, extended to
  generations.
- The window cannot be closed while any credential lacks a generation under the target.
- The application role gains no write. The population runner stays owner-only, as the
  TokenSignature follow-up makes it.
- A generation is signed by a key registered for its algorithm at its signing time (#248's rule).

## 5. Plan

1. **Lab.** Measure the schema change on a scratch database, together with the storage fix
   [lab/crypto-migration/CANDIDATES.md](../crypto-migration/CANDIDATES.md) found (a signature row
   names its key in the append-only key register instead of carrying a copy: 313 TB for UOV at
   350 million credentials, 3.4 TB for ML-DSA-87). Measure: a `generation` column and its
   parent, the unique key on `(token_id, algorithm_id, generation)`, and the extended triggers.
   Re-run the property test and the drill with rollback, key rotation and continuous churn added
   to the operations.
2. **Churn drill.** Move a population back and forth between ML-DSA-65 and ML-DSA-87, each pass
   under a new key, continuously for a fixed time. Sample the count of unverifiable holders, and
   the relying-party door, during every pass. Report passes per minute and credentials re-signed
   per second per runner.
3. **Product**, only if the lab holds: the migration pair, the check that pins the generation
   rule, KEY-CEREMONY.md's compromise path rewritten from "re-issue" to "fork under the new key",
   and the paper's map.

## 6. Falsifiers, written before the build

1. **Nobody goes dark.** If the churn drill ever samples a holder with no generation in force,
   at any instant of any pass, the design fails.
2. **History cannot be rewritten.** If any generation can be edited, deleted or un-deprecated, by
   the application role or by the procedures, the design fails.
3. **The lineage is total.** If any generation's chain does not reach the credential's genesis
   signature, the design fails.
4. **It is not slower.** If one runner re-signs fewer than 250 credentials per second under real
   ML-DSA (today: 310), the cost of generations is too high and the design is reworked.
5. **No new door.** If the change gives the application role a write it lacked, stop.
6. **Kill date.** If no operator outside the project has asked for key rotation or rollback of
   existing credentials by 2027-03-12, the product step is not taken and this stays a lab result.
