# Algorithm migration

**Reader:** an engineer or an assessor. **Job:** How a token moves to a new signature algorithm without a gap in coverage.

Every post-quantum algorithm shipping today will one day be superseded, and
some of them will be broken rather than retired. A national token corpus
cannot answer that with simultaneous mass reissuance: at population scale
there is no moment when every holder can be reached at once.

So a token carries signatures from more than one algorithm during a transition
window. `TokenSignature` is the many-to-one resolution that makes that
possible, and the invariants below are what keep the window from becoming a
hole.

This is one of the three answers to issuer trust concentration, alongside
federation without transitive trust in [federation.md](federation.md) and the
revocation ceiling in [issuer-discretion.md](issuer-discretion.md).

## What it does not do

- **It does not choose algorithms.** The schema records which algorithm
  produced a signature. Which algorithms are credible is a decision for the
  agencies and the jurisdiction's cryptographic authority, the same posture C7
  takes throughout.
- **It does not cascade deprecation.** `CryptographicAlgorithm.deprecation_date`
  says an algorithm is end-of-life globally.
  `TokenSignature.deprecation_date` says one signature is no longer accepted.
  Setting the first does not touch the second: an operator drives each,
  deliberately.
- **It does not escrow keys.** Private signing keys are not held by the issuer
  after issuance, which MISSION.md states as a permanent non-goal.
- **It is not threshold signing.** Multiple signatures under different
  algorithms is a migration window. Multiple parties signing one thing is a
  different problem, and not this one.
- **It needs no separate migration log.** The `TokenSignature` row is the
  audit of record: append-only, with a one-way deprecation marker, so the
  migration trail lives in the row's own state.

## Two invariants

**Every token has at least one non-deprecated signature.**
`enforce_token_has_active_signature` fires after every insert, update and
delete on `TokenSignature`, counts the active signatures for the affected
token, and raises when the count is zero. It runs after the operation, so what
it checks is the state that would be committed.

**A signature row is write-once, and its deprecation is one way.**
`enforce_token_signature_immutability` refuses deletes outright, refuses
updates to the identity, algorithm, bytes or timestamp, and constrains
`deprecation_date` to move from NULL to a timestamp once, never back to NULL,
and never earlier. Later is allowed: extending a migration window is a
legitimate operator decision.

Together: signatures are immutable except for the deprecation marker, and no
token can end up without one.

## The ceremony

`uc6_migrate_algorithm` is the only sanctioned path.

```sql
CALL uc6_migrate_algorithm(
    p_token_id      => 42,
    p_new_algorithm => 2,        -- the incoming algorithm
    p_new_signature => <bytes>,  -- produced outside the database
    p_deprecate_old => FALSE     -- FALSE keeps both active for the window
);
```

It takes a transaction-scoped advisory lock on the token, so migrations of
different tokens stay parallel. It validates that the token exists and that
the incoming algorithm exists and is not itself deprecated. It inserts the new
signature row, where the unique constraint blocks a second signature under an
algorithm the token already carries. If asked to deprecate the outgoing
signature it sets the date a second in the future, because
`deprecation_after_signed` requires the deprecation to follow the signing and
a row can be milliseconds old. Both triggers then fire on the way out.

## Migration is one-way per token

The consequence of that unique constraint is worth stating rather than leaving
to be inferred, because it is the first thing an operator will look for and
not find. **A token can never hold a second signature under an algorithm it
has already used**, so there is no route back to a previous algorithm: not by
un-setting a `deprecation_date`, which `enforce_token_signature_immutability`
refuses, and not by calling the procedure again, which
`one_signature_per_algorithm_per_token` refuses whether or not anything was
deprecated.

So an authority that migrates a population from A to B and then learns B is
the problem cannot return it to A. The move available is sideways, to a third
algorithm that must already exist in `CryptographicAlgorithm`, have keys, and
not itself be deprecated at the moment it is needed. Provisioning that spare
before it is needed is a migration-planning prerequisite, not something the
schema can supply on the day.

This is intended rather than a limitation to be fixed. TokenSignature is the
audit of record for migrations, and a record you can walk back is not one.
Measured in [lab/crypto-migration/rollback.py](../../lab/crypto-migration/rollback.py),
which runs the four refusals and a positive control against a live schema.

## What a verifier sees during a migration

Verification reads the signatures where `deprecation_date IS NULL`. A verifier
and a migrator racing on the same token is the interesting case, and the
answer is that the verifier sees its own snapshot. Under PostgreSQL's default
read-committed isolation each statement sees what was committed when it
started; under repeatable read, which some verification paths take for a
stronger guarantee, the whole transaction sees the snapshot from its start.

`ConcurrencyTests.test_uc6_verification_snapshot_consistent_with_migration`
pins the contract: a verifier that reads the active set, does other work, and
reads again sees the same set both times, even though a migration committed in
between.

That is the correct semantic rather than a limitation. A verification that
began under one cryptographic regime should finish under it; the migration
takes effect for the next request.

## Why the partial index

`idx_token_signature_active` covers `token_id` where `deprecation_date IS
NULL`. The active set is one row normally and two during a window, while the
deprecated history accumulates for ever. Indexing only the active rows keeps
verification's cost flat as the history grows.

## Where the signatures come from

At issuance the application produces the signature and passes it in: a real
ML-DSA-65 signature when the deployment has real post-quantum signing on,
which both shipped production paths do, and a labelled deterministic value
otherwise. The public key that produced it is stored beside it.

A direct SQL caller that passes nothing falls back to a labelled placeholder,
which is what the seed data carries, so a developer loading the sample schema
still gets rows that satisfy the invariants. The labels are what keep the two
distinguishable: a placeholder announces itself rather than resembling a
signature. [token-signature.md](token-signature.md) covers that in full.

## Where an adversary ends up

- **The claim.** Every token has at least one signature under a
  non-deprecated algorithm, at all times.
- **The direct attack.** During a window, forge under whichever active
  algorithm is weaker.
- **Why that is bounded.** The active set is exactly the algorithms still
  considered credible. Once one is deprecated its signatures stop verifying,
  however many tokens carry rows under it, and the window is
  operator-controlled rather than open-ended.
- **The next attack.** Race the cutover: get a verification in flight under
  the old algorithm as it is deprecated. That is the snapshot semantics above,
  and the in-flight verification completing under the regime it started in is
  the intended behaviour.
- **What it costs.** During a window a verification reads two signatures
  instead of one, which the partial index keeps cheap, and the operator has to
  drive every token through the procedure, individually or in bulk.

The shift the scheme buys is from everything failing at once when an algorithm
breaks, to an orderly transition the operator paces. The schema makes the
orderly version possible; it does not perform it.

## The lock catalogue

| Ceremony | Lock key | What stays parallel |
|---|---|---|
| Revocation | per agency | different agencies |
| Recovery | per individual | different individuals |
| Migration | per token | different tokens |

Three granularities, one mechanism. [concurrency.md](concurrency.md) holds the
whole catalogue, and `docs/operator/SECURITY-CONTROLS.md` carries the
operator-facing view of a migration.
