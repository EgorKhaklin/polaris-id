# Bulk enrollment

Roadmap P2.4. Onboarding an authority's existing population is the one workload
Polaris meets at a scale nothing else in the system does. Every other issuance
path is one person at a time through `uc1_issue_and_activate`. A migration is
millions of people, and running the single-issue path a million times is a
million round trips, a million transactions, and a million chances for a
partial failure to leave the import half done. This is the design that issues a
whole batch in one set-based transaction, with every row still passing the full
constraint set and the batch either landing whole or not at all.

## The shape

Two tables and one procedure, added by `2026-09-06-001-bulk-enrollment` and
present in the canonical schema:

```
BulkEnrollmentBatch     one row per import: the issuing agency, the algorithm,
                        a note, and (once issued) issued_at + rows_issued
BulkEnrollmentStaging   one row per person to enroll: the same fields uc1 takes,
                        plus scratch columns (individual_id, token_id) the
                        procedure fills in
```

`BulkEnrollmentStaging.batch_id` references the batch but does **not** cascade
from it. The audit rule is that nothing sweeps rows on a parent delete; staging
is cleaned explicitly by the operator when an import is done. A batch is one
issuing agency under one algorithm, which is the shape of a real migration and
is also what lets the authorization check run once for the whole batch instead
of once per row.

## Staging with COPY

An authority hands over an extract: a name, a date of birth, a jurisdiction, a
biometric type, the token value and physical serial of the blank credential,
and the contexts the credential may verify in. That extract is
batch-agnostic, so the operator stages it with `COPY` (the bulk-load path
Postgres is built for, not row-by-row `INSERT`) into a scratch table shaped as
exactly those columns, then attaches every staged row to a freshly created
batch. `polaris-id bulk-enroll` does this end to end from a pipe-delimited
file; the CI drill does it from a synthesized extract.

## Set-based issuance

`uc_bulk_issue(batch_id)` issues the whole batch in one transaction. It does
what `uc1` does, once for the batch and then set-based across every row:

1. **Authorize once.** The batch's agency must hold `ISSUE` or `BOTH` on the
   batch's algorithm in `AgencyAlgorithmAuth`, and the algorithm must not be
   deprecated. This is the same gate `uc1` applies per issuance; because a
   batch is one agency under one algorithm, it is checked once.
2. **Refuse a re-issue.** A batch whose `issued_at` is already set is refused,
   so replaying the same call cannot double-issue.
3. **Pre-assign the keys.** Every staged row is given an `individual_id` and a
   `token_id` from the real sequences up front, so the multi-table inserts that
   follow can correlate set-based instead of row by row.
4. **Insert through the full constraint set.** One `INSERT ... SELECT` per
   table builds the `Individual` rows, the `IdentityToken` rows in `RESERVE`,
   the `TokenSignature` rows, and the `ISSUED` lifecycle events. Every
   per-row trigger, foreign key, `CHECK`, and unique constraint fires exactly
   as it would for a single issuance: the token-value and physical-serial
   uniqueness, the M:N signature invariant, the append-only lifecycle seeding,
   the state machine.
5. **Activate.** One `UPDATE` moves the batch's tokens from `RESERVE` to
   `ACTIVE`. The audit trigger writes an `ACTIVATED` lifecycle row per token
   from the batch's agency, and the C3 partial unique index
   (`uq_one_active_per_person`) holds across the whole batch.

Because it is one transaction, a single violating row anywhere in steps 4 or 5
rolls back **every** row. The import is all-or-none: there is no state in which
half a batch is issued.

## New person, or a re-card

A staged `individual_id` left `NULL` is a first enrollment: the procedure
assigns a fresh id and creates a new `Individual`. A staged `individual_id`
that is set correlates the row to a person who already exists, which is a
re-card (issuing a new credential to someone already in the registry). The
procedure honors a set id and does not insert a duplicate `Individual` for it.

This is also what makes C3 reachable across a batch, and worth stating plainly:
C3 is one active token per person. A re-card of someone who still holds an
active token, or two staged rows for the same person, produces two active
tokens for one individual, which the partial unique index rejects at
activation, which rolls the batch back. A re-card is therefore only valid once
the person's prior token is no longer active (lost, revoked, or expired);
retiring the old credential is a separate, audited operation, not something the
bulk path does silently. The bulk path does not revoke anything.

## Throughput

Set-based issuance is the point, so it is measured, not asserted. On the
development database at v9.247, 5000 records staged by `COPY` and issued through
`uc_bulk_issue` in about 1.1 seconds, roughly 4500 rows per second, every token
active, signed, and event-logged. That number is hardware-specific and will
differ on production storage; the CI drill re-measures it on every push and
fails only if the rate falls under a deliberately low floor, which is a guard
against a catastrophic regression rather than a benchmark to defend.

## What proves it

`scripts/polaris-bulk-drill.sh` runs on every push (the `product-test` job). It
stages 5000 records with `COPY`, issues them and asserts every row is active,
signed, and carries an `ISSUED` and an `ACTIVATED` event over the rate floor,
and then proves the batch is all-or-none and correctly gated:

- a single duplicate physical serial rolls the whole batch back (atomicity);
- two staged rows for one person roll the whole batch back (C3 across the
  batch);
- an already-issued batch, an agency without `ISSUE` on the algorithm, and an
  empty batch are each refused with the exact error.

Every test runs inside a transaction that is rolled back, so the drill mints no
tokens: their append-only lifecycle events could not be cleaned up afterward,
and a drill that leaves state behind is not one you can run on every push. The
mechanism is pinned by `check_bulk_enrollment`, and the operator path by the
`bulk-enroll` cases in the CLI suite.

## Scope

It is not a general import-any-shape tool. One batch is one agency under one
algorithm, the extract columns are fixed, and correlation to an existing person
is by explicit id, not by fuzzy matching on name or date of birth. It does not
retire prior credentials, and it does not relax any constraint for the sake of
volume: a row that `uc1` would reject is a row `uc_bulk_issue` rejects, and it
takes the batch down with it. Onboarding a population is exactly a million
single issuances made atomic and fast, and nothing more permissive than that.
