# Concurrency

**Reader:** an engineer or an assessor. **Job:** Every race-prone path, the lock that serialises it, and the test that proves it.

C9 says race-prone paths are tested with real threads rather than asserted in
prose. This is the inventory behind that: every hazard, the mechanism that
holds it, and the test that proves the mechanism works. It is the document to
read before changing anything in `05_procedures.sql`, in
`security.py::authenticate`, or on any path that touches
`IdentityToken.status`.

## The hazards

| # | Scenario | Without the protection | Protection | Test |
|---|----------|----------------|------------|------|
| 1 | Two parallel UC-1s for the same individual | Both create new Individual rows + tokens. Not really a race; data quality issue. | None needed: UC-1 always creates a fresh Individual | n/a |
| 2 | Two parallel UC-1s for DIFFERENT individuals | Independent rows, no conflict | None needed | n/a |
| 3 | Two parallel UC-4s on the same `(lost_token, reserve_token)` pair | Idempotent: both T1 and T2 transition lost→LOST, both UPDATE reserve→ACTIVE. Final state correct; double `RevocationList` entry possible. | `SELECT FOR UPDATE Individual` serializes UC-4 per holder; second observer sees post-T1 state | `ConcurrencyTests.test_partial_unique_index_blocks_double_active` (related) |
| 4 | Two parallel UC-4s activating DIFFERENT reserves of same holder | Both could win, because `activation_sequence=2` was hardcoded. Could leave holder with two ACTIVE tokens *briefly*: partial unique index fired only when both tried final UPDATE. | Same `FOR UPDATE` lock + partial unique index `uq_one_active_per_person` | `test_partial_unique_index_blocks_double_active` |
| 5 | Manual UPDATE of `IdentityToken.status='ACTIVE'` for a holder who already has one | Allowed → "two active tokens" violation | Partial unique index `uq_one_active_per_person` (DB-level) | `test_partial_unique_index_blocks_double_active` |
| 6 | Concurrent failed logins for same user | Lost increments through a read-then-write window; the lockout is bypassable. | Atomic `UPDATE … SET col = col + 1 RETURNING` | `test_failed_login_count_is_atomic_under_concurrent_load` |
| 7 | Threshold-crossing concurrent failed logins both apply lockout | Each writes `locked_until = now + lock_min`, doubling the lockout interval | `WHERE locked_until IS NULL` predicate on the lockout UPDATE | covered by atomic-increment test |
| 8 | Concurrent INSERTs into `TokenLifecycleEvent` | None: append-only by design, no conflicts | DB-level append-only (no shared row state) | n/a |
| 9 | Verification event arrives during a token revocation | The verification reads pre-revocation state and succeeds | Acceptable by design: verifications are point-in-time. Token state at verification was valid. | n/a |

---

## What the partial unique index actually protects

```sql
CREATE UNIQUE INDEX uq_one_active_per_person
    ON IdentityToken (individual_id)
    WHERE status = 'ACTIVE';
```

This is a **partial** unique index: it only enforces uniqueness on
rows where `status = 'ACTIVE'`. So a holder can have:

- 1 ACTIVE
- N RESERVE  (any number, no constraint)
- N DORMANT
- N REVOKED, LOST, EXPIRED  (terminal states, all permitted)

The moment two transactions both try to set `status='ACTIVE'` for the
same `individual_id`, exactly one succeeds. The other gets:

```
ERROR: duplicate key value violates unique constraint "uq_one_active_per_person"
DETAIL: Key (individual_id)=(N) already exists.
```

In the application, this surfaces as `psycopg2.errors.UniqueViolation`
which `db_error_to_message()` translates to a user-friendly message.

---

## Why `SELECT FOR UPDATE` instead of `SERIALIZABLE`

Three options were considered:

1. **Optimistic**: let the partial unique index reject conflicts;
   handle `UniqueViolation` in the app. Pro: no lock contention.
   Con: error surface complicated by the activation_sequence race
   (which the unique index doesn't catch, because seq is just a number,
   not constrained).

2. **`SERIALIZABLE` isolation**: let Postgres detect serialization
   anomalies and retry. Pro: clean. Con: requires retry logic in every
   caller; `psycopg2` doesn't auto-retry; and the failure mode is a
   late `SerializationFailure` exception which is harder to map to a
   domain error than a clean `UniqueViolation`.

3. **`SELECT FOR UPDATE` row lock** (chosen): explicitly serialize on
   the holder row at the start of the procedure. Pro: deterministic;
   second writer observes post-T1 state and re-validates; no retry
   needed. Con: lock contention if many UC-4s for same holder fire
   simultaneously, but in practice UC-4 is rare (a holder reports a
   lost token once a year at most).

Option 3 also makes the `activation_sequence` race trivial to fix:
compute MAX inside the locked region.

---

## Why the auth atomic increment matters

The pre-v6 pattern was a textbook TOCTOU:

```python
new_count = user['failed_login_count'] + 1     # T  read N
# ... time passes, OTHER transaction reads N too ...
cur.execute("UPDATE … SET failed_login_count=%s …", (new_count,))   # write N+1
```

Two simultaneous failed logins both read `N`, both wrote `N+1`. Lost
increment. Concrete consequence: an attacker spammed parallel failed
logins; the counter never crossed the lockout threshold; brute force
was unrate-limited above the configured threshold.

The fix is the standard atomic-counter pattern:

```python
cur.execute(
    "UPDATE AppUser SET failed_login_count = failed_login_count + 1 "
    "WHERE user_id = %s RETURNING failed_login_count", (uid,))
new_count = cur.fetchone()['failed_login_count']
```

`UPDATE … SET col = col + 1` resolves under row-level lock in
PostgreSQL; both transactions queue at the lock; both see the correct
post-increment value via `RETURNING`.

---

## What is deliberately unprotected

- **Verification event ordering** doesn't matter. Two parallel
  verifications can interleave freely; each is an independent
  append-only fact about a point in time.

- **Lifecycle event ordering** is preserved by the audit trigger
  (`audit_token_state_change`) which fires AFTER UPDATE on
  `IdentityToken`. Postgres serializes UPDATEs on the same row, so the
  trigger executions are serialized too. The lifecycle audit order
  reflects the actual UPDATE order.

- **Login successes** don't need atomicity beyond what the session
  cookie already provides. No counter, no lockout state to corrupt.

- **CSRF token generation** uses `secrets.token_urlsafe(32)` which is
  cryptographically random; collision probability is ignorable.

- **Rate limiter state** is shared through Redis in any deployment with more
  than one worker, which is what the production configuration selects. The
  in-process backend remains for single-worker development, where its
  per-process counters are correct. [rate-limiter.md](rate-limiter.md) covers
  the selection and the atomicity that makes the Redis path exact.

---

## Adding a new hazard

A newly found race is added here as a row, then fixed in this order. Decide
between optimistic concurrency, a row lock, and an advisory lock. If it is a
row lock, take the smallest row that holds the contested state: for issuance
and activation that is the individual, not the token table. Then write a test
in `ConcurrencyTests` that triggers the race with real threads rather than
mocking the interleaving, and document the race and its fix both here and in
the procedure's own comment.

A concurrency bug with no test comes back.

---

## The per-agency lock: bounded revocation

The bounded-revocation procedure (`uc8_revoke_token`) has a different
shape of race than the row-level ones above. The rate-limit check
reads `count(*)` across many `TokenLifecycleEvent` rows joined to
`IdentityToken`: there is no single row to `FOR UPDATE`. Two threads
both at the boundary read the same count, each concludes that one more
revocation is within the bound, and both write, leaving the agency two over.

The fix is a **PostgreSQL transaction-scoped advisory lock** keyed on
the issuing agency id:

```sql
PERFORM pg_advisory_xact_lock(
    hashtext('polaris.revoke.' ||
        (SELECT issuing_agency_id::TEXT FROM IdentityToken WHERE token_id = p_token_id)));
```

Why this granularity:

- **Per-agency lock, not global.** Cross-agency revocations don't
  conflict: each agency has its own bound and its own counter.
  Locking globally would block legitimate parallel work needlessly.
  `ConcurrencyTests.test_uc8_cross_agency_revocations_do_not_block`
  asserts the parallelism behavior.
- **`hashtext` reduces the string key to the `bigint` that
  `pg_advisory_xact_lock` accepts.** Collision probability is
  ignorable at the cardinality of agency_ids.
- **`_xact_` flavor releases at COMMIT/ROLLBACK.** No application-side
  unlock; no leaked locks when a transaction errors out mid-way.

When to reach for this pattern:

- The contested state is a *derived* count (rate, sum, percentile),
  not a single row.
- The contention maps to a natural key, an entity identifier available at the
  start of the transaction.
- The rest of the schema should stay in read-committed isolation while one
  procedure needs a stronger guarantee.

Anti-pattern: do not advisory-lock on a hash of the *token id* in
this case. The bound applies to the *issuing agency*. Two threads
revoking *different tokens issued by the same agency* must serialize;
locking on token_id would let them both pass.

---

## The per-individual lock: the recovery ceremony

Same pattern as UC-8, applied to a different shape of contention.
`uc9_complete_recovery` faces this race: two threads (or two
admins, one per browser tab) calling
`uc9_complete_recovery(recovery_id=X)` on the same PENDING request
would each pass the cool-down + three-channel CHECKs before either
UPDATE landed. Without serialization, both would issue new ACTIVE
tokens for the same individual: violating C3 (one ACTIVE per
individual) and producing two RevocationList entries for each lost
token.

```sql
PERFORM pg_advisory_xact_lock(
    hashtext('polaris.recovery.' ||
        (SELECT claimed_individual_id::TEXT
         FROM RecoveryRequest WHERE recovery_id = p_recovery_id)));
```

Lock key per claimed-individual (not per recovery_id, because two
different recovery_ids for the same individual would also conflict:
though the partial unique index `uq_one_pending_recovery_per_individual`
makes that case impossible). Cross-individual recoveries don't
conflict. Transaction-scoped.

Test: `ConcurrencyTests.test_uc9_advisory_lock_serializes_concurrent_completes`
fires T=4 threads at the same PENDING and asserts exactly one
succeeds, T-1 fail with "not PENDING".

---

## The per-token lock: algorithm migration

Third entry in the catalog. Same advisory-lock mechanism as UC-8 and
UC-9, but the contention is per-token: `uc6_migrate_algorithm` races
on the same token would both try to insert new TokenSignature rows
and the trigger checks could interleave dangerously.

```sql
PERFORM pg_advisory_xact_lock(
    hashtext('polaris.migrate.' || p_token_id::TEXT));
```

Why per-token:

- The contested state is the **active-signature set per token**.
- Two threads migrating *different tokens* don't conflict: each
  token has its own row in IdentityToken and its own set of
  TokenSignature rows.
- Two threads migrating the *same token* must serialize so the
  invariant trigger (`enforce_token_has_active_signature`) sees a
  consistent count.

Test: `ConcurrencyTests.test_uc6_per_token_lock_serializes_concurrent_migrations`
fires 3 threads each migrating the same token to 3 distinct
algorithms; all succeed, final state has 4 active signatures
(1 seed + 3 migrations). Plus
`test_uc6_cross_token_migrations_run_in_parallel` confirms that different
tokens do not contend, and `test_uc6_migrate_takes_its_advisory_lock` that the
lock is taken at all. Neither uses a stopwatch: one worker calls the procedure
and holds its transaction open, the other probes under `lock_timeout`, so
Postgres answers rather than a clock being interpreted (v9.459-v9.462).

### Verification-snapshot consistency model

Distinct from the lock: when verification reads
`TokenSignature WHERE deprecation_date IS NULL` and a migrator
concurrently sets `deprecation_date` on a row, what does the verifier
see?

The verifier sees its pre-migration snapshot under PostgreSQL's
default READ COMMITTED (each statement sees committed state at
statement start) or REPEATABLE READ (whole transaction sees txn-start
snapshot). New migrations are visible to *subsequent* transactions.
Test `test_uc6_verification_snapshot_consistent_with_migration`
asserts this contract explicitly so the verification path can rely
on it.

## The per-algorithm lock: closing an anchor batch

Fourth entry in the catalog. `close_anchor_batch(algorithm_id, root,
proofs)` groups pending `BlockchainAnchor` rows by their underlying
token's signature algorithm and inserts a single `AnchorBatch` row
plus per-leaf merkle proofs. Without a lock, two parallel calls for
the same algorithm could each see the full pending leaf set and
produce two batches: either with identical roots (a wasted batch)
or with the leaves silently split across two batches (breaks the
audit-of-record's "one batch per leaf" invariant).

The lock key is `hashtext('polaris.anchor.close-batch.' ||
algorithm_id::TEXT)`. Same-algorithm closes serialize; cross-algorithm
closes parallelize. Per-algorithm scope is natural: different
algorithms have *disjoint* pending leaf sets, so cross-algorithm
contention is impossible by construction.

Test: `ConcurrencyTests.test_close_anchor_batch_same_algorithm_serializes`
asserts that two parallel close calls for algorithm 2 produce a
single batch of size 2 (one thread wins the lock, the other finds no
pending leaves and gets `no_data_found`).
Test: `ConcurrencyTests.test_close_anchor_batch_cross_algorithm_parallel`
holds algorithm 2's lock open and requires a close under algorithm 3 to proceed
anyway, under `lock_timeout`. Until v9.459 it timed the pair against a 0.55s
constant and passed against a lock key that ignored the algorithm entirely.

This lock is one of two the suite CANNOT observe on its own: the key is
`algorithm_id` and the procedure batches every pending row under it, so two
calls sharing the key touch the same rows and would serialize on the UPDATE
regardless. The property is still covered. Drop the advisory lock and all 866
tests pass; drop the `FOR UPDATE` in the sibling procedures and all 866 pass;
drop both and the suite fails. `_UNOBSERVABLE_LOCKS` in `polaris_checks` records
this with the measurements.

See `docs/design/anchoring.md` for the broader write-up.

## The per-attesting-agency lock: federation attestations

Fifth entry in the catalog. `uc10_attest_trust` and
`uc10_revoke_attestation` both hold
`pg_advisory_xact_lock(hashtext('polaris.federation.attest.' ||
attesting_agency_id::TEXT))` for the transaction. Without the lock,
same-agency concurrent attest+revoke could interleave such that the
final state is ambiguous (did the revoke see the attestation that's
about to commit?).

Per-attesting-agency scope is the natural unit: a single agency's
federation decisions are coordinated by that agency's operators;
parallel decisions by *different* agencies have no overlapping state
and can run concurrently.

Test: `ConcurrencyTests.test_uc10_same_attesting_agency_serializes`
holds attesting agency 4's lock open THROUGH THE PROCEDURE and requires a second
attest under the same agency to wait for it.

The paragraph this replaces described the older approach as a technique: "the
test manually holds the lock to make the serialization timing observable; the
procedure's lock acquisition inside is a no-op reacquire on the same
transaction." That is precisely why it proved nothing. Both threads serialized
on the TEST's lock, so the procedure's own locking never entered the
measurement, and reinstalling `uc10_attest_trust` with its
`PERFORM pg_advisory_xact_lock(...)` line deleted outright left the test green
(v9.460). A hold must go through the procedure or it measures the test.

Test: `ConcurrencyTests.test_uc10_cross_attesting_agency_parallelizes`
requires an attest by agency 5 to proceed while agency 4's is held.
Test: `ConcurrencyTests.test_uc10_attest_and_revoke_share_one_lock_key`
requires a revoke to wait on a held attest, which is the one thing the two
procedures do not share code for: `uc10_attest_trust` hashes its
`p_attesting_id` parameter while `uc10_revoke_attestation` SELECTs
`attesting_agency_id` out of the row and hashes that. A comment claimed the two
serialize from R11-3 until v9.462 and nothing measured it.

See `docs/design/federation.md` for the broader write-up.

## The global lock: closing a ZK epoch

Sixth entry in the catalog. `uc11_close_epoch` holds
`pg_advisory_xact_lock(hashtext('polaris.zk.close-epoch'))`: a
**single global key** rather than a per-entity key. The reason: epoch
closures are inherently global (`epoch_id` is a SERIAL), and
serializing them avoids race conditions on SERIAL assignment and on
the per-procedure Merkle-commitment workflow.

Distinct from the prior five entries, which are per-entity (per-agency,
per-individual, per-token, per-algorithm, per-attesting-agency). The
per-procedure scope here is the natural unit: the procedure is the
"entity" being serialized.

Test: `ConcurrencyTests.test_uc11_close_epoch_serializes_under_lock`
holds one closure open THROUGH THE PROCEDURE and requires a second to wait for
it under `lock_timeout`. It too used to hold the lock by hand and time the pair,
and it too stayed green against `uc11_close_epoch` with its
`PERFORM pg_advisory_xact_lock(...)` line deleted (v9.460).
Test: `ConcurrencyTests.test_uc11_close_epoch_both_rows_committed`
asserts that both serialized closures commit (lock = ordering, not
loss-of-write).

See `docs/design/zk-snark.md` for the broader write-up.

## Catalog summary

| Procedure | Lock granularity | Cross-key parallelism |
|---|---|---|
| `uc8_revoke_token` | per-agency | cross-agency parallel |
| `uc9_complete_recovery` | per-individual | cross-individual parallel |
| `uc6_migrate_algorithm` | per-token | cross-token parallel |
| `close_anchor_batch` | per-algorithm | cross-algorithm parallel |
| `uc10_attest_trust` / `uc10_revoke_attestation` | per-attesting-agency | cross-attesting-agency parallel |
| `uc11_close_epoch` | per-procedure (global) | N/A: all closures serialize |

**What the suite can and cannot see** (measured v9.459-v9.463, by reinstalling
each procedure with its lock removed and running the whole suite). Four of the six
are directly observable: delete the `pg_advisory_xact_lock` line from
`uc6_migrate_algorithm`, `uc8_revoke_token`, `uc10_attest_trust` or
`uc11_close_epoch` and a test goes red. Two are not. `uc9_complete_recovery` keys
on `claimed_individual_id` while `uq_one_pending_recovery_per_individual` allows
one PENDING recovery per individual, so any two callers that share the key target
the same row and serialize on its `FOR UPDATE` anyway; `close_anchor_batch` keys
on `algorithm_id` and batches every pending row under it, and under READ COMMITTED
a prober cannot see the holder's uncommitted batching. For both, dropping either
mechanism alone leaves all 866 tests green and dropping both turns the suite red,
which is defense-in-depth rather than an untested lock. `_UNOBSERVABLE_LOCKS` in
`polaris_checks/checks.py` carries the reasons, and
`check_advisory_locks_have_a_contention_test` fails if a seventh lock arrives with
no contention test and no declaration.

The same mechanism applied at six different granularities, each
chosen to match the *natural scope of contention* for that procedure.
The sixth entry breaks the per-entity pattern explicitly: ZK epoch
closures are inherently global because the merkle_root commitment
shape doesn't admit cross-key parallelism.
