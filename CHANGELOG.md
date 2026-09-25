# Changelog (recent ships)

This file holds the entries since the front door was rewritten at v9.453 (12 September
2026), the point from which the operating contract governs what is worth shipping.
Everything before it, v9.44 (3 June 2026) through v9.452, is in
[docs/history/CHANGELOG-v9.md](docs/history/CHANGELOG-v9.md), moved there unchanged on
16 September 2026 so that this file stays readable; the complete ship-by-ship history is
also in the git log. Entries are never edited retroactively: a correction is a later
entry. When this file grows past a reader's patience, its oldest entries move to the
archive, and `scripts/polaris-release-notes.sh` renders a moved entry from there.

---

## v1.0.0-rc.53 — 2026-09-25 (a credential cannot be created around issuance)

CORE-BUG against the issuance contract: a credential exists because `uc1_issue_and_activate` or
`uc_bulk_issue` issued it (two-witness signing, the algorithm authorization, the enrolment
evidence). The contract covers its permissions, its revocation-list entries (`uc4`, `uc8`,
`uc9`), its device bindings (`uc5`) and its recoveries (`uc9_initiate_recovery`) the same way.
Externally observable: the application role can no longer insert into `IdentityToken`,
`TokenPermission`, `RevocationList`, `DeviceBinding` or `RecoveryRequest`. Schema change:
migration `2026-09-25-012-credential-tables-written-only-by-their-procedures`. Nothing is
published.

The application role held INSERT on all five, and the application inserts none of them
directly; every procedure that does is SECURITY DEFINER, since rc.40 for issuance. With that
right the role could create a credential that never passed issuance and grant it permissions.
It could also put a token on the revocation list without the revocation gate, bind a device, or
open a recovery. Pairs seven to eleven of the open-door sweep. Two tables stay writable, because
the application writes them itself: `Individual` from the operator routes, and `TokenSignature`
from the population migration.

- The application role loses INSERT on the five tables; UPDATE is unchanged.
- Test: `test_app_role_cannot_create_a_credential_around_issuance`, as `polaris_app`, covers the
  five direct inserts. It goes red with the down migration applied.
- `check_aor_privilege_boundary` requires the five revokes; five new detection cases.

## v1.0.0-rc.52 — 2026-09-25 (duress events, archive checkpoints and erasure records cannot be fabricated)

CORE-BUG against three published refusals: `uc12_record_duress` records duress only for a
credential with a duress code enrolled; `uc_archive_purge` writes a checkpoint only for the purge
it performs; `uc_pseudonymize_individual` records an erasure only for the pseudonymization it does,
by an active admin. Externally observable: the application role can no longer insert into
`DuressEvent`, `LifecycleArchiveCheckpoint` or `IndividualErasureEvent`. Schema change: migration
`2026-09-25-011-append-only-records-written-only-by-their-procedures`. Nothing is published.

All three tables are append-only, and the application role held INSERT on each without ever
writing them directly. A direct write skipped each procedure's refusal, and the append-only rule
then made the record permanent. It could be a duress alarm for a holder who enrolled no duress
code, which is worse than a lost one: the duress record is net-negative against institutional
access. It could be a checkpoint claiming an archive and purge that never ran. Or it could be an
erasure record claiming a person was erased who was not. Fourth to sixth pairs of the open-door
sweep.

- The application role loses INSERT on the three tables. `uc12_record_duress` and
  `uc_archive_purge` were already SECURITY DEFINER; `uc_pseudonymize_individual` becomes so, with
  a pinned `search_path`. `Individual` has no row-level security, so running as the owner widens
  nothing it reads.
- Test: `test_app_role_cannot_fabricate_a_permanent_record`, as `polaris_app`. It covers the
  three direct inserts, an erasure through the procedure, and the duress procedure refusing a
  credential with no code on its own terms. It fails with the down migration applied.
- `check_aor_privilege_boundary` requires the three revokes and a definer
  `uc_pseudonymize_individual`; new detection cases.

## v1.0.0-rc.51 — 2026-09-25 (the anchoring layer is written only by the procedure that closes a batch)

CORE-BUG against the anchoring contract: `close_anchor_batch` sizes a batch from its pending
leaves, refuses a deprecated algorithm, and assigns every pending anchor with its proof in a
deterministic order ("defeats the publish-then-fork attack"). Externally observable: the
application role can no longer write `AnchorBatch` or `BlockchainAnchor`. Schema change: migration
`2026-09-25-010-anchors-written-only-by-close-anchor-batch`. Nothing is published.

The application role held INSERT on `AnchorBatch`, and INSERT, UPDATE and DELETE on
`BlockchainAnchor`, which carries no trigger. It could record a batch whose `batch_size` no
leaves bear out, or one under a deprecated algorithm. After a batch closed it could move an
anchor into another batch and rewrite its Merkle proof: the publish-then-fork the procedure's
ordering exists to prevent, done by other means. The application writes neither table; only
the sample data and the procedure, already SECURITY DEFINER, do. Third pair closed in the
open-door sweep.

- The application role loses INSERT on `AnchorBatch` and INSERT, UPDATE and DELETE on
  `BlockchainAnchor`.
- Test: `test_app_role_cannot_write_the_anchoring_layer`, as `polaris_app`, covers four
  attempts: moving an anchor, adding one, deleting one, recording a batch. Each fails with the
  down migration applied.
- `check_aor_privilege_boundary` requires both revokes; two new detection cases.

## v1.0.0-rc.50 — 2026-09-25 (a federation trust edge is recorded and revoked only through its admin-gated procedures)

CORE-BUG against the federation contract that a trust edge is an admin's decision
(`uc10_attest_trust`: "Federation attestation requires admin role"; the same for
`uc10_revoke_attestation`). Externally observable: the application role can no longer insert a
trust attestation directly or revoke one with a plain UPDATE. Schema change: migration
`2026-09-25-009-trust-edges-only-through-uc10`. Nothing is published.

The application role held INSERT and UPDATE on `AgencyTrustAttestation`. With INSERT it could
record a trust edge no admin signed, backdated and for any window. The signing pass signs every
unsigned edge with the attesting authority's own key, so such an edge would then be published as
that authority's signed attestation. With UPDATE it could set `revocation_date` and cut a trust
edge without the admin gate. The immutability trigger kept the edge's identity and validity fixed
after it existed, but it never asked who revoked. Found by the open-door sweep rc.49 began: for
every table a rule-procedure writes, can the application role write it directly? Twenty-three
pairs answered yes. This is the second closed, chosen first because it decides who is trusted.

- `uc10_attest_trust` and `uc10_revoke_attestation` are SECURITY DEFINER with a pinned
  `search_path`. The application role loses INSERT on `AgencyTrustAttestation` and keeps UPDATE,
  which the signing pass needs to attach a signature.
- `enforce_attestation_immutability` admits a change to `revocation_date` or `revocation_reason`
  only when the current role owns `uc10_revoke_attestation`, the rc.19 pattern for token
  revocation.
- Test: `test_app_role_records_and_revokes_trust_only_through_uc10`, as `polaris_app`. A direct
  insert and a direct revocation are refused, and both procedures still work for the role. It
  fails with the down migration applied.
- `check_aor_privilege_boundary` requires the revoke, both definers, and the trigger's owner test;
  three new detection cases.

## v1.0.0-rc.49 — 2026-09-25 (an epoch is written only by the procedure that enforces the anonymity floor)

CORE-BUG against rc.46, which promised that "`uc11_close_epoch` refuses an epoch below the
minimum anonymity set". Externally observable: the application role can no longer write
`TokenStateEpoch` or `TokenStateEpochLeaf` directly. Schema change: migration
`2026-09-25-008-epochs-written-only-by-uc11`. Nothing is published.

rc.46 put the floor in `uc11_close_epoch`, but the application role held INSERT on both epoch
tables. A client connected as that role could write an epoch the procedure refuses: one member,
signed by a non-admin, or with a `committed_count` its leaves do not bear out. The last matters
most, because the verifier reads that count as the anonymity set. The update and delete triggers
stopped changes to an epoch after it existed, but nothing stopped a new one. Found by asking of
the rc.46 fix what rc.40 asked of the lifecycle log: is the procedure the only way in?

- `uc11_close_epoch` is SECURITY DEFINER with a pinned `search_path`; the actor is authenticated
  by parameter, as in the other definer procedures. The application role loses INSERT, UPDATE and
  DELETE on `TokenStateEpoch` and INSERT on `TokenStateEpochLeaf`, and keeps EXECUTE on the
  procedure.
- Test: `test_app_role_writes_an_epoch_only_through_uc11`, as `polaris_app`. A direct epoch
  insert is refused, and so is a direct leaf insert. The procedure is still callable and still
  refuses an empty epoch on its own terms. With the down migration applied, it and the
  append-only privilege test fail.
- `check_aor_privilege_boundary` now requires both revokes and a definer `uc11_close_epoch`;
  three new cases in its detection test.

## v1.0.0-rc.48 — 2026-09-25 (Polaris's own database sessions run in UTC whatever PGTZ says)

CORE-BUG against rc.28's promise, closing the item rc.47 recorded as open, for the processes
Polaris ships. Externally observable: the application, the CLI and the simulator open every
database session in UTC even when their environment sets `PGTZ` to another zone. No schema
change. Nothing is published.

58 columns are `TIMESTAMP` without a zone. `CURRENT_TIMESTAMP` fills them in the writing
session's zone, and `_db_now` compares with them through `LOCALTIMESTAMP` for that reason. The
database's UTC setting is a default, and a client's `PGTZ` overrides it. With `PGTZ` at UTC+14,
issuing a credential that expires on the same UTC day broke `chk_token_time_order`: `issued_date`
was stamped with the next day's wall clock.

- Each of `polaris_web/app.py`, `polaris_cli/polaris.py` and `polaris_sim/__main__.py` sets
  `PGTZ=UTC` at module level, before its first connection. libpq sends `PGTZ` as the `timezone`
  startup parameter. That is one of the four parameters pgbouncer tracks, so the pin holds through
  the production pooler. A connection `options` string would not hold, because pgbouncer's
  `ignore_startup_parameters` does not admit it.
- Test: `test_the_products_own_sessions_run_in_utc_whatever_pgtz_says` starts each of the three
  with `PGTZ` at UTC+14 and asks its session for its timezone and wall-clock date. Removing the pin
  from any one of the three fails that subtest.
- Check 332, `check_product_sessions_pin_utc`, fails if any of the three loses the pin, sets it
  inside a function, sets it after connecting, or pins a zone other than UTC.
- Still open: a client that is not Polaris (an operator's `psql` with `PGTZ` set) writes those 58
  columns in its own zone. Only converting them to `TIMESTAMPTZ` closes that. The conversion
  changes every datetime the application reads from naive to aware, so it needs its own release.

## v1.0.0-rc.47 — 2026-09-25 (a client's timezone no longer moves an expiry decision)

CORE-BUG against rc.28, whose entry and `09_grants.sql` promise that the database judges dates on
UTC "for every session of this database, so no connection has to remember to ask". Externally
observable: every expiry and validity decision in the database, and in the SQL the application
sends, reads the UTC date whatever timezone the session set. Schema change: migration
`2026-09-25-007-utc-date-for-every-session` adds `polaris_utc_date()` and re-creates the fourteen
objects that read `CURRENT_DATE`. Nothing is published.

rc.28 made UTC the database's default timezone. A default is what a session gets when it does
not ask: a client with `PGTZ` set, a connection pooler, or a `SET timezone` overrides it, and
`CURRENT_DATE` is then that client's date. Found by running the web and constraint suites with
the database session at UTC+14 and at UTC-12, the axis flipped the way the application role and
the signer were flipped earlier the same day. At UTC+14 seven tests failed, among them an expired
credential signing in to a relying party. Most of the seven were fixtures computing "yesterday"
with the session's date. The defect under them is that the state-machine trigger, UC-1, UC-4,
UC-5, UC-8, UC-9, UC-10, bulk issuance, four Athena views, the authority chain and five
application queries judged dates in the client's zone. The application, the signed status
assertion and the verifiers judged them in UTC. For up to fourteen hours of every day the two
could disagree about whether a credential had expired.

- `polaris_utc_date()` (`05_procedures.sql`) is `(now() AT TIME ZONE 'UTC')::date`, which no
  session setting moves. Every product decision reads it; the test fixtures do too.
- Test: `test_a_session_timezone_does_not_move_an_expiry_decision` picks whichever of UTC+14
  and UTC-12 is on a different calendar date from UTC at the moment it runs. It asks the trigger
  to activate a credential that expired yesterday in UTC (refused) and one that expires today in
  UTC (allowed). With `CURRENT_DATE` put back in the trigger it fails.
- Check 331, `check_no_session_date_in_sql`, refuses `CURRENT_DATE` and `now()::date` in the
  product SQL and in the SQL the application and CLI send, and fails if `polaris_utc_date()` is
  not defined. Detection test in `polaris_checks/test_checks.py`.
- Open, recorded rather than fixed here: 58 columns are `TIMESTAMP` without a zone, filled by
  `CURRENT_TIMESTAMP` in the writing session's zone, and `_db_now` compares with them through
  `LOCALTIMESTAMP` for that reason. A session in another zone writes and compares a different
  wall clock. That is the same class one level down (the column type), and it needs its own
  migration.

## v1.0.0-rc.46 — 2026-09-25 (an epoch too small to hide anyone is refused, and a security test cannot skip in CI)

EXT-SECURITY: both findings come from an outside reviewer's questions of 25 September 2026.
Externally observable: `uc11_close_epoch` refuses an epoch smaller than the minimum anonymity set,
and a zero-knowledge proof against an older epoch below it answers `privacy unavailable` instead
of verifying. Schema change: migration `2026-09-25-006-minimum-anonymity-set`. Nothing is
published.

- **The anonymity set had no floor.** The reviewer asked what happens when an epoch's anonymity set
  is too small. It closed anyway: an epoch of one member published a root over one leaf, and a
  valid proof against it identified its holder by elimination. `uc11_close_epoch` now reads
  `polaris.min_epoch_anonymity_set` (twenty unless set; `09_grants.sql` sets twenty where nothing
  is set, and the notional sample data sets one, saying why) and refuses an epoch below it with
  `check_violation`. The authority waits for members or lengthens its cadence; epochs are not
  merged. An epoch closed below the floor before this release is not re-opened: a proof against
  it is answered `privacy unavailable: this epoch's anonymity set is N, below the minimum of M;
  present the credential online instead`, and not accepted. Tests:
  `test_an_epoch_below_the_minimum_anonymity_set_is_not_closed` and
  `test_a_proof_against_an_epoch_below_the_floor_is_privacy_unavailable` in
  `IssuerFederationTests`, the first failing on rc.45.
- **A skipped security test read as a pass.** `TestC1PrivilegeBoundary` had skipped in CI for want
  of a password while the run reported green (fixed in `985a82e`). The reviewer asked that "no
  skipped security tests in CI" be an invariant. Under `CI`, `test_check_constraints.py` now turns
  every `skipTest` into a failure naming the reason, and check 330,
  `check_security_suite_refuses_skips_in_ci`, fails the build if that guard is removed, weakened
  to a skip, or stops covering every test class. Detection test in `polaris_checks/test_checks.py`.
- **The report.** In all three editions: a lineage section with references (the report cited
  nothing before); "Sybil resistance" withdrawn for credential uniqueness per enrolment identity,
  not human uniqueness; "validated" for the national targets replaced by what was done (a model
  from single-machine measurements); the zero-knowledge second witness described as independent in
  implementation only; the anonymity floor and its failure semantics; the five percent revocation
  ceiling classified as a governance parameter; the database owner named as the actor the schema
  does not bind; who chooses the offline window and who bears it; a table of claims no outsider has
  yet tested; and an appendix listing everything outside Table 16 learned after the snapshot commit
  `4e74376`.

## v1.0.0-rc.45 — 2026-09-25 (two operator features failed for the role a deployment runs as)

CORE-BUG against rc.44. Externally observable: `polaris retention-set` records a single retention
decision in a deployment, and the Atlas simulation tick (`/api/sim/tick`) writes its events. Both
failed on every call for `polaris_app`, the role the CLI and the application connect as. Schema
change: migration `2026-09-25-005-retention-set-through-a-procedure` adds
`uc_set_retention_policy`. Nothing is published.

The web suite and the CLI suite connect as the schema owner, and so did the application and the
CLI they drive. The owner bypasses row-level security and holds every privilege, so anything that
needed more than `polaris_app` has passed every test and failed in every deployment.
`scripts/polaris-app-role-suite.py` runs both suites again with the application and the CLI
connected as `polaris_app` (the tests' own fixtures stay the owner), and found exactly two:

- `polaris retention-set`, for a single decision, superseded the current one with a direct
  `UPDATE RetentionPolicy`, which the application role is refused on purpose: superseding a
  retention decision without recording who did it is what that grant exists to stop. It now calls
  `uc_set_retention_policy`, `SECURITY DEFINER`, which makes the template procedure's actor checks
  (the actor exists, is an admin, is active), supersedes, and inserts. The procedure drill measures
  all three refusals.
- The simulation tick streamed verifications with `COPY FROM`, which PostgreSQL refuses on a table
  whose row-level security applies to the caller. The writer asks `row_security_active()` and uses
  batched inserts where the policy applies; the bulk simulator, running as the owner, keeps `COPY`.
  (Pushed as c2dbc56; recorded here with the release it belongs to.)

The harness is a CI step in the product job: 873 web tests and 113 CLI tests as `polaris_app`, none
failing. Against rc.44 it fails naming the two simulation tests and the two retention-set tests.

Counterexamples, failing on rc.44 under `scripts/polaris-app-role-suite.py`:
`RetentionCommandTests.test_retention_set_records_a_decision_and_show_reflects_it`,
`RetentionCommandTests.test_retention_set_supersedes_rather_than_edits`,
`AtlasSimulationModeTests.test_tick_streams_events_through_the_real_path`.

## v1.0.0-rc.44 — 2026-09-25 (binding an operator to an authority did not reach their live session)

CORE-BUG against rc.43. Externally observable: a live session whose account is bound to an
authority, moved to another, or unbound, ends on its next request with `revoke_reason`
`agency_changed` and a `SESSION_REVOKED` audit event, as a role change has since 2026-09-17.
Schema change: migration `2026-09-25-004-session-agency-changed` widens
`chk_opsession_revoke_reason` to admit the new reason. Nothing is published.

The authority an operator is bound to is copied into the session cookie at sign-in and was never
read again. Binding an operator to one authority is how an incident narrows what they can reach,
and it did not take until they signed in again. Measured on rc.43 as the application role: an
unbound account, signed in, was bound to authority 1; its live session went on answering 200 and
showing authority 3's credentials until the cookie expired. `validate_session` already re-read
the account's role and activity on every request, so it now reads the binding with them and ends
the session when it differs. Ending rather than adopting is the same choice the role change made:
a change of authority is a reason to re-authenticate, and a session carrying on under a binding it
did not sign in with would leave an audit trail that says one thing and a session that did
another. The migration comes with the code this time; 2026-09-24-001 records what happened when
the role change did not.

Counterexample, failing on rc.43:
`SessionLimitTests.test_an_authority_binding_change_ends_the_live_session`.

## v1.0.0-rc.43 — 2026-09-25 (a bound operator could bind a device to another authority's credential)

CORE-BUG against rc.42, and a regression introduced by rc.40. Externally observable: for an
operator bound to one authority, the token-scoped routes refuse (403) a credential that
row-level security hides from them, instead of passing it on. No schema change. Nothing is
published.

`_token_authority_denied`, the binding check for routes that name a token, looked up the token's
issuer and, when the lookup found no row, returned "not denied" for the route's own "not found"
to answer. For a bound operator that lookup runs under row-level security, so another
authority's credential is not missing, it is hidden. While `uc5_bind_device` ran as its caller
it could not see the token either, and the request failed. rc.40 made it `SECURITY DEFINER`, and
from then on the procedure saw what the gate could not. Measured on rc.42 as the application role
for an operator bound to authority 1: `POST /uc5/bind-device` for authority 3's token 2 answered
302 and the credential went from 2 device bindings to 3. The same probe against `/uc6/migrate`,
`/tokens/2/transition` and `/tokens/2/delete` changed nothing: uc6 stops earlier on its own
checks, and the other two write as the application role, so the same policy scopes their UPDATE
and DELETE. That is an accident of which role runs the write, so their gates now fail closed too.

For a bound operator a credential the lookup cannot see is refused, with the same 403 as a
credential of another authority; unbound, nothing is hidden and "not found" still answers.
`BoundOperatorRouteIsolationTests.test_no_route_acts_on_another_authoritys_credential` posts all
four, each from a freshly loaded database, as the application role, and asserts that nothing about
the credential changes. Against rc.42 it fails on `/uc5/bind-device` alone.

## v1.0.0-rc.42 — 2026-09-25 (a bound operator's session blinded the database's own rules)

CORE-BUG against rc.41, in operator isolation. Externally observable: for an operator bound to
one authority, `uc9_initiate_recovery` refuses a holder who has an ACTIVE credential anywhere,
and `RevocationList` refuses any token that is not REVOKED, LOST or EXPIRED, exactly as they do
unbound. Schema change: migration `2026-09-25-003-rules-see-past-the-operator-binding`. Nothing
is published.

Row-level security hides another authority's credentials from a bound operator, which is what
it is for. But seven routines enforce a rule by READING `IdentityToken` while running as their
caller, and under the binding the rows they had to see were invisible, so the rule held only
for unbound operators. Measured on rc.41 as `polaris_app` bound to authority 1, each case
refused unbound: `uc9_initiate_recovery` opened a recovery for the holder of authority 3's
ACTIVE token 2, and `enforce_revocation_status` let that ACTIVE token onto the revocation list.
The second failed OPEN on a NULL: the hidden row's status read as NULL, `NULL NOT IN (...)` is
NULL, and an IF reads NULL as false.

`uc6_migrate_algorithm`, `uc9_initiate_recovery`, `uc12_record_duress`, `close_anchor_batch`,
`enforce_revocation_status`, `enforce_predecessor_same_individual` and `enforce_agency_quota` are
`SECURITY DEFINER` with a pinned `search_path` and executable by the application role only. None
changes a credential's status, so none passes the revocation gate. The routes that reach them
ask the operator's binding themselves (check 323). The revocation trigger also refuses a NULL
status. `check_rule_routines_see_past_the_binding` (329) requires every trigger function and
procedure that reads one of the three row-level-secured tables to run as its owner; display
functions are exempt, since for them the operator's scope is the point. Run against rc.41, it
names the routines.

Also since rc.41, as plain commits: the route-level isolation tests, run as the application role
(`BoundOperatorRouteIsolationTests`); the verifier fuzzer's and the invariant properties' soak
budgets; and `polaris-oid4vp` accepts only canonical base64url (source only, see its commit).

Counterexample, failing on rc.41:
`TestC1PrivilegeBoundary.test_a_rule_the_database_enforces_holds_for_a_bound_operator`.

## v1.0.0-rc.41 — 2026-09-25 (a bound operator could read other authorities' credentials through a view)

CORE-BUG against rc.40, in operator isolation. Externally observable: every view is
`security_invoker`, so an operator bound to one authority sees through `v_ontology_token`,
`v_ontology_token_timeline`, `v_ontology_verification`, `ActiveTokens` and the rest exactly what
the underlying tables show them, and `/investigate/token/<id>` answers 404 for another
authority's credential. Schema change: migration `2026-09-25-002-views-run-as-their-caller`.
Nothing is published.

Reads by a bound operator are scoped by row-level security: the session carries
`polaris.operator_agency_id`, and the policies on `IdentityToken`, `VerificationEvent` and
`TokenLifecycleEvent` filter every query, which is why sixteen read routes need no filter of
their own. A view is evaluated with its OWNER's rights, and RLS on the tables beneath it applies
to the owner, who bypasses it. Measured on rc.40 as `polaris_app` bound to authority 1:
authority 3's token 2 was invisible in `IdentityToken` and visible, with its three-event
timeline, in `v_ontology_token`; `v_ontology_verification` showed 8 verifications where the
table showed 2. The investigate routes read those views.

`security_invoker = true` makes a view apply its caller's privileges and policies. The
application already holds `SELECT` on every table, so nothing else changes. `CREATE OR REPLACE
VIEW` without the option resets it, so all 26 definitions carry it, and the migration sets it on
every view a deployed database has. `check_views_run_as_their_caller` (328) requires it of every
definition in the base files and in migrations from this one on.

Also since rc.40, as plain commits: `SECURITY DEFINER` routines pin `search_path` (check 327)
and are executable by the application role only (migration `2026-09-25-001`); the purge
carve-out asks for the purge's owner (migration `2026-09-24-014`); the tests that connect as
`polaris_app` run in CI, where they had always skipped.

Counterexample, failing on rc.40:
`TestC1PrivilegeBoundary.test_a_view_shows_a_bound_operator_no_more_than_the_tables_do`.

## v1.0.0-rc.40 — 2026-09-24 (the application role could empty the audit of record through its partitions)

CORE-BUG against rc.39, in the C1 privilege boundary. Externally observable: `polaris_app`
holds only `SELECT` on every partition of `TokenLifecycleEvent`, `VerificationEvent`,
`EnrollmentStatusEvent` and `AuthAuditLog`, and no `INSERT` on `TokenLifecycleEvent`, whose
four writers are `SECURITY DEFINER`. Schema change: migration
`2026-09-24-013-audit-of-record-privilege-boundary-reaches-partitions`. Nothing is published.

Two holes in one boundary. The append-only guarantee is a trigger AND a privilege: the trigger
honours the purge carve-out's session setting, which any role can set, so `09_grants.sql`
revokes `UPDATE` and `DELETE` from the application role and only `uc_archive_purge`, running as
the owner, can delete. The revoke named the partitioned PARENTS, and the blanket grant at the top
of the same file had reached every PARTITION, where it stayed. Measured on rc.39 as
`polaris_app`, with the setting on: every row of all four event tables deleted through their
partitions (rolled back). The second hole was found while fixing the rc.38 and rc.39 sibling:
`polaris_app` held `INSERT` on `TokenLifecycleEvent` because its writers ran as the caller, so it
could append a lifecycle event nothing did.

`polaris_lock_event_partitions()` strips each partition to `SELECT` for the application role. A
row is always routed through the parent, whose privileges are the ones checked, so nothing the
application does needs more. `09_grants.sql` calls it after its grants, and
`uc_ensure_event_partitions` calls it after creating a partition, which inherits the default
grant. `uc1_issue_and_activate`, `uc5_bind_device`, `uc_bulk_issue` and the
`audit_token_state_change` trigger are `SECURITY DEFINER` with a pinned `search_path`, and the
application role loses `INSERT` on the lifecycle log. Running as the owner bypasses row-level
security; the web routes that call the first two ask the operator's binding themselves
(check 323 holds them to it), and bulk issuance is reachable only from the operator CLI.

`check_aor_privilege_boundary` now requires all of it; run against rc.39 it fails. Two existing
tests assumed the old grant: one appended to the lifecycle log to prove the application still
could, and now appends a verification through its parent; the purge test seeds its old row as
the owner.

Counterexamples, failing on rc.39:
`TestC1PrivilegeBoundary.test_no_partition_of_an_audit_table_can_be_emptied`,
`test_the_application_cannot_append_a_lifecycle_event` and
`test_a_partition_made_later_is_locked_too`.

## v1.0.0-rc.39 — 2026-09-24 (the application role could set a person's enrollment status)

CORE-BUG against rc.38. Externally observable: a direct `INSERT` into `EnrollmentStatusEvent`
is refused unless it comes from the recording trigger or from the table's owner. Schema change:
migration `2026-09-24-012-enrollment-status-written-only-by-its-recorder`. Nothing is
published.

The sibling of rc.38, found by asking which other append-only tables the application role
holds `INSERT` on but never writes itself. A person's enrollment status is the latest
`EnrollmentStatusEvent`, and `/api/v1/auth/authorize` refuses a holder who does not meet a
relying party's `required_enrollment`. Nothing in the product writes one except the trigger
that seeds `NOT_ENROLLED` when a person is created; the sample data is loaded by the owner. The
grant exists only because that trigger runs as the caller. Measured on rc.38: connected as
`polaris_app`, one `INSERT` made person 5, `LAPSED`, `ENROLLED`.

A `BEFORE INSERT` trigger on the partitioned parent refuses the row unless it arrives from
inside a trigger or the session is the owner, so the sample load and an operator at the
console still work, and a partition written directly obeys the same rule. The test also creates
a person as the application role and checks the seed still arrives.

Counterexample, failing on rc.38:
`test_check_constraints.TestC1PrivilegeBoundary.test_the_application_cannot_set_a_persons_enrollment_status`.

## v1.0.0-rc.38 — 2026-09-24 (the application role could invent entries in the change records)

CORE-BUG against rc.37. Externally observable: a direct `INSERT` into `AgencyEvent`,
`AppUserEvent` or `RelyingPartyEvent` is refused at any privilege, and every row those tables
hold carries the session's own `db_role`. Schema change: migration
`2026-09-24-011-events-written-only-by-their-recorder`. Nothing is published.

The three change records refused an `UPDATE` or `DELETE`, so history could not be rewritten.
But `polaris_app` holds `INSERT` on them, because the recording triggers run as the caller and
need it. That grant let the application role append an event nothing did, attributed to
whichever `db_role` it named. Measured on rc.37: connected as `polaris_app`, a rename of
authority 1 "by" `postgres`, and an account event likewise, both accepted. A compromised
application is exactly the threat the append-only layer is for, and it could not erase the
record but could pad it with invented entries.

A `BEFORE INSERT` trigger on each table now refuses any row that does not arrive from inside a
trigger (`pg_trigger_depth() >= 2`), and sets `db_role` to `session_user` whatever the
statement said. The recorders are unchanged. The sample-data and migration backfills write only
where an event is missing and run before the guard exists, so a load inserts nothing directly.
Two test fixtures that wrote `AppUserEvent` directly now switch triggers off for their one
statement, which only the owner can do, so the CHECK they exercise is still reached.

Also since rc.37, as plain commits: the holder-key and authority-key registers constrain their
`algorithm` column (migrations 008 and 009, check 326), and the enrollment evidence's free-text
values carry no document number (migration 010).

Counterexample, failing on rc.37:
`test_check_constraints.TestC1PrivilegeBoundary.test_the_change_records_accept_only_what_their_recorders_write`.

## v1.0.0-rc.37 — 2026-09-24 (reporting a credential lost could activate an expired reserve)

CORE-BUG against rc.36. Externally observable: `uc4_activate_reserve`, and
`/uc4/activate-reserve` which calls it, refuse a reserve past its `expiration_date`, and the
form no longer offers one. Schema change: migration
`2026-09-24-007-no-expired-reserve-activated`. Nothing is published.

`uc4_activate_reserve` checked that the reserve was `RESERVE` and never read its expiry. So
reporting a credential lost could spend it and promote a reserve already past its date. The
holder got a credential that reads `ACTIVE` in the table while every verifier refuses it as
expired, and nothing live remained. The refusal is not in the procedure. It is in
`enforce_token_state_machine`, the trigger every status change passes through, so no path into
`ACTIVE` accepts a credential past its date: not the procedure, not an operator's transition, not
a plain `UPDATE`. It is judged on `CURRENT_DATE`, which is the UTC date since rc.28. Because the
trigger aborts the procedure, the lost credential stays `ACTIVE` too; the test asserts the
holder is left exactly as they were.

The migration carries the trigger body. On the test database, down and then up gives the
function a fresh install builds, and down alone restores the old body.

Counterexamples, failing on rc.36: `Uc4ReserveExpiryTests.test_an_expired_reserve_is_not_activated`
and `test_no_path_activates_an_expired_credential`.

The gate for this release ran after 20:00 EDT, which is past midnight UTC, and four existing
tests failed there. They computed "today" with the local date. The server's today is the UTC
date, the database clock since rc.28, so for four hours every evening west of UTC they judged a
credential against the wrong day. CI runs in UTC and could never see it. All twenty local-date
calls in `test_app.py` now use the UTC date, and they pass after midnight UTC. A new check,
`check_no_local_date` (325), refuses `date.today()` and `datetime.now().date()` anywhere in the
product, its kits and its tests. No product code had one.

## v1.0.0-rc.36 — 2026-09-24 (a device could be bound to an expired credential)

CORE-BUG against rc.35. Externally observable: `uc5_bind_device`, and `/uc5/bind-device` which
calls it, refuse a credential past its `expiration_date`. Schema change: migration
`2026-09-24-006-no-device-for-an-expired-credential`. Nothing is published.

`uc5_bind_device` refused a credential that was not `ACTIVE` and never read its expiry, and an
expired credential still reads `ACTIVE`. The relying-party holder-key binding has refused one
since rc.24; this path had not. It now refuses a credential past its date, judged on
`CURRENT_DATE`, which is the UTC date since rc.28. The migration carries the body; round-tripped
on a scratch database built from rc.35 (binds, refuses, binds, refuses).

Writing its test exposed a masked one. rc.30's
`test_device_binding_and_migration_stay_within_the_binding` posted `binding_method='NFC'`, a
value the table's CHECK constraint refuses. So its device-binding half passed on the constraint,
whether or not the operator's binding was checked. It now posts an accepted method and asserts
the 403, and it fails when the route's binding check is removed.

Counterexample, failing on rc.35: `Uc5BindDeviceExpiryTests.test_an_expired_credential_takes_no_device`.

## v1.0.0-rc.35 — 2026-09-24 (an expired credential could prove membership for a whole epoch)

CORE-BUG against rc.34 (EXT-SECURITY). Externally observable: closing a ZK epoch commits only
credentials that are live through the epoch's `valid_until`. No schema change. Nothing is
published.

`/api/zk/epoch/close` snapshots the credentials a zero-knowledge membership proof can be made
against, for the epoch's whole life. It selected `status = 'ACTIVE'` alone, and nothing moves
`ACTIVE` to `EXPIRED` when the date passes. The two consequences:
- **an expired credential was committed**, and its holder could prove membership until the
  epoch ended;
- **a credential that expires mid-epoch was committed for all of it**, so it could be used to
  prove membership after it had ended.

Measured: context 1's epoch committed `{2, 3, 4}`, where token 3 had expired yesterday and token
4 expires tomorrow, in an epoch valid for thirty days.

The snapshot now requires `expiration_date >= valid_until`. It fails closed: a membership proof
says "valid" until the epoch ends, so a credential's last days are left out rather than vouched
for after it ends.

The rc.21 sweep dismissed this query as "valid right now". A snapshot that outlives the request
is a liveness decision. `check_liveness_asks_about_expiry` now reads SQL as well, with a declared
exemption for the one dashboard count. Run against the rc.34 route, it fails.

Counterexample, failing on rc.34:
`ZKSnarkTests.test_an_epoch_commits_only_credentials_live_through_its_end`.

## v1.0.0-rc.34 — 2026-09-24 (a rate that only moved when something happened)

CORE-BUG against rc.33. Externally observable: `/api/metrics` and the alerts built on it report
`request_rate_per_minute`, `error_rate_per_minute` and `auth_failures_per_minute` as of now. No
schema change. Nothing is published.

`observability.RateWindow` rolled its per-minute samples forward only when an event arrived.
Reading the rate did not move it, so the reported rate described the last minute anything
happened in, not the present. Measured with a controlled clock:
- **after a burst**: a burst of 100 auth failures, then nothing, still read 50 a minute an hour
  later, so an alert on the failure rate keeps firing after the attack has stopped;
- **in the minute just after the burst**: the rate read 0, because the previous minute's
  count was dropped until another event rotated it in.

Both paths now roll the window forward to the present first, counting silent minutes as zero.

Counterexample, failing on rc.33: `RateWindowTests.test_a_burst_ages_out_of_the_rate_without_new_events`.

## v1.0.0-rc.33 — 2026-09-24 (naming yourself as the actor revoked another authority's credential)

CORE-BUG against rc.32 (EXT-SECURITY), a regression from rc.19. Externally observable:
`/uc8/revoke` and `/uc4/activate-reserve` refuse an operator bound to an authority other than
the token's issuer. No schema change. Nothing is published.

Both routes checked the operator's binding against the `actor_agency_id` they were told to act
as, and never asked whose token it was. `/uc4` also skipped even that check when the actor
field was missing or malformed. Before rc.19 the procedures could not see another authority's
token for a bound operator, because the row-level policy hid it. rc.19 made
`uc8_revoke_token` and `uc4_activate_reserve` `SECURITY DEFINER`, which the policy does not
bind. Measured: an operator bound to authority 1, naming authority 1 as the actor, revoked
authority 3's token 2.

Both routes now ask about the token's own issuer before the actor. The same kind of regression
rc.30 fixed for `/uc9/decide`; the memory note from that round is what prompted this search.

`check_state_changing_routes_ask_the_binding` now also requires a route that takes a token ID
from its form or body to ask about that token's issuer. Two routes are declared as naming
another authority's credential by design: a verifier recording a verification, and a verifier
recording a duress signal. Run against the rc.32 routes, the check fails.

Counterexample, failing on rc.32:
`BoundOperatorActsOnlyAsItsAuthorityTests.test_revoking_asks_about_the_tokens_issuer_not_only_the_actor`.

## v1.0.0-rc.32 — 2026-09-24 (the transition route asked about an optional field)

CORE-BUG against rc.31 (EXT-SECURITY). Externally observable: `/tokens/<id>/transition` refuses
an operator bound to an authority other than the token's issuer. No schema change. Nothing is
published.

The route checked the operator's binding only against `actor_agency_id`, an optional form
field. A bound operator who left the field out moved another authority's credential to `LOST`,
`EXPIRED` or `DORMANT` with no check at all. Revocation was not reachable: rc.19's gate refuses
a direct move to `REVOKED`. Measured: an operator bound to authority 1 moved authority 3's
token 2 (302, the transition applied).

rc.31's `check_state_changing_routes_ask_the_binding` counted this route as bound, because it
does call `_operator_authority_permits`, behind that `if`. The route now always checks the
binding against the token's own issuer, and checks the named actor as well when one is given.
The check now also requires a route whose path names a token to look up that token's issuer.
Run against the rc.31 route, it fails.

Counterexample, failing on a worktree of rc.31:
`BoundOperatorActsOnlyAsItsAuthorityTests.test_a_transition_without_an_actor_still_asks_the_binding`.

## v1.0.0-rc.31 — 2026-09-24 (a bound admin could rewrite another authority's record)

CORE-BUG against rc.30 (EXT-SECURITY). Externally observable: `/agencies/<id>/edit`,
`/agencies/<id>/delete` and `/tokens/<id>/delete` refuse an admin bound to another authority.
No schema change. Nothing is published.

The sweep rc.30 prompted listed every POST route an admin or operator can reach, and whether
each checks the operator's binding. Three more asked nothing:
- **agency edit**: an admin bound to authority 1 changed authority 2's name, type,
  jurisdiction and authorization level (measured: 200);
- **agency delete**;
- **token delete**.

Each now checks the binding against the authority it names or owns.

The remaining unchecked routes are instance-wide by design. `check_state_changing_routes_ask_
the_binding` (check 323) declares each with its reason:
- people, who belong to no authority;
- creating an authority;
- the anchor ledger;
- epoch close;
- the warrant audit (a read, posted as a form);
- `/sql`, which refuses a bound account itself.

Any other state-changing admin or operator route with no binding check fails the build. A
declaration whose route has gone fails it too, so the list cannot become a list of exceptions
nobody holds.

Counterexample, failing on a worktree of rc.30:
`BoundOperatorActsOnlyAsItsAuthorityTests.test_a_bound_admin_edits_and_deletes_only_its_own_authority`.

## v1.0.0-rc.30 — 2026-09-24 (a bound admin decided another authority's recovery)

CORE-BUG against rc.29 (EXT-SECURITY), partly a regression from rc.19. Externally observable:
`/uc9/decide/<id>` refuses an account bound to an authority other than the one that requested
the recovery, and `/uc5/bind-device` and `/uc6/migrate` refuse an account bound to an
authority other than the token's issuer. No schema change. Nothing is published.

rc.15 made every route that names an authority check the operator's binding. Three state-
changing routes name something else, and asked nothing:
- **`/uc9/decide/<id>`** names a recovery request. It belongs to the authority that requested
  it, and approving it issues the new credential under that authority. A rejection was never
  refused. An approval had been refused only by the row-level policy on the credential insert,
  and rc.19 made `uc9_complete_recovery` `SECURITY DEFINER`, which the policy does not bind.
  Measured: an admin bound to authority 1 rejected authority 2's recovery request.
- **`/uc6/migrate`** names a token, and signs it under its issuer's key.
- **`/uc5/bind-device`** names a token.

The last two relied on the row-level policy hiding another authority's token from their
lookup. That holds for the application role and for nothing that runs as the owner. The test
suite, which connects as a superuser, measured `/uc6/migrate` re-signing authority 3's token for
an operator bound to authority 1.

`/uc9/decide` now checks the binding against the request's requesting authority, as the
attestation revocation checks the attestation's owner. `/uc5` and `/uc6` check it against the
token's issuer through `_token_authority_denied`.

Counterexamples, failing on a worktree of rc.29 (`BoundOperatorActsOnlyAsItsAuthorityTests`):
- `test_a_bound_admin_cannot_decide_another_authoritys_recovery`;
- `test_device_binding_and_migration_stay_within_the_binding`.

## v1.0.0-rc.29 — 2026-09-24 (rc.28 moved one clock, and two comparisons assumed it had not)

CORE-BUG against rc.28, and a regression it introduced. Externally observable: on an app host
whose local zone is not UTC, an expired ZK epoch is refused again, and the Atlas time windows
cover the span they name. No schema change. Nothing is published.

rc.28 pinned the database's timezone to UTC. Two comparisons read a TIMESTAMP-without-zone
column, written in the database's wall clock, against the app's `datetime.now()`. Their
comments gave the reason: "app and DB are co-located", so both clocks share a zone.
- **The ZK epoch boundary** (`_zk_verify_and_consume`): with the database on UTC and the app
  behind it, an epoch that ended half an hour ago read as still open for the length of the
  offset, and a proof against it was verified.
- **The Atlas windows**: a one-hour window stretched by the offset and took in an event three
  hours old.

The login lockout had learned this on 2026-09-17 and asks the database's clock. Both
comparisons now do the same, through `app._db_now()` (the database's `LOCALTIMESTAMP`).

Counterexamples, failing on a worktree of rc.28 (app on `America/New_York`, database on UTC):
- `ZKSnarkTests.test_an_epoch_that_ended_by_the_databases_clock_is_refused`
  (rc.28 went on to verify);
- `AtlasFilterAPITests.test_the_window_is_measured_on_the_clock_that_wrote_the_events`
  (rc.28 counted the three-hour-old event in a one-hour window).

## v1.0.0-rc.28 — 2026-09-24 (the database judged dates on its own clock)

CORE-BUG against rc.27. Externally observable: on a database initialised outside UTC,
attestation validity is now judged on the UTC date. Schema change: migration
`2026-09-24-005-database-clock-is-utc`. Nothing is published.

rc.27 moved credential expiry onto the UTC date, to agree with the signed status assertion and
the standalone verifiers. Attestation validity is judged in SQL, against `CURRENT_DATE`:
- the federation trust check behind `/verifications/new`;
- the relying-party API's trust queries;
- the Athena functions.

`CURRENT_DATE` answers in the session's timezone, and nothing pinned it. The shipped containers
run UTC by accident of the image. A database initialised anywhere else (the development
database here reports `America/New_York`) judged trust on its local date and signed on UTC's
for hours of every day.

`09_grants.sql` now sets the database's timezone to UTC with `ALTER DATABASE`, as it already
does the revocation defaults, so every session gets it without asking. The migration does the
same for an existing install; round-tripped on a scratch database (UTC, default, UTC). The full
suite passes with every test database on UTC, so nothing depended on the local zone.

Counterexample, failing on a worktree and database of rc.27:
`ZKSnarkTests.test_the_database_judges_dates_on_the_utc_clock` (`'America/New_York' != 'UTC'`).

## v1.0.0-rc.27 — 2026-09-24 (expiry was judged on the server's date, and the signature on UTC's)

CORE-BUG against rc.26. Externally observable: on a server whose local timezone is not UTC,
whether a credential is expired now follows the UTC date. No schema change. Nothing is
published.

`_not_expired` compared `expiration_date` with `date.today()`, the server's local date. The
signed status assertion ends an `ACTIVE` credential at `00:00Z` the day after its expiry, and
the standalone verifiers read UTC. rc.8 set the rule that the offline answer must agree with
the online one. On a host behind UTC the two disagreed for hours around every expiry date, and
the status assertion could be issued with an `expires_at` earlier than its `issued_at`. On a
host ahead of UTC, the credential expired early.

Measured at 19:00 UTC under `TZ=Pacific/Kiritimati` (UTC+14): rc.26 called a credential
expired on its own UTC expiry day. `_not_expired` and card personalization now take the date
from `datetime.now(timezone.utc)`.

The test runs the check in subprocesses under UTC+14 and UTC-12. At any moment one of those
zones disagrees with UTC about what today is, so the local-date version fails it at every hour
of the day, not only near midnight.

Counterexample, failing on a worktree of rc.26:
`ZKSnarkTests.test_expiry_is_judged_on_the_utc_date_whatever_the_server_zone`.

## v1.0.0-rc.26 — 2026-09-24 (a refused attestation stood anyway)

CORE-BUG against rc.25. Externally observable: `/api/federation/attest` records an
attestation and its signature in one transaction, so a refusal now means nothing was recorded.
In the development signing profile the edge is recorded unsigned rather than refused. No schema
change. Nothing is published.

The attestation route called `uc10_attest_trust`, committed, and only then signed the new edge
under the attesting authority's key. When signing failed, the caller got an error while the
attestation it described stood, recorded and unsigned. Failures included a custody error
(raised as a 500, since it is not a database error) and a constraint on the signature columns.
Measured under the test profile: 400 `Constraint violation.`, and the attestation count went
from 6 to 7. The failing constraint was `attestation_signature_complete`: the development
placeholder signer names no key, and the table refuses a signature without one, so every
attestation toward an authority with a registered key hit it.

The edge and its signature now commit together, and any failure rolls both back. A signer that
names no key leaves the edge unsigned, which the verifier already reports as such, instead of
recording bytes nothing can verify.

Found by a held-out round on `federation_routes.py`: ten mutations, of which six survived the
route's own test classes. Two of those (the signed statement losing its attested key, or its
canonical order) were caught by `test_canonical_equivalence`, an instrument the round had
missed. Four were genuine gaps, now pinned:
- the signature must be under the ATTESTING authority's key;
- a second signing must not replace the recorded signature;
- the viewer must show an expired attestation as `EXPIRED`;
- the viewer must count it as expired.

Writing the first of those four tests surfaced this defect.

Counterexamples, failing on a worktree of rc.25:
`IssuerFederationTests.test_an_attestation_that_cannot_be_signed_is_not_recorded` and
`test_a_placeholder_signature_leaves_the_edge_unsigned_not_refused`.

## v1.0.0-rc.25 — 2026-09-24 (a card could be made for an expired credential)

CORE-BUG against rc.24. Externally observable: `polaris_card.personalization.personalize`
refuses a credential past its `expiration_date`. No schema change. Nothing is published.

The last site in the sweep rc.23 began. Personalization refused a credential that was not
`ACTIVE`, so that a card, a signed object that then leaves the authority's control, is never
made for a credential the authority withdrew. It fetched `expiration_date` and never read it,
and an expired credential still reads `ACTIVE`. A card was personalized for it.

It now refuses one past its date, with the inclusive rule `rp_api._effective_status` applies.
`polaris_card` cannot import the web app, so the rule is stated again there, and the comment
names the function it must agree with. The device verifier needed nothing: its status comes
from a status assertion or the online check, and both honour the date.

Counterexample, failing on a worktree of rc.24:
`CardPersonalizationTests.test_an_expired_credential_gets_no_card`.

## v1.0.0-rc.24 — 2026-09-24 (an expired credential still signed its holder in)

CORE-BUG against rc.23 (EXT-SECURITY). Externally observable: an expired credential can no
longer sign in, authorize holder signing or bind a holder key, and the verifiable credential
and the mdoc attest it `EXPIRED` and not usable. No schema change. Nothing is published.

Nothing moves `ACTIVE` to `EXPIRED` when `expiration_date` passes. The status assertion learned
this at rc.8 and signs an expired credential `EXPIRED`. Five other relying-party routes read
the stored status and treated an expired credential as live:
- **login**: `/api/v1/auth/authorize` issued an authorization code for it;
- the verifiable credential signed `verificationResult: usable`, `credentialStatus: ACTIVE`;
- the mdoc signed `credential_status: ACTIVE`;
- holder signing (`/api/v1/sign/<agency>/holder`) and holder-key binding (`/api/v1/holder-key`)
  accepted it.

Found by the sweep rc.23 prompted: every place that decides liveness from `status` alone.

`rp_api._effective_status(row)` is now the one answer: `ACTIVE` past its (inclusive)
`expiration_date` is `EXPIRED`. The status assertion, all five routes above, and nothing else
compute it separately.

Counterexamples, failing on a worktree of rc.23:
`AuthBrokerTests.test_an_expired_credential_cannot_sign_in` (rc.23 returned 200 and a code) and
`ZKSnarkTests.test_an_expired_credential_is_not_signed_as_usable` (rc.23 signed `usable`).
`test_effective_status_is_the_one_answer_to_is_it_live` pins the boundary: the last valid day
is still valid.

## v1.0.0-rc.23 — 2026-09-24 (rc.22's guard read status alone, and an expired credential still reads ACTIVE)

CORE-BUG against rc.22. Externally observable: `/verifications/new` refuses a `SUCCESS`
against a credential past its `expiration_date`, as well as one that is not `ACTIVE`. No
schema change. Nothing is published.

rc.22 refused a `SUCCESS` against a credential whose status is not `ACTIVE`. But expiry is not
written back to status: rc.8 made the status assertion honour `expiration_date` for exactly
that reason. So a credential past its date still reads `ACTIVE`, and rc.22 recorded a
`SUCCESS` against it.

The guard now applies the relying-party API's own definition of currently valid: `ACTIVE`
**and** `_not_expired(expiration_date)`, calling the same function so the two cannot drift.

Counterexample, failing on rc.22:
`IssuerFederationTests.test_a_success_is_not_recorded_against_an_expired_active_credential`.

## v1.0.0-rc.22 — 2026-09-24 (a verification of a revoked credential was recorded as a success)

CORE-BUG against rc.21. Externally observable: `/verifications/new` refuses to record a
`SUCCESS` against a credential that is not `ACTIVE`. No schema change. Nothing is published.

The verification form appends to `VerificationEvent`, part of the audit-of-record. It already
refused a `SUCCESS` that the federation trust graph does not support, and its docstring says
why: the record would say something untrue. It never asked whether the credential was live.
Measured: the sample's `REVOKED` token 5, verified by the agency that issued it (implicitly
trusted, so the federation gate passes), was recorded as `SUCCESS`.

A `SUCCESS` against a revoked, lost, expired or not-yet-activated credential is untrue in the
same way, whoever the verifier trusts. The form now refuses it and tells the operator to record
the outcome the credential actually had. `FAILURE` against a dead credential is still recorded:
that a revoked credential was presented and refused is exactly what the log is for.

The guard is on the route, beside the federation gate it mirrors, not a trigger. The other
writers of `VerificationEvent` are the simulator, the benchmark and the capacity drill, which
generate synthetic load.

Counterexample, failing on rc.21:
`IssuerFederationTests.test_a_success_is_not_recorded_against_a_dead_credential`.

## v1.0.0-rc.21 — 2026-09-24 (the quantum migration left spare credentials on the fallen algorithm)

CORE-BUG against rc.20. Externally observable: a population migration now re-signs and, when
its window closes, deprecates `RESERVE` credentials along with `ACTIVE` ones, and the window
will not close while a spare is unmigrated. No schema change. Nothing is published.

`migration.py` re-signs a population under a new algorithm when the old one falls, then
closes the window by deprecating the old signatures. Its population was
`status = 'ACTIVE'`. A `RESERVE` credential is the spare a holder is moved onto when theirs is
lost (UC-4), so it was neither re-signed nor had its old signature deprecated. After a
completed migration, every spare still stood on the fallen algorithm alone. Activating one
issued a brand-new credential on exactly the algorithm the migration existed to leave.

Found by the sweep rc.20 prompted: every `status = 'ACTIVE'` query in the tree, asked whether
it meant "active now" or "can still be live". The others (proof membership snapshots, counts,
dashboards) mean "active now" and are unchanged.

The population is now `ACTIVE` and `RESERVE`, for re-signing, for the pending count that holds
the window open, and for deprecation. `test_only_active_credentials_are_re_signed` selected
`status <> 'ACTIVE'`, which picked the seed's spare. It pinned the defect rather than its own
rationale about revoked credentials. It is now `test_only_live_credentials_are_re_signed` and
selects a terminal credential.

The quantum-event drill's population was all `ACTIVE`, so it could not see spares. It now
seeds one for every tenth subject and asserts, after the window closes, that every spare
stands on the new algorithm alone. With the population put back to ACTIVE-only, that row
reports 301 spares left on the old algorithm.

Counterexample, failing on a worktree of rc.20:
`PopulationMigrationTests.test_a_spare_credential_is_migrated_with_the_population`.

## v1.0.0-rc.20 — 2026-09-24 (a pilot's wind-down left its spare credentials alive)

CORE-BUG against rc.19. Externally observable: a pilot wind-down now revokes the pilot's
`RESERVE` credentials, and refuses as co-signer an authority that issued only spares into the
pilot. No schema change. Nothing is published.

`pilot.wind_down` revokes every credential the pilot issued, then pseudonymizes every
participant. The consent language promises "the withdrawal of every credential". The function
selected credentials with `status = 'ACTIVE'`. A `RESERVE` credential is pre-issued so a holder
can be moved onto it, and `RESERVE -> ACTIVE` is a legal transition, so a spare is a credential
that can still become live.

Measured on a copy of the test database: after a full wind-down, the sample `RESERVE` token was
still `RESERVE`, and its holder was `PSEUDONYMIZED-1`. The same selection fed the co-signer
check. Agency 2, which had issued that spare and nothing `ACTIVE`, was accepted as co-signer of
a wind-down of its own credentials.

Fixed by one list of live statuses, `pilot.LIVE_STATUSES = ("ACTIVE", "RESERVE")`, which is now
used for four things:
- what is revoked;
- who counts as an issuer for the co-signer check;
- who is kept because another authority still serves them;
- the dry run's report.

`DORMANT` has no outgoing transition and stays outside it. The wind-down drill's final check
counted `ACTIVE` alone, the same blind spot; it now counts `ACTIVE` and `RESERVE`.

Counterexamples, failing on a worktree of rc.19:
`PilotWindDownTests.test_a_wind_down_leaves_no_credential_that_can_come_back` and
`test_an_authority_that_issued_only_spares_cannot_cosign`. On rc.19 the second did not merely
miss a refusal: the issuing authority co-signed, and the wind-down ran.

## v1.0.0-rc.19 — 2026-09-24 (revocation's only door was a setting the caller could set)

CORE-BUG against rc.18. Externally observable: the application role can no longer move a token
into `REVOKED` except through the revocation procedures, and a session can no longer loosen
the default revocation bound. Schema change: migration `2026-09-24-004-revocation-gate-by-role`.
Nothing is published.

`trg_enforce_revocation_velocity` is what makes `uc8_revoke_token` the only way into
`REVOKED`. It refuses a plain `UPDATE ... SET status='REVOKED'`, and it admitted the transition
when the session had set `polaris.revoke_check_done`. The procedure sets that flag after it has
checked the rate bound and the co-signer. But any session can set a session setting. Measured
as `polaris_app`, the role an installed deployment connects as:
`SELECT set_config('polaris.revoke_check_done', '1', false)` followed by the plain `UPDATE`
revoked the token. The rate bound, the co-signer rule and the CRL publication were all
skipped. The trigger's own comment said a direct UPDATE "from psql, the SQL console, or app
code" would be rejected.

The same shape held one level down. With no per-agency policy, `uc8_revoke_token` read the
default bound with `current_setting('polaris.default_max_revoke_percent')`. `09_grants.sql`
sets that with `ALTER DATABASE`, and a session can override it for itself. So the caller could
choose the bound it was about to be held to.

The fix copies the design `uc_archive_purge` already uses:
- The three procedures that set the flag (`uc4_activate_reserve`, `uc8_revoke_token`,
  `uc9_complete_recovery`) now run `SECURITY DEFINER`, with a pinned `search_path`. Each
  authenticates its actor by parameter, never by `current_user`, so running as the owner
  weakens no gate.
- The trigger honours the flag only when the current role owns `uc8_revoke_token`. That holds
  inside the procedures and for the schema owner, who could drop the trigger anyway. It never
  holds for the application role.
- `uc8_revoke_token` reads the default bound through the new
  `polaris_database_setting()`, which returns the database's setting and ignores the
  session's.

Migration tested on a scratch database built from rc.18. Before it, the self-set flag revokes;
it applies (refused, all three procedures `SECURITY DEFINER`), reverts (revokes again) and
re-applies (refused).

The existing test of this trigger ran as the schema owner, which owns the procedure. The new
tests run as `polaris_app`.

Counterexamples, failing on rc.18:
`IssuerDiscretionBoundsTests.test_the_application_role_cannot_unlock_the_trigger_itself` and
`test_a_session_cannot_loosen_the_default_bound`.
`test_the_application_role_revokes_through_the_procedure` is the control: the sanctioned path
still works for the application role.

## v1.0.0-rc.18 — 2026-09-24 (the SQL console cannot be scoped, so a bound account cannot use it)

CORE-BUG against rc.17. Externally observable: `/sql` returns 403 to an account bound to one
authority. No schema change. Nothing is published.

An operator bound to one authority is held to that authority's rows by row-level policies.
The policies read the scope from the session setting `polaris.operator_agency_id`, which the
application sets on every connection it opens for that operator. The SQL console opens such a
connection and then runs the operator's own text. A read-only transaction still permits
`set_config()`, and one `execute()` runs every statement in the string. So a bound admin or
auditor could post
`SELECT set_config('polaris.operator_agency_id', '', false); SELECT * FROM IdentityToken`
and read every authority's credentials.

Measured as the application role (`polaris_app`) in a read-only transaction, which is what the
console runs: a scope that hid two of five credentials hid none once the query cleared it.

Neither parsing the text nor re-checking the setting afterwards can close this. Parsing misses
a function call, a CTE or a separator inside a string, and the query can put the setting back
before it returns. The console now refuses a bound account outright, on GET and POST, and says
why. Unbound accounts, the default for every single-authority instance, keep it.

`scripts/polaris-authority-isolation-drill.py` said a bound operator could not read another
authority's credentials "through a raw SQL query". It now says the policies bound the queries
the application issues, never SQL the operator writes.

Counterexample, failing on rc.17:
`SQLConsoleTests.test_an_account_bound_to_one_authority_is_refused_the_console`. The escape
itself is measured by `test_why_a_bound_account_cannot_have_it_a_query_lifts_its_own_scope`,
and `test_an_unbound_account_keeps_the_console` guards the default.

## v1.0.0-rc.17 — 2026-09-24 (a document someone only looked at is not SUPERIOR evidence)

CORE-BUG against rc.16. Externally observable: the assurance level derived from some
evidence is lower. No schema change. Nothing is published.

v9.395 capped what evidence contributes by how it was **verified** (bound to the applicant):
a posted code caps at `FAIR`, knowledge-based answers at `WEAK`. It left how the document was
**validated** (checked to be genuine) uncapped. Any method other than `NONE` let the evidence
count at its full nominal strength. So a passport an operator only looked at
(`VISUAL_INSPECTION`) counted as `SUPERIOR`, and one `SUPERIOR` piece is IAL2 on its own.

NIST SP 800-63A grades validation the same way it grades verification:
- trained personnel inspecting a document reach `FAIR`;
- confirming the integrity of its physical security features reaches `STRONG`;
- `SUPERIOR` needs its cryptographic features checked, or its details confirmed with the
  issuing source.

`proofing.VALIDATION_CEILING` now caps `VISUAL_INSPECTION` at `FAIR` and
`PHYSICAL_SECURITY_FEATURES` at `STRONG`. `DIGITAL_SIGNATURE_CHECK` and
`ISSUING_SOURCE_CONFIRMATION` carry no ceiling. When both ceilings apply, the lower one wins.
`why_not_higher` now counts pieces that were capped, so an operator sees why a passport did
not reach IAL2.

Neither capped method was used by any test, drill or check before this entry. The same was
true of both verification methods v9.395 capped.

Existing `EnrollmentProofing` rows are append-only and are not rewritten. A record derived
under rc.16 from a visually inspected document keeps its level until the person is re-proofed.
The current level is the latest proofing event's level, so re-proofing sets it.

Counterexample, failing on rc.16:
`IdentityProofingTests.test_how_it_was_validated_caps_what_it_contributes` and
`test_a_looked_at_passport_does_not_carry_an_ial2_enrollment`.
`check_enrollment_proofing` exercises the ceiling through `effective_strength`. Its detection
test fails the check when the ceiling is removed, when it is set higher than the method can
reach, and when a `SUPERIOR` method is capped.

## v1.0.0-rc.16 — 2026-09-24 (a deactivated admin authorizes nothing)

CORE-BUG against rc.15. Externally observable: five procedures now refuse a deactivated admin.
Schema change: migration `2026-09-24-003-deactivated-admin-holds-no-authority`. Nothing is
published.

`uc9_complete_recovery` and `uc_pseudonymize_individual` refuse an actor whose account is not
active; `uc_pseudonymize_individual` says why ("a deactivated admin" cannot act). Five other
admin-gated procedures checked `AppUser.role` and never `AppUser.is_active`:
- `uc10_attest_trust`;
- `uc10_revoke_attestation`;
- `uc11_close_epoch`;
- `uc_apply_retention_template`;
- `uc_archive_purge`, the one `DELETE` path into the append-only audit, `SECURITY DEFINER`.

A deactivated admin's user id still authorized all five. The web routes could not reach them
with that account, because a deactivated account's sessions end. The CLI and the operator
scripts pass a user id straight in.

Each now refuses with `insufficient_privilege` after its role check. `05_procedures.sql`
carries the change for a fresh install, and the migration carries the five bodies for an
existing one. Measured on a scratch database built from rc.15: the migration applies (the
deactivated admin is refused), reverts (accepted again) and re-applies.

Counterexample, failing on rc.15:
`DeactivatedAdminHoldsNoAuthorityTests.test_a_deactivated_admin_authorizes_nothing`, five
procedures. A control shows the live admin is never refused for being inactive.

Found while reading `uc10_attest_trust` for a held-out round: its role check was the sibling of
a check two other procedures make with one more column.

---

## v1.0.0-rc.15 — 2026-09-24 (an operator bound to one authority acts only as that authority)

CORE-BUG against rc.14. Externally observable: nine routes now refuse, with 403, a bound
operator acting as another authority. Nothing is published.

`_operator_authority_permits` states the rule: an operator bound to an authority may only act as
that authority. It covers the half row-level policy cannot reach, because issuing, revoking and
signing are not reads. Two exchange routes called it. Nine routes let the request name the
authority that acts, and none asked:
- `/uc1/issue`;
- `/uc4/activate-reserve`;
- `/uc8/revoke`;
- `/uc9/initiate-recovery`;
- `/verifications/new`;
- `/api/duress/record`;
- `/tokens/<id>/transition`;
- `/api/federation/attest`;
- `/api/federation/revoke`.

Measured on rc.14: an admin bound to agency 2 posted an attestation naming agency 1 as the
attester, and got attestation #7 back, recorded as agency 1. The attestation ceremony signs an
edge under the attesting authority's own key whenever that authority has one. The same admin
issued a credential as agency 1.

Each route now refuses before anything is signed or written. Federation revoke asks the question
of the attestation's own attester. An unbound operator is unaffected: that remains the
single-authority default.

Counterexamples, nine of them, failing on rc.14: `BoundOperatorActsOnlyAsItsAuthorityTests`. A
control shows the same request as the operator's own authority is not refused by the binding.

`check_operator_acts_only_as_its_authority` fails any route that reads `issuing_agency_id`,
`actor_agency_id`, `requesting_agency_id` or `attesting_agency_id` from the request and does
not call the guard. A detection test covers both read forms and the empty case. The design
record, `per-authority-isolation.md`, states the half the guard holds.

Found by asking which callers of the guard's signing sites could choose the authority. Two of
the twenty-odd signing sites were guarded.

---

## v1.0.0-rc.14 — 2026-09-24 (every id space is sized, and three that ran out are widened)

CORE-BUG against rc.13. Externally observable: the schema (migration
`2026-09-24-002-widen-enrollment-sequences`) and the capacity report. Nothing is published.

`check_capacity_model` states on every push that "every sequence in the schema outlasts the
25-year horizon at the roadmap's stated national targets". It had sized nine of forty. The model
read `CREATE TABLE IF NOT EXISTS X` as a table named `IF`, and skipped any table it had no growth
driver for, without a word. Sized, three of the other thirty-one are 32-bit `SERIAL`s that run
out inside the horizon at the roadmap's surge target of 200,000 enrollments a day:
- `EnrollmentStatusEvent.event_id`, 9.8 years: a `NOT_ENROLLED` row is seeded per person, then
  `PENDING` and `ENROLLED` follow;
- `EnrollmentEvidence.evidence_id`, 9.8 years: up to three evidence pieces per proofing;
- `HolderKeyEvent.event_id`, 14.7 years: a binding and a rotation per credential.

When a sequence is exhausted every insert on the path fails, and here the path is enrollment.

What changed:
- The migration widens all three, with their sequences, and recreates the two views that read
  them (`IndividualCurrentEnrollment`, `HolderKeyCurrent`) with their grants. It declares each
  widening for `check_migrations_expand_contract`. It round-trips, and it applies both to an
  rc.13 schema and to a fresh one.
- `01_schema.sql` carries `BIGSERIAL` for all three.
- Every sequence is now in `GROWTH`, with a rate and its basis, or in `BOUNDED`, with the reason
  its table does not grow with the population. The check fails on one in neither, named.

Counterexamples, failing on rc.13, in `test_capacity_model_check_discriminates`:
- the `IF` parse;
- an unsized sequence;
- a `SERIAL` back on `EnrollmentEvidence`.

`docs/design/capacity-model.md` records what the model had not sized.

---

## v1.0.0-rc.13 — 2026-09-24 (a session ended by a role change is ended, not an error)

CORE-BUG against rc.12. Externally observable: what an operator whose role changes sees, and
what the audit of record says about it. Nothing is published. Schema change: migration
`2026-09-24-001-session-role-changed`, which adds one allowed value.

Since 2026-09-17 (940af89), `validate_session` promises to end a live session whose account's
role changed while it was live, and to audit `SESSION_REVOKED`. It writes
`revoke_reason = 'role_changed'`. The constraint `chk_opsession_revoke_reason` was never widened
to admit that value.

Measured on rc.12: after `UPDATE AppUser SET role = 'auditor'`, the old session's next request
raised `CheckViolation` in the before-request hook. The UPDATE rolled back, so:
- the session was never revoked;
- `SESSION_REVOKED` was never written to the append-only audit;
- every request from the old session failed with a server error instead of ending it and
  redirecting to the login.

The migration adds `role_changed` to the constraint. Its down migration refuses while any row
carries that value. It round-trips on a scratch database, and `DATA-MODEL.md` lists the value.

Counterexample, failing on rc.12:
`SessionLimitTests.test_a_role_change_ends_the_live_session`.

Found by a held-out mutation round on `security.py`. Deleting the role-change branch survived
every suite, and the test written to catch that deletion is what met the constraint. The same
round closed four more survivors in `SecurityHeldOutTests`:
- the limiter allowing one past its bound;
- the limiter window never sliding;
- an unparseable address matching an allow-list;
- a negative session limit passing the boot.

After: 12 of 12.

---

## v1.0.0-rc.12 — 2026-09-24 (ending a pilot does not erase somebody another authority serves)

CORE-BUG against rc.11. Externally observable: what `scripts/polaris-pilot.sh winddown`
pseudonymizes. Nothing is published.

`wind_down` promises to revoke first and pseudonymize second, "because pseudonymizing first would
leave live credentials belonging to a holder nobody can name any more" (`polaris_web/pilot.py`,
`docs/operator/PILOT.md`). A wind-down scoped to one authority pseudonymized every person who had
ever held any credential from it. On a shared instance that includes somebody whose pilot
credential was revoked and who was since enrolled by a second authority. They were erased, and
the second authority's live credential was left belonging to a holder nobody can name.
Measured before the fix: `Maria Santos`, served by agency 3, became `PSEUDONYMIZED-2` when
agency 1's pilot was wound down.

Now a participant who still holds an ACTIVE credential after the pilot's own revocations is
kept. The result reports `participants_kept_for_another_authority`, and so does the dry run. The
pilot credential is still revoked. `PILOT.md` states the rule.

Counterexample, failing on rc.11:
`PilotWindDownTests.test_a_scoped_wind_down_does_not_erase_someone_another_authority_still_serves`.

Found by reading the scoped path of a module whose only drill winds down a single authority on
an instance that serves nobody else.

---

## v1.0.0-rc.11 — 2026-09-24 (a range check that NaN cannot pass)

CORE-BUG against rc.10. Externally observable: what `/api/atlas/clusters` and
`/api/atlas/hexbin` accept and return. Nothing is published.

Both endpoints state their bound, "grid must be in (0, 90]" and "size must be in (0, 90]", and
checked it as `x <= 0 or x > 90`. Every comparison with NaN is False, so `?grid=nan` passed.
Measured before the fix:
- `/clusters` answered 200 with `"grid": NaN` and every event in the box collapsed into one
  cluster;
- `/hexbin` answered 200 with `"lat": NaN, "lon": NaN` for its hexes;
- neither response is JSON a browser can parse;
- NaN in the cache key never equals itself, so each such request missed the cache and added an
  entry that evicted a real one.

Both checks are now `not (0 < x <= 90)`, which NaN fails. Counterexample, failing on rc.10:
`AtlasAPITests.test_a_grid_or_hex_size_that_is_not_a_number_in_range_is_400`. It also covers
infinity, zero and out-of-range values, and a NaN or infinite bbox, which the bbox parser
already refused.

Found by asking where else the coexistence module's NaN defect (d19ba5a, a sunset verdict that
passed a NaN share) could live: every float parsed from a request was read.

---

## v1.0.0-rc.10 — 2026-09-24 (a sealed store cannot write outside its destination)

CORE-BUG against rc.9. Externally observable: what `polaris-secrets.sh unseal` writes, and
where. Nothing is published.

`unseal` promises to materialize the sealed store into `POLARIS_SECRETS_DIR`, a tmpfs, so that
no plaintext touches the disk (`docs/operator/SECRETS.md`). It joined each name in
`MANIFEST.json` onto that directory. The manifest is not authenticated. Under `age`, anybody
holding the public recipients file can seal a blob. So a manifest naming `../escaped`, with a
matching blob and hash, wrote attacker-chosen bytes outside the tmpfs, next to it, on every
boot that ran `unseal-if-configured`. Measured before the fix: the file was written.

Now a manifest name that is not a plain file name (`../x`, `/etc/x`, `a/b`, `.`, `..`, empty, a
NUL, a backslash) refuses the whole store before any blob is read.
`SECRETS.md` now states what the store is and is not trusted for: the manifest is unsigned, and
under `age` write access to the store is write access to the secrets.

Counterexample, failing on rc.9:
`HeldOutSecretStoreTests.test_a_manifest_name_cannot_write_outside_the_destination`.

Found by reading the code for a held-out mutation round on `secretstore.py`. In that round six
of twelve mutations survived `test_secretstore`, `test_custody` and the check layer:
- the backend-mismatch refusal deleted;
- a missing mode defaulting to 0644;
- an empty manifest accepted;
- the backend name made case-sensitive;
- the awskms name check deleted;
- the awskms AEAD no longer bound to the name.

The last two were masked. The existing rename test MOVED the blob, so the store was refused for
a missing file before any name was compared. It now copies, and a second test edits the blob's
`name` field to match, which only the AEAD can catch. After: 12 of 12. The awskms tests also
ran nowhere locally until boto3 was installed in the test environment; CI installs it.

---

## v1.0.0-rc.9 — 2026-09-24 (a migration run says what it could not do)

CORE-BUG against rc.8. Externally observable: what `polaris migrate-population` reports, and
what `migrate_population` returns. Nothing is published.

`migrate_population` promised that re-running it finishes the job. Migrating back onto an
algorithm the population had already left breaks that promise for some credentials. A
credential that already holds a deprecated signature under the target algorithm cannot get
another one: a token holds one signature per algorithm (`one_signature_per_algorithm_per_token`),
and none ever changes. The batch selected those credentials anyway, and its insert did nothing
for them.

The batch then misreported its own work. The name that held the selected rows was reused for
the insert's result, so `selected` reported the rows written. A batch that wrote none of what
it selected looked like the end of the population. The run stopped without an error, the
command told the operator to "Run again to continue", which never reached those credentials,
and `--deprecate-old` refused forever with a message about finishing the migration first.
Nobody was left without a valid signature: those credentials still stood on the signature they
already had. But the window could never close, and the operator was not told why.

Now:
- a batch selects only credentials it can sign;
- `selected` counts what was selected;
- the run returns `blocked`, the credentials no run can reach;
- the command prints them as `cannot be re-signed` and says to re-issue them;
- `--deprecate-old` refuses naming the same count.

`QUANTUM-EVENT.md` explains the case. Counterexamples, failing on rc.8:
`PopulationMigrationTests.test_migrating_back_names_the_credentials_it_cannot_re_sign`,
`test_a_batch_reports_what_it_selected_not_only_what_it_wrote`, and the command-line
`MigratePopulationCommandTests.test_migrating_back_says_which_credentials_no_run_can_reach`.

Found by a held-out mutation round on `migration.py`. Before it, ten of twelve mutations
survived both the migration tests and the quantum-event drill. Four more tests close four of
them:
- one credential left is enough to refuse closing the window;
- closing the window leaves an earlier deprecation's date where it was;
- a negative grace period does not backdate the record;
- the verifiability report can count a credential whose signatures have lapsed.

That last test switches the trigger off for one transaction, because the report is meant to
be the independent check, not a restatement of the trigger. Two of the twelve mutations are
equivalent: a limit reached one batch later, and a case-insensitive algorithm name.

The three maps carry it: a Table 16 row in both editions, and the migration limit in the math
edition, which no longer calls rollback wholly unmeasured.

---

## v1.0.0-rc.8 — 2026-09-23 (the offline answer agrees with the online one about expiry)

CORE-BUG against rc.7. Externally observable: what `POST /api/v1/status-assertion` signs.
Nothing is published.

Authorization, whether a credential is authoritative right now, is answered two ways: online
by `/api/v1/verify`, and offline by a short-lived signed status assertion that a holder staples
to a presentation. The two must give the same answer. On 2026-09-17 `/verify` learned to read
`expiration_date`, because nothing moves a credential from `ACTIVE` to `EXPIRED` when its date
passes and the endpoint had been answering `currently_authoritative: true` for credentials past
their stated end. The status-assertion route was the sibling path and was not changed: it
signed the stored status alone. So a credential past its expiry date got a freshly signed
`ACTIVE` assertion, and every offline verifier, the published one included, accepted it. The
online answer said no; the offline answer said yes.

Now an `ACTIVE` credential past its `expiration_date` is asserted `EXPIRED`, by the same
`_not_expired` rule `/verify` uses, and an `ACTIVE` assertion's `expires_at` is capped at the end
of the credential's expiration date (00:00Z the day after it), so an assertion minted on the
last valid day does not outlive the credential by up to its TTL.

Found by reading the route while mutation-testing the relying-party endpoint around it: the
held-out round had just shown that endpoint's own expiry check was untested, and the question
was which other path answers the same question. The test
(`RelyingPartyApiTests.test_a_status_assertion_never_says_active_for_an_expired_credential`)
failed on rc.7 on the `ACTIVE` assertion, and fails with the cap removed on an assertion ten
days past the credential; it passes with both.

The promise: CLAUDE.md section 1 and docs/reference/API.md (authorization answered online or by
the offline assertion); API.md's `status` row now states the expiry rule and the cap.

The same commit carries tests only, no behaviour, for held-out rounds on the SDKs' grant
coverage, the OpenID4VP status-list authority and HTTP framing, and the published verifier's
QR frame decoder.

## v1.0.0-rc.7 — 2026-09-19 (total on hostile input, this time actually)

CORE-BUG against rc.5. Externally observable. One package: `polaris-oid4vp`. Nothing is
published.

`status.py`'s `decide` says "Total on hostile input" on its first line and raised
`RecursionError` on a status list token nesting 30,000 arrays. `RecursionError` is not a
`ValueError`, so the `except (ValueError, UnicodeDecodeError)` around the parse never saw it.
The body is fetched from a URI named inside somebody else's credential, which is exactly the
input an attacker controls, and a verifier that dies on one credential has failed open for
every other credential in the queue.

**`sdjwt.py`, in the same package, has bounded JSON size, nesting depth and the bare constants
since 2026-09-17**, after 2,780 bytes of `[[[[...]]]]` raised out of it for the same reason.
I promoted this module out of `lab/` into a published package without carrying that lesson
across, so it shipped in rc.5 with a defect its sibling had already fixed. Found by asking
what the file next door protects against that this one does not.

`_json_bounded` now applies all three: 64 KiB, 64 levels, and `parse_constant` refusing NaN
and Infinity. Refusing the shape before parsing rather than catching `RecursionError`, because
that fires at a point depending on how much stack the caller already used, so the same input
is accepted from one call site and raises from another.

**Two copies of a security decision function is how they stop agreeing**, and it nearly
happened inside a day: the lab original would have kept the defect while its own adversaries
reported all clear. The lab copy is deleted and its 24 adversaries now import from the
package, so they attack what a relying party installs.

244 tests across seven suites; four mutations confirm each bound. One of those four found a
weak test rather than weak code: the first depth fixture used `{"a":` nesting at six bytes a
level, so 20,000 levels was 120 KB and the SIZE bound refused it. Removing the depth bound
changed nothing and the test did not notice. Nested arrays at two bytes a level keep 30,000
levels inside the size budget, where only the depth bound can refuse them.

That is the third time in one day a test passed because a mechanism other than the one it
named satisfied it.

---

## v1.0.0-rc.6 — 2026-09-19 (the capability rc.5 shipped, reachable from the thing you use)

A correction to rc.5, as a later entry rather than an edit to it. Externally observable. One
package: `polaris-oid4vp`. Nothing is published by this entry.

rc.5 added `status_resolver` to `verify_presentation` and did not thread it through
`Verifier`. `Verifier` is the class an operator constructs, the one that answers the wallet,
and the one the README's own run instructions show. So the capability existed in the package
and not in the product: a relying party using the documented entry point could not supply a
resolver at all, and nothing said so.

`Verifier(..., status_resolver=...)` now takes it and hands it down. The default is unchanged
in both places: no resolver means `not_evaluated`.

**The test written for this first did not catch it, and that is the more useful half.** It
asserted `assertIs(verifier.status_resolver, resolver)` against a fixture credential carrying
no status claim. Both were true with the resolver held in `__init__` and never passed on: the
object had it, nothing used it, and the assertion could not tell the difference. Removing the
threading left the suite green.

The credential has to NAME a status list, and the assertion has to be that the resolver's
answer reached the verdict. It does now, and two mutations confirm it: dropping the resolver
in `__init__` and failing to thread it past there both turn the suite red.

That is the second time today a test asserted the shape of a mechanism rather than its effect,
after a status-list adversary that checked a verdict was "not accepted" without checking which
refusal it was. Both passed against code that did not work.

240 tests across seven suites.

---

## v1.0.0-rc.5 — 2026-09-19 (asking is opt-in, and the answer can be absent)

Externally observable, so it is a version. One package moved: `polaris-oid4vp`. Nothing is
published by this entry; `docs/RELEASING.md` still records rc.3 on the registry.

rc.4 made the verdict say what it had NOT established about revocation. This adds the way to
establish it, and keeps the default exactly where rc.4 left it.

**`polaris_oid4vp.status` decides a Token Status List token.** `draft-ietf-oauth-status-list`
is the mechanism SD-JWT VC, CWT and ISO mdoc all reference, so one implementation reaches all
three. It is pure: `decide` is handed a token, `decide_by_fetching` is handed a `fetch`
callable. Nothing in it opens a socket, because timeouts, retries, connection limits and
caching are policy and belong to the caller.

**Asking is opt-in.** `verify_presentation(..., status_resolver=...)` takes a callable the
relying party supplies. With no resolver the verdict is `not_evaluated`, unchanged from rc.4,
which is the honest thing to say about a list nobody read. It is opt-in rather than automatic
because a status check couples your verification path to somebody else's uptime, and a library
that made that choice silently would be deciding, on the relying party's behalf, that their
traffic stops when a third party's endpoint does.

**Two states that must not be confused, and the reason this is a version and not a
refactor.** `not_evaluated` says nobody looked. `unreachable` says somebody looked and no
answer came back. A verifier that reports them identically has decided, without being asked,
that an unreachable status endpoint is as good as a credential whose issuer publishes none.
"I could not reach the list" is not "not revoked", and it is the state implementations lose
first, because refusing traffic when a third party is down is expensive and the pressure to
shrug is real.

**Who may publish status for whom is stated, not inferred.** The draft does not settle it:
section 11.3 says the Status Issuer MAY reuse the credential issuer's key when they are the
same entity and SHOULD share a Certificate Authority when they differ, both recommendations,
and `iss` is not even a required claim of a Status List Token. So a fetched list is signed by
a key the token often does not name, and the only binding it carries is `sub` equal to the
`uri` the credential gave. Fetch that URI and believe whatever signed the response and you
have asked DNS an authorization question. `StatedAuthority` requires an operator to record
that a named key may publish status for a named issuer at a named URI, and why; anything else
is `no_authority`. Authority is established BEFORE any fetch, so a URI inside an unvetted
credential is never a place a request is sent.

**What is refused, and what a refusal means.** A list published for another URI, a plain JWT
offered as a status list, an expired list, an index past the end of the array, a signature
that does not verify, a decompression bomb, an application-specific status value folded into
VALID, and a stale-but-unexpired list used to roll a revocation back: that last one is only
visible as age, so the verdict carries it and a caller can bound it. A 404 page is
`unreachable`, not a malformed list, because the endpoint failing is not the issuer publishing
something broken.

22 tests in `test_status.py`, and five more in `test_sdjwt.py` for the resolver hook, each
confirmed by mutation: a raising resolver reported as "nobody looked", a nonsense return
trusted, and the resolver ignored entirely all turn tests red.

The research, the twenty-two adversaries and the decision record that admitted this work are
in [lab/strategy/001-token-status-list.md](lab/strategy/001-token-status-list.md).

---

## v1.0.0-rc.4 — 2026-09-19 (a credential that might be revoked)

Externally observable, so it is a version and not housekeeping. One package moved:
`polaris-oid4vp`. Nothing else changed and nothing is published by this entry.

**The verdict now says what it did not establish about revocation.** `polaris-oid4vp`
verifies a presentation from a wallet that has never heard of Polaris: issuer signature,
`vct`, disclosure digests, `exp`, `nbf`, holder key binding, nonce, audience. Its verdict
was `{authentic, code, reason, claims}`, and there was no field about revocation anywhere
in it.

An SD-JWT VC's `status` claim is issuer-signed and, by the specification, MUST NOT be
selectively disclosable. This verifier already knew that: `status` sits in the list of
claim names a disclosure may never carry. So it parsed the claim, protected it, handed it
back inside `claims`, and said nothing about it. A relying party reading `authentic: true`
was being told the strongest thing this code can say, while the second question a relying
party actually has went unasked and unmentioned.

That is the principle rc.3 published, one surface over. rc.3 added `trust_evaluated` to
the detached verifier so three states would be distinguishable rather than collapsed, and
said of the two issuer fields that either is null when it cannot be established, "which is
not the same as false". Revocation had no field at all, so it did not have two states to
confuse: it had silence.

The verdict carries `revocation` now, in one of three states, and a relying party that
cannot tell them apart cannot make a decision about any of them:

- `no_status_claim`: the credential names no revocation list, so there is none to read.
- `not_evaluated`: it names a Token Status List at a URI and an index, and this verifier
  did not fetch it. Whether the issuer has revoked this credential is UNKNOWN, not false.
- `unsupported_status`: it carries a status claim in a form this verifier cannot read,
  which is not evidence that the credential is current.

**No status list is fetched, and that is the point of the change rather than a gap in it.**
Fetching is an online operation with a timeout, a cache and its own failure semantics, and
this package does not do it today. Saying so costs nothing. Claiming otherwise, or staying
quiet and letting `authentic: true` carry the weight, is the overstatement being removed.

`authentic` is unchanged and still means what it meant: the issuer signed this, the
disclosures match what was signed, the holder proved possession, the credential is inside
its own validity window. It was never a statement about revocation.

Six tests pin the states apart, including one whose only job is to fail if an
implementation returns a single constant, and one that fails if any path ever reports a
revocation as checked while the package opens no socket. All three were confirmed by
mutation: making the state constant, reporting the unfetched list as checked, and reading
an unsupported claim as absent each turn tests red.

The research behind it, the Token Status List decision function and the sixteen
adversaries against it, stays in `lab/strategy/` and is not part of this version. See
[lab/strategy/001-token-status-list.md](lab/strategy/001-token-status-list.md) for what is
settled and what is not.

---

## v1.0.0-rc.3 — 2026-09-17 (a genuine signature is not a trusted issuer)

Two published-contract ambiguities, found by an outside design-intent review and
resolved against the owner's stated principles: signature validity must not silently
imply issuer trust, historical authorization and current-key status are separate facts,
and where a fact cannot be established safely the answer is UNKNOWN rather than a guess.

Both are externally observable, so this is a version and not housekeeping.

**The detached verifier abstains instead of implying trust.** `polaris-verify` computed
`accept` as `signature_valid and issuer_trusted in (None, True)`, and `None` is what you
get when the caller passes no `--issuer-anchor`. So a credential signed by any key at all
exited 0, indistinguishable, to anything branching on exit status, from a verification
against a trust root that matched. The JSON was honest (`issuer_trusted: null` was right
there); the exit code was not.

A run with no trust root now abstains with exit 2 and says why. `--signature-only` is how
a caller states that cryptographic validity alone is the question, and that run exits 0
while reporting `trust was NOT evaluated`. The verdict carries a new `trust_evaluated`
field so the three states are distinguishable in JSON as well as by exit code. This is the
same discipline the package already applied to `--pqc-provider`: the mode a run uses is
something the caller states, not something the machine decides for them.

Measured before and after in `lab/interop/verifier_trust_default.py`, which now stands as
the guard: it fails if the three states are collapsed back onto one exit code, and fails
equally if `--signature-only` stops working, because a verifier that cannot answer "does
this signature verify" has lost a use case rather than gained a guarantee.

**`issuer_authentic` is replaced by two fields, because it was answering two questions and
getting the common one wrong.** It compared the signing key against
`Agency.signing_public_key_hex`, the authority's CURRENT key. Since a signature row is
immutable and `polaris key-event ... registered` moves that column, the two diverge the
moment an authority rotates: every credential issued before the last rotation reported
`issuer_authentic = false` while being perfectly legitimate. The field fired on good
credentials, which teaches an integrator to ignore it.

`/verify` and the relying-party API now report:

- `issuer_authorized_at_signing`: was this key authorized for this authority at the
  instant the credential was signed? Survives an ordinary rotation.
- `issuer_key_current`: is that key still active for the authority today? A rotation makes
  this false, which is a fact about the key and not a verdict on the credential.

Either is `null` when it cannot be established, which is not the same as false.

**The instant is the one that cannot be moved.** Historical authorization is only
meaningful if the time it compares against is integrity-protected.
`IdentityToken.issued_date` cannot serve: IdentityToken carries a state machine and an
audit trigger but no immutability guard, and a database session can UPDATE it freely
(measured). The instant used is the `ISSUED` row in `TokenLifecycleEvent`, an audit of
record under C1, where the same edit is refused. With no `ISSUED` row there is no
trustworthy instant and the answer is `null` rather than a guess.

What this does not survive, stated rather than discovered later:
`AuthorityKeyEvent.effective_at` is operator-supplied, so an authority that writes its own
key history can backdate an authorization. This answers against the recorded history; it
does not defend against the operator who writes it, which is the operator-as-adversary
`lab/duress/` already names.

**Six cases pin the new semantics**, in `FederationInAppTests`: a credential surviving an
ordinary rotation (the case the single boolean got wrong), a key never authorized for that
authority, a key authorized at signing and retired later, a credential signed *after* its
key was retired (the one case that must answer false rather than null), no protected
issuance instant, and a placeholder signature that decides neither.

`check_federation_in_app` requires both field names, requires the rotation case by name,
and now fails if `issuer_authentic=` reappears in the application.

**Not changed**, deliberately: the mdoc bridge's own `issuer_authentic` is a different
field answering a different question about an ISO 18013-5 document, and is untouched.
`polaris_card`'s pairwise handle, the other finding from the same review, is recorded in
`lab/linkability/pairwise_constructions.py` and left for a decision rather than swept in
here.

---

## v1.0.0-rc.2 — 2026-09-17 (a defect found in the candidate)

The contract says a defect found in the candidate makes rc.2 and nothing else moves the
number. The trigger fired twenty-two times in two days, across all four external doors and
the application, so this is that release and not a larger one.

**What a stranger installing rc.1 has.** Measured inside the downloaded wheels rather than
inferred from a changelog, on 2026-09-17: `polaris-oid4vp` 1.0.0rc1 never reads `exp` (the
string appears zero times in its `sdjwt.py`, against three here), so it accepts a credential
whose validity has ended. `polaris-verify` 1.0.0rc1 reads a trust attestation's `valid_until`
exactly once, inside its canonicaliser, so a time-boxed trust edge never expires; it has no
finite-number guards, so an agent grant signed with a non-finite `max_amount` is a signed
unlimited grant wearing a limit field. `polaris-sdk-python` has neither guard either. The npm
`polaris-sdk-ts` is still 0.1.0 and predates rc.1 entirely.

And the reason that matters rather than merely being true: `docs/STRANGER-PATH.md` was walked
end to end from PyPI the same day, and a stock walt.id wallet presented to the published
verifier and was ACCEPTED. The happy path works. Somebody evaluating Polaris against their
own wallet watches it succeed and has no way to learn their copy does not check expiry.
SECURITY.md now carries that, at the top, where a person who installed from a registry will
reach it instead of only a maintainer.

**The four external doors.** Fifteen defects in the OpenID4VP verifier, among them expired
credentials accepted, a key-binding `iat` of NaN defeating the replay window, a disclosure
able to overwrite the issuer or the key-binding key in the returned claims, and four
denial-of-service paths needing no credential. Sixteen in the detached verifier, including
the trust edge above, an agent grant whose algorithm the verifier ignored while the holder
had signed it, and four totality escapes where an inclusion proof carrying `Infinity` raised
instead of returning a verdict. Thirteen across the two reference SDKs, including a cached
bearer token that outlived the client's standing to use it.

**The application.** A credential past its own expiry stayed usable and the dashboard counted
it. An operator bound to one authority could make another authority sign. An operator account
could be locked exactly once, ever. Eleven refusals on the authentication surface were not
being made, among them an authenticator model refused by policy that could still complete a
login. A timestamp authority signed whatever it was handed: its docstring promises the content
itself is never sent, and the `digest_hex` shape check is the whole of that promise.

**Non-finite numbers, moved to the door.** `NaN` and `Infinity` survive `json.loads`, every
comparison against NaN is false, and `int(float('inf'))` raises an exception the usual
`except (TypeError, ValueError)` does not catch. After repairing five call sites individually
the refusal moved to one JSON provider, because fixing the twenty-first call site leaves the
twenty-second to be written. The same shape produced `_json_object()`: `get_json(silent=True)
or {}` is truthy for a JSON string, so an anonymous caller could make an unauthenticated
endpoint raise by sending `"a string"`.

**How the tests were found wanting, which is most of what changed.** The Flask application
was the one member of the mutation-drill family nobody had measured, and three of the ten
constraints are enforced there and nowhere else. Of 37 refusals answering 401, 403, 409, 413
or 429, **31 survived being switched off with the whole suite green**. Of fourteen rate
limiters, the login one was the only one any test drove. `check_local_gate_covers_ci` existed
to stop the local gate being narrower than CI and compared the ship tool against the wrong
file, so nine suites ran in CI that nothing local knew about.

**The lab.** Linkability went from five findings to eight. Two of the four fields its
issuer-metadata question named are not in a presentation at all; the anonymity set is the
(epoch, context) cell and the metadata gives an adversary nothing beyond it. A wallet whose
`holder-keygen` was interrupted by a network failure presents `holder_proof` with no
`holder_binding` beside it, identically at every verifier, which is a stable one-bit
fingerprint, and the cause was an uncaught `URLError`. A status assertion trimmed to its
timestamps reported `bounded` while handing over an instant to the second.

**What has not changed.** Polaris remains a reference implementation on notional data, not
production-ready, not audited, not certified, not deployed. The five conditions for 1.0.0 still
hold and the sixth still does not: an operator who is not the author has not reached a verified
result, and that row of the scoreboard is what makes 1.0.0 rather than another candidate.

---

## v1.0.0-rc.1 — 2026-09-15 (a version a stranger can read)

The tree version moves from 9.467 to 1.0.0-rc.1, and the four standalone packages from 0.1.0 to
1.0.0-rc.1. What changed is what the number means; the two defects found on the way are below.

**Why 1.0, and why a candidate.** The go-forward contract names five conditions for calling
anything 1.0.0, and all five hold: a clean-machine install works, the cryptographic mode is
explicit and safe, a named external client (walt.id's wallet, unmodified) completed a
presentation, a named external conformance suite (the OpenID Foundation's hosted suite) has
been run, and its result is published where it is not green (7 PASSED, 4 REVIEW). What is
still missing is not one of the five. The contract's 90-day objective also asks for an operator
who is not the author to have used the verifier, and that row of the scoreboard is blank. A
release candidate says both things at once. That operator makes 1.0.0; a defect found in the
candidate makes rc.2. Nothing else does.

**The maturity classifier moves from Alpha to Beta.** PyPI has no classifier for a candidate,
and Production/Stable would say more than has happened.

**Why the tree version stops moving.** 9.467 was a count of ships, bumped by the one that added a
check and the one that fixed a comment alike. Under the contract a version marks an externally
observable change, which is rare, so the tree number stops tracking internal activity. Standalone
packages keep their own semver, independently.

**What had to move with it.** Four invariant checks parsed the version as MAJOR.MINOR and judged
a document stamp stale when more than twenty minors behind the tree. That proxy dies the moment
the version stops bumping per ship: everything is forever within twenty minors of a number that
does not move. The stamps in SECURITY.md, CONTRIBUTING.md, PRODUCTION-READINESS.md and ROADMAP.md
must now equal the tree version exactly, so a version bump forces every outward document to be
re-read, which is when a document is most likely to have drifted. The thesis-terminus check
compared against (9, 40); it now treats that terminus as the permanent fact it is, since a reset
to 1.0 would otherwise have read as "before v9.40" and reopened a claim retired by recorded
decision.

**One latent defect surfaced by the move.** `check_roadmap_consistent` guarded its version
comparison with `if vm and ...`, so a version its regex could not parse skipped the comparison
and passed. On the first run against 1.0.0-rc.1 it would have gone green over a stamp it never read.
It now fails when the version cannot be read.

**A second, found by re-measuring.** Restating the README's test counts meant running the
product suites the way the README says they were measured, `pytest -q` per suite, and
`test_check_constraints` failed once: a relying party registered with no actor declared came
back recorded `by vanta`. The seed that reloads the sample database restarts every reached
table's ids from 1 (`TRUNCATE ... RESTART IDENTITY CASCADE`), and CASCADE reaches
`RelyingParty` through its key to `VerificationContext`. `RelyingPartyEvent` deliberately
carries no foreign key, so that ending a party's contract cannot erase its history, which also
means the reload never reaches it: its rows survived every reload, and the first party
registered after each one inherited every event of whichever party had held `rp_id` 1 in the
previous life. The test that caught it was reading the oldest event under its new id and finding
a dead party's. `04_data.sql` now names the record in the same statement, as `10_auth.sql` has
done for `AppUserEvent` since it was written, and `check_seed_restart_resets_dependent_records`
computes what the reload restarts from the schema's own foreign keys, migrations included, and
fails on the next record left behind. Its closure was compared with what Postgres actually
cascades to on the loaded database; they agree on every table.

**Installing a candidate.** pip skips pre-releases unless told, and 0.1.0 remains available as
the prior release, so the pip lines read `pip install --pre`. npm refuses to publish a
prerelease without a dist-tag (the first rc.1 run was refused on exactly that, and uploaded
nothing), so the candidate goes out under `next`: `npm install polaris-sdk-ts@next`, while plain
`npm install` keeps 0.1.0. The republish replaced the frozen 0.1.0 descriptions on PyPI,
one of which still said "Not on PyPI yet" from a page that was, literally, on PyPI. The GitHub release for this
version is a full release, not a pre-release: GitHub will not put its Latest marker on a
pre-release, and leaving that marker on v9.466 kept a retired numbering on the front door. The
tag says what the release is. The badge includes pre-releases, so it reads the tag rather than
the marker. The 295 v9 tags and their 294 GitHub releases were removed the same day: a series
that numbered ships rather than observable change, cleared from the front door instead of left
as 294 entries under the one that matters. Every one of those numbers still maps to its commit,
date and subtitle in [docs/history/RELEASES-v9.md](docs/history/RELEASES-v9.md), and every entry
is still in the changelog archive. The SBOM attachments went with the releases; the author holds
an archive of them, and nothing published depends on one.

**The README, rewritten.** The front door had grown by accretion: a three-hundred-word opening
paragraph, the wallet and conformance results told twice, the cryptographic claim made four times,
and the honest counterweight scattered across three sections. Rewritten from a blank page on
2026-09-16 in the order a stranger needs: what it is, its status with the two outside results and
the counterweight in one place, a two-minute try, the ten guarantees, the threats, the architecture,
the cryptography with its limits, what is verified and how, how to run it, where it sits, and where to
read next. Every pinned claim, count and vocabulary rule the checks hold the README to survived
unchanged; the checks and the link checker gate the result as before.

**The runbook, rewritten.** `CLAUDE.md` was a v9-era onboarding note that still called the system
national on its first line, described all ten constraints as database objects, named a Python
3.9 venv that does not exist, wrote the CHANGELOG header with a comma, counted five flake
signatures where the tool knows six, and never mentioned the operating contract, the
scoreboard, the four standalone products or the release candidate. Rewritten for 1.0.0-rc.1
in the order a fresh agent needs: what Polaris is and is not, what governs when instructions
conflict, the operating contract as a first-class section, the five evidence marks and the rules
that keep one from being upgraded into the next, C1-C10 at the level each is actually enforced,
how to work, how a change earns admission, how to test and falsify it, shipping and versioning,
where things live, the operational gotchas as symptom, cause, distinction and action, the style
rules, and engine over wrapper subordinated to the contract. Every command and path in it was
verified against the tree; the documentation disagreements found on the way are recorded in the
commit rather than reconciled silently.

The two test-count stamps in the README, last measured at v9.332, are re-measured at this
version and restated: 992 product tests passing (was 755) and 107 of 112 crypto witnesses (was
84 of 89), on the reference machine, `pytest -q` per suite. The growth is the suites' ordinary
accretion since v9.332, not anything this ship did; the three product tests and five crypto
witnesses skipped need real ML-DSA, a PKCS#11 module or a real KMS key.

## v9.467 — 2026-09-15 (a privacy promise kept by discipline alone)

A data-protection audit of the repository. Most of it came back clean, and the one finding is
the shape this project keeps finding in itself.

**Clean, and checked rather than assumed.** No credentials or API keys are committed. The one
`BEGIN PRIVATE KEY` in the tree is a fixture with `xyz` between the headers, used to assert file
permissions. `.gitignore` carries 13 secret patterns. Retention, erasure, the secret store's
lifecycle, redaction and the duress paths each already have a check with a detection test.
`docs/operator/PRIVACY.md` runs to 488 lines and states its own boundary honestly: it disclaims
GDPR and CCPA as deployment-specific, says Polaris has no special handling for minors, and says
outright that it is an architectural posture and not a legal privacy notice drafted by counsel.
That boundary is correct for a reference implementation on notional data and was left alone.

**The finding.** PRIVACY.md tells an operator, in as many words, that the application log does
NOT record form bodies, cookie values or token values. It is a sentence somebody reads before
deciding what a deployment may hold. It was true: none of the 21 logging call sites in the
application interpolates a request body, a credential or a holder attribute, and the structured
logger names no such field. But nothing enforced it and nothing tested it. A debugging line that
logged `request.form` could have landed and stayed, and the document would have gone on promising
otherwise.

`check_logs_exclude_pii` (271) reads the logging call sites and fails if one names a request
body, a cookie, a credential or a holder attribute, including across a call wrapped over several
lines. It also fails if PRIVACY.md stops making the promise, because a check that exists to keep
a published sentence true must not read as compliance once the sentence is gone. Six failure
modes are covered by its detection test, including the empty room.

What this does not do: it reads call sites, so it cannot prove a log is clean at runtime, and it
says nothing about what a deployment's own logging configuration adds. The document already tells
an operator to revert debug logging immediately and record it; that instruction is still theirs
to follow.

## v9.466 — 2026-09-15 (you can install it now)

A version because installation changed, which is externally observable and is the only kind of
change that earns one. Nothing else here alters product behaviour.

**All four standalone products are published.**

    pip install polaris-verify
    pip install polaris-oid4vp
    pip install polaris-sdk-python
    npm install polaris-sdk-ts

All at 0.1.0. The three PyPI packages went out by GitHub Actions trusted publishing over OIDC and
no API token was created for them at any point. npm needed one, because it cannot use trusted
publishing for a package's first publish (npm/cli#8544); that token covered one publish and was
revoked within the hour. The publish workflow now contains no `secrets.` reference at all.

Each was checked by installing from the live registry into a clean environment and running it
there. `polaris-oid4vp keygen` produces a working HAIP certificate set from a fresh venv, which
is the one that matters, because it is the package an outside verifier operator reaches for.

**The stranger's path no longer needs a clone.** [docs/STRANGER-PATH.md](docs/STRANGER-PATH.md)
goes from a clean machine to one accepted presentation from an external wallet in about ten
minutes: `pip install polaris-oid4vp`, two helper files by curl, then keygen, serve, present. It
was executed from an empty directory before it was written down, and it ends:

    <- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']

**Hosted conformance: 7 PASSED, 4 REVIEW.** The OpenID Foundation's hosted suite ran
`oid4vp-1final-verifier-haip-test-plan` against the verifier across the open internet. Eleven
modules, zero FAILURE, zero WARNING. Seven negative modules carry the service's own
`result: PASSED`. Four positive modules are FINISHED / REVIEW with screenshot evidence attached,
awaiting a Foundation reviewer, which only a certification submission triggers.

**REVIEW is not PASSED. Polaris is not certified. Publication is distribution, not validation.**

What is still absent, unchanged by any of the above: no independent security review by anyone who
did not build this, no operator other than the author has run it, no pilot, no real identity data.
A constraint lattice and a verifier that an unmodified wallet already spoke to is the whole of
what is demonstrated.

## v9.465 — 2026-09-15 (a wallet nobody here wrote said no, and it was right)

First named independent implementation on the board. An unmodified walt.id Wallet API v2
(`waltid/wallet-api2:1.0.0`) presented an SD-JWT VC to `polaris-oid4vp` over OpenID4VP 1.0 and
Polaris accepted it.

    <- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']

walt.id fetched the signed request object over `request_uri_method=post`, verified it under
`client_id_prefix=x509_hash` against the registered trust anchor, matched the credential with the
`dcql_query`, signed a key binding JWT with a P-256 key **it generated and this repository has
never held**, encrypted the response as `direct_post.jwt`, and Polaris verified the chain.

**And it refused Polaris first, correctly.** `polaris-oid4vp keygen` produced a request-signing
leaf certificate with no KeyUsage extension at all:

    Certificate does not contain client Key Usage 'digitalSignature'

The CA carried `keyCertSign`/`cRLSign`; the leaf carried nothing. Eleven of eleven HAIP verifier
modules in the OpenID Foundation conformance suite had run clean against that certificate, and
`test_cli.py` already asserted four separate properties of the same leaf without asserting this
one. The certificate whose entire job is signing request objects was not marked as usable for
signing, and it took an implementation from outside this repository to say so. Fixed here, with a
test that is red on a leaf missing it.

The exchange stands on two negative controls, because a verifier that accepts everything prints
the same success line. Same wallet, same credential, same path, verifier trusting a different
issuer key: `400 refused: issuer_signature`, and walt.id told only "the presentation was not
accepted". Re-presenting against an answered `state`: refused at the request stage.

Recorded in [lab/EXTERNAL-NOUNS.md](lab/EXTERNAL-NOUNS.md) with the image digest, the release tag, the
Polaris commit, the transcript and every incompatibility found, including two that are not
Polaris's: walt.id's `/credentials/present/resolve-request` is the only route in its handler file
not passed `clientIdTrustConfiguration`, so it reports `MissingX509TrustAnchors` whatever is
configured; and its `x509TrustAnchors` wants PEM though the type comment says base64 DER.

One wallet, one credential format, one presentation path, ES256 throughout. No claim is made that
`polaris-oid4vp` is interoperable in general.

## v9.464 — 2026-09-14 (the design doc described the defect as the technique)

Closing sweep over `docs/design/concurrency.md`, which had not moved while five ships rewrote what
it describes. Three passages were wrong and one of them was instructive.

The instructive one, on `uc10_same_attesting_agency_serializes`: *"The test manually holds the lock
to make the serialization timing observable; the procedure's lock acquisition inside is a no-op
reacquire on the same transaction."* That is the defect written down as a technique, and it reads
entirely reasonable. It is also exactly why the test proved nothing: both threads serialized on the
TEST's lock, so the procedure's own locking never entered the measurement. The replacement quotes
the old sentence rather than deleting it, because the sentence is the clearest statement of the
trap anyone will find.

The other two described mechanisms that no longer exist: `test_uc6_cross_token_migrations_run_in_parallel`
"confirms the wall-clock parallelism", and the cross-algorithm close "completes in ~0.3s (the held
lock duration), not ~0.6s (serialized)". Both now hold a lock through the procedure and probe under
`lock_timeout`.

The catalog summary gained the one fact it could not have carried before today: which of the six
locks the suite can actually see. Four go red when their `pg_advisory_xact_lock` line is deleted.
Two cannot be observed at all, and for those, dropping either mechanism leaves 866 tests green
while dropping both turns the suite red.

A design doc that describes a verification approach is making a claim about the code, and this one
had been making three false ones since this morning.

## v9.463 — 2026-09-14 (a surviving mutation that was the right answer)

Four ships today treated a surviving mutation as a defect. This one did not, and the difference is
worth writing down because the reflex that found the first four would have produced a false finding
here.

The procedure mutation drill mutates `RAISE EXCEPTION` and nothing else, so the six `FOR UPDATE`
clauses in `05_procedures.sql` had never been mutated. Dropping them one at a time:

  * `uc4_activate_reserve` holds three, and removing them turns
    `test_uc4_concurrent_same_tokens_one_winner_no_duplicate_crl` red. Load-bearing and watched.
  * `uc9_complete_recovery` and `uc10_revoke_attestation` hold one each, and removing either leaves
    **all 866 tests green**.

By the pattern of the last four ships that reads as two unwatched clauses. It is not. Each sits
after an advisory lock keyed on an entity that already covers the same row, so the experiment that
settles it is the one that removes BOTH. Run for each procedure:

    drop the FOR UPDATE      866 pass
    drop the advisory lock   866 pass
    drop both                the suite FAILS

That is defense-in-depth seen from outside: two sufficient mechanisms, and a test asserting the
PROPERTY rather than either implementation. Neither clause is dead and neither is untested. Adding
a test to "close" either gap would have pinned an implementation detail and made the pair harder to
change, for a defect that does not exist.

Recorded where someone would be standing when they consider deleting a line: a comment beside each
clause with the three measurements, and a note in `_UNOBSERVABLE_LOCKS` that an entry there means
"no test can tell these apart", never "nothing tests this". The list already named two advisory
locks as unobservable, and read as though the property behind them went unchecked. It does not.

No behaviour changed in this ship. The tree is byte-identical apart from comments, a version and
this entry.

## v9.462 — 2026-09-14 (a claim that lived in a comment)

The last thing in this family, and the smallest. Above the federation lock tests sits a comment
that has said since R11-3: "Same-attesting-agency attest + concurrent revoke serialize". No test
drove `uc10_revoke_attestation` concurrently. The claim lived in a comment.

It is not a trivial claim. The two procedures reach the same lock key by different routes.
`uc10_attest_trust` hashes its `p_attesting_id` PARAMETER; `uc10_revoke_attestation` SELECTs
`attesting_agency_id` out of the attestation row and hashes that. Nothing checked the routes
agree, and `AgencyTrustAttestation` carries `attested_agency_id` right beside it.

Now measured, and the rows are disjoint on purpose: the attest INSERTs a new attestation while the
revoke UPDATEs an existing one, so the key is the only thing they share. The claim held. The
mutation is the one a person would actually make, deriving the key from `attested_agency_id`
instead, and the test goes red against it while the comment would have stayed true.

`check_advisory_locks_have_a_contention_test` now requires every procedure that takes a lock to be
exercised in one direction or the other, not just one procedure per domain. That is the rule that
would have found this gap: `uc10_revoke_attestation` joined an existing lock domain and no test
ever drove it.

Four ships, one question. v9.459 found five tests measuring a sleep instead of a lock; v9.460 found
two substituting their own lock for the procedure's, and two locks that cannot be watched at all;
v9.461 found the local runner reading half its file; and this one found a claim nothing had ever
checked. The question was the same each time, and it was never whether the suite passes.

## v9.461 — 2026-09-14 (the local runner was reading half the file)

Found while verifying v9.459, and worth its own ship because it is about the instrument a person
checks a change with rather than about any particular test.

`scripts/polaris-test.sh app` runs `python test_app.py`. Python executes a file top to bottom, and
`test_app.py` had its `if __name__ == '__main__':` block at line 10269 with **27 top-level
definitions after it**. The block calls `loadTestsFromModule(sys.modules[__name__])` on the module
as it stands at that moment and then `sys.exit()`s, so the last 2,497 lines were never executed,
never defined, and never collected. The command reported 566 tests. With the runner moved to the
end it reports 704, so 138 were never running locally.

Two of the 566 it did run raised `NameError: name '_sql' is not defined`, because `_sql` is a
module-level helper defined at line 10252, below the block. Run the same tests through the module
path and they pass: the whole file loads because `__name__` is not `__main__`.

**CI never saw any of it,** which is the worst shape this defect can take. CI loads the module
rather than executing it, so the block never runs and all the classes are collected. The local
command a person checks a change with was the broken one, and the remote that would have caught it
is the one that works. A local suite that silently skips a fifth of a file and reports two
failures that do not exist is worse than one that refuses to start.

The runner is now the last thing in the file.

`check_test_runners_are_last_in_their_file` (270) holds it there across four test files. It found a
second instance on its first run, and the second instance turned out not to be a defect:
`polaris_checks/test_checks.py` has 186 definitions below its guard, but that guard delegates with
`pytest.main([__file__])`, which starts a fresh session and imports the file as a module. So the
check had to tell a runner that collects from the half-built `__main__` apart from one that
re-imports. That distinction was measured rather than reasoned: a two-test file of each shape, run
both ways. The unittest form collected 1 of 2; the pytest form collected 2 of 2. The check now
matches on `sys.modules[__name__]` and bare `unittest.main()`, and the detection test asserts the
delegating form stays OK, because otherwise the check is a style rule about where a block sits
rather than a statement about what runs.

## v9.460 — 2026-09-14 (the other direction, and two locks that cannot be watched)

v9.459 fixed five tests that claimed two operations on DIFFERENT entities do not serialize. Two
tests in the same class claim the opposite, that operations on the SAME entity do, and they were
worse.

Both took the advisory lock BY HAND. The test computed
`hashtext('polaris.federation.attest.4')` itself, acquired it, slept inside the transaction, and
then called the procedure. Both threads serialized on the TEST's lock, so the procedure's locking
never entered the measurement. Measured rather than argued: `uc10_attest_trust` and
`uc11_close_epoch` were reinstalled with their `PERFORM pg_advisory_xact_lock(...)` line **deleted
outright**, and both tests passed.

Taken with v9.459 that is the whole picture. The cross-entity tests prove a key SEPARATES and pass
happily against a procedure holding no lock at all, because two calls that never contend are
exactly what no lock looks like. The serialization tests were supposed to be the other half.
**Nothing in the suite would have noticed any of these six procedures giving up its lock.**

`assertContends` is the mirror of `assertDoesNotContend` and holds through the PROCEDURE. Four
domains are now proven to take their lock: `uc6_migrate_algorithm`, `uc8_revoke_token`,
`uc10_attest_trust`, `uc11_close_epoch`, each red against its own lockless build.

**Two are not observable, and the honest answer was to say so rather than ship a green test.** Both
were written first and both passed against a lockless procedure, which is how they were caught:

  * `uc9_complete_recovery` locks on `claimed_individual_id`, and
    `uq_one_pending_recovery_per_individual` allows one PENDING recovery per individual. Any two
    calls sharing the key target the same row and serialize on its `FOR UPDATE` regardless.
  * `close_anchor_batch` locks on `algorithm_id` and batches every pending row under it. Holding
    the first open does not help: under READ COMMITTED the probe cannot see the holder's
    uncommitted batching, reads the same set, and blocks on the UPDATE either way.

Neither lock is redundant. Each closes a window before its own SELECT. But from outside the
procedure they cannot be told from the row locks beside them, and `_UNOBSERVABLE_LOCKS` records
that with the reason rather than leaving a test that cannot tell.

**Three of the four lock-presence tests were wrong on their first draft, in the way this ship is
about.** They probed with the same entity as the holder, so they blocked on a unique index or a
row lock and passed against lockless builds. `uc6` was repaired by migrating to a DIFFERENT target
algorithm, which shares `token_id` with the holder but not `TokenSignature`'s
`(token_id, algorithm_id)`. The other two could not be repaired and became the two declarations
above. The helper now separates "blocked at the lock" from "reached its own validation and
objected there", because those look identical if you only watch whether the call returned.

`check_advisory_locks_have_a_contention_test` gained both rules: a test may not execute
`pg_advisory_xact_lock` itself and then call a procedure that takes one, and every domain needs a
holding-direction test or a declared reason. Its first version failed on the tree by matching its
own explanatory docstrings, which is the same error one level up, and it now matches a quoted SQL
literal instead of the word.

## v9.459 — 2026-09-14 (five concurrency tests, none of which could fail)

CI went red on a timing test by 7 milliseconds: `elapsed=0.557s not less than 0.55`. The obvious
repair is to move the number. Reading the test first was better.

`test_close_anchor_batch_cross_algorithm_parallel` existed to prove that two batch closes under
DIFFERENT algorithms do not serialize, because `close_anchor_batch` locks
`hashtext('polaris.anchor.close-batch.' || algorithm_id)` and the algorithm is what separates
them. It ran two threads, each sleeping 0.3s, and required the pair to finish in under 0.55s on
the reasoning that a shared lock would cost 0.6s.

**The sleep came before the CALL.** The procedure takes its advisory lock as its first statement
and holds it until commit, so at the moment both threads were sleeping neither held anything. Two
threads sleeping concurrently take 0.3s whether or not their keys collide. The stopwatch was
measuring the sleep.

Proven rather than argued. The procedure was rewritten with the lock key
`hashtext('polaris.anchor.close-batch.GLOBAL')` -- one key for every algorithm in the system --
installed into the test database, and the test passed. Then the same question was put to the rest
of the family, and the same mutation was applied to `uc8_revoke_token`, `uc9_complete_recovery`,
`uc6_migrate_algorithm` and `uc10_attest_trust`, dropping agency, individual, token and attesting
agency from their keys. **All five tests passed against lock keys that ignored the entity they
were keyed on.** Five tests, one defect, and it was in every one of them.

All five now ask Postgres instead of a clock. One worker calls the procedure and holds its
transaction open, so its advisory lock is genuinely held; the other runs under `lock_timeout`, so a
shared key raises `lock_not_available` rather than merely taking longer. There is no threshold and
no calibration, the answer does not move when the runner is busy, and the failure message carries
the offending key expression verbatim from Postgres:

    canceling statement due to lock timeout
    CONTEXT: SQL statement "SELECT pg_advisory_xact_lock(
            hashtext('polaris.anchor.close-batch.GLOBAL'))"

Each one also now asserts its own effect landed: both tokens REVOKED, both recoveries APPROVED with
a token issued, both migrations signed, both batches closed, both attestations recorded. A lock test
that never checks the work happened can be satisfied by two operations that both did nothing.

**A timing helper that told you to re-run a real regression.** `_assertRanInParallel` treated any
reading above `baseline + PARALLEL_SLEEP` as an unusable measurement, on the reasoning that two
workers cannot be slower than two run in sequence. The reasoning holds; the estimate it was applied
to does not. `baseline` timed one BARE round trip while each worker also ran the procedure under
test, so a genuinely serialized pair costs more than the estimate and lands in the band labelled
impossible. Measured against the global-key mutant: elapsed=0.643s versus a serialized estimate of
0.606s. A real shared-key regression would have been reported as "the machine stalled
mid-measurement; re-run this job." The helper is gone along with the approach.

`check_advisory_locks_have_a_contention_test` (269) keeps it that way. Every advisory-lock domain
in `05_procedures.sql` that carries a parameter must be driven by a test calling
`assertDoesNotContend`; a domain with a single global key must be declared with its reason
(`polaris.zk.close-epoch` is, because epoch_id comes from a SERIAL and closures must not skip a
gap). It also fails if the helper stops setting `lock_timeout`, since without one a shared key is
not an error but a slow pass, and if a parallelism claim is ever again decided by comparing elapsed
time against a constant. The check found one more thing on its first run: the batch-close test had
been rewritten inline before the shared helper existed and was not using it.

The five tests run in 9.3s where they took 11.6s, because none of them sleeps any more. That is the
smallest thing about this ship. The finding is that this family went red, was repaired twice in
three days, and neither repair touched the reason it could not fail. v9.397 replaced the absolute
thresholds with a measured baseline after a parallel run clocked 0.616s and was called serialized.
v9.456 added the unusable-measurement branch. Both were repairs to the calibration, which had never
been the problem. And v9.397 migrated three of the five call sites: the two left on the original
hardcoded 0.55 were `close_anchor_batch` and `uc10_attest_trust`, and the one that went red
yesterday was the first of those two.

## v9.458 — 2026-09-13 (the license was right and nothing held it there)

A question worth asking directly: keep Apache 2.0, or change it. Measured first, then answered.

**Keep it.** The reason is section 3, the express and irrevocable patent grant, with a clause
that terminates it for anyone who brings a patent suit over the work. MIT and BSD grant copyright
permission and say nothing about patents. For a reference implementation of a lattice signature
scheme that is the wrong silence to ship: the patent landscape around post-quantum cryptography is
younger than the algorithms, and an integrator building a production verifier out of this code
would be carrying that risk with nothing from the license. Copyleft would defeat the purpose,
which is to be built on, including by the deployments this models.

Nothing in the dependency tree argues otherwise, and that was checked rather than assumed. Every
Python, Rust and npm dependency is permissive (Apache-2.0, MIT, BSD-2/3-Clause, PSF-2.0, or dual
MIT/Apache-2.0) with one exception: psycopg2, LGPL 3 with an OpenSSL exception, used as an
unmodified library through its public API. Its obligations attach to psycopg2, not to this work.
NOTICE now says so by name instead of listing it among four dependencies that "each retain their
own license", which is true and useless to anyone doing a review.

**What was actually missing was enforcement.** All five package manifests already declared
Apache-2.0, the LICENSE appendix was filled in, NOTICE existed. Nothing held any of it there. A
package added later with no `license` field renders on npm and crates.io as no permission granted,
and the tree would have been green. `check_license_is_pinned` globs for manifests rather than
listing them, so a package added tomorrow is in scope without anyone remembering, and it holds
LICENSE, NOTICE, the README badge and the README's License section to one identifier. A tree where
it finds no manifest FAILS rather than reporting clean.

**And NOTICE was outside every honesty check.** It is the furthest-travelling surface the project
has, because section 4 requires a redistributor to carry it, and it said the project was
"maintained as a working system prepared for national deployment" while every checked surface said
reference implementation on notional data. It now says what the others say, and it is in
`_OUTWARD_SURFACES`, so the post-quantum agility rule holds it too: it points at the readiness
ledger rather than leaving the word unqualified.

---

## v9.457 — 2026-09-13 (a job that could not run what it was asked to run)

v9.456 wired the two-SDK mutation drill into the `pqc-real` CI job. That job has Python and a
built liboqs. It has no Node dependency tree, and the drill's TypeScript half runs `node --test`
inside `sdk/typescript`.

The drill behaved exactly as designed: before believing any mutation result it checks that the
UNMUTATED tree passes both suites, found that it did not, and refused to report. That is the right
refusal. But the job then died on its own setup rather than on a finding, which is a red build
that says nothing about the tree, and a red build that says nothing is how a real finding gets
waved through as "that job is flaky again".

`pqc-real` now sets up Node 24 and runs `npm ci` for the TypeScript SDK before the drill.

**The check that would have caught it.** `check_ci_jobs_install_what_they_run` asks, for every job
in `ci.yml`, whether it reaches the TypeScript SDK's suite, and if so whether it installs the
SDK's dependencies and pins the Node version. The version is not cosmetic: the suite executes
`.ts` sources directly under Node's type stripping, which older Node does not do.

**The need is one hop from the step.** The job runs a PYTHON script; the Python script runs
`node --test` inside `sdk/typescript`. Nothing in the job's own commands mentions Node at all, so
the check follows any repository script a step invokes and reads its source too. Both jobs that
reach the SDK are found that way, and a tree where none is found FAILS rather than reporting
clean.

**The first version of that check found the right job for the wrong reason.** It matched
`node --test` as a literal, which does not appear in the drill, whose invocation is the argv list
`["node", "--test"]`; it found `pqc-real` only through a second, incidental spelling in the
conformance arguments. Delete that one string and the check would have gone quietly blind. The
signal is now structural, naming the directory and an invocation of the runtime, which survives
both spellings and the next one.

---

## v9.456 — 2026-09-13 (the other reference implementation)

v9.455 inverted every refusal in the Python SDK and closed eighteen of eighteen. It asked the
question of one implementation. Polaris ships **two** reference verifiers, both certified by the
same conformance suite, and an integrator picks whichever matches their stack. The TypeScript one
had never been asked.

**Nine of fourteen.** Fourteen refusals in `sdk/typescript/src/index.ts`, nine of them able to
accept what they exist to reject with `node --test` and the conformance runner both green. The one
worth naming:

- **`sameBytes`, the constant-time comparison.** Its first act is a length guard. Inverted, arrays
  of different lengths fall through to a loop over the shorter one and compare EQUAL. A five-byte
  value matches a 32-byte Merkle root. That is the comparison every signature, root and digest
  check in the TypeScript SDK funnels through, and nothing in either suite noticed it was gone.
- `verifyInclusion`'s bounds check on the leaf index, and its node-shape check.
- `grantWithinLimits`' use-count ceiling and amount ceiling, the same pair the Python SDK had open.
- `grantCovers`' empty-action-list guard, `revocationEndsGrant`'s id match.

Six tests close them. The drill now runs both SDKs: **32 refusals, 4 declared survivors with
stated reasons, and a per-SDK negative control** that inverts every refusal at once and confirms
the harness can produce a survivor at all. Without that control, "0 survivors" and "the suite
never ran" print the same number.

**Three harness errors, each caught by the harness.** The TypeScript refusal regex was anchored to
a line start, so it matched nothing in a file that writes `if (cond) return false;` -- a vacuous
"0 of 0" that looked like a pass. The labeller only recognised top-level functions, so class
methods were all attributed to whichever function preceded them. And the sandbox copy excluded
`node_modules`, so the baseline could not resolve its own imports; the drill refused to report
rather than calling an unbuildable tree clean. The declared-survivor list is checked in both
directions, which is what caught the mislabelled names: a declared survivor that no longer
survives fails the drill just as a new survivor does.

`check_sdk_refusals_are_mutation_tested` now requires both SDKs to be in the drill's reach and the
TypeScript suite to exercise the length guard by name.

**A timing test that could not say what it measured.** `_assertRanInParallel` compared elapsed
time against a serialized estimate; when the sample was unusable (the runner stalled and elapsed
exceeded the estimate despite real parallelism) it reported a plain assertion failure that read as
a concurrency regression. It now names the case: the measurement is unusable, not the property.
`polaris-ship.py triage` carries a `concurrency-measurement-stall` signature so a rerun is the
named response rather than an investigation.

---

## v9.455 — 2026-09-13 (every refusal in the reference verifier could be made to accept)

Six mutation drills existed -- checks, constraints, procedures, triggers, the ZK circuit, the
conformance contract. None of them asked the question of `sdk/python/polaris_verify`, which is the
implementation an integrator builds against and the thing the conformance suite certifies: if a
refusal inside the SDK stopped refusing, would anything go red?

**Eighteen of eighteen.** Every `return False` in the reference verifier could be turned into
`return True` -- made to ACCEPT what it exists to reject -- with the SDK's own tests and
`run_conformance.py --self` both green. Among them:

- `grant_within_limits`: a grant's **exhausted use count**, and a **requested amount over the
  grant's ceiling**. Invert either and the reference verifier authorizes a delegated action
  beyond the authority the grant states, which is the whole point of P9.8 being bounded.
- `verify_inclusion`: a **leaf index outside the tree**, and a malformed proof node. Invert and a
  bogus Merkle proof verifies.
- `revocation_ends_grant`: the format check and the grant-id match.
- `grant_covers`: an empty action list treated as "all actions".

**This is not the conformance suite being broken**, and the distinction matters. An SDK whose
signature backends accept anything IS caught, by both suites -- that is the drill's negative
control. The published cases reach the happy path and a tampered-signature path; these guards sit
on inputs no case contains. So the contract certifies what it exercises, and these refusals were
outside it. They are closed in the SDK's own tests rather than by changing a frozen contract.

Eighteen tests later the drill reports **0 of 18**, and two of them were only reachable once the
inputs were found: a signature that is not bytes at all, which raises something other than
`InvalidSignature` and lands in the catch-all arm. Inverting that arm turns every unexpected error
during verification into an accept, which is the worst direction a failure nobody anticipated can
take.

**The mutation inverts rather than deletes, and that was learned the hard way.** The first version
replaced a refusal with `pass`; a function that then falls through returns None, which is falsy
too, so the mutation can be inert. It reported 17 of 18 -- UNDER-stating the gap -- and the
eighteenth appeared protected when it was not. `return False` becomes `return True` now, and
`check_sdk_refusals_are_mutation_tested` refuses a drill that deletes instead.

One thing the tests found on the way: the two signature backends answer an unaccepted algorithm
differently and both are right. `_verify_liboqs` returns False (refused); `_verify_cryptography`
returns None (this backend cannot answer, so the caller falls through to the other). The first
version of the test asserted both return False and was wrong about the contract. What neither may
do is return True, which is what the assertion says now.

**261 invariant checks. 45 tables.**

---

## v9.454 — 2026-09-13 (the headline rested on prose; now it rests on a rule)

v9.453 rewrote the front door to say what is true -- signed with ML-DSA-65 under an audited
algorithm-migration path -- and that left a gap worth naming rather than leaving implied. The
rules `check_post_quantum_claims_are_agility` pinned were the denylist of settled-security
phrasing and the requirement to point at the limitation. It deliberately permitted the words
"post-quantum", because they are accurate about ML-DSA-65, about the SLH-DSA hedge and about the
X25519MLKEM768 edge, and a check that refused a true statement gets routed around. So a future
headline could have gone back to "a post-quantum identity-token system" and still passed.

The overstatement is separable from the accurate use, and the separating line is grammatical.
"The TLS edge negotiates post-quantum key exchange" is a fact about a protocol. "Post-quantum
signatures (ML-DSA-65 by default)" is a fact about an algorithm. "A post-quantum credential
verification engine" is a claim that the SYSTEM cannot be broken by a quantum adversary, which is
a claim about Module-LWE staying hard. The check now refuses post-quantum used as an adjective on
the system, engine or platform, and permits every use that names the thing which actually is one.

Writing that rule immediately found what the v9.453 pass had missed: `site/index.html` still
opened its lede with "Polaris is a post-quantum credential verification engine", because that
rewrite corrected the README's version of the sentence and not the site's. The site now carries
the same framing as everything else, and says why -- ML-DSA-65 rests on Module-LWE hardness, which
is mathematics rather than a property of this repository, while the algorithm being a row in the
schema rather than a constant is.

One detection case from v9.452 had to be corrected rather than kept. It asserted that "a
post-quantum credential engine" must PASS, as the example of an accurate use the check must not
refuse -- and that is precisely the construction now refused. The fixture was asserting the wrong
thing was accurate; it now uses a statement about the SIGNATURE, which is one.

**260 invariant checks. 45 tables.**

---

## v9.453 — 2026-09-12 (forty-six citations to a document that is not in the repository)

v9.55 deleted the apparatus wholesale -- about 18,150 lines and the mythology docs with it.
Three hundred and ninety-seven versions later, **46 references across 24 live files still cited
it as the authority for a rule**, and one of them was an error message an operator reads:

    error: migration 'X' missing .down.sql (Sanctum §IV.2 requires bidirectional)

Somebody who hits that, goes looking for §IV.2 and finds no such document in the repository has
been sent after something that is not there. The rules those citations stood for are real and
worth stating; the pointers are not. Each is now the reason it encoded -- a migration that cannot
be reversed is one you can only go forward from; `schema_version` is append-only so a revert is a
new row rather than an edit -- which is both true and more useful than a section number.

Two were worse than dangling. `01_schema.sql` counted the deleted apparatus's session table among
the audit-of-record instances, so AnchorBatch was the FIFTH and AgencyTrustAttestation the SIXTH
by a tally that included a table the catalog does not have. They are the fourth and fifth.

And one was in the module this matters most for. `pqc_signing.py` explained the placeholder by
citing a deleted tier list, including in `availability_report()["notes"]`, which is
runtime-visible. It now states what the module actually does: real signing behind
`POLARIS_USE_REAL_PQC=1`, a labelled 32-byte placeholder without it, and where the limits are
written down.

`check_no_citations_to_deleted_apparatus` holds it. What it does NOT refuse is a sentence
recording that the apparatus was removed -- MISSION.md carries one, explaining that the owner's
recorded direction authorizes an amendment now, and that is the honest treatment rather than a
violation. Any retired name is allowed within 200 characters of "removed", "retired", "deleted" or
"no longer". The CHANGELOG, the migrations and DEVNOTES are exempt outright: they record what
happened, and rewriting them to satisfy a check would be editing the past. The check's own
docstring paraphrases its examples rather than quoting them, because this file is live and a
verbatim citation in it would be one.

**Two documents were also past their re-read window**, which `check_presentation_surface` caught
on the same push, and both needed more than a stamp.

SECURITY.md had no mention of the placeholder. A researcher reading its in-scope list would
reasonably report that credential signatures do not verify on a default checkout -- which is the
named development profile, already known, and now said so, along with what IS in scope there: the
guard failing, a placeholder that is not labelled, or a verifier that accepts one as a signature.

CONTRIBUTING.md told a contributor that `polaris-test.sh` passing is one of the conditions for a
merge, without saying that it runs **four of the eighteen suites CI runs**. v9.443 passed every
suite that document names and broke `polaris_sim.test_sim` in CI twice. It says so now.

**And the front door stopped calling itself post-quantum.** v9.452 established that the
defensible claim is agility rather than settled security; the headline had not caught up, and the
GitHub About box had reached the point of putting "post-quantum" in scare quotes -- which signals
doubt without explaining it, and is worse than either saying it plainly or not saying it.

The headline now reads the same on all five surfaces it appears on (README, the site title,
description, og:title and subtitle, CLAUDE.md, CITATION.cff and the repository description):
**an issuer-unlinkable, compulsion-resistant identity-token system signed with ML-DSA-65 under an
audited algorithm-migration path.** Every clause of that is a fact about this repository. The
system IS signed with ML-DSA-65; the migration path IS audited and runs in CI; and nothing there
asserts that Module-LWE stays hard, which is the part no repository can assert about itself.

"What Polaris is" now says so in the first sentence rather than leaving a reader to find the
limitation four documents away, and links to it.

**260 invariant checks. 45 tables.**

---

