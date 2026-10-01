# 002 lab results: the relying-party API as its own database login

Measured 2026-09-27 against the scratch database `polaris_rpcomp` (00_load_all.sql plus every
`migrations/*.up.sql` in sort order, PostgreSQL 16.14, placeholder signing profile). This executes
section 9 of [002-relying-party-api-compartment.md](../002-relying-party-api-compartment.md) and
reports against its section 10. No product file was changed; nothing was committed.
`polaris_rpcomp` and the cluster role `polaris_rp` are left in place.

## Files

| File | What it is |
| --- | --- |
| `polaris_rp_grants.sql` | The final grant script, idempotent, one comment per grant naming the route. |
| `run_rp_as_polaris_rp.py` | The runner: the relying-party test classes with `/api/v1/*` requests connected as `polaris_rp`, fixtures and operator routes as the owner. Records every 42501 on a `polaris_rp` connection, including swallowed ones. Modes `owner`, `asis`, `split`. |
| `probe_rp_statements.py` | Every SQL statement on the relying-party path (45), copied from `rp_api.py` and the `app.py` helpers, run as `polaris_rp` in rolled-back transactions. Covers paths no test reaches under the placeholder profile. |
| `probe_rate_limit_audit.py` | Drives `POST /api/v1/timestamp/1` past the per-address write limit as `polaris_rp`. |
| `attempt_operator_writes.py` | Step 5: the operator's writes attempted as `polaris_rp`, each rolled back. |
| `privilege_snapshot.sql` | Every right `polaris_rp` holds; the runner compares it before and after each run. |
| `out/*.json`, `out/final_privileges.txt` | Raw results of the runs below. |

## Final grant list

Measured from `privilege_snapshot.sql` after the last run.

- **Relations read: 26** (19 base tables, 7 views).
  Base tables: Agency, AgencyTrustAttestation, AnchorBatch, AuthorityKeyEvent,
  EnrollmentStatusEvent, ExchangeReceiptLog, HolderKeyEvent, IdentityToken (7 columns),
  Individual (4 columns: individual_id, legal_name, jurisdiction, enrollment_date), RelyingParty
  (10 columns), RevocationList, TimestampLog, TokenLifecycleEvent, TokenPermission,
  TokenSignature, TokenStateEpoch, TokenStateEpochLeaf, VerificationContext, ZkVerificationNonce.
  Views (all `security_invoker`, so each also needs its base tables): AuthorityKeyCurrent,
  HolderKeyCurrent, IndividualCurrentEnrollment, v_athena_agency, v_athena_proof_policy,
  v_athena_disclosure_policy, v_athena_trust_agreement.
- **Tables written: 7.** INSERT on AuthCodeConsumed, ExchangeNonce, ExchangeReceiptLog,
  HolderKeyEvent, TimestampLog, ZkVerificationNonce; UPDATE on the one column
  RelyingParty.last_used_at. USAGE on 3 sequences (exchangereceiptlog_seq_seq,
  holderkeyevent_event_id_seq, timestamplog_seq_seq).
- **Procedures executed: 1**, `uc12_record_duress`, SECURITY DEFINER (it writes DuressEvent as the
  owner). The non-definer functions the path calls (`polaris_database_setting`,
  `polaris_utc_date`, `_rp_weakens` in the RelyingParty trigger) are executable by PUBLIC. Every
  other SECURITY DEFINER routine (21) is closed to PUBLIC by 09_grants.sql and not granted.

Against the section-1 table ("6 writes, 17 reads"): one more write (ZkVerificationNonce), one
definer procedure that writes an audit-of-record table, and 26 relations read once the views'
base tables are counted.

`reload_sample_data` (04_data, 06_triggers, 09_grants, 10_auth) does not drop or widen these
grants: the snapshot was identical before and after every run (`grants_unchanged_by_reloads:
true` in each `out/*.json`), because 09_grants.sql touches only `polaris_app` and PUBLIC.

## The relying-party test classes

Every class in `polaris_web/test_app.py` whose tests call an `/api/v1/...` route (22):
ExchangeReceiptSignedTests, ExchangeReceiptLogTests, TimestampLogTests, RegistryTests,
ExchangeGatewayTests, DocumentSigningTests, AuthBrokerTests, ZKSnarkTests,
TransparencyProofBoundsTests, F03_RateLimitingTests, JsonRouteTotalityTests,
RouteGuardMatrixTests, CrossSiteDefenceMatrixTests, EndToEndFlowTests, RelyingPartyApiTests,
HolderKeyBindingTests, OfflineStatusAssertionTests, FederationManifestTests,
EpochRevocationTests, StatusBundleTests, OperatorAuthorityScopeTests,
RefusalsTheAppMutationDrillFound.

| Mode | What connects as `polaris_rp` | Tests | Pass | Fail | Skip | 42501 on `polaris_rp` |
| --- | --- | --- | --- | --- | --- | --- |
| owner (baseline) | nothing | 163 | 160 | 0 | 3 | 0 |
| asis | every `/api/v1/*` request, code as it stands | 163 | 80 | 80 | 3 | 80 |
| split | `/api/v1/*` except the two login-gated routes; the relying-party service honours no operator session | 163 | 160 | 0 | 3 | 0 |

The 3 skips are EndToEndFlowTests, which needs real ML-DSA-65 in every mode. In split mode the
application opened 509 connections as `polaris_rp` across 30 of the 34 relying-party endpoints;
the 4 not reached (the anchor log's STH and the three consistency routes) run only
`_transparency_entries`, which the statement probe covers. The statement probe: 45 statements,
0 refused with the final grants.

The measurement was shown to detect a missing right (`out/control-*.json`): with INSERT on
HolderKeyEvent and SELECT on Individual revoked, 17 of 20 AuthBrokerTests and
HolderKeyBindingTests failed with 18 recorded refusals; with only EXECUTE on
`uc12_record_duress` revoked, the duress test failed (`0 != 1`) and the runner recorded the
refusal the application swallowed (`DURESS RECORD FAILED` on stderr only). Grants restored after.

## Findings

### Category (a): genuine needs of the relying-party surface the static map missed

- **A-1. ZkVerificationNonce: INSERT and SELECT.** `POST /api/v1/auth/authorize` with a
  zero-knowledge step-up calls `_zk_verify_and_consume`, which consumes the nonce with
  `INSERT ... ON CONFLICT ON CONSTRAINT pk_zk_verification_nonce DO NOTHING RETURNING
  consumed_at`. Absent from the section-1 table. Found by the probe, not the tests: no test drives
  a step-up with a proof that verifies. SELECT on `consumed_at` alone is refused; the ON CONFLICT
  arbiter also needs SELECT on (epoch_id, context_id, nonce), so the whole table. The rows carry
  no token identifier.
- **A-2. The base tables under the `security_invoker` views.** HolderKeyCurrent needs
  HolderKeyEvent, AuthorityKeyCurrent needs AuthorityKeyEvent, the Athena views need Agency,
  VerificationContext and AgencyTrustAttestation, IndividualCurrentEnrollment needs
  EnrollmentStatusEvent and Individual (see B-2).
- **A-3. Three sequences** for the SERIAL inserts (HolderKeyEvent, ExchangeReceiptLog,
  TimestampLog).

### Category (b): the relying-party path touching operator-owned tables

- **B-1. DuressEvent, through `uc12_record_duress` (SECURITY DEFINER).** Route: `POST
  /api/v1/auth/authorize` with `presented_code`. `_check_and_record_duress` reads
  `IdentityToken.duress_code_hash` and, on a match, `_record_duress_async` runs `CALL
  uc12_record_duress(token_id, context_id, agency_id, 'AUDIT_TABLE')` on a background thread,
  which inserts into DuressEvent as the owner. Published behaviour (the auth broker records a
  duress code silently), so it cannot be removed without changing it. Step 5 measured the cost:
  as `polaris_rp`, the procedure accepts a fabricated duress event for any credential that has a
  code enrolled, with any context and agency; and the same role reads every enrolled
  `duress_code_hash`, which is both the list of holders who enrolled (what `lab/duress`'s timing
  ballast exists to hide) and material for an offline search of short codes. Not a write to an
  identity, token, agency or account table; a write to an audit-of-record table and a read of
  a secret in the token table.
- **B-2. Individual.legal_name.** Routes: `POST /api/v1/mdoc` and `POST
  /api/v1/auth/authorize` read `current_status` from IndividualCurrentEnrollment. PostgreSQL
  checks the invoker's rights on every column the view references, so a column grant without
  `legal_name` and `jurisdiction` is refused (measured). As the code stands, the public
  surface can read every holder's legal name. Removable without changing a published
  behaviour: the latest status from EnrollmentStatusEvent gives the same answer, and both routes
  already default to NOT_ENROLLED when there is no row. A read, not a write.
- **B-3. OperatorSession and AppUser, through the session hook.** Every `/api/v1/*` request that
  carries an operator session cookie runs `security.validate_session` before the route:
  `SELECT ... FROM OperatorSession s JOIN AppUser u`, and `UPDATE OperatorSession SET
  last_seen_at` or `SET revoked_at`. All 80 asis refusals were this statement (the test classes
  log in as admin by default). Two `/api/v1` routes need it for real: `POST
  /api/v1/exchange-receipt/<id>` and `POST /api/v1/sign/<id>` are login plus CSRF (API.md says
  so). Removable without changing a published behaviour: route those two paths to the operator
  service and do not honour operator sessions in the relying-party service (no other
  relying-party route reads the session). That is what split mode does, and it passes.
- **B-4. AuthAuditLog, through the write rate limit.** `_security_before_request` audits any
  POST past 60 per address per minute with `INSERT INTO AuthAuditLog (... 'RATE_LIMITED' ...)`
  before the route runs, `/api/v1` included. Not reached by any test; `probe_rate_limit_audit.py`
  drove 63 POSTs to `/api/v1/timestamp/1` as `polaris_rp`: 3 answered 429, 3 audit inserts
  refused and swallowed to stderr, 0 rows written. Published ("the next request is a 429 and a
  RATE_LIMITED audit row", docs/operator/SECURITY-CONTROLS.md, docs/reference/API.md), so it
  cannot be dropped; it can be kept with a narrow grant or a definer routine that writes only
  RATE_LIMITED rows. AuthAuditLog is the authentication audit, not an account table.

### Beyond the database: what the compartment does not hold

These are outside the letter of the section-10 criteria, which speak of database writes, but
they bound what the compartment is worth and the decision record's section 2 does not state
them.

- **N-1. The signing key is shared.** Every signed relying-party artifact (status assertion,
  mdoc, verifiable credential, manifest, checkpoint, feed, registry, trust list, id token,
  timestamp, signed document) is signed by `pqc_signing.signature_over_message(...,
  agency_id)`, which uses the same `custody.get_custody_for_agency` key that
  `signature_with_key_for_token` uses at issuance. A code-execution bug in the relying-party
  process holds the authority's signing capability (the key itself under file custody, a
  signing oracle under PKCS#11 or KMS). Offline verifiers trust that key. A database
  compartment does not separate this.
- **N-2. Every credential pack is readable in bulk.** Possession authentication
  (`_possession_authenticated`) is token_value plus the stored issuance signature, and
  `polaris_rp` must read both to compare them. Step 5: one `SELECT` returns every pack. A
  compromised relying-party service can then present as any holder to every
  possession-authenticated route (auth broker sign-in, holder-key binding, holder-authorized
  signing, status assertions). Narrowable without a published change (a definer lookup that
  takes the presented pack and returns only the verdict fields), but not as measured.
- **N-3. The holder-key register is writable for any credential.** INSERT on HolderKeyEvent
  (a section-1 write) is not bound to possession in the database: step 5 bound an attacker's key
  to token 1 directly. With N-2 the application-level possession check does not bind it either.
  Since 2026-10-01 the route records events through `uc_record_holder_key_event`, which sets
  each event's instant and keeps events in order on a live credential; a rerun also grants
  EXECUTE on it. The finding stands: the INSERT remains until a contract migration withdraws
  it, and the routine cannot read the live key's signature.
- The other own-table powers are nuisance-grade: burn a zero-knowledge nonce a holder has not
  used (measured), consume auth codes or exchange nonces, append junk hashes to the receipt and
  timestamp logs. None can be updated or deleted (measured, 42501).

## Step 5: operator writes attempted as polaris_rp

All 30 operator writes were refused with SQLSTATE 42501 (`out/attempts.json`; each attempt
rolled back):

| Attempt | Result |
| --- | --- |
| Issue: INSERT IdentityToken, `uc1_issue_and_activate` (function), CALL `uc_bulk_issue`, INSERT TokenSignature, INSERT TokenPermission | refused 42501 |
| Revoke: UPDATE IdentityToken.status, CALL `uc8_revoke_token`, INSERT RevocationList; un-revoke: DELETE RevocationList | refused 42501 |
| Re-point a signing key: UPDATE Agency.signing_public_key_hex; INSERT AuthorityKeyEvent | refused 42501 |
| Trust edges: CALL `uc10_attest_trust`, INSERT AgencyTrustAttestation | refused 42501 |
| Accounts: INSERT AppUser, UPDATE AppUser.role; INSERT OperatorSession | refused 42501 |
| Verification event: INSERT VerificationEvent | refused 42501 |
| Audit: DELETE TokenLifecycleEvent, VerificationEvent, AuthAuditLog, DuressEvent; INSERT AuthAuditLog; TRUNCATE TokenLifecycleEvent | refused 42501 |
| CALL `uc11_close_epoch`, `uc9_initiate_recovery`, `uc_pseudonymize_individual`, `uc_archive_purge`; CREATE TABLE | refused 42501 |
| Own registers against their purpose: UPDATE/DELETE HolderKeyEvent, DELETE on the five other registers, UPDATE RelyingParty scope / client_secret_hash / require_zk, INSERT RelyingParty | refused 42501 |
| Reads not needed: AppUser.password_hash, OperatorSession, Individual.date_of_birth, VerificationEvent, DuressEvent, IdentityToken.physical_serial | refused 42501 |

What succeeded (all by design of the grant list, reported because each is a capability a
compromised relying-party service keeps):

| Attempt | Result |
| --- | --- |
| CALL `uc12_record_duress` on a credential with a duress code enrolled (the one SECURITY DEFINER routine the role can EXECUTE) | **succeeded**: a fabricated DuressEvent (B-1) |
| INSERT HolderKeyEvent binding an attacker key to token 1 | **succeeded** (N-3) |
| SELECT every token_value with its stored signature | **succeeded** (N-2) |
| SELECT every enrolled duress_code_hash | **succeeded** (B-1) |
| SELECT every legal_name | **succeeded** (B-2) |
| INSERT ZkVerificationNonce for a nonce no holder used | **succeeded** |

## Verdict against section 10

- **"The surface is not separable": not triggered.** No relying-party route needs a write to an
  identity, token, agency or account table, directly or through a shared helper. Evidence: the
  split run (163 tests, 0 failed, 0 refusals, 509 connections as `polaris_rp`), the statement
  probe (45 of 45), and step 5 (30 of 30 operator writes refused). The operator-table touches
  found are B-1 (an audit-of-record insert through one definer procedure, published, keepable),
  B-3 (session reads and updates the split removes with no published change), B-4 (an
  authentication-audit insert, published, keepable through a narrow grant) and B-2 (a read,
  removable). On the criterion as written, the bet survives.
  **But the compartment holds less than section 2 says.** "Six append-mostly registers and one
  timestamp column" is false as a blast radius: the measured role can also fabricate duress
  events, bind a holder key to any credential, read every credential pack, every duress hash and
  every legal name, and the process that holds it holds the authority's signing capability
  (N-1). Before any product change, the record should state N-1 and N-2 as named limits or add
  them to the kill criteria; without separate custody and a lookup that does not expose packs
  in bulk, "the public API cannot write identities" is true and "a compromise of the public
  surface cannot act as the issuer" is not.
- **"It costs more than it protects": not measurable in the lab.** Nothing here ran two services
  or the stranger's path. What the lab does show: the relying-party role needs nothing the single
  process lacks, so a single-host default can stay as it is and the split can be optional. A
  split needs three things the code does not do today: the two login-gated `/api/v1` routes
  served by the operator side, the session hook off on the relying-party side, and a decision
  about custody (N-1). Open.
- **"Nobody runs it split": not measurable until a release after it ships.** No deployment
  (Helm, Linux, compose) separates `/api/v1` today; the Helm Caddy config proxies everything to
  one app service. Open.

## Reproduce

```bash
createdb -h localhost -U vanta polaris_rpcomp        # already exists; left in place
psql -h localhost -U vanta -d polaris_rpcomp -v ON_ERROR_STOP=1 -f lab/strategy/002/polaris_rp_grants.sql
PY=~/.local/share/polaris-venv312/bin/python
POLARIS_DB_HOST=localhost POLARIS_DB_NAME=polaris_rpcomp POLARIS_DB_USER=vanta \
  POLARIS_TEST_RELOAD_USER=vanta POLARIS_SECRET_KEY=local-test-secret-key-32-bytes-long \
  POLARIS_STATE_DIR=/tmp/polaris-state-rpcomp POLARIS_PQC_PROFILE=placeholder \
  $PY lab/strategy/002/run_rp_as_polaris_rp.py --mode split     # also --mode owner, --mode asis
$PY lab/strategy/002/probe_rp_statements.py
$PY lab/strategy/002/attempt_operator_writes.py
```

Gaps: all runs used the placeholder
signing profile, so EndToEndFlowTests skipped and the real-ML-DSA paths (exchange gateway,
service-to-service receipt minting) were covered only by the statement probe, not by a request.
