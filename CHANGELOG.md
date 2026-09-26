# Changelog

Externally observable changes to Polaris, a reference implementation on notional data.
Entries before v9.453 are in [docs/history/CHANGELOG-v9.md](docs/history/CHANGELOG-v9.md).
The full reasoning for each change, with its tests and measurements, is in its commit message.
Entries use the [Keep a Changelog](https://keepachangelog.com/) groups: Security, Fixed, Added, Changed.

---

## v1.0.0-rc.62 — 2026-09-26 (fifty-nine fixes, one release)

rc.4 to rc.62 were cut per fix and released together; from here a version moves only when a release is cut.

### Security

- (rc.62) The application role can no longer write `schema_version`, so it cannot mark a pending migration as applied.
- (rc.61) The application role can no longer rewrite the constitution rows the `/athena` console shows.
- (rc.59) The application role can no longer write `VerificationContext`, so it cannot lower a published proof policy.
- (rc.58) The application role can no longer revive a deprecated algorithm or grant an authority rights to one.
- (rc.57) An authority's signing key can change only to a key registered, and not retired or compromised, in `AuthorityKeyEvent`.
- (rc.56) A plain UPDATE of `IdentityToken` can change only `status`, not holder, expiry, value, issuer or duress code.
- (rc.55) The application role can no longer update or delete token permissions, device bindings or revocation-list entries.
- (rc.54) The application role can no longer record all three recovery channels itself or re-open an issued bulk batch.
- (rc.53) The application role can no longer create credentials, permissions, revocations, device bindings or recoveries outside their procedures.
- (rc.52) The application role can no longer fabricate duress events, archive checkpoints or erasure records.
- (rc.51) Anchor batches and anchors are written only by `close_anchor_batch`; the application role cannot move or rewrite them.
- (rc.50) Federation trust edges are recorded and revoked only through the admin-gated `uc10` procedures.
- (rc.49) Epochs are written only by `uc11_close_epoch`, so a direct insert cannot bypass the anonymity floor.
- (rc.46) An epoch below the minimum anonymity set (twenty by default) is refused, and CI fails on a skipped security test.
- (rc.44) Binding, moving or unbinding an operator's authority now ends their live session (`agency_changed`).
- (rc.43) Token routes refuse (403) a bound operator acting on a credential that row-level security hides from them.
- (rc.42) Seven rule-enforcing routines run as the owner, so recovery and revocation rules also hold for bound operators.
- (rc.41) Every view is `security_invoker`, so a bound operator sees no more through a view than through its tables.
- (rc.40) The application role holds only SELECT on audit-table partitions and can no longer append lifecycle events.
- (rc.39) The application role can no longer set a person's enrollment status by inserting `EnrollmentStatusEvent` rows.
- (rc.38) Change-record tables accept only rows from their recording triggers, with `db_role` set to the real session user.
- (rc.35) A zero-knowledge epoch commits only credentials that stay unexpired through the epoch's `valid_until`.
- (rc.33) `/uc8/revoke` and `/uc4/activate-reserve` check the token's issuer, not only the actor the request names.
- (rc.32) `/tokens/<id>/transition` checks the operator's binding against the token's issuer even when no actor is given.
- (rc.31) Agency edit, agency delete and token delete refuse an admin bound to another authority.
- (rc.30) Recovery decisions, device binding and algorithm migration refuse an account bound to another authority.
- (rc.24) An expired credential can no longer sign in, authorize holder signing or bind a holder key, and is attested `EXPIRED`.
- (rc.19) Only the revocation procedures can move a token to `REVOKED`, and a session cannot loosen the default revocation bound.
- (rc.18) `/sql` refuses (403) an account bound to one authority, because a query could clear its own scope.
- (rc.16) Five admin-gated procedures, including `uc_archive_purge`, now refuse a deactivated admin.
- (rc.15) Nine routes refuse (403) an operator bound to one authority acting as another.
- (rc.10) `polaris-secrets.sh unseal` refuses a store whose manifest names a path outside its destination.
- (rc.7) `polaris-oid4vp` status-list parsing bounds size, nesting depth and non-finite constants instead of raising `RecursionError`.

### Fixed

- (rc.60) Recovery channels can be recorded through the product again: new procedure, `POST /uc9/record-channel/<id>` and CLI command.
- (rc.48) The application, CLI and simulator open every database session in UTC whatever `PGTZ` says.
- (rc.47) Expiry and validity decisions in SQL use the UTC date (`polaris_utc_date()`) whatever the session timezone.
- (rc.45) `polaris retention-set` and the Atlas simulation tick now work when connected as the application role.
- (rc.37) Reporting a credential lost no longer activates a reserve past its expiration date.
- (rc.36) A device can no longer be bound to an expired credential.
- (rc.34) The per-minute rates in `/api/metrics` describe the present, not the last minute in which an event occurred.
- (rc.29) On an app host outside UTC, expired zero-knowledge epochs are refused and Atlas time windows cover their stated span.
- (rc.28) The database timezone is set to UTC, so attestation validity is judged on the UTC date.
- (rc.27) Credential expiry follows the UTC date on servers whose local timezone is not UTC.
- (rc.26) A federation attestation and its signature commit together; a failed signing records nothing.
- (rc.25) Card personalization refuses a credential past its expiration date.
- (rc.23) `/verifications/new` refuses a `SUCCESS` against an expired credential that still reads `ACTIVE`.
- (rc.22) `/verifications/new` refuses to record a `SUCCESS` against a credential that is not `ACTIVE`.
- (rc.21) Population algorithm migration re-signs and deprecates `RESERVE` credentials as well as `ACTIVE` ones.
- (rc.20) A pilot wind-down revokes the pilot's `RESERVE` credentials and counts them in the co-signer check.
- (rc.17) Visually inspected documents cap at `FAIR` evidence and physical-feature checks at `STRONG`, following NIST SP 800-63A.
- (rc.14) Three 32-bit id sequences that would run out inside the 25-year capacity horizon are widened to `BIGSERIAL`.
- (rc.13) A role change ends the operator's live session instead of raising a server error.
- (rc.12) A scoped pilot wind-down no longer pseudonymizes a person another authority still serves.
- (rc.11) Atlas `/clusters` and `/hexbin` answer 400 to a NaN or infinite `grid` or `size`.
- (rc.9) `polaris migrate-population` names the credentials it cannot re-sign instead of stopping silently.
- (rc.8) The signed status assertion reports an expired credential as `EXPIRED` and never outlives the credential.
- (rc.6) The `polaris-oid4vp` `Verifier` class now accepts `status_resolver` and passes it to verification.

### Added

- Mutation drills now delete each refusal inside trigger functions and weaken each row-level security policy; sixteen refusals and two policies that no test noticed are now covered.
- (rc.5) `polaris-oid4vp` can check a Token Status List through an opt-in `status_resolver`, reporting `unreachable` apart from `not_evaluated`.
- (rc.4) `polaris-oid4vp` verdicts carry a `revocation` field: `no_status_claim`, `not_evaluated` or `unsupported_status`.

## v1.0.0-rc.3 — 2026-09-17 (issuer trust and current-key status reported separately)

### Changed

- `polaris-verify` with no `--issuer-anchor` abstains with exit 2; `--signature-only` asks for signature validity alone.
- The `polaris-verify` verdict gains `trust_evaluated`, so abstained, trusted and untrusted runs differ in JSON and exit code.
- `issuer_authentic` in `/verify` and the relying-party API is replaced by `issuer_authorized_at_signing` and `issuer_key_current`.

### Security

- The signing instant is read from the append-only `ISSUED` lifecycle event, not the editable `IdentityToken.issued_date`.
- Not defended: `AuthorityKeyEvent.effective_at` is operator-supplied, so an authority writing its own key history can backdate it.

## v1.0.0-rc.2 — 2026-09-17 (defects found in rc.1)

### Security

- `polaris-oid4vp`: fifteen defects fixed, including accepting expired credentials, a NaN key-binding `iat`, and four denial-of-service paths.
- `polaris-verify`: sixteen defects fixed, including trust attestations that never expired and an ignored agent-grant algorithm.
- The two reference SDKs: thirteen defects fixed, including a cached bearer token that outlived the client's standing.
- Application: expired credentials stayed usable, a bound operator could make another authority sign, and eleven authentication refusals were missing.

### Changed

- NaN and Infinity are refused at one JSON provider, and a non-object JSON body no longer raises.
- `SECURITY.md` tells anyone who installed rc.1 from a registry which checks their copy lacks.
- The Flask application joined the mutation drills; 31 of its 37 refusals had survived being switched off.

## v1.0.0-rc.1 — 2026-09-15 (version scheme moves from ship counts to 1.0.0-rc.1)

### Changed

- The tree moves from 9.467 to 1.0.0-rc.1 and the four packages from 0.1.0 to 1.0.0-rc.1; PyPI classifier Beta.
- Installing the candidate needs `pip install --pre`; the npm SDK is published under the `next` tag.
- The 295 v9 tags and 294 GitHub releases were removed; [docs/history/RELEASES-v9.md](docs/history/RELEASES-v9.md) maps each to its commit.
- Document version stamps must equal the tree version exactly; the README was rewritten and its test counts re-measured.

### Fixed

- `check_roadmap_consistent` fails when it cannot parse the version, instead of skipping the comparison.
- Reloading sample data resets `RelyingPartyEvent`, so a new relying party no longer inherits an old party's history.

## v9.467 — 2026-09-15 (application-log privacy promise enforced)

### Added

- `check_logs_exclude_pii` fails if a logging call names a request body, cookie, credential or holder attribute.
- The same check fails if `docs/operator/PRIVACY.md` stops stating that promise; a repository audit found no committed secrets.

## v9.466 — 2026-09-15 (four packages published)

### Added

- Published at 0.1.0: `polaris-verify`, `polaris-oid4vp` and `polaris-sdk-python` on PyPI, `polaris-sdk-ts` on npm.
- [docs/STRANGER-PATH.md](docs/STRANGER-PATH.md) reaches an accepted external-wallet presentation from a clean machine without cloning.
- The OpenID Foundation hosted suite (`oid4vp-1final-verifier-haip-test-plan`) ran: 7 PASSED, 4 REVIEW, no failures; not a certification.

### Security

- PyPI publishing uses trusted publishing over OIDC; the single npm token was revoked within the hour.

## v9.465 — 2026-09-15 (first presentation from an unmodified external wallet)

### Added

- An unmodified walt.id Wallet API v2 presented an SD-JWT VC to `polaris-oid4vp` over OpenID4VP 1.0 and was accepted.
- Negative controls: a different trusted issuer key and a replayed `state` are both refused.
- Scope: one wallet, one credential format, one presentation path, ES256; no general interoperability claim.

### Fixed

- `polaris-oid4vp keygen` gives the request-signing certificate the `digitalSignature` key usage the wallet required.

## v9.464 — 2026-09-14 (concurrency design record corrected)

### Changed

- `docs/design/concurrency.md` corrects three passages and records which of the six locks the suite can observe.

## v9.463 — 2026-09-14 (redundant row locks measured and documented)

### Changed

- Comments beside two `FOR UPDATE` clauses record that each, or its advisory lock, suffices, and dropping both fails the suite.
- No behaviour changed.

## v9.462 — 2026-09-14 (concurrent attest and revoke tested)

### Added

- A test drives `uc10_revoke_attestation` against `uc10_attest_trust` and fails if the lock key uses the wrong agency column.
- `check_advisory_locks_have_a_contention_test` requires every procedure that takes a lock to be exercised.

## v9.461 — 2026-09-14 (local test runner collects the whole file)

### Fixed

- `scripts/polaris-test.sh app` ran 566 of 704 tests locally because the runner block sat mid-file; CI was unaffected.

### Added

- `check_test_runners_are_last_in_their_file` holds the runner block at the end of four test files.

## v9.460 — 2026-09-14 (lock-serialization tests exercise the procedures' own locks)

### Fixed

- Two serialization tests took the advisory lock themselves; `assertContends` now proves four procedures take their own lock.

### Changed

- The locks in `uc9_complete_recovery` and `close_anchor_batch` are declared unobservable from outside, with reasons.
- `check_advisory_locks_have_a_contention_test` refuses tests that take the lock by hand.

## v9.459 — 2026-09-14 (concurrency tests measure lock contention, not elapsed time)

### Fixed

- Five parallelism tests passed with lock keys that ignored their entity; they now use `lock_timeout` and assert each effect.

### Added

- `check_advisory_locks_have_a_contention_test` requires a contention test for every parameterised advisory-lock domain.

### Changed

- The `_assertRanInParallel` timing helper is removed.

## v9.458 — 2026-09-13 (Apache-2.0 license kept and pinned)

### Changed

- The license stays Apache-2.0 for its patent grant; `NOTICE` names psycopg2's LGPL 3 terms.
- `NOTICE` now describes the project as a reference implementation on notional data and is covered by the wording checks.

### Added

- `check_license_is_pinned` holds every package manifest, `LICENSE`, `NOTICE` and the README to one license identifier.

## v9.457 — 2026-09-13 (CI job installs the Node dependencies its drill runs)

### Fixed

- The `pqc-real` CI job sets up Node 24 and installs the TypeScript SDK before the SDK mutation drill.

### Added

- `check_ci_jobs_install_what_they_run` fails a job that reaches the TypeScript suite without installing it.

## v9.456 — 2026-09-13 (TypeScript SDK refusals mutation-tested)

### Fixed

- Nine of fourteen refusals in the TypeScript SDK could be inverted unnoticed, including `sameBytes`'s length guard; six tests close them.

### Changed

- The SDK mutation drill covers both SDKs (32 refusals, 4 declared survivors) with a per-SDK negative control.
- An unusable timing measurement is reported as such, and `polaris-ship.py triage` recognises it.

## v9.455 — 2026-09-13 (Python SDK refusals mutation-tested)

### Fixed

- All eighteen refusals in the Python reference verifier could be inverted with tests green; eighteen tests close them.

### Changed

- The drill inverts `return False` to `return True` rather than deleting it, and a check refuses a deleting drill.

## v9.454 — 2026-09-13 (quantum wording rule applied to the system as a whole)

### Changed

- `check_post_quantum_claims_are_agility` refuses quantum-safety wording applied to the system, engine or platform; naming algorithms stays permitted.

### Fixed

- `site/index.html` no longer opens with a quantum-safety claim about the system.

## v9.453 — 2026-09-12 (citations to a removed document replaced)

### Fixed

- 46 references in 24 files to a removed document, including one operator-facing error message, now state the rule directly.
- `01_schema.sql` no longer counts a removed table among the audit-of-record tables.

### Added

- `check_no_citations_to_deleted_apparatus` refuses new citations to the removed document.

### Changed

- `SECURITY.md` describes the development placeholder signer; `CONTRIBUTING.md` says `polaris-test.sh` runs four of CI's eighteen suites.
- The headline on every surface says the system is signed with ML-DSA-65 under an audited algorithm-migration path.
