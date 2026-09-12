# Polaris security posture

**Reader:** the security assessor evaluating a Polaris deployment for national use, and the operator who keeps that posture true. **Job:** state each control that exists today, name the code that enforces it, and name the automated check or test that pins it, so an assessment reads the repository instead of a claim.

Status: controls verified against the repository at v9.199 on 2026-09-02. This document is the control inventory; the file GitHub reads as the security policy is the root [SECURITY.md](../../SECURITY.md), which is why this one is named for what it holds rather than sharing that name. The disclosure policy (how to report a vulnerability, how to verify a release, the bug-bounty terms) is the root [SECURITY.md](../../SECURITY.md). The STRIDE model is [threat-model.md](../design/threat-model.md); the red-team boundary is [RED-TEAM-SCOPE.md](../RED-TEAM-SCOPE.md); the constitution (C1 to C10) is [MISSION.md](../../MISSION.md).

Every check named below is a `check_*` function in [polaris_checks/checks.py](../../polaris_checks/checks.py) and runs without a database: `python3 -m polaris_checks.run`. Every test class named below lives in [polaris_web/test_app.py](../../polaris_web/test_app.py) unless another file is named.

---

## Layers and enforcement points

| Layer | Surface | What it enforces | Pinned by |
|---|---|---|---|
| Database | [polaris_sql/](../../polaris_sql/README.md) | State-machine and append-only triggers, revocation and quota bounds, CHECK constraints, partial unique indexes, a `polaris_app` role with no DDL | `check_aor_append_only_triggers`, `check_aor_privilege_boundary`, `check_one_active_token_index`, `check_c10_no_money_tables`, `08_tests.sql` |
| Application | [security.py](../../polaris_web/security.py), [app.py](../../polaris_web/app.py) | Authentication, sessions, authorization, CSRF, rate limits, headers, body caps, error sanitization | `check_csp_forbids_unsafe_inline`, `check_cookie_secure_in_production`, `check_open_redirect_guard`, `check_c4_atomic_failed_login`, `check_session_origin_hardening`, the `F0x` test classes |
| Runtime | [Dockerfile](../../polaris_web/Dockerfile), [docker-compose.prod.yml](../../polaris_web/docker-compose.prod.yml), [docker-init.sh](../../polaris_web/docker-init.sh) | Fail-closed production startup, demo-account neutralization, no published database port, password floors, SCRAM and TLS on the database hop | `check_prod_fail_closed`, `check_prod_hardening`, `check_container_hardening`, `check_app_db_tls` |
| Supply chain | [.github/workflows/](../../.github/workflows/ci.yml) | SAST, dependency and image CVE scanning, SBOM, release provenance | `check_sast_scanning`, `check_cve_scanning`, `check_image_cve_scanning`, `check_sbom_workflow`, `check_release_provenance` |

The database layer is the security boundary. The application layer sits above it and is held to the same standard, but a control that exists only in Flask is documented as such.

---

## Threat model in brief

Polaris stores national-scale identity data: holder names, dates of birth, biometric binding metadata, verification history, device bindings, and audit chains. An attacker on the same network as the web server, without credentials, sees the anonymous surface only: the landing page, `/demo` (notional data), `/login` and the WebAuthn assertion endpoints, `security.txt`, the health probes, and the two metrics endpoints, which are meant to sit behind an operator-internal ACL at the edge (see OPERATIONS.md). An attacker holding an `auditor` account reads but cannot mutate state. An attacker holding an `operator` account performs lifecycle operations but cannot manage user records, decide recovery ceremonies, or run the SQL console. Compromise of an `admin` account is the worst case the application layer plans for; the controls that still hold there are the append-only audit tables, the database role without DDL, the revocation and quota bounds enforced by triggers, CSRF, and CSP.

Residuals the design accepts, each named where it belongs below: a rate limiter on the in-memory backend counts per process; an issuer under the revocation cap can still abuse the long tail; a holder too constrained to type a duress code produces no signal.

---

## Application controls

### Authentication

- Accounts live in `AppUser` ([01_schema.sql](../../polaris_sql/01_schema.sql)); passwords are Werkzeug scrypt hashes (`security.hash_password`, `method='scrypt'`). Three roles: `admin`, `operator`, `auditor`. `PasswordHashingTests` (3 tests) pins the hash format.
- Lockout: `LOGIN_FAILURE_THRESHOLD = 5` failures within `LOGIN_FAILURE_WINDOW_MIN = 10` minutes locks the account for `ACCOUNT_LOCK_MIN = 15` minutes. The failure counter increments in one `UPDATE ... RETURNING` (C4), pinned by `check_c4_atomic_failed_login`.
- Username enumeration: the unknown-user path runs a dummy scrypt verification and returns the same generic error as a wrong password; the lockout state is revealed only on a correct password.
- Session fixation: `session.clear()` runs before the session is populated at login. Logout is `POST` plus CSRF, so an image tag cannot end a session.
- Post-login `?next=` routes through `security.is_safe_next_url`, which rejects off-site targets including the backslash form browsers normalize to `//host`. Pinned by `check_open_redirect_guard`; tested by `NextUrlSafetyTests` and `F01_AuthenticationTests`.
- WebAuthn: enrollment, assertion, a per-account password deadline, hardware-only escalation, and an attestation policy (`POLARIS_WEBAUTHN_USER_VERIFICATION`, `POLARIS_WEBAUTHN_ATTESTATION`, `POLARIS_WEBAUTHN_REQUIRE_ATTESTATION`, `POLARIS_WEBAUTHN_ALLOWED_AAGUIDS`). Registration offers ML-DSA-65. The rollout is [WEBAUTHN-ROLLOUT.md](WEBAUTHN-ROLLOUT.md); `check_session_origin_hardening` pins the knobs and `WebAuthnCeremonyTests` exercises both ceremonies with a synthetic authenticator.
- Server-side sessions: every login registers a row in `OperatorSession` ([migration](../../polaris_sql/migrations/2026-09-01-001-operator-session.up.sql)), and `security.validate_session` runs on every request. Per role: a network allow-list (`POLARIS_NETWORK_POLICY_<ROLE>`, evaluated at login and on every live request), a concurrent-session cap (`POLARIS_SESSION_MAX_<ROLE>`, admin default 3), and an idle timeout (`POLARIS_SESSION_IDLE_MINUTES_<ROLE>`, admin default 30). `polaris-id user-passwd` and `polaris-id user-deactivate` revoke the account's live sessions. Tested by `NetworkPolicyTests` and `SessionLimitTests`; the operator model is [HARDENING.md](HARDENING.md) section 13.
- Demo accounts: [10_auth.sql](../../polaris_sql/10_auth.sql) seeds `admin`, `operator`, and `auditor` with published passwords for development. When `POLARIS_ENV=production`, [docker-init.sh](../../polaris_web/docker-init.sh) disables all three, scrambles their hashes, locks them, and retires the demo duress enrollment; the first real admin is created with `scripts/polaris-create-operator.sh`. Pinned by `check_prod_hardening`.

`F01_AuthenticationTests` (13 tests) covers anonymous redirect on every protected route, login success and failure, the generic error on an unknown user, the audit trail on login events, lockout, logout, GET-logout rejection, open-redirect resistance, and session-fixation resistance.

### Authorization

- `@login_required` guards every protected route; `@require_role(...)` narrows by role. Auditors read and use the read-only SQL console; operators run lifecycle workflows; admins decide recovery ceremonies and use the console too. User accounts are managed only by the CLI and scripts under database credentials; no web role has a user-management surface. A wrong-role request is refused and audited as `AUTHZ_DENIED`.
- The stored procedures re-check the role for the decisions that matter: `uc9_complete_recovery` raises `insufficient_privilege` unless the deciding user is an active admin, independent of the route decorator.
- `RoleBasedAccessControlTests` covers the cross-cutting cases.

### CSRF

- `security.issue_csrf_token` binds a 32-byte URL-safe random token to the session; `security.validate_csrf` compares with `hmac.compare_digest`.
- `@csrf_protect` wraps every state-changing route. 17 of the 18 templates with a `method="post"` form carry the hidden `csrf_token` input (v9.199); the login form is the one exception, because no session exists yet, and the login rate limit stands in for it.
- A rejection is a 403 and a `CSRF_REJECTED` audit row. `F02_CSRFTests` (5 tests) covers missing token, wrong token, valid token, the audit row, and the input's presence in every rendered form.

### Rate limiting

- Login: 10 attempts per client address per 60 seconds. State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`): 60 per client address per 60 seconds. The next request is a 429 and a `RATE_LIMITED` audit row.
- The defaults are the posture. `POLARIS_RATE_LIMIT_LOGIN_MAX`, `POLARIS_RATE_LIMIT_WRITE_MAX`, and `POLARIS_RATE_LIMIT_WRITE_WINDOW` exist so the [performance baseline](../reference/PERFORMANCE-BASELINE.md) can drive one scratch server from one address; `check_performance_baseline` pins the defaults at 10 / 60 / 60, and a production stack that raises them has lowered this control on purpose.
- Two backends with one contract: `InMemoryRateLimiter` (per process) and `RedisRateLimiter` (an atomic Lua script over a sorted set, shared by every worker, fail-closed on a Redis error). `POLARIS_RATE_LIMIT_BACKEND=auto` selects Redis when `POLARIS_REDIS_URL` is set; the production compose sets it, pinned by `check_prod_hardening`. Tested by `F03_RateLimitingTests`, `InMemoryRateLimiterTests`, `RedisRateLimiterTests`, `MultiProcessRateLimiterTests`, and `RateLimiterSelectionTests`.
- Residual: a multi-worker deployment on the in-memory backend multiplies every limit by the worker count. The backend logs that at startup, and [DEPLOYMENT.md](DEPLOYMENT.md) names the Redis variables.

Per-agency quotas on issuance, revocation, and verification are a database control and are described under [Issuer discretion bounds](#issuer-discretion-bounds).

### Response headers

`security.apply_security_headers` runs as `@app.after_request` on every response.

| Header | Value | Purpose |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; worker-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'` (plus `upgrade-insecure-requests` when HSTS is on) | No inline scripts, no eval, no remote scripts (C5), no framing |
| `X-Frame-Options` | `DENY` | Clickjacking fallback for older browsers |
| `X-Content-Type-Options` | `nosniff` | MIME confusion |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=(), browsing-topics=()` | Browser APIs denied by default |
| `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy` | `same-origin` | Cross-origin isolation; COEP is deliberately not set |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` when `POLARIS_HSTS=1` | Protocol downgrade |
| `Cache-Control` | `no-store, no-cache, must-revalidate, private` on authenticated responses | Sensitive content in caches |
| `Server` | `Polaris` (the edge proxy is authoritative and may strip it) | No server version on the wire |

The one relaxation: the Atlas page loads a self-hosted MapLibre library whose basemap style and tiles come from the origin the deployment configures (`POLARIS_ATLAS_BASEMAP_STYLE_URL`; the default is `basemaps.cartocdn.com`), so on that endpoint only, by a flag the view sets, `img-src` and `connect-src` admit that one origin and `img-src` and `worker-src` admit `blob:`. A self-hosted style leaves the page self-only apart from `blob:` (v9.237). `script-src` stays `'self'` everywhere; `check_csp_forbids_unsafe_inline` pins it. `F04_SecurityHeadersTests` (6 tests) covers the headers above.

### Cookies

`SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`, `SESSION_COOKIE_NAME = 'polaris_session'`, `PERMANENT_SESSION_LIFETIME` of 8 hours. `SESSION_COOKIE_SECURE` is forced on when `POLARIS_ENV=production` and is opt-in elsewhere with `POLARIS_COOKIE_SECURE=1`; `check_cookie_secure_in_production` pins the forcing. `F06_CookieHardeningTests` parses the `Set-Cookie` header on login.

### Request bounds and error handling

- `MAX_CONTENT_LENGTH` is 1 MiB (`security.MAX_REQUEST_BODY_BYTES`); an oversize body is a rendered 413.
- The `/sql` console is open to admin and auditor, read-only, caps a query at 5,000 characters, sets `statement_timeout` to 5 seconds, and opens the connection `readonly=True` so Postgres refuses a write smuggled through a CTE regardless of the keyword gate. Pinned by `check_sql_console_readonly`; tested by `SQLConsoleTests`. The connection is rolled back and closed in a `finally` on every path.
- `db_error_to_message` maps known constraint and trigger failures to readable messages, surfaces `chk_*` CHECK names (deliberate schema documentation), and answers everything else with a generic message while the full psycopg2 error goes to stderr. `F08_ErrorMessageSanitizationTests` (2 tests) proves an unknown error leaks no fragment.
- Free-text length is bounded by the column definitions (`VARCHAR(n)` plus CHECK constraints), the body cap, and `maxlength` on the inputs; there is no separate Python-level length layer by decision.

### Production fail-closed guards

With `POLARIS_ENV=production`, [app.py](../../polaris_web/app.py) refuses to start (exit 2) when:

| Condition | Why |
|---|---|
| `POLARIS_SECRET_KEY` is at a development default | Sessions signed with a known key are forgeable |
| `POLARIS_DB_SSLMODE` is not one of `require`, `verify-ca`, `verify-full` | `prefer` falls back to plaintext silently |
| `verify-ca` / `verify-full` without a readable `POLARIS_DB_SSLROOTCERT` | The peer cannot be verified without a pinned CA |
| `POLARIS_DURESS_SYNC=1` | Synchronous duress recording reintroduces a timing side-channel |

Outside production the secret-key case is a stderr warning. Pinned by `check_prod_fail_closed`; `F05_ProductionSecretGuardTests` (6 tests) covers the secret-key guard. Secret material itself follows [SECRETS.md](SECRETS.md).

---

## Audit logging

`AuthAuditLog` is append-only (the `reject_audit_modification` trigger rejects `UPDATE` and `DELETE`). Each row records the event, username, user id, client address, truncated user agent, and free-text detail. `X-Forwarded-For` is honored only when `POLARIS_TRUST_PROXY=1`, so the recorded address cannot be chosen by the client.

| Event type | When |
|---|---|
| `LOGIN_SUCCESS` | Successful authentication |
| `LOGIN_FAILED` | Wrong password, unknown user, inactive account |
| `LOGIN_LOCKED` | Account hit the lockout threshold |
| `LOGOUT` | Explicit logout (`POST /logout`) |
| `PASSWORD_CHANGED` / `ACCOUNT_CREATED` / `ACCOUNT_DEACTIVATED` | User management |
| `CSRF_REJECTED` | POST without a valid CSRF token |
| `AUTHZ_DENIED` | Logged-in user with the wrong role |
| `AUTH_REQUIRED` | Non-GET request without a session |
| `RATE_LIMITED` | Address exceeded the login or write limit |
| `WEBAUTHN_REGISTERED` / `WEBAUTHN_ASSERTED` / `WEBAUTHN_ASSERTION_FAILED` / `WEBAUTHN_DEREGISTERED` / `EMERGENCY_PASSWORD_LOGIN_AUTHORIZED` | The WebAuthn lifecycle |
| `NETWORK_POLICY_DENIED` | A correct password from outside the role's `POLARIS_NETWORK_POLICY_<ROLE>` (answered with the generic error), or a live session presented from outside it (ended) |
| `SESSION_EVICTED` | A login exceeded `POLARIS_SESSION_MAX_<ROLE>`; the least-recently-seen session was revoked |
| `SESSION_EXPIRED` | A session idled past `POLARIS_SESSION_IDLE_MINUTES_<ROLE>` |
| `SESSION_REVOKED` | A live session of a deactivated account was ended on its next request |
| `WEBAUTHN_REGISTRATION_REFUSED` | An enrollment the library rejected, or one the attestation policy refused (`policy:` in the detail) |

The allowed set is the `chk_authaudit_event_type` CHECK constraint. `F11_AuditLoggingTests` (3 tests) covers login audit, authorization-denial audit, and the append-only trigger. `AuditAccessLog` ([migration](../../polaris_sql/migrations/2026-05-15-003-audit-access-log.up.sql)) is the meta-audit: it records who queried the audit tables and is itself append-only through the same trigger function. Feeding these tables to a SIEM is an operator step in the [checklist](#operator-checklist).

---

## Database and runtime boundary

- **Application role.** [09_grants.sql](../../polaris_sql/09_grants.sql) gives `polaris_app` data privileges and no DDL; the archive purge runs as `SECURITY DEFINER` so the carve-out is unreachable from the app role. `check_aor_privilege_boundary` pins the definer; `test_check_constraints.py` opens an explicit `polaris_app` connection to prove the boundary.
- **Append-only audit-of-record.** `reject_audit_modification` is the `BEFORE UPDATE OR DELETE` trigger on every audit-of-record table: `TokenLifecycleEvent`, `VerificationEvent`, `EnrollmentStatusEvent`, `AnchorBatch`, `TokenStateEpochLeaf`, `DuressEvent`, `IndividualErasureEvent`, `AuthAuditLog`, and `AuditAccessLog`. `check_aor_privilege_boundary` names the tables and `check_aor_append_only_triggers` asserts the trigger family exists (C1).
- **Revocation and quota bounds.** A direct `UPDATE IdentityToken SET status='REVOKED'` that bypasses `uc8_revoke_token` is refused by `enforce_revocation_velocity_bound`, which passes only when the procedure has set the transaction-local GUC `polaris.revoke_check_done`; `enforce_agency_quota` fires on every issuance, revocation, and verification write. Both are described under [Issuer discretion bounds](#issuer-discretion-bounds).
- **Database port.** [docker-compose.yml](../../polaris_web/docker-compose.yml) does not publish 5432; the app reaches the database by service name. The production compose exposes the app only behind Caddy and keeps pgbouncer internal.
- **Database credentials.** [docker-init.sh](../../polaris_web/docker-init.sh) refuses a `POLARIS_APP_PASSWORD` under 16 characters, and under 24 characters also requires a digit, a letter, and a symbol (a generated 48-hex secret passes on length alone); a refusal exits 2 before the `ALTER ROLE` (the schema load and migrations have already run), and the `ALTER ROLE` output is discarded so the password never reaches the container log. The production database authenticates with `scram-sha-256` and the app requires an encrypting `POLARIS_DB_SSLMODE`; `check_app_db_tls` pins the hop.
- **Development default.** `polaris_dev_password` remains the development fallback for `POLARIS_DB_PASSWORD`. Production rotates it through `docker-init.sh`; `check_prod_app_password_synced` keeps the production compose and the init script agreeing.
- **Encryption at rest, keys, secrets.** [ENCRYPTION-AT-REST.md](ENCRYPTION-AT-REST.md), [KEY-CEREMONY.md](KEY-CEREMONY.md), [SECRETS.md](SECRETS.md), and [PQC-POSTURE.md](../reference/PQC-POSTURE.md) own those subjects; `check_encryption_at_rest_posture`, `check_key_custody_abstraction`, and `check_secrets_lifecycle_sealed` pin them.
- **Personal data.** Erasure and retention are [PRIVACY.md](PRIVACY.md); `check_erasure_procedure` pins the procedure.

---

## Holder-protection mechanisms

The project report's "Limitations and Open Problems" section ([polaris_project_report.tex](../paper/polaris_project_report.tex)) names six open problems. Four have a relational answer enforced at the schema layer and are described here because each is a control against the system's own operators. The other two, population coverage and the centralized trust assumption, are answered by [tiered-enrollment.md](../design/tiered-enrollment.md) and [federation.md](../design/federation.md).

### Issuer discretion bounds

The report's "Issuer trust concentration" problem asks for three things: cryptographic diversity across issuers ([Cryptographic migration](#cryptographic-migration) below), a federation model with mutual recognition (`AgencyTrustAttestation`, [federation.md](../design/federation.md)), and constitutional limits on issuer discretion. The third leg:

- `uc8_revoke_token` is the single sanctioned revocation path. It enforces a rolling-window cap on the share of its own tokens one issuing agency may revoke: system default 5.00% over 30 days (`polaris.default_max_revoke_percent`, `polaris.default_window_days`), overridable per agency with `polaris-id discretion-set`, which requires a justification of at least 20 characters. Since v9.426 that makes a loosening auditable in fact and not only in intent: the table keeps its history, so raising an agency's ceiling supersedes the bound in force and appends a new row rather than overwriting who set the last one, when, and why. `trg_discretion_policy_immutable` refuses any other edit and `uq_effective_discretion_policy` allows exactly one bound in force per agency, which is the one `uc8_revoke_token` reads. `polaris-id discretion-show --history` reads the record, flagging any bound looser than the system default. Before v9.426 the justification floor was real and this sentence was false: `agency_id` was the primary key, so a change overwrote the bound it replaced, and no command existed to make the change through in the first place.
- Above the cap a co-signer is required: a different agency holding `BOTH` authorization on the token's algorithm. The co-signer is recorded in the lifecycle row as `[COSIGN:<agency_id>]`, so a third party can detect one co-signer reused across mass-revocation events.
- A direct `UPDATE` to `REVOKED` that bypasses the procedure is refused by the `enforce_revocation_velocity_bound` trigger in [06_triggers.sql](../../polaris_sql/06_triggers.sql). `pg_advisory_xact_lock` keyed on the agency serializes concurrent revocations by the same agency (C9).
- Every decision about an outside relying party is recorded and a weakening has to say why (v9.425). `RelyingPartyEvent` is append-only and written by the `trg_relying_party_audited` trigger from the row diff, so registering a party, turning off the zero-knowledge step-up its holders must clear, disabling it, rotating its secret or widening its scope are all recorded whether the change comes through `polaris rp-policy` or through psql. A change that REDUCES what the party must satisfy before it learns something about a person is refused by the database without a stated reason of at least 20 characters; a tightening needs none. `polaris rp-history --weakened-only` reads the lowered bars. Before v9.425 all three of those decisions wrote nothing anywhere.
- `AgencyQuota` extends the same leg to issuance and verification: opt-in per-agency caps (issuances and revocations per rolling day, verifications per rolling hour) that the `enforce_agency_quota` trigger binds on every write path, advisory-locked so the count is exact under concurrent writers. Since v9.424 the caps are an append-only record rather than an editable setting: changing one supersedes the row in force and appends a new one, a partial unique index allows exactly one live cap per agency, and `trg_agency_quota_immutable` refuses any other edit, so who raised an agency's ceiling and why survives the next change. A refused write is an HTTP 429, a `quota_refused` log line, and a `polaris_quota_refusals_total` increment. Per-agency velocity counters feed the `PolarisIssuanceVelocity`, `PolarisRevocationVelocity`, and `PolarisVerificationVelocity` alerts ([observability README](../../deploy/observability/README.md)), which page when one agency's hour exceeds an absolute floor and four times its own trailing weekly mean. These controls bound what an agency may do and count what it does, never what a person is.

Tested by `IssuerDiscretionBoundsTests` and `AgencyQuotaTests`; pinned by `check_abuse_controls`. What the bound does not cover: slow abuse under the cap (4.99% a month compounds to roughly 60% a year, which civic audit reporting has to catch), collusion of every agency, and forgery of a co-signer identity (the co-signer is recorded procedurally, not hardware-attested). The full mechanism walk is [issuer-discretion.md](../design/issuer-discretion.md) and [abuse-controls.md](../design/abuse-controls.md).

### Catastrophic-loss recovery

The report's "Catastrophic-loss risk" problem: a holder loses every token and device at once and, without a recovery path, is civically dark until reissuance from scratch, which severs the predecessor chain. The answer is a two-phase out-of-band ceremony encoded in four CHECK constraints on `RecoveryRequest`:

| Constraint | What it enforces |
|---|---|
| `cooldown_window_minimum` | At least 48 hours between request and decision |
| `approved_requires_three_channels` | `APPROVED` requires biometric verification, a sworn-statement hash, and a witness agency with a co-signing user |
| `approved_after_cooldown` | The decision timestamp is at or after cool-down expiry |
| `approver_differs_from_requester` | The deciding `AppUser` is not the requesting one |

The partial unique index `uq_one_pending_recovery_per_individual` allows one `PENDING` request per individual. An operator initiates (`uc9_initiate_recovery`); an admin decides (`uc9_complete_recovery`, which raises `insufficient_privilege` for any other role; the `/uc9/decide/<id>` route also carries `@require_role('admin')`). `pg_advisory_xact_lock` on the claimed individual prevents two decisions on one request. Every transition during an approved recovery carries `[RECOVERY:<id>]` in its lifecycle `reason_code`, so audit replay reconstructs the ceremony from the lifecycle log alone.

Tested by `CatastrophicLossRecoveryTests`. Not covered: an attacker who controls all three channels and waits out the cool-down, and the report's "operational grace period" reading, since the holder stays dark during the 48-hour window (a temporary attestation credential is the planned answer). Mechanism walk: [recovery-ceremony.md](../design/recovery-ceremony.md).

### Cryptographic migration

The report's "Cryptographic migration during transitions" problem: how tokens move between post-quantum primitives when one is weakened or superseded. The report names mass reissuance or a multi-signature scheme; Polaris implements the multi-signature scheme.

`TokenSignature` resolves `IdentityToken` to signatures M:N, so a token carries signatures under several algorithms during a migration window. Two triggers hold the invariants:

| Trigger | Invariant |
|---|---|
| `enforce_token_has_active_signature` | Every token has at least one non-deprecated signature at all times |
| `enforce_token_signature_immutability` | A row is write-once except for a one-way `deprecation_date` (NULL to timestamp, once; never unset or backdated) |

`UNIQUE (token_id, algorithm_id)` blocks a duplicate-algorithm migration on one token, and `idx_token_signature_active` keeps the active-signature lookup indexed. `uc6_migrate_algorithm` is the single sanctioned path and takes `pg_advisory_xact_lock` on the token (C9); the route is `/uc6/migrate`. Tested by `MultiSignatureTests`.

Not covered: a compromise of a not-yet-deprecated algorithm (orderly deprecation cannot retroactively reject signatures that were valid when produced), and automatic cascade from `CryptographicAlgorithm.deprecation_date` (algorithm-wide and per-signature deprecation are separate columns by design; operator policy through UC-6 is the only path). Signing itself, real ML-DSA-65 or the deterministic placeholder, is [PQC-POSTURE.md](../reference/PQC-POSTURE.md). Mechanism walk: [multi-sig-migration.md](../design/multi-sig-migration.md).

### Compulsion resistance: duress codes

The report's "Compulsion resistance" problem: biometric binding stops casual theft but not compelled presentation. A holder under coercion types a secondary code. The verification flow:

1. Compares the input against `IdentityToken.duress_code_hash` with `werkzeug.security.check_password_hash` (scrypt, the same primitive as operator passwords).
2. On a match, records a `DuressEvent` row through `uc12_record_duress` on a background thread by default, so the match is not measurable in the response latency. `POLARIS_DURESS_SYNC=1` moves it onto the request thread for tests and is refused in production (`check_prod_fail_closed`).
3. In every branch (match, no match, no enrollment) the coercer sees the same response: the same 302, the same flash message, the same `VerificationEvent` row.

`DuressEvent` is append-only. The operator `/verifications` list does not join to it; admins and auditors read `/api/duress/events` or the table directly, and the `PolarisDuressEvent` alert pages on a new row (`check_duress_alertable`). Enrollment is per token and explicit; nothing derives a duress code automatically. Tested by `DuressCodeTests`.

Not covered: a coercer who knows the mechanism and forbids its use; a typo that misses the duress code and raises suspicion (codes are chosen to differ from verify codes by enough characters that a typo does not collide); and aggregate timing analysis across many holders. Mechanism walk: [duress-codes.md](../design/duress-codes.md).

---

## Test Coverage

Measured at v9.237 (the README's "Verified, not asserted" table is the
canonical statement and is re-stamped on every ship that changes it):

```
SQL self-tests : 91 assertions in 08_tests.sql, plus 12_v7_constraints.sql and 13_substrate.sql
Web            : 471 (test_app.py, 12 skipped without optional backends) + 83 constraint tests + 16 property tests + 19 secret-store tests
CLI            : 79 (test_cli.py)
Crypto         : 95 passing of 99 collected across the signing, custody and ZK witness suites (3 need a PKCS#11 token, 1 a real KMS key)
Invariants     : 119 checks, each with a detection test (polaris_checks, v9.237)
```

Run with:
```bash
cd polaris_sql && psql -d polaris_test -f 08_tests.sql
cd polaris_web && python3 -m pytest test_app.py test_check_constraints.py test_secretstore.py -q
cd polaris_cli && python3 -m pytest test_cli.py -q
python3 -m polaris_checks.run
```

---

## Operator checklist

1. **Set `POLARIS_ENV=production`.** The app then refuses a default secret key, a plaintext-capable database mode, and synchronous duress recording, and forces the Secure cookie flag. The production compose sets it.
2. **Never run the seeded accounts outside development.** Production startup neutralizes `admin`, `operator`, and `auditor`; create the first real admin with `scripts/polaris-create-operator.sh --role admin --username <name>`. To rotate a password by hand:
   ```python
   from werkzeug.security import generate_password_hash
   print(generate_password_hash('YourStrongPassword!', method='scrypt'))
   ```
   then `UPDATE AppUser SET password_hash = '...' WHERE username = '<name>';`, or use `polaris-id user-passwd`, which also revokes the account's live sessions.
3. **Enable HSTS** with `POLARIS_HSTS=1` once the deployment is HTTPS-only; the edge configuration is [DEPLOYMENT.md](DEPLOYMENT.md).
4. **Trust `X-Forwarded-For` only behind a known proxy.** Set `POLARIS_TRUST_PROXY=1` after confirming the edge sets and overwrites the header; otherwise every audit row and rate-limit key uses a client-chosen address.
5. **Run the Redis rate-limit backend** whenever `POLARIS_WORKERS` is above 1: set `POLARIS_REDIS_URL`. The production compose does.
6. **Feed `AuthAuditLog`, `AuditAccessLog`, and `DuressEvent` into a SIEM** and alert on lockouts, repeated `CSRF_REJECTED` from one address, `AUTHZ_DENIED` bursts, and any duress row. The shipped alert rules are in [RUNBOOKS.md](RUNBOOKS.md).
7. **Audit `AppUser` on a schedule**: remove inactive accounts, rotate passwords, review roles.
   ```sql
   SELECT username, role, last_login_at,
          CURRENT_DATE - last_login_at::date AS days_idle
     FROM AppUser
    WHERE is_active
    ORDER BY last_login_at NULLS FIRST;
   ```
8. **Pin admin sessions to the networks they come from.** Set `POLARIS_NETWORK_POLICY_ADMIN` to the office, VPN, or bastion ranges. Keep the default admin cap (3 concurrent sessions) and idle timeout (30 minutes) unless the operation needs otherwise. Review and end live sessions by hand when needed:
   ```sql
   SELECT session_id, u.username, s.role, s.client_ip, s.created_at, s.last_seen_at
     FROM OperatorSession s JOIN AppUser u USING (user_id)
    WHERE s.revoked_at IS NULL ORDER BY s.last_seen_at DESC;
   UPDATE OperatorSession SET revoked_at = now(), revoke_reason = 'operator'
    WHERE session_id = '<id>';
   ```
   [HARDENING.md](HARDENING.md) section 13 has the full model.
9. **Raise the WebAuthn bar once every operator holds a hardware key:** `POLARIS_WEBAUTHN_USER_VERIFICATION=required`, then `POLARIS_WEBAUTHN_ATTESTATION=direct` with `POLARIS_WEBAUTHN_REQUIRE_ATTESTATION=1` and, for a fixed fleet, `POLARIS_WEBAUTHN_ALLOWED_AAGUIDS`. [WEBAUTHN-ROLLOUT.md](WEBAUTHN-ROLLOUT.md) Phase 6.
10. **Set `AgencyQuota` caps for every issuing agency** with `polaris-id quota-set` and keep the velocity alerts routed to a pager; the runbook is [RUNBOOKS.md](RUNBOOKS.md).
11. **Keep the host hardened** per [HARDENING.md](HARDENING.md) and verify the release you deploy per the root [SECURITY.md](../../SECURITY.md).

---

## Compliance mapping (selected)

| Control | Standard | Implementation |
|---|---|---|
| Identification and authentication | NIST SP 800-53 IA-2 | `AppUser` with scrypt passwords; WebAuthn with attestation policy |
| Access enforcement | NIST SP 800-53 AC-3 | `@require_role` per route; role re-checked in the deciding procedures; account management only by CLI and scripts under database credentials |
| Account management | NIST SP 800-53 AC-2 | `is_active`, lockout, server-side session registry, CLI revocation |
| Audit generation | NIST SP 800-53 AU-2 | `AuthAuditLog`, `AuditAccessLog`, `TokenLifecycleEvent`, `VerificationEvent`, `DuressEvent` |
| Audit protection | NIST SP 800-53 AU-9 | `reject_audit_modification` on every audit-of-record table |
| Boundary protection | NIST SP 800-53 SC-7 | CSP, `X-Frame-Options`, body cap, no published database port, app behind the edge |
| Transmission confidentiality | NIST SP 800-53 SC-8 | HSTS, Secure cookie, encrypting `POLARIS_DB_SSLMODE` required in production |
| Cryptographic key management | NIST SP 800-53 SC-12 | scrypt for passwords; `scram-sha-256` on the database; issuer keys per [KEY-CEREMONY.md](KEY-CEREMONY.md) |
| Resource availability | NIST SP 800-53 SC-5 | Per-address rate limits, body cap, SQL console timeout, per-agency quotas |

---

## Appendix: the 2026 hardening engagement

The application-layer controls above began as a single cybersecurity patching pass over the web application, CLI, database, container runtime, and operational configuration, mapped to OWASP Top 10 (2021), CWE, and NIST SP 800-53. The pass predates the [CHANGELOG](../../CHANGELOG.md), whose earliest entry is v9.44 (2026-06-03); the code it introduced (`security.py`, `10_auth.sql`, the `F0x` test classes) is still the enforcement surface.

Before the pass, every route in `app.py` was anonymously reachable, no form carried a CSRF token, nothing was rate-limited, and no response carried a security header. The pass introduced the authentication layer, CSRF tokens on every form, headers on every response, per-address limits on login and writes, hardened cookies, sanitized error messages, the append-only auth audit log, and the tightened Docker and shell-script surfaces. The schema-level invariants (state-machine triggers, append-only audit tables, partial unique indexes, foreign keys, the no-DDL application role) were already in place; the pass worked above them. Fourteen findings, fourteen patched, each pinned by a test class or a shell-level check named in the table. Later work extended several of them (Redis rate limiting, WebAuthn, the session registry, per-agency quotas); the present-tense description of each is in the sections above.

| Finding | Severity | OWASP | CWE | Patch, as shipped | Test class |
|---|---|---|---|---|---|
| F-01 No authentication on any endpoint | Critical | A01 | CWE-306 | `AppUser` and `AuthAuditLog` tables, `@login_required`, lockout, generic login error, safe `?next=`, `session.clear()` at login, POST-only logout | `F01_AuthenticationTests` |
| F-02 No CSRF protection | High | A01 | CWE-352, CWE-208 | Session-bound token, `hmac.compare_digest`, `@csrf_protect`, hidden input in every POST form | `F02_CSRFTests` |
| F-03 No rate limiting | High | A04 | CWE-307, CWE-770 | Sliding-window limiter: 10 logins and 60 writes per address per minute, `RATE_LIMITED` audited | `F03_RateLimitingTests` |
| F-04 Missing security headers | Medium | A05 | CWE-693 | `apply_security_headers` after every request | `F04_SecurityHeadersTests` |
| F-05 Default secret key non-fatal in production | High | A05 | CWE-798 | `POLARIS_ENV=production` plus a default key exits 2 at startup | `F05_ProductionSecretGuardTests` |
| F-06 Database password fallback default | Medium | A05 | CWE-798 | `docker-init.sh` password gates; no echo of the password into logs | shell-level verification |
| F-07 Cookies without Secure, HttpOnly, SameSite | Medium | A02 | CWE-614, CWE-1004 | `HttpOnly`, `SameSite=Lax`, Secure flag, branded name, 8-hour lifetime | `F06_CookieHardeningTests` |
| F-08 Database errors leak internals | Low | A09 | CWE-209 | `db_error_to_message` maps known failures and answers the rest generically | `F08_ErrorMessageSanitizationTests` |
| F-09 No input length limits | Low | A04 | CWE-20 | Existing layers judged sufficient (column widths, body cap, `maxlength`); documented, no code | none |
| F-10 SQL console did not roll back on failure | Low | A04 | none | `try/finally` rollback and close | implicit in `SQLConsoleTests` |
| F-11 No audit log of authentication | High | A09 | CWE-778 | Append-only `AuthAuditLog` with the event set above | `F11_AuditLoggingTests` |
| F-12 Compose published the Postgres port | Medium | A05 | CWE-668 | `ports:` block removed from the db service | static review |
| F-13 No password complexity in `docker-init.sh` | Low | A05 | CWE-521 | Length floor plus character-class rules, exit 2 on refusal | shell-level verification |
| F-14 No request body size limit | Low | A04 | CWE-770 | `MAX_CONTENT_LENGTH` 1 MiB, custom 413, SQL console cap | implicit |

`RoleBasedAccessControlTests` and `PasswordHashingTests` were added in the same pass for cross-cutting verification.
