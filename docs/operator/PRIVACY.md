# PRIVACY.md

**Reader:** the privacy officer or data-protection reviewer assessing a
Polaris deployment. **Job:** state what personal data Polaris collects, what
it retains, how the architecture enforces minimization, and what holders can
expect. This is distinct from [SECURITY-CONTROLS.md](SECURITY-CONTROLS.md) (which covers
attacks) and [docs/design/threat-model.md](../design/threat-model.md)
(which covers the architectural defenses).

---

## What Polaris collects

### About holders (Individuals)

| Data | Purpose | Retention |
|---|---|---|
| `legal_name` | Identity attestation | Permanent (audit invariant C1) |
| `date_of_birth` | Identity attestation | Permanent |
| `country_code` | Jurisdiction routing | Permanent |
| `external_ref` | Cross-reference to upstream | Permanent (optional column) |

These are the irreducible minimum to issue an identity token. No
biometric data is stored in the schema (only the type of binding,
e.g. "FINGERPRINT"; the template lives on the device, not in
Polaris).

### About operators (AppUsers)

| Data | Purpose | Retention |
|---|---|---|
| `username` | Authentication | Until account removed |
| `password_hash` (scrypt, via Werkzeug) | Authentication | Until rotation |
| `role` | Authorization | Until role change |
| `agency_id` | Scope of access | Until reassignment |
| `failed_login_count`, `locked_until` | Brute-force defense | Cleared on successful login or admin reset |

Operator data is operational and rotatable. A removed operator's
authentication state is removed; their agency-attributed audit
events stay (the action is permanent, even when the actor is gone).

### About events

| Event type | What's recorded | Retention |
|---|---|---|
| `TokenLifecycleEvent` | token_id, agency, type, timestamp, reason, geo (optional) | Append-only in hot storage (C1); archived and purged after the `TOKEN_LIFECYCLE` retention, five years by default |
| `VerificationEvent` (FULL) | token_id, requesting agency, context, timestamp, geo | Append-only (C1); archived and purged after the `VERIFICATION` retention, five years by default |
| `VerificationEvent` (SELECTIVE) | token_id, requesting agency, context, timestamp, geo, attribute set | Append-only (C1); same `VERIFICATION` retention |
| `VerificationEvent` (ZERO_KNOWLEDGE) | requesting agency, context, timestamp, geo | Append-only (C1); same `VERIFICATION` retention; note `token_id IS NULL` (C2) |
| `AuthAuditLog` | username, event_type, ip_address, timestamp | Append-only; archived and purged after the `AUTH_AUDIT` retention, five years by default |

"Archived and purged" means the rows leave the hot table only after a
manifest-hashed archive holds them and a checkpoint records the deletion; the
carve-out below is the whole of that path. The retention itself is a recorded
decision in `RetentionPolicy`, per table class and jurisdiction, behind a
365-day CHECK floor that no configuration reaches
([design/retention.md](../design/retention.md)). Every other audit table is
permanent.

The audit invariant (C1) means events are permanent. This is a
deliberate trade-off: the system's repudiation defense (R-R1, R-R2
in `docs/design/threat-model.md`) requires that events cannot be
deleted, even at the holder's request.

---

## What Polaris does NOT collect

- **Biometric templates.** The biometric is bound at the device
  level; Polaris stores only the binding type (FINGERPRINT, FACE,
  IRIS) and the enrollment date.
- **Holder addresses, phone numbers, email.** Not in the schema.
  If an upstream system needs these, they live there, not here.
- **Verification request payloads.** A verification records THAT
  it happened, not what was inside. The relying party stores its
  own request data.
- **Browser fingerprinting / tracking pixels / cookies beyond the
  Flask session cookie.** No analytics, no third-party scripts (CSP
  enforces this, C5).
- **Real-time geolocation.** Latitude/longitude are recorded for
  events at the time of the event for audit purposes. Holders are
  not tracked between events.

---

## Architectural enforcement of minimization

Polaris's architecture makes some forms of data leakage
structurally impossible:

### ZERO_KNOWLEDGE verifications

Constraint C2 enforces that ZK events have `token_id IS NULL`. The
verification graph for ZK events cannot be reconstructed from the
event log: there is no link back to the holder. This is enforced
at two layers:

1. **CHECK constraint** (`chk_disclosure_token_consistency` on
   `VerificationEvent`) rejects any ZERO_KNOWLEDGE row that carries a
   `token_id`, whoever writes it and through whichever client.
2. **Form coercion** at the application layer, so the web form cannot
   even attempt the write.

An application bug or a raw SQL insert cannot file a ZK event with a
token_id; the constraint rejects the row before commit.

### Append-only audit

Constraint C1 makes lifecycle and verification events immutable.
This is the basis for non-repudiation, but it's also the basis for
a privacy claim: an operator cannot "tidy up" a holder's history
without leaving a permanent record of the attempted tidying.

**Encryption at rest:** the production stack supports encryption
at rest at the storage layer via LUKS on bare metal, storage-layer
encryption on managed Postgres, or filesystem-level encryption
(fscrypt). [ENCRYPTION-AT-REST.md](ENCRYPTION-AT-REST.md) carries
the three concrete recipes and the verification step;
[OPERATIONS.md](OPERATIONS.md#encryption-at-rest) points at them.
The application-layer privacy posture documented in this file
(append-only audit, C2 ZK-NULL coupling, the constitutional
carve-out for archived rows) is independent of and complementary
to disk-level encryption: both layers protect different attack
surfaces (the application against operator-side mistakes; the
filesystem against host-side reads).

**Constitutional carve-out:** for four high-volume audit tables
(`TokenLifecycleEvent`, `VerificationEvent`,
`EnrollmentStatusEvent`, `AuthAuditLog`), rows older than the class's
retention cutoff can be moved from hot storage to a manifest-hashed
archive tarball via `uc_archive_purge()`. The cutoff is not a number the
operator types: it resolves from `RetentionPolicy`, and the procedure
refuses any cutoff inside a class's window (v9.234). The hot row is
deleted; a `LifecycleArchiveCheckpoint` row recording the cutoff that
applied to each class, the archive SHA-256, and the operator user_id is
written in the same transaction, and the purge verifies the archive
against its manifest before deleting anything (v9.235). The checkpoint table is strictly append-only; the
procedure is the only DELETE path. **Non-repudiation is preserved
at the constitutional level**: every event is reconstructible from
the hot table or (older than the cutoff) from the archive tarball
referenced by the checkpoint. The privacy claim, "an operator
cannot disappear a holder's history", is also preserved: any
purge produces an append-only checkpoint row, so attempted
tidying still leaves a permanent record.

This manifest-hashed-archive design was selected over a literal
no-deletions-ever policy (operationally infeasible past ~5 years)
and over PostgreSQL partitioning (non-trivial migration).

### Identity ≠ money (C10)

Polaris's deliberate refusal to carry value (C10) means it's
structurally not a financial-surveillance database. There's no
schema for transactions, balances, spending patterns, or merchant
codes. Adding any of those would require schema changes that the
Vocation (anti-coercion, in `MISSION.md`) refuses on sight.

### CSP `script-src 'self'` (C5)

No third-party scripts run in the operator UI. No CDNs, no
analytics, no tracking beacons. Every network request from the
operator's browser goes to the Polaris instance, with one exception the
operator controls: the Atlas basemap. By default its style and tiles
come from `basemaps.cartocdn.com`, so on that page the tile coordinates
of an investigation and the operator's address reach a third party.
`POLARIS_ATLAS_BASEMAP_STYLE_URL` points the Atlas at a self-hosted
style instead, and the page's CSP follows it (v9.237; the runbook's
"The Atlas basemap" section). Until v9.237 this document said there was
no exception, which was not true of the Atlas.

---

## Holder rights

### Right to access

A holder can request all data Polaris has about them. The query is
straightforward:

```sql
SELECT * FROM Individual WHERE individual_id = $1;
SELECT * FROM IdentityToken WHERE individual_id = $1;
SELECT * FROM TokenLifecycleEvent WHERE token_id IN
    (SELECT token_id FROM IdentityToken WHERE individual_id = $1);
SELECT * FROM VerificationEvent WHERE token_id IN
    (SELECT token_id FROM IdentityToken WHERE individual_id = $1);
```

(This request itself should be authenticated and audited; out-of-
scope for the schema.)

### Right to rectification

Updates to `Individual` are permitted via the operator UI. Updates
write a `TokenLifecycleEvent` if a token state is affected;
updates to non-token fields are not currently audited (BACKLOG:
audit non-token Individual changes).

### Right to erasure (limited)

Polaris does NOT support deleting holder data. The audit invariant
(C1) is non-negotiable. What CAN happen:

- Mark tokens REVOKED or LOST (the tokens stay; status is recorded)
- Anonymize `Individual.legal_name` to a pseudonym (the row stays;
  the name is replaced); this is operationally supported

The pseudonymization is a shipped mechanism: the stored
procedure `uc_pseudonymize_individual(individual_id, actor_user_id, reason)`
replaces `legal_name` with a `PSEUDONYMIZED-<id>` marker and records the act
in the append-only `IndividualErasureEvent` (who, when, why; never the prior
name or a hash of it, which would defeat the erasure). It is admin-gated and
issues no `DELETE`, so it cannot become a path around C1. Operators invoke it
via `scripts/polaris-pseudonymize-individual.sh`. The Individual row and every
audit/token reference to its `individual_id` survive, preserving
non-repudiation; only the plaintext name is gone.

The architectural inability to delete is itself a privacy claim of
a kind: Polaris cannot be coerced into "disappearing" a person's
identity history. This is intentional; without it, the system
cannot make non-repudiation guarantees.

A jurisdiction with a "right to be forgotten" law that requires
hard deletion is structurally incompatible with Polaris's audit
invariant. Such a deployment would need a MISSION amendment
(weakening C1) and the corresponding loss of non-repudiation.

### Right to portability

Holder data can be exported as a JSON document via a (future)
`/api/individuals/<id>/export` endpoint (BACKLOG). The audit log
fragments referencing the holder are included; the holder cannot
take with them an audit trail that references actions by other
agencies.

---

## Data sharing

Polaris does NOT share data with external systems by default.
Possible cross-system flows:

- **Verification events**: when an external relying party calls a
  Polaris verification endpoint, the event is recorded in Polaris.
  The relying party gets back a proof of the result; they do not
  receive holder PII (unless disclosure_level is `FULL`, in which
  case the holder consented to that level for that context).

- **Revocation list**: `RevocationList` rows can be published
  externally (CRL distribution). Published data: token_id (an
  opaque integer), revocation reason, effective date. No holder
  PII.

- **Aggregated atlas data**: `/api/atlas/*` endpoints return counts per
  cell, area, bucket or category. None returns an event or a holder
  identifier (lab/strategy/009); a single event is read on the verification
  log, which records the read.

There is no third-party tracking or telemetry. No data goes to any
vendor by default.

---

## Logs and PII

The application log (`/tmp/polaris_app.log` in development; configurable
in production) records:

- HTTP method + path + status code + timing
- Outcome of authentication attempts (success/failure)
- IP address (for AuthAuditLog only; access log per gunicorn config)

The application log does NOT record:

- Form bodies (so passwords and PII don't end up in logs)
- Cookie values
- Token values

If logging configuration is changed to capture more (e.g. to debug
an issue), revert immediately after, and document the reversion in
`DEVNOTES/known-gotchas.md` so it doesn't regress.

---

## Cookies

Polaris uses one cookie:

- `session`: Flask session cookie. `HttpOnly`, `Secure`,
  `SameSite=Lax`. Contents are a signed (and optionally encrypted)
  payload representing the authenticated operator. No third-party
  cookies.

---

## What changes between development and production

Development uses `polaris_dev_password` for the database, the
default secret key, and HTTP rather than HTTPS. None of these are
acceptable in production:

- Secret key MUST be rotated to a random 32-byte value
- Database password MUST be unique
- HTTPS MUST be enforced (HSTS recommended)
- `Secure` cookie attribute MUST be set (default in Flask when
  HTTPS is detected)

See the [OPERATIONS.md](OPERATIONS.md#pre-deploy-checklist) pre-deploy checklist.

---

## Operational privacy posture in production

The production compose stack
([`docker-compose.prod.yml`](../../polaris_web/docker-compose.prod.yml))
ships with three privacy-relevant architectural choices that go beyond the
schema-level invariants above. They narrow the attack surface through which
holder or operator data could leak.

### File-mounted secrets

Production runs with Docker secrets rather than environment variables for
sensitive credentials. Every credential in the secrets matrix (the Flask
session signing key, the application and superuser database passwords, the
ML-DSA-65 signing key) is mounted at `/run/secrets/<name>` from the host
secrets directory (mode 0700; the per-file modes are in
[SECRETS.md, section 1](SECRETS.md#1-the-secrets-matrix)). The app, pgbouncer,
and postgres read them through the `*_FILE` environment convention
(`POLARIS_SECRET_KEY_FILE`, `POLARIS_DB_PASSWORD_FILE`,
`POSTGRES_PASSWORD_FILE`, `POLARIS_PQC_SIGNING_KEY_FILE`).

Practical implications for privacy:

- **`docker inspect` does not show secret values.** A bystander with
  `docker` group membership but no filesystem read access cannot read the
  secrets through container introspection.
- **Process listings (`ps -ef`) do not show secret values.** Environment
  variables can leak through `/proc/<pid>/environ`; file-mounted secrets do
  not.
- **Container logs cannot accidentally include secrets** because the app
  never accepts a secret through stdin or argv.
- **Backups do not carry the secrets directory.** The `polaris-backup.sh`
  tarball holds the `pg_dump` and a SHA-256 manifest and nothing else; on a
  restore to a new host the secrets are regenerated or restored separately
  ([DR.md](DR.md)).

The invariant layer pins this: `check_secrets_lifecycle_sealed` requires the
compose file to read every secret through `${POLARIS_SECRETS_DIR:-./secrets}`,
and `check_pgbouncer_self_built` requires pgbouncer to read the database
password from `POLARIS_DB_PASSWORD_FILE` rather than the environment
([SECRETS.md, section 7](SECRETS.md#7-structural-guarantees)).

### TLS at the edge

All operator and holder-facing traffic is terminated by Caddy, built from
`caddy:2.11.4-alpine` with the rate-limit plugin compiled in
([`Dockerfile.caddy`](../../polaris_web/Dockerfile.caddy)), using Let's
Encrypt certificates for the configured `POLARIS_DOMAIN`. Caddy renews them
automatically. The [`Caddyfile`](../../polaris_web/Caddyfile) sets the
canonical security-header set:

| Header | Value | Privacy effect |
|---|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Browsers refuse to downgrade to HTTP for 2 years |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Outbound links do not leak the path the operator was on |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=(), payment=(), usb=()` | Polaris does not ask for any sensitive browser API |
| `X-Frame-Options` | `DENY` | Polaris pages cannot be iframed (clickjacking and UI redress) |
| `Cross-Origin-Opener-Policy` | `same-origin` | Window-handle isolation |
| `Cross-Origin-Resource-Policy` | `same-origin` | Resource loading isolated |

Internal hops run on the isolated compose network. The app-to-pgbouncer and
pgbouncer-to-postgres hops use the self-signed pairs from the secrets matrix
with `sslmode=verify-ca`; Redis runs without AUTH on the private network
([SECRETS.md, section 1](SECRETS.md#1-the-secrets-matrix)). The privacy claim
is that nothing leaves the host without TLS termination first.

`check_caddy_self_built` in `polaris_checks` pins the self-built edge, and CI
validates the Caddyfile against the built image.

### What gets logged in production

The production stack writes three log streams:

1. **`polaris_web/logs/access.log`**: Caddy access log (JSON), mounted from
   `/var/log/caddy` in the container. Records timestamp, client IP, host,
   method, path, status code, bytes, request duration, and request headers.
   Caddy omits the values of credential headers (`Cookie`, `Authorization`,
   `Set-Cookie`) from its access log unless `log_credentials` is enabled in
   the Caddyfile's global options, and the shipped Caddyfile does not enable it. **Does not record:** request bodies or response bodies.

2. **`polaris_web/logs/caddy.log`**: Caddy system log (JSON). Records ACME,
   TLS, and config events. **Does not record:** client requests.

3. **App logs**: gunicorn access and error logs on container stdout and
   stderr ([`gunicorn.conf.py`](../../polaris_web/gunicorn.conf.py)). Records
   HTTP method, path, status, timing, referer, and user agent. **Does not
   record:** form bodies, cookie values, or token values (see "Logs and PII"
   above).

Postgres and Redis logs are container stdout by default; the operator routes
them to their log aggregator. The schema's audit tables
(`TokenLifecycleEvent`, `VerificationEvent`, `AuthAuditLog`,
`EnrollmentStatusEvent`, `DuressEvent`, `AnchorBatch`,
`AgencyTrustAttestation`, `TokenStateEpoch`) are the system's *durable*
privacy-relevant record; the log streams above are *operational* and may be
aggressively rotated.

### Rotation cadence (privacy half-life)

The recommended cadence from [SECRETS.md, section 1](SECRETS.md#1-the-secrets-matrix):

| Secret | Rotation cadence | Privacy rationale |
|---|---|---|
| `polaris_secret_key` | 90 days | Bounds the session-cookie-replay window |
| `polaris_db_password` | 90 days | Bounds the database-credential blast radius |
| `polaris_db_root_password` | 180 days | Bounds the superuser blast radius |
| TLS certificate | automatic (Caddy renews from Let's Encrypt) | Standard Web PKI rotation |

Any secret rotates immediately on a suspected compromise or when an operator
with prior access leaves. Rotation is operator-driven through
`./scripts/polaris-rotate-secret.sh <name>`
([SECRETS.md, section 4](SECRETS.md#4-rotation)). The prior value is archived
under `polaris_web/secrets/.archive/<name>.<timestamp>` (mode 0600) so an
operator can investigate if a rotation breaks production.

### What the production stack does not change

- **Schema invariants C1-C10 are untouched.** Append-only audit, ZK-NULL
  coupling, identity ≠ money: all preserved verbatim.
- **No new data is collected.** The production stack is operational, not
  schema. Holder data, operator data, and event data are exactly as before.
- **No new third-party data flows.** Caddy talks to Let's Encrypt for TLS
  issuance only. No analytics, no telemetry, no vendor-bound data egress.

---

## Population coverage

The PDF §9 names a sociotechnical risk: a national identity system
that assumes universal enrollment can become a coercion gradient.
Newborns, undocumented residents, unhoused people, those without
reliable access to reissuance infrastructure, and those whose
biometrics don't register reliably with available hardware would
all be outside the system. The schema must be honest about this.

The schema records a five-status enrollment vocabulary
(`NOT_ENROLLED`, `PENDING_ENROLLMENT`, `ENROLLED`, `EXEMPT`,
`LAPSED`) recorded in the append-only `EnrollmentStatusEvent` table.
Three things matter for privacy:

1. **`NOT_ENROLLED` is the default, not a positive flag.** Every
   new `Individual` row gets a `NOT_ENROLLED` event from the seed
   trigger. The absence of enrollment is materialized only so it
   can be transitioned out of cleanly; it is not a tag the schema
   imposes.

2. **`civic_enrollment_summary` returns counts only.** The
   per-jurisdiction × status rollup is a first-class query.
   Per-individual enumeration of `NOT_ENROLLED` is *not* exposed
   as a function; an admin who needs it writes the join against
   `IndividualCurrentEnrollment` directly, which leaves a trace in
   `AuthAuditLog`.

3. **`EXEMPT` is the positive vocabulary** for "civic participant
   recognized without token." Recording an individual as EXEMPT is
   frictionless: a single INSERT. The PDF §9 second-clause "accepted
   path without tokens" gets first-class affordance.

The asymmetric design (EXEMPT frictionless, mass-NOT_ENROLLED
enumeration deliberate) is the privacy stance. The schema cannot
prevent misuse, but it can make the misuse named. Naming is the
precondition for governance catching it.

See `docs/design/tiered-enrollment.md` for the full adversary walk and
mechanism-design rationale.

---

## What this document does NOT cover

- Compliance frameworks (GDPR, CCPA, etc.): those are deployment-
  specific and depend on your jurisdiction
- Subprocessors / hosting providers: depends on your deployment
- Children's data: Polaris has no special handling for minors;
  the deployment is responsible for any age-related restrictions

This file describes Polaris's architectural posture, not a legal
privacy notice. A real privacy notice would be drafted by counsel
with knowledge of the deployment context.
