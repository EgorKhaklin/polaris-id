# OPERATIONS.md: the Polaris day-2 runbook

**Reader:** the operator who runs a deployed Polaris instance day to day.
**Job:** the routine work (backups, audit review, rotations, migrations, the
certificate watch), the signals to watch, the first steps of an incident, and
the upgrade and retirement paths.

Everything else lives in its own document and is linked from here:
installation in [INSTALL.md](INSTALL.md), [LINUX-SERVER.md](LINUX-SERVER.md),
[DEPLOYMENT.md](DEPLOYMENT.md) and [KUBERNETES.md](KUBERNETES.md); the host in
[HARDENING.md](HARDENING.md); secrets in [SECRETS.md](SECRETS.md); recovery in
[DR.md](DR.md) and the drill ledger [DR-DRILLS.md](DR-DRILLS.md); high
availability in [FAILOVER.md](FAILOVER.md); per-alert runbooks in
[RUNBOOKS.md](RUNBOOKS.md); service objectives in [SLOS.md](SLOS.md); the
threat model in [../design/threat-model.md](../design/threat-model.md)
and [../../SECURITY.md](../../SECURITY.md); the API in
[../reference/API.md](../reference/API.md).

---

## Table of contents

1. [Before day 2](#before-day-2)
2. [The running stack](#the-running-stack)
3. [Day-2 operations](#day-2-operations)
4. [Backup & restore](#backup--restore)
5. [Scaling](#scaling)
6. [Monitoring & alerting](#monitoring--alerting)
7. [Encryption at rest](#encryption-at-rest)
8. [Incident response](#incident-response)
9. [Common errors](#common-errors)
10. [Upgrades](#upgrades)
11. [Decommissioning](#decommissioning)
12. [What this document does NOT cover](#what-this-document-does-not-cover)

---

## Before day 2

Deploying is [DEPLOYMENT.md](DEPLOYMENT.md)'s job: the path, the
procedure, the first operator account and the verification block live there.
This checklist is what to have in hand before the first production start.

### Pre-deploy checklist

- [ ] DNS A record for `${POLARIS_DOMAIN}` resolves to this host
- [ ] TCP/80 + TCP/443 reachable from the public internet
- [ ] All secrets generated via `scripts/polaris-generate-secrets.sh`;
      `ls -la secrets/` shows the directory `0700` and each file with the
      mode the generator set (`0600`, or `0644` for the files a non-root
      container user must read; [SECRETS.md](SECRETS.md#1-the-secrets-matrix))
- [ ] `secrets/` is in `.gitignore` (verify: `git check-ignore -v
      secrets/polaris_secret_key`)
- [ ] Backup destination configured (a local directory for
      `polaris-backup.sh --dest` with an off-host copy, or the pgBackRest S3
      repository), and the backup key file set
      (`POLARIS_BACKUP_KEY_FILE`; see [DR.md](DR.md))
- [ ] Pager wired: the on-call product's webhook URL written to a file
      mounted at `/etc/alertmanager/secrets/pager_webhook_url` (see
      [RUNBOOKS.md, Paging](RUNBOOKS.md#paging-wiring-the-receiver)), and a
      synthetic `PolarisDuressEvent` sent through it with `amtool alert add`
- [ ] Admin operator username and password file ready for the first
      `polaris-create-operator.sh` run (see [the first operator account](DEPLOYMENT.md#the-first-operator-account))
- [ ] Production invariants verified by `python3 -m polaris_checks.run`:
      app-to-DB TLS (`check_app_db_tls`), fail-closed `sslmode`
      (`check_prod_fail_closed`), self-built Caddy (`check_caddy_self_built`),
      the liveness/readiness split of `/api/health`
      (`check_health_liveness_readiness_split`), the prod compose hardening
      set (`check_prod_hardening`), and the edge trust boundary
      (`check_prod_compose_trusts_edge`)
- [ ] Read [SECURITY.md](../../SECURITY.md) once

---

## The running stack

What is up once a deploy succeeds; the reference for every day-2 command
below.

### Services

| Service | Image | Role | Port (internal) |
|---|---|---|---|
| `caddy` | `polaris-caddy:prod` (built from `Dockerfile.caddy`, Caddy 2.11.4 with the rate-limit module) | TLS termination, security headers, rate limit | 80 + 443 (host) |
| `app` | `polaris-app:prod` (built from `Dockerfile.prod`) | Flask + gunicorn (`WEB_CONCURRENCY`, default 4) | 8000 |
| `pgbouncer` | `polaris-pgbouncer:prod` (built from `Dockerfile.pgbouncer`) | Transaction-mode connection pool in front of Postgres | 6432 |
| `postgres` | `polaris-postgres:prod` (built from `Dockerfile.postgres`: `postgres:16-alpine` plus pgBackRest) | Database | 5432 |
| `redis` | `redis:7-alpine` (digest-pinned) | Rate-limiter backend | 6379 |

Volumes:
- `pg_data` (named): Postgres data
- `pgbackrest_repo` (named): the local pgBackRest repository when WAL archiving is enabled
- `redis_data` (named): Redis AOF/RDB
- `caddy_data` (named): Caddy's Let's Encrypt certs + state
- `caddy_config` (named): Caddy's config-time state
- `polaris_state` (named): script state
- `./secrets/`: file-mounted secrets, read-only at `/run/secrets/*`
- `./logs/` (bind mount): gunicorn's `/var/log/polaris`. Caddy logs to stdout (v9.239), where the json-file driver caps and rotates it: `docker compose logs caddy`

---

## Day-2 operations

### Routine maintenance

| Task | Frequency | Command |
|---|---|---|
| Backup | Daily (automated) | `./scripts/polaris-backup.sh` (cron or the `polaris-backup.timer` unit) |
| Verify backup integrity | Weekly | `./scripts/polaris-backup.sh --verify-latest` |
| Restore drill | Quarterly | `./scripts/polaris-restore.sh <latest> --target=polaris_drill` |
| Restore dry-run | Monthly | `./scripts/polaris-restore.sh <latest> --dry-run` (manifest-verify only) |
| RPO/RTO drill | Monthly (automated) | `./scripts/polaris-dr-drill.sh --record`; ledger in [DR-DRILLS.md](DR-DRILLS.md) |
| Audit-log archive | Yearly | `./scripts/polaris-archive.sh --from-policy` (C1-preserving export, one cutoff per retention class) |
| Retention review | Yearly, or when a jurisdiction's schedule changes | `SELECT * FROM RetentionPolicy WHERE superseded_at IS NULL` (the purge refuses any cutoff inside these windows) |
| Verify archive integrity | Quarterly | `./scripts/polaris-archive.sh --verify-latest --dest=DIR` |
| Audit-log purge | Operator-driven, after archive verify | `./scripts/polaris-purge.sh --archive=TARBALL --actor-user-id=N` |
| Audit-log archive, per class | Yearly, when retention differs by class | `./scripts/polaris-archive.sh --from-policy` then the purge above |
| Certificate transparency check | Daily (cron) | `./scripts/polaris-ct-monitor.sh`: alerts on unexpected cert issuance for `${POLARIS_DOMAIN}`; see [Certificate transparency monitoring](#certificate-transparency-monitoring) |
| Audit-log rotation | Yearly (cron) | `./scripts/polaris-rotate-logs.sh --actor-user-id=N`: archive from the retention policy, verify, purge, in one cron-ready pipeline (`--cutoff-days` overrides the policy with one fixed cutoff) |
| Operator onboarding | As needed | `./scripts/polaris-create-operator.sh --username NAME --role admin\|operator\|auditor --password-file PATH`: scrypt-hashed AppUser + AuthAuditLog entry |
| Scrape `/metrics` | Continuous (Prometheus) | `curl http://app:8000/metrics` from the stack network: Prometheus text-format exposition; see [Prometheus metrics](#prometheus-metrics-metrics) for the required edge ACL |
| Rotate `POLARIS_SECRET_KEY` | 180 days | `./scripts/polaris-rotate-secret.sh polaris_secret_key` |
| Rotate DB password | 180 days | `./scripts/polaris-rotate-secret.sh polaris_db_password` |
| OS security updates | Monthly | distro-specific (`apt upgrade` / `dnf update`); see [HARDENING.md](HARDENING.md) |
| Docker image refresh | Monthly | `./scripts/polaris-deploy.sh prod` |
| Review AuthAuditLog for anomalies | Weekly | see [Audit review](#audit-review) |

### Audit review

Every state-changing event lands in an append-only audit table. Weekly
review queries (run through `psql` inside the stack, as below, or tail the
auth events with `polaris-id audit-log`):

```bash
# Weekly: failed-login surface
docker compose -f polaris_web/docker-compose.prod.yml exec postgres \
  psql -U polaris_app -d polaris -c "
    SELECT username, count(*) AS attempts,
           min(event_timestamp) AS first, max(event_timestamp) AS last
    FROM AuthAuditLog
    WHERE event_type IN ('LOGIN_FAILED', 'LOGIN_LOCKED')
      AND event_timestamp > now() - interval '7 days'
    GROUP BY username
    ORDER BY attempts DESC LIMIT 20;"

# Weekly: token lifecycle mix
docker compose -f polaris_web/docker-compose.prod.yml exec postgres \
  psql -U polaris_app -d polaris -c "
    SELECT event_type, count(*) FROM TokenLifecycleEvent
    WHERE event_timestamp > now() - interval '7 days'
    GROUP BY event_type ORDER BY count(*) DESC;"

# Weekly: revocations per issuing agency
docker compose -f polaris_web/docker-compose.prod.yml exec postgres \
  psql -U polaris_app -d polaris -c "
    SELECT t.issuing_agency_id, count(*) AS revocations_7d
    FROM TokenLifecycleEvent e
    JOIN IdentityToken t USING (token_id)
    WHERE e.event_type = 'REVOKED'
      AND e.event_timestamp > now() - interval '7 days'
    GROUP BY t.issuing_agency_id ORDER BY revocations_7d DESC LIMIT 5;"
```

The per-agency velocity alerts in
[polaris-alerts.yml](../../deploy/observability/polaris-alerts.yml) watch the
same signal continuously; see
[Per-agency quotas and velocity alerts](#per-agency-quotas-and-velocity-alerts).

### Reading container logs

```bash
# Live tail of the app
docker compose -f polaris_web/docker-compose.prod.yml logs -f --tail=100 app

# Last 24h of access log
docker compose -f polaris_web/docker-compose.prod.yml logs --since=24h app | grep -E "GET|POST"

# Caddy (TLS + reverse proxy)
docker compose -f polaris_web/docker-compose.prod.yml logs --tail=100 caddy

# Postgres
docker compose -f polaris_web/docker-compose.prod.yml logs --tail=100 postgres
```

The app's persistent log files are written to `./logs/` (mounted into the app
container as `/var/log/polaris/`). Caddy's access and error logs go to its
stdout: the edge runs as an unprivileged user with no writable host directory
(v9.239), and `docker compose logs caddy` is where its log is read. Container
stdout is capped by the json-file driver (`max-size` x `max-file`), so logs
cannot fill the disk.

### Operator authentication (WebAuthn-MFA)

Operator login for admin accounts is two-factor: password + WebAuthn
assertion. The rollout, phase by phase, is
[WEBAUTHN-ROLLOUT.md](WEBAUTHN-ROLLOUT.md); the enrollment and recovery
procedures are [SECRETS.md, WebAuthn operator MFA](SECRETS.md#9-webauthn-operator-mfa).

**Enrollment cadence:**
- New admin accounts via `polaris-create-operator.sh --role admin` get
  `webauthn_required_after = now() + 30 days`
- During the grace period: password-only login completes; the user sees a
  warning banner with the day count
- After the deadline with no credential: login refused with operator guidance
- After the deadline with a credential enrolled: password + WebAuthn assertion
  required

**Enroll a credential:**
1. Log in via `/login`
2. Navigate to `/settings/webauthn`
3. Press *Enroll WebAuthn credential* and follow the browser prompt
4. Optionally enroll a second credential as backup

**Operator emergency recovery (locked-out admin):**

If an admin loses their authenticator AND the deadline has passed, a second
admin runs:

```bash
./scripts/polaris-recover-admin.sh \
    --target <username-of-locked-out-admin> \
    --authorizing-user-id <your-admin-user-id> \
    --window-minutes 15
```

The grant is audited as `EMERGENCY_PASSWORD_LOGIN_AUTHORIZED`. The target
must enroll a new credential at `/settings/webauthn` before the window closes,
otherwise the refusal returns.

For solo-admin deployments (no second admin available), generate a printed
mnemonic at enrollment time via `./scripts/polaris-generate-recovery-code.sh`
and store it offline; `polaris-recover-admin.sh --recovery-code` then stands in
for the second admin. The incident-time procedure is
[DR.md, section 4.6](DR.md).

**Audit the WebAuthn surface:**

```sql
-- Last 20 WebAuthn-class events
SELECT event_timestamp, event_type, username, detail
  FROM AuthAuditLog
 WHERE event_type LIKE 'WEBAUTHN_%'
    OR event_type = 'EMERGENCY_PASSWORD_LOGIN_AUTHORIZED'
 ORDER BY event_timestamp DESC LIMIT 20;

-- Enrolled credentials per admin
SELECT u.username, count(c.credential_id) AS credentials
  FROM AppUser u
  LEFT JOIN OperatorWebauthnCredential c ON c.user_id = u.user_id
 WHERE u.role = 'admin' AND u.is_active = TRUE
 GROUP BY u.username
 ORDER BY u.username;

-- Admins approaching their enrollment deadline (next 7 days)
SELECT username, webauthn_required_after
  FROM AppUser
 WHERE role = 'admin'
   AND webauthn_required_after IS NOT NULL
   AND webauthn_required_after > now()
   AND webauthn_required_after < now() + interval '7 days'
 ORDER BY webauthn_required_after;
```

### Bulk enrollment (population onboarding)

Onboarding an authority's existing population is a set-based operation, not a
loop over the single-issue path. Records are staged with `COPY` and the whole
batch is issued in one transaction: every row passes the same constraint set a
single issuance passes, and a single violation rolls the entire batch back (all
issued, or none). One batch is one issuing agency under one algorithm. The
mechanism is [bulk-enrollment.md](../design/bulk-enrollment.md).

**The extract.** A pipe-delimited file, one line per person, columns in order:

```
legal_name|date_of_birth|jurisdiction|biometric_binding_type|token_value|physical_serial|permitted_contexts
```

`biometric_binding_type` is one of `NONE`/`FINGERPRINT`/`FACE`/`IRIS`;
`permitted_contexts` is a Postgres array literal (`{}` or `{1,4}`). Each row's
`token_value` and `physical_serial` are the credential's own identifiers and
must be unique across the registry.

**Dry run first.** Stage and validate the extract without issuing; it rolls
back and reports the row count:

```bash
polaris-id bulk-enroll ./population.csv --agency 1 --algorithm 1 --dry-run
```

**Issue the batch.** The issuing agency must hold `ISSUE` or `BOTH` on the
algorithm (`AgencyAlgorithmAuth`); an unauthorized agency is refused with exit
3 and nothing is issued:

```bash
polaris-id bulk-enroll ./population.csv --agency 1 --algorithm 1 --note '2026 Q3 migration'
# -> ✓ Batch #7: issued and activated 240418 tokens set-based (agency 1, algorithm 1).
```

A duplicate serial anywhere in the file, or two rows for one person, takes the
**whole** batch down (exit 3, nothing issued): fix the extract and re-run. The
batch row itself is rolled back on failure, so a failed run leaves no trace.

**After a run.** Issued tokens are ordinary `IdentityToken` rows and are
`ACTIVE` immediately. The staging rows are scratch and can be removed once you
have confirmed the import; they do not cascade from the batch, so clear them
explicitly:

```sql
DELETE FROM BulkEnrollmentStaging WHERE batch_id = 7;
```

To onboard people who are already in the registry (a re-card), set the staged
`individual_id` to the existing person; C3 still holds, so their prior token
must already be inactive (lost, revoked, or expired) or the batch rolls back.
Retiring the old credential is a separate, audited step.

### Retire a cryptographic algorithm

An algorithm is retired by its `deprecation_date`. Once the date has passed,
`uc1_issue_token` refuses to mint a new token under it and
`uc6_migrate_algorithm` refuses to migrate a token onto it; existing tokens
keep verifying until they are migrated:

```sql
UPDATE CryptographicAlgorithm
SET deprecation_date = CURRENT_DATE
WHERE name = 'ECDSA-P256';
```

To move a holder onto a new algorithm, run UC-6 (`polaris-id migrate-algorithm`
on the CLI, or `POST /uc6/migrate`; see [API.md](../reference/API.md)). The
algorithm inventory and the post-quantum posture are in
[PQC-POSTURE.md](../reference/PQC-POSTURE.md).

### Schema migrations

Polaris ships its own migration runner. State lives in the `schema_version`
table (an append-only audit-of-record table) and migration files are
hand-written SQL pairs under `polaris_sql/migrations/`.

**What it is:**

- Each schema change is two files:
  `<YYYY-MM-DD>-<NNN>-<slug>.up.sql` and `.down.sql`
- Files apply in lexicographic order via `scripts/polaris-migrate.sh`
- SHA-256 of every applied file is recorded for tamper detection
- The `schema_version` registry is append-only (UPDATE/DELETE forbidden);
  reverts append a new `event_type='reverted'` row rather than mutating

Authoring a new migration is a development task; the workflow and the
expand-contract policy are in the
[migrations README](../../polaris_sql/migrations/README.md). The file pair
is committed together.

**Inspect state on the production stack:**

```bash
# What's on disk and what's currently applied
./scripts/polaris-migrate.sh --target=docker-stack --status
```

**Apply pending migrations:**

```bash
# Apply ALL pending, recording your operator user_id in the registry
./scripts/polaris-migrate.sh --target=docker-stack \
    --actor-user-id <your-user-id> --up

# Apply only the next N pending
./scripts/polaris-migrate.sh --target=docker-stack \
    --actor-user-id <your-user-id> --up 1

# Preview what would be applied without writing
./scripts/polaris-migrate.sh --target=docker-stack --dry-run --up
```

The `--actor-user-id` flag records WHO authorized the change. Use your own
`AppUser.user_id`; do not share accounts. Find your id with:

```bash
docker compose -f polaris_web/docker-compose.prod.yml exec postgres \
    psql -U postgres -d polaris -c \
    "SELECT user_id, username FROM AppUser WHERE role='admin'"
```

**Revert the most recent applied migration:**

```bash
./scripts/polaris-migrate.sh --target=docker-stack \
    --actor-user-id <your-user-id> --down 1
```

The runner refuses to revert if the `.up.sql` file has been edited since the
recorded SHA-256 was taken (exit code 6, tamper detection). If you legitimately
need to change an already-applied migration, write a new one that fixes the
problem; do not edit history.

**Exit codes** (greppable for incident response and CI):

| Code | Meaning |
|------|---------|
| 0    | success (or `--status` / `--dry-run` finished) |
| 2    | usage error |
| 3    | migrations directory missing/empty (only an issue for `--up`/`--down`) |
| 4    | filename validation error (must match `YYYY-MM-DD-NNN-slug`) |
| 5    | database call failed (migration content or psql error) |
| 6    | SHA-256 mismatch on revert: file edited post-apply, refusing |
| 7    | invalid argument (e.g., `--down 0`) |

**Backups + migrations.** Take a backup BEFORE applying a migration on
production. Polaris does not pause writes during the migration's transaction;
PostgreSQL transactional DDL handles isolation correctly, but if anything goes
wrong at the application-state level (a constraint that fails halfway through
a batched UPDATE, for example), restoring from the most recent pre-migration
backup is the recovery path. See [Backup & restore](#backup--restore).

**The registry itself is the audit-of-record.** Querying it shows exactly
which migrations have run, when, by whom, and against which file content (the
recorded SHA-256). It is append-only at the database level, so even a
compromised admin role cannot silently rewrite migration history.

### Certificate transparency monitoring

Polaris's TLS certs are issued by Let's Encrypt via Caddy's ACME client. Any
cert for `${POLARIS_DOMAIN}` issued by a DIFFERENT issuer is a sign of:

- A misconfigured Caddy that re-issued instead of renewed
- Compromised DNS allowing rogue ACME validation by a third party
- A CA mis-issuance attack (rare but real)

The CT monitor polls the public crt.sh log, compares against an
operator-maintained allowlist (`$STATE_DIR/ct-monitor/known.txt`, where
`STATE_DIR` is `POLARIS_STATE_DIR`, default `/tmp/polaris-state`), and alerts
on anything unexpected.

**Initial setup:**

```bash
# 1. Capture the current legitimate cert's SHA-256 fingerprint
echo | openssl s_client -connect ${POLARIS_DOMAIN}:443 \
                        -servername ${POLARIS_DOMAIN} 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 \
    | awk -F= '{print $2}' | tr -d ': ' | tr '[:upper:]' '[:lower:]'

# 2. Add to allowlist
./scripts/polaris-ct-monitor.sh --add-known <fingerprint>

# 3. Verify
./scripts/polaris-ct-monitor.sh --list-known
```

**Daily cron** (recommended):

```cron
# /etc/cron.d/polaris-ct-monitor
# Run at 06:00 UTC daily; CT logs have ~2h propagation latency,
# so once a day catches every unexpected issuance within 24h.
0 6 * * * polaris cd /opt/polaris && ./scripts/polaris-ct-monitor.sh \
              --window-days 1 \
              --check ${POLARIS_DOMAIN} \
              >> /var/log/polaris/ct-monitor.log 2>&1
```

**On alert** (exit code 5):

The script logs anomalies to `$STATE_DIR/ct-monitor/anomalies.log`.
Investigate via the TLS procedure in [DR.md, section 4.5](DR.md). If the new
cert is a legitimate renewal (Caddy auto-renews about 30 days before expiry,
which produces a fresh fingerprint), add it to the allowlist:

```bash
./scripts/polaris-ct-monitor.sh --add-known <new-fingerprint>
```

If unfamiliar, treat as a SEV-2 incident; the cert may have been issued to an
attacker who controls a different CA path or the operator's DNS.

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0    | No anomalies (all certs in window are in the allowlist OR no certs in window) |
| 2    | Usage error |
| 3    | `POLARIS_DOMAIN` not set + no `--check` argument |
| 4    | Network error (crt.sh unreachable; treat as inconclusive and retry next cycle) |
| 5    | Anomaly: UNKNOWN cert detected; investigate immediately |
| 6    | Malformed allowlist file |

---

## Backup & restore

This section is the routine: take, verify, and restore a backup. Recovery
targets, the WAL-archiving path, and the incident procedures are
[DR.md](DR.md); the measured numbers are [DR-DRILLS.md](DR-DRILLS.md).

### Backup

`scripts/polaris-backup.sh` produces a single timestamped tarball containing
every durable component:

- `pg_dump` of the Polaris database (custom format), encrypted with the key
  in `POLARIS_BACKUP_KEY_FILE` (the script warns loudly when the key is unset
  and the dump goes out in plaintext)
- `MANIFEST.json` with timestamps + SHA-256 hashes of each component

```bash
./scripts/polaris-backup.sh                    # writes /var/backups/polaris-<timestamp>.tar.gz
./scripts/polaris-backup.sh --dest /path/to/dir   # a different local directory
./scripts/polaris-backup.sh --verify-latest    # extracts + verifies most recent backup
```

### Backup schedule

The Linux installer wires `polaris-backup.timer` (daily 03:00 UTC) and
`polaris-backup-verify.timer` (Sunday 04:00 UTC). The cron equivalent:

```bash
# /etc/cron.d/polaris-backup
0 3 * * * polaris /opt/polaris/scripts/polaris-backup.sh --dest /var/backups/polaris
0 4 * * 0 polaris /opt/polaris/scripts/polaris-backup.sh --dest /var/backups/polaris --verify-latest
```

`/var/backups/polaris` is on the same disk as the database; copy the tarballs
off-host or enable the pgBackRest S3 repository
([HARDENING.md, section 11](HARDENING.md)).

Retention policy:

| Layer | Window | Where |
|---|---|---|
| Daily | 30 days | Local + offsite |
| Weekly | 12 weeks | Offsite (S3 / Glacier) |
| Monthly | 12 months | Cold storage |
| Yearly | Indefinite | Cold storage |

### Restore

`scripts/polaris-restore.sh` is the scripted counterpart to
`polaris-backup.sh`. It verifies every component's SHA-256 hash against the
in-band `MANIFEST.json`, then restores PostgreSQL. It fails closed without the
backup key and refuses to clobber a non-empty target database without
`--force`.

```bash
# Standard path: restore into a fresh database
createdb polaris_restored
./scripts/polaris-restore.sh \
    /var/backups/polaris-20260514T030000Z.tar.gz \
    --target=polaris_restored

# Verify-only mode (manifest check, then list what would be restored)
./scripts/polaris-restore.sh \
    /var/backups/polaris-20260514T030000Z.tar.gz \
    --dry-run

# Restore into the running production stack. --force is required: the
# pre-flight refuses a non-empty target (exit 6) and the live DB always
# has tables.
./scripts/polaris-restore.sh \
    /var/backups/polaris-20260514T030000Z.tar.gz \
    --target=docker-stack --force

# Also cross-check the restored schema_version table against migrations/
./scripts/polaris-restore.sh <backup> --target=docker-stack --verify-schema-version
```

Exit codes (greppable for incident response):

| Code | Meaning |
|---|---|
| 0 | Restore succeeded |
| 2 | Usage error |
| 3 | Backup file not found |
| 4 | MANIFEST.json missing inside archive |
| 5 | Manifest hash verification failed |
| 6 | Target DB not empty; `--force` required |
| 7 | `pg_restore` failed (state may be partial) |
| 8 | Filesystem audit-of-record restore failed |
| 9 | `docker` not available (when `--target=docker-stack`) |
| 10 | `schema_version` diverges from `migrations/` (`--verify-schema-version`) |

After restore:

```bash
# Run integrity checks
psql -d polaris_restored -c "SELECT count(*) FROM IdentityToken;"
psql -d polaris_restored -f polaris_sql/08_tests.sql
# The summary line "Total: N tests, N passed, 0 failed" must report 0 failed
```

If this was a real recovery (not a drill), **rotate every secret next**;
assume the prior secrets are also compromised:

```bash
./scripts/polaris-rotate-secret.sh polaris_secret_key
./scripts/polaris-rotate-secret.sh polaris_db_password
./scripts/polaris-rotate-secret.sh polaris_db_root_password
```

Recovery objectives (RPO, RTO), the continuous WAL-archiving path that
tightens them (pgBackRest, offsite by env alone), point-in-time restore, and
the drill that measures them are owned by [DR.md, section 1](DR.md); do not
quote a number that is not in [DR-DRILLS.md](DR-DRILLS.md).

### What NOT to back up

- The codebase itself: that is in git
- `./logs/`: captured by your log aggregator
- Docker images: rebuilt from the Dockerfiles
- `secrets/`: sealed outside the backup tarball; generate fresh via
  `scripts/polaris-generate-secrets.sh` and use the same DB password as the
  restore source, OR rotate everything after restore (preferred)

### Retention policy

How long each class of audit row is kept is a decision recorded in the
database, not a number typed at the purge. `RetentionPolicy` holds one
effective row per (table class, jurisdiction) with the retention in days, a
justification, and the operator who set it. A fresh deployment ships with five
years for every class.

The CLI is the shortest path; the SQL below it is the same thing by hand.

```bash
# What is in force, and the cutoff each class resolves to.
polaris-id retention-show
polaris-id retention-show --jurisdiction=US-CA --history   # + superseded decisions

# Adopt a profile, or record a decision of your own. Both append: the previous
# decision is superseded, never edited. Admin only.
polaris-id retention-set --actor-user-id=7 --jurisdiction=US-CA --template=MINIMIZED
polaris-id retention-set --actor-user-id=7 --jurisdiction=US-CA \
    --table-class=AUTH_AUDIT --days=1095 \
    --justification="State retention schedule 4.2 for operator access records."
```

```bash
# What is in force right now.
psql -d polaris -c "
    SELECT table_class, COALESCE(jurisdiction, '(default)') AS jurisdiction,
           retention_days, set_by_user_id, effective_from
    FROM RetentionPolicy
    WHERE superseded_at IS NULL
    ORDER BY table_class, jurisdiction NULLS FIRST"

# What the purge will use for one class.
psql -d polaris -c "SELECT retention_days_for('VERIFICATION'), retention_cutoff('VERIFICATION')"

# Adopt a named profile for a jurisdiction. STANDARD-5Y is 1825 days for every
# class; MINIMIZED keeps the civic record at 1825 and holds operational
# history for 730. Admin only; both are engineering defaults, not legal
# determinations.
psql -d polaris -c "CALL uc_apply_retention_template('MINIMIZED', 'US-CA', <admin user_id>)"

# Or record a decision of your own. The justification is required and must be
# at least twenty characters: it is what an assessor reads.
psql -d polaris -c "
    INSERT INTO RetentionPolicy (table_class, jurisdiction, retention_days,
                                 justification, set_by_user_id)
    VALUES ('AUTH_AUDIT', 'US-CA', 1095,
            'State retention schedule 4.2 for operator access records.', 7)"
```

**Three things the database will refuse.**

- A retention shorter than 365 days. The floor is a CHECK constraint, so no
  configuration reaches below it. Lowering it is a schema change.
- Editing or deleting a policy row. Only `superseded_at` may change, and only
  forward. Replacing a decision appends a row; the previous decision and its
  justification stay readable.
- A purge inside the window. `uc_archive_purge` resolves the retention for
  every class it would delete from and raises if the cutoff is younger,
  naming the class and the earliest cutoff it would accept. It refuses rather
  than quietly purging less than asked.

If a purge fails with "cutoff is inside the retention window", the cutoff is
wrong or the policy is: either purge at an older cutoff, or record a shorter
retention first and say why. The design record is
[docs/design/retention.md](../design/retention.md).

### Audit-log archive + purge

The audit-log retention decision selected archive-then-delete via a dedicated
procedure. C1's append-only invariant is preserved at the constitutional level
by the archive + checkpoint chain; the table-level invariant is loosened for
DELETE on every table whose trigger runs `reject_audit_modification()` when
and only when `uc_archive_purge()` is running, and the procedure itself
deletes from four high-volume audit tables (`TokenLifecycleEvent`,
`VerificationEvent`, `EnrollmentStatusEvent`, `AuthAuditLog`).

**Purging per class (v9.235).** If the retention schedule differs by class,
a single cutoff cannot express it: a five-year purge leaves behind operational
history the schedule says can go, and a two-year purge is refused because it
falls inside the civic record's window. Archive from the policy instead, and
the purge follows it.

```bash
# Resolves a cutoff per class from RetentionPolicy and exports each table at
# its own boundary. --jurisdiction selects a jurisdiction's policy set.
./scripts/polaris-archive.sh --from-policy --dest=/var/backups
./scripts/polaris-archive.sh --from-policy --jurisdiction=US-CA --dest=/var/backups

# The purge reads the per-class cutoffs back out of the manifest. Nothing else
# changes: same verification, same coverage pre-check, same checkpoint.
./scripts/polaris-purge.sh \
    --archive=/var/backups/polaris-archive-<TIMESTAMP>.tar.gz \
    --actor-user-id=<admin user_id>

# What was actually deleted, and under which decision.
psql -d polaris -c "
    SELECT checkpoint_id, cutoff_source, COALESCE(jurisdiction, '(default)') AS jurisdiction,
           cutoff_lifecycle, cutoff_verification, cutoff_enrollment, cutoff_authaudit,
           rows_purged_total
    FROM LifecycleArchiveCheckpoint ORDER BY purged_at DESC LIMIT 5"
```

The purge refuses an archive whose per-class cutoffs fall inside the retention
now in force, so an archive taken under a longer-lived policy cannot be used to
purge under a shorter one. It also verifies every file in the archive against
the manifest before deleting anything: the carve-out's justification is that
the archive reconstitutes every purged row, and an archive edited after it was
written does not.

To rehearse the whole chain on a database you can afford to change:
`bash scripts/polaris-retention-drill.sh`. It runs on every CI push.

**Two-step retention workflow (one cutoff for every class):**

```bash
# Step 1: produce a manifest-hashed archive of rows older than the
#         retention floor (5y = 1825 days; polaris-archive.sh's own default
#         is 365, polaris-rotate-logs.sh's is 1825).
./scripts/polaris-archive.sh --cutoff-days=1825 --dest=/var/backups

# Step 2: verify the archive (re-hashes every component against MANIFEST.json).
./scripts/polaris-archive.sh --verify-latest --dest=/var/backups

# Step 3: actually purge the matching rows from hot tables. This is
#         the deletion step; it requires --actor-user-id (must be admin).
./scripts/polaris-purge.sh \
    --archive=/var/backups/polaris-archive-<TIMESTAMP>.tar.gz \
    --actor-user-id=<admin user_id>

# Step 4: smoke. The hot tables now exclude the purged rows; the
#         LifecycleArchiveCheckpoint table has one new row recording
#         the SHA-256 + cutoff + per-table row counts.
psql -d polaris -c "
    SELECT checkpoint_id, purged_at, cutoff_timestamp,
           rows_purged_total, archive_uri
    FROM LifecycleArchiveCheckpoint
    ORDER BY purged_at DESC LIMIT 5"
```

**Non-repudiation chain.** Operators who need to answer "did event X
happen?":

1. Query the hot tables. If found, done.
2. If not, query `LifecycleArchiveCheckpoint` for cutoffs that would have
   covered when X was expected.
3. Retrieve the archive tarball at `archive_uri`; verify its SHA-256 matches
   `archive_sha256` in the checkpoint.
4. Extract; read the matching CSV file in the tarball; locate X.

**Archive custody is operator-discretion.** The procedure stores the URI
verbatim in `archive_uri`; the operator is responsible for keeping the archive
accessible at that URI for the chain to remain whole. If the archive moves,
append a new checkpoint row recording the move (the table is append-only; the
move itself is audit-of-record).

**What the GUC carve-out does and does not allow:**

| Action | Outside `uc_archive_purge` | Inside `uc_archive_purge` |
|---|---|---|
| DELETE on protected audit tables | rejected (insufficient_privilege) | permitted |
| UPDATE on protected audit tables | rejected | rejected |
| DELETE on LifecycleArchiveCheckpoint | rejected | rejected (no carve-out at this layer) |
| UPDATE on LifecycleArchiveCheckpoint | rejected | rejected |

`SET LOCAL polaris.purge_in_progress` is transaction-scoped; if the procedure
rolls back, the deletes and the checkpoint roll back together, atomically.

**Coverage.** `uc_archive_purge()` deletes from four tables:
`TokenLifecycleEvent`, `VerificationEvent`, `EnrollmentStatusEvent`,
`AuthAuditLog`. The GUC carve-out lives in `reject_audit_modification()`
itself and keys only on `polaris.purge_in_progress`, so while the transaction
is inside the procedure DELETE is open on all nine tables that share the
function: those four plus `IndividualErasureEvent`, `AnchorBatch`,
`TokenStateEpochLeaf`, `DuressEvent`, and `AuditAccessLog`. The procedure
simply does not delete from the other five. Only `AgencyTrustAttestation`
(`trg_attestation_immutable`, `enforce_attestation_immutability()`) and
`LifecycleArchiveCheckpoint` (`reject_checkpoint_modification()`) have
separate, carve-out-free triggers.

---

## Scaling

### When to scale

The measured single-host numbers are in
[PERFORMANCE-BASELINE.md](../reference/PERFORMANCE-BASELINE.md) (the
end-to-end baseline CI re-runs) and [SCALING.md](../reference/SCALING.md)
(the atlas at 10 million events). Past those, the architecture supports the
moves below. Each subsection names the inflection point at which it pays off
and the concrete recipe to apply.

### Connection pooling (pgbouncer): the default

**Inflection:** roughly 30-50 concurrent operators, 100 concurrent sessions,
or sustained 100+ verifications/sec. Without pgbouncer, Polaris's per-request
connection pattern saturates Postgres's `max_connections` ceiling (default
100). With pgbouncer in transaction-pooling mode, thousands of short-lived app
connections multiplex onto a small handful of long-lived backend connections.

**Already shipped:** the production stack (`docker-compose.prod.yml`) places
pgbouncer between the app and Postgres by default. The app reads
`POLARIS_DB_HOST=pgbouncer` and `POLARIS_DB_PORT=6432`; pgbouncer forwards to
`postgres:5432` over TLS (`verify-ca`). No operator action needed for standard
deployments.

**Tuning knobs** (defaults in `docker-compose.prod.yml`):

| Setting | Default | Raise when |
|---|---|---|
| `PGBOUNCER_DEFAULT_POOL_SIZE` | 20 | App workers x 1.5 above this (so 30+ for 20 gunicorn workers) |
| `PGBOUNCER_MIN_POOL_SIZE`     | 5  | Cold-start latency matters; a pre-warmed pool reduces first-request P99 |
| `PGBOUNCER_RESERVE_POOL_SIZE` | 5  | Bursty traffic; the reserve absorbs spikes |
| `PGBOUNCER_MAX_CLIENT_CONN`   | 500 | Clients see "no more connections allowed" |
| `PGBOUNCER_MAX_DB_CONNECTIONS` | 50 | Must stay below Postgres `max_connections` minus admin headroom (~10) |
| `PGBOUNCER_SERVER_LOGIN_RETRY` | 1 | Never above a few seconds. PgBouncer's own default is 15 s, and on it the chaos drill measured a half-second Postgres crash as a 16.2 s outage for the application (v9.242); at 1 s it measures 1.9 s |
| `PGBOUNCER_DNS_NXDOMAIN_TTL` | 1 | Docker unregisters a container's name while it restarts; PgBouncer's 15 s default caches that failure for 15 s (v9.242) |
| `PGBOUNCER_SERVER_CONNECT_TIMEOUT` | 3 | Never above a few seconds: a connect that has not completed in 3 s is a dead or demoted peer. On the 15 s default the failover drill measured a connect started just before HAProxy marked the old leader down stalling every client for 15 s (v9.243) |
| `PGBOUNCER_TCP_USER_TIMEOUT` | 5000 ms | Never above a few seconds: a backend that stops answering mid-query (a frozen node) is retired in 5 s instead of TCP's minutes. On Kubernetes nothing else cuts the pool's connections to a frozen leader; the kind drill found the writes hanging until it was set (v9.244) |
| `PGBOUNCER_QUERY_TIMEOUT` | 15 s | A query with no answer for this long is cancelled and its server connection recycled: the backstop for a backend that vanishes mid-query (a deleted pod, a hung node) and is still TCP-healthy at every visible hop, so nothing else times out. Polaris's transactions are one short statement, so 15 s is pathological on any substrate (v9.244) |

**Operator commands:**

The pgbouncer admin console (`SHOW POOLS`, `SHOW CLIENTS`, `SHOW STATS`) is
intentionally disabled: the runtime `pgbouncer.ini` written by
[polaris_web/pgbouncer-entrypoint.sh](../../polaris_web/pgbouncer-entrypoint.sh)
sets no `admin_users` or `stats_users`, so the application role cannot issue
`PAUSE`/`RELOAD`/`SHUTDOWN` (least privilege), and the alpine pgbouncer image
ships no `psql`. Observe the pool from the outside instead:

```bash
# pgbouncer's own log (pool open/close, waits, auth failures)
docker compose -f polaris_web/docker-compose.prod.yml logs pgbouncer | tail -50

# Server-side view of the pooled connections
docker compose -f polaris_web/docker-compose.prod.yml exec -u postgres postgres \
    psql -d polaris -c "SELECT usename, state, count(*) FROM pg_stat_activity
                        WHERE usename = 'polaris_app' GROUP BY 1, 2;"
```

**When pgbouncer transaction-pooling is wrong:**

- Client-side cached prepared statements (Polaris uses none) need
  session-pooling, or the cache disabled.
- `LISTEN`/`NOTIFY` (Polaris uses neither): transaction-pooling discards the
  listening session at transaction end.
- `SET SESSION` calls: Polaris uses only transaction-scoped GUCs
  (`polaris.actor_agency_id` and `polaris.reason_code` via `set_config(...,
  true)`, `polaris.purge_in_progress` via `SET LOCAL`), which are fine.

### gunicorn worker tuning: `WEB_CONCURRENCY`

**Inflection:** sustained CPU utilization above ~70% on the app container, OR
p95 latency creeping above the request budget.

**Recipe:**

```bash
# In polaris.env (or the shell that runs the deploy):
export WEB_CONCURRENCY=8

# Then deploy as usual:
./scripts/polaris-deploy.sh prod
```

Rule of thumb: `WEB_CONCURRENCY = (2 x vCPU) + 1` for the gunicorn default
sync worker class. The default is 4 (suitable for 2-vCPU hosts). On an
8-vCPU host raise to 17. Above 16 workers, also raise
`PGBOUNCER_DEFAULT_POOL_SIZE` proportionally.

### Event-table partitions

The four append-only event tables (TokenLifecycleEvent, VerificationEvent,
EnrollmentStatusEvent, AuthAuditLog) are monthly range-partitioned on
`event_timestamp` ([../design/partitioning.md](../design/partitioning.md),
roadmap P2.1). New rows route to a monthly partition automatically; nothing in
the application changes.

- **Premaking months.** `uc_ensure_event_partitions(months_ahead)` creates the
  current month plus a buffer. The deploy calls it on every upgrade, and
  `polaris-partition-maintenance.timer` runs it monthly (the 2nd at 04:00 UTC).
  A month with no partition is not data loss (the row lands in the DEFAULT
  partition) but forfeits fast detach-based purge for that month, so keep the
  timer running. Run it by hand against the stack with
  `scripts/polaris-partition-maintenance.sh`.
- **Fast purge.** `uc_detach_event_partitions_before(cutoff)` detaches every
  whole month at or below the cutoff in O(1) (metadata only) and re-adds the
  append-only trigger to each detached table, which stays immutable until you
  archive and drop it. The retention purge (`uc_archive_purge`) still works by
  row-level DELETE; detach is the fast complement for whole months.
- **Inspect.** `\d+ verificationevent` lists the partitions; a row's home is
  `SELECT tableoid::regclass FROM verificationevent WHERE …`.
- **Upgrading a large pre-v9.245 deployment.** The migration converts the tables
  in place (it attaches the existing table as the DEFAULT partition, no copy);
  its only non-instant step is re-creating the indexes on that partition. On a
  very large table, build them `CONCURRENTLY` out of band before the migration
  so it adopts them instead of rebuilding.

### Read replica: for atlas-dominated read load

**Inflection:** the atlas API (`/api/atlas/*`) dominates request volume AND
p99 latency is above 200ms.

**Status (v9.246, roadmap P2.2):** shipped. When a replica is configured the
app routes its read-only surfaces (the atlas API, the verification list, the
token export) to it; correctness-critical reads (a verification decision,
issuance, a token's current state) stay on the primary. On the HA profile the
app dials the pooler's `polaris_ro` database, routed to the router's
`/replica` endpoint (`pg-router:5433`); a failover moves the replica the
router picks. Single node (no replica configured) is unaffected: every read
uses the primary.

**Configure it.** Set `POLARIS_DB_REPLICA_NAME` (the pooler's read database,
`polaris_ro` on the HA profile) on the app, and `POLARIS_DB_REPLICA_HOST` /
`POLARIS_DB_REPLICA_PORT` on the pooler so it serves `<db>_ro` onward to the
replica. Unset means single node.

**The staleness contract.** A read routed to the replica is eventually
consistent: at most `POLARIS_REPLICA_MAX_LAG_S` seconds behind the primary
(default 10). Beyond that, or if the replica is unreachable, the read falls
back to the primary (fresh) so the surface stays available; the fallback is
counted on `polaris_replica_failback_total`. These surfaces do not guarantee
read-your-writes, which is why only analytical reads route there. Every routed
response carries `X-Polaris-Data-Source` (`replica` or `primary-failback`) and,
when served from the replica, `X-Polaris-Replica-Lag-Seconds`; `/api/health`
reports the replica's lag and whether it is serving reads under the contract (a
lagging replica is informational, not unhealthy). `polaris-failover-drill.sh`
asserts the app serves reads from the replica, and that the surfaces stay up
across a failover.

### The HA profile: living with Patroni

Under [`docker-compose.ha.yml`](../../polaris_web/docker-compose.ha.yml)
([DEPLOYMENT.md](DEPLOYMENT.md#automated-database-failover-ha-profile)) the
database is two Patroni members behind `pg-router`. The day-2 surface is
`patronictl`, run inside either member:

```bash
P="docker compose -f polaris_web/docker-compose.prod.yml -f polaris_web/docker-compose.ha.yml exec postgres patronictl -c /var/lib/postgresql/patroni.yml"
$P list                                   # members, roles, timeline, lag
$P switchover --primary postgres --candidate postgres2   # planned; asks to confirm
$P history                                # every timeline change and why
$P show-config                            # the cluster parameters in the DCS
$P edit-config                            # change them (Patroni restarts what needs a restart)
```

A planned switchover is the way to restart or upgrade the leader's host:
switch the lease to the other member, work on the idle one, switch back. A
lost member rebuilds itself when it starts again (`pg_rewind`, or a fresh
clone if rewind cannot apply); `$P reinit postgres2` forces a fresh clone.
Never edit `postgresql.conf` on a member: Patroni owns it. The stack-level
proof that this holds under a leader loss, a lease partition, a switchover
and an etcd crash is [`scripts/polaris-failover-drill.sh`](../../scripts/polaris-failover-drill.sh),
run on every push; the measured numbers are in [FAILOVER.md](FAILOVER.md).

### Redis cluster: for high-QPS rate limiting

**Inflection:** sustained 500+ req/min/IP across distinct clients, OR
rate-limiter Redis latency p95 above 5ms.

**Status:** not shipped. The app's rate-limiter selection in `security.py`
discovers Redis via `POLARIS_REDIS_URL`; a Sentinel or Cluster endpoint can be
pointed at the same way. The shipped single instance runs with
`maxmemory 256mb` and `allkeys-lru`.

### PostGIS: for atlas spatial queries at very high cardinality

**Inflection:** atlas API p95 above 500ms at 5M+ events with the default
B-tree spatial indexes; B-tree breaks down past ~10M events because it does
not model 2D proximity natively.

**Recipe:** the `polaris_sql/13_postgis.sql` script is optional by design; the
schema works with and without the extension.

```bash
# 1. As a Postgres superuser, install the extension once:
docker compose -f polaris_web/docker-compose.prod.yml exec postgres \
    psql -U postgres -d polaris -c "CREATE EXTENSION postgis;"

# 2. Re-run the load script so 13_postgis.sql picks up the change:
docker compose -f polaris_web/docker-compose.prod.yml exec postgres \
    psql -U postgres -d polaris -f /docker-entrypoint-initdb.d/sql/13_postgis.sql

# 3. Confirm:
docker compose -f polaris_web/docker-compose.prod.yml exec postgres \
    psql -U postgres -d polaris -c "
        SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='postgis') AS postgis_loaded,
               EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name='verificationevent' AND column_name='geo')
                       AS geo_column_present"
```

After step 3 both should return `t`. The schema gains:
- `VerificationEvent.geo` (generated, stored) + `gix_verification_geo` (GiST)
- `TokenLifecycleEvent.geo` (generated, stored) + `gix_lifecycle_geo` (GiST)

The atlas functions still use the B-tree path; operators with PostGIS active
can query the GiST index directly (a sample `ST_DWithin` query is in
[docs/design/atlas-scaling.md](../design/atlas-scaling.md), section
"PostGIS-optional scaling path").

**When NOT to enable PostGIS:** managed Postgres tiers that gate it behind
paid plans. The B-tree fallback is operationally complete below ~5M events.

### Vertical alternative

For most deployments the cheaper move is vertical scaling first, horizontal
second:

- 2 vCPU to 4 vCPU: doubles app throughput with a gunicorn worker bump
- 4 GB to 16 GB: enables larger `shared_buffers` for Postgres
- SSD to NVMe: cuts atlas p99 at large cardinality

These changes are operator-driven and do not require app code changes.

### Storage growth

`VerificationEvent` grows fastest. Planning rule (an estimate carried from the
v8.77 runbook, not a measurement; measure your own instance with
`pg_total_relation_size('verificationevent')`):

- ~300 bytes per VerificationEvent row (including indexes)
- 1M verifications/day gives ~330 MB/day, ~120 GB/year

Plan 5-year retention; the
[archive + purge pipeline](#audit-log-archive--purge) moves older rows to
cold storage with the non-repudiation chain intact.

---

## Monitoring & alerting

### Health check

`GET /api/health` (no auth) returns structured JSON; the full payload and the
per-component semantics are specified in
[API.md](../reference/API.md#get-apihealth). The fields the thresholds hang
on:

- `status`: the worst per-component status; `healthy` or `degraded` answer
  HTTP 200, `unhealthy` answers HTTP 503
- `checks.database.latency_ms`: above 500 ms the component is `degraded`
- `checks.database.table_count`: below 20 is `degraded`, zero is `unhealthy`
- `checks.disk.free_gb` and `checks.disk.used_pct`: below 5 GB free or above
  85% used is `degraded`; below 0.5 GB free is `unhealthy`
- `checks.redis.status`: an unreachable Redis backend is `degraded` (the
  limiter fails closed)
- `checks.zk_binary.status`: the prover binary present and executable

`/api/health/live` and `/api/health/ready` are the cheap probes Caddy, Compose
and Kubernetes use. The contract is enforced by `HealthEndpointTests` in
`polaris_web/test_app.py`.

### Alerts and thresholds

The alert rules are a shipped, promtool-validated artifact:
[polaris-alerts.yml](../../deploy/observability/polaris-alerts.yml) (10
rules, severity-labelled to the SEV ladder in [DR.md](DR.md)). Every rule has
a runbook in [RUNBOOKS.md](RUNBOOKS.md), and the availability, latency, and
database-latency objectives the thresholds derive from are in
[SLOS.md](SLOS.md). Do not maintain a second threshold table here.

### Prometheus metrics (`/metrics`)

A Prometheus-compatible `/metrics` endpoint exposes time-series data
complementing `/api/health`'s point-in-time view. No authentication; it
carries the duress signal, so it must be reachable only by the operator's
monitoring, never the public internet ([HARDENING.md, section 10](HARDENING.md)).

**Edge exposure (operator-supplied until the software ship lands).** The
shipped [polaris_web/Caddyfile](../../polaris_web/Caddyfile) reverse-proxies
every path of the public site to the app, including `/metrics` and
`/api/metrics`, with no source-IP ACL; the app applies none either. A
production operator must add a Caddy matcher restricting both paths to the
monitoring network before the site goes public:

```caddyfile
{$POLARIS_DOMAIN} {
    @metrics {
        path /metrics /api/metrics
        not remote_ip 10.0.0.0/8      # your monitoring CIDR
    }
    respond @metrics 404

    reverse_proxy {$POLARIS_UPSTREAMS:app:8000} {
        # ... shipped block unchanged ...
    }
}
```

**Scrape config example** (Prometheus `prometheus.yml`; the shipped one is
[deploy/observability/prometheus.yml](../../deploy/observability/prometheus.yml)).
Scrape the app directly on the stack network, as
[polaris_web/docker-compose.observability.yml](../../polaris_web/docker-compose.observability.yml)
does, rather than through the public domain:

```yaml
scrape_configs:
  - job_name: polaris
    metrics_path: /metrics
    scheme: http
    scrape_interval: 30s
    static_configs:
      - targets: ['app:8000']
```

**Exposed metrics:**

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `polaris_requests_total` | counter | route, method, status | HTTP requests served |
| `polaris_request_latency_seconds` | histogram | route | Per-route request latency |
| `polaris_verifications_total` | counter | disclosure_level | VerificationEvent rows recorded through the app |
| `polaris_duress_events_total` | counter | | Duress-code matches recorded; `PolarisDuressEvent` pages on any increase |
| `polaris_agency_events_total` | counter | kind, agency_id | Issuances, revocations (by the token's issuing agency), and verifications (by the requesting agency): the per-agency velocity signal the `Polaris*Velocity` alerts compare against each agency's own trailing week |
| `polaris_quota_refusals_total` | counter | kind, agency_id | Writes refused by an `AgencyQuota` cap (`PolarisQuotaRefusals` pages on any increase) |
| `polaris_db_query_latency_seconds` | histogram | | DB round-trip (sampled on `/api/health` probes) |
| `polaris_app_info` | gauge | version | App metadata; value always 1; the label carries the data |

`/metrics` aggregates across all gunicorn workers (Prometheus multiprocess
mode), so an absolute counter is whole-app.

**Alerting stack:** the rules file ships alongside a
[prometheus.yml](../../deploy/observability/prometheus.yml) scrape config
wired to the shipped [alertmanager.yml](../../deploy/observability/alertmanager.yml)
routing and pager receiver, and a [README](../../deploy/observability/README.md).
CI runs `promtool` and `amtool` on all three and drills the duress page path
end to end (`scripts/polaris-page-drill.sh`); weekly, the chaos drill stops
both app colours until `PolarisAppDown` reaches the webhook through the same
rules and routing ([CHAOS-DRILLS.md](CHAOS-DRILLS.md)); the pager URL itself is yours
(a mounted file; [RUNBOOKS.md, Paging](RUNBOOKS.md#paging-wiring-the-receiver)).

### Per-agency quotas and velocity alerts

Quotas are the database's bound on what an AGENCY may do; the alerts are the
early sight of an agency changing behaviour before a quota exists or engages.
Both are per agency, never per person.

**Quotas.** `AgencyQuota` holds up to three caps per agency: issuances per
rolling day, revocations per rolling day (of the tokens that agency issued),
verifications per rolling hour (as the requesting agency). NULL = no cap of
that kind, no row = no caps, so nothing changes until you set one:

```bash
polaris-id quota-set 5 --verify-per-hour 500 --justification "First National Bank: contracted verification volume is ~300/h"
polaris-id quota-set 2 --issue-per-day 200 --revoke-per-day 20 --justification "PA bureau: enrollment capacity of two offices"
polaris-id quota-set 5 --verify-per-hour 0 --justification "verification cap lifted after the audit"   # 0 clears one cap
polaris-id quota-show
polaris-id quota-show --history          # what each cap replaced, and why
```

Setting a cap never overwrites the last one. The live row is superseded and a new
row appended, so who raised an agency's ceiling, when, and on what stated reason
stays readable; `quota-show` answers what is enforced now, `quota-show --history`
answers what it replaced. The database holds that shape rather than trusting the
writer: `uq_effective_agency_quota` allows one un-superseded row per agency and
`trg_agency_quota_immutable` refuses an edit of any decided field, refuses DELETE,
and makes superseding one-way (v9.424).

The `enforce_agency_quota` trigger binds every write path (the stored
procedures, the SQL console, a bulk loader) and is exact under concurrent
writers; a refused write is an HTTP 429 with the trigger's own sentence
(`quota exceeded: agency 5 has reached its verify quota of 500 per hour (AgencyQuota)`),
a `quota.refused` structured log line, and a `polaris_quota_refusals_total`
increment. The percentage bound on revocation velocity
(`trg_enforce_revocation_velocity`) still applies; whichever trips first
refuses. An uncapped agency pays one primary-key lookup per write.

**Relying parties.** Registering an outside relying party grants it standing to ask
this system about people, so `polaris-id rp-register` requires a `--justification` and
records it. Changing its policy afterwards is recorded too:

```bash
polaris-id rp-register "First National Bank" --require-zk \
    --justification "contracted verification volume, ~300/h, step-up required by contract"
polaris-id rp-policy <client_id> --no-require-zk \
    --justification "the bank's proof integration slips to Q4; step-up returns then"
polaris-id rp-history <client_id>              # every decision, and who made it
polaris-id rp-history --weakened-only          # only the bars that were lowered
```

A change that REDUCES what the party must satisfy (the zero-knowledge step-up turned
off, a required enrollment dropped, the context restriction lifted, the scope widened,
the credential re-enabled, the rate limit raised) is refused by the DATABASE without a
20-character justification, so it is refused through psql as well. A tightening needs
none. The record is written by `trg_relying_party_audited` rather than by this CLI, so
a change made any other way appears in `rp-history` on the same terms.

**Velocity alerts.** `PolarisIssuanceVelocity`, `PolarisRevocationVelocity`,
and `PolarisVerificationVelocity` fire when one agency's last hour exceeds an
absolute floor (20 / 5 / 200) AND four times that agency's own trailing 7-day
hourly mean; `PolarisQuotaRefusals` fires on any refusal. The rules are
unit-tested with `promtool test rules` in CI, and the whole path (a cap held
under real traffic from the load generator, the database, `/metrics`, and the
log agreeing) is `scripts/polaris-abuse-drill.sh`. Runbooks:
[RUNBOOKS.md](RUNBOOKS.md).

### Changing the edge or database configuration

A Caddyfile change is applied live (v9.240). Edit
[`polaris_web/Caddyfile`](../../polaris_web/Caddyfile) and either run the
deploy, which reloads the edge as its step 5a, or reload it yourself:

```bash
docker compose -f polaris_web/docker-compose.prod.yml exec -T caddy \
    caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//config/admin.sock
```

A Caddyfile that fails to adapt is refused and the running configuration keeps
serving. Recreating the edge container (an image update) is a sub-second gap
for clients; `scripts/polaris-window-drill.sh` measures it on every push.

A PostgreSQL parameter that is reloadable takes effect with
`SELECT pg_reload_conf()` after `ALTER SYSTEM SET`; one that requires a restart
(`shared_buffers`, `wal_level`) needs `docker compose restart postgres`, which
the pooler turns into a second of latency rather than errors, as the same
drill shows. Pick a quiet minute for it all the same.

### Distributed tracing

Opt-in OpenTelemetry traces across the app and the database, joined to the
structured logs by the correlation id. OFF by default; one knob:

```bash
POLARIS_OTEL=1                                   # the switch (announced in the log stream)
OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo:4318    # your collector (this is the overlay default)
```

With it on, every request gets a server span (name = the route template;
`http.target` is the query-stripped path; `polaris.request_id` carries the
correlation id) and every psycopg2 call a client span inside it carrying the
parameterized statement template only: never values, never identity. An
inbound `traceparent` is honoured only behind `POLARIS_TRUST_PROXY`,
symmetric with `X-Request-ID`. Health probes are excluded by default
(`POLARIS_OTEL_EXCLUDE=/api/health/live,/api/health/ready`). Sampling uses
the standard `OTEL_TRACES_SAMPLER[_ARG]` knobs.

### The Atlas basemap

The Atlas draws its events over a vector basemap. By default that is CARTO's
free dark-matter style, and the operator's browser fetches the style and its
tiles from `basemaps.cartocdn.com` on that one page: the tile coordinates of
an investigation, and the operator's address, leave the estate. Nothing else
in the console reaches a third party. A deployment that cannot allow even
that (an air-gapped network, or a privacy posture that forbids it) points the
Atlas at a self-hosted MapLibre style, and the page's Content-Security-Policy
follows the configured origin (v9.237):

```bash
POLARIS_ATLAS_BASEMAP_STYLE_URL=https://tiles.internal.example/dark/style.json
# or, served by the app itself from polaris_web/static:
POLARIS_ATLAS_BASEMAP_STYLE_URL=/static/basemap/style.json
```

Any MapLibre-compatible style works; the map falls back to plotted markers
over an empty globe if the style cannot be fetched.

**The join, in practice:** a caller quotes an `X-Request-ID`; TraceQL
`{span.polaris.request_id="<id>"}` finds the trace; a log line's `trace_id`
field finds the same trace; `docker logs polaris-app | jq
'select(.trace_id=="<id>")'` goes the other way. `tracing.py` documents the
vocation constraints (ephemeral ids, nothing persisted to the DB, exception
class names only).

### Grafana dashboards-as-code

The dashboards are committed JSON, not UI state:
[deploy/observability/grafana/](../../deploy/observability/grafana/)
provisions two dashboards (`polaris-overview`, the /metrics headliners with
the alert thresholds drawn in; `polaris-traces`, TraceQL panels keyed on the
correlation id) plus the Prometheus and Tempo datasources. Run the whole
stack as an overlay:

```bash
docker compose -f docker-compose.prod.yml -f docker-compose.observability.yml up -d
```

(Prometheus, Alertmanager, Tempo, Grafana on the stack network; Grafana on
`127.0.0.1:3000` only, because it can display the duress signal and so never
faces the public internet. See
[deploy/observability/README.md](../../deploy/observability/README.md).)
CI validates the dashboards and drills the OTLP wire path on every push
(`scripts/polaris-trace-drill.sh`).

---

## Encryption at rest

The production stack's `pg_data` volume is not encrypted by Polaris; at-rest
protection of the live database is host-level and operator-gated. What is
sensitive on disk, what is already protected (backups, transit), why the
control is the volume rather than the column, and the LUKS / managed-TDE /
fscrypt recipes with their verification step are all in
[ENCRYPTION-AT-REST.md](ENCRYPTION-AT-REST.md).

---

## Incident response

The severity ladder, the decision tree, and the recovery procedures by
failure class are [DR.md](DR.md); every alert has a runbook in
[RUNBOOKS.md](RUNBOOKS.md). The three triage paths below are the ones that
start from a symptom rather than an alert.

### Database unreachable

`/api/health` returns 503 (`database: unhealthy`) and application pages fail
with the app's own error responses. Caddy keeps proxying, because its upstream
probe is `/api/health/live` (process liveness, no DB touch); a Caddy 502 means
the app itself is down (see [DR.md](DR.md), section 4.1).

1. `docker compose -f polaris_web/docker-compose.prod.yml ps`:
   is the postgres container up?
2. `docker compose -f polaris_web/docker-compose.prod.yml logs
   postgres | tail -50`
3. Check disk space: `df -h` (most common cause)
4. Check `pg_stat_activity` for stuck queries:
   `docker compose ... exec postgres psql -U polaris_app -c "SELECT
   pid, state, query_start, query FROM pg_stat_activity WHERE state
   != 'idle';"`
5. If recoverable, `docker compose ... restart postgres`. If not,
   restore from the latest backup ([DR.md, section 4.3](DR.md)).

### Suspected operator-credential compromise

1. **Immediate:** lock the affected operator account:

   ```sql
   UPDATE AppUser SET locked_until = now() + interval '30 days'
   WHERE username = '<compromised>';
   ```

2. **Audit:** review `AuthAuditLog` for the suspected window:

   ```sql
   SELECT event_timestamp, event_type, ip_address, user_agent, detail
   FROM AuthAuditLog
   WHERE username = '<x>'
     AND event_timestamp > now() - interval '7 days'
   ORDER BY event_timestamp DESC;
   ```

   Look for unusual IPs, unusual times.

3. **Review token actions** in the window (operators are not bound to an
   agency; review every lifecycle event and match the actor from the audit
   trail):

   ```sql
   SELECT event_id, token_id, actor_agency_id, event_type, event_timestamp, reason_code
   FROM TokenLifecycleEvent
   WHERE event_timestamp > '<compromise window start>'
   ORDER BY event_timestamp DESC;
   ```

   Any tokens issued / revoked / lost during the window need re-validation
   by an uncompromised operator.

4. **Rotate:** new password (`polaris-id user-passwd <username>`), new session
   secret if the compromise is widespread
   (`./scripts/polaris-rotate-secret.sh polaris_secret_key` invalidates ALL
   sessions).

5. **Document:** record a dated post-mortem
   ([DR.md, section 9, Post-incident review](DR.md); the internal summary
   template is section 8.4). If a new attack class was used, also update
   [DEVNOTES/known-gotchas.md](../../DEVNOTES/known-gotchas.md).

### Suspected schema tampering (DBA-level compromise)

1. **Stop writes:** `docker compose -f
   polaris_web/docker-compose.prod.yml stop app`.

2. **Verify constraints intact:**

   The production image ships no `test_*.py` (see
   `check_prod_image_no_test_deps`), so run the suite from a repo checkout
   with the Python 3.12 venv, pointing the `POLARIS_DB_*` environment at the
   stack's database. The postgres container publishes no host port, so give
   the checkout reach into `polaris-net` first (a temporary forward such as
   `docker run --rm --network polaris_web_polaris-net -p 127.0.0.1:5432:5432
   alpine/socat TCP-LISTEN:5432,fork TCP:postgres:5432`, torn down afterwards):

   ```bash
   cd polaris_web && \
   POLARIS_DB_HOST=127.0.0.1 POLARIS_DB_PORT=5432 POLARIS_DB_NAME=polaris \
   POLARIS_DB_USER=postgres \
   POLARIS_DB_PASSWORD="$(cat secrets/polaris_db_root_password)" \
     python3 -m unittest test_check_constraints
   ```

   Each C1-C10 invariant should pass. Any failure means the schema has been
   modified.

3. **Check append-only triggers:**

   ```sql
   SELECT DISTINCT trigger_name, event_object_table
   FROM information_schema.triggers
   WHERE trigger_name LIKE '%append_only%'
   ORDER BY trigger_name;
   ```

   Expected: 11 distinct `trg_*_append_only` triggers (`DISTINCT` matters:
   each is `BEFORE UPDATE OR DELETE`, and `information_schema.triggers` emits
   one row per event): lifecycle, verification, enrollment event, erasure,
   anchor batch, checkpoint, epoch leaf, duress event, auth audit (from
   `polaris_sql/06_triggers.sql`), schema version (from
   `polaris_sql/00_migrations_table.sql`), and audit access (from
   `polaris_sql/migrations/2026-05-15-003-audit-access-log.up.sql`). All
   should match those committed files.

4. **Check audit-table row counts:**

   ```sql
   SELECT 'lifecycle' AS table, count(*) FROM TokenLifecycleEvent
   UNION ALL SELECT 'verification', count(*) FROM VerificationEvent
   UNION ALL SELECT 'enrollment', count(*) FROM EnrollmentStatusEvent
   UNION ALL SELECT 'anchor-batch', count(*) FROM AnchorBatch
   UNION ALL SELECT 'attestation', count(*) FROM AgencyTrustAttestation
   UNION ALL SELECT 'duress', count(*) FROM DuressEvent;
   ```

   Compare against the latest backup. Any unexplained decrement indicates
   tampering.

5. **If tampering confirmed:** restore from backup. The audit log is the
   source of truth; if it has been tampered with, the system has lost its
   non-repudiation guarantee and a public disclosure may be required.

### Unbounded resource consumption

Symptom: gunicorn workers hung; CPU 100%; atlas API slow.

1. **Check the cache:** `GET /api/atlas/cache-stats`; a high miss rate
   suggests a query pattern not benefiting from the cache.
2. **Check for an attacker:** `docker compose logs caddy | grep 429`;
   Caddy rate-limiter rejections indicate brute-force.
3. **Check connection count:** `SELECT count(*) FROM
   pg_stat_activity WHERE usename = 'polaris_app';` If above 100, a
   connection leak; restart gunicorn:
   `docker compose ... restart app`.
4. **Check the ZK queue:** the Plonky2 prover is CPU-bound; a backed-up
   epoch close queue can starve other requests. Defer non-urgent epoch
   closes.

---

## Common errors

### "Caddy could not get certificate"

Cause: Let's Encrypt HTTP-01 challenge failed. Most often DNS has not
propagated, or TCP/80 is firewalled.

```bash
# Verify DNS
dig +short ${POLARIS_DOMAIN}
# Should match this host's public IP

# Verify port 80 is open from outside
curl -fsS http://${POLARIS_DOMAIN}/
# From a different host; should return 308 redirect to https

# Tail Caddy logs
docker compose -f polaris_web/docker-compose.prod.yml logs caddy | tail -50
```

### "/api/health reports zk_binary degraded (zk binary not present)"

`_health_check_zk_binary` reports `degraded`, not `unhealthy`, when the prover
is missing or not executable, so HTTP stays 200 and the overall status is
`degraded`. Cause: the production image was built without the Rust toolchain,
or the prover binary was not bundled.

```bash
# Verify binary exists in the running container
docker compose -f polaris_web/docker-compose.prod.yml exec app \
  ls -la /opt/polaris/zk

# If missing, force rebuild
docker compose -f polaris_web/docker-compose.prod.yml build --no-cache app
docker compose -f polaris_web/docker-compose.prod.yml up -d --force-recreate app
```

`Dockerfile.prod` has a `--build-arg POLARIS_ZK_BUILD=1` (default on) that
includes a release build of the Plonky2 prover in the builder stage. Set
`--build-arg POLARIS_ZK_BUILD=0` to skip if you do not need ZK epochs (for a
development restore, for example).

### "Postgres docker volume drift"

Cause: the password in `secrets/polaris_db_password` does not match what the
`pg_data` volume was initialized with. Common after restore-from-backup if
backups were taken under different secrets.

```bash
# OPTION A: rotate the secret to match the volume's expected password
echo "<the original password>" > secrets/polaris_db_password
chmod 0600 secrets/polaris_db_password
docker compose -f polaris_web/docker-compose.prod.yml up -d --force-recreate

# OPTION B: nuke the volume and re-initialize (destroys all data!)
docker compose -f polaris_web/docker-compose.prod.yml down -v
./scripts/polaris-deploy.sh prod
```

### "Login redirects to /login again"

Cause: `POLARIS_SECRET_KEY` was rotated. All session cookies signed under the
old key now fail validation. Expected behavior; operators must sign in again.

### "Localhost refused to connect" (dev launcher only)

Affects only the dev launcher (`polaris_mac_launch.sh`), not the production
stack; the two root causes and their fixes are in
[DEVNOTES/known-gotchas.md](../../DEVNOTES/known-gotchas.md).

### "ZK prove takes >30 seconds"

The Plonky2 prover is CPU-bound. To improve:

1. Pin more CPUs to the app container (Compose `cpus:` on the `app` service)
2. Reduce leaves per epoch (close more often)

---

## Upgrades

### Polaris version upgrade

```bash
# Standard path
./scripts/polaris-deploy.sh prod
```

This pulls the latest commit, rebuilds the app image, applies schema
migrations idempotently, and recreates the app container(s) with the new
code. The DB volume is preserved. With the
[blue-green profile](DEPLOYMENT.md#zero-downtime-deploys-blue-green-profile)
(`polaris_web/docker-compose.bluegreen.yml`, proven by
`scripts/polaris-rolling-drill.sh`) the roll is measured at zero dropped
requests; without it, service pauses while the single `app` container is
recreated.

Always read [CHANGELOG.md](../../CHANGELOG.md) for the version you are
upgrading to; an entry with "breaking change" in the notes requires extra
steps.

**Upgrading across v9.239.** The edge now runs as uid 1000 and listens on
8080/8443 behind the host's 80/443. A deployment created earlier has
`caddy_data` and `caddy_config` volumes owned by root, which the new edge could
neither read (the ACME account and certificates) nor write (renewals).
`polaris-deploy.sh` re-owns both volumes once before it starts the edge. If
you bring the stack up some other way, do it by hand first:

```bash
for v in polaris_web_caddy_data polaris_web_caddy_config; do
    docker run --rm -v "$v:/v" alpine:3.24 chown -R 1000:1000 /v
done
```

### Postgres version upgrade

The `postgres` service is a built image (`Dockerfile.postgres`, pinned to a
`postgres:16-alpine` digest). A major-version move (16 to 17) is a
dump-and-restore with the shipped scripts. Plan a window; the database is
down for the duration.

```bash
# 1. Backup, and keep the tarball's path
./scripts/polaris-backup.sh --dest /var/backups/polaris

# 2. Stop the stack
docker compose -f polaris_web/docker-compose.prod.yml down

# 3. Change the FROM line in polaris_web/Dockerfile.postgres to the new major

# 4. Retire the old data volume (the backup from step 1 is the only copy now).
#    The compose project prefixes the volume name, so look it up.
docker volume rm "$(docker volume ls -q | grep pg_data)"

# 5. Rebuild and bring the stack up on an empty cluster, then restore into it
./scripts/polaris-deploy.sh prod --no-pull
./scripts/polaris-restore.sh /var/backups/polaris/<step-1 tarball> \
    --target=docker-stack --force --verify-schema-version
```

If continuous WAL archiving is enabled, run the stanza upgrade before the
first new-major backup:

```bash
docker compose -f polaris_web/docker-compose.prod.yml exec -u postgres postgres \
    pgbackrest --stanza=polaris stanza-upgrade
```

### TLS certificate renewal

Caddy auto-renews about 30 days before expiry. No manual action is needed.
Confirm the live certificate's dates:

```bash
openssl s_client -connect ${POLARIS_DOMAIN}:443 -servername ${POLARIS_DOMAIN} </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -dates
```

If `notAfter` is under 30 days out, renewal is failing: read the Caddy logs
(the "Caddy could not get certificate" entry above) and follow
[DR.md, section 4.5](DR.md). A renewal produces a new fingerprint for the
[CT monitor](#certificate-transparency-monitoring) allowlist.

---

## Decommissioning

If you ever need to retire a Polaris instance:

1. **Final backup**, then copy the tarball off the host

   ```bash
   ./scripts/polaris-backup.sh --dest /var/backups/polaris
   ```

2. **Notify dependent verifiers.** Anyone consuming `/api/federation/*` or
   `/api/zk/*` needs the migration window.

3. **Set all operators to read-only**

   ```sql
   UPDATE AppUser SET role = 'auditor' WHERE role != 'auditor';
   ```

4. **Stop accepting new tokens** by deprecating every algorithm;
   `uc1_issue_token` refuses issuance under a deprecated algorithm while
   verification of existing tokens continues:

   ```sql
   UPDATE CryptographicAlgorithm SET deprecation_date = CURRENT_DATE
   WHERE deprecation_date IS NULL OR deprecation_date > CURRENT_DATE;
   ```

5. **Cool-down window** (recommended 30 days): verifications continue
   working; no new issuance.

6. **Final audit export**

   ```bash
   pg_dump -Fc polaris -t TokenLifecycleEvent -t VerificationEvent \
     -t AuthAuditLog -t DuressEvent -t AnchorBatch \
     -t AgencyTrustAttestation -f final-audit-$(date +%Y%m%d).dump
   ```

7. **Tear down**

   ```bash
   docker compose -f polaris_web/docker-compose.prod.yml down -v
   ```

8. **Preserve audit volumes.** `pg_data` should be archived per your
   retention policy. The audit-of-record discipline requires that these never
   be destroyed without a documented sunset decision.

---

## What this document does NOT cover

- Application code internals: [CLAUDE.md](../../CLAUDE.md), [DEVNOTES/](../../DEVNOTES/README.md)
- Cryptographic algorithm choice: [PQC-POSTURE.md](../reference/PQC-POSTURE.md), [SECURITY.md](SECURITY-CONTROLS.md)
- Schema design: [DATA-MODEL.md](../reference/DATA-MODEL.md)
- Threat model: [docs/design/threat-model.md](../design/threat-model.md)
- API reference: [API.md](../reference/API.md)
- Privacy posture: [PRIVACY.md](PRIVACY.md)
- WebAuthn and hardware-token operator auth: [WEBAUTHN-ROLLOUT.md](WEBAUTHN-ROLLOUT.md)
- Disaster recovery targets and the drill ledger: [DR.md](DR.md), [DR-DRILLS.md](DR-DRILLS.md)
- Restore procedures by failure class: [DR.md](DR.md)
- High availability (streaming standby, failover): [FAILOVER.md](FAILOVER.md)
- Developer tooling (pre-commit hooks, test discipline): [CONTRIBUTING.md](../../CONTRIBUTING.md)
- Multi-region deployment: not covered by any Polaris document
- SOC 2 readiness checklist: not covered by any Polaris document

---

*Last verified against the code: 2026-09-02 (v9.199).*
