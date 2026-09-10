# Disaster recovery runbook

**Reader:** the on-call engineer with an open incident: the database lost a
tablespace, a host failed, an admin authenticator is gone, ransomware
encrypted the disk, a region went dark, or an operator wiped a critical row.
**Job:** name the failure class, follow its procedure, and restore service
within the targets below. [`OPERATIONS.md`](OPERATIONS.md) is the day-to-day
runbook; [`FAILOVER.md`](FAILOVER.md) is the streaming-replication complement
for the case where a standby survives the primary.

---

## Table of contents

1. [Targets: RPO and RTO](#1-targets-rpo-and-rto)
2. [Severity matrix](#2-severity-matrix)
3. [Decision tree: what failed](#3-decision-tree-what-failed)
4. [Procedures by failure class](#4-procedures-by-failure-class)
   - 4.1 [Application crash / container exit](#41-application-crash--container-exit)
   - 4.2 [Database corruption: single table](#42-database-corruption-single-table)
   - 4.3 [Database corruption: full cluster](#43-database-corruption-full-cluster)
   - 4.4 [Disk full / volume exhaustion](#44-disk-full--volume-exhaustion)
   - 4.5 [TLS cert expired / chain broken](#45-tls-cert-expired--chain-broken)
   - 4.6 [Locked-out admin (no WebAuthn authenticator)](#46-locked-out-admin-no-webauthn-authenticator)
   - 4.7 [Ransomware / encrypted volume](#47-ransomware--encrypted-volume)
   - 4.8 [Region-wide outage](#48-region-wide-outage)
5. [WAL archiving and the offsite repo (pgBackRest)](#5-wal-archiving-and-the-offsite-repo-pgbackrest)
6. [Drill cadence](#6-drill-cadence)
7. [On-call playbook](#7-on-call-playbook)
8. [Communications templates](#8-communications-templates)
9. [Post-incident review](#9-post-incident-review)
10. [Cross-references](#10-cross-references)

---

## 1. Targets: RPO and RTO

| Target | Value | How it is met | How it is measured |
|---|---|---|---|
| **RPO** (recovery point objective) | **300 s** | Continuous WAL archiving through pgBackRest with `archive_timeout = '60s'`, applied by [`polaris_web/docker-init.sh`](../../polaris_web/docker-init.sh) when `POLARIS_PGBACKREST_ENABLED=1` at the first init of the data volume; an existing cluster needs the same `ALTER SYSTEM` statements by hand (section 5). A partially filled WAL segment is pushed within 60 s, so the recovery point is bounded by the archive interval, not by the backup schedule. | [`scripts/polaris-dr-drill.sh`](../../scripts/polaris-dr-drill.sh): the age of the newest recovered marker at the moment the primary is killed. `RPO_TARGET=300`. |
| **RTO** (recovery time objective) | **14400 s** (4 h) | `pgbackrest --stanza=polaris restore`, archive replay, promotion, and the application brought up against the restored database (section 4.3). | The same drill: time from the kill to `/api/health` reporting the database healthy. `RTO_TARGET=14400`. |

The drill runs on every push to `main` (job `dr-drill` in
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)) and on the first
of every month with `--record`
([`.github/workflows/dr-drill.yml`](../../.github/workflows/dr-drill.yml)),
which appends the measured row to the ledger,
[`DR-DRILLS.md`](DR-DRILLS.md), and commits it, pass or fail. On a Linux host
installed by [`deploy/linux/install.sh`](../../deploy/linux/install.sh),
`polaris-dr-drill.timer` runs the same drill monthly and appends to
`/var/lib/polaris/dr-drills.md`. The ledger is machine-appended: do not edit
or restyle it by hand. Read the ledger before quoting either number; the two
rows dated 2026-09-02 (v9.192) measure RPO 41.6 s and 36.0 s and RTO to
service 4.7 s and 4.4 s on a clean stack with the sample data. A larger
repository restores more slowly; `pgbackrest info` reports its size.

**Without WAL archiving** (`POLARIS_PGBACKREST_ENABLED` unset), the recovery
point is the most recent encrypted `pg_dump` from
[`scripts/polaris-backup.sh`](../../scripts/polaris-backup.sh). The shipped
schedule is daily at 03:00 UTC (`polaris-backup.timer`, or the cron line
installed by [`scripts/polaris-cron-install.sh`](../../scripts/polaris-cron-install.sh)),
so the recovery point is up to 24 h old. The 300 s target holds only while
archiving is enabled and `pgbackrest --stanza=polaris check` passes. A
configured archive that fails its check is SEV-2 (section 2).

**Managed Postgres.** pgBackRest runs inside the shipped postgres image
([`polaris_web/Dockerfile.postgres`](../../polaris_web/Dockerfile.postgres));
its `archive_command` executes on the database host. A managed service (RDS,
Cloud SQL, Azure Flexible Server) does not run this image, so its recovery
point and point-in-time restore are the provider's, and the drill above does
not measure them. The procedures in section 4 that call `pgbackrest` are
replaced by the provider's restore console in that deployment.

**Standby survives the primary.** Streaming replication keeps a standby within
seconds of the primary and meets the 300 s target more tightly than the
archive interval; the bootstrap and promotion runbook is
[`FAILOVER.md`](FAILOVER.md). Replication does not replace backups: a logical
error replicates to the standby, so the point-in-time restore in section 4.3
remains the recovery for that class.

---

## 2. Severity matrix

| Severity | Definition | Response time | Escalation |
|---|---|---|---|
| **SEV-1** | Total service outage; users cannot log in or perform any operation | Immediate (page on-call within 5 min) | Page secondary on-call within 15 min if no acknowledgment |
| **SEV-2** | Major degradation; one core flow broken (token issuance failing) OR data-integrity risk (WAL archiving stopped, `pgbackrest check` failing) | Within 15 min | Secondary on-call within 30 min |
| **SEV-3** | Minor degradation; one non-critical surface broken (atlas tile cache cold) OR isolated user impact | Within 1 hour | Secondary on-call if unresolved at 4 h |
| **SEV-4** | Cosmetic or single-user issue with a workaround | Next business day | None |

The shipped alerting rules in
[`deploy/observability/polaris-alerts.yml`](../../deploy/observability/polaris-alerts.yml)
carry a severity label on this ladder: `PolarisAppInfoAbsent`
(`absent(polaris_app_info)` for 5 min) is SEV-1; `PolarisHighDBLatency`
(`polaris_db_query_latency_seconds` p99 over 5 s) is SEV-2. Alertmanager
routing and the pager receiver are in
[`deploy/observability/alertmanager.yml`](../../deploy/observability/alertmanager.yml);
one runbook per alert is in [`RUNBOOKS.md`](RUNBOOKS.md).

---

## 3. Decision tree: what failed

`/api/health` reports the checks `database`, `redis`, `zk_binary`, `disk`,
and `custody`; the overall status is the worst of them, and the route returns
503 when it is `unhealthy`.

```
Is /api/health responding at all?
├── No  → § 4.1 Application crash
└── Yes → read the JSON body
    │
    ├── status: "unhealthy"
    │   └── which check?
    │       ├── database  → § 4.2 or § 4.3
    │       ├── disk      → § 4.4
    │       └── custody   → the signing-key custody backend failed to load; issuance
    │                       refuses. KEY-CEREMONY.md (custody drivers).
    │
    ├── status: "degraded"
    │   └── keep serving, investigate: disk under 5 GB free or over 85% used (§ 4.4),
    │       redis unreachable (the rate limiter fails closed; restart the redis
    │       container, and if it recurs, § 4.1), or zk_binary missing (epoch
    │       closes and /api/zk/verify fail; token issue and token verify continue)
    │
    └── status: "healthy" but users report failures
        └── Caddy logs show TLS handshake failures → § 4.5
            AuthAuditLog shows login refusals        → § 4.6
```

---

## 4. Procedures by failure class

### 4.1 Application crash / container exit

**Symptoms:** `/api/health` returns connection-refused or 502; the gunicorn
process is gone; `docker compose ps` shows `app` restarting in a loop.

**Procedure:**

```bash
# 1. The immediate cause is usually in the last 200 log lines.
docker compose -f polaris_web/docker-compose.prod.yml logs --tail=200 app

# 2. Common causes and fixes:
#    "Connection refused" to postgres      → § 4.2 / § 4.3
#    "OperationalError" missing column     → migration drift;
#                                            ./scripts/polaris-migrate.sh --status, apply pending if safe
#    "ImportError"                         → a dependency missing from the image;
#                                            ./scripts/polaris-deploy.sh prod rebuilds it
#    "OOMKilled"                           → raise the container memory limit in docker-compose.prod.yml

# 3. A single crash with a now-stable restart loop: watch /api/health for
#    15 min and resume. Unstable: escalate to SEV-1 and go to § 4.3.
```

### 4.2 Database corruption: single table

**Symptoms:** the `database` health check passes, but specific queries return
`ERROR: invalid page in block ...` or one table fails `SELECT` while its
neighbours are fine.

A backup from `polaris-backup.sh` is a tarball `polaris-<ts>.tar.gz` (or
`polaris-<ts>.tar.gz.enc` when `POLARIS_BACKUP_KEY_FILE` was set at backup
time) containing `polaris.dump` (pg_dump custom format) and `MANIFEST.json`
with SHA-256 hashes; the destination is `/var/backups` (script default) or
`/var/backups/polaris` on a host installed by
[`deploy/linux/install.sh`](../../deploy/linux/install.sh).

**Procedure:**

```bash
# 1. Confirm the scope: the postgres log names the relation, and a full scan
#    of the suspect table reproduces the error while neighbours read cleanly.
docker compose -f polaris_web/docker-compose.prod.yml logs --tail=200 postgres | grep -i "invalid page"
docker compose -f polaris_web/docker-compose.prod.yml exec postgres \
    psql -U postgres -d polaris -c "SELECT count(*) FROM identitytoken;"

# 2. Verify the newest backup's manifest. --verify-latest sees plaintext and
#    encrypted (.enc) tarballs; for .enc it decrypts with POLARIS_BACKUP_KEY_FILE
#    before re-hashing every file in MANIFEST.json.
DEST=/var/backups            # /var/backups/polaris on a host installed by install.sh
POLARIS_BACKUP_KEY_FILE=/etc/polaris/backup.key ./scripts/polaris-backup.sh --verify-latest --dest "$DEST"

# Without the script (a bare restore host), the same check by hand:
LATEST=$(ls -1t "$DEST"/polaris-*.tar.gz* | head -1)
WORK=$(mktemp -d)
case "$LATEST" in
  *.enc) openssl enc -d -aes-256-cbc -pbkdf2 -pass file:"$POLARIS_BACKUP_KEY_FILE" \
             -in "$LATEST" -out "$WORK/backup.tar.gz" ;;
  *)     cp "$LATEST" "$WORK/backup.tar.gz" ;;
esac
tar xzf "$WORK/backup.tar.gz" -C "$WORK"
MANIFEST=$(find "$WORK" -name MANIFEST.json | head -1)
(cd "$(dirname "$MANIFEST")" && \
    jq -r '.sha256 | to_entries[] | "\(.value)  \(.key)"' MANIFEST.json | sha256sum -c)
DUMP=$(find "$WORK" -name polaris.dump | head -1)

# 3. Extract only the affected table from the custom-format dump.
TARGET_TABLE=identitytoken
pg_restore -t "$TARGET_TABLE" -f "$WORK/restore-${TARGET_TABLE}.sql" "$DUMP"

# 4. Drop and reload it inside one transaction (CASCADE if FKs depend on it;
#    read the generated SQL first).
docker compose -f polaris_web/docker-compose.prod.yml cp "$WORK/restore-${TARGET_TABLE}.sql" postgres:/tmp/
docker compose -f polaris_web/docker-compose.prod.yml exec postgres \
    psql -U postgres -d polaris -v ON_ERROR_STOP=1 \
    -c "BEGIN;" -c "DROP TABLE ${TARGET_TABLE} CASCADE;" -f "/tmp/restore-${TARGET_TABLE}.sql" -c "COMMIT;"

# 5. Re-run /api/health and the failing queries.
```

**Audit-of-record concern:** restoring an audit-class table
(`TokenLifecycleEvent`, `VerificationEvent`, `AuthAuditLog`) from a dump older
than the corruption loses the events written in between. WAL replay (section
4.3) preserves every event up to the chosen target time. Prefer section 4.3
for audit-class tables.

### 4.3 Database corruption: full cluster

**Symptoms:** the `database` health check fails outright; the postgres
container does not start; the log reports the cluster is not consistent.

This is the procedure the drill measures. It requires WAL archiving to have
been enabled (section 5) before the failure; without it, restore the newest
dump with [`scripts/polaris-restore.sh`](../../scripts/polaris-restore.sh)
(`--target=docker-stack`, `--dry-run` first).

**Procedure:**

```bash
COMPOSE="docker compose -f polaris_web/docker-compose.prod.yml"

# 1. Stop the app so nothing else writes.
$COMPOSE stop app

# 2. Forensic snapshot of the broken volume BEFORE recovery (auditors and a
#    ransomware investigation both need what was on disk at failure time).
PG_VOLUME=$(docker volume ls -q | grep pg_data)
docker run --rm -v "$PG_VOLUME":/data -v "$(pwd)":/snap busybox \
    tar czf /snap/forensic-snapshot-$(date -u +%Y%m%dT%H%M%S).tgz /data

# 3. Point-in-time restore from the pgBackRest repo, targeting the last
#    known-good moment (just before the corruption window). The one-off
#    container reuses the service definition (repo mount, rendered
#    conf.d/repo.conf, credential fragment) and runs as postgres; the drill
#    runs the same command without --type=time.
TARGET_TIME="2026-05-14 03:14:00 UTC"
$COMPOSE stop postgres
$COMPOSE run --rm --no-deps --user postgres postgres sh -c \
    "rm -rf /var/lib/postgresql/data/* && \
     pgbackrest --stanza=polaris --type=time --target=\"$TARGET_TIME\" --target-action=promote restore"

# 4. Start postgres; it replays the archive to the target and promotes.
$COMPOSE up -d postgres
$COMPOSE logs --follow postgres | grep -m1 "database system is ready to accept connections"
$COMPOSE exec postgres psql -U postgres -d polaris -c "SELECT pg_is_in_recovery();"   # f

# 5. Verify integrity (the drill compares the IdentityToken and schema_version
#    counts with their pre-failure values; the audit tables date the recovery point).
$COMPOSE exec postgres psql -U postgres -d polaris -c "
    SELECT count(*) FROM IdentityToken;
    SELECT count(*) FROM schema_version;
    SELECT count(*) FROM TokenLifecycleEvent;
    SELECT count(*) FROM VerificationEvent;
    SELECT max(event_timestamp) FROM TokenLifecycleEvent;
"

# 6. Bring the app back and smoke-test.
$COMPOSE up -d app
curl -sf https://${POLARIS_DOMAIN}/api/health | jq .
```

For a restore that omits `--type=time`, pgBackRest replays every archived
segment, which is the drill's path. If the repo is offsite (section 5) the
same command reads it from S3; the one-off container needs the same
`POLARIS_PGBACKREST_S3_*` env and the mounted credential fragment, which the
compose service definition supplies.

**Audit-of-record continuity:** WAL replay preserves every event up to the
target timestamp. Events between the target time and the moment of corruption
are lost; record that window in the post-incident review (section 9) so the
auditor can reconcile holder-reported verification events that are absent
from the restored database.

### 4.4 Disk full / volume exhaustion

**Symptoms:** the `disk` health check reports `unhealthy` (under 500 MB free)
or `degraded` (under 5 GB free or over 85% used); writes fail with "no space
left on device"; postgres stops accepting transactions because WAL writes are
blocked.

**Procedure:**

```bash
# 1. Find what is filling the disk.
df -h | head -5
du -sh /var/lib/docker/volumes/*/_data | sort -h | tail -5

# 2. Common culprits:
#    a. WAL backlog: archive_command is failing, so postgres keeps every segment.
#       docker compose -f polaris_web/docker-compose.prod.yml exec -u postgres postgres \
#           pgbackrest --stanza=polaris check
#       Fix the repo (section 5); postgres drains the backlog once pushes succeed.
#    b. Audit-log accumulation (5-year retention); --actor-user-id is required:
#       ./scripts/polaris-rotate-logs.sh --actor-user-id <admin user_id> --dest /var/backups
#       (archive, verify, purge; --dest /var/backups/polaris on an install.sh host)
#    c. Container logs are capped by the shipped compose (json-file, max-size
#       10m, max-file 5, on every service), so they are not the culprit. Check
#       the bind-mounted polaris_web/logs (Caddy and app file logs), the local
#       pgbackrest_repo volume, and host syslog or journald.

# 3. Emergency space recovery (LAST RESORT, destructive):
#    docker volume prune     (orphaned volumes; safe when nothing else uses Docker)
#    docker system prune -a  (orphaned images; the next deploy rebuilds)

# 4. Once the disk has 20% free, restart what halted.
docker compose -f polaris_web/docker-compose.prod.yml restart postgres app
```

### 4.5 TLS cert expired / chain broken

**Symptoms:** browsers show certificate warnings; `curl --insecure` works
while plain `curl` fails; Caddy logs show TLS handshake errors.

**Procedure:**

```bash
# 1. Current certificate state.
echo | openssl s_client -connect ${POLARIS_DOMAIN}:443 -servername ${POLARIS_DOMAIN} 2>/dev/null \
    | openssl x509 -noout -dates -issuer -subject

# 2. Make Caddy re-acquire from the ACME CA (the Caddyfile is mounted at
#    /etc/caddy/Caddyfile; the ACME account email is admin@${POLARIS_DOMAIN}).
#    The Caddyfile sets `admin off`, so `caddy reload` is unavailable; restart
#    the container instead.
docker compose -f polaris_web/docker-compose.prod.yml restart caddy
docker compose -f polaris_web/docker-compose.prod.yml logs --tail=50 caddy | grep -i "obtaining\|certificate\|tls"

# 3. If Let's Encrypt is rate-limiting, wait for the window to reset, or
#    temporarily add `acme_ca https://acme-staging-v02.api.letsencrypt.org/directory`
#    to the Caddyfile, restart caddy, then remove it and restart again.

# 4. Check Certificate Transparency for an issuance you did not request.
./scripts/polaris-ct-monitor.sh --check ${POLARIS_DOMAIN}
```

### 4.6 Locked-out admin (no WebAuthn authenticator)

**Symptoms:** an admin cannot log in; the authenticator is lost, broken, or
elsewhere; the account's `webauthn_required_after` deadline has passed.

**Procedure:**

```bash
# Path A: second-admin pairing (preferred when two or more admins exist).
./scripts/polaris-recover-admin.sh \
    --target locked-out-admin-username \
    --authorizing-user-id <your-admin-user-id> \
    --window-minutes 15

# The locked-out admin has 15 minutes to log in with the password alone AND
# enroll a fresh authenticator at /settings/webauthn. The grant is audited as
# EMERGENCY_PASSWORD_LOGIN_AUTHORIZED.

# Path B: printed recovery code (solo-admin deployment). The mnemonic was
# bound in advance with polaris-generate-recovery-code.sh --bind-to <username>
# and stored offline. It is read from stdin, never argv.
./scripts/polaris-recover-admin.sh --target <self-username> --recovery-code -
# type the mnemonic, then Ctrl+D. The same window opens; the audit row carries
# recovered_via=printed_recovery_code.
```

[SECRETS.md, section 9 (WebAuthn operator MFA)](SECRETS.md#9-webauthn-operator-mfa)
is the full enrollment and recovery runbook.

### 4.7 Ransomware / encrypted volume

**Symptoms:** files carry unfamiliar extensions; postgres does not start
because its data files are unreadable; a ransom note sits in the deploy
directory.

**Procedure:**

```bash
# Do NOT pay. Do NOT restart anything until step 1 completes.

# 1. Disconnect the host from the network now (stops lateral movement toward
#    the backups and buys time for forensics).
sudo ip link set eth0 down   # or unplug the cable

# 2. Forensic disk image BEFORE any recovery action.
sudo dd if=/dev/sda of=/external-drive/forensic-image.img bs=4M status=progress

# 3. Confirm the backups are NOT also encrypted.
#    a. The pgBackRest repo in S3 (section 5): the bucket belongs in a separate
#       account with versioning and MFA-delete, so a host compromise cannot
#       reach it.
aws s3 ls s3://${POLARIS_PGBACKREST_S3_BUCKET}/ --recursive | tail -10
#    b. The pg_dump tarballs from polaris-backup.sh, copied offsite on the
#       same terms.

# 4. Provision a fresh host (different region, credentials, and SSH keys);
#    install Polaris from clean source; restore from the offsite repo
#    (section 4.3) or the newest offsite tarball (polaris-restore.sh).

# 5. Forensics, in parallel with recovery:
#    - entry vector (SSH brute force, a stolen key, supply chain)
#    - lateral movement: if ANY base backup in the repo is itself encrypted,
#      the attacker was inside before that backup; restore from before it
#    - legal and compliance: GDPR breach notification is 72 h from discovery
#      when personal data may have been exposed

# 6. After recovery, rotate EVERY secret: the attacker may hold
#    POLARIS_SECRET_KEY, the database passwords, AppUser password hashes, and
#    session tokens. WebAuthn private keys never leave the authenticators.
#    Rotation is per secret; SECRETS.md section 4 (Rotation) lists them.
./scripts/polaris-rotate-secret.sh <name>
./scripts/polaris-deploy.sh prod
```

### 4.8 Region-wide outage

**Symptoms:** the cloud provider's status page shows a regional incident;
several services in the region are unreachable at once.

**Procedure (single-region deployment):**

Without a second region Polaris is unavailable until the region recovers.

1. **Communicate** with the "service down" template (section 8.2). Quote the
   provider's status page; do not promise a recovery time you cannot meet.
2. **Confirm the backups live outside the region**: the pgBackRest S3 repo
   (section 5) in a bucket outside the failed region, or cross-region
   replication on it. If they do not, file that as a SEV-2 finding in the
   post-incident review.
3. **Do not improvise a cross-region failover.** An untested failover during
   an incident creates a second incident.

**Procedure (with a standby region):**

Since v9.359 a second region ships as a profile:
[`polaris_web/docker-compose.dr.yml`](../../polaris_web/docker-compose.dr.yml).
It is a Patroni **standby cluster**, not another member of the first cluster,
and the difference is the point. A member across the boundary would put the WAN
inside region A's quorum: the lease store would have to be reachable across it,
and a region going dark would take part of the other region's consensus with it.
A standby cluster keeps its own lease store, so region B's availability does not
depend on region A's, and it replicates asynchronously, so region A's write
latency does not depend on region B either.

**The price, stated before the procedure rather than discovered during it.**
Asynchronous replication means the recovery point is **not zero**. Promoting
region B accepts the writes region A acknowledged that had not yet crossed.
`scripts/polaris-region-evacuation-drill.sh` measures that number under a live
write stream on every push rather than asserting it, and writes an RTO/RPO ledger
row. Synchronous cross-region replication would make the recovery point zero and
put the WAN's round trip on every commit in region A; that is a different product
and the choice is yours, not the repository's.

1. **Confirm region A is actually gone**, not slow. Promoting while region A is
   still accepting writes is how two regions diverge, and nothing below repairs
   that. Check the provider's status page and that region A's Patroni REST
   endpoint is unreachable from outside the region, not only from inside it.
2. **Communicate** as above, and say that a recovery point is expected: some
   acknowledged writes will be lost. Give the drill's most recent measured number
   as the order of magnitude, not as a promise.
3. **Promote region B.** On a `dr-postgres` member:

   ```bash
   patronictl -c /var/lib/postgresql/patroni.yml edit-config --force --set standby_cluster=null
   ```

   Patroni removes the standby configuration from region B's own lease store, the
   standby leader promotes, and its timeline advances. Confirm with
   `patronictl list`: the role must read `Leader`, not `Standby Leader`.
4. **Point the application at region B** and confirm a write succeeds.
5. **Record the recovery point.** Compare what clients were told succeeded
   against what region B holds; anything missing is real data loss and belongs in
   the post-incident review with the affected records named.
6. **Do not bring region A back as a primary.** When the region returns its
   database holds a diverged timeline. Rebuild it as a standby of region B, or
   restore it from the archive. Two primaries on two timelines is the one state
   from which there is no clean recovery.

The two regions are two placements, which is yours: the compose file is the same
with `POLARIS_PATRONI_STANDBY_HOST` naming region A's real address, and etcd needs
TLS between members once it leaves a single host's internal network. See
[multi-region.md](../design/multi-region.md) for the design record.

---

## 5. WAL archiving and the offsite repo (pgBackRest)

The postgres image carries pgBackRest
([`polaris_web/Dockerfile.postgres`](../../polaris_web/Dockerfile.postgres)),
[`polaris_web/pgbackrest.conf`](../../polaris_web/pgbackrest.conf) defines the
`polaris` stanza (retention of two full backups, bundled repo
(`repo1-bundle=y`), zstd compression), and
[`polaris_web/docker-init.sh`](../../polaris_web/docker-init.sh) sets
`archive_mode = on`, `archive_command = 'pgbackrest --stanza=polaris archive-push %p'`,
`wal_level = replica`, and `archive_timeout = '60s'` when
`POLARIS_PGBACKREST_ENABLED=1`. Archiving is off by default so a deployment
with no repo does not accumulate unarchivable WAL. `docker-init.sh` is an
initdb script: it runs only when the postgres container boots with an empty
data volume, so the flag alone changes nothing on an existing cluster. On an
existing cluster apply the same settings by hand and restart postgres
(`archive_mode` is restart-only):

```bash
COMPOSE="docker compose -f polaris_web/docker-compose.prod.yml"
$COMPOSE exec postgres psql -U postgres -d polaris \
    -c "ALTER SYSTEM SET archive_mode = on;" \
    -c "ALTER SYSTEM SET archive_command = 'pgbackrest --stanza=polaris archive-push %p';" \
    -c "ALTER SYSTEM SET wal_level = replica;" \
    -c "ALTER SYSTEM SET archive_timeout = '60s';"
$COMPOSE restart postgres
```

**Where the repo lives** is rendered into `/etc/pgbackrest/conf.d/repo.conf` at
every container start by
[`polaris_web/pgbackrest-conf.sh`](../../polaris_web/pgbackrest-conf.sh) from
env; nothing in `pgbackrest.conf` is edited (pgBackRest refuses an option set
in two files). With no `POLARIS_PGBACKREST_S3_BUCKET` the repo is the local
volume `/var/lib/pgbackrest`, which does not survive the host; `docker-init.sh`
prints a warning when archiving is enabled against a local repo. Three
settings on the postgres service make it offsite:

```bash
export POLARIS_PGBACKREST_S3_BUCKET=<bucket>
export POLARIS_PGBACKREST_S3_ENDPOINT=s3.<region>.amazonaws.com   # any S3-compatible endpoint
export POLARIS_PGBACKREST_S3_REGION=<region>
# optional: _PATH (default /polaris), _PORT, _URI_STYLE=path (MinIO, Ceph),
#           _CA_FILE (a private endpoint's CA bundle), _VERIFY_TLS=n (tests only)
export POLARIS_PGBACKREST_ENABLED=1
```

**The S3 key pair** is a root-level secret: it can read, write, and delete
every backup. It is never env. The renderer exits 3 and the container refuses
to start if it finds `POLARIS_PGBACKREST_S3_KEY` or
`POLARIS_PGBACKREST_S3_KEY_SECRET` in its environment, because env leaks
through `docker inspect`, `docker compose config`, and the process listing.
The pair goes in the file-mounted fragment that
[`scripts/polaris-generate-secrets.sh`](../../scripts/polaris-generate-secrets.sh)
creates as a commented template, mounted read-only at
`/etc/pgbackrest/conf.d/repo-creds.conf`:

```bash
$EDITOR polaris_web/secrets/pgbackrest_repo_creds.conf   # uncomment and fill in:
# [global]
# repo1-s3-key=<access-key>
# repo1-s3-key-secret=<secret-key>
```

An operator with a different repo type (Azure, GCS, SFTP) mounts their own
read-only `/etc/pgbackrest/conf.d/repo.conf`; the renderer leaves a mounted
file alone.

**Enable it.** [`scripts/polaris-deploy.sh`](../../scripts/polaris-deploy.sh)
runs `stanza-create` and `check` when `POLARIS_PGBACKREST_ENABLED=1` and
prints the fix-up command if either fails. By hand, inside the postgres
container as the `postgres` user:

```bash
COMPOSE="docker compose -f polaris_web/docker-compose.prod.yml"
$COMPOSE exec -u postgres postgres pgbackrest --stanza=polaris stanza-create
$COMPOSE exec -u postgres postgres pgbackrest --stanza=polaris check
# schedule a base backup (daily is typical); the repo keeps two full backups
$COMPOSE exec -u postgres postgres pgbackrest --stanza=polaris --type=full backup
$COMPOSE exec -u postgres postgres pgbackrest --stanza=polaris info
```

Run `pgbackrest --stanza=polaris check` daily; a failing check means WAL is
piling up on the primary and the recovery point is drifting (SEV-2).

**Proof.** Two CI round-trips exercise archive, backup, and restore with WAL
replay: one against a local repo (job step "pgBackRest archive + backup +
restore round-trip" in [`ci.yml`](../../.github/workflows/ci.yml)) and one
offsite against a TLS MinIO endpoint through the same env-and-fragment path an
operator uses
([`scripts/polaris-offsite-drill.sh`](../../scripts/polaris-offsite-drill.sh)),
which also proves the key-pair-in-env refusal. The RPO/RTO drill in section 1
restores from the same repo layout. The Kubernetes chart mounts the same
credential fragment from a Secret ([`KUBERNETES.md`](KUBERNETES.md)).

---

## 6. Drill cadence

A procedure that is never drilled is not a recovery procedure. The cadence:

| Drill | Frequency | Procedure | Pass criteria |
|---|---|---|---|
| **Backup verify** | Weekly (`polaris-backup-verify.timer`, Sunday 04:00 UTC; or the cron line from `polaris-cron-install.sh`) | `./scripts/polaris-backup.sh --verify-latest` (plaintext or `.enc`; with `POLARIS_BACKUP_KEY_FILE` set it decrypts first) | Every file in `MANIFEST.json` re-hashes clean |
| **RPO/RTO drill (automated)** | Every push (CI) and monthly on the 1st (`dr-drill.yml`, `polaris-dr-drill.timer`) | `./scripts/polaris-dr-drill.sh --record`: scratch archiving primary, full backup, 90 s of marker writes, SIGKILL and volume destroyed, restore and replay, app up | RPO at most 300 s, RTO at most 14400 s, token count and `schema_version` rows equal; the row lands in [`DR-DRILLS.md`](DR-DRILLS.md) pass or fail |
| **Restore-only drill** | Quarterly (`polaris-cron-install.sh` runs `polaris-restore.sh --dry-run` on the newest plaintext tarball on the 1st of Jan/Apr/Jul/Oct; its glob does not match `.enc`, so an encrypted deployment runs the drill by hand) | Restore the newest tarball into a fresh database: `./scripts/polaris-restore.sh <tarball> --target=polaris_drill`; compare row counts | Row counts within 1% of production; an admin can log in |
| **PITR drill** | Quarterly | Section 4.3 with `--type=time` targeting one hour ago, on a scratch stack | The recovered database is consistent at the target time |
| **Full-stack rebuild** | Half-yearly | New host from clean source; restore from the offsite repo; verify TLS issuance, admin login, token issuance | Within the RTO target |
| **Locked-out admin recovery** | Half-yearly | An admin removes their own credential and runs `polaris-recover-admin.sh` from a peer | Under 15 min; the `EMERGENCY_PASSWORD_LOGIN_AUTHORIZED` audit row is visible |
| **Ransomware tabletop** | Annual | Walk section 4.7 on paper; confirm every step's tool and credential is reachable from the on-call's emergency kit | Every step has a named owner and an access path |

The automated drill records itself. Record every manual drill as a dated
entry in the operator's incident tracker, with the measured time and any step
that did not match this document.

---

## 7. On-call playbook

```
Step 1.  Acknowledge the page within 5 min (SEV-1) / 15 min (SEV-2).

Step 2.  Read the alert body first; RUNBOOKS.md has one entry per alert.

Step 3.  Open three views:
         (a) https://${POLARIS_DOMAIN}/api/health
         (b) the Grafana dashboards (deploy/observability/grafana)
         (c) docker compose logs --tail=200 over SSH

Step 4.  Walk the section 3 decision tree. Name the failure class.

Step 5.  Open the matching section 4 procedure and follow it step by
         step. Do not improvise: when a step does not apply, write in
         the incident channel why, then continue.

Step 6.  Post to the incident channel at every state transition
         (restore started, restore complete, app reachable, smoke test
         passed).

Step 7.  When /api/health returns "healthy" and the smoke tests pass,
         declare the incident resolved and start the post-mortem clock
         (24 h to the write-up; 7 days to the internal review).

Step 8.  Close the incident in the tracker with the measured time to
         restore and the data loss window, if any.
```

---

## 8. Communications templates

### 8.1 Status page: service degraded

```
[INVESTIGATING] We are investigating reports of slowness in
<component>. Some users may experience <symptom>. Updates every
30 minutes until resolved.

Polaris on-call
```

### 8.2 Status page: service down

```
[CRITICAL] Polaris is currently unavailable. The cause is under
investigation. Estimated time to resolution: <X> minutes per our
recovery target. We will update every 15 minutes until service is
restored.

Polaris on-call
```

### 8.3 Customer-facing: incident resolved

```
Subject: Polaris service restored, incident <ID>

Polaris was unavailable from <start UTC> to <end UTC> because of
<one-sentence cause>. Service has been restored. Total downtime:
<X> minutes.

Data impact: <none / specify>. We do not believe holder data was
exposed.

A full post-mortem will be published at <link> within 7 business
days.

Polaris team
```

### 8.4 Internal post-incident summary

```
INCIDENT <ID>  /  <date>  /  <severity>

TIMELINE
  HH:MM UTC  Alert fired (<which alert>)
  HH:MM UTC  On-call acknowledged
  HH:MM UTC  Root cause identified (<one sentence>)
  HH:MM UTC  Mitigation started
  HH:MM UTC  Service restored
  HH:MM UTC  Incident closed

IMPACT
  - Duration: <X> minutes
  - Users affected: <count or %>
  - Data loss: <none / X seconds of WAL>
  - SLO breach: <yes/no, by how much>

ROOT CAUSE
  <2-3 paragraphs>

MITIGATIONS APPLIED
  <bulleted list of immediate actions taken>

PREVENTIVE ACTIONS (with owners and dates)
  - [ ] <action 1>  /  owner: <name>  /  by: <date>
  - [ ] <action 2>  /  owner: <name>  /  by: <date>

LESSONS
  <2-3 sentences: what was learned and what changes next time>
```

---

## 9. Post-incident review

Every SEV-1 and SEV-2 incident gets a blameless post-mortem within 7 business
days, filed as a dated record in the operator's incident tracker, with
preventive-action tickets opened there.

Blameless means the review examines systems and processes, not individuals.
When an operator made a mistake, the question is which process let that
mistake reach production. Adversarial framing teaches people to hide
mistakes; blameless framing teaches them to surface mistakes before they
become incidents.

The section 8.4 template is the structure. Reviewers check:

- Is the root cause correctly identified?
- Are the preventive actions specific, actionable, and assigned?
- Are the lessons captured at the right level of generality?
- Does an audit trail (commits, `AuthAuditLog` rows, deploy logs) back each
  timeline entry?

---

## 10. Cross-references

- [`OPERATIONS.md`](OPERATIONS.md): day-to-day operations, including the
  backup and restore section and the "Incident response" section for
  database-unreachable and credential-compromise cases.
- [`DR-DRILLS.md`](DR-DRILLS.md): the machine-appended ledger of measured RPO
  and RTO.
- [`FAILOVER.md`](FAILOVER.md): streaming replication, standby bootstrap, and
  promotion.
- [`RUNBOOKS.md`](RUNBOOKS.md) and [`SLOS.md`](SLOS.md): one runbook per
  alert and the SLO thresholds that map to the section 2 ladder.
- [`SECRETS.md`](SECRETS.md): [rotation](SECRETS.md#4-rotation),
  [the sealed secret store](SECRETS.md#5-the-sealed-secret-store), and
  [WebAuthn operator MFA](SECRETS.md#9-webauthn-operator-mfa) (enrollment and
  recovery).
- [`KEY-CEREMONY.md`](KEY-CEREMONY.md): signing-key custody, for the
  `custody` health check.
- [`ENCRYPTION-AT-REST.md`](ENCRYPTION-AT-REST.md): backup encryption and
  volume encryption.
- [`KUBERNETES.md`](KUBERNETES.md): the same pgBackRest credential fragment
  delivered as a Secret.
- [`PRODUCTION-READINESS.md`](../PRODUCTION-READINESS.md): the
  deployment-scale gaps, multi-region among them.
- [`docs/design/threat-model.md`](../design/threat-model.md): the STRIDE
  threat model these procedures answer.
- Scripts: [`polaris-dr-drill.sh`](../../scripts/polaris-dr-drill.sh),
  [`polaris-offsite-drill.sh`](../../scripts/polaris-offsite-drill.sh),
  [`polaris-backup.sh`](../../scripts/polaris-backup.sh),
  [`polaris-restore.sh`](../../scripts/polaris-restore.sh),
  [`polaris-rotate-logs.sh`](../../scripts/polaris-rotate-logs.sh)
  (wraps [`polaris-archive.sh`](../../scripts/polaris-archive.sh) and
  [`polaris-purge.sh`](../../scripts/polaris-purge.sh)),
  [`polaris-recover-admin.sh`](../../scripts/polaris-recover-admin.sh),
  [`polaris-ct-monitor.sh`](../../scripts/polaris-ct-monitor.sh),
  [`polaris-rotate-secret.sh`](../../scripts/polaris-rotate-secret.sh).
  For a read-only health read of a running deployment, `GET /api/health`
  reports structured per-component status; on a development checkout,
  `./polaris_mac_launch.sh doctor` inspects the local stack.
- [`polaris_web/docker-compose.prod.yml`](../../polaris_web/docker-compose.prod.yml):
  the production stack, including the `pg_data` and `pgbackrest_repo` volumes.

---

**Maintenance:** when a new failure class occurs in production, or a drill
finds a procedure inadequate, update this document and link the change to its
post-mortem record. A finding from a real incident lands here, not only in
chat.
