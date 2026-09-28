#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# Polaris Docker Init Script
#
# Runs once when the postgres container boots with an empty data volume.
# Loads the Polaris schema + sample data + procedures + triggers + grants
# via 00_load_all.sql, which now includes 09_grants.sql.
#
# After this completes, the polaris_app role exists with the right grants
# and the database has 73 sample rows ready for the Flask app to query.
# ============================================================================

set -e

# v9.243 (roadmap P2.7) — under the HA profile Patroni owns the server
# configuration: TLS, the replication role and pg_hba, and WAL archiving are
# cluster parameters written by patroni-entrypoint.sh, and this script is run
# by Patroni's post_init hook for what is the same on both profiles (the
# schema, the migrations, the application role, the production lock). The
# three ALTER SYSTEM blocks below are skipped in that mode.
MANAGED="${POLARIS_INIT_MANAGED_BY:-}"

echo "Loading Polaris SQL package..."

# 00_load_all.sql uses \i with relative paths, so we cd into the SQL directory
# before invoking psql.
cd /docker-entrypoint-initdb.d/sql
psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     -f /docker-entrypoint-initdb.d/sql/00_load_all.sql

# v9.121 — enable TLS so the app<->DB hop is encrypted. The self-signed server
# cert is mounted read-only at /etc/polaris-pg-certs (postgres:16-alpine has no
# openssl, so the cert is generated on the host by polaris-generate-secrets.sh).
# Copy it into the data dir (owned by this postgres user, key 0600) and turn ssl
# on. ALTER SYSTEM persists to postgresql.auto.conf, so the real server start
# after init comes up with TLS. Idempotent / optional: no cert -> no TLS.
PG_CERT_SRC=/etc/polaris-pg-certs
PG_DATA_DIR="${PGDATA:-/var/lib/postgresql/data}"
if [ "$MANAGED" = "patroni" ]; then
    echo "TLS, replication and archiving are Patroni parameters under the HA profile; skipping ALTER SYSTEM."
elif [ -f "$PG_CERT_SRC/server.crt" ] && [ -f "$PG_CERT_SRC/server.key" ]; then
    echo "Enabling Postgres TLS from the mounted cert..."
    cp "$PG_CERT_SRC/server.crt" "$PG_DATA_DIR/server.crt"
    cp "$PG_CERT_SRC/server.key" "$PG_DATA_DIR/server.key"
    chmod 0600 "$PG_DATA_DIR/server.key"
    chmod 0644 "$PG_DATA_DIR/server.crt"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
        -c "ALTER SYSTEM SET ssl = on;" \
        -c "ALTER SYSTEM SET ssl_cert_file = 'server.crt';" \
        -c "ALTER SYSTEM SET ssl_key_file = 'server.key';"
    echo "Postgres TLS enabled (ssl=on; the app<->DB hop will be encrypted)."
else
    echo "No TLS cert at $PG_CERT_SRC — Postgres runs WITHOUT TLS (POLARIS_DB_SSLMODE must be 'prefer')."
fi

# v9.18 — apply all pending migrations after the baseline schema loads.
# Without this, columns added post-v8.95 (e.g., AppUser.webauthn_required_after
# from the 2026-05-14-002-operator-webauthn migration) are missing from
# fresh containers, and any code path that queries them 500s. The fix
# mirrors scripts/polaris-migrate.sh's apply path: lexicographic ordering,
# per-file transaction, SHA-256 recorded in schema_version. actor_user_id
# is NULL (system-applied during init; no human actor at boot time).
MIG_DIR="/docker-entrypoint-initdb.d/sql/migrations"
if [ -d "$MIG_DIR" ]; then
    echo "Applying schema migrations..."
    count=0
    for up_file in "$MIG_DIR"/*.up.sql; do
        [ -f "$up_file" ] || continue
        name=$(basename "$up_file" .up.sql)
        sha=$(sha256sum "$up_file" | awk '{print $1}')
        # Wrap in a single transaction: apply + record in schema_version.
        sql_tmp=$(mktemp)
        cat > "$sql_tmp" <<SQL
BEGIN;
\i $up_file
INSERT INTO schema_version (name, event_type, actor_user_id, file_sha256)
VALUES ('$name', 'applied', NULL, '$sha');
COMMIT;
SQL
        if ! psql -v ON_ERROR_STOP=1 \
                  --username "$POSTGRES_USER" \
                  --dbname "$POSTGRES_DB" \
                  -f "$sql_tmp" > /dev/null; then
            echo "FATAL: migration '$name' failed to apply" >&2
            rm -f "$sql_tmp"
            exit 4
        fi
        rm -f "$sql_tmp"
        count=$((count + 1))
        echo "  ✓ applied: $name (sha=${sha:0:16}…)"
    done
    echo "Applied $count migration(s)."
fi

# Sync the polaris_app role password to the prod secret. 09_grants.sql created
# the role with the dev default ('polaris_dev_password'); the app and pgbouncer
# both authenticate as polaris_app with the generated /run/secrets/polaris_db_password.
# Without this rotation the role keeps the dev password while everything else
# presents the generated one — authentication fails (or, worse, the dev password
# is what is live in production).
#
# v9.85 — read the file-mounted secret first (the *_FILE convention the rest of
# the prod stack uses, G28). docker-compose.prod.yml points
# POLARIS_APP_PASSWORD_FILE at the SAME /run/secrets/polaris_db_password the app
# and pgbouncer read, so the role's password ends up equal to theirs. `cat`
# command substitution strips the trailing newline, matching the app's
# _read_secret_file().read().strip(), so the two values compare byte-for-byte.
if [ -n "$POLARIS_APP_PASSWORD_FILE" ] && [ -r "$POLARIS_APP_PASSWORD_FILE" ]; then
    POLARIS_APP_PASSWORD="$(cat "$POLARIS_APP_PASSWORD_FILE")"
fi

if [ -n "$POLARIS_APP_PASSWORD" ] && [ "$POLARIS_APP_PASSWORD" != "polaris_dev_password" ]; then
    # F-13: password complexity gate. The polaris_app role can read every row in
    # the schema, so a weak password is the whole database one guess away.
    #   - absolute floor: 16 characters.
    #   - under 24 chars (human-chosen territory): also require a digit, a
    #     letter, and a symbol, to resist dictionary attacks.
    #   - 24+ chars: length alone is the entropy. The generated secret is 48 hex
    #     chars (openssl rand -hex 24, ~192 bits) and has NO symbol by
    #     construction, so a blanket symbol rule would reject our own secret.
    if [ ${#POLARIS_APP_PASSWORD} -lt 16 ]; then
        echo "FATAL: POLARIS_APP_PASSWORD must be at least 16 characters." >&2
        exit 2
    fi
    if [ ${#POLARIS_APP_PASSWORD} -lt 24 ]; then
        if ! echo "$POLARIS_APP_PASSWORD" | grep -q '[0-9]'; then
            echo "FATAL: POLARIS_APP_PASSWORD under 24 chars must contain a digit." >&2
            exit 2
        fi
        if ! echo "$POLARIS_APP_PASSWORD" | grep -q '[A-Za-z]'; then
            echo "FATAL: POLARIS_APP_PASSWORD under 24 chars must contain a letter." >&2
            exit 2
        fi
        if ! echo "$POLARIS_APP_PASSWORD" | grep -q '[^A-Za-z0-9]'; then
            echo "FATAL: POLARIS_APP_PASSWORD under 24 chars must contain a symbol." >&2
            exit 2
        fi
    fi

    echo "Rotating polaris_app password..."
    # Pass via env-var to psql to avoid showing it in process listings or logs.
    PGPASSWORD_NEW="$POLARIS_APP_PASSWORD" psql -v ON_ERROR_STOP=1 \
         --username "$POSTGRES_USER" \
         --dbname "$POSTGRES_DB" \
         -c "ALTER ROLE polaris_app WITH PASSWORD '$POLARIS_APP_PASSWORD'" \
         > /dev/null  # suppress any echo of the SQL
fi

# v9.126 — streaming-replication readiness. When the operator provides a
# replication secret, make THIS primary replication-ready: set the WAL params a
# standby needs (persisted via ALTER SYSTEM and applied on the real server start,
# exactly like the TLS block above), create a least-privilege REPLICATION role
# from the file-mounted secret, and allow it in pg_hba. The STANDBY HOST itself
# is operator-gated (a second machine; co-locating it gives no HA) — it is
# bootstrapped with `pg_basebackup -R` per docs/operator/FAILOVER.md. Optional:
# with no replicator secret, this is a single node and nothing is touched.
REPL_PWFILE="${POLARIS_REPLICATOR_PASSWORD_FILE:-}"
if [ "$MANAGED" != "patroni" ] && [ -n "$REPL_PWFILE" ] && [ -r "$REPL_PWFILE" ]; then
    REPL_PW="$(cat "$REPL_PWFILE")"
    if [ ${#REPL_PW} -lt 16 ]; then
        echo "FATAL: the replication password must be at least 16 characters." >&2
        exit 2
    fi
    # The pg_hba CIDR is operator-controlled: 'samenet' covers a standby on the
    # same compose network; a remote standby needs its real CIDR. Validate it so
    # a bad value is a loud config error, not a corrupt pg_hba line.
    REPL_CIDR="${POLARIS_REPLICATION_CIDR:-samenet}"
    case "$REPL_CIDR" in
        ''|*[!A-Za-z0-9./:_-]*) echo "FATAL: POLARIS_REPLICATION_CIDR has invalid characters." >&2; exit 2 ;;
    esac
    echo "Enabling streaming-replication readiness (wal_level=replica + polaris_replicator role)..."
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" >/dev/null \
        -c "ALTER SYSTEM SET wal_level = replica;" \
        -c "ALTER SYSTEM SET max_wal_senders = 10;" \
        -c "ALTER SYSTEM SET max_replication_slots = 10;" \
        -c "ALTER SYSTEM SET hot_standby = on;" \
        -c "ALTER SYSTEM SET wal_log_hints = on;"
    # The replication role. docker-init runs once on a fresh data dir, so the role
    # does not pre-exist; the secret is hex (no quote to escape), matching the
    # polaris_app rotation above.
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" >/dev/null \
        -c "CREATE ROLE polaris_replicator WITH LOGIN REPLICATION PASSWORD '$REPL_PW'"
    # Allow the replication role in pg_hba (idempotent: append only if absent).
    PG_HBA="${PGDATA:-/var/lib/postgresql/data}/pg_hba.conf"
    HBA_LINE="host replication polaris_replicator $REPL_CIDR scram-sha-256"
    if [ -f "$PG_HBA" ] && ! grep -qF "$HBA_LINE" "$PG_HBA"; then
        echo "$HBA_LINE" >> "$PG_HBA"
    fi
    echo "Streaming-replication readiness enabled (standby host is operator-supplied; see FAILOVER.md)."
fi

# v9.126+ — continuous WAL archiving (pgBackRest). OFF unless the operator opts
# in (after provisioning the repo + running stanza-create), so a deployment with
# no repo does not pile up unarchivable WAL. Sets archive_mode (restart-only;
# persisted via ALTER SYSTEM and applied on the real server start, like the TLS
# block) + the archive_command that pushes WAL through the stanza config mounted
# at /etc/pgbackrest/pgbackrest.conf. The stanza-create + scheduled backups are
# the operator's steps (docs/operator/DR.md); the CI round-trip proves the path.
if [ "$MANAGED" != "patroni" ] && [ "${POLARIS_PGBACKREST_ENABLED:-0}" = "1" ]; then
    echo "Enabling continuous WAL archiving via pgBackRest (archive_mode=on)..."
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" >/dev/null \
        -c "ALTER SYSTEM SET archive_mode = on;" \
        -c "ALTER SYSTEM SET archive_command = 'pgbackrest --stanza=polaris archive-push %p';" \
        -c "ALTER SYSTEM SET wal_level = replica;" \
        -c "ALTER SYSTEM SET max_wal_senders = 10;" \
        -c "ALTER SYSTEM SET archive_timeout = '60s';"
    # v9.192 (roadmap P1.10): archive_timeout is what BOUNDS the RPO. Without it a
    # quiet primary archives a segment only when 16 MB of WAL fills, which on a
    # small authority can be hours; with it, any partially filled segment is
    # switched and pushed within 60 s, so the recovery point is never more than
    # about a minute behind. scripts/polaris-dr-drill.sh measures it monthly.
    echo "WAL archiving enabled. Run 'pgbackrest --stanza=polaris stanza-create' + schedule backups (DR.md)."
    # v9.130 — warn loudly if the repo is LOCAL (no repo1-type=s3). A local repo
    # on the DB host does not survive host loss, so it is not the offsite
    # durability an operator enabling archiving usually expects.
    # v9.173 — the repo location is rendered into conf.d/repo.conf by the image
    # entrypoint from POLARIS_PGBACKREST_S3_* env (P0.9), so look there too.
    if ! grep -qsE '^[[:space:]]*repo1-type[[:space:]]*=[[:space:]]*s3' \
            /etc/pgbackrest/pgbackrest.conf /etc/pgbackrest/conf.d/*.conf; then
        echo "WARNING: pgBackRest archiving is enabled but the repo is LOCAL (no repo1-type=s3)." >&2
        echo "         A local repo does NOT survive host loss. Set POLARIS_PGBACKREST_S3_BUCKET," >&2
        echo "         _ENDPOINT and _REGION on the postgres service and put the S3 credentials" >&2
        echo "         in secrets/pgbackrest_repo_creds.conf for real durability (DR.md)." >&2
    fi
fi

# Production hardening (BLOCKER): the SQL seed (10_auth.sql) loads three demo
# accounts with PUBLICLY-KNOWN passwords (admin/Admin@123!, operator/Operator@123!,
# auditor/Auditor@123!) — and 04_data.sql enrolls a demo duress code. Fine for
# dev; in production that is an instant full compromise. In production mode we
# neutralize them: disable login (is_active=FALSE), scramble the password to a
# random unusable value (so re-enabling does not restore the known password), and
# lock the account. We do NOT delete the rows — append-only audit tables FK to
# AppUser (ON DELETE NO ACTION) and audit history must survive. The operator then
# bootstraps the real first admin with scripts/polaris-create-operator.sh. No
# default credentials ship; /login refuses everyone until a real admin exists.
if [ "${POLARIS_ENV:-}" = "production" ]; then
    echo "Production mode: neutralizing demo accounts (disable + scramble password)..."
    psql -v ON_ERROR_STOP=1 \
         --username "$POSTGRES_USER" \
         --dbname "$POSTGRES_DB" >/dev/null <<'SQL'
    UPDATE AppUser
       SET is_active     = FALSE,
           password_hash = 'DISABLED:' || gen_random_uuid()::text,
           locked_until  = 'infinity'::timestamptz
     WHERE username IN ('admin', 'operator', 'auditor');
    -- Retire any demo duress-code enrollment so a publicly-known duress code does
    -- not silently flag real verifications. IdentityToken holds the duress hash.
    UPDATE IdentityToken SET duress_code_hash = NULL WHERE duress_code_hash IS NOT NULL;
SQL
    echo "  Demo accounts disabled. Create the first real admin before use:"
    echo "    scripts/polaris-create-operator.sh --role admin --username <name>"
fi

echo "Polaris init complete."
