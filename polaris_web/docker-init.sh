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
# Lab record 017 (managed PostgreSQL): scripts/polaris-db-init.sh runs this script against a
# database the operator's provider runs, as its owner, with POLARIS_INIT_MANAGED_BY=external
# and POLARIS_SQL_DIR naming the checkout's polaris_sql; psql then reaches the server through
# PGHOST and the other libpq variables. The server's configuration is the provider's, so the
# same three blocks are skipped.
MANAGED="${POLARIS_INIT_MANAGED_BY:-}"
case "$MANAGED" in
    ""|patroni|external) ;;
    # An unknown mode would skip the bundled server's TLS, replication and archiving silently.
    *) echo "FATAL: POLARIS_INIT_MANAGED_BY must be empty, patroni or external (got '$MANAGED')." >&2; exit 2 ;;
esac
SQL_DIR="${POLARIS_SQL_DIR:-/docker-entrypoint-initdb.d/sql}"

# The polaris_app password is read and judged before anything is written: a refusal after the
# schema had loaded would leave a half-initialised database, which the image never initialises
# again. It is set after the migrations, below.
#
# Syncing the polaris_app role password to the prod secret. 09_grants.sql created
# the role with the dev default ('polaris_dev_password'); the app and pgbouncer
# both authenticate as polaris_app with the generated /run/secrets/polaris_db_password.
# Without this rotation the role keeps the dev password while everything else
# presents the generated one: authentication fails (or, worse, the dev password
# is what is live in production).
#
# v9.85: read the file-mounted secret first (the *_FILE convention the rest of
# the prod stack uses, G28). docker-compose.prod.yml points
# POLARIS_APP_PASSWORD_FILE at the SAME /run/secrets/polaris_db_password the app
# and pgbouncer read, so the role's password ends up equal to theirs. `cat`
# command substitution strips the trailing newline; the leading and trailing whitespace go too, as
# the app's _read_secret_file().read().strip() drops them, so the two values compare byte-for-byte.
if [ -n "$POLARIS_APP_PASSWORD_FILE" ] && [ -r "$POLARIS_APP_PASSWORD_FILE" ]; then
    POLARIS_APP_PASSWORD="$(cat "$POLARIS_APP_PASSWORD_FILE")"
fi
POLARIS_APP_PASSWORD="${POLARIS_APP_PASSWORD#"${POLARIS_APP_PASSWORD%%[![:space:]]*}"}"
POLARIS_APP_PASSWORD="${POLARIS_APP_PASSWORD%"${POLARIS_APP_PASSWORD##*[![:space:]]}"}"
# In production polaris_app never keeps the public development password: an empty or absent secret
# (a file holding only a newline) is refused before anything is written, not skipped.
if [ "${POLARIS_ENV:-}" = "production" ] \
        && { [ -z "$POLARIS_APP_PASSWORD" ] || [ "$POLARIS_APP_PASSWORD" = "polaris_dev_password" ]; }; then
    echo "FATAL: production needs polaris_app's password (POLARIS_APP_PASSWORD_FILE): it is empty or the public development one." >&2
    exit 2
fi

ROTATE_APP_PASSWORD=0
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

    # Printable ASCII only: the verifier below is computed over the password's bytes, and libpq
    # normalises other characters (SASLprep) before it proves them. The generated secret is hex.
    if printf '%s' "$POLARIS_APP_PASSWORD" | LC_ALL=C grep -q '[^ -~]'; then
        echo "FATAL: POLARIS_APP_PASSWORD must be printable ASCII." >&2
        exit 2
    fi
    command -v python3 > /dev/null \
        || { echo "FATAL: python3 computes polaris_app's SCRAM verifier and is not on PATH." >&2; exit 2; }
    ROTATE_APP_PASSWORD=1
fi

# polaris_app gets its password BEFORE the schema loads. 09_grants.sql creates the role with the
# development password only when it does not exist, so creating it here first means that password is
# never set: not while the load runs, and not after a load or a migration that fails (a role is the
# cluster's, and outlives a dropped database). The server receives a SCRAM-SHA-256 verifier computed
# here, as psql's \password sends one, never the password: it reaches neither a command line nor the
# statement a server may log (on a managed database, the provider's log). The password travels to
# python on stdin.
if [ "$ROTATE_APP_PASSWORD" = 1 ]; then
    echo "Setting polaris_app's password..."
    verifier=$(printf '%s' "$POLARIS_APP_PASSWORD" | python3 -c '
import base64, hashlib, hmac, os, sys
pw = sys.stdin.buffer.read(); salt = os.urandom(16); n = 4096
salted = hashlib.pbkdf2_hmac("sha256", pw, salt, n)
ck = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
sk = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
b64 = lambda x: base64.b64encode(x).decode()
print("SCRAM-SHA-256$%d:%s$%s:%s" % (n, b64(salt), b64(hashlib.sha256(ck).digest()), b64(sk)))')
    if [ -n "$(psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -qtAc \
                 "SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app'")" ]; then
        app_role_sql="ALTER ROLE polaris_app WITH PASSWORD '%s';\n"
    else
        app_role_sql="CREATE ROLE polaris_app WITH LOGIN PASSWORD '%s';\n"
    fi
    printf "$app_role_sql" "$verifier" \
        | psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -q > /dev/null
fi

echo "Loading Polaris SQL package..."

# 00_load_all.sql uses \i with relative paths, so we cd into the SQL directory
# before invoking psql.
cd "$SQL_DIR"
psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     -f "$SQL_DIR/00_load_all.sql"

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
elif [ "$MANAGED" = "external" ]; then
    echo "TLS, replication and archiving are the database provider's; skipping ALTER SYSTEM."
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
MIG_DIR="$SQL_DIR/migrations"
if [ -d "$MIG_DIR" ]; then
    echo "Applying schema migrations..."
    count=0
    for up_file in "$MIG_DIR"/*.up.sql; do
        [ -f "$up_file" ] || continue
        name=$(basename "$up_file" .up.sql)
        # sha256sum on Linux and in the image; shasum where an operator's host has only that.
        sha=$( (sha256sum "$up_file" 2>/dev/null || shasum -a 256 "$up_file") | awk '{print $1}')
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

# v9.126 — streaming-replication readiness. When the operator provides a
# replication secret, make THIS primary replication-ready: set the WAL params a
# standby needs (persisted via ALTER SYSTEM and applied on the real server start,
# exactly like the TLS block above), create a least-privilege REPLICATION role
# from the file-mounted secret, and allow it in pg_hba. The STANDBY HOST itself
# is operator-gated (a second machine; co-locating it gives no HA) — it is
# bootstrapped with `pg_basebackup -R` per docs/operator/FAILOVER.md. Optional:
# with no replicator secret, this is a single node and nothing is touched.
REPL_PWFILE="${POLARIS_REPLICATOR_PASSWORD_FILE:-}"
if [ -z "$MANAGED" ] && [ -n "$REPL_PWFILE" ] && [ -r "$REPL_PWFILE" ]; then
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

# v9.126+ — continuous WAL archiving (pgBackRest). ON by default since lab record
# 017 (gate row OP-14; POLARIS_PGBACKREST_ENABLED=0 turns it off). Sets
# archive_mode (restart-only; persisted via ALTER SYSTEM and applied on the real
# server start, like the TLS block) + the archive_command that pushes WAL through
# the stanza config mounted at /etc/pgbackrest/pgbackrest.conf, and creates the
# stanza here, against this init server, so the first real start archives rather
# than piling up WAL. The base backups are polaris-deploy.sh's (the first) and
# polaris-backup.sh's (the scheduled ones); the CI round-trip proves the path.
if [ -z "$MANAGED" ] && [ "${POLARIS_PGBACKREST_ENABLED:-1}" = "1" ]; then
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
    # The stanza, now: stanza-create reads this server's identity over its socket and does not
    # need archiving to be active yet. Best effort: an unreachable offsite repository must not
    # stop the database from initialising; polaris-deploy.sh runs stanza-create and check again.
    if pgbackrest --stanza=polaris stanza-create >/dev/null 2>&1; then
        echo "WAL archiving enabled; pgBackRest stanza created."
    else
        echo "WARNING: WAL archiving is enabled but stanza-create failed; WAL will accumulate until" >&2
        echo "         'pgbackrest --stanza=polaris stanza-create' succeeds (polaris-deploy.sh retries it)." >&2
    fi
    # v9.130 — warn loudly if the repo is LOCAL (no repo1-type=s3). A local repo
    # on the DB host does not survive host loss, so it is not the offsite
    # durability an operator enabling archiving usually expects.
    # v9.173 — the repo location is rendered into conf.d/repo.conf by the image
    # entrypoint from POLARIS_PGBACKREST_S3_* env (P0.9), so look there too.
    # 2026-10-10: the bucket is repo2 beside the local repo1, so any repo index counts.
    if ! grep -qsE '^[[:space:]]*repo[0-9]+-type[[:space:]]*=[[:space:]]*s3' \
            /etc/pgbackrest/pgbackrest.conf /etc/pgbackrest/conf.d/*.conf; then
        echo "WARNING: pgBackRest archiving is enabled but the repo is LOCAL (no S3 repo configured)." >&2
        echo "         A local repo does NOT survive host loss. Set POLARIS_PGBACKREST_S3_BUCKET," >&2
        echo "         _ENDPOINT and _REGION on the postgres service and put the S3 credentials and" >&2
        echo "         repo2-cipher-pass in secrets/pgbackrest_repo_creds.conf for real durability (DR.md)." >&2
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
# The sample also sets the zero-knowledge anonymity floor to ONE so its handful of
# credentials can close an epoch (04_data.sql says why); production puts back the
# default of 20, or every epoch it closed could identify its members by elimination.
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
    -- The sample's anonymity floor of ONE goes; the procedures read the database's setting.
    DO $$
    BEGIN
        EXECUTE format('ALTER DATABASE %I SET polaris.min_epoch_anonymity_set = 20', current_database());
    END$$;
SQL
    echo "  Zero-knowledge anonymity floor: 20 (the notional sample's 1 does not carry into production)."
    echo "  Demo accounts disabled. Create the first real admin before use:"
    echo "    scripts/polaris-create-operator.sh --role admin --username <name>"
fi

echo "Polaris init complete."
