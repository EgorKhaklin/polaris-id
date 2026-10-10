#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-restore.sh — recovery-from-backup with manifest verification
#
# v8.81 / Arc B Phase 1.5 (completes the v8.77 backup/restore loop).
# Inverse of polaris-backup.sh. Reads a timestamped tarball produced by
# polaris-backup.sh, verifies every component's SHA-256 hash against
# the in-band MANIFEST.json, then restores:
#
#   - PostgreSQL database (pg_restore from the custom-format dump)
#
# Refuses to clobber a non-empty database without --force.
#
# Usage:
#   ./scripts/polaris-restore.sh BACKUP_FILE [options]
#
# Options:
#   --target=<db_name>      Target database to restore into (default: polaris)
#   --target=docker-stack   Restore via the running docker-compose.prod.yml
#                           Postgres container instead of a host-level DB
#   --force                 Allow restore over a non-empty DB (DANGEROUS)
#   --dry-run               Verify manifest + list what would be restored,
#                           but make no changes
#   --skip-db               Skip database restore (FS-AoR only)
#   --verify-schema-version Cross-check schema_version table against
#                           migrations/*.up.sql on disk after restore.
#                           Exits EXIT_SCHEMA_MISMATCH=10 if divergent or unreadable
#                           (prevents serving half-restored DB). v9.23.
#
# Every database restore keeps the backup's privileges: the target's schema default privileges are
# cleared before pg_restore (the dump restores its own), and afterwards every table, column, routine
# and sequence the dump holds, the public schema and the default privileges must carry the ACLs the
# same dump gives a new database. Otherwise EXIT_PRIVILEGE_MISMATCH=11.
#
# And the backup's database settings (database-settings.json: ALTER DATABASE ... SET and ALTER ROLE
# ... IN DATABASE ... SET, which pg_restore applies only with --create): the target's are replaced by
# them and read back. A file that cannot be read or applied, that records none, or settings that read
# back otherwise, exit EXIT_SETTINGS_MISMATCH=12. A backup taken before they were recorded leaves the
# target's as they are.
#
# Examples:
#   ./scripts/polaris-restore.sh /var/backups/polaris-20260514T030000Z.tar.gz
#   ./scripts/polaris-restore.sh polaris-backup.tar.gz --target=polaris_restored
#   ./scripts/polaris-restore.sh latest.tar.gz --target=docker-stack
#   ./scripts/polaris-restore.sh latest.tar.gz --dry-run
#
# Pattern: every step prints a "[step N/M] ..." line; on any failure
# the script exits non-zero with a numbered exit code (see EXIT_*).
# ============================================================================

set -euo pipefail

# Exit codes (greppable in incident response).
EXIT_OK=0
EXIT_USAGE=2
EXIT_BACKUP_MISSING=3
EXIT_MANIFEST_MISSING=4
EXIT_MANIFEST_VERIFY_FAIL=5
EXIT_NON_EMPTY_DB=6
EXIT_DB_RESTORE_FAIL=7
EXIT_FS_RESTORE_FAIL=8
EXIT_DOCKER_MISSING=9
EXIT_SCHEMA_MISMATCH=10   # v9.23 — schema_version table vs migrations/ diverged
EXIT_PRIVILEGE_MISMATCH=11   # the restored privileges are not the backup's, or cannot be read or made so
EXIT_SETTINGS_MISMATCH=12    # the restored database settings are not the backup's, or cannot be read or applied

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
# Run by hand (sudo resets the environment), read the configuration polaris.service runs with.
source "${SCRIPT_DIR}/polaris-env.sh"
COMPOSE_FILE="${POLARIS_ROOT}/polaris_web/docker-compose.prod.yml"

# Defaults.
TARGET_DB="polaris"
USE_DOCKER_STACK=0
DRY_RUN=0
FORCE=0
SKIP_FS=0
SKIP_DB=0
VERIFY_SCHEMA=0   # v9.23 — opt-in schema_version cross-check after restore
BACKUP_FILE=""

usage() {
    sed -n '2,41p' "$0" | sed 's/^# \{0,1\}//'
    exit "${EXIT_USAGE}"
}

# Parse args.
for arg in "$@"; do
    case "${arg}" in
        --target=docker-stack) USE_DOCKER_STACK=1 ;;
        --target=*)            TARGET_DB="${arg#--target=}" ;;
        --force)               FORCE=1 ;;
        --dry-run)             DRY_RUN=1 ;;
        --skip-fs)             SKIP_FS=1 ;;
        --skip-db)             SKIP_DB=1 ;;
        --verify-schema-version) VERIFY_SCHEMA=1 ;;   # v9.23
        --help|-h)             usage ;;
        -*)                    echo "error: unknown option ${arg}" >&2; usage ;;
        *)
            if [[ -z "${BACKUP_FILE}" ]]; then
                BACKUP_FILE="${arg}"
            else
                echo "error: only one backup file may be specified" >&2
                usage
            fi
            ;;
    esac
done

if [[ -z "${BACKUP_FILE}" ]]; then
    echo "error: backup file is required" >&2
    usage
fi
if [[ ! -f "${BACKUP_FILE}" ]]; then
    echo "error: backup file not found: ${BACKUP_FILE}" >&2
    exit "${EXIT_BACKUP_MISSING}"
fi

BACKUP_FILE="$(cd "$(dirname "${BACKUP_FILE}")" && pwd)/$(basename "${BACKUP_FILE}")"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

step() { echo "  [${1}] ${2}"; }

run_psql() {
    if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
        docker compose -f "${COMPOSE_FILE}" exec -T postgres \
            psql -U postgres "$@"
    else
        psql -U "${PGUSER:-postgres}" -d "${TARGET_DB}" "$@" 2>&1 || true
    fi
}

run_pg_restore() {
    local dump="$1"
    if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
        docker compose -f "${COMPOSE_FILE}" exec -T postgres \
            pg_restore -U postgres -d "${TARGET_DB}" --clean --if-exists < "${dump}"
    else
        pg_restore -U "${PGUSER:-postgres}" -d "${TARGET_DB}" --clean --if-exists "${dump}"
    fi
}

# psql on one database, its status psql's own, columns tab-separated.
db_sql() {  # db_sql DB SQL
    if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
        docker compose -f "${COMPOSE_FILE}" exec -T postgres psql -U postgres -d "$1" -X -At -v ON_ERROR_STOP=1 -F $'\t' -c "$2"
    else
        psql -U "${PGUSER:-postgres}" -d "$1" -X -At -v ON_ERROR_STOP=1 -F $'\t' -c "$2"
    fi
}

# The dump's schema alone, into a new database: the privileges it gives a database that has no
# default privileges of its own.
scratch_schema_restore() {  # scratch_schema_restore DB DUMP
    if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
        docker compose -f "${COMPOSE_FILE}" exec -T postgres \
            pg_restore -U postgres -d "$1" --schema-only < "$2"
    else
        pg_restore -U "${PGUSER:-postgres}" -d "$1" --schema-only "$2"
    fi
}

# The dump's table of contents (pg_restore -l reads no database).
dump_contents() {  # dump_contents DUMP
    if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
        docker compose -f "${COMPOSE_FILE}" exec -T postgres pg_restore -U postgres -l < "$1"
    else
        pg_restore -U "${PGUSER:-postgres}" -l "$1"
    fi
}

# The target's default privileges, set aside before pg_restore. pg_restore --clean recreates every
# table, sequence and routine of the dump, and a new object takes the database's default privileges:
# 09_grants.sql's give polaris_app SELECT, INSERT, UPDATE and DELETE on new tables and EXECUTE on new
# routines. pg_dump writes each object's grants as a difference from PostgreSQL's built-in default,
# so the revokes that narrowed polaris_app were never replayed: until 2026-10-10 a restore into an
# initialised database (the stack's, after its first start) gave it back write access to the
# append-only tables, the counts and the owner-only routines, and UPDATE on every column of AppUser.
# The dump restores its own default privileges, with its grants, at the end. Database-wide ones
# (ALTER DEFAULT PRIVILEGES without IN SCHEMA) change what every new object starts with in a way
# this cannot undo, so they are refused.
CLEAR_DEFAULT_PRIVILEGES=$(cat <<'SQL'
DO $clear$
DECLARE r record;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_default_acl WHERE defaclnamespace = 0) THEN
        RAISE EXCEPTION 'database-wide default privileges are set for %: remove them, or restore into a new database (--target=NAME)',
            (SELECT string_agg(DISTINCT defaclrole::regrole::text, ', ') FROM pg_default_acl WHERE defaclnamespace = 0);
    END IF;
    FOR r IN
        SELECT DISTINCT d.defaclrole::regrole::text AS owner, n.nspname AS nsp,
               CASE d.defaclobjtype WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES'
                                    WHEN 'f' THEN 'FUNCTIONS' WHEN 'T' THEN 'TYPES' END AS kind,
               CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END AS grantee
          FROM pg_default_acl d JOIN pg_namespace n ON n.oid = d.defaclnamespace
          CROSS JOIN LATERAL aclexplode(d.defaclacl) a
    LOOP
        EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %I REVOKE ALL ON %s FROM %s',
                       r.owner, r.nsp, r.kind, r.grantee);
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_default_acl) THEN
        RAISE EXCEPTION 'default privileges remain after they were cleared';
    END IF;
END
$clear$;
SQL
)

# What the privilege check reads in either database: the ACL as stored of every table, view, sequence
# and routine of the public schema and of every column with grants of its own, each keyed by the
# object it belongs to; and the public schema's and the default privileges, which are always compared.
PRIVILEGE_FACTS=$(cat <<'SQL'
SELECT 'relation ' || c.oid::regclass::text, 'relation ' || c.oid::regclass::text, coalesce(c.relacl::text, '-')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
UNION ALL
SELECT 'relation ' || c.oid::regclass::text, 'column ' || c.oid::regclass::text || '.' || quote_ident(a.attname), a.attacl::text
  FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND a.attnum > 0 AND NOT a.attisdropped AND a.attacl IS NOT NULL
UNION ALL
SELECT 'routine ' || p.oid::regprocedure::text, 'routine ' || p.oid::regprocedure::text, coalesce(p.proacl::text, '-')
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
UNION ALL
SELECT '*', 'schema public', coalesce(nspacl::text, '-') FROM pg_namespace WHERE nspname = 'public'
UNION ALL
SELECT '*', 'default privileges of ' || d.defaclrole::regrole::text || ' in ' || coalesce(n.nspname, 'every schema')
       || ' on ' || d.defaclobjtype::text, d.defaclacl::text
  FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
 ORDER BY 2
SQL
)
SCRATCH_DB=""
SETTINGS_HELPER="${SCRIPT_DIR}/polaris_db_settings.py"

cat <<BANNER

  Polaris — restore from backup
  ─────────────────────────────
  Backup:      ${BACKUP_FILE}
  Target DB:   ${TARGET_DB}$([[ "${USE_DOCKER_STACK}" -eq 1 ]] && echo " (via docker compose stack)" || echo "")
  Dry run:     $([[ "${DRY_RUN}" -eq 1 ]] && echo yes || echo no)
  Force:       $([[ "${FORCE}" -eq 1 ]] && echo yes || echo no)
  Skip DB:     $([[ "${SKIP_DB}" -eq 1 ]] && echo yes || echo no)

BANNER

# ---------------------------------------------------------------------------
# Step 1: Extract + verify manifest
# ---------------------------------------------------------------------------
WORK=$(mktemp -d)
cleanup() {
    rm -rf "${WORK}"
    if [[ -n "${SCRATCH_DB}" ]]; then
        db_sql postgres "DROP DATABASE IF EXISTS \"${SCRATCH_DB}\"" > /dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

step "1/6" "extracting ${BACKUP_FILE} → ${WORK}…"
# Encrypted backups (.enc, produced when POLARIS_BACKUP_KEY_FILE was set at
# backup time) must be decrypted before extraction. Decrypt to a temp tarball
# using the same key; the MANIFEST SHA-256 check below then catches any tamper.
EXTRACT_SRC="${BACKUP_FILE}"
if [[ "${BACKUP_FILE}" == *.enc ]]; then
    KEY_FILE="${POLARIS_BACKUP_KEY_FILE:-}"
    if [[ -z "${KEY_FILE}" || ! -r "${KEY_FILE}" ]]; then
        echo "  ✗ ${BACKUP_FILE} is encrypted but POLARIS_BACKUP_KEY_FILE is unset/unreadable" >&2
        exit "${EXIT_MANIFEST_MISSING}"
    fi
    EXTRACT_SRC="${WORK}/decrypted.tar.gz"
    if ! openssl enc -d -aes-256-cbc -pbkdf2 \
            -in "${BACKUP_FILE}" -out "${EXTRACT_SRC}" -pass "file:${KEY_FILE}"; then
        echo "  ✗ decryption failed — wrong key, or the backup is corrupt/tampered" >&2
        exit "${EXIT_MANIFEST_MISSING}"
    fi
    echo "  ✓ decrypted encrypted backup"
fi
tar -xzf "${EXTRACT_SRC}" -C "${WORK}"

# Find the extracted polaris-<ts>/ directory.
EXTRACTED=$(find "${WORK}" -maxdepth 1 -mindepth 1 -type d -name 'polaris-*' | head -1)
if [[ -z "${EXTRACTED}" || ! -d "${EXTRACTED}" ]]; then
    echo "  ✗ extracted backup does not contain a polaris-*/ directory" >&2
    exit "${EXIT_MANIFEST_MISSING}"
fi

step "2/6" "verifying MANIFEST.json (SHA-256 hashes)…"
if [[ ! -f "${EXTRACTED}/MANIFEST.json" ]]; then
    echo "  ✗ MANIFEST.json missing — backup is malformed" >&2
    exit "${EXIT_MANIFEST_MISSING}"
fi

# Use the same verifier Python embeds in polaris-backup.sh.
if ! python3 - "${EXTRACTED}" <<'PY'
import json, hashlib, os, sys
base = sys.argv[1]
with open(os.path.join(base, "MANIFEST.json")) as f:
    m = json.load(f)
ok = True
for name, expected in m.get("sha256", {}).items():
    p = os.path.join(base, name)
    if not os.path.exists(p):
        print(f"  ✗ {name} missing from archive")
        ok = False
        continue
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    got = h.hexdigest()
    if got != expected:
        print(f"  ✗ {name} hash mismatch  expected={expected[:16]}  got={got[:16]}")
        ok = False
    else:
        print(f"  ✓ {name}  ({m.get('size_bytes', {}).get(name, '?')} bytes)")
# The settings the restore replays must be the ones the backup hashed, not a file put beside them.
if os.path.exists(os.path.join(base, "database-settings.json")) and "database-settings.json" not in m.get("sha256", {}):
    print("  ✗ database-settings.json is not covered by the manifest")
    ok = False
print()
print(f"  manifest declares Polaris version: {m.get('polaris_version', 'unknown')}")
print(f"  manifest timestamp:                {m.get('timestamp_utc',  'unknown')}")
if not ok:
    sys.exit(1)
PY
then
    echo "  ✗ manifest verification failed — refusing to proceed" >&2
    exit "${EXIT_MANIFEST_VERIFY_FAIL}"
fi

# ---------------------------------------------------------------------------
# Step 3: Dry-run summary or proceed
# ---------------------------------------------------------------------------
if [[ "${DRY_RUN}" -eq 1 ]]; then
    step "3/6" "dry-run — listing what would be restored…"
    echo
    echo "  Would restore the following components:"
    [[ "${SKIP_DB}" -eq 0 ]] && \
        echo "    • PostgreSQL dump  →  database '${TARGET_DB}'"
    if [[ "${SKIP_DB}" -eq 0 && -f "${EXTRACTED}/database-settings.json" ]]; then
        echo "    • database settings (database-settings.json)  →  database '${TARGET_DB}', replacing its own"
    elif [[ "${SKIP_DB}" -eq 0 ]]; then
        echo "    • no database settings recorded (an older backup): '${TARGET_DB}' keeps its own"
    fi
    echo
    echo "  Dry-run complete. Re-run without --dry-run to apply."
    exit "${EXIT_OK}"
fi

# ---------------------------------------------------------------------------
# Step 4: DB pre-flight (non-empty check)
# ---------------------------------------------------------------------------
if [[ "${SKIP_DB}" -eq 0 ]]; then
    if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
        if ! command -v docker >/dev/null 2>&1; then
            echo "  ✗ docker not on PATH (required for --target=docker-stack)" >&2
            exit "${EXIT_DOCKER_MISSING}"
        fi
        # Capture before matching: under pipefail a grep -q that leaves early can SIGPIPE compose.
        RUNNING_IDS="$(docker compose -f "${COMPOSE_FILE}" ps --status running --quiet 2>/dev/null || true)"
        if [[ -z "$RUNNING_IDS" ]]; then
            echo "  ✗ docker stack not running (start with polaris-deploy.sh prod)" >&2
            exit "${EXIT_DOCKER_MISSING}"
        fi
    fi

    step "3/6" "pre-flight: checking target DB state…"
    # Count tables in the public schema; >0 means non-empty.
    table_count=$(run_psql -tA -d "${TARGET_DB}" -c \
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" 2>/dev/null | tr -dc '0-9' || echo "0")
    table_count=${table_count:-0}

    if [[ "${table_count}" != "0" ]] && [[ "${FORCE}" -eq 0 ]]; then
        echo "  ✗ target DB '${TARGET_DB}' has ${table_count} tables in public schema."
        echo "     Refusing to clobber. Either:"
        echo "       (a) drop + recreate the target DB before restore:"
        echo "             dropdb ${TARGET_DB} && createdb ${TARGET_DB}"
        echo "       (b) restore into a fresh DB:"
        echo "             $(basename "$0") <backup> --target=polaris_restored"
        echo "       (c) pass --force to overwrite (DANGEROUS)"
        exit "${EXIT_NON_EMPTY_DB}"
    fi

    if [[ "${table_count}" != "0" ]]; then
        echo "  ⚠  target DB has ${table_count} tables; --force is in effect"
    else
        echo "  ✓ target DB is empty"
    fi
else
    step "3/6" "DB restore skipped (--skip-db)"
fi

# ---------------------------------------------------------------------------
# Step 5: Restore PostgreSQL
# ---------------------------------------------------------------------------
if [[ "${SKIP_DB}" -eq 0 ]]; then
    step "4/6" "restoring PostgreSQL → '${TARGET_DB}'…"
    # pg_restore returns non-zero for BENIGN reasons, not just real failures:
    # the --clean --if-exists DROPs of objects that do not exist yet, and
    # version-specific SET directives a newer pg_dump emits that an older target
    # rejects (e.g. `SET transaction_timeout` from a PG17+ dump restored into
    # PG16). pg_restore ignores those ("errors ignored on restore: N") and the
    # DATA still lands. Treating that exit code as failure made a SUCCESSFUL
    # restore report "✗ pg_restore failed — DB state may be partial" and abort —
    # exactly the false alarm a DR tool must not raise. So we capture the code
    # but judge success by VERIFYING THE OUTCOME: the core schema must be present.
    if ! clear_err=$(db_sql "${TARGET_DB}" "${CLEAR_DEFAULT_PRIVILEGES}" 2>&1); then
        echo "  ✗ cannot set aside ${TARGET_DB}'s default privileges, so the restore would not keep the backup's; nothing was restored:" >&2
        printf '%s\n' "${clear_err}" | sed -n '1,5p' | sed 's/^/      /' >&2
        exit "${EXIT_PRIVILEGE_MISMATCH}"
    fi
    pg_restore_rc=0
    run_pg_restore "${EXTRACTED}/polaris.dump" || pg_restore_rc=$?

    restored_tables=$(run_psql -tA -d "${TARGET_DB}" -c \
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" 2>/dev/null | tr -dc '0-9' || echo "0")
    core_present=$(run_psql -tA -d "${TARGET_DB}" -c \
        "SELECT to_regclass('public.identitytoken') IS NOT NULL" 2>/dev/null | tr -d '[:space:]')
    if [[ "${core_present}" != "t" ]]; then
        echo "  ✗ restore FAILED — core table 'identitytoken' is absent after pg_restore" >&2
        echo "    (pg_restore exit=${pg_restore_rc}, ${restored_tables} tables in public schema)" >&2
        exit "${EXIT_DB_RESTORE_FAIL}"
    fi
    if [[ "${pg_restore_rc}" -ne 0 ]]; then
        echo "  ✓ restore complete (${restored_tables} tables; core schema verified present)."
        echo "    Note: pg_restore exited ${pg_restore_rc} on benign warnings (ignored DROPs or a"
        echo "    newer-dump SET directive). The data restored; no action needed."
    else
        echo "  ✓ pg_restore complete (${restored_tables} tables in public schema)"
    fi

    # The backup's database settings. pg_restore applies them only with --create, so until 2026-10-10
    # a restore into a new database lost them, and one into an initialised database kept that
    # database's own. The target's are reset and the backup's set in one transaction, then read back
    # and compared both ways. A file that cannot be read or applied, or settings that read back
    # otherwise, stop the restore here: nothing was changed by a replay that failed.
    step "4.2/6" "database settings: the backup's, on '${TARGET_DB}'…"
    settings_file="${EXTRACTED}/database-settings.json"
    if [[ ! -e "${settings_file}" ]]; then
        echo "  • this backup records no database settings (taken before 2026-10-10): '${TARGET_DB}' keeps its own"
    else
        if ! settings_sql=$(python3 "${SETTINGS_HELPER}" replay "${settings_file}" "${TARGET_DB}" 2>"${WORK}/settings.err") \
           || ! settings_query=$(python3 "${SETTINGS_HELPER}" query 2>>"${WORK}/settings.err"); then
            echo "  ✗ the backup's database settings cannot be read, so they were not restored:" >&2
            sed -n '1,5p' "${WORK}/settings.err" | sed 's/^/      /' >&2
            exit "${EXIT_SETTINGS_MISMATCH}"
        fi
        # Every Polaris database carries 09_grants.sql's settings, so a record of none is a reading
        # that saw nothing: replayed, it would reset the target's to none.
        settings_count=$(python3 "${SETTINGS_HELPER}" count "${settings_file}" 2>/dev/null || echo 0)
        if ! [[ "${settings_count}" =~ ^[0-9]+$ ]] || (( settings_count < 1 )); then
            echo "  ✗ the backup records no database settings, so the target's would be reset to none; '${TARGET_DB}' keeps its own" >&2
            exit "${EXIT_SETTINGS_MISMATCH}"
        fi
        if ! settings_err=$(db_sql "${TARGET_DB}" "${settings_sql}" 2>&1); then
            echo "  ✗ the backup's database settings could not be applied to '${TARGET_DB}', which keeps its own:" >&2
            printf '%s\n' "${settings_err}" | sed -n '1,5p' | sed 's/^/      /' >&2
            exit "${EXIT_SETTINGS_MISMATCH}"
        fi
        if ! restored_settings=$(db_sql "${TARGET_DB}" "${settings_query}" 2>"${WORK}/settings.err"); then
            echo "  ✗ cannot read '${TARGET_DB}'s database settings, so the restore is unverified:" >&2
            sed -n '1,5p' "${WORK}/settings.err" | sed 's/^/      /' >&2
            exit "${EXIT_SETTINGS_MISMATCH}"
        fi
        if ! settings_mismatch=$(printf '%s\n' "${restored_settings}" | python3 "${SETTINGS_HELPER}" compare "${settings_file}" 2>&1); then
            echo "  ✗ the restored database settings are not the backup's:" >&2
            printf '%s\n' "${settings_mismatch}" | sed -n '1,40p' | sed 's/^/      /' >&2
            exit "${EXIT_SETTINGS_MISMATCH}"
        fi
        echo "  ✓ the backup's database settings, restored: ${settings_count}"
    fi

    # The privileges, against what the same dump gives a new database with no default privileges
    # (template0). Every object the backup holds must carry its ACL; objects it does not hold are not
    # this restore's, but the public schema's and the default privileges are compared both ways. A
    # check that cannot run is an unverified restore, never a passed one.
    step "4.5/6" "privileges: the restored database's against the backup's…"
    # A scratch database a killed run left behind (only SIGKILL skips the trap). A run beside this one
    # keeps its own: its DROP fails while that run is connected, and at worst that run exits 11.
    for stale in $(db_sql postgres "SELECT datname FROM pg_database WHERE datname LIKE 'polaris\\_restore\\_privileges\\_%'" 2>/dev/null); do
        db_sql postgres "DROP DATABASE IF EXISTS \"${stale}\"" > /dev/null 2>&1 || true
    done
    SCRATCH_DB="polaris_restore_privileges_$$"
    if ! scratch_err=$(db_sql postgres "CREATE DATABASE \"${SCRATCH_DB}\" TEMPLATE template0" 2>&1); then
        SCRATCH_DB=""
        echo "  ✗ cannot create a scratch database to read the backup's privileges, so the restore is unverified:" >&2
        printf '%s\n' "${scratch_err}" | sed -n '1,5p' | sed 's/^/      /' >&2
        exit "${EXIT_PRIVILEGE_MISMATCH}"
    fi
    scratch_schema_restore "${SCRATCH_DB}" "${EXTRACTED}/polaris.dump" > /dev/null 2>&1 || true   # benign errors, as above
    if ! want_privileges=$(db_sql "${SCRATCH_DB}" "${PRIVILEGE_FACTS}" 2>"${WORK}/privileges.err"); then
        echo "  ✗ cannot read the backup's privileges from a scratch database, so the restore is unverified:" >&2
        sed -n '1,5p' "${WORK}/privileges.err" | sed 's/^/      /' >&2
        exit "${EXIT_PRIVILEGE_MISMATCH}"
    fi
    # The reference must hold every table, sequence, view and routine the dump holds: an object that did
    # not restore into the scratch database would go uncompared, and the check would pass where it could
    # not read. The dump's own table of contents names them (its routines with schema-qualified argument
    # types and ", " between them, as regprocedure writes neither).
    if ! dump_toc=$(dump_contents "${EXTRACTED}/polaris.dump" 2>"${WORK}/privileges.err"); then
        echo "  ✗ cannot list the backup's contents, so the restore is unverified:" >&2
        sed -n '1,5p' "${WORK}/privileges.err" | sed 's/^/      /' >&2
        exit "${EXIT_PRIVILEGE_MISMATCH}"
    fi
    dump_objects=$(printf '%s\n' "${dump_toc}" \
        | sed -n -E 's/^[0-9]+; [0-9]+ [0-9]+ (TABLE|SEQUENCE|VIEW|MATERIALIZED VIEW|FOREIGN TABLE) public ([^ ]+) [^ ]+$/relation \2/p; s/^[0-9]+; [0-9]+ [0-9]+ (FUNCTION|PROCEDURE|AGGREGATE) public (.+) [^ ]+$/routine \2/p' \
        | sed -E '/^routine /{s/, /,/g; s/public\.//g;}' | LC_ALL=C sort -u) || dump_objects=""
    listed=$(grep -c -E '^[0-9]+; [0-9]+ [0-9]+ (TABLE|SEQUENCE|VIEW|MATERIALIZED VIEW|FOREIGN TABLE|FUNCTION|PROCEDURE|AGGREGATE) public ' \
                 <<< "${dump_toc}" || true)
    if ! grep -qx 'relation identitytoken' <<< "${dump_objects}" \
            || [[ "$(printf '%s\n' "${dump_objects}" | grep -c . || true)" != "${listed}" ]]; then
        echo "  ✗ the backup's contents could not all be read (${listed} tables, sequences, views and routines listed), so the restore is unverified" >&2
        exit "${EXIT_PRIVILEGE_MISMATCH}"
    fi
    unreferenced=$(LC_ALL=C comm -23 <(printf '%s\n' "${dump_objects}") \
                       <(printf '%s\n' "${want_privileges}" | cut -f2 | LC_ALL=C sort -u)) || {
        echo "  ✗ cannot compare the backup's contents with its restored schema, so the restore is unverified" >&2
        exit "${EXIT_PRIVILEGE_MISMATCH}"
    }
    if [[ -n "${unreferenced}" ]]; then
        echo "  ✗ $(printf '%s\n' "${unreferenced}" | grep -c .) of the backup's $(printf '%s\n' "${dump_objects}" | grep -c .) tables, sequences, views and routines are missing from its restored schema, so their privileges are unverified:" >&2
        printf '%s\n' "${unreferenced}" | sed -n '1,12p' | sed 's/^/      /' >&2
        exit "${EXIT_PRIVILEGE_MISMATCH}"
    fi
    if ! restored_privileges=$(db_sql "${TARGET_DB}" "${PRIVILEGE_FACTS}" 2>"${WORK}/privileges.err"); then
        echo "  ✗ cannot read ${TARGET_DB}'s privileges, so the restore is unverified:" >&2
        sed -n '1,5p' "${WORK}/privileges.err" | sed 's/^/      /' >&2
        exit "${EXIT_PRIVILEGE_MISMATCH}"
    fi
    privilege_mismatch=$(awk -F'\t' '
        NR == FNR { want[$2] = $3; root[$1] = 1; next }
        $1 == "*" || ($1 in root) { got[$2] = $3 }
        END {
            for (k in want)
                if (!(k in got)) print k ": missing after the restore (the backup: " want[k] ")"
                else if (got[k] != want[k]) print k ": restored " got[k] ", the backup " want[k]
            for (k in got) if (!(k in want)) print k ": restored " got[k] ", the backup none"
        }' <(printf '%s\n' "${want_privileges}") <(printf '%s\n' "${restored_privileges}") | sort) || {
        echo "  ✗ cannot compare the restored privileges with the backup's, so the restore is unverified" >&2
        exit "${EXIT_PRIVILEGE_MISMATCH}"
    }
    if [[ -n "${privilege_mismatch}" ]]; then
        echo "  ✗ the restored privileges are not the backup's ($(printf '%s\n' "${privilege_mismatch}" | grep -c .) differ):" >&2
        printf '%s\n' "${privilege_mismatch}" | sed -n '1,100p' | sed 's/^/      /' >&2
        exit "${EXIT_PRIVILEGE_MISMATCH}"
    fi
    echo "  ✓ the backup's privileges, restored: $(printf '%s\n' "${want_privileges}" | grep -c .) tables, columns, routines, sequences and defaults"
else
    step "4/6" "DB restore skipped"
fi

# ---------------------------------------------------------------------------
# Step 6.5 (v9.23): schema-version cross-check.
# Opt-in via --verify-schema-version. Compares schema_version rows in
# the restored DB to the migrations/*.up.sql files on disk. If they
# diverge, exits EXIT_SCHEMA_MISMATCH so a half-restored DB does not
# silently start serving traffic.
# ---------------------------------------------------------------------------
if [[ "${VERIFY_SCHEMA}" -eq 1 && "${SKIP_DB}" -eq 0 ]]; then
    step "6.5/6" "schema-version cross-check"
    migrations_dir="${POLARIS_ROOT}/polaris_sql/migrations"
    if [[ ! -d "${migrations_dir}" ]]; then
        echo "  • migrations/ directory absent; skipping cross-check"
    else
        expected_versions=$(find "${migrations_dir}" -maxdepth 1 -name '*.up.sql' \
            -exec basename {} .up.sql \; 2>/dev/null | sort -u)
        # A migration is applied when its latest event says so: the rule polaris-migrate.sh's
        # is_currently_applied() keeps, since schema_version is an append-only event log and a
        # revert is a new row. A read that fails is a failed check, never an empty list. Until
        # 2026-10-10 this selected a column the table does not have and discarded the error, so
        # every good restore exited 10 with every migration reported missing.
        applied_sql="SELECT name FROM (SELECT DISTINCT ON (name) name, event_type FROM schema_version"
        applied_sql+=" ORDER BY name, occurred_at DESC, event_id DESC) latest"
        applied_sql+=" WHERE event_type = 'applied' ORDER BY name"
        sv_err=$(mktemp)
        if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
            sv_read() { docker compose -f "${COMPOSE_FILE}" exec -T postgres \
                psql -U postgres -d "${TARGET_DB}" -X -At -v ON_ERROR_STOP=1 -c "${applied_sql}"; }
        else
            sv_read() { psql -U "${PGUSER:-postgres}" -d "${TARGET_DB}" -X -At -v ON_ERROR_STOP=1 -c "${applied_sql}"; }
        fi
        if ! actual_raw=$(sv_read 2>"${sv_err}"); then
            echo "  ✗ cannot read schema_version in ${TARGET_DB}, so the restore is unverified:"
            sed 's/^/      /' "${sv_err}" | head -5
            rm -f "${sv_err}"
            exit "${EXIT_SCHEMA_MISMATCH}"
        fi
        rm -f "${sv_err}"
        actual_versions=$(printf '%s\n' "${actual_raw}" | sed '/^$/d' | sort -u)

        missing_in_db=$(comm -23 <(echo "${expected_versions}") <(echo "${actual_versions}") 2>/dev/null || true)
        extra_in_db=$(comm -13 <(echo "${expected_versions}") <(echo "${actual_versions}") 2>/dev/null || true)

        if [[ -n "${missing_in_db}" ]]; then
            echo "  ✗ schema mismatch — migrations on disk but NOT in restored DB:"
            echo "${missing_in_db}" | sed 's/^/      /'
            echo "      either run polaris-migrate.sh --up to apply, or restore"
            echo "      an older codebase matching the backup's vintage."
            exit "${EXIT_SCHEMA_MISMATCH}"
        fi
        if [[ -n "${extra_in_db}" ]]; then
            echo "  ✗ schema mismatch — migrations in restored DB but NOT on disk:"
            echo "${extra_in_db}" | sed 's/^/      /'
            echo "      the backup is from a NEWER codebase than this checkout."
            exit "${EXIT_SCHEMA_MISMATCH}"
        fi
        echo "  ✓ schema_version table matches migrations/ on disk"
    fi
fi

# ---------------------------------------------------------------------------
# Step 7: Final summary
# ---------------------------------------------------------------------------
step "6/6" "restore complete."
cat <<DONE

  Recommended next steps:
    1. Smoke the restored stack:
         curl -fsS http://localhost:8000/api/health | jq .
    2. Re-run the integrity tests:
         psql -d ${TARGET_DB} -f polaris_sql/08_tests.sql
    3. If this was a real recovery, rotate every secret next:
         ./scripts/polaris-rotate-secret.sh polaris_secret_key
         ./scripts/polaris-rotate-secret.sh polaris_db_password
         ./scripts/polaris-rotate-secret.sh polaris_db_root_password

  Operator runbook:  docs/operator/OPERATIONS.md § Backup & restore

DONE
exit "${EXIT_OK}"
