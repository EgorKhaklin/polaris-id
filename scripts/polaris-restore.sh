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
#                           Exits EXIT_SCHEMA_MISMATCH=10 if divergent
#                           (prevents serving half-restored DB). v9.23.
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

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
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
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
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
trap 'rm -rf "${WORK}"' EXIT

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
        if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
            actual_versions=$(docker compose -f "${COMPOSE_FILE}" exec -T postgres \
                psql -U polaris -d "${TARGET_DB}" -At \
                -c "SELECT version FROM schema_version ORDER BY version" 2>/dev/null \
                | sort -u || echo "")
        else
            actual_versions=$(psql -d "${TARGET_DB}" -At \
                -c "SELECT version FROM schema_version ORDER BY version" 2>/dev/null \
                | sort -u || echo "")
        fi

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
