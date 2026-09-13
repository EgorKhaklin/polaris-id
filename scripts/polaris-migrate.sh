#!/usr/bin/env bash
# ============================================================================
# polaris-migrate.sh — Polaris schema migration runner
#
# v8.95 / Position C from a recorded decision.
# Custom polaris-native: hand-written SQL files in pairs (.up + .down);
# state in `schema_version` table (append-only: a revert is a new row, never an
# UPDATE or DELETE, so the history of what ran cannot be edited);
# SHA-256-of-file recorded at apply time and verified at revert time.
#
# Migration file naming (enforced by schema_version.name CHECK):
#
#     polaris_sql/migrations/<YYYY-MM-DD>-<NNN>-<slug>.up.sql
#     polaris_sql/migrations/<YYYY-MM-DD>-<NNN>-<slug>.down.sql
#
# Both files are REQUIRED: a migration that cannot be reversed is one you can only
# go forward from. The .down may
# be effectively a no-op (e.g., a comment explaining the change is
# irreversible — the file documents that, and stays as audit-of-record).
#
# Lexicographic ordering on the filename is the apply order; the
# YYYY-MM-DD-NNN prefix makes the order obvious and stable.
#
# Usage:
#   ./scripts/polaris-migrate.sh --status           # current state (default)
#   ./scripts/polaris-migrate.sh --up               # apply all pending
#   ./scripts/polaris-migrate.sh --up N             # apply N pending
#   ./scripts/polaris-migrate.sh --down N           # revert N most-recent applied
#   ./scripts/polaris-migrate.sh --sync-objects     # re-apply idempotent objects
#                                                   # (procedures/triggers/views/grants)
#                                                   # so changed objects reach an upgraded DB
#   ./scripts/polaris-migrate.sh --dry-run --up     # list pending; no INSERT
#   ./scripts/polaris-migrate.sh --target=docker-stack ...   # use prod stack
#   ./scripts/polaris-migrate.sh --target=dev-stack ...      # use dev compose stack
#   ./scripts/polaris-migrate.sh --actor-user-id N --up      # record actor
#
# Exit codes:
#   0  success (or --status / --dry-run completed)
#   2  usage error
#   3  migration directory missing or empty (only an issue for --up/--down)
#   4  filename validation error (file doesn't match the required pattern)
#   5  database call failed
#   6  SHA-256 mismatch on revert (file edited post-apply; refuse to revert
#      with the modified content — the recorded SHA is authoritative)
#   7  invalid argument (e.g., --down 0)
#
# Reference: a recorded decision.
# ============================================================================

set -euo pipefail

EXIT_OK=0
EXIT_USAGE=2
EXIT_DIR_MISSING=3
EXIT_FILENAME=4
EXIT_DB=5
EXIT_SHA_MISMATCH=6
EXIT_ARG=7

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
POLARIS_ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
MIGRATIONS_DIR="${POLARIS_ROOT}/polaris_sql/migrations"
COMPOSE_FILE="${POLARIS_ROOT}/polaris_web/docker-compose.prod.yml"
DEV_COMPOSE_FILE="${POLARIS_ROOT}/polaris_web/docker-compose.yml"

MODE="status"   # default
COUNT=0         # 0 = "all" for --up; required for --down
DRY_RUN=0
USE_DOCKER_STACK=0
USE_DEV_STACK=0
ACTOR_USER_ID="NULL"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --status)              MODE="status" ;;
        --up)
            MODE="up"
            # Optional numeric argument
            if [[ $# -gt 1 ]] && [[ "$2" =~ ^[0-9]+$ ]]; then
                COUNT="$2"; shift
            fi
            ;;
        --down)
            MODE="down"
            shift
            if [[ -z "${1:-}" ]] || ! [[ "$1" =~ ^[0-9]+$ ]]; then
                echo "error: --down requires a numeric count" >&2
                exit "${EXIT_USAGE}"
            fi
            COUNT="$1"
            if [[ "${COUNT}" -lt 1 ]]; then
                echo "error: --down N requires N >= 1" >&2
                exit "${EXIT_ARG}"
            fi
            ;;
        --sync-objects)        MODE="sync-objects" ;;
        --dry-run)             DRY_RUN=1 ;;
        --target=docker-stack) USE_DOCKER_STACK=1 ;;
        --target=dev-stack)    USE_DEV_STACK=1 ;;
        --actor-user-id=*)     ACTOR_USER_ID="${1#--actor-user-id=}" ;;
        --actor-user-id)       shift; ACTOR_USER_ID="${1:-NULL}" ;;
        --help|-h)
            sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'
            exit "${EXIT_USAGE}"
            ;;
        *) echo "warn: unknown arg $1" >&2 ;;
    esac
    shift
done

# --actor-user-id is interpolated unquoted into the schema_version INSERT;
# require NULL (the default) or a numeric id so it cannot inject SQL.
if [[ "${ACTOR_USER_ID}" != "NULL" ]] && ! [[ "${ACTOR_USER_ID}" =~ ^[0-9]+$ ]]; then
    echo "error: --actor-user-id must be numeric (or omitted for NULL)" >&2
    exit "${EXIT_USAGE}"
fi

# ---------------------------------------------------------------------------
# Migration safety timeouts (production hazard: a migration that needs an
# ACCESS EXCLUSIVE lock — most ALTER TABLE forms — queues behind any open
# transaction and, once granted, blocks ALL reads and writes on that table.
# An unbounded wait turns one slow query into a site-wide stall.
#
#   lock_timeout      — how long a statement waits for a lock before it ERRORS
#                       (fail fast instead of queueing + holding up the line).
#   statement_timeout — max wall-clock for any single migration statement.
#
# Both are SET LOCAL inside the apply/revert transaction (auto-reset at COMMIT)
# and are overridable for long, legitimate work (e.g. a big in-transaction
# index build: raise POLARIS_MIGRATE_STATEMENT_TIMEOUT, or 0 to disable).
# Validated strictly because they are interpolated into the SQL.
# ---------------------------------------------------------------------------
MIGRATE_LOCK_TIMEOUT="${POLARIS_MIGRATE_LOCK_TIMEOUT:-3s}"
MIGRATE_STATEMENT_TIMEOUT="${POLARIS_MIGRATE_STATEMENT_TIMEOUT:-60s}"
TIMEOUT_PATTERN='^[0-9]+(ms|s|min|h)?$'
for _pair in "lock_timeout=${MIGRATE_LOCK_TIMEOUT}" "statement_timeout=${MIGRATE_STATEMENT_TIMEOUT}"; do
    if ! [[ "${_pair#*=}" =~ ${TIMEOUT_PATTERN} ]]; then
        echo "error: ${_pair%%=*} must be a Postgres duration like 3s, 250ms, 5min, or 0 (got '${_pair#*=}')" >&2
        exit "${EXIT_USAGE}"
    fi
done

# Filename pattern (must match schema_version.name CHECK).
NAME_PATTERN='^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{3}-[a-z][a-z0-9_-]*$'

# --target=dev-stack drives the DEV compose stack (service `db`, database
# polaris_test). It exists because the launcher's Docker path needs migrations
# and code-object sync against the container database: the v9.152 refresh only
# ever ran on the native path, so a persistent dev volume kept pre-v9.146 atlas
# function signatures and the app 500d with the exact ATLAS-FEED-INTERRUPTED
# failure v9.152 was shipped to fix. Files are streamed over stdin, so nothing
# needs to be mounted at a particular container path.
# The docker branches redirect stdin from /dev/null. Without that,
# `docker compose exec -T` attaches the caller's stdin and DRAINS it, so when
# run_psql is called inside a `while read` loop (do_up's pending scan), the
# first exec swallows every remaining line of the loop's input and the loop
# ends after one iteration: three genuinely pending migrations reported as
# "no pending migrations". run_psql_file is exempt: its stdin IS the payload.
run_psql() {
    if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
        docker compose -f "${COMPOSE_FILE}" exec -T postgres \
            psql -U postgres -d polaris -tA "$@" < /dev/null
    elif [[ "${USE_DEV_STACK}" -eq 1 ]]; then
        docker compose -f "${DEV_COMPOSE_FILE}" exec -T db \
            psql -U postgres -d polaris_test -tA "$@" < /dev/null
    else
        psql -h "${POLARIS_DB_HOST:-localhost}" \
             -U "${POLARIS_DB_USER:-postgres}" \
             -d "${POLARIS_DB_NAME:-polaris}" \
             -tA "$@"
    fi
}

run_psql_file() {
    if [[ "${USE_DOCKER_STACK}" -eq 1 ]]; then
        docker compose -f "${COMPOSE_FILE}" exec -T postgres \
            psql -U postgres -d polaris -v ON_ERROR_STOP=1 < "$1"
    elif [[ "${USE_DEV_STACK}" -eq 1 ]]; then
        docker compose -f "${DEV_COMPOSE_FILE}" exec -T db \
            psql -U postgres -d polaris_test -v ON_ERROR_STOP=1 < "$1"
    else
        psql -h "${POLARIS_DB_HOST:-localhost}" \
             -U "${POLARIS_DB_USER:-postgres}" \
             -d "${POLARIS_DB_NAME:-polaris}" \
             -v ON_ERROR_STOP=1 -f "$1"
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Returns 0 if name is currently applied (its last event is 'applied').
is_currently_applied() {
    local name="$1"
    local last_event
    last_event=$(run_psql -c "
        SELECT event_type FROM schema_version
        WHERE name = '${name}'
        ORDER BY occurred_at DESC, event_id DESC
        LIMIT 1
    " 2>/dev/null | tr -d '[:space:]')
    [[ "${last_event}" == "applied" ]]
}

# Returns the recorded SHA-256 for the most recent 'applied' event
# of the given migration name. Empty string if never applied.
last_apply_sha() {
    local name="$1"
    run_psql -c "
        SELECT file_sha256 FROM schema_version
        WHERE name = '${name}' AND event_type = 'applied'
        ORDER BY occurred_at DESC, event_id DESC
        LIMIT 1
    " 2>/dev/null | tr -d '[:space:]'
}

# List all migration names available on disk (up.sql files).
list_on_disk() {
    if [[ ! -d "${MIGRATIONS_DIR}" ]]; then
        return 0
    fi
    for f in "${MIGRATIONS_DIR}"/*.up.sql; do
        [[ -f "${f}" ]] || continue
        local base
        base="$(basename "${f}" .up.sql)"
        echo "${base}"
    done | sort
}

# Validate every on-disk migration has both .up.sql and .down.sql AND
# matches the naming convention. Fails fast on any violation.
validate_filenames() {
    local any=0
    while IFS= read -r name; do
        any=1
        if ! [[ "${name}" =~ ${NAME_PATTERN} ]]; then
            echo "error: migration name '${name}' does not match ${NAME_PATTERN}" >&2
            exit "${EXIT_FILENAME}"
        fi
        if [[ ! -f "${MIGRATIONS_DIR}/${name}.down.sql" ]]; then
            echo "error: migration '${name}' has no .down.sql; every migration must be\n       reversible, so the down file is required even when it only drops what the up\n       file added" >&2
            exit "${EXIT_FILENAME}"
        fi
    done < <(list_on_disk)
}

# ---------------------------------------------------------------------------
# MODE: status
# ---------------------------------------------------------------------------
do_status() {
    local on_disk applied pending
    validate_filenames 2>/dev/null || true
    on_disk=$(list_on_disk)

    echo
    echo "  Polaris schema migration status"
    echo "  ────────────────────────────────"
    echo

    if [[ -z "${on_disk}" ]]; then
        echo "  Migrations on disk:  (none)"
    else
        echo "  Migrations on disk:"
        while IFS= read -r name; do
            if is_currently_applied "${name}"; then
                printf "    ✓ %s  (applied)\n" "${name}"
            else
                printf "    ⬜ %s  (pending)\n" "${name}"
            fi
        done <<< "${on_disk}"
    fi
    echo

    # Total events in the registry (audit-of-record visibility)
    local total
    total=$(run_psql -c "SELECT count(*) FROM schema_version" 2>/dev/null | tr -d '[:space:]')
    echo "  schema_version events (lifetime, append-only):  ${total:-0}"

    # Currently-applied count
    local applied_count
    applied_count=$(run_psql -c "
        SELECT count(*) FROM (
            SELECT name FROM schema_version sv1
            WHERE event_type = 'applied'
              AND NOT EXISTS (
                  SELECT 1 FROM schema_version sv2
                  WHERE sv2.name = sv1.name
                    AND sv2.event_type = 'reverted'
                    AND sv2.occurred_at > sv1.occurred_at
              )
        ) t
    " 2>/dev/null | tr -d '[:space:]')
    echo "  Currently applied (last event = applied):       ${applied_count:-0}"
    echo
}

# ---------------------------------------------------------------------------
# MODE: up (apply N pending, or all if N=0)
# ---------------------------------------------------------------------------
do_up() {
    if [[ ! -d "${MIGRATIONS_DIR}" ]]; then
        echo "  → migrations directory empty: ${MIGRATIONS_DIR}"
        exit "${EXIT_OK}"
    fi
    validate_filenames

    local pending=()
    while IFS= read -r name; do
        if ! is_currently_applied "${name}"; then
            pending+=("${name}")
        fi
    done < <(list_on_disk)

    if [[ "${#pending[@]}" -eq 0 ]]; then
        echo "  ✓ no pending migrations (everything on disk is applied)."
        exit "${EXIT_OK}"
    fi

    # Apply up to COUNT pending, or all if COUNT=0
    local limit="${#pending[@]}"
    if [[ "${COUNT}" -gt 0 ]] && [[ "${COUNT}" -lt "${limit}" ]]; then
        limit="${COUNT}"
    fi

    echo
    echo "  Polaris schema migrate --up"
    echo "  ───────────────────────────"
    echo "  Pending: ${#pending[@]}"
    echo "  Applying: ${limit}"
    [[ "${DRY_RUN}" -eq 1 ]] && echo "  Dry-run: yes (no INSERT will issue)"
    echo

    for ((i=0; i<limit; i++)); do
        local name="${pending[$i]}"
        local up_file="${MIGRATIONS_DIR}/${name}.up.sql"
        local sha
        sha=$(sha256_of "${up_file}")
        if [[ "${DRY_RUN}" -eq 1 ]]; then
            echo "  [dry-run] would apply: ${name}  (sha=${sha:0:16}…)"
            continue
        fi

        # Apply the migration + INSERT schema_version in one transaction. The
        # migration body is INLINED (cat) rather than `\i ${up_file}` so this
        # works against a containerized postgres too: --target=docker-stack pipes
        # the SQL over stdin, and a host-path `\i` would not resolve inside the
        # container. cat preserves the file verbatim, including $$-quoting.
        local sql_tmp
        sql_tmp=$(mktemp)
        {
            printf 'BEGIN;\n'
            printf "SET LOCAL lock_timeout = '%s';\n" "${MIGRATE_LOCK_TIMEOUT}"
            printf "SET LOCAL statement_timeout = '%s';\n" "${MIGRATE_STATEMENT_TIMEOUT}"
            cat "${up_file}"
            printf '\nINSERT INTO schema_version (name, event_type, actor_user_id, file_sha256)\n'
            printf "VALUES ('%s', 'applied', %s, '%s');\n" "${name}" "${ACTOR_USER_ID}" "${sha}"
            printf 'COMMIT;\n'
        } > "${sql_tmp}"
        if ! run_psql_file "${sql_tmp}" >/dev/null 2>&1; then
            local out
            out=$(run_psql_file "${sql_tmp}" 2>&1 || true)
            rm -f "${sql_tmp}"
            echo "  ✗ failed: ${name}" >&2
            echo "${out}" >&2
            exit "${EXIT_DB}"
        fi
        rm -f "${sql_tmp}"
        echo "  ✓ applied: ${name}  (sha=${sha:0:16}…)"
    done
    echo
}

# ---------------------------------------------------------------------------
# MODE: down (revert N most recent applied)
# ---------------------------------------------------------------------------
do_down() {
    if [[ "${COUNT}" -lt 1 ]]; then
        echo "error: --down N requires N >= 1" >&2
        exit "${EXIT_ARG}"
    fi
    validate_filenames

    # Get the N most-recently-applied (currently applied) migrations,
    # in reverse order (newest first).
    local applied_csv
    applied_csv=$(run_psql -c "
        SELECT name FROM schema_version sv1
        WHERE event_type = 'applied'
          AND NOT EXISTS (
              SELECT 1 FROM schema_version sv2
              WHERE sv2.name = sv1.name
                AND sv2.event_type = 'reverted'
                AND sv2.occurred_at > sv1.occurred_at
          )
        ORDER BY occurred_at DESC, event_id DESC
        LIMIT ${COUNT}
    " 2>/dev/null)

    if [[ -z "${applied_csv}" ]]; then
        echo "  ✓ nothing currently applied; nothing to revert."
        exit "${EXIT_OK}"
    fi

    echo
    echo "  Polaris schema migrate --down ${COUNT}"
    echo "  ─────────────────────────────────"
    [[ "${DRY_RUN}" -eq 1 ]] && echo "  Dry-run: yes (no INSERT will issue)"
    echo

    while IFS= read -r name; do
        [[ -z "${name}" ]] && continue
        local up_file="${MIGRATIONS_DIR}/${name}.up.sql"
        local down_file="${MIGRATIONS_DIR}/${name}.down.sql"
        if [[ ! -f "${down_file}" ]]; then
            echo "  ✗ revert refused: ${name}.down.sql missing" >&2
            exit "${EXIT_FILENAME}"
        fi
        # Tamper-detection: file SHA-256 must match the one recorded at apply.
        local recorded current
        recorded=$(last_apply_sha "${name}")
        current=$(sha256_of "${up_file}")
        if [[ "${recorded}" != "${current}" ]]; then
            echo "  ✗ revert refused: ${name}.up.sql SHA-256 has changed since apply" >&2
            echo "      recorded: ${recorded}" >&2
            echo "      current:  ${current}" >&2
            echo "      The file was edited post-apply; refusing to revert with the" >&2
            echo "      modified content. Restore the original up.sql or manually" >&2
            echo "      audit the change before proceeding." >&2
            exit "${EXIT_SHA_MISMATCH}"
        fi

        local down_sha
        down_sha=$(sha256_of "${down_file}")
        if [[ "${DRY_RUN}" -eq 1 ]]; then
            echo "  [dry-run] would revert: ${name}  (down sha=${down_sha:0:16}…)"
            continue
        fi

        # Inline the down body (see do_up) so revert works over docker-stack too.
        local sql_tmp
        sql_tmp=$(mktemp)
        {
            printf 'BEGIN;\n'
            printf "SET LOCAL lock_timeout = '%s';\n" "${MIGRATE_LOCK_TIMEOUT}"
            printf "SET LOCAL statement_timeout = '%s';\n" "${MIGRATE_STATEMENT_TIMEOUT}"
            cat "${down_file}"
            printf '\nINSERT INTO schema_version (name, event_type, actor_user_id, file_sha256)\n'
            printf "VALUES ('%s', 'reverted', %s, '%s');\n" "${name}" "${ACTOR_USER_ID}" "${down_sha}"
            printf 'COMMIT;\n'
        } > "${sql_tmp}"
        if ! run_psql_file "${sql_tmp}" >/dev/null 2>&1; then
            local out
            out=$(run_psql_file "${sql_tmp}" 2>&1 || true)
            rm -f "${sql_tmp}"
            echo "  ✗ revert failed: ${name}" >&2
            echo "${out}" >&2
            exit "${EXIT_DB}"
        fi
        rm -f "${sql_tmp}"
        echo "  ✓ reverted: ${name}  (down sha=${down_sha:0:16}…)"
    done <<< "${applied_csv}"
    echo
}

# ---------------------------------------------------------------------------
# MODE: sync-objects — re-apply the idempotent DB object definitions (views,
# procedures, triggers, queries, atlas/foresight/ontology helpers, grants).
#
# These live in CREATE OR REPLACE / GRANT files that 00_load_all.sql loads on a
# FRESH database. A persistent-volume UPGRADE never re-runs 00_load_all.sql, so
# without this a changed procedure or trigger never reaches an upgraded DB — e.g.
# v9.117's uc1_issue_and_activate signature change would be absent and issuance
# would fail. All listed files are pure CREATE OR REPLACE / GRANT and verified
# safe to re-apply to a populated DB. The deploy runs this after --up.
# ---------------------------------------------------------------------------
SQL_DIR="${POLARIS_ROOT}/polaris_sql"
OBJECT_FILES=(
    03_view.sql
    05_procedures.sql
    06_triggers.sql
    07_queries.sql
    11_atlas.sql
    14_foresight_helpers.sql
    15_ontology.sql
    16_athena.sql
    09_grants.sql
)

do_sync_objects() {
    echo "Syncing idempotent DB objects (views, procedures, triggers, grants)…"
    local f path out
    for f in "${OBJECT_FILES[@]}"; do
        path="${SQL_DIR}/${f}"
        if [[ ! -f "${path}" ]]; then
            echo "  ! skip ${f} (not found)"
            continue
        fi
        if [[ "${DRY_RUN}" -eq 1 ]]; then
            echo "  [dry-run] would re-apply ${f}"
            continue
        fi
        # Execute ONCE and judge the captured result. The previous form ran the
        # file a second time on failure just to capture the error output: the
        # v9.153 create-operator lesson (harmless here only because these files
        # are idempotent, but the pattern invites the same bug).
        if out=$(run_psql_file "${path}" 2>&1); then
            echo "  ✓ ${f}"
        else
            echo "  ✗ ${f}" >&2
            echo "${out}" | tail -3 >&2
            exit "${EXIT_DB}"
        fi
    done
    echo "  Objects synced — procedure/trigger/view/grant definitions match the source."
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "${MODE}" in
    status)       do_status ;;
    up)           do_up ;;
    down)         do_down ;;
    sync-objects) do_sync_objects ;;
    *)
        echo "error: unknown mode ${MODE}" >&2
        exit "${EXIT_USAGE}"
        ;;
esac

exit "${EXIT_OK}"
