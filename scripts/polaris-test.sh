#!/bin/bash
# =============================================================================
# scripts/polaris-test.sh — one-shot runner for the database-backed suites
#
# The Polaris test suite needs:
#   - Python venv with flask + psycopg2 (the system python doesn't have them)
#   - 8 environment variables set (DB host/port/name/user/pw, secret, state, etc.)
#   - Redis running on a non-standard port (so the multi-process limiter tests
#     can exercise the Redis backend; tests skip cleanly if no Redis but the
#     contract-mixin tests are valuable, so we want Redis)
#   - The user logged in as admin to be unlocked (a previous run of the auth
#     tests can lock it; reload_sample_data() fixes it but only between tests,
#     not before the first one)
#
# Pre-v8.5 every test run required typing all of the above. polaris-test.sh wraps
# it. The redis instance is per-invocation so failures don't leave a stale
# pid file behind.
#
# Usage:
#     scripts/polaris-test.sh                       # the polaris_web suites CI runs
#     scripts/polaris-test.sh app                   # test_app.py alone
#     scripts/polaris-test.sh quick                 # skip the slow tests
#     scripts/polaris-test.sh CursorPaginationTokensTests   # single class
#     scripts/polaris-test.sh CursorPaginationTokensTests.test_cursor_walks_full_set_with_no_dupes_or_skips
# =============================================================================

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

if [ -t 1 ]; then
    BOLD="\033[1m"; G="\033[0;32m"; Y="\033[0;33m"; R="\033[0;31m"
    DIM="\033[2m"; NC="\033[0m"
else
    BOLD=""; G=""; Y=""; R=""; DIM=""; NC=""
fi

# -----------------------------------------------------------------------------
# Find a Python venv with flask + psycopg2.
# Order of preference: env var override, repo-local venv, the codex venv that
# the macOS dev box is using, system python3.
# -----------------------------------------------------------------------------
PYVENV="${POLARIS_TEST_PYTHON:-}"
if [ -z "$PYVENV" ]; then
    for cand in \
        "$ROOT/polaris_web/venv/bin/python" \
        "/private/tmp/polaris-codex-venv312/bin/python" \
        "/Users/$(whoami)/venv/bin/python" \
        "$(command -v python3.12)" \
        "$(command -v python3)"
    do
        if [ -x "$cand" ] && \
           "$cand" -c "import flask, psycopg2" 2>/dev/null; then
            PYVENV="$cand"
            break
        fi
    done
fi
if [ -z "$PYVENV" ]; then
    printf "${R}No Python with flask + psycopg2 found.${NC}\n"
    printf "Set POLARIS_TEST_PYTHON to the venv path, or run:\n"
    printf "    pip install flask psycopg2-binary\n"
    exit 1
fi

# -----------------------------------------------------------------------------
# Test selection — first non-flag arg passed verbatim to unittest.
# -----------------------------------------------------------------------------
SELECTOR="${1:-}"
case "$SELECTOR" in
    quick)
        # Strip known-slow tests via -k. The concurrency suite is the slowest
        # (real threads, real DB transactions). Property tests on Hypothesis
        # are also slow when hypothesis is installed.
        PYTEST_ARGS=(-m unittest discover -s . -p 'test_app.py' -v)
        EXCLUDE_PATTERN="ConcurrencyTests|HypothesisProperties"
        ;;
    "")
        # The same polaris_web modules CI runs under scripts/polaris-coverage.sh.
        # Before v9.234 this was test_app.py alone, while the preflight told the
        # operator it covered five suites: a broken test in test_check_constraints
        # passed here and would have failed in CI.
        PYTEST_ARGS=(-m unittest test_app test_check_constraints
                     test_invariants_property test_redaction_property)
        EXCLUDE_PATTERN=""
        ;;
    app)
        PYTEST_ARGS=(test_app.py)
        EXCLUDE_PATTERN=""
        ;;
    *)
        PYTEST_ARGS=(-m unittest "test_app.${SELECTOR}" -v)
        EXCLUDE_PATTERN=""
        ;;
esac

# -----------------------------------------------------------------------------
# Redis lifecycle — bring up a per-test instance on 6399, shut down on exit.
# -----------------------------------------------------------------------------
REDIS_PORT=6399
REDIS_PIDFILE="/tmp/polaris-test-redis-$$.pid"
REDIS_PID=""

cleanup() {
    if [ -n "$REDIS_PID" ] && kill -0 "$REDIS_PID" 2>/dev/null; then
        redis-cli -p "$REDIS_PORT" SHUTDOWN NOSAVE >/dev/null 2>&1 || true
    fi
    rm -f "$REDIS_PIDFILE"
}
trap cleanup EXIT

if command -v redis-server >/dev/null 2>&1; then
    redis-server --daemonize yes \
                 --port "$REDIS_PORT" \
                 --dir /tmp \
                 --pidfile "$REDIS_PIDFILE" \
                 >/dev/null 2>&1 || true
    sleep 0.4
    if [ -f "$REDIS_PIDFILE" ]; then
        REDIS_PID=$(cat "$REDIS_PIDFILE" 2>/dev/null || echo "")
    fi
    if [ -n "$REDIS_PID" ] && redis-cli -p "$REDIS_PORT" PING >/dev/null 2>&1; then
        printf "${DIM}redis: up on :%s (pid %s)${NC}\n" "$REDIS_PORT" "$REDIS_PID"
    else
        printf "${Y}redis: failed to start; Redis-backed tests will skip${NC}\n"
        REDIS_PID=""
    fi
else
    printf "${Y}redis-server not on PATH; Redis-backed tests will skip${NC}\n"
fi

# -----------------------------------------------------------------------------
# Database identity. This runner used to hardcode polaris_app, and that never
# worked: reload_sample_data() TRUNCATEs AppUser/AuthAuditLog, and 09_grants.sql
# deliberately does NOT grant TRUNCATE to polaris_app (the app role must never
# be able to truncate an audit table — C1). The reload failed with "permission
# denied for table authauditlog", psql still exited 0 (no ON_ERROR_STOP), so
# reload_sample_data saw a clean returncode and every later test died in setUp
# with a 401 because the admin row was never re-seeded: 200 errors pointing
# nowhere near the cause.
#
# Run as the schema OWNER, which is what ci.yml does (POLARIS_DB_USER: postgres).
# That is not a shortcut: the append-only tests assert the C1 TRIGGER's
# "append-only" message, and under a least-privilege role the DELETE is refused
# by GRANT before the trigger ever runs. Connecting as the owner is what makes
# those tests exercise the trigger rather than the privilege, so weakening them
# to accept "permission denied" would let a broken C1 trigger pass silently.
# -----------------------------------------------------------------------------
if [ -z "${POLARIS_TEST_RELOAD_USER:-}" ]; then
    POLARIS_TEST_RELOAD_USER=$(psql -h localhost -d polaris_test -tAc \
        "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()" \
        2>/dev/null | tr -d '[:space:]')
    [ -z "$POLARIS_TEST_RELOAD_USER" ] && POLARIS_TEST_RELOAD_USER="$(whoami)"
fi
printf "${DIM}db user: %s (schema owner, matching ci.yml)${NC}\n" \
    "$POLARIS_TEST_RELOAD_USER"

# -----------------------------------------------------------------------------
# Pre-flight: clear admin lockout. Auth tests can leave it locked.
# -----------------------------------------------------------------------------
if command -v psql >/dev/null 2>&1; then
    PGPASSWORD=polaris_dev_password psql -q -h localhost -U polaris_app \
        -d polaris_test \
        -c "UPDATE AppUser SET locked_until=NULL, failed_login_count=0 WHERE 1=1" \
        >/dev/null 2>&1 || true
fi

# -----------------------------------------------------------------------------
# Run.
# -----------------------------------------------------------------------------
cd "$ROOT/polaris_web"

# shellcheck disable=SC2086
output=$( \
  POLARIS_DB_HOST=localhost \
  POLARIS_DB_NAME=polaris_test \
  POLARIS_DB_USER="${POLARIS_TEST_RELOAD_USER}" \
  POLARIS_DB_PASSWORD="${POLARIS_TEST_DB_PASSWORD:-}" \
  POLARIS_PORT=2222 \
  POLARIS_SECRET_KEY="test-secret-$(date +%s)" \
  POLARIS_PQC_PROFILE=placeholder \
  POLARIS_STATE_DIR=/tmp/polaris-state \
  POLARIS_TEST_RELOAD_VIA=direct \
  POLARIS_TEST_RELOAD_USER="${POLARIS_TEST_RELOAD_USER}" \
  POLARIS_TEST_REDIS_URL="redis://localhost:${REDIS_PORT}/0" \
  "$PYVENV" "${PYTEST_ARGS[@]}" 2>&1
)
status=$?

# -----------------------------------------------------------------------------
# Compact summary.
# -----------------------------------------------------------------------------
if echo "$output" | tail -20 | grep -qE "^OK$|^OK \("; then
    n=$(echo "$output" | grep -oE 'Ran [0-9]+ tests' | tail -1 | grep -oE '[0-9]+')
    secs=$(echo "$output" | grep -oE 'in [0-9.]+s' | tail -1)
    printf "${G}PASS${NC}  %s tests %s\n" "${n:-?}" "${secs:-}"
    exit 0
fi

# Failure — print the relevant tail
printf "${R}FAIL${NC}\n"
echo "$output" | tail -40
exit "$status"
