#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-dr-drill.sh — prove the recovery targets by MEASUREMENT (roadmap
# P1.10, v9.192): RPO <= 5 min and RTO <= 4 h, on a clean stack, with the
# numbers written to a committed ledger (docs/operator/DR-DRILLS.md).
#
# The scenario, timed with a wall clock:
#   1. A pgBackRest-enabled primary (the shipped postgres image with the
#      Polaris schema and migrations baked in) with continuous WAL archiving
#      to a repo and archive_timeout=60s (the setting docker-init.sh applies
#      when POLARIS_PGBACKREST_ENABLED=1; it is what bounds the RPO).
#   2. stanza-create, check, a full backup (its duration recorded).
#   3. A writer commits one timestamped marker row EVERY SECOND for
#      POLARIS_DR_MARK_SECONDS (default 90), so the archive holds a known,
#      dense history of "what was committed when".
#   4. DISASTER at T_fail: the primary is killed with SIGKILL and its data
#      volume destroyed. Nothing survives but the repo.
#   5. RECOVERY: a fresh container runs `pgbackrest restore`, replays every
#      archived WAL segment, promotes; then (when a python with the app's
#      requirements exists) the application is started against it and polled
#      until /api/health reports the database healthy.
#   6. RTO = time from T_fail to a healthy service (and, separately, to the
#      database accepting queries). RPO = T_fail minus the timestamp of the
#      newest marker that came back; the markers written but not recovered
#      are the loss the archive interval permits. Integrity: the token count
#      and the schema_version rows equal the pre-disaster values.
#
# Pass: RPO <= 300 s, RTO (service) <= 14400 s, integrity equal. The measured
# values are printed, written to $POLARIS_DR_OUT (json), and with --record
# appended as a row to the ledger, PASS or FAIL alike (a failed drill is the
# most important row in that table).
#
# Usage: scripts/polaris-dr-drill.sh [--record[=FILE]] [--no-build]
#   --record      append the result row to docs/operator/DR-DRILLS.md
#                 (or the given FILE, e.g. /var/lib/polaris/dr-drills.md on a host)
#   --no-build    use POLARIS_PG_IMAGE as is (default builds polaris-postgres:drill)
# Env: POLARIS_DR_MODE (a label for the row: ci, ci-monthly, host, local),
#      POLARIS_DR_MARK_SECONDS, POLARIS_DR_OUT, POLARIS_DR_DB_PORT (default 25432)
# Needs docker + python3; the app stage additionally needs flask + psycopg2.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
PG_IMAGE="${POLARIS_PG_IMAGE:-polaris-postgres:drill}"
NET=polaris-dr-net; PRI=polaris-dr-pri; RES=polaris-dr-res; REPO=polaris-dr-repo
WORK="$(mktemp -d)"
OUT="${POLARIS_DR_OUT:-$ROOT/dr-drill.json}"
MODE="${POLARIS_DR_MODE:-local}"
MARK_SECONDS="${POLARIS_DR_MARK_SECONDS:-90}"
DB_PORT="${POLARIS_DR_DB_PORT:-25432}"
ARCHIVE_TIMEOUT=60
RPO_TARGET=300; RTO_TARGET=14400
RECORD=""; BUILD=1
while [ $# -gt 0 ]; do
    case "$1" in
        --record) RECORD="$ROOT/docs/operator/DR-DRILLS.md" ;;
        --record=*) RECORD="${1#--record=}" ;;
        --no-build) BUILD=0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
APP_PID=""
cleanup() {
    [ -n "$APP_PID" ] && { kill "$APP_PID" >/dev/null 2>&1 || true; }
    docker rm -f -v "$PRI" "$RES" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    docker volume rm "$REPO" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
now() { python3 -c 'import time; print(time.time())'; }
VERSION="$(python3 -c "import sys; sys.path.insert(0,'$ROOT/polaris_web'); import __version__ as v; print(v.__version__)")"
GIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
[ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ] && GIT="${GIT}+dirty"
DATE="$(date -u +%Y-%m-%dT%H:%MZ)"
record_row() {  # record_row STATUS RPO RTO_DB RTO_SVC BACKUP_S RECOVERED WRITTEN NOTE
    [ -n "$RECORD" ] || return 0
    printf '| %s | v%s | %s | %s | %s | %s | %s | %s | %s/%s | %s | %s |\n' \
        "$DATE" "$VERSION" "$GIT" "$MODE" "$2" "$3" "$4" "$5" "$6" "$7" "$1" "$8" >> "$RECORD"
    echo "   ledger row appended to $RECORD ($1)"
}
fail() {
    echo "--- $PRI logs (last 20) ---" >&2; docker logs "$PRI" 2>&1 | tail -20 >&2 || true
    echo "--- $RES logs (last 20) ---" >&2; docker logs "$RES" 2>&1 | tail -20 >&2 || true
    record_row FAIL "-" "-" "-" "-" "-" "-" "$*"
    echo "::error::$*" >&2; exit 1
}
psql_pri() { docker exec -e PGPASSWORD=rootpw "$PRI" psql -h 127.0.0.1 -U postgres -d polaris -tAqc "$1"; }
psql_res() { docker exec -e PGPASSWORD=rootpw "$RES" psql -h 127.0.0.1 -U postgres -d polaris -tAqc "$1"; }

echo "== Polaris DR drill ($MODE): v$VERSION @ $GIT, $DATE; targets RPO<=${RPO_TARGET}s RTO<=${RTO_TARGET}s =="
if [ "$BUILD" = 1 ]; then
    echo "== 0. build the pgbackrest-enabled postgres image =="
    docker build -q -f "$ROOT/polaris_web/Dockerfile.postgres" -t "$PG_IMAGE" "$ROOT" >/dev/null
fi
docker network create "$NET" >/dev/null 2>&1 || true
docker volume create "$REPO" >/dev/null
: > "$WORK/creds.conf"

echo "== 1. primary with continuous WAL archiving (archive_timeout=${ARCHIVE_TIMEOUT}s) =="
docker run -d --name "$PRI" --network "$NET" \
    -e POSTGRES_PASSWORD=rootpw -e POSTGRES_DB=polaris \
    -v "$REPO:/var/lib/pgbackrest" \
    -v "$ROOT/polaris_web/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro" \
    -v "$WORK/creds.conf:/etc/pgbackrest/conf.d/repo-creds.conf:ro" \
    "$PG_IMAGE" \
    -c wal_level=replica -c archive_mode=on \
    -c "archive_command=pgbackrest --stanza=polaris archive-push %p" \
    -c "archive_timeout=${ARCHIVE_TIMEOUT}" -c max_wal_senders=3 >/dev/null
# TCP: only the real server listens on it (the entrypoint's temporary init
# server answers the socket while the schema loads).
for i in $(seq 1 120); do psql_pri 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
psql_pri 'SELECT 1' >/dev/null 2>&1 || fail "the primary did not come up"
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris stanza-create >/dev/null
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris check >/dev/null
tokens_before=$(psql_pri "SELECT count(*) FROM IdentityToken" | tr -d '[:space:]')
sv_before=$(psql_pri "SELECT count(*) FROM schema_version" | tr -d '[:space:]')
[ "${tokens_before:-0}" -ge 1 ] || fail "the image did not load the Polaris schema + sample data"
psql_pri "CREATE TABLE dr_marker (id serial PRIMARY KEY, ts timestamptz NOT NULL DEFAULT clock_timestamp())" >/dev/null
echo "   schema loaded: $tokens_before tokens, $sv_before schema_version rows"

echo "== 2. full backup =="
t0=$(now)
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris --type=full backup >/dev/null
backup_s=$(python3 -c "print(round($(now) - $t0, 1))")
echo "   full backup in ${backup_s}s"

echo "== 3. one committed marker per second for ${MARK_SECONDS}s (the archive fills as time passes) =="
for i in $(seq 1 "$MARK_SECONDS"); do
    psql_pri "INSERT INTO dr_marker DEFAULT VALUES" >/dev/null
    [ $((i % 30)) -eq 0 ] && echo "   ${i}s: $(psql_pri "SELECT coalesce(last_archived_wal,'none') FROM pg_stat_archiver" | tr -d '[:space:]') archived last"
    sleep 1
done
written=$(psql_pri "SELECT count(*) FROM dr_marker" | tr -d '[:space:]')

echo "== 4. DISASTER: SIGKILL the primary and destroy its data volume =="
T_FAIL=$(now)
docker kill -s KILL "$PRI" >/dev/null
docker rm -f -v "$PRI" >/dev/null
echo "   primary gone at T_fail; $written markers had been committed"

echo "== 5. RECOVERY: restore from the repo into a fresh container, replay the archive, promote =="
docker run -d --name "$RES" --network "$NET" --user postgres \
    -p "127.0.0.1:${DB_PORT}:5432" \
    -v "$REPO:/var/lib/pgbackrest" \
    -v "$ROOT/polaris_web/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro" \
    "$PG_IMAGE" \
    sh -c 'rm -rf /var/lib/postgresql/data/* && pgbackrest --stanza=polaris restore && exec postgres' >/dev/null
for i in $(seq 1 600); do
    if [ "$(psql_res 'SELECT pg_is_in_recovery()' 2>/dev/null | tr -d '[:space:]')" = "f" ]; then break; fi
    sleep 1
done
[ "$(psql_res 'SELECT pg_is_in_recovery()' 2>/dev/null | tr -d '[:space:]')" = "f" ] || fail "the restored database did not finish archive recovery within 600s"
T_DB=$(now)
rto_db_s=$(python3 -c "print(round($T_DB - $T_FAIL, 1))")
recovered=$(psql_res "SELECT count(*) FROM dr_marker" | tr -d '[:space:]')
last_epoch=$(psql_res "SELECT coalesce(extract(epoch FROM max(ts)), 0) FROM dr_marker" | tr -d '[:space:]')
tokens_after=$(psql_res "SELECT count(*) FROM IdentityToken" | tr -d '[:space:]')
sv_after=$(psql_res "SELECT count(*) FROM schema_version" | tr -d '[:space:]')
rpo_s=$(python3 -c "print(round($T_FAIL - $last_epoch, 1) if $last_epoch > 0 else -1)")
echo "   database serving after ${rto_db_s}s; markers recovered $recovered/$written; RPO ${rpo_s}s"

echo "== 6. the application against the restored database =="
PY=""
for cand in "$ROOT/polaris_web/venv/bin/python" "/private/tmp/polaris-codex-venv312/bin/python" "$(command -v python3.12 || true)" "$(command -v python3 || true)"; do
    if [ -n "$cand" ] && [ -x "$cand" ] && "$cand" -c "import flask, psycopg2" 2>/dev/null; then PY="$cand"; break; fi
done
app_stage=false; rto_svc_s="$rto_db_s"
if [ -n "$PY" ]; then
    app_stage=true
    ( cd "$ROOT/polaris_web" && POLARIS_PORT=2299 POLARIS_DB_HOST=127.0.0.1 POLARIS_DB_PORT="$DB_PORT" \
      POLARIS_DB_NAME=polaris POLARIS_DB_USER=postgres POLARIS_DB_PASSWORD=rootpw \
      POLARIS_SECRET_KEY="dr-drill-$(date +%s)-not-a-real-key" POLARIS_STATE_DIR="$WORK/state" \
      POLARIS_RATE_LIMIT_BACKEND=memory exec "$PY" app.py > "$WORK/app.log" 2>&1 ) &
    APP_PID=$!
    healthy=""
    for i in $(seq 1 120); do
        healthy=$("$PY" - <<'PYEOF' 2>/dev/null || true
import json, urllib.request
try:
    h = json.load(urllib.request.urlopen("http://127.0.0.1:2299/api/health", timeout=3))
except Exception as e:
    try:
        import urllib.error
        h = json.load(e) if isinstance(e, urllib.error.HTTPError) else {}
    except Exception:
        h = {}
print("yes" if h.get("checks", {}).get("database", {}).get("status") == "healthy" else "no")
PYEOF
)
        [ "$healthy" = "yes" ] && break
        sleep 1
    done
    [ "$healthy" = "yes" ] || { tail -20 "$WORK/app.log" >&2 || true; fail "the application did not report the restored database healthy within 120s"; }
    T_APP=$(now)
    rto_svc_s=$(python3 -c "print(round($T_APP - $T_FAIL, 1))")
    echo "   application healthy against the restored database after ${rto_svc_s}s"
else
    echo "   (no python with the app's requirements found: RTO is measured to the database only)"
fi

echo "== 7. verdict =="
status=PASS; note="markers recovered $recovered/$written"
python3 -c "import sys; sys.exit(0 if $rpo_s >= 0 and $rpo_s <= $RPO_TARGET else 1)" || { status=FAIL; note="RPO ${rpo_s}s exceeds ${RPO_TARGET}s"; }
python3 -c "import sys; sys.exit(0 if $rto_svc_s <= $RTO_TARGET else 1)" || { status=FAIL; note="RTO ${rto_svc_s}s exceeds ${RTO_TARGET}s"; }
[ "$tokens_after" = "$tokens_before" ] || { status=FAIL; note="token count $tokens_after != $tokens_before"; }
[ "$sv_after" = "$sv_before" ] || { status=FAIL; note="schema_version rows $sv_after != $sv_before"; }
[ "${recovered:-0}" -ge 1 ] || { status=FAIL; note="no markers recovered"; }
python3 - "$OUT" <<PYEOF
import json, sys, platform
json.dump({
  "stamp": {"version": "$VERSION", "git": "$GIT", "date": "$DATE", "mode": "$MODE",
            "host": platform.platform(), "image": "$PG_IMAGE", "archive_timeout_s": $ARCHIVE_TIMEOUT},
  "targets": {"rpo_s": $RPO_TARGET, "rto_s": $RTO_TARGET},
  "measured": {"rpo_s": $rpo_s, "rto_db_s": $rto_db_s, "rto_service_s": $rto_svc_s, "backup_s": $backup_s,
               "markers_written": $written, "markers_recovered": $recovered,
               "tokens_before": $tokens_before, "tokens_after": $tokens_after,
               "schema_version_rows": $sv_before, "app_stage": "$app_stage" == "true"},
  "status": "$status"}, open(sys.argv[1], "w"), indent=2)
PYEOF
record_row "$status" "$rpo_s" "$rto_db_s" "$rto_svc_s" "$backup_s" "$recovered" "$written" "$note"
echo "   RPO ${rpo_s}s (target ${RPO_TARGET}) · RTO ${rto_svc_s}s to service, ${rto_db_s}s to database (target ${RTO_TARGET}) · backup ${backup_s}s · $note"
if [ "$status" = PASS ]; then
    echo "== DR DRILL PASSED: results in $OUT =="
else
    echo "::error::DR DRILL FAILED: $note" >&2; exit 1
fi
