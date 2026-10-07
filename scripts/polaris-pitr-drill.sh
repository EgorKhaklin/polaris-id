#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-pitr-drill.sh: a restore to a chosen point in time, tested (lab record 017, gate row
# OP-12). docs/operator/DR.md section 4.3 restores to "the last known-good moment" with
# pgbackrest --type=time; this runs that command and checks what came back against what the
# database held at that moment.
#
#   1. a pgBackRest-enabled primary (the shipped postgres image, continuous WAL archiving) and a
#      full backup;
#   2. one committed marker row per second; halfway, the drill reads the database's own clock (T)
#      and records the markers, their digest and the token count as of T; the markers go on;
#   3. the archive is forced to hold everything, then the primary and its volume are destroyed;
#   4. a fresh container restores with --type=time --target=T and promotes;
#   5. the restored database must hold exactly the markers committed by T (same count, same
#      digest), none committed after it, and the token count of T.
#
# Usage: scripts/polaris-pitr-drill.sh [--no-build] [--prove-control]
#   --no-build       use POLARIS_PG_IMAGE as is (default builds polaris-postgres:drill)
#   --prove-control  restore to the archive's end instead of T: the checks must then see the
#                    markers committed after T, or they could not tell the two restores apart
# Env: POLARIS_PITR_MARK_SECONDS (default 40), POLARIS_PG_IMAGE
# Exit: 0 the restore stopped exactly at T; 1 otherwise, saying how.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
PG_IMAGE="${POLARIS_PG_IMAGE:-polaris-postgres:drill}"
NET=polaris-pitr-net; PRI=polaris-pitr-pri; RES=polaris-pitr-res; REPO=polaris-pitr-repo
WORK="$(mktemp -d)"
MARK_SECONDS="${POLARIS_PITR_MARK_SECONDS:-40}"
BUILD=1 CONTROL=0
for arg in "$@"; do
    case "$arg" in
        --no-build) BUILD=0 ;;
        --prove-control) CONTROL=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done
leftovers() {  # what an earlier run left: containers, network, repository volume
    docker rm -f -v "$PRI" "$RES" > /dev/null 2>&1 || true
    docker network rm "$NET" > /dev/null 2>&1 || true
    docker volume rm "$REPO" > /dev/null 2>&1 || true
}
cleanup() { leftovers; rm -rf "$WORK"; }
trap cleanup EXIT
fail() {
    echo "--- $RES logs (last 20) ---" >&2; docker logs "$RES" 2>&1 | tail -20 >&2 || true
    echo "FAIL: $*" >&2; exit 1
}
psql_pri() { docker exec -e PGPASSWORD=rootpw "$PRI" psql -h 127.0.0.1 -U postgres -d polaris -tAqc "$1"; }
psql_res() { docker exec -e PGPASSWORD=rootpw "$RES" psql -h 127.0.0.1 -U postgres -d polaris -tAqc "$1"; }
# The markers as of now: how many, and a digest of every (id, commit time) pair.
STATE="SELECT count(*) || ' ' || md5(coalesce(string_agg(id || '@' || ts, ',' ORDER BY id), '')) FROM pitr_marker"
leftovers

if [[ "$BUILD" == 1 ]]; then
    echo "== 0. build the pgbackrest-enabled postgres image =="
    docker build -q -f "$ROOT/polaris_web/Dockerfile.postgres" -t "$PG_IMAGE" "$ROOT" > /dev/null
fi
docker network create "$NET" > /dev/null
docker volume create "$REPO" > /dev/null
: > "$WORK/creds.conf"

echo "== 1. a primary archiving its WAL, and a full backup =="
docker run -d --name "$PRI" --network "$NET" \
    -e POSTGRES_PASSWORD=rootpw -e POSTGRES_DB=polaris \
    -v "$REPO:/var/lib/pgbackrest" \
    -v "$ROOT/polaris_web/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro" \
    -v "$WORK/creds.conf:/etc/pgbackrest/conf.d/repo-creds.conf:ro" \
    "$PG_IMAGE" \
    -c wal_level=replica -c archive_mode=on \
    -c "archive_command=pgbackrest --stanza=polaris archive-push %p" \
    -c archive_timeout=60 > /dev/null
for _ in $(seq 1 120); do psql_pri 'SELECT 1' > /dev/null 2>&1 && break; sleep 1; done
psql_pri 'SELECT 1' > /dev/null 2>&1 || fail "the primary did not come up"
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris stanza-create > /dev/null
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris check > /dev/null
psql_pri "CREATE TABLE pitr_marker (id serial PRIMARY KEY, ts timestamptz NOT NULL DEFAULT clock_timestamp())" > /dev/null
docker exec -u postgres "$PRI" pgbackrest --stanza=polaris --type=full backup > /dev/null
echo "   backed up: $(psql_pri "SELECT count(*) FROM IdentityToken") tokens"

echo "== 2. a marker a second for ${MARK_SECONDS}s; T taken from the database's clock halfway =="
half=$(( MARK_SECONDS / 2 ))
for i in $(seq 1 "$MARK_SECONDS"); do
    psql_pri "INSERT INTO pitr_marker DEFAULT VALUES" > /dev/null
    if [[ "$i" == "$half" ]]; then
        sleep 0.5
        T=$(psql_pri "SELECT clock_timestamp()")
        AT_T=$(psql_pri "$STATE")
        TOKENS_AT_T=$(psql_pri "SELECT count(*) FROM IdentityToken")
        sleep 0.5
        echo "   T = $T: markers ${AT_T%% *}, tokens $TOKENS_AT_T"
        continue
    fi
    sleep 1
done
AT_END=$(psql_pri "$STATE")
[[ "${AT_END%% *}" -gt "${AT_T%% *}" ]] || fail "no marker was committed after T"
echo "   at the end: markers ${AT_END%% *}"

echo "== 3. the archive holds everything; then the primary and its volume are destroyed =="
# The segment pg_switch_wal() completes holds the last marker; T's restore needs it archived.
SEG=$(psql_pri "SELECT pg_walfile_name(pg_switch_wal())")
for _ in $(seq 1 60); do
    [[ "$(psql_pri "SELECT coalesce(last_archived_wal, '') >= '$SEG' FROM pg_stat_archiver")" == t ]] && break
    sleep 1
done
[[ "$(psql_pri "SELECT coalesce(last_archived_wal, '') >= '$SEG' FROM pg_stat_archiver")" == t ]] \
    || fail "the archive did not take segment $SEG within 60 s"
docker kill -s KILL "$PRI" > /dev/null
docker rm -f -v "$PRI" > /dev/null

TARGET="--type=time \"--target=$T\" --target-action=promote"
[[ "$CONTROL" == 1 ]] && TARGET=""
echo "== 4. restore $([[ "$CONTROL" == 1 ]] && echo "to the archive's end (the control)" || echo "to T and promote") =="
docker run -d --name "$RES" --network "$NET" --user postgres \
    -v "$REPO:/var/lib/pgbackrest" \
    -v "$ROOT/polaris_web/pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro" \
    "$PG_IMAGE" \
    sh -c "rm -rf /var/lib/postgresql/data/* && pgbackrest --stanza=polaris $TARGET restore && exec postgres" > /dev/null
for _ in $(seq 1 600); do
    [[ "$(psql_res 'SELECT pg_is_in_recovery()' 2> /dev/null | tr -d '[:space:]')" == f ]] && break
    sleep 1
done
[[ "$(psql_res 'SELECT pg_is_in_recovery()' 2> /dev/null | tr -d '[:space:]')" == f ]] || fail "the restore did not reach T and promote within 600 s"

echo "== 5. what came back =="
GOT=$(psql_res "$STATE")
if [[ "$CONTROL" == 1 ]]; then
    late=$(psql_res "SELECT count(*) FROM pitr_marker WHERE ts > '$T'")
    [[ "$GOT" != "$AT_T" && "$late" -gt 0 ]] \
        || { echo "FAIL: the control restored to the archive's end and the checks still saw T's state" >&2; exit 1; }
    echo "  ok (control): a restore to the archive's end brings back the $late markers after T; the checks tell it from T"
    exit 0
fi
[[ "$GOT" == "$AT_T" ]] || fail "the markers came back as '${GOT}', not as they stood at T: '${AT_T}'"
echo "  ok: exactly the ${AT_T%% *} markers committed by T, digest equal"
after=$(psql_res "SELECT count(*) FROM pitr_marker WHERE ts > '$T'")
[[ "$after" == 0 ]] || fail "$after marker(s) committed after T came back"
echo "  ok: none of the $(( ${AT_END%% *} - ${AT_T%% *} )) markers committed after T came back"
[[ "$(psql_res "SELECT count(*) FROM IdentityToken")" == "$TOKENS_AT_T" ]] || fail "the token count differs from T's"
echo "  ok: the token count is T's ($TOKENS_AT_T)"
echo "a restore to a chosen point in time stopped exactly there"
