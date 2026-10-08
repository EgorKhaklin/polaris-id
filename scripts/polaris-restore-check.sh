#!/usr/bin/env bash
# Copyright 2026 Egor Khaklin and the Polaris contributors
# SPDX-License-Identifier: Apache-2.0
# ============================================================================
# polaris-restore-check.sh - restore the newest pgBackRest backup and the WAL archive after it into
# a scratch instance, prove the copy against the live database, and record the result (lab record
# 017, gate row OP-11).
#
# It runs INSIDE the postgres image, which carries it at /opt/polaris/scripts, as root so it can
# hand pgBackRest and PostgreSQL to the postgres user. scripts/polaris-restore-verify.sh starts it
# in a one-off container of the Compose service, which brings the repository, its configuration and
# the secrets; it reaches the live database over the service's network, as postgres.
#
# What a run proves, in order (the first that fails ends the run, and nothing is recorded):
#   1. the newest backup and the WAL that makes it consistent are intact (`pgbackrest verify --set`);
#      damage elsewhere in the repository is reported and noted, not fatal;
#   2. the archive is current: the live database switches WAL, and the file it completes is
#      archived within --archive-timeout;
#   3. the newest backup and the archive after it restore, and PostgreSQL starts on them and
#      finishes recovery, with archiving OFF (a copy must never push WAL into the repository) and
#      no TCP listener;
#   4. the copy is this cluster (system identifier), its replay reached the switch, it carries the
#      live schema_version history, and pg_amcheck finds its tables and B-tree indexes sound;
#   5. every append-only table (a reject_*_modification trigger refuses its UPDATE and DELETE) with a server-assigned time
#      holds the same rows in the copy as in the live database, counted and hashed, over the
#      window from --window-days before the switch to --margin-minutes before it (and before any
#      transaction still open at the switch). --full compares from the beginning.
# Then it records a BackupEvent of kind 'restore-verified' on the live database
# (PolarisRestoreUnverified pages when the newest is 8 days old).
#
# Usage (inside the container):
#   polaris-restore-check.sh [--keep] [--full] [--window-days N] [--margin-minutes N]
#                            [--archive-timeout S] [--recovery-timeout S]
#   polaris-restore-check.sh --compare-only     # steps 4-5 again, against a copy a --keep run left up
# Environment: POLARIS_LIVE_HOST (postgres), POLARIS_LIVE_PORT (5432), POLARIS_LIVE_DB (polaris),
#   POLARIS_LIVE_PASSWORD_FILE (/run/secrets/polaris_db_root_password), POLARIS_RESTORE_DIR
#   (/var/lib/postgresql/restore-verify), POLARIS_PGBACKREST_STANZA (polaris).
# Exit: 0 verified and recorded; 1 a check failed; 2 usage; 3 nothing to verify here (no archiving,
#   no backup, no room for the copy).
# ============================================================================
set -euo pipefail

STANZA="${POLARIS_PGBACKREST_STANZA:-polaris}"
LIVE_HOST="${POLARIS_LIVE_HOST:-postgres}"
LIVE_PORT="${POLARIS_LIVE_PORT:-5432}"
DB="${POLARIS_LIVE_DB:-polaris}"
PWFILE="${POLARIS_LIVE_PASSWORD_FILE:-/run/secrets/polaris_db_root_password}"
DIR="${POLARIS_RESTORE_DIR:-/var/lib/postgresql/restore-verify}"
SOCKDIR=/var/run/postgresql
STATE="${DIR}.state"
LOG="${DIR}.log"
KEEP=0; COMPARE_ONLY=0; FULL=0
WINDOW_DAYS=8; MARGIN_MIN=15; ARCHIVE_TIMEOUT=300; RECOVERY_TIMEOUT=14400

usage() { sed -n '/^# Usage/,/^# Exit/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep) KEEP=1 ;;
        --compare-only) COMPARE_ONLY=1 ;;
        --full) FULL=1 ;;
        --window-days) WINDOW_DAYS="${2:?}"; shift ;;
        --margin-minutes) MARGIN_MIN="${2:?}"; shift ;;
        --archive-timeout) ARCHIVE_TIMEOUT="${2:?}"; shift ;;
        --recovery-timeout) RECOVERY_TIMEOUT="${2:?}"; shift ;;
        -h|--help) usage ;;
        *) echo "restore-check: unknown argument $1" >&2; usage ;;
    esac
    shift
done
for n in "$WINDOW_DAYS" "$MARGIN_MIN" "$ARCHIVE_TIMEOUT" "$RECOVERY_TIMEOUT"; do
    [[ "$n" =~ ^[0-9]+$ ]] || { echo "restore-check: $n is not a whole number" >&2; exit 2; }
done

say() { printf 'restore-check: %s\n' "$*"; }
fail() {
    printf 'restore-check: FAILED: %s\n' "$*" >&2
    # --keep keeps a copy that failed too, so the operator can look at it.
    if [[ "$KEEP" == 1 && "$COMPARE_ONLY" == 0 ]] && copy_up; then
        printf 'failed: %s\n' "$*" > "${DIR}.verdict"
        trap - EXIT
        while :; do sleep 3600; done
    fi
    exit 1
}
na() { printf 'restore-check: nothing to verify: %s\n' "$*" >&2; exit 3; }
if command -v gosu >/dev/null 2>&1; then AS_PG=(gosu postgres); else AS_PG=(su-exec postgres); fi
[[ "$(id -u)" == 0 ]] || { echo "restore-check: run as root (it hands pgBackRest and PostgreSQL to postgres)" >&2; exit 2; }
[[ -r "$PWFILE" ]] || na "no password file for the live database at $PWFILE"
PGPASSWORD="$(cat "$PWFILE")"; export PGPASSWORD
# Both sides render rows the same way, whatever the server's defaults.
export PGOPTIONS="-c TimeZone=UTC -c DateStyle=ISO,YMD -c IntervalStyle=postgres -c extra_float_digits=1 -c bytea_output=hex"

live() { psql -X -qtA -v ON_ERROR_STOP=1 -h "$LIVE_HOST" -p "$LIVE_PORT" -U postgres -d "$DB" -c "$1"; }
copy() { "${AS_PG[@]}" psql -X -qtA -v ON_ERROR_STOP=1 -h "$SOCKDIR" -p 5432 -U postgres -d "$DB" -c "$1"; }
copy_up() { "${AS_PG[@]}" pg_ctl -D "$DIR" status >/dev/null 2>&1; }

# --- 4 and 5: what the copy must be ----------------------------------------------------------
prove_copy() {
    # shellcheck disable=SC1090
    . "$STATE"   # SWITCH_LSN, LO, HI (written when the probe was taken)
    local sid_live sid_copy replayed hist_live hist_copy
    sid_live="$(live "SELECT system_identifier FROM pg_control_system()")"
    sid_copy="$(copy "SELECT system_identifier FROM pg_control_system()")"
    [[ -n "$sid_live" && "$sid_live" == "$sid_copy" ]] \
        || fail "the copy is another cluster (system identifier $sid_copy, live $sid_live)"
    replayed="$(copy "SELECT pg_last_wal_replay_lsn()")"
    if [[ "$(copy "SELECT coalesce(pg_last_wal_replay_lsn() >= '$SWITCH_LSN'::pg_lsn, false)")" != t ]]; then
        grep -E 'archive-get|invalid|unable|ERROR|FATAL|WARN' "$LOG" 2>/dev/null | tail -5 >&2 || true
        fail "the copy's replay stopped at $replayed, before the WAL switch at $SWITCH_LSN: WAL the live database wrote is missing from the archive or unreadable"
    fi
    hist_live="$(live "SELECT count(*) || ' ' || md5(coalesce(string_agg(event_id || ':' || name || ':' || event_type || ':' || file_sha256, ',' ORDER BY event_id), '')) FROM schema_version")"
    hist_copy="$(copy "SELECT count(*) || ' ' || md5(coalesce(string_agg(event_id || ':' || name || ':' || event_type || ':' || file_sha256, ',' ORDER BY event_id), '')) FROM schema_version")"
    [[ "$hist_live" == "$hist_copy" ]] || fail "schema_version differs: live ${hist_live%% *} events, copy ${hist_copy%% *}"
    say "the copy is this cluster ($sid_live), replayed to $replayed (the switch was $SWITCH_LSN), schema history equal (${hist_live%% *} events)"

    if ! "${AS_PG[@]}" pg_amcheck -h "$SOCKDIR" -p 5432 -U postgres -d "$DB" --install-missing --heapallindexed > "${DIR}.amcheck" 2>&1; then
        tail -20 "${DIR}.amcheck" >&2
        fail "pg_amcheck found the copy's tables or indexes unsound"
    fi
    say "pg_amcheck: every table and B-tree index of the copy is sound"

    # The append-only tables (their reject_*_modification trigger refuses every UPDATE and DELETE; the
    # enforce_*_immutability ones allow some changes, so a row there may differ for good reason), and
    # for each its first column whose time the server assigns.
    local tables
    tables="$(live "SELECT quote_ident(n.nspname) || '.' || quote_ident(c.relname) || '|' || coalesce(quote_ident(d.attname), '')
                     FROM pg_trigger tg
                     JOIN pg_proc p ON p.oid = tg.tgfoid AND p.proname ~ '^reject_.*_modification$'
                     JOIN pg_class c ON c.oid = tg.tgrelid AND c.relkind IN ('r', 'p') AND NOT c.relispartition
                     JOIN pg_namespace n ON n.oid = c.relnamespace
                     LEFT JOIN LATERAL (
                         SELECT a.attname FROM pg_attribute a
                           JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
                          WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                            AND a.atttypid IN ('timestamp'::regtype, 'timestamptz'::regtype)
                            AND pg_get_expr(ad.adbin, ad.adrelid) ~* '(current_timestamp|localtimestamp|now\\(\\)|statement_timestamp\\(\\)|transaction_timestamp\\(\\)|clock_timestamp\\(\\))'
                          ORDER BY a.attnum LIMIT 1) d ON true
                    GROUP BY 1 ORDER BY 1")"
    [[ -n "$tables" ]] || fail "the live database has no append-only table; this is not a Polaris schema"
    local compared=0 rows=0 skipped=() differ=() tbl col q a b
    while IFS='|' read -r tbl col; do
        if [[ -z "$col" ]]; then skipped+=("$tbl"); continue; fi
        q="SELECT count(*) || ' ' || coalesce(sum(('x' || substr(md5(t::text), 1, 15))::bit(60)::bigint::numeric), 0)
             FROM $tbl t WHERE $col >= '$LO'::timestamptz AND $col <= '$HI'::timestamptz"
        a="$(live "$q")"; b="$(copy "$q")"
        if [[ "$a" != "$b" ]]; then
            differ+=("$tbl (live ${a%% *} rows, copy ${b%% *})")
        fi
        compared=$((compared + 1)); rows=$((rows + ${a%% *}))
    done <<< "$tables"
    if [[ ${#differ[@]} -gt 0 ]]; then
        fail "the copy differs from the live database in ${#differ[@]} append-only table(s) between $LO and $HI: ${differ[*]}"
    fi
    COMPARED="$compared"; ROWS="$rows"
    say "$compared append-only tables hold the same $rows rows in the copy and the live database, $LO to $HI"
    if [[ ${#skipped[@]} -gt 0 ]]; then
        say "not compared (no server-assigned time to bound them by): ${skipped[*]}"
    fi
}

if [[ "$COMPARE_ONLY" == 1 ]]; then
    [[ -r "$STATE" ]] && copy_up || { echo "restore-check: no copy is up here; start one with --keep" >&2; exit 2; }
    prove_copy
    say "verified again (not recorded: a comparison is not a restore)"
    exit 0
fi

# --- preconditions ----------------------------------------------------------------------------
[[ ! -e "$DIR" ]] || { echo "restore-check: $DIR already exists (a kept copy?); remove it first" >&2; exit 2; }
live "SELECT 1" >/dev/null || fail "cannot reach the live database at $LIVE_HOST:$LIVE_PORT"
[[ "$(live "SHOW archive_mode")" != off ]] || na "WAL archiving is off on the live database (POLARIS_PGBACKREST_ENABLED)"
info="$("${AS_PG[@]}" pgbackrest --stanza="$STANZA" --output=json info 2>/dev/null)" || na "pgBackRest has no readable repository for stanza $STANZA"
# The image has no Python: the labels, oldest first, straight from pgBackRest's compact JSON.
label="$(printf '%s' "$info" | grep -o '"label":"[^"]*"' | tail -1 | cut -d'"' -f4 || true)"
[[ -n "$label" ]] || na "the repository holds no backup yet"
need_kb=$(( $(live "SELECT sum(pg_database_size(oid)) FROM pg_database") / 1024 ))
parent="$(dirname "$DIR")"
free_kb="$(df -Pk "$parent" | awk 'NR==2 {print $4}')"
(( free_kb > need_kb + need_kb / 5 )) \
    || na "the copy needs about $((need_kb / 1024)) MiB and $parent has $((free_kb / 1024)) MiB free (POLARIS_RESTORE_DIR)"

# --- 1. the repository ------------------------------------------------------------------------
# verify reports what it found and exits 0 either way (2.58: "status: error", "checksum invalid: 1",
# "completed successfully"), so its status line is the verdict, not its exit code; and without
# --verbose it prints no report at all for a clean repository. The newest backup
# and the WAL that makes it consistent must verify: that is what this run restores. Damage elsewhere
# in the repository (an older backup, or a gap a past archiving failure left) costs the restore
# points it covers, not this one, so it is reported and noted in the record, and does not fail it.
t0=$(date +%s)
verify() {  # verify [--set=LABEL] -> the report; returns 1 unless its status line says ok
    VERIFY_REPORT="$("${AS_PG[@]}" pgbackrest --stanza="$STANZA" --output=text --verbose=y --log-level-console=warn "$@" verify 2>&1)" \
        || fail "pgbackrest verify could not run: $(printf '%s' "$VERIFY_REPORT" | tail -3)"
    grep -Eq '^status: ok$' <<< "$VERIFY_REPORT"
}
if ! verify --set="$label" || ! grep -Fq "backup: $label, status: valid" <<< "$VERIFY_REPORT"; then
    printf '%s\n' "$VERIFY_REPORT" >&2
    fail "pgbackrest verify found the newest backup ($label) or the WAL it needs damaged"
fi
OLDER_DAMAGE=""
if ! verify; then
    OLDER_DAMAGE="$(grep -E 'invalid|missing|error' <<< "$VERIFY_REPORT" | tr -s ' ' | head -3 | paste -sd ';' -)"
    printf '%s\n' "$VERIFY_REPORT" >&2
    say "WARNING: the repository holds damage outside the newest backup (restore points it covers are lost): $OLDER_DAMAGE"
fi
say "the newest backup ($label) and the WAL it needs verify"

# --- 2. the archive is current ----------------------------------------------------------------
# The window is fixed first and ends before the oldest transaction a client still has open: such a
# transaction's rows carry its start time and may commit after the switch. Everything committed
# before then is in WAL before the switch, so a copy that replays past the switch holds it.
read -r lo hi < <(live "SELECT
        CASE WHEN $FULL = 1 THEN '-infinity' ELSE to_char((now() - make_interval(days => $WINDOW_DAYS)) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') || 'Z' END,
        to_char((least(now() - make_interval(mins => $MARGIN_MIN),
                       coalesce((SELECT min(xact_start) FROM pg_stat_activity
                                  WHERE backend_type = 'client backend' AND xact_start IS NOT NULL
                                    AND pid <> pg_backend_pid()), 'infinity'))
                 - interval '1 microsecond') AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') || 'Z'" | tr '|' ' ')
probe="$(live "SELECT pg_switch_wal()")"
target="$(live "SELECT pg_walfile_name('$probe'::pg_lsn - 1)")"
deadline=$(( $(date +%s) + ARCHIVE_TIMEOUT ))
until [[ "$(live "SELECT coalesce(last_archived_wal, '') COLLATE \"C\" >= '$target' COLLATE \"C\" FROM pg_stat_archiver")" == t ]]; do
    if (( $(date +%s) > deadline )); then
        fail "the archive is not current: $target was not archived within ${ARCHIVE_TIMEOUT}s ($(live "SELECT 'last archived ' || coalesce(last_archived_wal, 'none') || ', last failed ' || coalesce(last_failed_wal, 'none') FROM pg_stat_archiver"))"
    fi
    sleep 2
done
say "the archive is current: the WAL switch at $probe completed $target, and it is archived"

# --- 3. restore, and recover ------------------------------------------------------------------
cleanup() {
    if [[ "$KEEP" != 1 ]]; then
        copy_up && "${AS_PG[@]}" pg_ctl -D "$DIR" -m immediate stop >/dev/null 2>&1 || true
        rm -rf "$DIR" "$STATE" "$LOG" "${DIR}.amcheck" 2>/dev/null || true
    fi
}
trap cleanup EXIT
install -d -o postgres -g postgres -m 0700 "$DIR"
printf 'SWITCH_LSN=%q\nLO=%q\nHI=%q\n' "$probe" "$lo" "$hi" > "$STATE"
"${AS_PG[@]}" pgbackrest --stanza="$STANZA" --pg1-path="$DIR" --archive-mode=off --log-level-console=warn restore \
    || fail "pgBackRest could not restore $label"
# The command line wins over the restored configuration: no archiving (pgBackRest set it off too),
# no TCP, and the socket where this script looks.
# pg_ctl -w returns once the copy accepts connections (a hot standby does before recovery ends) and
# fails if it dies first; a long recovery may outlast its wait while the server keeps going.
if ! "${AS_PG[@]}" pg_ctl -D "$DIR" -l "$LOG" -w -t 300 start \
        -o "-c archive_mode=off -c listen_addresses='' -c unix_socket_directories=$SOCKDIR -c port=5432" >/dev/null; then
    copy_up || { tail -20 "$LOG" >&2; fail "PostgreSQL would not start on the restored files"; }
fi
deadline=$(( $(date +%s) + RECOVERY_TIMEOUT ))
until [[ "$(copy "SELECT pg_is_in_recovery()" 2>/dev/null || true)" == f ]]; do
    copy_up || { tail -20 "$LOG" >&2; fail "PostgreSQL stopped while recovering the restored files"; }
    (( $(date +%s) <= deadline )) || { tail -20 "$LOG" >&2; fail "recovery did not finish within ${RECOVERY_TIMEOUT}s"; }
    sleep 2
done
restored_s=$(( $(date +%s) - t0 ))
say "restored $label and the archive after it, and recovery finished, in ${restored_s}s"

# --- 4 and 5 ----------------------------------------------------------------------------------
prove_copy

# --- record -----------------------------------------------------------------------------------
detail="restored and replayed past the switch at $probe in ${restored_s}s; system id, schema history and pg_amcheck clean; $COMPARED append-only tables equal ($ROWS rows) from $lo to $hi"
[[ -z "$OLDER_DAMAGE" ]] || detail="$detail; older damage in the repository: $OLDER_DAMAGE"
psql -X -q -v ON_ERROR_STOP=1 -h "$LIVE_HOST" -p "$LIVE_PORT" -U postgres -d "$DB" \
     -v location="pgBackRest stanza $STANZA, backup $label" -v detail="${detail:0:300}" \
     <<< "INSERT INTO BackupEvent (kind, location, detail) VALUES ('restore-verified', :'location', :'detail');" \
    || fail "verified, but the result could not be recorded in BackupEvent"
say "verified, and recorded in BackupEvent (restore-verified)"

if [[ "$KEEP" == 1 ]]; then
    echo verified > "${DIR}.verdict"
    say "the copy stays up in this container (--keep): compare again with --compare-only; remove the container when done"
    trap - EXIT
    while :; do sleep 3600; done
fi
