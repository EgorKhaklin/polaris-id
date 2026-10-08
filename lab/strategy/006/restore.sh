#!/usr/bin/env bash
# Copyright 2026 Egor Khaklin and the Polaris contributors
# SPDX-License-Identifier: Apache-2.0
# ============================================================================
# lab/strategy/006/restore.sh: the stack try.sh started proves that its newest backup restores, and
# the proof refuses what it must (lab record 017, gate row OP-11).
#
# On that stack, through scripts/polaris-restore-verify.sh:
#   1. a full pgBackRest backup, recorded. alerts.sh, when it ran first, left a gap in the archive on
#      purpose (its /bin/true archive_command), and a restore starts from the newest backup;
#   2. the newest backup and the archive after it restore into a scratch copy, which is proven against
#      the live database: exit 0, and one more restore-verified BackupEvent;
#   3. with archive_command failing, the run fails on the archive and records nothing;
#   4. --keep leaves the copy up, with archiving off and no TCP listener; --compare-only passes on
#      it, and names the table once a row of the copy is deleted;
#   5. a damaged WAL file archived after the newest backup: the copy's replay stops short of the
#      switch, and the run records nothing;
#   6. a damaged file of the newest backup: pgbackrest verify stops the run, which records nothing.
#      The repository stays damaged, so these run last.
# Exit: 0 every step held; 1 a step failed.
# ============================================================================
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE="${ROOT}/lab/strategy/006"
export COMPOSE_PROJECT_NAME=polaris-try POLARIS_DOMAIN=localhost
export POLARIS_COMPOSE_EXTRA="-f ${ROOT}/polaris_web/docker-compose.citest.yml -f ${HERE}/names.yml"
COMPOSE=(docker compose -f "${ROOT}/polaris_web/docker-compose.prod.yml"
         -f "${ROOT}/polaris_web/docker-compose.citest.yml" -f "${HERE}/names.yml")
VERIFY="${ROOT}/scripts/polaris-restore-verify.sh"
COPY=polaris-restore-verify
T0=$(date +%s)
step() { printf '\n[%3ds] %s\n' "$(( $(date +%s) - T0 ))" "$1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok: $*"; }
sql() { "${COMPOSE[@]}" exec -T postgres psql -U postgres -d polaris -X -qtA -v ON_ERROR_STOP=1 -c "$1" < /dev/null; }
verified() { sql "SELECT count(*) FROM BackupEvent WHERE kind = 'restore-verified'"; }
copy_sql() { docker exec "$COPY" gosu postgres psql -X -qtA -h /var/run/postgresql -d polaris -c "$1"; }
SAVED_ARCHIVE_COMMAND=""
cleanup() {
    docker rm -f "$COPY" > /dev/null 2>&1 || true
    if [[ -n "$SAVED_ARCHIVE_COMMAND" ]]; then
        sql "ALTER SYSTEM SET archive_command = '${SAVED_ARCHIVE_COMMAND//\'/\'\'}'" > /dev/null 2>&1
        sql "SELECT pg_reload_conf()" > /dev/null 2>&1
    fi
}
trap cleanup EXIT
[[ "$(sql "SHOW archive_mode" 2>/dev/null)" == on ]] \
    || fail "run lab/strategy/006/try.sh first: this needs its stack, archiving"

step "1/6 a full pgBackRest backup, recorded"
"${COMPOSE[@]}" exec -T -u postgres postgres pgbackrest --stanza=polaris --type=full --log-level-console=warn backup < /dev/null \
    || fail "the full backup failed"
sql "INSERT INTO BackupEvent (kind, location, detail) VALUES ('pgbackrest', 'pgBackRest stanza polaris', 'full, by lab/strategy/006/restore.sh')" > /dev/null \
    || fail "recording the backup"
ok "a full backup, recorded"

step "2/6 the newest backup restores, and the copy is proven against the live database"
before=$(verified)
# No margin: on a stack minutes old every row is recent, and the window must hold them to prove
# anything. The check still ends it before any transaction a client holds open.
out=$(bash "$VERIFY" --margin-minutes 0 2>&1); rc=$?
printf '%s\n' "$out" | grep -E '^restore-check' | sed 's/^/    /'
[[ $rc -eq 0 ]] || { printf '%s\n' "$out" | tail -25 >&2; fail "the restore check failed (exit $rc)"; }
[[ "$(verified)" -eq $((before + 1)) ]] || fail "the verified restore was not recorded"
tables=$(printf '%s\n' "$out" | sed -n 's/.*: \([0-9]*\) append-only tables hold the same \([0-9]*\) rows.*/\1 \2/p')
read -r ntables nrows <<< "${tables:-0 0}"
(( ntables >= 20 && nrows > 0 )) || fail "the comparison covered $ntables tables and $nrows rows: too few to prove anything"
ok "verified and recorded: $ntables append-only tables, $nrows rows, equal in the copy and the live database"

step "3/6 the archive is not current: the run must fail and record nothing"
SAVED_ARCHIVE_COMMAND=$(sql "SHOW archive_command")
sql "ALTER SYSTEM SET archive_command = '/bin/false'" > /dev/null && sql "SELECT pg_reload_conf()" > /dev/null \
    || fail "configuring a failing archive_command"
sql "INSERT INTO BackupEvent (kind, location, detail) VALUES ('pgbackrest', 'lab/strategy/006/restore.sh', 'a write the archive must take')" > /dev/null
before=$(verified)
out=$(bash "$VERIFY" --margin-minutes 0 --archive-timeout 20 2>&1); rc=$?
[[ $rc -eq 1 ]] || { printf '%s\n' "$out" >&2; fail "with archiving failing the run exited $rc, not 1"; }
printf '%s\n' "$out" | grep -q 'the archive is not current' || { printf '%s\n' "$out" >&2; fail "the run failed, but not on the archive"; }
[[ "$(verified)" -eq $before ]] || fail "a run that failed recorded a verified restore"
cleanup; SAVED_ARCHIVE_COMMAND=""
for _ in $(seq 1 30); do
    [[ "$(sql "SELECT coalesce(last_archived_time > coalesce(last_failed_time, '-infinity'), false) FROM pg_stat_archiver")" == t ]] && break
    sleep 2
done
ok "refused: $(printf '%s\n' "$out" | sed -n 's/^restore-check: FAILED: //p' | cut -c1-120); nothing recorded; archiving restored"

step "4/6 a kept copy: archiving off, no TCP; --compare-only names a row the copy lost"
bash "$VERIFY" --keep --margin-minutes 0 > /dev/null 2>&1 || fail "the --keep run did not verify"
[[ "$(copy_sql "SHOW archive_mode")" == off ]] || fail "the copy runs with archiving on: it could push WAL into the repository"
[[ -z "$(copy_sql "SHOW listen_addresses")" ]] || fail "the copy listens on TCP"
bash "$VERIFY" --compare-only > /dev/null 2>&1 || fail "--compare-only failed on the copy as restored"
copy_sql "ALTER TABLE backupevent DISABLE TRIGGER USER" > /dev/null
copy_sql "DELETE FROM backupevent WHERE event_id = (SELECT min(event_id) FROM backupevent)" > /dev/null \
    || fail "deleting a row from the copy"
out=$(bash "$VERIFY" --compare-only 2>&1); rc=$?
[[ $rc -eq 1 ]] && printf '%s\n' "$out" | grep -q 'public.backupevent' \
    || { printf '%s\n' "$out" >&2; fail "--compare-only did not name the table the copy lost a row from (exit $rc)"; }
bash "$VERIFY" --discard > /dev/null
ok "the copy ran with archiving off and no listener; the deleted row was named: $(printf '%s\n' "$out" | grep -o 'public.backupevent ([^)]*)')"

# The newest backup and where its WAL stops, from pgBackRest itself.
newest() {  # newest label|stop
    "${COMPOSE[@]}" exec -T -u postgres postgres pgbackrest --stanza=polaris --output=json info < /dev/null 2> /dev/null \
        | python3 -c "import json,sys; b=json.load(sys.stdin)[0]['backup'][-1]; print(b['label'] if sys.argv[1] == 'label' else b['archive']['stop'])" "$1"
}
damage() {  # damage <file in the postgres container>: 16 bytes overwritten in its middle
    "${COMPOSE[@]}" exec -T -u postgres postgres sh -c "printf XXXXXXXXXXXXXXXX | dd of='$1' bs=1 seek=200 conv=notrunc 2>/dev/null" < /dev/null
}

step "5/6 a damaged WAL file archived after the newest backup: the copy must stop short"
STOP=$(newest stop); [[ -n "$STOP" ]] || fail "could not read where the newest backup's WAL stops"
victim=$("${COMPOSE[@]}" exec -T postgres sh -c "ls /var/lib/pgbackrest/archive/polaris/*/*/ | grep -E '^[0-9A-F]{24}-' | sort" < /dev/null \
         | awk -v stop="$STOP" 'substr($0, 1, 24) > stop { print; exit }' | tr -d '\r')
[[ -n "$victim" ]] || fail "no WAL archived after the newest backup to damage"
damage "$("${COMPOSE[@]}" exec -T postgres sh -c "ls /var/lib/pgbackrest/archive/polaris/*/*/$victim" < /dev/null | tr -d '\r')" \
    || fail "damaging $victim"
before=$(verified)
out=$(bash "$VERIFY" --margin-minutes 0 2>&1); rc=$?
[[ $rc -eq 1 ]] && printf '%s\n' "$out" | grep -q 'missing from the archive or unreadable' \
    || { printf '%s\n' "$out" | tail -25 >&2; fail "WAL damaged after the newest backup was not refused at replay (exit $rc)"; }
[[ "$(verified)" -eq $before ]] || fail "a run that failed recorded a verified restore"
ok "refused at replay: $(printf '%s\n' "$out" | sed -n 's/^restore-check: FAILED: //p' | cut -c1-110)"

step "6/6 a damaged file of the newest backup: the run must stop at pgbackrest verify"
LABEL=$(newest label)
# A data file of the backup (a bundle, or a copied file), not its manifest, which pgBackRest keeps twice.
file=$("${COMPOSE[@]}" exec -T postgres sh -c "find /var/lib/pgbackrest/backup/polaris/$LABEL -type f -size +4k ! -name 'backup.manifest*' | sort | head -1" < /dev/null | tr -d '\r')
[[ -n "$file" ]] || fail "no file of the newest backup ($LABEL) to damage"
damage "$file" || fail "damaging $file"
before=$(verified)
out=$(bash "$VERIFY" --margin-minutes 0 2>&1); rc=$?
[[ $rc -eq 1 ]] && printf '%s\n' "$out" | grep -q "verify found the newest backup ($LABEL)" \
    || { printf '%s\n' "$out" | tail -25 >&2; fail "a damaged file of the newest backup was not refused at verify (exit $rc)"; }
[[ "$(verified)" -eq $before ]] || fail "a run that failed recorded a verified restore"
ok "refused at verify: $(printf '%s\n' "$out" | grep -E 'checksum invalid|status:' | tr -s ' ' | tr '\n' ' ')"

echo
echo "the newest backup restores and is proven; an archive that is not current, a copy that differs, a damaged WAL file and a damaged backup are each refused"
