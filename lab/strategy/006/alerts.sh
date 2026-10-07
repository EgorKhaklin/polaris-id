#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# lab/strategy/006/alerts.sh: do the infrastructure alerts fire when their condition is real, and
# clear when it is repaired? (lab record 017, gate row OP-15). On the stack try.sh started, it runs
# Prometheus with the shipped rules (each `for:` shortened to 5 s, rules evaluated every 2 s) and
# the blackbox exporter with the shipped module, both on the stack's network, and:
#
#   1. reads every infrastructure signal off the running app: the clock skew, the WAL archive's
#      last success and failure, the state filesystem, the newest backup per kind;
#   2. the edge's certificate: Caddy's internal authority issues 12-hour certificates, so
#      PolarisCertificateExpiring must fire, from the certificate the edge actually serves;
#   3. backups: a fresh stack has none on record, so PolarisBackupStale must fire; then
#      polaris-backup.sh takes and records one, and the alert must clear;
#   4. WAL archiving: archive_mode on with an archive_command that fails, so PolarisArchiveFailing
#      must fire; then one that succeeds, and it must clear. The stack's settings are put back.
#
# Replica lag, disk and clock skew are proven by the rules' promtool unit tests and the app's own
# tests; this stack has no replica, its disk is the host's, and its clock is the host's.
#
# Run try.sh first. Exit: 0 every alert fired and cleared as required; 1 otherwise, saying which.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE="${ROOT}/lab/strategy/006"
OBS="${ROOT}/deploy/observability"
export COMPOSE_PROJECT_NAME=polaris-try POLARIS_DOMAIN=localhost
COMPOSE=(docker compose -f "${ROOT}/polaris_web/docker-compose.prod.yml"
         -f "${ROOT}/polaris_web/docker-compose.citest.yml" -f "${HERE}/names.yml")
NET=polaris-try_polaris-net
PROM_IMAGE="prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"
BB_IMAGE="prom/blackbox-exporter@sha256:e753ff9f3fc458d02cca5eddab5a77e1c175eee484a8925ac7d524f04366c2fc"
PROM=polaris-alerts-drill-prometheus BB=polaris-alerts-drill-blackbox
WORK="$(mktemp -d)"
T0=$(date +%s)
step() { printf '\n[%3ds] %s\n' "$(( $(date +%s) - T0 ))" "$1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok: $*"; }
psql_owner() {  # psql_owner <statement>...: each statement in its own transaction (ALTER SYSTEM needs that)
    local args=() st
    for st in "$@"; do args+=(-c "${st}"); done
    "${COMPOSE[@]}" exec -T postgres psql -U postgres -d polaris -X -qtA -v ON_ERROR_STOP=1 "${args[@]}"
}
# The stack's own archive settings, as ALTER SYSTEM left them before this drill (archiving is on by
# default since gate row OP-14, so RESET would switch it off). Read from the file, not from SHOW:
# with archive_mode off, SHOW archive_command prints "(disabled)".
auto_conf() {  # auto_conf <name>: the value postgresql.auto.conf holds for it, or nothing
    psql_owner "SELECT setting FROM pg_file_settings WHERE name = '$1' AND sourcefile LIKE '%postgresql.auto.conf' ORDER BY seqno DESC LIMIT 1"
}
set_or_reset() {  # set_or_reset <name> <value>: ALTER SYSTEM SET it, or RESET it when the value is empty
    if [[ -n "$2" ]]; then
        "${COMPOSE[@]}" exec -T postgres psql -U postgres -d polaris -X -qtA -v ON_ERROR_STOP=1 -v v="$2" \
            <<<"ALTER SYSTEM SET $1 = :'v';"
    else
        psql_owner "ALTER SYSTEM RESET $1"
    fi
}
restore_archive() {  # the stack's own archive settings, whatever this drill changed
    set_or_reset archive_mode "${SAVED_ARCHIVE_MODE:-}" > /dev/null 2>&1
    set_or_reset archive_command "${SAVED_ARCHIVE_COMMAND:-}" > /dev/null 2>&1
}
cleanup() {
    docker rm -f "${PROM}" "${BB}" > /dev/null 2>&1
    [[ -n "${ARCHIVE_TOUCHED:-}" ]] && { restore_archive; "${COMPOSE[@]}" restart postgres > /dev/null 2>&1; }
    rm -rf "${WORK}"
}
trap cleanup EXIT

[[ -s "${HERE}/out/caddy-root.crt" ]] || fail "run lab/strategy/006/try.sh first (it starts the stack this examines)"
docker network inspect "${NET}" > /dev/null 2>&1 || fail "no ${NET}: is the try.sh stack up?"

# The drill copy of the shipped configuration: the same rules and jobs, faster.
sed -e 's/^\(  scrape_interval: \).*/\12s/' -e 's/^\(  evaluation_interval: \).*/\12s/' \
    -e '/^alerting:/,/^scrape_configs:/{/^alerting:/d;/^  alertmanagers:/d;/^    - static_configs:/d;/^        - targets:/d;}' \
    "${OBS}/prometheus.yml" > "${WORK}/prometheus.yml"
sed -e 's/^\(        for: \)[0-9]*[smh]$/\15s/' "${OBS}/polaris-alerts.yml" > "${WORK}/polaris-alerts.yml"
cp "${OBS}/polaris-slo.yml" "${WORK}/polaris-slo.yml"
sed 's|__POLARIS_DOMAIN__|localhost|g' "${OBS}/blackbox.yml" > "${WORK}/blackbox.yml"
grep -q "for: 5s" "${WORK}/polaris-alerts.yml" || fail "the drill copy of the rules did not take the short holds"

step "0/4 Prometheus and the blackbox exporter on the stack's network"
docker run -d --name "${BB}" --network "${NET}" --network-alias blackbox --user 65534:65534 \
    -v "${WORK}/blackbox.yml:/etc/blackbox/blackbox.yml:ro" "${BB_IMAGE}" \
    --config.file=/etc/blackbox/blackbox.yml > /dev/null || fail "starting the blackbox exporter"
docker run -d --name "${PROM}" --network "${NET}" \
    -v "${WORK}:/etc/prometheus:ro" "${PROM_IMAGE}" --config.file=/etc/prometheus/prometheus.yml > /dev/null \
    || fail "starting Prometheus"
api() {  # api <path>: GET Prometheus's HTTP API from the stack's network
    docker run --rm --network "${NET}" curlimages/curl:8.11.1 -s "http://${PROM}:9090$1"
}
alert_state() {  # alert_state <alertname>: firing, pending or inactive
    api "/api/v1/alerts" | python3 -c 'import json,sys
name = sys.argv[1]
states = [a["state"] for a in json.load(sys.stdin)["data"]["alerts"] if a["labels"].get("alertname") == name]
print("firing" if "firing" in states else "pending" if "pending" in states else "inactive")' "$1"
}
wait_for() {  # wait_for <alertname> <firing|inactive> <seconds>
    for _ in $(seq 1 "$3"); do [[ "$(alert_state "$1")" == "$2" ]] && return 0; sleep 1; done
    return 1
}
for _ in $(seq 1 60); do api "/-/ready" > /dev/null 2>&1 && break; sleep 1; done
api "/-/ready" > /dev/null 2>&1 || { docker logs "${PROM}" 2>&1 | tail -10 >&2; fail "Prometheus never became ready"; }

step "1/4 every infrastructure signal, read off the running app"
for _ in $(seq 1 30); do
    up=$(api '/api/v1/query?query=up%7Bjob%3D%22polaris%22%7D' | python3 -c 'import json,sys; r=json.load(sys.stdin)["data"]["result"]; print(sum(float(x["value"][1]) for x in r))' 2>/dev/null)
    [[ "${up}" == "1.0" || "${up}" == "2.0" ]] && break; sleep 1
done
[[ "${up:-0}" != "0" ]] || fail "Prometheus never scraped the app (job polaris)"
for series in polaris_clock_skew_seconds 'polaris_db_archive_last_timestamp_seconds{outcome="failed"}' \
              'polaris_state_filesystem_bytes{kind="size"}' 'polaris_backup_last_success_timestamp_seconds{kind="dump"}' \
              'probe_ssl_earliest_cert_expiry'; do
    q=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "${series}")
    n=$(api "/api/v1/query?query=${q}" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["data"]["result"]))' 2>/dev/null)
    [[ "${n:-0}" -ge 1 ]] || fail "Prometheus has no ${series}"
done
ok "the skew, the archive, the filesystem, the backups and the edge certificate are all scraped"

step "2/4 the edge's certificate (Caddy's internal authority issues 12-hour certificates)"
wait_for PolarisCertificateExpiring firing 60 || fail "PolarisCertificateExpiring did not fire on a 12-hour certificate"
ok "PolarisCertificateExpiring fired on the certificate the edge serves"

step "3/4 backups: none on record, then one taken"
wait_for PolarisBackupStale firing 60 || fail "PolarisBackupStale did not fire on a stack with no backup on record"
ok "PolarisBackupStale fired with no backup on record"
mkdir -p "${WORK}/backups"
bash "${ROOT}/scripts/polaris-backup.sh" --dest "${WORK}/backups" > "${WORK}/backup.log" 2>&1 \
    || { tail -10 "${WORK}/backup.log" >&2; fail "polaris-backup.sh"; }
grep -q "recorded in BackupEvent (dump)" "${WORK}/backup.log" || { tail -10 "${WORK}/backup.log" >&2; fail "the backup was not recorded"; }
wait_for PolarisBackupStale inactive 60 || fail "PolarisBackupStale did not clear after a recorded backup"
ok "a recorded backup cleared it"

step "4/4 WAL archiving: failing, then succeeding"
SAVED_ARCHIVE_MODE=$(auto_conf archive_mode) SAVED_ARCHIVE_COMMAND=$(auto_conf archive_command)
ARCHIVE_TOUCHED=1
psql_owner "ALTER SYSTEM SET archive_mode = 'on'" "ALTER SYSTEM SET archive_command = '/bin/false'" > /dev/null \
    || fail "configuring a failing archive_command"
"${COMPOSE[@]}" restart postgres > /dev/null 2>&1
for _ in $(seq 1 60); do psql_owner "SELECT 1" > /dev/null 2>&1 && break; sleep 1; done
psql_owner "SELECT pg_switch_wal()" > /dev/null 2>&1 || fail "the database did not come back to switch WAL"
wait_for PolarisArchiveFailing firing 90 || fail "PolarisArchiveFailing did not fire while every archive attempt failed"
ok "PolarisArchiveFailing fired while archive_command failed"
psql_owner "ALTER SYSTEM SET archive_command = '/bin/true'" "SELECT pg_reload_conf()" > /dev/null
psql_owner "SELECT pg_switch_wal()" > /dev/null 2>&1
wait_for PolarisArchiveFailing inactive 90 || fail "PolarisArchiveFailing did not clear once archiving succeeded"
ok "a succeeding archive_command cleared it"

printf '\nDone in %ds: each alert fired on its real condition and cleared on its repair.\n' "$(( $(date +%s) - T0 ))"
