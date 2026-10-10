#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# lab/strategy/006/doctor.sh: does scripts/polaris-doctor.sh name what is broken? (lab record 017,
# gate row OP-17). On the stack try.sh started, it breaks one thing at a time and requires the
# doctor to name exactly that, then repairs it and requires a clean bill again:
#
#   0. the healthy stack                     -> nothing failing
#   1. Redis stopped                         -> redis named first
#   2. PostgreSQL stopped                    -> postgres named first
#   3. the session-key secret file emptied   -> secrets named first, the file named
#   4. a setting production refuses          -> the app (or the configuration check) named first,
#      (POLARIS_DB_SSLMODE=disable)             and the setting named by the configuration check
#
# Run try.sh first. The stack is left as it was found.
# Exit: 0 every fault was named and every repair came back clean; 1 otherwise, saying which.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE="${ROOT}/lab/strategy/006"
OUT="${HERE}/out"
# It recreates a service from the host's image tags (building it if missing): one build or deploy at a time.
source "${ROOT}/scripts/polaris-host-lock.sh"
polaris_host_lock "the lab doctor"
export COMPOSE_PROJECT_NAME=polaris-try POLARIS_DOMAIN=localhost
export POLARIS_COMPOSE_EXTRA="-f ${ROOT}/polaris_web/docker-compose.citest.yml -f ${HERE}/names.yml"
export POLARIS_DOCTOR_URL=https://localhost:8443 POLARIS_DOCTOR_CACERT="${OUT}/caddy-root.crt"
COMPOSE=(docker compose -f "${ROOT}/polaris_web/docker-compose.prod.yml"
         -f "${ROOT}/polaris_web/docker-compose.citest.yml" -f "${HERE}/names.yml")
SECRET="${ROOT}/polaris_web/secrets/polaris_secret_key"
OVERRIDE="${OUT}/doctor-bad-config.yml"
T0=$(date +%s)
step() { printf '\n[%3ds] %s\n' "$(( $(date +%s) - T0 ))" "$1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok: $*"; }
[[ -s "${POLARIS_DOCTOR_CACERT}" ]] || fail "run lab/strategy/006/try.sh first (it starts the stack this examines)"

doctor() {  # run it; leave its output in DOC and its exit status in RC
    DOC=$(bash "${ROOT}/scripts/polaris-doctor.sh" 2>&1); RC=$?
}
first_failing() { printf '%s\n' "${DOC}" | sed -n 's/.*failing: .* (start with \(.*\))\./\1/p'; }
expect_clean() {
    for _ in $(seq 1 45); do
        doctor
        [[ ${RC} -eq 0 ]] && { ok "$1: nothing failing"; return; }
        sleep 2
    done
    printf '%s\n' "${DOC}" >&2
    fail "$1: the doctor still reports a failure"
}
expect_named() {  # expect_named <component, or a|b> <what>; also requires every extra grep pattern
    local want="$1" what="$2"; shift 2
    for _ in $(seq 1 30); do
        doctor
        [[ ${RC} -eq 1 && "$(first_failing)" =~ ^(${want})$ ]] && break
        sleep 2
    done
    [[ ${RC} -eq 1 && "$(first_failing)" =~ ^(${want})$ ]] \
        || { printf '%s\n' "${DOC}" >&2; fail "${what}: the doctor named '$(first_failing)', not '${want}' (exit ${RC})"; }
    for pattern in "$@"; do
        printf '%s\n' "${DOC}" | grep -- "${pattern}" >/dev/null \
            || { printf '%s\n' "${DOC}" >&2; fail "${what}: the doctor's report does not say '${pattern}'"; }
    done
    ok "${what}: named $(first_failing) first$( [[ $# -gt 0 ]] && printf ', and said: %s' "$*")"
}
wait_healthy() {  # wait_healthy <service>
    local cid
    for _ in $(seq 1 60); do
        cid=$("${COMPOSE[@]}" ps -q "$1" 2> /dev/null)
        [[ -n "${cid}" && "$(docker inspect --format '{{.State.Health.Status}}' "${cid}" 2> /dev/null)" == healthy ]] && return
        sleep 2
    done
    fail "$1 did not come back healthy"
}

step "0/4 the healthy stack"
expect_clean "the healthy stack"

step "1/4 Redis stopped"
"${COMPOSE[@]}" stop redis > /dev/null 2>&1
expect_named redis "Redis stopped" "FAIL  redis "
"${COMPOSE[@]}" start redis > /dev/null 2>&1; wait_healthy redis
expect_clean "Redis restarted"

step "2/4 PostgreSQL stopped"
"${COMPOSE[@]}" stop postgres > /dev/null 2>&1
expect_named postgres "PostgreSQL stopped" "FAIL  postgres "
"${COMPOSE[@]}" start postgres > /dev/null 2>&1; wait_healthy postgres; wait_healthy pgbouncer
expect_clean "PostgreSQL restarted"

step "3/4 the session-key secret file emptied"
cp -p "${SECRET}" "${OUT}/doctor-secret-backup"
: > "${SECRET}"
expect_named secrets "the secret emptied" "polaris_secret_key: .* is empty"
cp -p "${OUT}/doctor-secret-backup" "${SECRET}"
expect_clean "the secret restored"

step "4/4 a setting production refuses (POLARIS_DB_SSLMODE=disable)"
printf 'services:\n  app:\n    environment:\n      POLARIS_DB_SSLMODE: disable\n' > "${OVERRIDE}"
"${COMPOSE[@]}" -f "${OVERRIDE}" up -d --no-deps --force-recreate app > /dev/null 2>&1
POLARIS_COMPOSE_EXTRA_SAVED="${POLARIS_COMPOSE_EXTRA}"
export POLARIS_COMPOSE_EXTRA="${POLARIS_COMPOSE_EXTRA} -f ${OVERRIDE}"
# The app restarts in a loop; caught between two restarts it can look briefly running, so either
# the app or the configuration check comes first. Either way the refused setting must be named.
expect_named "app|configuration" "a refused setting" "FAIL  configuration .*POLARIS_DB_SSLMODE"
export POLARIS_COMPOSE_EXTRA="${POLARIS_COMPOSE_EXTRA_SAVED}"
"${COMPOSE[@]}" up -d --no-deps --force-recreate app > /dev/null 2>&1; wait_healthy app
expect_clean "the setting restored"

printf '\nDone in %ds: every fault named first, every repair clean.\n' "$(( $(date +%s) - T0 ))"
