#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# lab/strategy/006/posture.sh: do the running containers hold the posture the production compose
# file declares? (lab record 017, phase 5). On the stack try.sh started, which has just issued and
# verified a credential through it, it asks the kernel rather than the compose file:
#
#   1. caddy, app, pgbouncer and redis run on a read-only root: Docker says so, and a write to /
#      inside each is refused with "Read-only file system";
#   2. what they must write lands in memory or a volume: the app's /tmp and pgbouncer's
#      /etc/pgbouncer are tmpfs, and pgbouncer's userlist.txt (the database password) is there;
#   3. every service's main process holds no effective capability and cannot gain privileges
#      (CapEff 0, NoNewPrivs 1 in /proc/1/status), postgres and redis included: they drop to
#      their own users after preparing their data directories.
#
# Run try.sh first. Exit: 0 every container held its posture; 1 one did not, and it says which.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HERE="${ROOT}/lab/strategy/006"
export COMPOSE_PROJECT_NAME=polaris-try POLARIS_DOMAIN=localhost
COMPOSE=(docker compose -f "${ROOT}/polaris_web/docker-compose.prod.yml"
         -f "${ROOT}/polaris_web/docker-compose.citest.yml" -f "${HERE}/names.yml")
FAILED=0
fail() { echo "FAIL: $*" >&2; FAILED=1; }
ok() { echo "  ok: $*"; }
cid() { "${COMPOSE[@]}" ps -q "$1" 2> /dev/null; }
status_of() { docker exec "$1" sh -c "grep '^$2:' /proc/1/status" 2> /dev/null | awk '{print $2}'; }

[[ -s "${HERE}/out/caddy-root.crt" ]] || { echo "FAIL: run lab/strategy/006/try.sh first (it starts the stack this examines)" >&2; exit 1; }

echo "== 1. read-only roots"
for svc in caddy app pgbouncer redis; do
    c=$(cid "${svc}")
    [[ -n "${c}" ]] || { fail "${svc} is not running"; continue; }
    [[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "${c}")" == true ]] \
        || { fail "${svc}: Docker does not run it on a read-only root"; continue; }
    if out=$(docker exec "${c}" sh -c 'echo probe > /posture-probe' 2>&1); then
        docker exec "${c}" sh -c 'rm -f /posture-probe' > /dev/null 2>&1
        fail "${svc}: a write to / succeeded"
    elif [[ "${out}" == *"Read-only file system"* ]]; then
        ok "${svc}: a write to / is refused (Read-only file system)"
    else
        fail "${svc}: a write to / failed for another reason: ${out}"
    fi
done

echo "== 2. what they write lands in memory"
app=$(cid app); pgb=$(cid pgbouncer)
docker exec "${app}" sh -c "grep -q '^tmpfs /tmp ' /proc/mounts" 2> /dev/null \
    && ok "app: /tmp is tmpfs" || fail "app: /tmp is not tmpfs"
docker exec "${pgb}" sh -c "grep -q '^tmpfs /etc/pgbouncer ' /proc/mounts && test -s /etc/pgbouncer/userlist.txt" 2> /dev/null \
    && ok "pgbouncer: userlist.txt is written to tmpfs /etc/pgbouncer" \
    || fail "pgbouncer: /etc/pgbouncer is not tmpfs, or it holds no userlist.txt"

echo "== 3. no capabilities, no privilege escalation"
for svc in caddy app pgbouncer redis postgres; do
    c=$(cid "${svc}")
    [[ -n "${c}" ]] || { fail "${svc} is not running"; continue; }
    capeff=$(status_of "${c}" CapEff); nnp=$(status_of "${c}" NoNewPrivs)
    if [[ "${capeff}" =~ ^0+$ && "${nnp}" == 1 ]]; then
        ok "${svc}: CapEff ${capeff}, NoNewPrivs 1"
    else
        fail "${svc}: CapEff '${capeff}', NoNewPrivs '${nnp}' (want all zero and 1)"
    fi
done

[[ ${FAILED} -eq 0 ]] || exit 1
echo "every container holds the posture the compose file declares"
