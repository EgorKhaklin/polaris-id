#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-upgrade-drill.sh: an operator on the previous release upgrades to this commit the way
# docs/operator/OPERATIONS.md says, and keeps everything they had (lab record 017, gate row OP-19).
#
#   1. a checkout of the previous release runs that release's own lab/strategy/006/try.sh: its
#      images, its secrets and ML-DSA-65 key, its stack; it issues credential A;
#   2. the same checkout moves to this commit, detached as a release tag's checkout is, and
#      upgrades as OPERATIONS.md's "Polaris version upgrade" says: polaris-generate-secrets.sh (it
#      writes only what is missing), then polaris-deploy.sh prod --no-pull (images, migrations,
#      objects, the app, a smoke test); the upgraded database's security state
#      (scripts/lib/polaris-db-state.sh) must equal, table by table, that of this commit installed
#      fresh, in a throwaway cluster of its own, from the postgres image the upgrade deployed
#      (scripts/lib/polaris-db-reference.sh): what an upgrade leaves different from a fresh install
#      of the same release is drift;
#   3. a release that cannot start is deployed the same way: its smoke test fails and the deploy
#      puts back the app image it replaced, which the app then runs, serving (under Docker's
#      containerd image store, which upgrade.yml turns on, as a clean install of Engine 29 has it);
#      its migrations and object sync change nothing, so the security state is exactly as step 2
#      left it;
#   4. after it: no migration is pending; every Polaris container runs an image built from this
#      commit; this commit's try.sh issues credential B on the upgraded stack and polaris-verify
#      accepts it; credential A's authenticity pack, fetched again from the upgraded stack,
#      verifies against the key the old release minted, and the app still says A's signature is
#      valid.
#
# It uses try.sh's compose project and port, so no other try.sh stack may run beside it.
#
# Usage: polaris-upgrade-drill.sh [previous-release-tag] (default: the newest v* tag before HEAD)
# Exit: 0 every step held; 1 one did not, and it says which; 2 a prerequisite is missing.
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET=$(git -C "${ROOT}" rev-parse HEAD)
FROM="${1:-$(git -C "${ROOT}" describe --tags --abbrev=0 --match 'v[0-9]*' "${TARGET}^")}"
WORK="$(mktemp -d)"
TREE="${WORK}/polaris"
export COMPOSE_PROJECT_NAME=polaris-try POLARIS_DOMAIN=localhost
T0=$(date +%s)
step() { printf '\n[%4ds] %s\n' "$(( $(date +%s) - T0 ))" "$1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok: $*"; }
cleanup() {
    docker rm -f polaris-reference-upgrade > /dev/null 2>&1 || true
    [[ -d "${TREE}" ]] && bash "${TREE}/lab/strategy/006/try.sh" --down > /dev/null 2>&1 || true
    git -C "${ROOT}" worktree remove --force "${TREE}" > /dev/null 2>&1 || true
}
trap cleanup EXIT

docker info > /dev/null 2>&1 || { echo "needs a running Docker" >&2; exit 2; }
if [[ -n "$(docker ps -q --filter label=com.docker.compose.project=polaris-try)" ]]; then
    echo "a try.sh stack is running; stop it first: bash lab/strategy/006/try.sh --down" >&2
    exit 2
fi
echo "upgrading ${FROM} ($(git -C "${ROOT}" rev-parse --short "${FROM}^{commit}")) to ${TARGET:0:8}"
# The host's image tags, for the whole drill: the try.sh and the deploy it runs go on under it.
source "${ROOT}/scripts/polaris-host-lock.sh"
polaris_host_lock "the upgrade drill"

# The database's security state, read inside try.sh's postgres container (whichever release's
# compose files made it, so found by its labels) as the superuser the image's init made, as step
# 4's psql reads it. The libraries are this commit's: the previous release's checkout has none.
source "${ROOT}/scripts/lib/polaris-db-state.sh"
source "${ROOT}/scripts/lib/polaris-db-reference.sh"
STATE_DB=polaris
REFERENCE=polaris-reference-upgrade
STATE_IN=stack
pg_container() {
    local ids
    ids=$(docker ps -q --filter label=com.docker.compose.project=polaris-try \
                      --filter label=com.docker.compose.service=postgres) || return 1
    [[ -n "${ids}" && "${ids}" != *$'\n'* ]] \
        || { echo "not one running postgres container in polaris-try (${ids:-none})" >&2; return 1; }
    printf '%s' "${ids}"
}
pg_run() { local c; c=$(pg_container) || return 1; docker exec -u postgres "${c}" "$@" < /dev/null; }
# STATE_IN=reference reads the fresh install in its own cluster instead (scripts/lib/
# polaris-db-reference.sh).
sql() {
    if [[ "${STATE_IN}" == reference ]]; then
        polaris_db_reference_sql "${REFERENCE}" "$1"
    else
        pg_run psql -X -q -At -v ON_ERROR_STOP=1 -U postgres -d "${STATE_DB}" -c "$1"
    fi
}
state() {  # NAME WHEN: the security state of ${STATE_DB} into ${WORK}/state-NAME
    polaris_db_state security > "${WORK}/state-$1" || fail "the security state could not be read $2"
}

step "1/4 the previous release, ${FROM}, as its own try.sh leaves it"
git -C "${ROOT}" worktree add --detach "${TREE}" "${FROM}" > /dev/null 2>&1 || fail "checking out ${FROM}"
OUT="${TREE}/lab/strategy/006/out"
bash "${TREE}/lab/strategy/006/try.sh" > "${WORK}/try-before.log" 2>&1 \
    || { tail -20 "${WORK}/try-before.log" >&2; fail "${FROM}'s own try.sh"; }
A=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token_id"])' "${OUT}/pack.json")
cp "${OUT}/pack.json" "${WORK}/pack-A-before.json"
ok "${FROM} issued credential #${A} and polaris-verify accepted it"
state before "on ${FROM}, before the upgrade"
ok "${FROM}'s security state read ($(grep -c . "${WORK}/state-before") facts; kept as the record)"

step "2/4 upgrade to ${TARGET:0:8} as OPERATIONS.md says"
git -C "${TREE}" checkout --detach -q "${TARGET}" || fail "moving the checkout to ${TARGET:0:8}"
bash "${TREE}/scripts/polaris-generate-secrets.sh" > "${WORK}/secrets.log" 2>&1 \
    || { tail -20 "${WORK}/secrets.log" >&2; fail "polaris-generate-secrets.sh"; }
POLARIS_COMPOSE_EXTRA="-f docker-compose.citest.yml -f ${TREE}/lab/strategy/006/names.yml" \
    bash "${TREE}/scripts/polaris-deploy.sh" prod --no-pull > "${WORK}/deploy.log" 2>&1 \
    || { tail -30 "${WORK}/deploy.log" >&2; fail "polaris-deploy.sh prod"; }
ok "polaris-deploy.sh prod finished: migrations, objects, the app, its smoke test"
state a1 "after the upgrade"
# The reference: this commit installed fresh in a throwaway cluster of its own, from the image the
# upgrade deployed. That image must carry this commit's SQL and init, or the upgrade would be
# compared with some other release.
image="$(docker inspect --format '{{.Image}}' "$(pg_container)")" && [[ -n "${image}" ]] \
    || fail "the upgraded postgres container's image could not be read"
# Its first boot gets the stack's other password files too, so it creates what the stack's did:
# with a replication password, the init (or Patroni, under the HA profile) made polaris_replicator.
ref_env=()
repl="$(pg_run printenv POLARIS_REPLICATOR_PASSWORD_FILE 2> /dev/null || true)"
[[ -z "${repl}" ]] || ref_env+=("POLARIS_REPLICATOR_PASSWORD_FILE=$(basename "${repl}")")
polaris_db_reference_run "${image}" "${REFERENCE}" "${WORK}/reference-secrets" "${WORK}/reference.log" \
        ${ref_env[@]+"${ref_env[@]}"} \
    || { tail -20 "${WORK}/reference.log" >&2; fail "installing ${TARGET:0:8} fresh in a throwaway cluster"; }
( pg_run() { docker exec -u postgres "${REFERENCE}" "$@" < /dev/null; }
  polaris_db_reference_carries "${TREE}/polaris_sql" ) \
    || fail "the upgraded postgres image does not carry ${TARGET:0:8}'s SQL and init, so it is no reference"
STATE_IN=reference
state reference "from the fresh ${TARGET:0:8} install"
STATE_IN=stack
polaris_db_reference_stop "${REFERENCE}" "${WORK}/reference-secrets"
# The reference had a cluster of its own: the operator's database and roles read as before it.
state a1-again "after the reference"
polaris_db_state_same "${WORK}/state-a1" "${WORK}/state-a1-again" \
    || fail "building the reference changed the upgraded database or the cluster's roles (< before it, > after)"
polaris_db_reference_roles "${TREE}/polaris_sql" > "${WORK}/polaris-roles" \
    || fail "the roles polaris_sql creates could not be read"
left_out="$(polaris_db_state_cross_cluster "${WORK}/state-reference" "${WORK}/state-a1" "${WORK}/polaris-roles" \
              "${WORK}/state-reference.cmp" "${WORK}/state-a1.cmp")" \
    || fail "the two clusters' states could not be set side by side"
[[ -z "${left_out}" ]] || ok "left out, a role one cluster has and Polaris does not create: $(echo ${left_out})"
polaris_db_state_same_by_table "${WORK}/state-reference.cmp" "${WORK}/state-a1.cmp" \
    || fail "the upgraded database's security state is not a fresh ${TARGET:0:8} install's (< fresh only, > upgrade only)"
moved=$(diff "${WORK}/state-before" "${WORK}/state-a1" | grep -c '^[<>]' || true)
ok "the upgraded database's security state is a fresh ${TARGET:0:8} install's, table by table ($(grep -c . "${WORK}/state-a1") facts; ${moved} moved since ${FROM})"

COMPOSE=(docker compose -f "${TREE}/polaris_web/docker-compose.prod.yml"
         -f "${TREE}/polaris_web/docker-compose.citest.yml" -f "${TREE}/lab/strategy/006/names.yml")
content() {  # a short digest of an image's layers and config; an unreadable image names itself
    local raw
    raw=$(docker image inspect --format '{{json .RootFS.Layers}}{{json .Config}}' "$1" 2> /dev/null) \
        && [[ -n "${raw}" ]] || { printf 'unreadable(%s)' "$1"; return; }
    printf '%s' "${raw}" | shasum -a 256 | cut -c1-12
}
app_content() { content "$(docker inspect --format '{{.Image}}' "$("${COMPOSE[@]}" ps -q app)")"; }
# Each service's container after the upgrade and the content of the image it runs, read now: step 3's
# deploy builds the image set again, and under Docker's containerd image store a build that moves a
# tag can drop the record of the image a running container was created from (on Docker Desktop it
# dropped caddy's, pgbouncer's and postgres's), so step 4 could not read it back. Step 4 takes this
# reading for a container still running from here, and reads one made since then itself.
SVCS=(app caddy pgbouncer postgres)
upgraded_ids=()
upgraded_content=()
for svc in "${SVCS[@]}"; do
    cid=$("${COMPOSE[@]}" ps -q "${svc}") && [[ -n "${cid}" ]] || fail "no ${svc} container after the upgrade"
    upgraded_ids+=("${cid}")
    upgraded_content+=("$(content "$(docker inspect --format '{{.Image}}' "${cid}")")")
done

step "3/4 a release that cannot start is rolled back to the image it replaced"
# polaris-deploy.sh rolled back by re-tagging the running image's ID. Under Docker's containerd image
# store, the default on a clean install of Docker Engine 29 and later, that ID no longer resolves once
# the build moves polaris-app:prod, so the rollback stopped at `docker tag` and left the failed release
# serving. The deploy now pins the running image as polaris-app:rollback-<project> before it builds.
before=$(app_content)
GUNI="${TREE}/polaris_web/gunicorn.conf.py"
cp "${GUNI}" "${WORK}/gunicorn.conf.py.good"
printf '\nraise SystemExit("the upgrade drill: a release that does not start")\n' >> "${GUNI}"
rc=0
POLARIS_COMPOSE_EXTRA="-f docker-compose.citest.yml -f ${TREE}/lab/strategy/006/names.yml" \
    bash "${TREE}/scripts/polaris-deploy.sh" prod --no-pull > "${WORK}/deploy-broken.log" 2>&1 || rc=$?
cp "${WORK}/gunicorn.conf.py.good" "${GUNI}"
[[ "${rc}" -ne 0 ]] || fail "the deploy of a release that cannot start reported success"
grep -q "Rolled back" "${WORK}/deploy-broken.log" \
    || { tail -25 "${WORK}/deploy-broken.log" >&2; fail "the deploy of a release that cannot start did not roll back"; }
after=$(app_content)
[[ "${after}" == "${before}" ]] \
    || fail "after the rollback the app runs image content ${after}, not ${before}, the image the deploy replaced"
status=$(curl -s --cacert "${OUT}/caddy-root.crt" https://localhost:8443/api/health \
         | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status"))' 2> /dev/null || true)
[[ "${status}" == healthy || "${status}" == degraded ]] || fail "the app does not serve after the rollback (status ${status:-none})"
ok "a release that could not start was rolled back to the image it replaced (content ${before}); the app serves (${status})"
# Its deploy ran the migrations (none pending) and the object sync again: neither may change a
# privilege, a definition or a setting (a sync that gave back what a migration revoked, 2026-10-10).
state a2 "after the rollback"
polaris_db_state_same "${WORK}/state-a1" "${WORK}/state-a2" \
    || fail "the failed deploy and its rollback changed the security state (< after the upgrade, > after the rollback)"
ok "the failed deploy and its rollback left the security state exactly as the upgrade did"

step "4/4 what the operator had, after the upgrade and the rollback"
mig=$(cd "${TREE}" && bash scripts/polaris-migrate.sh --target=docker-stack --dry-run --up 2>&1) \
    || { printf '%s\n' "${mig}" | tail -10 >&2; fail "polaris-migrate.sh could not read the upgraded database"; }
grep -q "no pending migrations" <<< "${mig}" \
    || fail "$(grep -c 'would apply' <<< "${mig}") migration(s) still pending after the upgrade"
ok "no migration pending"
# Lab record 017 (gate row OP-14): archiving is on by default, and the deploy turns it on for a cluster
# that ran without it and takes the first full backup, so the upgraded deployment has a point to restore to.
[[ "$("${COMPOSE[@]}" exec -T postgres psql -X -t -A -U postgres -d polaris -c 'SHOW archive_mode' < /dev/null \
      | tr -d '[:space:]')" == on ]] || fail "WAL archiving is not on after the upgrade"
"${COMPOSE[@]}" exec -T -u postgres postgres pgbackrest --stanza=polaris --output=json info < /dev/null 2> /dev/null \
    | grep '"type": *"full"' >/dev/null || fail "the repository holds no full base backup after the upgrade"
ok "WAL archiving is on and the repository holds a full base backup"
# Gate row OP-11: the deploy proved that first backup restores (scripts/polaris-restore-verify.sh) and
# recorded it, so PolarisRestoreUnverified's clock starts at a verified restore.
verified="$("${COMPOSE[@]}" exec -T postgres psql -X -t -A -U postgres -d polaris \
    -c "SELECT count(*) FROM BackupEvent WHERE kind = 'restore-verified'" < /dev/null | tr -d '[:space:]')"
[[ "${verified:-0}" -ge 1 ]] || { grep -A14 'verifying that it restores' "${WORK}/deploy.log" >&2 || true
                                 fail "the deploy recorded no verified restore of its first backup"; }
ok "the deploy restored its first backup into a scratch copy and proved it ($verified recorded)"
# Build this commit's image set the one supported way; where the upgrade already built an image
# this is a cache hit. A service whose running image differs in content (its layers or its
# config) was not rebuilt. Content, not the image ID: with Docker's containerd image store two
# fully cached builds of one Dockerfile get different IDs (BuildKit's per-build metadata).
# Each running image is read before the rebuild: once a rebuild moves the tag, the containerd
# store keeps no record of the image a container was created from. A container still running from
# the upgrade was read then (above); its image cannot have changed without a new container.
running=()
for i in "${!SVCS[@]}"; do
    cid=$("${COMPOSE[@]}" ps -q "${SVCS[$i]}") && [[ -n "${cid}" ]] || fail "no ${SVCS[$i]} container after the rollback"
    if [[ "${cid}" == "${upgraded_ids[$i]}" ]]; then
        running+=("${upgraded_content[$i]}")
    else
        running+=("$(content "$(docker inspect --format '{{.Image}}' "${cid}")")")
    fi
done
bash "${TREE}/scripts/polaris-image-build.sh" --stack prod > "${WORK}/rebuild.log" 2>&1 \
    || { tail -20 "${WORK}/rebuild.log" >&2; fail "building ${TARGET:0:8}'s images"; }
stale=()
for i in "${!SVCS[@]}"; do
    built=$(content "polaris-${SVCS[$i]}:prod")
    [[ "${running[$i]}" == "${built}" ]] || stale+=("${SVCS[$i]} runs content ${running[$i]}, not ${built}")
done
[[ ${#stale[@]} -eq 0 ]] || fail "not on the images ${TARGET:0:8} builds: $(printf '%s; ' "${stale[@]}")"
ok "app, caddy, pgbouncer and postgres run the images ${TARGET:0:8} builds"
bash "${TREE}/lab/strategy/006/try.sh" > "${WORK}/try-after.log" 2>&1 \
    || { tail -20 "${WORK}/try-after.log" >&2; fail "this commit's try.sh on the upgraded stack"; }
B=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token_id"])' "${OUT}/pack.json")
[[ "${B}" != "${A}" ]] || fail "try.sh after the upgrade did not issue a new credential"
ok "credential #${B}, issued after the upgrade, verifies"
# Credential A, issued before the upgrade, asked of the upgraded app as its operator.
BASE=https://localhost:8443 CA="${OUT}/caddy-root.crt" JAR="${WORK}/cookies"
CSRF=$(curl -s --cacert "${CA}" -c "${JAR}" -b "${JAR}" "${BASE}/login" \
       | { grep -o 'name="csrf_token" value="[^"]*"' || true; } | sed -n 1p | sed 's/.*value="//;s/"$//')
[[ "$(curl -s --cacert "${CA}" -c "${JAR}" -b "${JAR}" -o /dev/null -w '%{http_code}' \
      --data-urlencode "csrf_token=${CSRF}" --data-urlencode "username=try-operator" \
      --data-urlencode "password@"<(tr -d '\r\n' < "${OUT}/operator-password") "${BASE}/login")" == 302 ]] \
    || fail "signing in as try-operator after the upgrade"
valid=$(curl -s --cacert "${CA}" -b "${JAR}" "${BASE}/api/tokens/${A}/verify" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("signature_valid"))')
[[ "${valid}" == True ]] || fail "the upgraded app says credential #${A}'s signature_valid is ${valid}"
curl -s --cacert "${CA}" -b "${JAR}" "${BASE}/api/tokens/${A}/authenticity-pack" > "${WORK}/pack-A-after.json"
python3 - "${WORK}/pack-A-before.json" "${WORK}/pack-A-after.json" <<'PY' || fail "credential #${A}'s pack changed across the upgrade"
import json, sys
before, after = (json.load(open(p)) for p in sys.argv[1:])
for k in ("token_id", "token_value", "signature_hex", "public_key_hex", "algorithm"):
    assert before.get(k) == after.get(k), k
PY
cp "${WORK}/pack-A-after.json" "${OUT}/pack-A-after.json"
(cd "${OUT}" && ./venv/bin/polaris-verify --pqc-provider auto --issuer-anchor anchors.json \
    --pack pack-A-after.json > /dev/null) \
    || fail "credential #${A}'s pack, fetched after the upgrade, does not verify against ${FROM}'s key"
ok "credential #${A}: the app says its signature is valid, and its pack, fetched again, is unchanged and verifies against ${FROM}'s key"

printf '\nDone in %ds: %s upgraded to %s with nothing lost.\n' "$(( $(date +%s) - T0 ))" "${FROM}" "${TARGET:0:8}"
