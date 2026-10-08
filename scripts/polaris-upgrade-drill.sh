#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-upgrade-drill.sh: an operator on the previous release upgrades to this commit the way
# docs/operator/OPERATIONS.md says, and keeps everything they had (lab record 017, gate row OP-19).
#
#   1. a checkout of the previous release runs that release's own lab/strategy/006/try.sh: its
#      images, its secrets and ML-DSA-65 key, its stack; it issues credential A;
#   2. the same checkout moves to this commit, as `git pull` would, and upgrades as OPERATIONS.md's
#      "Polaris version upgrade" says: polaris-generate-secrets.sh (it writes only what is
#      missing), then polaris-deploy.sh prod (images, migrations, objects, the app, a smoke test);
#   3. a release that cannot start is deployed the same way: its smoke test fails and the deploy
#      puts back the app image it replaced, which the app then runs, serving (under Docker's
#      containerd image store, which upgrade.yml turns on, as a clean install of Engine 29 has it);
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

step "1/4 the previous release, ${FROM}, as its own try.sh leaves it"
git -C "${ROOT}" worktree add --detach "${TREE}" "${FROM}" > /dev/null 2>&1 || fail "checking out ${FROM}"
OUT="${TREE}/lab/strategy/006/out"
bash "${TREE}/lab/strategy/006/try.sh" > "${WORK}/try-before.log" 2>&1 \
    || { tail -20 "${WORK}/try-before.log" >&2; fail "${FROM}'s own try.sh"; }
A=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token_id"])' "${OUT}/pack.json")
cp "${OUT}/pack.json" "${WORK}/pack-A-before.json"
ok "${FROM} issued credential #${A} and polaris-verify accepted it"

step "2/4 upgrade to ${TARGET:0:8} as OPERATIONS.md says"
git -C "${TREE}" checkout --detach -q "${TARGET}" || fail "moving the checkout to ${TARGET:0:8}"
bash "${TREE}/scripts/polaris-generate-secrets.sh" > "${WORK}/secrets.log" 2>&1 \
    || { tail -20 "${WORK}/secrets.log" >&2; fail "polaris-generate-secrets.sh"; }
POLARIS_COMPOSE_EXTRA="-f docker-compose.citest.yml -f ${TREE}/lab/strategy/006/names.yml" \
    bash "${TREE}/scripts/polaris-deploy.sh" prod --no-pull > "${WORK}/deploy.log" 2>&1 \
    || { tail -30 "${WORK}/deploy.log" >&2; fail "polaris-deploy.sh prod"; }
ok "polaris-deploy.sh prod finished: migrations, objects, the app, its smoke test"

COMPOSE=(docker compose -f "${TREE}/polaris_web/docker-compose.prod.yml"
         -f "${TREE}/polaris_web/docker-compose.citest.yml" -f "${TREE}/lab/strategy/006/names.yml")
content() {  # a short digest of an image's layers and config; an unreadable image names itself
    local raw
    raw=$(docker image inspect --format '{{json .RootFS.Layers}}{{json .Config}}' "$1" 2> /dev/null) \
        && [[ -n "${raw}" ]] || { printf 'unreadable(%s)' "$1"; return; }
    printf '%s' "${raw}" | shasum -a 256 | cut -c1-12
}
app_content() { content "$(docker inspect --format '{{.Image}}' "$("${COMPOSE[@]}" ps -q app)")"; }

step "3/4 a release that cannot start is rolled back to the image it replaced"
# polaris-deploy.sh rolled back by re-tagging the running image's ID. Under Docker's containerd image
# store, the default on a clean install of Docker Engine 29 and later, that ID no longer resolves once
# the build moves polaris-app:prod, so the rollback stopped at `docker tag` and left the failed release
# serving. The deploy now pins the running image as polaris-app:rollback before it builds.
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
    | grep -q '"type": *"full"' || fail "the repository holds no full base backup after the upgrade"
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
# store keeps no record of the image a container was created from.
SVCS=(app caddy pgbouncer postgres)
running=()
for svc in "${SVCS[@]}"; do
    running+=("$(content "$(docker inspect --format '{{.Image}}' "$("${COMPOSE[@]}" ps -q "${svc}")")")")
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
       | { grep -o 'name="csrf_token" value="[^"]*"' || true; } | head -1 | sed 's/.*value="//;s/"$//')
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
