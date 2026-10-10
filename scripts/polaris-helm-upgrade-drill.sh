#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-helm-upgrade-drill.sh: the previous release, installed with Helm, upgraded to this
# commit the way docs/operator/KUBERNETES.md says (lab record 017, gate rows OP-18 and OP-19).
#
#   1. A kind cluster with Calico enforcing NetworkPolicy and the namespace under the restricted
#      Pod Security Standard, as scripts/polaris-helm-drill.sh builds it (its pinned Calico).
#   2. The previous release (the newest v* tag before this commit): its four images built from its
#      own tree, its chart installed, a marker row written.
#   3. This commit's images built, and `helm upgrade` with this chart: the pre-upgrade Job
#      (templates/migrate-job.yaml) applies the migrations the release lacks, then syncs the
#      database objects, before the new pods roll. The upgraded database's security state
#      (scripts/lib/polaris-db-state.sh) must then equal, table by table, that of this commit
#      installed fresh, in a throwaway cluster of its own (a container on this host), from the
#      postgres image the upgrade deployed (scripts/lib/polaris-db-reference.sh): what an upgrade
#      leaves different from a fresh install of the same release is drift.
#   4. Afterwards: no migration pending (the runner in the new image, asked inside a database pod),
#      migrations recorded that the previous release did not have, the app healthy through the
#      edge, the marker intact.
#
# Usage: scripts/polaris-helm-upgrade-drill.sh [FROM_TAG]   (KEEP_CLUSTER=1 keeps the cluster)
# Requires docker, kind, kubectl, helm. Exit 0 the upgrade migrated and the release came back
# healthy; 1 otherwise, saying how.
# ============================================================================
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)"
TARGET="$(git -C "${ROOT}" rev-parse HEAD)"
FROM="${1:-$(git -C "${ROOT}" describe --tags --abbrev=0 --match 'v[0-9]*' "${TARGET}^")}"
CLUSTER=polaris-helm-upgrade NS=polaris REL=polaris
WORK="$(mktemp -d)"
PF_PID=""
fail() { echo "::error::$*" >&2; exit 1; }
cleanup() {
    docker rm -f polaris-reference-helm > /dev/null 2>&1 || true
    [[ -n "${PF_PID}" ]] && kill "${PF_PID}" 2> /dev/null || true
    [[ "${KEEP_CLUSTER:-0}" == 1 ]] || kind delete cluster --name "${CLUSTER}" > /dev/null 2>&1 || true
    git -C "${ROOT}" worktree remove --force "${WORK}/from" > /dev/null 2>&1 || true
    rm -rf "${WORK}"
}
trap cleanup EXIT
for t in docker kind kubectl helm; do command -v "$t" > /dev/null || fail "$t is required"; done
ok() { echo "  ok: $*"; }
# One Calico pin, the Helm drill's: read, not copied, so the two cannot drift apart.
CALICO_VERSION=$(sed -n 's/^CALICO_VERSION=//p' "${ROOT}/scripts/polaris-helm-drill.sh")
CALICO_SHA256=$(sed -n 's/^CALICO_SHA256=//p' "${ROOT}/scripts/polaris-helm-drill.sh")
[[ -n "${CALICO_VERSION}" && -n "${CALICO_SHA256}" ]] || fail "could not read the Calico pin from polaris-helm-drill.sh"

# This commit's images are built under the host's production tags: one build or deploy at a time.
source "${ROOT}/scripts/polaris-host-lock.sh"
polaris_host_lock "the Helm upgrade drill"
echo "== 1. the two releases' images: ${FROM} and ${TARGET:0:8} =="
git -C "${ROOT}" worktree add -q --detach "${WORK}/from" "${FROM}" || fail "checking out ${FROM}"
( cd "${WORK}/from" && bash scripts/polaris-image-build.sh --stack from > "${WORK}/build-from.log" 2>&1 ) \
    || { tail -20 "${WORK}/build-from.log" >&2; fail "building ${FROM}'s images"; }
( cd "${ROOT}" && bash scripts/polaris-image-build.sh --stack prod > "${WORK}/build-to.log" 2>&1 ) \
    || { tail -20 "${WORK}/build-to.log" >&2; fail "building this commit's images"; }
ok "built polaris-{app,caddy,pgbouncer,postgres}:from (${FROM}) and :prod (${TARGET:0:8})"

echo "== 2. kind, Calico ${CALICO_VERSION}, a restricted namespace =="
kind delete cluster --name "${CLUSTER}" > /dev/null 2>&1 || true
kind create cluster --name "${CLUSTER}" --config "${ROOT}/deploy/helm/kind-config.yaml" --wait 60s > /dev/null
curl -sSfL --retry 3 "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml" \
    -o "${WORK}/calico.yaml" || fail "downloading Calico ${CALICO_VERSION}"
[[ "$( (sha256sum "${WORK}/calico.yaml" 2> /dev/null || shasum -a 256 "${WORK}/calico.yaml") | cut -d' ' -f1)" \
   == "${CALICO_SHA256}" ]] || fail "the Calico manifest is not the pinned one"
kubectl apply -f "${WORK}/calico.yaml" > /dev/null
kubectl -n kube-system rollout status ds/calico-node --timeout=300s > /dev/null
kubectl wait --for=condition=Ready node --all --timeout=120s > /dev/null
kind load docker-image --name "${CLUSTER}" \
    polaris-app:from polaris-caddy:from polaris-pgbouncer:from polaris-postgres:from \
    polaris-app:prod polaris-caddy:prod polaris-pgbouncer:prod polaris-postgres:prod > /dev/null
kubectl create namespace "${NS}" > /dev/null
kubectl label namespace "${NS}" pod-security.kubernetes.io/enforce=restricted > /dev/null
( cd "${ROOT}" && bash scripts/polaris-generate-secrets.sh > /dev/null 2>&1 ) || true
kubectl -n "${NS}" create secret generic polaris-secrets --from-file="${ROOT}/polaris_web/secrets/" > /dev/null
ok "cluster up, eight images loaded, namespace restricted"

diagnose() {
    # Every command may fail (a pod with no log yet): under pipefail one that did ended the drill here, before
    # the fail that names what broke. A Pending pod has no log, only the scheduler's reasons.
    kubectl -n "${NS}" get pods,jobs -o wide >&2 || true
    { kubectl -n "${NS}" get events --sort-by=.lastTimestamp 2>&1 || true; } | tail -20 >&2
    for p in $(kubectl -n "${NS}" get pods -o name || true); do
        echo "== ${p} ==" >&2; { kubectl -n "${NS}" logs "${p}" --tail=15 2>&1 || true; } | sed 's/^/    /' >&2
    done
}
COMMON=(--set domain=localhost --set edge.tls=internal --set secrets.existingSecret=polaris-secrets
        --set images.pullPolicy=Never --wait --timeout 12m)
leader_pod() {  # the member that is not recovering: either pod can win Patroni's first election, and a write
               # sent to the replica is refused ("cannot execute CREATE SCHEMA in a read-only transaction").
               # Asked of each pod rather than read from a label, so both releases' charts answer the same way.
    local p
    for _ in $(seq 1 60); do
        for p in "${REL}-postgres-0" "${REL}-postgres-1"; do
            if [[ "$(kubectl -n "${NS}" exec "$p" -c postgres -- psql -h /var/run/postgresql -U postgres -d polaris \
                     -tAqc 'SELECT pg_is_in_recovery()' 2> /dev/null)" == f ]]; then
                echo "$p"; return 0
            fi
        done
        sleep 2
    done
    return 1
}
psql_db() {  # psql_db <sql>: as the owner, inside the member that leads, over its socket
    local pod; pod=$(leader_pod) || fail "no member left recovery within 120s"
    kubectl -n "${NS}" exec "$pod" -c postgres -- psql -h /var/run/postgresql -U postgres -d polaris -tAqc "$1"
}
# The database's security state, read inside the member that leads, over its socket, as psql_db
# reads it. The leader is found again for every command: Patroni may hand over during or after the
# roll, and a write sent to the replica is refused.
source "${ROOT}/scripts/lib/polaris-db-state.sh"
source "${ROOT}/scripts/lib/polaris-db-reference.sh"
STATE_DB=polaris
REFERENCE=polaris-reference-helm
STATE_IN=stack
# The drill's own fixture: written under FROM, and made the same way in the reference, so the two
# states compare whole rather than through a filter that could hide something.
MARKER_DDL="CREATE SCHEMA drill; CREATE TABLE drill.marker (note text)"
pg_run() {
    local pod
    pod=$(leader_pod) || { echo "no member left recovery within 120s" >&2; return 1; }
    kubectl -n "${NS}" exec "${pod}" -c postgres -- "$@" < /dev/null
}
# STATE_IN=reference reads the fresh install in its own cluster instead (scripts/lib/
# polaris-db-reference.sh).
sql() {
    if [[ "${STATE_IN}" == reference ]]; then
        polaris_db_reference_sql "${REFERENCE}" "$1"
    else
        pg_run psql -X -q -At -v ON_ERROR_STOP=1 -h /var/run/postgresql -U postgres -d "${STATE_DB}" -c "$1"
    fi
}
state() {  # NAME WHEN: the security state of ${STATE_DB} into ${WORK}/state-NAME
    polaris_db_state security > "${WORK}/state-$1" || fail "the security state could not be read $2"
}

echo "== 3. ${FROM}, installed with its own chart =="
helm install "${REL}" "${WORK}/from/deploy/helm/polaris" -n "${NS}" "${COMMON[@]}" \
    --set images.app=polaris-app:from --set images.caddy=polaris-caddy:from \
    --set images.pgbouncer=polaris-pgbouncer:from --set images.postgres=polaris-postgres:from > /dev/null \
    || { diagnose; fail "helm install of ${FROM}"; }
psql_db "${MARKER_DDL}; INSERT INTO drill.marker VALUES ('${FROM}')" \
    > /dev/null || fail "writing the marker"
BEFORE=$(psql_db "SELECT count(*) FROM schema_version WHERE event_type = 'applied'")
ok "${FROM} running; ${BEFORE} migrations recorded; marker written"
state before "on ${FROM}, before the upgrade"
ok "${FROM}'s security state read ($(grep -c . "${WORK}/state-before") facts; kept as the record)"

echo "== 4. helm upgrade to ${TARGET:0:8} =="
helm upgrade "${REL}" "${ROOT}/deploy/helm/polaris" -n "${NS}" "${COMMON[@]}" > "${WORK}/upgrade.log" 2>&1 \
    || { cat "${WORK}/upgrade.log" >&2; kubectl -n "${NS}" logs "job/${REL}-migrate" --tail=30 >&2 || true; diagnose; \
         fail "helm upgrade"; }
ok "helm upgrade finished; its pre-upgrade migration Job succeeded"
state after "after the upgrade"
# The leading member's image carries this commit's SQL and init, and the reference runs the image
# the chart was upgraded to, loaded into kind from this host: polaris-postgres:prod.
polaris_db_reference_carries "${ROOT}/polaris_sql" \
    || { diagnose; fail "the leading member's image does not carry ${TARGET:0:8}'s SQL and init"; }
# Its first boot gets the stack's other password files too, so it creates what the stack's did:
# with a replication password, the init (or Patroni, under the HA profile) made polaris_replicator.
ref_env=()
repl="$(pg_run printenv POLARIS_REPLICATOR_PASSWORD_FILE 2> /dev/null || true)"
[[ -z "${repl}" ]] || ref_env+=("POLARIS_REPLICATOR_PASSWORD_FILE=$(basename "${repl}")")
polaris_db_reference_run polaris-postgres:prod "${REFERENCE}" "${WORK}/reference-secrets" "${WORK}/reference.log" \
        ${ref_env[@]+"${ref_env[@]}"} \
    || { tail -20 "${WORK}/reference.log" >&2; fail "installing ${TARGET:0:8} fresh in a throwaway cluster"; }
( pg_run() { docker exec -u postgres "${REFERENCE}" "$@" < /dev/null; }
  polaris_db_reference_carries "${ROOT}/polaris_sql" ) \
    || fail "polaris-postgres:prod does not carry ${TARGET:0:8}'s SQL and init, so it is no reference"
polaris_db_reference_sql "${REFERENCE}" "${MARKER_DDL}" > /dev/null \
    || fail "making the drill's marker table in the reference"
STATE_IN=reference
state reference "from the fresh ${TARGET:0:8} install"
STATE_IN=stack
polaris_db_reference_stop "${REFERENCE}" "${WORK}/reference-secrets"
# The reference had a cluster of its own: the operator's database and roles read as before it.
state after-again "after the reference"
polaris_db_state_same "${WORK}/state-after" "${WORK}/state-after-again" \
    || fail "building the reference changed the upgraded database or the cluster's roles (< before it, > after)"
polaris_db_reference_roles "${ROOT}/polaris_sql" > "${WORK}/polaris-roles" \
    || fail "the roles polaris_sql creates could not be read"
left_out="$(polaris_db_state_cross_cluster "${WORK}/state-reference" "${WORK}/state-after" "${WORK}/polaris-roles" \
              "${WORK}/state-reference.cmp" "${WORK}/state-after.cmp")" \
    || fail "the two clusters' states could not be set side by side"
[[ -z "${left_out}" ]] || ok "left out, a role one cluster has and Polaris does not create: $(echo ${left_out})"
polaris_db_state_same_by_table "${WORK}/state-reference.cmp" "${WORK}/state-after.cmp" \
    || fail "the upgraded database's security state is not a fresh ${TARGET:0:8} install's (< fresh only, > upgrade only)"
moved=$(diff "${WORK}/state-before" "${WORK}/state-after" | grep -c '^[<>]' || true)
ok "the upgraded database's security state is a fresh ${TARGET:0:8} install's, table by table ($(grep -c . "${WORK}/state-after") facts; ${moved} moved since ${FROM})"

echo "== 5. what the operator has now =="
LEADER=$(leader_pod) || fail "no member left recovery within 120s after the upgrade"
pending=$(kubectl -n "${NS}" exec "${LEADER}" -c postgres -- env POLARIS_DB_HOST=/var/run/postgresql \
          POLARIS_DB_USER=postgres /opt/polaris/scripts/polaris-migrate.sh --dry-run --up 2>&1) \
    || { echo "${pending}" | tail -10 >&2; fail "the migration runner could not read the upgraded database"; }
grep -q "no pending migrations" <<< "${pending}" || { echo "${pending}" | tail -10 >&2; fail "migrations still pending"; }
AFTER=$(psql_db "SELECT count(*) FROM schema_version WHERE event_type = 'applied'")
[[ "${AFTER}" -gt "${BEFORE}" ]] || fail "no migration was applied by the upgrade (${BEFORE} before, ${AFTER} after)"
ok "no migration pending; the upgrade applied $(( AFTER - BEFORE )) (${BEFORE} -> ${AFTER} recorded)"
[[ "$(psql_db "SELECT note FROM drill.marker")" == "${FROM}" ]] || fail "the marker did not survive the upgrade"
ok "the marker written under ${FROM} is intact"
kubectl -n "${NS}" port-forward "svc/${REL}-caddy" 18444:443 > /dev/null 2>&1 & PF_PID=$!
code=""
for _ in $(seq 1 40); do
    code=$(curl -sk --max-time 20 -o /dev/null -w '%{http_code}' https://localhost:18444/api/health || true)
    [[ "${code}" == 200 ]] && break; sleep 3
done
[[ "${code}" == 200 ]] || { diagnose; fail "the edge did not serve /api/health after the upgrade (HTTP ${code})"; }
ok "/api/health answers 200 through the edge on ${TARGET:0:8}"
echo "a Helm upgrade from ${FROM} migrated the database before the new release rolled, and the release came back healthy"
