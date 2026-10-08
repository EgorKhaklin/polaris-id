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
#      database objects, before the new pods roll.
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
    kubectl -n "${NS}" get pods,jobs -o wide >&2 || true
    for p in $(kubectl -n "${NS}" get pods -o name); do
        echo "== ${p} ==" >&2; kubectl -n "${NS}" logs "${p}" --tail=15 2>&1 | sed 's/^/    /' >&2
    done
}
COMMON=(--set domain=localhost --set edge.tls=internal --set secrets.existingSecret=polaris-secrets
        --set images.pullPolicy=Never --wait --timeout 12m)
psql_db() {  # psql_db <sql>: as the owner, inside the database pod, over its socket
    kubectl -n "${NS}" exec "${REL}-postgres-0" -c postgres -- psql -h /var/run/postgresql -U postgres -d polaris -tAqc "$1"
}

echo "== 3. ${FROM}, installed with its own chart =="
helm install "${REL}" "${WORK}/from/deploy/helm/polaris" -n "${NS}" "${COMMON[@]}" \
    --set images.app=polaris-app:from --set images.caddy=polaris-caddy:from \
    --set images.pgbouncer=polaris-pgbouncer:from --set images.postgres=polaris-postgres:from > /dev/null \
    || { diagnose; fail "helm install of ${FROM}"; }
psql_db "CREATE SCHEMA drill; CREATE TABLE drill.marker (note text); INSERT INTO drill.marker VALUES ('${FROM}')" \
    > /dev/null || fail "writing the marker"
BEFORE=$(psql_db "SELECT count(*) FROM schema_version WHERE event_type = 'applied'")
ok "${FROM} running; ${BEFORE} migrations recorded; marker written"

echo "== 4. helm upgrade to ${TARGET:0:8} =="
helm upgrade "${REL}" "${ROOT}/deploy/helm/polaris" -n "${NS}" "${COMMON[@]}" > "${WORK}/upgrade.log" 2>&1 \
    || { cat "${WORK}/upgrade.log" >&2; kubectl -n "${NS}" logs "job/${REL}-migrate" --tail=30 >&2 || true; diagnose; \
         fail "helm upgrade"; }
ok "helm upgrade finished; its pre-upgrade migration Job succeeded"

echo "== 5. what the operator has now =="
pending=$(kubectl -n "${NS}" exec "${REL}-postgres-0" -c postgres -- env POLARIS_DB_HOST=/var/run/postgresql \
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
