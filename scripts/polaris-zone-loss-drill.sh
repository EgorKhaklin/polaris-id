#!/usr/bin/env bash
# Copyright 2026 Egor Khaklin and the Polaris contributors
# SPDX-License-Identifier: Apache-2.0
# ============================================================================
# polaris-zone-loss-drill.sh: the chart survives the loss of a node that holds the database leader
# (lab record 017, gate row OP-7). Runs identically in CI and locally (Docker, kind, kubectl, helm).
#
# A kind cluster of one control plane and three workers, the workers labelled zone-a, zone-b and
# zone-c, Calico enforcing the NetworkPolicies, the restricted Pod Security Standard, the four
# self-built images loaded, and the chart installed with its defaults.
#
#   1. Placement: the two database members are on two nodes in two zones, and the edge, the app, the
#      router and pgbouncer each have their two pods on two nodes.
#   2. A marker row, written through the leader and present on the replica.
#   3. The leader's node is killed (`docker kill` of its kind node: its kubelet, its pods and its network
#      gone at once, as a host that loses power, with no shutdown to hand anything over).
#   4. Within the ceilings, measured from the stop:
#        the other member leads;
#        an insert through a surviving app pod (app -> pgbouncer -> router -> leader) succeeds;
#        /api/health answers 200 through a surviving edge pod, Redis included (if Redis was on the
#        stopped node, it was moved, which the rate limiter needs: it refuses without Redis);
#        the marker is intact.
#   5. The node starts again, and the old leader rejoins as a replica.
#
# Kind on one machine simulates hosts and zones: separate kubelets and network namespaces, one kernel.
# It proves the placement and the failover, not a real zone's network or power.
#
# Env: KEEP_CLUSTER=1 keeps the cluster; KIND_CLUSTER (default polaris-zones); POLARIS_ZONE_OUT (JSON);
#      the ceilings POLARIS_ZONE_CEIL_LEAD (90), _WRITE (180), _HEALTH (240), _REJOIN (240), seconds.
# Exit: 0 every step held; 1 otherwise.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
CLUSTER="${KIND_CLUSTER:-polaris-zones}"
NS=polaris
REL=polaris
OUT="${POLARIS_ZONE_OUT:-}"
CEIL_LEAD="${POLARIS_ZONE_CEIL_LEAD:-90}"
CEIL_WRITE="${POLARIS_ZONE_CEIL_WRITE:-180}"
CEIL_HEALTH="${POLARIS_ZONE_CEIL_HEALTH:-240}"
CEIL_REJOIN="${POLARIS_ZONE_CEIL_REJOIN:-240}"
# The CNI pin the Helm drill reads (one place to bump it).
CALICO_VERSION=$(sed -n 's/^CALICO_VERSION=//p' "${ROOT}/scripts/polaris-helm-drill.sh")
CALICO_SHA256=$(sed -n 's/^CALICO_SHA256=//p' "${ROOT}/scripts/polaris-helm-drill.sh")
CALICO_MANIFEST="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
WORK="$(mktemp -d)"
PF_PID=""
STOPPED=""
fail() { echo "::error::$*" >&2; diagnose; exit 1; }
ok() { echo "  ok: $*"; }
now() { date +%s; }
diagnose() {
    echo "--- diagnostics ---" >&2
    kubectl -n "${NS}" get pods -o wide >&2 2> /dev/null || true
    kubectl get nodes -L topology.kubernetes.io/zone >&2 2> /dev/null || true
}
cleanup() {
    [[ -n "${PF_PID}" ]] && kill "${PF_PID}" 2> /dev/null || true
    [[ -n "${STOPPED}" ]] && docker start "${STOPPED}" > /dev/null 2>&1 || true
    if [[ "${KEEP_CLUSTER:-0}" != 1 ]]; then kind delete cluster --name "${CLUSTER}" > /dev/null 2>&1 || true; fi
    rm -rf "${WORK}"
}
trap cleanup EXIT
for t in docker kind kubectl helm; do command -v "$t" > /dev/null || { echo "$t is required" >&2; exit 1; }; done
for i in polaris-app:prod polaris-caddy:prod polaris-pgbouncer:prod polaris-postgres:prod; do
    docker image inspect "$i" > /dev/null 2>&1 || { echo "image $i not built (scripts/polaris-image-build.sh --stack prod)" >&2; exit 1; }
done

echo "== 0. kind: a control plane and three workers in three zones, Calico, the images =="
cat > "${WORK}/kind.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16"
nodes:
  - role: control-plane
  - role: worker
    labels: {topology.kubernetes.io/zone: zone-a}
  - role: worker
    labels: {topology.kubernetes.io/zone: zone-b}
  - role: worker
    labels: {topology.kubernetes.io/zone: zone-c}
EOF
kind delete cluster --name "${CLUSTER}" > /dev/null 2>&1 || true
kind create cluster --name "${CLUSTER}" --config "${WORK}/kind.yaml" --wait 120s > /dev/null
curl -sSfL --retry 3 "${CALICO_MANIFEST}" -o "${WORK}/calico.yaml" || { echo "could not download ${CALICO_MANIFEST}" >&2; exit 1; }
GOT="$( (sha256sum "${WORK}/calico.yaml" 2> /dev/null || shasum -a 256 "${WORK}/calico.yaml") | cut -d' ' -f1)"
[[ "${GOT}" == "${CALICO_SHA256}" ]] || { echo "calico ${CALICO_VERSION} manifest is ${GOT}, not ${CALICO_SHA256}" >&2; exit 1; }
kubectl apply -f "${WORK}/calico.yaml" > /dev/null
kubectl -n kube-system rollout status ds/calico-node --timeout=400s > /dev/null
kubectl wait --for=condition=Ready node --all --timeout=180s > /dev/null
kind load docker-image --name "${CLUSTER}" polaris-app:prod polaris-caddy:prod polaris-pgbouncer:prod polaris-postgres:prod > /dev/null
kubectl create namespace "${NS}" > /dev/null
kubectl label namespace "${NS}" pod-security.kubernetes.io/enforce=restricted > /dev/null
( cd "${ROOT}" && bash scripts/polaris-generate-secrets.sh > /dev/null 2>&1 ) || true
kubectl -n "${NS}" create secret generic polaris-secrets --from-file="${ROOT}/polaris_web/secrets/" > /dev/null
helm install "${REL}" "${ROOT}/deploy/helm/polaris" -n "${NS}" --set domain=localhost --set edge.tls=internal \
    --set secrets.existingSecret=polaris-secrets --set images.pullPolicy=Never --wait --timeout 15m > /dev/null \
    || fail "helm install did not reach ready"
ok "three workers in three zones; the chart installed with its defaults"

zone_of() { kubectl get node "$1" -o jsonpath='{.metadata.labels.topology\.kubernetes\.io/zone}'; }
nodes_of() {  # nodes_of <component>: the nodes its running pods are on, one per line
    kubectl -n "${NS}" get pods -l "app.kubernetes.io/component=$1" --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}'
}
pg() {  # pg <pod> <sql>: as the owner, in that member, over its socket
    kubectl -n "${NS}" exec "$1" -c postgres -- psql -h /var/run/postgresql -U postgres -d polaris -tAqc "$2" 2> /dev/null
}
leader() {  # the member that is not recovering, or nothing
    local p
    for p in "${REL}-postgres-0" "${REL}-postgres-1"; do
        [[ "$(pg "$p" 'SELECT pg_is_in_recovery()')" == f ]] && { echo "$p"; return 0; }
    done
    return 1
}

echo "== 1. placement =="
DBN=(); while IFS= read -r n; do [[ -n "$n" ]] && DBN+=("$n"); done < <(nodes_of postgres)
[[ ${#DBN[@]} -eq 2 && "${DBN[0]}" != "${DBN[1]}" ]] || fail "the database members are not on two nodes: ${DBN[*]}"
[[ "$(zone_of "${DBN[0]}")" != "$(zone_of "${DBN[1]}")" ]] || fail "the database members share a zone: ${DBN[*]}"
ok "database members on ${DBN[0]} ($(zone_of "${DBN[0]}")) and ${DBN[1]} ($(zone_of "${DBN[1]}"))"
for c in caddy app pg-router pgbouncer; do
    n=$(nodes_of "$c" | sort -u | grep -c .)
    [[ "$n" -ge 2 ]] || fail "$c's pods are on $n node(s); two nodes keep one serving when a node goes"
done
ok "the edge, the app, the router and pgbouncer each run on two nodes"

echo "== 2. a marker through the leader, held by the replica =="
L0=$(leader) || fail "no member leads"
R0=$([[ "${L0}" == "${REL}-postgres-0" ]] && echo "${REL}-postgres-1" || echo "${REL}-postgres-0")
pg "${L0}" "CREATE SCHEMA drill; CREATE TABLE drill.zone_marker (id bigserial PRIMARY KEY, note text, at timestamptz DEFAULT now());
            GRANT USAGE ON SCHEMA drill TO polaris_app; GRANT INSERT, SELECT ON drill.zone_marker TO polaris_app;
            GRANT USAGE ON SEQUENCE drill.zone_marker_id_seq TO polaris_app;
            INSERT INTO drill.zone_marker (note) VALUES ('before the node stops')" > /dev/null || fail "writing the marker on ${L0}"
for _ in $(seq 1 30); do [[ "$(pg "${R0}" 'SELECT count(*) FROM drill.zone_marker')" == 1 ]] && break; sleep 2; done
[[ "$(pg "${R0}" 'SELECT count(*) FROM drill.zone_marker')" == 1 ]] || fail "the replica ${R0} never received the marker"
L0NODE=$(kubectl -n "${NS}" get pod "${L0}" -o jsonpath='{.spec.nodeName}')
REDISNODE=$(nodes_of redis | head -1)
ok "leader ${L0} on ${L0NODE} ($(zone_of "${L0NODE}")); the replica ${R0} holds the marker; Redis on ${REDISNODE}"

# The write path and the health path, from pods on nodes that stay up.
survivor() { kubectl -n "${NS}" get pods -l "app.kubernetes.io/component=$1" --field-selector=status.phase=Running \
                 -o jsonpath='{range .items[*]}{.metadata.name} {.spec.nodeName}{"\n"}{end}' | awk -v n="${L0NODE}" '$2 != n {print $1; exit}'; }
APPPOD=$(survivor app); EDGEPOD=$(survivor caddy)
[[ -n "${APPPOD}" && -n "${EDGEPOD}" ]] || fail "no app or edge pod off ${L0NODE}"
cat > "${WORK}/insert.py" <<'EOF'
import os, sys, psycopg2
c = psycopg2.connect(host=os.environ["POLARIS_DB_HOST"], port=os.environ["POLARIS_DB_PORT"],
                     dbname=os.environ["POLARIS_DB_NAME"], user=os.environ["POLARIS_DB_USER"],
                     password=open(os.environ["POLARIS_DB_PASSWORD_FILE"]).read().strip(),
                     sslmode=os.environ.get("POLARIS_DB_SSLMODE", "prefer"),
                     sslrootcert=os.environ.get("POLARIS_DB_SSLROOTCERT"), connect_timeout=3)
c.autocommit = True
c.cursor().execute("INSERT INTO drill.zone_marker (note) VALUES (%s)", (sys.argv[1],))
EOF
kubectl -n "${NS}" cp "${WORK}/insert.py" "${APPPOD}:/tmp/insert.py" -c app > /dev/null 2>&1 \
    || kubectl -n "${NS}" exec -i "${APPPOD}" -c app -- sh -c 'cat > /tmp/insert.py' < "${WORK}/insert.py" \
    || fail "could not place the writer in ${APPPOD}"
insert_ok() { kubectl -n "${NS}" exec "${APPPOD}" -c app -- python3 /tmp/insert.py "$1" > /dev/null 2>&1; }
insert_ok "a write before the stop" || fail "an insert through ${APPPOD} failed before anything stopped"
kubectl -n "${NS}" port-forward "pod/${EDGEPOD}" 18445:8443 > /dev/null 2>&1 & PF_PID=$!
health() {  # prints "<http code> <redis status>"
    curl -sk --max-time 5 -o "${WORK}/h.json" -w '%{http_code}' https://localhost:18445/api/health 2> /dev/null || echo 000
    printf ' %s\n' "$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1]))["checks"].get("redis") or {}).get("status"))' "${WORK}/h.json" 2> /dev/null || echo none)"
}
for _ in $(seq 1 30); do [[ "$(health)" == "200 healthy" ]] && break; sleep 2; done
[[ "$(health)" == "200 healthy" ]] || fail "the edge pod ${EDGEPOD} is not healthy before the stop ($(health))"
ok "writes through ${APPPOD} and health through ${EDGEPOD}, both off ${L0NODE}"

echo "== 3. ${L0NODE}, the leader's node, is killed =="
t0=$(now)
docker kill "${L0NODE}" > /dev/null; STOPPED="${L0NODE}"

echo "== 4. what is left serves =="
lead_s=""; write_s=""; health_s=""
while :; do
    el=$(( $(now) - t0 ))
    if [[ -z "${lead_s}" && "$(pg "${R0}" 'SELECT pg_is_in_recovery()')" == f ]]; then lead_s=${el}; fi
    # Recovery counts once the other member leads: an answer before that came from the old state.
    if [[ -n "${lead_s}" && -z "${write_s}" ]] && insert_ok "a write after the stop"; then write_s=${el}; fi
    if [[ -n "${lead_s}" && -z "${health_s}" && "$(health)" == "200 healthy" ]]; then health_s=${el}; fi
    [[ -n "${lead_s}" && -n "${write_s}" && -n "${health_s}" ]] && break
    [[ -z "${lead_s}" ]] && (( el > CEIL_LEAD )) && fail "${R0} did not lead within ${CEIL_LEAD}s of the stop"
    [[ -z "${write_s}" ]] && (( el > CEIL_WRITE )) && fail "no insert succeeded within ${CEIL_WRITE}s of the stop"
    [[ -z "${health_s}" ]] && (( el > CEIL_HEALTH )) && fail "the edge was not healthy (Redis included) within ${CEIL_HEALTH}s ($(health))"
    sleep 2
done
[[ "$(pg "${R0}" "SELECT count(*) FROM drill.zone_marker WHERE note = 'before the node stops'")" == 1 ]] \
    || fail "the marker written before the stop is missing on the new leader"
ok "${R0} led after ${lead_s}s; inserts resumed after ${write_s}s; /api/health 200, Redis healthy, after ${health_s}s; the marker intact"

echo "== 5. ${L0NODE} starts again =="
docker start "${L0NODE}" > /dev/null; STOPPED=""
t1=$(now); rejoin_s=""
while :; do
    if [[ "$(pg "${L0}" 'SELECT pg_is_in_recovery()')" == t ]]; then rejoin_s=$(( $(now) - t1 )); break; fi
    (( $(now) - t1 > CEIL_REJOIN )) && fail "${L0} did not rejoin as a replica within ${CEIL_REJOIN}s of its node starting"
    sleep 3
done
ok "${L0} rejoined as a replica after ${rejoin_s}s"

if [[ -n "${OUT}" ]]; then
    python3 - "${OUT}" "${L0NODE}" "${REDISNODE}" "${lead_s}" "${write_s}" "${health_s}" "${rejoin_s}" <<'EOF'
import json, sys
o, node, redis, lead, write, health, rejoin = sys.argv[1:]
json.dump({"stopped_node": node, "redis_was_on_it": node == redis, "new_leader_s": int(lead),
           "inserts_resumed_s": int(write), "edge_healthy_s": int(health), "old_leader_rejoined_s": int(rejoin)},
          open(o, "w"), indent=2)
EOF
fi
echo "the leader's node stopped: the other member led, inserts and the edge came back, and the node rejoined"
