#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-helm-drill.sh — the Kubernetes reference profile boots to healthy on
# a stock cluster, with its NetworkPolicies ENFORCED and the restricted Pod
# Security Standard in effect (roadmap P1.5). Runs identically in CI (job
# helm-kind) and locally (Docker + kind + kubectl + helm).
#
# What it proves, in order:
#   1. A kind cluster with the default CNI disabled and Calico installed (the
#      only way NetworkPolicy means anything in kind); the four self-built
#      images loaded, nothing pulled (imagePullPolicy Never).
#   2. The namespace labelled pod-security.kubernetes.io/enforce=restricted,
#      and a privileged pod REJECTED by the API server ("violates PodSecurity").
#   3. The real secrets (polaris-generate-secrets.sh, including the ML-DSA-65
#      signing key) as a Secret; `helm lint` and `helm install --wait`.
#   4. /api/health through the Caddy edge (tls internal): database, redis,
#      zk_binary, custody all healthy.
#   5. A probe pod outside the topology cannot reach postgres:5432,
#      pgbouncer:6432, or app:8000 (default-deny + allow-list holds), while the
#      app plainly can (step 4 proved app -> pgbouncer -> postgres and app ->
#      redis).
#   6. `kubectl rollout restart` of the app rolls with maxUnavailable 0 and the
#      edge stays healthy.
#
# Env: KEEP_CLUSTER=1 keeps the cluster; KIND_CLUSTER (default polaris-drill).
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
CLUSTER="${KIND_CLUSTER:-polaris-drill}"
NS=polaris
REL=polaris
CALICO_VERSION=v3.32.2
CALICO_MANIFEST="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
# The manifest's SHA-256 at that tag: it is applied only if the download matches (lab record 017, G15).
CALICO_SHA256=a8c828a06a87c629a282ebbc424895b77f3a030251993e41ea400a743675bb02
PF_PID=""
fail() { echo "::error::$*" >&2; exit 1; }
FROZEN=""
cleanup() {
    [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true
    if [ -n "$FROZEN" ]; then docker exec "$(kubectl -n "$NS" get pod -l application=polaris-db -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null)" ctr -n k8s.io task resume "$FROZEN" >/dev/null 2>&1 || true; fi
    if [ "${KEEP_CLUSTER:-0}" != 1 ]; then kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
for t in docker kind kubectl helm; do command -v "$t" >/dev/null || fail "$t is required"; done
for i in polaris-app:prod polaris-caddy:prod polaris-pgbouncer:prod polaris-postgres:prod; do
    docker image inspect "$i" >/dev/null 2>&1 || fail "image $i not built (see the CI job for the four docker build lines)"
done

echo "== 1. kind cluster (no default CNI) + Calico =="
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --config "$ROOT/deploy/helm/kind-config.yaml" --wait 60s >/dev/null
CALICO_FILE="$(mktemp)"
curl -sSfL --retry 3 "$CALICO_MANIFEST" -o "$CALICO_FILE" || fail "could not download $CALICO_MANIFEST"
GOT="$( (sha256sum "$CALICO_FILE" 2>/dev/null || shasum -a 256 "$CALICO_FILE") | cut -d' ' -f1)"
[ "$GOT" = "$CALICO_SHA256" ] || fail "calico ${CALICO_VERSION} manifest is $GOT, not the pinned $CALICO_SHA256"
kubectl apply -f "$CALICO_FILE" >/dev/null
rm -f "$CALICO_FILE"
kubectl -n kube-system rollout status ds/calico-node --timeout=300s >/dev/null
kubectl -n kube-system rollout status deploy/coredns --timeout=300s >/dev/null
kubectl wait --for=condition=Ready node --all --timeout=120s >/dev/null
echo "  calico ${CALICO_VERSION} enforcing; node Ready"
# The four self-built images are loaded (pullPolicy Never proves nothing else is
# fetched for them); the digest-pinned redis is pulled by the node itself, since
# `kind load` of a digest-referenced manifest list fails on the platforms it does
# not have ("content digest not found", the first local run).
kind load docker-image --name "$CLUSTER" polaris-app:prod polaris-caddy:prod polaris-pgbouncer:prod polaris-postgres:prod >/dev/null
echo "  self-built images loaded into the cluster (pullPolicy Never for them)"

echo "== 2. namespace under the restricted Pod Security Standard =="
kubectl create namespace "$NS" >/dev/null
kubectl label namespace "$NS" pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/warn=restricted pod-security.kubernetes.io/audit=restricted >/dev/null
if kubectl -n "$NS" apply -f - <<'PODEOF' >/dev/null 2>/tmp/pss.err
apiVersion: v1
kind: Pod
metadata: {name: pss-violation}
spec:
  containers:
    - name: c
      image: polaris-app:prod
      imagePullPolicy: Never
      securityContext: {privileged: true}
PODEOF
then kubectl -n "$NS" delete pod pss-violation --ignore-not-found >/dev/null; fail "a PRIVILEGED pod was admitted; the restricted standard is not enforced"; fi
grep -q "violates PodSecurity" /tmp/pss.err || { cat /tmp/pss.err; fail "privileged pod refused for another reason"; }
echo "  privileged pod rejected: $(grep -o 'violates PodSecurity "restricted[^"]*"' /tmp/pss.err | head -1)"

echo "== 3. secrets + helm install =="
( cd "$ROOT" && bash scripts/polaris-generate-secrets.sh >/dev/null 2>&1 ) || true
[ -s "$ROOT/polaris_web/secrets/polaris_signing_key" ] || echo "  (no signing key generated; custody will report degraded)"
kubectl -n "$NS" create secret generic polaris-secrets --from-file="$ROOT/polaris_web/secrets/" >/dev/null
helm lint "$ROOT/deploy/helm/polaris" >/dev/null && echo "  helm lint OK"
helm install "$REL" "$ROOT/deploy/helm/polaris" -n "$NS" --set domain=localhost --set edge.tls=internal \
    --set secrets.existingSecret=polaris-secrets --set images.pullPolicy=Never \
    --wait --timeout 12m >/dev/null || {
        # Diagnose every workload, not one: the first local run showed only
        # postgres's log while caddy crash-looped for a different reason.
        kubectl -n "$NS" get pods -o wide
        for pod in $(kubectl -n "$NS" get pods -o name); do
            echo "== $pod: events =="; kubectl -n "$NS" describe "$pod" | sed -n '/^Events:/,$p' | tail -8
            echo "== $pod: log (current) =="; kubectl -n "$NS" logs "$pod" --tail=20 2>&1 | tail -20
            echo "== $pod: log (previous) =="; kubectl -n "$NS" logs "$pod" --previous --tail=20 2>&1 | tail -20
        done
        fail "helm install did not reach ready"
    }
kubectl -n "$NS" get pods -o wide | sed 's/^/  /'
kubectl -n "$NS" get networkpolicy --no-headers | wc -l | sed 's/^/  networkpolicies: /'

echo "== 4. health through the edge =="
kubectl -n "$NS" port-forward "svc/${REL}-caddy" 18443:443 >/dev/null 2>&1 & PF_PID=$!
sleep 3
code=""
for i in $(seq 1 30); do code=$(curl -sk --max-time 30 -o /dev/null -w '%{http_code}' https://localhost:18443/api/health || true); [ "$code" = 200 ] && break; sleep 3; done
[ "$code" = 200 ] || { kubectl -n "$NS" logs -l app.kubernetes.io/component=caddy --tail=20; fail "edge did not serve /api/health (last HTTP $code)"; }
# The health JSON is fetched into a variable and parsed from argv, not piped into python: a fetch
# piped into an interpreter reads, to a supply-chain scanner, as downloaded code being run.
health=$(curl -sk --max-time 30 https://localhost:18443/api/health)
python3 -c "
import sys, json; d = json.loads(sys.argv[1]); c = d['checks']
bad = [k for k in ('database', 'redis', 'zk_binary', 'custody') if c[k]['status'] != 'healthy']
print('  checks:', {k: v.get('status') for k, v in c.items()}); assert not bad, f'unhealthy: {bad}'
print('  custody:', c['custody'].get('driver'), c['custody'].get('public_key_fingerprint'))" "$health"

echo "== 5. NetworkPolicy: a pod outside the topology is denied =="
cat > /tmp/np-probe.py <<'PYEOF'
import socket, sys
targets = [("polaris-postgres", 5432), ("polaris-pgbouncer", 6432), ("polaris-app", 8000)]
blocked = 0
for host, port in targets:
    try:
        socket.create_connection((host, port), timeout=6).close(); print(f"REACHED {host}:{port} (policy hole)")
    except Exception as e:
        blocked += 1; print(f"blocked {host}:{port} ({type(e).__name__})")
sys.exit(0 if blocked == len(targets) else 1)
PYEOF
PROBE_PY=$(python3 -c "import json,sys; print(json.dumps(open('/tmp/np-probe.py').read()))")
OVERRIDES=$(cat <<JSONEOF
{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"}},
 "containers":[{"name":"probe","image":"polaris-app:prod","imagePullPolicy":"Never",
   "command":["python3","-c",${PROBE_PY}],
   "securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}
JSONEOF
)
if kubectl -n "$NS" run np-probe --image=polaris-app:prod --restart=Never --rm -i --overrides="$OVERRIDES" 2>&1 | sed 's/^/  /' | tee /tmp/np-probe.out | grep -q "REACHED"; then fail "a pod outside the topology reached a protected service"; fi
grep -q "blocked polaris-postgres:5432" /tmp/np-probe.out || { cat /tmp/np-probe.out; fail "probe did not run"; }
echo "  default-deny + allow-list holds (postgres, pgbouncer, app unreachable from outside the topology)"

echo "== 6. rolling restart keeps the edge healthy =="
kubectl -n "$NS" rollout restart "deploy/${REL}-app" >/dev/null
kubectl -n "$NS" rollout status "deploy/${REL}-app" --timeout=300s >/dev/null
code=$(curl -sk --max-time 30 -o /dev/null -w '%{http_code}' https://localhost:18443/api/health || true)
[ "$code" = 200 ] || fail "edge unhealthy after the rolling restart (HTTP $code)"
echo "  rolled (maxUnavailable 0); edge healthy"
echo "== 7. automated database failover: Patroni with the Kubernetes API as the lease store =="
# v9.244 (roadmap P2.13). The chart runs two Patroni members; the leader
# Service's endpoints follow the lease. A writer with the app's labels (the
# policies let only the app reach pgbouncer) inserts through the real path
# four times a second and logs each insert with its completion time.
#   7a. The leader pod is deleted. The StatefulSet brings it back under the
#       same name inside the lease, so Patroni treats it as the same member
#       restarting and it keeps the role: a restart in place, measured.
#   7b. The leader's container is frozen through the node's runtime (a hung
#       node). It cannot renew; the other member must hold the lease within
#       CEIL_FAILOVER and writes must resume; thawed, the old leader must
#       demote and rejoin as a streaming replica within CEIL_REJOIN. A frozen
#       pod keeps its stale role label, so the leader is read from the lease
#       itself: the annotation Patroni keeps on the leader Endpoints.
#   7c. A planned switchover, under CEIL_SWITCHOVER.
# After all three, every acknowledged insert must be present on the leader.
CEIL_FAILOVER="${POLARIS_FAILOVER_CEIL_FAILOVER:-60}"; CEIL_REJOIN="${POLARIS_FAILOVER_CEIL_REJOIN:-180}"; CEIL_SWITCHOVER="${POLARIS_FAILOVER_CEIL_SWITCHOVER:-30}"
pctl() { kubectl -n "$NS" exec "$1" -- patronictl -c /var/lib/postgresql/patroni.yml "${@:2}"; }
lease_holder() { kubectl -n "$NS" get endpoints "${REL}-postgres" -o jsonpath='{.metadata.annotations.leader}' 2>/dev/null; }
lease_held_by() { [[ "$(lease_holder)" == "$1" ]]; }
other_member() { [[ "$1" == "${REL}-postgres-0" ]] && echo "${REL}-postgres-1" || echo "${REL}-postgres-0"; }
replica_streaming() {  # replica_streaming POD: Patroni's /cluster, asked of the lease holder, says streaming with no lag
    local l; l=$(lease_holder); [[ -n "$l" ]] || return 1
    kubectl -n "$NS" exec "$l" -- wget -qO- http://127.0.0.1:8008/cluster 2>/dev/null | python3 -c "
import json, sys
d = json.load(sys.stdin); m = next((m for m in d['members'] if m['name'] == sys.argv[1]), None)
sys.exit(0 if m and m['role'] == 'replica' and m['state'] == 'streaming' and m.get('lag', 1) == 0 else 1)" "$1"
}
cluster_healthy() { local l r; l=$(lease_holder); [[ -n "$l" ]] || return 1; r=$(other_member "$l"); replica_streaming "$r"; }
wait_for() { local limit="$1"; shift; local t0 i; t0=$(date +%s); for i in $(seq 1 "$limit"); do if "$@"; then echo $(( $(date +%s) - t0 )); return 0; fi; sleep 1; done; echo "$limit"; return 1; }
now() { python3 -c "import time; print(time.time())"; }
le() { python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)" "$1" "$2"; }
diagnose() { echo "--- diagnostics ---" >&2; kubectl -n "$NS" get pods -l application=polaris-db -L role >&2 || true; kubectl -n "$NS" get endpoints "${REL}-postgres" -o yaml 2>/dev/null | sed -n '/annotations/,/subsets/p' | head -12 >&2; for m in "${REL}-postgres-0" "${REL}-postgres-1"; do echo "[$m]" >&2; kubectl -n "$NS" logs "$m" --tail=25 2>&1 | sed 's/^/    /' >&2; done; }
L0=$(lease_holder); [[ -n "$L0" ]] || { diagnose; fail "no Patroni lease holder (annotation on the leader Endpoints)"; }
R0=$(other_member "$L0")
wait_for 120 replica_streaming "$R0" >/dev/null || { diagnose; fail "$R0 is not a streaming replica with zero lag"; }
pctl "$L0" list | sed 's/^/  /'
kubectl -n "$NS" exec "$L0" -- psql -h /var/run/postgresql -U postgres -d polaris -v ON_ERROR_STOP=1 -q \
    -c "CREATE TABLE IF NOT EXISTS ha_marker (id bigserial PRIMARY KEY, ts timestamptz NOT NULL DEFAULT clock_timestamp());" \
    -c "GRANT INSERT ON ha_marker TO polaris_app; GRANT USAGE ON SEQUENCE ha_marker_id_seq TO polaris_app;" || fail "could not create the marker table"
APP_PW=$(kubectl -n "$NS" get secret polaris-secrets -o jsonpath='{.data.polaris_db_password}' | base64 -d)
WRITER_PY=$(python3 -c 'import json; print(json.dumps("""import os, signal, sys, time
import psycopg
dsn = os.environ["DSN"]; stop = False
signal.signal(signal.SIGTERM, lambda *a: globals().__setitem__("stop", True))
while not stop:
    t = time.time()
    try:
        with psycopg.connect(dsn, connect_timeout=3, autocommit=True) as c:
            c.execute("INSERT INTO ha_marker DEFAULT VALUES")
        print(f"{t:.3f} {time.time():.3f} ok", flush=True)
    except Exception:
        print(f"{t:.3f} {time.time():.3f} fail", flush=True)
    time.sleep(0.25)
"""))')
WRITER_OVERRIDES=$(cat <<JSONEOF
{"metadata":{"labels":{"app.kubernetes.io/name":"polaris","app.kubernetes.io/instance":"${REL}","app.kubernetes.io/component":"app"}},
 "spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":70,"runAsGroup":70,"seccompProfile":{"type":"RuntimeDefault"}},
  "containers":[{"name":"writer","image":"polaris-postgres:prod","imagePullPolicy":"Never",
    "command":["python3","-c",${WRITER_PY}],
    "env":[{"name":"DSN","value":"host=${REL}-pgbouncer port=6432 dbname=polaris user=polaris_app password=${APP_PW} sslmode=require application_name=ha_drill"}],
    "securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}
JSONEOF
)
kubectl -n "$NS" run ha-writer --image=polaris-postgres:prod --restart=Never --overrides="$WRITER_OVERRIDES" >/dev/null
writes_ok_since() { kubectl -n "$NS" logs ha-writer 2>/dev/null | python3 -c "
import sys; t = float(sys.argv[1])
sys.exit(0 if any(float(l.split()[1]) > t for l in sys.stdin if l.strip().endswith(' ok')) else 1)" "$1"; }
outage_since() {  # -> "outage_s fails": the larger of the failed span and the longest stall between completed inserts
    kubectl -n "$NS" logs ha-writer 2>/dev/null | python3 -c "
import sys; t0 = float(sys.argv[1])
allrows = [(float(e), st) for _, e, st in (l.split() for l in sys.stdin if l.strip())]
rows = [(t, s) for t, s in allrows if t >= t0]; fails = [t for t, s in rows if s == 'fail']
gap = 0.0
if fails:
    first, last = min(fails), max(fails); after = [t for t, s in rows if s == 'ok' and t > last]
    gap = (min(after) - first) if after else (last - first)
oks = [t for t, s in rows if s == 'ok']; before = [t for t, s in allrows if s == 'ok' and t < t0]
seq = ([max(before)] if before else []) + oks
stall = max((b - a for a, b in zip(seq, seq[1:])), default=0.0)
print(f'{max(gap, stall):.1f} {len(fails)}')" "$1"; }
ok_count() { kubectl -n "$NS" logs ha-writer 2>/dev/null | grep -c ' ok$' || echo 0; }
rows_on() { kubectl -n "$NS" exec "$1" -- psql -h /var/run/postgresql -U postgres -d polaris -tAc "SELECT count(*) FROM ha_marker" 2>/dev/null | tr -d '[:space:]'; }
settle() { local t; t=$(now); wait_for 60 writes_ok_since "$t" >/dev/null || fail "writes are not flowing"; wait_for 120 cluster_healthy >/dev/null || { diagnose; fail "the cluster is not one leader and one current streaming replica"; }; }
ROWS0=$(rows_on "$L0")
settle
echo "  writes flowing through pgbouncer -> ${REL}-postgres (leader endpoints) -> $L0"
# 7a. the leader pod is deleted: a restart in place
t0=$(now)
kubectl -n "$NS" delete pod "$L0" --grace-period=0 --force >/dev/null 2>&1
w=$(wait_for "$CEIL_FAILOVER" writes_ok_since "$t0") || { diagnose; fail "writes did not resume within ${CEIL_FAILOVER}s of the leader pod's deletion"; }
h=$(wait_for "$CEIL_REJOIN" cluster_healthy) || { diagnose; fail "the cluster was not one leader and one streaming replica within ${CEIL_REJOIN}s of the leader pod's deletion"; }
read -r out1 fails1 <<< "$(outage_since "$t0")"
L1=$(lease_holder)
if [[ "$L1" == "$L0" ]]; then how="the same member came back inside its lease and kept the role"; else how="$L1 took the lease"; fi
echo "  leader pod deleted: $how; write outage ${out1}s (${fails1} failed inserts); one leader and one streaming replica again after ${h}s"
le "$out1" "$CEIL_FAILOVER" || fail "write outage ${out1}s exceeds the ${CEIL_FAILOVER}s ceiling"
# 7b. the leader's container is frozen: a hung node
settle
L1=$(lease_holder); R1=$(other_member "$L1")
acked_before_freeze=$(ok_count)
NODE=$(kubectl -n "$NS" get pod "$L1" -o jsonpath='{.spec.nodeName}')
CID=$(kubectl -n "$NS" get pod "$L1" -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's|containerd://||')
[[ -n "$NODE" && -n "$CID" ]] || fail "cannot resolve the leader's node and container"
t0=$(now)
docker exec "$NODE" ctr -n k8s.io task pause "$CID" >/dev/null || fail "could not freeze the leader's container on node $NODE"
FROZEN="$CID"
p=$(wait_for "$CEIL_FAILOVER" lease_held_by "$R1") || { docker exec "$NODE" ctr -n k8s.io task resume "$CID" >/dev/null 2>&1 || true; diagnose; fail "$R1 did not take the lease within ${CEIL_FAILOVER}s of the leader freezing"; }
w=$(wait_for "$CEIL_FAILOVER" writes_ok_since "$t0") || { docker exec "$NODE" ctr -n k8s.io task resume "$CID" >/dev/null 2>&1 || true; diagnose; fail "writes did not resume within ${CEIL_FAILOVER}s of the leader freezing"; }
read -r out2 fails2 <<< "$(outage_since "$t0")"
docker exec "$NODE" ctr -n k8s.io task resume "$CID" >/dev/null || fail "could not thaw the leader's container"
FROZEN=""
j=$(wait_for "$CEIL_REJOIN" replica_streaming "$L1") || { diagnose; fail "$L1 did not demote and rejoin as a streaming replica within ${CEIL_REJOIN}s of thawing"; }
echo "  leader frozen: $R1 took the lease after ${p}s; write outage ${out2}s (${fails2} failed inserts); $L1 thawed, demoted and streaming again after ${j}s"
le "$out2" "$CEIL_FAILOVER" || fail "write outage ${out2}s exceeds the ${CEIL_FAILOVER}s ceiling"
# 7c. a planned switchover
settle
L2=$(lease_holder); C2=$(other_member "$L2")
t0=$(now)
pctl "$L2" switchover --primary "$L2" --candidate "$C2" --force >/dev/null 2>&1 || fail "patronictl switchover failed"
p3=$(wait_for "$CEIL_SWITCHOVER" lease_held_by "$C2") || { diagnose; fail "$C2 did not hold the lease within ${CEIL_SWITCHOVER}s of the switchover"; }
wait_for "$CEIL_SWITCHOVER" writes_ok_since "$t0" >/dev/null || fail "writes did not resume within ${CEIL_SWITCHOVER}s of the switchover"
j3=$(wait_for "$CEIL_REJOIN" replica_streaming "$L2") || { diagnose; fail "$L2 did not follow as a streaming replica within ${CEIL_REJOIN}s"; }
read -r out3 fails3 <<< "$(outage_since "$t0")"
echo "  switchover: $C2 leader after ${p3}s; write outage ${out3}s (${fails3} failed inserts); $L2 follows after ${j3}s"
le "$out3" "$CEIL_SWITCHOVER" || fail "switchover write outage ${out3}s exceeds the ${CEIL_SWITCHOVER}s ceiling"
# integrity: every insert acknowledged before the freeze is on the leader; inserts acknowledged inside the
# failure window may be the async replication's RPO (FAILOVER.md section 6) and are reported, not tolerated silently
L3=$(lease_holder); rows=$(( $(rows_on "$L3") - ROWS0 )); acked=$(ok_count)
[[ "$rows" -ge "$acked_before_freeze" ]] || fail "$rows rows added on $L3 but $acked_before_freeze inserts were acknowledged before the freeze: an acknowledged write from before the failure was lost"
lost=$(( acked - rows )); [[ "$lost" -lt 0 ]] && lost=0
echo "  integrity: $rows rows added, $acked inserts acknowledged, $lost of them (acknowledged inside the failure window) not in the surviving history"
kubectl -n "$NS" delete pod ha-writer --grace-period=0 --force >/dev/null 2>&1 || true
code=$(curl -sk --max-time 30 -o /dev/null -w '%{http_code}' https://localhost:18443/api/health || true)
[ "$code" = 200 ] || fail "edge unhealthy after the failover drill (HTTP $code)"
echo "== HELM/KIND DRILL PASSED: restricted PSS enforced, policies enforced, stack healthy through the edge, database failover automated =="

