#!/usr/bin/env bash
# ============================================================================
# polaris-failover-drill.sh — induced failures against the HA profile, with
# every recovery measured under a live write stream (roadmap P2.7, v9.243).
#
# The HA profile (polaris_web/docker-compose.ha.yml) puts the database under
# Patroni: two members, a leader lease in a three-member etcd, HAProxy routing
# writes to whichever member holds the lease. This drill is the proof that the
# supervisor does what docs/operator/FAILOVER.md says, on a booted stack:
#
#   export POLARIS_DOMAIN=localhost
#   export POLARIS_COMPOSE_EXTRA="-f docker-compose.citest.yml -f docker-compose.bluegreen.yml -f docker-compose.ha.yml"
#   scripts/polaris-failover-drill.sh
#
# A writer inserts through the real client path (pgbouncer, HAProxy, the
# leader) four times a second and logs every attempt, so each scenario's
# "write gap" is the time between the first failed insert and the first
# successful one after it: what an application would have seen. Reads run
# against the edge as in the other drills.
#
#   1. The leader node is lost: its container is killed and stays down past
#      the lease. Patroni promotes the replica and writes resume within
#      CEIL_FAILOVER; when the node is started again it must rejoin as a
#      replica (pg_rewind) within CEIL_REJOIN. (A leader whose PROCESS crashes
#      and restarts inside its own lease is not a failover: Patroni restarts
#      it in place and keeps the lease, which is what a supervisor should do.)
#   2. The leader is cut off from the lease store only (its clients and the
#      other member can still reach it). It must demote itself within
#      CEIL_DEMOTE: that is the split-brain guard. What follows has two
#      honest outcomes. If the other member is current it takes the lease and
#      writes resume. If the demoting leader's last records never reached it
#      (a fast shutdown's final WAL, a few hundred bytes), Patroni will not
#      promote a member while a reachable member is ahead, and the member
#      that is ahead cannot take the lease without the store: the cluster is
#      leaderless (read-only everywhere) until the partition heals, after
#      which the member that is ahead takes the lease back. The drill accepts
#      both, asserts that no insert was acknowledged while nobody held the
#      lease, heals the partition, and measures the outage either way.
#   3. A planned switchover (patronictl). The write gap must stay under
#      CEIL_SWITCHOVER; the old leader must follow as a replica.
#   4. One etcd member crashes. The leader must NOT change, no write may
#      fail, and the member must restart on its own within CEIL_RESTART.
#
# The ceilings are hard assertions, the same discipline as the window and
# chaos drills. The measured numbers are the ones FAILOVER.md states.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
URL="${POLARIS_DRILL_URL:-https://localhost:8443}"
OUT="${POLARIS_FAILOVER_OUT:-}"
CEIL_FAILOVER="${POLARIS_FAILOVER_CEIL_FAILOVER:-60}"
CEIL_REJOIN="${POLARIS_FAILOVER_CEIL_REJOIN:-120}"
CEIL_DEMOTE="${POLARIS_FAILOVER_CEIL_DEMOTE:-45}"
CEIL_SWITCHOVER="${POLARIS_FAILOVER_CEIL_SWITCHOVER:-30}"
CEIL_RESTART="${POLARIS_FAILOVER_CEIL_RESTART:-60}"
read -r -a COMPOSE_EXTRA <<< "${POLARIS_COMPOSE_EXTRA:-}"
compose() { (cd "$ROOT/polaris_web" && docker compose -f docker-compose.prod.yml "${COMPOSE_EXTRA[@]}" "$@"); }
WORK="$(mktemp -d)"
[[ -n "$OUT" ]] || OUT="$WORK/failover.json"
PY_IMAGE="python:3.12-alpine@sha256:d81968c559557b881aa557ff6d1200acec8e72a2c85fcb4ad1806e8d13e09f0b"
WRITER=polaris-ha-writer
SECRETS="${POLARIS_SECRETS_DIR:-$ROOT/polaris_web/secrets}"
VERSION="$(sed -n 's/^__version__: str = "\(.*\)"/\1/p' "$ROOT/polaris_web/__version__.py")"
GIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
DCS_NET=""; PARTITIONED=""; PARTITION_ALIAS_ARGS=()

diagnose() {  # what the cluster looked like when a scenario failed; the CI job tears the stack down afterwards
    echo "--- diagnostics ---" >&2
    for m in postgres postgres2; do
        echo "[$m] /cluster: $(rest "$m" /cluster 2>/dev/null || echo unreachable)" >&2
        echo "[$m] /patroni: $(rest "$m" /patroni 2>/dev/null || echo unreachable)" >&2
        echo "[$m] last 40 log lines:" >&2; docker logs --tail 40 "polaris-$m" 2>&1 | sed 's/^/    /' >&2
    done
    echo "[pg-router] last 15 log lines:" >&2; docker logs --tail 15 polaris-pg-router 2>&1 | sed 's/^/    /' >&2
    for e in etcd1 etcd2 etcd3; do echo "[$e] $(docker inspect -f '{{.State.Status}} health={{.State.Health.Status}}' "polaris-$e" 2>/dev/null)" >&2; done
    echo "[writer] last 12 lines:" >&2; tail -12 "$WORK/state/writes.log" 2>/dev/null | sed 's/^/    /' >&2
}
fail() { echo "::error::$*" >&2; diagnose; exit 1; }
cleanup() {
    if [[ -n "${TRAFFIC_PID:-}" ]]; then kill -TERM "$TRAFFIC_PID" 2>/dev/null || true; wait "$TRAFFIC_PID" 2>/dev/null || true; fi
    if [[ -n "${VERIFY_PID:-}" ]]; then kill -TERM "$VERIFY_PID" 2>/dev/null || true; wait "$VERIFY_PID" 2>/dev/null || true; fi
    docker rm -f "$WRITER" >/dev/null 2>&1 || true
    if [[ -n "$PARTITIONED" && -n "$DCS_NET" ]]; then
        docker network connect ${PARTITION_ALIAS_ARGS[@]+"${PARTITION_ALIAS_ARGS[@]}"} "$DCS_NET" "polaris-$PARTITIONED" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- primitives -----------------------------------------------------------------
now() { python3 -c "import time; print(time.time())"; }
elapsed() { python3 -c "import sys,time; print(int(round(time.time() - float(sys.argv[1]))))" "$1"; }
wait_for() {  # wait_for SECONDS FN ... -> prints elapsed seconds; returns 1 on timeout
    local limit="$1"; shift; local t0 i; t0=$(date +%s)
    for i in $(seq 1 "$limit"); do if "$@"; then echo $(( $(date +%s) - t0 )); return 0; fi; sleep 1; done
    echo "$limit"; return 1
}
crash() {  # SIGKILL the container's init from the host pid namespace: a crash the restart policy answers
    local pid; pid=$(docker inspect -f '{{.State.Pid}}' "$1")
    [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || fail "cannot resolve the init pid of $1"
    docker run --rm --privileged --pid=host "$PY_IMAGE" kill -9 "$pid" >/dev/null
}
rest() { docker exec "polaris-$1" wget -qO- "http://127.0.0.1:8008$2" 2>/dev/null; }
cluster_field() {  # cluster_field VIA FIELD [MEMBER]: leader | role MEMBER | state MEMBER | lag MEMBER | timeline MEMBER
    rest "$1" /cluster | python3 -c "
import json, sys
d = json.load(sys.stdin); what = sys.argv[1]; who = sys.argv[2] if len(sys.argv) > 2 else None
ms = d.get('members', [])
if what == 'leader': print(next((m['name'] for m in ms if m.get('role') == 'leader'), '')); sys.exit()
m = next((m for m in ms if m['name'] == who), None)
print('' if m is None else m.get(what, ''))" "$2" "${3:-}" 2>/dev/null || true
}
leader_via() { cluster_field "$1" leader; }
leader() {  # ask either member; the survivor answers when one is down
    local l; l=$(leader_via postgres); [[ -n "$l" ]] || l=$(leader_via postgres2); echo "$l"
}
other() { [[ "$1" == postgres ]] && echo postgres2 || echo postgres; }
is_primary() { rest "$1" /primary >/dev/null; }
not_primary() { ! is_primary "$1"; }
leader_is() { [[ "$(leader_via "$2")" == "$1" ]]; }
leader_changed_from() { local l; l=$(leader_via "$2"); [[ -n "$l" && "$l" != "$1" ]]; }
replica_streaming() {  # replica_streaming MEMBER VIA
    [[ "$(cluster_field "$2" role "$1")" == "replica" && "$(cluster_field "$2" state "$1")" == "streaming" ]]
}
container_healthy() { [[ "$(docker inspect --format '{{.State.Health.Status}}' "$1" 2>/dev/null)" == "healthy" ]]; }
edge_ok() { curl -sk -o /dev/null -w '%{http_code}' "$URL/api/health" 2>/dev/null | grep -q 200; }
writes_ok_since() {  # an insert COMPLETED after T
    python3 -c "
import sys
t = float(sys.argv[2])
ok = [float(l.split()[1]) for l in open(sys.argv[1]) if l.strip().endswith(' ok')]
sys.exit(0 if any(x > t for x in ok) else 1)" "$WORK/state/writes.log" "$1" 2>/dev/null
}
gap_since() {  # gap_since T0 -> "gap_s fails stall_s": the failed-insert span, the failed count, and the longest
               # interval between two successful inserts since T0 (a queued insert stalls rather than fails)
    python3 -c "
import sys
t0 = float(sys.argv[2])
allrows = [(float(e), st) for _, e, st in (l.split() for l in open(sys.argv[1]) if l.strip())]  # completion time, outcome
rows = [(t, s) for t, s in allrows if t >= t0]
fails = [t for t, s in rows if s == 'fail']
gap = 0.0
if fails:
    first, last = min(fails), max(fails)
    after = [t for t, s in rows if s == 'ok' and t > last]
    gap = (min(after) - first) if after else (last - first)
oks = [t for t, s in rows if s == 'ok']
before = [t for t, s in allrows if s == 'ok' and t < t0]
seq = ([max(before)] if before else []) + oks
stall = max((b - a for a, b in zip(seq, seq[1:])), default=0.0)
print(f'{gap:.1f} {len(fails)} {stall:.1f}')" "$WORK/state/writes.log" "$1"
}
outage() { python3 -c "import sys; print(max(float(sys.argv[1]), float(sys.argv[2])))" "$1" "$2"; }
le() { python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)" "$1" "$2"; }

# --- the write stream and the read traffic ---------------------------------------
cat > "$WORK/writer.py" <<'PYEOF'
import os, signal, sys, time
import psycopg
dsn = os.environ["DSN"]; log = open("/state/writes.log", "a", buffering=1)
stop = False
signal.signal(signal.SIGTERM, lambda *a: globals().__setitem__("stop", True))
while not stop:
    t = time.time()   # each line: start, end, outcome; an insert queued in the pooler is a long line, not a fast one
    try:
        with psycopg.connect(dsn, connect_timeout=3, autocommit=True) as c:
            c.execute("INSERT INTO ha_marker DEFAULT VALUES")
        log.write(f"{t:.3f} {time.time():.3f} ok\n")
    except Exception:
        log.write(f"{t:.3f} {time.time():.3f} fail\n")
    time.sleep(0.25)
PYEOF
cat > "$WORK/traffic.py" <<'PYEOF'
import json, signal, ssl, sys, threading, time, urllib.request
base = sys.argv[1]; out = sys.argv[2]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
stats = {"requests": 0, "served": 0, "drops": 0, "by": {}}
lock = threading.Lock(); stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *a: stop.set())
def worker(path):
    while not stop.is_set():
        key = "ok"
        try:
            with urllib.request.urlopen(base + path, timeout=5, context=ctx) as r:
                if r.status != 200: key = f"http_{r.status}"
        except urllib.error.HTTPError as e: key = f"http_{e.code}"
        except Exception as e: key = "transport:" + type(e).__name__
        with lock:
            stats["requests"] += 1
            if key == "ok": stats["served"] += 1
            elif key != "http_429": stats["drops"] += 1
            stats["by"][key] = stats["by"].get(key, 0) + 1
        time.sleep(0.25)
threads = [threading.Thread(target=worker, args=(p,), daemon=True) for p in ["/api/health/live"] * 2 + ["/api/health"] * 2]
[t.start() for t in threads]
while not stop.is_set(): time.sleep(0.2)
time.sleep(0.5)
with open(out, "w") as fh: json.dump(stats, fh)
PYEOF
ok_count() { grep -c ' ok$' "$WORK/state/writes.log" 2>/dev/null || echo 0; }
rows_on() { docker exec "polaris-$1" psql -h /var/run/postgresql -U postgres -d polaris -tAc "SELECT count(*) FROM ha_marker" 2>/dev/null | tr -d '[:space:]'; }
replica_current() {  # replica_current MEMBER VIA: streaming with zero lag, twice a second apart
    local i; for i in 1 2; do
        replica_streaming "$1" "$2" || return 1
        [[ "$(cluster_field "$2" lag "$1")" == "0" ]] || return 1
        [[ $i -eq 1 ]] && sleep 1
    done
    return 0
}
ROWS0=0
no_lost_write() {  # no_lost_write FLOOR: every insert acknowledged before the failure began (FLOOR of them) is in
                   # the surviving history; inserts acknowledged after it began may be the async replication's
                   # RPO (FAILOVER.md section 6) and are reported, not tolerated silently
    local floor="$1" leader rows acked lost; leader=$(leader); rows=$(( $(rows_on "$leader") - ROWS0 )); acked=$(ok_count)
    [[ "$rows" -ge "$floor" ]] || fail "$rows rows added to ha_marker on $leader but $floor inserts were acknowledged before the failure began: an acknowledged write from before the failure was lost"
    lost=$(( acked - rows )); [[ "$lost" -lt 0 ]] && lost=0
    echo "  integrity: $rows rows added on $leader, $acked inserts acknowledged, $lost of them (acknowledged inside the failure window) not in the surviving history"
}
member_role_is() { [[ "$(rest "$1" /patroni | python3 -c "import json,sys; print(json.load(sys.stdin).get('role',''))" 2>/dev/null)" == "$2" ]]; }
settle() {  # the write stream must be flowing and the replica current before a scenario starts its clock
    local t l r; t=$(now); wait_for 60 writes_ok_since "$t" >/dev/null || fail "writes are not flowing before the next scenario"
    l=$(leader); r=$(other "$l")
    wait_for 90 replica_current "$r" "$l" >/dev/null || fail "$r is not a current streaming replica of $l before the next scenario ($(cluster_field "$l" state "$r"), lag $(cluster_field "$l" lag "$r"))"
}
traffic_start() { : > "$1"; python3 "$WORK/traffic.py" "$URL" "$1" & TRAFFIC_PID=$!; }
traffic_stop()  { kill -TERM "$TRAFFIC_PID" 2>/dev/null || true; wait "$TRAFFIC_PID" 2>/dev/null || true; TRAFFIC_PID=""; }
drops() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['drops'], 'of', d['requests'])" "$1"; }
# The recovery probe (P2.9): after a failover, does the login-gated, replica-routed
# verify-AT-USE endpoint answer 200 again? --once logs in fresh (proving the auth
# write path recovered too) and retries, so it is called after writes have resumed.
verify_recovered() { python3 "$ROOT/scripts/polaris-verify-load.py" --url "$URL" --login "polarisdrill:${VPASS:-}" --once; }

echo "== failover drill: v$VERSION @ $GIT, against $URL =="
edge_ok || fail "edge not healthy before the drill"
NET=$(compose config --format json | python3 -c "import json,sys; print(json.load(sys.stdin)['networks']['polaris-net']['name'])")
DCS_NET=$(compose config --format json | python3 -c "import json,sys; print(json.load(sys.stdin)['networks']['polaris-dcs']['name'])")
[[ -n "$NET" && -n "$DCS_NET" ]] || fail "could not resolve the stack networks (is docker-compose.ha.yml in POLARIS_COMPOSE_EXTRA?)"
L0=$(leader); [[ -n "$L0" ]] || fail "no Patroni leader reachable"
R0=$(other "$L0")
replica_streaming "$R0" "$L0" || fail "$R0 is not a streaming replica of $L0 before the drill ($(cluster_field "$L0" role "$R0")/$(cluster_field "$L0" state "$R0"))"
echo "  leader $L0, replica $R0 streaming, timeline $(cluster_field "$L0" timeline "$L0")"

# v9.246 (roadmap P2.2): the app routes its read-only surfaces to the replica
# through the pooler's polaris_ro database -> pg-router:5433. /api/health reports
# the replica's reachability and lag; assert the app is actually serving reads
# from it (healthy + within the staleness contract).
RH=$(curl -sk "$URL/api/health" 2>/dev/null | python3 -c "import json,sys; r=(json.load(sys.stdin).get('checks') or {}).get('database_replica'); print('%s/%s' % (r.get('status'), r.get('serving_reads')) if r else 'absent')" 2>/dev/null || echo err)
echo "  read replica routing: database_replica=$RH"
[[ "$RH" == "healthy/True" ]] || fail "the app is not routing reads to the replica (database_replica=$RH; expected healthy/True)"

# The marker table the writer fills, created on the leader by the superuser
# over the local socket (pg_hba: local trust, like the stock image).
docker exec "polaris-$L0" psql -h /var/run/postgresql -U postgres -d polaris -v ON_ERROR_STOP=1 -q \
    -c "CREATE TABLE IF NOT EXISTS ha_marker (id bigserial PRIMARY KEY, ts timestamptz NOT NULL DEFAULT clock_timestamp());" \
    -c "GRANT INSERT ON ha_marker TO polaris_app; GRANT USAGE ON SEQUENCE ha_marker_id_seq TO polaris_app;" \
    || fail "could not create the marker table on $L0"
ROWS0=$(rows_on "$L0"); [[ "$ROWS0" =~ ^[0-9]+$ ]] || fail "cannot count ha_marker on $L0"
mkdir -p "$WORK/state"; : > "$WORK/state/writes.log"; chmod 0777 "$WORK/state"; chmod 0644 "$WORK/writer.py"
APP_PW=$(cat "$SECRETS/polaris_db_password")
docker rm -f "$WRITER" >/dev/null 2>&1 || true
docker run -d --name "$WRITER" --network "$NET" \
    -e DSN="host=pgbouncer port=6432 dbname=polaris user=polaris_app password=$APP_PW sslmode=require application_name=ha_drill" \
    -v "$WORK/writer.py:/writer.py:ro" -v "$WORK/state:/state" --entrypoint python3 polaris-postgres:prod /writer.py >/dev/null
t=$(now); wait_for 30 writes_ok_since "$t" >/dev/null || { docker logs "$WRITER" 2>&1 | tail -5 >&2; fail "the writer never completed an insert through pgbouncer and HAProxy"; }
echo "  writes flowing through pgbouncer -> pg-router -> $L0"

# A real admin for the verification load: production disables the demo accounts,
# so compute the scrypt hash in the app container (it carries werkzeug; the CI
# runner does not) and insert it on the current leader (it replicates). P2.9: the
# verify-AT-USE path must RECOVER after each failover, and keep serving under load.
echo "== bootstrap: a verification load on /api/tokens/<id>/verify =="
VPASS="drill-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
VHASH=$(compose exec -T -e P="$VPASS" app python3 -c \
    "import os; from werkzeug.security import generate_password_hash as g; print(g(os.environ['P'], method='scrypt'))" 2>/dev/null | tr -d '\r') \
    || fail "could not compute the operator hash in the app container"
docker exec "polaris-$L0" psql -h /var/run/postgresql -U postgres -d polaris -v ON_ERROR_STOP=1 -c \
    "INSERT INTO AppUser (username,password_hash,role,is_active,webauthn_required_after) VALUES ('polarisdrill','$VHASH','admin',TRUE,NULL) ON CONFLICT (username) DO UPDATE SET password_hash=EXCLUDED.password_hash, is_active=TRUE, locked_until=NULL, failed_login_count=0" >/dev/null \
    || fail "could not bootstrap the drill admin on $L0"
verify_recovered || fail "the verify-at-use endpoint did not answer 200 before the drill"
# One steady verification load spanning ALL scenarios; asserted at the end. A
# low rate (~2 rps): the per-scenario health traffic already runs near the edge's
# per-IP rate budget, and 429s are tolerated (not drops), not counted as served.
python3 "$ROOT/scripts/polaris-verify-load.py" --url "$URL" --login "polarisdrill:$VPASS" \
    --threads 2 --interval 1.0 --out "$WORK/verify.json" & VERIFY_PID=$!

# --- 1. the leader node is lost ------------------------------------------------------
settle
echo "== 1. the leader node ($L0) is lost: killed, and it stays down past the lease =="
traffic_start "$WORK/s1.json"
acked0=$(ok_count); t0=$(now)
docker kill -s KILL "polaris-$L0" >/dev/null   # a manual stop to Docker: no restart, the node is gone
p1=$(wait_for "$CEIL_FAILOVER" leader_changed_from "$L0" "$R0") || fail "no new leader within ${CEIL_FAILOVER}s of losing the leader"
L1=$(leader_via "$R0"); [[ "$L1" == "$R0" ]] || fail "the new leader is $L1, not the surviving replica $R0"
w1=$(wait_for "$CEIL_FAILOVER" writes_ok_since "$t0") || fail "writes did not resume within ${CEIL_FAILOVER}s of losing the leader"
read -r gap1 fails1 stall1 <<< "$(gap_since "$t0")"; out1=$(outage "$gap1" "$stall1")
compose start "$L0" >/dev/null 2>&1 || fail "could not start $L0 again"
j1=$(wait_for "$CEIL_REJOIN" replica_streaming "$L0" "$L1") || fail "$L0 did not rejoin as a streaming replica within ${CEIL_REJOIN}s of starting again"
sleep 2; traffic_stop
tl1=$(cluster_field "$L1" timeline "$L1")
echo "  promoted $L1 after ${p1}s; writes: ${fails1} failed (span ${gap1}s), longest stall ${stall1}s, outage ${out1}s; $L0 rejoined as a replica ${j1}s after it was started; timeline $tl1; reads dropped $(drops "$WORK/s1.json")"
le "$out1" "$CEIL_FAILOVER" || fail "write outage ${out1}s exceeds the ${CEIL_FAILOVER}s ceiling"
no_lost_write "$acked0"
[[ "$(cluster_field "$L1" timeline "$L0")" == "$tl1" ]] || fail "$L0 is on timeline $(cluster_field "$L1" timeline "$L0"), the leader on $tl1: it did not follow"
verify_recovered || fail "verification did not recover after the leader was lost (scenario 1)"

# --- 2. the leader is cut off from the lease store -------------------------------------
settle
echo "== 2. the leader ($L1) is cut off from the lease store; its clients and the other member can still reach it =="
PARTITION_ALIAS_ARGS=()
while IFS= read -r a; do [[ -n "$a" ]] && PARTITION_ALIAS_ARGS+=(--alias "$a"); done < <(docker inspect -f '{{json (index .NetworkSettings.Networks "'"$DCS_NET"'").Aliases}}' "polaris-$L1" \
    | python3 -c "import json,sys; [print(a) for a in (json.load(sys.stdin) or [])]")
traffic_start "$WORK/s2.json"
acked0=$(ok_count); t0=$(now)
docker network disconnect "$DCS_NET" "polaris-$L1"; PARTITIONED="$L1"
d2=$(wait_for "$CEIL_DEMOTE" not_primary "$L1") || fail "$L1 kept answering /primary for ${CEIL_DEMOTE}s without its lease: the split-brain guard did not hold"
# The member stops answering /primary the moment Patroni decides to demote,
# a second or so before its Postgres restarts read-only; inserts it still
# acknowledges in that second are within its lease. The leaderless clock
# starts when it is read-only.
wait_for 30 member_role_is "$L1" replica >/dev/null || fail "$L1 did not restart read-only within 30s of standing down"
acked_at_demotion=$(ok_count)
outcome2=promoted
if p2=$(wait_for "$CEIL_FAILOVER" leader_is "$L0" "$L0"); then
    :
else
    outcome2=leaderless
    behind=$(docker logs --since 90s "polaris-$L0" 2>&1 | grep -c "ahead of my wal position" || true)
    acked_leaderless=$(( $(ok_count) - acked_at_demotion ))
    [[ "$acked_leaderless" -eq 0 ]] || fail "$acked_leaderless inserts were acknowledged while no member held the lease"
    echo "  no member took the lease in ${CEIL_FAILOVER}s: $L0 deferred to $L1, which is ahead of it ($behind such checks) and cannot reach the store; no insert was acknowledged meanwhile"
fi
docker network connect "${PARTITION_ALIAS_ARGS[@]}" "$DCS_NET" "polaris-$L1"; PARTITIONED=""
if [[ "$outcome2" == leaderless ]]; then
    p2=$(wait_for "$CEIL_FAILOVER" leader_changed_from "" "$L0") || fail "no member took the lease within ${CEIL_FAILOVER}s of the partition healing"
    p2=$(( $(elapsed "$t0") ))
fi
w2=$(wait_for "$CEIL_FAILOVER" writes_ok_since "$t0") || fail "writes did not resume within ${CEIL_FAILOVER}s"
L2=$(leader); R2=$(other "$L2")
j2=$(wait_for "$CEIL_REJOIN" replica_streaming "$R2" "$L2") || fail "$R2 did not rejoin as a streaming replica within ${CEIL_REJOIN}s"
sleep 2; traffic_stop
read -r gap2 fails2 stall2 <<< "$(gap_since "$t0")"; out2=$(outage "$gap2" "$stall2")
if [[ "$outcome2" == promoted ]]; then
    echo "  $L1 demoted itself after ${d2}s; $L0 took the lease after ${p2}s; writes: ${fails2} failed (span ${gap2}s), longest stall ${stall2}s, outage ${out2}s; $R2 rejoined after ${j2}s; reads dropped $(drops "$WORK/s2.json")"
    le "$out2" "$CEIL_FAILOVER" || fail "write outage ${out2}s exceeds the ${CEIL_FAILOVER}s ceiling"
else
    echo "  $L1 demoted itself after ${d2}s; leaderless until the partition healed; $L2 held the lease ${p2}s after the partition began; writes: ${fails2} failed (span ${gap2}s), longest stall ${stall2}s, outage ${out2}s; $R2 streaming after ${j2}s; reads dropped $(drops "$WORK/s2.json")"
fi
no_lost_write "$acked0"
verify_recovered || fail "verification did not recover after the lease partition (scenario 2)"

# --- 3. a planned switchover ------------------------------------------------------------
settle
L3=$(leader); C3=$(other "$L3")
echo "== 3. a planned switchover ($L3 -> $C3) =="
traffic_start "$WORK/s3.json"
t0=$(now)
docker exec "polaris-$L3" patronictl -c /var/lib/postgresql/patroni.yml switchover --primary "$L3" --candidate "$C3" --force >/dev/null 2>&1 \
    || fail "patronictl switchover failed"
p3=$(wait_for "$CEIL_SWITCHOVER" leader_is "$C3" "$C3") || fail "$C3 did not become leader within ${CEIL_SWITCHOVER}s of the switchover"
w3=$(wait_for "$CEIL_SWITCHOVER" writes_ok_since "$t0") || fail "writes did not resume within ${CEIL_SWITCHOVER}s of the switchover"
j3=$(wait_for "$CEIL_REJOIN" replica_streaming "$L3" "$C3") || fail "$L3 did not follow as a streaming replica within ${CEIL_REJOIN}s"
sleep 2; traffic_stop
read -r gap3 fails3 stall3 <<< "$(gap_since "$t0")"; out3=$(outage "$gap3" "$stall3")
echo "  $C3 leader after ${p3}s; writes: ${fails3} failed (span ${gap3}s), longest stall ${stall3}s, outage ${out3}s; $L3 follows after ${j3}s; reads dropped $(drops "$WORK/s3.json")"
le "$out3" "$CEIL_SWITCHOVER" || fail "switchover write outage ${out3}s exceeds the ${CEIL_SWITCHOVER}s ceiling"
no_lost_write "$(ok_count)"
L1="$C3"
verify_recovered || fail "verification did not recover after the switchover (scenario 3)"

# --- 4. an etcd member crashes ----------------------------------------------------------
settle
echo "== 4. one etcd member (etcd1) crashes =="
traffic_start "$WORK/s4.json"
t0=$(now)
crash polaris-etcd1
sleep 25
[[ "$(leader_via "$L1")" == "$L1" ]] || fail "the leader changed when one etcd member crashed; the quorum did not hold"
read -r gap4 fails4 stall4 <<< "$(gap_since "$t0")"
[[ "$fails4" -eq 0 ]] || fail "${fails4} inserts failed while one etcd member was down; the quorum must carry the lease"
le "$stall4" 5 || fail "writes stalled ${stall4}s while one etcd member was down; the quorum must carry the lease"
r4=$(wait_for "$CEIL_RESTART" container_healthy polaris-etcd1) || fail "etcd1 did not restart healthy within ${CEIL_RESTART}s"
sleep 2; traffic_stop
echo "  leader unchanged, 0 failed inserts, longest stall ${stall4}s; etcd1 back healthy after ${r4}s; reads dropped $(drops "$WORK/s4.json")"
verify_recovered || fail "verification did not recover after the etcd member crash (scenario 4)"

wait_for 30 edge_ok >/dev/null || fail "stack not healthy at the end of the drill"

# P2.9: verification held under load across the whole failover sequence. Reads
# (verification included) DO drop during a database failover's window, so this
# does not assert zero drops the way the app-tier rolling drill does; it asserts
# verification kept being SERVED at rate throughout and recovered after each
# failover (the four verify_recovered probes above). The drop count is reported
# next to the write outages so the two are comparable.
if [[ -n "${VERIFY_PID:-}" ]]; then kill -TERM "$VERIFY_PID" 2>/dev/null || true; wait "$VERIFY_PID" 2>/dev/null || true; VERIFY_PID=""; fi
python3 - "$WORK/verify.json" "$WORK/verify-latency.json" <<'PYEOF'
import json, sys
s = json.load(open(sys.argv[1]))
print(f"  verification under load across the failover sequence: {s['requests']} requests, "
      f"{s['served']} served, {s['drops']} dropped, breakdown {s['by']}")
assert s["served"] >= 100, f"only {s['served']} verifications served across the drill: too few to certify"

# v9.387 (roadmap P1.18 item 6) — the latency of verification ON THIS TOPOLOGY.
#
# The point of the item is "no one-core x8": stop reporting a single-core number
# multiplied by a core count as though a fleet had been measured. So what is
# printed here is what this two-member cluster actually did, at the rate this
# drill actually offered, and NOTHING is extrapolated from it.
#
# The percentiles the sample cannot carry are reported as unavailable rather than
# computed anyway. This drill offers ~2 rps on purpose (the per-scenario health
# traffic already sits near the edge's per-IP budget), so a p99 here would be the
# slowest single request wearing a statistic's name.
lat = s.get("latency_ms", {})
have = " ".join(f"{k}={lat[k]}ms" for k in ("p50", "p95", "p99") if lat.get(k) is not None)
print(f"  verification latency on this topology (n={lat.get('n', 0)} served, "
      f"{s.get('achieved_rps')}/s offered on {s.get('threads')} thread(s)): "
      f"{have or 'no percentile the sample supports'}")
for name, why in sorted(lat.get("_unavailable", {}).items()):
    print(f"    {name} not reported: {why}")
assert lat.get("p50") is not None, (
    "no p50 for verification latency across the drill; the sample should be well "
    f"past the floor at {s['served']} served")
json.dump({"latency_ms": lat, "achieved_rps": s.get("achieved_rps"),
           "threads": s.get("threads"), "served": s["served"]},
          open(sys.argv[2], "w"), indent=2)
print("  verification was served at rate throughout and recovered after every failover")
PYEOF
python3 - "$OUT" "$WORK/verify-latency.json" "$p1" "$out1" "$fails1" "$stall1" "$j1" "$d2" "$outcome2" "$p2" "$out2" "$fails2" "$stall2" "$j2" "$p3" "$out3" "$fails3" "$stall3" "$j3" "$stall4" "$r4" <<'PYEOF'
import json, sys
o, lat_path, p1, o1, f1, s1, j1, d2, oc2, p2, o2, f2, s2, j2, p3, o3, f3, s3, j3, s4, r4 = sys.argv[1:]
summary = {
    "leader_lost":           {"promoted_s": int(p1), "write_outage_s": float(o1), "failed_inserts": int(f1), "longest_stall_s": float(s1), "rejoined_s": int(j1)},
    "leader_cut_from_dcs":   {"demoted_s": int(d2), "outcome": oc2, "lease_held_again_s": int(p2), "write_outage_s": float(o2), "failed_inserts": int(f2), "longest_stall_s": float(s2), "rejoined_s": int(j2)},
    "switchover":            {"promoted_s": int(p3), "write_outage_s": float(o3), "failed_inserts": int(f3), "longest_stall_s": float(s3), "followed_s": int(j3)},
    "etcd_member_crashed":   {"leader_changed": False, "failed_inserts": 0, "longest_stall_s": float(s4), "restarted_s": int(r4)},
}
# v9.387 (P1.18 item 6): the verification latency measured ON THIS TOPOLOGY rides
# in the uploaded summary, so the one number an operator can cite about a real
# multi-node cluster is an artifact rather than a line in a log that scrolls away.
try:
    summary["verification"] = json.load(open(lat_path))
except (OSError, ValueError):
    pass
json.dump(summary, open(o, "w"), indent=2); print(json.dumps(summary))
PYEOF
echo "== FAILOVER DRILL PASSED: the replica took over a lost leader, a leader without its lease stood down, a switchover was a short gap, and the quorum carried an etcd crash =="
