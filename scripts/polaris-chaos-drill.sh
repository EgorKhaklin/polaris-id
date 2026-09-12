#!/usr/bin/env bash
# ============================================================================
# polaris-chaos-drill.sh — induced failures against the booted stack, with
# recovery measured and paging verified (roadmap P2.11, v9.242).
#
# polaris-chaos-test.sh asks whether the APPLICATION fails safe (it runs on
# every push). This drill asks what the STACK does when a component dies:
# whether the other colour carries the traffic, whether a killed container
# comes back on its own and how fast, whether the database and the pooler
# recover from a crash and a partition without an app restart, and whether a
# real outage reaches a pager. It runs against a production stack already up
# with the blue-green overlay (and, without a public domain, the internal-CA
# edge), the same way the rolling and window drills do:
#
#   export POLARIS_DOMAIN=localhost
#   export POLARIS_COMPOSE_EXTRA="-f docker-compose.citest.yml -f docker-compose.bluegreen.yml"
#   scripts/polaris-chaos-drill.sh [--record[=FILE]]     # --record appends a ledger row
#
# Paging is verified with real components: a Prometheus scraping the real app
# containers at one-second cadence with the shipped alert rules, the shipped
# Alertmanager configuration, and a webhook sink. Scenario B stops both app
# colours for longer than PolarisAppDown's two-minute `for`, and the drill
# waits for that alert to arrive at the sink before it starts them again.
#
# Scenarios, each under continuous traffic against the edge:
#   A. one app colour crashed (SIGKILL): zero dropped requests; the container
#      restarts on its own within CEIL_RESTART.
#   B. both app colours stopped for 150 s: requests drop (the generator must
#      see the outage), PolarisAppDown reaches the sink, service returns
#      within CEIL_RESTART of `compose start`.
#   C. redis crashed: the app keeps serving; redis restarts on its own;
#      readiness returns to healthy within CEIL_RESTART.
#   D. postgres crashed: readiness reports the database down, crash recovery
#      brings it back within CEIL_DB, and the app containers are not replaced.
#
# A crash is a SIGKILL of the container's init delivered from the host pid
# namespace. `docker kill` is not one: Docker records it as a manual stop and
# the restart policy does not apply, so a "killed" container stays down and the
# drill would be measuring nothing but its own primitive (found at v9.242
# when the first run left app-green exited and waiting). Killing PID 1 from
# inside the container is ignored by the kernel; from an ancestor namespace it
# is a crash like any other, and unless-stopped brings the container back.
# The partition has the same trap: `docker network connect` without --alias
# reattaches a container under its container name only, and the compose
# service alias (`pgbouncer`, the name the app dials) is gone, so the app
# fails DNS forever and the drill blames the stack. The reconnect restores the
# aliases the container had and proves the app resolves the name again before
# the recovery clock is read.
#   E. pgbouncer partitioned from the network for 15 s: readiness reports the
#      database down, and recovers within CEIL_RESTART of the reconnect.
#
# Every scenario records its recovery time; the ceilings are hard assertions,
# the same discipline as the window drill: a stack that recovers slowly fails
# CI rather than quietly widening a number nobody measures.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
URL="${POLARIS_DRILL_URL:-https://localhost:8443}"
OUT="${POLARIS_CHAOS_OUT:-}"
RECORD=""
for arg in "$@"; do
    case "$arg" in
        --record) RECORD="$ROOT/docs/operator/CHAOS-DRILLS.md" ;;
        --record=*) RECORD="${arg#--record=}" ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done
CEIL_RESTART="${POLARIS_CHAOS_CEIL_RESTART:-60}"
CEIL_DB="${POLARIS_CHAOS_CEIL_DB:-90}"
CEIL_PAGE="${POLARIS_CHAOS_CEIL_PAGE:-240}"
OUTAGE_S="${POLARIS_CHAOS_OUTAGE_S:-150}"
MODE="${POLARIS_CHAOS_MODE:-local}"
read -r -a COMPOSE_EXTRA <<< "${POLARIS_COMPOSE_EXTRA:-}"
compose() { (cd "$ROOT/polaris_web" && docker compose -f docker-compose.prod.yml "${COMPOSE_EXTRA[@]}" "$@"); }
WORK="$(mktemp -d)"
[[ -n "$OUT" ]] || OUT="$WORK/chaos.json"
OBS="$ROOT/deploy/observability"
PROM_IMAGE="prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"
AM_IMAGE="prom/alertmanager@sha256:690c7b525f4367aa91f73e2f91c632206d32e97c6384bdbf2fb7a861b420340d"
PY_IMAGE="python:3.12-alpine@sha256:d81968c559557b881aa557ff6d1200acec8e72a2c85fcb4ad1806e8d13e09f0b"
SINK=polaris-chaos-sink; AM=polaris-chaos-alertmanager; PROM=polaris-chaos-prometheus
DATE="$(date -u +%Y-%m-%dT%H:%MZ)"
VERSION="$(sed -n 's/^__version__: str = "\(.*\)"/\1/p' "$ROOT/polaris_web/__version__.py")"
GIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)$(git -C "$ROOT" diff --quiet 2>/dev/null || echo +dirty)"
declare -a ROW=()   # per-scenario "name=seconds" for the ledger

record_row() {  # record_row STATUS PAGE_S NOTE
    [ -n "$RECORD" ] || return 0
    printf '| %s | v%s | %s | %s | %s | %s | %s | %s |\n' \
        "$DATE" "$VERSION" "$GIT" "$MODE" "${ROW[*]:-}" "$2" "$1" "$3" >> "$RECORD"
    echo "   ledger row appended to $RECORD ($1)"
}
cleanup() {
    if [[ -n "${TRAFFIC_PID:-}" ]]; then kill -TERM "$TRAFFIC_PID" 2>/dev/null || true; wait "$TRAFFIC_PID" 2>/dev/null || true; fi
    docker rm -f "$SINK" "$AM" "$PROM" >/dev/null 2>&1 || true
    # Never leave the stack partitioned or stopped behind a failure.
    if [[ -n "${NET:-}" ]] && ! docker inspect -f '{{json .NetworkSettings.Networks}}' polaris-pgbouncer 2>/dev/null | grep -q "\"$NET\""; then
        docker network connect ${PGB_ALIAS_ARGS[@]+"${PGB_ALIAS_ARGS[@]}"} "$NET" polaris-pgbouncer >/dev/null 2>&1 || true
    fi
    compose start app app-green >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
fail() { record_row FAIL "-" "$*"; echo "::error::$*" >&2; exit 1; }

# --- the traffic generator (the window drill's) --------------------------------
cat > "$WORK/traffic.py" <<'PYEOF'
import json, signal, ssl, sys, threading, time, urllib.request
base = sys.argv[1]; out = sys.argv[2]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
stats = {"requests": 0, "served": 0, "drops": 0, "by": {}, "first_drop": None, "last_drop": None, "max_latency_s": 0.0}
lock = threading.Lock(); stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *a: stop.set())
def worker(path):
    while not stop.is_set():
        key = "ok"; t0 = time.time()
        try:
            with urllib.request.urlopen(base + path, timeout=5, context=ctx) as r:
                if r.status != 200: key = f"http_{r.status}"
        except urllib.error.HTTPError as e: key = f"http_{e.code}"
        except Exception as e: key = "transport:" + type(e).__name__
        now = time.time()
        with lock:
            stats["requests"] += 1
            stats["max_latency_s"] = max(stats["max_latency_s"], round(now - t0, 2))
            if key == "ok": stats["served"] += 1
            elif key != "http_429":
                stats["drops"] += 1
                stats["first_drop"] = stats["first_drop"] or now
                stats["last_drop"] = now
            stats["by"][key] = stats["by"].get(key, 0) + 1
        time.sleep(0.25)
threads = [threading.Thread(target=worker, args=(p,), daemon=True) for p in ["/api/health/live"] * 2 + ["/api/health"] * 2]
[t.start() for t in threads]
while not stop.is_set(): time.sleep(0.2)
time.sleep(0.5)
stats["window_s"] = round(stats["last_drop"] - stats["first_drop"], 1) if stats["drops"] else 0.0
with open(out, "w") as fh: json.dump(stats, fh)
PYEOF
traffic_start() { : > "$1"; python3 "$WORK/traffic.py" "$URL" "$1" & TRAFFIC_PID=$!; sleep 3; }
traffic_stop()  { kill -TERM "$TRAFFIC_PID" 2>/dev/null || true; wait "$TRAFFIC_PID" 2>/dev/null || true; TRAFFIC_PID=""; }
stat() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2"; }
edge_ok() { curl -sk -o /dev/null -w '%{http_code}' "$URL/api/health" 2>/dev/null | grep -q 200; }
db_healthy() {
    curl -sk "$URL/api/health" 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if d['checks']['database']['status']=='healthy' else 1)" 2>/dev/null
}
db_down() {
    curl -sk "$URL/api/health" 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if d['checks']['database']['status']!='healthy' else 1)" 2>/dev/null
}
wait_for() {  # wait_for SECONDS FN ... -> prints elapsed seconds, returns 1 on timeout
    local limit="$1"; shift; local t0 i; t0=$(date +%s)
    for i in $(seq 1 "$limit"); do if "$@"; then echo $(( $(date +%s) - t0 )); return 0; fi; sleep 1; done
    echo "$limit"; return 1
}
container_healthy() { [[ "$(docker inspect --format '{{.State.Health.Status}}' "$1" 2>/dev/null)" == "healthy" ]]; }
container_running() { [[ "$(docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null)" == "true" ]]; }
crash() {  # SIGKILL the container's init from the host pid namespace (see the header)
    local pid; pid=$(docker inspect -f '{{.State.Pid}}' "$1")
    [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || fail "cannot resolve the init pid of $1"
    docker run --rm --privileged --pid=host "$PY_IMAGE" kill -9 "$pid" >/dev/null
}

echo "== chaos drill ($MODE): v$VERSION @ $GIT, $DATE, against $URL =="
edge_ok || fail "edge not healthy before the drill"
NET=$(compose config --format json | python3 -c "import json,sys; print(json.load(sys.stdin)['networks']['polaris-net']['name'])")
[[ -n "$NET" ]] || fail "could not resolve the stack network"
app_ids_before=$(compose ps -q app app-green | sort | tr '\n' ' ')
# The pooler's network aliases (compose sets the service name); a reconnect
# without them leaves `pgbouncer` unresolvable (see the header).
PGB_ALIASES=()
while IFS= read -r a; do [[ -n "$a" ]] && PGB_ALIASES+=("$a"); done < <(docker inspect -f '{{json (index .NetworkSettings.Networks "'"$NET"'").Aliases}}' polaris-pgbouncer \
    | python3 -c "import json,sys; [print(a) for a in (json.load(sys.stdin) or [])]")
[[ "${#PGB_ALIASES[@]}" -gt 0 ]] || fail "pgbouncer has no network aliases on $NET; the app dials one"
PGB_ALIAS_ARGS=(); for a in "${PGB_ALIASES[@]+"${PGB_ALIASES[@]}"}"; do PGB_ALIAS_ARGS+=(--alias "$a"); done
app_resolves_pgbouncer() { docker exec polaris-app python3 -c "import socket; socket.gethostbyname('pgbouncer')" >/dev/null 2>&1; }
app_resolves_pgbouncer || fail "the app cannot resolve pgbouncer before the drill"

# --- paging path: real Prometheus on the real app, shipped rules + Alertmanager, a sink --
echo "== 0. the paging path: Prometheus scraping the real app, Alertmanager, a webhook sink =="
mkdir -p "$WORK/state"; : > "$WORK/state/hooks.log"; chmod 0777 "$WORK/state"
cat > "$WORK/sink.py" <<'PYEOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0")); body = self.rfile.read(n)
        with open("/state/hooks.log", "ab") as f: f.write(body.replace(b"\n", b" ") + b"\n")
        self.send_response(200); self.end_headers()
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
PYEOF
echo "http://polaris-chaos-sink:8080/webhook" > "$WORK/pager_webhook_url"; chmod 0644 "$WORK/pager_webhook_url" "$WORK/sink.py"
sed -e 's/scheme: https/scheme: http/' \
    -e "s/targets: \['polaris.example.com:443'\]/targets: ['polaris-app:8000', 'polaris-app-green:8000']/" \
    -e "s/targets: \['alertmanager:9093'\]/targets: ['polaris-chaos-alertmanager:9093']/" \
    -e 's/30s/1s/g' "$OBS/prometheus.yml" > "$WORK/prometheus.yml"
grep -q "polaris-app:8000" "$WORK/prometheus.yml" || fail "the drill prometheus.yml did not take the app targets"
docker rm -f "$SINK" "$AM" "$PROM" >/dev/null 2>&1 || true
docker run -d --name "$SINK" --network "$NET" -v "$WORK/sink.py:/sink.py:ro" -v "$WORK/state:/state" "$PY_IMAGE" python /sink.py >/dev/null
docker run -d --name "$AM" --network "$NET" \
    -v "$OBS/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro" \
    -v "$WORK/pager_webhook_url:/etc/alertmanager/secrets/pager_webhook_url:ro" \
    "$AM_IMAGE" --config.file=/etc/alertmanager/alertmanager.yml --cluster.listen-address= >/dev/null
docker run -d --name "$PROM" --network "$NET" \
    -v "$WORK/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
    -v "$OBS/polaris-alerts.yml:/etc/prometheus/polaris-alerts.yml:ro" \
    -v "$OBS/polaris-slo.yml:/etc/prometheus/polaris-slo.yml:ro" \
    "$PROM_IMAGE" >/dev/null
prom_query() { docker exec "$SINK" python -c "
import json,sys,urllib.parse,urllib.request
q=urllib.parse.quote(sys.argv[1]); d=json.load(urllib.request.urlopen('http://polaris-chaos-prometheus:9090/api/v1/query?query='+q, timeout=3))
print(' '.join(r['value'][1] for r in d['data']['result']))" "$1" 2>/dev/null; }
scraping() { [[ "$(prom_query 'sum(up{job="polaris"})' | tr -d ' ')" == "2" ]]; }
wait_for 60 scraping >/dev/null || fail "Prometheus never scraped both app colours (up{job=polaris} != 2)"
echo "  Prometheus scrapes both colours; Alertmanager routes sev1 with no group wait; sink ready"

# --- A. one colour killed ------------------------------------------------------
echo "== A. one app colour crashed under traffic =="
traffic_start "$WORK/a.json"
crash polaris-app-green
a_t=$(wait_for "$CEIL_RESTART" container_healthy polaris-app-green) || fail "app-green did not restart healthy within ${CEIL_RESTART}s"
sleep 2; traffic_stop
a_drops=$(stat "$WORK/a.json" drops); a_req=$(stat "$WORK/a.json" requests)
echo "  app-green back healthy in ${a_t}s; ${a_drops} of ${a_req} requests dropped"
[[ "$a_drops" -eq 0 ]] || fail "${a_drops} requests dropped while one colour was dead; the other colour must carry them"
ROW+=("A=${a_t}s")

# --- B. both colours stopped: the outage must page --------------------------------
echo "== B. both app colours stopped for ${OUTAGE_S}s: the outage must page =="
traffic_start "$WORK/b.json"
t0=$(date +%s)
compose stop -t 1 app app-green >/dev/null 2>&1 || fail "could not stop the app colours"
paged=""
for i in $(seq 1 "$CEIL_PAGE"); do
    if grep -q '"alertname":"PolarisAppDown"' "$WORK/state/hooks.log" 2>/dev/null; then paged=$(( $(date +%s) - t0 )); break; fi
    sleep 1
done
[[ -n "$paged" ]] || { docker logs "$PROM" 2>&1 | tail -10 >&2; fail "PolarisAppDown never reached the sink within ${CEIL_PAGE}s of the outage"; }
grep -q '"status":"firing"' "$WORK/state/hooks.log" || fail "the sink received a notification that was not a firing alert"
elapsed=$(( $(date +%s) - t0 )); [[ "$elapsed" -ge "$OUTAGE_S" ]] || sleep $(( OUTAGE_S - elapsed ))
compose start app app-green >/dev/null 2>&1 || fail "could not start the app colours"
b_t=$(wait_for "$CEIL_RESTART" edge_ok) || fail "service did not return within ${CEIL_RESTART}s of starting the colours"
sleep 2; traffic_stop
b_drops=$(stat "$WORK/b.json" drops); b_req=$(stat "$WORK/b.json" requests)
echo "  page delivered ${paged}s after the outage began; service back ${b_t}s after start; ${b_drops} of ${b_req} requests dropped"
[[ "$b_drops" -gt 0 ]] || fail "the generator saw no drops during a ${OUTAGE_S}s outage; it cannot detect one"
ROW+=("B=${b_t}s")

# --- C. redis killed ----------------------------------------------------------------
echo "== C. redis crashed under traffic =="
traffic_start "$WORK/c.json"
crash polaris-redis
c_t=$(wait_for "$CEIL_RESTART" container_healthy polaris-redis) || fail "redis did not restart healthy within ${CEIL_RESTART}s"
wait_for "$CEIL_RESTART" edge_ok >/dev/null || fail "readiness did not return to healthy after redis came back"
sleep 2; traffic_stop
c_drops=$(stat "$WORK/c.json" drops); c_req=$(stat "$WORK/c.json" requests); c_by=$(stat "$WORK/c.json" by)
echo "  redis back healthy in ${c_t}s; ${c_drops} of ${c_req} requests dropped; breakdown ${c_by}"
ROW+=("C=${c_t}s")

# --- D. postgres killed (a crash) -------------------------------------------------
echo "== D. postgres crashed (SIGKILL) under traffic =="
traffic_start "$WORK/d.json"
t0=$(date +%s)
crash polaris-postgres
wait_for 30 db_down >/dev/null || echo "  (readiness never saw the database down: crash recovery beat the probe)"
wait_for "$CEIL_DB" db_healthy >/dev/null || fail "the database did not recover within ${CEIL_DB}s of a crash"
d_t=$(( $(date +%s) - t0 ))
sleep 2; traffic_stop
d_drops=$(stat "$WORK/d.json" drops); d_req=$(stat "$WORK/d.json" requests); d_win=$(stat "$WORK/d.json" window_s)
echo "  database healthy ${d_t}s after the crash; ${d_drops} of ${d_req} requests dropped, window ${d_win}s"
app_ids_after=$(compose ps -q app app-green | sort | tr '\n' ' ')
[[ "$app_ids_before" == "$app_ids_after" ]] || fail "the app containers were replaced during the database crash; recovery must not need an app restart"
ROW+=("D=${d_t}s")

# --- E. pgbouncer partitioned --------------------------------------------------------
echo "== E. pgbouncer partitioned from the network for 15s =="
traffic_start "$WORK/e.json"
docker network disconnect "$NET" polaris-pgbouncer >/dev/null
wait_for 30 db_down >/dev/null || echo "  (readiness never saw the partition)"
sleep 15
t0=$(date +%s)
docker network connect "${PGB_ALIAS_ARGS[@]+"${PGB_ALIAS_ARGS[@]}"}" "$NET" polaris-pgbouncer >/dev/null
wait_for 10 app_resolves_pgbouncer >/dev/null || fail "the app cannot resolve pgbouncer after the reconnect; the drill's own primitive lost the aliases (${PGB_ALIASES[*]})"
wait_for "$CEIL_RESTART" db_healthy >/dev/null || fail "the database path did not recover within ${CEIL_RESTART}s of the reconnect"
e_t=$(( $(date +%s) - t0 ))
sleep 2; traffic_stop
e_drops=$(stat "$WORK/e.json" drops); e_req=$(stat "$WORK/e.json" requests); e_win=$(stat "$WORK/e.json" window_s)
echo "  database path healthy ${e_t}s after the reconnect; ${e_drops} of ${e_req} requests dropped, window ${e_win}s"
ROW+=("E=${e_t}s")

wait_for 30 edge_ok >/dev/null || fail "stack not healthy at the end of the drill"
python3 - "$OUT" "$a_t" "$a_drops" "$b_t" "$paged" "$b_drops" "$c_t" "$c_drops" "$d_t" "$d_drops" "$d_win" "$e_t" "$e_drops" "$e_win" <<'PYEOF'
import json, sys
o, a_t, a_d, b_t, paged, b_d, c_t, c_d, d_t, d_d, d_w, e_t, e_d, e_w = sys.argv[1:]
summary = {
    "one_colour_crashed":    {"recovered_s": int(a_t), "drops": int(a_d)},
    "both_colours_stopped":  {"paged_s": int(paged), "recovered_s": int(b_t), "drops": int(b_d)},
    "redis_crashed":         {"recovered_s": int(c_t), "drops": int(c_d)},
    "postgres_crashed":      {"recovered_s": int(d_t), "drops": int(d_d), "window_s": float(d_w)},
    "pgbouncer_partitioned": {"recovered_s": int(e_t), "drops": int(e_d), "window_s": float(e_w)},
}
json.dump(summary, open(o, "w"), indent=2); print(json.dumps(summary))
PYEOF
record_row PASS "$paged" "one colour: 0 drops; outage paged; postgres crash window ${d_win}s, partition window ${e_win}s; no app restart"
echo "== CHAOS DRILL PASSED: the other colour carried the traffic, the outage paged, every component came back on its own =="
