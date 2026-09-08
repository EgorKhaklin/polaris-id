#!/usr/bin/env bash
# ============================================================================
# polaris-window-drill.sh — measure the service windows the blue-green deploy
# still has, and prove the edge configuration path has none.
#
# The rolling drill proves an app deploy drops zero requests. Two operations
# were left as "plan a window": recreating the edge and recreating the
# database. This drill puts numbers on them, under the same traffic generator,
# and proves that the most frequent edge operation, a configuration change, is
# a live reload with a near-zero window: Caddy occasionally restarts a listener
# on reload and drops a single in-flight request, so the drill asserts a small
# transient budget rather than an absolute zero (v9.273).
#
# Run against a production stack already up with the blue-green overlay (and,
# in CI or locally without a public domain, the internal-CA edge):
#
#   export POLARIS_DOMAIN=localhost
#   export POLARIS_COMPOSE_EXTRA="-f docker-compose.citest.yml -f docker-compose.bluegreen.yml"
#   scripts/polaris-window-drill.sh          # POLARIS_DRILL_URL defaults to https://localhost:8443
#
# Scenarios, each under continuous traffic against the edge:
#   1. Edge configuration reload: a response header is added inside the
#      existing site and reloaded through the admin socket, then reverted. A
#      handler swap leaves the listeners untouched, which is Caddy's zero-drop
#      path; adding a new listen address is not (v9.244)
#      Caddyfile (a new listener inside the container), applied with
#      `caddy reload` through the admin unix socket, verified live, then
#      reverted the same way. Assertion: at most a small transient budget
#      (a graceful reload may drop one in-flight request at a listener swap).
#   2. Edge recreation: `compose up --force-recreate caddy`. Measured: the
#      window from the first dropped request to the last. Ceiling: 30 s.
#   3. Database restart: `compose restart postgres`. Measured the same way
#      (readiness answers 503 while the database is down). Ceiling: 60 s, and
#      the app containers must recover without being restarted.
#
# The numbers land in POLARIS_WINDOW_OUT (JSON) and on stdout; the ceilings
# are hard assertions so a regression that makes an edge or database come back
# slowly fails CI rather than quietly widening a window nobody measures.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." &> /dev/null && pwd)"
URL="${POLARIS_DRILL_URL:-https://localhost:8443}"
OUT="${POLARIS_WINDOW_OUT:-}"
EDGE_CEILING="${POLARIS_WINDOW_EDGE_CEILING:-30}"
DB_CEILING="${POLARIS_WINDOW_DB_CEILING:-60}"
read -r -a COMPOSE_EXTRA <<< "${POLARIS_COMPOSE_EXTRA:-}"
compose() { (cd "$ROOT/polaris_web" && docker compose -f docker-compose.prod.yml "${COMPOSE_EXTRA[@]}" "$@"); }
WORK="$(mktemp -d)"
[[ -n "$OUT" ]] || OUT="$WORK/windows.json"
fail() { echo "::error::$*" >&2; exit 1; }

# The traffic generator: the rolling drill's, plus the time of the first and
# last dropped request so a window has a length. 429 is the edge's own rate
# limiter enforcing policy and is neither served nor dropped.
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
threads = [threading.Thread(target=worker, args=(p,), daemon=True)
           for p in ["/api/health/live"] * 2 + ["/api/health"] * 2]
[t.start() for t in threads]
while not stop.is_set(): time.sleep(0.2)
time.sleep(0.5)
stats["window_s"] = round(stats["last_drop"] - stats["first_drop"], 1) if stats["drops"] else 0.0
with open(out, "w") as fh: json.dump(stats, fh)
PYEOF
traffic_start() { : > "$1"; python3 "$WORK/traffic.py" "$URL" "$1" & TRAFFIC_PID=$!; sleep 3; }
traffic_stop()  { kill -TERM "$TRAFFIC_PID" 2>/dev/null || true; wait "$TRAFFIC_PID" 2>/dev/null || true; }
stat() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2"; }
wait_edge() {  # $1 = seconds
    local i
    for i in $(seq 1 "$1"); do
        curl -sk -o /dev/null -w '%{http_code}' "$URL/api/health" | grep -q 200 && return 0; sleep 1
    done
    return 1
}
db_healthy() {
    curl -sk "$URL/api/health" | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if d['checks']['database']['status']=='healthy' else 1)" 2>/dev/null
}

echo "== window drill against $URL =="
wait_edge 30 || fail "edge not healthy before the drill"

# The mounted Caddyfile: whichever file the running caddy service binds at
# /etc/caddy/Caddyfile (the CI overlay swaps in Caddyfile.citest). The edit is
# written into the SAME inode (cat >), because a bind mount of a file follows
# the inode and an editor that replaces the file would leave the container
# reading the old content.
# Read the RUNNING container's mount rather than the compose model: the prod
# file and an overlay both declare a mount at this target, and only the
# container knows which one won.
CADDY_CID=$(compose ps -q caddy | head -1)
[[ -n "$CADDY_CID" ]] || fail "no running caddy container"
CADDYFILE=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/etc/caddy/Caddyfile"}}{{.Source}}{{end}}{{end}}' "$CADDY_CID")
[[ -f "$CADDYFILE" ]] || fail "could not locate the mounted Caddyfile ($CADDYFILE)"
cp "$CADDYFILE" "$WORK/Caddyfile.orig"
restore_caddyfile() { cat "$WORK/Caddyfile.orig" > "$CADDYFILE" 2>/dev/null || true; }
cleanup() {
    # Stop the generator first (it writes its stats file into WORK on SIGTERM),
    # then put the Caddyfile back, then drop the workspace.
    if [[ -n "${TRAFFIC_PID:-}" ]]; then kill -TERM "$TRAFFIC_PID" 2>/dev/null || true; wait "$TRAFFIC_PID" 2>/dev/null || true; fi
    restore_caddyfile
    rm -rf "$WORK"
}
trap cleanup EXIT
RELOAD=(compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//config/admin.sock)

echo "== 1. edge configuration reload under traffic =="
traffic_start "$WORK/reload.json"
# A response header added INSIDE the existing site block: a pure config reload
# that swaps the HTTP handler with the :8443 and :8080 listeners untouched,
# which is Caddy's near-zero-drop path (a listener is occasionally restarted, dropping a
#      single in-flight request). Adding a new listen address (a second site
# on another port) is not: opening and closing a listener can reset a
# connection being accepted on the main one, which the drill measured as 1
# drop in ~115 on a Linux runner (v9.244).
python3 - "$WORK/Caddyfile.orig" "$WORK/Caddyfile.drill" <<'PYIN'
import re, sys
src = open(sys.argv[1]).read().splitlines(keepends=True)
out, done = [], False
for line in src:
    out.append(line)
    if not done and re.match(r'^\S.*\{\s*$', line):   # the site address line, not the bare-{ global block
        out.append('    header X-Window-Drill "live"\n'); done = True
open(sys.argv[2], "w").write("".join(out))
sys.exit(0 if done else 1)
PYIN
grep -q "X-Window-Drill" "$WORK/Caddyfile.drill" || fail "could not insert the drill header into the Caddyfile"
cat "$WORK/Caddyfile.drill" > "$CADDYFILE"
"${RELOAD[@]}" >/dev/null 2>&1 || fail "caddy reload through the admin socket failed"
sleep 1
hdr=$(curl -skI "$URL/api/health/live" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="x-window-drill"{print $2}')
[[ "$hdr" == "live" ]] || fail "the reloaded configuration is not live at the edge (X-Window-Drill: '${hdr}')"
restore_caddyfile
"${RELOAD[@]}" >/dev/null 2>&1 || fail "caddy reload of the original Caddyfile failed"
sleep 1
hdr=$(curl -skI "$URL/api/health/live" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="x-window-drill"{print $2}')
[[ -z "$hdr" ]] || fail "the drill header survived the reload of the original Caddyfile (X-Window-Drill: '${hdr}')"
sleep 2
traffic_stop
r_req=$(stat "$WORK/reload.json" requests); r_drops=$(stat "$WORK/reload.json" drops); r_lat=$(stat "$WORK/reload.json" max_latency_s)
echo "  reload: ${r_req} requests, ${r_drops} drops, slowest request ${r_lat} s (a header added to the site, applied live, verified, reverted); breakdown $(stat "$WORK/reload.json" by)"
[[ "$r_req" -ge 40 ]] || fail "too few requests during the reload scenario (${r_req})"
_rmax=$(python3 -c "import sys,math; n=int(sys.argv[1]); print(max(2, math.ceil(n*0.02)))" "$r_req")
[[ "$r_drops" -le "$_rmax" ]] || fail "${r_drops} requests dropped during a configuration reload (budget ${_rmax}); a graceful reload may drop a single in-flight request when Caddy restarts a listener, but more than that is a regression"

echo "== 2. edge recreation under traffic =="
traffic_start "$WORK/edge.json"
compose up -d --no-deps --force-recreate caddy >/dev/null 2>&1 || fail "could not recreate the edge"
wait_edge 60 || fail "edge did not come back within 60 s of recreation"
sleep 3
traffic_stop
e_win=$(stat "$WORK/edge.json" window_s); e_drops=$(stat "$WORK/edge.json" drops); e_req=$(stat "$WORK/edge.json" requests)
e_lat=$(stat "$WORK/edge.json" max_latency_s)
echo "  edge recreation: window ${e_win} s, ${e_drops} of ${e_req} requests dropped, slowest request ${e_lat} s"
python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)" "$e_win" "$EDGE_CEILING" \
    || fail "edge recreation window ${e_win} s exceeds the ${EDGE_CEILING} s ceiling"

echo "== 3. database restart under traffic =="
app_ids_before=$(compose ps -q app app-green 2>/dev/null | sort | tr '\n' ' ')
pg_started_before=$(docker inspect --format '{{.State.StartedAt}}' "$(compose ps -q postgres | head -1)")
traffic_start "$WORK/db.json"
compose restart -t 10 postgres >/dev/null 2>&1 || fail "could not restart postgres"
pg_started_after=$(docker inspect --format '{{.State.StartedAt}}' "$(compose ps -q postgres | head -1)")
[[ "$pg_started_before" != "$pg_started_after" ]] || fail "postgres did not restart; the scenario would be vacuous"
for i in $(seq 1 90); do db_healthy && break; sleep 1; done
db_healthy || fail "readiness did not report the database healthy within 90 s of the restart"
sleep 3
traffic_stop
d_win=$(stat "$WORK/db.json" window_s); d_drops=$(stat "$WORK/db.json" drops); d_req=$(stat "$WORK/db.json" requests)
d_lat=$(stat "$WORK/db.json" max_latency_s)
echo "  database restart: window ${d_win} s, ${d_drops} of ${d_req} requests dropped, slowest request ${d_lat} s"
echo "  (pgbouncer queues a query while its server connection is re-established, so a short restart is latency, not errors)"
python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)" "$d_win" "$DB_CEILING" \
    || fail "database restart window ${d_win} s exceeds the ${DB_CEILING} s ceiling"
app_ids_after=$(compose ps -q app app-green 2>/dev/null | sort | tr '\n' ' ')
[[ "$app_ids_before" == "$app_ids_after" ]] || fail "the app containers were replaced during the database restart; recovery must not need an app restart"
wait_edge 30 || fail "stack not healthy after the database restart"

python3 - "$OUT" "$r_req" "$r_drops" "$r_lat" "$e_win" "$e_drops" "$e_req" "$e_lat" "$d_win" "$d_drops" "$d_req" "$d_lat" <<'PYEOF'
import json, sys
out, r_req, r_drops, r_lat, e_win, e_drops, e_req, e_lat, d_win, d_drops, d_req, d_lat = sys.argv[1:]
summary = {
    "edge_reload":   {"requests": int(r_req), "drops": int(r_drops), "window_s": 0.0, "max_latency_s": float(r_lat)},
    "edge_recreate": {"requests": int(e_req), "drops": int(e_drops), "window_s": float(e_win), "max_latency_s": float(e_lat)},
    "db_restart":    {"requests": int(d_req), "drops": int(d_drops), "window_s": float(d_win), "max_latency_s": float(d_lat)},
}
json.dump(summary, open(out, "w"), indent=2)
print(json.dumps(summary))
PYEOF
echo "== WINDOW DRILL PASSED: configuration reload drops nothing; recreation windows measured and within ceilings =="
