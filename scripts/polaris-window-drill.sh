#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-window-drill.sh: measure the service windows the blue-green deploy
# still has, and judge the edge configuration path under traffic.
#
# The rolling drill proves an app deploy drops zero requests. Two operations
# were left as "plan a window": recreating the edge and recreating the
# database. This drill puts numbers on them, under one traffic generator
# (scripts/polaris-window-traffic.py), and judges the most frequent edge
# operation, a configuration change, applied as a live reload: under traffic
# that retries a connection closed before an answer once, no request fails,
# no failure of another class occurs, and no more such closes than workers
# times reloads.
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
#      existing site, applied with `caddy reload` through the admin unix
#      socket, verified live, then reverted the same way. Judged by the
#      generator (--judge-reload): at least 40 requests served, no failure
#      after one retry, no failure of any class but a close before an answer,
#      and no more such closes than workers times reloads.
#   2. Edge recreation: `compose up --force-recreate caddy`. Measured: the
#      window from the first dropped request to the last. Ceiling: 30 s.
#   3. Database restart: `compose restart postgres`. Measured the same way
#      (a route that reads the database fails while it is down). Ceiling: 60 s, and
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

# The traffic generator (scripts/polaris-window-traffic.py): four workers on two public routes,
# a new connection per request, every failure recorded with its class, phase, reason chain and
# duration, and the time of the first and last drop so a window has a length. 429 is the edge's
# own rate limiter enforcing policy and is neither served nor dropped.
TRAFFIC="$SCRIPT_DIR/polaris-window-traffic.py"
[[ -f "$TRAFFIC" ]] || fail "the traffic generator $TRAFFIC is missing"
traffic_start() { : > "$1"; python3 "$TRAFFIC" "$URL" "$@" & TRAFFIC_PID=$!; sleep 3; }
traffic_stop()  { kill -TERM "$TRAFFIC_PID" 2>/dev/null || true; wait "$TRAFFIC_PID" 2>/dev/null || true; }
stat() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2"; }
# The edge serves a public route; the roll-up is read at the app's own address, since the edge
# refuses the health answers to a client outside POLARIS_METRICS_ALLOW.
app_health() { docker exec polaris-app curl -s "$@" http://localhost:8000/api/health 2>/dev/null; }
wait_edge() {  # $1 = seconds
    local i
    for i in $(seq 1 "$1"); do
        curl -sk -o /dev/null -w '%{http_code}' "$URL/.well-known/security.txt" | grep 200 >/dev/null \
            && app_health -o /dev/null -w '%{http_code}' | grep 200 >/dev/null && return 0; sleep 1
    done
    return 1
}
# The health JSON is fetched into a variable and parsed from argv, not piped into python: a fetch
# piped into an interpreter reads, to a supply-chain scanner, as downloaded code being run.
db_healthy() {
    local body; body=$(app_health) || return 1
    python3 -c "import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if d['checks']['database']['status']=='healthy' else 1)" "$body" 2>/dev/null
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
CADDY_CID=$(compose ps -q caddy | sed -n 1p)
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
# It recreates a service from the host's image tags (building it if missing): one build or deploy at a time.
source "${ROOT}/scripts/polaris-host-lock.sh"
polaris_host_lock "the window drill"
RELOAD=(compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//config/admin.sock)

echo "== 1. edge configuration reload under traffic =="
# The one scenario whose traffic retries: a request whose connection closed before an answer is
# sent once more at once, on a new connection, as a client of an idempotent GET may. A reload
# binds a new listener and shuts the old server down, which closes a connection it had accepted
# and not answered, at most once per connection; the judge holds the count of such closes to
# workers times reloads.
traffic_start "$WORK/reload.json" --retry
reloads=0
# A response header added INSIDE the existing site block: a pure configuration reload that swaps
# the HTTP handler and keeps the :8443 and :8080 addresses.
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
reloads=$((reloads + 1))
sleep 1
hdr=$(curl -skI "$URL/.well-known/security.txt" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="x-window-drill"{print $2}')
[[ "$hdr" == "live" ]] || fail "the reloaded configuration is not live at the edge (X-Window-Drill: '${hdr}')"
restore_caddyfile
"${RELOAD[@]}" >/dev/null 2>&1 || fail "caddy reload of the original Caddyfile failed"
reloads=$((reloads + 1))
sleep 1
hdr=$(curl -skI "$URL/.well-known/security.txt" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="x-window-drill"{print $2}')
[[ -z "$hdr" ]] || fail "the drill header survived the reload of the original Caddyfile (X-Window-Drill: '${hdr}')"
sleep 2
traffic_stop
r_req=$(stat "$WORK/reload.json" requests); r_drops=$(stat "$WORK/reload.json" drops); r_lat=$(stat "$WORK/reload.json" max_latency_s)
r_raw=$(stat "$WORK/reload.json" raw_retried); r_other=$(stat "$WORK/reload.json" other)
echo "  reload: ${r_req} requests over ${reloads} reloads, ${r_drops} failed after one retry, ${r_raw} closed before an answer and retried, ${r_other} other failures, slowest request ${r_lat} s (a header added to the site, applied live, verified, reverted); breakdown $(stat "$WORK/reload.json" by)"
echo "  reload failures (class, phase, reason chain, seconds): $(stat "$WORK/reload.json" failures)"
[[ "$reloads" -eq 2 ]] || fail "the reload scenario counted ${reloads} reloads, not 2"
verdict=$(python3 "$TRAFFIC" --judge-reload "$WORK/reload.json" "$reloads") \
    || fail "configuration reload under traffic: ${verdict}"
echo "  reload judged: ${verdict}"

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
pg_started_before=$(docker inspect --format '{{.State.StartedAt}}' "$(compose ps -q postgres | sed -n 1p)")
traffic_start "$WORK/db.json"
compose restart -t 10 postgres >/dev/null 2>&1 || fail "could not restart postgres"
pg_started_after=$(docker inspect --format '{{.State.StartedAt}}' "$(compose ps -q postgres | sed -n 1p)")
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

python3 - "$OUT" "$r_req" "$r_drops" "$r_lat" "$r_raw" "$r_other" "$e_win" "$e_drops" "$e_req" "$e_lat" "$d_win" "$d_drops" "$d_req" "$d_lat" <<'PYEOF'
import json, sys
out, r_req, r_drops, r_lat, r_raw, r_other, e_win, e_drops, e_req, e_lat, d_win, d_drops, d_req, d_lat = sys.argv[1:]
summary = {
    "edge_reload":   {"requests": int(r_req), "drops": int(r_drops), "window_s": 0.0, "max_latency_s": float(r_lat),
                      "closed_before_an_answer_retried": int(r_raw), "other_failures": int(r_other)},
    "edge_recreate": {"requests": int(e_req), "drops": int(e_drops), "window_s": float(e_win), "max_latency_s": float(e_lat)},
    "db_restart":    {"requests": int(d_req), "drops": int(d_drops), "window_s": float(d_win), "max_latency_s": float(d_lat)},
}
json.dump(summary, open(out, "w"), indent=2)
print(json.dumps(summary))
PYEOF
echo "== WINDOW DRILL PASSED: configuration reload applied live with no failure after one retry; recreation windows measured and within ceilings =="
