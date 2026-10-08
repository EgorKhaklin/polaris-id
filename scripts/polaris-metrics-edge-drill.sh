#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-metrics-edge-drill.sh: who can read /metrics and /api/metrics through the edge?
# (lab record 017, gate row OP-26)
#
# Both surfaces carry polaris_duress_events_total and neither authenticates, so whoever reads
# them can see that, and roughly when, a duress alarm fired. The edge is the control. This
# drill takes the matcher out of the SHIPPED polaris_web/Caddyfile (not a copy of it), puts
# it in front of a stub upstream, and asks from two places:
#
#   in-network   a client on the stack's own network
#   via SNAT     the same request through a TCP forwarder, which is what a client on the
#                internet looks like to the edge behind an L4 load balancer, Kubernetes'
#                default externalTrafficPolicy, rootless Docker's port driver or Docker's
#                userland proxy for IPv6: a private address that is not the client's
#
# With POLARIS_METRICS_ALLOW unset, both must get 404 (no one is allowed by default; a
# monitoring network has to be named). Naming a range lets that range in and no one else.
# Ordinary routes stay 200 throughout.
#
# Usage: polaris-metrics-edge-drill.sh [caddy image] (default polaris-caddy:prod)
# Exit: 0 every probe answered as required; 1 one did not.
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-polaris-caddy:prod}"
PY_IMAGE=python:3.12-alpine
NET="polaris-metrics-drill-$$"
WORK="$(mktemp -d)"
cleanup() { docker rm -f "${NET}-up" "${NET}-edge" "${NET}-fwd" > /dev/null 2>&1 || true
            docker network rm "${NET}" > /dev/null 2>&1 || true; }
trap cleanup EXIT

# The rule, exactly as shipped: from the matcher to its respond line.
sed -n '/@metrics_from_outside {/,/respond @metrics_from_outside 404/p' "${ROOT}/polaris_web/Caddyfile" > "${WORK}/rule"
grep -q 'respond @metrics_from_outside 404' "${WORK}/rule" || { echo "FAIL: no metrics rule in the shipped Caddyfile" >&2; exit 1; }
{ printf '{\n    admin off\n    auto_https off\n}\n:8080 {\n'; cat "${WORK}/rule"; printf '    reverse_proxy %s-up:8000\n}\n' "${NET}"; } > "${WORK}/Caddyfile"

cat > "${WORK}/up.py" <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'polaris_duress_events_total 0\n'
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(('0.0.0.0', 8000), H).serve_forever()
EOF
# A TCP forwarder: the edge sees the forwarder's address, not the client's (SNAT).
cat > "${WORK}/fwd.py" <<'EOF'
import asyncio, sys
async def pipe(r, w):
    try:
        while data := await r.read(65536):
            w.write(data); await w.drain()
    finally:
        w.close()
async def handle(r, w):
    ur, uw = await asyncio.open_connection(sys.argv[1], 8080)
    await asyncio.gather(pipe(r, uw), pipe(ur, w))
async def main():
    async with await asyncio.start_server(handle, '0.0.0.0', 9000) as s:
        await s.serve_forever()
asyncio.run(main())
EOF

docker network create "${NET}" > /dev/null
docker run -d --name "${NET}-up" --network "${NET}" -v "${WORK}/up.py:/u.py:ro" "${PY_IMAGE}" python /u.py > /dev/null
docker run -d --name "${NET}-fwd" --network "${NET}" -v "${WORK}/fwd.py:/f.py:ro" "${PY_IMAGE}" python /f.py "${NET}-edge" > /dev/null

edge() {  # edge <POLARIS_METRICS_ALLOW or empty>
    docker rm -f "${NET}-edge" > /dev/null 2>&1 || true
    local env=()
    [[ -n "$1" ]] && env=(-e "POLARIS_METRICS_ALLOW=$1")
    docker run -d --name "${NET}-edge" --network "${NET}" ${env[@]+"${env[@]}"} \
        -v "${WORK}/Caddyfile:/etc/caddy/Caddyfile:ro" "${IMAGE}" > /dev/null
}
probe() {  # probe <expected code> <in-network|via SNAT> <path>
    local host port code
    if [[ "$2" == "via SNAT" ]]; then host="${NET}-fwd"; port=9000; else host="${NET}-edge"; port=8080; fi
    for _ in $(seq 1 20); do
        code=$(docker run --rm --network "${NET}" "${PY_IMAGE}" python -c "
import urllib.request, urllib.error
try:
    print(urllib.request.urlopen('http://${host}:${port}$3', timeout=3).status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print(0)" 2> /dev/null)
        [[ "${code}" != 0 && "${code}" != 502 ]] && break
        sleep 1
    done
    if [[ "${code}" == "$1" ]]; then
        echo "  ok: $2 $3 -> ${code}"
    else
        echo "FAIL: $2 $3 answered ${code}, expected $1" >&2
        docker logs "${NET}-edge" 2>&1 | tail -10 >&2
        exit 1
    fi
}

echo "== POLARIS_METRICS_ALLOW unset: no one reads the metrics"
edge ""
for where in "in-network" "via SNAT"; do
    probe 404 "${where}" /metrics
    probe 404 "${where}" /api/metrics
    probe 200 "${where}" /
done

SUBNET=$(docker network inspect "${NET}" --format '{{(index .IPAM.Config 0).Subnet}}')
echo "== POLARIS_METRICS_ALLOW=${SUBNET} (the monitoring network named): it reads them"
edge "${SUBNET}"
probe 200 "in-network" /metrics
probe 200 "in-network" /api/metrics

echo "== POLARIS_METRICS_ALLOW=203.0.113.0/24 (somewhere else named): no one here reads them"
edge "203.0.113.0/24"
for where in "in-network" "via SNAT"; do
    probe 404 "${where}" /metrics
    probe 200 "${where}" /
done
echo "the metrics surfaces are refused unless the monitoring network is named, through an SNAT hop too"
