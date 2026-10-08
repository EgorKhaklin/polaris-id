#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-client-ip-drill.sh: does the app see the client's own address behind a load balancer,
# and only when that balancer is named? (lab record 017, gate row OP-26)
#
# The rate limiter, AuthAuditLog and the access policies key on the address the edge passes
# upstream. This runs the shipped edge configuration (polaris_web/Caddyfile.citest, production
# but for TLS; check_client_ip_behind_proxies holds its client-address lines to production's)
# with a stub upstream that echoes the X-Forwarded-For and X-Real-IP it receives, behind an L7
# load balancer that appends to X-Forwarded-For as nginx and the cloud balancers do:
#
#   1. POLARIS_TRUSTED_PROXIES unset, client -> balancer -> edge  : the balancer's address
#   2. the balancer named, client -> balancer -> edge             : the client's address
#   3. the balancer named, the client sends X-Forwarded-For: <forged> through it
#                                                                 : the client's address, not the forgery
#   4. the balancer named, the client sends the forgery to the edge directly
#                                                                 : the client's address
#
# Usage: polaris-client-ip-drill.sh [caddy image] (default polaris-caddy:prod)
# Exit: 0 every case passed the address it should; 1 otherwise.
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-polaris-caddy:prod}"
PY_IMAGE=python:3.12-alpine
NET="polaris-client-ip-drill-$$"
WORK="$(mktemp -d)"
FORGED=203.0.113.66
cleanup() { docker rm -f "${NET}-up" "${NET}-edge" "${NET}-lb" "${NET}-client" > /dev/null 2>&1 || true
            docker network rm "${NET}" > /dev/null 2>&1 || true; }
trap cleanup EXIT

cat > "${WORK}/up.py" <<'EOF'
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"xff": self.headers.get("X-Forwarded-For"),
                           "real_ip": self.headers.get("X-Real-IP")}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(("0.0.0.0", 8000), H).serve_forever()
EOF
# The load balancer appends to X-Forwarded-For whatever it received (it trusts every peer),
# which is what lets a client try to forge the first entry.
cat > "${WORK}/lb.Caddyfile" <<EOF
{
    admin off
    auto_https off
    servers {
        trusted_proxies static 0.0.0.0/0
    }
}
:9000 {
    reverse_proxy https://${NET}-edge:8443 {
        header_up Host localhost
        transport http {
            tls_insecure_skip_verify
            tls_server_name localhost
        }
    }
}
EOF
# The client: asks through the balancer or the edge, optionally sending a forged header.
cat > "${WORK}/ask.py" <<'EOF'
import http.client, json, socket, ssl, sys, urllib.parse
url, forged = urllib.parse.urlsplit(sys.argv[1]), (sys.argv[2] if len(sys.argv) > 2 else "")
headers = {"Host": "localhost", **({"X-Forwarded-For": forged} if forged else {})}
if url.scheme == "https":
    # The edge serves localhost: connect to its address, name localhost in the handshake.
    class Conn(http.client.HTTPSConnection):
        def connect(self):
            sock = socket.create_connection((self.host, self.port), self.timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname="localhost")
    conn = Conn(url.hostname, url.port, timeout=5, context=ssl._create_unverified_context())
else:
    conn = http.client.HTTPConnection(url.hostname, url.port, timeout=5)
conn.request("GET", "/", headers=headers)
print(json.loads(conn.getresponse().read())["xff"] or "")
EOF

docker network create "${NET}" > /dev/null
ip_of() { docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
docker run -d --name "${NET}-up" --network "${NET}" -v "${WORK}/up.py:/u.py:ro" "${PY_IMAGE}" python /u.py > /dev/null
docker run -d --name "${NET}-client" --network "${NET}" -v "${WORK}/ask.py:/ask.py:ro" "${PY_IMAGE}" sleep 600 > /dev/null
docker run -d --name "${NET}-lb" --network "${NET}" -v "${WORK}/lb.Caddyfile:/etc/caddy/Caddyfile:ro" "${IMAGE}" > /dev/null
CLIENT=$(ip_of "${NET}-client")
LB=$(ip_of "${NET}-lb")

edge() {  # edge <POLARIS_TRUSTED_PROXIES or empty>
    docker rm -f "${NET}-edge" > /dev/null 2>&1 || true
    local env=(-e "POLARIS_UPSTREAMS=${NET}-up:8000")
    [[ -n "$1" ]] && env+=(-e "POLARIS_TRUSTED_PROXIES=$1")
    docker run -d --name "${NET}-edge" --network "${NET}" "${env[@]}" \
        -v "${ROOT}/polaris_web/Caddyfile.citest:/etc/caddy/Caddyfile:ro" "${IMAGE}" > /dev/null
}
ask() {  # ask <via lb|direct> [forged]; prints the X-Forwarded-For the upstream received
    local url
    if [[ "$1" == "via lb" ]]; then url="http://${NET}-lb:9000/"; else url="https://${NET}-edge:8443/"; fi
    for _ in $(seq 1 20); do
        if out=$(docker exec "${NET}-client" python /ask.py "${url}" "${2:-}" 2> /dev/null); then
            printf '%s' "${out}"; return
        fi
        sleep 1
    done
    printf 'no answer'
}
expect() {  # expect <what> <want> <got>
    if [[ "$3" == "$2" ]]; then echo "  ok: $1 -> $3"; else echo "FAIL: $1: the app was told '$3', expected '$2'" >&2; exit 1; fi
}

echo "client ${CLIENT}, load balancer ${LB}"
echo "== 1. POLARIS_TRUSTED_PROXIES unset"
edge ""
expect "via the balancer, not trusted" "${LB}" "$(ask "via lb")"
echo "== 2-4. the balancer named (${LB}/32)"
edge "${LB}/32"
expect "via the balancer" "${CLIENT}" "$(ask "via lb")"
expect "via the balancer, forging ${FORGED}" "${CLIENT}" "$(ask "via lb" "${FORGED}")"
expect "straight to the edge, forging ${FORGED}" "${CLIENT}" "$(ask direct "${FORGED}")"
echo "the app is told the client's own address behind a named balancer, and no forgery gets through"
