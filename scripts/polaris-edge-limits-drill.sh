#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-edge-limits-drill.sh: can a slow or oversized client tie up the app through the edge?
# (lab record 017, phase 5)
#
# The app runs synchronous gunicorn workers, four to an instance: a worker reading a request
# body serves no one else until the body ends. This runs the shipped edge configuration
# (polaris_web/Caddyfile.citest, production but for TLS) in front of a stub upstream that, like
# one such worker, serves one request at a time, and asks:
#
#   1. a client trickles a 40-byte body at a byte a second; a GET sent three seconds later
#      must be answered within 3 s (the slow body must not reach, or hold, the upstream);
#   2. that slow body is ended by the edge, not by the client finishing it;
#   3. a 2 MiB body (the app accepts 1 MiB) is refused 413 by the edge, and the upstream never
#      sees it;
#   4. a client that trickles its request headers is disconnected within 15 s.
#
# Usage: polaris-edge-limits-drill.sh [caddy image] (default polaris-caddy:prod)
# Exit: 0 every case held; 1 otherwise, saying which.
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-polaris-caddy:prod}"
PY_IMAGE=python:3.12-alpine
NET="polaris-edge-limits-drill-$$"
WORK="$(mktemp -d)"
cleanup() { docker rm -f "${NET}-up" "${NET}-edge" "${NET}-client" > /dev/null 2>&1 || true
            docker network rm "${NET}" > /dev/null 2>&1 || true; }
trap cleanup EXIT

# One request at a time, like a synchronous worker: it reads the whole body before answering,
# and logs each request it finished.
cat > "${WORK}/up.py" <<'EOF'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def _answer(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        print("served %s %s (%d bytes)" % (self.command, self.path, n), file=sys.stderr, flush=True)
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers()
        self.wfile.write(b"ok")
    do_GET = do_POST = _answer
    def log_message(self, *a): pass
HTTPServer(("0.0.0.0", 8000), H).serve_forever()
EOF
cat > "${WORK}/probe.py" <<'EOF'
import http.client, json, socket, ssl, sys, threading, time
HOST, PORT, MODE = sys.argv[1], 8443, sys.argv[2]
CTX = ssl._create_unverified_context()

def tls():
    s = socket.create_connection((HOST, PORT), timeout=60)
    return CTX.wrap_socket(s, server_hostname="localhost")

def ended(s, limit):
    """Seconds until the server answers or closes, up to limit; None if it never does."""
    t0 = time.time()
    s.settimeout(limit)
    try:
        s.recv(64)
    except socket.timeout:
        return None
    except OSError:
        pass
    return round(time.time() - t0, 1)

def get(timeout):
    class Conn(http.client.HTTPSConnection):
        def connect(self):
            self.sock = CTX.wrap_socket(socket.create_connection((self.host, self.port), self.timeout),
                                        server_hostname="localhost")
    t0 = time.time()
    try:
        c = Conn(HOST, PORT, timeout=timeout)
        c.request("GET", "/after-the-slow-body", headers={"Host": "localhost"})
        status = c.getresponse().status
    except Exception as e:
        status = type(e).__name__
    return status, round(time.time() - t0, 1)

if MODE == "ready":
    print(get(3)[0])
elif MODE == "slow-body":
    out = {}
    def slow():
        s = tls()
        t0 = time.time()
        s.sendall(b"POST /slow HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\n"
                  b"Content-Length: 40\r\n\r\n")
        sent = 0
        try:
            while sent < 40:
                s.sendall(b"x"); sent += 1
                time.sleep(1)
        except OSError:
            pass
        out["body_bytes_sent"] = sent
        out["body_ended_after"] = round(time.time() - t0, 1)
        out["body_finished_by_client"] = sent == 40
    t = threading.Thread(target=slow); t.start()
    time.sleep(3)
    out["get_status"], out["get_seconds"] = get(20)
    t.join(90)
    print(json.dumps(out))
elif MODE == "oversize":
    s = tls()
    body = b"x" * (2 * 1024 * 1024)
    s.sendall(b"POST /big HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\n"
              b"Content-Length: %d\r\n\r\n" % len(body))
    try:
        s.sendall(body)
    except OSError:
        pass
    s.settimeout(20)
    try:
        line = s.recv(64).split(b"\r\n")[0].decode()
    except OSError:
        line = "closed"
    print(json.dumps({"status_line": line}))
elif MODE == "slow-header":
    s = tls()
    s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
    t0 = time.time()
    closed = None
    for _ in range(40):
        try:
            s.sendall(b"a")
        except OSError:
            closed = round(time.time() - t0, 1); break
        s.settimeout(1)
        try:
            if s.recv(64) == b"":
                closed = round(time.time() - t0, 1); break
            closed = round(time.time() - t0, 1); break   # an answer (408 or 400) ends it too
        except socket.timeout:
            continue
        except OSError:
            closed = round(time.time() - t0, 1); break
    print(json.dumps({"header_cut_after": closed}))
EOF

docker network create "${NET}" > /dev/null
docker run -d --name "${NET}-up" --network "${NET}" -v "${WORK}/up.py:/u.py:ro" "${PY_IMAGE}" python -u /u.py > /dev/null
docker run -d --name "${NET}-client" --network "${NET}" -v "${WORK}/probe.py:/p.py:ro" "${PY_IMAGE}" sleep 900 > /dev/null
docker run -d --name "${NET}-edge" --network "${NET}" -e "POLARIS_UPSTREAMS=${NET}-up:8000" \
    -v "${ROOT}/polaris_web/Caddyfile.citest:/etc/caddy/Caddyfile:ro" "${IMAGE}" > /dev/null
for _ in $(seq 1 30); do
    [[ "$(docker exec "${NET}-client" python /p.py "${NET}-edge" ready 2> /dev/null)" == 200 ]] && break
    sleep 1
done

probe() { docker exec "${NET}-client" python /p.py "${NET}-edge" "$1"; }
field() { python3 -c 'import json,sys; v = json.loads(sys.argv[1]).get(sys.argv[2]); print("" if v is None else v)' "$1" "$2"; }
FAILED=0
ok() { echo "  ok: $*"; }
bad() { echo "FAIL: $*" >&2; FAILED=1; }

echo "== 1-2. a body trickled at a byte a second, and a GET three seconds later"
out=$(probe slow-body); echo "     ${out}"
secs=$(field "${out}" get_seconds); status=$(field "${out}" get_status)
if [[ "${status}" == 200 ]] && python3 -c "import sys; sys.exit(0 if float('${secs}') <= 3 else 1)"; then
    ok "the GET was answered in ${secs} s while the slow body trickled"
else
    bad "the GET was answered ${status} after ${secs} s: the slow body held the upstream"
fi
if [[ "$(field "${out}" body_finished_by_client)" == False ]]; then
    ok "the edge ended the slow body after $(field "${out}" body_ended_after) s"
else
    bad "the client finished its 40-byte body at a byte a second; the edge never ended it"
fi
if docker logs "${NET}-up" 2>&1 | grep -q "served POST /slow"; then
    bad "the upstream served the slow body"
fi

echo "== 3. a 2 MiB body"
out=$(probe oversize); echo "     ${out}"
if [[ "$(field "${out}" status_line)" == "HTTP/1.1 413"* ]]; then ok "refused 413 at the edge"; else bad "not refused 413: $(field "${out}" status_line)"; fi
if docker logs "${NET}-up" 2>&1 | grep -q "served POST /big"; then bad "the upstream served the oversized body"; else ok "the upstream never saw it"; fi

echo "== 4. request headers trickled at a byte a second"
out=$(probe slow-header); echo "     ${out}"
cut=$(field "${out}" header_cut_after)
if [[ -n "${cut}" ]] && python3 -c "import sys; sys.exit(0 if float('${cut}') <= 15 else 1)"; then
    ok "the edge ended the connection after ${cut} s"
else
    bad "the edge held a connection trickling its headers for 40 s"
fi

[[ ${FAILED} -eq 0 ]] || exit 1
echo "a slow or oversized client is ended at the edge, and the upstream serves everyone else"
