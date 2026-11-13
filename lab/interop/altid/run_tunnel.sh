#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# run_tunnel.sh -- the lab AVP verifier (serve.py) behind the integrator's own cloudflared quick tunnel, for a test
# flow with a phone. Modelled on scripts/polaris-dev-tunnel.sh: its production refusal, its cloudflared check, and
# its quick tunnel with no account, whose https URL it reads back. Lab only: it refuses POLARIS_ENV=production.
#
#   lab/interop/altid/run_tunnel.sh [--port 8765]
#
#   AVP_PYTHON  the interpreter for serve.py, with cbor2 and cryptography (default python3)
#   AVP_QR_LIB  a directory holding segno, passed to serve.py --qr-lib (optional; without it the links show as text)
#   AVP_RUNS    where the captures go (default runs/ beside this script)
#
# cloudflared's log goes to a temporary file outside runs/ and is read only for the URL. On Ctrl-C and on a TERM, both
# processes are stopped by their recorded PIDs, so no listener is left, and the log is deleted.
# serve.py runs under `wait`, not exec, so the exit trap stays this shell's. The last line is "done".
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT=8765
while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        -h|--help) sed -n '5,18p' "$0"; exit 0 ;;
        *) echo "run_tunnel: unknown argument $1" >&2; exit 2 ;;
    esac
done
if [ "$(printf '%s' "${POLARIS_ENV:-}" | tr '[:upper:]' '[:lower:]')" = "production" ]; then
    echo "run_tunnel: refusing to run under POLARIS_ENV=production; this is a lab tool." >&2
    exit 2
fi
if ! command -v cloudflared >/dev/null 2>&1; then
    echo "run_tunnel: cloudflared is not on PATH. It is the tunnel you run; install it yourself, then re-run." >&2
    exit 2
fi
PY="${AVP_PYTHON:-python3}"
RUNS="${AVP_RUNS:-$HERE/runs}"

CF_LOG="$(mktemp "${TMPDIR:-/tmp}/avp-cf.XXXXXX")"  # an explicit template: BSD mktemp -t ignores TMPDIR
CF_PID=""
SV_PID=""
cleanup() {
    trap - EXIT INT TERM
    if [ -n "$SV_PID" ]; then kill "$SV_PID" 2>/dev/null || true; wait "$SV_PID" 2>/dev/null || true; fi
    if [ -n "$CF_PID" ]; then kill "$CF_PID" 2>/dev/null || true; wait "$CF_PID" 2>/dev/null || true; fi
    rm -f "$CF_LOG"
    echo "done"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo ">> starting a cloudflared quick tunnel to http://127.0.0.1:$PORT"
cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" >"$CF_LOG" 2>&1 &
CF_PID=$!
URL=""
for _ in $(seq 1 40); do
    URL="$({ grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$CF_LOG" || true; } | sed -n 1p)"
    [ -n "$URL" ] && break
    kill -0 "$CF_PID" 2>/dev/null || break
    sleep 1
done
if [ -z "$URL" ]; then
    echo "run_tunnel: the tunnel gave no URL in 40 s" >&2
    exit 1
fi
echo ">> public URL: $URL"

QR=()
if [ -n "${AVP_QR_LIB:-}" ]; then QR=(--qr-lib "$AVP_QR_LIB"); fi
"$PY" -I "$HERE/serve.py" --public-url "$URL" --trust "$HERE/trust/dktb-test.pem" --pins "$HERE/trust/PINS" \
    --port "$PORT" --runs "$RUNS" ${QR[@]+"${QR[@]}"} &
SV_PID=$!
echo ">> cross-device: open $URL/ on a computer and scan a QR with the phone"
echo ">> same device:  open $URL/?flow=link on the phone"
echo ">> Ctrl-C stops the verifier and the tunnel."
wait "$SV_PID"
