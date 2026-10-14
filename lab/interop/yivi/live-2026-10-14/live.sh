#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# The live Yivi scan: a quick tunnel, the unchanged verifier (strict: both Yivi anchors), the QR.
# As it ran on 2026-10-14, with its paths made parameters and nothing else changed:
#   live.sh <polaris-oid4vp package dir> <capture dir> <work dir>
# The work dir takes what the script kept beside itself (cf.log, cf.pid, serve.log, serve.pid,
# link.txt, qr.png, qr.html); live.py stays beside this script, and the two anchors are read
# from lab/interop/yivi/. YIVI_PKI and POLARIS_PY default to the paths it had.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ANCHORS="$(cd "$HERE/.." && pwd)"
PKG="$1"; CAP="$2"; W="$3"
mkdir -p "$W"
PKI="${YIVI_PKI:-$HOME/Desktop/polaris-private/captures/yivi/pki}"
PY="${POLARIS_PY:-$HOME/.local/share/polaris-venv312/bin/python}"
PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
[ -n "$PORT" ] || { echo "no port"; exit 1; }
mkdir -p "$CAP"; chmod 700 "$CAP"
CFHOME="$(mktemp -d)"
HOME="$CFHOME" cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" >"$W/cf.log" 2>&1 &
echo $! > "$W/cf.pid"
URL=""
for _ in $(seq 1 60); do
    URL="$({ grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$W/cf.log" || true; } | sed -n 1p)"
    [ -n "$URL" ] && break
    sleep 1
done
[ -n "$URL" ] || { echo "FAIL tunnel did not come up"; tail -5 "$W/cf.log"; exit 1; }
echo "tunnel $URL"
# Wait for the tunnel's DNS before the request exists (the 300 s window starts at --once).
for _ in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$URL/" || true)"
    case "$code" in 502|503|530|000) sleep 2 ;; *) break ;; esac
done
"$PY" -I -u "$HERE/live.py" "$PKG" "$CAP" serve --pki "$PKI" --bind 127.0.0.1 --port "$PORT" \
    --public-base-url "$URL" --no-local-tls \
    --issuer-trust-anchor "$ANCHORS/yivi-attestation-providers-ca.pem" \
    --issuer-trust-anchor "$ANCHORS/yivi-requestors-root-ca.pem" \
    --vct pbdf.sidn-pbdf.email --claim domain --once >"$W/serve.log" 2>&1 &
echo $! > "$W/serve.pid"
Q=""
for _ in $(seq 1 30); do
    Q="$({ grep -E '^  openid4vp://\?' "$W/serve.log" || true; } | sed -n 1p | sed 's/^  openid4vp:\/\/?//')"
    [ -n "$Q" ] && break
    sleep 1
done
[ -n "$Q" ] || { echo "FAIL no launch link"; tail -20 "$W/serve.log"; exit 1; }
for _ in $(seq 1 30); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$URL/done" || true)" = 200 ] && break
    sleep 2
done
echo "done-page $(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$URL/done" || true)"
LINK="https://open.yivi.app/-/openid4vp?$Q"
printf '%s\n' "$LINK" > "$W/link.txt"
qrencode -s 12 -m 4 -o "$W/qr.png" "$LINK"
cat > "$W/qr.html" <<HTML
<html><body style="margin:0;background:#fff;display:flex;align-items:center;justify-content:center;height:100vh">
<img src="qr.png" style="height:92vh;image-rendering:pixelated"></body></html>
HTML
open "$W/qr.png"
date -u +"QR shown %Y-%m-%dT%H:%M:%SZ"
echo "qr up"
