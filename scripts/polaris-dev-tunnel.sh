#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# polaris-dev-tunnel.sh -- make a LOCAL, notional-data OpenID4VP verifier reachable by a wallet
# ANYWHERE, in one command, for a demo or an evaluation. It uses YOUR OWN tunnel (cloudflared by
# default); no credential or presentation traffic ever passes through a Polaris-operated service.
# Dev and evaluation only: it refuses to run under POLARIS_ENV=production.
#
#   scripts/polaris-dev-tunnel.sh [--port 9443] [--pki ./pki-tunnel] \
#       [--issuer-jwks issuers.json] [--issuer-trust-anchor ca.pem]
#
# What it does, in order:
#   1. refuses to run in production, and refuses if cloudflared is absent (with how to get it);
#   2. starts a cloudflared quick tunnel (no account) and reads back the public https URL;
#   3. mints a test certificate whose name is the tunnel host (polaris-oid4vp keygen --host);
#   4. serves the verifier bound to localhost, advertising the tunnel URL as its public base
#      (polaris-oid4vp serve --public-base-url), so the request_uri a wallet fetches is reachable;
#   5. prints the URL and the anchor to register, and cleans up both processes on exit.
#
# The verifier holds no credential data: it checks presentations a wallet sends. The issuer/app
# issuance path is a separate, data-bearing surface and is NOT tunnelled by this script.
set -euo pipefail

PORT=9443
PKI="./pki-tunnel"
EXTRA=()
while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        --pki) PKI="$2"; shift 2 ;;
        --issuer-jwks) EXTRA+=(--issuer-jwks "$2"); shift 2 ;;
        --issuer-trust-anchor) EXTRA+=(--issuer-trust-anchor "$2"); shift 2 ;;
        -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
        *) echo "polaris-dev-tunnel: unknown argument $1" >&2; exit 2 ;;
    esac
done

if [ "$(printf '%s' "${POLARIS_ENV:-}" | tr '[:upper:]' '[:lower:]')" = "production" ]; then
    echo "polaris-dev-tunnel: refusing to run under POLARIS_ENV=production. This is a dev and" >&2
    echo "evaluation tool; a production verifier sits behind your own ingress, not a quick tunnel." >&2
    exit 2
fi
if ! command -v cloudflared >/dev/null 2>&1; then
    echo "polaris-dev-tunnel: cloudflared is not installed. It is the tunnel YOU run; Polaris" >&2
    echo "operates no relay. Install it (https://github.com/cloudflare/cloudflared) or adapt this" >&2
    echo "script to ngrok/tailscale. Then re-run." >&2
    exit 2
fi
if ! command -v polaris-oid4vp >/dev/null 2>&1; then
    echo "polaris-dev-tunnel: polaris-oid4vp is not on PATH (pip install --pre polaris-oid4vp)." >&2
    exit 2
fi

CF_LOG="$(mktemp -t polaris-cf.XXXXXX)"
CF_PID=""
cleanup() { [ -n "$CF_PID" ] && kill "$CF_PID" 2>/dev/null || true; rm -f "$CF_LOG"; }
trap cleanup EXIT INT TERM

echo ">> starting a cloudflared quick tunnel to https://localhost:$PORT ..."
# The verifier serves plain HTTP on the loopback (--no-local-tls); cloudflare terminates the
# PUBLIC HTTPS that the HAIP profile requires of the request_uri. No credential traffic passes
# through a Polaris-operated service: the tunnel is cloudflare's and yours.
cloudflared tunnel --url "http://localhost:$PORT" >"$CF_LOG" 2>&1 &
CF_PID=$!

URL=""
for _ in $(seq 1 40); do
    URL="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$CF_LOG" | sed -n 1p || true)"
    [ -n "$URL" ] && break
    sleep 1
done
if [ -z "$URL" ]; then
    echo "polaris-dev-tunnel: the tunnel did not come up in 40s. cloudflared said:" >&2
    tail -8 "$CF_LOG" >&2
    exit 1
fi
HOST="${URL#https://}"
echo ">> public URL: $URL"

echo ">> minting a test certificate for $HOST"
polaris-oid4vp keygen --out "$PKI" --host "$HOST" >/dev/null

echo ">> serving the verifier (bound to 127.0.0.1:$PORT, advertised as $URL)"
echo "   point a wallet at:  $URL"
echo "   request object:     GET  $URL/request.jwt"
echo "   response endpoint:  POST $URL/response"
echo "   register this anchor with the wallet under test: $PKI/anchor.pem"
echo "   (Ctrl-C stops the verifier and the tunnel.)"
exec polaris-oid4vp serve --pki "$PKI" --bind 127.0.0.1 --port "$PORT" \
    --public-base-url "$URL" --no-local-tls ${EXTRA[@]+"${EXTRA[@]}"}
