#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# polaris-issuance-tunnel.sh -- make a LOCAL, notional-data OpenID4VCI issuer reachable by a wallet
# ANYWHERE, in one command, so the wallet can GET a credential copy (lab/strategy/012-issuance-tunnel.md).
# It is the issuer half of the round-trip; scripts/polaris-dev-tunnel.sh is the verifier half. It uses
# YOUR OWN tunnel (cloudflared by default); no credential traffic passes through a Polaris service.
#
#   scripts/polaris-issuance-tunnel.sh --agency 7 [--port 2223] [--keys-dir DIR] [--days 90]
#
# What it does, in order:
#   1. refuses to run in production, and refuses if cloudflared is absent (with how to get it);
#   2. starts a cloudflared quick tunnel (no account) and reads back the public https URL;
#   3. mints a TEST wallet-copy certificate whose SAN URI is the tunnel's issuer identifier
#      (scripts/polaris-credential-copy-test-pki.py), so the metadata and every offer name the tunnel;
#   4. serves the application bound to 127.0.0.1 behind the issuance-only filter
#      (scripts/polaris-issuance-tunnel-serve.py), so ONLY the wallet's OID4VCI paths cross the tunnel;
#   5. prints the issuer URL, the test anchor, and how to mint an offer (an operator step, OFF the
#      tunnel), and cleans up both processes on exit.
#
# The operator mints the offer on the loopback, not over the tunnel, because minting it needs an
# operator sign-in and the filter keeps sign-in and the offer route off the tunnel on purpose. The
# offer-minting application must share this run's database, POLARIS_SECRET_KEY and the keys dir below.
set -euo pipefail

AGENCY=""
PORT=2223
KEYS_DIR=""
DAYS=90
PY="${POLARIS_PYTHON:-python3}"
HERE="$(cd "$(dirname "$0")" && pwd)"

while [ $# -gt 0 ]; do
    case "$1" in
        --agency) AGENCY="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --keys-dir) KEYS_DIR="$2"; shift 2 ;;
        --days) DAYS="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "polaris-issuance-tunnel: unknown argument $1" >&2; exit 2 ;;
    esac
done

if [ -z "$AGENCY" ]; then
    echo "polaris-issuance-tunnel: pass --agency N, the id of a notional agency in your stack whose" >&2
    echo "wallet copies you want to issue over the tunnel (the id in /api/v1/oid4vci/N)." >&2
    exit 2
fi
if [ "$(printf '%s' "${POLARIS_ENV:-}" | tr '[:upper:]' '[:lower:]')" = "production" ]; then
    echo "polaris-issuance-tunnel: refusing to run under POLARIS_ENV=production. This is a dev and" >&2
    echo "evaluation tool; a production issuer sits behind your own ingress and PKI, not a quick tunnel." >&2
    exit 2
fi
if ! command -v cloudflared >/dev/null 2>&1; then
    echo "polaris-issuance-tunnel: cloudflared is not installed. It is the tunnel YOU run; Polaris" >&2
    echo "operates no relay. Install it (https://github.com/cloudflare/cloudflared) or adapt this" >&2
    echo "script to ngrok/tailscale. Then re-run." >&2
    exit 2
fi
if [ -z "$KEYS_DIR" ]; then
    KEYS_DIR="$(mktemp -d -t polaris-vci-keys.XXXXXX)"
fi

CF_LOG="$(mktemp -t polaris-cf.XXXXXX)"
CF_PID=""
SERVE_PID=""
cleanup() {
    [ -n "$SERVE_PID" ] && kill "$SERVE_PID" 2>/dev/null || true
    [ -n "$CF_PID" ] && kill "$CF_PID" 2>/dev/null || true
    rm -f "$CF_LOG"
}
trap cleanup EXIT INT TERM

echo ">> starting a cloudflared quick tunnel to http://localhost:$PORT ..."
cloudflared tunnel --url "http://localhost:$PORT" >"$CF_LOG" 2>&1 &
CF_PID=$!

URL=""
for _ in $(seq 1 40); do
    URL="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$CF_LOG" | sed -n 1p || true)"
    [ -n "$URL" ] && break
    sleep 0.5
done
if [ -z "$URL" ]; then
    echo "polaris-issuance-tunnel: the tunnel did not come up; last log lines:" >&2
    tail -5 "$CF_LOG" >&2
    exit 1
fi

ISSUER="$URL/api/v1/oid4vci/$AGENCY"
echo ">> minting a TEST wallet-copy certificate for $ISSUER"
"$PY" "$HERE/polaris-credential-copy-test-pki.py" --agency "$AGENCY" \
    --issuer-url "$ISSUER" --out "$KEYS_DIR" --days "$DAYS" >/dev/null

echo ">> serving the issuer (OID4VCI-only, bound to 127.0.0.1:$PORT, advertised as $URL)"
echo "   issuer identifier:   $ISSUER"
echo "   issuer metadata:     GET  $ISSUER/.well-known/openid-credential-issuer"
echo "   register this test anchor with the wallet: $KEYS_DIR/$AGENCY.anchor.pem"
echo ""
echo "   Mint an offer (an operator step, OFF the tunnel): run your Polaris on a loopback port with"
echo "   the SAME database, POLARIS_SECRET_KEY, and POLARIS_CREDENTIAL_COPY_KEYS_DIR=$KEYS_DIR, sign"
echo "   in as an operator, and POST /tokens/<token_id>/wallet-offer. Hand the returned"
echo "   openid-credential-offer to the wallet; it redeems the code and fetches the copy over the tunnel."
echo "   (Ctrl-C stops the issuer and the tunnel.)"

POLARIS_CREDENTIAL_COPY_KEYS_DIR="$KEYS_DIR" POLARIS_ISSUANCE_TUNNEL_PORT="$PORT" \
    "$PY" "$HERE/polaris-issuance-tunnel-serve.py" &
SERVE_PID=$!
wait "$SERVE_PID"
