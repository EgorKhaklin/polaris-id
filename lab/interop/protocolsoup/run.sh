#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ProtocolSoup's wallet harness, which the OpenID Foundation lists as a certified OpenID4VP 1.0 +
# HAIP 1.0 wallet, presents an SD-JWT VC to the PUBLISHED polaris-oid4vp, then six controls.
#
# The wallet is backend/cmd/walletharness from github.com/ParleSec/ProtocolSoup at a pinned commit
# (tag v4.0.0), built unmodified in a Go image pinned by digest, every module checked against
# ProtocolSoup's own go.sum, and run as three containers, each configured only by environment.
# It is driven through its headless JSON API by walk.py, which also plays the issuer: the harness
# makes the holder key, fetches the issuer's key from the credential's iss and checks the
# signature before it stores the credential, fetches the request object by POST, checks x509_hash
# against the verifier anchor it was given, matches the DCQL query, signs the key binding JWT and
# posts the encrypted direct_post.jwt response. The verifier trusts the issuer's CA
# (--issuer-trust-anchor). Docker and git are required.
#
#   lab/interop/protocolsoup/run.sh                                     # the newest polaris-oid4vp
#   POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/protocolsoup/run.sh
#
# Exits 0 only if the presentation is accepted AND every control is refused where it should be.
set -euo pipefail

PS_REPO="${PS_REPO:-https://github.com/ParleSec/ProtocolSoup.git}"
PS_COMMIT="${PS_COMMIT:-97d306cafa3a005dd01c1641b13c9b5abb6bcc19}"   # tag v4.0.0
GO_IMAGE="${GO_IMAGE:-golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2}"
PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
[ -e "$PKG" ] && PKG="$(cd "$PKG" && pwd)"   # a path to the tree, made absolute
PORT="${PORT:-9485}"
ISSUER_PORT=$((PORT + 1))
WALLET_PORTS=($((PORT + 2)) $((PORT + 3)) $((PORT + 4)))
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
NAME="polaris-protocolsoup-$$"
ADD_HOST=()
[ "$(uname)" = Linux ] && ADD_HOST=(--add-host host.docker.internal:host-gateway)
# A path to a tree or a wheel is made absolute before the cd into WORK; a requirement stays as is.
if [ -e "$PKG" ]; then PKG="$(cd "$(dirname "$PKG")" && pwd)/$(basename "$PKG")"; fi

command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || {
  echo "the wallet is built and run in a Go image: start Docker" >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo "git is needed to fetch ProtocolSoup" >&2; exit 2; }
for p in "$PORT" "$ISSUER_PORT" "${WALLET_PORTS[@]}"; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $p is in use; set PORT (the run uses PORT to PORT+4)" >&2
    exit 2
  fi
done

echo "work dir   $WORK"
echo "wallet     ProtocolSoup $PS_COMMIT, backend/cmd/walletharness"
echo "verifier   pip install --pre $PKG"
mkdir -p "$WORK" && cd "$WORK"
"$PY" -m venv venv
venv/bin/pip install -q --require-hashes -r "$HERE/../requirements.txt"
if [ -e "$PKG" ]; then
  venv/bin/python -c 'import sys; sys.exit(sys.version_info < (3, 10))' || {
    echo "building $PKG from the tree needs Python 3.10 or newer; set PYTHON to one" >&2; exit 2; }
  venv/bin/pip install -q --require-hashes -r "$HERE/../requirements-build.txt"
fi
venv/bin/pip wheel -q --pre --no-deps --no-build-isolation -w wheel "$PKG"
venv/bin/pip install -q --no-deps wheel/*.whl
echo "installed  polaris-oid4vp $(venv/bin/python -c 'import importlib.metadata as m; print(m.version("polaris-oid4vp"))')"

# ProtocolSoup at exactly PS_COMMIT, and only backend/ (a partial, sparse fetch of one commit).
rm -rf src && git init -q src
git -C src remote add origin "$PS_REPO"
git -C src fetch -q --depth 1 --filter=blob:none origin "$PS_COMMIT"
git -C src sparse-checkout set backend
git -C src checkout -q FETCH_HEAD
[ "$(git -C src rev-parse HEAD)" = "$PS_COMMIT" ] || { echo "fetched the wrong commit" >&2; exit 2; }

# The harness, for the container's own platform, on the Go version docker/Dockerfile.wallet-harness
# uses, without the browser UI (the headless API needs none; static/ keeps its placeholder).
# -mod=readonly: every module is checked against ProtocolSoup's go.sum and nothing in the tree is
# rewritten. The module and build caches are named volumes so a second run does not download again.
started=$(date +%s)
docker run --rm -v "$WORK/src/backend":/src:ro -v "$WORK":/out -w /src \
  -v polaris-go-mod:/go/pkg/mod -v polaris-go-build:/root/.cache/go-build \
  -e CGO_ENABLED=0 -e GOFLAGS=-mod=readonly -e GOTOOLCHAIN=local "$GO_IMAGE" \
  sh -c 'go version && go build -trimpath -o /out/wallet-harness ./cmd/walletharness' | sed 's/^/           /'
echo "built      wallet-harness in $(( $(date +%s) - started )) s"

venv/bin/polaris-oid4vp keygen --out pki --host host.docker.internal --port "$PORT" >/dev/null
venv/bin/polaris-oid4vp keygen --out other-pki --host host.docker.internal --port "$PORT" >/dev/null
# The issuer: a key certified by a CA made for the run, published as a JWKS at its iss, which is
# where the harness looks for it, over HTTPS with a listener certificate of its own.
venv/bin/python "$HERE/walk.py" keys issuer "https://host.docker.internal:$ISSUER_PORT"

ISSUER_PID=""
VERIFIER_PID=""
stop_verifier() {
  if [ -n "$VERIFIER_PID" ]; then
    kill "$VERIFIER_PID" 2>/dev/null || true
    wait "$VERIFIER_PID" 2>/dev/null || true
    VERIFIER_PID=""
  fi
}
cleanup() {
  stop_verifier
  [ -n "$ISSUER_PID" ] && { kill "$ISSUER_PID" 2>/dev/null || true; wait "$ISSUER_PID" 2>/dev/null || true; }
  for w in a d e; do
    docker logs "$NAME-$w" > "wallet-$w.container.log" 2>&1 || true
    docker rm -f "$NAME-$w" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

PYTHONUNBUFFERED=1 venv/bin/python "$HERE/walk.py" serve issuer "$ISSUER_PORT" > issuer.log 2>&1 &
ISSUER_PID=$!
for _ in $(seq 1 40); do grep -q 'serving' issuer.log 2>/dev/null && break; sleep 0.25; done
grep -q 'serving' issuer.log || { echo "the issuer did not start; see $WORK/issuer.log" >&2; exit 2; }

# One harness per trust configuration, each configured only by environment:
#   WALLET_TARGET_BASE_URL  the verifier's origin. The harness refuses .internal names and private
#                           addresses for any host but this one and the issuer's. It is not made
#                           the wallet's own verifier: that is a callback at <origin>/oid4vp/response,
#                           which Polaris does not use, so the harness treats it as an external
#                           verifier and the user's approval is asked for.
#   WALLET_ISSUER_BASE_URL  the issuer's origin, which the harness exempts the same way
#   WALLET_DID_METHOD=jwk   the holder key is readable from the wallet's DID, which walk.py binds
#                           the credential to
#   WALLET_VERIFIER_X509_TRUST_ANCHOR_PEM  the CA the wallet trusts for x509_hash request objects
#   SSL_CERT_FILE           the image's CA bundle, plus the verifier's and the issuer's listener
#                           certificates: the TLS registration a counterparty makes for a test
#                           verifier. Nothing turns a check off.
start_wallet() {  # $1 letter, $2 host port, $3 verifier anchor, $4 the verifier listener certificate
  docker run -d --name "$NAME-$1" ${ADD_HOST[@]+"${ADD_HOST[@]}"} -p "127.0.0.1:$2:8080" \
    -v "$WORK":/in:ro \
    -e WALLET_TARGET_BASE_URL="https://host.docker.internal:$PORT" \
    -e WALLET_ISSUER_BASE_URL="https://host.docker.internal:$ISSUER_PORT" \
    -e WALLET_DID_METHOD=jwk \
    -e WALLET_VERIFIER_X509_TRUST_ANCHOR_PEM="$(cat "$3")" \
    "$GO_IMAGE" sh -c 'cat /etc/ssl/certs/ca-certificates.crt "$0" /in/issuer/tls.pem > /tmp/roots.pem && SSL_CERT_FILE=/tmp/roots.pem exec /in/wallet-harness' \
    "/in/$4" >/dev/null
  for _ in $(seq 1 120); do curl -sf "http://127.0.0.1:$2/health" >/dev/null 2>&1 && return 0; sleep 0.25; done
  echo "wallet $1 did not start; see docker logs $NAME-$1" >&2
  exit 2
}
start_wallet a "${WALLET_PORTS[0]}" pki/anchor.pem pki/tls.pem
start_wallet d "${WALLET_PORTS[1]}" other-pki/anchor.pem pki/tls.pem
start_wallet e "${WALLET_PORTS[2]}" pki/anchor.pem other-pki/tls.pem
API_A="http://127.0.0.1:${WALLET_PORTS[0]}"
API_D="http://127.0.0.1:${WALLET_PORTS[1]}"
API_E="http://127.0.0.1:${WALLET_PORTS[2]}"
# Each wallet's session gets one credential, minted for the key the harness made for it.
venv/bin/python "$HERE/walk.py" enrol "$API_A" walk-a issuer | sed 's/^/  wallet a  /'
venv/bin/python "$HERE/walk.py" enrol "$API_D" walk-d issuer | sed 's/^/  wallet d  /'
venv/bin/python "$HERE/walk.py" enrol "$API_E" walk-e issuer | sed 's/^/  wallet e  /'

start_verifier() {  # $1 issuer trust anchor, $2 log
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host host.docker.internal \
    --bind 0.0.0.0 --port "$PORT" --issuer-trust-anchor "$1" --once > "$2" 2>&1 &
  VERIFIER_PID=$!
  for _ in $(seq 1 240); do grep -q 'state=' "$2" 2>/dev/null && return 0; sleep 0.25; done
  echo "verifier did not start; see $WORK/$2" >&2
  exit 2
}

launch_uri() {  # $1 log file, $2 optional client_id override
  venv/bin/python - "$1" "${2:-}" <<'EOF'
import re, sys, urllib.parse
log = open(sys.argv[1]).read()
cid = sys.argv[2] or re.search(r"x509_hash:[A-Za-z0-9_-]+", log).group(0)
ruri = re.findall(r"https://\S+request\.jwt\?state=[A-Za-z0-9_-]+", log)[-1]
print("openid4vp://authorize?" + urllib.parse.urlencode(
    {"client_id": cid, "request_uri": ruri, "request_uri_method": "post"}))
EOF
}

present() {  # $1 wallet API, $2 its session, $3 launch URI, $4 log
  venv/bin/python "$HERE/walk.py" present "$1" "$2" issuer "$3" > "$4" 2>&1 || true
  sleep 1  # the verifier logs its verdict after it answers
}

fail=0
expect() {  # $1 label, $2 file, $3 pattern that must appear
  if grep -qE "$3" "$2"; then echo "  ok    $1"; else echo "  FAIL  $1 (no /$3/ in $2)"; fail=1; fi
}

echo "== genuine presentation"
start_verifier issuer/issuer-ca.pem verifier.log
URI=$(launch_uri verifier.log)
present "$API_A" walk-a "$URI" wallet.log
expect "the harness dispatched" wallet.log '^DISPATCHED: the verifier answered 200'
expect "the verifier accepted it" verifier.log '<- 200 authentic'
{ grep -E '<- 200' verifier.log || true; } | sed 's/^/        /'
sed 's/^/        /' wallet.log

echo "== control (b): the same request again, after it was answered"
present "$API_A" walk-a "$URI" wallet-b.log
expect "refused at the request stage" wallet-b.log '^REQUEST REFUSED .*request_uri POST returned 404'
stop_verifier

echo "== control (c): a launch URI whose client_id is not the signed request's"
start_verifier issuer/other-issuer-ca.pem verifier-other.log
present "$API_A" walk-a "$(launch_uri verifier-other.log x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)" wallet-c.log
expect "the harness refused the request" wallet-c.log '^REQUEST REFUSED .*does not match URI client_id'

echo "== control (d): the wallet trusts an unrelated CA for the verifier"
present "$API_D" walk-d "$(launch_uri verifier-other.log)" wallet-d.log
expect "the harness refused the request" wallet-d.log '^REQUEST REFUSED .*request object verification failed: .*unknown authority'

echo "== control (e): the wallet trusts a different listener certificate"
present "$API_E" walk-e "$(launch_uri verifier-other.log)" wallet-e.log
expect "the connection was refused" wallet-e.log '^REQUEST REFUSED .*tls: failed to verify certificate'

echo "== control (a): the verifier trusts a different issuer CA"
present "$API_A" walk-a "$(launch_uri verifier-other.log)" wallet-a.log
expect "the harness was not accepted" wallet-a.log '^DISPATCH FAILED: the verifier answered 400'
expect "the verifier refused the issuer" verifier-other.log '<- 400 refused: issuer_key'
stop_verifier

echo "== control (f): a credential signed by a key its issuer does not publish"
venv/bin/python "$HERE/walk.py" enrol "$API_A" walk-f issuer issuer/stranger-key.pem > import-f.log 2>&1 || true
expect "the harness refused to store it" import-f.log '^IMPORT REFUSED .*issuer signature'

[ "$fail" -eq 0 ] && echo "RESULT: accepted, and all six controls refused" || echo "RESULT: FAILED"
exit "$fail"
