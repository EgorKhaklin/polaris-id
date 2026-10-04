#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# walt.id's Wallet API v2 presents an SD-JWT VC to the PUBLISHED polaris-oid4vp, then two controls.
#
# The README's sequence as one command. Everything runs from a scratch directory: a fresh venv with
# polaris-oid4vp from PyPI, the verifier's test PKI, and the wallet from its image, unmodified (only
# its configuration is touched, by setup.sh: the listener's certificate in its trust store and the
# request-object anchor in its client-id trust). walt.id generates the holder key itself; the
# credential is bound to the public half it reports.
#
#   lab/interop/waltid/run.sh                                          # wallet-api2 1.1.1, by digest
#   WALTID_IMAGE=waltid/wallet-api2:1.0.0 lab/interop/waltid/run.sh    # the first recorded run's
#   POLARIS_OID4VP=polaris-oid4vp==1.0.0rc7 lab/interop/waltid/run.sh  # a release, pinned
#
# Exits 0 only if the genuine presentation is accepted AND both controls are refused. A run that
# only printed the success line would say nothing: a verifier that accepts everything prints it too.
set -euo pipefail

IMAGE="${WALTID_IMAGE:-waltid/wallet-api2:1.1.1@sha256:d5fab1868802c98a28ce2ccee5ac6cc282f0b3a7ad079382ed42934296b700b5}"
# What a stranger installs: the newest release, candidates included. Pin it to repeat a run.
PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
PORT="${PORT:-9443}"
CONTAINER="${CONTAINER:-polaris-waltid}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
WALTID=http://localhost:7006
# Docker Desktop supplies host.docker.internal; Docker Engine on Linux does not.
ADD_HOST=()
[ "$(uname)" = Linux ] && ADD_HOST=(--add-host host.docker.internal:host-gateway)

command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { echo "walt.id runs from its image: start Docker" >&2; exit 2; }
for p in "$PORT" 7006; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $p is in use (the verifier takes PORT, the wallet 7006)" >&2
    exit 2
  fi
done
# A container of that name is somebody's; this walk only removes the one it starts.
if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "a container named $CONTAINER exists; remove it or set CONTAINER" >&2
  exit 2
fi

echo "work dir   $WORK"
echo "wallet     $IMAGE"
echo "verifier   pip install --pre $PKG"
mkdir -p "$WORK" && cd "$WORK"
"$PY" -m venv venv
# Every third-party package by hash (../requirements.txt); then polaris-oid4vp itself, as one wheel.
venv/bin/pip install -q --require-hashes -r "$HERE/../requirements.txt"
if [ -e "$PKG" ]; then
  venv/bin/python -c 'import sys; sys.exit(sys.version_info < (3, 10))' || {
    echo "building $PKG from the tree needs Python 3.10 or newer; set PYTHON to one, or set" >&2
    echo "POLARIS_OID4VP to a release on PyPI, which installs its wheel on any supported Python" >&2
    exit 2
  }
  venv/bin/pip install -q --require-hashes -r "$HERE/../requirements-build.txt"
fi
venv/bin/pip wheel -q --pre --no-deps --no-build-isolation -w wheel "$PKG"
venv/bin/pip install -q --no-deps wheel/*.whl
echo "installed  polaris-oid4vp $(venv/bin/python -c 'import importlib.metadata as m; print(m.version("polaris-oid4vp"))')"

VERIFIER_PID=""
stop_verifier() {  # `wait` returns the killed server's 143, which set -e would take as ours
  if [ -n "$VERIFIER_PID" ]; then
    kill "$VERIFIER_PID" 2>/dev/null || true
    wait "$VERIFIER_PID" 2>/dev/null || true
    VERIFIER_PID=""
  fi
}
cleanup() { stop_verifier; docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$CONTAINER" ${ADD_HOST[@]+"${ADD_HOST[@]}"} -p 7006:7006 "$IMAGE" >/dev/null
for _ in $(seq 1 60); do curl -sf -m 2 "$WALTID/livez" >/dev/null 2>&1 && break; sleep 1; done
curl -sf -m 2 "$WALTID/livez" >/dev/null || { echo "walt.id did not come up at $WALTID" >&2; exit 2; }
echo "digest     $(docker image inspect "$IMAGE" --format '{{index .RepoDigests 0}}' | cut -d@ -f2)"

venv/bin/polaris-oid4vp keygen --out pki --host host.docker.internal --port "$PORT" >/dev/null
PYTHON="$WORK/venv/bin/python" WALTID="$WALTID" CONTAINER="$CONTAINER" bash "$HERE/setup.sh" ./pki >/dev/null
WID="$(cat wallet-id.txt)" KID="$(cat key-id.txt)"

start_verifier() {  # $1 the issuer JWKS the verifier trusts, $2 log file
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host host.docker.internal \
    --bind 0.0.0.0 --port "$PORT" --issuer-jwks "$1" --once > "$2" 2>&1 &
  VERIFIER_PID=$!
  for _ in $(seq 1 40); do grep -q 'state=' "$2" 2>/dev/null && return 0; sleep 0.25; done
  echo "verifier did not start; see $WORK/$2" >&2
  exit 2
}

launch_uri() {  # $1 log file
  venv/bin/python - "$1" <<'EOF'
import re, sys, urllib.parse
log = open(sys.argv[1]).read()
cid = re.search(r"x509_hash:[A-Za-z0-9_-]+", log).group(0)
ruri = re.findall(r"https://\S+request\.jwt\?state=[A-Za-z0-9_-]+", log)[-1]
print("openid4vp://authorize?" + urllib.parse.urlencode(
    {"client_id": cid, "request_uri": ruri, "request_uri_method": "post"}))
EOF
}

present() {  # $1 launch URI, $2 wallet response file. /credentials/present, not .../resolve-request (README)
  venv/bin/python -c 'import json, sys; print(json.dumps({"requestUrl": sys.argv[1], "keyId": sys.argv[2]}))' \
    "$1" "$KID" > request.json
  curl -s -m 60 -X POST "$WALTID/wallet/$WID/credentials/present" \
    -H 'Content-Type: application/json' --data @request.json > "$2" || true
  sleep 1  # the verifier logs its verdict after it answers
}

fail=0
expect() {  # $1 label, $2 file, $3 pattern that must appear
  if grep -qE "$3" "$2"; then echo "  ok    $1"; else echo "  FAIL  $1 (no /$3/ in $2)"; fail=1; fi
}

echo "== genuine presentation"
start_verifier issuer-jwks.json verifier.log
URI=$(launch_uri verifier.log)
present "$URI" wallet.json
expect "the wallet transmitted and was answered" wallet.json '"transmission_success":true'
expect "the verifier accepted it" verifier.log '<- 200 authentic'
{ grep -E '<- 200' verifier.log || true; } | sed 's/^/        /'

echo "== control: the same request again, after it was answered"
present "$URI" wallet-replay.json
expect "refused at the request stage" wallet-replay.json 'no such outstanding request'
stop_verifier

echo "== control: the verifier trusts a different issuer key under the same kid"
venv/bin/python - <<'EOF'
import base64, json
from cryptography.hazmat.primitives.asymmetric import ec
kid = json.load(open("issuer-jwks.json"))[0]["kid"]
n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")
json.dump([{"kty": "EC", "crv": "P-256", "x": b(n.x), "y": b(n.y), "kid": kid}],
          open("issuer-jwks-other.json", "w"))
EOF
start_verifier issuer-jwks-other.json verifier-other.log
present "$(launch_uri verifier-other.log)" wallet-other.json
expect "the wallet was told only that it was not accepted" wallet-other.json 'the presentation was not accepted'
expect "the verifier refused the issuer" verifier-other.log '<- 400 refused: issuer_signature'
stop_verifier

[ "$fail" -eq 0 ] && echo "RESULT: accepted, and both controls refused" || echo "RESULT: FAILED"
exit "$fail"
