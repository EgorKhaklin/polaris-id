#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# eudi-dev presents an SD-JWT VC to the PUBLISHED polaris-oid4vp, then three controls.
#
# Everything runs from a scratch directory: a fresh venv with polaris-oid4vp from PyPI, the
# verifier's test PKI, and the wallet's own state. The wallet generates its holder key itself;
# this script reads only the public half, to bind the credential to it.
#
#   lab/interop/eudi-dev/run.sh                       # eudi-dev v2.3.7, newest polaris-oid4vp
#   EUDI_IMAGE=ghcr.io/dominikschlosser/eudi-dev:v2.4.3 lab/interop/eudi-dev/run.sh
#   EUDI_NATIVE=1 lab/interop/eudi-dev/run.sh         # the wallet's own binary, no Docker
#
# With Docker running, the wallet runs from its image. Without it (or with EUDI_NATIVE=1), the
# wallet's release binary for this machine (macOS or Linux, x86-64 or arm64) is downloaded and
# checked against the SHA-256 pinned below for v2.3.7, or, for another EUDI_VERSION, against the
# checksums the release publishes.
#
# Exits 0 only if the genuine presentation is accepted AND every control is refused where it
# should be. A run that only printed the success line would say nothing: a verifier that
# accepts everything prints it too.
set -euo pipefail

IMAGE="${EUDI_IMAGE:-ghcr.io/dominikschlosser/eudi-dev:v2.3.7}"
EUDI_VERSION="${EUDI_VERSION:-v2.3.7}"
# What a stranger installs: the newest release, candidates included. Pin it to repeat a run.
PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
PORT="${PORT:-9443}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# The issuer script: named explicitly, downloaded beside this file (docs/STRANGER-PATH.md), or
# where it sits in a clone of the repository.
ISSUER="${ISSUER:-}"
if [ -z "$ISSUER" ]; then
  for candidate in "$HERE/issue_sdjwt_vc.py" "$HERE/../waltid/issue_sdjwt_vc.py"; do
    [ -f "$candidate" ] && ISSUER="$candidate" && break
  done
fi
if [ -z "$ISSUER" ] || [ ! -f "$ISSUER" ]; then
  echo "issue_sdjwt_vc.py not found: put it beside run.sh or set ISSUER" >&2
  exit 2
fi
ISSUER="$(cd "$(dirname "$ISSUER")" && pwd)/$(basename "$ISSUER")"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
if [ "${EUDI_NATIVE:-}" != 1 ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  MODE=docker
  # The verifier as the container reaches it. Docker Desktop supplies host.docker.internal;
  # Docker Engine on Linux does not.
  VHOST=host.docker.internal BIND=0.0.0.0
  ADD_HOST=()
  [ "$(uname)" = Linux ] && ADD_HOST=(--add-host host.docker.internal:host-gateway)
else
  MODE=native VHOST=localhost BIND=127.0.0.1
fi

# v2.3.7's release binaries, pinned here so a download is checked against this repository and
# not only against a file published beside it.
pinned_sha256() {
  case "$1" in
    eudi-v2.3.7-darwin-amd64) echo 983f9d51b0792bc4456458e91ec3a5906f45858bea192c48413e7704d93d9b36 ;;
    eudi-v2.3.7-darwin-arm64) echo 2cefced5cce8c25c4b1d5cf35796e8e4ce470c92067b176dd18e8c6061385fef ;;
    eudi-v2.3.7-linux-amd64) echo 075732b061128e37481d35397c16e80ff54302b9b335637a5d5164230630dd64 ;;
    eudi-v2.3.7-linux-arm64) echo ff944f0f2dac473ef22a02265b4abcd6c13407b91f3dd8c1f24a882ddefec28f ;;
  esac
}

fetch_wallet() {  # the release binary for this machine, into ./eudi, or exit 2
  local os arch name want got rel
  case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;;
    *) echo "no eudi-dev binary for $(uname -s); install Docker instead" >&2; exit 2 ;; esac
  case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;;
    *) echo "no eudi-dev binary for $(uname -m); install Docker instead" >&2; exit 2 ;; esac
  name="eudi-$EUDI_VERSION-$os-$arch"
  rel="https://github.com/dominikschlosser/eudi-dev/releases/download/$EUDI_VERSION"
  curl -fsSL -o eudi "$rel/$name"
  want="$(pinned_sha256 "$name")"
  [ -n "$want" ] || want="$(curl -fsSL "$rel/checksums.txt" | awk -v n="$name" '$2 == n {print $1}')"
  got="$( (sha256sum eudi 2>/dev/null || shasum -a 256 eudi) | cut -d' ' -f1)"
  if [ -z "$want" ] || [ "$got" != "$want" ]; then
    echo "the $name download does not match its SHA-256; not running it" >&2
    rm -f eudi
    exit 2
  fi
  chmod +x eudi
}

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $PORT is in use; set PORT (keygen writes it into the certificate)" >&2
  exit 2
fi

echo "work dir   $WORK"
if [ "$MODE" = docker ]; then echo "wallet     $IMAGE"; else echo "wallet     eudi-dev $EUDI_VERSION, its own binary (no Docker)"; fi
echo "verifier   pip install --pre $PKG"
mkdir -p "$WORK" && cd "$WORK"
"$PY" -m venv venv
venv/bin/pip install -q --pre "$PKG"
echo "installed  polaris-oid4vp $(venv/bin/python -c 'import importlib.metadata as m; print(m.version("polaris-oid4vp"))')"
venv/bin/polaris-oid4vp keygen --out pki --host "$VHOST" --port "$PORT" >/dev/null
mkdir -p home
# In Docker the wallet runs as the image's own user and keeps its state in this directory.
# Docker Desktop maps file ownership across the mount and Docker Engine does not, so on Linux
# that user could not create its state here without this.
chmod a+rwx home
[ "$MODE" = native ] && fetch_wallet

# No trust is configured for the verifier's TLS listener. keygen's listener certificate is
# self-signed, and eudi-dev (v2.3.7 and v2.4.3, measured 2026-09-30) presents without being given
# it, even to a host name the certificate does not carry: it does not validate it. What binds
# the exchange is the signed request object (x509_hash) and the response encrypted to its key.
wallet() {
  # File storage through the environment: v2.4 reads EUDI_DEV_STORAGE, v2.3.7 has no
  # --storage flag and keeps files by default.
  if [ "$MODE" = docker ]; then
    # The ${a[@]+...} form because macOS's bash 3.2 calls an empty array unbound under set -u.
    docker run --rm ${ADD_HOST[@]+"${ADD_HOST[@]}"} -v "$WORK/home:/home/app/.eudi-dev" -v "$WORK:/in" \
      -e EUDI_DEV_STORAGE=file "$IMAGE" wallet "$@"
  else
    EUDI_DEV_STORAGE=file ./eudi wallet "$@" --wallet-dir "$WORK/home/wallet"
  fi
}
in_wallet_view() {  # a file of the work dir, as the wallet sees it
  if [ "$MODE" = docker ]; then echo "/in/$1"; else echo "$WORK/$1"; fi
}

# The wallet makes its own holder key on first use. In Docker it is read through the container,
# as the user that owns it: on Linux the file belongs to the image's user, mode 0600, and this
# shell cannot open it. Only the public half is kept; the copy is removed as soon as it is read.
wallet info >/dev/null
if [ "$MODE" = docker ]; then
  docker run --rm -v "$WORK/home:/home/app/.eudi-dev" --entrypoint cat "$IMAGE" \
    /home/app/.eudi-dev/wallet/holder.pem > holder.pem
else
  cp "$WORK/home/wallet/holder.pem" holder.pem
fi
venv/bin/python - <<'EOF'
import base64, json, os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
key = serialization.load_pem_private_key(open("holder.pem", "rb").read(), None)
os.remove("holder.pem")
pub = key.public_key()
assert isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1)
n = pub.public_numbers()
b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")
json.dump({"kty": "EC", "crv": "P-256", "x": b(n.x), "y": b(n.y), "kid": "eudi-dev-holder"},
          open("holder-jwk.json", "w"))
EOF
venv/bin/python "$ISSUER" --holder-jwk holder-jwk.json --out issued.json >/dev/null
venv/bin/python - <<'EOF'
import base64, json
from cryptography.hazmat.primitives.asymmetric import ec
issued = json.load(open("issued.json"))
open("credential.txt", "w").write(issued["credential"])
json.dump(issued["issuer_jwks"], open("issuer-jwks.json", "w"))
# Control (a): a different key under the SAME kid, so only the signature can tell them apart.
n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")
json.dump([{"kty": "EC", "crv": "P-256", "x": b(n.x), "y": b(n.y),
            "kid": issued["issuer_jwks"][0]["kid"]}], open("issuer-jwks-other.json", "w"))
EOF
wallet import "$(in_wallet_view credential.txt)" | tail -1

VERIFIER_PID=""
stop_verifier() {  # `wait` returns the killed server's 143, which set -e would take as ours
  if [ -n "$VERIFIER_PID" ]; then
    kill "$VERIFIER_PID" 2>/dev/null || true
    wait "$VERIFIER_PID" 2>/dev/null || true
    VERIFIER_PID=""
  fi
}
trap stop_verifier EXIT

start_verifier() {  # $1 issuer JWKS, $2 log file
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host "$VHOST" \
    --bind "$BIND" --port "$PORT" --issuer-jwks "$1" --once > "$2" 2>&1 &
  VERIFIER_PID=$!
  for _ in $(seq 1 40); do grep -q 'state=' "$2" 2>/dev/null && return 0; sleep 0.25; done
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

present() {  # $1 launch URI, $2 wallet log
  wallet accept "$1" --auto-accept --haip --mode strict --no-open > "$2" 2>&1 || true
}

fail=0
expect() {  # $1 label, $2 file, $3 pattern that must appear
  if grep -qE "$3" "$2"; then echo "  ok    $1"; else echo "  FAIL  $1 (no /$3/ in $2)"; fail=1; fi
}

echo "== genuine presentation"
start_verifier issuer-jwks.json verifier.log
URI=$(launch_uri verifier.log)
present "$URI" wallet.log
expect "the wallet submitted and was answered 200" wallet.log 'Response: 200'
expect "the verifier accepted it" verifier.log '<- 200 authentic'
grep -E '<- 200' verifier.log | sed 's/^/        /'

echo "== control (b): the same request again, after it was answered"
present "$URI" wallet-replay.log
expect "refused at the request stage" wallet-replay.log 'request_uri returned HTTP 404'
stop_verifier

echo "== control (c): a launch URI whose client_id is not the signed request's"
start_verifier issuer-jwks-other.json verifier-other.log
present "$(launch_uri verifier-other.log x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)" wallet-c.log
expect "the wallet refused the request" wallet-c.log 'does not match outer client_id'

echo "== control (a): the verifier trusts a different issuer key under the same kid"
present "$(launch_uri verifier-other.log)" wallet-a.log
expect "the wallet was told only that it was not accepted" wallet-a.log 'Response: 400'
expect "the verifier refused the issuer signature" verifier-other.log '<- 400 refused: issuer_signature'
stop_verifier

[ "$fail" -eq 0 ] && echo "RESULT: accepted, and all three controls refused" || echo "RESULT: FAILED"
exit "$fail"
