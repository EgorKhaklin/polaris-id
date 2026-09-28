#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# eudi-dev presents an SD-JWT VC to the PUBLISHED polaris-oid4vp, then three controls.
#
# Everything runs from a scratch directory: a fresh venv with polaris-oid4vp from PyPI, the
# verifier's test PKI, and the wallet's own state. The wallet generates its holder key itself;
# this script reads only the public half, to bind the credential to it.
#
#   lab/interop/eudi-dev/run.sh                       # eudi-dev v2.3.7, polaris-oid4vp 1.0.0rc7
#   EUDI_IMAGE=ghcr.io/dominikschlosser/eudi-dev:v2.4.3 lab/interop/eudi-dev/run.sh
#
# Exits 0 only if the genuine presentation is accepted AND every control is refused where it
# should be. A run that only printed the success line would say nothing: a verifier that
# accepts everything prints it too.
set -euo pipefail

IMAGE="${EUDI_IMAGE:-ghcr.io/dominikschlosser/eudi-dev:v2.3.7}"
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
ADD_HOST=()
# Docker Desktop supplies host.docker.internal; Docker Engine on Linux does not.
[ "$(uname)" = Linux ] && ADD_HOST=(--add-host host.docker.internal:host-gateway)

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $PORT is in use; set PORT (keygen writes it into the certificate)" >&2
  exit 2
fi

echo "work dir   $WORK"
echo "wallet     $IMAGE"
echo "verifier   pip install --pre $PKG"
mkdir -p "$WORK" && cd "$WORK"
"$PY" -m venv venv
venv/bin/pip install -q --pre "$PKG"
echo "installed  polaris-oid4vp $(venv/bin/python -c 'import importlib.metadata as m; print(m.version("polaris-oid4vp"))')"
venv/bin/polaris-oid4vp keygen --out pki --host host.docker.internal --port "$PORT" >/dev/null
mkdir -p home
# The wallet runs as the image's own user and keeps its state in this directory. Docker Desktop
# maps file ownership across the mount and Docker Engine does not, so on Linux that user could
# not create its state here without this.
chmod a+rwx home

wallet() {
  # The ${a[@]+...} form because macOS's bash 3.2 calls an empty array unbound under set -u.
  # File storage through the environment: v2.4 reads EUDI_DEV_STORAGE, v2.3.7 has no
  # --storage flag and keeps files by default.
  docker run --rm ${ADD_HOST[@]+"${ADD_HOST[@]}"} -v "$WORK/home:/home/app/.eudi-dev" -v "$WORK:/in" \
    -e SSL_CERT_FILE=/in/pki/anchor.pem -e EUDI_DEV_STORAGE=file "$IMAGE" wallet "$@"
}

# The wallet makes its own holder key on first use. It is read through the container, as the
# user that owns it: on Linux the file belongs to the image's user, mode 0600, and this shell
# cannot open it. Only the public half is kept; the copy is removed as soon as it is read.
wallet info >/dev/null
docker run --rm -v "$WORK/home:/home/app/.eudi-dev" --entrypoint cat "$IMAGE" \
  /home/app/.eudi-dev/wallet/holder.pem > holder.pem
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
wallet import /in/credential.txt | tail -1

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
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host host.docker.internal \
    --bind 0.0.0.0 --port "$PORT" --issuer-jwks "$1" --once > "$2" 2>&1 &
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
