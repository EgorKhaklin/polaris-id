#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# A wallet on irmago, the Go library under the Yivi wallet, presents an SD-JWT VC to the PUBLISHED
# polaris-oid4vp, then five controls.
#
# The wallet (wallet/) is a small Go program on github.com/privacybydesign/irmago, pinned in
# wallet/go.mod with every module's hash in wallet/go.sum. irmago makes the holder key, verifies
# and stores the credential, and answers the request: its OpenID4VP client fetches the request
# object (by GET), checks x509_hash against the verifier trust anchor, matches the DCQL query
# against the stored credential, signs the key binding JWT with the stored key and dispatches the
# encrypted direct_post.jwt response. The credential is minted by ../waltid/issue_sdjwt_vc.py
# under an issuer CA made for the run. The wallet is built with the local Go toolchain, or with
# BUILD=docker in a Go image pinned by digest; it is pure Go, so either way it runs here.
#
#   lab/interop/irmago/run.sh                                     # the newest polaris-oid4vp
#   POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/irmago/run.sh
#   BUILD=docker lab/interop/irmago/run.sh                        # build in the pinned Go image
#
# Exits 0 only if the presentation is accepted AND every control is refused where it should be.
set -euo pipefail

GO_IMAGE="${GO_IMAGE:-golang:1.27.1-trixie@sha256:3b77fc618ec235a1ab412de7737f120dd507c57e8d87de4cbb7994fb94275ed5}"
GO="${GO:-go}"
BUILD="${BUILD:-}"
PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
PORT="${PORT:-9482}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
ISSUER="$HERE/../waltid/issue_sdjwt_vc.py"

if [ -z "$BUILD" ]; then
  if command -v "$GO" >/dev/null 2>&1; then BUILD=local; else BUILD=docker; fi
fi
if [ "$BUILD" = docker ]; then
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || {
    echo "the wallet is built in a Go image (no local go, or BUILD=docker): start Docker" >&2; exit 2; }
fi
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $PORT is in use; set PORT (keygen writes it into the certificate)" >&2
  exit 2
fi

echo "work dir   $WORK"
echo "wallet     irmago $(awk '$1 == "github.com/privacybydesign/irmago" {print $2}' "$HERE/wallet/go.mod") (wallet/go.mod)"
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

# The wallet, for this machine. -mod=readonly: every module is checked against wallet/go.sum and
# nothing in the tree is rewritten. In the image the build cross-compiles (CGO_ENABLED=0), and the
# module and build caches are named volumes so a second run does not download again.
case "$(uname -s)" in Darwin) GOOS=darwin ;; Linux) GOOS=linux ;; *) GOOS="$(uname -s | tr '[:upper:]' '[:lower:]')" ;; esac
case "$(uname -m)" in arm64 | aarch64) GOARCH=arm64 ;; x86_64 | amd64) GOARCH=amd64 ;; *) GOARCH="$(uname -m)" ;; esac
started=$(date +%s)
if [ "$BUILD" = docker ]; then
  docker run --rm -v "$HERE/wallet":/src:ro -v "$WORK":/out -w /src \
    -v polaris-go-mod:/go/pkg/mod -v polaris-go-build:/root/.cache/go-build \
    -e CGO_ENABLED=0 -e GOOS="$GOOS" -e GOARCH="$GOARCH" -e GOFLAGS=-mod=readonly "$GO_IMAGE" \
    sh -c 'go version && go build -trimpath -o /out/wallet-bin .' | sed 's/^/           /'
else
  (cd "$HERE/wallet" && CGO_ENABLED=0 GOFLAGS=-mod=readonly "$GO" version \
    && CGO_ENABLED=0 GOFLAGS=-mod=readonly "$GO" build -trimpath -o "$WORK/wallet-bin" .) | sed 's/^/           /'
fi
echo "built      wallet-bin for $GOOS/$GOARCH ($BUILD) in $(( $(date +%s) - started )) s"

venv/bin/polaris-oid4vp keygen --out pki --host localhost --port "$PORT" >/dev/null
venv/bin/polaris-oid4vp keygen --out other-pki --host localhost --port "$PORT" >/dev/null
# The holder key is irmago's, made by its OpenID4VCI key service; holder.json is the key its proof
# of possession carries. Two credentials are minted for it, each under its own issuer CA: the
# wallet stores the first, and control (a) has the verifier trust the second one's CA instead.
./wallet-bin init wallet >/dev/null
venv/bin/python "$ISSUER" --x5c --holder-jwk wallet/holder.json --out credential.json >/dev/null
venv/bin/python "$ISSUER" --x5c --holder-jwk wallet/holder.json --out credential-other.json >/dev/null
venv/bin/python - <<'EOF'
import json
d = json.load(open("credential.json"))
open("credential.txt", "w").write(d["credential"])
open("issuer-ca.pem", "w").write(d["issuer_ca_pem"])
open("other-issuer-ca.pem", "w").write(json.load(open("credential-other.json"))["issuer_ca_pem"])
EOF
./wallet-bin store wallet credential.txt issuer-ca.pem | sed 's/^/           /'

VERIFIER_PID=""
stop_verifier() {
  if [ -n "$VERIFIER_PID" ]; then
    kill "$VERIFIER_PID" 2>/dev/null || true
    wait "$VERIFIER_PID" 2>/dev/null || true
    VERIFIER_PID=""
  fi
}
trap stop_verifier EXIT

start_verifier() {  # $1 issuer trust anchor, $2 log
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host localhost \
    --bind 127.0.0.1 --port "$PORT" --issuer-trust-anchor "$1" --once > "$2" 2>&1 &
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

present() {  # $1 launch URI, $2 wallet log, $3 the anchor the wallet trusts for the verifier,
             # $4 the listener certificate it trusts (pki/tls.pem unless given)
  ./wallet-bin present wallet "$3" "${4:-pki/tls.pem}" "$1" > "$2" 2>&1 || true
  sleep 1  # the verifier logs its verdict after it answers
}

fail=0
expect() {  # $1 label, $2 file, $3 pattern that must appear
  if grep -qE "$3" "$2"; then echo "  ok    $1"; else echo "  FAIL  $1 (no /$3/ in $2)"; fail=1; fi
}

echo "== genuine presentation"
start_verifier issuer-ca.pem verifier.log
URI=$(launch_uri verifier.log)
present "$URI" wallet.log pki/anchor.pem
expect "irmago dispatched" wallet.log '^DISPATCHED'
expect "the verifier accepted it" verifier.log '<- 200 authentic'
{ grep -E '<- 200' verifier.log || true; } | sed 's/^/        /'

echo "== control (b): the same request again, after it was answered"
present "$URI" wallet-replay.log pki/anchor.pem
expect "refused at the request stage" wallet-replay.log '^REQUEST REFUSED .*HTTP 404'
stop_verifier

echo "== control (c): a launch URI whose client_id is not the signed request's"
start_verifier other-issuer-ca.pem verifier-other.log
present "$(launch_uri verifier-other.log x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)" wallet-c.log pki/anchor.pem
expect "irmago refused the request" wallet-c.log '^REQUEST REFUSED .*names client_id'

echo "== control (d): the wallet trusts an unrelated CA for the verifier"
present "$(launch_uri verifier-other.log)" wallet-d.log other-pki/anchor.pem
expect "irmago refused the request" wallet-d.log '^REQUEST REFUSED .*relying party certificate.*unknown authority'

echo "== control (e): the wallet trusts a different listener certificate"
present "$(launch_uri verifier-other.log)" wallet-e.log pki/anchor.pem other-pki/tls.pem
expect "the connection was refused" wallet-e.log '^REQUEST REFUSED .*tls: failed to verify certificate'

echo "== control (a): the verifier trusts a different issuer CA"
present "$(launch_uri verifier-other.log)" wallet-a.log pki/anchor.pem
expect "irmago was not accepted" wallet-a.log '^DISPATCH FAILED .*status code 400'
expect "the verifier refused the issuer" verifier-other.log '<- 400 refused: issuer_key'
stop_verifier

[ "$fail" -eq 0 ] && echo "RESULT: accepted, and all five controls refused" || echo "RESULT: FAILED"
exit "$fail"
