#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# OID4VCgo's own OpenID4VP wallet harness presents an x5c-signed SD-JWT VC to polaris-oid4vp,
# then three controls.
#
# The wallet is cmd/conformance-wallet-vp from github.com/idfoundry/oid4vcgo, the binary its
# author certified with against the OpenID Foundation's wallet test plan. It is built here, at a
# pinned version, inside the official Go image, and run in a container given no trust for the
# verifier's TLS listener: keygen's listener certificate is self-signed, and the wallet presents
# without it (measured 2026-09-30), so it does not validate it; from v0.22.0 it says so when it
# starts. It issues its own fixture credential with an x5c chain under a CA this script
# generates, and polaris-oid4vp is told to trust that CA (--issuer-trust-anchor).
#
#   lab/interop/oid4vcgo/run.sh                                  # OID4VCgo v0.12.0
#   OID4VCGO_VERSION=v0.19.0 lab/interop/oid4vcgo/run.sh
#   OID4VCGO_VERSION=v0.22.0 lab/interop/oid4vcgo/run.sh         # also checks the verifier's chain
#   OID4VCGO_VERSION=v0.23.0 lab/interop/oid4vcgo/run.sh         # and holds its leaf to HAIP
#   OID4VCGO_VERSION=latest lab/interop/oid4vcgo/run.sh          # the newest release
#   OID4VCGO_BIN=/path/to/conformance-wallet-vp lab/interop/oid4vcgo/run.sh   # a prebuilt binary
#   OID4VCGO_SRC=/path/to/a/checkout lab/interop/oid4vcgo/run.sh  # built from that module
#
# Exits 0 only if the genuine presentation is accepted AND every control is refused.
set -euo pipefail
# A run that stops before its last line fails, whatever its EXIT trap's last command returns:
# after a set -u failure, bash 3.2 (macOS /bin/bash) exits with the trap's own status, and $? in
# the trap is already 0. Every trap below hands its status to exit_trap.
finished=0
exit_trap() {  # $1 the run's exit status: kept, unless the run stopped early with 0
  local rc="$1"
  if [ "$finished" != 1 ] && [ "$rc" = 0 ]; then rc=1; fi
  exit "$rc"
}

VERSION="${OID4VCGO_VERSION:-v0.12.0}"
# A wallet before its release: OID4VCGO_BIN, a prebuilt binary run as is, or OID4VCGO_SRC, a
# checkout built here. Either replaces the version; both at once, or one that is not what it
# names, stops the run before anything is built.
WALLET_BIN="${OID4VCGO_BIN:-}"
WALLET_SRC="${OID4VCGO_SRC:-}"
if [ -n "$WALLET_BIN" ] && [ -n "$WALLET_SRC" ]; then
  echo "OID4VCGO_BIN and OID4VCGO_SRC are both set; set one, so the run tests one wallet" >&2
  exit 2
fi
if [ -n "$WALLET_BIN" ]; then
  [ -f "$WALLET_BIN" ] || { echo "OID4VCGO_BIN=$WALLET_BIN: no such file" >&2; exit 2; }
  [ -x "$WALLET_BIN" ] || { echo "OID4VCGO_BIN=$WALLET_BIN: not executable" >&2; exit 2; }
  WALLET_BIN="$(cd "$(dirname "$WALLET_BIN")" && pwd)/$(basename "$WALLET_BIN")"
elif [ -n "$WALLET_SRC" ]; then
  [ -f "$WALLET_SRC/go.mod" ] || { echo "OID4VCGO_SRC=$WALLET_SRC: not a Go module (no go.mod)" >&2; exit 2; }
  [ -d "$WALLET_SRC/cmd/conformance-wallet-vp" ] || {
    echo "OID4VCGO_SRC=$WALLET_SRC: no cmd/conformance-wallet-vp in it" >&2; exit 2; }
  WALLET_SRC="$(cd "$WALLET_SRC" && pwd)"
fi
PY_FOR_LATEST="${PYTHON:-python3}"
if [ -z "$WALLET_BIN$WALLET_SRC" ] && [ "$VERSION" = latest ]; then
  # The newest release as the Go module proxy states it, so the rest of the walk, which reads the
  # version, sees a real one.
  VERSION="$(curl -fsSL https://proxy.golang.org/github.com/idfoundry/oid4vcgo/@latest \
    | "$PY_FOR_LATEST" -c 'import json, sys; print(json.load(sys.stdin)["Version"])')"
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
# A clone's own package is the default, so a run tests the tree; POLARIS_OID4VP overrides it, and
# --issuer-trust-anchor, which the run needs, is in every published release from 1.0.0rc8.
PKG="${POLARIS_OID4VP:-$HERE/../../../packages/polaris-oid4vp}"
# The images the wallet is built and run in, pinned by digest so a run is the run that was reviewed
# (read from Docker Hub's manifest index on 2026-10-11: golang:1.26 and alpine:3.20).
GO_IMAGE="golang:1.26@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89"
ALPINE_IMAGE="alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
PORT="${PORT:-9443}"
WALLET_PORT="${WALLET_PORT:-8443}"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
ADD_HOST=()
[ "$(uname)" = Linux ] && ADD_HOST=(--add-host host.docker.internal:host-gateway)

for p in "$PORT" "$WALLET_PORT"; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $p is in use; set PORT / WALLET_PORT" >&2
    exit 2
  fi
done

echo "work dir   $WORK"
if [ -n "$WALLET_BIN" ]; then
  echo "wallet     binary $WALLET_BIN, sha256 $( (sha256sum "$WALLET_BIN" 2>/dev/null || shasum -a 256 "$WALLET_BIN") | cut -d' ' -f1)"
elif [ -n "$WALLET_SRC" ]; then
  SRC_COMMIT="$(git -C "$WALLET_SRC" rev-parse HEAD 2>/dev/null || echo "not a git checkout")"
  [ -n "$(git -C "$WALLET_SRC" status --porcelain 2>/dev/null || true)" ] && SRC_COMMIT="$SRC_COMMIT, with uncommitted changes"
  echo "wallet     source $WALLET_SRC, commit $SRC_COMMIT, cmd/conformance-wallet-vp built with go build"
else
  echo "wallet     github.com/idfoundry/oid4vcgo $VERSION, cmd/conformance-wallet-vp"
fi
echo "verifier   $PKG, built as a wheel; its dependencies by hash"
mkdir -p "$WORK" && cd "$WORK"
"$PY" -m venv venv
# Every third-party package by hash (../requirements.txt); then polaris-oid4vp itself, built from
# $PKG with nothing else fetched and installed as that one wheel. A release from PyPI arrives as
# its published wheel and builds nothing; a path is built here, with the build backend by hash
# (../requirements-build.txt), whose setuptools supports Python 3.10 or newer.
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
venv/bin/polaris-oid4vp serve --help | grep -- --issuer-trust-anchor >/dev/null || {
  echo "this polaris-oid4vp has no --issuer-trust-anchor; set POLARIS_OID4VP to one that does" >&2
  exit 2
}

# The wallet, built at exactly $VERSION for the container's own architecture inside the official
# Go image. `go install pkg@version` pins the module version with no go.mod of our own.
# GOTOOLCHAIN=auto: a release needing a newer Go than a cached image holds (v0.39.0: 1.26.9) fetches it.
# OID4VCGO_BIN is copied in as is; it runs in alpine, so it must be a static Linux binary.
# OID4VCGO_SRC is built the same way from the checkout, mounted read-only; -buildvcs=false, since
# git in the container refuses a checkout another user owns (its commit is printed above).
if [ -n "$WALLET_BIN" ]; then
  cp "$WALLET_BIN" "$WORK/wallet"
elif [ -n "$WALLET_SRC" ]; then
  docker run --rm -v "$WALLET_SRC:/src:ro" -v "$WORK:/out" -w /src -e CGO_ENABLED=0 -e GOTOOLCHAIN=auto \
    "$GO_IMAGE" go build -buildvcs=false -o /out/conformance-wallet-vp ./cmd/conformance-wallet-vp
  mv "$WORK/conformance-wallet-vp" "$WORK/wallet"
else
  docker run --rm -v "$WORK:/out" -e CGO_ENABLED=0 -e GOBIN=/out -e GOTOOLCHAIN=auto "$GO_IMAGE" \
    go install "github.com/idfoundry/oid4vcgo/cmd/conformance-wallet-vp@$VERSION"
  mv "$WORK/conformance-wallet-vp" "$WORK/wallet"
fi

venv/bin/python "$HERE/setup_pki.py" "$WORK" >/dev/null
venv/bin/polaris-oid4vp keygen --out pki --host host.docker.internal --port "$PORT" >/dev/null

# From v0.22.0 the wallet checks the request object's x5c leaf against `verifier_trust_anchors_pem`
# (OpenID4VP 5.9.3, HAIP 5), added after our report (idfoundry/oid4vcgo#312, #314). From that
# version on it is told to trust keygen's CA, the anchor HAIP keeps out of the chain, and control
# (d) tells it an unrelated one instead.
# A binary or a checkout is taken as v0.22.0 or newer: it is tested before its release.
CHECKS_VERIFIER=1
[ -n "$WALLET_BIN$WALLET_SRC" ] || CHECKS_VERIFIER=$(venv/bin/python -c 'import sys; v = tuple(int(x) for x in sys.argv[1].lstrip("v").split(".")); print(int(v >= (0, 22, 0)))' "$VERSION")
set_verifier_anchor() {  # $1 the CA the wallet trusts for the verifier's request object
  venv/bin/python - "$1" <<'EOF'
import json, pathlib, sys
cfg = pathlib.Path("config.json")
c = json.loads(cfg.read_text())
c["verifier_trust_anchors_pem"] = pathlib.Path(sys.argv[1]).read_text()
cfg.write_text(json.dumps(c, indent=2))
EOF
}
[ "$CHECKS_VERIFIER" = 1 ] && set_verifier_anchor pki/anchor.pem

VERIFIER_PID=""
stop_verifier() {
  if [ -n "$VERIFIER_PID" ]; then
    kill "$VERIFIER_PID" 2>/dev/null || true
    wait "$VERIFIER_PID" 2>/dev/null || true
    VERIFIER_PID=""
  fi
}
stop_all() { stop_verifier; docker rm -f polaris-oid4vcgo-wallet >/dev/null 2>&1 || true; }
trap 'exit_rc=$?; stop_all; exit_trap "$exit_rc"' EXIT

start_verifier() {  # $1 issuer trust anchor, $2 log file
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host host.docker.internal \
    --bind 0.0.0.0 --port "$PORT" --issuer-trust-anchor "$1" --once > "$2" 2>&1 &
  VERIFIER_PID=$!
  for _ in $(seq 1 40); do grep -q 'state=' "$2" 2>/dev/null && return 0; sleep 0.25; done
  echo "verifier did not start; see $WORK/$2" >&2
  exit 2
}

start_wallet() {
  docker rm -f polaris-oid4vcgo-wallet >/dev/null 2>&1 || true
  docker run -d --name polaris-oid4vcgo-wallet ${ADD_HOST[@]+"${ADD_HOST[@]}"} -p "$WALLET_PORT:8443" \
    -v "$WORK:/w" "$ALPINE_IMAGE" /w/wallet -config /w/config.json >/dev/null
  for _ in $(seq 1 40); do docker logs polaris-oid4vcgo-wallet 2>&1 | grep "listening" >/dev/null && break; sleep 0.25; done
}
start_wallet
docker logs polaris-oid4vcgo-wallet 2>&1 | grep -i "warning" | sed 's/^/wallet says  /' || true

authorize() {  # $1 log to read the request from, $2 optional client_id, $3 output file
  local q
  q=$(venv/bin/python - "$1" "${2:-}" <<'EOF'
import re, sys, urllib.parse
log = open(sys.argv[1]).read()
cid = sys.argv[2] or re.search(r"x509_hash:[A-Za-z0-9_-]+", log).group(0)
ruri = re.findall(r"https://\S+request\.jwt\?state=[A-Za-z0-9_-]+", log)[-1]
print(urllib.parse.urlencode({"client_id": cid, "request_uri": ruri}))
EOF
)
  curl -sk -o "$3" -w "%{http_code}" "https://localhost:$WALLET_PORT/authorize?$q" || true
}

fail=0
expect() {  # $1 label, $2 file, $3 pattern
  if grep -qE "$3" "$2"; then echo "  ok    $1"; else echo "  FAIL  $1 (no /$3/ in $2)"; fail=1; fi
}

echo "== genuine presentation"
start_verifier issuer-ca.pem verifier.log
authorize verifier.log "" wallet.html >/dev/null
expect "the wallet reports it presented" wallet.html 'Presented'
expect "the verifier accepted it" verifier.log '<- 200 authentic'
grep -E '<- 200 authentic' verifier.log | sed 's/^/        /'

echo "== control (b): the same request again, after it was answered"
authorize verifier.log "" replay.html >/dev/null
expect "refused at the request stage" replay.html 'no such outstanding request'
stop_verifier

echo "== control (c): a launch whose client_id is not the signed request's"
start_verifier other-ca.pem verifier-other.log
authorize verifier-other.log x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA mismatch.html >/dev/null
expect "the wallet refused the request" mismatch.html 'does not match'

echo "== control (a): the verifier trusts an unrelated CA"
authorize verifier-other.log "" other.html >/dev/null
expect "the wallet was told only that it was not accepted" other.html 'not accepted'
expect "the verifier refused the issuer's chain" verifier-other.log '<- 400 refused: issuer_key'

if [ "$CHECKS_VERIFIER" = 1 ]; then
  echo "== control (d): the wallet trusts an unrelated CA for the verifier"
  stop_verifier
  set_verifier_anchor other-ca.pem
  start_wallet
  start_verifier issuer-ca.pem verifier-untrusted.log
  authorize verifier-untrusted.log "" untrusted.html >/dev/null
  echo "        wallet answered: $(head -c 300 untrusted.html | tr -s '\n' ' ')"
  if grep -q '<- 200 authentic' verifier-untrusted.log; then echo "  FAIL  the verifier received a presentation"; fail=1
  else echo "  ok    the wallet presented nothing to a verifier outside its anchors"; fi
fi

[ "$fail" -eq 0 ] && echo "RESULT: accepted, and every control refused" || echo "RESULT: FAILED"
finished=1
exit "$fail"
