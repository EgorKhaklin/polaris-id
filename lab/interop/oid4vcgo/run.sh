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
#
# Exits 0 only if the genuine presentation is accepted AND every control is refused.
set -euo pipefail

VERSION="${OID4VCGO_VERSION:-v0.12.0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# --issuer-trust-anchor is in the tree and not in any published release yet (1.0.0rc7 has only
# --issuer-jwks), so a clone's own package is the default; POLARIS_OID4VP overrides it.
PKG="${POLARIS_OID4VP:-$HERE/../../../packages/polaris-oid4vp}"
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
echo "wallet     github.com/idfoundry/oid4vcgo $VERSION, cmd/conformance-wallet-vp"
echo "verifier   pip install $PKG"
mkdir -p "$WORK" && cd "$WORK"
"$PY" -m venv venv
venv/bin/pip install -q "$PKG"
echo "installed  polaris-oid4vp $(venv/bin/python -c 'import importlib.metadata as m; print(m.version("polaris-oid4vp"))')"
venv/bin/polaris-oid4vp serve --help | grep -q -- --issuer-trust-anchor || {
  echo "this polaris-oid4vp has no --issuer-trust-anchor; set POLARIS_OID4VP to one that does" >&2
  exit 2
}

# The wallet, built at exactly $VERSION for the container's own architecture inside the official
# Go image. `go install pkg@version` pins the module version with no go.mod of our own.
docker run --rm -v "$WORK:/out" -e CGO_ENABLED=0 -e GOBIN=/out golang:1.26 \
  go install "github.com/idfoundry/oid4vcgo/cmd/conformance-wallet-vp@$VERSION"
mv "$WORK/conformance-wallet-vp" "$WORK/wallet"

venv/bin/python "$HERE/setup_pki.py" "$WORK" >/dev/null
venv/bin/polaris-oid4vp keygen --out pki --host host.docker.internal --port "$PORT" >/dev/null

# From v0.22.0 the wallet checks the request object's x5c leaf against `verifier_trust_anchors_pem`
# (OpenID4VP 5.9.3, HAIP 5), added after our report (idfoundry/oid4vcgo#312, #314). From that
# version on it is told to trust keygen's CA, the anchor HAIP keeps out of the chain, and control
# (d) tells it an unrelated one instead.
CHECKS_VERIFIER=$(venv/bin/python -c 'import sys; v = tuple(int(x) for x in sys.argv[1].lstrip("v").split(".")); print(int(v >= (0, 22, 0)))' "$VERSION")
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
trap stop_all EXIT

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
    -v "$WORK:/w" alpine:3.20 /w/wallet -config /w/config.json >/dev/null
  for _ in $(seq 1 40); do docker logs polaris-oid4vcgo-wallet 2>&1 | grep -q "listening" && break; sleep 0.25; done
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
grep -E '<- 200' verifier.log | sed 's/^/        /'

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
  if grep -q '<- 200' verifier-untrusted.log; then echo "  FAIL  the verifier received a presentation"; fail=1
  else echo "  ok    the wallet presented nothing to a verifier outside its anchors"; fi
fi

[ "$fail" -eq 0 ] && echo "RESULT: accepted, and every control refused" || echo "RESULT: FAILED"
exit "$fail"
