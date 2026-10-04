#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# Credo issues a credential under a P-256 did:cheqd it registers on cheqd's own localnet, a Credo
# holder presents it to the PUBLISHED polaris-oid4vp, then the controls.
#
# Everything runs on this machine: cheqd-node's image (pinned by digest) as a one-validator
# localnet (localnet.sh), so no tokens, accounts or public network are involved; Credo from the
# lock file (`npm ci`); polaris-oid4vp from PyPI in a fresh venv, its dependency by hash. Polaris
# resolves no DIDs: ledger.py, this walk's own code, reads the issuer's DID document and the
# status list from the localnet and hands the verifier the key (--issuer-jwks).
#
#   lab/interop/cheqd/run.sh                                     # the newest polaris-oid4vp
#   POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/cheqd/run.sh
#
# Exits 0 only if the presentation is accepted, the status list reads VALID, and every control is
# refused where it should be.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
# A path (the tree's package, a wheel) is made absolute before the cd below.
if [ -e "$PKG" ]; then PKG="$(cd "$(dirname "$PKG")" && pwd)/$(basename "$PKG")"; fi
PORT="${PORT:-9490}"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
export CHEQD_RPC="http://127.0.0.1:${CHEQD_RPC_PORT:-26657}"
export CHEQD_REST="http://127.0.0.1:${CHEQD_REST_PORT:-1317}"
export PIP_DISABLE_PIP_VERSION_CHECK=1

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "the localnet runs in Docker: start it" >&2
  exit 2
fi
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $PORT is in use; set PORT (keygen writes it into the certificate)" >&2
  exit 2
fi

echo "work dir   $WORK"
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

# Credo, exactly as package-lock.json pins it. No install script runs: nothing here needs one.
(cd "$HERE" && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error >/dev/null)
echo "credo      $(cd "$HERE" && node -p "['core', 'cheqd', 'openid4vc'].map((p) => '@credo-ts/' + p + ' ' + require('./node_modules/@credo-ts/' + p + '/package.json').version).join(', ')")"
walk() { node "$HERE/walk.ts" "$@"; }

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
  [ -n "${KEEP_LOCALNET:-}" ] || bash "$HERE/localnet.sh" down
}
trap cleanup EXIT

bash "$HERE/localnet.sh" up

echo "== the issuer: Credo registers a P-256 did:cheqd, publishes a status list, issues"
walk issue "$WORK" > issuer.log 2>&1 || { cat issuer.log; exit 1; }
sed -e 's/^\[[^]]*\] /  credo  /' issuer.log
echo "== the walk resolves the DID on the localnet (Polaris resolves none)"
venv/bin/python "$HERE/ledger.py" did issued.json issuer-jwks.json issuer-jwks-other.json | sed 's/^/  /'

venv/bin/polaris-oid4vp keygen --out pki --host localhost --port "$PORT" >/dev/null
venv/bin/polaris-oid4vp keygen --out other-pki --host localhost --port "$PORT" >/dev/null

start_verifier() {  # $1 issuer JWKS, $2 log
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host localhost --bind 127.0.0.1 \
    --port "$PORT" --issuer-jwks "$1" --once > "$2" 2>&1 &
  VERIFIER_PID=$!
  for _ in $(seq 1 240); do grep -q 'state=' "$2" 2>/dev/null && return 0; sleep 0.25; done
  echo "verifier did not start; see $WORK/$2" >&2
  exit 2
}

launch_uri() {  # $1 the verifier's log
  venv/bin/python - "$1" <<'EOF'
import re, sys, urllib.parse
log = open(sys.argv[1]).read()
cid = re.search(r"x509_hash:[A-Za-z0-9_-]+", log).group(0)
ruri = re.findall(r"https://\S+request\.jwt\?state=[A-Za-z0-9_-]+", log)[-1]
print("openid4vp://authorize?" + urllib.parse.urlencode(
    {"client_id": cid, "request_uri": ruri, "request_uri_method": "post"}))
EOF
}

present() {  # $1 launch URI, $2 the holder's log, $3 the CA the holder trusts for the verifier
  # The listener's certificate is self-signed; Node trusts it only when told to, which is the
  # TLS registration a counterparty makes for a test verifier.
  NODE_EXTRA_CA_CERTS="$WORK/pki/tls.pem" walk present "$WORK" "$1" "$WORK/$3" > "$2" 2>&1 || true
  sleep 1  # the verifier logs its verdict after it answers
}

fail=0
expect() {  # $1 label, $2 file, $3 pattern that must appear
  if grep -qE "$3" "$2"; then echo "  ok    $1"; else echo "  FAIL  $1 (no /$3/ in $2)"; fail=1; fi
}

echo "== genuine presentation"
start_verifier issuer-jwks.json verifier.log
URI=$(launch_uri verifier.log)
present "$URI" holder.log pki/anchor.pem
expect "the holder dispatched" holder.log '^DISPATCHED: the verifier answered 200'
expect "the verifier accepted it" verifier.log '<- 200 authentic'
{ grep -E '<- 200' verifier.log || true; } | sed 's/^/        /'

echo "== control (b): the same request again, after it was answered"
present "$URI" holder-replay.log pki/anchor.pem
expect "refused at the request stage" holder-replay.log "^REQUEST REFUSED: .*status code '404'"
stop_verifier

echo "== control (c): Credo trusts an unrelated CA for the verifier"
start_verifier issuer-jwks-other.json verifier-other.log
present "$(launch_uri verifier-other.log)" holder-c.log other-pki/anchor.pem
expect "Credo refused the request" holder-c.log '^REQUEST REFUSED: .*No trusted certificate'

echo "== control (a): the verifier trusts a different key than the DID resolves to"
present "$(launch_uri verifier-other.log)" holder-a.log pki/anchor.pem
expect "the holder was not accepted" holder-a.log '^DISPATCH FAILED: the verifier answered 400'
expect "the verifier refused the issuer" verifier-other.log '<- 400 refused: issuer_(key|signature)'
stop_verifier

echo "== the status list on the ledger, decided by polaris_oid4vp.status"
if venv/bin/python "$HERE/ledger.py" status issued.json VALID > status.log 2>&1; then
  echo "  ok    VALID while the credential is current"
else
  echo "  FAIL  the status list did not read VALID (see $WORK/status.log)"; fail=1
fi
sed 's/^/        /' status.log

echo "== control (d): the issuer revokes the credential on the ledger"
walk revoke "$WORK" > revoke.log 2>&1 || { cat revoke.log; fail=1; }
sed -e 's/^\[[^]]*\] /  credo  /' revoke.log
if venv/bin/python "$HERE/ledger.py" status issued.json INVALID > status-revoked.log 2>&1; then
  echo "  ok    INVALID after the revocation"
else
  echo "  FAIL  the status list did not read INVALID (see $WORK/status-revoked.log)"; fail=1
fi
sed 's/^/        /' status-revoked.log

[ "$fail" -eq 0 ] && echo "RESULT: accepted, the status list read VALID, and all four controls refused" || echo "RESULT: FAILED"
exit "$fail"
