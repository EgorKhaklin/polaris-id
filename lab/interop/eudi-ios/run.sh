#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# A wallet on the EU reference OpenID4VP library for iOS presents an SD-JWT VC to the PUBLISHED
# polaris-oid4vp, then four controls.
#
# The wallet (wallet/) is a small Swift program on eudi-lib-ios-openid4vp-swift, the OpenID4VP
# library of the EUDI iOS wallet kit: it resolves the request (x509_hash, the signed request object
# fetched by POST with wallet metadata) and dispatches the encrypted direct_post.jwt response. The
# presentation is built with eudi-lib-sdjwt-swift, as the wallet kit builds one. SwiftPM builds it
# from the commits wallet/Package.resolved pins. It needs macOS: the library is built on Apple's
# Security framework and CryptoKit. The holder key is made here and the credential bound to it by
# ../waltid/issue_sdjwt_vc.py.
#
#   lab/interop/eudi-ios/run.sh                                     # the newest polaris-oid4vp
#   POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/eudi-ios/run.sh
#
# Exits 0 only if the presentation is accepted AND every control is refused where it should be.
set -euo pipefail

PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
PORT="${PORT:-9483}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
ISSUER="$HERE/../waltid/issue_sdjwt_vc.py"

[ "$(uname)" = Darwin ] || { echo "the wallet needs macOS (Apple's Security framework and CryptoKit)" >&2; exit 2; }
command -v swift >/dev/null 2>&1 || { echo "the wallet is built with SwiftPM: install Swift 6.2 or newer" >&2; exit 2; }
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $PORT is in use; set PORT (keygen writes it into the certificate)" >&2
  exit 2
fi

echo "work dir   $WORK"
echo "wallet     eudi-lib-ios-openid4vp-swift (wallet/Package.swift), $(swift --version 2>/dev/null | grep -o 'Swift version [0-9.]*')"
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

# The wallet, built from a copy of the package so the tree stays clean. --force-resolved-versions
# builds exactly the commits Package.resolved pins and fails if the manifest asks for anything else.
# WALLET_BUILD names a build directory to reuse between runs (a first build takes minutes).
rm -rf wallet && mkdir wallet
cp -R "$HERE/wallet/Package.swift" "$HERE/wallet/Package.resolved" "$HERE/wallet/Sources" wallet/
BUILD="${WALLET_BUILD:-$WORK/wallet-build}"
swift build --package-path wallet --scratch-path "$BUILD" -c release --force-resolved-versions \
  > build.log 2>&1 || { tail -20 build.log >&2; echo "the wallet did not build; see $WORK/build.log" >&2; exit 2; }
WALLET="$(swift build --package-path wallet --scratch-path "$BUILD" -c release --show-bin-path)/polaris-eudi-ios-wallet"
pinned() {  # $1 a package identity in Package.resolved
  venv/bin/python -c 'import json, sys
print(next(p["state"]["version"] for p in json.load(open("wallet/Package.resolved"))["pins"] if p["identity"] == sys.argv[1]))' "$1"
}
echo "built      eudi-lib-ios-openid4vp-swift $(pinned eudi-lib-ios-openid4vp-swift), eudi-lib-sdjwt-swift $(pinned eudi-lib-sdjwt-swift)"

venv/bin/polaris-oid4vp keygen --out pki --host localhost --port "$PORT" >/dev/null
venv/bin/polaris-oid4vp keygen --out other-pki --host localhost --port "$PORT" >/dev/null
venv/bin/python - <<'EOF'
import base64, json
from cryptography.hazmat.primitives.asymmetric import ec
k = ec.generate_private_key(ec.SECP256R1()); n = k.private_numbers(); p = n.public_numbers
b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")
pub = {"kty": "EC", "crv": "P-256", "x": b(p.x), "y": b(p.y)}
json.dump(dict(pub, d=b(n.private_value)), open("holder-key.json", "w"))
json.dump({"holder_jwk": pub}, open("holder.json", "w"))
EOF
venv/bin/python "$ISSUER" --holder-jwk holder.json --out credential.json >/dev/null
venv/bin/python - <<'EOF'
import base64, json
from cryptography.hazmat.primitives.asymmetric import ec
d = json.load(open("credential.json"))
open("credential.txt", "w").write(d["credential"])
json.dump(d["issuer_jwks"], open("issuer-jwks.json", "w"))
# Control (a): a different key under the SAME kid, so only the signature can tell them apart.
n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")
json.dump([{"kty": "EC", "crv": "P-256", "x": b(n.x), "y": b(n.y), "kid": d["issuer_jwks"][0]["kid"]}],
          open("issuer-jwks-other.json", "w"))
EOF

VERIFIER_PID=""
stop_verifier() {
  if [ -n "$VERIFIER_PID" ]; then
    kill "$VERIFIER_PID" 2>/dev/null || true
    wait "$VERIFIER_PID" 2>/dev/null || true
    VERIFIER_PID=""
  fi
}
trap stop_verifier EXIT

start_verifier() {  # $1 issuer JWKS, $2 log
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host localhost \
    --bind 127.0.0.1 --port "$PORT" --issuer-jwks "$1" --once > "$2" 2>&1 &
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

present() {  # $1 launch URI, $2 wallet log, $3 the anchor the wallet trusts for the verifier
  # The listener's self-signed certificate is pinned by the wallet's own URLSession, for this
  # session only: the TLS registration a counterparty makes for a test verifier.
  "$WALLET" "$1" credential.txt holder-key.json "$3" pki/tls.pem > "$2" 2>&1 || true
  sleep 1  # the verifier logs its verdict after it answers
}

fail=0
expect() {  # $1 label, $2 file, $3 pattern that must appear
  if grep -qE "$3" "$2"; then echo "  ok    $1"; else echo "  FAIL  $1 (no /$3/ in $2)"; fail=1; fi
}

echo "== genuine presentation"
start_verifier issuer-jwks.json verifier.log
URI=$(launch_uri verifier.log)
present "$URI" wallet.log pki/anchor.pem
expect "the wallet fetched the request object by POST" wallet.log 'POST /request\.jwt <- 200'
expect "the wallet dispatched and the verifier accepted" wallet.log '^DISPATCHED Accepted'
expect "the verifier accepted it" verifier.log '<- 200 authentic'
{ grep -E '<- 200' verifier.log || true; } | sed 's/^/        /'

echo "== control (b): the same request again, after it was answered"
present "$URI" wallet-replay.log pki/anchor.pem
expect "the verifier refused the request object" wallet-replay.log 'POST /request\.jwt <- 404'
expect "the wallet stopped there" wallet-replay.log '^REQUEST REFUSED'
stop_verifier

echo "== control (c): a launch URI whose client_id is not the signed request's"
start_verifier issuer-jwks-other.json verifier-other.log
present "$(launch_uri verifier-other.log x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)" wallet-c.log pki/anchor.pem
expect "the wallet refused the request" wallet-c.log '^REQUEST REFUSED.*client_id[^ ]* do not match'

echo "== control (d): the wallet trusts an unrelated CA for the verifier"
present "$(launch_uri verifier-other.log)" wallet-d.log other-pki/anchor.pem
expect "the wallet refused the request" wallet-d.log '^REQUEST REFUSED.*Could not trust certificate chain'

echo "== control (a): the verifier trusts a different issuer key under the same kid"
present "$(launch_uri verifier-other.log)" wallet-a.log pki/anchor.pem
expect "the wallet was not accepted" wallet-a.log '^(DISPATCHED Rejected|DISPATCH FAILED)'
expect "the verifier refused the issuer" verifier-other.log '<- 400 refused: issuer_signature'
stop_verifier

[ "$fail" -eq 0 ] && echo "RESULT: accepted, and all four controls refused" || echo "RESULT: FAILED"
exit "$fail"
