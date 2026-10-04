#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# Procivis One Core (holder and issuer) presents an SD-JWT VC that it issued to itself to the
# PUBLISHED polaris-oid4vp, then four controls.
#
# Procivis One Core is built from its source at a pinned commit (there is no public image) with
# cargo, in a Rust image pinned by digest, and runs as one core-server instance with two
# organisations: an issuer and a holder. procivis.py only makes REST calls. Procivis makes the
# issuer's key and CSR, issues the credential over OpenID4VCI and accepts it into its holder,
# resolves the OpenID4VP request (x509_hash, the signed request object) and builds and sends the
# encrypted direct_post.jwt response. The verifier is the only Polaris software in the exchange.
#
#   lab/interop/procivis/run.sh                                     # the newest polaris-oid4vp
#   POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/procivis/run.sh
#
# Exits 0 only if the presentation is accepted AND every control is refused where it should be.
set -euo pipefail

IMAGE="${RUST_IMAGE:-rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1}"
ONE_CORE_TAG=v1.87.2
ONE_CORE_COMMIT=8b701da849c8b9ad8a339c76c5191d69548bffff
# SHA-256 of https://codeload.github.com/procivis/one-core/tar.gz/$ONE_CORE_COMMIT
ONE_CORE_SHA256=c22c5f52d696f12d67e78f525bc29322825b46924c3bef80da95548bc935558f
PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
[ -e "$PKG" ] && PKG="$(cd "$PKG" && pwd)"   # a path to the tree, made absolute
PORT="${PORT:-9484}"
API_PORT="${API_PORT:-9485}"   # core-server's REST API, published on 127.0.0.1 only
JOBS="${CARGO_JOBS:-4}"
CARGO_VOLUME="${CARGO_VOLUME:-polaris-procivis-cargo}"
TARGET_VOLUME="${TARGET_VOLUME:-polaris-procivis-target}"
CONTAINER="polaris-procivis-$PORT"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
export PYTHONDONTWRITEBYTECODE=1  # procivis.py imports pki.py from the tree; leave no __pycache__
ADD_HOST=(--add-host procivis.test:127.0.0.1)
[ "$(uname)" = Linux ] && ADD_HOST+=(--add-host host.docker.internal:host-gateway)

command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { echo "Procivis builds and runs in a Rust image: start Docker" >&2; exit 2; }
for p in "$PORT" "$API_PORT"; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $p is in use; set PORT or API_PORT (keygen writes PORT into the certificate)" >&2
    exit 2
  fi
done

echo "work dir   $WORK"
echo "holder     Procivis One Core $ONE_CORE_TAG ($ONE_CORE_COMMIT), built in $IMAGE"
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

# Procivis One Core at the pinned commit, checked against its hash, built with the lockfile it
# ships (--locked). Cargo's registry, its git checkouts and the target directory are named
# volumes, and the binary is kept in the target volume under the commit and the image, so only
# the first run builds (Procivis's crates embed build information, which rebuilds them on every
# cargo invocation in a tree without .git).
curl -fsSL -o one-core.tar.gz "https://codeload.github.com/procivis/one-core/tar.gz/$ONE_CORE_COMMIT"
venv/bin/python - "$ONE_CORE_SHA256" <<'EOF'
import hashlib, sys
got = hashlib.sha256(open("one-core.tar.gz", "rb").read()).hexdigest()
sys.exit(0 if got == sys.argv[1] else "one-core.tar.gz has SHA-256 %s, not the pinned %s" % (got, sys.argv[1]))
EOF
rm -rf one-core && mkdir one-core && tar xzf one-core.tar.gz -C one-core --strip-components 1
BIN="core-server-$ONE_CORE_COMMIT-$(printf %s "$IMAGE" | venv/bin/python -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest()[:12])')"
started=$(date +%s)
docker run --rm -v "$WORK":/work -w /work/one-core -v "$CARGO_VOLUME":/usr/local/cargo/registry \
  -v "$CARGO_VOLUME-git":/usr/local/cargo/git -v "$TARGET_VOLUME":/target -e CARGO_TARGET_DIR=/target \
  -e APP_VERSION="$ONE_CORE_TAG" "$IMAGE" bash -c '
    if [ ! -x "/target/$0" ]; then
      cargo build --release --locked -j "$1" -p core-server && cp /target/release/core-server "/target/$0" || exit 1
    fi
    cp "/target/$0" /work/core-server' "$BIN" "$JOBS" \
  > build.log 2>&1 || { tail -20 build.log; echo "the build failed; see $WORK/build.log" >&2; exit 2; }
if grep -q 'Finished' build.log; then
  echo "built      core-server in $(( $(date +%s) - started ))s (cargo -j $JOBS)"
else
  echo "built      core-server: the binary built by an earlier run ($TARGET_VOLUME:/$BIN)"
fi

venv/bin/polaris-oid4vp keygen --out pki --host host.docker.internal --port "$PORT" >/dev/null
venv/bin/polaris-oid4vp keygen --out other-pki --host host.docker.internal --port "$PORT" >/dev/null
venv/bin/python "$HERE/pki.py" tls procivis.test procivis-tls
venv/bin/python "$HERE/pki.py" ca "Procivis walk issuer CA" issuer-ca
venv/bin/python "$HERE/pki.py" ca "An unrelated issuer CA" other-issuer-ca
# Fresh secrets for this run only: the API token and the keys Procivis encrypts its key storage
# and its OpenID4VCI state with.
TOKEN=$(venv/bin/python -c 'import secrets; print(secrets.token_hex(16))')
( umask 077; venv/bin/python - "$TOKEN" > procivis.env <<'EOF'
import secrets, sys
print("ONE_app__auth__staticToken=" + sys.argv[1])
print("ONE_keyStorage__INTERNAL__params__private__encryption=" + secrets.token_hex(32))
for protocol in ("OPENID4VCI_FINAL1", "OPENID4VCI_FINAL1_HAIP", "OPENID4VCI_FINAL1_SWIYU"):
    for param in ("encryption", "nonce__signingKey"):
        print("ONE_issuanceProtocol__%s__params__private__%s=%s" % (protocol, param, secrets.token_hex(32)))
EOF
)
mkdir -p data

VERIFIER_PID=""
stop_verifier() {
  if [ -n "$VERIFIER_PID" ]; then
    kill "$VERIFIER_PID" 2>/dev/null || true
    wait "$VERIFIER_PID" 2>/dev/null || true
    VERIFIER_PID=""
  fi
}
stop_holder() {
  docker logs "$CONTAINER" >> procivis.log 2>&1 || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap 'stop_verifier; stop_holder' EXIT

start_holder() {  # $1 the certificate the holder trusts for the verifier's TLS listener
  # core-server, with tls_front.py terminating TLS for its base URL (https://procivis.test, which
  # resolves to the container itself). The holder's TLS trust is the system store: the
  # certificate for procivis.test and the one named here, nothing else added.
  stop_holder
  docker run -d --name "$CONTAINER" -p "127.0.0.1:$API_PORT:3000" "${ADD_HOST[@]}" \
    --env-file procivis.env -v "$WORK":/work -v "$WORK/data":/data -v "$HERE":/walk:ro "$IMAGE" bash -c '
      cp /work/procivis-tls.pem /usr/local/share/ca-certificates/procivis-tls.crt
      cp "/work/$0" /usr/local/share/ca-certificates/verifier-tls.crt
      update-ca-certificates >/dev/null 2>&1
      python3 /walk/tls_front.py /work/procivis-tls.pem /work/procivis-tls-key.pem 443 3000 &
      cd /work/one-core && exec /work/core-server -c config/config-procivis-base.yml -c /walk/procivis.yml' \
    "$1" >/dev/null
  for _ in $(seq 1 120); do
    docker logs "$CONTAINER" 2>&1 | grep -q 'Starting server at' && return 0
    sleep 0.5
  done
  docker logs "$CONTAINER" 2>&1 | tail -20
  echo "core-server did not start" >&2
  exit 2
}

start_verifier() {  # $1 issuer trust anchor, $2 log
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host host.docker.internal \
    --bind 0.0.0.0 --port "$PORT" --issuer-trust-anchor "$1" --once --verbose > "$2" 2>&1 &
  VERIFIER_PID=$!
  for _ in $(seq 1 240); do grep -q 'state=' "$2" 2>/dev/null && return 0; sleep 0.25; done
  echo "verifier did not start; see $WORK/$2" >&2
  exit 2
}

launch_uri() {  # $1 log file, $2 scheme (openid4vp or haip-vp), $3 optional client_id override
  venv/bin/python - "$1" "$2" "${3:-}" <<'EOF'
import re, sys, urllib.parse
log = open(sys.argv[1]).read()
cid = sys.argv[3] or re.search(r"x509_hash:[A-Za-z0-9_-]+", log).group(0)
ruri = re.findall(r"https://\S+request\.jwt\?state=[A-Za-z0-9_-]+", log)[-1]
print(sys.argv[2] + "://authorize?" + urllib.parse.urlencode(
    {"client_id": cid, "request_uri": ruri, "request_uri_method": "post"}))
EOF
}

present() {  # $1 launch URI, $2 holder log
  venv/bin/python "$HERE/procivis.py" present "http://127.0.0.1:$API_PORT" "$TOKEN" state.json "$1" \
    > "$2" 2>&1 || true
  sleep 1  # the verifier logs its verdict after it answers
}

fail=0
expect() {  # $1 label, $2 file, $3 pattern that must appear
  if grep -qE "$3" "$2"; then echo "  ok    $1"; else echo "  FAIL  $1 (no /$3/ in $2)"; fail=1; fi
}

echo "== issuance: Procivis's issuer offers the credential, its holder accepts it"
start_holder pki/tls.pem
venv/bin/python "$HERE/procivis.py" issue "http://127.0.0.1:$API_PORT" "$TOKEN" state.json issuer-ca \
  procivis.test | tee issuance.log
expect "the holder stored the credential" issuance.log '^ISSUED .*state ACCEPTED'

echo "== genuine presentation, openid4vp:// (Procivis's OPENID4VP_FINAL1 profile)"
start_verifier issuer-ca.pem verifier.log
present "$(launch_uri verifier.log openid4vp)" holder.log
expect "the holder dispatched" holder.log '^DISPATCHED'
expect "the verifier accepted it" verifier.log '<- 200 authentic'
{ grep -E '<- 200' verifier.log || true; } | sed 's/^/        /'
stop_verifier

echo "== genuine presentation, haip-vp:// (Procivis's OPENID4VP_FINAL1_HAIP profile)"
start_verifier issuer-ca.pem verifier-haip.log
URI=$(launch_uri verifier-haip.log haip-vp)
present "$URI" holder-haip.log
expect "the holder dispatched, under the HAIP profile" holder-haip.log '^REQUEST .*OPENID4VP_FINAL1_HAIP'
expect "the verifier accepted it" verifier-haip.log '<- 200 authentic'
{ grep -E '<- 200' verifier-haip.log || true; } | sed 's/^/        /'

echo "== control (b): the same request again, after it was answered"
present "$URI" holder-replay.log
expect "refused at the request stage" holder-replay.log '^REQUEST REFUSED.*404'
stop_verifier

echo "== control (c): a launch URI whose client_id is not the signed request's"
start_verifier other-issuer-ca.pem verifier-other.log
present "$(launch_uri verifier-other.log haip-vp x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)" holder-c.log
expect "the holder refused the request" holder-c.log '^REQUEST REFUSED.*client_id mismatch'

echo "== control (a): the verifier trusts a different issuer CA"
present "$(launch_uri verifier-other.log haip-vp)" holder-a.log
expect "the holder was not accepted" holder-a.log '^DISPATCH FAILED'
expect "the verifier refused the issuer" verifier-other.log '<- 400 refused: issuer_key'
stop_verifier

echo "== control (d): the holder trusts an unrelated certificate for the verifier's TLS"
start_holder other-pki/tls.pem
start_verifier issuer-ca.pem verifier-d.log
present "$(launch_uri verifier-d.log haip-vp)" holder-d.log
docker logs "$CONTAINER" > holder-d-server.log 2>&1 || true
expect "the holder refused the request" holder-d.log '^REQUEST REFUSED.*error sending request'
expect "because the listener's certificate did not verify" holder-d-server.log 'failed to verify TLS certificate'
stop_verifier

[ "$fail" -eq 0 ] && echo "RESULT: accepted, and all four controls refused" || echo "RESULT: FAILED"
exit "$fail"
