#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# SpruceID's OpenID4VP library, through the headless wallet in its own repository, presents an
# SD-JWT VC to the PUBLISHED polaris-oid4vp, then three controls.
#
# The wallet is examples/wallet-conformance-adapter from github.com/spruceid/openid4vp, the HTTP
# wallet its authors point the OpenID Foundation's wallet test plan at. It is fetched at a pinned
# commit and built in a Rust image pinned by digest. The library resolves the request (x509_hash,
# the signed request object fetched by GET); the adapter re-signs the credential it embeds (typ
# dc+sd-jwt, x5c), adds a key binding JWT, and the library encrypts the direct_post.jwt response.
# Two of the adapter's fixtures are replaced before the build, and nothing else: its issuer key and
# certificate, by ones under a CA made here (polaris-oid4vp trusts that CA, --issuer-trust-anchor),
# and its credential's type, urn:eudi:pid:1, the type the published verifier asks for.
#
#   lab/interop/spruceid/run.sh                                     # the newest polaris-oid4vp
#   POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/spruceid/run.sh
#
# Exits 0 only if the presentation is accepted AND every control is refused where it should be.
set -euo pipefail

IMAGE="${RUST_IMAGE:-rust:1.99.0-bookworm@sha256:59037199c44290f2befcdd58dcc540164763fc296950255aaefeef096a1866b0}"
COMMIT="${SPRUCEID_COMMIT:-e5f29b85f14ca0b3c6eb6852e4d2d158f601fd63}"
PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
PORT="${PORT:-9481}"
WALLET_PORT="${WALLET_PORT:-9482}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
WALLET=polaris-spruceid-wallet
ADAPTER=examples/wallet-conformance-adapter
ADD_HOST=()
[ "$(uname)" = Linux ] && ADD_HOST=(--add-host host.docker.internal:host-gateway)

command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { echo "the wallet is built and run in a Rust image: start Docker" >&2; exit 2; }
for p in "$PORT" "$WALLET_PORT"; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $p is in use; set PORT / WALLET_PORT" >&2
    exit 2
  fi
done

echo "work dir   $WORK"
echo "wallet     github.com/spruceid/openid4vp $COMMIT, $ADAPTER, in $IMAGE"
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

# The adapter's source at exactly $COMMIT (a full hash), fetched by that hash.
rm -rf spruceid && git init -q spruceid
git -C spruceid fetch -q --depth 1 https://github.com/spruceid/openid4vp.git "$COMMIT"
git -C spruceid -c advice.detachedHead=false checkout -q FETCH_HEAD
[ "$(git -C spruceid rev-parse HEAD)" = "$COMMIT" ] || { echo "fetched the wrong commit" >&2; exit 2; }

# The two fixtures. The adapter signs its credential with an issuer key and certificate compiled
# into crypto/issuer.rs. That certificate names no issuer (it has no subjectAltName) while the
# credential says iss https://issuer.example.com, which the verifier refuses (issuer_key, see the
# README), and a certificate that does name it needs the adapter's CA key, which is not published.
# So: a CA made here, an issuer key, and a certificate naming the credential's own iss, written
# into the two constants. And the credential's vct, in credentials.json and in the issuer payload
# the adapter re-signs: 1.0.0rc15 asks for urn:eudi:pid:1, and the adapter selects by type.
venv/bin/python - "spruceid/$ADAPTER" <<'EOF'
import base64, datetime, pathlib, re, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

adapter = pathlib.Path(sys.argv[1])
now = datetime.datetime.now(datetime.timezone.utc)
day = datetime.timedelta(days=1)
DER, PEM = serialization.Encoding.DER, serialization.Encoding.PEM

def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

def make_ca(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - day).not_valid_after(now + 30 * day)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                           critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert

creds = adapter / "credentials.json"
text = creds.read_text()
old_vct, new_vct = "https://credentials.example.com/pid/1.0", "urn:eudi:pid:1"
raw = re.search(r'"raw_credential": "([^"]+)"', text).group(1)
payload_b64 = raw.split("~")[0].split(".")[1]
payload = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)).decode()
iss = re.search(r'"iss":"([^"]+)"', payload).group(1)

ca_key, ca = make_ca("issuer test CA (lab/interop/spruceid)")
_, other = make_ca("unrelated issuer test CA (lab/interop/spruceid)")
key = ec.generate_private_key(ec.SECP256R1())
leaf = (x509.CertificateBuilder().subject_name(name("test issuer (lab/interop/spruceid)"))
        .issuer_name(ca.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - day).not_valid_after(now + 30 * day)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                       critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(iss)]),
                       critical=False)
        .sign(ca_key, hashes.SHA256()))
pathlib.Path("issuer-ca.pem").write_bytes(ca.public_bytes(PEM))
# Control (a): a CA that signed nothing here.
pathlib.Path("other-ca.pem").write_bytes(other.public_bytes(PEM))

rs = adapter / "crypto" / "issuer.rs"
src = rs.read_text()
for const, value in (
        ("ISSUER_KEY_PKCS8_B64", key.private_bytes(DER, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption())),
        ("ISSUER_LEAF_DER_B64", leaf.public_bytes(DER))):
    src, n = re.subn(r'(const %s: &str = ")[^"]+(";)' % const,
                     lambda m: m.group(1) + base64.b64encode(value).decode() + m.group(2), src)
    assert n == 1, const
rs.write_text(src)

assert payload.count('"vct":"%s"' % old_vct) == 1 and text.count('"vct": "%s"' % old_vct) == 1
new_payload = payload.replace('"vct":"%s"' % old_vct, '"vct":"%s"' % new_vct)
new_payload_b64 = base64.urlsafe_b64encode(new_payload.encode()).decode().rstrip("=")
assert text.count(payload_b64) == 1
creds.write_text(text.replace(payload_b64, new_payload_b64)
                 .replace('"vct": "%s"' % old_vct, '"vct": "%s"' % new_vct))
EOF
changed="$(git -C spruceid diff --name-only | tr '\n' ' ')"
[ "$changed" = "$ADAPTER/credentials.json $ADAPTER/crypto/issuer.rs " ] || {
  echo "the adapter changed beyond its two fixtures: $changed" >&2; exit 2; }
echo "changed   $(git -C spruceid diff --shortstat): issuer key and certificate, credential vct"

# Built in the pinned image. The library commits no lock file and neither does this walk (see the
# README), so Cargo resolves the newest releases its manifests allow. The registry and the build
# are named volumes, so a later run recompiles only the library's own crates and the adapter.
SECONDS=0
docker run --rm -v "$WORK":/w -w /w/spruceid -e CARGO_TARGET_DIR=/target \
  -v polaris-cargo-registry:/usr/local/cargo/registry -v polaris-cargo-git:/usr/local/cargo/git \
  -v polaris-spruceid-target:/target "$IMAGE" bash -c \
  'cargo build -q --example wallet-conformance-adapter && cp /target/debug/examples/wallet-conformance-adapter /w/adapter'
echo "built      $ADAPTER in ${SECONDS}s"

venv/bin/polaris-oid4vp keygen --out pki --host host.docker.internal --port "$PORT" >/dev/null

VERIFIER_PID=""
stop_verifier() {
  if [ -n "$VERIFIER_PID" ]; then
    kill "$VERIFIER_PID" 2>/dev/null || true
    wait "$VERIFIER_PID" 2>/dev/null || true
    VERIFIER_PID=""
  fi
}
stop_all() {
  stop_verifier
  docker logs "$WALLET" > wallet-adapter.log 2>&1 || true
  docker rm -f "$WALLET" >/dev/null 2>&1 || true
}
trap stop_all EXIT

# The adapter fetches the request object with the library's HTTP client, rustls with the public
# web roots compiled in, and refuses keygen's self-signed listener certificate whatever the
# container trusts. So the verifier serves plain HTTP to it on the Docker host; the request object
# is still signed and checked, and the response still encrypted to the verifier's key.
start_verifier() {  # $1 issuer trust anchor, $2 log
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host host.docker.internal \
    --bind 0.0.0.0 --port "$PORT" --no-local-tls --public-base-url "http://host.docker.internal:$PORT" \
    --issuer-trust-anchor "$1" --once > "$2" 2>&1 &
  VERIFIER_PID=$!
  for _ in $(seq 1 40); do grep -q 'state=' "$2" 2>/dev/null && return 0; sleep 0.25; done
  echo "verifier did not start; see $WORK/$2" >&2
  exit 2
}

docker rm -f "$WALLET" >/dev/null 2>&1 || true
docker run -d --name "$WALLET" ${ADD_HOST[@]+"${ADD_HOST[@]}"} -p "127.0.0.1:$WALLET_PORT:3000" \
  -v "$WORK":/w "$IMAGE" /w/adapter --port 3000 --public-url "http://localhost:$WALLET_PORT" >/dev/null
for _ in $(seq 1 40); do curl -fs "http://127.0.0.1:$WALLET_PORT/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -fs "http://127.0.0.1:$WALLET_PORT/health" >/dev/null || { echo "the wallet did not start; see docker logs $WALLET" >&2; exit 2; }

authorize() {  # $1 verifier log, $2 optional client_id, $3 output file: the wallet's answer
  local q code
  q=$(venv/bin/python - "$1" "${2:-}" <<'EOF'
import re, sys, urllib.parse
log = open(sys.argv[1]).read()
cid = sys.argv[2] or re.search(r"x509_hash:[A-Za-z0-9_-]+", log).group(0)
ruri = re.findall(r"https?://\S+request\.jwt\?state=[A-Za-z0-9_-]+", log)[-1]
print(urllib.parse.urlencode({"client_id": cid, "request_uri": ruri}))
EOF
)
  code=$(curl -s -o "$3" -w "%{http_code}" "http://127.0.0.1:$WALLET_PORT/authorize?$q" || true)
  printf '\nHTTP %s\n' "$code" >> "$3"
  sleep 1  # the verifier logs its verdict after it answers
}

fail=0
expect() {  # $1 label, $2 file, $3 pattern that must appear
  if grep -qE "$3" "$2"; then echo "  ok    $1"; else echo "  FAIL  $1 (no /$3/ in $2)"; fail=1; fi
}

echo "== genuine presentation"
start_verifier issuer-ca.pem verifier.log
authorize verifier.log "" wallet.out
expect "the wallet reports the response was taken" wallet.out '^HTTP 200$'
expect "the verifier accepted it" verifier.log '<- 200 authentic'
{ grep -E '<- 200' verifier.log || true; } | sed 's/^/        /'

echo "== control (b): the same request again, after it was answered"
authorize verifier.log "" replay.out
expect "refused at the request stage" replay.out 'no such outstanding request'
stop_verifier

echo "== control (c): a launch whose client_id is not the signed request's"
start_verifier other-ca.pem verifier-other.log
authorize verifier-other.log x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA mismatch.out
expect "the wallet refused the request" mismatch.out 'different client ids'
if grep -q '<- ' verifier-other.log; then echo "  FAIL  the verifier received a response"; fail=1
else echo "  ok    nothing reached the verifier"; fi

echo "== control (a): the verifier trusts an unrelated issuer CA"
authorize verifier-other.log "" other.out
expect "the wallet was told it was not accepted" other.out 'verifier_error'
expect "the verifier refused the issuer" verifier-other.log '<- 400 refused: issuer_key'
stop_verifier

[ "$fail" -eq 0 ] && echo "RESULT: accepted, and all three controls refused" || echo "RESULT: FAILED"
exit "$fail"
