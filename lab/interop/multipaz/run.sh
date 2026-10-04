#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# A wallet on Multipaz presents an SD-JWT VC to the PUBLISHED polaris-oid4vp, then three controls.
#
# The wallet (wallet/) is a small Kotlin program on org.multipaz:multipaz, the OpenWallet
# Foundation's identity credential library, on its JVM target. Multipaz's uriSchemePresentment()
# fetches the signed request object (x509_hash, by POST), matches the DCQL query, builds the
# presentation with a key binding JWT and posts the encrypted direct_post.jwt response; its trust
# manager decides whether the verifier is trusted. The wallet is compiled and run in a JDK image
# pinned by digest, with every dependency checked against wallet/gradle/verification-metadata.xml.
# The holder key is made here and the credential bound to it by ../waltid/issue_sdjwt_vc.py --x5c,
# under an issuer CA the verifier trusts (--issuer-trust-anchor).
#
#   lab/interop/multipaz/run.sh                                     # the newest polaris-oid4vp
#   POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/multipaz/run.sh
#
# Exits 0 only if the presentation is accepted AND every control is refused where it should be.
set -euo pipefail

IMAGE="${JDK_IMAGE:-gradle:8.14.3-jdk21@sha256:21bd311ed01360c189b8870c6b6e988199ff10f72d445d02fb39d3cff9da91d7}"
PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
PORT="${PORT:-9489}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
ISSUER="$HERE/../waltid/issue_sdjwt_vc.py"
WALLET=/in/wallet/build/install/polaris-multipaz-wallet/bin/polaris-multipaz-wallet
ADD_HOST=()
[ "$(uname)" = Linux ] && ADD_HOST=(--add-host host.docker.internal:host-gateway)
# A local path (a tree checkout, a wheel) is resolved before the cd below.
[ -e "$PKG" ] && PKG="$(cd "$(dirname "$PKG")" && pwd)/$(basename "$PKG")"

command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { echo "the wallet runs in a JDK image: start Docker" >&2; exit 2; }
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $PORT is in use; set PORT (keygen writes it into the certificate)" >&2
  exit 2
fi

echo "work dir   $WORK"
echo "wallet     org.multipaz:multipaz (wallet/build.gradle.kts), in $IMAGE"
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

# The wallet, built once into a copy of wallet/ so the tree stays clean; Gradle's own cache is a
# named volume so a second run does not download again.
rm -rf wallet && cp -R "$HERE/wallet" wallet
docker run --rm -v "$WORK/wallet":/w -w /w -v polaris-gradle-cache:/home/gradle/.gradle "$IMAGE" \
  gradle --no-daemon -q installDist >/dev/null
echo "built      $(ls wallet/build/install/*/lib/multipaz-jvm-*.jar | xargs -n1 basename)"

venv/bin/polaris-oid4vp keygen --out pki --host host.docker.internal --port "$PORT" >/dev/null
venv/bin/polaris-oid4vp keygen --out other-pki --host host.docker.internal --port "$PORT" >/dev/null
# Multipaz's trust manager finds a verifier's CA by key identifier: the CA's Subject Key Identifier
# against the Authority Key Identifier of the certificate it signed, the identifiers RFC 5280 has
# a conforming CA put in both. keygen's test certificates carried neither until the tree's fix of
# 2026-10-04, so for a release without it this re-issues each pair under a new CA key (keygen keeps
# none) with them added: the same leaf key, names, validity and extensions as keygen wrote. A keygen
# that writes them is used as written.
venv/bin/python - <<'EOF'
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
for d in ("pki", "other-pki"):
    old_ca = x509.load_pem_x509_certificate(open(d + "/anchor.pem", "rb").read())
    old_leaf = x509.load_pem_x509_certificate(open(d + "/client.pem", "rb").read())
    try:
        old_ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        old_leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        print("pki        %s: keygen's certificates carry key identifiers, used as written" % d)
        continue
    except x509.ExtensionNotFound:
        print("pki        %s: re-issued with key identifiers (this keygen writes none)" % d)
    leaf_key = serialization.load_pem_private_key(open(d + "/client-key.pem", "rb").read(), None)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    def reissue(old, subject_key, ids):
        b = (x509.CertificateBuilder().subject_name(old.subject).issuer_name(old_ca.subject)
             .public_key(subject_key).serial_number(x509.random_serial_number())
             .not_valid_before(old.not_valid_before_utc).not_valid_after(old.not_valid_after_utc))
        for ext in list(old.extensions) + ids:
            b = b.add_extension(ext.value, ext.critical)
        return b.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    ca = reissue(old_ca, ca_key.public_key(), [x509.Extension(ski.oid, False, ski)])
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
    leaf = reissue(old_leaf, leaf_key.public_key(), [x509.Extension(aki.oid, False, aki)])
    open(d + "/anchor.pem", "wb").write(ca)
    open(d + "/client.pem", "wb").write(leaf)
EOF

venv/bin/python - <<'EOF'
import base64, json
from cryptography.hazmat.primitives.asymmetric import ec
k = ec.generate_private_key(ec.SECP256R1()); n = k.private_numbers(); p = n.public_numbers
b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")
pub = {"kty": "EC", "crv": "P-256", "x": b(p.x), "y": b(p.y)}
json.dump(dict(pub, d=b(n.private_value)), open("holder-key.json", "w"))
json.dump({"holder_jwk": pub}, open("holder.json", "w"))
EOF
# --x5c: the issuer key is certified in the credential's x5c header, chaining to a CA made for
# this run, which the verifier trusts (--issuer-trust-anchor). Multipaz reads a credential's
# claims only through an issuer key named that way.
venv/bin/python "$ISSUER" --holder-jwk holder.json --x5c --out credential.json >/dev/null
venv/bin/python - <<'EOF'
import datetime, json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
d = json.load(open("credential.json"))
open("credential.txt", "w").write(d["credential"])
open("issuer-ca.pem", "w").write(d["issuer_ca_pem"])
# Control (a): a different CA under the SAME name, so only its key can tell them apart.
ca = x509.load_pem_x509_certificate(d["issuer_ca_pem"].encode())
key = ec.generate_private_key(ec.SECP256R1())
now = datetime.datetime.now(datetime.timezone.utc)
b = (x509.CertificateBuilder().subject_name(ca.subject).issuer_name(ca.subject)
     .public_key(key.public_key()).serial_number(x509.random_serial_number())
     .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30)))
for ext in ca.extensions:
    if not isinstance(ext.value, x509.SubjectKeyIdentifier):
        b = b.add_extension(ext.value, ext.critical)
b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
open("issuer-ca-other.pem", "wb").write(b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
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

start_verifier() {  # $1 the issuer CA the verifier trusts, $2 log
  # --verbose logs each request's method and path, which shows how the wallet fetched the request.
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host host.docker.internal \
    --bind 0.0.0.0 --port "$PORT" --issuer-trust-anchor "$1" --once --verbose > "$2" 2>&1 &
  VERIFIER_PID=$!
  for _ in $(seq 1 240); do grep -q 'state=' "$2" 2>/dev/null && return 0; sleep 0.25; done
  echo "verifier did not start within 60 s; see $WORK/$2" >&2
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

present() {  # $1 launch URI, $2 wallet log, $3 the anchor the wallet trusts for the verifier
  # The listener's self-signed certificate goes into the JDK's trust store: the TLS registration
  # a counterparty makes for a test verifier, as walt.id's walk does. The JDK's HTTP client logs
  # each request and the status it got back.
  docker run --rm ${ADD_HOST[@]+"${ADD_HOST[@]}"} -e JAVA_OPTS=-Djdk.httpclient.HttpClient.log=requests \
    -v "$WORK":/in "$IMAGE" bash -c \
    'keytool -importcert -cacerts -storepass changeit -noprompt -alias polaris-listener -file /in/pki/tls.pem >/dev/null 2>&1 && '"$WALLET"' "$0" /in/credential.txt /in/holder-key.json "$1"' \
    "$1" "/in/$3" > "$2" 2>&1 || true
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
expect "the wallet trusted the verifier" wallet.log '^TRUST trusted'
expect "the wallet fetched the request by POST" verifier.log '^POST /request\.jwt'
expect "the wallet dispatched and the verifier answered 200" wallet.log '^DISPATCHED'
expect "the verifier accepted it" verifier.log '<- 200 authentic'
{ grep -E '<- 200' verifier.log || true; } | sed 's/^/        /'

echo "== control (b): the same request again, after it was answered"
present "$URI" wallet-replay.log pki/anchor.pem
expect "refused at the request stage" wallet-replay.log '^REQUEST REFUSED while fetching the request'
stop_verifier

echo "== control (c): the wallet trusts an unrelated CA for the verifier"
start_verifier issuer-ca-other.pem verifier-other.log
present "$(launch_uri verifier-other.log)" wallet-c.log other-pki/anchor.pem
expect "Multipaz's trust manager did not trust it" wallet-c.log '^TRUST not trusted'
expect "the wallet refused the request" wallet-c.log '^REQUEST REFUSED the verifier is not trusted'

echo "== control (a): the verifier trusts a different issuer CA under the same name"
present "$(launch_uri verifier-other.log)" wallet-a.log pki/anchor.pem
expect "the wallet was not accepted" wallet-a.log '^DISPATCH FAILED'
expect "the verifier refused the issuer" verifier-other.log '<- 400 refused: issuer_key'
stop_verifier

[ "$fail" -eq 0 ] && echo "RESULT: accepted, and all three controls refused" || echo "RESULT: FAILED"
exit "$fail"
