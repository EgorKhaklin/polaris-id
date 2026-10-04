#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ERICA, the German EUDI Wallet programme's local verifier testing tool, acts as the wallet against
# the PUBLISHED polaris-oid4vp: its checks on the request, a genuine presentation, its negative
# modes, and controls.
#
# ERICA (gitlab.opencode.de/bmi/eudi-wallet/erica) is built from a pinned commit with its own
# Dockerfile and lockfiles, the node base image pinned by digest through a named build context,
# and driven over the HTTP API its web UI calls (drive.py): ERICA fetches the request object,
# validates it against its PID presentation profile, simulates the wallet in one mode and posts
# the encrypted direct_post.jwt response. Its PID is urn:eudi:pid:de:1, which the verifier is
# asked for with --vct (the tree has it; 1.0.0rc15 asks for urn:eudi:pid:1 and has no --vct).
#
#   POLARIS_OID4VP="$PWD/packages/polaris-oid4vp" lab/interop/erica/run.sh   # the tree
#   lab/interop/erica/run.sh                                  # the newest polaris-oid4vp on PyPI
#
# Exits 0 only if the presentation is accepted AND every negative case is refused where it should be.
set -euo pipefail

ERICA_REPO="${ERICA_REPO:-https://gitlab.opencode.de/bmi/eudi-wallet/erica.git}"
ERICA_COMMIT="${ERICA_COMMIT:-2c27dc9254d7fc97c20ac4677747014519aa48ba}"
NODE_IMAGE="${NODE_IMAGE:-node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402}"
PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
PORT="${PORT:-9486}"
ERICA_PORT="${ERICA_PORT:-$((PORT + 1))}"   # and ERICA_PORT + 1 for the second instance
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
VCT="urn:eudi:pid:de:1"
VHOST="polaris-verifier.test"
NAME="polaris-erica-$PORT"
NET="198.18.$((PORT % 256))"   # RFC 2544 test range: outside the ranges ERICA refuses to fetch from
IMAGE="polaris-lab/erica:${ERICA_COMMIT:0:12}"
ADD_HOST=()
[ "$(uname)" = Linux ] && ADD_HOST=(--add-host host.docker.internal:host-gateway)
[ -e "$PKG" ] && PKG="$(cd "$PKG" && pwd)"   # a tree path, absolute before the cd below

command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { echo "ERICA runs in Docker: start it" >&2; exit 2; }
for p in "$PORT" "$ERICA_PORT" "$((ERICA_PORT + 1))"; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $p is in use; set PORT (keygen writes it into the certificate) or ERICA_PORT" >&2
    exit 2
  fi
done

echo "work dir   $WORK"
echo "wallet     ERICA $ERICA_COMMIT ($ERICA_REPO)"
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
VCT_ARGS=()
CLAIMS=no
SERVE_HELP="$(venv/bin/polaris-oid4vp serve --help)"   # captured: grep -q in a pipe trips pipefail
case "$SERVE_HELP" in
  *--vct*) VCT_ARGS=(--vct "$VCT") ;;
  *) echo "           this polaris-oid4vp has no --vct: it asks for urn:eudi:pid:1, and ERICA's $VCT is refused" ;;
esac
# A verifier with --verifier-info (the tree since 2026-10-04) also refuses a presentation that
# discloses claims the request did not select (OpenID4VP 1.0 6.4); with it the validation step
# carries a registration certificate and OVER_DISCLOSURE joins the modes that must be refused.
case "$SERVE_HELP" in
  *--verifier-info*)
    NEWER=1
    venv/bin/python - verifier-info.json "${VCT}" <<'EOF'
import base64, datetime, json, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID
b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
# A registrar made for this run: ERICA trusts no registrar it was not given, so the certificate
# shows the request carries one, not that anyone registered this verifier.
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Polaris lab test registrar")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
header = {"alg": "ES256", "typ": "rc-wrp+jwt",
          "x5c": [base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()]}
payload = {"name": "Polaris lab walk", "sub": "polaris-lab", "iat": int(now.timestamp()),
           "purpose": [{"lang": "en", "value": "Interoperability testing"}],
           "credentials": [{"format": "dc+sd-jwt", "meta": {"vct_values": [sys.argv[2]]},
                            "claim": [{"path": ["given_name"]}, {"path": ["family_name"]}]}]}
signing_input = b64(json.dumps(header).encode()) + "." + b64(json.dumps(payload).encode())
r, s_ = utils.decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
jwt = signing_input + "." + b64(r.to_bytes(32, "big") + s_.to_bytes(32, "big"))
# One object, as ERICA and the German EUDI wallet guide read verifier_info (OpenID4VP 1.0 5.1
# has an array; polaris-oid4vp carries either as given).
json.dump({"format": "registration_cert", "data": jwt}, open(sys.argv[1], "w"))
EOF
    VALIDATE_ARGS=(--verifier-info verifier-info.json) ;;
  *) NEWER=; VALIDATE_ARGS=() ;;
esac
case "$SERVE_HELP" in *--claim*) CLAIMS=yes ;; esac

# ERICA at the pinned commit, built with its own Dockerfile from exactly the committed files.
started=$(date +%s)
rm -rf erica-src
git clone -q "$ERICA_REPO" erica-src
git -C erica-src -c advice.detachedHead=false checkout -q "$ERICA_COMMIT"
git -C erica-src archive "$ERICA_COMMIT" \
  | docker build -q --build-context "node:22-alpine=docker-image://$NODE_IMAGE" -t "$IMAGE" - >/dev/null
echo "built      $IMAGE in $(( $(date +%s) - started )) s"

venv/bin/polaris-oid4vp keygen --out pki --host "$VHOST" --port "$PORT" >/dev/null
venv/bin/polaris-oid4vp keygen --out other-pki --host "$VHOST" --port "$PORT" >/dev/null

# The issuer trust anchor is ERICA's own test root, committed in its repository (and served at
# /api/issuer/trust-anchor). ERICA signs its PID under it with x5c [leaf, root]: the root rides in
# the chain, which HAIP 1.0 6.1.1 forbids, and its leaf has no subjectAltName naming the iss. The
# second instance reads a chain made here under that same root and its published key, shaped as
# HAIP wants: an intermediate CA in the slot ERICA sends after the leaf, and a leaf naming ERICA's
# iss. ERICA's code and image are unchanged; only the files in its issuer directory differ.
cp erica-src/src/security/issuer/issuer-certificate.pem erica-root.pem
venv/bin/python - <<'EOF'
import datetime, re, shutil
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
src = "erica-src/src/security/issuer/"
root = x509.load_pem_x509_certificate(open(src + "issuer-certificate.pem", "rb").read())
root_key = serialization.load_pem_private_key(open(src + "issuer-private-key.pem", "rb").read(), None)
iss = re.search(r'ISSUER_DID\s*=\s*"([^"]+)"', open("erica-src/src/simulator/TestKeys.ts").read()).group(1)
now = datetime.datetime.now(datetime.timezone.utc)
day = datetime.timedelta(days=1)
usage = dict(content_commitment=False, key_encipherment=False, data_encipherment=False,
             key_agreement=False, encipher_only=False, decipher_only=False)
ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
                     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EUDI VP Debugger - TEST ONLY"),
                     x509.NameAttribute(NameOID.COMMON_NAME, "Test PID intermediate CA (polaris lab walk)")])
ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(root.subject)
      .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now - day).not_valid_after(now + 30 * day)
      .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
      .add_extension(x509.KeyUsage(digital_signature=False, key_cert_sign=True, crl_sign=True, **usage),
                     critical=True)
      .sign(root_key, hashes.SHA256()))
leaf = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
                                 x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EUDI VP Debugger"),
                                 x509.NameAttribute(NameOID.COMMON_NAME, "EUDI VP Debugger Wallet Simulator")]))
        .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - day).not_valid_after(now + 30 * day)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False, **usage),
                       critical=True)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(iss)]), critical=False)
        .sign(ca_key, hashes.SHA256()))
pem = lambda k: k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
out = "erica-issuer/"
import os; os.makedirs(out, exist_ok=True)
open(out + "issuer-certificate.pem", "wb").write(ca.public_bytes(serialization.Encoding.PEM))
open(out + "issuer-private-key.pem", "wb").write(pem(ca_key))
open(out + "sdjwt-signer-certificate.pem", "wb").write(leaf.public_bytes(serialization.Encoding.PEM))
open(out + "sdjwt-signer-private-key.pem", "wb").write(pem(leaf_key))
for name in ("mdoc-signer-certificate.pem", "mdoc-signer-private-key.pem"):
    shutil.copy(src + name, out + name)
print("issuer     ERICA's root (sha256 %s), iss %s"
      % (root.fingerprint(hashes.SHA256()).hex()[:16], iss))
EOF
chmod 0644 erica-issuer/*.pem   # test keys made for this run; the container user reads them

CONTAINERS=()
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
  for c in ${CONTAINERS[@]+"${CONTAINERS[@]}"}; do docker logs "$c" > "$c.log" 2>&1 || true; docker rm -f "$c" >/dev/null 2>&1 || true; done
  docker network rm "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ERICA refuses to fetch a request_uri on loopback or in the RFC 1918 ranges (its SSRF guard,
# src/security/URLValidator.ts). So it reaches the verifier by a name it resolves to an address on
# a Docker network outside those ranges, where a TCP forwarder (node, from ERICA's own image)
# passes the connection to the verifier on this machine. TLS runs end to end through it.
docker network create --subnet "$NET.0/24" "$NAME" >/dev/null
FORWARD='const net=require("net");const [lp,h,p]=process.argv.slice(1);net.createServer(c=>{const u=net.connect(+p,h);const end=()=>{c.destroy();u.destroy()};c.on("error",end);u.on("error",end);c.on("close",end);u.on("close",end);c.pipe(u).pipe(c)}).listen(+lp,"0.0.0.0")'
docker run -d --name "$NAME-fwd" --network "$NAME" --ip "$NET.10" ${ADD_HOST[@]+"${ADD_HOST[@]}"} \
  --entrypoint node "$IMAGE" -e "$FORWARD" "$PORT" host.docker.internal "$PORT" >/dev/null
CONTAINERS+=("$NAME-fwd")

# Two ERICA instances: as shipped, and reading the issuer files made above. Each trusts the
# verifier's self-signed listener certificate through NODE_EXTRA_CA_CERTS; TLS checks stay on.
erica_start() {  # $1 name, $2 host port, then extra docker run arguments
  local name="$1" port="$2"; shift 2
  docker run -d --name "$name" --network "$NAME" --add-host "$VHOST:$NET.10" \
    -e NODE_EXTRA_CA_CERTS=/pki/tls.pem -v "$WORK/pki/tls.pem:/pki/tls.pem:ro" \
    -p "127.0.0.1:$port:3001" "$@" "$IMAGE" >/dev/null
  CONTAINERS+=("$name")
}
erica_start "$NAME-shipped" "$ERICA_PORT"
erica_start "$NAME-chain" "$((ERICA_PORT + 1))" -v "$WORK/erica-issuer:/app/dist/security/issuer:ro"
SHIPPED="http://127.0.0.1:$ERICA_PORT"
CHAIN="http://127.0.0.1:$((ERICA_PORT + 1))"
for url in "$SHIPPED" "$CHAIN"; do
  for _ in $(seq 1 120); do curl -fsS "$url/health" >/dev/null 2>&1 && break; sleep 0.5; done
  curl -fsS "$url/health" >/dev/null || { echo "ERICA at $url did not start" >&2; exit 2; }
done
for c in "$NAME-shipped" "$NAME-chain"; do
  case "$(docker logs "$c" 2>&1)" in
    *'Loaded stable test issuer + signer certificates from disk'*) ;;
    *) echo "$c did not load its issuer files (it would have generated others)" >&2; exit 2 ;;
  esac
done
curl -fsS -o served-anchor.json "$SHIPPED/api/issuer/trust-anchor"
venv/bin/python -c '
import json
served = json.load(open("served-anchor.json"))["data"]["certificate"]["pem"].strip()
assert served == open("erica-root.pem").read().strip(), "the served trust anchor is not the committed one"'

start_verifier() {  # $1 issuer trust anchor, $2 log, then extra serve arguments
  local anchor="$1" log="$2"; shift 2
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host "$VHOST" --bind 0.0.0.0 \
    --port "$PORT" --issuer-trust-anchor "$anchor" ${VCT_ARGS[@]+"${VCT_ARGS[@]}"} "$@" --once > "$log" 2>&1 &
  VERIFIER_PID=$!
  for _ in $(seq 1 240); do grep -q 'state=' "$log" 2>/dev/null && return 0; sleep 0.25; done
  echo "verifier did not start; see $WORK/$log" >&2
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

erica() {  # $1 ERICA, $2 launch URI, $3 mode, $4 PID template, $5 record, $6 log
  venv/bin/python "$HERE/drive.py" present "$1" "$2" "$3" "$4" "$5" > "$6" 2>&1 || true
  sleep 1  # the verifier logs its verdict after it answers
}

fail=0
expect() {  # $1 label, $2 file, $3 pattern that must appear
  if grep -qE "$3" "$2"; then echo "  ok    $1"; else echo "  FAIL  $1 (no /$3/ in $2)"; fail=1; fi
}
verdict() { { grep -E '<- [0-9]{3} ' "$1" || true; } | sed 's/^/        /'; }

echo "== ERICA's checks on the request (validation only, nothing posted)"
start_verifier erica-root.pem verifier-validate.log ${VALIDATE_ARGS[@]+"${VALIDATE_ARGS[@]}"}
venv/bin/python "$HERE/drive.py" validate "$SHIPPED" "$(launch_uri verifier-validate.log)" validate.json > erica-validate.log 2>&1 || true
expect "ERICA took the request" erica-validate.log '^VALIDATED'
stop_verifier
venv/bin/python "$HERE/drive.py" findings validate.json > findings.txt
echo "  every check ERICA failed, verbatim (findings.txt):"
sed 's/^/        /' findings.txt

echo "== ERICA's own issuer chain, as shipped"
start_verifier erica-root.pem verifier-shipped.log
erica "$SHIPPED" "$(launch_uri verifier-shipped.log)" VALID normal shipped.json erica-shipped.log
expect "the verifier refused the chain" verifier-shipped.log '<- 400 refused: issuer_key: x5c certificate 1 is a trust anchor'
verdict verifier-shipped.log
stop_verifier

echo "== genuine presentation (ERICA's PID under its root, the chain HAIP-shaped)"
start_verifier erica-root.pem verifier.log
URI=$(launch_uri verifier.log)
erica "$CHAIN" "$URI" VALID normal genuine.json erica.log
expect "ERICA dispatched" erica.log '^DISPATCHED'
expect "the verifier accepted it" verifier.log '<- 200 authentic'
verdict verifier.log

echo "== control (b): the same request again, after it was answered"
erica "$CHAIN" "$URI" VALID normal replay.json erica-replay.log
expect "ERICA refused at the request" erica-replay.log '^REQUEST REFUSED .*HTTP 404'
stop_verifier

# ERICA's edge-case PIDs. Where the verifier can be asked for values (--claim PATH=VALUE), it asks
# for the template's own strings, so a 200 means they arrived intact. They are read from the
# templates ERICA signs, in src/simulator/PIDTemplateLoader.ts; the JSON files beside it in
# pid-templates/ are not loaded, and they differ (special-characters: "Björgßöñ" there,
# "Bjørgßöñ" in the loader).
claim() {  # $1 template, $2 claim: PATH="the template's value", as JSON
  venv/bin/python -c 'import json, re, sys
src = open("erica-src/src/simulator/PIDTemplateLoader.ts", encoding="utf-8").read()
block = re.search(r"\"?%s\"?: \{.*?\n    \}," % re.escape(sys.argv[1]), src, re.S).group(0)
v = re.search(r"\b%s: \"([^\"]*)\"" % sys.argv[2], block).group(1)
print("%s=%s" % (sys.argv[2], json.dumps(v, ensure_ascii=False)))' "$1" "$2"
}
echo "== PID template special-characters"
SPECIAL=()
[ "$CLAIMS" = yes ] && SPECIAL=(--claim "$(claim special-characters given_name)" --claim "$(claim special-characters family_name)")
start_verifier erica-root.pem verifier-special.log ${SPECIAL[@]+"${SPECIAL[@]}"}
erica "$CHAIN" "$(launch_uri verifier-special.log)" VALID special-characters special.json erica-special.log
expect "the verifier accepted it" verifier-special.log '<- 200 authentic'
verdict verifier-special.log
stop_verifier
if [ "$CLAIMS" = yes ]; then
  echo "== PID template incomplete-birthdate, the verifier asking for birthdate too"
  start_verifier erica-root.pem verifier-birthdate.log --claim given_name --claim family_name \
    --claim "$(claim incomplete-birthdate birthdate)"
  erica "$CHAIN" "$(launch_uri verifier-birthdate.log)" VALID incomplete-birthdate birthdate.json erica-birthdate.log
  expect "the verifier accepted it" verifier-birthdate.log '<- 200 authentic.*birthdate'
  verdict verifier-birthdate.log
  stop_verifier
fi

# ERICA's negative modes that break the credential, its validity window or its key binding, or
# withhold a requested claim, each answering its own request: every one must be refused.
for mode in EXPIRED NOT_YET_VALID MISSING_SIGNATURE MISSING_CLAIMS WRONG_NONCE \
            MISSING_HOLDER_BINDING WRONG_AUDIENCE WRONG_ISSUER WRONG_CREDENTIAL_TYPE \
            ${NEWER:+OVER_DISCLOSURE}; do
  echo "== mode $mode"
  start_verifier erica-root.pem "verifier-$mode.log"
  erica "$CHAIN" "$(launch_uri "verifier-$mode.log")" "$mode" normal "$mode.json" "erica-$mode.log"
  expect "the verifier refused it" "verifier-$mode.log" '<- 400 refused: '
  verdict "verifier-$mode.log"
  stop_verifier
done

# INVALID_SIGNATURE signs with ERICA's alternate test key (src/simulator/TestKeys.ts), whose x and
# y are not a point on P-256, so Node refuses the key and ERICA builds no presentation at all.
echo "== mode INVALID_SIGNATURE"
start_verifier erica-root.pem verifier-INVALID_SIGNATURE.log
erica "$CHAIN" "$(launch_uri verifier-INVALID_SIGNATURE.log)" INVALID_SIGNATURE normal INVALID_SIGNATURE.json erica-INVALID_SIGNATURE.log
expect "ERICA built nothing to send" erica-INVALID_SIGNATURE.log '^SIMULATION FAILED Invalid JWK EC key'
stop_verifier

echo "== control (c): a launch URI whose client_id is not the signed request's"
start_verifier other-pki/anchor.pem verifier-other.log
erica "$CHAIN" "$(launch_uri verifier-other.log x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)" VALID normal c.json erica-c.log
expect "ERICA refused the request" erica-c.log '^REQUEST REFUSED .*client_id mismatch'

echo "== control (a): the verifier trusts a different issuer CA"
erica "$CHAIN" "$(launch_uri verifier-other.log)" VALID normal a.json erica-a.log
expect "ERICA was not accepted" erica-a.log '^DISPATCH FAILED'
expect "the verifier refused the issuer" verifier-other.log '<- 400 refused: issuer_key'
verdict verifier-other.log
stop_verifier

[ "$fail" -eq 0 ] && echo "RESULT: accepted, and every negative case refused" || echo "RESULT: FAILED"
exit "$fail"
