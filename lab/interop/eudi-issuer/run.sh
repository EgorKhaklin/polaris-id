#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# The EU reference PID issuer issues an SD-JWT VC PID over OpenID4VCI to a wallet on the EU's own
# libraries, the wallet presents it to the PUBLISHED polaris-oid4vp, which trusts only the issuer's
# certificate authority, then four controls.
#
# The issuer (eudi-srv-pid-issuer v0.11.1, pinned by digest) runs as its own docker-compose runs
# it (compose.yaml): Keycloak with its test user, PostgreSQL, HAProxy at https://localhost. The
# wallet (wallet/) is a small Kotlin program on eu.europa.ec.eudi:eudi-lib-jvm-openid4vci-kt and
# eudi-lib-jvm-openid4vp-kt. It obtains the PID with the authorization code flow (PAR, PKCE, DPoP,
# attestation-based client authentication, a key attestation), logging the test user in over
# HTTP, then presents given_name and family_name. polaris-oid4vp is given the root of the test
# PKI that ships in the issuer's own compose as its only --issuer-trust-anchor.
#
#   lab/interop/eudi-issuer/run.sh                                  # the newest polaris-oid4vp
#   POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/eudi-issuer/run.sh
#   POLARIS_OID4VP=$PWD/packages/polaris-oid4vp lab/interop/eudi-issuer/run.sh   # the tree
#
# Exits 0 only if the PID is issued, the presentation is accepted AND every control is refused where
# it should be.
set -euo pipefail

IMAGE="${JDK_IMAGE:-gradle:8.14.3-jdk21@sha256:21bd311ed01360c189b8870c6b6e988199ff10f72d445d02fb39d3cff9da91d7}"
PKG="${POLARIS_OID4VP:-polaris-oid4vp}"
PORT="${PORT:-9488}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
PROJECT="${COMPOSE_PROJECT:-polaris-eudi-issuer}"
# eudi-srv-pid-issuer v0.11.1, and the ABCA Keycloak extension its compose builds Keycloak with.
UPSTREAM="https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/9177177071157b20724b04eed619049e40679bbb"
ABCA="https://repo1.maven.org/maven2/eu/europa/ec/eudi/abca-keycloak-ext/0.2.0/abca-keycloak-ext-0.2.0.jar"

command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { echo "the issuer and the wallet run in containers: start Docker" >&2; exit 2; }
docker compose version >/dev/null 2>&1 || { echo "docker compose (v2) is required" >&2; exit 2; }
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $PORT is in use; set PORT (keygen writes it into the certificate)" >&2
  exit 2
fi
if [ -n "$(docker compose -p "$PROJECT" ps -q 2>/dev/null)" ]; then
  echo "a compose project named $PROJECT is running; stop it or set COMPOSE_PROJECT" >&2
  exit 2
fi
# Absolute paths before the cd below: compose.yaml and docker mount from WORK, and pip reads a tree.
if [ -d "$PKG" ]; then
  PKG="$(cd "$PKG" && pwd)"
elif [ -e "$PKG" ]; then
  PKG="$(cd "$(dirname "$PKG")" && pwd)/$(basename "$PKG")"
fi
mkdir -p "$WORK" && WORK="$(cd "$WORK" && pwd)"

echo "work dir   $WORK"
echo "issuer     eudi-srv-pid-issuer v0.11.1 (compose.yaml)"
echo "wallet     eudi-lib-jvm-openid4vci-kt and eudi-lib-jvm-openid4vp-kt (wallet/build.gradle.kts), in $IMAGE"
echo "verifier   pip install --pre $PKG"
cd "$WORK"
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

# The issuer's own files, from the release's commit, each checked against the SHA-256 it had when
# this walk was written. A changed file stops the run rather than being used.
venv/bin/python - "$UPSTREAM" "$ABCA" <<'EOF'
import hashlib, os, sys, urllib.request
upstream, abca = sys.argv[1:3]
files = {
    "docker-compose/docker-compose.yaml": "893dcf4cdf16dde6ee05ab4e6a573bc217a2906a4e73f3c5c10ecdd85cb8d6f2",
    "docker-compose/haproxy/certs/localhost.tls.crt": "60a6f930548d9612d3aaddef1a80d279ac08483b3a37ee1778ddfe41534906ff",
    "docker-compose/haproxy/certs/localhost.tls.pem": "a4709850f96dd7e1f7611a1cbacbb7b661b993714594c7b0718087aed8fa0f45",
    "docker-compose/keycloak/certs/keycloak.tls.crt": "f104a369baa82f7477ad380dea0b524cf9dd8dbab44395d17fd9acfdad7c2668",
    "docker-compose/keycloak/certs/keycloak.tls.key": "5443e8b07ea0e6f7951db683f1c282e71d254f91214e9e9d3e5798450ab3a92d",
    "docker-compose/keycloak/conf/keycloak.conf": "16e48754044ef32f18451f7f7b6db69e79980fd6f88a215665b074a030212f3c",
    "docker-compose/keycloak/realms/pid-issuer-realm-realm.json": "1b84f8e7362e5090f24b2e39936876273f5fc5bdf6bcfdf74e7b2ee506c0ce2d",
    "docker-compose/keycloak/realms/pid-issuer-realm-users-0.json": "8c30b65cdf407cfa85cfa1b38e83a84f7af0c5d58407afbc655030d0806d17df",
    "docker-compose/pid-issuer/issuer-keys.jks": "9b011617a4d3245ae487f3fa84955bbade1a7fa80973fc241d9b95d9fdffd83f",
    "docker-compose/postgresql/schema/V1.sql": "cd7629f10dfabf421ea4ce0c8fec2fcf8df3adf6629ace2440dde91f9c08200f",
}
sources = {path: upstream + "/" + path for path in files}
files["abca-keycloak-ext-0.2.0.jar"] = "4b10222577445f936ead647980b22e672ee9e38e0c1e5b8ac8dab60dd5ea8a86"
sources["abca-keycloak-ext-0.2.0.jar"] = abca
for path, digest in files.items():
    with urllib.request.urlopen(sources[path], timeout=60) as response:
        body = response.read()
    if hashlib.sha256(body).hexdigest() != digest:
        sys.exit("upstream %s changed (sha256 %s); refusing to run it" % (path, hashlib.sha256(body).hexdigest()))
    os.makedirs(os.path.dirname(os.path.join("upstream", path)) or ".", exist_ok=True)
    open(os.path.join("upstream", path), "wb").write(body)
# Every service's environment as upstream's docker-compose.yaml sets it, one env file each.
service, section, env = None, None, {}
for line in open("upstream/docker-compose/docker-compose.yaml"):
    indent = len(line) - len(line.lstrip(" "))
    if indent == 2 and line.rstrip().endswith(":"):
        service, section = line.strip()[:-1], None
    elif indent == 4 and ":" in line:
        section = line.strip().split(":", 1)[0]
    elif service and section == "environment" and line.lstrip().startswith("- ") and "=" in line:
        key, value = line.strip()[2:].split("=", 1)
        env.setdefault(service, []).append("%s=%s" % (key, value))
for name, out in (("postgres", "postgres.env"), ("keycloak", "keycloak.env"), ("pid-issuer", "issuer.env")):
    assert env.get(name), "no environment for %s in upstream's compose" % name
    open(out, "w").write("\n".join(env[name]) + "\n")
print("upstream   %d files, sha256 as pinned; %d issuer settings from its compose" % (len(files), len(env["pid-issuer"])))
EOF

# The test wallet provider: a key and certificate that sign the wallet's client attestation and key
# attestation, and the status list both point at, all entries valid. Keycloak and the issuer fetch
# it from HAProxy and check its signature under the certificate in its x5c; no trust validator is
# configured upstream, so both accept any wallet provider, which is what lets a wallet built here
# be issued to at all.
venv/bin/python - <<'EOF'
import base64, datetime, json, time, zlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Polaris lab test wallet provider")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
open("wallet-provider-key.pem", "wb").write(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
open("wallet-provider.pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
header = {"alg": "ES256", "typ": "statuslist+jwt",
          "x5c": [base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()]}
claims = {"sub": "http://haproxy/wallet-provider/status-list", "iat": int(time.time()) - 60,
          "exp": int(time.time()) + 86400, "status_list": {"bits": 1, "lst": b64(zlib.compress(bytes(16), 9))}}
signing_input = b64(json.dumps(header).encode()) + "." + b64(json.dumps(claims).encode())
r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
open("status-list.jwt", "w").write(signing_input + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big")))
EOF

export WORK  # compose.yaml mounts from it
COMPOSE=(docker compose -p "$PROJECT" -f "$HERE/compose.yaml")
VERIFIER_PID=""
UP_PID=""
stop_verifier() {
  if [ -n "$VERIFIER_PID" ]; then
    kill "$VERIFIER_PID" 2>/dev/null || true
    wait "$VERIFIER_PID" 2>/dev/null || true
    VERIFIER_PID=""
  fi
}
cleanup() {
  stop_verifier
  [ -z "$UP_PID" ] || wait "$UP_PID" 2>/dev/null || true
  "${COMPOSE[@]}" logs --no-color > "$WORK/issuer-stack.log" 2>&1 || true
  [ "${KEEP_ISSUER:-0}" = 1 ] || "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The issuer stack starts while the wallet compiles.
"${COMPOSE[@]}" up -d --quiet-pull > compose-up.log 2>&1 &
UP_PID=$!

# The wallet, built once into a copy of wallet/ so the tree stays clean; Gradle's own cache is a
# named volume so a second run does not download again.
rm -rf wallet && cp -R "$HERE/wallet" wallet
docker run --rm -v "$WORK/wallet":/w -w /w -v polaris-gradle-cache:/home/gradle/.gradle "$IMAGE" \
  gradle --no-daemon -q installDist >/dev/null
echo "built      $(ls wallet/build/install/*/lib/eudi-lib-jvm-openid4vci-kt-*.jar wallet/build/install/*/lib/eudi-lib-jvm-openid4vp-kt-*.jar | xargs -n1 basename | tr '\n' ' ')"

wait "$UP_PID" || { UP_PID=""; tail -5 compose-up.log >&2; echo "the issuer stack did not start; see $WORK/compose-up.log" >&2; exit 2; }
UP_PID=""
for _ in $(seq 1 120); do
  "${COMPOSE[@]}" logs pid-issuer 2>/dev/null | grep -q 'Started PidIssuerApplication' && break
  sleep 2
done
"${COMPOSE[@]}" logs pid-issuer 2>/dev/null | grep -q 'Started PidIssuerApplication' || {
  echo "the issuer did not start; see $WORK/issuer-stack.log" >&2; exit 2; }
HAPROXY="$("${COMPOSE[@]}" ps -q haproxy)"
echo "issuer     up at https://localhost/pid-issuer (inside the HAProxy container's network)"

wallet() {  # $1 log file, then the wallet's arguments. It runs in HAProxy's network namespace,
  # where https://localhost is the issuer. The issuer's and the verifier's test TLS certificates
  # go into the JDK's trust store: the registration a counterparty makes for a test server.
  local log="$1"; shift
  docker run --rm --network "container:$HAPROXY" -v "$WORK":/in "$IMAGE" bash -c \
    'keytool -importcert -cacerts -storepass changeit -noprompt -alias issuer-tls -file /in/upstream/docker-compose/haproxy/certs/localhost.tls.crt >/dev/null 2>&1 &&
     { [ ! -f /in/pki/tls.pem ] || keytool -importcert -cacerts -storepass changeit -noprompt -alias polaris-listener -file /in/pki/tls.pem >/dev/null 2>&1; } &&
     exec /in/wallet/build/install/polaris-eudi-issuer-wallet/bin/polaris-eudi-issuer-wallet "$@"' \
    wallet "$@" > "$log" 2>&1 || true
}

fail=0
expect() {  # $1 label, $2 file, $3 pattern that must appear
  if grep -qE "$3" "$2"; then echo "  ok    $1"; else echo "  FAIL  $1 (no /$3/ in $2)"; fail=1; fi
}

echo "== issuance"
wallet issue.log issue https://localhost/pid-issuer /in/wallet-provider-key.pem /in/wallet-provider.pem \
  http://haproxy/wallet-provider/status-list /in/credential.txt /in/holder-key.json
expect "the issuer issued a PID" issue.log '^ISSUED '
grep -E '^(authorized|ISSUED|REFUSED)' issue.log | sed 's/^/        /' || true
[ -s credential.txt ] || { echo "RESULT: FAILED (no credential; see $WORK/issue.log)"; exit 1; }

# What the issuer signed, and the trust anchor the verifier is given: the root of the test PKI in
# the issuer's own keystore, which the issuer leaves out of the credential's x5c.
docker run --rm -v "$WORK/upstream/docker-compose/pid-issuer":/k:ro -v "$WORK":/out "$IMAGE" \
  keytool -exportcert -rfc -keystore /k/issuer-keys.jks -storepass keys -alias "issuance root" -file /out/issuer-ca.pem >/dev/null 2>&1
venv/bin/python - <<'EOF'
import base64, json
from cryptography import x509
jwt = open("credential.txt").read().split("~")[0]
pad = lambda s: s + "=" * (-len(s) % 4)
header = json.loads(base64.urlsafe_b64decode(pad(jwt.split(".")[0])))
payload = json.loads(base64.urlsafe_b64decode(pad(jwt.split(".")[1])))
chain = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in header["x5c"]]
anchor = x509.load_pem_x509_certificate(open("issuer-ca.pem", "rb").read())
san = chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
print("credential typ=%s vct=%s iss=%s" % (header["typ"], payload["vct"], payload["iss"]))
print("           x5c %s" % " <- ".join(c.subject.rfc4514_string() for c in chain))
print("           leaf names %s" % ", ".join(str(n.value) for n in san))
print("           anchor %s, %s the x5c" % (anchor.subject.rfc4514_string(),
      "INSIDE" if any(c == anchor for c in chain) else "not in"))
json.dump(payload.get("nbf", payload["iat"]), open("nbf.json", "w"))
EOF

# The verifier, its PKI, and an unrelated CA for control (a).
venv/bin/polaris-oid4vp keygen --out pki --host host.docker.internal --port "$PORT" >/dev/null
venv/bin/polaris-oid4vp keygen --out other-pki --host host.docker.internal --port "$PORT" >/dev/null

start_verifier() {  # $1 issuer trust anchor, $2 log
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host host.docker.internal \
    --bind 0.0.0.0 --port "$PORT" --issuer-trust-anchor "$1" --once > "$2" 2>&1 &
  VERIFIER_PID=$!
  for _ in $(seq 1 240); do grep -q 'state=' "$2" 2>/dev/null && return 0; sleep 0.25; done
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
  wallet "$2" present "$1" /in/credential.txt /in/holder-key.json "/in/$3"
  sleep 1  # the verifier logs its verdict after it answers
}

# The issuer dates nbf 20 seconds after issuance (ISSUER_PID_SD_JWT_VC_NOTUSEBEFORE, upstream's
# default); a verifier refuses the PID before then, so the presentation waits for it.
WAIT=$(venv/bin/python -c 'import json, time; print(max(0, int(json.load(open("nbf.json")) - time.time()) + 2))')
[ "$WAIT" -gt 0 ] && { echo "waiting    ${WAIT}s for the PID's nbf"; sleep "$WAIT"; }

echo "== genuine presentation"
start_verifier issuer-ca.pem verifier.log
URI=$(launch_uri verifier.log)
present "$URI" wallet.log pki/anchor.pem
expect "the wallet dispatched and the verifier accepted" wallet.log '^DISPATCHED Accepted'
expect "the verifier accepted it" verifier.log "<- 200 authentic, claims .*'family_name', 'given_name'"
{ grep -E '<- 200' verifier.log || true; } | sed 's/^/        /'

echo "== control (b): the same request again, after it was answered"
present "$URI" wallet-replay.log pki/anchor.pem
expect "refused at the request stage" wallet-replay.log '^REQUEST REFUSED.*UnableToFetchRequestObject.*404 Not Found'
stop_verifier

echo "== control (c): a launch URI whose client_id is not the signed request's"
start_verifier other-pki/anchor.pem verifier-other.log
present "$(launch_uri verifier-other.log x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)" wallet-c.log pki/anchor.pem
expect "the wallet refused the request, for the client_id" wallet-c.log '^REQUEST REFUSED.*ClientId mismatch'

echo "== control (d): the wallet trusts an unrelated CA for the verifier"
present "$(launch_uri verifier-other.log)" wallet-d.log other-pki/anchor.pem
expect "the wallet refused the request, for the chain" wallet-d.log '^REQUEST REFUSED.*Untrusted x5c'

echo "== control (a): the verifier trusts an unrelated CA instead of the issuer's"
present "$(launch_uri verifier-other.log)" wallet-a.log pki/anchor.pem
expect "the wallet was not accepted" wallet-a.log 'Rejected|DISPATCH FAILED'
expect "the verifier refused the issuer" verifier-other.log '<- 400 refused: issuer_key'
{ grep -E '<- 400' verifier-other.log || true; } | sed 's/^/        /'
stop_verifier

[ "$fail" -eq 0 ] && echo "RESULT: issued, accepted, and all four controls refused" || echo "RESULT: FAILED"
exit "$fail"
