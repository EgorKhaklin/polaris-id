#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# Axle's Kotlin OpenID4VP client, driven by a harness written here, presents an SD-JWT VC to the
# PUBLISHED polaris-oid4vp, then six controls.
#
# Axle (github.com/openwallet-foundation-labs/axle, Apache-2.0) has no tags or releases, so it is
# pinned by commit. Its source is fetched at that commit into a new empty directory and never
# changed or run on this machine: the harness (harness/) joins its kotlin/ build as a Gradle
# included build and calls its public modules (openid4vp, trust, testkit), and both are compiled
# and run only inside the official Gradle image, pinned by digest, with every dependency checked
# against harness/gradle/verification-metadata.xml. The harness makes the holder key in Axle's
# software secure area; this script reads only the public half, and ../waltid/issue_sdjwt_vc.py
# --x5c binds the credential to it under an issuer CA made for this run, which the verifier
# trusts (--issuer-trust-anchor).
#
#   lab/interop/axle/run.sh                                         # polaris-oid4vp 1.0.0rc16
#   POLARIS_OID4VP=polaris-oid4vp lab/interop/axle/run.sh           # the newest release
#   AXLE_SHA=<commit> lab/interop/axle/run.sh                       # another Axle commit
#
# Exits 0 only if the genuine presentation is accepted AND every control is refused where it
# should be.
# shellcheck disable=SC2329  # report_line and stop_all run from the EXIT trap
set -euo pipefail
# The last lines of every run, whichever way it ends: a run that stops early is the report most
# worth having, and a run whose output does not end in "done" did not finish.
report_line() { echo "Tell us how it went, success or failure: https://github.com/EgorKhaklin/polaris-id/issues/new?template=stranger_path_report.yml"; }
VERIFIER_PID="" HARNESS="axle-interop-$$"
stop_verifier() {  # `wait` returns the killed server's 143, which set -e would take as ours
  if [ -n "$VERIFIER_PID" ]; then
    kill "$VERIFIER_PID" 2>/dev/null || true
    wait "$VERIFIER_PID" 2>/dev/null || true
    VERIFIER_PID=""
  fi
}
stop_all() { stop_verifier; docker rm -f "$HARNESS" >/dev/null 2>&1 || true; }
trap 'stop_all || true; report_line; echo "done"' EXIT

AXLE_REPO="https://github.com/openwallet-foundation-labs/axle"
AXLE_SHA="${AXLE_SHA:-f7b8054171bb49f3c27589d0b19b03285ed1dcc1}"
IMAGE="${GRADLE_IMAGE:-gradle:9.3.1-jdk17@sha256:5fb7d4ea7ddf10b24c317bc7d665a7da6aae9104042091625f3061f98661b487}"
PKG="${POLARIS_OID4VP:-polaris-oid4vp==1.0.0rc16}"
PORT="${PORT:-9491}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$(mktemp -d)}"
PY="${PYTHON:-python3}"
ISSUER="$HERE/../waltid/issue_sdjwt_vc.py"
HARNESS_BIN=/in/harness/build/install/polaris-axle-harness/bin/polaris-axle-harness
ADD_HOST=()
[ "$(uname)" = Linux ] && ADD_HOST=(--add-host host.docker.internal:host-gateway)
# A local path (a tree checkout, a wheel) is resolved before the cd below.
[ -e "$PKG" ] && PKG="$(cd "$(dirname "$PKG")" && pwd)/$(basename "$PKG")"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "Axle builds and runs in a Gradle image: start Docker" >&2
  exit 2
fi
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $PORT is in use; set PORT (keygen writes it into the certificate)" >&2
  exit 2
fi

echo "work dir   $WORK"
echo "wallet     Axle's Kotlin OpenID4VP client, driven by a harness written here (harness/)"
echo "axle       $AXLE_REPO at $AXLE_SHA"
echo "image      $IMAGE"
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

# Axle's source at exactly $AXLE_SHA, into a new empty directory. Nothing of it runs here: git only
# writes the files, and the build below runs in the container.
[ ! -e axle ] || { echo "$WORK/axle already exists; use a fresh WORK" >&2; exit 2; }
mkdir axle
git -C axle init -q
git -C axle fetch -q --depth 1 "$AXLE_REPO" "$AXLE_SHA"
git -C axle -c advice.detachedHead=false checkout -q FETCH_HEAD
[ "$(git -C axle rev-parse HEAD)" = "$AXLE_SHA" ] || { echo "the checkout is not $AXLE_SHA" >&2; exit 2; }

# The harness and Axle's modules, built together into a copy of harness/ so the tree stays clean.
# Gradle's cache is a named volume of its own, so a second run does not download again.
rm -rf harness && cp -R "$HERE/harness" harness
if ! docker run --rm -v "$WORK/harness":/w -v "$WORK/axle":/axle -w /w -e AXLE_KOTLIN=/axle/kotlin \
    -v polaris-axle-gradle-cache:/home/gradle/.gradle "$IMAGE" gradle --no-daemon -q installDist > build.log 2>&1; then
  tail -30 build.log >&2
  echo "the build failed; see $WORK/build.log" >&2
  exit 2
fi
echo "built      $(cd harness/build/install/polaris-axle-harness/lib && echo openid4vp-*.jar trust-*.jar testkit-*.jar)"

venv/bin/polaris-oid4vp keygen --out pki --host host.docker.internal --port "$PORT" >/dev/null
venv/bin/polaris-oid4vp keygen --out other-pki --host host.docker.internal --port "$PORT" >/dev/null

# The harness starts, makes the holder key in Axle's SoftwareSecureArea, writes its public half,
# and waits for jobs. It runs in the same image, with the verifier reached as host.docker.internal.
docker run -d --name "$HARNESS" ${ADD_HOST[@]+"${ADD_HOST[@]}"} -v "$WORK":/in "$IMAGE" "$HARNESS_BIN" /in >/dev/null
for _ in $(seq 1 240); do [ -f holder-jwk.json ] && break; sleep 0.25; done
[ -f holder-jwk.json ] || { docker logs "$HARNESS" >&2 || true; echo "the harness did not start" >&2; exit 2; }
echo "holder     $(docker logs "$HARNESS" 2>&1 | sed -n 1p)"

# The credential, bound to the harness's key, under a CA made for this run (--x5c). Then the
# material for the controls: (a) a CA under the same name with another key; (e) the same
# credential with its issuer-signed payload backdated by a day, its signature unchanged; (f) a
# credential from a second CA, bound to a key the harness does not hold.
venv/bin/python -c 'import json, sys; json.dump({"holder_jwk": json.load(open("holder-jwk.json"))}, open("holder.json", "w"))'
venv/bin/python "$ISSUER" --holder-jwk holder.json --x5c --out credential.json >/dev/null
venv/bin/python - <<'EOF'
import base64, json
from cryptography.hazmat.primitives.asymmetric import ec
n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")
json.dump({"holder_jwk": {"kty": "EC", "crv": "P-256", "x": b(n.x), "y": b(n.y)}}, open("other-holder.json", "w"))
EOF
venv/bin/python "$ISSUER" --holder-jwk other-holder.json --x5c --out credential-other-holder.json >/dev/null
venv/bin/python - <<'EOF'
import base64, datetime, json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
d = json.load(open("credential.json"))
open("credential.txt", "w").write(d["credential"])
open("issuer-ca.pem", "w").write(d["issuer_ca_pem"])
o = json.load(open("credential-other-holder.json"))
open("credential-other-holder.txt", "w").write(o["credential"])
open("issuer-ca-2.pem", "w").write(o["issuer_ca_pem"])
# (a): a different CA under the SAME name, so only its key can tell them apart.
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
# (e): the issuer-signed payload with iat a day earlier and the original signature, so only the
# signature can tell. Axle's holder does not check its own credential's issuer signature.
jwt, rest = d["credential"].split("~", 1)
h, p, s = jwt.split(".")
payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
payload["iat"] -= 86400
p2 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
open("credential-altered.txt", "w").write(".".join((h, p2, s)) + "~" + rest)
EOF

start_verifier() {  # $1 the issuer CA the verifier trusts, $2 log
  # --verbose logs each request's method and path, which shows how the wallet fetched the request.
  PYTHONUNBUFFERED=1 venv/bin/polaris-oid4vp serve --pki pki --host host.docker.internal \
    --bind 0.0.0.0 --port "$PORT" --issuer-trust-anchor "$1" --once --verbose > "$2" 2>&1 &
  VERIFIER_PID=$!
  for _ in $(seq 1 240); do grep -q 'state=' "$2" 2>/dev/null && return 0; sleep 0.25; done
  echo "verifier did not start within 60 s; see $WORK/$2" >&2
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

JOB=0
present() {  # $1 launch URI, $2 credential, $3 the CA the wallet trusts for the verifier, $4 wallet log
  JOB=$((JOB + 1))
  local n
  n=$(printf '%02d' "$JOB")
  mkdir -p jobs
  printf '%s\n%s\n%s\n' "$1" "$2" "$3" > "jobs/$n.tmp"
  mv "jobs/$n.tmp" "jobs/$n.job"
  for _ in $(seq 1 600); do [ -f "jobs/$n.done" ] && break; sleep 0.2; done
  if [ -f "jobs/$n.done" ]; then cp "jobs/$n.out" "$4"; else echo "HARNESS TIMEOUT job $n" > "$4"; fi
  sleep 1  # the verifier logs its verdict after it answers
}

fail=0
expect() {  # $1 label, $2 file, $3 pattern that must appear
  if grep -qE "$3" "$2"; then echo "  ok    $1"; else echo "  FAIL  $1 (no /$3/ in $2)"; fail=1; fi
}
refused() {  # $1 verifier log: print its refusal line
  { grep -E '<- 4[0-9][0-9]' "$1" || true; } | sed 's/^/        /'
}

echo "== genuine presentation"
start_verifier issuer-ca.pem verifier.log
URI=$(launch_uri verifier.log)
present "$URI" credential.txt pki/anchor.pem wallet.log
expect "Axle's request verifier trusted the verifier" wallet.log '^TRUST trusted'
expect "Axle fetched the request by POST" verifier.log '^POST /request\.jwt'
expect "Axle dispatched and the verifier answered 2xx" wallet.log '^DISPATCHED'
expect "the verifier accepted it" verifier.log '<- 200 authentic'
{ grep -E '<- 200' verifier.log || true; } | sed 's/^/        /'

echo "== control (b): the same request again, after it was answered"
present "$URI" credential.txt pki/anchor.pem wallet-b.log
expect "refused at the request stage" wallet-b.log '^REQUEST REFUSED .*request_uri fetch failed: HTTP 404'
stop_verifier

echo "== control (c): a launch URI whose client_id is not the signed request's"
start_verifier issuer-ca-other.pem verifier-other.log
present "$(launch_uri verifier-other.log x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)" credential.txt pki/anchor.pem wallet-c.log
expect "Axle refused the request" wallet-c.log "^REQUEST REFUSED .*request object client_id .* != request client_id"

echo "== control (d): the wallet trusts an unrelated CA for the verifier"
present "$(launch_uri verifier-other.log)" credential.txt other-pki/anchor.pem wallet-d.log
expect "Axle reported the verifier not trusted" wallet-d.log '^TRUST not trusted'
expect "the harness declined, so nothing was sent" wallet-d.log '^DECLINED'
if grep -qE '<- [0-9]{3}' verifier-other.log; then echo "  FAIL  the verifier received a presentation"; fail=1
else echo "  ok    the verifier received no presentation"; fi

echo "== control (a): the verifier trusts a different issuer CA under the same name"
present "$(launch_uri verifier-other.log)" credential.txt pki/anchor.pem wallet-a.log
expect "the wallet was not accepted" wallet-a.log '^DISPATCH FAILED'
expect "the verifier refused the issuer" verifier-other.log '<- 400 refused: issuer_key'
refused verifier-other.log
stop_verifier

echo "== control (e): the issuer-signed payload altered after issuance"
start_verifier issuer-ca.pem verifier-altered.log
present "$(launch_uri verifier-altered.log)" credential-altered.txt pki/anchor.pem wallet-e.log
expect "Axle presented it and was not accepted" wallet-e.log '^DISPATCH FAILED'
expect "the verifier refused the issuer's signature" verifier-altered.log '<- 400 refused: issuer_signature'
refused verifier-altered.log
stop_verifier

echo "== control (f): a credential bound to a key the wallet does not hold"
start_verifier issuer-ca-2.pem verifier-holder.log
present "$(launch_uri verifier-holder.log)" credential-other-holder.txt pki/anchor.pem wallet-f.log
expect "Axle presented it and was not accepted" wallet-f.log '^DISPATCH FAILED'
expect "the verifier refused the key binding" verifier-holder.log '<- 400 refused: kb_signature'
refused verifier-holder.log
stop_verifier

touch jobs/stop
if [ "$fail" -eq 0 ]; then
  echo "RESULT: accepted, and all six controls refused (Axle's Kotlin OpenID4VP client, driven by a harness written here)"
else
  echo "RESULT: FAILED (Axle's Kotlin OpenID4VP client, driven by a harness written here)"
fi
exit "$fail"
