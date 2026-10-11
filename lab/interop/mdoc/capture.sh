#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# Captures one ISO 18013-5 mdoc DeviceResponse presented over OpenID4VP 1.0 direct_post.jwt, with
# the inputs its SessionTranscript is built from, for verify_mdoc.py.
#
# The EU reference PID issuer issues one of its mso_mdoc credentials (CONFIG: its mDL,
# org.iso.18013.5.1.mDL, by default, or its PID, eu.europa.ec.eudi.pid_mso_mdoc) to the
# ../eudi-issuer wallet, exactly as ../eudi-issuer/run.sh runs it: this script runs that run.sh's
# first 218 lines (the issuer stack, the wallet build, the issuance), pinned by SHA-256, against a
# copy of ../eudi-issuer whose wallet asks for that configuration and presents with
# wallet/src/main/kotlin/Present.kt. The wallet resolves a request from the published
# polaris-oid4vp, builds the DeviceResponse, writes it and the OpenID4VP inputs to OUT, then sends
# it. polaris-oid4vp verifies SD-JWT VC only, so it refuses the response; that is expected.
#
#   lab/interop/mdoc/capture.sh                       # OUT defaults to WORK/capture
#   OUT=lab/interop/mdoc/capture-mdl lab/interop/mdoc/capture.sh
#   CONFIG=eu.europa.ec.eudi.pid_mso_mdoc OUT=lab/interop/mdoc/capture-pid lab/interop/mdoc/capture.sh
#   MODE=direct_post OUT=lab/interop/mdoc/capture-mdl-direct-post lab/interop/mdoc/capture.sh
#
# Everything runs in containers except the verifier (a venv). Docker with Compose v2 is required.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ISSUER="$HERE/../eudi-issuer"
HEAD_LINES=218
HEAD_SHA256=8c403ba7cf7c8a72db0afb7f0efb1a0549981bf54ea7e5339f4cace457dae3cb
CONFIG="${CONFIG:-org.iso.18013.5.1.mDL}"
case "$CONFIG" in
  org.iso.18013.5.1.mDL) MDOC_DOCTYPE=org.iso.18013.5.1.mDL; MDOC_NS=org.iso.18013.5.1 ;;
  eu.europa.ec.eudi.pid_mso_mdoc) MDOC_DOCTYPE=eu.europa.ec.eudi.pid.1; MDOC_NS=eu.europa.ec.eudi.pid.1 ;;
  *) echo "CONFIG: the issuer's mDL or mso_mdoc PID" >&2; exit 2 ;;
esac
# MODE=jwt: polaris-oid4vp's own request (an SD-JWT VC query, direct_post.jwt). MODE=direct_post:
# the same verifier through request_shim.py (an mso_mdoc query, plain direct_post, no thumbprint).
MODE="${MODE:-jwt}"
case "$MODE" in jwt|direct_post) ;; *) echo "MODE: jwt or direct_post" >&2; exit 2 ;; esac
WORK="${WORK:-$(mktemp -d)}"
mkdir -p "$WORK" && WORK="$(cd "$WORK" && pwd)"
OUT="${OUT:-$WORK/capture}"
mkdir -p "$OUT" && OUT="$(cd "$OUT" && pwd)"

got=$(sed -n "1,${HEAD_LINES}p" "$ISSUER/run.sh" | shasum -a 256 | cut -d' ' -f1)
[ "$got" = "$HEAD_SHA256" ] || { echo "../eudi-issuer/run.sh lines 1-$HEAD_LINES changed (sha256 $got); refusing to run it" >&2; exit 2; }

# The harness: ../eudi-issuer with this wallet. Issue.kt and Main.kt are that wallet's; Issue.kt
# asks for CONFIG instead of the PID's SD-JWT VC configuration, and nothing else changes.
H="$WORK/harness/eudi-issuer"
rm -rf "$WORK/harness" && mkdir -p "$H/wallet/src/main/kotlin"
cp "$ISSUER/compose.yaml" "$ISSUER/haproxy.cfg" "$H/"
cp "$HERE/../requirements.txt" "$HERE/../requirements-build.txt" "$WORK/harness/"
cp -R "$HERE/wallet/." "$H/wallet/"
cp "$ISSUER/wallet/src/main/kotlin/Main.kt" "$H/wallet/src/main/kotlin/"
sed "s/CredentialConfigurationIdentifier(\"eu.europa.ec.eudi.pid_vc_sd_jwt\")/CredentialConfigurationIdentifier(\"$CONFIG\")/" \
  "$ISSUER/wallet/src/main/kotlin/Issue.kt" > "$H/wallet/src/main/kotlin/Issue.kt"
[ "$(diff "$ISSUER/wallet/src/main/kotlin/Issue.kt" "$H/wallet/src/main/kotlin/Issue.kt" | grep -c '^>')" = 1 ] || {
  echo "Issue.kt: the configuration id was not replaced exactly once" >&2; exit 2; }

{ sed -n "1,${HEAD_LINES}p" "$ISSUER/run.sh"; cat <<'TAIL'

# ---- mdoc capture (lab/interop/mdoc/capture.sh) ----
echo "== the mdoc and its chain"
docker run --rm -v "$WORK/upstream/docker-compose/pid-issuer":/k:ro -v "$WORK":/out "$IMAGE" \
  keytool -exportcert -rfc -keystore /k/issuer-keys.jks -storepass keys -alias "issuance root" -file /out/issuer-ca.pem >/dev/null 2>&1
[ -s issuer-ca.pem ] || { echo "RESULT: FAILED (no issuance root exported)"; exit 1; }

venv/bin/polaris-oid4vp keygen --out pki --host host.docker.internal --port "$PORT" >/dev/null
start_verifier() {  # as ../eudi-issuer/run.sh; MODE=direct_post goes through request_shim.py
  if [ "$MODE" = direct_post ]; then SERVE=(venv/bin/python -I -u request_shim.py "$MDOC_DOCTYPE" "$MDOC_NS");
  else SERVE=(venv/bin/polaris-oid4vp); fi
  PYTHONUNBUFFERED=1 "${SERVE[@]}" serve --pki pki --host host.docker.internal \
    --bind 0.0.0.0 --port "$PORT" --issuer-trust-anchor "$1" --once > "$2" 2>&1 &
  VERIFIER_PID=$!
  for _ in $(seq 1 240); do grep -q 'state=' "$2" 2>/dev/null && return 0; sleep 0.25; done
  echo "verifier did not start; see $WORK/$2" >&2
  exit 2
}
launch_uri() {  # as ../eudi-issuer/run.sh
  venv/bin/python - "$1" <<'EOF'
import re, sys, urllib.parse
log = open(sys.argv[1]).read()
cid = re.search(r"x509_hash:[A-Za-z0-9_-]+", log).group(0)
ruri = re.findall(r"https://\S+request\.jwt\?state=[A-Za-z0-9_-]+", log)[-1]
print("openid4vp://authorize?" + urllib.parse.urlencode(
    {"client_id": cid, "request_uri": ruri, "request_uri_method": "post"}))
EOF
}

echo "== presentation"
start_verifier issuer-ca.pem verifier.log
rm -rf capture
wallet present.log present "$(launch_uri verifier.log)" /in/credential.txt /in/holder-key.json /in/pki/anchor.pem /in/capture
sleep 1
stop_verifier
grep -E '^(resolved|built|CAPTURED|DISPATCH)' present.log | sed 's/^/        /' || true
{ grep -E '<- [0-9]{3}' verifier.log || true; } | sed 's/^/        verifier: /'
expect "the wallet wrote the DeviceResponse" present.log '^CAPTURED '
[ -s capture/device-response.cbor ] || { echo "RESULT: FAILED (no capture; see $WORK/present.log)"; exit 1; }
cp issuer-ca.pem capture/iaca-root.pem
date -u +%Y-%m-%dT%H:%M:%SZ > capture/captured-at.txt
cp credential.txt capture/issued-issuer-signed.b64url.txt
for f in present verifier issue; do cp "$f.log" "capture/$f.txt"; done  # *.log is git-ignored
echo "$CONFIG" > capture/credential-configuration.txt
echo "$MODE" > capture/request-mode.txt
venv/bin/python -c 'import importlib.metadata as m; print(m.version("polaris-oid4vp"))' > capture/polaris-oid4vp.version
ls wallet/build/install/*/lib/ > capture/wallet-libs.txt
[ "$fail" -eq 0 ] && touch capture/COMPLETE && echo "RESULT: captured" || echo "RESULT: FAILED"
finished=1  # the head's exit_trap: a run that stops before this line fails, whatever its status
exit "$fail"
TAIL
} > "$H/run.sh"
chmod +x "$H/run.sh"

mkdir -p "$WORK/run" && cp "$HERE/request_shim.py" "$WORK/run/"
MODE="$MODE" MDOC_DOCTYPE="$MDOC_DOCTYPE" MDOC_NS="$MDOC_NS" CONFIG="$CONFIG" COMPOSE_PROJECT="${COMPOSE_PROJECT:-polaris-mdoc-capture}" PORT="${PORT:-9491}" WORK="$WORK/run" "$H/run.sh"
# run.sh's exit status is not enough: under bash, its EXIT trap turns a `set -u` failure into exit 0
# (checked on bash 3.2). The capture counts only if the tail reached its last line.
[ -f "$WORK/run/capture/COMPLETE" ] || { echo "RESULT: FAILED (the capture did not complete; see $WORK/run)" >&2; exit 1; }
rm "$WORK/run/capture/COMPLETE"
rm -rf "$OUT" && cp -R "$WORK/run/capture" "$OUT"
echo "capture    $OUT"
echo "done"
