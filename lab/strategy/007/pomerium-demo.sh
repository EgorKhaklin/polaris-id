#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# lab/strategy/007/pomerium-demo.sh -- Pomerium admits a person whose wallet presented to the gate,
# and an agent whose holder granted it an action.
#
# Everything runs on this machine, and none of it was written for Polaris except the gate:
#   - the gate (lab/strategy/007/gate.py, this tree's code), an OIDC provider over polaris-oid4vp
#     and polaris-verify;
#   - walt.id's wallet (waltid/wallet-api2, unmodified), holding a credential it was issued;
#   - Pomerium (unmodified, pinned by digest), an identity-aware proxy configured with the gate as
#     its generic OIDC provider, protecting traefik/whoami (pinned), which echoes what it is sent;
#   - a headless browser (Playwright) standing in for the person;
#   - an agent holding an ML-DSA-65 grant chain (grants.py), calling two API routes.
#
# Exits 0 only if all of this holds:
#   - the person reaches the protected page with the claims the gate released;
#   - the agent reaches each API route with a token for that route's action, and every control
#     is refused (agent_drive.py lists them);
#   - the same wallet is refused once the gate no longer trusts the credential's issuer.
#
# Needs Docker, a python3 with `playwright` (chromium installed) and a `cryptography` with ML-DSA,
# and ports 7006, 8443, 9443 and 9444 free. PYTHON overrides the interpreter.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PY="${PYTHON:-python3}"
WORK="${WORK:-$(mktemp -d)}"
POMERIUM="pomerium/pomerium@sha256:164ee284218491d61a5ed9610122f73c99de9b17b1ce4d263773e5f3711ca123"  # 0.33.3
WHOAMI="traefik/whoami@sha256:c4717a8d1f0134a7444e24f881160e033991f23027c6c5a9a3f8fd22e70d1d44"
WALLET="waltid/wallet-api2:1.0.0"
NET=polaris-gate-net
ADD_HOST=()
[ "$(uname)" = Linux ] && ADD_HOST=(--add-host host.docker.internal:host-gateway)
# *.localhost.pomerium.io no longer resolves in public DNS (it used to answer 127.0.0.1), so the
# names are mapped here: for curl, the browser (drive.py), the agent and Pomerium itself.
NAMES=(authenticate verify status config)
RESOLVE=(); for n in "${NAMES[@]}"; do RESOLVE+=(--resolve "$n.localhost.pomerium.io:8443:127.0.0.1"); done
for n in "${NAMES[@]}"; do ADD_HOST+=(--add-host "$n.localhost.pomerium.io:127.0.0.1"); done

for p in 7006 8443 9443 9444; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then echo "port $p is in use" >&2; exit 2; fi
done
"$PY" -c 'import playwright; from cryptography.hazmat.primitives.asymmetric import mldsa' 2>/dev/null \
  || { echo "this python ($PY) needs playwright, and a cryptography with ML-DSA" >&2; exit 2; }

GATE_PID=""
cleanup() {   # keeps the script's own exit status: a failed run must not exit 0
  rc=$?
  if [ -n "$GATE_PID" ]; then kill "$GATE_PID" 2>/dev/null || true; wait "$GATE_PID" 2>/dev/null || true; fi
  docker rm -f polaris-gate-pomerium polaris-gate-whoami polaris-gate-wallet >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  exit "$rc"
}
trap cleanup EXIT

echo "work dir   $WORK"
mkdir -p "$WORK" && cd "$WORK"
export PYTHONPATH="$ROOT/packages/polaris-oid4vp"

echo "== the gate's certificates (polaris-oid4vp keygen)"
"$PY" -m polaris_oid4vp.cli keygen --out ./pki --host host.docker.internal --port 9443 >/dev/null

echo "== an issuer, a holder and the agent the holder grants read:status and write:config"
"$PY" "$HERE/grants.py" mint --out ./agent --actions read:status,write:config

echo "== walt.id's wallet, and one credential in it"
docker run -d --name polaris-gate-wallet -p 7006:7006 "${ADD_HOST[@]}" "$WALLET" >/dev/null
for _ in $(seq 1 90); do curl -sf http://localhost:7006/livez >/dev/null && break; sleep 1; done
CONTAINER=polaris-gate-wallet PYTHON="$PY" bash "$ROOT/lab/interop/waltid/setup.sh" ./pki >setup.log 2>&1 \
  || { tail -20 setup.log; exit 1; }

SECRET="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(24))')"
cat > clients.json <<EOF
{"pomerium": {"secret": "$SECRET",
  "redirect_uris": ["https://authenticate.localhost.pomerium.io:8443/oauth2/callback"]}}
EOF

start_gate() {   # start_gate ISSUER_JWKS_FILE
  [ -n "$GATE_PID" ] && { kill "$GATE_PID" 2>/dev/null || true; wait "$GATE_PID" 2>/dev/null || true; }
  "$PY" -u "$HERE/gate.py" --pki ./pki --clients clients.json --host host.docker.internal \
    --issuer-jwks "$1" --grant-issuer-keys agent/issuer.pub >gate.log 2>&1 &
  GATE_PID=$!
  for _ in $(seq 1 30); do
    curl -sfk https://localhost:9444/.well-known/openid-configuration >/dev/null && return 0; sleep 0.5
  done
  cat gate.log; exit 1
}

echo "== the gate, trusting the credential's issuer"
start_gate issuer-jwks.json

echo "== Pomerium, with the gate as its OIDC provider, protecting whoami"
# It listens on 8443 inside the container as well: it calls its own authenticate URL to verify
# an agent's bearer token, and that URL must reach it from inside.
"$PY" - <<'EOF'
import base64, secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
signing = ec.generate_private_key(ec.SECP256R1()).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
b64 = lambda raw: base64.b64encode(raw).decode()
client_secret = __import__("json").load(open("clients.json"))["pomerium"]["secret"]
open("pomerium.yaml", "w").write("""address: ":8443"
authenticate_service_url: https://authenticate.localhost.pomerium.io:8443
idp_provider: oidc
idp_provider_url: https://host.docker.internal:9444
idp_client_id: pomerium
idp_client_secret: %s
certificate_authority_file: /pki/tls.pem
shared_secret: %s
cookie_secret: %s
signing_key: %s
jwt_claims_headers: [given_name, family_name, action, holder]
routes:
  - from: https://verify.localhost.pomerium.io:8443
    to: http://polaris-gate-whoami:80
    allow_any_authenticated_user: true
    pass_identity_headers: true
  - from: https://status.localhost.pomerium.io:8443
    to: http://polaris-gate-whoami:80
    bearer_token_format: idp_identity_token
    pass_identity_headers: true
    policy:
      - allow:
          and:
            - claim/action: read:status
  - from: https://config.localhost.pomerium.io:8443
    to: http://polaris-gate-whoami:80
    bearer_token_format: idp_identity_token
    pass_identity_headers: true
    policy:
      - allow:
          and:
            - claim/action: write:config
""" % (client_secret, b64(secrets.token_bytes(32)), b64(secrets.token_bytes(32)), b64(signing)))
EOF
docker network create "$NET" >/dev/null
docker run -d --name polaris-gate-whoami --network "$NET" "$WHOAMI" >/dev/null
docker run -d --name polaris-gate-pomerium --network "$NET" -p 8443:8443 "${ADD_HOST[@]}" \
  -e SSL_CERT_FILE=/pki/tls.pem -v "$WORK/pomerium.yaml:/pomerium/config.yaml:ro" -v "$WORK/pki:/pki:ro" \
  "$POMERIUM" >/dev/null
for _ in $(seq 1 60); do
  code=$(curl -sk "${RESOLVE[@]}" -o /dev/null -w '%{http_code}' https://verify.localhost.pomerium.io:8443/ || true)
  [ "$code" = 302 ] && break; sleep 1
done

fail=0
WALLET_ID=$(cat wallet-id.txt); KEY_ID=$(cat key-id.txt)

echo "== a person opens the protected page, and presents from walt.id"
"$PY" "$HERE/drive.py" https://verify.localhost.pomerium.io:8443/ http://localhost:7006 "$WALLET_ID" "$KEY_ID" > admitted.json
"$PY" - <<'EOF' || fail=1
import json, sys
r = json.load(open("admitted.json"))
# Pomerium names a claim header after the claim (X-Pomerium-Claim-Given_name): compare loosely.
h = {k.lower().replace("_", "-"): v for k, v in r["headers"].items()}
given, family = h.get("x-pomerium-claim-given-name"), h.get("x-pomerium-claim-family-name")
ok = r["reached"] and given == "Jean" and family == "Dupont"
print("  %s    admitted to %s with given_name=%s family_name=%s" % (
    "ok" if ok else "FAIL", r["url"], given, family))
sys.exit(0 if ok else 1)
EOF

echo "== an agent calls two API routes with tokens the gate issued against its grant"
"$PY" "$HERE/agent_drive.py" --loopback .localhost.pomerium.io --dir ./agent --gate https://localhost:9444 --cafile pki/tls.pem \
  --audience pomerium --read https://status.localhost.pomerium.io:8443/ \
  --write https://config.localhost.pomerium.io:8443/ > agent.out || fail=1
grep -v '^{' agent.out

echo "== control: the gate no longer trusts that issuer"
"$PY" -c '
import json
from cryptography.hazmat.primitives.asymmetric import ec
import base64
n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).rstrip(b"=").decode()
json.dump({"keys": [{"kty": "EC", "crv": "P-256", "x": b(n.x), "y": b(n.y)}]}, open("unrelated-jwks.json", "w"))'
start_gate unrelated-jwks.json
"$PY" "$HERE/drive.py" https://verify.localhost.pomerium.io:8443/ http://localhost:7006 "$WALLET_ID" "$KEY_ID" > refused.json
"$PY" - <<'EOF' || fail=1
import json, sys
r = json.load(open("refused.json"))
print("  %s    not admitted (ended at %s)" % ("FAIL" if r["reached"] else "ok", r["url"][:80]))
sys.exit(1 if r["reached"] else 0)
EOF

[ "$fail" -eq 0 ] && echo "RESULT: a person admitted by credential, an agent by grant, and every control refused" \
                  || { echo "RESULT: FAILED"; tail -20 gate.log; docker logs --tail 30 polaris-gate-pomerium 2>&1 | tail -30; }
exit "$fail"
