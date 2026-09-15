#!/usr/bin/env bash
# setup.sh -- the mechanical half of the stranger's path.
#
# Creates a wallet in a running walt.id, has walt.id generate its own P-256 key, mints one
# SD-JWT VC bound to that key, imports it, and wires walt.id to trust the verifier's PKI.
# None of that teaches you anything, which is why it is a script and the interesting parts
# are not.
#
#   ./setup.sh ./pki
#
# Prints the two values `serve` and the presentation need.
set -euo pipefail

PKI="${1:?usage: ./setup.sh <pki-dir-from-polaris-oid4vp-keygen>}"
WALTID="${WALTID:-http://localhost:7006}"
CONTAINER="${CONTAINER:-polaris-waltid}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"

for f in anchor.pem tls.pem; do
  [ -f "$PKI/$f" ] || { echo "no $PKI/$f -- run polaris-oid4vp keygen first" >&2; exit 2; }
done
curl -sf -m 5 "$WALTID/livez" >/dev/null || { echo "walt.id is not answering at $WALTID" >&2; exit 2; }

say() { printf '  %-22s %s\n' "$1" "$2"; }

# 1. Stores and a wallet. `noDidStore:false` matters: the key endpoint does not return a
#    public JWK, so the only way to read one out is to make a did:jwk from it.
for s in keys credentials dids; do
  curl -sf -X POST "$WALTID/stores/$s/stranger" -H 'Content-Type: application/json' -d '{}' >/dev/null || true
done
WID=$(curl -sf -X POST "$WALTID/wallet" -H 'Content-Type: application/json' \
  -d '{"keyStoreIds":["stranger"],"credentialStoreIds":["stranger"],"didStoreId":"stranger","noDidStore":false}' \
  | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["walletId"])')

# 2. walt.id generates the holder key. `backend` is the discriminator, not `type`: the
#    OpenAPI schema says type and the server rejects it.
KID=$(curl -sf -X POST "$WALTID/wallet/$WID/keys/generate" -H 'Content-Type: application/json' \
  -d '{"backend":"jwk","keyType":"secp256r1"}' \
  | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["keyId"])')

DIDDOC=$("$PY" - "$WALTID" "$WID" "$KID" <<'PYEOF'
import json, sys, urllib.request
waltid, wid, kid = sys.argv[1:4]
req = urllib.request.Request("%s/wallet/%s/dids/create" % (waltid, wid),
    data=json.dumps({"method": "jwk", "keyId": kid, "options": {}}).encode(),
    headers={"Content-Type": "application/json"}, method="POST")
doc = json.load(urllib.request.urlopen(req, timeout=30))
jwk = doc["document"]["verificationMethod"][0]["publicKeyJwk"]
print(json.dumps({"holder_jwk": jwk}))
PYEOF
)
echo "$DIDDOC" > holder.json

# 3. One SD-JWT VC whose cnf.jwk is the key walt.id just generated. The key binding JWT it
#    later signs is therefore signed by a private key you do not have either.
"$PY" "$HERE/issue_sdjwt_vc.py" --holder-jwk holder.json --out credential.json >/dev/null
"$PY" -c '
import json
d = json.load(open("credential.json"))
json.dump(d["issuer_jwks"], open("issuer-jwks.json", "w"))
json.dump({"rawCredential": d["credential"]}, open("import.json", "w"))
'
curl -sf -X POST "$WALTID/wallet/$WID/credentials/import" -H 'Content-Type: application/json' \
  --data @import.json >/dev/null

# 4. Two things walt.id must trust: the listener's TLS certificate, and the CA that signs
#    the request object. The second is the registration `keygen` already tells you to do.
docker cp "$PKI/tls.pem" "$CONTAINER:/tmp/polaris-tls.pem" >/dev/null
docker exec "$CONTAINER" keytool -importcert -noprompt -trustcacerts -alias polaris-stranger \
  -file /tmp/polaris-tls.pem -keystore /opt/java/openjdk/lib/security/cacerts \
  -storepass changeit >/dev/null 2>&1 || true
"$PY" -c '
pem = open("'"$PKI"'/anchor.pem").read().strip().replace(chr(10), "\\n")
open("wallet-service.conf", "w").write(
    "publicBaseUrl = \"http://localhost:7006\"\n\nclientIdTrust {\n  x509TrustAnchors = [\"" + pem + "\"]\n}\n")
'
docker cp wallet-service.conf "$CONTAINER:/waltid-wallet-api2/config/wallet-service.conf" >/dev/null
docker restart "$CONTAINER" >/dev/null
for _ in $(seq 30); do curl -sf -m 2 "$WALTID/livez" >/dev/null 2>&1 && break; sleep 1; done

echo "ready:"
say "wallet"   "$WID"
say "key"      "$KID"
say "issuer"   "issuer-jwks.json"
echo "$WID" > wallet-id.txt
echo "$KID" > key-id.txt
