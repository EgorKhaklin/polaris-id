#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
#
# compose-init.sh -- prepare the shared /work volume for the container-only agent demo
# (compose.yaml): the gate's certificates (named for the `gate` service), an ML-DSA-65 agent
# grant, the OIDC client, and Pomerium's config. Runs once in the gate image; the other
# services wait for it to finish.
set -eu
WORK=/work

echo "[init] gate certificates (host=gate, the compose service name)"
python -m polaris_oid4vp.cli keygen --out "$WORK/pki" --host gate --port 9443 >/dev/null

echo "[init] an issuer, a holder, and the agent it grants read:status and write:config"
python /app/lab/strategy/007/grants.py mint --out "$WORK/agent" --actions read:status,write:config

echo "[init] the OIDC client and Pomerium's config"
python - <<'PY'
import base64, json, secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
WORK = "/work"
secret = secrets.token_urlsafe(24)
json.dump({"pomerium": {"secret": secret,
                        "redirect_uris": ["https://authenticate.localhost.pomerium.io:8443/oauth2/callback"]}},
          open(WORK + "/clients.json", "w"))
b64 = lambda raw: base64.b64encode(raw).decode()
signing = ec.generate_private_key(ec.SECP256R1()).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
open(WORK + "/pomerium.yaml", "w").write("""address: ":8443"
authenticate_service_url: https://authenticate.localhost.pomerium.io:8443
idp_provider: oidc
idp_provider_url: https://gate:9444
idp_client_id: pomerium
idp_client_secret: %s
certificate_authority_file: /work/pki/tls.pem
shared_secret: %s
cookie_secret: %s
signing_key: %s
jwt_claims_headers: [action, holder]
routes:
  - from: https://status.localhost.pomerium.io:8443
    to: http://whoami:80
    bearer_token_format: idp_identity_token
    pass_identity_headers: true
    policy:
      - allow:
          and:
            - claim/action: read:status
  - from: https://config.localhost.pomerium.io:8443
    to: http://whoami:80
    bearer_token_format: idp_identity_token
    pass_identity_headers: true
    policy:
      - allow:
          and:
            - claim/action: write:config
""" % (secret, b64(secrets.token_bytes(32)), b64(secrets.token_bytes(32)), b64(signing)))
print("[init] wrote clients.json and pomerium.yaml")
PY

echo "[init] done"
