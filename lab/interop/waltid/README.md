# walt.id Wallet API v2 → polaris-oid4vp

The sequence that produced the row in [`EXTERNAL-NOUNS.md`](../../../EXTERNAL-NOUNS.md).
walt.id runs unmodified at a pinned digest; only its configuration is touched.

## 1. The wallet

    docker run -d --name polaris-waltid -p 7006:7006 \
      waltid/wallet-api2:1.0.0   # sha256:d2248288f41ceba029a7fd943fed623ef7f0f846edfee666ac6f7e621c4d739e

Standalone is enough: it uses SQLite and needs neither Postgres nor the compose stack.

    curl -X POST localhost:7006/stores/keys/polaris        -H 'Content-Type: application/json' -d '{}'
    curl -X POST localhost:7006/stores/credentials/polaris -H 'Content-Type: application/json' -d '{}'
    curl -X POST localhost:7006/stores/dids/polaris        -H 'Content-Type: application/json' -d '{}'
    curl -X POST localhost:7006/wallet -H 'Content-Type: application/json' \
      -d '{"keyStoreIds":["polaris"],"credentialStoreIds":["polaris"],"didStoreId":"polaris","noDidStore":false}'
    curl -X POST localhost:7006/wallet/$WID/keys/generate -H 'Content-Type: application/json' \
      -d '{"backend":"jwk","keyType":"secp256r1"}'

`backend`, not `type`, is the discriminator; the OpenAPI schema names `type` and the server
rejects it. The key endpoint does not return the public JWK, so read it out of a `did:jwk`:

    curl -X POST localhost:7006/wallet/$WID/dids/create -H 'Content-Type: application/json' \
      -d '{"method":"jwk","keyId":"'$KID'","options":{}}'

## 2. The credential

`issue_sdjwt_vc.py` mints one SD-JWT VC whose `cnf.jwk` is the key walt.id just generated,
so the key binding JWT it later produces is signed by a private key this repository has
never seen. That is the whole point; without it the exchange proves nothing.

    python3 issue_sdjwt_vc.py --holder-jwk waltid.json --out credential.json
    curl -X POST localhost:7006/wallet/$WID/credentials/import \
      -H 'Content-Type: application/json' -d '{"rawCredential":"<the ~-joined credential>"}'

walt.id parses `typ: dc+sd-jwt` (the OpenID4VP 1.0 final identifier, not the older
`vc+sd-jwt`) and reports both disclosures with their salts.

## 3. The verifier

    polaris-oid4vp keygen --out ./pki --host host.docker.internal --port 9443
    polaris-oid4vp serve  --pki ./pki --host host.docker.internal --bind 0.0.0.0 \
                          --port 9443 --issuer-jwks issuer-jwks.json --once

Two configuration steps on the walt.id side, both legitimate registration rather than
workarounds:

  * **TLS.** The listener's certificate is self-signed, and walt.id is right to refuse it.
    `keytool -importcert -file pki/tls.pem -keystore /opt/java/openjdk/lib/security/cacerts
    -storepass changeit` inside the container.
  * **The request-object trust anchor**, which is the registration `keygen` already tells
    you to perform. In `/waltid-wallet-api2/config/wallet-service.conf`:

        clientIdTrust { x509TrustAnchors = ["-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"] }

    PEM, as one quoted string with escaped newlines. The type's own comment says "DERs in
    base64 format"; base64 DER crashes the service with `Invalid PEM` at startup, which is
    also the quickest way to prove the key is being read at all.

## 4. The exchange

    curl -X POST localhost:7006/wallet/$WID/credentials/present \
      -H 'Content-Type: application/json' \
      -d '{"requestUrl":"openid4vp://authorize?client_id=...&request_uri=...&request_uri_method=post","keyId":"'$KID'"}'

    {"transmission_success":true,"verifier_response":{"redirect_uri":"..."}}

and on the verifier:

    <- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']

**Use `/credentials/present`, not `/credentials/present/resolve-request`.** The latter is
the only route in walt.id's handler file that is not passed `clientIdTrustConfiguration`,
so it reports `MissingX509TrustAnchors` no matter what is configured.

## 5. The controls, without which none of the above means anything

A verifier that accepts everything prints the same success line.

  * **Wrong issuer key.** Serve with a JWKS holding a different key under the same `kid`.
    Same wallet, same credential, same path: `400 refused: issuer_signature`. walt.id is
    told only `the presentation was not accepted`.
  * **Replay.** Present twice against one `state`: the second is refused at the request
    stage with `no such outstanding request`.
