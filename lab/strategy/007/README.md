# lab/strategy/007: the access gate

Lab code for [record 007](../007-access-gate.md), not a product. Its falsifiers are in the record
and were written before this code.

`gate.py` is an OpenID Connect provider whose sign-in is a wallet presentation:

1. A relying party sends a person to `/authorize`. This is any OIDC client: an identity-aware proxy
   such as Pomerium, or an application.
2. The person's wallet presents a credential to `polaris-oid4vp`'s certified verifier, embedded here
   unchanged.
3. The relying party exchanges a code at `/token` for an ID token. The token is ES256, its subject is
   pairwise per client (an HMAC of the client and the holder key's RFC 7638 thumbprint), and it carries
   `given_name` and `family_name` only under the `profile` scope.

Pending requests, codes and access tokens live in memory until they expire. Nothing records who
signed in where, and there is no access log.

## Run the tests

    python3 -m unittest lab/strategy/007/test_gate.py

They drive the whole flow with `polaris-oid4vp`'s own test wallet, which the verifier judges for
real, and they check:

- the ID token against the published JWKS;
- that two clients see two subjects and one client sees one;
- that a refused presentation issues no code;
- that a code is single-use and bound to its client, redirect URI and PKCE verifier;
- that requests and codes expire;
- that nothing is kept after the exchange.

## Run the gate

    polaris-oid4vp keygen --out ./pki --host host.docker.internal --port 9443
    echo '{"pomerium": {"secret": "change-me", "redirect_uris": ["https://authenticate.localhost.pomerium.io/oauth2/callback"]}}' > clients.json
    python3 lab/strategy/007/gate.py --pki ./pki --clients clients.json --host host.docker.internal \
        --issuer-jwks issuer-jwks.json

Wallets reach the verifier on 9443. Relying parties discover the provider at
`https://host.docker.internal:9444/.well-known/openid-configuration`.

## Pomerium, end to end

    PYTHON=python3 lab/strategy/007/pomerium-demo.sh

It runs four things:
- the gate;
- walt.id's wallet (`waltid/wallet-api2:1.0.0`, unmodified), with one credential issued into it;
- Pomerium 0.33.3 (unmodified, pinned by digest), with the gate as its generic OIDC provider,
  protecting `traefik/whoami`;
- a headless browser standing in for the person.

The browser opens the protected page, Pomerium sends it to the gate, the wallet presents, and
Pomerium admits the person; whoami shows the claims the gate released. Then the gate stops trusting
the credential's issuer, the same wallet presents again, and the person is refused. The script
exits 0 only if both happen.

It needs Docker, a `python3` with `cryptography` and `playwright` (Chromium installed), and ports
7006, 8443, 9443 and 9444. Measured 2026-10-01 on macOS with Docker Desktop, in 42 seconds once
the images were local:

    ok    admitted to https://verify.localhost.pomerium.io:8443/ with given_name=Jean family_name=Dupont
    ok    not admitted (ended at https://authenticate.localhost.pomerium.io:8443/oauth2/callback?error=access_den)
    RESULT: admitted by credential, and refused when the issuer is not trusted

Pomerium needed no change: it is configured with `idp_provider: oidc` and the gate's URL, as for
any OIDC provider.

## Status

- Step 2, the gate and its tests: done.
- Step 3, Pomerium end to end with a foreign wallet: done.
- Step 4, agent grants as per-request tokens Pomerium checks: next.
