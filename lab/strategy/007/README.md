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

## Status

- Step 2, the gate and its tests: done.
- Step 3, Pomerium end to end with a foreign wallet: next.
- Step 4, agent grants as per-request tokens: after step 3.
