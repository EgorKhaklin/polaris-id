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

An agent gets in by what it can prove, too:

1. It asks `/agent/nonce` for a nonce, naming the relying party (`audience`).
2. It sends `/agent/token` its holder's grant chain and a proof over that nonce for one action. The
   chain is the issuer's credential, the issuer's binding of the holder key, and the holder's grant
   naming the agent's key and its actions (WIRE-SPEC 3.17, ML-DSA-65). `polaris-verify` decides
   every link.
3. The answer is an ES256 token for that one action and that relying party, valid for 60 seconds
   at most and never past the grant. Its `sub` is pairwise per holder, grant and action. `holder`
   is the holder's pairwise handle, `act.sub` the agent's, and `action` the action.
4. The holder ends a grant by sending its revocation to `/agent/revoke`. From then on the gate
   issues no token for it, even once the holder's binding is renewed. Tokens already issued run
   out within their minute.

A grant with use or amount limits is refused. Enforcing one takes a count of requests, and a proxy
admitting requests on a token keeps none. It is refused rather than widened.

Pending requests, codes, access tokens and agent nonces live in memory until they expire;
revocations live there until their grants would have expired. Nothing records who signed in
where, and there is no access log.

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

For agents, under real ML-DSA-65 chains (`grants.py` mints them), they check:
- a token per action, verified under the JWKS, with a subject per action and one holder handle
  per relying party;
- no token for an action outside the grant, a proof for another action, another agent's key, or an
  issuer the gate does not trust;
- a nonce serves one request, for one audience, and expires;
- only the grant's holder can revoke it, and a revoked grant stays revoked when its binding is
  renewed;
- a limited grant is refused, and a token never outlives its grant.

The agent tests need a `cryptography` with ML-DSA (`polaris_web/requirements.txt` pins one).

## Run the gate

    polaris-oid4vp keygen --out ./pki --host host.docker.internal --port 9443
    echo '{"pomerium": {"secret": "change-me", "redirect_uris": ["https://authenticate.localhost.pomerium.io/oauth2/callback"]}}' > clients.json
    python3 lab/strategy/007/gate.py --pki ./pki --clients clients.json --host host.docker.internal \
        --issuer-jwks issuer-jwks.json --grant-issuer-keys issuer.pub

Wallets reach the verifier on 9443. Relying parties discover the provider at
`https://host.docker.internal:9444/.well-known/openid-configuration`.

## Pomerium, end to end

    PYTHON=python3 lab/strategy/007/pomerium-demo.sh

It runs five things:
- the gate;
- walt.id's wallet (`waltid/wallet-api2:1.0.0`, unmodified), with one credential issued into it;
- Pomerium 0.33.3 (unmodified, pinned by digest), with the gate as its generic OIDC provider,
  protecting `traefik/whoami` on three routes;
- a headless browser standing in for the person;
- an agent (`agent_drive.py`) whose holder granted it `read:status` and `write:config`.

The browser opens the protected page, Pomerium sends it to the gate, the wallet presents, and
Pomerium admits the person; whoami shows the claims the gate released.

Then the agent calls two API routes. Each takes a bearer token (`bearer_token_format:
idp_identity_token`, so Pomerium verifies it as an ID token from its own OIDC provider, the gate)
and requires one action (`claim/action`). The agent gets a token for each action from the gate
and is admitted on that action's route only. Six controls follow:
- a token on the other action's route;
- the same proof sent twice;
- an action outside the grant;
- no token;
- the same claims signed by a key the gate never held;
- the holder revoking the grant.

Last, the gate stops trusting the credential's issuer, the same wallet presents again, and the
person is refused. The script exits 0 only if every one of these holds.

It needs Docker, a `python3` with `playwright` (Chromium installed) and a `cryptography` with
ML-DSA, and ports 7006, 8443, 9443 and 9444. `*.localhost.pomerium.io` no longer resolves in public
DNS (by 2026-10-04), so the script maps those names to 127.0.0.1 itself, for curl, the browser, the
agent and Pomerium's container. Measured 2026-10-01 on macOS with Docker Desktop, in
44 seconds once the images were local:

    ok    admitted to https://verify.localhost.pomerium.io:8443/ with given_name=Jean family_name=Dupont
    ok    the gate issued a token for read:status (200)
    ok    Pomerium admitted it to the read:status route (200, action=read:status)
    ok    and refused it on the write:config route (403)
    ok    a write:config token was admitted to its route (200, action=write:config)
    ok    the read:status token is still refused there afterwards (403)
    ok    the gate refused the same proof again, a replay (400 invalid_grant)
    ok    the gate refused an action outside the grant (403 access_denied)
    ok    Pomerium refused a request with no token (302)
    ok    Pomerium refused the same claims signed by a key the gate never held (403)
    ok    the holder revoked the grant at the gate (200)
    ok    the gate refused the agent from then on (403: the holder revoked this grant)
    ok    not admitted (ended at https://authenticate.localhost.pomerium.io:8443/oauth2/callback?error=access_den)
    RESULT: a person admitted by credential, an agent by grant, and every control refused

Pomerium needed no change. People sign in through `idp_provider: oidc` and the gate's URL, as for
any OIDC provider. Agents use two of its documented route settings: `bearer_token_format` and a
`claim/` policy. Pomerium listens on 8443 inside its container too, because it verifies a bearer
token through its own authenticate URL.

## The agent half with only Docker

`pomerium-demo.sh` needs a host Python with Playwright for the person's browser. The agent half
needs no browser, so it also runs with **only Docker**, through `compose.yaml`:

    docker compose -f lab/strategy/007/compose.yaml up --build --exit-code-from driver
    docker compose -f lab/strategy/007/compose.yaml down -v        # afterwards

Four containers: the gate (built from [`Dockerfile`](Dockerfile), carrying only `cryptography`),
unmodified Pomerium and `traefik/whoami` (both pinned), and the agent. The gate writes its own
certificates and a fresh ML-DSA-65 grant on start; the agent then gets a per-action token and
calls the two protected routes, with the same controls as above. The run exits 0 only if the
agent is admitted on each action's route and every control is refused. Measured 2026-10-01 on
macOS with Docker Desktop, 9 seconds once the image was built:

    ok    the gate issued a token for read:status (200)
    ok    Pomerium admitted it to the read:status route (200, action=read:status)
    ok    and refused it on the write:config route (403)
    ok    a write:config token was admitted to its route (200, action=write:config)
    ok    the read:status token is still refused there afterwards (403)
    ok    the gate refused the same proof again, a replay (400 invalid_grant)
    ok    the gate refused an action outside the grant (403 access_denied)
    ok    Pomerium refused a request with no token (302)
    ok    Pomerium refused the same claims signed by a key the gate never held (403)
    ok    the holder revoked the grant at the gate (200)
    ok    the gate refused the agent from then on (403: the holder revoked this grant)

## Status

- Step 2, the gate and its tests: done.
- Step 3, Pomerium end to end with a foreign wallet: done.
- Step 4, agent grants as short-lived tokens Pomerium checks on every request: done.
