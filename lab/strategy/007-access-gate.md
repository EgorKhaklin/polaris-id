# 007: a gate that admits people and agents by credential

**Opened 2026-10-01.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md).
State: OPEN. The falsifiers below were written first (632b01b4). Step 2, the gate and its tests
([`007/`](007/README.md)), followed the same day.

---

## The finding that started it

Two halves of an access gate are in the tree and do not meet.

- The OpenID4VP verifier (`packages/polaris-oid4vp`, 1.0.0rc7 OpenID Certified to the OID4VP 1.0 + HAIP
  1.0 Verifier profile) decides a wallet's presentation. It answers only the lab harness and the test
  suites.
- The auth broker (P8.4, `polaris_web/rp_auth.py`) gives a relying party a `polaris-id-token/1`. Its
  subject is a credential hash under that relying party's scope, and nothing records who logged in
  where. But the token is ML-DSA-signed in a Polaris format, and no access proxy reads it.

Meanwhile every identity-aware proxy surveyed on 2026-10-01 admits users through one interface: a
generic OpenID Connect provider. That covers AWS Verified Access, Google IAP, Cloudflare Access,
Pomerium, oauth2-proxy, OpenZiti, Tailscale, Headscale and NetBird; Entra takes one only as an
external MFA method.

- **Kept:** the broker's position that a login leaves no record of who logged in where, and that the
  subject is derived under the relying party's own scope.
- **Kept:** the certified verifier as the only thing that decides a presentation.
- **Dropped:** a Polaris-only token as the sole output of a login. It has no consumer.
- **New position:** a gate the relying organisation runs itself. A wallet presentation goes in, and a
  standard OIDC ID token comes out (ES256, which every consumer verifies), with a pairwise subject per
  client. A holder's agent grant goes in, and a short-lived, audience-bound token comes out that a
  proxy checks on every request.

Post-quantum signatures stay where they are verified, in the credential and the grant. The token a
proxy reads is classical because the proxies are.

## 1. What capability is being considered?

An OIDC provider (discovery, authorize, token, JWKS, userinfo) whose sign-in step is an OpenID4VP
presentation decided by `polaris-oid4vp`. It also mints per-request tokens for agents that present a
valid agent grant and agent proof.

## 2. What problem would it solve?

A person can hold a credential, but no access proxy will admit them by it. An organisation also cannot
admit a partner's employee by the credential that employer issued without federating identity
providers first. And an agent's authority is delegated through an identity provider, not by the
person who holds it.

## 3. Who would plausibly need it?

- Teams running an open-source proxy who want credential-based admission without an IdP vendor.
- Operators of MCP servers who must decide what an agent may do on a person's behalf.
- Organisations admitting contractors or partners.

## 4. What already solves it?

- Wallet-to-OIDC bridges: Keycloak 26.8 (experimental OID4VP, released 2026-10-01, not certified),
  walt.id's OIDC bridge (Enterprise), Gataca Vouch and Hopae Connect.
- Delegation mediated by an identity provider: Entra Agent ID, Okta Cross App Access, Auth0 for AI
  Agents and Aembit.
- Commercial verifiable-credential delegation chains: Dock/Truvera.

## 5. Can Polaris interoperate instead of rebuild?

That is the whole design. The gate rebuilds no proxy, policy engine or IdP. It speaks OIDC to all of
them, and Keycloak can broker it as an upstream IdP.

## 6. What unique advantage could Polaris obtain?

The combination nobody else ships:
- a certified HAIP verifier;
- self-hosting per organisation, with pairwise subjects, so no shared service sees every login;
- agent grants issued and revoked by the holder, proven on each request;
- holder-of-key assertions;
- partner credentials accepted without IdP federation.

## 7. What happens if Polaris does NOT build it?

The certified verifier keeps answering only a test harness, and the agent-grant chain stays a
conformance suite with no enforcement point. Wallet-to-OIDC becomes a Keycloak feature either way.

## 8. What other work would be delayed?

None of the release work: the doors (STRANGER-PATH, `polaris-verify`, `polaris-oid4vp`, the SDKs)
stay first. The gate takes the time after them.

## 9. Can the idea be tested cheaply in LAB first?

Yes, entirely in `lab/strategy/007/`, nothing in `packages/`:
1. the gate's OIDC face over the existing verifier;
2. Pomerium in Docker, protecting a sample upstream, admitting a person whose wallet (eudi-dev or
   walt.id, both already scripted) presented to the gate;
3. an agent grant minted into a per-request token that Pomerium checks with a claim policy.

## 10. What evidence would prove the bet was wrong?

Written before the work:
- **No outsider by 2026-11-12.** No named person or team outside the project runs the Pomerium
  demonstration by that date: the bet is wrong and the record closes as KILLED.
- **Pairwise subjects do not survive.** If they cannot survive the claims a proxy policy needs
  (correlation through a disclosed claim), the privacy advantage is not real. The gate then narrows to
  agent grants or closes.
- **Pomerium cannot enforce the agent path unmodified.** If Pomerium cannot enforce the
  agent-grant path without code changes on its side, the agent half is not interoperation. It closes,
  and the human half stands alone.
- **Keycloak gets there first.** If Keycloak's OID4VP path becomes stable and certified before the gate
  has an outside user, the gate's value is the verifier and the grants, not the OIDC face. The record
  pivots to a Keycloak integration.
