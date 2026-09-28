# 005, section 9 step 1: the wall an OpenID4VCI issuer has to clear

2026-09-27. What an OpenID4VCI 1.0 issuer has to implement, what HAIP 1.0 adds, what the
OpenID Foundation's issuer test plan exercises, and what the two wallets already on the
scoreboard send. Every item below names its source. The survey read the pages through a
summarising fetcher, so a section number here is a pointer, and it gets checked against the
specification text before any sentence outside the lab quotes it.

## The base specification (OpenID4VCI 1.0 Final)

Source: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>

- **Mandatory:** the Credential Endpoint.
- **Optional:** the Credential Offer, `tx_code`, the deferred endpoint and notification.
- **Conditional:** a Nonce Endpoint, if the issuer requires `c_nonce`.
- **Metadata:** at `/.well-known/openid-credential-issuer`, with authorization server
  metadata per RFC 8414.
- **Grant types:** the base specification mandates neither grant type.

A pre-authorized-code issuer with a nonce endpoint and `jwt` proofs is therefore a complete
OpenID4VCI issuer.

## What HAIP 1.0 adds for an issuer

Source: <https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html>

- **The authorization code grant, required.** The pre-authorized code is not in the profile.
  The FAPI 2.0 Security Profile applies, with PKCE S256 and PAR at the authorization endpoint.
- **DPoP, required,** including `DPoP-Nonce`.
- **Client authentication, required of every wallet.** The attestation-based format is
  recommended rather than required, but the conformance plan fixes it (see below).
- **`x5c` on credentials and status list tokens:** the chain excludes the trust anchor, and the
  signing certificate is not self-signed.
- **Algorithm and validity:** ES256; `exp`, a Token Status List, or both.
- **Batch issuance** is signalled in metadata.

## The OpenID Foundation issuer test plan

Sources: `oid4vci-1_0-issuer-haip-test-plan` in the conformance suite
(`VCIIssuerTestPlanHaip.java`), and
<https://openid.net/certification/conformance-testing-for-openid-for-verifiable-credential-issuance/>.

- **What the plan fixes:** client attestation for client authentication, DPoP as the sender
  constraint, and the authorization code grant.
- **What the suite plays:** an emulated wallet. The tester supplies the attester keys and a
  PEM trust anchor, and the issuer has to be configured to trust that attester.
- **The modules include:**
  - six negative client-attestation modules;
  - proof and nonce refusals;
  - the FAPI 2.0 Security Profile modules.
  - One implementer counts 61 modules in all.
- **Public reachability:** the hosted suite reaches the issuer over public HTTPS.
- **Self-certified issuers listed:** small ones among them (a single-author Go implementation,
  and ProtocolSoup), so the wall is scope, not infrastructure an individual cannot run.

## The two wallets

- **Credo 0.6.3.** It does both grants, DPoP "if supported by the authorization server",
  wallet attestation and key attestation (the calling code supplies the attestation JWTs), and
  `dc+sd-jwt`.
- **walt.id Wallet API v2 1.0.0.** It is a holder for both grants and SD-JWT VC. DPoP from the
  wallet is not confirmed in 1.0.0. Client attestation depends on an attestation service. A fix
  for the proof's `iss` on the authorization code grant was merged after 1.0.0
  (waltid-identity PR 2246).

## What this does to the bet

**No kill criterion fires.** Nothing here needs infrastructure a documented Polaris deployment
cannot run, and a private CA is enough for the certificate chain. The step does split the
record in two, because the cheap path and the certifiable path are different protocols:

1. **The wallet loop** decides kill criteria 1 and 2 (the binding, and the absence of
   workarounds). It is a pre-authorized-code issuer with `jwt` proofs, which both wallets take
   through their public APIs, with Polaris's issuance rules behind it. It is small, and
   section 9 steps 2 and 3 run on it.
2. **The certification** is a FAPI 2.0 authorization server: the authorization code grant,
   PAR, DPoP with nonces, attestation-based client authentication that passes six negative
   modules, and a certificate chain. That is the larger half, and walt.id 1.0.0 may not reach
   it without a later release. It is decided on its own after stage 1, and only if stage 1
   survives.

The record's third criterion ("the wall is infrastructure") does not fire. The size of stage
2 is a cost, not a falsifier, and it is written here so the decision to take it on is made
knowing it.
