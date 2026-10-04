# vck (holder and issuer) → polaris-oid4vp

A wallet built on [vck](https://github.com/a-sit-plus/vck), A-SIT Plus's Kotlin Multiplatform
credential library, presents an SD-JWT VC over OpenID4VP 1.0 `direct_post.jwt` to
`polaris-oid4vp` as installed from PyPI. vck also issued the credential, so the verifier is the
only Polaris software in the exchange.

The wallet is [`wallet/src/main/kotlin/Wallet.kt`](wallet/src/main/kotlin/Wallet.kt), about a
hundred lines. vck does the work:
- its `IssuerAgent` signs the credential (`urn:eudi:pid:1`, `given_name` and `family_name`
  selectively disclosable), bound to a holder key made here;
- its `HolderAgent` checks the issuer's signature before storing the credential;
- its `OpenId4VpWallet` resolves the request (`x509_hash`, the signed request object fetched by
  POST with wallet metadata and a wallet nonce, the DCQL query), builds the presentation (the
  disclosures and the key binding JWT) and dispatches the response, encrypted to the verifier's
  key (`ECDH-ES`).

The program only wires the keys, the stored credential and the anchor the wallet trusts for the
verifier: a request object is trusted only when its `x5c` chains to the anchor
`polaris-oid4vp keygen` made (`RelyingPartyTrust.Certificates`). Its OpenID4VP is vck's own, a
sixth implementation beside walt.id's, Credo's, eudi-dev's, OID4VCgo's and the EU reference
library's.

## Run it

    lab/interop/vck/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/vck/run.sh

[`run.sh`](run.sh) runs everything in a scratch directory (`WORK`):
- `polaris-oid4vp` from PyPI in a fresh venv, its dependencies by hash;
- the wallet, compiled in a JDK image pinned by digest. Every library is checked against
  [`wallet/gradle/verification-metadata.xml`](wallet/gradle/verification-metadata.xml), written
  from an empty Gradle cache, so a dependency that changes under its version fails the build;
- the verifier's test PKI, and a holder and an issuer key;
- the credential, issued by vck, then the presentation and the three controls.

It exits 0 only if the presentation is accepted and every control is refused. Docker is required.
The verifier listens on port 9444 (`PORT`).

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts a different issuer key | the verifier | `<- 400 refused: issuer_signature`; vck reported `DISPATCH FAILED ... the presentation was not accepted` |
| (b) | The same request presented again after it was answered | the verifier, at the request | vck: `REQUEST REFUSED ... no such outstanding request` |
| (c) | The wallet trusts an unrelated CA for the verifier | the wallet | vck: `InvalidRequest: ... not trusted by any configured trusted relying party certificates` |

vck names the issuer's key by a JWK in the credential's header, which is how its holder checks
the signature before storing it. The verifier ignores that header: it trusts only the keys it was
given (`--issuer-jwks`), which is what (a) shows. (c) is a control on the library: the trust
decision the wallet hands it is the one it applies.

## Result, 2026-10-04

Against `polaris-oid4vp` 1.0.0rc15 from PyPI, with `vck-openid-ktor` 8.0.0 (Ktor 3.5.2, CIO) on
JDK 21: accepted, `<- 200 authentic, claims ['cnf', 'exp', 'family_name', 'given_name', 'iat',
'iss', 'nbf', 'status', 'sub', 'vct']`, and vck reported `AuthenticationSuccess`. All three
controls were refused.

## What this does not establish

- It is a wallet built here on the library, not a wallet app. The library is the part that
  speaks OpenID4VP and SD-JWT VC: it issued, fetched, checked and answered. The trust decision
  and the keys are this repository's few lines, as they are any wallet's.
- The credential carries a `status` claim (vck adds one). The CLI harness resolves no status
  list (status is opt-in in the `Verifier` API), so this run says nothing about revocation.
- One credential format and one path, ES256 throughout.
- Same category as the other rows: the author drove a published library on one machine. It is not
  an outside party using Polaris, and not a claim of interoperability in general.
