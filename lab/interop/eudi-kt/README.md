# EU reference OpenID4VP library (holder) → polaris-oid4vp

A wallet built on `eu.europa.ec.eudi:eudi-lib-jvm-openid4vp-kt`, the OpenID4VP library of the
European Commission's EUDI Wallet reference implementation, presents an SD-JWT VC over OpenID4VP 1.0
`direct_post.jwt` to `polaris-oid4vp` as installed from PyPI.

The wallet is [`wallet/src/main/kotlin/Wallet.kt`](wallet/src/main/kotlin/Wallet.kt), about a hundred
lines. The library does the protocol:
- it resolves the authorization request: `x509_hash`, the signed request object fetched by POST with
  wallet metadata, and the DCQL query;
- it dispatches the response, encrypted to the verifier's key (`ECDH-ES`).

The wallet does only what the library leaves to a wallet: it decides whom to trust and builds the
presentation. A request object is trusted only when its `x5c` holds a certificate signed by the anchor
`polaris-oid4vp keygen` made. The presentation is the credential plus a key binding JWT (`aud`, `nonce`,
`iat`, `sd_hash`), built the way the library's own `Example.kt` builds one. Its OpenID4VP is the
library's own, a fifth implementation beside walt.id's, Credo's, eudi-dev's and OID4VCgo's.

## Run it

    lab/interop/eudi-kt/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc14 lab/interop/eudi-kt/run.sh

[`run.sh`](run.sh) runs everything in a scratch directory (`WORK`):
- `polaris-oid4vp` from PyPI in a fresh venv, its dependencies by hash;
- the wallet, compiled in a JDK image pinned by digest. Every library is checked against
  [`wallet/gradle/verification-metadata.xml`](wallet/gradle/verification-metadata.xml), so a
  dependency that changes under its version fails the build;
- the verifier's test PKI, a holder key, and one credential bound to that key
  (`../waltid/issue_sdjwt_vc.py`);
- the presentation and the four controls.

It exits 0 only if the presentation is accepted and every control is refused. Docker is required.
The verifier listens on port 9443 (`PORT`).

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts a different issuer key under the same `kid` | the verifier | `<- 400 refused: issuer_signature`; the library reported `Rejected` |
| (b) | The same request presented again after it was answered | the verifier, at the request | the library: `UnableToFetchRequestObject`, `404 Not Found` |
| (c) | The launch URI names a `client_id` that is not the signed request's | the wallet | the library: `InvalidJarJwt(ClientId mismatch. JAR request x509_hash:AAAA..., jwt x509_hash:...)` |
| (d) | The wallet trusts an unrelated CA for the verifier | the wallet | the library: `InvalidJarJwt(Untrusted x5c)` |

(c) and (d) are controls on the library. (c) shows it compares the signed request object with what it
was launched with. (d) shows the trust decision the wallet hands it is the one it applies, rather
than presenting to whatever it is pointed at.

## Result, 2026-10-03

Against `polaris-oid4vp` 1.0.0rc14 from PyPI, with `eudi-lib-jvm-openid4vp-kt` 0.16.2 (Ktor 3.3.3,
OkHttp) on JDK 21: accepted, `<- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat',
'iss', 'vct']`, and the library reported `Accepted`. All four controls were refused.

Re-walked 2026-10-04 against `polaris-oid4vp` 1.0.0rc15 from PyPI, built with Kotlin 2.4.20 and
Bouncy Castle 1.86: accepted, `<- 200 authentic`, and all four controls refused. The library brings
Bouncy Castle 1.83, which OSV lists advisories against (fixed in 1.85), and Kotlin 2.2.21 had one in
its build cache (fixed in 2.4.20); [`build.gradle.kts`](wallet/build.gradle.kts) lifts both. The
verification metadata now lists only what the build resolves (121 components, no OSV advisory),
regenerated with `gradle --write-verification-metadata sha256 installDist` after removing the old
file. Generate it from an empty Gradle cache: a warm cache resolved the plugin classpath without
`kotlinx-coroutines-bom` 1.8.0, which a clean machine fetches from the Gradle plugin portal, and the
first CI run of this walk failed on it (2026-10-04). Its SHA-256 matches the copy on Maven Central.

## What this does not establish

- It is a wallet built here on the library, not the EUDI reference wallet app. The library is the
  part that speaks OpenID4VP: it fetched, checked and answered the request. The trust decision and
  the presentation are this repository's few lines, as they are any wallet's.
- One credential format and one path, ES256 throughout. The credential was minted by this
  repository's issuer script and trusted through a JWKS.
- Same category as the other rows: the author drove a published library on one machine. It is not
  an outside party using Polaris, and not a claim of interoperability in general.
