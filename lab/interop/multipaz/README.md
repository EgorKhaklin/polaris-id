# Multipaz (holder) → polaris-oid4vp

A wallet built on [Multipaz](https://github.com/openwallet-foundation/multipaz), the identity
credential library Google started and the OpenWallet Foundation now hosts (Kotlin Multiplatform,
Apache-2.0), presents an SD-JWT VC over OpenID4VP 1.0 `direct_post.jwt` to `polaris-oid4vp` as
installed from PyPI. Multipaz runs on its JVM target, from Maven Central, with no Android and no UI.

The wallet is [`wallet/src/main/kotlin/Wallet.kt`](wallet/src/main/kotlin/Wallet.kt), about a
hundred lines. Multipaz does the protocol, in its `uriSchemePresentment()`:
- it fetches the signed request object by POST (`request_uri_method=post`) and checks its type and
  its signature against the `x5c` leaf;
- it asks the wallet whether the verifier is trusted, and matches the DCQL query against its
  document store;
- it builds the presentation, the requested disclosures and a key binding JWT (`aud` the
  `client_id`, `nonce`, `sd_hash`) signed by the holder key in its software secure area, and posts
  the response encrypted to the verifier's key (`ECDH-ES`).

Whether the verifier is trusted is decided by Multipaz's trust manager (`ConfigurableTrustManager`),
which the wallet loads with the anchor `polaris-oid4vp keygen` made. Multipaz hands that verdict to
the wallet's consent step, which in a wallet app is a prompt to the user. This wallet has no user:
it consents (Multipaz's `promptModelSilentConsent`) to a verifier the trust manager trusts and
declines any other. Its OpenID4VP is Multipaz's own, a seventh implementation beside walt.id's,
Credo's, eudi-dev's, OID4VCgo's, the EU reference library's and vck's.

Two things differ from the other JVM walks, both measured on 2026-10-04:
- **The verifier's certificates are re-issued with key identifiers.** Multipaz's trust manager
  finds a CA by key identifier: the CA's Subject Key Identifier against the Authority Key
  Identifier of the certificate it signed, the two extensions RFC 5280 has a conforming CA include
  (4.2.1.1, 4.2.1.2). `keygen`'s test certificates carry neither. With them as written, the trust
  manager skipped the anchor (`Skipping certificate without SKI`) and the wallet declined the
  genuine request. [`run.sh`](run.sh) re-issues the pair under a new CA key (`keygen` keeps none)
  with the identifiers added and nothing else changed: the same leaf key, names, validity and
  extensions.
- **The issuer is named by `x5c`.** Multipaz reads a stored SD-JWT VC's claims only through an
  issuer certificate in its header (`Only X509-certified keys are supported in SD-JWT`), so a
  credential naming its issuer by `kid` matched nothing. The credential is minted by
  `../waltid/issue_sdjwt_vc.py --x5c` under a CA made for the run, and the verifier trusts that CA
  (`--issuer-trust-anchor`).

## Versions

| | |
|---|---|
| Wallet library | `org.multipaz:multipaz` 0.101.0 (2026-09-10) from Maven Central, its JVM jar `multipaz-jvm-0.101.0.jar` (`sha256:ae868d3d9d3ad91f0735bdec8c0dda57d69855624724a8982f580019dc72bb11`), Apache-2.0, [source](https://github.com/openwallet-foundation/multipaz) |
| Wallet build | Kotlin 2.4.20 and Ktor 3.3.3 (the Java engine, Multipaz's own on the JVM), in `gradle:8.14.3-jdk21` pinned by digest (Temurin 21.0.9) |
| Verifier | `polaris-oid4vp` 1.0.0rc15 from PyPI, with `cryptography` 50.0.2, in a fresh venv |
| Runtime | Python 3.12.13, Docker 29.8.1, macOS 26.3 (Darwin 25.3.0) |

## Run it

    lab/interop/multipaz/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/multipaz/run.sh
    POLARIS_OID4VP=packages/polaris-oid4vp lab/interop/multipaz/run.sh    # the tree's verifier

[`run.sh`](run.sh) runs everything in a scratch directory (`WORK`):
- `polaris-oid4vp` from PyPI in a fresh venv, its dependencies by hash;
- the wallet, compiled in a JDK image pinned by digest. Every library is checked against
  [`wallet/gradle/verification-metadata.xml`](wallet/gradle/verification-metadata.xml), written
  from an empty Gradle cache, so a dependency that changes under its version fails the build;
- the verifier's test PKI (`keygen`'s, re-issued with key identifiers), a holder key, and one
  credential bound to that key;
- the presentation and the three controls.

It exits 0 only if the presentation is accepted and every control is refused. Docker is required.
The verifier listens on port 9489 (`PORT`).

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts a different issuer CA under the same name | the verifier | `<- 400 refused: issuer_key: the x5c leaf does not chain to any configured trust anchor`; the wallet's response got `400` (`DISPATCH FAILED`) |
| (b) | The same request presented again after it was answered | the verifier, at the request | `404` to the wallet's fetch of the request object; Multipaz: `IllegalStateException: Check failed.` |
| (c) | The wallet trusts an unrelated CA for the verifier | the wallet, on Multipaz's verdict | Multipaz's trust manager: `No trusted root certificate could not be found`; the consent step declined, and Multipaz raised `PresentmentCanceledException` before anything was sent |

(c) is a control on Multipaz's trust manager: it found no path from the request's `x5c` to the
anchor the wallet trusts, where on the genuine request it found one. The refusal is the wallet's
consent step acting on that verdict, the decision Multipaz leaves to a wallet. Multipaz's checks
say `Check failed.` without saying which; the JDK's HTTP client log, kept in each wallet log, shows
the status the verifier returned.

## Result, 2026-10-04

Against `polaris-oid4vp` 1.0.0rc15 from PyPI, with Multipaz 0.101.0 on JDK 21: accepted,
`<- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']`, and the
verifier answered the wallet `200` with its `redirect_uri`. All three controls were refused. The
same against the tree's `packages/polaris-oid4vp`.

The wallet builds from an empty Gradle cache in 46 s, and a run takes about 30 s once the cache is
warm. The verification metadata lists 95 components; OSV-Scanner 2.6.0 finds no advisory against
any of them, and the SHA-256 the metadata pins for the Multipaz jar is the one Maven Central
publishes. Changing one digit of it fails the build.

## What this does not establish

- It is a wallet built here on the library, not a Multipaz wallet app. The library is the part that
  speaks OpenID4VP and SD-JWT VC: it fetched, checked, matched, signed, encrypted and answered. The
  anchor, the keys and the consent policy are this repository's few lines, as they are any
  wallet's.
- The wallet trusted re-issued certificates, not `keygen`'s as written (above). The verifier signed
  with `keygen`'s leaf key either way.
- Multipaz 0.101.0 posts no wallet nonce or wallet metadata when it fetches the request object (its
  source marks that as to do), so the verifier's `wallet_nonce` handling is not exercised here; the
  [vck walk](../vck/README.md) exercises it.
- One credential format and one path, ES256 throughout. The credential was minted by this
  repository's issuer script.
- Same category as the other rows: the author drove a published library on one machine. It is not
  an outside party using Polaris, and not a claim of interoperability in general.
