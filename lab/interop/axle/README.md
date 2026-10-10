# Axle (holder) → polaris-oid4vp

Axle's Kotlin OpenID4VP client, driven by a harness written here, presents an SD-JWT VC over
OpenID4VP 1.0 `direct_post.jwt` to `polaris-oid4vp` as published on PyPI.
[Axle](https://github.com/openwallet-foundation-labs/axle) (Apache-2.0, an OpenWallet Foundation
Labs project) describes itself as a headless SDK for building EUDI wallets. It is not a wallet
app, and nothing here is one: the harness ([`harness/`](harness/src/main/kotlin/Holder.kt)) is a
small program written in this repository that calls Axle's public modules at a pinned commit,
with Axle's code unchanged.

**Result, 2026-10-10: accepted.** `polaris-oid4vp` 1.0.0rc16 printed

    <- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']

for a presentation Axle's client built, encrypted and posted, and all six controls were refused.

## What Axle does and what the harness does

Axle's code does the protocol:

- `Openid4VpClient.resolveRequest` fetches the signed request object by POST (the launch URI says
  `request_uri_method=post`), with wallet metadata and, since the harness gives it a random
  source, a `wallet_nonce` it then requires the request object to echo. It checks the `typ` and
  that the request object's `client_id` is the launch URI's.
- `X509RequestVerifier` checks the request's signature against its `x5c` leaf, the `x509_hash`
  client identifier against that leaf, and whether the chain reaches the anchor it was given.
- `DcqlEngine` matches the DCQL query; `HeldSdJwtVc` selects the disclosures and signs the key
  binding JWT through `SoftwareSecureArea`, the software key store Axle ships for desktop and
  server hosts, which also made the holder key.
- `Openid4VpClient.respond` encrypts the response to the verifier's key (ECDH-ES) and posts it.

The harness supplies what a host app supplies: the HTTP transport (Axle's `HttpTransport` port,
on the JDK client, trusting only the verifier listener's own certificate), the trust anchor, and
the consent step. Axle reports an untrusted verifier as `VerifierInfo.trusted = false` and leaves
the decision to the app; the harness then declines. Control (d) is that decision, made on Axle's
verdict.

Axle's higher-level `Wallet` facade (`kotlin/wallet`) was not used: it has no path to load a
credential issued outside OpenID4VCI (`CredentialsService` offers list, get, export, delete,
status and match; `IssuanceService` takes credentials only from an issuer). The `openid4vp`
module's `HeldSdJwtVc` takes one directly, so the harness calls that module.

## Versions

| | |
|---|---|
| Axle | `github.com/openwallet-foundation-labs/axle` at `f7b8054171bb49f3c27589d0b19b03285ed1dcc1` (main, 2026-08-31; Axle has no tags or releases), modules `openid4vp`, `trust`, `testkit` and their dependencies in `kotlin/` |
| Build and runtime image | `gradle:9.3.1-jdk17@sha256:5fb7d4ea7ddf10b24c317bc7d665a7da6aae9104042091625f3061f98661b487` (the Gradle version Axle's wrapper names, and JDK 17, its toolchain); Kotlin 2.2.21, the version Axle's build declares |
| Dependencies | every one checked against [`harness/gradle/verification-metadata.xml`](harness/gradle/verification-metadata.xml) (82 components, Axle's build included); changing one digit of a pinned hash fails the build |
| Verifier | `polaris-oid4vp` 1.0.0rc16 from PyPI, its dependencies by hash ([`../requirements.txt`](../requirements.txt)) |
| Runtime | Python 3.9.6 (the verifier's venv), Docker 29.8.1, macOS 26.3 (arm64) |

## Run it

    lab/interop/axle/run.sh                                         # polaris-oid4vp 1.0.0rc16
    POLARIS_OID4VP=polaris-oid4vp lab/interop/axle/run.sh           # the newest release
    AXLE_SHA=<commit> lab/interop/axle/run.sh                       # another Axle commit

It installs the verifier into a fresh venv in a scratch directory (`WORK`), fetches Axle's
source at the pinned commit into a new empty directory there, and builds the harness and Axle's
modules together in the image above, as a Gradle included build. Nothing of Axle runs on the
machine itself. The harness then runs in the same image: it makes the holder key and writes only
its public half, which [`../waltid/issue_sdjwt_vc.py`](../waltid/issue_sdjwt_vc.py) `--x5c` binds
the credential to, under an issuer CA made for the run that the verifier trusts
(`--issuer-trust-anchor`). The script hands the harness one job per presentation and judges what
both sides printed. It exits 0 only if the genuine presentation is accepted and every control is
refused where it should be, and its last line is `done` on every exit path. Port 9491 by default
(`PORT`). A named volume (`polaris-axle-gradle-cache`) keeps Gradle's downloads for the next run.

The verifier binds `0.0.0.0` for the run (`--bind 0.0.0.0`). The harness's container reaches it as
`host.docker.internal`, which on Linux the script maps to Docker's host gateway
(`--add-host host.docker.internal:host-gateway`), an address a loopback-only listener does not
serve.

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts a CA with the issuer CA's name and another key | the verifier | `<- 400 refused: issuer_key: the x5c leaf does not chain to any configured trust anchor` |
| (b) | The same request presented again after it was answered | the verifier, at the request | Axle: `request_uri fetch failed: HTTP 404` |
| (c) | The launch URI names a `client_id` that is not the signed request's | Axle | `request object client_id 'x509_hash:NIOx…' != request client_id 'x509_hash:AAAA…'` |
| (d) | The wallet trusts an unrelated CA for the verifier's request object | Axle's verdict, the harness's decision | Axle: `chain does not validate to a trust anchor`; the harness declined and the verifier received nothing |
| (e) | The credential's issuer-signed payload, `iat` moved back a day, with the original signature | the verifier | `<- 400 refused: issuer_signature: the issuer signature over the credential does not verify under any trusted issuer key` |
| (f) | A credential bound to a key the wallet does not hold | the verifier | `<- 400 refused: kb_signature: the key binding JWT signature does not verify under the credential's cnf.jwk, so the holder did not produce this presentation` |

In (a), (e) and (f) Axle presented and was told only `the presentation was not accepted`. In (e)
and (f) Axle presented a credential a holder could have checked first: it does not verify its own
credential's issuer signature, nor that its key matches the credential's `cnf`. The verifier is
the party that must refuse either, and did.

## What this does not establish

- It is Axle's Kotlin OpenID4VP client, driven by a harness written here. It is not an Axle wallet
  app, not Axle's `Wallet` facade (above), and not its Swift SDK, which is a separate port.
- The harness supplies the transport, the trust anchor and the consent decision. Control (d) shows
  Axle's trust verdict and the harness acting on it; a different host could act differently.
- The issuer key, its CA and the credential are test material this repository's script made. The
  verifier's PKI is `polaris-oid4vp keygen`'s test PKI.
- One credential format, one path, ES256 and P-256 throughout, at one Axle commit, on one machine.
- Same category as the other rows: the author drove a published SDK on one machine. It is not an
  outside party using Polaris, not a certification, and not a claim that Axle is interoperable in
  general.
