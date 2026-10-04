# EU reference OpenID4VP library for iOS (holder) → polaris-oid4vp

A wallet built on `eudi-lib-ios-openid4vp-swift`, the iOS OpenID4VP library of the European
Commission's EUDI Wallet reference implementation, presents an SD-JWT VC over OpenID4VP 1.0
`direct_post.jwt` to `polaris-oid4vp` as installed from PyPI.

The wallet is [`wallet/Sources/Wallet/Wallet.swift`](wallet/Sources/Wallet/Wallet.swift), about 250
lines. The library does the protocol:
- it resolves the authorization request: `x509_hash`, the signed request object fetched by POST with
  wallet metadata and a wallet nonce (which it checks the request object echoes), and the DCQL
  query;
- it dispatches the response, encrypted to the verifier's key (`ECDH-ES`).

The wallet does only what the library leaves to a wallet: it decides whom to trust and builds the
presentation. A request object is trusted only when its `x5c` chains, under Apple's Security
framework, to the anchor `polaris-oid4vp keygen` made. The presentation is built with
`eudi-lib-sdjwt-swift`, the EU SD-JWT library, the way the EUDI iOS wallet kit builds one: the
disclosures the DCQL query names, and a key binding JWT (`aud`, `nonce`, `iat`, `sd_hash`) signed
with the holder key. Unlike the [Kotlin walk](../eudi-kt/README.md), where the key binding JWT is
this repository's code, here the EU library computes `sd_hash` and signs it. Its OpenID4VP is the
library's own, written in Swift on JOSESwift and Apple's Security framework, separately from the
Kotlin library of the same project.

Both EU libraries are pinned to the exact versions the EUDI iOS wallet kit 0.54.5 pins:
`eudi-lib-ios-openid4vp-swift` 0.43.2 and `eudi-lib-sdjwt-swift` 0.14.7.
[`wallet/Package.resolved`](wallet/Package.resolved) pins all eleven packages to commits.

## Run it

    lab/interop/eudi-ios/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/eudi-ios/run.sh

[`run.sh`](run.sh) runs everything in a scratch directory (`WORK`):
- `polaris-oid4vp` from PyPI in a fresh venv, its dependencies by hash;
- the wallet, built by SwiftPM from a copy of `wallet/` with `--force-resolved-versions`, so it
  builds exactly the commits `Package.resolved` pins and fails if the manifest asks for anything
  else. A first build took about three minutes on an eight-core M3, and ten on the same machine
  under heavy load; `WALLET_BUILD` names a build directory to reuse, and a warm build takes seconds;
- the verifier's test PKI, a holder key, and one credential bound to that key
  (`../waltid/issue_sdjwt_vc.py`);
- the presentation and the four controls.

It exits 0 only if the presentation is accepted and every control is refused. It needs macOS and
Swift 6.2 or newer; the Command Line Tools are enough, Xcode is not needed. The library is built on
Apple's Security framework and CryptoKit, so it does not build on Linux, and a CI canary would run on
a macOS runner. The verifier listens on `localhost:9483` (`PORT`).

The verifier's listener presents the self-signed certificate `keygen` wrote. The wallet's
`URLSession` delegate accepts it only when the server presents exactly that certificate, for that
session only; nothing is trusted globally. macOS's TLS server policy refuses that certificate even
as an explicit anchor, because it names no extended key usage for server authentication (`Extended
key usage does not match certificate usage`), so the pin is checked as an X.509 certificate (its
signature and validity) and not under the TLS server policy.

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts a different issuer key under the same `kid` | the verifier | `<- 400 refused: issuer_signature`; the library reported `rejected` |
| (b) | The same request presented again after it was answered | the verifier, at the request | the verifier answered `POST /request.jwt` with 404; the library: `invalidJwtPayload` |
| (c) | The launch URI names a `client_id` that is not the signed request's | the wallet | the library: `validationError("client_id's do not match")` |
| (d) | The wallet trusts an unrelated CA for the verifier | the wallet | the library: `validationError("Could not trust certificate chain")` |

(c) and (d) are controls on the library. (c) shows it compares the signed request object with what it
was launched with. (d) shows the trust decision the wallet hands it is the one it applies, rather
than presenting to whatever it is pointed at. The wallet logs each HTTP exchange the library makes
(method, path, status), which is where the 404 in (b) is read.

## Result, 2026-10-04

Against `polaris-oid4vp` 1.0.0rc15 from PyPI, with `eudi-lib-ios-openid4vp-swift` 0.43.2 and
`eudi-lib-sdjwt-swift` 0.14.7, built with Swift 6.2.3 on macOS 26 (arm64): accepted, `<- 200
authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']`, and the library
reported `accepted`. All four controls were refused. The same wallet built on 0.43.0, the newest
GitHub release of the library (0.43.1 and 0.43.2 are tags), was accepted too; only the genuine
presentation was run against it.

OSV lists no advisory against any of the eleven pinned packages, queried by version (ecosystem
`SwiftURL`) and by commit, nor against the C code two of them vendor (libsecp256k1 0.7.1 in
`secp256k1.swift`, BoringSSL in `swift-crypto`).

## The wallet kit's own setting, 2026-10-04

    JAR_ENCRYPTION=1 lab/interop/eudi-ios/run.sh

runs the wallet with the library configured as the EUDI iOS wallet kit 0.54.5 configures it
(`jarConfiguration: .encryptionOption`): it fetches the request object by POST, sends its key in
`wallet_metadata` and refuses an object that is not encrypted to it.

| Verifier | Result |
|---|---|
| PyPI 1.0.0rc15 | refused at the request stage: `validationError("The operation couldn’t be completed. (JOSESwift.JOSESwiftError error 5.)")`; the controls never reached their own stages |
| this repository at 13d79e2b, which encrypts the request object for a wallet that asks | accepted: `<- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']`, and all four controls refused |

The default stays `.noEncryptionOption` until a release carries the change, so the weekly canary,
which runs against PyPI, measures what a stranger installs.

## What this does not establish

- It is a wallet built here on the library, not the EUDI reference wallet app or the wallet kit. The
  library is the part that speaks OpenID4VP: it fetched, checked and answered the request. The trust
  decision is this repository's few lines; the presentation is the EU SD-JWT library's, called as the
  wallet kit calls it.
- It does not show that an app built on the wallet kit presents to the published release. With the
  wallet kit's setting (above) 1.0.0rc15 is refused and only the tree is accepted; the app itself,
  with its own trust, storage and user interface, was not run.
- One credential format and one path, ES256 throughout. The credential was minted by this
  repository's issuer script and trusted through a JWKS.
- The library was built and run for macOS. Nothing here ran on an iPhone.
- Same category as the other rows: the author drove a published library on one machine. It is not
  an outside party using Polaris, and not a claim of interoperability in general.
