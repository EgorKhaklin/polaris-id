# Outside implementations, measured

Seven wallets and eight more outside implementations have presented to, or issued for,
`polaris-oid4vp`. One row each: its version, the date, what ran, the result and the controls that
had to be refused. Each row is its
latest dated run and links the evidence in this tree. A row says what was measured on that date,
with that version, and nothing larger. As of 2026-10-14.

"Wallet" is software that ran unmodified, configuration only (trust anchors, TLS roots). Where a
row names a library, a short wallet or harness written here drove it. Every run presented an SD-JWT
VC over OpenID4VP 1.0 `direct_post.jwt`, ES256, and carried controls that must each be refused,
because a verifier that accepts everything prints the same success line.

## Measured

| Implementation | Kind | Version or commit | Date | Verifier | What ran | Result | Controls, each refused | Evidence |
|---|---|---|---|---|---|---|---|---|
| walt.id Wallet API v2 | wallet | 1.1.1 (`waltid/wallet-api2:1.1.1`, by digest) | 2026-10-03 | PyPI 1.0.0rc14 | a presentation | accepted: `200 authentic` | 2: wrong issuer key under the same `kid`; the answered request again | [waltid](../../lab/interop/waltid/README.md#one-command) |
| Credo (OpenWallet Foundation) | wallet | 0.7.2, with `@credo-ts/cheqd` 0.7.2 on a local `cheqd-node` 4.2.1 ledger | 2026-10-04 | PyPI 1.0.0rc15 | an issuance under a P-256 `did:cheqd`, its status list on the ledger; a presentation | accepted: `200 authentic`; the ledger's status list read VALID | 4: a key the DID does not resolve to; the answered request again; Credo trusting an unrelated CA for the verifier (Credo refused); the credential revoked on the ledger (INVALID) | [cheqd](../../lab/interop/cheqd/README.md#result-2026-10-04) |
| eudi-dev | wallet | v2.3.7 | 2026-10-10 | PyPI 1.0.0rc16 | a presentation, kept as files | accepted | 3: an unrelated issuer CA; the answered request again; a mismatched `client_id` (the wallet refused) | [eudi-dev](../../lab/interop/eudi-dev/README.md#a-captured-presentation-2026-10-10), [capture](../../lab/interop/eudi-dev/capture/README.md) |
| OID4VCgo | wallet | v0.25.0 | 2026-10-03 | PyPI 1.0.0rc14 | a presentation | accepted: `200 authentic` | 4: an unrelated issuer CA; the answered request again; a mismatched `client_id`; an unrelated CA for the verifier (the last two refused by the wallet) | [oid4vcgo](../../lab/interop/oid4vcgo/README.md#v0250-against-the-published-verifier-2026-10-03) |
| ProtocolSoup | wallet | v4.0.0 (`97d306ca`) | 2026-10-04 | PyPI 1.0.0rc15 | a presentation | accepted: `200 authentic` | 6: an unrelated issuer CA; the answered request again; a mismatched `client_id`; an unrelated CA for the verifier; another listener certificate; a credential its `iss` does not sign for (the last four refused by the harness) | [protocolsoup](../../lab/interop/protocolsoup/README.md#result-2026-10-04) |
| Procivis One Core | wallet | v1.87.2 (`core-server`) | 2026-10-04 | PyPI 1.0.0rc15 | an issuance over its own OpenID4VCI; a presentation under each of its `OPENID4VP_FINAL1` and `OPENID4VP_FINAL1_HAIP` profiles | accepted: `200 authentic`, both profiles | 4: an unrelated issuer CA; the answered request again; a mismatched `client_id`; an unrelated TLS certificate for the listener (the last two refused by Procivis) | [procivis](../../lab/interop/procivis/README.md#result-2026-10-04) |
| the Yivi app (built on irmago) | wallet | 8.3.1 (iOS App Store build, developer mode) | 2026-10-14 | this repository at `8e6f4834` | a presentation of a credential Yivi issued, one claim asked for; to repeat it, an iPhone or Android phone with the Yivi app in developer mode, as [the walk's README](../../lab/interop/yivi/README.md#run-it-again) describes | accepted: `200 authentic`; one claim (domain) disclosed | 2: a replayed response; neither Yivi anchor trusted | [yivi](../../lab/interop/yivi/README.md#result-2026-10-14); earlier: irmago v1.4.0 under a wallet built here, 2026-10-04, [irmago](../../lab/interop/irmago/README.md#result-2026-10-04) |
| EU reference OpenID4VP library, `eudi-lib-jvm-openid4vp-kt` | library | 0.16.2 | 2026-10-04 | PyPI 1.0.0rc15 | a presentation | accepted: `200 authentic` | 4: wrong issuer key under the same `kid`; the answered request again; a mismatched `client_id`; an unrelated CA for the verifier (the last two refused by the library) | [eudi-kt](../../lab/interop/eudi-kt/README.md#result-2026-10-03) |
| EU reference OpenID4VP library for iOS, `eudi-lib-ios-openid4vp-swift` | library | 0.43.2, with `eudi-lib-sdjwt-swift` 0.14.7, set as the EUDI iOS wallet kit 0.54.5 sets it (encrypted request object) | 2026-10-04 | PyPI 1.0.0rc16 | a presentation | accepted | 4: wrong issuer key under the same `kid`; the answered request again; a mismatched `client_id`; an unrelated CA for the verifier (the last two refused by the library) | [eudi-ios](../../lab/interop/eudi-ios/README.md#the-wallet-kits-own-setting-2026-10-04) |
| EU reference PID issuer, `eudi-srv-pid-issuer` | issuer | v0.11.1 (by digest) | 2026-10-04 | PyPI 1.0.0rc15 | an issuance of a PID over OpenID4VCI to a wallet on `eudi-lib-jvm-openid4vci-kt` 0.14.1; a presentation | accepted: `200 authentic` | 4: an unrelated CA in place of the issuer's; the answered request again; a mismatched `client_id`; an unrelated CA for the verifier (the last two refused by the library) | [eudi-issuer](../../lab/interop/eudi-issuer/README.md#result-2026-10-04) |
| vck (A-SIT Plus), `vck-openid-ktor` | library | 8.0.0 | 2026-10-04 | PyPI 1.0.0rc15 | an issuance by vck's own `IssuerAgent`; a presentation | accepted: `200 authentic` | 3: a different issuer key; the answered request again; an unrelated CA for the verifier (vck refused) | [vck](../../lab/interop/vck/README.md#result-2026-10-04) |
| Multipaz (OpenWallet Foundation), JVM target | library | 0.101.0 | 2026-10-04 | PyPI 1.0.0rc15 | a presentation | accepted: `200 authentic` | 3: a different issuer CA under the same name; the answered request again; an unrelated CA for the verifier (Multipaz's trust manager found no path and the wallet declined) | [multipaz](../../lab/interop/multipaz/README.md#result-2026-10-04) |
| Axle (OpenWallet Foundation Labs), Kotlin OpenID4VP client | library | `f7b8054171bb` (no releases) | 2026-10-10 | PyPI 1.0.0rc16 | a presentation | accepted: `200 authentic` | 6: an issuer CA of the same name with another key; the answered request again; a mismatched `client_id` (Axle refused); an unrelated CA for the verifier (Axle reported it untrusted, the harness declined); the issuer-signed payload altered; a credential bound to a key the wallet does not hold | [axle](../../lab/interop/axle/README.md#controls) |
| SpruceID `openid4vp`, its wallet conformance adapter | library | `e5f29b85` (the adapter's test issuer key, certificate and `vct` replaced) | 2026-10-04 | PyPI 1.0.0rc15 | a presentation | accepted: `200 authentic` | 3: an unrelated issuer CA; the answered request again; a mismatched `client_id` (the library refused) | [spruceid](../../lab/interop/spruceid/README.md#result-2026-10-04) |
| ERICA (the German EUDI Wallet programme's verifier test tool) | test tool | `2c27dc92` (its PID re-made under its own root for the run) | 2026-10-04 | this repository at `520456da` | its request checks; its negative modes; a presentation | accepted: `200 authentic`; ERICA's checks on the request: 31 of 31, and 17 of 18 parse-url checks (the access certificate is not from a German registrar) | 3: an unrelated issuer CA; the answered request again; a mismatched `client_id` (ERICA refused); and each of its negative modes that reached the verifier | [erica](../../lab/interop/erica/README.md#result-2026-10-04) |

## Weekly canary

[`wallet-canary.yml`](../../.github/workflows/wallet-canary.yml) runs the walk of every implementation above but Axle (for the Yivi app, the walk of irmago, the library under it),
at the versions it pins (for some also at their newest release), against the newest
`polaris-oid4vp` on PyPI, with the OpenID Foundation conformance suite.
Each job installs the package from PyPI, presents, then runs that walk's controls. Its latest
scheduled run, [38399849299](https://github.com/EgorKhaklin/polaris-id/actions/runs/38399849299) on 2026-10-13,
ran against 1.0.0, the version 20 of its 22 jobs print (the two Credo jobs print none): 22 of 22
jobs passed.

## Reported upstream

Defects found in a row's implementation and reported in public, with their state as read on
2026-10-11.

| Implementation | Report | State |
|---|---|---|
| OID4VCgo | [issue 312](https://github.com/IDFoundry/OID4VCgo/issues/312): its conformance wallet did not check the verifier's TLS certificate | closed; v0.22.0 added a warning and an optional chain check ([record](../../lab/EXTERNAL-NOUNS.md#wallets)) |
| eudi-dev | [issue 21](https://github.com/dominikschlosser/eudi-dev/issues/21): the wallet did not check the verifier's TLS certificate, even in strict mode | closed; v2.5.0 checks it ([record](../../lab/interop/eudi-dev/README.md#the-verifiers-tls-checked-in-strict-mode-2026-10-02)) |
| EU reference PID issuer | [issue 662](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/issues/662): its docker-compose test keystore's `mso_mdoc` signing certificate lacks the ISO 18013-5 Annex B extensions | open |
| Axle | [pull request 93](https://github.com/openwallet-foundation-labs/axle/pull/93): Bouncy Castle in its Kotlin test dependencies to 1.86, as the walk lifts it | open |

## What no row establishes

- The author drove every run, on one machine, with a phone for the Yivi app. No row is an outside
  party using Polaris; the one exception, OID4VCgo's CI running its own walk, is in [the scoreboard's Use section](../../lab/EXTERNAL-NOUNS.md#use).
- One credential format (SD-JWT VC), one response mode (`direct_post.jwt`), ES256. Nothing about
  mdoc, the Digital Credentials API or the post-quantum path.
- A row is dated: a newer release of its implementation is unmeasured until a row says otherwise.

The dated history of every run, earlier versions included, is the
[scoreboard](../../lab/EXTERNAL-NOUNS.md#wallets).
