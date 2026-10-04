# irmago (holder) → polaris-oid4vp

A wallet built on [irmago](https://github.com/privacybydesign/irmago), the Go library under the
Yivi wallet app (Privacy by Design Foundation, Apache-2.0), presents an SD-JWT VC over OpenID4VP
1.0 `direct_post.jwt` to `polaris-oid4vp` as installed from PyPI.

The wallet is [`wallet/main.go`](wallet/main.go), about 350 lines, wired the way irmago's own
client (`client/client.go`) wires the library for the app, for SD-JWT VCs only and without the
online status-list and type-metadata lookups. irmago does the work:
- its OpenID4VCI key service makes the holder key, with the proof of possession an issuer reads
  the key from;
- its SD-JWT VC holder verifier checks the credential before it is stored (the issuer's
  signature, its `x5c` chain to an installed issuer anchor, `iss` in that certificate, the
  disclosures), and its store keeps it bound to that key;
- its OpenID4VP client resolves the request (the request object fetched by GET, `x509_hash`
  checked against the verifier trust anchor, the DCQL query matched against the stored
  credential), builds the presentation (the disclosures and a key binding JWT signed with the
  stored key) and dispatches the response, encrypted to the verifier's key (`ECDH-ES`, `A128GCM`).

The program does only what irmago leaves to a wallet: it installs the trust anchors irmago
checks against (the issuer CA, and the CA `polaris-oid4vp keygen` made for the verifier), tells
Go's default transport to trust the verifier's listener certificate (irmago sends every request
through one shared client on it), and consents to what irmago asks, handing back the claim paths
it is shown, as the app's screen does. The credential is minted for irmago's key by this
repository's issuer script under an issuer CA made for the run.

## Run it

    lab/interop/irmago/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/irmago/run.sh
    BUILD=docker lab/interop/irmago/run.sh

[`run.sh`](run.sh) runs everything in a scratch directory (`WORK`):
- `polaris-oid4vp` from PyPI in a fresh venv, its dependencies by hash;
- the wallet, compiled with the local Go toolchain (Go 1.27.1, which `go` fetches by the
  `toolchain` line of [`wallet/go.mod`](wallet/go.mod) when the local one is older), or with
  `BUILD=docker` in a Go image pinned by digest. It is pure Go, so the image cross-compiles it for
  the machine it runs on. Every module is checked against [`wallet/go.sum`](wallet/go.sum), so a
  dependency that changes under its version fails the build;
- the verifier's test PKI, the holder key (irmago's), and one credential bound to it
  (`../waltid/issue_sdjwt_vc.py --x5c`), which irmago verifies and stores and the verifier trusts
  through its CA (`--issuer-trust-anchor`);
- the presentation and the five controls.

It exits 0 only if the presentation is accepted and every control is refused. The verifier
listens on port 9482 (`PORT`). Docker is needed only for `BUILD=docker`, or when there is no
local `go`.

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts a different issuer CA | the verifier | `<- 400 refused: issuer_key: the x5c leaf does not chain to any configured trust anchor`; irmago: `response status was not ok, status code 400` |
| (b) | The same request presented again after it was answered | the verifier, at the request | irmago: `authorization request returned HTTP 404` |
| (c) | The launch URI names a `client_id` that is not the signed request's | the wallet | irmago: `the link names client_id "x509_hash:AAAA..." but the signed request names "x509_hash:..."` |
| (d) | The wallet trusts an unrelated CA for the verifier | the wallet | irmago: `failed to verify relying party certificate: ... x509: certificate signed by unknown authority` |
| (e) | The wallet trusts a different listener certificate | the wallet | `tls: failed to verify certificate: x509: certificate signed by unknown authority` |

(c) and (d) are controls on irmago: it compares the signed request object with the link it was
launched with, and it applies the verifier anchors installed in its trust model rather than
presenting to whatever it is pointed at. (e) shows the listener certificate is checked: the
program adds trust for it, it does not turn the check off.

## Result, 2026-10-04

Against `polaris-oid4vp` 1.0.0rc15 from PyPI, with irmago v1.4.0 on Go 1.27.1: accepted,
`<- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']`, and irmago
reported `managed to complete openid4vp session`. All five controls were refused, with the wallet
built by the local toolchain and again in the pinned image from empty caches (245 s on a shared
machine).

irmago v1.4.0 requires `golang.org/x/crypto` v0.55.0, which OSV lists two `ssh` advisories
against (fixed in v0.56.0), and `ssh` is compiled in; [`go.mod`](wallet/go.mod) lifts it to
v0.57.0. OSV then lists one advisory against the modules in `go.sum`: GO-2026-5932, which marks
`golang.org/x/crypto/openpgp` unmaintained in every release. No openpgp package is compiled in,
and govulncheck v1.8.0 finds no vulnerable code reachable.

## What this does not establish

- It is a wallet built here on the library, not the Yivi app. irmago is the part that speaks
  OpenID4VP and SD-JWT VC: it made the key, checked and stored the credential, and fetched,
  checked and answered the request. The trust anchors, the TLS trust and the consent are this
  repository's few lines, as they are any wallet's.
- irmago fetches the request object by GET whatever `request_uri_method` says (its code says so),
  so this run says nothing about the POST path or a wallet nonce.
- The app keeps irmago's holder tables in SQLCipher, a C library. irmago opens them on any GORM
  dialector, and this wallet uses a pure Go SQLite, so the build needs no C toolchain; the
  holder code over them is the same.
- One credential format and one path, ES256 throughout. The credential was minted by this
  repository's issuer script, under a CA made for the run.
- Same category as the other rows: the author drove a published library on one machine. It is not
  an outside party using Polaris, and not a claim of interoperability in general.
