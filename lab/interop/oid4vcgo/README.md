# OID4VCgo (holder) → polaris-oid4vp

OID4VCgo's own OpenID4VP wallet, `cmd/conformance-wallet-vp` from
[github.com/idfoundry/oid4vcgo](https://github.com/IDFoundry/OID4VCgo) (Go, MIT, by Oscar
Sanderson), presents an SD-JWT VC over OpenID4VP 1.0 `direct_post.jwt` to `polaris-oid4vp`. It is
the binary its author wrote to run the OpenID Foundation's wallet test plan, run unmodified. It
shares no code with walt.id, Credo or eudi-dev: a fourth language stack and JOSE implementation.

Unlike the three earlier wallets, it presents a credential it issues ITSELF, with its own
SD-JWT VC code, signed under a key whose certificate carries an `x5c` chain to a CA. So this run
also exercises `serve --issuer-trust-anchor`, the way HAIP issuers are trusted, against a chain
and a credential encoder nobody here wrote.

**Result, 2026-09-28: accepted.** `polaris-oid4vp` printed

    <- 200 authentic, claims ['cnf', 'exp', 'family_name', 'given_name', 'vct']

for a presentation the wallet built, encrypted and POSTed after verifying the signed request
object against its `x5c` leaf and the `x509_hash` client identifier. The wallet reported
`Presented` and followed the verifier's `redirect_uri`. All three controls were refused.

The OpenID Foundation lists OID4VCgo 0.12.0 as a certified OID4VP 1.0 + HAIP 1.0 Wallet
(2026-09-23). The run used exactly that release, and then v0.19.0, the current one.

## What it found

The wallet follows the `redirect_uri` an accepted response carries, as HAIP 5.1 intends, and
`polaris-oid4vp serve` answered that path 404: a presentation that succeeded ended on an error
page for the person holding the phone. walt.id, Credo and eudi-dev never followed it. Fixed:
`serve` now answers the path with a constant page (`DONE_PATH`, `test_serve.DonePageTests`).

## v0.22.0: the wallet checks the verifier's chain (2026-09-30)

We reported to OID4VCgo that the harness accepted any verifier TLS certificate without saying so
([issue 312](https://github.com/IDFoundry/OID4VCgo/issues/312)). Its author answered the same day
with v0.22.0 ([PR 314](https://github.com/IDFoundry/OID4VCgo/pull/314)):

- the harness logs `WARNING: this harness does not verify the Verifier's TLS certificate` when it
  starts;
- with the new `verifier_trust_anchors_pem`, it checks the request object's `x5c` leaf against
  the anchors it is given (OpenID4VP 5.9.3, HAIP 5), refusing a self-signed leaf and a chain
  that does not reach one;
- its README says what a passing run does and does not show.

For v0.22.0 and later, `run.sh` gives the wallet `keygen`'s CA (`pki/anchor.pem`, the anchor HAIP
keeps out of the chain) and adds control (d). Measured 2026-09-30 against this repository:
accepted, `<- 200 authentic`, with the TLS warning logged, and all four controls refused. In (d),
the wallet trusted an unrelated CA for the verifier and presented nothing:

    untrusted verifier: wallet: verifier certificate: certchain: certificate chain does not
    verify against a trusted root: x509: certificate signed by unknown authority

## v0.23.0: the verifier's leaf is held to HAIP (2026-10-01)

OID4VCgo's author closed issue 312 as fixed in v0.22.0 and said v0.23.0 goes further: the wallet
refuses a verifier leaf that is a CA certificate or whose key usage does not allow
`digitalSignature`, and an `x5c` that carries its own trust anchor (HAIP 1.0 section 5).
`keygen` already makes that shape, and `test_cli` holds it there: the anchor is a CA and the leaf
is not, the leaf's critical key usage asserts `digitalSignature`, and the chain the verifier sends
stops below the anchor.

Measured 2026-10-01 with `OID4VCGO_VERSION=v0.23.0` against this repository at 4e208b5a
(`polaris-oid4vp` 1.0.0rc12 in the tree): accepted, `<- 200 authentic`, and all four controls
refused, (d) with the same `certificate signed by unknown authority`.

## Versions

| | |
|---|---|
| Wallet | `github.com/idfoundry/oid4vcgo` v0.12.0 (`h1:0S48shym0HCNkh95aBA9W+v3r5daoOVG858PX3B7RrQ=`), v0.19.0 (`h1:avvf87LFxqfqjiHFdqvqJp/A5qsV1VU9vtvvlqFJqSo=`) v0.22.0 and v0.23.0, `cmd/conformance-wallet-vp`, built with `go install` in `golang:1.26`, run in `alpine:3.20` |
| Verifier | `polaris-oid4vp` from this repository by default, so a run tests the tree (1.0.0rc12 at 4e208b5a); `--issuer-trust-anchor`, which the run needs, is in every release from 1.0.0rc8, so `POLARIS_OID4VP=polaris-oid4vp==1.0.0rc11` runs a published one |
| Runtime | Python 3.12, Docker 29.4.3, macOS 26.3 |

## Run it

    lab/interop/oid4vcgo/run.sh                                   # v0.12.0, the certified release
    OID4VCGO_VERSION=v0.19.0 lab/interop/oid4vcgo/run.sh
    OID4VCGO_VERSION=v0.22.0 lab/interop/oid4vcgo/run.sh          # adds control (d)

It installs the verifier from this repository into a fresh venv, its dependencies by hash from
[`../requirements.txt`](../requirements.txt) and, since it builds the verifier from the tree, the
build backend by hash from [`../requirements-build.txt`](../requirements-build.txt), which needs
Python 3.10 or newer (`POLARIS_OID4VP` overrides the verifier; a release on PyPI builds nothing),
builds the wallet at the pinned version inside the official Go image, writes a test PKI
([`setup_pki.py`](setup_pki.py): the issuer CA, the issuer's CA-issued leaf, the holder key, the
wallet's own TLS pair, and an unrelated CA for control (a)), runs the wallet in a container, and
drives it through its `/authorize` endpoint. It
exits 0 only if the genuine presentation is accepted and every control is refused. Ports 9443
and 8443 (`PORT`, `WALLET_PORT`).

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts an unrelated CA instead of the issuer's | the verifier | `<- 400 refused: issuer_key: the x5c leaf does not chain to any configured trust anchor`; the wallet got only "the presentation was not accepted" |
| (b) | The same request presented again after it was answered | the verifier, at the request | `no such outstanding request` (404) |
| (c) | The launch names a `client_id` that is not the signed request's | the wallet | `client_id "x509_hash:AAAA..." does not match x5c leaf's own x509_hash` |
| (d) | From v0.22.0: the wallet trusts an unrelated CA for the verifier | the wallet | `certificate chain does not verify against a trusted root` |

## What this does not establish

- The issuer key, its certificate and the CA are test material this script generates; the wallet
  signs the credential with them using its own code. It is not a credential from a real issuer.
- One credential format, one path, ES256/P-256 throughout; the verifier is the repository's,
  not a published release.
- The same category of evidence as the other three rows: the author drove a published
  implementation on one machine. It is not an outside party using Polaris.
- **The wallet's TLS, observed 2026-09-30.** Until then this page said the wallet trusted only
  the verifier's test TLS anchor, set through `SSL_CERT_FILE`. That file was `keygen`'s CA, which
  does not sign the listener's certificate (`keygen` makes it self-signed), and with the setting
  removed, in an alpine container with no CA bundle at all, the run still passes: v0.12.0
  validates no TLS certificate. The wallet's own behaviour, recorded here and not absorbed; from
  v0.22.0 the wallet says so when it starts (above).
