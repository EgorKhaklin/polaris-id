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

## Versions

| | |
|---|---|
| Wallet | `github.com/idfoundry/oid4vcgo` v0.12.0 (`h1:0S48shym0HCNkh95aBA9W+v3r5daoOVG858PX3B7RrQ=`) and v0.19.0 (`h1:avvf87LFxqfqjiHFdqvqJp/A5qsV1VU9vtvvlqFJqSo=`), `cmd/conformance-wallet-vp`, built with `go install` in `golang:1.26`, run in `alpine:3.20` |
| Verifier | `polaris-oid4vp` from this repository (its version string still reads 1.0.0rc7), because `--issuer-trust-anchor` is in no published release yet; the published 1.0.0rc7 is what [`../eudi-dev/`](../eudi-dev/README.md) exercises |
| Runtime | Python 3.12, Docker 29.4.3, macOS 26.3 |

## Run it

    lab/interop/oid4vcgo/run.sh                                   # v0.12.0, the certified release
    OID4VCGO_VERSION=v0.19.0 lab/interop/oid4vcgo/run.sh

It installs the verifier from this repository into a fresh venv (`POLARIS_OID4VP` overrides),
builds the wallet at the pinned version inside the official Go image, writes a test PKI
([`setup_pki.py`](setup_pki.py): the issuer CA, the issuer's CA-issued leaf, the holder key, the
wallet's own TLS pair, and an unrelated CA for control (a)), runs the wallet in a container that
trusts only the verifier's test TLS anchor, and drives it through its `/authorize` endpoint. It
exits 0 only if the genuine presentation is accepted and every control is refused. Ports 9443
and 8443 (`PORT`, `WALLET_PORT`).

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts an unrelated CA instead of the issuer's | the verifier | `<- 400 refused: issuer_key: the x5c leaf does not chain to any configured trust anchor`; the wallet got only "the presentation was not accepted" |
| (b) | The same request presented again after it was answered | the verifier, at the request | `no such outstanding request` (404) |
| (c) | The launch names a `client_id` that is not the signed request's | the wallet | `client_id "x509_hash:AAAA..." does not match x5c leaf's own x509_hash` |

## What this does not establish

- The issuer key, its certificate and the CA are test material this script generates; the wallet
  signs the credential with them using its own code. It is not a credential from a real issuer.
- One credential format, one path, ES256/P-256 throughout; the verifier is the repository's,
  not a published release.
- The same category of evidence as the other three rows: the author drove a published
  implementation on one machine. It is not an outside party using Polaris.
