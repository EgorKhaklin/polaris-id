# eudi-dev (holder) → polaris-oid4vp

An unmodified eudi-dev wallet, a Go implementation by Dominik Schlosser, acting as the holder,
presents an SD-JWT VC over OpenID4VP 1.0 `direct_post.jwt` to `polaris-oid4vp` as installed from
PyPI. It has the same shape as [`../waltid/`](../waltid/README.md) and
[`../credo/`](../credo/README.md): the wallet generates its own holder key, a credential is
minted bound to that key, and the wallet's own code fetches the request, builds the
presentation and sends it. It shares no code with either: a third language, library and JOSE
stack.

**Result, 2026-09-28: accepted, with the wallet in HAIP strict mode.** `polaris-oid4vp` printed

    <- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']

for a presentation eudi-dev built, encrypted and POSTed from `wallet accept --auto-accept
--haip --mode strict`, and eudi-dev reported `Response: 200`. `--haip` makes the wallet enforce
HAIP 1.0 on the presentation (x509_hash, direct_post.jwt, DCQL, a signed request object,
ES256); strict mode refuses where the default mode only reports. All three controls were
refused. Neither side was changed.

The OpenID Foundation lists eudi-dev v2.3.7 as a certified OID4VP 1.0 + HAIP 1.0 Wallet
(`sd_jwt_vc`, `direct_post.jwt`, 2026-09-18), beside `polaris-oid4vp` 1.0.0rc7 as a certified
Verifier. The run below used exactly those two releases, and then the wallet's current one.

## Versions

| | |
|---|---|
| Wallet | `ghcr.io/dominikschlosser/eudi-dev:v2.3.7` (`sha256:2df7ac5c79206a29c66eb8c49acdcc07d0ec76c7d6d260056edccaac9257e081`) and `:v2.4.3` (`sha256:d544031950e9b5e911fe2212e5e57e109459d53e294e1b6feb243036e5dac3fc`), Apache-2.0, [source](https://github.com/dominikschlosser/eudi-dev) |
| Verifier | `polaris-oid4vp` 1.0.0rc7 from PyPI, with `cryptography` 50.0.1, in a fresh venv |
| Runtime | Python 3.12.13, Docker 29.4.3, macOS 26.3 (Darwin 25.3.0) |

## Run it

    lab/interop/eudi-dev/run.sh                                            # v2.3.7
    EUDI_IMAGE=ghcr.io/dominikschlosser/eudi-dev:v2.4.3 lab/interop/eudi-dev/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc7 lab/interop/eudi-dev/run.sh    # the run above, exactly

One command, about a minute once the image is local. It installs the verifier from PyPI into a
fresh venv in a scratch directory (`WORK`, default a new temporary one), the newest release as
`pip install --pre` gives a stranger unless `POLARIS_OID4VP` pins one, and prints the version it
got. [`wallet-canary.yml`](../../../.github/workflows/wallet-canary.yml) runs it weekly on a
machine nobody here set up, against v2.3.7 and the wallet's latest release. It makes the verifier's
test PKI with `polaris-oid4vp keygen`, lets the wallet generate its holder key, mints one SD-JWT
VC bound to it with [`../waltid/issue_sdjwt_vc.py`](../waltid/issue_sdjwt_vc.py), imports it,
and runs the presentation and the controls. It exits 0 only if the genuine presentation is
accepted and every control is refused where it should be. Port 9443 by default (`PORT`).

The wallet trusts the verifier's TLS listener through `SSL_CERT_FILE`, set to the test anchor
`keygen` wrote. Nothing else is configured on the wallet side.

## Controls

A verifier that accepts everything prints the same success line, so each of these is the same
wallet, credential and path with one thing wrong.

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts a different issuer key under the same `kid` | the verifier | `<- 400 refused: issuer_signature`; the wallet got only `"the presentation was not accepted"` |
| (b) | The same request presented again after it was answered | the verifier, at the request | the wallet: `POST to request_uri returned HTTP 404` |
| (c) | The launch URI names a `client_id` that is not the signed request's | the wallet | `request object client_id "x509_hash:..." does not match outer client_id "x509_hash:AAAA..."` |

(c) is a control on the wallet: it shows eudi-dev reads the signed request object and compares
it with what it was launched with, rather than presenting to whatever it is pointed at.

## What this does not establish

- **Not observed.** Whether eudi-dev posted a `wallet_nonce` with `request_uri_method=post`
  (neither side's log records it at the default verbosity). It chose A128GCM (its debug line
  prints a 16-byte content key), so A256GCM was not reached. Whether it validates the request
  object's certificate chain against the anchor it was given as a TLS root, or checks only the
  `x509_hash` binding, was not isolated.
- One credential format, one path, ES256/P-256 throughout, the credential minted by this
  repository's issuer script and trusted through a JWKS rather than `x5c`.
- It is the same category of evidence as the walt.id and Credo rows: the author drove a
  published wallet on one machine. It is not an outside party using Polaris, and not a claim
  that `polaris-oid4vp` is interoperable in general.
