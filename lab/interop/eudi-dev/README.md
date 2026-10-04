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
| Wallet | `ghcr.io/dominikschlosser/eudi-dev:v2.3.7` (`sha256:2df7ac5c79206a29c66eb8c49acdcc07d0ec76c7d6d260056edccaac9257e081`), `:v2.4.3` (`sha256:d544031950e9b5e911fe2212e5e57e109459d53e294e1b6feb243036e5dac3fc`) and `:v2.5.0` (`sha256:c6d28d171f12db5410cd5b4670572b13c350aa9fd54e7c4389a7544fe404b6bc`), Apache-2.0, [source](https://github.com/dominikschlosser/eudi-dev) |
| Verifier | `polaris-oid4vp` 1.0.0rc7 from PyPI, with `cryptography` 50.0.1, in a fresh venv |
| Runtime | Python 3.12.13, Docker 29.4.3, macOS 26.3 (Darwin 25.3.0) |

## Run it

    lab/interop/eudi-dev/run.sh                                            # v2.3.7
    EUDI_IMAGE=ghcr.io/dominikschlosser/eudi-dev:v2.4.3 lab/interop/eudi-dev/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc7 lab/interop/eudi-dev/run.sh    # the run above, exactly
    EUDI_NATIVE=1 lab/interop/eudi-dev/run.sh                              # no Docker
    EUDI_ISSUER=1 lab/interop/eudi-dev/run.sh                              # eudi-dev's own issuer
    EUDI_TUNNEL=1 lab/interop/eudi-dev/run.sh                              # each verifier behind its own tunnel

One command, about a minute once the image is local. It installs the verifier from PyPI into a
fresh venv in a scratch directory (`WORK`, default a new temporary one), the newest release as
`pip install --pre` gives a stranger unless `POLARIS_OID4VP` pins one, with its dependencies by hash
from [`../requirements.txt`](../requirements.txt), and prints the version it got. A release arrives as
its published wheel and builds nothing, so this runs on Python 3.9 or newer; with `POLARIS_OID4VP`
set to a path in the tree, the walk builds it, with the build backend by hash from
[`../requirements-build.txt`](../requirements-build.txt), which needs Python 3.10 or newer. [`wallet-canary.yml`](../../../.github/workflows/wallet-canary.yml) runs it weekly on a
machine nobody here set up, against v2.3.7 and the wallet's latest release. It makes the verifier's
test PKI with `polaris-oid4vp keygen`, lets the wallet generate its holder key, mints one SD-JWT
VC bound to it with [`../waltid/issue_sdjwt_vc.py`](../waltid/issue_sdjwt_vc.py), imports it,
and runs the presentation and the controls. It exits 0 only if the genuine presentation is
accepted and every control is refused where it should be. Port 9443 by default (`PORT`).

**Without Docker.** When Docker is not running, or with `EUDI_NATIVE=1`, the script downloads
the wallet's own release binary for the machine (macOS or Linux, x86-64 or arm64) and runs it
instead of the image. The v2.3.7 binaries' SHA-256 are pinned in `run.sh`, so a download is
checked against this repository, not only against the checksums published beside it; a
mismatch stops the run before the binary is executed. Walked 2026-09-30 on macOS (arm64) with
the system Python 3.9.6 and no Docker, the verifier installed as PyPI's wheel: accepted, all three
controls refused, 15 s from an empty directory. [`wallet-canary.yml`](../../../.github/workflows/wallet-canary.yml) runs this mode too.

**Nothing is configured for the verifier's TLS listener for a wallet that does not check it.**
A wallet that does (eudi-dev v2.5.0 and later in strict mode, found from its own `--help`) is given
`keygen`'s listener certificate to trust (`--tls-ca`), and control (d) below shows the check ran.
`keygen`'s listener certificate is self-signed; its test anchor signs the request object's certificate,
not the listener's. Until 2026-09-30 this script set `SSL_CERT_FILE` to that anchor and this page
said the wallet trusted the listener through it. It did not: eudi-dev v2.3.7 and v2.4.3 present
with the setting removed, and v2.3.7 as its own binary on macOS presents to `127.0.0.1` with a
listener certificate that names only `localhost`. The wallet does not validate the verifier's
TLS certificate. What binds the exchange is the signed request object (`x509_hash`) and the
response encrypted to its key, which control (c) exercises from the wallet's side.

## Controls

A verifier that accepts everything prints the same success line, so each of these is the same
wallet, credential and path with one thing wrong.

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts a different issuer key under the same `kid` | the verifier | `<- 400 refused: issuer_signature`; the wallet got only `"the presentation was not accepted"` |
| (b) | The same request presented again after it was answered | the verifier, at the request | the wallet: `POST to request_uri returned HTTP 404` |
| (c) | The launch URI names a `client_id` that is not the signed request's | the wallet | `request object client_id "x509_hash:..." does not match outer client_id "x509_hash:AAAA..."` |
| (d) | The wallet trusts an unrelated certificate for the verifier's TLS (only when the wallet checks TLS) | the wallet | `tls: failed to verify certificate: x509: certificate signed by unknown authority` |

(c) is a control on the wallet: it shows eudi-dev reads the signed request object and compares
it with what it was launched with, rather than presenting to whatever it is pointed at.

## An issuer nobody here wrote (2026-09-30)

eudi-dev also issues. `eudi issue sdjwt --wallet --pid` signs a full EUDI PID Rulebook SD-JWT VC
with its PID Provider certificate in `x5c`, bound to the wallet's own holder key, with nested and
array disclosures and a status list reference. The certificate chains in one link to
"OID4VC Dev Wallet CA" (`eudi wallet ca-cert` exports it), carries digitalSignature, and states
one critical extended key usage: ISO/IEC 18013-5's document signer, `1.0.18013.5.1.2`, the usage
EUDI issuers put on their signing certificates. The verifier trusted only that CA
(`serve --issuer-trust-anchor`), and the wallet presented with `--haip --mode strict`:

| | `polaris-oid4vp` | Result |
|---|---|---|
| The genuine presentation | 1.0.0rc10 from PyPI | refused: `issuer_key`, because the document signer was not among the usages it took from an issuer certificate |
| The same | this repository at c8014978, then 1.0.0rc11 from PyPI | accepted: `<- 200 authentic, claims ['cnf', 'exp', 'family_name', 'given_name', 'iat', 'iss', 'status', 'vct']` |
| Control: the answered request again | c8014978, 1.0.0rc11 | refused at the request: `request_uri returned HTTP 404` |
| Control: the verifier trusts an unrelated CA | c8014978, 1.0.0rc11 | refused: `issuer_key` |
| Control: a launch URI whose `client_id` is not the signed request's | 1.0.0rc11 | refused by the wallet |

Walked by hand on macOS (arm64), with eudi-dev v2.3.7's own binary and the system Python 3.9.6.
`EUDI_ISSUER=1 run.sh` does the same with the three controls above, in Docker or without it
(accepted, all three refused, both ways, against 1.0.0rc11 from PyPI on 2026-09-30), and
[`wallet-canary.yml`](../../../.github/workflows/wallet-canary.yml) runs it weekly.
It is the first row here in which neither the wallet nor the credential's issuer is this
repository's: the verifier is the only Polaris software in the exchange. The credential's status
reference points at eudi-dev's own status list, which nothing here fetched, so revocation reads
`not_evaluated`.

    eudi wallet info --wallet-dir W; eudi issue sdjwt --wallet --pid --wallet-dir W
    eudi wallet ca-cert --wallet-dir W > eudi-ca.pem
    polaris-oid4vp keygen --out pki --host localhost --port 9443
    polaris-oid4vp serve --pki pki --host localhost --bind 127.0.0.1 --port 9443 \
      --issuer-trust-anchor eudi-ca.pem --once
    eudi wallet accept "<the launch URI serve prints>" --auto-accept --haip --mode strict --no-open --wallet-dir W

## The verifier's TLS checked in strict mode (2026-10-02)

[eudi-dev issue 21](https://github.com/dominikschlosser/eudi-dev/issues/21) reported that the wallet
did not validate the verifier's TLS certificate, even in `--mode strict`. The maintainer fixed it in
[v2.5.0](https://github.com/dominikschlosser/eudi-dev/releases/tag/v2.5.0) and asked for a re-test.

- Wallet: `ghcr.io/dominikschlosser/eudi-dev:v2.5.0`
  (`sha256:c6d28d171f12db5410cd5b4670572b13c350aa9fd54e7c4389a7544fe404b6bc`).
- Verifier: `polaris-oid4vp` 1.0.0rc13 from PyPI, its self-signed listener on `host.docker.internal:9443`.

Run with the image overridden, the walk otherwise unchanged:

    EUDI_IMAGE=ghcr.io/dominikschlosser/eudi-dev:v2.5.0 lab/interop/eudi-dev/run.sh

In strict mode (the walk's own `wallet accept ... --mode strict`), the wallet now refuses the
listener's self-signed certificate at the request fetch, so the genuine presentation does not
complete:

    fetching request_uri: ... tls: failed to verify certificate: x509: certificate signed by unknown authority

Adding `--tls-verify=false` to that same `wallet accept` restores the previous behaviour: the wallet
presents and the verifier answers `<- 200 authentic`, with all three controls still refused. So
v2.5.0 strict mode validates the verifier's TLS certificate (the issue 21 fix), and the documented
override remains for local development. v2.3.7 and v2.4.3 presented regardless (the Versions above);
v2.5.0 does not. The one destination checked here is that listener; every-destination is the release
notes' wording, not this run's.

Since 2026-10-03 the walk gives a wallet that checks TLS the listener's own certificate to trust
(`--tls-ca`), so the default walk runs v2.5.0's strict mode with its check on: against 1.0.0rc14
from PyPI, accepted, and all four controls refused, (d) with the error above. The same for v2.5.1,
the `latest` the canary floats on (`sha256:47f3df6f89fdb70b788522c1f9f2cc7e1aecbc7ed56df44d4258cbb8f672526f`).

## Strict mode with the verifier's TLS checked, through a tunnel (2026-10-03)

The run above left v2.5.0's strict mode refusing the self-signed listener. `EUDI_TUNNEL=1` puts
each verifier the walk starts behind its own cloudflared quick tunnel
(`serve --public-base-url <tunnel> --no-local-tls`), so the wallet fetches the request and posts
its response over a certificate it can validate, and strict mode runs with its TLS check on (no
`--tls-verify=false`). Each verifier gets a fresh tunnel, because a quick tunnel does not reliably
reconnect to an origin restarted under it ([010, section 12](../../strategy/010-dev-tunnel.md)).

    EUDI_TUNNEL=1 EUDI_ISSUER=1 \
      EUDI_IMAGE=ghcr.io/dominikschlosser/eudi-dev:v2.5.0@sha256:c6d28d171f12db5410cd5b4670572b13c350aa9fd54e7c4389a7544fe404b6bc \
      lab/interop/eudi-dev/run.sh

v2.5.0's own issuer changed shape. Its PID Provider certificate is now signed by an intermediate CA,
"EUDI Dev Test pid CA NL" (basicConstraints cA with pathLen 0, keyCertSign), which the credential
carries as `x5c[1]`, under the root that `eudi wallet ca-cert` exports (pathLen 1). v2.3.7 signed
the leaf under the root directly.

| | `polaris-oid4vp` | Result |
|---|---|---|
| The genuine presentation, strict mode, TLS checked | 1.0.0rc14 from PyPI | refused: `issuer_key: the x5c leaf does not chain to any configured trust anchor`, because the verifier read the leaf alone |
| The same | this repository at bf3798d4 | accepted: `<- 200 authentic, claims ['cnf', 'exp', 'family_name', 'given_name', 'iat', 'iss', 'status', 'vct']` |
| Control: the answered request again | bf3798d4 | refused at the request, through the tunnel: `request_uri returned HTTP 404` |
| Control: a launch URI whose `client_id` is not the signed request's | bf3798d4 | refused by the wallet, through a second tunnel |
| Control: the verifier trusts an unrelated CA | bf3798d4 | refused: `issuer_key` |

From bf3798d4 the verifier reads the CA certificates an `x5c` carries after its leaf, in order and at
most three, each checked as a link to the next and the last to a configured anchor
([package README](../../../packages/polaris-oid4vp/README.md)). The same commit, walked the earlier
ways, still accepts v2.3.7's one-link chain (`EUDI_ISSUER=1`, all three controls refused) and
OID4VCgo v0.23.0's issuer ([oid4vcgo](../oid4vcgo/README.md), every control refused). Walked on
macOS (arm64) with Docker; 1.0.0rc14 does not carry the change, so a release after it is the first
that will.

## What this does not establish

- **Not observed.** Whether eudi-dev posted a `wallet_nonce` with `request_uri_method=post`
  (neither side's log records it at the default verbosity). It chose A128GCM (its debug line
  prints a 16-byte content key), so A256GCM was not reached.
- **Observed 2026-09-30, the wallet's trust.** Given no trust anchor at all, eudi-dev still
  accepts a request object whose certificate chains only to `keygen`'s test CA, so it does not
  require that chain to reach anything it trusts: the `x509_hash` binding is what it checks. It
  does not validate the verifier's TLS certificate either (above). Both are the wallet's own
  behaviour, recorded here and not absorbed.
- One credential format, one path, ES256/P-256 throughout. Except in the run above, the
  credential was minted by this repository's issuer script and trusted through a JWKS rather
  than `x5c`.
- It is the same category of evidence as the walt.id and Credo rows: the author drove a
  published wallet on one machine. It is not an outside party using Polaris, and not a claim
  that `polaris-oid4vp` is interoperable in general.
