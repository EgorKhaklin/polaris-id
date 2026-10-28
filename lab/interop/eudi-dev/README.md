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
| Wallet | `ghcr.io/dominikschlosser/eudi-dev:v2.3.7` (`sha256:2df7ac5c79206a29c66eb8c49acdcc07d0ec76c7d6d260056edccaac9257e081`), `:v2.4.3` (`sha256:d544031950e9b5e911fe2212e5e57e109459d53e294e1b6feb243036e5dac3fc`) and `:v2.5.0` (`sha256:c6d28d171f12db5410cd5b4670572b13c350aa9fd54e7c4389a7544fe404b6bc`), Apache-2.0, [source](https://github.com/eudi-dev/eudi-dev) |
| Verifier | `polaris-oid4vp` 1.0.0rc7 from PyPI, with `cryptography` 50.0.1, in a fresh venv |
| Runtime | Python 3.12.13, Docker 29.4.3, macOS 26.3 (Darwin 25.3.0) |

## Run it

    lab/interop/eudi-dev/run.sh                                            # v2.3.7
    EUDI_IMAGE=ghcr.io/dominikschlosser/eudi-dev:v2.4.3 lab/interop/eudi-dev/run.sh
    EUDI_IMAGE=ghcr.io/eudi-dev/eudi-dev:v3.3.1 lab/interop/eudi-dev/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc7 lab/interop/eudi-dev/run.sh    # the run above, exactly
    EUDI_NATIVE=1 lab/interop/eudi-dev/run.sh                              # no Docker
    EUDI_NATIVE=1 EUDI_VERSION=v3.3.1 lab/interop/eudi-dev/run.sh          # 3.x's own binary
    EUDI_ISSUER=1 lab/interop/eudi-dev/run.sh                              # eudi-dev's own issuer
    EUDI_TUNNEL=1 lab/interop/eudi-dev/run.sh                              # each verifier behind its own tunnel

One command, about a minute once the image is local. It installs the verifier from PyPI into a
fresh venv in a scratch directory (`WORK`, default a new temporary one, removed when the run passes
and kept, with its path printed, when it fails), the newest release as
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
wallet, credential and path with one thing wrong. Each is judged as
[the next section](#how-a-verdict-is-read-2026-10-21) says: by the wallet's exit status and JSON,
and by the verifier's record of this walk's own request, not by what either side prints, except
that a control the wallet refuses needs the wallet to name that control's reason.

| | What changed | Refused by | The walk requires, while that wallet runs |
|---|---|---|---|
| (a) | The verifier trusts a different issuer key under the same `kid` (with `EUDI_ISSUER=1` or `EUDI_CAPTURE`, an unrelated CA) | the verifier | one response to this walk's request, refused with `issuer_signature` (`issuer_key` under a CA), and the request object served; the wallet's JSON says HTTP 400, and a 3.x wallet exits non-zero |
| (b) | The same request presented again after it was answered | the verifier, at the request | the wallet exits non-zero, says its fetch of the request was answered 404, and no response arrives; the request object is not served, and is refused at least once |
| (c) | The launch URI names a `client_id` that is not the signed request's | the wallet | the wallet exits non-zero, says the request object's `client_id` does not match the one this walk launched it with, and no response arrives; the request object was served, so the wallet read it before refusing |
| (d) | The wallet trusts an unrelated certificate for the verifier's TLS (only when the wallet checks TLS) | the wallet | the wallet exits non-zero, names the untrusted certificate on its fetch of this walk's request, and no response arrives; the request object is neither served nor refused, on a count that (c), run just before on the same request, has already moved |

The request object conditions are read from `serve --result`; against a `polaris-oid4vp` without
it (1.0.0, from PyPI), (b), (c) and (d) rest on the exit status, on no response arriving and on
the wallet's refusal. An exit status and no response alone are what a wallet that stopped for any
other reason leaves (a flag it does not know, a certificate file it could not open), so each
control also needs the wallet's refusal for its own reason, read in eudi-dev's words on stderr:
`POST to request_uri returned HTTP 404` for (b);
`request object client_id "x509_hash:..." does not match outer client_id "x509_hash:AAAA..."` for
(c), naming the `client_id` this walk launched it with; and, for (d), Go's
`tls: failed to verify certificate: x509: certificate signed by unknown authority` on this walk's
own request URI. v2.3.7 and v3.3.1 word (b) and (c) the same (3.x adds a prefix and the HTTP
status); v2.5.0 and v3.3.1 word (d) so. A wallet that words a refusal otherwise fails that control.

(c) is a control on the wallet: it shows eudi-dev reads the signed request object and compares
it with what it was launched with, rather than presenting to whatever it is pointed at.

## How a verdict is read (2026-10-21)

Until 2026-10-21 the walk matched what the two sides printed: the genuine presentation passed when
the wallet printed `Response: 200` and the verifier `<- 200 authentic`, and each control when one
of a few error texts appeared. eudi-dev 3.3.1 prints `submitted: HTTP 200` for the same answer.
Run that way against v3.3.1's image by digest, with polaris-oid4vp 1.0.0 from PyPI, the walk printed
`RESULT: FAILED` and exited 1 although the verifier accepted the presentation (`<- 200 authentic`)
and every control was refused: the two checks that failed looked for `Response: 200` and
`Response: 400`, where the wallet had printed `submitted: HTTP 200` and `submitted: HTTP 400`
(measured 2026-10-21). Now each verdict is read from:

- **The wallet**: its exit status and its `--json` output. 3.x writes one JSON document to stdout
  (`status`, and the verifier's answer in `response.status_code`) and exits non-zero when the
  verifier refuses or nothing is presented. 2.x, v2.3.7 included, prints lines of text and then a
  JSON object (`status_code`, `body`, `redirect_uri`), and exits 0 when the verifier answers 400:
  for 2.x the walk reads the status from that object, and asks for a non-zero exit only where the
  wallet presented nothing.
- **The verifier**: its record of its one request, read before and after each wallet run: the
  responses received, the outcome of the latest (`accepted`, or `refused` with the check), and
  the request object fetches it served and refused. The record comes from `serve --result FILE`
  ([package README](../../../packages/polaris-oid4vp/README.md)) when the installed
  `polaris-oid4vp` lists that option in its help; 1.0.0, the release on PyPI on 2026-10-21, does
  not, and the walk reads the same off the `<-` lines its log prints, without the fetches.
- **This walk's request**: the `state` in the launch URI the wallet was given must be the state of
  the verifier's record, and only what changed during that wallet's run counts.

The genuine presentation passes when the wallet exits 0 with HTTP 200 in its JSON (from 3.x, with
`status` `submitted`) and exactly one response to this request arrived and was accepted. The
controls are the table above.

Measured on 2026-10-21 on macOS (arm64), each run exiting 0 with `RESULT: accepted`, against
polaris-oid4vp 1.0.0 from PyPI (its record read off the log) and against the package with
`serve --result`: eight runs.

| eudi-dev | Run as | Controls refused |
|---|---|---|
| v2.3.7 | the image, `ghcr.io/dominikschlosser/eudi-dev@sha256:2df7ac5c79206a29c66eb8c49acdcc07d0ec76c7d6d260056edccaac9257e081` | three: it does not check the verifier's TLS, so there is no (d) |
| v2.3.7 | its release binary (`EUDI_NATIVE=1`), SHA-256 `2cefced5cce8c25c4b1d5cf35796e8e4ce470c92067b176dd18e8c6061385fef` (darwin-arm64, as pinned) | three |
| v3.3.1 | the image, `ghcr.io/eudi-dev/eudi-dev@sha256:69140395c4d82536ab468069c0a6a603a2215cfac7060f74ef3db5fd63706908` | four |
| v3.3.1 | its release binary (`EUDI_NATIVE=1 EUDI_VERSION=v3.3.1`), SHA-256 `f0b8ebfc1aed9f1cc63a9756d492be0dd90ba3002dfdddb8f12cd4559fd16ce8` (darwin-arm64, as the release's checksums give it) | four |

v3.3.2's image (`sha256:7c0d5cd742fa9c5ee21e12e36665cfe35969460fbc209f9b8acc0751a06d9741`),
released that day, passed against 1.0.0 too. With the package changed to accept any issuer
signature under a trusted `kid`, the v3.3.1 image run exited 1 with `RESULT: FAILED`: control (a)
was accepted, and both of its checks failed.

## No other wallet answers (2026-10-21)

eudi-dev 2.x's `wallet accept` first offers the request to a wallet server already running on the
machine: without `--port`, it tries the server its URL handler recorded and then `localhost:8085`,
and when one answers `GET /api/log` it posts the request there and prints that server's result as
its own. A walk run beside an eudi-dev wallet server on the default port would have judged that
wallet, not the one it set up. 3.x presents from its own process, and starts its own server on a
port pair, moving to another pair when that one is taken.

The walk now passes `--port` with two adjacent ports it found free, so 2.x asks only there, where
nothing answers, and 3.x serves there. Without Docker, the wallet's whole state directory is the
work dir's (`EUDI_DEV_HOME`), so no URL handler or remote set up on the machine is read. The walk
also clears `EUDI_DEV_SEED`: the 3.x image sets it to the public seed `eudi-dev`, from which the
wallet derives its keys (eudi-dev's SECURITY.md, l.10 at v3.3.2). Two wallets started from v3.3.1's image as the walk starts one, but with
that seed, held the same holder, issuer and CA keys (their CA certificates carried different
serial numbers); with it cleared, each held its own (measured 2026-10-21).

[`test_walk.py`](test_walk.py) runs each verdict above without a wallet (CI runs it). With
`EUDI_WALLET_TESTS=1` it also holds a listener on `localhost:8085` that answers as a wallet server
would, runs the walk with v2.3.7's own binary, and fails if anything reaches the listener; the
canary runs it. Measured 2026-10-21 on macOS (arm64), against the walk as it was before that day,
which passed no `--port`: in each of v2.3.7's four wallet runs, the wallet asked the listener
`GET /api/log`, posted the request to its `/api/presentations` and printed its answer
(`Submitted: Response: 200`), and no response reached the verifier. The walk's check
`the wallet submitted and was answered 200` passed on that answer, and the run failed on its other
checks. With `--port`, nothing reached the listener and the walk passed; with only `--port`
removed from this walk, the listener was reached again and the walk failed: the verifier's record
showed no response to its request.

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

[eudi-dev issue 21](https://github.com/eudi-dev/eudi-dev/issues/21) reported that the wallet
did not validate the verifier's TLS certificate, even in `--mode strict`. The maintainer fixed it in
[v2.5.0](https://github.com/eudi-dev/eudi-dev/releases/tag/v2.5.0) and asked for a re-test.

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
macOS (arm64) with Docker; 1.0.0rc14 does not carry the change, and 1.0.0rc15 is the first release
that does.

## From PyPI 1.0.0rc15 (2026-10-04)

    EUDI_NATIVE=1 EUDI_VERSION=v2.5.1 EUDI_ISSUER=1 POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 \
      lab/interop/eudi-dev/run.sh

eudi-dev v2.5.1's own binary, in strict mode with its TLS check on (it trusts keygen's listener
certificate through `--tls-ca`), presented a PID its own issuer signed under the intermediate CA
above. 1.0.0rc15 from PyPI accepted it: `<- 200 authentic, claims ['cnf', 'exp', 'family_name',
'given_name', 'iat', 'iss', 'status', 'vct']`. All four controls were refused: an unrelated issuer
CA (`issuer_key`), the answered request again, a mismatched `client_id` and an unrelated TLS trust
(the last two by the wallet). The same walk against 1.0.0rc14 from PyPI refused the genuine
presentation: `issuer_key: the x5c leaf does not chain to any configured trust anchor`. Walked on
macOS (arm64), no Docker and no tunnel.

## One member of a nested claim (2026-10-04)

The PID eudi-dev's own issuer signs nests its claims as the PID Rulebook does: `address` and
`place_of_birth` are objects whose members are each disclosable. A verifier that can ask only for
top-level names has to ask for the whole `address`, and gets the street and the house number with
the locality. `polaris-oid4vp` at c35393ac asks for a path, optionally with the value it must
have (`serve --claim`; the walk's `CLAIMS` passes them):

    EUDI_NATIVE=1 EUDI_ISSUER=1 CLAIMS="given_name address.locality place_of_birth.country=NL" \
      POLARIS_OID4VP=packages/polaris-oid4vp lab/interop/eudi-dev/run.sh

| Asked for | eudi-dev v2.3.7, its own binary and PID provider | Verifier |
|---|---|---|
| `given_name`, `address.locality`, `place_of_birth.country=NL` | its DCQL engine selected exactly those three and disclosed them: `Disclosing: [given_name address.locality place_of_birth.country]` | `<- 200 authentic`; all three controls refused |
| `place_of_birth.country=DE` (the PID says NL) | `no matching credentials found for the DCQL query`: it presented nothing | nothing to judge |

The street address, house number, postal code and region stayed with the wallet. The verifier
refuses a wallet that would send another value anyway (`claims`; unit tests, a wallet that
ignores `values`). This PID carries no age statements, so `age_equal_or_over.18` is not
exercised here; the same path and value check covers it in the package's tests.

## A captured presentation (2026-10-10)

[`capture/`](capture/README.md) holds one genuine exchange as files another verifier can vendor
and check offline: the presentation with its key binding JWT, the DCQL-keyed `vp_token`, the
signed request and the issuer's CA, with [their provenance](capture/PROVENANCE.md) and a test that
verifies them with the clock frozen at the capture. `EUDI_CAPTURE=DIR` writes them:

    EUDI_CAPTURE=../ecap/capture3 POLARIS_OID4VP=polaris-oid4vp==1.0.0rc16 PORT=9547 lab/interop/eudi-dev/run.sh

In that mode the issuer script signs under an `x5c` certificate and the verifier trusts its CA
(`--issuer-trust-anchor`), so control (a) trusts an unrelated CA, and the genuine presentation's
verifier runs through [`capture_serve.py`](capture_serve.py), which runs the installed
`polaris-oid4vp serve` in-process and records the bytes it serves, reads and decrypts. Against
eudi-dev v2.3.7 and 1.0.0rc16 from PyPI: accepted, all three controls refused.

## What was run

- **Observed 2026-10-10, in the capture above.** eudi-dev v2.3.7 posts a `wallet_nonce` with
  `request_uri_method=post`, and a `wallet_metadata` asking for the request object encrypted to
  its own key, which `polaris-oid4vp` 1.0.0rc16 did. It chose A128GCM for the response.
- **Observed 2026-09-30, the wallet's trust.** Given no trust anchor at all, eudi-dev still
  accepts a request object whose certificate chains only to `keygen`'s test CA: the `x509_hash`
  binding is what it checks.
- One credential format, one path, ES256/P-256 throughout. Except in the run above, the
  credential was minted by this repository's issuer script and trusted through a JWKS rather
  than `x5c`.
- The author drove a published wallet on one machine.
