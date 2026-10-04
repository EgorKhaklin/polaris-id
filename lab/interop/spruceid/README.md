# SpruceID OpenID4VP library (holder) → polaris-oid4vp

SpruceID's OpenID4VP 1.0 library for Rust, [`spruceid/openid4vp`](https://github.com/spruceid/openid4vp),
presents an SD-JWT VC over OpenID4VP 1.0 `direct_post.jwt` to `polaris-oid4vp` as installed from
PyPI, through the headless wallet in the library's own repository.

The wallet is
[`examples/wallet-conformance-adapter`](https://github.com/spruceid/openid4vp/tree/e5f29b85f14ca0b3c6eb6852e4d2d158f601fd63/examples/wallet-conformance-adapter)
at commit `e5f29b85` (2026-07-27), the HTTP wallet its authors point the OpenID Foundation's wallet
test plan at. No wallet code is written here. The library and the adapter do the work:
- the library resolves the request: `x509_hash`, the signed request object fetched by GET, the
  DCQL query. It checks that the `client_id` is the hash of the `x5c` leaf, that the leaf's key
  signed the request object, and that the launch named the same `client_id`;
- the adapter signs the credential it holds as a HAIP issuer does (`typ` `dc+sd-jwt`, `x5c`),
  discloses the two claims asked for and adds a key binding JWT; the library encrypts the
  response to the verifier's key (`ECDH-ES`).

Its OpenID4VP is SpruceID's own, separate from the implementations the other walks drive.

## What was changed in the adapter

Two fixtures, and nothing else. [`run.sh`](run.sh) changes them in its copy of the source before
the build, and refuses to build if any other file differs (4 lines in 2 files):

- **The issuer key and certificate** (two constants in `crypto/issuer.rs`). The adapter's
  certificate names no issuer: it has no subjectAltName, while the credential says `iss`
  `https://issuer.example.com`. Its CA is published in the adapter's README, and the verifier was
  given it: the chain verified, and the verifier refused the binding, `<- 400 refused: issuer_key:
  the credential names issuer 'https://issuer.example.com' and the certificate that signed it
  names no issuer (no URI or DNS subjectAltName), so nothing binds the two` (2026-10-04, with only
  the second change below). A certificate that names the `iss` needs that CA's private key, which
  is not published, so `run.sh` makes a CA, an issuer key and a certificate naming
  `https://issuer.example.com`, and the verifier trusts the CA (`--issuer-trust-anchor`).
- **The credential's type** (`credentials.json`: its `vct`, and the same claim in the issuer
  payload the adapter re-signs), from `https://credentials.example.com/pid/1.0` to
  `urn:eudi:pid:1`. 1.0.0rc15 asks for `urn:eudi:pid:1`, and the adapter picks a credential by
  type.

The claims, the holder key and everything the library does are the adapter's own.

## Plain HTTP between the wallet and the verifier

The library fetches the request object with rustls and the public web roots compiled into it,
which nothing at run time extends: with the verifier's self-signed listener certificate in the
container's trust store and in `SSL_CERT_FILE`, it still refused, `invalid peer certificate:
UnknownIssuer`. So the verifier serves plain HTTP on the Docker host (`--no-local-tls
--public-base-url http://host.docker.internal:9481`). The request object is still signed and
checked, and the response still encrypted to the verifier's key; the transport is not under test
here.

## Run it

    lab/interop/spruceid/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/spruceid/run.sh

[`run.sh`](run.sh) runs everything in a scratch directory (`WORK`):
- `polaris-oid4vp` from PyPI in a fresh venv, its dependencies by hash;
- the library's source, fetched at commit `e5f29b85` by its hash (`SPRUCEID_COMMIT`), and the two
  fixtures above;
- the adapter, built with Cargo in `rust:1.99.0-bookworm` pinned by digest and run in the same
  image. A cold build took about 8 minutes here (8 cores, shared with other builds); the Cargo
  registry and the build are named volumes, so a later run recompiles only the library's own
  crates and the adapter (44 seconds);
- the verifier's test PKI, the issuer CA, the presentation and the three controls.

The library commits no lock file, and this walk does not add one: OSV lists advisories against
crates the library depends on (most through `ssi` 0.16) with no fixed release in the ranges it
allows. Cargo resolves the newest releases those ranges allow when the build runs.

It exits 0 only if the presentation is accepted and every control is refused. Docker is required.
The verifier listens on port 9481 (`PORT`), the wallet on 9482 (`WALLET_PORT`).

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts an unrelated issuer CA | the verifier | `<- 400 refused: issuer_key: the x5c leaf does not chain to any configured trust anchor`; the adapter: `verifier_error`, `Verifier returned 400 Bad Request` |
| (b) | The same request presented again after it was answered | the verifier, at the request | the library: `authorization request request was unsuccessful (status: 404 Not Found)`, `no such outstanding request` |
| (c) | The launch names a `client_id` that is not the signed request's | the wallet | the library: `Authorization Request and Request Object have different client ids` |

(c) is a control on the library: it compares the signed request object with what it was launched
with, and presents nothing when they differ. The adapter is configured with no anchor for
verifiers, so this walk has no control on the wallet's trust in the verifier.

## Result, 2026-10-04

Against `polaris-oid4vp` 1.0.0rc15 from PyPI, with `spruceid/openid4vp` at `e5f29b85`, built with
Rust 1.99.0: accepted, `<- 200 authentic, claims ['cnf', 'exp', 'family_name', 'given_name',
'iat', 'iss', 'sub', 'vct']`, and the adapter returned the verifier's answer (`200`, with its
`redirect_uri`). All three controls were refused.

## What this does not establish

- The wallet is the library's conformance adapter, a test harness: it holds one fixed credential
  and consents to every request. It is not a wallet app. The library is the part that speaks
  OpenID4VP: it fetched, checked and answered the request.
- The credential's issuer is a CA made by `run.sh`, which took replacing two of the adapter's
  fixtures (above); with its own certificate the verifier refused it, for the reason given there.
- The transport was plain HTTP (above), so nothing here exercises either side's TLS.
- The build's dependencies are resolved when it runs, not pinned (above).
- One credential format and one path, ES256 throughout.
- Same category as the other walks: the author drove a published library on one machine. It is
  not an outside party using Polaris, and not a claim of interoperability in general.
