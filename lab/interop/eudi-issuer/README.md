# EU reference PID issuer → EU reference wallet libraries → polaris-oid4vp

The European Commission's reference PID issuer,
[eudi-srv-pid-issuer](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer), issues an
SD-JWT VC PID over OpenID4VCI 1.0 to a wallet built on the EU's own OpenID4VCI library, and the
wallet presents it over OpenID4VP 1.0 `direct_post.jwt`, on the EU's own OpenID4VP library, to
`polaris-oid4vp` as installed from PyPI. The verifier trusts one issuer certificate authority and
no other: the root of the test PKI that ships in the issuer's own docker-compose, given as its
only `--issuer-trust-anchor`. The verifier is the only Polaris software in the exchange.

The issuer runs as its own docker-compose runs it ([`compose.yaml`](compose.yaml)): Keycloak with
the EU's attestation-based client authentication extension and the realm's test user, PostgreSQL,
the issuer, and HAProxy in front of both at `https://localhost`. [`run.sh`](run.sh) fetches the
upstream files from the v0.11.1 commit, checks each SHA-256, and takes every service's environment
from upstream's `docker-compose.yaml` unchanged. What differs is listed at the top of
`compose.yaml`: images pinned by digest, no status-list service (nothing calls it), and HAProxy also
serving the test wallet provider's status list.

The issuer offers one flow, the authorization code flow (its README marks the pre-authorized code
flow unsupported), and asks a wallet for a lot: a pushed authorization request with PKCE, DPoP-bound
tokens, attestation-based client authentication (the realm's `eudiw-abca` client), and a JWT proof
that carries a key attestation with key storage and user authentication at `iso_18045_high` (the EU
wallet unit attestation profile, TS3). The wallet is [`Issue.kt`](wallet/src/main/kotlin/Issue.kt)
to obtain the PID and [`Present.kt`](wallet/src/main/kotlin/Present.kt) to present it, about four
hundred lines with [`Main.kt`](wallet/src/main/kotlin/Main.kt). The libraries do the protocol:
- `eudi-lib-jvm-openid4vci-kt` resolves the issuer and authorization server metadata, pushes the
  authorization request, fetches the client attestation challenge, exchanges the code, keeps the
  DPoP nonces, fetches the credential nonce, signs the proof, and encrypts and decrypts the
  credential request and response;
- `eudi-lib-jvm-openid4vp-kt` resolves the presentation request (`x509_hash`, the signed request
  object fetched by POST, the DCQL query) and dispatches the response, encrypted to the verifier's
  key (`ECDH-ES`).

The wallet does what the libraries leave to a wallet:
- it logs the test user (`tneal`, from the issuer's realm) in at Keycloak's login form over plain
  HTTP, as a browser would, with no browser: it opens the authorization URL the library prepared,
  posts the form, and hands the library the code from the redirect;
- a test wallet provider that `run.sh` makes signs the client attestation and the key attestation
  under a self-signed certificate in `x5c`, and a status list that both point at. Keycloak and the
  issuer fetch it from HAProxy and check its signature. Upstream configures no trust validator, so
  both accept any wallet provider: that is what lets a wallet built here be issued to at all;
- it presents the PID: of its 25 disclosures, the two the query names (`given_name`,
  `family_name`), and a key binding JWT under the attested key the PID is bound to.

## The PID and its certificate

| | |
|---|---|
| Format | `typ` `dc+sd-jwt`, `vct` `urn:eudi:pid:1`, ES256, `iss` `https://localhost/pid-issuer` |
| Claims | 25 disclosures (names, birth, nationality, address, picture, sex, email, document data); `nbf` 20 seconds after `iat`, `exp` 31 days after |
| `x5c` | `CN=ISSUANCE` ← `CN=ISSUANCE INTERMEDIATE`. The keystore holds the chain up to `CN=ISSUANCE ROOT`, and the issuer leaves a self-signed last certificate out of `x5c` |
| Leaf | not a CA, no key usage stated, subjectAltName `DNS:localhost`, `DNS:pid-issuer`, `IP:127.0.0.1`, no URI name |
| HAIP 1.0 6.1.1 | met: the trust anchor is not in `x5c`, and the leaf is neither self-signed nor a CA |
| `iss` naming | met: `iss` is an https URL whose host, `localhost`, is a DNS name of the leaf |

`polaris-oid4vp` 1.0.0rc15 asks for `vct` `urn:eudi:pid:1` with `given_name` and `family_name`,
which is what this issuer issues, so the published verifier ran with its defaults: no `--vct` and
no `--claim`.

## Versions

| | |
|---|---|
| Issuer | eudi-srv-pid-issuer v0.11.1, `ghcr.io/eu-digital-identity-wallet/eudi-srv-pid-issuer:v0.11.1` (`sha256:2e6176a00f3bea3266d79cdf8182c2fcad96436f5a7a463ad504eb533a6e06f2`, linux/amd64 only), Apache-2.0; its `docker-compose/` files at commit `9177177071157b20724b04eed619049e40679bbb` |
| Authorization server | Keycloak 26.6.2, `quay.io/keycloak/keycloak:26.6.2-2` (`sha256:f9ba7b2af90db8dc749a57ca9aedca51e840cb9224441ab546a968da941da900`), with `eu.europa.ec.eudi:abca-keycloak-ext` 0.2.0 from Maven Central (`sha256:4b10222577445f936ead647980b22e672ee9e38e0c1e5b8ac8dab60dd5ea8a86`) |
| Around them | `postgres:18.4-alpine3.24` (`sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15`), `haproxy:2.8.3` (`sha256:fdd14bba61bed25638503b51a9d59ee31082d71a461ec28eddb29ad522156c67`) |
| Wallet | `eu.europa.ec.eudi:eudi-lib-jvm-openid4vci-kt` 0.14.1 and `eudi-lib-jvm-openid4vp-kt` 0.16.2, Ktor 3.3.3 (OkHttp), Kotlin 2.4.20, Bouncy Castle 1.86, on JDK 21 in `gradle:8.14.3-jdk21` (`sha256:21bd311ed01360c189b8870c6b6e988199ff10f72d445d02fb39d3cff9da91d7`) |
| Verifier | `polaris-oid4vp` 1.0.0rc15 from PyPI, in a fresh venv |
| Runtime | Python 3.12.13, Docker 29.8.1, macOS 26.3 (Darwin 25.3.0, arm64; the issuer image ran under emulation) |

## Run it

    lab/interop/eudi-issuer/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/eudi-issuer/run.sh

[`run.sh`](run.sh) runs everything in a scratch directory (`WORK`):
- `polaris-oid4vp` from PyPI in a fresh venv, its dependencies by hash;
- the issuer's own files (its compose file, realm, keystore, TLS certificates and schema) from the
  release's commit, and the Keycloak extension from Maven Central, each checked against its SHA-256;
- the test wallet provider's key, certificate and status list;
- the issuer stack, and meanwhile the wallet, compiled in a JDK image pinned by digest. Every library
  is checked against [`wallet/gradle/verification-metadata.xml`](wallet/gradle/verification-metadata.xml)
  (124 components), written by `gradle --write-verification-metadata sha256 installDist` from an
  empty Gradle cache, so a dependency that changes under its version fails the build;
- the issuance; a wait for the PID's `nbf`, which a verifier holds it to; the presentation and the
  four controls. The wallet runs inside HAProxy's network namespace, where `https://localhost` is
  the issuer, and imports the issuer's and the verifier's test TLS certificates into its JDK's trust
  store.

It exits 0 only if the PID is issued, the presentation is accepted and every control is refused.
Docker with Compose v2 is required. The verifier listens on port 9488 (`PORT`). The stack is removed
at the end (`KEEP_ISSUER=1` keeps it; its logs are in `WORK/issuer-stack.log`).

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts an unrelated CA instead of the issuer's | the verifier | `<- 400 refused: issuer_key: the x5c leaf does not chain to any configured trust anchor`; the library reported `Rejected` |
| (b) | The same request presented again after it was answered | the verifier, at the request | the library: `UnableToFetchRequestObject`, `404 Not Found`, `no such outstanding request` |
| (c) | The launch URI names a `client_id` that is not the signed request's | the wallet | the library: `InvalidJarJwt(ClientId mismatch. JAR request x509_hash:AAAA..., jwt x509_hash:...)` |
| (d) | The wallet trusts an unrelated CA for the verifier | the wallet | the library: `InvalidJarJwt(Untrusted x5c)` |

(a) is the one this walk is for: the verifier accepts the PID because of the anchor it was given,
not because the credential names its own chain. (c) and (d) are controls on the OpenID4VP library,
as in [`../eudi-kt/`](../eudi-kt/README.md).

## Result, 2026-10-04

Against `polaris-oid4vp` 1.0.0rc15 from PyPI: the issuer issued a PID to the wallet (a DPoP-bound
access token for `tneal`, then the credential, bound to the attested key), and the verifier
accepted its presentation, `<- 200 authentic, claims ['cnf', 'exp', 'family_name', 'given_name',
'iat', 'iss', 'nbf', 'vct']`, while the library reported `Accepted`. All four controls were refused.
Neither side was changed.

The run took under two minutes with the images and the Gradle cache present: the stack was up in
about 45 seconds, issuance took 8, and 20 went on waiting for the PID's `nbf`. The wallet's first
build, from an empty Gradle cache, took 55 seconds, and a first run also pulls the four images in
`compose.yaml`.

## What this does not establish

- The issuer is the reference implementation's development deployment as its own compose
  describes it: `https://localhost`, its published test keys and its test user. It is not a PID
  provider, and the trust anchor is a test root whose private key is public in the issuer's
  repository; trusting it means something only on this machine.
- The issuer accepted the wallet because no trust validator is configured upstream. The client and
  key attestations were signed by a key `run.sh` made, so this run says nothing about what the
  issuer does with a wallet provider it is told to trust or refuse.
- The wallet is built here on the two libraries; it is not the EUDI reference wallet app. The
  login is scripted against Keycloak's form, and which disclosures to present and the key binding
  are this repository's few lines, as they are any wallet's.
- The PID carries no status reference (the issuer allocates one only under a reuse policy, which
  upstream does not enable), so this run says nothing about revocation. One format (SD-JWT VC; the
  issuer's mso_mdoc PID was not requested), one flow, ES256 throughout.
- Same category as the other rows: the author drove published software on one machine. It is not
  an outside party using Polaris, and not a claim of interoperability in general.
