# ERICA (wallet simulator) → polaris-oid4vp

[ERICA](https://gitlab.opencode.de/bmi/eudi-wallet/erica), the "EUDI Relying Party Integration
Compliance Analyzer" of the German EUDI Wallet programme (TypeScript, MIT), is a local testing
tool for relying parties: it fetches a verifier's request, checks it against OpenID4VP, HAIP and
its German PID presentation profile, simulates the wallet in a chosen mode (a valid PID, or one
broken on purpose) and posts the `direct_post.jwt` response. Here it is the wallet, and
`polaris-oid4vp` is the verifier.

ERICA has no command line; its web UI is a page over two endpoints, and
[`drive.py`](drive.py) calls them as the UI does: `POST /api/parse-url` (ERICA fetches the
request object from the launch URI and checks it), then `POST /api/debug` (ERICA validates the
request against its PID profile, builds the presentation in one mode and posts it, encrypted
`ECDH-ES`/`A128GCM` to the key in `client_metadata`). ERICA does the work: the request
validation, the SD-JWT VC with its disclosures and key binding JWT, the encryption and the post.

Two things stand between ERICA and a verifier on the same machine, and the run handles each
without changing ERICA:

- **ERICA refuses to fetch a `request_uri` on loopback or in the RFC 1918 ranges** (its SSRF
  guard, `src/security/URLValidator.ts`). The run gives the verifier a name, `polaris-verifier.test`,
  that ERICA resolves to an address on a Docker network in 198.18.0.0/15 (the RFC 2544 test
  range, which the guard does not list), where a TCP forwarder (node, from ERICA's own image)
  passes the connection to the verifier on this machine. TLS runs end to end through it: ERICA
  trusts the verifier's self-signed listener certificate through `NODE_EXTRA_CA_CERTS`, and its
  checks stay on.
- **ERICA's own PID breaks a HAIP rule the verifier enforces.** It signs under its committed test
  root ([`src/security/issuer/`](https://gitlab.opencode.de/bmi/eudi-wallet/erica/-/tree/2c27dc9254d7fc97c20ac4677747014519aa48ba/src/security/issuer),
  also served at `/api/issuer/trust-anchor`) with `x5c` [leaf, root]: the root rides in the
  chain, which HAIP 1.0 6.1.1 forbids, and the verifier refuses it (below). Its leaf also has no
  subjectAltName, so nothing in it names the credential's `iss`
  (`https://debugger.eudi-wallet-demo.example`), which `polaris-oid4vp` requires when `iss` is
  present. So the run starts a second ERICA whose issuer directory holds a chain made for the run
  under that same root and its published key, shaped as HAIP wants: an intermediate CA in the
  slot ERICA sends after the leaf, and a leaf naming ERICA's `iss` as a URI. ERICA's code and
  image are the same; only the files it loads at startup differ.

In both cases the verifier trusts exactly ERICA's committed root (`--issuer-trust-anchor`,
SHA-256 `28f1a8c2...9d9ec901`), and the run checks that it is the certificate ERICA serves.

## Versions

- ERICA at commit [`2c27dc92`](https://gitlab.opencode.de/bmi/eudi-wallet/erica/-/commit/2c27dc9254d7fc97c20ac4677747014519aa48ba)
  (2026-09-24, `main`), built with its own Dockerfile and npm lockfiles from exactly the
  committed files (`git archive`), with `node:22-alpine` pinned by digest through a named build
  context. The lockfiles are ERICA's and are not copied here.
- `polaris-oid4vp`: the tree at `6df94c73`, and 1.0.0rc15 from PyPI. ERICA's PID is of type
  `urn:eudi:pid:de:1`; the tree's `serve` is asked for it with `--vct`, which rc15 does not have
  (it asks for `urn:eudi:pid:1`). The tree's `--claim PATH=VALUE` is what lets the template cases
  below ask for exact values.

## Run it

    POLARIS_OID4VP="$PWD/packages/polaris-oid4vp" lab/interop/erica/run.sh
    lab/interop/erica/run.sh                               # the newest polaris-oid4vp on PyPI

[`run.sh`](run.sh) runs everything in a scratch directory (`WORK`): `polaris-oid4vp` in a fresh
venv (dependencies by hash), ERICA cloned and built at the pinned commit (about a minute from
empty caches), the verifier's test PKI, the issuer chain under ERICA's root, the Docker network
and forwarder, two ERICA containers, then ERICA's checks on the request, the presentations and
the controls, each against a fresh `serve --once`. It exits 0 only if the presentation is
accepted and every negative case is refused. Docker is required. The verifier listens on port
9486 (`PORT`) and ERICA on the two ports after it (`ERICA_PORT`).

## What ERICA says about the request

ERICA ran 48 checks on the request: 18 as it fetched and parsed it (the URL, the TLS fetch, the
JWT, the `x5c` certificate, the signature, the `client_id` in the link against the signed one)
and 30 on its content under its PID presentation profile. Every check of an OpenID4VP or HAIP
rule passed:
`x509_hash` with a SHA-256 of the right length, `direct_post.jwt`, an HTTPS `response_uri` and
no `redirect_uri`, `client_metadata` with an encryption key, `aud`
`https://self-issued.me/v2`, `iss` equal to `client_id`, a nonce of sufficient length, a
`state`, a well-formed DCQL query for `dc+sd-jwt`, and no field outside its profile. What
failed, verbatim (`findings.txt`), against the tree asked for `urn:eudi:pid:de:1`:

    WARNING parse-url url.request_jwt.x5c_trust_anchor (Trust Anchor Validation, Security)
        issue    Access Certificate not trusted by any Registrar in trust list
        details  Access Certificate signature could not be verified against any trusted Registrar
        fix      Ensure the RP's Access Certificate is signed by a trusted Registrar
    ERROR request profile.verifier_info.presence (Verifier Info Presence (PID), Profile)
        issue    PID Presentation requires verifier_info to relay the registration certificate
        field    verifier_info
        expected verifier_info object
        actual   undefined
        fix      Add verifier_info with registration certificate
        spec     EUDI-ARF 3.2
    verdict  valid=False, 29 of 30 request checks passed, 1 error(s), 0 warning(s)
             17 of 18 parse-url checks passed

Against 1.0.0rc15, one error more, between those two:

    ERROR request profile.pid.credential.0.vct_values.invalid (Credential 0 VCT Values Invalid, Profile)
        issue    Invalid PID credential type. Expected "urn:eudi:pid:de:1"
        field    dcql_query.credentials[0].meta.vct_values
        expected "urn:eudi:pid:de:1"
        actual   urn:eudi:pid:1
        fix      Change vct_values to ["urn:eudi:pid:de:1"]
        spec     EUDI-ARF 3.2
    verdict  valid=False, 28 of 30 request checks passed, 2 error(s), 0 warning(s)

All three are about the German ecosystem rather than the protocol. In ERICA's model a relying
party is registered: its access certificate (the request's `x5c`) is signed by a Registrar on
ERICA's trust list (`src/security/trustlist/registrar.jwt`, one German Registrar certificate),
and its registration certificate travels in the request as `verifier_info` (EUDI ARF 3.2, as
ERICA cites it). `polaris-oid4vp keygen` makes test certificates under its own CA, and the
request carries no `verifier_info`. The German PID is `urn:eudi:pid:de:1`, which the tree can be
asked for and rc15 cannot.

ERICA fetches the request object by GET whatever `request_uri_method` says, which OpenID4VP 1.0
(5.10) allows a wallet that does not support POST, so it sends no wallet nonce.

## ERICA's negative modes

Each mode answered its own request, with the chain made for the run under ERICA's root. ERICA got
the same answer
every time, `HTTP 400 ... "the presentation was not accepted"`; the reason is in the verifier's
log only.

| Mode | What ERICA changes | Refused by | What it said |
|---|---|---|---|
| `EXPIRED` | `exp` a day ago | the verifier | `<- 400 refused: credential_validity: the credential expired 86401 seconds ago (exp), outside the 300 second allowance` |
| `NOT_YET_VALID` | `nbf` a day ahead | the verifier | `<- 400 refused: credential_validity: the credential is not yet valid for another 86400 seconds (nbf), outside the 300 second allowance` |
| `MISSING_SIGNATURE` | the issuer JWT's signature empty | the verifier | `<- 400 refused: issuer_signature: the issuer signature over the credential does not verify under any trusted issuer key` |
| `MISSING_CLAIMS` | the last requested claim (`family_name`) withheld | the verifier | `<- 400 refused: claims: the presentation does not disclose 'family_name', which the request asked for` |
| `WRONG_NONCE` | the key binding JWT's `nonce` | the verifier | `<- 400 refused: nonce: the key binding JWT's nonce is not the one this request asked for, ...` |
| `MISSING_HOLDER_BINDING` | no key binding JWT | the verifier | `<- 400 refused: kb_missing: the presentation carries no key binding JWT, so nothing ties it to the holder who presented it` |
| `WRONG_AUDIENCE` | the key binding JWT's `aud` | the verifier | `<- 400 refused: audience: the key binding JWT's aud is 'wrong-audience' and this verifier is 'x509_hash:...': ...` |
| `WRONG_ISSUER` | `iss` `did:example:wrong-issuer`, signed | the verifier | `<- 400 refused: issuer_key: the credential names issuer 'did:example:wrong-issuer' and the certificate that signed it names 'https://debugger.eudi-wallet-demo.example'` |
| `WRONG_CREDENTIAL_TYPE` | `vct` `urn:eudi:wrong:type` | the verifier | `<- 400 refused: vct: the credential is of type 'urn:eudi:wrong:type' and this request asked for ['urn:eudi:pid:de:1']: ...` |
| `INVALID_SIGNATURE` | would sign with an alternate test key | nothing was sent | ERICA: `Invalid JWK EC key`. The key's `x` and `y` (`src/simulator/TestKeys.ts`) are not a point on P-256, so Node refuses it and ERICA builds no presentation |

`WRONG_ISSUER` and `WRONG_CREDENTIAL_TYPE` are listed as planned in ERICA's README; its API takes
them and its SD-JWT generator applies them. `MODIFIED_CLAIMS`, `FORMAT_MISMATCH` and
`MALFORMED_SD_JWT`, also listed as planned, are not run: at this commit the first has the issuer
sign the altered value, and the other two change nothing in the SD-JWT ERICA builds. A signature
by a wrong key would meet the check `MISSING_SIGNATURE` met, `issuer_signature`.

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts a different issuer CA | the verifier | `<- 400 refused: issuer_key: the x5c leaf does not chain to any configured trust anchor` |
| (b) | The same request presented again after it was answered | the verifier, at the request | ERICA: `Failed to fetch request_uri: HTTP 404` |
| (c) | The launch URI names a `client_id` that is not the signed request's | ERICA | `client_id mismatch: URL has 'x509_hash:AAAA...' but JWT payload has 'x509_hash:...'` |

## Result, 2026-10-04

Against the tree (`6df94c73`, `--vct urn:eudi:pid:de:1`), with ERICA `2c27dc92` on Node 22:

- ERICA's own chain, as shipped: refused,
  `<- 400 refused: issuer_key: x5c certificate 1 is a trust anchor, and HAIP 1.0 6.1.1 keeps the anchor out of x5c`.
- ERICA's PID under its root with the chain made for the run: accepted,
  `<- 200 authentic, claims ['cnf', 'exp', 'family_name', 'given_name', 'iat', 'iss', 'nbf', 'sub', 'vct']`,
  and ERICA reported the post a success, with the verifier's `redirect_uri`.
- ERICA's PID templates: `special-characters` accepted with the verifier asking for its exact
  `given_name` and `family_name` (`Müñez`, `Bjørgßöñ`), and `incomplete-birthdate` accepted
  with the verifier asking for `birthdate` `1994-00-00`, so each value arrived as ERICA signed
  it. The values are read from `src/simulator/PIDTemplateLoader.ts`, which is what ERICA signs:
  the JSON templates beside it are not loaded and differ (`Björgßöñ`), which the verifier's
  value check found.
- The nine negative modes in the table that reach the verifier were refused, each by the check
  its defect names, and the three controls were refused.

Against 1.0.0rc15 from PyPI: ERICA's PID was refused for its type
(`<- 400 refused: vct: the credential is of type 'urn:eudi:pid:de:1' and this request asked for ['urn:eudi:pid:1']: ...`),
and so were the negative modes, most of them by that same check, which rc15 makes before the
validity window and the key binding. The controls were refused as above.

## What this does not establish

- ERICA is a testing tool, not a wallet. Its holder key and its PID are fixed test material
  published in its repository, and its checks are its own: its README calls it a debugging tool,
  not a compliance certification service, and passing its checks is not HAIP conformance.
- The accepted presentation was signed through a chain made for the run under ERICA's root. ERICA
  as shipped is refused, for the reason above, so this shows ERICA's request handling, SD-JWT VC,
  key binding and encryption working with the verifier, and not that ERICA's own chain does.
- ERICA fetched the request object by GET, so this says nothing about the POST path or a wallet
  nonce. It reached the verifier through a forwarder on a Docker network, because of its SSRF
  guard.
- The verifier was asked for `urn:eudi:pid:de:1`, which only the tree can be (`--vct`).
- Same category as the other rows: the author drove a published tool on one machine. It is not
  an outside party using Polaris, and not a claim of interoperability in general.
