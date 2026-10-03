# Credo (holder) → polaris-oid4vp

An unmodified Credo agent, the OpenWallet Foundation's TypeScript framework, acting as the
holder, presents an SD-JWT VC over OpenID4VP 1.0 `direct_post.jwt` to `polaris-oid4vp` as
installed from PyPI. It has the same shape as [`../waltid/`](../waltid/README.md): the wallet
generates its own key, a credential is minted bound to that key, the wallet registers the
verifier's CA, and the wallet's own code builds and sends the presentation.

**Result, 2026-09-27: accepted.** `polaris-oid4vp` printed

    <- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']

for a presentation that Credo's `acceptOpenId4VpAuthorizationRequest` built, encrypted and
POSTed. Credo got back `200 {"redirect_uri": "https://localhost:9543/done"}`. All four
negative controls were refused (see below). Neither side needed a change: Polaris is the
PyPI release, and Credo runs from the npm tarballs with nothing patched.

## Versions

| | |
|---|---|
| Wallet | `@credo-ts/core` 0.6.3, `@credo-ts/openid4vc` 0.6.3, `@credo-ts/node` 0.6.3 |
| OpenID4VP library underneath | `@openid4vc/openid4vp` 0.4.6, `@openid4vc/oauth2` 0.4.6, `@sd-jwt/core` 0.19.0 |
| Verifier | `polaris-oid4vp` 1.0.0rc7 from PyPI (`pip install --pre polaris-oid4vp`), with `cryptography` 50.0.1 |
| Runtime | Node v24.11.1 (it runs `.ts` natively; no transpiler), Python 3.12.13, macOS (Darwin 25.3.0) |

`package.json` pins the three Credo packages exactly and `package-lock.json` pins the rest.
Credo 0.6.3 is the newest 0.6.x. 0.7.1 was already on npm on this date and was **not** tried. 0.7.2 was walked on
2026-10-03 ([Credo 0.7.2](#credo-072-2026-10-03)).

## Reproduce

    cd lab/interop/credo
    npm ci                                     # installs only into ./node_modules
    python3.12 -m venv /tmp/p && /tmp/p/bin/pip install --pre polaris-oid4vp
    PATH=/tmp/p/bin:$PATH PYTHON=/tmp/p/bin/python npm run present

Credo needs no native module in this configuration (no Askar), so `npm ci` has nothing to
build. The command exits 0 and prints `RESULT: ACCEPTED by polaris-oid4vp` only if the
verifier's first verdict line is `<- 200 authentic`. The four controls:

    for c in wrong-issuer foreign-holder replay untrusted-verifier; do
      CONTROL=$c PATH=/tmp/p/bin:$PATH PYTHON=/tmp/p/bin/python npm run present
    done

Each control exits 0 only when the side that should refuse did refuse. `PORT` (default 9543)
moves the verifier. `npm run typecheck` runs `tsc --strict` over both files.

## Credo 0.7.2 (2026-10-03)

Credo 0.7 names an SD-JWT VC issuer only by DID or by certificate. Storing the walk's credential,
signed under a bare `kid`, throws
`SdJwtVcError: Unsupported signing method for SD-JWT VC. Only did and x5c are supported at the moment.`
So from 0.7 `present.ts` issues under a certificate in `x5c` (`issue_sdjwt_vc.py --x5c`: a CA made
for the run, and a leaf for the issuer key that names the `iss` URL). Credo trusts that CA
(X509 trusted certificates); the verifier trusts it with `--issuer-trust-anchor`; and the
`wrong-issuer` control has the verifier trust an unrelated CA. The walk reads Credo's version from
`node_modules`, so 0.6.3 keeps the recorded `kid` and JWKS path.

| Run | Result against `polaris-oid4vp` 1.0.0rc14 from PyPI |
|---|---|
| positive | accepted: `<- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']` |
| `wrong-issuer` | refused by the verifier: `issuer_key: the x5c leaf does not chain to any configured trust anchor` |
| `foreign-holder` | refused by the verifier: `kb_signature` |
| `replay` | the first POST accepted, the identical second one refused |
| `untrusted-verifier` | refused by Credo: `No trusted certificate was found while validating the X.509 chain` |

Versions: `@credo-ts/core`, `@credo-ts/openid4vc` and `@credo-ts/node` 0.7.2, `@openid4vc/openid4vp`
and `@openid4vc/oauth2` 0.6.0, `@sd-jwt/core` 0.21.1, Node v24.11.1. The runs are recorded in
[`evidence/credo-0.7.2/`](evidence/credo-0.7.2/). The pins stay at 0.6.3: the OpenID4VCI receive
scripts were recorded on it and were not re-run on 0.7.2 (they typecheck under both). To repeat:

    npm ci && npm install --no-save @credo-ts/core@0.7.2 @credo-ts/node@0.7.2 @credo-ts/openid4vc@0.7.2
    EVIDENCE_DIR=evidence/credo-0.7.2 PATH=/tmp/p/bin:$PATH PYTHON=/tmp/p/bin/python npm run present
    npm ci                                     # back to the pinned 0.6.3

## What `present.ts` does

1. `polaris-oid4vp keygen --out run/pki --host localhost --port 9543`.
2. Starts an in-memory Credo agent. Credo's `NodeKeyManagementService` creates a P-256 key
   with `agent.kms.createKey`, so the private half exists only inside Credo's KMS.
3. Mints the credential by running [`../waltid/issue_sdjwt_vc.py`](../waltid/issue_sdjwt_vc.py)
   unchanged, with Credo's public JWK as `cnf.jwk` (`typ: dc+sd-jwt`, `vct: urn:eudi:pid:1`,
   `given_name` and `family_name` selectively disclosable). Credo stores it through
   `agent.sdJwtVc.store` as an `SdJwtVcRecord` whose `kmsKeyId` names the key from step 2.
4. Runs `polaris-oid4vp serve --once` with that issuer's JWKS and turns the printed
   `client_id`, `request_uri` and `request_uri_method` into `openid4vp://authorize?...`.
5. `agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(url)`: Credo fetches the
   request object, checks the `x509_hash` client id against the `x5c` leaf, validates the leaf
   to the registered CA, and runs the DCQL query against its store (`can_be_satisfied: true`).
   Then `selectCredentialsForDcqlRequest` and `acceptOpenId4VpAuthorizationRequest`. Credo
   produces the KB-JWT (`aud` = the `x509_hash:` client id, `nonce` = the request nonce,
   `sd_hash`), the `vp_token` `{"pid": ["<sd-jwt>~<disclosures>~<kb-jwt>"]}`, the
   ECDH-ES/A128GCM JWE to the key in `client_metadata.jwks`, and the `direct_post.jwt` POST.
6. Stops the verifier and writes `evidence/<run>/`.

### Configuration, all of it through public API

The only settings the exchange needed. None of them is a workaround, and none reaches into
Credo's internals.

* **Storage.** Credo 0.6 ships no in-memory storage, and `new Agent` refuses to start without
  one. Its error names the options: "the AskarModule, DrizzleStorageModule, or implement your
  own". Askar needs a native library fetched by an install script, so
  [`MemoryStorageService.ts`](MemoryStorageService.ts) implements Credo's exported
  `StorageService` interface (a Map plus tag matching). Because an empty store has no
  storage-version record, which Credo reads as version 0.1, the agent runs with
  `autoUpdateStorageOnStartup: true`. Migrating an empty store changes nothing.
* **The request-object trust anchor.** `new X509Module({ trustedCertificates: [anchor.pem] })`
  registers the CA, not the leaf. This is the registration `keygen` tells a counterparty to
  do, and it is the counterpart of walt.id's `clientIdTrust.x509TrustAnchors`. Credo takes the
  PEM as it stands.
* **TLS.** The listener's certificate is self-signed, and Node is right to refuse it. The
  script re-executes itself with `NODE_EXTRA_CA_CERTS=run/pki/tls.pem`, the Node equivalent of
  walt.id's `keytool -importcert`.
* **A logging `fetch`.** The agent's `fetch` dependency is a pass-through that records each
  request and response into `wire.json`. It changes nothing about the requests.

## The controls

A verifier that accepts everything prints the same success line, so the positive run means
something only because these fail. They use the same wallet, the same code path and the same
kind of credential.

| `CONTROL=` | What changes | Who must refuse | What happened |
|---|---|---|---|
| `wrong-issuer` | The verifier trusts a different P-256 key under the same `kid` | verifier | `<- 400 refused: issuer_signature`. Credo was told only `the presentation was not accepted` |
| `foreign-holder` | `cnf.jwk` is a key generated outside Credo. The record's `kmsKeyId` still names Credo's key, so Credo signs the KB-JWT with a key that does not match `cnf` | verifier | `<- 400 refused: kb_signature` |
| `replay` | After the accepted run, Credo's exact JWE is POSTed a second time | verifier | first `<- 200 authentic`, second `<- 400 refused: invalid_request: the response did not decrypt under any outstanding request's key` |
| `untrusted-verifier` | Credo's `X509Module` trusts a CA from a second, unrelated `keygen` | Credo | `resolveOpenId4VpAuthorizationRequest` throws `No trusted certificate was found while validating the X.509 chain` (Credo's `X509Service.validateCertificateChain`). No response is ever POSTed |

`foreign-holder` shows that the verifier's acceptance depends on a signature by the key Credo
holds. `untrusted-verifier` shows that the anchor registration is load-bearing on the wallet
side: Credo does not accept the `x5c` chain on its own authority.

## Observations (neither side is at fault)

These are not failures. They are recorded because they set the boundaries of what this run
exercised.

1. **`request_uri_method=post` with an empty body.** Credo honours `post`, but it sends
   neither `wallet_metadata` nor `wallet_nonce`. The body is empty; see `wire.json`, request 1.
   OpenID4VP 1.0 Section 5.10 makes both parameters optional for the wallet, so this is
   conformant. It also means Polaris's `wallet_nonce` echo (`request_object(...,
   wallet_nonce=)`) was **not** exercised by this run.
2. **`apu` and `apv` in the response JWE header.** Credo sets `apu` to a fresh wallet nonce and
   `apv` to the request nonce, both base64url-encoded (ECDH-ES `PartyUInfo` and `PartyVInfo`,
   RFC 7518 Section 4.6.1). OpenID4VP 1.0 does not require them, and RFC 7518 permits them.
   Polaris derived the same key: the Concat KDF input includes them, and the response
   decrypted. The conformance-suite capture in `testdata/` has the same header fields, so
   this adds a second independent JWE producer (Credo's KMS, not Nimbus) that agrees with
   `jwe.py` on them.
3. **Credo picks `A128GCM`** from the verifier's `encrypted_response_enc_values_supported:
   ["A128GCM", "A256GCM"]`. A256GCM was not exercised by this run.
4. **Credo does not check `kmsKeyId` against `cnf.jwk` when it presents** (the
   `foreign-holder` control). It signs with the key the record names and lets the verifier
   refuse. This is a holder-side convenience, not a protocol deviation. It is recorded only
   because it is what made that control possible to build without touching Credo.

## What this does and does not show

It shows that one unmodified, independently written wallet framework, at the versions above,
can complete an OpenID4VP 1.0 `direct_post.jwt` presentation of an SD-JWT VC against
`polaris-oid4vp` 1.0.0rc7 as published, with Polaris's `x509_hash` client id and
per-request encryption key, and that the four controls fail as they must.

It does not show:

* **An independent operator.** The glue script (`present.ts`) and the issuer
  (`issue_sdjwt_vc.py`) are this repository's, and one person ran both sides on one machine
  over `localhost`. Credo's code made every protocol decision on the wallet side, but nobody
  outside ran it.
* **An independent issuer, or x5c issuer trust.** The verifier trusts the issuer through
  `--issuer-jwks`, as in the walt.id run.
* **Anything about Credo 0.7.x**, a mobile Credo wallet built on it, `dc_api`, mdoc,
  presentation-definition requests, transaction data, or `request_uri_method=get`.

## Files

| File | |
|---|---|
| `package.json`, `package-lock.json` | exact Credo pins, `npm run present`, `npm run typecheck` |
| `present.ts` | the harness |
| `MemoryStorageService.ts` | Credo's `StorageService` interface, in memory |
| `evidence/<run>/verifier.log` | everything `polaris-oid4vp serve --verbose` printed |
| `evidence/<run>/wallet.log` | the harness's timestamped log of Credo's side |
| `evidence/<run>/wire.json` | every HTTP request Credo made and every response it received |
| `evidence/<run>/resolved-request.json` | the request object as Credo verified it, and its DCQL match |
| `evidence/<run>/outcome.json` | versions, the `openid4vp://` URL, what Credo returned or threw, the verifier's verdict, and the pre-encryption `vp_token` |
| `run/` (ignored) | this run's test keys and credential, regenerated every time |
