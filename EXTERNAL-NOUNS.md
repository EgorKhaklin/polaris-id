# External nouns

Implementations that are not this repository, and what happened when Polaris met them.

A noun earns a row by being a named thing someone else built, run unmodified at a pinned
version, against Polaris code that was not adjusted to flatter it. Everything else in this
tree is Polaris agreeing with Polaris.

---

## walt.id Wallet API v2 → `polaris-oid4vp` (SD-JWT VC over OpenID4VP 1.0)

**Result: the exchange completed. Polaris accepted a presentation built by walt.id.**

| | |
|---|---|
| External implementation | walt.id Wallet API v2, `waltid/wallet-api2:1.0.0` |
| Image digest | `sha256:d2248288f41ceba029a7fd943fed623ef7f0f846edfee666ac6f7e621c4d739e` |
| Release | walt-id/waltid-identity `v1.0.0`, published 2026-08-24 |
| Polaris commit | `375186b` (verifier), fix landed as v9.465 |
| Polaris component | `packages/polaris-oid4vp` 0.1.0 |
| Date | 2026-09-15 |
| Modifications to walt.id | none; stock image, configuration only |

### What was exchanged

    walt.id                                             polaris-oid4vp
      |  POST /request.jwt?state=...  (request_uri_method=post)  |
      |<--- signed request object, ES256, x5c, typ oauth-authz-req+jwt
      |  verifies signature via client_id_prefix=x509_hash       |
      |  against the registered trust anchor                     |
      |  matches the credential with the dcql_query              |
      |  signs a key binding JWT with ITS OWN private key        |
      |  encrypts the response, JWE ECDH-ES (direct_post.jwt)    |
      |  POST /response --------------------------------------->  |
                                                    200 authentic

Polaris verdict, from the verifier's own log:

    <- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'vct']

The key binding JWT is the part that matters. walt.id generated the P-256 key itself
(`keyId dsR9Z6-qkRv8LAr9HquBKIryCj5Z07_nofwhy_Yam_k`), reported only its public half
through `did:jwk`, and signed the presentation with a private key this repository has
never held.

### Negative control

A successful exchange proves nothing on its own: a verifier that accepts everything
produces the same line. Same wallet, same credential, same protocol path, one difference
-- the verifier configured to trust a different issuer key:

    <- 400 refused: issuer_signature: the issuer signature over the credential
       does not verify under the trusted issuer key

walt.id received `{"error":"invalid_request","error_description":"the presentation was
not accepted"}` and nothing more, which is the intended behaviour: the operator's log
carries the cause, the wallet does not.

A second control: re-presenting against an already-answered `state` is refused at the
request stage with `no such outstanding request`. Sessions are single use.

### What Polaris got wrong, and it took an outsider to say so

**`polaris-oid4vp keygen` produced a request-signing leaf certificate with no KeyUsage
extension at all.** walt.id refused it:

    Certificate does not contain client Key Usage 'digitalSignature'

The CA certificate carried `keyCertSign`/`cRLSign`; the leaf carried none. Eleven of
eleven HAIP verifier modules in the OpenID Foundation conformance suite had run clean
against that certificate, and `test_cli.py` asserted four separate properties of the leaf
without asserting this one. A certificate whose only purpose is signing request objects
was not marked as usable for signing.

Classified **EXT-INTEROP, fix Polaris**: RFC 5280 leaves KeyUsage optional, but a leaf
that exists solely to sign should assert `digitalSignature`, and a relying party is
entitled to require it. Fixed in v9.465 with a test that fails on a leaf missing it.

### Incompatibilities found, and how they were classified

| Observation | Classification | Action |
|---|---|---|
| Leaf certificate carried no `digitalSignature` KeyUsage | Polaris defect | fixed, v9.465 |
| `POST /credentials/present/resolve-request` reports `MissingX509TrustAnchors` even when anchors are configured | walt.id: that route is the only one in its file that does not receive `clientIdTrustConfiguration`, while `/present` and `/isolated` both do | documented; no Polaris change. Use `/present` |
| walt.id rejects a self-signed TLS certificate on `request_uri` | neither; test-harness topology | test CA added to the container truststore |
| `x509TrustAnchors` wants PEM, though the type comment says "DERs in base64 format" | walt.id documentation | documented; PEM works |

### What this does NOT establish

One wallet, one credential format, one presentation path. It says nothing about mDL/ISO
18013-5, nothing about any other wallet, and nothing about Polaris's post-quantum path:
this exchange is ES256/P-256 end to end, which is what the HAIP profile pins and what
walt.id implements. No claim is made that `polaris-oid4vp` is interoperable in general.

### Reproducing it

    lab/interop/waltid/issue_sdjwt_vc.py   mints the SD-JWT VC bound to walt.id's key
    lab/interop/waltid/README.md            the exact sequence, including the two controls
