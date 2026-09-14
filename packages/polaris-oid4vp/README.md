# polaris-oid4vp

**An OpenID4VP 1.0 verifier under the High Assurance Interoperability Profile.** It checks a
presentation produced by a wallet that has never heard of Polaris: an SD-JWT VC signed with
ES256, with holder key binding, delivered over `direct_post.jwt`.

**Status: 0.1.0, and the transport half is not built yet.** What exists is the half that
decides. Nothing here has been certified, and no external party has used it.

---

## Why this is a separate package

`polaris-verify` promises that it opens no socket. That promise is externally stated, it is
enforced by a check in the tree, and it is worth keeping: a verifier you can run on a machine
with no network is a different and better thing than one you cannot. This needs to listen, so
it lives somewhere else rather than quietly making that promise false.

It also carries a hard dependency on `cryptography`, where `polaris-verify` deliberately
carries none. Both facts point the same way.

---

## Why it exists at all

Under the go-forward operating contract the unit of progress is a surviving external
dependency, and the first named interoperability target is an OpenID4VP 1.0 + HAIP verifier.
The OpenID Foundation's conformance suite has a test plan for exactly that role,
`oid4vp-1final-verifier-haip-test-plan`, and in it **the suite signs the credential**, so
Polaris's own ML-DSA-65 issuance is not involved. The measurement that established this, along
with the plan's contents and a run that gets every automated condition green, is in
[`lab/interop/`](../../lab/interop/).

Eleven modules apply to SD-JWT VC. **Seven are negative**: the wallet sends a presentation
broken in one specific way and the verifier has to refuse it. Those seven are scored
automatically on a 4xx, with no human in the loop, which makes them the closest thing to an
external adversary this project has been offered.

## What is here

[`polaris_oid4vp/sdjwt.py`](polaris_oid4vp/sdjwt.py) verifies an SD-JWT VC presentation and
returns a verdict. It touches no socket and reads no configuration: it is given the
presentation, the nonce and audience the request asked for, and the keys the issuer is trusted
under. Each of the seven conformance refusals has its own reason code:

| Conformance module | Refusal code |
|---|---|
| `invalid-credential-signature` | `issuer_signature` |
| `invalid-sd-hash` | `sd_hash` |
| `invalid-kb-jwt-signature` | `kb_signature` |
| `invalid-kb-jwt-nonce` | `nonce` |
| `invalid-kb-jwt-aud` | `audience` |
| `kb-jwt-iat-in-past` | `kb_freshness` |
| `kb-jwt-iat-in-future` | `kb_freshness` |

```python
from polaris_oid4vp.sdjwt import verify_presentation

verdict = verify_presentation(
    presentation,                     # the ~-separated string the wallet sent
    expected_nonce=request_nonce,     # what YOUR request asked for, not what it claims
    expected_audience=client_id,
    trust_anchors=[anchor],           # or issuer_jwks=[...]
)
verdict.authentic, verdict.code, verdict.reason, verdict.claims
```

`expected_nonce` and `expected_audience` are required and are refused if empty. A verifier
that reads them out of the presentation it is checking has made two of those seven tests pass
by not performing them, and has made every presentation replayable.

[`polaris_oid4vp/jwe.py`](polaris_oid4vp/jwe.py) opens the response. HAIP pins
`direct_post.jwt`, so the `vp_token` arrives as a JWE encrypted to a key the verifier
published in `client_metadata.jwks`, and it has to be decrypted before there is anything to
check. ECDH-ES direct key agreement over P-256 with A128GCM or A256GCM, and **nothing else**:
`alg` and `enc` arrive in an attacker-controlled header, so a short list and a refusal for
everything outside it is the useful thing for a verifier to have.

## What is not here yet

The listener: serving the signed request object at a `request_uri`, accepting the wallet's
POST, and answering 200 or 4xx. [`lab/interop/probe.py`](../../lab/interop/probe.py) has
driven that whole exchange against the conformance suite and gets every automated condition
green, so the shape is known. It is not implemented here, and until it is, the seven negative
modules cannot be run: refusing one of them IS an HTTP 4xx.

## Tests

```bash
cd packages/polaris-oid4vp && python3 -m unittest test_sdjwt test_jwe test_conformance_capture
```

46 tests in three files, and they are not equal in weight.

`test_sdjwt` (23) and `test_jwe` (14) are this package agreeing with itself: the material is
built here and checked here. Each carries a positive control, because a verifier that refuses
everything passes every refusal test ever written, and both directions were checked by
patching the verifier rather than assumed. A verifier that always accepts fails 19 of the 23;
one that always refuses fails 4.

`test_conformance_capture` (9) is the one that is evidence of something. It holds a real
`direct_post.jwt` response produced by the **OpenID Foundation conformance suite's wallet**,
committed as a fixture so it runs with no Docker and no network. The JWE was built by Nimbus
JOSE in Java and the SD-JWT by the suite's own code: if this package's ECDH-ES, its Concat
KDF, its AAD binding or its disclosure digests were subtly wrong, it would not open. It opens,
and the presentation inside verifies, disclosing exactly the two claims the DCQL query asked
for out of the eleven the credential commits to.

The same fixture proves the refusals: a year later it is stale, under another nonce or
another audience it is not ours, with `given_name` rewritten from Jean to Jeanne the digest no
longer matches what the issuer signed.

**None of that is a conformance result.** The suite ran locally, nothing was scored or
published, and `lab/EXTERNAL-NOUNS.md` stays at zero.
