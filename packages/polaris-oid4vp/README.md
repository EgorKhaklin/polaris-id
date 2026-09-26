# polaris-oid4vp

**An OpenID4VP 1.0 verifier under the High Assurance Interoperability Profile.** It checks a
presentation from a wallet that has never heard of Polaris: an SD-JWT VC signed with ES256, with
holder key binding, delivered over `direct_post.jwt`.

<a href="https://openid.net/certification/certified-oid4vp-haip-final/"><img src="https://raw.githubusercontent.com/EgorKhaklin/polaris-id/main/docs/assets/openid-certified-mark-on-white.png" alt="OpenID Certified" width="160"></a>

**OpenID Certified™ by Egor Khaklin to the OpenID4VP 1.0 + HAIP 1.0 Verifier profile.**
`polaris-oid4vp 1.0.0rc7` finished all eleven modules of the Foundation's hosted
`oid4vp-1final-verifier-haip-test-plan` (`sd_jwt_vc`, `direct_post.jwt`) without failure, and the OpenID
Foundation [lists the certification](https://openid.net/certification/certified-oid4vp-haip-final/)
(2026-09-24). It covers that version in that role: not an endorsement, not an audit, and not
other versions.

**Status:** a release candidate. Outside results: the Foundation's hosted suite (0.1.0, then
1.0.0rc7 for certification) and one unmodified external wallet, walt.id Wallet API v2 (last
against 1.0.0-rc.3). No operator other than the author has run it and no independent security
review exists. Details: [the scoreboard](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/EXTERNAL-NOUNS.md).

**Try it in ten minutes, without cloning anything:**
[the stranger's path](https://github.com/EgorKhaklin/polaris-id/blob/main/docs/STRANGER-PATH.md)
takes a clean machine with Docker, this package and an unmodified walt.id wallet to an accepted
presentation. If it fails for you, please open an issue.

## Install and run

```bash
pip install --pre polaris-oid4vp
polaris-oid4vp keygen --out ./pki --host verifier.example
polaris-oid4vp serve  --pki ./pki --port 9443 --issuer-jwks issuers.json
```

- `keygen` makes a CA, a leaf it signs and a listener certificate, and prints the `client_id`
  and the anchor a counterparty registers. The profile rejects a self-signed leaf and a trust
  anchor inside the chain; `keygen` avoids both. Its keys are for testing.
- `serve` with no `--issuer-jwks` refuses every presentation (`issuer_key`) and says so on stderr.
- The CLI is a test harness. A deployment embeds `Verifier` (it needs your status policy; see
  Revocation).

This is a separate package from `polaris-verify` because it listens on a socket and depends on
`cryptography`; `polaris-verify` does neither.

## Verifying a presentation

```python
from polaris_oid4vp.sdjwt import verify_presentation

verdict = verify_presentation(
    presentation,                     # the ~-separated string the wallet sent
    expected_nonce=request_nonce,     # what YOUR request asked for
    expected_audience=client_id,
    trust_anchors=[anchor],           # or issuer_jwks=[...]
    expected_vct="urn:eudi:pid:1",    # the credential type you asked for
)
verdict.authentic, verdict.code, verdict.reason, verdict.claims
```

`expected_nonce` and `expected_audience` are required: reading them from the presentation would
make every presentation replayable. `sdjwt.py` touches no socket and reads no configuration.

| Refusal code | Refuses |
|---|---|
| `issuer_signature` | an issuer signature that does not verify |
| `sd_hash` | a key-binding JWT not bound to this presentation |
| `kb_signature` | a key-binding signature that does not verify |
| `nonce`, `audience` | a key-binding JWT for another request or verifier |
| `kb_freshness` | a key-binding `iat` outside the window |
| `credential_validity` | a credential past its `exp` or before its `nbf` |
| `vct` | a credential of a type the query did not ask for |
| `disclosure` | a disclosure of a claim that must be signed (`iss`, `exp`, `cnf`, ...), a colliding claim, or nesting past the depth cap |
| `issuer_key` | an untrusted key, or an x5c leaf outside its validity or not marked for signing |
| `malformed` | over 256 KiB, JSON over 64 KiB or 64 levels, or non-finite numbers |

Recursive disclosures (SD-JWT 4.2.4.1) are supported.

**Refusal codes are for the operator and never go on the wire.** Every refused presentation gets
one constant body, so the verifier is not a per-check oracle:

```json
{"error": "invalid_request", "error_description": "the presentation was not accepted"}
```

**Open:** response timing still differs by which check refused; this is not measured.

The response JWE (`jwe.py`) accepts only ECDH-ES over P-256 with A128GCM or A256GCM, with a
fresh encryption key per request. The listener (`verifier.py`, `serve.py`) is standard library
only.

## Revocation

`verdict.revocation` is one of five states:

| State | Meaning |
|---|---|
| `no_status_claim` | the credential names no status list |
| `not_evaluated` | it names one and no resolver was supplied |
| `unsupported_status` | its status claim is in a form this verifier cannot read |
| `checked` | a resolver answered; `status` carries the issuer's value |
| `unreachable` | a resolver was asked and got no answer |

- **Opt-in:** pass `status_resolver=` to `Verifier(...)` or `verify_presentation`. Without one
  nothing is fetched and the state is `not_evaluated`.
- `status.py` decides a Token Status List (`draft-ietf-oauth-status-list`) without opening a
  socket; `decide_by_fetching` takes your `fetch` callable.
- **Who may publish status for whom is stated, not inferred:** `StatedAuthority` records that a
  named key may publish for a named issuer at a named URI. Anything else is `no_authority`, and
  no request is sent to a URI an unvetted credential names.

## Conformance run

```bash
git clone --depth 1 https://gitlab.com/openid/conformance-suite.git
cd conformance-suite && docker compose -f docker-compose-prebuilt.yml up -d
python3 scripts/polaris-oid4vp-conformance-drill.py
```

Seven negative modules PASS; four positive modules end in REVIEW (the suite wants a screenshot
of a displayed result). The drill carries two negative controls: a verifier that refuses
everything must fail the positive modules, and one that accepts everything must fail all seven
negative ones.

## Tests

```bash
cd packages/polaris-oid4vp && python3 -m unittest test_sdjwt test_jwe test_verifier \
    test_serve test_cli test_conformance_capture test_status
```

- 303 tests in seven files. `test_conformance_capture` replays a real `direct_post.jwt` response built by the
  OpenID Foundation suite's wallet (Nimbus JOSE), so this package's ECDH-ES, KDF, AAD binding and
  digests are checked against an independent implementation.
- `scripts/polaris-oid4vp-mutation-drill.py` makes each of the 103 refusals accept and requires a
  test to fail: 97 are caught, and the 6 survivors are declared with their reasons.
- Held-out boundary mutations (off-by-one windows, header binding, listener routing) each have a
  dedicated test class.
