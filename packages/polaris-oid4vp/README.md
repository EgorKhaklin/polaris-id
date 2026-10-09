# polaris-oid4vp

[![PyPI](https://img.shields.io/pypi/v/polaris-oid4vp?include_prereleases&label=PyPI&color=3775a9&labelColor=0a1421&style=flat-square)](https://pypi.org/project/polaris-oid4vp/)
[![OpenID Certified: polaris-oid4vp verifier](https://img.shields.io/badge/OpenID_Certified-polaris--oid4vp_verifier-c9a352?labelColor=0a1421&style=flat-square)](https://github.com/EgorKhaklin/polaris-id/blob/main/docs/reference/SPEC-COMPLIANCE.md#openid-certified)
[![CI](https://img.shields.io/github/actions/workflow/status/EgorKhaklin/polaris-id/ci.yml?branch=main&label=CI&labelColor=0a1421&style=flat-square)](https://github.com/EgorKhaklin/polaris-id/actions/workflows/ci.yml)
[![GitHub stars](https://img.shields.io/github/stars/EgorKhaklin/polaris-id?label=stars&labelColor=0a1421&style=flat-square)](https://github.com/EgorKhaklin/polaris-id)
[![Discord](https://img.shields.io/badge/Discord-join_the_server-5865F2?logo=discord&logoColor=white&labelColor=0a1421&style=flat-square)](https://discord.gg/ragewuCKj)

**An OpenID4VP 1.0 verifier under the High Assurance Interoperability Profile.** It checks a
presentation from a wallet that has never heard of Polaris: an SD-JWT VC signed with ES256, with
holder key binding, delivered over `direct_post.jwt`.

<a href="https://openid.net/certification/certified-oid4vp-haip-final/"><img src="https://raw.githubusercontent.com/EgorKhaklin/polaris-id/main/docs/assets/openid-certified-mark-on-white.png" alt="OpenID Certified" width="160"></a>

**OpenID® Certified™ by Egor Khaklin to the OpenID4VP 1.0 + HAIP 1.0 Verifier profile** at
version 1.0.0rc7, which passed all eleven modules of the Foundation's hosted HAIP verifier test plan
(`sd_jwt_vc`, `direct_post.jwt`; [listing](https://openid.net/certification/certified-oid4vp-haip-final/),
2026-09-24). The certification covers that version in that role. OpenID® and OpenID® Certified™
are trademarks of the OpenID Foundation, used under its [certification terms](https://openid.net/certification/mark/).

**Status:** this release, 1.0.0rc16, is the certified rc7 verifier plus the fixes made since; the
certification names rc7. It is re-run weekly against the outside implementations in the table
below. No operator other than the author has run it and no independent security review exists.
Details: [the scoreboard](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/EXTERNAL-NOUNS.md).

**Try it in ten minutes, without cloning anything:**
[the stranger's path](https://github.com/EgorKhaklin/polaris-id/blob/main/docs/STRANGER-PATH.md)
takes a clean machine with Docker, this package and an unmodified walt.id wallet to an accepted
presentation. If it fails for you, please open an issue.

## Tested against

Outside OpenID4VP implementations present to this verifier, each unmodified unless its row says
otherwise: configuration only (trust anchors, TLS roots). Every walk also sends controls that must be refused, because a
verifier that accepts everything prints the same success line; among them a wrong issuer key
under the same `kid`, the answered request again, a mismatched `client_id`, a key the wallet does
not hold and an untrusted CA. A [weekly canary](https://github.com/EgorKhaklin/polaris-id/blob/main/.github/workflows/wallet-canary.yml) re-runs
the walks against the newest release on PyPI.

| Implementation | Maintained by | Language | Last walk |
|---|---|---|---|
| [walt.id Wallet API v2](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/waltid/README.md) | walt.id | Kotlin | 1.1.1, against 1.0.0rc16 (2026-10-04) |
| [Credo](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/credo/README.md) | OpenWallet Foundation | TypeScript | 0.7.2, against 1.0.0rc14 (2026-10-03) |
| [`eudi-lib-jvm-openid4vp-kt`](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/eudi-kt/README.md), the EUDI Wallet's OpenID4VP library, under a short wallet built for the walk | European Commission | Kotlin | 0.16.2, against 1.0.0rc16 (2026-10-04) |
| [vck](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/vck/README.md) (`vck-openid-ktor`), under a short wallet built for the walk; vck also issued the credential | A-SIT Plus | Kotlin | 8.0.0, against 1.0.0rc16 (2026-10-04) |
| [`eudi-lib-ios-openid4vp-swift`](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/eudi-ios/README.md), the EUDI Wallet's iOS OpenID4VP library, under a short wallet built for the walk | European Commission | Swift | 0.43.2, against 1.0.0rc16 (2026-10-04) |
| [irmago](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/irmago/README.md), the library under the Yivi wallet, under a short wallet built for the walk | Privacy by Design Foundation (Yivi) | Go | v1.4.0, against 1.0.0rc16 (2026-10-04) |
| [SpruceID `openid4vp`](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/spruceid/README.md), its conformance adapter with the test issuer replaced | SpruceID | Rust | e5f29b85, against 1.0.0rc16 (2026-10-04) |
| [Procivis One Core](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/procivis/README.md) (`core-server`), which also issued the credential | Procivis | Rust | v1.87.2, against 1.0.0rc16 (2026-10-04) |
| [ProtocolSoup](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/protocolsoup/README.md), its wallet harness (listed as certified) | ParleSec | Go | v4.0.0, against 1.0.0rc16 (2026-10-04) |
| [The EU reference PID issuer](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/eudi-issuer/README.md) (`eudi-srv-pid-issuer`), issuing to a wallet built on the EU's libraries | European Commission | Kotlin | v0.11.1, against 1.0.0rc16 (2026-10-04) |
| [Credo on a cheqd ledger](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/cheqd/README.md), the issuer a `did:cheqd` with its status list on the ledger | cheqd, OpenWallet Foundation | TypeScript, Go | cheqd-node 4.2.1 and Credo 0.7.2, against 1.0.0rc15 (2026-10-04) |
| [Multipaz](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/multipaz/README.md), under a short wallet built for the walk | OpenWallet Foundation | Kotlin | 0.101.0, against 1.0.0rc16 (2026-10-04) |
| [ERICA](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/erica/README.md), the German EUDI Wallet programme's verifier testing tool, with its negative modes | the German EUDI Wallet programme (opencode.de) | TypeScript | 2c27dc92, against the tree (2026-10-04) |
| [eudi-dev](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/eudi-dev/README.md), HAIP strict mode with its TLS check on | dominikschlosser | Go | v2.5.1, against 1.0.0rc15 (2026-10-04) |
| [OID4VCgo](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/oid4vcgo/README.md) | IDFoundry | Go | 0.25.0, against 1.0.0rc14 (2026-10-03) |
| [The OpenID Foundation's conformance suite](https://github.com/EgorKhaklin/polaris-id/blob/main/docs/reference/SPEC-COMPLIANCE.md#openid-certified) | OpenID Foundation | Java | eleven of eleven HAIP verifier modules clean against 1.0.0rc15, both controls noticed (2026-10-04); 1.0.0rc7 certified (2026-09-24) |

The author drove every walk: interoperability with those implementations, not use by their
maintainers. Each walk is one script you can run against your own copy; to test your wallet,
point it at `polaris-oid4vp serve` as below. The weekly canary last walked every row above
against 1.0.0rc16 from PyPI on 2026-10-06, and every walk passed
([run 37460790872](https://github.com/EgorKhaklin/polaris-id/actions/runs/37460790872)).

## Install and run

```bash
pip install --pre polaris-oid4vp
polaris-oid4vp keygen --out ./pki --host verifier.example
polaris-oid4vp serve  --pki ./pki --port 9443 --issuer-jwks issuers.json
```

- `keygen` makes a CA, a leaf it signs and a listener certificate, and prints the `client_id`
  and the anchor a counterparty registers. The profile rejects a self-signed leaf and a trust
  anchor inside the chain; `keygen` avoids both. The CA and the leaf carry the key identifiers
  RFC 5280 asks for, which some wallets find a CA by. The listener certificate is marked for server
  authentication, which Apple's TLS policy requires even of a certificate a client trusts by
  name. Its keys are for testing.
- A wallet that fetches the request object by POST and asks for it encrypted (its
  `wallet_metadata` lists `ECDH-ES` in `request_object_encryption_alg_values_supported`, an
  `enc` this package produces, A128GCM or A256GCM, and a P-256 key in `jwks`) gets the signed
  object encrypted to that key, as the EUDI iOS wallet kit requires. A wallet that asks for
  nothing, or for something this cannot produce, gets the signed object.
- `--verifier-info FILE` puts attestations about the verifier into the request object, such as
  the registration certificate a registrar issues: a JSON array as OpenID4VP 1.0 section 5.1 has
  it, or one object, `{"format": "registration_cert", "data": "<JWT>"}`, as the German EUDI
  Wallet guide and its testing tool read it. The German ecosystem requires one for a PID request.
  This package carries it as given and does not check it.
- `serve --issuer-trust-anchor ca.pem` trusts an issuer that signs with its certificate in `x5c`,
  as HAIP issuers do (repeatable; each file may hold several PEM certificates). The leaf must
  chain to an anchor, directly or through the CA certificates the `x5c` sends after it (at most
  three, in order, each certifying the one before it; each a CA allowed to sign certificates,
  inside its validity period and its path length, with no critical extension this does not
  read, and none of them the anchor itself). The leaf must be inside its validity period and,
  when it states a key usage, include digitalSignature; one that states extended key usages must name one an
  issuer may hold (ISO 18013-5's document signer, as EUDI issuers use, or client auth, code
  signing or email protection). A leaf that states no key usage is not restricted by one. An `iss` must be
  a name the leaf gives: a URI subjectAltName exactly, or, for a leaf naming only DNS hosts, an
  https URL on one. Without `iss`, the certificate's subject is the issuer.
- `--issuer-jwks` trusts every key it lists for every `iss`, except one whose `use`, `key_ops` or `alg`
  says it is not for ES256 signatures; list one issuer's keys per verifier.
- `--public-base-url https://verifier.example` sets the HTTPS origin a wallet reaches this
  verifier by when it runs behind a reverse proxy or a tunnel, where the public URL differs
  from the local `--bind`/`--port`. It is used for the `request_uri` and `response_uri`;
  without it they are `https://<--host>:<--port>`.
- `--no-local-tls` serves the local listener over plain HTTP, for when that proxy or tunnel
  terminates TLS and provides the public HTTPS. The listener still binds `--bind` (localhost by
  default); pair it with `--public-base-url`, which is then the HTTPS `request_uri` a wallet uses.
- `--claim` names a claim to ask for (repeatable; without it, `given_name` and `family_name`): a
  name, a dotted path of object keys, or a JSON array of keys, optionally `=VALUE` (JSON) for
  the value it must have. A path asks for one member of a nested claim and nothing around it:
  `--claim age_equal_or_over.18=true` asks an EUDI PID whether its holder is 18 or over and
  nothing else, where `--claim age_equal_or_over` would ask for every age statement it holds.
  A presentation that withholds a claim, or discloses it with another value or type (`1` is
  not `true`), is refused (`claims`). Array indices are not accepted: an undisclosed element is
  left out of the disclosed claims, so a position counted afterwards is not the one the issuer
  signed. `--vct` (repeatable) names the credential types to accept; without it,
  `urn:eudi:pid:1`. `Verifier(claims=..., vct_values=...)` takes the same, a claim as a name, a
  list of keys, or `{"path": [...], "values": [...]}`.
- `serve` with neither `--issuer-jwks` nor `--issuer-trust-anchor` refuses every presentation
  (`issuer_key`) and says so on stderr. An `--issuer-jwks` file it cannot read, or none of whose keys
  can verify ES256 when no anchor is given, stops `serve` before it listens (exit 2).
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
| `kb_freshness` | a key-binding `iat` outside the window, or an `exp` or `nbf` it carries that has passed or not arrived |
| `claims` | (`Verifier`) a presentation that withholds a claim the request asked for, discloses it with a value the request does not accept, or discloses a selectively disclosable claim the request did not select (OpenID4VP 1.0 section 6.4) |
| `revoked` | (`Verifier`) a credential whose checked status value is not VALID (0) |
| `credential_validity` | a credential past its `exp` or before its `nbf` |
| `vct` | a credential of a type the query did not ask for |
| `issuer_typ` | an issuer JWT not typed `dc+sd-jwt`, a W3C VC Data Model `vc+sd-jwt` credential among them |
| `disclosure` | a disclosure of a claim that must be signed (`iss`, `exp`, `cnf`, ...), a colliding claim, a digest the credential commits to twice, or nesting past the depth cap |
| `issuer_key` | an untrusted key, an x5c leaf outside its validity, not marked for signing, self-signed or a CA, or one that does not name the credential's `iss` |
| `crit` | an issuer JWT, key-binding JWT or status list token whose `crit` names an extension; none is implemented |
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

`verdict.revocation` is one of seven states:

| State | Meaning |
|---|---|
| `no_status_claim` | the credential names no status list |
| `not_evaluated` | it names one and no resolver was supplied |
| `unsupported_status` | its status claim is in a form this verifier cannot read |
| `checked` | a resolver answered; `status` carries the issuer's value |
| `unreachable` | a resolver was asked and got no answer |
| `no_authority` | no key is stated as entitled to publish this issuer's status at that URI, so no list can count as evidence |
| `list_refused` | the status reference, the list or its signature failed a check, so nothing is usable as evidence; `code` says which |

- **A checked status that is not VALID is refused:** with a resolver, `Verifier` answers a
  credential whose status list value is not 0 with the same 400 as any refusal (`revoked`).
  The other states are not facts about the credential and stay in the verdict for your policy.
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

The wallet canary runs the drill weekly against the newest release on PyPI, with the suite's
prebuilt images at their newest (`POLARIS_OID4VP_INSTALLED=1` makes it import the installed
package instead of the tree). A run is not a certification.

## Tests

```bash
cd packages/polaris-oid4vp && python3 -m unittest test_sdjwt test_jwe test_verifier \
    test_serve test_cli test_conformance_capture test_status
```

- 422 tests in seven files. `test_conformance_capture` replays a real `direct_post.jwt` response built by the
  OpenID Foundation suite's wallet (Nimbus JOSE), so this package's ECDH-ES, KDF, AAD binding and
  digests are checked against an independent implementation.
- `scripts/polaris-oid4vp-mutation-drill.py` makes each of the 120 refusals accept and requires a
  test to fail: 116 are caught, and the 4 survivors are declared with their reasons (measured
  2026-10-01, after the day's review fixes; CI runs it on every push).
- Held-out boundary mutations (off-by-one windows, header binding, listener routing) each have a
  dedicated test class.
