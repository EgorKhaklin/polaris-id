# polaris-oid4vp

[![PyPI](https://img.shields.io/pypi/v/polaris-oid4vp?include_prereleases&label=PyPI&color=3775a9&labelColor=0a1421&style=flat-square)](https://pypi.org/project/polaris-oid4vp/)
[![Status: pre-pilot](https://img.shields.io/badge/status-pre--pilot-9a6b2f?labelColor=0a1421&style=flat-square)](https://github.com/EgorKhaklin/polaris-id/blob/main/docs/PRODUCTION-READINESS.md)
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

**Status:** This release, 1.0.0, builds on 1.0.0rc7, the certified version, with the fixes and additions made since.
The newest release runs against the OpenID Foundation's conformance suite every week in CI. It is re-run weekly against the outside implementations in the table
below. One outside project, IDFoundry/OID4VCgo, runs it in its CI, daily and on each of its
releases, since 2026-10-11; no relying party uses it, Polaris has never held real identity data,
and no independent security review exists ([readiness](https://github.com/EgorKhaklin/polaris-id/blob/main/docs/PRODUCTION-READINESS.md)).
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

The author drove every walk but one, which OID4VCgo's CI runs itself: interoperability with
those implementations, not use by their maintainers. Each walk is one script you can run against your own copy; to test your wallet,
point it at `polaris-oid4vp serve` as below. The "Last walk" column records the walks driven
by hand. The weekly canary last walked every implementation in the table, at pinned and latest
builds, against 1.0.0rc16 installed from PyPI on 2026-10-06, and every walk passed
([run 37460790872](https://github.com/EgorKhaklin/polaris-id/actions/runs/37460790872)).

## Install and run

```bash
pip install polaris-oid4vp
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
  This package carries it as given, checking the shape section 5.1 asks for; a registration
  certificate labelled with its own media type is refused. `--verifier-info-profile
  etsi-119472-2` holds it to ETSI TS 119 472-2 (below).
- `serve --issuer-trust-anchor ca.pem` trusts an issuer that signs with its certificate in `x5c`,
  as HAIP issuers do (repeatable; each file may hold several PEM certificates). The leaf must
  chain to an anchor, directly or through the CA certificates the `x5c` sends after it (at most
  three, in order, each certifying the one before it; each a CA allowed to sign certificates,
  inside its validity period and its path length, with no critical extension this does not
  read, and none of them the anchor itself). The leaf must be inside its validity period and,
  when it states a key usage, include digitalSignature; one that states extended key usages must name one an
  issuer may hold (ISO 18013-5's document signer, as EUDI issuers use; the EUDI PID Rulebook's
  document signer, 1.3.130.2.0.0.1.2, as the EU reference PID issuer uses; or client auth, code
  signing or email protection). A leaf that states no key usage is not restricted by one. The
  issuer is the leaf's subject under the anchor its chain ends at. A leaf that names an issuer
  must name the credential's `iss`: a URI subjectAltName exactly, or, for a leaf naming only DNS
  hosts, an https URL on one. A leaf with neither (the EU reference PID issuer's has no
  subjectAltName) leaves `iss` unbound: the verdict reports it apart, not in `claims`.
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

**Trust, in two steps.** Start with pinned trust: `--issuer-trust-anchor` (`trust_anchors=` in
the API) holds the issuer CA certificates a relying party received directly, and `--issuer-jwks`
the issuer keys. That is what this package does today. The second step, reading issuers from a
trusted list, is not supported yet. The order follows the FY2025 Japan-EU educational-credential
interoperability demonstration, which pre-shared its root and intermediate certificates in the
first round and puts trusted lists in the scope of the second (Digital Agency,
[scope definition document](https://www.digital.go.jp/assets/contents/node/basic_page/field_ref_resources/a238993a-8e6a-455c-b3d3-bbebf6ef273e/b59aa26d/20260918_policies_trust_report_02.pdf), 2026-09-18).

**Anchor the issuer CA, never a broad root that also certifies other roles.** A trust anchor
authorises any end-entity certificate beneath it whose key usage and extended key usage permit
signing to sign credentials this verifier accepts. Configure the CA that signs your issuers'
certificates, not a root that also certifies relying parties, TLS endpoints or other roles: their
certificates cannot be told from an issuer's by their contents (a relying party's and an issuer's
may both carry the extended key usage `clientAuth`), so the anchor is the only thing that separates
them. For example, Yivi publishes a self-signed Yivi Requestors Root CA with two CAs beneath it: the
Yivi Attestation Providers CA, which signs credential issuers, and the Yivi Relying Parties CA.
Anchor the Attestation Providers CA. Anchoring the root would accept a relying party's certificate
as an issuer whenever its usages permit signing, as `clientAuth` does (`IssuerAnchorScopeTests` in
`test_sdjwt.py`). Where one root certifies issuers and relying parties alike, with no narrower
issuer CA beneath it, anchoring cannot separate the roles, and this package cannot either: trust in
a credential that carries `x5c` comes from its anchor, and there is no setting that limits accepted
issuers to named `iss` values.

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

For an issuer that signs with its certificate in `x5c`, the verdict also says who signed:
`issuer_subject` is the leaf's subject and `issuer_anchor` the subject of the configured anchor
its chain ends at (RFC 4514 strings). `iss_bound` is `True` when the leaf gives the credential's
`iss` as one of its names, and `None` when there is no `iss`. It is `False` when the leaf gives
no name an `iss` could be, so nothing binds `iss` to the key: the `iss` is then left out of
`claims`, reported as `unbound_iss`, and not given to a status resolver. All four are `None`
for an issuer key configured with `issuer_jwks`, and for a refusal.

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
| `disclosure` | a disclosure that supplies a claim SD-JWT VC keeps out of disclosures (draft 19, section 2.2.2.3: `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts`, `status`) or anything inside one, judged by where it lands, so a disclosed `sub` or `iat`, or a private claim's `status` member, is accepted; a disclosure named `_sd`, `_sd_alg` or `...`; a colliding claim, a digest the credential commits to twice, or nesting past the depth cap |
| `issuer_key` | an untrusted key; an x5c leaf, or a CA certificate it sends, outside its validity (the reason names the period); a leaf not marked for signing (the reason names the key usage, or an extended key usage for another purpose), self-signed or a CA, or one whose subjectAltName names an issuer other than the credential's `iss` |
| `crit` | an issuer JWT, key-binding JWT or status list token whose `crit` names an extension; none is implemented |
| `transaction_data_missing`, `transaction_data_extra`, `transaction_data_mismatch` | (transaction data) `transaction_data_hashes` that lack, add to or differ from the hashes of the entries the key-binding JWT must bind, in the request's order |
| `transaction_data_alg` | (transaction data) a `transaction_data_hashes_alg` that is not a string, not allowed by every entry it binds, absent when an entry names algorithms, or not computable here |
| `ts12_jti`, `ts12_response_mode`, `ts12_amr` | (a TS12 entry naming the credential) no `jti` or one used before; a `response_mode` other than the request's; `amr` that is not single-member objects naming at least two TS12 categories |
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

## Transaction data

A request may carry OpenID4VP 1.0 `transaction_data` (section 8.4), opt-in per request:
`Verifier.new_request(transaction_data=[...])`, or `serve --transaction-data FILE --once`. An entry
is a base64url string, sent exactly as given, or a JSON object, encoded once. It must name the
request's credential query (`--credential-query-id`, default `pid`), and a TS12 payment
(`urn:eudi:sca:payment:1`) must satisfy TS12's own JSON Schema for it, or the request is refused
before it is sent. A request without `transaction_data` is unchanged.

The presentation's key-binding JWT must then carry:

- `transaction_data_hashes`: base64url(HASH(the ASCII bytes of each string as sent)), never of the
  decoded JSON (Appendix B.3.3.1), for exactly the entries it binds, in the request's order;
- `transaction_data_hashes_alg`: a string naming an algorithm every entry it binds allows
  (sha-256 by default; sha-384 and sha-512 when an entry lists them), required when one lists any;
- for a TS12 entry (`urn:eudi:sca:...`) naming its credential (TS12 section 3.6): a `jti` not seen
  before, the request's `response_mode`, and `amr` naming at least two TS12 categories.

`verdict.transaction_data` says what the JWT was held to: the entries, the reading, the algorithm
and the `jti`.

**Which entries each key-binding JWT binds**, when a response presents several credentials, is not
settled by OpenID4VP 1.0 (SIROS's question B8). Both readings are implemented and one is named:
`per_credential`, the entries whose `credential_ids` name that credential (SIROS, multipaz), or
`all_entries`, every entry (SUNET/vc). Under `per_credential` an entry naming two presented
credentials is bound by exactly one of them, as section 5.1 has the wallet "use only one of the
referenced Credentials"; twice or not at all is refused.
`polaris-oid4vp verdict --request R --vp-token T` judges a captured response under both, and with
two readings that differ decides only under `--transaction-data-scope`. Otherwise it accepts
nothing: `accepted` is null and the command exits 2. An undecided reading is not an acceptance. With
one credential query, as `serve` asks, both expect every entry.
[lab/interop/transaction-data](https://github.com/EgorKhaklin/polaris-id/blob/main/lab/interop/transaction-data/README.md)
holds this to SIROS's published vectors and to a two-credential vector.

Not covered: the DC API, mdoc, schemas for TS12's other three types, TS12 rules its schema does not
encode, and JSON Schema `format` (an annotation). A `Verifier` remembers a `jti` for one day.

## verifier_info under ETSI TS 119 472-2

ETSI TS 119 472-2 V1.2.1 makes `verifier_info` mandatory in its HAIP-common request object
(OIDFVP-HAIP-COMMON-REQ-RO-01 to -16), and the German EUDI Wallet (its core library 0.30, in iOS
0.3.9 and Android 0.61.3) refuses every request from an `x509_hash` verifier, as this one is, that
carries no registration certificate. `Verifier(..., verifier_info_profile="etsi-119472-2")`, or
`serve --verifier-info-profile etsi-119472-2`, refuses to start a request whose `verifier_info`
does not meet those requirements: a `ValueError` names the requirement's ID, and `serve` exits 2
before it listens. Under the profile:

- `verifier_info` is an array of objects with exactly one `registrar_dataset` element, whose
  `data` holds `identifier`, `srvDescription`, `registryURI`, `intendedUseIdentifier`, `purpose`
  and `policyURI`, each non-empty and the two URIs absolute, and optionally `credential`;
- it carries at most one `registration_cert` element, its `data` a non-empty string; neither
  element carries `credential_ids`, and a format naming a registration certificate otherwise
  (`WRPRC`, `registration_certificate`) is refused;
- with a registration certificate, the request may ask for nothing the certificate does not
  register: the DCQL query's format and `meta`, and each claim path. The certificate's
  `credentials` are read as ETSI TS 119 475 writes them, with `claim` (a certificate saying
  `claims` is refused as not ETSI's key, never read as registering nothing; one without `claim`
  holds the format and `meta` only). Claim paths compare exactly, the way the Android wallet
  compares them: a registered `["age_equal_or_over"]` does not cover `["age_equal_or_over",
  "18"]`, nor `["nationalities", null]` cover `["nationalities", 0]`. `values` are not compared.
  `serve` says at startup whether this check ran.

**Shape and labels only.** The profile does not validate the registration certificate's
signature or chain, the registrar's data against its registry, or the access certificate that
signs the request; it reads the certificate's payload, unverified, only to check this verifier's
own request against it, and judges no wallet's behaviour. RO-16 has the certificate's `data` be
"the base64url encoding of the serialized RP registration certificate", which leaves open whether
a JWT goes as its compact serialization or encoded once more; both forms are read.

In every mode, profile or none, a registration certificate labelled with its own media type
(`rc-wrp+jwt` or `rc-wrp+cwt` as its format, or a JWS typed `rc-wrp+jwt` under another format) is
refused, because its format is `registration_cert`. Otherwise a request without the profile is
unchanged, byte for byte. The cases, as JSON another verifier can read, are in
[testdata/verifier-info](https://github.com/EgorKhaklin/polaris-id/tree/main/packages/polaris-oid4vp/testdata/verifier-info).
The approach follows EUDIPLO's `registration_cert` configuration and ERICA's request checks.

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
- **Unbound iss:** delegated status lists are not consulted; status is established only by a
  list signed with the credential's own key. The resolver is given `issuer=None` for such a
  credential, so a `StatedAuthority` entry for the name in its `iss` is never found.

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

- 614 tests in seven files. `test_conformance_capture` replays a real `direct_post.jwt` response built by the
  OpenID Foundation suite's wallet (Nimbus JOSE), so this package's ECDH-ES, KDF, AAD binding and
  digests are checked against an independent implementation.
- `scripts/polaris-oid4vp-mutation-drill.py` makes each of the 176 refusals accept and requires a
  test to fail: 172 are caught, and the 4 survivors are declared with their reasons (measured
  2026-10-11; CI runs it on every push).
- Held-out boundary mutations (off-by-one windows, header binding, listener routing) each have a
  dedicated test class.
