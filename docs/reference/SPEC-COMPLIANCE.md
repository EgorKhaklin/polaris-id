# Specification compliance

What Polaris implements, at what version, in what role, and how it is certified. Every line is
scoped on purpose: implementing a standard is not a certification, and a certification covers one
package version in one role, never the whole system. The evidence marks (implemented, experimental,
externally exercised) are the vocabulary of [PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md);
what outside parties have actually run is [EXTERNAL-NOUNS.md](../../lab/EXTERNAL-NOUNS.md).

| Standard | Role | Where | Evidence (suite, version) | Exceptions | Run by | Date |
|---|---|---|---|---|---|---|
| OpenID4VP 1.0 + HAIP 1.0 | Verifier | `polaris-oid4vp` 1.0.0rc7 | polaris-oid4vp 1.0.0rc7: self-certification to the OpenID4VP 1.0 + HAIP 1.0 Verifier profile (sd_jwt_vc, direct_post.jwt), approved and listed by the OpenID Foundation, 2026-09-24 (OCS-3049). The Foundation's conformance suite, hosted plan `oid4vp-1final-verifier-haip-test-plan` (7hXWngaA7f0QO): 11 of 11 modules finished without failure ([listing](https://openid.net/certification/certified-oid4vp-haip-final/), [record](../../lab/EXTERNAL-NOUNS.md#conformance-profile)) | `sd_jwt_vc` only, no mdoc; no Digital Credentials API; one DCQL credential query; no array indices or null wildcard in claim paths | self (OIDF conformance suite), listed by OIDF | 2026-09-24 |
| OpenID4VP 1.0 + HAIP 1.0 | Verifier | `polaris-oid4vp` 1.0.0rc18 at 5fd6c06d (not certified) | [`test_verifier.py`](../../packages/polaris-oid4vp/test_verifier.py), 81 tests; [`test_jwe.py`](../../packages/polaris-oid4vp/test_jwe.py), 38 tests | `sd_jwt_vc` only, no mdoc; no Digital Credentials API; one DCQL credential query; no array indices or null wildcard in claim paths | self | 2026-10-10 |
| SD-JWT VC (IETF draft 19) | verify + issue | `polaris-oid4vp` (verify), wallet copies (issue) | verify: [`test_sdjwt.py`](../../packages/polaris-oid4vp/test_sdjwt.py), 184 tests at 5fd6c06d; [lab record 018](../../lab/strategy/018-negative-vectors.md)'s [`vectors.json`](../../lab/interop/negative-vectors/vectors.json) 0.1.0, 23 of 23 verdicts as expected. issue: [`test_wallet_copy.py`](../../polaris_web/test_wallet_copy.py) `CopyTests`, 3 tests | `dc+sd-jwt` only (`vc+sd-jwt` refused); ES256 only | self | 2026-10-10 |
| OpenID4VCI 1.0 | Issuer | `/api/v1/oid4vci` | [`test_wallet_copy.py`](../../polaris_web/test_wallet_copy.py), 12 tests at 5fd6c06d; [lab record 005, step 5](../../lab/strategy/005/STEP5.md): Credo 0.6.3 and walt.id Wallet API v2 1.0.0 each received a wallet copy from `polaris_web` | pre-authorized code only; not HAIP; `dc+sd-jwt` signed ES256 only | self | 2026-10-10; step 5 2026-09-28 |
| Token Status List (IETF draft) | publish + check | `polaris-oid4vp` (check), issuer (publish) | check: [`test_status.py`](../../packages/polaris-oid4vp/test_status.py), 56 tests at 5fd6c06d; [lab/interop/status-list](../../lab/interop/status-list/README.md): draft-ietf-oauth-status-list-21's vectors and signed example, and lists made by `@sd-jwt/jwt-status-list` 0.19.0, every status matched (5,447 decisions). publish: [`test_wallet_copy.py`](../../polaris_web/test_wallet_copy.py) `StatusListTests`, 2 tests, the issuer's list read by `polaris-oid4vp` | a draft, not an RFC; the verifier checks status only when given a resolver | self | 2026-10-10; status-list 2026-10-04 |
| ML-DSA-65 (FIPS 204) | issuance signer | `pqc_signing`, custody | [`vectors/kat/mldsa_65_verify.json`](../../vectors/kat/mldsa_65_verify.json), 58 vectors curated from Project Wycheproof's `mldsa_65_verify_test.json` at 613a2e44cb64: all 58 decided as Wycheproof decides under both witnesses, liboqs 0.15.0 and `cryptography` 50.0.1 ([`polaris-kat-verify.py`](../../scripts/polaris-kat-verify.py)); [`test_pqc_signing.py`](../../polaris_web/test_pqc_signing.py), 62 tests, 1 skipped (it needs liboqs with Falcon and Node with `@noble/post-quantum`) | wallet copies are ES256, not ML-DSA-65; the vectors test the primitive, not the credential protocol | self | 2026-10-10 |
| FN-DSA (draft FIPS 206) | verify; experimental signer | `polaris-verify`, both SDKs | [`test_sdk.py`](../../sdk/python/test_sdk.py) `FnDsaFamilyTests`, 4 tests at 5fd6c06d (Python SDK, liboqs 0.15.0); conformance vectors `pack-fndsa1024-*` and `pack-fndsa512-unaccepted` in [conformance/vectors](../../conformance/vectors/); signing time: [lab record 015, step 4](../../lab/strategy/015/STEP4.md) | FIPS 206 is a draft, so the wire name is `Falcon-padded-1024`; signs only as an opt-in experimental signer, never in production; the timing test is first-order, not a constant-time proof | self | 2026-10-10; step 4 2026-10-06 |

Each row names the run that shows it. A test count is the count at the commit named, on the row's
date. Self means the author ran it; what outside parties have run is in
[EXTERNAL-NOUNS.md](../../lab/EXTERNAL-NOUNS.md).

## OpenID Certified

`polaris-oid4vp 1.0.0rc7` is OpenID Certified by Egor Khaklin to the OpenID4VP 1.0 + HAIP 1.0
**Verifier** profile (`sd_jwt_vc`, `direct_post.jwt`), reviewed and published by the OpenID
Foundation on 24 September 2026
([listing](https://openid.net/certification/certified-oid4vp-haip-final/)). It is a
self-certification for that package version in that role: not an endorsement, not an audit, and not
a certification of the rest of Polaris. A later package version is not certified until it is
re-tested and re-submitted. OpenID® and OpenID® Certified™ are trademarks of the OpenID
Foundation, used under its [certification terms](https://openid.net/certification/mark/).

## OpenID4VP 1.0

Polaris's standalone verifier `polaris-oid4vp` implements the OpenID for Verifiable Presentations
1.0 Verifier role (certified, above). The Wallet role is not Polaris's; outside wallets present to
the verifier, and which ones have is recorded in [EXTERNAL-NOUNS.md](../../lab/EXTERNAL-NOUNS.md).
It verifies one credential format, SD-JWT VC (`dc+sd-jwt`): it supports neither mdoc
(ISO/IEC 18013-5) nor the browser's Digital Credentials API. Its request carries one DCQL
credential query. A claim is a name or a path of object keys, with
optional `values` the disclosed value must match in type and value (`age_equal_or_over`, `18`,
`true`: one statement of an EUDI PID, not all of them); array indices and the null wildcard are not
supported. A presentation that discloses a selectively disclosable claim the query did not select,
other than the object a requested member is reached through, is refused: section 6.4 says a
wallet MUST NOT send one. A wallet may fetch the signed request object by POST (`request_uri_method=post`) with a
`wallet_nonce`, which the object then carries; when its `wallet_metadata` asks for the object
encrypted and names a P-256 key, ECDH-ES and A128GCM or A256GCM, the signed object comes back
encrypted to that key (a nested JWT, RFC 9101 section 6.1). The operator may add `verifier_info`
(section 5.1), such as a registrar's registration certificate, which the request object carries
unchanged. A request may carry `transaction_data` (section 8.4): the key binding JWT must hash each
entry as sent (Appendix B.3.3.1) with an algorithm the entry allows, and for an EU TS12 (SCA)
entry carry TS12's `jti`, `response_mode` and `amr`. Which entries each key binding JWT binds when
a response presents several credentials is settled by the specification only for an entry naming
several of them (section 5.1: one of them binds it), so the reading is a named option.

## HAIP 1.0

The High Assurance Interoperability Profile, Verifier (certified, above): the `sd_jwt_vc` credential
format, the `direct_post.jwt` response mode with an encrypted response, and an x509 client
identifier. The normative wire details are in [WIRE-SPEC.md](WIRE-SPEC.md).

## SD-JWT VC

Issuer-signed SD-JWT VCs (`dc+sd-jwt`) are verified by the verifier, which checks the issuer
signature, the certificate chain, the selective-disclosure digests and the key binding.
Disclosures are held to section 2.2.2.3 of the IETF draft (draft 19): one that supplies `iss`,
`nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts` or `status`, or anything inside one, is
refused (`disclosure`); `sub` and `iat` may be disclosed. An issuer
JWT typed `vc+sd-jwt` is refused (`issuer_typ`): that was the type's name before SD-JWT VC renamed
it, and it now names a W3C VC Data Model credential. Polaris issues SD-JWT VCs as wallet copies over
OpenID4VCI, typed `dc+sd-jwt` and signed ES256 under a per-agency certificate. See
[WIRE-SPEC.md](WIRE-SPEC.md).

## OpenID4VCI 1.0

Polaris issues wallet copies through OpenID for Verifiable Credential Issuance 1.0 with a
pre-authorized code: each agency holding a wallet-copy key is a credential issuer under
`/api/v1/oid4vci/<agency_id>`, with issuer metadata at the `.well-known` paths. See [API.md](API.md).

## Token Status List

Revocation is published and checked as a Token Status List
(`draft-ietf-oauth-status-list`, past working group last call, not yet an RFC). The verifier decides
VALID, INVALID, SUSPENDED or unreachable and never reports "could not reach" as "not revoked". See
[WIRE-SPEC.md](WIRE-SPEC.md).

## ML-DSA-65

The default issuance signer is ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)),
under an audited algorithm-migration path; the algorithm is a row in `CryptographicAlgorithm`, not
hardcoded, and ML-DSA-87 is accepted for migration. This names the signer. Whether Module-LWE
resists a quantum adversary is mathematics, not a property of this software; every post-quantum
sentence stands beside [PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md).


## FN-DSA (draft FIPS 206)

Since 1.0.0-rc.71: the detached verifier and both SDKs accept `Falcon-padded-1024`, round-3 Falcon-1024 with fixed-length signatures, the scheme FIPS 206 (a draft) standardises. The wire name is the scheme's, because the standard is not final. Polaris signs under it only as an experimental signer (an explicit opt-in, never in production, two-witnessed), while FIPS 206 is a draft. Its signing time showed no dependence on the secret key on the two platforms measured, Apple M3 and Linux x86_64 ([lab record 015, step 4](../../lab/strategy/015/STEP4.md)); that is a first-order timing test, not a constant-time proof. Conformance vectors: `pack-fndsa1024-*`, `pack-fndsa512-unaccepted`.