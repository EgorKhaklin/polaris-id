# Specification compliance

What Polaris implements, at what version, in what role, and how it is certified. Every line is
scoped on purpose: implementing a standard is not a certification, and a certification covers one
package version in one role, never the whole system. The evidence marks (implemented, experimental,
externally exercised) are the vocabulary of [PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md);
what outside parties have actually run is [EXTERNAL-NOUNS.md](../../lab/EXTERNAL-NOUNS.md).

| Standard | Role | Where | State |
|---|---|---|---|
| OpenID4VP 1.0 | Verifier | `polaris-oid4vp` | OpenID Certified (see below) |
| HAIP 1.0 | Verifier | `polaris-oid4vp` | OpenID Certified (see below) |
| SD-JWT VC | verify + issue | verifier + wallet copies | implemented |
| OpenID4VCI 1.0 | Issuer | `/api/v1/oid4vci` | implemented |
| Token Status List | publish + check | `polaris-oid4vp`, issuer | implemented (IETF draft) |
| ML-DSA-65 (FIPS 204) | issuance signer | `pqc_signing`, custody | implemented |

## OpenID Certified

`polaris-oid4vp 1.0.0rc7` is OpenID Certified by Egor Khaklin to the OpenID4VP 1.0 + HAIP 1.0
**Verifier** profile (`sd_jwt_vc`, `direct_post.jwt`), reviewed and published by the OpenID
Foundation on 24 September 2026
([listing](https://openid.net/certification/certified-oid4vp-haip-final/)). It is a
self-certification for that package version in that role: not an endorsement, not an audit, and not
a certification of the rest of Polaris. A later package version is not certified until it is
re-tested and re-submitted.

## OpenID4VP 1.0

Polaris's standalone verifier `polaris-oid4vp` implements the OpenID for Verifiable Presentations
1.0 Verifier role (certified, above). The Wallet role is not Polaris's; outside wallets present to
the verifier, and which ones have is recorded in [EXTERNAL-NOUNS.md](../../lab/EXTERNAL-NOUNS.md).
Its request carries one DCQL credential query. A claim is a name or a path of object keys, with
optional `values` the disclosed value must match in type and value (`age_equal_or_over`, `18`,
`true`: one statement of an EUDI PID, not all of them); array indices and the null wildcard are not
supported.

## HAIP 1.0

The High Assurance Interoperability Profile, Verifier (certified, above): the `sd_jwt_vc` credential
format, the `direct_post.jwt` response mode with an encrypted response, and an x509 client
identifier. The normative wire details are in [WIRE-SPEC.md](WIRE-SPEC.md).

## SD-JWT VC

Issuer-signed SD-JWT VCs (`dc+sd-jwt` / `vc+sd-jwt`) are verified by the verifier, which checks the
issuer signature, the certificate chain, the selective-disclosure digests and the key binding; and
are issued as wallet copies over OpenID4VCI, signed ES256 under a per-agency certificate. See
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
