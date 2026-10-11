# testdata

## conformance-suite-capture.json: material this project did not make

`conformance-suite-capture.json` is one complete `direct_post.jwt` authorization response,
produced by the **OpenID Foundation conformance suite's** fake wallet during a local run of
`oid4vp-1final-verifier-haip-test-plan`, module `oid4vp-1final-verifier-happy-flow`, on
2026-09-14. It holds the encrypted response exactly as it arrived, plus the four values a
verifier needs to be held to it: the nonce the request sent, the `client_id` it sent as, the
issuer's public JWK, and the ephemeral key the response was encrypted to.

**It is committed, not fetched**, so `test_conformance_capture.py` runs in CI with no Docker
and no network. [`lab/interop/probe.py`](../../../lab/interop/probe.py) is what produced it.

## Why it matters more than the other tests

Every other test in this package builds its own material, so every other test is this package
agreeing with itself, and two consistent mistakes pass a round trip as cleanly as two correct
implementations. Here the JWE was built by Nimbus JOSE in Java and the SD-JWT by the suite's
own code. If this package's ECDH-ES, its Concat KDF, its AAD binding or its disclosure digests
were subtly wrong, this fixture would not open.

## The keys in it are throwaway

Both private keys were generated for that one run and have never protected anything. They are
here because a capture you cannot decrypt is a blob, and a fixture nobody can re-verify is an
assertion. Do not reuse them for anything.

## When it goes stale

The key binding JWT carries an `iat`, and freshness is relative to it, so the tests pin `now`
to that value rather than widening the acceptance window until an old presentation passes,
which would be the check deleting itself. One test deliberately does the opposite and asserts
the same fixture is REFUSED a year later.

## `eudi-pid-ds/`: the EU reference PID issuer's certificates

Three certificates the EU reference PID issuer,
[eudi-srv-web-issuing-eudiw-py](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py),
publishes as test material, added upstream in commit `e410ecd319a2b0c7a81b33093ce156b0d67f54dc`
(2024-07-01) and unchanged at `4a9233215c12d720ac0ca52c36bfeeb0651c1514` (main on 2026-10-10).
Upstream is Apache-2.0, and its NOTICE.txt reads "EU Digital Identity Wallet, Copyright (c) 2023
European Commission". Fetched 2026-10-10:

| Upstream file | SHA-256 | Taken from it |
|---|---|---|
| `api_docs/test_tokens/DS-token/PID-DS-0002.zip` | `6d3f3ce6661cf1aa8f85591643506a0a805b3ddf34d77b8b2e1cd13116178c09` | `PID-DS-0002.cert.der`, SHA-256 `77c89447a275b9d23634e66c2ecfeee11b0f98d551ac6b1f2b27966afaf8dd8f` |
| `api_docs/test_tokens/DS-token/PID-DS-0003.zip` | `c790f513a26c979e7feec6576e6efa71b06a5356c58f56a1f2efff17278614e6` | `PID-DS-0003.cert.der`, SHA-256 `a5f46f401f953a602e102784b8b2a19b2a834924ba9e9edfdb179bd04a452fc0` |
| `api_docs/test_tokens/IACA-token/PIDIssuerCAUT01.pem.gz` | `8bf206193c208abaf90407f026357decbde090ea0f22765c6a4244ed8ab638c6` | `PIDIssuerCAUT01.pem`, its whole content (CRLF line ends), SHA-256 `3b04635db064490bf4cf22538de024189982065413a7d5bb002e99644c11b8af` |

Each zip also holds the document signer's private key. It was not extracted and is not here; the
zips were read with Python's `zipfile`, and only the `.cert.der` member was written out.

The two document signers are `CN=PID DS - 0002` and `CN=PID DS - 0003`
(`O=EUDI Wallet Reference Implementation, C=UT`), issued by `CN=PID Issuer CA - UT 01` and valid
from 2024-07-01 to 2025-09-24. Each carries a critical extended key usage naming only
1.3.130.2.0.0.1.2, a critical key usage of digitalSignature, an issuerAltName and a CRL
distribution point, and no subjectAltName. The CA is self-signed (P-384, valid to 2032-11-27)
with a critical extended key usage of 1.3.130.2.0.0.1.7. `test_sdjwt.py`
(`ReferencePidIssuerCertificateTests`) checks these hashes first, so a changed file fails as a
changed file. It verifies the real chain at a time inside the certificates' validity, and signs
credentials with throwaway keys under copies of their extensions, because their keys are not here.

## transaction-data-two-credentials.json: a vector this project made

No published transaction_data vector presents more than one credential, and whether each key
binding JWT hashes only the entries naming its credential or all of them (SIROS's question B8)
only arises when one does. This file asks for two credentials, `pid` and `pay`, with one EU TS12
payment entry naming `pay`, and gives what each key binding JWT must carry under each reading and
one response written each way. It was written by
[`lab/interop/transaction-data/two_credentials.py`](../../../lab/interop/transaction-data/two_credentials.py),
which mints with its own code rather than this package's; the private keys were discarded.
`TwoCredentialVectorTests` and `VerdictCommandTests` judge it at its own `at`, as the capture is
judged at its `iat`.

## verifier-info/: verifier_info cases for ETSI TS 119 472-2, made by this project

One JSON file per case for the opt-in `etsi-119472-2` profile (the package README's "verifier_info
under ETSI TS 119 472-2"): the control, a `registrar_dataset` with its six members and a credential
plus a registration certificate registering the two claims the request asks for; one case per rule,
each the control with a single defect; a certificate without `claim`, held to its format and `meta`
only; and the same `verifier_info` outside the profile. Each file holds `id`, `changed` (what differs
from the control), `class` (`control`; `spec` or `spec-implied` when a cited requirement states or
implies the verdict; `lint` for the over-asking check; `off-profile`), `clauses`, `requirement` (the
ID a refusal names), `says` (text the refusal carries), `settings` (the profile, and the DCQL query's
id, credential types and claims), `verifier_info`, and `expect`, `accept` or `refuse`, after the
vectors of [lab record 018](../../../lab/strategy/018-negative-vectors.md).

They are test material. Every identifier is in example.invalid, and each registration certificate is
a JWT typed `rc-wrp+jwt` signed by a throwaway P-256 key made for these files and discarded, never a
registrar's. Nothing checks that signature: the profile checks no certificate's signature.
`VerifierInfoVectorTests` judges every file through `Verifier`, and `VerifierInfoProfileServeTests`
through `serve`.
