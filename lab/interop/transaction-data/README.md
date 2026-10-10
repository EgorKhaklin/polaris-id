# transaction-data: OpenID4VP transaction_data against the published vectors

`polaris-oid4vp` checks OpenID4VP 1.0 `transaction_data` (section 8.4, Appendix B.3.3.1) and
EU TS12's key binding claims (section 3.6). SIROS's wallet work (sirosfoundation/wallet-frontend
#354 and #361) asks for a second verifier to test against, and leaves one question open, which it
calls B8: when a response presents several credentials, does each key binding JWT hash only the
entries whose `credential_ids` name its credential, or all of them? This directory holds the
package to the vectors SIROS published and adds the one vector B8 needs.

## Run it

    python3 lab/interop/transaction-data/wmp_vectors.py        # network; cryptography, jsonschema
    python3 lab/interop/transaction-data/two_credentials.py    # rewrites the vector in testdata/

`wmp_vectors.py` reads two files from GitHub at pinned commits, checks each against its git blob
id and SHA-256, and keeps them in memory. Neither is copied into this repository: the vectors
carry no licence.

| File | Repository and commit | Blob |
|---|---|---|
| `vectors/openid4x/transaction-data-hashes.json` | sirosfoundation/wmp (formerly leifj/wmp) `2c679022` | `b7423abe` |
| `docs/technical-specifications/api/ts12-urn-eudi-sca-payment-1-data-model.json` | eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications `ee91a294` | `0c9a0c60` |

It exits 0 only if every check holds:

1. **The 7 hash-only vectors.** All 21 hashes (sha-256, sha-384, sha-512) come out of the
   package's `transaction_data_hash` from `raw`, none from the decoded bytes, and the request
   builder refuses each entry as a payment (their `amount` is a string; TS12's schema says number).
2. **The 5 conforming vectors, end to end.** A `Verifier` asking for credential query `pay` sends
   each `raw` byte for byte; a wallet written here answers with a key binding JWT carrying the
   vector's own published hash, for each algorithm the entry allows (6 answers: the last vector
   allows sha-256 and sha-384); each is answered 200. The hash of the decoded JSON is refused
   (`transaction_data_mismatch`), once per vector.
3. **TS12's payment schema.** The mapping in `polaris_oid4vp/verifier.py` equals the published
   schema less `$schema`, `examples` and `format`, and the `jsonschema` package (2020-12, formats
   not asserted) agrees with `ts12_payment_problems` on 31 payloads. One difference is by design:
   python-jsonschema matches `pattern` with Python's `re.search`, whose `$` also matches before a
   final newline, so it accepts the currency `"EUR\n"`, which ECMA-262 (JSON Schema's regex
   dialect) refuses.

## The B8 vector

`two_credentials.py` writes
[`transaction-data-two-credentials.json`](../../../packages/polaris-oid4vp/testdata/transaction-data-two-credentials.json):
two credential queries, `pid` and `pay`, and one TS12 payment entry naming `pay`. It mints with its
own code (`cryptography` only), not the package's. What each key binding JWT must carry:

| Reading | `pid` | `pay` |
|---|---|---|
| `per_credential` (SIROS, multipaz) | no `transaction_data_hashes` | the payment's hash, `sha-256`, and TS12's `jti`, `response_mode`, `amr` |
| `all_entries` (SUNET/vc) | the payment's hash, `sha-256` | the same as under `per_credential` |

The file carries one response written each way. `polaris-oid4vp verdict` accepts each under its
own reading and refuses it under the other (`pid`: `transaction_data_missing` one way,
`transaction_data_extra` the other); asked to decide without a named reading, it does not.

Under `per_credential`, an entry whose `credential_ids` name two presented credentials is bound by
exactly one of them, the wallet's choice: OpenID4VP 1.0 section 5.1, "If there is more than one
element in the array, the Wallet MUST use only one of the referenced Credentials for transaction
authorization." SIROS's rule read literally would put it in both. No published vector has that
shape; the package's tests (`AnEntryNamingTwoPresentedCredentialsTests`) accept it bound by either
credential and refuse it bound by both or by neither.

## Results

2026-10-10, the tree of this change: `wmp_vectors.py` passed (7 hash-only vectors, 21 hashes; 5
conforming vectors end to end; the schema equal and 31/31 payloads agreeing). The package's
tests (`TwoCredentialVectorTests`, `VerdictCommandTests`) hold the B8 vector.

This is internal evidence: the vectors are SIROS's, the runs are this project's. No outside wallet
has presented transaction data to this verifier, so nothing here is a row in
[EXTERNAL-NOUNS.md](../../EXTERNAL-NOUNS.md).
