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
