# testdata: material this project did not make

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
