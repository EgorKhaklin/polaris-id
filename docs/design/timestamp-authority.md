# The timestamp authority (P8.7a)

**Reader:** an engineer or an assessor who wants to know how Polaris attaches trustworthy
time to a thing without learning what the thing is.

**Status:** shipped v9.321 as the first piece of the trust-service lifecycle (P8.7).
`polaris-timestamp/1`, minted at `POST /api/v1/timestamp/<id>`, verified offline by
`scripts/polaris-verify.py` (`verify_timestamp`, `timestamp_binds`).

## What it is

An authority signs a binding of an arbitrary SHA3-256 digest to an instant under its
registered ML-DSA-65 key. The requester sends the digest and, if it wants, a nonce of its own;
it gets back a signed statement `{format, authority, digest_hex, digest_algorithm, nonce,
issued_at, algorithm}`. Anyone can later verify the signature offline and, holding the data,
check that `SHA3-256(data)` is the digest the authority signed. That is the whole primitive:
RFC-3161-class timestamping, in Polaris's own canonical-JSON discipline, on a post-quantum
signature.

## Why digest-only, and why no log

The route accepts a digest, never content, so the authority learns nothing about what it
timestamps; and it keeps no per-request record unless the caller asks for an anchor (P8.5b,
below), because a timestamp authority that logs every request is a store of who timestamped
what, when. A conventional authority keeps a serial
number and an audit trail; Polaris deliberately does not. The evidence is the signed artifact
in the requester's hands, and the only bound on the route is a per-authority rate limit. If a
deployment wants the SET of timestamps to be auditable, the answer is the transparency log
(commit each timestamp's digest as an append-only leaf), not a request log. Since v9.341 that
is exactly what an ANCHORED request does, at the caller's choice: `anchor: true` appends the
timestamp's SHA3-256 to the append-only timestamp log and staples the inclusion evidence, the
one record the authority then keeps (a digest and an instant). Unanchored requests still leave
nothing. See [timestamp-transparency.md](timestamp-transparency.md).

## What it is for

- **Document signing (P8.5)** needs an instant a signature can be placed at that is not the
  signer's own assertion. This is that instant.
- **Independent time evidence for any artifact.** An exchange receipt's `occurred_at` is the
  responder's word. Timestamp the receipt's canonical bytes at a *second* authority and a
  third party has time evidence from a key other than the responder's; `timestamp_binds`
  checks the binding against the receipt bytes. The drill does exactly this.
- **Long-term validation.** When a signing key is later retired or compromised (P8.7b), a
  timestamp proves a signature existed before that event.

## Trust

The signature proves *an* authority signed; whether that authority is trusted is the relying
party's decision over its own anchor keys (`verify_timestamp(ts, anchor_keys=[...])`). The
signed registry (P8.3) will carry which authorities offer timestamping; the trust list (P8.7b)
will carry a key's status over time.

## What runs

`scripts/polaris-timestamp-drill.py` stands up an authority, a second authority, and a
stranger with distinct real ML-DSA-65 roots and drives the matrix every release (the
`pqc-real` CI job): authentic; binds to its data and to nothing else; nonce echoed; digest-only;
tampered signature, swapped digest, and rewritten instant all caught; trusted only under an
anchor set that includes the authority; a receipt timestamped by the second authority binds
to the receipt bytes under a key other than the responder's; hostile input does not crash the
verifier. The statement is in the canonical-equivalence oracle (app and verifier byte-identical),
the wire spec (section 3.9), the conformance suite (both SDKs verify the published vectors),
and the metamorphic fuzzer. `check_timestamp_authority` pins all of it, with a detection test.
