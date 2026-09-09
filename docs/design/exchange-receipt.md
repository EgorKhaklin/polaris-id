# The exchange receipt (P8.2)

**Reader:** an engineer or an assessor who wants to know how Polaris records that
an institutional exchange happened and was authorized, without becoming the
message log that a surveillance system would.

**Status:** shipped v9.317 as the first primitive of the P8 exchange fabric.
`polaris-exchange-receipt/1`, minted at `POST /api/v1/exchange-receipt/<id>` and
verified offline by `scripts/polaris-verify.py` (`verify_exchange_receipt`).

## Why not a message log

An X-Road-class fabric mediates requests between institutions and, for evidentiary
value, can log the exchanged messages: a security server signs and timestamps the
traffic so a receipt can later be proven to a third party. That evidence is real,
and so is its cost: a store of who asked what about whom, which is exactly the
population-scale record Polaris's vocation forbids.

The exchange receipt is the inversion. It proves the same three things a message log
proves -- that an exchange **occurred**, **between these parties**, and was
**authorized** -- while retaining none of the payload. It does this by committing to
the request and the response **by hash**, never by content.

## The receipt

When a responder serves an authenticated, authorized request, it signs a
`polaris-exchange-receipt/1` over the canonical statement of:

```jsonc
{ "format": "polaris-exchange-receipt/1",
  "requester": { "public_key_hex": "<the requesting party's key>" },
  "responder": { "agency_id": 1, "name": "..." },
  "context_id": 1,
  "request_hash":  "<SHA3-256 of the request body, hex>",
  "response_hash": "<SHA3-256 of the response body, hex>",
  "authorized_via": { "authority": {...}, "context_id": 1 },
  "occurred_at": "...", "algorithm": "ML-DSA-65" }
```

The bytes signed are `SHA3-256(canonical)` under the same discipline as every other
Polaris artifact (sorted-keys compact JSON; see [the wire spec](../reference/WIRE-SPEC.md)
section 3.8). The signature is the responder's. The bodies never appear.

## Evidence without retention

The mint endpoint accepts **only the hashes** (`request_hash`, `response_hash`),
never the bodies: the app cannot retain what it is never given, and the endpoint
rejects anything that is not a 64-character SHA3-256 hex digest. The responder mints
a receipt only if the requester is **authorized** -- some `AgencyTrustAttestation`
attests the requester's key in the presented context -- and records which authority's
attestation authorized it.

`verify_exchange_receipt` then decides, offline, two things a third party can check
from the receipt alone:

1. **It is authentic** -- the responder's ML-DSA-65 signature verifies under the
   two-witness rule (and, with a pinned responder key, that the expected responder
   signed it).
2. **The requester was authorized** -- given the federation manifests the relying
   party trusts, some trusted manifest attests the requester's key in the receipt's
   context, exactly the non-transitive trust of the section 4 credential decision.

Neither check needs the payload. A party that *does* hold the request or response
body may pass it to confirm the commitment binds (`request_hash == SHA3-256(request)`),
which ties the receipt to a specific exchange; a party that does not still obtains the
proof of occurrence and authorization. That is the whole point: the evidence is
separable from the data.

## What runs

`scripts/polaris-exchange-receipt-drill.py` stands up a requester, a responder, and an
attester with distinct real ML-DSA-65 roots, mints a receipt, and drives the matrix
every release (the `pqc-real` CI job): the receipt is authentic and responder-bound;
the requester is authorized through a trusted attestation; occurrence and authorization
are proven **without** the payload and the commitment binds **with** it; and a wrong
body, a tampered receipt, or an unauthorized requester is caught. `check_exchange_receipt`
pins the endpoint, the offline verify, the hashes-only rule, the oracle coverage, the
wire-spec entry, and the drill, with a detection test. The app builder and the verifier
produce byte-identical signed bytes, pinned by the canonical-equivalence oracle.

## Boundaries and what's next

- **Auth.** v1 mints under operator auth (login + CSRF). Service-to-service auth for
  an institutional caller (OAuth, the relying-party path) is P8.2b.
- **Anchoring.** A receipt's hash can be committed to the transparency log so the set
  of receipts is itself append-only and monitorable; wiring that is a follow-on.
- **The fabric.** This is the evidence primitive, not the mediation layer. A gateway
  that routes and mediates requests between institutions (the X-Road security-server
  analogue), producing a receipt per exchange, is the larger P8.2 build; the receipt
  is the part that makes it anti-surveillance by construction.
