# The exchange gateway (P8.2d)

**Reader:** an engineer building an institution's integration with the fabric, or an assessor
who wants to know how two institutions exchange a request through Polaris trust and what is
left behind.

**Status:** shipped v9.324, the flagship of the exchange fabric. `POST /api/v1/exchange/<id>`
with a `polaris-exchange-request/1` envelope; verified offline by `scripts/polaris-verify.py`
(`verify_exchange_request`, `exchange_evidence`, and the receipt's `verify_exchange_receipt`).

## The exchange

A requesting institution wants a service that another institution's system provides. It
builds the request body (JSON), signs an envelope under its registered ML-DSA-65 key -- the
SHA3-256 of the body's canonical JSON, the target agency and service kind, the context, a
nonce it will never reuse, and the time -- and posts envelope and body to the target
institution's Polaris instance. The gateway there:

1. refuses outright without real ML-DSA-65 (a placeholder signature is not authentication);
2. checks the envelope is well-formed, addressed to this agency, names a service kind this
   instance forwards to, is fresh, and that `request_hash` binds the body;
3. **authenticates** the requester by a key it already knows (a registered authority) and
   verifies the signature two-witness under that key;
4. **authorizes** it through the in-context trust graph -- the RESPONDING agency itself
   attests the requester's key in the envelope's context (v9.333: an attestation by any
   other agency on the instance authorizes nothing here; trust is explicit, directional
   and non-transitive, as a relying party trusts only the manifests it chose) -- *before anything leaves the
   process*;
5. **consumes the nonce** in the append-only replay register `ExchangeNonce`: an identical
   envelope replayed to any worker is refused, and a request is never delivered twice;
6. **forwards** the body to the upstream the operator configured for that kind
   (`POLARIS_EXCHANGE_UPSTREAMS`, a JSON map of kind to URL; a URL never comes from a
   request), passing the authenticated requester key and context as headers;
7. **receipts** the exchange: a section 3.8 receipt with the envelope's signed time as
   `occurred_at`, binding both bodies by hash, its hash appended to the receipt log;
8. returns the upstream's response body together with the receipt. The receipt is the
   response envelope; there is no second signed artifact to keep.

Nothing but the receipt's hash and the consumed nonce is written. The bodies exist for the
life of the request and are never logged; the two-instance drill reads B's process log and
its tables to prove it.

## Evidence without retention, completed

The pair (envelope, receipt) is the evidence of one exchange. The envelope is the requester's
signed intent; the receipt is the responder's signed account; they agree on the requester key,
the context, the request hash and the instant (`exchange_evidence`), and each is verifiable
offline by a third party with no access to either body. A party that holds a body confirms
the commitment binds. A conventional fabric keeps the exchanged messages to make the exchange
provable; Polaris keeps the proof and not the messages.

## Why these choices

- **Signature, not bearer.** The institution already holds a post-quantum key the trust graph
  knows; the signature is the institutional identity, with no secret to leak.
- **Authorize before forward.** The upstream must never see a request the trust graph would
  have refused; the check pins the order.
- **A durable replay register, not a nonce in memory.** Multiple workers, one register: the
  same recipe as the ZK nonce, strictly append-only. A failed upstream call still consumes the
  nonce; a retry needs a new one, which is the honest semantics for a request that may have
  been delivered.
- **Operator-configured upstreams.** Routing is deployment policy, not request content; the
  registry advertises the kinds an instance forwards to (`instance.exchange_kinds`), so a
  requester discovers what it may ask for.

## What runs

The two-instance drill (`federation-two-instances`) runs an echo upstream behind B, launches
B with it configured, and drives from A: a mediated exchange (200) whose receipt is
B-signed, requester-authorized and binds both bodies; the envelope verifying offline;
envelope + receipt forming one chain; the receipt in B's log; the same envelope replayed
(409); the same request with a new nonce (200); an unknown requester (401); a body the
envelope does not bind (400); a tampered signature (401); a kind B does not forward (404); a
stale envelope (401); the registry advertising the gateway and the kind; no body in B's
process log; and the replay register holding exactly the delivered nonces. The envelope is in
the canonical-equivalence oracle, the wire spec (section 3.11), the conformance suite (both
SDKs), and the metamorphic fuzzer; a DB test proves the gateway fails closed.
`check_exchange_gateway` pins the whole order of operations, with a detection test.

## Boundaries

Bodies are JSON in v1. The gateway is the target institution's own instance; a third-party
hub that forwards between two instances it does not own is a routing topology this design
does not need, because discovery (P8.3) tells a requester which instance to call. Streaming,
large payloads, and asynchronous exchanges are outside v1.
