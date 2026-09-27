# Polaris verification conformance suite

**What this is:** the integration contract for verifying a Polaris identity
credential. A relying party (or an SDK author) certifies its own verifier -- in
any language -- by making it pass this suite. Passing it is what "conformant"
means (ROADMAP P3.5).

The suite covers the **offline** checks over the protocol's signed artifacts, each
specified normatively in [`docs/reference/WIRE-SPEC.md`](../docs/reference/WIRE-SPEC.md). It
certifies the **authenticity** of the app-signed artifacts a relying party, a service or an
auditor holds (27 artifact types, listed in `cases.json` and held to that file by
`check_conformance_spec_counts_its_artifacts`, because this sentence said sixteen for eleven
releases after the suite had grown past it); among them:

- the **authenticity pack** (is the ML-DSA signature genuine under the declared, accepted
  parameter set, and -- with a trusted issuer anchor set -- is the signing key trusted?);
- the **status assertion** (genuine, fresh, and ACTIVE?);
- and the **epoch checkpoint**, **revocation feed**, **federation manifest**, **status
  bundle**, and **transparency STH**, each verified through one generic signed-statement
  check: the signature over `SHA3-256(canonical)`, freshness for a windowed artifact, and
  the artifact's own commitment (feed/bundle) or self-consistency (manifest).

It also certifies the composite federation **trust decision** (`artifact: cross-authority`):
given a foreign credential's pack, the federation manifests the relying party trusts, a
trusted anchor set, and a presented context, decide accept or reject -- accept only when the
credential is authentic AND a trusted manifest attests its key in that context AND (if a
revocation feed is supplied) it is not revoked. Online authorization (a live call to
`POST /api/v1/verify`, specified in [`docs/reference/API.md`](../docs/reference/API.md)) is
the only check not in these offline vectors, because it depends on live issuer state.

It certifies the **timestamp anchor** (`artifact: timestamp-anchor`, P9.6). A timestamp on
its own does not settle long-term validation: whoever holds the timestamp authority's key
can mint a backdated one. An anchored timestamp is an entry in an append-only log whose head
is published and cosigned by independent witnesses, so a forgery has to be absent from every
witnessed head of its claimed era. A conformant verifier decides, offline, that the
inclusion proof is for this timestamp's own hash, that it reconstructs a head the expected
log key signed, and (when the case names trusted witnesses) that enough distinct trusted
witnesses cosigned that exact head.

## The verifier contract

A verifier is a command that reads ONE case as JSON on **stdin**. The case names the
`artifact` it is about (default `authenticity-pack` when absent), and the verifier
dispatches on it, printing its verdict as JSON on **stdout**. The runner checks every
key the case's expected verdict names; the verifier may report additional keys.

```json
{ "artifact": "authenticity-pack",
  "pack": { "...": "a polaris-authenticity-pack/1" },
  "anchors": ["<issuer public key hex>", "..."] }
   -> { "authentic": true, "issuer_trusted": true }

{ "artifact": "status-assertion",
  "assertion": { "...": "a polaris-status-assertion/1" },
  "now": "2026-06-01T00:00:00Z" }
   -> { "authentic": true, "fresh": true, "active": true }

{ "artifact": "trust-attestation",
  "object": { "...": "a polaris-trust-attestation/1" },
  "attesting_agency_id": 2,
  "expected_key": "<the attested public key the relying party actually holds>" }
   -> { "authentic": true, "fresh": null }

{ "artifact": "id-token",
  "object": { "...": "a polaris-id-token/1" },
  "audience": "<the relying party this verifier IS>",
  "nonce": "<the nonce from the login this verifier started>",
  "now": "2026-05-01T12:01:00Z" }
   -> { "authentic": true, "audience_matches": true, "nonce_matches": true, "fresh": true }

{ "artifact": "timestamp-anchor",
  "timestamp": { "...": "a polaris-timestamp/1 carrying an unsigned `anchor`" },
  "log_key": "<the timestamp log's public key hex>",
  "trusted_witnesses": ["<witness public key hex>", "..."],
  "threshold": 2 }
   -> { "anchored": true, "witnessed": true }

{ "artifact": "agent-grant-use",
  "grant": { "...": "a polaris-agent-grant/1" },
  "requested_action": "read:status",
  "revocation": { "...": "a polaris-grant-revocation/1, only when the case asks about it" },
  "agent_proof": { "...": "a polaris-agent-proof/1, only when the case asks about it" },
  "expected_nonce": "<the nonce this service issued>",
  "binding": { "...": "a polaris-holder-binding/1, with the credential it binds" },
  "credential": { "...": "the credential's polaris-authenticity-pack/1" },
  "verifier_scope": "<this relying party's scope>",
  "now": "2026-05-01T00:00:30Z" }
   -> { "authentic": true, "action_in_scope": true, "revoked": false, "agent_proved": true,
        "principal_bound": true, "pairwise_handle": "<hex>", "correlation": "exposed" }

{ "artifact": "exchange-use",
  "object": { "...": "a polaris-exchange-request/1, polaris-exchange-receipt/1 or polaris-exchange-mint/1" },
  "requester_key": "<the requester's key this party expects (an envelope)>",
  "responder_key": "<the responder's key this party expects (a receipt or a mint)>",
  "manifests": [ { "...": "the polaris-federation-manifest/1 objects this party trusts" } ],
  "body": { "...": "the request body this party holds (an envelope)" },
  "request_body": "<the request body, as exchanged (a receipt)>",
  "response_body": "<the response body, as exchanged (a receipt)>",
  "now": "2026-05-01T00:00:30Z" }
   -> envelope: { "authentic": true, "requester_matches": true, "requester_authorized": true,
                  "body_bound": true }
   -> receipt:  { "authentic": true, "responder_matches": true, "requester_authorized": true,
                  "via": { "...": "the attesting manifest's authority" }, "request_bound": true,
                  "response_bound": true, "responder": { "...": "the receipt's signed responder" } }
   -> mint:     { "authentic": true, "responder_matches": true }
```

For a grant in use (since 1.0.0-rc.63) each link is answered separately, and `null` where the
case did not supply what the question needs:

- `action_in_scope`: the requested action is in the grant's signed `actions`; an absent or
  empty list grants nothing.
- `revoked`: the revocation is genuine AND signed by the grant's holder key AND names this
  grant. A genuine revocation by any other key ends nothing.
- `agent_proved`: the proof is genuine AND signed by the agent key the grant names, under the
  algorithm the holder authorized, naming this grant, the requested action and this
  service's nonce. Anything else is a copied grant or a replay.
- `principal_bound`: the grant is signed by the holder key the credential's issuer bound to
  it, under a binding that is genuine, fresh and `active`. A revoked binding speaks for nobody, and
  neither does a genuine issuer-signed object of another type carrying a binding's fields.
- `pairwise_handle`, `correlation`: with `verifier_scope`, the handle this relying party keys
  the principal by (`pairwise_handle` of the bound holder key) and `"exposed"`, because a
  grant's handle is a stable value the relying party can store.

For an exchange in use (since 1.0.0-rc.64) the verifier dispatches on the object's `format`.
Each question is answered only when the case supplies what it needs (`null` otherwise), and
none past `authentic` for an object its signer did not sign:

- `authentic`: the signature is genuine. For an envelope, the key that verifies must also be
  the requester key the signed statement names; a stranger's genuine signature in the
  requester's name is not the requester's envelope.
- `requester_matches`, `responder_matches`: the signing key is the one this party expected.
- `requester_authorized`: some manifest among those supplied is genuine and fresh at `now`
  and attests the requester's key in EXACTLY the object's context, inside the attestation's
  own `valid_until` (the section 4 rule of the wire spec, applied to the requester). A
  receipt that states no context is not authorized by an attestation from another context.
  The decision is made at the case's `now`, never at the verifier's clock.
- `via` (receipt): the `authority` of the manifest that authorized the requester; `null`
  when none did, including when that manifest names no authority.
- `body_bound` (envelope): `request_hash` is the SHA3-256 of the body's canonical JSON
  (sorted keys, compact separators), as wire spec section 3.11 defines it.
- `request_bound`, `response_bound` (receipt): the commitment is the SHA3-256 of the body
  bytes AS EXCHANGED (a string is hashed as its UTF-8), with no re-serialization, so a
  receipt case supplies each body as the exact string. The two rules differ: `body_bound`
  hashes canonical JSON, the receipt's fields hash the raw body.
- `responder` (receipt): the receipt's signed `responder`, reported only for a genuine
  receipt; a forged receipt names nobody.

For the timestamp anchor the verdict is:

- `anchored` (bool) -- the anchor's inclusion proof is for `SHA3-256(canonical timestamp)`,
  the proof and the head describe the same tree, the head is an authentic
  `polaris-transparency-sth/1` for `polaris-timestamp-log` (signed by `log_key` when one is
  given), and the RFC-6962 path reconstructs the head's root.
- `witnessed` (bool or null) -- `null` when no `trusted_witnesses` were supplied; otherwise
  whether at least `threshold` DISTINCT trusted witnesses have cosigned that exact head
  (same log, tree size and root). A stolen log key can sign a fabricated head, so a
  fabricated anchor is `anchored: true, witnessed: false`, and that is the verdict a relying
  party doing long-term validation MUST act on.

`anchors` is present only when the case supplies a trusted issuer set; `now` pins the
evaluation time for a windowed artifact (so a published vector stays verifiable). For the
authenticity pack the verdict is:

```json
{ "authentic": true, "issuer_trusted": true }
```

- `authentic` (bool) -- the signature verifies as a genuine ML-DSA signature under the
  pack's declared `algorithm` (ML-DSA-65 or ML-DSA-87; a genuine ML-DSA-44 signature MUST
  be `false`, the set is below the floor) over `SHA3-256(token_value.encode("utf-8"))`
  under the pack's `public_key_hex`.
  A placeholder pack (`algorithm` is the placeholder label, or a null
  `public_key_hex`) is **not** authenticatable offline and MUST be `false`.
- `issuer_trusted` (bool or null) -- `null` when no `anchors` were supplied;
  otherwise whether the pack's `public_key_hex` is in the anchor set. A genuine
  signature by a key that is NOT in the anchors is `authentic: true,
  issuer_trusted: false` -- a valid signature by an untrusted key, which a relying
  party MUST reject.

The reference implementation of this contract is the Python SDK's
`python -m polaris_verify.conformance` ([`sdk/python/`](../sdk/python/)).

## The cases

[`cases.json`](cases.json) lists every case: an authenticity pack (referenced from
the published [`vectors/`](../vectors/), which CI independently re-verifies under
liboqs and OpenSSL), an optional anchor set (`"self"` means the pack's own key is
trusted), and the verdict a conformant verifier MUST return:

| case | authentic | issuer_trusted | why |
|---|---|---|---|
| genuine-no-anchors | true | null | a real signature, trust not asked |
| genuine-trusted-anchor | true | true | real signature, key in the anchors |
| genuine-untrusted-anchor | true | false | real signature, key NOT in the anchors |
| tampered-signature | false | null | one byte flipped; MUST fail |
| tampered-token | false | null | genuine signature over a different token_value |
| wrong-key | false | null | genuine signature checked against an unrelated key |
| placeholder | false | null | the dev/CI placeholder; not authenticatable offline |

Trust-attestation cases (`artifact: trust-attestation`, v9.421). An attestation is an EDGE
between two agencies, and a genuine edge between two OTHER agencies verifies perfectly. So the
case supplies the agency and the key the relying party actually has, and a verifier that checks
only the signature accepts an attestation that is not the one it is relying on.

Timestamp-anchor witnessing (`artifact: timestamp-anchor`, v9.421). A cosignature counts toward
the witness threshold only when it verifies. `timestamp-anchor-forged-cosignature` trusts both
cosigners, corrupts one signature, and requires `witnessed: false` at a threshold of two:
counting a cosignature without checking it makes the quorum arithmetic rather than evidence.

ID-token cases (`artifact: id-token`, verdict `{authentic, audience_matches, nonce_matches,
fresh}`, v9.420). An ID token is the one artifact whose signature being valid is not the
question. A token minted for relying party A carries a perfectly good signature when it is
replayed at relying party B, and a token from an earlier login carries one too. So the contract
asks three things and not one: is it authentic, was it issued to THIS relying party, and does it
carry the nonce from THIS login. Before v9.420 an ID token was checked as a generic signed
artifact, and a verifier that looked only at the signature passed every case in this suite.

Status-assertion cases (`artifact: status-assertion`, verdict `{authentic, fresh, active}`):

| case | expects | why |
|---|---|---|
| status-assertion-active | authentic true, fresh true, active true | a genuine ACTIVE assertion inside its window |
| status-assertion-expired | authentic true, fresh false | genuine, but `now` is past `expires_at` |
| status-assertion-tampered | authentic false | one signature byte flipped; MUST fail |

## What this contract does NOT constrain

A conformance suite is read as a boundary, so it has to say where its boundary is. Measured
rather than recalled, by `scripts/polaris-contract-reach-drill.py`, which runs every case and
records which of the reference SDK's public functions actually execute: **the 151 cases enter
19 of the SDK's 22 public functions.** Three are never entered by any case, which means an
implementation can get them wrong, or omit them, and still pass every case here.

| never entered | why the contract does not ask |
|---|---|
| `nullifiers_link`, `handles_link` | linkability is a question about TWO presentations, and every case carries one artifact. There is no case shaped like "here are two, are they the same holder" |
| `grant_within_limits` | whether a use stays inside a grant's limits depends on the service's own count of uses, which no case carries. Scope, revocation and the agent's proof are asked (`agent-grant-use`, since 1.0.0-rc.63) |

Those three are covered by the SDK's own tests. That is a different guarantee: it binds this
implementation, not the contract, and a third party certifying against these cases inherits
none of it.

The drill refuses to report at all if its measurement collected nothing, because a failed
measurement and a contract that constrains nothing print the same list. `--prove-control`
runs it with collection disabled and requires that refusal.

**The same gap, between the implementations.** Three verifiers here check these artifacts:
the detached verifier a relying party installs, and the two reference SDKs. All three pass all
151 cases, and a case constrains only the keys it names, so on every other key they could
differ and the suite would stay green. `scripts/polaris-sdk-agreement-drill.py` compares them
to EACH OTHER, key for key, on every case, and CI runs it.

It found one defect and one boundary.

The defect: `epoch-leaves-swapped` reported `fresh: true` from Python and `fresh: null` from
TypeScript, because the TypeScript epoch-leaves commitment check returned early where its four
siblings fell through, so one implementation answered the same question two ways. Fixed, and
pinned by a test whose failure message names both values. **The two SDKs now return identical
verdicts, key for key, on every published case.**

The boundary: **36 unconstrained divergences remain, every one of them between the detached
verifier and an SDK**, on two keys and for two reasons.

| key | detached | SDKs | why |
|---|---|---|---|
| `fresh`, on an artifact that failed authentication (16 cases) | `null` | the window's answer | the detached verifier RETURNS at the failure, so freshness is never asked. The SDKs fall through to a tail that answers it regardless, which is separately true of a forgery |
| `issuer_trusted`, on the two cross-authority cases | `true` | `false` | on the detached side this key is not reported by the verifier at all: the conformance adapter derives it from `key_status`, which asks "is this key revoked or unknown" rather than "is it in the anchor set the caller supplied" |

Neither convention is wrong and this contract does not choose between them. A relying party
gating on `fresh is not false` cannot tell the difference; one gating on `fresh is true` can,
and in every one of those cases `authentic` is already false, so the authenticity gate refuses
first either way. Harmonising them would be a behaviour change justified by nothing but
tidiness, so the drill accounts for these two rules and **fails on any divergence outside
them**. The known ones stay visible rather than being buried in a count.

## Self-certifying

```bash
# The bundled Python reference SDK:
python3 conformance/run_conformance.py --self

# Your own verifier, in any language (stdin -> stdout, per the contract above):
python3 conformance/run_conformance.py --verifier "node my_verifier.js"
```

The runner exits non-zero if any case does not match, so it drops straight into a
CI gate. Polaris runs `--self` on every release; a published SDK or an external
integration is conformant exactly when it passes the same cases.

## Versioning

`cases.json` carries `"format": "polaris-conformance/1"`. Cases are only ADDED
within a format version (a new case is a stricter contract, never a looser one);
a breaking change to the verdict schema or an existing expectation bumps the
format version. The `vectors/` a case references are frozen once published.

## Cross-version compatibility (P8.8b)

Every case carries `since`, the protocol release that introduced it. Version 1 is frozen
under [`frozen/v1`](frozen/v1/FREEZE.md): the cases and vectors as published, pinned by
`SHA256SUMS`, with a pinned older detached verifier vendored beside them.
`scripts/polaris-compat-suite.py` runs on every CI push and proves both directions: the
current detached verifier and both SDKs hold every frozen case, and the pinned older
verifier agrees on every current case at or before its release, never accepts what a later
case expects rejected, and may only decline what it predates. A protocol change that would
require changing the frozen set is a new major with its own frozen set.

