# The aggregate mirrored status feed (P3.2c)

**Reader:** an engineer or an assessor who understands the P3.2b per-authority
revocation feed and epoch checkpoint, and wants to know how those scale to a
federation of many authorities without a trusted intermediary.

**Status:** shipped v9.308. The object is `polaris-federation-status-bundle/1`,
published at `GET /api/v1/federation-status-bundle/<agency_id>` and consumed
offline by `scripts/polaris-verify.py`.

## The problem

P3.2b let a relying party check a foreign credential's non-revocation against the
issuer's own signed revocation feed, offline, with no issuer contact. That is one
fetch per authority. In a federation of thousands of authorities a relying party
that accepts credentials from many of them would fetch many feeds and many epoch
checkpoints, each from that authority's own endpoint: N round-trips and N points
of availability failure, every one of which is a place the check can stall.

The status distribution backbone (roadmap P2.6) is a single, short-lived,
CDN-distributable, signed artifact that carries current status. P3.2c is that
backbone at federation scale: one **status bundle** that mirrors many authorities'
feeds, so a relying party fetches it once and checks any member's credential
offline.

## The object

A status bundle is a mirror. It carries, for each member authority, that
authority's own `polaris-revocation-feed/1` and `polaris-epoch-checkpoint/1`
**verbatim**, each still under that authority's own ML-DSA-65 signature. Around
that set the publisher adds one envelope signature of its own.

```jsonc
{ "format": "polaris-federation-status-bundle/1",
  "publisher": { "agency_id": 1, "name": "..." },
  "members": [ { "authority_id": 1,
                 "revocation_feed": { "format": "polaris-revocation-feed/1", "...": "..." },
                 "epoch_checkpoint": { "format": "polaris-epoch-checkpoint/1", "...": "..." } },
               "..." ],
  "members_root_hex": "<commitment over the member set>",
  "member_count": 1,
  "issued_at": "...", "expires_at": "...", "algorithm": "ML-DSA-65",
  "signature_hex": "...", "public_key_hex": "..." }
```

The publisher signs `SHA3-256(canonical)` of the statement
`{format, publisher, members_root_hex, member_count, issued_at, expires_at,
algorithm}`. The members list itself is **not** in the signed statement: it is
committed by `members_root_hex`, so the signed bytes stay small and fixed-shape
rather than canonicalizing a deep list of nested signed objects. The commitment is
`SHA3-256` over the sorted, newline-joined per-member digests, each the `SHA3-256`
of the member entry's canonical JSON. It is order-independent, so anyone assembling
the same members computes the same root, and it binds the bundle to the **exact**
feeds it mirrors: adding, dropping, or swapping a member changes the root.

As with every signed object in Polaris, the application builder
(`polaris_web/app.py` `_status_bundle_statement`) and the standalone verifier
(`scripts/polaris-verify.py` `_status_bundle_canonical`) must produce byte-identical
signed bytes. That equality is pinned by the canonical-equivalence oracle
(`polaris_web/test_canonical_equivalence.py`), so a drift in either side fails CI.

## The trust model: the publisher is untrusted for correctness

This is the property the whole design exists to hold. The publisher (the
aggregator) is **not trusted** to tell the truth about any member's status. Trust
in a credential's status roots in the **member authority's** signature over its own
feed, never in the aggregator's.

The publisher's own signature is only an **envelope**. It provides exactly three
things, and nothing else:

1. **Freshness.** `expires_at` bounds how old the aggregation is, so a member's
   absence from the bundle is a *current* absence, not a stale snapshot replayed
   from a time before that member joined.
2. **Set integrity.** `members_root_hex` commits to exactly the member set, so the
   set cannot be tampered after signing.
3. **Attribution.** The envelope is signed, so an omission or a stale mirror is
   attributable to a named publisher rather than anonymous.

What the envelope does **not** provide is status truth. That comes from each member
feed's own signature, verified in its own right.

### What an aggregator can and cannot do

- It **cannot forge a member's status.** To make a revoked credential look active it
  would have to drop the leaf from that member's embedded feed. But the feed is
  signed by the member's key over a canonical form that includes the revoked-leaf
  list and its commitment; the aggregator does not hold the member's key, so the
  altered feed no longer verifies. Even an aggregator in **full control of the
  bundle** who recomputes `members_root_hex` and re-signs the envelope is defeated
  here: the envelope is valid, but the member feed inside it is not, and the
  delegated decision rejects. This is the headline case in the drill.
- It **cannot silently omit an authority.** A credential whose issuer is not present
  in the bundle is **fail-closed**: the decision is reject ("not verifiable"), never
  a silent accept. An aggregator can refuse to carry an authority, but it cannot
  thereby make that authority's credentials pass.
- It **can** withhold or delay the bundle entirely (a liveness attack, not a safety
  one), the same denial any distribution point can mount; the relying party sees a
  missing or stale bundle and fails closed, and can fetch the per-authority feeds
  directly as it did before P3.2c.

### How the aggregator obtains member feeds

The property above rests on one operational rule: **the aggregator holds no member's
private key.** It obtains each member's feed as an artifact that member already
signed, and preserves it byte for byte. It never builds or re-signs a partner's
feed, because doing so would require a key it must not have, and it would collapse
the whole guarantee (a party that can sign a member's feed can forge that member's
status).

Concretely, a federation hub **fetches** each authority's revocation feed and epoch
checkpoint from that authority's own endpoint (`GET /api/v1/revocation-feed/<id>`,
`GET /api/v1/epoch-checkpoint/<id>`), **verifies** each against that authority's
registered public key, embeds it **verbatim**, and signs only the outer envelope
with its own key. A member it cannot fetch is simply absent, which is fail-closed
for a verifier, never fabricated.

A single Polaris instance can therefore only vouch for itself: its
`GET /api/v1/federation-status-bundle/<id>` endpoint mirrors exactly the publishing
authority's own feed and checkpoint, under the publisher's own signature, and
mirrors no one else. The cross-authority case, where a hub aggregates a **peer's**
fetched-and-verified feed and signs only its envelope while holding no peer key, is
exercised end to end across two independent instances over real HTTP by
`scripts/polaris-federation-instances-drill.py`.

## Verification

Two functions in the standalone verifier, no Polaris code, no database, no network.

`verify_status_bundle(bundle, now, max_window_seconds, publisher_key)` checks only
the **envelope**: the publisher's signature over `SHA3-256(canonical)` under the
two-witness rule, that `members_root_hex` recomputed from the embedded members
matches (so the set was not tampered), freshness, and, if `publisher_key` is pinned,
that the expected publisher signed it. It establishes no member's status.

`verify_cross_authority_via_bundle(pack, context_id, trusted_manifests, bundle, ...)`
decides a foreign credential, fail-closed at every step:

1. the bundle envelope must be authentic and fresh (and match the pinned publisher,
   if one is given), else reject;
2. the credential's issuer must be **present** in the bundle (matched by the member
   feed's signing key), else reject as not verifiable;
3. the trust and revocation decision is the **same** `verify_cross_authority`
   decision as P3.2b, run against the **member's own** signed feed. A forged,
   tampered, stale, or wrong-key member feed rejects there exactly as it would if
   the relying party had fetched it directly.

On the accept path the result reports `epoch_bound`: whether the member's embedded
epoch checkpoint is authentic, fresh, and bound to the same issuer key, so the
status is tied to a committed epoch rather than a bare instant. The answer the
bundle produces equals what the issuer's own feed would give. **The aggregator adds
availability, not trust.**

## Freshness is a pick-two

A bundle's own window is intentionally short (`POLARIS_STATUS_BUNDLE_TTL`, default
one hour) because its job is a current view of a member's absence. The member feeds
it embeds carry their own, longer windows (`POLARIS_REVOCATION_FEED_TTL`, default
one day). A relying party that sets a single `max_window_seconds` ceiling applies it
uniformly, so a high-assurance verifier that demands everything be fresher than the
feed's own window will reject the embedded feed and fall back to a directly-fetched,
shorter-lived feed or an online check. That is the same freshness-versus-availability
triangle as offline verification (see [offline-verification.md](offline-verification.md)):
a bundle buys availability and a fresher *envelope*, not fresher *feeds*.

## Privacy

A bundle is published trust data. Each member feed is a CRL of revoked leaves
(`SHA3-256(token_value)`), never the active population: a leaf is derivable only by a
holder of the credential, and no `token_value` appears. The bundle carries no
personal data. Because a relying party verifies entirely offline, neither the issuer
nor the aggregator learns that a verification happened, so distributing status this
way is more private than an online status callback, not less.

## No new mutation path

A bundle is a **view**, assembled from the per-authority views over the append-only
`TokenStateEpoch` and `RevocationList` tables. The endpoint reuses the same
`_revocation_feed_body` and `_epoch_checkpoint_body` builders the per-authority
endpoints use, so there is one construction path and no new writable store. Nothing
about a bundle can change history; it only re-presents it.

## What runs

- `scripts/polaris-federation-status-bundle-drill.py` stands up two real authorities
  and a separate aggregator, all with distinct real ML-DSA-65 roots, and drives the
  accept/reject matrix under real signatures every release (the `pqc-real` CI job):
  accept an active foreign credential through the mirror, reject a revoked one,
  fail-closed on an omitted authority and on a stale bundle, reject a tampered set,
  and the headline case where an aggregator in full control of the bundle still
  cannot forge a member's status.
- `check_federation_status_bundle` pins the endpoint, the verifier functions, the
  standalone constraint, the oracle coverage, the drill, its CI wiring, and the
  endpoint test, with a detection test that fails the check on each missing leg.
- `StatusBundleTests` in `polaris_web/test_app.py` validates the published shape, the
  commitment, the app-versus-verifier canonical byte equality, and the no-personal-
  data rule against a real server-built bundle.

## Deferred

Epoch-bound cross-authority **zero-knowledge** presentation is deferred to P3.2d: a
holder proving in zero knowledge that a credential is included in an authority's
issued set at a committed epoch, across the federation trust graph, without revealing
the credential. P3.2c binds *status* to a committed epoch (`epoch_bound`); binding a
*ZK presentation* to one is the next step and touches the Plonky2 circuit.
