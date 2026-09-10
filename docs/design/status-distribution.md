# Status distribution: serving a signed status through an untrusted network

**Reader:** an operator putting a cache or a content-delivery network in front of an
authority, or a verifier author deciding how long an answer may be trusted. **Job:** state
which artifacts may be cached, for exactly how long, and which must never be.

Signing a status artifact is what makes this possible at all. Because the issuer's signature
travels with the bytes, an untrusted intermediary can carry them: a cache cannot forge a
status any more than an aggregator can. That is the whole reason to sign a feed rather than
answer a query. But a cache introduces the one failure signing does not prevent, which is
**time**. A cached status is a status the issuer may already have withdrawn.

## The rule

**A cache directive is never a constant. It is the artifact's own remaining life.**

Every windowed artifact carries an `expires_at` that the issuer signed. The response's
`max-age` is `expires_at - now`, so a cache physically cannot outlive the window the issuer
committed to: when the artifact expires the cache entry expires with it and the next consumer
returns to the origin. A fixed `max-age` would eventually exceed some artifact's window, and
the symptom would be a revoked credential that keeps verifying for a while, which is the
failure this whole layer exists to prevent.

Two corollaries, both enforced rather than advised:

- **An expired artifact is `no-store`.** Caching something every verifier must reject creates
  nothing but a stale copy to serve later.
- **An artifact whose window cannot be parsed is `no-store`.** Guessing an interval for a
  body you did not understand is the same mistake with an extra step.

## What is deliberately absent

`stale-while-revalidate` and `stale-if-error` are not used and should not be added. Both
exist to serve a known-stale body when the origin is slow or unreachable, and a known-stale
revocation feed is precisely the artifact an attacker wants served: the cheapest attack on
this design is to make the origin unreachable and let the network serve yesterday's answer.

A status origin that is down should fail. A verifier that cannot reach one should refuse, or
fall back to the offline path with its own stated window, and never accept an answer whose
freshness it cannot establish. That is the same discipline the offline trade already
states: a deployment picks a window, and the window is policy, not law.

## Which artifacts may be cached

| Artifact | Same for every consumer? | Directive |
|---|---|---|
| `polaris-revocation-feed/1` | yes | `public`, to its own window |
| `polaris-epoch-checkpoint/1` | yes | `public`, to its own window |
| `polaris-federation-status-bundle/1` | yes | `public`, to its own window |
| `polaris-federation-manifest/1` | yes | `public`, to its own window |
| `polaris-trust-list/1` | yes | `public`, to its own window |
| `polaris-registry/1` | yes | `public`, to its own window |
| `polaris-epoch-leaves/1` | yes | `public`, to its own window |
| `polaris-status-assertion/1` | **no** | `no-store` |
| `polaris-holder-binding/1` | **no** | `no-store` |
| `polaris-timestamp/1` | **no** | `no-store` |

The split is not about sensitivity in the abstract. It is about whether the artifact names
one credential. A status assertion names one `token_value`; a shared cache holding one would
serve one holder's credential to another, and a signature cannot undo a disclosure. Those
three are `no-store` rather than `private`, because `private` still permits the requester's
own browser to keep a copy on disk, and a holder's device is exactly where a coerced search
looks.

Getting this split backwards is the one change here that would be a privacy incident rather
than a performance regression, which is why `check_status_distribution` pins both halves and
the drill asserts both.

## Revalidation

Public artifacts carry a strong `ETag` over their canonical bytes, so an intermediary can
revalidate without the origin re-signing, and two consumers holding the same ETag hold the
same signed bytes. `X-Polaris-Expires-At` repeats the artifact's own expiry in a header, so
an operator can see a cache's behaviour without parsing the body.

`Vary: Accept-Encoding` is set so a compressed and an uncompressed copy do not collide.

## What this does not solve

Distribution at content-delivery scale is still an operator's deployment, not something the
repository ships: there is no CDN configuration here, no origin-shield topology, and no
measured cache hit rate at national volume. What is shipped is the property a CDN needs to be
*safe* in front of this origin, which is that no correct cache can serve a status past the
window its issuer signed. The remaining work is placement, and placement is the operator's.

The monotonicity that makes a cached feed safe to compare against a newer one is a property
of the underlying table rather than of the cache: `RevocationList` is append-only, so a feed
that drops a published revocation is a caught rollback. See
[epoch-cadence.md](epoch-cadence.md) for how often the artifacts change, and
[../reference/WIRE-SPEC.md](../reference/WIRE-SPEC.md) for what each one carries.

## Proven by

`scripts/polaris-status-distribution-drill.py`, on every push: every public artifact's
`max-age` is bounded by its own signed window, no public artifact permits stale serving, every
per-holder artifact is `no-store`, and an expired or unparseable window is not cached at all.
