# The trust-service lifecycle (P8.7b)

**Reader:** an engineer operating an authority, or an assessor asking what happens to
everything an authority signed when its key is rotated or, worse, compromised.

**Status:** shipped v9.328. The append-only `AuthorityKeyEvent` register and its
`AuthorityKeyCurrent` view; `polaris-trust-list/1` at `GET /api/v1/trust-list/<id>`; the
CLI's `key-register`, `key-retire`, `key-compromise`; `verify_trust_list` and
`key_status_at` in the detached verifier, consulted by the cross-authority decision and by
long-term validation.

## One subsystem, not five mechanisms

Before this ship an authority had a single current key and every surface said "active".
Rotation was possible (a re-issued credential carries the key that signed it) but nothing
recorded that a key had been retired, nothing could say a key was compromised, and no verifier
could decide a key's status at any instant but now. The lifecycle is now one thing:

- **The register.** Every event in a key's life is an append-only row: `registered`,
  `retired` (an orderly rotation), `compromised` (untrusted from an `effective_at` that may
  predate the discovery). Nothing is edited or removed; transitions are one-way by
  construction, because a later row can only add a worse status. `AuthorityKeyCurrent`
  derives each key's status and the instants each took effect. The CLI records events;
  registering a key also makes it the agency's current signing key.
- **Honest surfaces.** The federation manifest's `anchors` now list every key of the
  authority with its real status, so a verifier sees a retired or compromised key for what
  it is; the registry's `authorities` report the current key's real status and carry the
  register itself (`keys`, built by the same function as the anchors and the trust list, so
  the three surfaces cannot disagree). An instance with no recorded events reports its single
  key active, exactly as before.
- **The trust list.** A signed statement of every key an instance knows -- its own and its
  federated peers' -- with statuses and instants. It must be signed by a key it lists as
  active for its own publisher: an impostor cannot publish one in an authority's name, and a
  publisher cannot sign one under a key it has retired.
- **Status at an instant.** `key_status_at(list, key, instant)`: compromised from its
  instant, retired from its instant, active from registration, unknown before it. This is
  what makes the rest possible.

## Compromise recovery

Given a trust list it trusts, the cross-authority decision rejects a credential whose issuer
key is compromised -- independently of the issuer's own manifest, which a holder of the
compromised key could forge. Long-term validation of a signed document requires the signer
key active at the evidence's instant *per the list*: a document signed and timestamped before
the compromise instant stays valid, one after does not, even though its embedded manifest
(the signer's own word) says active. Credentials re-issued under the new key are accepted;
nothing the old key signed is silently kept. Without a trust list every decision behaves
exactly as before, so nothing already deployed changes shape.

The two-instance drill does this live: B publishes its trust list; a relying party holding it
accepts A's credential; B records A's key compromised; the re-fetched list says so, B's
registry reports it, and the same relying party rejects the same credential -- with no change
to A at all. That is the point of an independent register: the recovery does not depend on
the compromised party's cooperation.

## Boundaries

Rotation of a live instance's signing key file or HSM slot is an operational ceremony
(`docs/design/multi-sig-migration.md`); this ship records and publishes the lifecycle, it does
not operate the HSM. Algorithm migration -- a second signature algorithm verified side by side
-- is the next ship (P8.8).

## What runs

`scripts/polaris-trust-lifecycle-drill.py` (the `pqc-real` CI job, 15 cases) under real
ML-DSA-65: authentic, impostor, retired-key and tampered lists; status at an instant across
registration, retirement and a compromise whose instant predates its recording; the
credential accepted before and rejected after; the re-issued key accepted; documents before
and after the compromise instant; the fallback without a list; hostile input. The
two-instance drill records a compromise on B and watches the decision flip over HTTP. The
trust list is in the canonical-equivalence oracle, the wire spec (section 3.15), the
conformance suite (both SDKs apply the publisher rule; an impostor vector is published), and
the metamorphic fuzzer; a DB test proves the register is append-only and one-way.
`check_trust_lifecycle` pins all of it, with a detection test.
