# Inter-authority protocol v1: the federation manifest (P3.2)

**Reader:** anyone building a second Polaris authority, or a relying party that
accepts credentials from more than one. **Job:** how two independent authorities,
each its own trust root (see [federation-topology.md](federation-topology.md)),
publish what another party needs to verify their credentials, with no central
service.

**Status:** v1 (P3.2, anchor cross-publication and attestation exchange) plus epoch
alignment and revocation propagation (P3.2b), 2026-09-08. Two more signed objects, the
epoch checkpoint and the revocation feed, are now published and consumed offline; they
are described in [Epoch alignment and revocation propagation](#epoch-alignment-and-revocation-propagation-p32b).

## The artifact: a signed federation manifest

An authority publishes one signed object, `polaris-federation-manifest/1`:

```jsonc
{
  "format": "polaris-federation-manifest/1",
  "authority": { "agency_id": 1, "name": "..." },
  "anchors":   [ { "public_key_hex": "...", "algorithm": "ML-DSA-65", "status": "active" } ],
  "attestations": [
    { "attested_agency_id": 2, "attested_public_key_hex": "...", "context_id": 3, "valid_until": "..." }
  ],
  "epoch":      { "number": 12, "root_hex": "..." },
  "revocation": { "as_of": "..." },
  "issued_at":  "2026-09-08T00:00:00Z",
  "expires_at": "2026-09-09T00:00:00Z",
  "algorithm":  "ML-DSA-65",
  "signature_hex": "...",     // over SHA3-256(canonical), the manifest minus this envelope
  "public_key_hex": "..."
}
```

- **Anchor cross-publication.** `anchors` are the authority's own signing keys, its
  trust roots. A relying party verifies that authority's credentials against these.
- **Attestation exchange.** `attestations` are the rows the authority has made in its
  `AgencyTrustAttestation` graph: "I accept agency I's tokens in context C", carrying
  I's key so a verifier can bind the attestation to a foreign credential's signature.
  It is directional and per-context; it is never transitive.
- **Epoch and revocation** are carried as references (the current token-state epoch
  number and root, a revocation as-of marker). The manifest publishes them; the signed
  epoch checkpoint and revocation feed that make them consumable are P3.2b, below.

The manifest is served at `GET /api/v1/federation-manifest/<agency_id>`. It is public
(published trust data, no personal data), signed with the authority's own key, and
short-lived (`POLARIS_FEDERATION_MANIFEST_TTL`, default one day) so anchors and
attestations do not go stale.

## What a consumer checks (offline)

The reference consumer is `scripts/polaris-verify.py` (`verify_manifest`,
`verify_cross_authority`), standalone, no network:

1. **Self-consistency.** The manifest is signed by one of the ACTIVE anchor keys it
   declares as its own roots, so it cannot be signed by a stranger key.
2. **Authenticity.** The signature verifies over `SHA3-256(canonical)` under that key,
   with two witnesses.
3. **Freshness.** `now` is within `[issued_at, expires_at)`, and the window is no
   longer than a ceiling the consumer accepts.
4. **Trust.** The consumer honors a manifest only from an authority whose anchor is in
   its own trusted set.

To accept a FOREIGN credential (issued by authority I, presented to a relying party
that trusts authority V), the decision is:

    accept iff the credential's signature is genuine
             AND V's manifest is authentic and fresh and trusted
             AND V's manifest attests to the credential's signing key in the presented context

So trust flows exactly along the attestation edges the manifests publish, never a
transitive closure, and the whole decision is made against published keys with no
issuer contact.

## Freshness and staleness

Anchors, attestations, and revocation state change; the manifest's TTL bounds how
stale a cached manifest can be. A consumer imposes its own tighter ceiling for the
freshness it requires. A rotated anchor is published with `status` other than
`active` so an old key stops being a valid signer while its issued credentials still
verify against it as a retired anchor (the rotation model of KEY-CEREMONY.md).

## Epoch alignment and revocation propagation (P3.2b)

The manifest carries the epoch and revocation references; P3.2b makes them consumable
with two more signed objects an authority publishes, both signed by the SAME key that
signs its manifest and its credentials, both verified offline by the same standalone
`scripts/polaris-verify.py`, and both derived as views over existing append-only tables
(`TokenStateEpoch`, `RevocationList`) with no new mutation path.

### The epoch checkpoint

`GET /api/v1/epoch-checkpoint/<agency_id>` publishes a signed `polaris-epoch-checkpoint/1`:
the authority's commitment to the latest point on its append-only `TokenStateEpoch` chain,
carrying the epoch number and Merkle root and the prior epoch it extends.

```jsonc
{ "format": "polaris-epoch-checkpoint/1",
  "authority": { "agency_id": 1, "name": "..." },
  "epoch": { "number": 12, "root_hex": "...", "committed_count": 3, "valid_until": "..." },
  "prev": { "number": 11, "root_hex": "..." },
  "as_of": "...", "issued_at": "...", "expires_at": "...",
  "algorithm": "ML-DSA-65", "signature_hex": "...", "public_key_hex": "..." }
```

- **Monotonicity and fork detection.** `verify_epoch_checkpoint` authenticates one
  checkpoint (two witnesses, freshness, and, with an expected issuer key, that it is
  signed by that authority). `check_epoch_chain` compares two: an adjacent pair must
  chain (`prev` references the earlier epoch exactly), and two DIFFERENT roots signed at
  one epoch number is a **fork** — cryptographic proof the authority equivocated about
  its own history.
- **Alignment.** `epoch_aligned` cross-checks a checkpoint against the epoch its
  authority's own (separately trusted) manifest commits to. An authority cannot serve a
  checkpoint that disagrees with its signed manifest without being caught.

### The revocation feed

`GET /api/v1/revocation-feed/<agency_id>` publishes a signed `polaris-revocation-feed/1`:
the sorted set of revoked-credential leaves (`SHA3-256(token_value)`) for the credentials
the authority issued that are now revoked, plus a commitment over them.

```jsonc
{ "format": "polaris-revocation-feed/1",
  "authority": { "agency_id": 1, "name": "..." },
  "epoch_number": 12, "as_of": "...",
  "revoked_root_hex": "...", "revoked_count": 2, "revoked_leaves": [ "<sha3-256 hex>", "..." ],
  "issued_at": "...", "expires_at": "...", "algorithm": "ML-DSA-65", "signature_hex": "...", "public_key_hex": "..." }
```

- **Propagation with no issuer contact.** A relying party presented a FOREIGN credential
  checks its non-revocation against the issuer's feed offline. `verify_cross_authority`
  takes the feed and is fail-closed: a genuine, fresh feed BOUND to the issuer's key must
  also show the credential is not revoked; a missing binding, a forged or stale feed, or
  a listed (revoked) credential all reject. Revocation crosses the authority boundary
  through published, signed data, not a callback the issuer could log.
- **Monotonicity and rollback detection.** Because `RevocationList` is append-only a
  genuine feed only grows and its `as_of` only advances. `check_revocation_progression`
  compares two feeds from one issuer and flags a **rollback**: a newer feed that drops a
  previously-published revocation, or moves `as_of` backward, is equivocation.
- **Privacy.** The feed is a CRL of revoked leaves, not the active population: a leaf is
  `SHA3-256(token_value)`, derivable only by a holder of the credential, and the feed
  carries no `token_value` and no personal data.

### Still deferred (P3.2c and beyond)

- An **aggregate** cross-authority status distribution (a shared, mirrored feed rather
  than per-authority endpoints) is the P2.6 backbone and is not built here.
- **Epoch-bound ZK presentation** across authorities (checking a foreign membership
  proof against a checkpoint's root) reuses these checkpoints but is scoped with the ZK
  presentation work, not here.

## How this is tested

`scripts/polaris-federation-manifest-drill.py` stands up two authorities with distinct
real ML-DSA-65 roots, has one attest to the other, and drives the whole accept/reject
matrix (right context accepts; wrong context, un-attested issuer, untrusted authority,
stranger-signed manifest, expired manifest, and forged credential all reject) under
real ML-DSA every release in the `pqc-real` CI job. The endpoint's shape, the
attestation exchange, and the no-personal-data rule are covered by
`polaris_web/test_app.py` `FederationManifestTests`. Pinned by
`check_inter_authority_protocol`.
