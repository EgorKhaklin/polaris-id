# Inter-authority protocol v1: the federation manifest (P3.2)

**Reader:** anyone building a second Polaris authority, or a relying party that
accepts credentials from more than one. **Job:** how two independent authorities,
each its own trust root (see [federation-topology.md](federation-topology.md)),
publish what another party needs to verify their credentials, with no central
service.

**Status:** v1, 2026-09-08. Roadmap P3.2. It carries anchor cross-publication and
attestation exchange; epoch alignment and revocation propagation are named here and
deferred to P3.2b.

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
  number and root, a revocation as-of marker). v1 publishes them; the alignment and
  propagation protocols that consume them are P3.2b.

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

## Deferred to P3.2b

- **Epoch alignment:** the protocol by which authorities agree on and cross-check
  each other's token-state epochs (the manifest carries the reference; the alignment
  handshake is not built).
- **Revocation propagation:** distributing revocation beyond the per-credential status
  assertion (P3.6) and the manifest's as-of marker; this is the P2.6 status-distribution
  backbone applied across authorities.

## How this is tested

`scripts/polaris-federation-manifest-drill.py` stands up two authorities with distinct
real ML-DSA-65 roots, has one attest to the other, and drives the whole accept/reject
matrix (right context accepts; wrong context, un-attested issuer, untrusted authority,
stranger-signed manifest, expired manifest, and forged credential all reject) under
real ML-DSA every release in the `pqc-real` CI job. The endpoint's shape, the
attestation exchange, and the no-personal-data rule are covered by
`polaris_web/test_app.py` `FederationManifestTests`. Pinned by
`check_inter_authority_protocol`.
