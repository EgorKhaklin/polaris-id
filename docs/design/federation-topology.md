# Federation topology: federated per-authority instances (ADR)

**Reader:** anyone extending the federation track, or assessing why Polaris is
shaped the way it is. **Job:** record the topology decision, the reasoning, and
the threat-model difference, so the choice is deliberate and cannot drift.

**Status:** Accepted, 2026-09-08. Roadmap P3.1. This decision governs the P3
federation track: the inter-authority protocol (P3.2) and two-instance
interoperation in CI (P3.10) are built on it. It reopens no non-goal and does not
soften the constitution.

## Context

The federation track needs a topology before an inter-authority protocol can be
specified. Two shapes are possible.

- **Central instance.** One Polaris instance holds every person's identity and
  every agency's tokens under one trust root. Agencies are tenants; a relying party
  trusts the central service.
- **Federated per-authority instances.** Each issuing authority runs its own
  instance and holds its own signing key, which is its own trust root. Cross-authority
  trust is recorded explicitly and is not transitive. A relying party verifies against
  published keys, with no central service in the path.

Polaris's schema and engine already implement the federated shape (see Grounding).
This record states the choice so it is not silently reversed.

## Decision

Polaris is federated per-authority. Concretely:

1. **Each authority is its own root.** An authority signs with its own ML-DSA-65 key
   (`Agency.signing_public_key_hex`, selected by `custody.get_custody_for_agency`).
   That key is the authority's trust root. No shared root exists that authorities
   chain to. (A single global signing key exists only as the degenerate fallback for
   a non-federated, single-issuer deployment; federated agencies each register their
   own.)
2. **Cross-authority trust is explicit and non-transitive.** An attestation is a
   directional, per-context row: "verifier V accepts issuer I's tokens in context C"
   (`AgencyTrustAttestation`). Verification succeeds iff V is the issuer, or exactly
   one active attestation row `V -> I -> C` exists. The resolver
   (`_federation_trust_holds`) performs a single non-recursive lookup: it never
   computes a closure, so V trusting I never implies V trusts what I trusts.
3. **A relying party verifies against published keys, with no central service.** The
   detached verifier (`scripts/polaris-verify.py`, `verify_pack(pack, anchor_keys)`)
   decides trust as membership in the relying party's own published anchor set, offline.
4. **There is no central identity database, no central trust root, and no central
   verification service.**

## Why this is not a free choice

The constitution forces the federated shape; it is not chosen for engineering taste.

The vocation names the federation trust graph as load-bearing: identity is portable
across attesting agencies, and "no agency holds a monopoly" (MISSION.md). A central
instance is a monopoly by construction: one party holds every identity and makes every
trust decision. The constitution also states that Polaris is "NOT a surveillance
backbone" and that Polaris is not an authority (MISSION.md), and the project refuses
"population-scale aggregation ... and the refusal is structural" (README.md). A single
database of every person is that aggregation. The federated topology is therefore
derived from the anti-monopoly and anti-surveillance clauses. A central instance would
contradict them, so it is not an available option regardless of its convenience.

## Threat-model delta

| Dimension | Central instance | Federated per-authority (chosen) |
|---|---|---|
| Breach blast radius | One breach exposes every identity and every trust decision | Bounded to the breached authority's population; other roots and tokens are untouched |
| Aggregation | A single store to seize, subpoena, or mine; a central verification log can reconstruct a population's movements | No single store; a relying party's verification touches no central service, so there is no central log to reconstruct |
| Coercion | One trust and revocation authority is a single coercible party, against the vocation | Each authority controls only its own tokens; coercing one does not reach the others |
| Trust semantics | Implicit global trust | Explicit, per-context, non-transitive: a relying party's trust is exactly the attestations it holds, never a closure it did not choose |
| Cost | Lower: cross-authority coordination is free inside one instance | Higher: needs a cross-authority protocol (attestation exchange, anchor cross-publication, epoch alignment, revocation propagation). This is the price of the vocation, accepted here. |

The federated choice is deliberately the more expensive one. The complexity it adds is
the P3.2 protocol and the P3.10 interoperation proof; a central instance would avoid
that work but violate the constitution.

## Grounding (this model already runs)

- **Explicit, non-transitive attestation.** `AgencyTrustAttestation` is the sixth
  append-only audit-of-record table (`polaris_sql/01_schema.sql`); the resolver
  `_federation_trust_holds` (`polaris_web/app.py`) does a single non-recursive lookup;
  writes go through `uc10_attest_trust` / `uc10_revoke_attestation`. See
  [federation.md](federation.md).
- **Per-authority roots.** `Agency.signing_public_key_hex` and
  `custody.get_custody_for_agency` give each agency its own key; issuance signs with it
  and `/verify` reports `issuer_authentic` (roadmap PE.3b). Pinned by
  `check_federation_in_app`.
- **Cross-issuer trust decided against published keys, not a database.**
  `scripts/polaris-federation-drill.py` stands up two issuers with distinct real
  ML-DSA-65 roots plus a third outsider and proves, via the detached verifier's anchor
  set, that each relying party accepts its own issuer and rejects a foreign one
  (roadmap PE.3). Pinned by `check_federation_real`; the detached verifier is standalone
  and pinned by `check_detached_verifier`.

## Consequences

- **P3.2** specifies the inter-authority protocol v1: attestation exchange, anchor
  cross-publication, epoch alignment, revocation propagation, with conformance vectors.
- **P3.10** boots two instances as two authorities in CI and proves cross-verification,
  attestation revocation, and anchor cross-checks end to end.
- Deployment placement (which authority runs where) stays operator-supplied; this ADR
  fixes the topology, not the deployment.
- The decision is kept honest against the code by `check_federation_topology`: the ADR
  may not claim the federated model unless the primitives it cites are present.
