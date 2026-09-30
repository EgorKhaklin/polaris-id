# Federation

**Reader:** an engineer or an assessor. **Job:** How cross-agency trust is recorded and consulted, with no transitive trust.

Every token names the agency that issued it, and without a federation model a
verifier either trusts all issuers or none of them. Trusting all of them means
one compromised agency can issue tokens the whole system honours, which is
issuer trust concentration in its simplest form.

The answer here is a declarative trust graph: an explicit, directional,
per-context statement that one agency accepts another, consulted on every
cross-agency verification.

## The three pieces

1. **`AgencyTrustAttestation`**, whose rows are directed edges. A row says
   that the attesting agency accepts the attested agency for one verification
   context.
2. **`uc10_attest_trust` and `uc10_revoke_attestation`**, admin-only
   procedures, each holding an advisory lock on the attesting agency.
3. **The verification flow**, which consults the graph before recording a
   success. Same-agency verification is implicit and needs no row;
   cross-agency verification requires an active edge.

## No transitive trust

An edge from A to B and an edge from B to C do not make an edge from A to C.
The check looks for exactly one row matching the verifier, the issuer and the
context. It never recurses and never computes a closure.

This is the same refusal to derive that runs through the schema, and here it
buys three things. Nothing is granted silently: adding one edge cannot open a
path the operator did not intend. Cycles stop being a problem, because nothing
walks the graph. And an operator who wants multi-hop trust declares every hop,
which means the audit trail contains every decision rather than the inputs to
an inference.

The failure it prevents is a federation collapsing into its most permissive
member: with explicit-only edges, the trust set cannot grow without someone
acting.

## Revocation looks forward

Revoking an attestation sets `revocation_date` and `revocation_reason`
together, and both are immutable afterwards. Verification consults the live
state, and the effect is forward-only:

- Verification events recorded while the edge was active are not invalidated.
  They happened, and C1 keeps them; the schema does not rewrite history.
- Verifications after the revocation see the revoked state and fail the check.
- A verification already in flight sees its own snapshot, which is
  read-committed semantics doing the right thing.

## One attestation at a time, per attesting agency

Both procedures take a transaction-scoped advisory lock keyed on the attesting
agency. Without it, an attestation and a revocation from the same agency can
interleave into an ambiguous final state. With it, one agency's changes
serialise and different agencies proceed in parallel.

| Ceremony | Lock key |
|---|---|
| Revocation | per agency |
| Recovery | per individual |
| Algorithm migration | per token |
| Anchor batch close | per algorithm |
| Attestation and its revocation | per attesting agency |

[concurrency.md](concurrency.md) holds the catalogue and the reasoning behind
each granularity.

## What `signed_by` is, and is not

The column records which Polaris operator created the attestation. It is not a
cryptographic signature from the attesting agency.

That is an honest limit rather than an oversight. Operator accounts have no
link to an agency and no cryptographic standing on an agency's behalf. The
model assumes Polaris is run by an authority with the standing to record
attestations, which is true of this pre-pilot system and would not be
enough for a production federation.

The upgrade is a migration that adds a nullable signature and its algorithm,
requires them on new attestations, and leaves existing rows valid and
queryable. What blocks it is not the schema: it is agency-level signing key
management, which is its own design problem and one of the operator decisions
in the readiness ledger.

## Self-attestation is refused

`attestation_no_self_attestation` rejects a row whose attesting and attested
agencies are the same.

Accepting them as harmless no-ops was the alternative, and it loses on three
counts. A graph full of self-edges obscures the cross-agency edges that carry
meaning. Same-agency verification already short-circuits before the graph is
consulted, so such a row would be either redundant or misleading. And an
operator error is better surfaced when the row is written than silently
ignored when it is read.

## The seeded graph

The sample data carries six attestations: a federal travel authority accepting
three issuers for travel, and a bank accepting the same three for banking. No
healthcare edges exist, because the only healthcare-permitted token in the
sample verifies at same-agency checkpoints.

The point of seeding it is that the sample verification events become
explicable through the graph rather than through hard-coded trust.

## Where an adversary ends up

- **The claim.** Trust is explicit only. One agency accepts another for one
  context if and only if an unrevoked row says so, and no chain of edges
  implies an edge.
- **The direct attack.** Compromise an agency that the target already trusts.
  That works, and federation does not claim otherwise. What it does is confine
  the blast radius to exactly the explicitly trusted set.
- **Where it settles.** Each edge has to be attacked on its own. Compromising
  several agencies buys those edges and not their closure, which is precisely
  what transitive trust would have given away.
- **The next attack.** Write an attestation directly in the database.
  `enforce_attestation_immutability` refuses updates after the row exists, and
  the procedures are the only sanctioned path in. An attacker with the
  database owner's shell has larger options than this, and the trigger is not
  claimed to stop them.
- **What it costs.** Full pairwise trust among many agencies costs a row per
  pair. That is accepted: the alternative is inferring relationships nobody
  declared. A grouping abstraction could amortise the cost later without
  weakening the no-transitivity rule.

The boundary is the same one the whole schema keeps: it records that A
attested B, and it does not answer whether A should have.

## Reading the code

- `polaris_sql/01_schema.sql`: `AgencyTrustAttestation` and its constraints.
- `polaris_sql/02_indexes.sql`: the partial unique index over active
  attestations, and the revocation index.
- `polaris_sql/05_procedures.sql`: `uc10_attest_trust`,
  `uc10_revoke_attestation`.
- `polaris_sql/06_triggers.sql`: `enforce_attestation_immutability`.
- `polaris_web/app.py`: `_federation_trust_holds`, the verification extension,
  and the two federation routes, which accept the CSRF token as a header for
  JSON callers.
- `polaris_web/test_app.py`: `IssuerFederationTests`, and the concurrency
  tests for the attest and revoke race.
- [audit-of-record.md](audit-of-record.md): why an attestation is immutable
  once written.
