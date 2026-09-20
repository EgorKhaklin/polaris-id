# meta/redaction-proof.md: verification-graph redaction (M2-12 / R11-7)

**Status:** Active. Companion to property tests in
`polaris_web/test_redaction_property.py`.

C2: the schema-level invariant that `VerificationEvent.token_id IS NULL`
when `disclosure_level = 'ZERO_KNOWLEDGE'`: is a *syntactic* claim. A
syntactic claim is necessary but not sufficient: the column being NULL
does not, by itself, guarantee that the holder of a ZK event cannot be
identified by an adversary with full database read access. This document
strengthens C2 from "the column is NULL" to "the privacy claim holds
against an explicit adversary model." It also enumerates the
counterexamples: the operational conditions under which the syntactic
NULL is not enough.

## 1. Adversary model

**Capability.** Passive read-only attacker with full `SELECT` privilege
on every table in the public schema. This is the worst-case insider:
an auditor whose role grants broad visibility, or an attacker who has
exfiltrated a database snapshot and can read it indefinitely.

**Cannot do.** Insert, update, or delete any row. Observe future
events. Observe network-layer or timing side-channels at insertion
time (the schema records them only with the granularity it stores:
`event_timestamp` is the field that exposes timing, with one-second
resolution by default).

**Has.** Complete schema knowledge. Complete content of all tables.
Knowledge that ZK events have `token_id IS NULL` (C2). Knowledge that
exactly one `IdentityToken` is `ACTIVE` per individual (C3). Public
information about agencies' physical jurisdictions and operational
hours.

## 2. Privacy claim (formal)

Let `H = {h_1, ..., h_n}` be the set of enrolled individuals (rows of
`Individual`). Let `V_zk` be a `VerificationEvent` row with
`disclosure_level = 'ZERO_KNOWLEDGE'`. Let `holder(V_zk)` denote the
ground-truth individual whose token produced `V_zk` (a piece of
information NOT stored in the row by C2).

Let `A` be any deterministic algorithm that takes the database state
`D` and the row `V_zk` as input and outputs a guess
`A(D, V_zk) ∈ H ∪ {⊥}` where `⊥` denotes "no guess".

**Claim (informal):** For a randomly-selected `V_zk` whose holder is
not the subject of correlated SELECTIVE/FULL events at nearby times,
locations, or contexts (the "isolated ZK event" case),

```
P[A(D, V_zk) = holder(V_zk)] ≤ 1/n + ε
```

where `1/n` is the baseline of uniform random guessing over the
population and `ε` accounts for the structural information present
in the row's non-holder columns (agency, context, location at the
fidelity stored).

**Claim (operational restatement):** For an adversary whose only
information is the ZK row itself, the success rate is bounded by the
prior distribution of holders consistent with the row's non-holder
columns. When that distribution is flat (no holder is more likely than
any other to be at this location, in this context, with this agency),
the bound is `1/n`.

## 3. Side-channel enumeration

Five side-channels are known and named here so the privacy claim is
not misread as stronger than it is. Each is a pathway through which
information about `holder(V_zk)` leaks; some are mitigated at the
schema level, the rest depend on operational policy.

### S1 · Temporal correlation with non-ZK events (NOT mitigated by schema)

If holder `h_i` produces a SELECTIVE or FULL `VerificationEvent`
`V_s` at time `T_s` with `token_id = t_i`, and a ZK event `V_zk`
appears at time `T_zk ≈ T_s` from the same agency in a similar
location, the temporal proximity is a strong link. The adversary
learns `holder(V_zk) = h_i` not from `V_zk`'s columns but from the
juxtaposition.

**Mitigation:** operational. Per-holder rate-limiting across
disclosure levels; agency rotation in client policy. The schema does
not enforce this and would over-reach if it tried.

### S2 · Spatial uniqueness (NOT mitigated by schema)

`requestor_location` is free-text; `latitude`/`longitude` are stored
with full precision. If a ZK event has coordinates that match a
single holder's known address (e.g., "verification at 1234 Main St,
Springfield"), the location alone identifies the holder. The schema
records what the verifier presents.

**Mitigation:** operational. Verifier-side rounding of location data
before submission; redaction of `requestor_location` to city level
in audit-export views.

### S3 · Sequential `event_id` clustering (mitigated only weakly)

`event_id` is a `SERIAL`. Two events with adjacent `event_id` values
were inserted close in time (subject to clock skew). For an adversary
who already has temporal correlation, sequential `event_id` is a
secondary confirmation rather than a new channel.

**Mitigation:** none beyond what S1 mitigations provide. The schema
deliberately retains insertion-order observability for audit purposes
(UC-7).

### S4 · `proof_commitment` determinism (TESTABLE; mitigated by spec)

The PDF specifies that `proof_commitment` is "a cryptographic
commitment retained for fraud-investigation correlation." The intent
is that the same holder's repeated ZK events produce DIFFERENT
commitments (otherwise commitments themselves cluster events from a
holder). If a buggy or coerced implementation produces deterministic
per-holder commitments, the privacy claim degrades immediately.

**Test:** `test_proof_commitments_are_unique_per_zk_event`, across all
sample data, no two ZK events share a commitment. A regression
breaks this test.

### S5 · Agency-context-bias (mitigated only by population scale)

Some holders use specific agencies more than others (a CA-resident
banks at a CA bank, etc.). Per-holder agency-frequency distributions
provide weak side-channels. In small populations, frequency
distributions narrow the holder set; in large populations, they
contribute noise.

**Mitigation:** scale. The privacy claim's `ε` term absorbs this.

## 4. Claims that hold (the isolated-ZK-event case)

For a single ZK event with no nearby SELECTIVE/FULL events from the
same holder, no spatially-unique location, and a uniformly-distributed
`proof_commitment`, the adversary's information about the holder is
exactly the prior `P(holder = h_i)`: typically uniform `1/n`.

The property tests in `test_redaction_property.py` instantiate this
case: a synthetic population, ZK-only events, no temporal/spatial
correlation, distinct commitments. The adversary's success rate is
empirically indistinguishable from `1/n`.

## 5. Counterexamples (the failure modes)

The same property-test file demonstrates the failure modes
explicitly. These are not weaknesses being papered over: they are
limitations being made testable:

- **CE-1 (Temporal):** SELECTIVE event at time `T` with
  `token_id = t_i`; ZK event at time `T + δ` (δ ≤ 60 s) from the same
  agency. Adversary success rate ≈ 1.0. Documented as an operational
  concern.
- **CE-2 (Spatial uniqueness):** ZK event at coordinates matching only
  one holder's home address. Adversary success rate ≈ 1.0. Documented.
- **CE-3 (Deterministic commitments):** if `proof_commitment`
  collides per holder, clustering succeeds. Already a regression
  test.

These counterexamples are how the privacy claim is honest. A claim
that hides its failure modes is weaker than one that names them.

## 6. Relationship to C2

C2 says: `disclosure_level = 'ZERO_KNOWLEDGE'` rows have `token_id IS
NULL`. This is necessary (a ZK row with non-NULL `token_id` is a
trivial linkage) but not sufficient (a NULL token_id row can still be
linked via the side-channels above).

This document and the property tests below extend C2 from "syntactic"
to "semantic": the privacy claim is bounded by the adversary's prior
on the population, given the row's observable non-holder columns.

## 7. Test surface

| Test | What it asserts | Ref |
|---|---|---|
| `test_zk_only_sequence_resists_reconstruction` | Adversary success rate on ZK-only events ≤ baseline + slack | §4 |
| `test_proof_commitments_are_unique_per_zk_event` | S4 mitigation in force in sample data | §3 S4 |
| `test_temporal_correlation_breaks_redaction` | CE-1 succeeds (documented limitation) | §5 |
| `test_spatial_uniqueness_breaks_redaction` | CE-2 succeeds (documented limitation) | §5 |
| `test_isolated_zk_event_has_no_holder_reference` | C2 + the absence of `individual_id` columns | §2 |

## 8. What this document is not

Not a cryptographic proof of zero-knowledge. The substrate-level work
(M2-1 / R10-1) replaces `proof_commitment` with a real ZK-SNARK; that
proof's properties live in the cryptography, not the schema. This
document covers ONLY the schema's redaction posture against a
read-access adversary. The two layers compose: a real ZK-SNARK
prevents the holder from being inferred from the commitment itself;
the schema-level redaction proven here prevents the holder from being
inferred from the row's non-cryptographic columns. Together they
realize the architectural claim that a ZERO_KNOWLEDGE verification
"records that a valid token was presented without recording which
token" (PDF §1, paragraph 9).

## 9. Re-evaluation triggers

This proof should be revisited when:

- A new column is added to `VerificationEvent` (any new column is a
  new potential side-channel: does it survive the analysis?).
- Schema-level changes alter what an adversary sees (e.g., M2-9
  tiered enrollment exposes a new `EnrollmentStatus` column on
  `Individual` that adversaries can pivot through).
- M2-1 (real ZK-SNARK) lands and the `proof_commitment` becomes a
  real proof: re-verify §3 S4 against the new construction's
  properties.
- A new operational deployment introduces a side-channel not listed
  in §3.
