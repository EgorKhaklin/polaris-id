# Athena: the authority-and-constitution layer

**Status:** shipped v9.266 (roadmap P6.8). **Code:** [`polaris_sql/16_athena.sql`](../../polaris_sql/16_athena.sql).
**Design study:** [`DEVNOTES/athena-ontology-assessment.md`](../../DEVNOTES/athena-ontology-assessment.md).

Athena is a read-only semantic and provenance layer over the *authority* tables,
plus a first-class, machine-checked model of the constitution. Atlas answers
*what is happening*; Athena answers *what exists, how it relates, and where
authority comes from* — the governance questions the tree could otherwise answer
only by hand.

## What it answers

| Question | Function |
|---|---|
| Why may this agency issue under this algorithm? | `athena_authority_chain(agency, algorithm)` |
| What proof / disclosure policy bounds this context? | `athena_explain_proof(context)` |
| If this algorithm is deprecated, who is affected? | `athena_affected_by_algorithm(algorithm)` |
| Which mechanism enforces this constitutional rule? | `athena_rule_enforcement(rule)` |

Ten object views (`v_athena_jurisdiction`, `_agency`, `_algorithm`,
`_credential_class`, `_relying_party_class`, `_proof_policy`,
`_disclosure_policy`, `_trust_agreement`, and the curated
`athena_constitutional_rule` / `athena_key_custody`) and eight edge views
(`v_athena_authorizes`, `_may_issue`, `_may_request`, `_relies_on`,
`_approved_by`, `_constrains`, `_enforced_by`, `_supersedes`) sit over `Agency`,
`AgencyAlgorithmAuth`, `CryptographicAlgorithm`, `VerificationContext`,
`AgencyTrustAttestation`, and `RetentionPolicy`. Each is a `SELECT`, so it cannot
outlive its source.

## The constitution as data

`athena_constitutional_rule` holds C1-C10 and the Vocation as rows;
`athena_rule_enforcement` maps each to the exact live mechanism that enforces it
— a trigger, a partial unique index, a named CHECK constraint, a `check_*`
function, or a stored procedure. This closes the prose-drift gap that
[`meta/constraint-lattice.md`](../../meta/constraint-lattice.md) has today: the
map is only true because a check proves it. `check_athena_rule_enforcement_resolves`
fails the build if any named mechanism no longer exists, and the DB test
`AthenaOntologyTests.test_rule_enforcement_map_matches_live_catalog` proves each
one is present in the running catalog, not merely the source.
The rows are the owner's to write: `16_athena.sql` and `09_grants.sql` revoke INSERT, UPDATE and
DELETE on the three curated tables from the application role (1.0.0-rc.61; before it, that role
could make the console say a rule was enforced by nothing), and `check_athena_read_only` requires
both revokes.

## Why it is safe to exist

Athena is safe only because person-legibility is made *structurally impossible*,
not merely discouraged. Five invariants gate the layer, each with an adversarial
detection test (`polaris_checks/checks.py`, `test_checks.py`):

- **`check_athena_no_person`** — no Athena view, function, or table references a
  natural-person table or column (`Individual`, `individual_id`, `IdentityToken`,
  `TokenPermission`, `VerificationEvent`, a token or duress column), and no
  column is a stable per-person surrogate. Athena reads only the authority
  tables, which contain no person. The same ship removed the v9.19
  `v_ontology_individual` / `v_ontology_individual_tokens` person-aggregating
  views; that single-entity data now lives only on the audited, login-gated
  `/investigate/individual/<id>` route.
- **`check_athena_read_only`** — every Athena function is `STABLE`, non-mutating,
  and `SECURITY INVOKER`; "graph says revoke -> revoked" is impossible.
- **`check_athena_functions_bounded`** — every function caps its output with
  `LIMIT`; an event-touching function would have to inherit the Atlas C8 window.
- **`check_athena_non_sovereign`** — every authority edge resolves to an existing
  authority table (no independent authority store), the "current" views exclude
  revoked/superseded authority, and Athena owns only the three descriptive
  curated tables (a new `athena_*` table is a governance event).
- **`check_athena_rule_enforcement_resolves`** — every rule maps to a mechanism
  that exists, and every rule is enforced.

The one-line test the whole design passes: **it makes power easier to inspect
without making people easier to control.**

## The operator console (v9.267)

`/athena` is the read-only operator surface, a four-tab console (`athena.html`,
`athena-console.js`; nav between Atlas and Individuals). **Constitution**
(server-rendered) shows C1-C10 and the Vocation, each with its live enforcement
mechanisms as kind-badged chips. **Authority** resolves the authority chain for
an agency + algorithm ("Not authorized to issue" when no grant exists) and the
deprecation blast radius for an algorithm. **Proof policy** explains a context's
requirements and its three disclosure levels. **Trust graph** lists the current
attestations. The three drill-downs call `/api/athena/authority-chain`,
`/api/athena/affected-by-algorithm`, and `/api/athena/explain-proof` (login-gated,
replica-routed). The console reads only the person-free Athena layer and renders
every result with `createElement` (never `innerHTML`), so `script-src 'self'`
stays strict (C5); `check_athena_console` pins that, and the headless-browser UI
drill asserts the console renders in a real browser.

## What is deliberately NOT built

No person / household / relationship object; no subject handle (opaque or not)
stable across contexts; no ZK-subject traversal; no population segmentation or
scoring; no graph database or RDF; no actions (read-only MVP); no
`SECURITY DEFINER`. If the person-prohibition ever obstructs a feature, that is
the signal to stop, not to relax it (assessment, kill criteria).
