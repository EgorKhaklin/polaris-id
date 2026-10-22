# Abuse controls

**Reader:** an engineer or an assessor. **Job:** The per-agency quotas, where they are enforced, and what an operator sees when one refuses a write.

Two controls bound the shape of an agency's behaviour rather than the volume of
a single caller: a hard limit, and an early signal. They sit alongside the
constitutional revocation ceiling described in
[issuer-discretion.md](issuer-discretion.md).

- **Quotas** are opt-in, set per agency and per kind of write, counted over a
  rolling window, and enforced by the `enforce_agency_quota` BEFORE trigger in
  the database. A cap therefore holds on every path: a stored procedure, the
  SQL console, a bulk loader. There is no session variable that disables it,
  unlike the raw-UPDATE guard, because a sanctioned procedure is still the
  agency doing the thing the cap bounds.
- **Velocity alerts** compare each agency against its own trailing week rather
  than a global number, so a large agency's ordinary day never trips a small
  agency's threshold, and an absolute floor keeps a young or quiet agency's
  first few actions from paging anyone.

## The choices, and the reasons

- **Opt-in rather than default caps.** The revocation bound has a default
  because revocation is destructive. Issuance and verification volumes are
  legitimate functions of an agency's size, so a default absolute cap would
  break a large legitimate agency on its first day and protect nobody in the
  meantime. The always-on control is the alert; the cap is the operator's
  answer to it.
- **Counts, alongside the percentage bound.** `enforce_revocation_velocity_bound`
  bounds revocation as a share of an agency's issued base. A share says nothing
  about absolute rate, and no percentage bound can exist for issuance, which
  has no denominator, or for verification, which is not against the agency's
  own tokens. Counts per window compose with the percentage: whichever trips
  first refuses the write.
- **Windows read from the audit tables.** The count comes from
  `IdentityToken.issued_date`, the REVOKED rows in `TokenLifecycleEvent`, and
  `VerificationEvent.event_timestamp`, never from a separate counter that could
  drift from the history it claims to summarise.
- **Exact under concurrency.** A transaction-scoped advisory lock, keyed by
  agency and kind, serialises the count and the write. The C9 test races twelve
  writers against a cap of five and gets exactly five. Without the lock the cap
  is approximately five.
- **The uncapped path stays the hot path.** One primary-key lookup on
  `AgencyQuota`, then `RETURN NEW`, before any lock or count, so a bulk loader
  and every deployment that configures no quota pay nothing measurable.
- **Per agency, never per person.** The counters' labels and the caps' keys are
  agency identifiers, whose cardinality is bounded. Nothing here filters or
  scores the population: the vocation is the design line, not a policy layered
  on top of it.
- **The refusal is loud on every surface.** The trigger's sentence reaches the
  operator as HTTP 429, the log as a `quota.refused` line carrying the request
  id, the metric as `polaris_quota_refusals_total`, and the pager as
  `PolarisQuotaRefusals`. A cap that refused silently would be
  indistinguishable from a bug.

## What an adversary meets

- *An operator scripts the issuance form at three in the morning.*
  `PolarisIssuanceVelocity` pages within the hour, on an absolute floor of
  twenty issuances and four times the agency's trailing baseline. The
  operator's sessions are ended through the CLI, a cap is set, and the tokens
  already issued are revoked through the bounded procedure rather than by
  editing history.
- *A verifier sweeps the population.* `PolarisVerificationVelocity` pages at
  two hundred verifications in an hour and four times the baseline;
  `quota-set --verify-per-hour` stops the sweep at the database on the next
  write, and the federation attestation behind it can be revoked.
- *Someone bypasses the application with psql.* The trigger fires on the raw
  insert. The SQL console writes nothing: its queries run read-only, as a
  role that holds `SELECT` alone.
- *Concurrent writers race a cap.* The advisory lock makes the loser see the
  winner's row, which the concurrency test asserts.
- *A cap is set too low and legitimate operators are refused.*
  `PolarisQuotaRefusals` pages at severity three for exactly this case, and the
  runbook's first step is `polaris-id quota-show`, which prints the
  justification recorded with the cap.

## Boundaries

These are not a request rate limiter: that is per IP and lives in
`security.py`. They are not analytics on holders. They are not on by default.
And they are not a policy Polaris decides: the caps and the justifications
beside them are rows the deploying authority writes.
