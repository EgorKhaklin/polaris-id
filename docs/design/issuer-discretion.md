# Issuer discretion

**Reader:** an engineer or an assessor. **Job:** The limits on what an issuing agency can do at scale, and where they bind.

An identity system's worst failure is not a forged token. It is the authority
that issued a population's tokens revoking them at scale, which is
denaturalisation carried out with a database. This is the schema-level bound on
that: a ceiling on how fast one agency can revoke its own tokens, above which a
co-signer from a different agency is required.

It is one of three answers to issuer trust concentration. The other two are
cryptographic diversity, covered in
[multi-sig-migration.md](multi-sig-migration.md), and federation without
transitive trust, covered in [federation.md](federation.md).

The bound does not make Polaris an authority over the holder. The agency still
makes every revocation decision. What is constrained is the shape of agency
behaviour at volume, the same category as C3, which constrains issuance, and
C7, which constrains what an agency may sign with.

## The two numbers

| Setting | Default | Why |
|---|---|---|
| `polaris.default_max_revoke_percent` | 5.00 | At an even spread this still allows roughly sixty percent of an agency's issued base in a year, so it does not stop slow abuse. What it stops is the surprise: mass revocation in a day is impossible without a co-signer, and the slow version is an observable trend. |
| `polaris.default_window_days` | 30 | Short enough to catch a coordinated campaign inside a useful horizon, long enough to absorb a legitimate bursty workflow such as a hardware recall. |

Per-agency overrides live in `IssuerDiscretionPolicy`; an agency with no row
inherits the system default. The sample data carries one override in each
direction: a federal agency loosened to seven percent to accommodate
coordinated recalls, and a county authority tightened to three. The
`justification` column has a twenty-character floor, so a loosening cannot be
recorded without a stated reason.

Both numbers are policy, and the defaults are a Schelling point rather than a
derivation: a lower ceiling or a shorter window is a stronger bound and more
friction on legitimate work. These defaults prefer resistance to mass
revocation over operational latitude.

## Who may co-sign

A co-signer must differ from the acting agency, and must hold `BOTH`
authorisation on the token's algorithm through `AgencyAlgorithmAuth`.

Eligibility is a set rather than one named authority on purpose. Once the rate
bound holds, the next attack is to compromise the co-signer; against a set, an
attacker has to compromise every candidate, which scales badly for them. The
co-signer's identity is recorded in the lifecycle event's `reason_code` as
`[COSIGN:<agency_id>]`, so an auditor can see one co-signer appearing again and
again across mass-revocation events.

## Serialising the check

`uc8_revoke_token` opens with a transaction-scoped advisory lock keyed on the
issuing agency:

```sql
PERFORM pg_advisory_xact_lock(
    hashtext('polaris.revoke.' ||
        (SELECT issuing_agency_id::TEXT FROM IdentityToken WHERE token_id = p_token_id)));
```

That makes the read-then-write rate check atomic for a single agency. Two
transactions racing the revocation that would cross the bound block on the
lock, and the loser sees the winner's row when its own rate query runs.

The alternatives were considered and rejected. `SERIALIZABLE` isolation would
push retry logic on serialisation failures into the application and change the
isolation level for everything else. `SELECT … FOR UPDATE` has no single row to
take: the rate query joins `TokenLifecycleEvent` against `IdentityToken` across
many rows, so the natural granularity is a derived key. A global lock would
serialise unrelated agencies, and
`ConcurrencyTests.test_uc8_cross_agency_revocations_do_not_block` asserts that
two agencies do not block each other. The lock is transaction-scoped, so it
releases at commit or rollback with nothing to unlock by hand.

## Revocation and the published list

`uc8_revoke_token` sets `IdentityToken.status` to `REVOKED` and inserts into
`RevocationList` in the same transaction. Without that second write a
verifier's freshness check would not see the revocation, and the token's state
would diverge from the published list.

The two `reason_code` columns are deliberately different.
`RevocationList.reason_code` is constrained to the canonical vocabulary:
`COMPROMISED`, `LOST`, `STOLEN`, `SUPERSEDED`, `ADMINISTRATIVE`, `DEATH`. The
lifecycle event's is wider and undomained, which is where the co-signer tag
lives. The verifier-facing list stays canonical; the audit trail carries the
procedural detail.

## Making the procedure the only path

`enforce_revocation_velocity_bound` is a BEFORE UPDATE trigger on
`IdentityToken`. It refuses any transition to `REVOKED` unless
`uc8_revoke_token` has set the per-transaction setting
`polaris.revoke_check_done` **and** the current role owns `uc8_revoke_token`.

The second condition is what makes it a door rather than a sign. Until 1.0.0-rc.19 the setting
alone was enough, and any session can set a setting: a `polaris_app` session set it and revoked
with a plain UPDATE. The three procedures that revoke (`uc4_activate_reserve`,
`uc8_revoke_token`, `uc9_complete_recovery`) now run `SECURITY DEFINER`, so inside them the
current role is the owner, and outside them the application role never is. The default bound
is read from the database's own setting (`polaris_database_setting()`), not the session's, for
the same reason: a caller must not choose the bound it is about to be held to.

The trigger does not repeat the rate arithmetic. Its job is to close every
other door: a direct UPDATE from psql, from the SQL console, or from
application code that skipped the procedure is refused with
`insufficient_privilege`.

## Where an adversary ends up

- **The claim.** No agency can revoke more than the configured share of its
  issued base in a window without a co-signer from another agency. The base is every credential
  the agency has issued, whatever its status now (`uc8_revoke_token` counts `IdentityToken` rows
  for the agency with no status filter). It does not shrink as credentials are revoked, so
  against the credentials still LIVE the share is larger: an agency with 1,000 issued and 100
  live may revoke 50 a window at 5%, half of what is left. Until 2026-09-24 this line said
  "outstanding tokens", which the code never measured; measuring against live credentials would
  be the stricter bound, and is recorded as an open decision rather than changed here.
- **The strongest attack.** Stay just under the ceiling indefinitely. At the
  default that is still most of a population inside a year, so the bound
  converts a surprise into a trend.
- **Where it settles.** Mass revocation needs either a co-signature, which
  names two agencies in the audit trail instead of one, or a slow burn that
  downstream reporting can see before it completes.
- **The next attack.** Compromise the co-signer, which the eligibility set and
  the recorded co-signer identity are there to make expensive and visible.
- **What it costs.** The bound can refuse a legitimate bulk revocation, which
  the per-agency override and the co-signature exist to absorb.

## What it does not protect against

- **Slow abuse under the ceiling.** An agency revoking just under the bound
  every month for a year still reaches most of its population. The counter is
  audit reporting and public scrutiny of revocation rates, not the schema.
- **Every agency captured at once.** The leverage of a co-signature ends when
  there is nobody uncompromised to sign.
- **`LOST` and `EXPIRED` events**, which are individual-scale transitions
  rather than bulk operations. If either were used as laundered revocation,
  extending the bound to cover them would be the answer.
- **Forgery of the co-signer's identity.** The co-signature is recorded
  procedurally, not cryptographically. Hardware-attested co-signing would be
  the next layer, and it is not built.

## Related

- [tiered-enrollment.md](tiered-enrollment.md) bounds the entry to the system,
  where this bounds the exit.
- [concurrency.md](concurrency.md) carries the advisory-lock pattern used
  here, alongside every other lock in the system.
- `meta/redaction-proof.md` covers the verification-graph redaction proof, the
  answer to the same class of concentration question on the privacy side.
- MISSION.md's C1, the append-only audit, and C7, algorithm authority as data,
  are the constitutional constraints this builds on.
