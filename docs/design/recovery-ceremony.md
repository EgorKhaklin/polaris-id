# The recovery ceremony

**Reader:** an engineer or an assessor. **Job:** How a holder recovers an identity without a single point of compromise.

A fire takes the wallet and the reserve token together. A theft takes the
phone and the backup device. Without a recovery path, the holder is civically
excluded permanently by an accident, and the system that was supposed to prove
who they are is the thing preventing it.

Recovery is therefore mandatory. What makes it dangerous is that a recovery
path is also an impersonation path: whoever can convince the system that they
lost their identity can be issued a new one. The ceremony exists to make the
second thing expensive without making the first thing impossible.

This is the third of three structural defences against the schema turning on
the holder. [tiered-enrollment.md](tiered-enrollment.md) covers entry, where
non-enrolment must not become an exclusion gradient.
[issuer-discretion.md](issuer-discretion.md) covers exit, where mass
revocation needs a co-signature. This covers return.

The four checks on `RecoveryRequest` constrain the shape of the decision, not
its content. Agencies and their out-of-band verification decide who recovers;
the schema decides what a decision has to look like to be recorded at all.

## Two phases, two roles

### Initiating, by an operator

`uc9_initiate_recovery` inserts a `PENDING` row and issues nothing. The
48-hour cool-down starts here. It refuses two cases: an individual who still
holds an active token, because reserve activation is the right path for a
partial loss, and an individual who already has a pending request, which the
partial unique index would also catch but which the procedure rejects first
with a clearer message.

Between the phases, out of band, the three channels are verified: a biometric
check, a sworn statement, and a witnessing agency. That work happens in the
world, not in the database. The tests insert rows with the channels already
recorded.

**Recording them.** Until 1.0.0-rc.54 the application role could set all three
with a plain UPDATE, so the "three independent channels" were in practice one
role's word. rc.54 took that UPDATE away and left no path in the product to
record a channel at all, so no recovery could be approved without the schema
owner. Since 1.0.0-rc.60 `uc9_record_recovery_channel` (the queue's buttons,
`POST /uc9/record-channel/<id>`, `polaris recovery-record-channel`) records one
channel at a time on a pending request, attributed and gated per channel:

- **Biometric** and **sworn statement**: an active operator or admin who is not
  the requester, recorded as `biometric_recorded_by` and `sworn_recorded_by`;
  the statement is recorded as its SHA-256, never its text.
- **Witness**: the witness co-signs as themselves, an active operator or admin
  bound to an authority other than the requesting one, recorded as
  `witness_agency_id` and `witness_co_sign_user_id`.
- Each channel is recorded once, and none after a decision (the trigger).

The approver still has to be an admin who is neither the requester nor the
witness (`witness_differs_from_parties`). What the procedure cannot establish is
that the biometric check happened: it records who attests that it did.

**What the four-eyes rule binds.** Every actor in the ceremony (requester,
recorders, witness, approver) is a user id the caller passes; the database
cannot tell which operator is really at the keyboard, because every operator
reaches it through the one application role. The rule binds an honest
application completely. An attacker holding the application's database
credential can name four different operators and complete a recovery alone.
The ledger (`docs/PRODUCTION-READINESS.md`) states this bound for every
people-rule, and what would close it: a per-operator database identity or
operator-signed decisions, neither built.

### Completing, by an admin

`uc9_complete_recovery` requires the admin role twice over: the route carries
`@security.require_role('admin')`, and the procedure raises if the deciding
user's role is not admin. An operator can start a recovery and cannot finish
one; an auditor can see it and touch nothing.

An approval runs in this order:

1. Take a transaction-scoped advisory lock on the claimed individual.
2. Confirm the deciding user is an admin.
3. Select the request `FOR UPDATE` and confirm it is still pending.
4. Confirm the approver is not the requester, which a schema check also
   enforces.
5. On approval: confirm the cool-down has expired and all three channels are
   verified, both also schema checks; validate the new token's parameters;
   mark every non-terminal token of the individual `LOST`, tagged
   `LOST_BY_RECOVERY [RECOVERY:<id>]`, with a row written to the revocation
   list for each so verifier-side freshness checks see it; insert the
   replacement as `RESERVE` with no predecessor, because the prior chain is
   gone rather than superseded; activate it, tagged
   `RECOVERY_ISSUED [RECOVERY:<id>]`; and record the decision, the deciding
   user and the resulting token on the request.
6. On rejection: update the request and nothing else. No token, no revocation
   rows.

The tag in each lifecycle event's reason code is the join key back to the
request that drove it, so an audit replay reconstructs a whole recovery from
the lifecycle log alone.

## Where an adversary ends up

- **The claim.** Recovery needs three independent out-of-band channels: a
  biometric check, a sworn statement, and a witnessing agency.
- **The direct attack.** Compromise one channel and rely on procedural
  laxity.
- **Why that fails.** The three are chosen for independent failure modes:
  local hardware and a person, a legal instrument on paper, an institution.
  All three have to fall together.
- **The next attack.** Compromise just enough to get past a tired admin at two
  in the morning. Four things stand in the way: the mandatory 48-hour
  cool-down, the admin role gate on completion, the requirement that the
  approver is not the requester, and the pending queue being visible to every
  other admin in real time, so a suspicious pattern is seen before the
  decision lands.
- **What it costs.** A legitimate recovery takes at least 48 hours, and the
  holder is without an identity for that window. That cost is real, and it is
  the reason the operational grace period below is an open item rather than a
  closed one.

The shape of the defence is multiplicative rather than additive: the attacker
must compromise three channels, and defeat the cool-down, and obtain an admin
signature.

## The grace period, in two readings

A production recovery protocol is usually described as needing a grace period
during which the holder keeps access to essential services. That admits two
readings, and only one of them is built.

**The administrative window** is the procedural time between request and
decision, which stops a premature approval. That is the 48-hour cool-down, and
`cooldown_window_minimum` enforces it in the schema.

**The operational window** is a substitute credential that keeps the holder
functioning while the request is pending. That is not built. It needs a
`TemporaryAttestation` row with a lifetime tied to the cool-down, and, more
significantly, a verifier-side acceptance rule for a flagged set of essential
services, which is an integration question with the parties who would honour
it rather than a schema question. When it lands it should be additive: a child
row on the pending request, expiring with the cool-down. The schema is shaped
so that it can be.

## What each check is holding up

- **`cooldown_window_minimum`.** Without it a recovery can be approved
  instantly, leaving no window in which the real holder discovers and stops an
  impersonation.
- **`approved_requires_three_channels`.** Without it an approval no longer
  means the three channels were verified, and one compromised channel becomes
  sufficient.
- **`approved_after_cooldown`.** Without it the cool-down is bypassed by
  backdating the decision.
- **`approver_differs_from_requester`.** Without it one person initiates and
  approves, and the two-person separation the ceremony rests on collapses.

None of the four is decorative.

## The per-individual lock

Two threads completing the same pending request would each pass the cool-down
and three-channel checks before either update landed. The transaction-scoped
advisory lock, keyed on the claimed individual, serialises them: the first
commits, the second sees the approved state and refuses. Recoveries for
different individuals stay parallel.
`ConcurrencyTests.test_uc9_advisory_lock_serializes_concurrent_completes`
races it with real threads, which is what C9 requires.

## Related

- [concurrency.md](concurrency.md) holds the advisory-lock catalogue this
  entry belongs to.
- `docs/operator/SECURITY-CONTROLS.md` carries the operator-facing threat
  model for recovery.
