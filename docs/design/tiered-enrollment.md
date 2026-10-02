# Tiered enrolment

**Reader:** an engineer or an assessor. **Job:** The evidence tiers behind an issued token.

A national identity system that has only two states, holds a token or does
not, forces every person outside it into one undifferentiated absence. That
absence is then trivially weaponised: build the list of everyone who is not in
it. This layer gives enrolment a vocabulary instead, so that not holding a
token has a stated reason rather than being an inference from silence.

## The five states

Every `Individual` has a current enrolment status drawn from a five-value set:

| Status | Meaning |
|---|---|
| `NOT_ENROLLED` | The default, seeded by trigger when the row is created: a newborn, an undocumented resident, someone unhoused. |
| `PENDING_ENROLLMENT` | Enrolment has begun; biometrics or documentation are in progress. |
| `ENROLLED` | Holds at least one non-terminal token, RESERVE or ACTIVE. Recorded as a policy event, never derived from token state. |
| `EXEMPT` | Civic-policy recognition of participation without a token: biometric incompatibility, religious exemption, conscientious objection, an alternative path. |
| `LAPSED` | Was enrolled and is not now, by policy event. Distinct from never having been enrolled. |

Transitions land in `EnrollmentStatusEvent`, which is append-only. The
`IndividualCurrentEnrollment` view returns the most recent event per
individual, falling back to `NOT_ENROLLED` when there is none. Together they
are the schema's answer to the requirement that a person can take part in
civic life without a token: `EXEMPT` is that path, made first-class rather
than left as an absence.

## The constraint this is calibrated against

Polaris is not an authority. This layer adds vocabulary for a policy state and
never decides which state a person should be in. Three choices keep it on that
side of the line:

1. **`NOT_ENROLLED` is a default, not a flag.** The absence of enrolment is
   materialised only so that it can be transitioned out of cleanly.
2. **Nothing is derived from token state.** A person with no active token may
   be enrolled with a reserve token, exempt, or lapsed. Those are different
   policy events with different meanings, and deriving one from token state
   would collapse the distinction.
3. **No trigger-enforced state machine.** Sequencing belongs to the policy
   that owns it; the schema records what that policy claims, the same posture
   `TokenLifecycleEvent` takes.

## The asymmetry, which is the whole design

`EXEMPT` and `NOT_ENROLLED` both mean no token, and they are deliberately not
symmetric.

Recording someone as exempt is a single insert into `EnrollmentStatusEvent`. It
is one row, it is a positive recognition, and the audit trail reads as one.

Enumerating the not-enrolled is possible and deliberately unhelped.
`civic_enrollment_summary(jurisdiction)` returns counts by jurisdiction and
status, and nothing else. Since 2026-10-02 it reads them from maintained totals
(`EnrollmentCount`, lab/strategy/008), so it costs the same at any population; the
per-person status behind them (`EnrollmentCurrent`) is closed to the application
role, so it does not make the list below any cheaper to build. An admin can join `IndividualCurrentEnrollment`
directly and get names, but no function offers it, and the access appears in
`AuthAuditLog` when they do.

The attack this anticipates is not the obvious one. Once a system has a
first-class exempt state, the next move is to treat `NOT_ENROLLED` as a
positive marker: build the list of everyone in this jurisdiction who has not
enrolled. The asymmetry does not prevent that query. It makes it a named,
deliberate act against a named state, rather than something inferred from the
absence of a row.

The schema cannot stop the misuse. It can stop the misuse from being
accidental, and naming is the precondition for governance noticing.

## Where an adversary ends up

- **The claim.** Non-enrolled people are first-class rows. `Individual` exists
  without any token, indefinitely, and civic queries can answer whether a
  person is known without requiring enrolment.
- **The strongest attack.** Make non-enrolment civically impossible from
  outside: no token, no healthcare; no token, no school. That converts an
  opt-in layer into an opt-out one through policy gradient rather than through
  anything in the schema.
- **Where it settles.** The schema records enrolment state without privileging
  any value of it, and `EXEMPT` gives the non-token path a recognised name, so
  the gradient is at least contested rather than uncontested.
- **The next attack.** Treat `NOT_ENROLLED` as a marker and enumerate it.
- **The answer.** The asymmetry above: exemption is easy, enumeration is
  explicit and audited.
- **What it costs.** Legitimate uses also need to enumerate the unenrolled: a
  vaccination outreach, a voter-registration drive. Those are not prevented.
  They are made explicit rather than implicit.

This is the least technical and most sociotechnical part of the system, and
the contribution it makes is visibility rather than prevention.

## Why nothing is auto-derived

The temptation is to emit `ENROLLED` when a person gains a non-terminal token
and `LAPSED` when their last one goes terminal. It would save hand-recording,
and it is rejected for three reasons:

1. A person can be exempt regardless of token state. Someone recognised under
   an alternative path may still hold a historical token, and derivation would
   overwrite their exemption.
2. `PENDING_ENROLLMENT` is a real state between being known to the system and
   holding a token. Derivation would skip it entirely.
3. `LAPSED` is a policy event with a reason. Deriving "the tokens went
   terminal, therefore civic enrolment ended" is exactly the conflation this
   schema refuses: an administrative revocation is not a person leaving civic
   life.

The cost is that a human records the transition. The benefit is that the
schema does not make policy decisions on their behalf.

## The seed trigger

`trg_seed_default_enrollment_status` fires `AFTER INSERT ON Individual` and
writes a `NOT_ENROLLED` event with the reason `INDIVIDUAL_ROW_CREATED` and no
recording agency, which marks it as a system event. It is an AFTER trigger
because `individual_id` is a `SERIAL`: a BEFORE trigger would see NULL.

It fires for every insert, including the sample data. That is correct: the
seeded individuals all begin in the default state, and `04_data.sql` then
layers the real events on top.

An import from a predecessor system that carries its own enrolment history can
disable the trigger for the duration with `ALTER TABLE … DISABLE TRIGGER
trg_seed_default_enrollment_status`. That needs table-owner privileges, which
`polaris_app` does not have, so it is a database-administrator operation and
not something the application can do to itself.

## Related

- [issuer-discretion.md](issuer-discretion.md) bounds the exit from the system,
  where this bounds the entry.
- [recovery-ceremony.md](recovery-ceremony.md) covers the third leg, returning
  after a loss.
- `docs/operator/PRIVACY.md` states the population-coverage posture an
  operator has to hold up.
