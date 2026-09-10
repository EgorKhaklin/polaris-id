# PILOT.md: running a pilot, and ending one

**Reader:** the institution deciding whether to run a Polaris pilot, and the operator who will
have to end it. **Job:** what you are promising participants, what you can actually deliver
when it stops, and who has to agree before it can.

**Read the ending first.** A pilot's real promise is not that it will work. It is that it can
be wound back. That is the promise institutions say yes on, and it is the one that fails
quietly: erasure becomes a paragraph in a consent form, nobody ever executes it, and "what is
still in there?" gets answered years later by whoever inherits the database.

The wind-down is [`polaris_web/pilot.py`](../../polaris_web/pilot.py) and
[`scripts/polaris-pilot-winddown-drill.py`](../../scripts/polaris-pilot-winddown-drill.py)
runs it end to end against a real database on every push.

---

## 1. What you may truthfully tell a participant

`pilot.consent_language()` returns this, and it is generated from what the code does rather
than written from what would be reassuring:

> When this pilot ends, your credential is revoked and your name is replaced in our records
> with a meaningless marker. Your name will no longer be readable by anyone operating this
> system.
>
> What is **not** removed, and cannot be: the record that a person was enrolled, that
> credentials were issued to them, and that verifications happened. Those records stay, without
> your name attached. They are kept append-only on purpose, so that nobody, including us, can
> quietly erase evidence of what this system did. That protection applies to you as much as it
> constrains you.
>
> We cannot promise your data will be deleted, because in this system that would not be true.
>
> Ending this pilot requires a second, independent authority to co-sign the withdrawal of every
> credential. No single organisation running this pilot, including the one that enrolled you,
> can revoke everyone on its own.

**Do not replace "your name is replaced" with "your data is deleted".** C1 makes the
audit-of-record append-only and non-negotiable, so deletion is not something this system can
do. A consent form is where the gap between what a system does and what its operators believe
it does becomes a promise to a person, and that word is where it happens.

## 2. Arrange the co-signer before you start

**A wind-down is a mass revocation, and the system refuses to let one authority perform one.**
`uc8_revoke_token` bounds the share of an agency's population that may be revoked in a rolling
window and demands a co-signing agency past it, because a lone authority able to revoke a
population at will is the coercion this system exists to make expensive.

Ending a pilot has exactly that shape, so the control applies to you ending your own pilot.
Three things must be true of the co-signer, and all three are checked **before anything is
revoked**, because a wind-down that fails halfway leaves a pilot in a state nobody designed:

1. It is not the authority that issued the pilot's credentials. A second authority agreeing is
   the whole content of co-signing; the same one signing twice is not.
2. It holds `BOTH` authorization on **every** algorithm the pilot issued under. A co-signer
   valid for some of the population and not the rest would revoke part of it and then raise.
3. It exists and is active.

**Arrange this before enrolling anybody.** Discovering at the end that no eligible co-signer
exists means a pilot that cannot be wound down as one act.

## 3. Ending it

```python
from pilot import wind_down, residue, consent_language

plan = wind_down(conn, actor_user_id, agency_id=PILOT_AGENCY,
                 cosigner_agency_id=COSIGNER, dry_run=True)   # what would happen
wind_down(conn, actor_user_id, agency_id=PILOT_AGENCY, cosigner_agency_id=COSIGNER,
          reason="pilot concluded")
```

Credentials are revoked first, then participants pseudonymized. That order matters:
pseudonymizing first would leave live credentials belonging to a holder nobody can name any
more, which is worse than either state on its own.

**It is idempotent.** A wind-down that could not be re-run is one nobody dares run the first
time.

## 4. What is still in there afterwards

`residue()` answers that, **derived from the schema rather than from a list somebody
maintains**. A hand-written inventory of what a wind-down leaves behind stops being true the
first time a table is added, and the failure is silent: the privacy claim keeps reading
correctly while becoming false. Add a table with a foreign key to `Individual` and it appears
in the report on the next run, whether or not anyone thought about it.

Run it and put the output in your exit report. It is the honest answer to the question a
participant, a regulator or your successor will actually ask.

## 5. What this row does not yet ship

P5.1 also names a one-command deployment profile, an ops pack, a metrics and reporting bundle
and a DPIA template. Those are not done, and the roadmap row says so. What ships here is the
rollback-and-erasure plan as a path that runs, and the consent language constrained by it,
because those are the parts whose absence would let a pilot start on a promise the system
cannot keep.

For deployment today, use the existing profiles: [DEPLOYMENT.md](DEPLOYMENT.md),
[KUBERNETES.md](KUBERNETES.md), [LINUX-SERVER.md](LINUX-SERVER.md). For the operational
posture around a running instance, [OPERATIONS.md](OPERATIONS.md) and [PRIVACY.md](PRIVACY.md).
