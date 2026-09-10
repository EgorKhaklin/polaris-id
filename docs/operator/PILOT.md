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

## 5. One command

```bash
scripts/polaris-pilot.sh up                                   # the stack
scripts/polaris-pilot.sh report                               # the pack below
scripts/polaris-pilot.sh winddown --cosigner N --agency N     # end it
scripts/polaris-pilot.sh down                                 # stop, data kept
```

`down` is not a wind-down. Stopping a pilot is not ending one, and the command says so.

## 6. The pack you owe your DPO, before you start

**Run `report` before you enrol anybody, not only at the end.** It prints, derived from the
live schema rather than transcribed:

- every table and roughly what it holds;
- **every identifying column found by name across the whole schema**, which is the list a
  hand-written inventory gets wrong. On the shipped seed it finds 77, including a `legal_name`
  re-exposed through a view and the duress columns nobody wants enumerated;
- the effective retention policy per class, from `RetentionPolicy` and not from prose;
- who can read it, by role;
- what survives a wind-down;
- the consent language of §1.

**This is not a DPIA and there is no template for one here.** A DPIA names a controller, a
lawful basis and a jurisdiction; [PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md) says
plainly that it is counsel's work and not an engineering task, and a fill-in-the-blanks form
would invite somebody to treat the blanks as the whole job. What engineering can supply is the
factual half a DPIA is usually wrong about, and supply it in a form that does not go stale on
the next migration.

## 7. What is reused rather than reinvented

The **ops pack** is the existing runbooks: [OPERATIONS.md](OPERATIONS.md) for day two,
[DR.md](DR.md) and [FAILOVER.md](FAILOVER.md) for recovery, [RUNBOOKS.md](RUNBOOKS.md) for
alert response, [PRIVACY.md](PRIVACY.md) for the privacy posture,
[QUANTUM-EVENT.md](QUANTUM-EVENT.md) for an algorithm migration. The **metrics bundle** is the
shipped observability stack (`deploy/observability/`: Prometheus, the alert rules and their
tests, the SLO recording rules, Grafana dashboards), which `up` brings with it. Deployment
substrates other than compose are [KUBERNETES.md](KUBERNETES.md) and
[LINUX-SERVER.md](LINUX-SERVER.md).

Nothing in a pilot profile should be a second copy of those. A pilot that ran on its own
parallel ops documentation would be a pilot whose findings do not transfer.
