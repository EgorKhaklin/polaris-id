# The national capacity model

**Reader:** the operator or assessor asking whether this system can run a country, and the
reviewer checking whether the answer was arrived at honestly. **Job:** validate the roadmap's
four stated planning targets, say which figures rest on a measurement and which on an
assumption, and name what stops the system reaching them.

The mechanism is [`polaris_web/capacity.py`](../../polaris_web/capacity.py). The measured
numbers under it are [BENCHMARK.md](../reference/BENCHMARK.md).

---

## 1. What the model found

The roadmap states four targets and says in the same sentence that they are "to be validated,
not asserted":

> 350M persons; 5,000 sustained and 50,000 peak verifications/s nationally across federated
> instances; an enrollment surge of 200,000/day sustained during rollout years; 99.99%
> availability on the verification path.

Every throughput target clears by more than an order of magnitude.

| Target | What it costs | Source |
| --- | --- | --- |
| 50,000 peak verifications/s | ~6.4 cores | MEASURED: 7,848/s per core, single-witness verify-at-use |
| 5,000 sustained verifications/s | under one core | MEASURED |
| 200,000 enrollments/day | ~9 minutes of one signer | MEASURED: 372 tokens/s, signing-bound |

And the system could not have run for a week at the sustained target, because
`VerificationEvent.event_id` was a 32-bit `SERIAL`. Two billion, one row per verification, five
thousand a second: **five days.** At the 50,000/s peak target, **twelve hours.**

Nothing is slow when a sequence is exhausted. Nothing is overloaded, no query degrades, no
index bloats. Every insert on the path fails with `nextval: reached maximum value of sequence`,
and on the verification path that is the whole service.

That is why the model reads the schema rather than a spreadsheet of throughput figures. A
spreadsheet says the system is ten times faster than it needs to be. It is, and that was not
the question.

---

## 2. Two findings that carry no assumption

Most capacity arithmetic depends on a growth assumption somebody can argue with. Two of these
do not, which is why they were acted on rather than filed.

**`VerificationEvent.event_id`** grows one row per verification, and the rate is the roadmap's
own stated target. There is no modelling step between the schema and the answer.

**`TokenStateEpochLeaf.leaf_id`** holds one row per token per epoch, so its exhaustion point is
a COUNT OF CLOSURES rather than a duration: a 350M-credential population exhausts a 32-bit leaf
id on the **sixth epoch closure**, whenever those happen. Expressing it in days would have
required assuming a cadence and would have made the finding weaker, not stronger.

The remaining figures are labelled `ASSUMED` and print their assumption beside the number.

---

## 3. The fix, and why the sequence is the part that gets missed

[`2026-09-10-015-widen-surrogate-ids`](../../polaris_sql/migrations/2026-09-10-015-widen-surrogate-ids.up.sql)
widens five surrogate ids to 64-bit: the two above, plus `TokenLifecycleEvent.event_id`,
`TokenSignature.signature_id` (a quantum-event migration re-signs the whole population in one
pass, so it consumes 350M ids at once) and `AuthAuditLog.audit_id`.

**A `SERIAL` is two objects.** An `integer` column, and a sequence declared `AS integer`.
`ALTER TABLE ... ALTER COLUMN ... TYPE BIGINT` changes the first and not the second. After it,
`information_schema` reports `bigint`, the schema file looks right, the capacity model reports
the target MET, and the sequence still refuses to issue 2,147,483,648. The widening looks done
and is not, and nothing discovers it until the day the old ceiling arrives.

So the migration widens both, and
[`scripts/polaris-capacity-drill.py`](../../scripts/polaris-capacity-drill.py) does not inspect
types at all. It sets each sequence one short of the old ceiling and inserts across it, with a
deliberately half-widened scratch table alongside as the control: a `BIGINT` column whose
sequence is still `AS integer`, which fails at exactly the point the real one used to. Without
that control, a passing widening test proves only that the number fit.

**Why now rather than when it matters.** `ALTER COLUMN TYPE` rewrites the table and every index
on it, and for the partitioned `VerificationEvent` it rewrites every partition. Against a
national deployment holding two billion rows that is a multi-hour outage on the busiest table
in the system; against a deployment that has not started, it is instant. The right time to
widen an id column is before there is anything in it.

**Widening is an expand, not a contract.** A rolling deploy runs the old code against the new
schema, and old code reading a wider column reads the same values. `check_migrations_expand_
contract` grades the claim rather than inferring it: the migration declares
`-- widens: Table.column OLD -> NEW`, and the check verifies the pair is a recognised widening,
that the declared target matches what the statement sets, and that **no foreign key references
the column** -- a parent widened to `BIGINT` under a child still declaring `INTEGER` would
accept ids the child cannot hold.

**The migration is not zero-downtime, and the declaration does not pretend it is.** The
column change is an expand, but the five row-returning functions that expose these ids
declare their result columns explicitly, and `CREATE OR REPLACE` cannot change a return type
-- so they are dropped and the object sync recreates them, leaving a gap of seconds in which
`uc7_warrant_audit` and the four Atlas readers do not exist. `polaris-deploy.sh` runs the
migration and the sync before rolling either colour, so the gap is bounded; it is not zero.
Combined with the partition rewrite, this belongs in a maintenance window.

Those functions are found from the catalog rather than listed: a `TABLE`-returning function's
result columns are `OUT` arguments, so the ones exposing a widened id as 32-bit can be asked
for by name and type. A hand-written list is worse than useless here, because
`DROP FUNCTION IF EXISTS` with a signature that does not match reports "does not exist,
skipping" and leaves exactly the broken function it was meant to remove. Four of the five in
the first draft did that.

The down-migration narrows back and **can fail**, which is correct. There is no safe narrowing
of a value that no longer fits, and coping by truncating would rewrite identifiers on rows C1
makes permanent.

---

## 4. What is not validated, and stays that way

**99.99% availability on the verification path** is 52.6 minutes of downtime a year.
Establishing it needs a failure rate and a recovery time from a multi-region deployment under
real traffic.

What is measured is narrower and says so. The rolling-deploy drill holds an authenticated
verification load across the transition and drops zero verifications. The failover drill
induces four failures and demonstrates that verification recovers after each and keeps serving
at rate. Both run on a **two-member topology on CI hardware**, not across regions.

A 99.99% figure extrapolated from that would be an assertion wearing a measurement's clothes,
so `validate()` reports the target `UNVALIDATED` and says what would settle it. A target
nothing here can establish never becomes MET because its other numbers look comfortable, and
that rule is checked by running the model rather than by finding the constant's name in it.

---

## 5. What the model still reports rather than decides

`Individual.individual_id` and `IdentityToken.token_id` are also `SERIAL`, and last about 29
years at the stated enrollment rate. That is outside the model's 25-year horizon rather than
comfortably beyond it, and both are referenced by foreign keys across the schema, so widening
them means widening every referencing column too.

The model prints the nearest surviving 32-bit column on every run for that reason. A column
that clears the horizon by four years has not been shown to be safe; it has been shown to be
outside a window somebody chose.

---

## 6. What is checked

| Mechanism | What it holds |
| --- | --- |
| `check_capacity_model` | Recomputes the exhaustion arithmetic from the live schema every push, so a `SERIAL` reintroduced on a table that grows with national traffic fails on that push. Resolves every MEASURED constant against BENCHMARK.md. Runs the model to confirm an unvalidated target is never reported met. Fails if the schema parse finds no sequence columns at all. |
| `check_migrations_expand_contract` | Grades declared widenings: recognised pair, declared target matches the statement, and no foreign key references the column. |
| `scripts/polaris-capacity-drill.py` | Inserts across the old 32-bit ceiling on a real database, with a half-widened control that must fail there. |
| `polaris_web/test_capacity.py` | 25 measured tests, including that a partitioned table is not lost by the parser (`VerificationEvent` ends its `CREATE TABLE` differently from every other table, and losing it would have hidden the whole finding). |

---

## 7. Running it

```
python3 -c "from polaris_web.capacity import validate, render_markdown; \
  print(render_markdown(validate(open('polaris_sql/01_schema.sql').read())))"
```

Change a target, a growth assumption or the horizon and the verdicts move. That is the point:
the model is a thing you re-run, not a number you are asked to believe.
