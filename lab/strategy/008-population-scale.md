# 008: Polaris at population scale

**Opened 2026-10-01.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md),
on the owner's direction of 2026-10-01: Polaris is to hold eight billion credentials and more, for
as long as it runs. State: OPEN. The falsifiers in section 10 were written before the changes they
judge; section 11 records what they found. Step 1, the Overview, is done; the operation forms,
the lists, the detail pages and the 64-bit keys are next.

---

## The finding that started it

The [capacity model](../../docs/design/capacity-model.md) sizes every id space against the
roadmap's planning target, 350M persons, and on every push it reports that
`Individual.individual_id` and `IdentityToken.token_id` are 32-bit `SERIAL`s lasting about 29
years at the stated enrollment rate. It reports that and decides nothing. ROADMAP.md marks P2,
"Scale architecture (1 to 10M persons, HA)", as built.

Two things in the tree stop holding against that:

1. **The keys.** A 32-bit key holds 2,147,483,647 rows. At eight billion credentials the database
   refuses the 2,147,483,648th whatever the hardware, and at the old target a population with
   renewal history reaches the same wall inside the model's own horizon.
2. **The console.** The operator console opened with exact counts over every credential and
   every verification ever recorded, recomputed on every page view, and seven of its operation
   forms rendered a dropdown listing every active credential or every person. Measured on a
   synthetic population of 2,000,000 persons (3,640,000 credentials, 10,000,000 verifications)
   on one laptop: see `008/BENCH.md`. Each of those costs grows with the population, so a
   console that is quick on notional data is the first thing to fail at the scale P2 says is
   built.

- **Kept:** the capacity model's method (sized from the schema on every push, rates from stated
  targets, an unclassified sequence fails); the console's figures, which are what an operator
  acts on; exact counts wherever the table is small.
- **Dropped:** that a 32-bit key is a tradeoff to be weighed against a horizon (at the owner's
  target it fails on the first day), and that a console page may cost in proportion to the
  population it describes.
- **New position:** every id space that grows with the population or its activity is 64-bit,
  sequences included; every console page costs the same at any population. A page reads a
  primary-key or unique-index lookup, a bounded slice of an index, a capped count that says "or
  more", or an estimate that says it is one: the planner's statistics or a block sample of the
  table, exact below a million rows.

## 1. What capability is being considered?

- **Keys:** `IdentityToken.token_id`, `Individual.individual_id`, every column that references
  them, and the other population-scaled 32-bit keys the audit lists, widened to `BIGINT` with
  their sequences, the routines that take or return them, and the views that read them.
- **Console:** figures that are exact at any size or bounded and labelled (`polaris_web/population.py`);
  lists paged by key instead of by offset; record lookup by identifier instead of dropdowns of the
  population; counts formatted for thirteen digits.
- **Exact counts at any population:** `PopulationCount`, kept by statement triggers that only append
  signed changes, so a writer never waits on a counter row (migration 2026-10-01-005).
- **Indexes** the bounded queries need, added as expand-only migrations (2026-10-01-004).

## 2. What problem would it solve?

The database could not hold the owner's population, and the console could not be used long
before the database filled.

## 3. Who would plausibly need it?

- The owner, by direction.
- Any authority whose credentials, counted with renewals and history, pass 2,147,483,647.
- Any evaluator who loads a realistic population and opens the console.

## 4. What existing systems already solve it?

PostgreSQL: `BIGINT` keys and sequences declared `AS bigint`; the planner's own row estimates
(`pg_class.reltuples`); `TABLESAMPLE SYSTEM` block sampling; B-tree range scans with `LIMIT`.
Keyset pagination is the standard remedy for `OFFSET`. Nothing here is invented.

## 5. Can Polaris interoperate instead of rebuild?

Yes, entirely: every mechanism is a database feature or a query shape.

## 6. What unique advantage could Polaris obtain?

An identity authority whose schema and operator console are measured flat from notional data to
millions of rows, with the bench and its numbers in the tree, so the claim is re-runnable rather
than asserted.

## 7. What happens if Polaris does NOT build it?

The database stops issuing at 2,147,483,647 credentials, and the console's Overview, lists and
forms become unusable at a fraction of that (measured in `008/BENCH.md`).

## 8. What other work would be delayed?

The remaining console rework phases (workflows, transparency pages, the Atlas and Athena, the
launcher) and lane 1's coverage target.

## 9. Can the idea be tested cheaply in LAB first?

Yes: `008/` holds the generator for a synthetic population and the bench that times every
console page against it. The console changes are measured there before and after.

## 10. What evidence would prove the bet was wrong?

Written before the changes land. Any one of these falsifies the claim it names:

1. **Flat pages.** A console page whose median server time on the bench's large population is
   more than three times its time on the seed data, after the change.
2. **No population scans.** A console query whose plan, on a fresh schema with sequential scans
   disabled for planning, still contains a sequential scan of a population table
   (`IdentityToken`, `Individual`, `TokenSignature`, or an event table).
3. **Keys.** An insert of a credential or a person with an id above 2,147,483,647, or of a row
   referencing one, refused anywhere in the schema, on a fresh database or a migrated one.
4. **Honest estimates.** An estimated figure shown without its mark, or an estimate that differs
   from the exact count by more than 5% for a value above 1% of its table on the bench.
5. **Small deployments unchanged.** Any figure on the seed data that is not exact.

## 11. What the falsifiers found (step 1, the Overview)

Measured on one laptop (PostgreSQL 16) against the seed and a synthetic population of 2,000,012
persons, 3,640,007 credentials and 10,000,010 verifications ([008/gen.sql](008/gen.sql),
[008/bench.py](008/bench.py), numbers in [008/BENCH.md](008/BENCH.md)).

- **Falsifier 4 fired twice, and both methods were dropped rather than tuned.**
  - A block sample (`TABLESAMPLE SYSTEM`) of 50,000 rows put every status 6% high in one draw:
    the bench stores credentials clustered by status, so a sample of blocks is a sample of
    clusters. ANALYZE's own statistics were within 1%, but PostgreSQL hides them from a role a
    row-level security policy applies to, and rightly: they would show an authority-bound operator
    the whole population. Replaced by exact counts (`PopulationCount`).
  - A rate over the latest 10,000 verifications, times a window, missed the 24-hour count by 57%:
    the bench had been idle since loading, and the quiet hour stretched the slice's span. Any
    traffic with pauses or a daily cycle does the same. Replaced by exact counts up to a cap,
    and shares that describe the latest slice and say so.
- **Falsifier 2** is a test (`test_every_overview_query_has_a_bounded_plan`) that runs every
  Overview query with EXPLAIN ANALYZE over a synthetic population and fails on any read beyond
  the page's own bounds. On its first runs it caught: the row estimate returning nothing for an
  unpartitioned table (`pg_partition_tree` lists only partitions), which would have scanned a
  million rows on every view and then sampled 5% of the table; the planner reading every active
  credential to count the few past their expiry; and a sort of the whole lifecycle history to show
  ten events, which was the guard's own error (an incremental sort streams). Its control fails
  the old population count.
- **Falsifier 1:** the Overview took 10.4 s at two million persons and takes 0.12 s, against 0.09
  s on the seed (1.3 times). The forms, the lists and the detail pages still fail it.
- **Falsifier 5** holds: on the seed every Overview figure is exact (a test).
- **Falsifier 3** is untested: the keys are still 32-bit.
