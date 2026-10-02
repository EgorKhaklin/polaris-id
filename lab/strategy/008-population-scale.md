# 008: Polaris at population scale

**Opened 2026-10-01.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md),
on the owner's direction of 2026-10-01: Polaris is to hold eight billion credentials and more, for
as long as it runs. State: OPEN. The falsifiers in section 10 were written before the changes they
judge; sections 11 to 13 record what they found. Steps 1 to 3 (the Overview, the operation
forms, the lists and record pages) are done; the aggregate pages (enrolment, the signals queue,
the Atlas), the revocation procedure's counts and the 64-bit keys are next.

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
  population (`polaris_web/lookup.py`); counts formatted for thirteen digits.
- **Exact counts at any population:** `PopulationCount`, kept by statement triggers that only append
  signed changes, so a writer never waits on a counter row (migration 2026-10-01-005).
- **Indexes** the bounded queries need, added as expand-only migrations (2026-10-01-004, and
  -006 for the person lookup).

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

## 12. What the falsifiers found (step 2, the operation forms)

Seven forms (UC-4, UC-5, UC-6, UC-7, UC-8, UC-9's first phase, and recording a verification)
rendered a dropdown of every active credential, every credential or every person. Each now starts
from one record, opened from that record's own page or found by what the operator holds:
a credential by its number, token value or card serial (three unique indexes, read one at a time),
a person by number or by the beginning of the name with the date of birth
(`idx_individual_birth_name`, migration 2026-10-01-006, at most 20 rows and a "more" mark).

- **Falsifier 2** is `test_every_lookup_has_a_bounded_plan`: every lookup and every form opened on
  the record it found, run with EXPLAIN ANALYZE over the synthetic population, reads no scan
  beyond 80 rows. Its control, `test_the_person_lookup_needs_its_index`, drops the index and must
  fail: a name search then reads everyone born that day. The first draft looked a credential up
  with one `token_value = $1 OR physical_serial = $1 OR token_id = $2`; with bitmap scans priced
  out, as they are at scale, that plan reads the whole table, so it is three lookups.
- **Falsifier 1** holds for all seven. Opened on a record, at two million persons each costs
  7.5 to 16 ms, within 1.2 times its time on the seed; listing a population, they took 1.7 s to
  39 s and up to 629 MB of HTML. A lookup costs 6 to 12 ms at either size
  ([008/BENCH.md](008/BENCH.md), step 2).
- **What the operator typed never reaches a URL.** The lookup is a POST; the page it leads to
  names the record by its number (the relying-party API keeps identifiers out of URLs the same
  way). A credential another authority issued reads exactly as one that does not exist, to an
  operator bound to one authority (a test compares the two answers).
- **Found on the way, recorded rather than folded in:** UC-4 asked the operator's binding about the
  lost credential and not the reserve it activates (closed in its own commit); the warrant audit's
  own comment says zero-knowledge events come back redacted, while its query returns none of them
  (the page now says what the query does; the comment is corrected with the next migration that
  replaces the function); and `uc8_revoke_token` counts an authority's every credential, and every
  revocation in the window, on each revocation (open: the engine half of the next step).

## 13. What the falsifiers found (step 3, the lists and the record pages)

- **Lists page by key by default.** The credentials, people and verification lists already had
  key paging, behind a parameter; a list opened from a link paged by offset, and OFFSET reads every
  row it skips (`/verifications?page=5000` took 3.1 s at two million persons). Key paging is now
  the default and an old page number answers while its offset stays within 10,000 rows.
- **A filter the indexes do not serve reads a bounded window.** Filtering the verification log by
  outcome walked the time index until it had a page of matches: one match in a million read a
  million rows for a page. A filtered page now reads at most 20,000 events, says how far it looked,
  and its pager goes on from there. Filtering by credential is new and is served by the
  credential's own index, so it needs no window.
- **Foreign keys between population tables carry an index.** A catalogue query found nine with
  none: reading one record's rows scanned the referencing table, and deleting a referenced row
  scanned it to check the key. The investigation page found a credential's successor by a parallel
  scan of every credential (904 ms at 3.6 million), and every credential's page read its device
  bindings and revocations the same way. Migration 2026-10-01-007 adds the nine;
  `test_every_foreign_key_between_population_tables_is_indexed` reads the catalogue for any other,
  and its control drops one.
- **A record's page shows the latest rows** of whatever grows while the record lives (its
  verifications, its lifecycle, its epoch leaves), links the rest, and counts lifetimes up to a
  cap that says "or more".
- **Falsifier 1** holds for every list and record page at two million persons: each costs
  within 1.7 times its seed time, and an offset page past the bound is refused (one 5,000
  pages into the verification log took 37 s). A filter with no match in the log took 1.4 s and
  takes 49 ms; the credential investigation page took 200 ms and takes 51 ms
  ([008/BENCH.md](008/BENCH.md), step 3). The enrolment summary still fails it (6.4 s): it is
  the next step's.
- **Falsifier 2** is `test_every_list_and_record_page_has_a_bounded_plan`: the lists by key, a rare
  filter through its window, a credential's page, both investigation pages and the log filtered by
  one credential, run with EXPLAIN ANALYZE over the synthetic population with every bound shrunk.
