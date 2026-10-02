# 009: The Atlas and Athena, rebuilt around what Polaris is for

**Opened 2026-10-02.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md),
on the owner's direction of 2026-10-01: the Atlas is to be reworked completely, as the best version
of what it should be rather than a restyle, and Athena, which has no real use today, is to be
remade with one. State: OPEN. The falsifiers in section 10 were written before the changes they
judge; section 12 records what they found. Steps A0 (the Atlas names no person), B1 (the
live constraint board) and B2 (the self-test) are done. This is the console work [008](008-population-scale.md) left for
last ("the Atlas"), and it inherits 008's rule that a page costs the same at any population.

---

## The finding that started it

Three things the tree says stop holding against the rest of it.

1. **Athena says live and reads nothing live.** The console tells an operator that each
   constitutional rule is "linked to the exact live mechanism that enforces it", and that the
   build fails if a named mechanism disappears from the tree. The page reads the curated rows in
   `athena_rule_enforcement`; the check behind it, `check_athena_rule_enforcement_resolves`, reads
   the repository. Neither reads the database the console is connected to. A database built from
   an older schema, a trigger switched off with `ALTER TABLE ... DISABLE TRIGGER`, or a unique
   index left invalid by a failed build shows the same page. The curated row for C1 says an
   "AFTER trigger" refuses changes to the audit; every audit-of-record trigger is a BEFORE
   trigger (`check_aor_append_only_triggers` requires it), and nothing compares the two.
2. **The Atlas is built to look at single events and single people.** Its page route describes it
   as "a live operational investigation surface, not a dashboard", whose panels exist "to explain
   a single event when the operator clicks one". At street zoom its map plots each disclosed
   verification at its coordinates with the holder's name and credential number
   (`/api/atlas/points`); its event feed and its records grid name the holder of every disclosed
   event; all three answer any signed-in role. Admin and auditor can also find a person by name
   and focus the map on that person's located history (`/api/atlas/subjects/search`,
   `/api/atlas/subject`). [federation-topology.md](../../docs/design/federation-topology.md)
   gives, as a reason Polaris is federated, that "a central verification log can reconstruct a
   population's movements". Within one authority, the Atlas draws that reconstruction on a map.
   The record pages already show the holder and the place of a disclosed verification to whoever
   handles the credential; what only the Atlas adds is the coordinates and the picture. And it
   adds them unrecorded: the warrant audit, both investigation pages and every page of the
   verification log write an `AuditAccessLog` row, while the points, the feed and the grid write
   none. [transparency-program.md](../../docs/design/transparency-program.md) states the rule (a
   route that reads a tracked table's rows through a function writes the row) and
   `check_audited_reads_are_logged` enforces it, but the check reads only `05_procedures.sql`,
   and the four functions behind those routes are in `11_atlas.sql`: the escape the check was
   written for, one file over.
3. **The Atlas costs the population.** Each view of the page counts five tables that grow with
   the population and aggregates every credential and every verification four more times: 5.1 s
   at two million persons against 36 ms on the seed ([008/BENCH.md](008/BENCH.md)). Its person
   search is an `ILIKE '%...%'` over every person, and a person's focus reads all of their events
   with no bound.

- **Kept:** C6 (a zero-knowledge event is counted and never located) and C8 (every Atlas response
  is capped); the record pages as the place a record is read, by number, under the role gates and
  C6; the warrant audit (UC-7) as the lawful path to one person's history, which writes a row to
  the audit of record on every access; Athena's design law (read-only, never sovereign, no person)
  and its authority, proof and trust questions, which answer real questions; 008's scale rule;
  the console's design system.
- **Dropped:** that the Atlas is an investigation surface, for single events, named holders or one
  person's trail; and that Athena may report the repository's state as the system's.
- **New position:** the Atlas shows the system and never a person: counts over fixed windows and
  regions, read from rows the database keeps, each capped, none of which narrows to a holder, with
  what it withholds listed on the page beside the rule that withholds it. Athena shows each
  constitutional mechanism as the database it is connected to holds it, at the moment the page is
  read, says what it cannot verify from there, and can attempt the forbidden writes itself and
  show what refused them.

## 1. What capability is being considered?

**Athena**

- **B1, the constraint board.** Each mechanism `athena_rule_enforcement` names is looked up in the
  catalogue of the connected database when the page is read: a trigger present, enabled, and its
  timing and events; a CHECK constraint present and validated; a unique index present, valid and
  unique; a routine present. The board shows the definition the database holds. C1 is listed per
  audit-of-record table, one trigger each, so a table that lost its guard is named. C5's script
  policy and C8's caps are read from the running application and labelled as application rules.
  Repository checks are labelled as such: they run on every change and read the repository, not
  this database. "Present and switched on" is not "refuses": a trigger whose function was rewritten
  to let writes through still shows as present, which is what B2 is for.
- **B2, the self-test.** On demand, an admin or auditor runs a fixed set of probes on the
  application's own database connection. Each probe attempts one forbidden write inside a
  savepoint, and the transaction they share is always rolled back, including when a probe
  succeeds. Targets are rows that already exist, changed to their own values (a BEFORE trigger
  fires all the same), or inserts that must fail a named rule. Each probe declares the refusal it
  expects (an SQLSTATE and the mechanism) and the board shows what actually refused it, with the
  database's message cut to its first line and no values from a row. A probe the database accepts
  shows as not enforced. The probes:
  - C1: an UPDATE of an audit-of-record row;
  - C2: a zero-knowledge verification that carries a credential number;
  - C3: a second ACTIVE credential for one person;
  - the success rules: a SUCCESS recorded for a credential that is not live;
  - the binding: a credential moved to another holder;
  - the application role's withdrawn writes: a direct `DuressEvent` insert.

  C8 is not a database rule. Its probe calls an Atlas route with a limit above the cap and shows
  the clamped value, drawn apart from the database refusals: a green C1 means the database
  refused; a green C8 means the application clamped. The probes set `application_name`, so the
  constraint-violation lines they leave in the server log name the self-test, and the operator
  runbook says to expect them. A refused insert can still advance a sequence; the gap is the only
  trace a probe leaves.
- **B3, the authority graph.** The application role's privileges read from the catalogue against
  the boundary `09_grants.sql` declares, the federation trust edges (non-transitive, from the
  existing views), and the signing custody in force.
- **B4, the governance log.** The constitution's amendments and the qualifying reasons behind
  product changes, as a curated list.

**Atlas**

- **A0, no person.** No Atlas response carries a holder's name or a credential number; the person
  search and the person focus are removed. One person's history stays where it was already
  lawful and audited: the warrant audit and the record pages.
- **A1, liveness and throughput:** issuance, verification and revocation over fixed windows, read
  from hourly rollups kept the way `PopulationCount` is kept (008 step 4b).
- **A2, integrity:** the latest epoch and anchor batch, and the Athena board's verdict.
- **A4, bounded anomaly:** counts by authority, context, outcome and region against the previous
  window. Its group keys are never a person, and no control narrows one.
- **A5, the limits panel:** what the Atlas will not show, each item beside the rule that forbids
  it and linked to that rule live in Athena.
- **The map** becomes counts per region (the requesting authority's jurisdiction) over a fixed
  window. The point, cluster and hexagon layers go: at street zoom a count of one is a point.
- A3 (capacity) is `/metrics`, which exists; it is not rebuilt here.

## 2. What problem would it solve?

The console is where an operator runs the system and where an evaluator decides whether to trust
it without reading the schema. Today the Atlas's natural improvement path, more detail, finer and
faster, ends in the tool an identity authority must not have, and Athena tells an evaluator
nothing a README does not, with a word ("live") that is not true of it.

## 3. Who would plausibly need it?

- The owner, by direction.
- The first pilot operator, who must run the system day to day without holding a surveillance
  surface they would answer for.
- An evaluator, auditor or reviewer who must decide whether the system enforces what it claims
  without reading the code. The board and the self-test answer that on the database in front of
  them, not on the repository.

## 4. What existing systems already solve it?

General dashboards (Grafana, Metabase, Superset) solve operational charts; their default is to
drill to the row, which is the shape the Atlas is leaving. Database monitors report whether a
trigger or an index exists. None of them knows which mechanisms a constitution depends on, and
none attempts the forbidden writes and reports what refused them.

## 5. Can Polaris interoperate instead of rebuild?

For rendering, it reuses what the console already ships (the design system, MapLibre GL for the
regions). For the data and the guarantees, no: the views read Polaris's own rollups and its own
catalogue, and the probes are Polaris's own rules.

## 6. What unique advantage could Polaris obtain?

An operations console that cannot become a tracking tool, and a governance page on which an
outsider can watch the database refuse to break its own rules. A system whose console is built
around following people cannot offer either without giving that up.

## 7. What happens if Polaris does NOT build it?

The Atlas stays a per-event, per-person map that any signed-in role can read, at a cost that
grows with the population, and Athena stays a page of text that calls itself live.

## 8. What other work would be delayed?

The remaining console phases (the transparency pages, the launcher) and the 64-bit keys of 008.
The connector work runs in parallel and is not delayed.

## 9. Can the idea be tested cheaply in LAB first?

Each surface is measured on 008's synthetic population before and after, and each falsifier below
is a test or a measurement, not a review. The board and the self-test are tested by breaking the
mechanisms they report on, the way the mutation drills are.

## 10. What evidence would prove the bet was wrong?

Written before the changes land. Any one of these falsifies the claim it names.

1. **A person surface.** Any Atlas or Athena view, query, filter or export that returns, or can
   be narrowed to, one person's history, location trail or linked events, beyond the record pages
   reached by number and the warrant audit.
2. **Find-the-unenrolled.** Any view whose main use is listing the people who are not enrolled or
   not verified ([tiered enrollment](../../docs/design/tiered-enrollment.md)), or any per-person
   status the application role can read that would make such a list cheap.
3. **Not scale-flat.** Any Atlas or Athena page or API route whose median server time on 008's
   large population is more than three times its seed time, or whose plan scans a table that
   grows with the population.
4. **A located zero-knowledge event**, on any new read path (the redaction property suite and
   `check_c6_atlas_redacts_zk_location`).
5. **An unbounded aggregate:** an Atlas response without a C8 cap, or a window without its label.
6. **Athena that only looks live:** a board tile or a self-test result that is fixed in code,
   cached across requests, or read from the repository while it is presented as the database's.
7. **A self-test that writes:** a probe whose transaction commits, or a row a probe leaves behind.
8. **A board that cannot fail:** a trigger disabled, a constraint dropped, an index invalidated or
   a probe's rule made permissive, without the matching tile turning red in a test that does it.
9. **Overclaim:** Athena or Atlas wording that strengthens duress past "aware" or states the
   certification past its one scoped sentence (`check_duress_claims_are_aware`,
   `check_public_claims_honest`).

**Kill criterion.** If by 2026-12-31 no evaluator, operator or reviewer outside the project has
used the Atlas or Athena and said it changed what they would trust or adopt, the rebuild was
presentation, and both surfaces return to the lab.

## 11. Order of work

1. A0: the Atlas names no person. It goes first because its unrecorded reads are a defect against
   a rule the tree already states, not only a direction this record takes; the audited-reads
   check reads every SQL file in the same change.
2. B1, the constraint board, with C1 listed per audit-of-record table.
3. B2, the self-test.
4. The Atlas on rollups: A1, A2, A4, the regions map, and A5.
5. B3 and B4.

Each step is reviewed before it merges, measured on 008's population, and recorded below.

Not decided here: the verification log lists each disclosed verification with its holder to every
console role. Whether an operator should see holders on a list, rather than on a record looked up
by number, is a question about the record pages, not the Atlas, and it is left to its own record.

## 12. What the falsifiers found

### Step A0 (2026-10-02): the Atlas names no person

**Falsifier 1 had fired before anything was built.** Measured on main (`4f18e1b6`) on a freshly
loaded database, signed in as an operator: `/api/atlas/events` returned 17 events, 14 of them
naming the holder with the credential number and coordinates, and no `AuditAccessLog` row was
written; one page of the verification log writes one. The map's points and the records grid
returned the same names to every role, and admin and auditor could focus the map on one
person's located history.

Withdrawn: `atlas_points_verifications`, `atlas_points_lifecycles`, `atlas_recent_events` and
`atlas_records` (dropped by the object-synced file, so a running database loses them too) and
the five routes behind them (`/api/atlas/points`, `/events`, `/records`, `/subjects/search`,
`/subject`), which now answer 404. On the page: the Records tab, the Points layer, the event
feed and its detail panel, the person search and its banner, and the +PQ modifier, which
filtered only the points. A click on a region opens the density surface; nothing opens an
event.

Pinned: `check_atlas_console` holds every `atlas_*` function in any SQL source, the migrations
included, and every Atlas route anywhere in the package to counts (no column naming a person, a
credential or one event, no read of `Individual`); `check_audited_reads_are_logged` reads every
SQL source instead of `05_procedures.sql` alone. Both fail on main's tree, on exactly these
functions. `AtlasShowsNoPersonTests` asserts the effect: the withdrawn routes answer 404 to
every role, and no response from any remaining Atlas route carries a person, credential or
event key or a holder's name, nor writes an access row it would owe.

Not answered yet: falsifier 3. The remaining aggregates still read raw events (the page took
5.1 s at two million persons, `008/BENCH.md`); step 4 moves them onto rollups.

### Step B1 (2026-10-02): the constraint board

`athena_board.read_board()` builds the Constitution tab from the connected database's
catalogue at request time: a trigger present and switched on, on its table and on every
partition it was cloned to; a constraint present and validated on every copy; an index valid,
ready, live and unique; a routine present; each with the definition the database holds. C1 is
listed table by table (32 rows, one per audit-of-record table, held to exactly that set by
`check_athena_rule_enforcement_resolves`). The curated C1 note had said an "AFTER trigger"
refuses changes; every audit trigger is BEFORE, and the note says so now. C5 and C8 are read
from the running application and drawn apart from the database's refusals.

**Falsifier 6 (Athena that only looks live)** is now a check: `check_athena_console` requires the
board to ask the catalogue (`pg_trigger.tgenabled`, `pg_constraint.convalidated`,
`pg_index.indisvalid`, `pg_proc`), the route to build the page from it, and the page to say when
it read the database. **Falsifier 8 (a board that cannot fail)** is tested on a real database:
a C1 trigger switched off on its table, the same trigger switched off on one partition only, a
constraint dropped, and the C3 unique index replaced by a plain index of the same name each turn
their rule red on the board and on the page (`AthenaConstraintBoardTests`).

What the board still cannot see: a mechanism that is present, switched on and hollow. That is
B2's self-test.

### Step B2 (2026-10-02): the self-test

`POST /athena/self-test` runs six probes on the application's own connection, each inside a
savepoint, in one transaction that is always rolled back: C1, C2, C3, the success rules, the
binding and the privilege boundary. Each reports what refused it (read from the database's
error: a trigger function, a constraint or index, or the privilege boundary) against what was
expected, with every number in the message masked. C8's probe asks the Atlas breakdown for a
thousand times its cap, through the route as the signed-in user, and is drawn as an
application clamp. Only an administrator or auditor may run it, and an account bound to one
authority is refused, as the SQL console refuses one.

What it found about the role: run as the schema owner (as the suite and a development stack
connect), three probes are accepted, because the success rules, the binding and the privilege
boundary deliberately do not bind the owner; the page says so. Run as `polaris_app`, all six are
refused. The self-test is how an operator learns which of the two their deployment is.

**Falsifier 7 (a self-test that writes)** is a check and a test: `check_athena_console`
requires the module never to commit or switch to autocommit and to roll back the transaction and
every savepoint in a `finally`; `AthenaSelfTestTests` compares the verification and duress
counts and every credential's status and holder before and after a run. **Falsifier 8**, for the
self-test: with `reject_audit_modification` rewritten to let writes through (present, switched
on, hollow: what the board cannot see), the C1 probe is accepted and reads as not enforced, as
the owner; as `polaris_app` the privilege boundary still refuses it, and the probe says that is
what refused it. On the seed no person holds both an ACTIVE credential and a live reserve, so
the C3 probe reports "not run"; given such a person, it is refused by `uq_one_active_per_person`.

Review (2026-10-02): approved, with the run recorded in the application log rather than a
widened AuthAuditLog event type. Two notes taken: the masking covers numbers only, and says to
mask any text column a later probe writes; and each rule card now carries its probe's result
beside the catalogue's, so a reader sees "in force" corroborated by "refused when tried", or
the card marked when the two disagree (`test_a_hollow_trigger_marks_its_card`).

### Step 4, part one (2026-10-02): the activity rollups

What the Atlas will read instead of the event tables. `VerificationRollup` counts verifications
by hour, requesting authority, context, outcome, disclosure level and the verified credential's
algorithm; `LifecycleRollup` counts transitions by hour, acting authority and type; each has a
daily twin for windows longer than a week and a delta table its statement trigger appends to.
They are kept the way `PopulationCount` is (writers only append, one fold at a time, a reader
sums totals and deltas, the owner alone recounts) and carry the row-level security of the table
they count. No column names a person, a credential or a place, and none holds a coordinate. No
reader moves in this part: the Atlas still reads the events, and falsifier 3 is measured in the
next.

Two decisions this part makes. **The hour is the finest grain.** Today the series route cuts
the 1-hour window into as many as 240 buckets of 15 seconds (the console asks for 48, of 75
seconds), which with an authority and an outcome selected comes close to placing one
verification in time; the rollups cannot. **Hourly cells live as long
as the events they count.** `uc_archive_purge` folds and then deletes the hours wholly before
its cutoff; the daily rows stay, as statistics that say nothing finer than a day. The load's own
purge test shows it: a verification 1,100 days old is purged, its hour goes, and its day still
counts it. The recount keeps the hours and days a recorded purge cut through, since their events
are partly gone and a recount would undercount them.

Measured on a fresh load: every hour's cells equal a recount of the events. Sixteen mutants,
each killed by the fast suite (`TestActivityRollups`): each of the four triggers dropped, the
fold emptied, the purge without its rollup step, the recount ignoring the purge or recounting
nothing, each of the six row-level policies opened, the lifecycle policy hiding transitions no
authority made, and a write grant to the application role. The purge and the recount are shown
waiting for a fold that holds the lock and no row, since only then does a wait prove the lock.
Measuring that found the population recount's own lock test passing with its lock deleted: two
recounts contend on the rows each deletes, lock or no lock. It holds a fold now, and the deleted
lock turns it red.

Not decided here: small cells. A cell for a rare authority and context in one hour can count one
event, and someone who knows that one person was there learns its outcome. The hour floor
narrows this without closing it. Whether the readers suppress or coarsen cells under a minimum
size is a question for the next part, where the readers are built.

### Step 4, part two (2026-10-02): the Atlas on the rollups

Every Atlas reader now sums the rollups and none reads an event table: the headline, the series,
the breakdowns and cross-tabs, the heatmap, the stacked series, the authority facet and the
regions. The cluster, hexagon and timeline layers are withdrawn, since at street zoom a bin of
one is a point, and the map draws counts per jurisdiction alone, each placed from reference data
about the jurisdiction (`static/atlas-regions.json`), never from where anyone was verified. A
window starts at the top of the hour, or past a week the day, that holds its nominal start, and
says so. One context and one authority at a time: with a set, the answer for all but one would
subtract from the answer for all.

**Small cells are withheld.** Every count below five is `null` and reads "<5". Every count is a
part of its window's scope, withheld when it or the rest of its scope is below five, so a
category of 98 in a scope of 100 does not give the other 2 back; a share is withheld when its
count is. A fixed dimension lists every value, a zero withheld like a small count; an open list
folds its small categories into one row; the authority facet lists every authority in name
order, active or not; a cross-tab row's total is withheld when the cells withheld beneath it sum
to less than five. A question whose scope holds fewer than fifty events is answered, withheld as
any, and logged with who asked and what, cache hits included. What this does not close:
subtraction across responses can still recover a small cell, for example a breakdown with and
without one outcome. Complementary suppression is the stronger fix, and it is deferred until a
deployment's use shows which questions are asked together.

**Falsifier 3, measured.** On 008's population (two million people, ten million verifications,
one laptop, warm, in process): the page from 6,728 to 31 ms, the all-time series from 5,738 to
26 ms, the regions from 5,649 to 17 ms. Against the seed database every route runs at 1.0 to 2.4
times its seed cost, except one: `/api/atlas/heatmap?window=30d` at 3.4 times (43.1 against
12.6 ms), over the line. It reads hours, and at this load nearly every combination of authority,
context, outcome, disclosure level and algorithm is active in nearly every hour, so the hourly
rollup saturates at hours times combinations. It is recorded as measured and not rounded away;
the fix, an hourly total per authority for the heatmap's unfiltered case, is deferred until a
deployment needs a thirty-day heatmap faster than 43 ms. No reader's plan scans a table that
grows with the population: `AtlasReadsNoEventTableTests` revokes the application role's SELECT
on both event tables inside a rolled-back transaction and calls every reader, and the national
benchmark does the same under load.

**Falsifiers 4 and 5.** No `atlas_*` function returns a location and no rollup has a column for
one (`check_c6_atlas_redacts_zk_location`, its constitution mutation now the regions handing a
latitude back). Every response carries its window, grain, start and minimum, and every count a
caller chooses is clamped (`_ATLAS_MAX_CATEGORIES`, `_ATLAS_MAX_REGIONS`, `_ATLAS_MAX_BUCKETS`).

What building it found, each fixed with a test that fails without the fix:

- A series could carry one bucket more than its cap. The width was the window over the buckets
  rounded up, and at an exact multiple that cuts one more, the last starting at the window's end.
- The authority filter took any `str.isdigit()` string, a superscript two among them, which the
  SQL then matched as text against nothing. It takes ASCII digits now, normalised.
- "Failure" meant two things on one page: the headline and the map counted `FAILURE`, the series,
  heatmap and breakdowns every outcome but `SUCCESS`. Every reader means the latter now.
- A list or a map cut at its cap read as complete; each says when it was cut. The heatmap's `all`
  claimed every hour while a purge shortens them; it says where its hours begin.
- In the browser, an interval holding a window's whole activity drew nothing when the intervals
  beside it were withheld, the stacked series sloped through a withheld interval as through a
  zero, and a tab's label vanished under the pointer. The simulator stamped events on the host's
  local clock while the windows are measured on the database's, so on a host off UTC a live
  simulation landed hours in the past and the hour windows showed nothing.
- The UI drill booted its app on a port without checking it was free, and took the PID of a
  subshell, so its app outlived it; a later run on the same port drove the old server and
  reported on old code. It refuses a busy port and owns its process now, and so does the
  performance baseline.

Ninety Atlas tests; twelve mutants of the withholding, windows, caps, logging, facet order and
readers, each killed by the test that names it; the constitution drill catches all ten; the
check-mutation drill leaves none of 134 checks standing.

Next: whether the event tables keep the location indexes the Atlas no longer reads, since every
insert pays for them, and the optional PostGIS layer with them. Then B3 and B4.

### Step 4, part three (2026-10-02): no coordinate written, indexed or shown

With the Atlas on the rollups, no query filters or sorts an event by where it happened. Tracing
the writers found none in production: no route, API path or procedure writes a coordinate, and
the auto-audit trigger copied `polaris.event_lat` and `event_lon` into each lifecycle row from
session settings nothing set. Only the simulator and the seed filled the columns, and the seed
loads in every deployment, so its demonstration rows carry a few.

The first trace searched for the words latitude and longitude and missed what names neither. The
optional `13_postgis.sql` GiST-indexed a generated `geo` column on both event tables wherever
PostGIS could be created, which no test database has. And three reads took whole rows: the token
export (`le.*`, `ve.*`) put each event's coordinates in the file it downloads, though it exports
the detail page, which shows none; the detail page read them and dropped them; and the
investigation timeline's view carried a transition's into a field nothing displays.

So the columns were a capability rather than a trail: empty for every real event, and one session
setting away from a location history per credential with no change to the schema. This part
closes the writers, the indexes and the reads, and leaves the columns for a later release:

- Five indexes are dropped (migration 2026-10-02-005): the three B-trees on (latitude, longitude)
  and, where they exist, the two GiST indexes on `geo`. Per million located verifications the two
  B-trees on `VerificationEvent` held 177 MB (73 and 104) beside a 208 MB heap, maintained on
  every located insert for no query. Inserting a million located verifications took 38.7 and
  53.4 s with them and 34.8 and 33.2 s without, on a machine loaded by other work; the size is
  the stable figure.
- `13_postgis.sql` creates nothing: a spatial extension and columns that are NULL on every row
  Polaris writes would add attack surface and serve no query. It reports any `geo` column an
  earlier release left.
- The audit trigger no longer reads the settings (the same migration carries its body, so a
  database built by load-then-migrate runs it too), and the simulator no longer generates
  coordinates, so demonstration data looks like production's.
- The token export and the detail page name their columns, and the timeline view gives a
  transition no detail. Nothing in the application selects a coordinate.

One reader keeps them on purpose: `polaris-archive.sh` copies whole rows, because
`polaris-purge.sh` needs an archive that reconstitutes every row it deletes. An archive made
before the contract step carries whatever coordinates the database held.

`TestEventsCarryNoLocation` reads the catalogue for an index on either event table or its
partitions over a coordinate or a column generated from one, shows on a temporary table that it
sees the generated case, and sets both settings before a status change to show the row carries
none; both fail against the down migration's state, with the `geo` columns and without.
`check_event_locations_unindexed` reads every load file, a DO block's EXECUTE strings included,
for the same index, since CI cannot run the PostGIS path; it fails on the file as it stood. The
export test finds the seeded coordinates in the file neither as keys nor as values.

Next, a release later: drop the columns, the generated `geo` columns, the seed's coordinates and
the tests and checks that name them. An archive made before then keeps its coordinates for as
long as the archive retention policy keeps the archive. `requestor_location`, the place a
verifier states, is a separate question: it has a reader, the warrant audit.
