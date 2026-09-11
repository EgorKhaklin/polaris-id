# Changelog (recent ships)

This file is the curated record of Polaris's recent ships. The complete
ship-by-ship history is preserved in the git log.

---

## v9.390 — 2026-09-11 (a fixture that could not run the thing it was testing)

v9.389 made `check_conformance_suite` probe the conformance runner by EXECUTING it against a
stub verifier that rejects everything. Its existing detection test builds a synthetic tree whose
`run_conformance.py` is a two-line stub, so the probe could not run and the test's control case
broke.

The fixture now carries a real minimal runner -- it parses `--verifier`, scores `cases.json`,
and implements the positive-control gate -- and the test gains the perturbation that matters: a
runner with the gate removed must FAIL the check. Before this, the gate was verified only by
hand against the real tree.

I pushed v9.389 without seeing that failure, because the command piped pytest into `tail` and
the `&&` that followed read `tail`'s exit code, not pytest's. A pipeline's status is its LAST
command unless you ask for `PIPESTATUS`, and a gate whose result is discarded by a pipe is not
a gate. That one is now in CONTRIBUTING.md, alongside the other two this session cost: install
`ruff` before trusting the preflight, and check a schema change against a real database with
`psql` even when the application suites cannot run locally.

The twenty-minor freshness gate came due on SECURITY.md and CONTRIBUTING.md in the same ship,
and re-reading them found something to fix rather than a stamp to bump. SECURITY.md now points
a researcher at [REVIEW-PACKET.md](docs/REVIEW-PACKET.md) before they start, so they can tell an
accepted limitation from a defect before spending a day on one.

---

## v9.389 — 2026-09-11 (thirty-five conformance cases passed because nothing could be verified)

Item 7 of P1.18 asks what a newcomer actually experiences, so I ran the four commands the README
tells them to run. The third one, `conformance/run_conformance.py --self`, printed
`FAIL: 36/71` on a machine without liboqs installed.

THE 36 FAILURES WERE NOT THE PROBLEM. THE 35 PASSES WERE. Every case expecting a GENUINE
artifact failed, and every case expecting a REJECTION passed -- because the verifier had no
post-quantum backend and was reporting `authentic=False` to everything. A suite that scores
"a tampered signature is refused" as a pass, from a verifier that also refuses an untampered
one, is measuring nothing and reporting a majority green.

The runner now declares such a run VOID: if not one case expecting a genuine artifact passed,
the rejection cases proved nothing and there is no verdict to report. The rule names no cause,
which is what makes it durable -- a missing library, a misconfigured backend and a future
regression all produce the same false reassurance, and a rule that names none of them catches
all three. It adds a diagnosis when it can (the missing `liboqs-python`) without depending on
it, so a newcomer who skipped the install step is told so instead of reading a wall of failures.

`check_conformance_suite` verifies this by RUNNING the runner against a stub verifier that
rejects everything and requiring exit 2, not by finding the word VOID in the file. A check on
the spelling is satisfied by a comment. The probe stub is written to a temp directory rather
than into `conformance/`, because a check that writes into the repository to do its work leaves
litter the moment it is interrupted.

The detection test caught one of these errors in itself. It embedded the stub's verdict with
`json.dumps` into Python source, which put `false` in the file; the stub died; and the runner's
"verifier exited" path ALSO returns 2, so the exit-code assertion passed for entirely the wrong
reason. The assertion that the output actually says VOID is what caught it. That is the same
failure as the one this ship is about, one level up.

- the positive-control gate in `conformance/run_conformance.py`, pinned behaviourally by
  `check_conformance_suite` with a two-path detection test (rejects-everything is void;
  accepts-everything is nonconformant, which is a verdict and not void)

---

## v9.388 — 2026-09-10 (P1.18 item 8: a limitations list that fails the build when a limitation is fixed)

Item 8 asks for an external-review packet: a threat matrix for the existing subsystems, blunt
known-limitations, and guarantee-attack prompts. `docs/REVIEW-PACKET.md` is that, and the part
worth describing is how it is kept true.

EVERY CITATION RESOLVES AND EVERY CITED CHECK RUNS. Thirty-six checks and several drills are
named across twelve subsystems and twelve attack prompts, and naming one that fails is the same
as naming one that is gone. That half is the discipline the 800-63 mapping already uses, and it
caught a bad citation on the drill's first execution: a PQC drill that does not exist under that
name.

THE LIMITATIONS ARE CHECKED IN THE OTHER DIRECTION, and that is the new idea. Each of the eleven
carries a WITNESS -- a file and a string that must still be present for the limitation to hold.
Implement the external ledger backend and the witness string goes; the drill fails; the entry
has to be removed. A limitations list that can only be appended to is a confession nobody
maintains. An out-of-date one is worse than that: it tells a reviewer the system is WEAKER than
it is, and nobody catches it, because a stale limitation reads as modesty.

THE MATRIX MUST NAME WHAT DOES NOT STAND IN THE WAY. Every threat row carries a residual column
and the drill fails a row that leaves it thin. A row with a mechanism and no residual is the half
of the picture that reassures, and it is the half a reviewer can already read off the check
names. So the packet says that the two-witness rule is about the correctness of a signature and
not the legitimacy of the decision to issue; that a stale epoch accepts a credential revoked
since; that a superuser on the database host is outside the append-only boundary entirely; that
nobody outside the authority can detect an access that was never recorded; and that two colluding
authorities clear the mass-revocation bound.

AND THE PACKET SAYS ON ITS OWN FIRST PAGE THAT NOBODY HAS REVIEWED IT. Every guarantee it lists
is checked by machinery written by the same hand as the guarantee, and a packet that opens with
its controls and omits that sentence is committing the failure it exists to prevent. The last
attack prompt follows from it: A-12 asks a reviewer to break the check layer itself, because if a
check can be made to pass on a tree where its property is false, everything above it is worth
less than it looks.

- `check_review_packet` with a five-fixture detection test, and
  `scripts/polaris-review-packet-drill.py` on every push (224 checks)
- six verified detections in the drill, including the one that matters: a limitation that has
  been FIXED fails the build
- [REVIEW-PACKET.md](docs/REVIEW-PACKET.md)

---

## v9.387 — 2026-09-10 (P1.18 item 6: the model was doing the thing the item forbids)

Roadmap P1.18 item 6 asks for verification latency measured on the real topology, and states the
rule in four words: **no one-core x8**. Stop reporting a single-core measurement multiplied by a
core count as though a fleet had been measured.

P7.3's capacity model, shipped hours earlier, was doing exactly that. `verification_peak` divided
the 50,000/s target by a measured 7,848/s per core, reported "6.4 cores", and labelled the whole
thing MEASURED. The per-core rate is measured. The multiplication has never been run.

Core counts are now EXTRAPOLATED under a named assumption -- verification fans out because it
needs only a public key and shares no state, which is plausible and unmeasured, and the
difference between those two words is why the constant has a name. The measured per-core figure
is reported beside the quotient so a reader can see which half was measured. Every MET verdict
now carries what it rests on, under its own heading, because a verdict and its assumption travel
together or the verdict cannot be graded. `check_capacity_model` fails if a core count is ever
relabelled MEASURED again, or extrapolated without naming its assumption.

The measurement half: `polaris-verify-load.py` -- the harness the HA drills already run -- now
records latency, and the failover drill publishes what this two-member cluster actually did, at
the rate the drill actually offered, with nothing extrapolated from it.

PERCENTILES ARE GATED ON WHAT THE SAMPLE CAN CARRY. p50 needs 20 samples, p95 needs 100, p99
needs 1000. Below the floor the percentile is withheld with the reason, because a p99 over a
hundred requests is the slowest single request wearing a statistic's name, which is the same
error as one-core-x8 one level down. The drill offers ~2 rps on purpose (the health traffic
already sits near the edge's per-IP budget), so it will report a p50 and say plainly that the
p99 is not available and what would make it so. Latency is collected for SERVED responses only:
a 429 measures the edge's rate limiter and a transport failure measures the timeout setting, and
folding either into a percentile reports the harness's own configuration as the system's
behaviour. Nearest-rank, so every number is a request that actually happened.

Still owed on item 6: a committed report on a real multi-node topology driven by the synthetic
nation (P2.14). That needs the Docker/Patroni stack and a load large enough to earn a p99, and
writing the document without them would be the overstatement the item exists to stop.

- `check_capacity_model` gains the extrapolation rule, with detection tests
- six measured tests for the percentile floors in `scripts/test_verify_load.py`, three more in
  `polaris_web/test_capacity.py`

---

## v9.386 — 2026-09-10 (off by one in the control, right about the trap)

The capacity drill's first ever execution, in v9.385's CI. Fourteen of its fifteen cases held
on the first run, including the one that matters: a real verification row landed at event_id
2,147,483,648, and narrowing the column back was refused once it had.

The failure was in the drill's own control case. `setval(seq, n)` sets `last_value` to `n`, so
the NEXT `nextval` returns `n + 1`; setting the half-widened sequence to `INT4_MAX - 1` and
expecting the next insert to be `INT4_MAX - 1` was off by one. The insert correctly produced
`INT4_MAX`, which is the last id that fits, and the insert after it was correctly refused.

The control was right about the trap the whole time. Verified against a real sequence rather
than by reasoning about it a second time: a `BIGINT` column whose sequence is still declared
`AS integer` refuses with `nextval: reached maximum value of sequence` at exactly
2,147,483,647, which is the half-finished widening the migration exists to avoid.

---

## v9.385 — 2026-09-10 (the widening the schema alone could not tell me about)

v9.384 widened five surrogate ids and broke nine CI jobs, all of them for one reason: every job
loads the schema, and `uc7_warrant_audit` declares `RETURNS TABLE (event_id INTEGER, ...)`
while now receiving a `BIGINT`. Postgres refuses with "structure of query does not match
function result type" the first time the procedure file is loaded.

Widening a column is not a one-line change, and the three things it touches are all invisible
from the column definition:

FIVE ROW-RETURNING FUNCTIONS declare these ids in their result columns, and `CREATE OR REPLACE`
CANNOT change a function's return type. They are now dropped by the migration and recreated by
the object sync -- and they are FOUND rather than listed. A `TABLE`-returning function's result
columns are `OUT` arguments in the catalog, so the ones exposing a widened id as 32-bit can be
asked for by name and type. The first draft listed five signatures by hand and four of them
were wrong, which is worse than useless: `DROP FUNCTION IF EXISTS` with a signature that does
not match says "does not exist, skipping" and leaves the broken function in place.

THREE VIEWS depend on these columns, and Postgres refuses `ALTER COLUMN TYPE` while they do.
The migration captures each view's definition AND ITS GRANTS from the live catalog, drops it,
alters, and recreates it. From the catalog rather than from a copy in the migration, because a
copy is right the day it is written and wrong the first time somebody edits the view.
`polaris_app` holds real privileges on all three, and losing them would take the application
down in a way that looks nothing like a migration problem.

THE COLUMN WORK IS NOW CONDITIONAL on a target still being `integer`, so applying this to a
database loaded from the current schema touches no view at all. The sequence widening stays
unconditional, because a sequence left at the 32-bit ceiling under a 64-bit column is the
half-finished state the whole migration exists to avoid.

AND THE MIGRATION SAYS IT IS NOT ZERO-DOWNTIME rather than implying otherwise. Between
`--up` and `--sync-objects` those functions do not exist; `polaris-deploy.sh` runs both before
rolling either colour, so the gap is seconds, but it is not zero. With the partition rewrite
underneath it, this belongs in a maintenance window -- which is the argument for running it
before there is anything in the table.

The underlying failure was mine: I verified the widening against the schema file and the model,
and never loaded it into a database, because no local interpreter here has Flask. Loading the
SQL needs only `psql`, which was available the whole time. Both paths are now exercised
locally before pushing: a fresh load, and an upgrade from the pre-widening schema through the
migration and the object sync, ending with a real row inserted at event_id 2,147,483,648.

---

## v9.384 — 2026-09-10 (P7.3: the targets are met and the column ran out of integers)

The roadmap states four national planning targets and says in the same sentence that they are
"to be validated, not asserted". Validating them found both halves of the answer, and the
second half is not a throughput number.

EVERY THROUGHPUT TARGET CLEARS BY MORE THAN AN ORDER OF MAGNITUDE. 50,000 peak verifications a
second is about 6.4 cores of a measured 7,848 per core, and verify-at-use needs only a public
key so it fans out across replicas without touching custody. A 200,000/day enrollment surge is
about nine minutes of one signer at a measured 372 tokens/s. Judged on throughput this system
is ten times faster than its targets require.

AND IT COULD NOT HAVE RUN FOR A WEEK AT THE SUSTAINED TARGET, because `VerificationEvent.
event_id` was a 32-bit `SERIAL`. Two billion, one row per verification, five thousand a second:
five days. At the 50,000/s peak target, twelve hours. Nothing is slow when a sequence is
exhausted and no query degrades; every insert on the path fails, and on the verification path
that is the whole service. `TokenStateEpochLeaf.leaf_id` was worse in the way that matters
most: the table holds one row per token per epoch, so a 350M population exhausts it on the
SIXTH epoch closure, and that figure needs no assumption about cadence at all.

`polaris_web/capacity.py` is therefore a model that reads the schema, not a spreadsheet of
core counts. Every figure is labelled MEASURED, DERIVED, ASSUMED or UNVALIDATED, and the two
findings above are DERIVED -- arithmetic on the schema and a target quoted from the roadmap,
with no modelling step in between, which is why they were acted on rather than filed. A target
is reported MET only when its throughput is met, no id space blocks it, and no link in its
derivation is UNVALIDATED.

Migration `2026-09-10-015` widens five surrogate ids to 64 bits. A `SERIAL` IS TWO OBJECTS: an
`integer` column and a sequence declared `AS integer`, and `ALTER COLUMN TYPE BIGINT` changes
only the first. After that `information_schema` says `bigint`, the schema file looks right, the
model reports MET, and the sequence still refuses to issue 2,147,483,648. So the drill inspects
nothing: it sets each sequence one short of the old ceiling and inserts across it, with a
deliberately half-widened scratch table alongside as the control that must fail at exactly that
point. Without the control a passing widening test proves only that the number fit.

Widening is an EXPAND, not a contract -- old code reading a wider column reads the same values
-- so `check_migrations_expand_contract` learned to grade a declared
`-- widens: Table.column OLD -> NEW` instead of refusing every type change. It verifies the
pair is a recognised widening, that the declared target matches what the statement sets, and
that no foreign key references the column, since a parent widened under a still-narrow child is
exactly the rolling-deploy breakage the policy exists to prevent. Declaring the migration a
contract to get past the checker would have been a lie, and weakening the checker would have
been worse.

99.99% AVAILABILITY STAYS UNVALIDATED and says why. It is 52.6 minutes a year; establishing it
needs a failure rate and a recovery time from a multi-region deployment under real traffic, and
what is measured is a rolling deploy that drops zero verifications and a failover that induces
four failures and recovers, on a two-member topology on CI hardware. Extrapolating 99.99% from
that would be an assertion wearing a measurement's clothes.

Two defects found while building the check itself. It loaded the model with importlib, whose
loader reuses cached bytecode when the source's mtime-to-the-second and size both match, so two
versions of the file differing by four characters loaded as the same module and a changed
constant read as unchanged; it also wrote a `.pyc` into `polaris_web/` as a side effect of
running a check. Both gone: the model is compiled from source text. And an earlier draft
checked that `UNVALIDATED_LINKS` was MENTIONED in `validate()`; disabling the branch that
consults it left the mention on the line below and passed. The guard now runs the model.

- `check_capacity_model` and the widening rule in `check_migrations_expand_contract`, each with
  a detection test (223 checks)
- `polaris_web/capacity.py`, `polaris_web/test_capacity.py` (25 measured tests),
  `scripts/polaris-capacity-drill.py` on every push against a real database
- [capacity-model.md](docs/design/capacity-model.md)

---

## v9.383 — 2026-09-10 (a gate that says READY without linting)

CI's product-test job runs `ruff check .` as its FIRST step, so a single unused import fails the
whole run before a test executes. v9.382 shipped with one: `itertools`, left behind when the
transparency drill's adversary was replaced by a reachability DP. The local preflight printed
READY anyway, because it never linted and never said it had not.

`scripts/polaris-preflight.sh` now runs ruff when it is present, and when it is absent says so
loudly rather than passing quietly. A gate that stays silent about what it did not check is how
READY stops meaning anything.

---

## v9.382 — 2026-09-10 (P7.7: an authority cannot publish what it never recorded)

Building the public transparency program began by asking what was recordable about the
warrant-authorized verification history, and the answer was nothing.

`AuditAccessLog` has recorded reads of the four tables holding people's histories since v9.20,
and eight routes called the helper that writes it. THE WARRANT-AUDIT ROUTE DID NOT, and it is
the single most invasive read the system offers: one named person's entire verification
history, on an authority's say-so. It escaped because the read is behind a function name.
Every other read of `VerificationEvent` is a `SELECT` in `app.py`; UC-7 selects from
`uc7_warrant_audit()`, the table appears only in `05_procedures.sql`, and the route reads as if
it touched nothing. A reviewer hunting unlogged reads would have had to already know which
procedures return that table's rows.

The route now records the access, and `check_audited_reads_are_logged` states the rule where
the evasion lives: a stored procedure that RETURNS ROWS SOURCED FROM a tracked audit table is
an audited read, and every route calling one must log. Procedures that only count or purge
internally are not caught, because they hand the caller nothing. The check fails if it finds no
such procedure at all, since a broken parse must not pass by finding nothing to check. The row
records the QUERY and never the RESULTS: an audit-of-audit that copied the subject's history
would double the exposure it exists to police, and the warrant already authorises one copy.

`polaris_web/transparency.py` + `polaris-id transparency-report` then publish the program.
EVERY FIGURE SAYS WHERE IT CAME FROM, because two claims that look identical on the page are
not the same claim: a reader with the public log can recompute the anchor cadence and catch an
authority that misstates it, and nobody outside can derive the warrant-audit counts at all.
Counts of people are suppressed; counts of the system's own operations are not, since no person
is disclosed by them and blurring them would hide the operator's failures behind a privacy
control. The anchor figures publish the longest GAP, graded against a maximum the authority
declares, because an authority that anchored nine hundred times and then went dark for nine
days has a nine-day hole the count alone hides.

AND SUPPRESSING A SMALL COUNT IS NOT PROTECTING IT. Withhold the cell reading 3, publish the
total beside the two that survived, subtract, and the 3 is back with a marker beside it
claiming it was protected. So every withheld cell's feasible interval is computed against
everything published, here and in every earlier report, and THE REPORT IS NOT GENERATED when a
small cell has been narrowed to one value. Three things fall out of making that check real:
the two kinds of withheld cell are known to lie in different ranges (`[0, k)` for a cell
withheld because it is small, `[k, total]` for one withheld to protect another) and treating
them alike makes the arithmetic look infeasible and withholds the whole table; withholding the
total is the LAST resort, after complementary suppression, because the total is what an
oversight reader came for; and there is no running total across periods, since republished each
quarter it looks like one figure and is many, which would publish every per-period margin
without anybody deciding to. That last rule also makes republishing free: a period's
suppression depends on nothing outside it, so it recomputes to the same answer and publication
is sticky without storing which decisions were sticky.

The drill attacks the report AS PUBLISHED rather than inspecting the logic, over thousands of
random tables and a growing multi-quarter series with the adversary holding every report the
program ever issued. It enumerates reachable sums rather than recomputing the module's own
closed-form bounds, because two different algorithms agreeing is evidence and one agreeing with
itself is not. Run against naive primary-only suppression it recovers exact figures from 4,273
tables.

- `check_audited_reads_are_logged` and `check_transparency_program`, each with a detection test
  (222 checks)
- `polaris_web/transparency.py`, `polaris_web/test_transparency.py` (36 measured tests),
  `scripts/polaris-transparency-report-drill.py` on every push, `polaris-id
  transparency-report`
- [transparency-program.md](docs/design/transparency-program.md)

---

## v9.381 — 2026-09-10 (P7.5: the sunset is the moment it becomes compulsory)

A new national credential arrives beside a driving licence and a passport, and
for years it is the second thing somebody carries. The dangerous moment in that
period is not the cutover, which is undramatic: one more accepted credential at
the counter.

**The sunset is the moment an identity system becomes compulsory.** Until the
old credential stops being accepted, a person who cannot or will not hold the
new one still has a way through the door. Afterwards they do not, and nobody had
to decide to make it mandatory. It happened because a migration reached its last
milestone.

So `polaris_web/coexistence.py` treats the sunset as a decision with a floor
under it, and **refuses to compute a verdict from what the issuer can see**.

**What the database holds is the supply side**: how many enrolled people hold an
active credential, credential health, trust-list reach, whether epochs are
actually published so offline verification has something to check against. All
of it is about the authority's own readiness.

**What it cannot hold decides whether anyone is harmed**: what share of relying
parties accept it, whether a person without one can still obtain every service
the old credential opened, whether that path is usable by somebody with no
smartphone, no fixed address and no appetite for a government website *without
having to explain themselves*, and whether somebody arriving tomorrow can still
get the legacy credential.

`sunset_readiness` takes those four as arguments and refuses without them. The
refusal is the mechanism rather than a formality: an operator who has to type
the answer has to have asked the question. It quotes the **questions**, not the
field names, because a field gets filled in and a question gets considered.

**Two blockers sit above every percentage**, checked before any adoption figure
so the figure never looks like the deciding number: no alternate path at all,
and a path that exists on paper. One requiring a smartphone, a fixed address or
an explanation excludes the people most likely to need it, and counting it is
how an exclusion gets recorded as a success.

**The denominator nobody mentions.** `enrolled_holding_share` counts people the
authority has *already enrolled*. Everyone it has never met sits outside that
denominator, and they are exactly who a sunset strands. The figure carries that
warning in its own output, because a number this reassuring gets quoted without
it.

And `may_sunset: true` says in its own text that it is not permission from the
people affected. It means the engineering facts raise no objection; the decision
stays one somebody makes and answers for.

A prose check was tripped by bold markers inside a phrase, the third time
formatting that changes nothing about a sentence has broken one (a line wrap, a
string-literal seam, and now emphasis). Emphasis is normalised away now.

## v9.380 — 2026-09-10 (the tool that decides what to verify, verified)

`polaris-ship.py plan` decides what a ship has to verify: which suites the
changed paths select, which routes changed, and which drills exercise them. It
sat at 16% coverage, and its selection logic had no tests at all.

**A verification selector that mis-selects does not fail loudly.** It prints a
shorter list, the ship passes the checks it was told to run, and the suite that
would have caught the defect was simply never named. That is the quiet half of
the tool, and it is the half worth testing.

Two of the fifteen new tests pin properties that would otherwise be silent:

- **A changed *helper* selects every route that calls it.** The handler's own
  source is untouched, so nothing about that route looks changed by a naive
  diff, and that route is exactly what broke. This is the case
  `changed_routes` exists for.
- **A route that is a prefix of another must not over-match.**
  `/api/v1/thing` selecting a drill that only mentions `/api/v1/thing-else`
  would drag in unrelated drills on every ship, and a plan that names
  everything is one an operator learns to skim. The entry that mattered gets
  skimmed with it.

Sharding is covered too, for the one sharding bug that does not announce
itself: a unit dropped between shards is a test that silently never ran.

16% to 31%. The percentage is the smaller half of the point.

## v9.379 — 2026-09-10 (a module a drill covers is a module nothing covers)

v9.378's CI broke the coverage floor, and the cause was two ships old.

`proofing.py` shipped at v9.371 with a drill and no measured suite.
`pilot.py` did the same at v9.376. **A drill proves a path runs; it does not
count toward coverage**, because the gate measures the unittest suites and a
drill is a separate process. So both modules sat at **0%** while looking
thoroughly tested, and the floor caught the pair of them two ships later, in a
run whose failure looked like it belonged to the ship that tripped it rather
than to either ship that caused it.

I made the same omission twice, which is the argument for a check rather than
for being more careful.

**The fix is tests, not a lower floor.** `IdentityProofingTests` and
`PilotWindDownTests` take `proofing.py` from 0% to 93% and `pilot.py` from 0%
to 79%; the total is back to 75% against a floor of 74.

**And `check_modules_are_measured` names the next one at the moment it is
added.** A module exempts itself with a `coverage:exempt` marker in its own
source, carrying the reason. The marker lives next to the code rather than in a
list inside the check, for the same reason the SQL already uses that
convention: a central list of exemptions goes stale silently, and a stale entry
is a hole waiting for a future module of that name. A bare marker with no
reason, or a one-word one, is refused: the sentence beside it is the whole
point. Three modules carry one today, each explaining why a unit test would be
testing a stand-in rather than the module.

## v9.378 — 2026-09-10 (P5.1 closed: the pack you owe before you start)

v9.376 shipped the wind-down. This adds the rest and closes the row.

**One command.** `scripts/polaris-pilot.sh` with `up`, `report`, `winddown` and
`down`. Two refusals are built into it rather than left to a stack trace:
`winddown` without `--cosigner` explains that a wind-down is a mass revocation
and one authority cannot perform one, and `down` says in as many words that it
is **not** a wind-down. Stopping a pilot is not ending one, and an operator who
conflates them believes participants were erased when nothing was.

**The DPIA input pack, and what it refuses to be.** `report` prints the factual
half a DPIA is usually wrong about, derived from the live schema: every table,
**every identifying column found by name across the whole schema**, the
effective retention policy per class from `RetentionPolicy` rather than from
prose, who can read it by role, what survives a wind-down, and the consent
language.

On the shipped seed that column search finds **77**, including a `legal_name`
re-exposed through a view and the duress columns nobody wants enumerated. That
is the list a hand-written inventory gets wrong, and the entries it forgets are
the ones that matter.

**It is not a DPIA and there is no template for one.** A DPIA names a
controller, a lawful basis and a jurisdiction;
[PRODUCTION-READINESS.md](docs/PRODUCTION-READINESS.md) says plainly that it is
counsel's work and not an engineering task. A fill-in-the-blanks form would
invite somebody to treat the blanks as the whole job. What engineering can
supply is the facts, in a form that does not go stale on the next migration,
and `report` says so in its own output.

**Run it before you enrol anybody**, not only at the end. Run at the end it
tells you what you could no longer have changed.

**The ops pack and metrics bundle are reused, not reinvented**: the existing
runbooks and the shipped `deploy/observability/` stack, which `up` brings with
it. A pilot running on its own parallel ops documentation would be one whose
findings do not transfer.

## v9.377 — 2026-09-10 (triage says what it actually knows)

v9.376's CI went red on the Docker image job, in a layer nothing in that ship
touched: the postgres image installs Patroni over `apk` and `pip`, and that
layer failed on the runner while building clean locally under
`docker build --no-cache`. A flake, and the same class as the two the triage
tool already knows.

**`triage` reported "investigate (no known flake signature matched)" over an
empty string.** `gh` refuses `--log-failed` while *any* job in the run is still
going, so triaging a run whose failure has already landed produced a confident
verdict about evidence the tool never saw. That reads exactly like a considered
answer, which is worse than no answer: the next person spends the twenty
minutes I just spent, and a tool that reports a conclusion it did not reach is
the thing this repository refuses everywhere else.

It now says `UNKNOWN, no log to read yet`, names why, and gives the command to
re-run once the run finishes.

**The Alpine layer is now a known signature**, with advice that says how to
*confirm* it is a flake (`docker build --no-cache -f
polaris_web/Dockerfile.postgres .`) rather than just asserting it. A signature
that tells you to rerun without telling you how to check is a signature that
will eventually excuse a real failure.

**And the classifier has tests.** `scripts/test_ship_tool.py` runs the real log
line the signature was written for, verbatim, because a signature tested
against a paraphrase of its log is tested against nothing. The tests also push
the other way: a check violation, a drill failure, a `ModuleNotFoundError` and
an assertion error must all still classify as *investigate*, since a classifier
that called real failures flakes would turn a red build into a rerun loop and
the defect would ship.

## v9.376 — 2026-09-10 (P5.1a: a pilot that can actually be undone)

A pilot's real promise is not that it will work. It is that it can be wound
back. That is the promise institutions say yes on, and it is the one that fails
quietly: erasure becomes a paragraph in a consent form, nobody ever executes
it, and "what is still in there?" gets answered years later by whoever inherits
the database.

**Building it found that the system refuses to let one authority do it.** A
wind-down is a mass revocation, and `uc8_revoke_token` bounds the share of an
agency's population that may be revoked in a rolling window, demanding a
co-signing agency past it. That control exists because a lone authority able to
revoke a population at will is the coercion this system exists to make
expensive, and **it applies to an operator ending their own pilot.** The
refusal arrived partway through the first drill run, which is exactly where it
should not: the co-signer is now validated before anything is revoked, against
three conditions, because one valid for part of the population would revoke that
part and then raise, leaving the pilot in a state nobody designed.

An authority that issued into the pilot cannot co-sign its own wind-down. A
second authority agreeing is the whole content of co-signing; the same one
signing twice is not.

**The consent language is generated from what the code does.** C1 makes the
audit-of-record append-only and non-negotiable, so Polaris cannot delete a
participant; the supported erasure is pseudonymization. So the language
**refuses the promise of deletion in those words** rather than passing by not
mentioning it, because a form that said nothing on the subject would satisfy a
naive test and none of the obligation. It also tells the participant that what
is kept is kept so nobody, *including the operator*, can quietly erase evidence
of what the system did, and that the protection applies to them as much as it
constrains them.

**The residue report is derived from the schema.** A hand-maintained inventory
of what a wind-down leaves behind stops being true the first time a table is
added, and the failure is silent: the privacy claim keeps reading correctly
while becoming false. The drill adds a table with a foreign key to `Individual`
and requires it to appear unprompted.

The drill also asserts, in the unusual direction for a privacy test, that the
audit-of-record is **still there** afterwards. A wind-down that removed it would
have broken the guarantee that nobody can quietly erase what the system did.

**P5.1 stays open.** This is the rollback-and-erasure plan and the consent
language it constrains. The one-command deployment profile, ops pack, metrics
bundle and DPIA template are not done, and `docs/operator/PILOT.md` says which
parts are absent rather than reading as a complete pilot kit.

Three of my own checks were too loose again, each in a way worth naming: one
grepped for a phrase split across two adjacent string literals, one read code
order from text that included a comment naming the very function it was
ordering against, and one would have passed on a consent form that simply said
nothing.

## v9.375 — 2026-09-10 (P6.7 closed: the other two specs)

v9.374 graduated `meta/tla/` to checked and shipped the C1 purge-coverage
spec. This adds the two P6.7 also named, and closes the row.

**C2, and what the easy version would have been.**
`chk_disclosure_token_consistency` requires `token_id IS NULL` on every
ZERO_KNOWLEDGE verification event. Modelling *that* would prove a CHECK
constraint holds, which it does by construction, and would say nothing about
whether the holder is identifiable. The property worth proving is what an
observer holding **every recorded row** can conclude, and Polaris records two
things per zero-knowledge verification: the event, and a consumed nullifier
that is derived from the holder's own secret.

So the recorded value *does* vary with the holder. That is deliberate: it is
how one relying party refuses a second claim. `C2ZeroKnowledgeUnlinkability`
proves both halves hold at once, which is the whole design: one verifier
recognises a repeat, and two verifiers pooling everything they hold still
cannot tell they saw the same person.

**Status freshness, and the bound that moves.** An offline verifier holding an
assertion minted before a revocation cannot know about it, and no protocol
makes it know. What `StatusFreshness` proves is that its ignorance is
*bounded*: a verifier never accepts a credential more than one window after it
was revoked. That is the claim offline verification actually makes. It is not
"revocation is immediate", which would be false, and **the window is the
exposure, stated in the units the operator sets it in**.

**All three counterparts have the same shape**, and that shape is the reason
for writing them. Each is a change that looks like a simplification, leaves
everything local working, and moves a guarantee somewhere nobody is watching:

- Drop the single-setter assumption on the purge carve-out, and a committed
  DELETE can have no committed checkpoint.
- Take the scope out of the nullifier, and one relying party can *still* refuse
  a repeat, so the mechanism looks fine, while two of them can now link a
  person.
- Stop checking the window against the verifier's own ceiling, and the verifier
  is still correct about the assertion it was handed, while the issuer now
  decides its exposure.

Four specs, 11 `MODELS` bindings resolved against the tree, three counterpart
configurations required to fail. Writing `StatusFreshness` cost one detour:
TLA+ will not compare a record with a string, so the obvious "record or none"
sentinel made `TypeOK` itself fail to evaluate rather than fail to hold. The
assertion the verifier holds is modelled as a set of at most one.

## v9.374 — 2026-09-10 (P6.7: the specs, actually checked)

`meta/tla/` carried one TLA+ spec for years, described as "checked once to show
the technique". Nothing re-checked it. Graduating it to maintained found three
defects in the artifact, and each one is an argument for having done so:

- **It could not be parsed.** The file was named `c3-one-active-token.tla`
  while the module inside was `C3OneActiveToken`. TLA+ requires the two to
  match, so the spec as committed could not be checked at all, and its
  companion configuration existed only as a comment at the foot of the file. It
  had never been run in the form it shipped.
- **It violated its own type invariant.** Every action incremented `op_count`
  and none guarded it, so the counter ran past `MaxOperations` and `TypeOK`
  failed at the thirteenth step of a twelve-step bound.
- **It had already drifted.** It quoted a partial unique index named
  `uq_one_active_token_per_individual`. No such index exists anywhere in the
  tree; the real one is `uq_one_active_per_person`.

The substantive claim survived all three: C3 was never violated in any
reachable state. What failed was everything around it, silently, for as long as
nothing ran the checker.

**The README's objection was right, and was not an argument for leaving it
unchecked.** It argued against maintained specs because a model that has
drifted from the schema is worse than no model. The drift it predicted had
already happened to the single unmaintained spec. So a spec now declares the
objects it models and the drill resolves each one against the file it names:
rename the index and CI fails on the push that renamed it. **Drift is not
prevented by care. It is detected by a citation that has to resolve.**

**A new spec, and a real result.** `C1PurgeCoverage.tla` models the
append-only trigger's single DELETE carve-out and proves purge coverage: every
audit row that has left the table is covered by a committed checkpoint
recording that it left. A deletion that commits without its checkpoint is a
hole in the audit chain that nothing afterwards can see, because the absence
looks exactly like a row that never existed.

What the model shows is sharper than the property. **Coverage does not follow
from the trigger**, which permits any DELETE while the carve-out GUC is `TRUE`.
It follows from that GUC having exactly one setter, inside `uc_archive_purge`,
which writes the checkpoint in the same transaction. So the safety of the audit
chain rests on nothing else ever setting it, and `check_formal_specs` now
counts the setters in the SQL: a formal result whose assumption nothing
enforces is a result about a system nobody is running.

**A spec that cannot fail proves nothing.** The same rule the check layer
applies to itself. `C1PurgeCoverage.violation.cfg` turns the second setter on
and the drill requires TLC to find a committed uncovered delete under it; if
the invariant held there, it would be vacuous. Writing it caught my own first
version, where an unbounded counter left TLC still enumerating at 35 million
distinct states with the queue nearly empty.

**P6.7 stays open.** This is the graduation and one of the specs it asks for.
The C2 spec and the epoch/status protocol remain, and the row is marked in
progress rather than done.

## v9.373 — 2026-09-10 (P6.5: the automated third, enforced)

An identity system a person cannot operate is one that excludes them from
identity. That is the same failure as the trusted-referee gap named in the
800-63 mapping one ship ago, at a different layer, and it lands on the same
people.

`scripts/polaris-accessibility-drill.sh` boots the app, logs in as an operator,
and drives **sixteen surfaces** in a real headless Chromium, running axe-core
against the rendered DOM of each at the WCAG 2.0, 2.1 and 2.2 A and AA rule
tags. Serious and critical violations fail the build; moderate and minor ones
are counted against a ceiling that is **zero**, because that is the category
which otherwise accumulates below the threshold anybody is watching.

**The engine pin is load-bearing.** The convenient Python wrapper bundles axe
4.4.3, which is from 2022 and predates WCAG 2.2 entirely: it has *none* of the
2.2 rules. Auditing with it and reporting "WCAG 2.2 AA" would be a claim about a
standard the tool has never heard of. The pin is 4.13.0 and the drill asserts
its own engine is new enough to have the rules it is testing, because a pin in a
shell script is a comment as far as the audit is concerned.

**What the first audit found.** Fifteen of sixteen surfaces were already clean.
The Atlas had three real defects, each a barrier rather than a technicality:

- **Contrast, seven nodes.** `--ink-faint` was `#6e8299`: **4.43:1** against the
  4.5:1 AA floor, on labels the Atlas renders at 10px. That is the label under
  every number an operator reads, and failing by 0.07 is still failing. Now
  `#7b8fa6` at 5.26:1. A check caught that the public site carried the same
  token with the old value, so the same defect was live on that surface too.
- **A scrollable region no keyboard could reach.** The Overview panel scrolls
  and nothing inside it takes focus, so there was no way to scroll it without a
  mouse. Fixed with `tabindex="0"` and *only* that: the element is already a
  `tabpanel` named by its tab, and the `role="region"` I first added would have
  replaced the correct role with a vaguer one.
- **Two charts with no accessible name.** Both hero charts carry `role="img"`
  and no label, so a screen-reader operator was told "graphic" and nothing else.
  They are now named from their own data, so the label says what the picture
  says and cannot go stale the way a static string would.

**What this does not claim.** Automated testing detects roughly a third of WCAG
failures. It cannot tell whether alt text is *meaningful*, whether a focus order
makes sense, whether an error message explains what to do, or whether a
screen-reader user can complete a task. **A green run is a floor, not
conformance**, and ROADMAP's "not claimed" list still carries accessibility
conformance for exactly that reason. `check_accessibility` fails if that caveat
is removed, because "the accessibility checks pass" is precisely the sentence
that gets quoted as conformance.

Writing the detection test found the check itself too loose: `wcag2a` is a
substring of `wcag2aa`, so dropping the earlier tag would never have been
noticed. It matches the quoted tag now.

## v9.372 — 2026-09-10 (P6.2: a control mapping that goes red)

A control mapping is the easiest document in a project to write and the easiest
to let rot. It is a table of claims about a codebase, maintained by hand, read
by people who cannot check it, and it goes stale the first time somebody deletes
the thing a row was pointing at. Nothing turns red. The document just becomes
untrue.

So [docs/reference/NIST-800-63-MAPPING.md](docs/reference/NIST-800-63-MAPPING.md)
is executable. Every row cites a `check:`, `test:`, `drill:` or `schema:`
artifact, and `scripts/polaris-assurance-mapping-drill.py` resolves each one
against the tree and **runs every cited check**. Naming a check that was renamed
away fails; naming one that fails today fails too, because those are the same
thing from a reader's point of view. **When the evidence disappears, CI goes red
rather than the document going quietly stale.**

**Forty rows across IAL, AAL and FAL.** Thirty-two MET, two PARTIAL, five GAP,
one EXTERNAL. The totals are recomputed from the rows by the drill, because a
summary that can drift from its own table is worse than no summary: it is the
part a reader believes.

**What it refuses to claim.** The front matter says, before anything else, that
this is not a conformance claim, that no assessment has been performed, and that
a deployment does not inherit these properties by running the code. A row marked
MET means the mechanism is in this tree and CI proves it still is. It does not
mean an assessor agreed. This is the file somebody quotes after reading only its
first page, so it has to refuse that reading on the first page.

**The highest levels are stated in one place**, or a reader infers them from the
greenest row: **AAL2** for the holder's credential, with AAL3 explicitly waiting
on FIPS 140 validation and certified silicon that are bought rather than written;
**FAL1**, with FAL2's confidentiality provided by the channel rather than by the
assertion, and a holder-of-key mechanism that is real but is not in 800-63C's
assertion format.

**The gaps are named rather than rounded away.** Address confirmation, which
Polaris cannot do because it records no address at all. Trusted-referee flows,
whose absence excludes exactly the people most likely to need them. The kiosk
build. On-card biometric comparison, which is the one place a template would
have to exist. Each carries the sentence explaining it, because that sentence is
the whole value of writing a gap down.

Writing this caught two of my own errors immediately, which is the point: a
cited check name that did not exist (`c3_one_identity_per_person`, actually
`one_active_token_index`), and a stated gap total I had written from memory
rather than counted. Both failed the drill on its first run.

The drill also states its own limit. It cannot tell you the mapping is
*correct*: whether a row's requirement is really what the standard asks, and
whether the cited check really proves it, is an assessor's judgement and no
script substitutes for it. What it guarantees is narrower and still worth
having.

## v9.371 — 2026-09-10 (P4.4a: what an enrollment rested on)

Polaris could issue a credential and had no way to say how the person was
proven to be who they claimed. `EnrollmentStatusEvent` recorded *that*
enrollment happened; nothing recorded what it rested on. No assurance level
could be asserted honestly, and the NIST 800-63-4 mapping (P6.2) was blocked on
exactly that.

`EnrollmentProofing` and `EnrollmentEvidence` are the 16th and 17th
audit-of-record instances, append-only by trigger, and
`polaris_web/proofing.py` is the model over them.

**The level is derived, never asserted.** An enrollment does not claim IAL2
because someone typed IAL2. `derive_ial` returns what the recorded evidence
supports, across the published 800-63A combinations. Claiming *more* is refused
**with the reason**, since a refusal that only said "no" sends the operator back
to run the same session again. Claiming *less* is allowed: an authority may hold
itself to less than it could assert, and refusing that would push operators to
overstate in order to record anything at all. IAL1 is returned rather than
raised, because an authority that must record *something* will otherwise record
the level it wanted.

**Evidence nobody checked is not evidence.** Validation asks whether a document
is genuine; verification asks whether it belongs to the person in front of you.
A piece that fails either contributes nothing whatever its nominal strength, and
the second is the sharper one: **a genuine passport belonging to somebody else
passes validation and fails verification**, and counting it anyway is how an
IAL2 enrollment ends up resting on a theft.

**Liveness is not optional.** A photograph of a face and a lifted fingerprint
both produce excellent quality scores, so a capture that fails liveness does not
count toward IAL3. The database holds that floor itself: an `INSERT` that skips
the application cannot record an IAL3 whose session was unsupervised or whose
liveness is not true.

**`BiometricCapture` has no field for a template**, and `__slots__` keeps it
that way, so a vendor SDK is adapted at the edge and its own types never reach
the record. That is vendor-neutrality by construction; letting each vendor's
blob through and promising not to store it is a promise rather than a boundary.
Matching later is a different system with different retention and a different
legal posture, and binding a credential to a modality does not require becoming
one.

**What has no column:** no document number, no scan, no expiry, no template, no
date of birth, no address. Refused by name *and* absent from both tables. A row
says a STRONG piece of evidence of type PASSPORT was validated by a signature
check and bound to the applicant by biometric comparison. That is enough to
justify a level and not enough to reconstruct somebody's documents, and the
difference is what keeps an enrollment archive from being a second identity
database sitting behind the first.

`current_ial` returns the latest proofing event's level, deliberately not the
highest ever reached: an authority that re-proofs someone and finds less has
learned something, and a high-water mark would report a level nothing currently
supports.

**P4.4 stays open.** This is its engine half. The kiosk build (a locked-down
browser, its supervision model, its physical siting) is deployment packaging and
remains; the row is marked in progress rather than done.

## v9.370 — 2026-09-10 (P4.7: duress in time, not just in bytes)

The card's duress mechanism was already indistinguishable at the level of
bytes: same commands, same status words, same response length. That is
necessary and it is not sufficient. A coercer standing at the reader also
observes how long the card took.

**The defect this row found.** The card skipped the duress comparison when the
holder had not enrolled a duress PIN. That made **enrollment itself
observable**, and the shape of the harm is worth stating: it does not endanger
the holder who skipped enrollment, it endangers the ones who *did* enroll, by
splitting the population into two classes a coercer can tell apart. Learning
that a card has no duress PIN tells them the PIN they just watched was the real
one.

A card now always holds a duress comparand. When no duress PIN is enrolled it
is an unguessable value of the same length beginning with a NUL, which a keypad
cannot put in a command's data field, so the comparison always runs, always
costs the same, and never matches. This is the physical-layer twin of the P4.3
rule that every card carries a duress *slot* whether or not a PIN is enrolled:
both exist so the mechanism says nothing about the individual.

**The entry method, specified.** A second PIN, of the same length as the first,
at the same pinpad. The length rule is not stylistic: the PIN travels in the
data field of a `VERIFY` command, so a six-digit duress PIN beside a
four-digit normal one announces which class was entered to anyone watching the
exchange, without their needing to see the keypad. Four alternatives are
recorded with the reason each was rejected.

**The measurement, and what it will not claim.**
`scripts/polaris-duress-timing-drill.py` measures four pairs with a permutation
test that calibrates itself against the machine's own noise, and judges the
gaps against **10 microseconds**: what a coercer could read through a reader,
where an NFC exchange is milliseconds and the field's jitter is tens of
microseconds. Gaps of a few tens of *nanoseconds* are Python object layout, and
a drill that failed on those would be measuring the emulator rather than the
design. Every gap is printed with the resolution the run achieved rather than
rounded to "no difference".

A right PIN and a wrong one **do** differ, by around a hundred nanoseconds.
That is measured and reported rather than asserted away: it is not a leak,
because the status word already announces the difference, and it has to, since
a holder who mistyped needs to be told.

**A check that pinned a spelling instead of a property.** The first version of
the structural assertion matched the exact text of the original defect. I
reintroduced the leak with different wording to confirm the drill would catch
it, and it did not. Both the drill and `check_duress_on_card` now require the
duress comparison to be the whole right-hand side of its assignment: anything
else there is a guard, whatever it is called. The detection test exercises three
different spellings.

**The safety review** is the half that is about the person: the mechanism
signals, it does not prevent, and treating it as prevention is how it gets
people hurt. Recall under stress, blocking read as defiance, the silence
offline, and the fact that a rare signal is a loud one, all recorded in
[docs/design/duress-on-card.md](docs/design/duress-on-card.md).

## v9.369 — 2026-09-10 (P4.5: the thing at the counter, and what a check costs)

A border post, a bank counter, a pharmacy. `polaris_card/verifier_device.py`
reads a card over NFC or a presentation over QR and decides, with connectivity
or with none.

**Three facts, kept apart.** Possession (the card signed *this device's*
challenge just now), authenticity (the authority issued this card),
authorization (the credential still stands inside a window this device
accepts). All three are needed to accept and each is reported on its own,
because a device that returns one boolean teaches its operator nothing about a
refusal. **Possession alone is not acceptance**: a card revoked this morning
still signs, and the device says so in as many words.

**The replay a signature cannot refuse.** The challenge and the scope are inside
the card's signature, so a response relayed to a *different* device fails. A
response replayed to the *same* device does not: the signature over that
challenge is perfectly valid the second time, and nothing about the bytes says
they have been seen before. Only the device remembering its own outstanding
challenges refuses that, so it does. A presentation refused for the wrong scope
does **not** consume the challenge, or an attacker could burn the ones an
honest holder is about to use.

**The tension this row found, and reports rather than hides.** A P3.6 status
assertion signs the `token_value` in the clear, because that is what binds it to
a credential. So a device that checks authorization offline **learns the stable
credential identifier**, and two such devices can tell they saw the same person.
The card's key mode gives a per-verifier handle and gives up nothing, but
nothing binds that handle to a status assertion. Every verdict therefore carries
`linkability`, one of `pairwise`, `credential-linkable`, or `unknown`.

It is recorded **before** the assertion is verified, and the drill caught that
the first version did not. The device read the token value the moment it held
the assertion; a failed verification does not un-disclose an identifier.
Reporting linkability only on success would have been accounting for what the
device *accepted* rather than for what it *learned*.

**The QR ceiling, measured.** A presentation is 179 characters of base64url and
fits comfortably. With a classical-only card object it is 495 and still fits.
With a dual-signature card object it is **7,519**, past even the 4,296 an
absolute-maximum version-40 QR code holds, never mind the ~1,800 a phone screen
renders and a handheld scanner reads. **So the QR path cannot carry a
post-quantum card object**, and a device that needs post-quantum authenticity
needs NFC. That is a constraint with a number, not a preference.

### The CI signal I had been misreading

This repository runs two workflows per commit, `Polaris CI` and `Pages`, and
`gh run list --limit 1` returns whichever finished last. For three ships
(v9.365, v9.367, and the system-map fix between them) I watched the `Pages`
run, saw success, and reported the ship as green when `Polaris CI` was red.

The failure was one job in all three, and always the same: the quantum-event
drill added in v9.365 was wired into the `pqc-real` job, which installs a
minimal dependency set and not `psycopg2`, so the drill exited 3 and failed the
step. Everything else in those runs was green. `psycopg2-binary` is now
installed there, pinned from `requirements.txt` like the neighbouring pins, and
the remaining drills in that job were audited for the same gap.

## v9.368 — 2026-09-10 (P4.3: a record becomes an object)

Personalization is the moment a database record becomes an object in
somebody's pocket. It is the only step where the authority's signature is
applied to something that then leaves its control, and there is no recall.

**The card generates its own keys; nothing injects them.** An injected key
existed somewhere else first: on the personalization host, in its memory,
possibly in a log or a core dump, and the authority can only *assert* that it
was destroyed. A generated key has no such history, so "the private key never
left the card" becomes a fact about where it was made rather than a promise
about what was deleted. `personalize()` has no parameter through which a
private key could be supplied and `CardPersonalization` has no column to write
one into. That absence is the design, and the drill asserts it directly: the
private half of the key the card kept appears in nothing the flow produced,
recorded or returned.

**Every personalization is an audit-of-record event.** `CardPersonalization`
is the 15th such instance, append-only by trigger. The drill tries an `UPDATE`
and a `DELETE` and both are refused by the database rather than by the
application.

**A card is personalized once, and a credential gets one card.** The card
refuses a second `GENERATE KEYPAIR` or `PUT CARD OBJECT` for the life of the
part, **by its own rule** rather than by whatever backs its slots, because
leaving that to the host would make it a property of exactly the party the
rule exists to constrain. The database refuses a second card for one
credential with a unique index. Two live cards answering for one credential is
a revocation that only half works.

**Every card carries a duress slot, whether or not the holder ever enrolls a
duress PIN.** Both public keys are recorded in full, because the authority has
to verify a later presentation and a fingerprint cannot do that, and because
the authority is precisely who must be able to tell a duress presentation
apart. If a duress slot only existed when one was wanted, its presence in the
record would be a fact about the holder; because every card has one, it says
nothing about anybody. A `CHECK` refuses a card whose two slots are equal.

The card gained a lifecycle (`BLANK` to `PERSONALIZED`, no path back), on-card
key generation, extended-length APDUs for objects past 255 bytes, and a blank
card now refuses to sign at all: a card with no signed object has nothing a
verifier could check a response against, so signing anyway would produce
something that looks like a credential.

Writing the detection test made the check materially stronger in three places.
Each fixture removed one thing and the check still passed, because it was
matching a mention rather than the thing: `self._generated` appearing in an
assignment rather than in the guard, `SW_ALREADY_PERSONALIZED` in a `return`
rather than in a definition, and `duress_public_key` in a `CHECK` constraint
rather than as a column. All three now check what they meant to.

## v9.367 — 2026-09-10 (P4.2: the software token, and two things it taught the profile)

P4.1 said what is on a card. This is what a card **does**:
`polaris_card/emulator.py`, ISO 7816-4 command and response pairs with real
status words, two PIN slots, a retry counter and a PUK, published in
`polaris_card/vectors/apdu-exchanges.json`.

**APDUs rather than a comfortable Python API, on purpose.** A reader written
against a method call has to be rewritten the day a card arrives. A reader
written against APDUs does not. That is the entire content of "everything
downstream develops against the emulator", and the drill tests it rather than
asserting it: its reader is built from nothing but the published vectors and
the profile, and it completes a full presentation.

**Then it is attacked.** A captured response replayed under a fresh challenge is
refused, and relayed to a different reader is refused, because both the
challenge and the scope are inside the signature. The card signs nothing before
a PIN and refuses a challenge short enough to wait for a repeat of, so it is
never an oracle. Three wrong PINs block it, the block survives a power cycle,
and a blocked card refuses both correct PINs alike.

**Building it found two things the profile had not said**, and both are about
what is on the wire rather than what is in the card:

**The two PINs must be the same length.** The PIN travels in the command's data
field, so its length is observable. A six-digit duress PIN beside a four-digit
normal one announces which class was entered without anyone needing to see the
keypad. The emulator refuses the mismatch at construction.

**The card emits a fixed-length raw `r||s` signature, never DER.** This is what
a secure element actually returns; DER is something host software wraps around
it. More importantly it makes the indistinguishability **exact** rather than
statistical: a DER signature's length varies by a byte or two per signature, so
with DER "a duress response looks the same" is a claim you can only sample for,
and the first version of this drill duly found a response length one slot had
produced and the other had not in thirty trials. With a fixed length there is
one response length and it carries nothing. The reader wraps to DER on its own
side, where a varying length costs nothing.

The coercer's transcript is now compared byte position by byte position: same
commands, same lengths, same status words, same order. The PIN digits themselves
are excluded, deliberately, because they are the holder's input and a coercer
may well have watched them typed. The claim was never that they cannot see the
digits; it is that nothing tells them whether those digits were the normal PIN
or the duress one.

## v9.366 — 2026-09-10 (P4.1: the card profile, and the limits it states)

The schema has modelled the card since the first version: serials, biometric
binding type, duress hash, succession. What it never had was an encoding, so
the card was a set of columns nobody could implement against. `polaris_card/`
is that encoding, its reference codec, and its published vectors.

**A card is a key and a signed reference, not a copy of the record.** The token
value, the holder's name and date of birth, biometric templates and the duress
code in any form are refused **by name** rather than left out of the field
list, because absence is not a property: a vocabulary that happens not to
include a field stops excluding it the day somebody adds one. The card carries
a one-way reference to the credential, so a read of a card in a pocket does not
hand a reader the identifier the relying-party API accepts.

**The encoding has exactly one reading.** Deterministic TLV, tags ascending and
non-repeating, unknown tags refused rather than skipped. All three matter
because the object is signed: a format with two encodings of the same content
is one where a signature moves onto content it did not authorise, and a reader
that skips what it does not recognise verifies a signature over bytes it never
looked at.

**Two signatures, and both must verify.** A card carries a classical signature
today's certified silicon can make and a post-quantum one for the day it can,
over exactly the same body. When both are present, both must verify:
accept-if-either would hand the whole scheme to whoever breaks the classical
leg first, which is the entire reason a transitional card carries two. Whether
post-quantum is *required* is verifier policy rather than a format version, so
one population holds both while the fleet turns over.

**Three limits, stated rather than left to be discovered.** An offline verifier
cannot raise a duress alarm, because there is nobody to raise it to, so the card
must behave identically offline under either PIN; a card that behaved
differently would tell the coercer which one was entered, which is worse than
having no duress feature. A card cannot prove offline that it is the current
one, because activation is an event rather than a date, so succession is
resolved by the status layer's freshness window. And unlinkable proof of
membership needs the holder's phone: no fielded secure element computes a
Plonky2 proof, so in v0 the card is the key and the wallet is the prover.

The physical layer is now in the threat model, which had no entries for it:
T-P1 the card read in a pocket, T-P2 the lost card presented offline, T-P3 the
classical algorithm falling while the fleet is classical, T-P4 the coercer, and
T-P5 the forged object, each with its residual risk stated, plus two new
out-of-scope rows for what a card profile genuinely cannot address.

Proven by 27 tests against the published vectors and
`scripts/polaris-card-profile-drill.py` under real P-256 and real ML-DSA-65: a
card is refused under another authority's key, every field flipped in turn fails
the signature, and a valid signature under one algorithm does not rescue a
forged one under the other, in either direction.

## v9.365 — 2026-09-10 (P7.6: re-signing a population when an algorithm falls)

Polaris exists because the algorithms in today's credentials will not hold.
Every other part of the system treats that as a design premise. This ship
treats it as an operation somebody has to perform, on a population, under time
pressure, and measures what it costs.

**UC-6 migrates one token; this migrates a country.** `polaris_web/migration.py`
plus `polaris migrate-population` re-sign the whole ACTIVE population under a
new parameter set, built out of the same constraints the per-token procedure
relies on rather than around them. The unique constraint is the serialization
point, so two runners racing one credential produce one row; the triggers still
fire per row, so the database will not let a migration strand a token.

**Nobody goes dark, and it is checked after every batch.** The number that
matters is not throughput, it is how many holders have a credential that
verifies under nothing. It is zero before the migration, after every batch
during it, and after the window closes. The drill samples it at every batch
boundary rather than at the ends, because a gap that opens and closes between
two endpoints is invisible to a before-and-after check.

**The window cannot be closed early, and that is a refusal.** The old signature
keeps verifying until its deprecation date, and that interval IS the migration.
Deprecating as you go leaves credentials that verify only under an algorithm
fielded verifiers may not accept yet, and the holder finds out at a border while
the console reports progress. `deprecate_superseded` refuses to run while any
ACTIVE credential is unmigrated.

**Resume is the default, not a feature.** The work remaining is a query
("ACTIVE credentials with no active signature under the target algorithm"), not
a cursor or a progress file. Kill the runner and run it again: it finishes what
is left. Run sixty-four of them and they divide the population by
`SKIP LOCKED` without coordinating.

**A migration that cannot sign stops.** The target parameter set is an argument
rather than process configuration, because during a migration two are live: the
instance keeps issuing under the current algorithm while the population moves.
`custody.get_custody_for_algorithm` refuses when no key exists for the target
instead of using the key it has. Signing with ML-DSA-65 and recording the row as
ML-DSA-87 would be a false label on a real signature in the audit-of-record, and
every later verification would read the mismatch as tampering.

**The measurement, under real ML-DSA-87 with one custodied key:** about 345
credentials/second on a single runner, of which **91% is signing and 9% is the
database**. 350M is ~11.7 days on one runner, ~4.4 hours on 64. The finding an
operator needs is that lever: this migration is bounded by signing throughput,
so buying database capacity for it buys almost nothing, and if the key lives in
an HSM then that HSM's rate is the migration's speed limit. The runbook is
[docs/operator/QUANTUM-EVENT.md](docs/operator/QUANTUM-EVENT.md).

The scale drill also found a defect before it shipped: `execute_values` pages its
argument at 100 rows and issues one statement per page, so `cur.rowcount`
reported only the last page. A 250-row batch reported 100 written, and an
operator running a national migration would have been reading a number that
undercounts by the page size. The count now comes from `RETURNING`.

## v9.364 — 2026-09-10 (P3.9: per-authority isolation, and the part policies cannot fix)

A review row, and the review found something. `AppUser` had no authority
binding at all, and **sixteen operator routes read credential data with no
issuing-agency filter.** In a single-authority instance that is invisible and
harmless. In a shared one it means any operator sees every authority's holders.

**The fix is a database policy, not sixteen `WHERE` clauses.** Patching sixteen
query bodies would be exactly the application-level policy the schema exists to
refuse: it holds until the seventeenth route, which nobody remembers to write.
So `IdentityToken`, `VerificationEvent` and `TokenLifecycleEvent` carry row-level
policies keyed on a session setting, and the application's only job is to say
who is asking. `scripts/polaris-authority-isolation-drill.py` drops to the
application role and asks the database directly, because "the application filters
by agency" is not the claim worth making.

**The unscoped default stays permissive.** An unbound operator sees everything,
which is what a single-authority instance, the relying-party surface and every
test suite rely on. A policy that quietly hid rows from an unbound caller would
be a silent behaviour change wearing the word "security".

**One trap, recorded because it nearly shipped.** The natural way to write a
permissive default is `setting = '' OR col = setting::int`. PostgreSQL does not
guarantee `OR` short-circuits, so the cast runs on an unscoped session and the
query dies with `invalid input syntax for type integer: ""`. That is not a
failure of isolation, it is an outage: every query against the table raises, so
an unauthenticated instance stops serving. The drill caught it on its first run.
The shipped form is `col = coalesce(NULLIF(setting, '')::INTEGER, col)`, which
never lets the cast see an empty string, and `check_per_authority_isolation`
refuses any unguarded cast so it cannot come back.

**What the review could not fix.** A person is not owned by an authority. Two
authorities may both have issued to the same individual over time, and C3
constrains credentials, not people. There is no honest per-authority policy for
`Individual`, so in a shared instance these policies **bound** what an operator
sees and do not achieve isolation. The drill asserts that limit rather than
leaving it in prose. That changes the status of the topology decision: **one
authority per instance is load-bearing, not stylistic.**

Also pinned: the scope reaches every connection `get_db` hands out, the read
replica included, and it comes from the authenticated session rather than the
request. The scope is applied with `is_local=false`, which is safe only because
`get_db` opens a fresh connection per request; the check holds that pairing, so
introducing a pool without resetting the scope on checkout fails rather than
silently handing one operator's authority to the next request.

## v9.363 — 2026-09-10 (P3.8: a verification result in the W3C VC data model)

The sibling of the mdoc bridge, and the roadmap row's phrase "explicitly a
format, not a trust model" is the whole design. What differs is what the
document is about.

**It attests a verification result, not an identity.** Not "this person is X"
but "at this instant, presented against this credential, the issuing authority's
answer was this". The subject vocabulary is closed and refuses identity fields
and `token_value` by name, because the drift from "a verification result" to "a
credential about a person" happens one convenient field at a time. Polaris makes
no identity claims anywhere else; a credential that made them would be a larger
claim than the whole system supports.

**A general verifier can parse it and cannot verify it.** The cryptosuite is
`polaris-mldsa-jcs-2026`, because every registered Data Integrity suite is
classical. Naming a registered one would assert something *false* about how the
proof was made, and that is worse than being unverifiable: a general verifier
would attempt the wrong algorithm and report a failure indistinguishable from
tampering. So a relabelled document is refused rather than accepted, and the
verdict reports the structure apart from the proof with `verifier_interop`
naming the gap.

Canonicalisation is JCS over the document minus its proof, not RDF Dataset
Canonicalization, because the `-rdfc-` suites need a full JSON-LD processor and
the detached verifier stays import-standalone. A check pins that both sides
canonicalise identically, since a mismatch would mean the app signs bytes the
verifier never reconstructs.

The subject `id` is the P9.4 pairwise handle under a `verifier_scope`, and absent
otherwise. VC 2.0 permits a subject with no `id`, and that is more honest than
minting a stable identifier, which would hand back exactly the correlation handle
the presentation layer bounds.

One real defect fixed on the way: under the development placeholder profile there
is no public key at all, and building the verification method sliced it. A
credential signed by no key must be refusable rather than un-buildable, so it now
says so and the verifier refuses it.

`check_vc_format` with a ten-fixture detection test, and both container images
now copy the new module, which the invariant layer caught for the second ship
running.

---

## v9.362 — 2026-09-10 (P3.7: a format bridge to ISO 18013-5, and what does not cross)

A Polaris credential now renders in the ISO/IEC 18013-5 mdoc structure. A reader
that speaks that standard parses the document, walks its namespaces, and verifies
every disclosed element's digest against the signed Mobile Security Object, which
is the standard's whole selective-disclosure mechanism. The drill proves that with
an independent CBOR implementation rather than the one that wrote the bytes.

**It cannot verify the issuer signature, and that is the design.** The signature is
ML-DSA-65, COSE algorithm -49, and 18013-5 mandates ES256, ES384, ES512 or EdDSA.
The obvious fix is to sign with something a reader knows, and it is the wrong one: a
post-quantum credential carrying a classical signature is a classical credential,
and the reader would be correctly verifying a signature that no longer carries the
property the credential was issued for. So the structure bridges and the
cryptography does not. The verdict reports `digests_match` and `issuer_authentic`
separately, with `reader_interop` naming the difference in words, because a caller
reporting the first as the second would be claiming a verification that did not
happen.

**It is not an mDL and does not claim to be.** The docType is
`id.polaris.credential.1`, never `org.iso.18013.5.1.mDL`. A Polaris credential holds
no name, date of birth, portrait or driving privileges, and a document claiming that
docType while carrying none of its elements would be a false statement in a
machine-readable format, which is the worst place to put one: a machine cannot read
the caveat in the surrounding prose. The honest consequence is that a reader looking
for an mDL will not accept this as one. What bridges is the reader's machinery, not
its expectations.

**It never carries the token value.** That is the correlation handle P9.4 spent a
ship bounding, and an mdoc carrying it would hand the identifier back in a different
encoding with no way for the reader to know. The refusal is at build time and stands
on its own rather than following from the closed vocabulary, because the day
somebody adds the element to the vocabulary the vocabulary check stops firing and
only an independent guard saves them.

The detached verifier parses mdoc CBOR with its own hand-written decoder rather than
a library, because it must stay import-standalone. The drill checks the app's output
against that decoder, which is the two-witness discipline applied to the format.

`check_mdoc_bridge` with an eleven-fixture detection test, and a design record that
says plainly this is a format bridge and not a trust bridge.

---

## v9.361 — 2026-09-10 (P2.12: the proof-library question, evaluated and decided)

**Decision: keep Plonky2.** This is a spike with a decision record, not a
migration, which is what the roadmap row asked for.

The question is honest. Plonky2 is pinned at `1.1.0` and has been stable a long
time, and from the outside "finished" and "unmaintained" look identical. For a
system that expects to outlive its dependencies, that is a real supply-chain risk
even when nothing is broken. The answer is still no, for now.

**Measured here**, at national tree depth 24, through the CLI so the numbers
include the process start and circuit construction the application actually pays:
prove 33 ms, verify 12 ms, proof 77,840 bytes. Proving is barely sensitive to
depth, and the proof size does not move with it at all, because it is a property
of the FRI configuration rather than of the statement. There is no performance
case for a rewrite, and v9.360 found separately that verification is not the cost
driver either.

**Reasoned from the code rather than from a blog post.** A migration re-expresses
the circuit as an algebraic intermediate representation over modular component
crates, rather than Plonky2's ready-made recursive `CircuitBuilder`, and it
invalidates every published epoch exactly as the P9.3 leaf change did at smaller
scale. The surprise, and a useful one for whoever eventually decides: the
two-witness model would largely survive, because the second witness is
deliberately statement-level and never parses proof bytes. It would need
re-anchoring to a new hash, not rebuilding.

**Deliberately not verified, and recorded as such:** Plonky3's current release
status, either library's external audit status, and maintenance trajectory. Those
have a shelf life measured in months, and a decision record that quietly presents
unchecked claims as findings is how a soundness-core rewrite gets justified by a
paragraph nobody sourced. The record says which is which.

Re-evaluation triggers are recorded, the first being a stable Plonky3 release while
Plonky2 still has none. `check_plonky3_evaluation` with a seven-fixture detection
test, which also fails if the lockfile moves off the version the record evaluated.

**Phase P2 is complete at this version.** Every row is shipped except the Atlas
console and the national simulation harness, both of which are wrapper or
multi-arc work rather than scale architecture, and both already marked in
progress. The exit gate, P2.9's capacity model, was green before this phase
resumed.

---

## v9.360 — 2026-09-10 (P2.10: a cost model you re-run)

A committed cost table is out of date the week it is written, and worse, it hides
which of its inputs are facts about the code and which are guesses about a
deployment nobody has run. Measured verification throughput is a property of the
software; verifications per person per year is a property of a society. Presenting
them in the same font misleads even when every figure is right.

So this is a script. Every input is labelled MEASURED, COMPUTED, ASSUMED or PRICED,
and the error bars sit where they belong.

**The finding, stated rather than left to be derived: verification throughput is
not the cost driver at any realistic national scale.** Single-witness verify-at-use
measures about 7,848 ML-DSA-65 verifications per second per core. A hundred million
people verified twelve times a year is 38 per second on average, 381 at a ten-times
peak. One core. The whole cryptographic load of a national identity system fits
inside the base capacity a deployment needs anyway.

What costs money is availability and retention: the database copies that high
availability and a standby region require, and the verification events accumulating
for the window. Both are policy choices, not cryptographic ones.

| Population | Peak verify/s | Cores for it | Annual | Per 1M/year |
|---|---|---|---|---|
| 1,000,000 | 3.8 | 1 | $12,677 | $12,677 |
| 10,000,000 | 38 | 1 | $13,241 | $1,324 |
| 100,000,000 | 381 | 1 | $18,876 | $189 |

The per-million figure falls with scale because the base capacity is a floor, not a
rate. One measurement was taken for this model: a verification event costs 228.6
bytes including every index, from 200,010 rows in the partitioned table.

**What it excludes, each of which can exceed the whole figure:** staff and on-call,
the physical token and its personalisation, enrolment stations, support, legal,
compliance, external audit, and the hardware security module a real deployment needs
and this repository has never used. A cost figure that omits those is not
conservative, it is wrong in the direction that gets a project funded and then
stranded. The document also repeats that the throughput under it is a single-node
measurement whose multi-node scale is projected.

`check_cost_model` with a thirteen-fixture detection test, pinning that the model
stays runnable, that its measured rate is the benchmark's own, and that the
exclusions stay named.

---

## v9.359 — 2026-09-10 (P2.8: a second region, evacuated and measured)

The HA profile survives a node dying: Patroni's lease moves and another member in
the same region takes over, with no data loss. It does not survive the region.

The tempting fix is a third Patroni member "in region B", and it is wrong in three
places at once. The lease store would have to be reachable across the wide-area
network, so a partition between regions partitions the consensus itself, and a
three-member etcd split two-and-one loses quorum when the two-member side goes
dark, which is exactly the outage the second region existed to survive. Write
latency would include the round trip. And a member of region A's cluster living in
region B is still region A's problem when region A's lease store is unreachable:
the regions are not independent, they are one cluster with a long wire.

**So region B is a standby cluster.** A different scope, its own lease store,
streaming asynchronously from region A's router so a failover *inside* region A
does not break replication to B, and electing no primary of its own so the two can
never both accept writes.

**The price is measured, not asserted.** Asynchronous replication means the
recovery point is not zero, and a runbook that does not say how far from zero is
one nobody can plan against. The evacuation drill runs on every push under a live
write stream, recording every acknowledged write as it goes, because once the
region is gone nobody can ask it what it acknowledged. It cuts the region the way a
region goes dark, members and router and lease store at once, promotes region B,
and reports both numbers. Measured locally: 5 seconds to serve, zero rows lost at
the drill's write rate, against ceilings of 90 seconds and 50 rows.

**Two things matter more than either number**, and both are asserted. Region B
holds no row region A never acknowledged: a recovery point is a stated cost, but
divergence would mean a promotion publishes writes no client was told succeeded.
And what crossed is a contiguous prefix, because a standby holding 1-40 and 45-60
has skipped rather than lagged, and counting rows would not catch it.

`docs/operator/DR.md` carries the procedure and states the non-zero recovery point
before it rather than during the incident, along with the rule that a returned
region A is rebuilt as a standby and never brought back as a primary: two primaries
on two timelines is the one state with no clean recovery.
`docs/design/multi-region.md` is the design record. `check_multi_region_dr` with a
fourteen-fixture detection test.

**Not done, and the row says so.** Placement is the operator's. Promotion is
deliberate rather than automatic, because an automatic cross-region promotion would
have to distinguish "region A is gone" from "region A is unreachable from here".
Zero data loss would need synchronous replication with the WAN on every commit in
region A, which is a different product.

---

## v9.358 — 2026-09-10 (P2.6: a signed status through an untrusted cache)

Signing a status artifact is what lets an untrusted intermediary carry it: a
cache cannot forge a status any more than an aggregator can. That is the whole
reason to sign a feed rather than answer a query. But a cache introduces the one
failure signing does not prevent, which is time. A cached status is a status the
issuer may already have withdrawn, and until now these endpoints emitted no cache
directives at all, so a network in front of them had nothing to go on.

**The rule: a cache directive is never a constant.** It is the artifact's own
remaining life, computed from the `expires_at` the issuer signed, so a cache
physically cannot outlive the window the issuer committed to. When the artifact
expires the cache entry expires with it. A fixed `max-age` would eventually exceed
some artifact's window, and the symptom would be a revoked credential that keeps
verifying for a while, which is the failure this whole layer exists to prevent.

Two corollaries, enforced rather than advised. An artifact already past its expiry
is `no-store`, because caching what every verifier must reject only creates a stale
copy to serve later. An artifact whose window cannot be parsed is `no-store` too,
because guessing an interval for a body you did not understand is the same mistake
with an extra step.

**`stale-while-revalidate` and `stale-if-error` are refused.** Both exist to serve
a known-stale body when the origin is slow or unreachable, and a known-stale
revocation feed is precisely the artifact an attacker wants served: the cheapest
attack on this design is to make the origin unreachable and let the network answer
from yesterday. A status origin that is down should fail.

**The split that would leak if it were backwards.** Seven artifacts are
byte-identical for every consumer and are `public`, cached to their own window with
a strong ETag to revalidate on. Three name one credential, and are `no-store`: a
status assertion carries one `token_value`, so a shared cache holding it would
serve one holder's credential to another, and a signature cannot undo a
disclosure. They are `no-store` rather than `private` because `private` still lets
the requester's own browser keep a copy on disk, and a holder's device is exactly
where a coerced search looks. Both halves are pinned by the check and asserted by
the drill.

Freshness rules published at `docs/design/status-distribution.md`.
`check_status_distribution` with a twelve-fixture detection test.

**Not done here, and the roadmap row says so.** CDN placement, origin-shield
topology and a measured cache hit rate at national volume are an operator's
deployment. What ships is the property a CDN needs to be safe in front of this
origin: no correct cache can serve a status past the window its issuer signed.

---

## v9.357 — 2026-09-10 (P2.5: the epoch pipeline at national depth)

An epoch tree is fixed-depth, and the obvious implementation pads the leaf vector
to 2^depth before hashing anything. At the demo depth of 14 that is free, which is
why it survived. At the national depth of 24 it took **10.8 seconds and 2.9 GB** to
compute a root over a thousand members, and the number did not move with the
population: sixteen million leaves were materialised whatever the real one was. An
authority on that budget closes epochs by the minute and the gigabyte and pays all
of it on zeros.

The padding is one repeated value, so every subtree above the real members is an
all-zero subtree with exactly one hash per level. Folding those in makes a root cost
O(members + depth), and repairing a single member O(depth) rather than a rebuild.

| Members at depth 24 | Root | Peak memory |
|---|---|---|
| 1,000 | 0.01s | 27 MB |
| 100,000 | 0.24s | tens of MB |
| 1,000,000 | 2.10s | tens of MB |

**Two things keep that from being a shortcut.** The sparse root is element for
element the root the padded construction produced, asserted across the shapes that
break naive implementations including a full tree with no padding, so no epoch
already published becomes unverifiable. The padded construction is deliberately
kept, unused in production, purely as the thing parity is measured against. And the
independent Python witness folds the padding the same way, so it still agrees at
depth 24, where before it could not run at all.

**"Parallel proving" is amended away, and what replaced it is better.** P9.2 moved
proving to the holder's device, so the authority no longer proves. The
authority-side batch that remained was one inclusion path per member, and measuring
it found the wall was not compute but storage: 1,718 bytes each, roughly 17 GB of
JSON to close a ten-million-member epoch, written on every close and read by
nothing. Every query in the application selects `leaf_hash`; the published anonymity
set serves leaf hashes; the holder derives their own path. The schema's own comment
flagged the column as plaintext at rest a later version would have to encrypt. So
the answer at scale is not to parallelise it but not to materialise it: migration
011 makes `proof_path` nullable, an epoch close stores none, and epochs closed
before this keep what they recorded.

**The cadence spec is published.** `docs/design/epoch-cadence.md` states the thing a
schedule number actually controls: revocation freshness, the size of the anonymity
crowd, and how often a relying party's one-human-once ledger resets. Those pull
against each other and no cadence satisfies all three. It also names the constraint
this ship did not move: the 10,000-member epoch cap and the bounded published set
are sized for the default depth and are now the binding national-scale limit.
Raising them is a resource-exhaustion decision about a public body, not a number to
bump, so nothing here bumps it.

`check_epoch_pipeline_scale` with a twelve-fixture detection test, and a drill that
runs at depth 24 on every push with wall-clock and memory ceilings a return of the
padding would breach.

---

## v9.356 — 2026-09-10 (the paper describes the system that exists)

Version 2 of the paper was written from the tree at `v9.345`. Phase P9 then
closed five absences the paper had recorded as open, and the paper went on saying
they were open. A citable document that describes a system which no longer exists
is worse than no document, so the holder-side sections were rewritten.

Section 8.3 said the prover runs on the Polaris host and there is no per-verifier
nullifier. Section 8.4 called cross-verifier correlation "a permanent, documented
property". Section 17 opened with "Nothing in this section is solved" and marked
the nullifier, local proving, the pairwise handle and the agent grant as
proposals. All four run. The delegation figure drew the entire chain dashed; it is
redrawn as built, with a single dashed box for the residue that is not closed. The
capability ledger moved four rows and added one for the residue.

**Each closed absence is paired with the bound it does not clear**, which is the
part a rewrite like this gets wrong if it is written in a hurry. The nullifier does
not hide the holder from the issuer, which derives every leaf to build the tree. The
pairwise handle bounds what a verifier stores, not what it is shown, because a full
credential still carries a stable token value. The agent grant hides the human from
the agent's actions, not the credential from the service. Section 17 also records
why the nullifier was not the small circuit change the section had predicted: an
opaque leaf cannot anchor a nullifier to anything, so the leaf had to become a
Poseidon commitment the circuit opens.

**Two dates, stated rather than blurred.** The front matter, the capability ledger
and the closing sentence now say the body was measured at `v9.345` and the
holder-side sections at `v9.355`. The counts elsewhere are still the `v9.345`
measurements and are labelled as such. A partial re-measurement would be worse than
an honestly labelled old one.

A sweep of the whole document then found four more claims that P9 had made false,
three of them in the sections an assessor reads first. The limitations list said
there is no holder-side key, no on-device proving, no scoped nullifier and no
pairwise presentation, and that attestations are recorded by an operator rather
than signed; it now names the residue that remains, which is blinded and one-time
presentations, and states the issuer bound separately. Section 4 and the ledger
said `RecoveryRequest` rests on procedure discipline; it has been enforced by a
trigger since v9.347, thirteen of thirteen. Sections 12 and 18 said anchor
verification lives only in the detached verifier; it has been in both SDKs since
v9.346.

`docs/design/auth-broker.md` carried the same stale claim about the login subject
and is corrected. The paper rebuilds at 58 pages with no overfull boxes, no
underfull vertical boxes and no undefined references, and `rendered-from.txt` is
restamped so `check_paper_pdf_is_current` holds.

---

## v9.355 — 2026-09-10 (a runnable path, and the holder arc written down)

Two gaps left by P9.8 and P9.4, both about whether the work is reachable by the
person who needs it.

**A service can decide a grant from the command line.** `verify_agent_grant`
existed only as a Python function, which makes it a library. The party who needs
it is a service operator with a JSON file and a shell, and a capability reachable
only from Python will not be used. The detached verifier now takes
`--agent-grant`, with `--holder-binding`, `--credential`, `--agent-proof`,
`--grant-revocation`, `--action`, `--service-nonce` and `--verifier-scope`, and
prints each of the five links separately: "this grant was revoked" and "this agent
does not hold the key it names" call for different responses at the service. Exit
0 accepts, 2 refuses. `check_agent_grant` now requires the CLI.

**The holder arc has a design doc.** `docs/design/holder-side-keys.md` gathers the
four mechanisms P9 built, each with the bound it does NOT clear: the holder key and
why its proof must not cover the presented code; proving locally and why a swapped
anonymity set is a refusal rather than a note; the scoped nullifier and its two
bounds, the issuer and the epoch; the pairwise handle and the difference between
what a verifier stores and what it is shown; and the agent grant, whose revocation
belongs to the holder alone. A closing section collects what the issuer still knows,
because four mechanisms read together can sound like more than they are.

`docs/design/auth-broker.md` still said the ID token's subject is a credential hash
and called the resulting correlation permanent. That stopped being true at v9.353;
it now describes the pairwise derivation, states the cost, and names what did not
change.

---

## v9.354 — 2026-09-10 (P9.8: delegation without the credential)

A person wants an agent to act for them. What people actually do is hand over
the credential, and that gives the agent everything the person can do, forever,
revocable only by revoking the person. A grant is the opposite of each of those.

`polaris-agent-grant/1`, signed by the HOLDER key, names its actions, states its
limits, expires on its own, and carries `grant_id` as a revocation handle that
belongs to it alone. `actions` and `limits` are inside the signed statement,
which is the difference between a bounded grant and one that only looks bounded:
a grant widened in transit fails rather than passing invisibly. An empty
`actions` grants nothing, and there is no way to say everything.

`polaris-grant-revocation/1` is signed by the same holder key. Anyone may publish
bytes; only the holder may end the grant. The issuer is not contacted and never
learns the grant existed, and the human's credential is untouched throughout. A
person can end their agent's authority without asking permission from, or being
observed by, the authority that issued their identity.

`polaris-agent-proof/1` is signed by the AGENT key over the action and the
service's own nonce. Without it a grant is a bearer token and whoever copies it
in transit becomes the agent. With it, a captured proof replays neither to a
second service nor to a second action at the first.

Two smaller decisions worth naming. A revocation carries no reason field, and
none will be added: a place to record why a grant ended is a place a coercer can
demand be filled in or left empty, and either way it turns a revocation into a
signal about the person. And an unknown limit key is refused rather than ignored,
because a grant that says `max_transfers: 3` to a service that has never heard of
`max_transfers` must not be treated as unlimited.

The bound is stated, as in P9.4. Under a plain holder binding a service still
sees the credential's token value, so the verdict reports `correlation: exposed`.
A grant hides the human from the agent's actions, not the credential from the
service.

Wire spec, canonical-equivalence oracle, both SDKs, and six conformance vectors
that pass in all three implementations, taking the published contract to 71
cases. The three artifacts join the metamorphic fuzzer, where the grant is the
one object whose interesting mutation is a WIDENING rather than a corruption;
2072 cases, all fail-closed. `check_agent_grant` with a twelve-fixture detection
test, and a drill proving twenty-four cases under real ML-DSA-65.

This closes P9. Every row in the phase is shipped.

---

## v9.353 — 2026-09-10 (P9.4: bounded, not permanent)

The login token's subject was `SHA3-256(token_value)`. The same sixty-four
characters at every relying party in the system. Two of them comparing user
tables matched people exactly, forever, and neither had to do anything wrong,
because the identifier they had been handed was a global one. The subject is the
value a relying party writes down, and written-down values are the ones that get
pooled, sold, subpoenaed and breached, so this was the correlation handle that
mattered most in practice.

It is now `SHA3-256("polaris-pairwise/1" || token_value || client_id)`: stable at
one relying party, so an account still works, and unrecognisable at the next. The
same derivation gives the presentation layer its handle, from the holder key
rather than the token value. The wallet emits it under `--verifier-scope`, and
the verifier recomputes it from the binding it already verified rather than
trusting the holder for it. A handle with no scope is refused rather than
globalised, because a value derived from the holder key alone would be a global
identifier wearing the word pairwise, and a hash of the empty string would key
every holder to one record.

**The bound, stated rather than glossed.** A full-credential presentation still
shows the verifier a stable token value, the issuer's signature and the holder's
public key. Two relying parties who deliberately keep the raw material can still
correlate. So `verify_presentation` now reports `correlation`, and it has to be
able to say the unflattering word: `exposed` for a plain credential, `bounded`
only for the zero-knowledge form, whose handle is P9.3's scoped nullifier and
which shows the verifier no stable credential at all. The guarantee is about what
a verifier should store, not about what it is shown. The drill asserts that bound
as carefully as it asserts the benefit, so nobody reads it for more than it says.

The README, the paper's privacy section and the status ledger said this was a
permanent, documented property. It is not any more, so they say bounded rather
than permanent, and the paper is rebuilt and restamped: 56 pages, no overfull
boxes, no undefined references. The issuer's own records are unchanged
throughout; this changes what a relying party is told, not what the issuer knows.

Two checks were pinning the old behaviour and now pin the new. `check_auth_broker`
required the subject to be `sha3_256(token_value)`, which was pinning the defect.
`check_public_claims_honest` required the flat old sentence, and now requires both
halves, because either alone misleads: stored handles are per-verifier, and a
presentation still shows stable material.

**Breaking for relying parties:** every existing account subject changes once. A
relying party that loses its registration and re-registers gets a new client id,
and its accounts become strangers. That is the standing cost of not handing out a
global identifier.

Both SDKs derive the handle identically, pinned by a cross-language anchor.
`check_pairwise_presentation` with a ten-fixture detection test.

---

## v9.352 — 2026-09-10 (P9.3: one person, once per scope)

A relying party constantly needs to know whether this person has already claimed
here. The usual answer is an account, which is an identifier, which is a lifelong
correlation handle. The scoped nullifier answers the same question without one.

**The leaf became a commitment the circuit opens.** This is the part that took the
work, and the reason the roadmap resized this row after reading the circuit. The
epoch leaf was `SHA3-256(token_id | token_value | context_id)`, computed outside
the circuit and handed in as an opaque private value. A nullifier beside an opaque
leaf proves only that the prover knows some number: nothing ties the two to one
secret, so a prover could pair any member's leaf with a nullifier of their own
choosing, and every property below would be a claim rather than a proof. Verifying
a SHA3-256 preimage in-circuit costs thousands of constraints; Poseidon costs about
a hundred. So the leaf is now `Poseidon(secret || context_id)`, the circuit opens
it, and the old SHA3-256 derivation became the holder secret.

**The nullifier.** The circuit gains a `scope` public input, the relying party's own
domain separator, and a `nullifier` public input, `Poseidon(secret || scope ||
epoch_id)`, derived from the same secret as the leaf. `verify` binds both like any
other public input. One person proving twice in one scope and epoch presents the
same nullifier under a fresh nonce and a different proof, so the verifier refuses
the repeat while learning nothing about who was refused. The same person at a
second relying party presents a value the two cannot correlate.

**Two bounds, stated rather than glossed.** The nullifier does not hide the holder
from the ISSUER, which derives every member's secret in order to build the epoch
tree and could compute any nullifier in any scope. The property is between relying
parties. And it resets each epoch, deliberately, so that membership never becomes a
permanent pseudonym.

**Not backward compatible.** An epoch closed before this ship holds SHA3-256 leaves
the current circuit cannot open, and its proofs do not verify against the current
verifier. Epochs are re-closed, not migrated.

**Two witnesses, not one.** The independent Python witness re-derives both the leaf
and the nullifier from the secret rather than taking the bundle's word, so a Rust
verifier that quietly stopped constraining them would be caught instead of agreed
with. The cross-language differential pins both derivations bit for bit across
contexts, scopes and epochs.

Sixteen crate tests, twenty-nine differential tests, an eighteen-case drill under
the real circuit, `check_scoped_nullifier` with a nine-fixture detection test, and
the comparison rule in both SDKs, because exact hex only, never across scopes,
never across epochs is easy to get wrong by hand.

---

## v9.351 — 2026-09-10 (the detached verifier answers for itself)

Two defects in `scripts/polaris-verify.py`, both found by pointing the published
conformance contract at the detached verifier in-process for the first time.

**A swapped anonymity set read as authentic.** The members of an epoch leaves bundle
ride outside the bytes that were signed, bound only by `leaves_root_hex`. The verifier
recomputed that commitment, recorded the mismatch in a note, and still reported
`leaves_authentic: true`. An attacker who swaps every member but one leaves the
signature genuine, and the holder's own `member_index` still finds them, inside a crowd
that does not exist. The set was published to give the holder a crowd to hide in, and
this handed back a crowd of one. A mismatch is now a refusal, matching
`verify_revocation_feed`, which has always refused the same shape of tamper, and
matching both SDKs, which already folded the commitment into their verdict. Only the
detached verifier disagreed.

**A caller's `now` was never turned into an instant.** Every freshness gate compared
`now` directly against parsed timestamps, while the conformance cases, the CLI and every
docstring invite an ISO-8601 string. Four artifact types raised TypeError where the
comparison sat outside a try. Four more sat inside one and answered `fresh: false` with a
note blaming the artifact's own timestamps. The second is the worse failure: a verifier
that calls fresh material stale, and blames the material, is believed. All seven gates
now normalise through a new `_instant()`, which honours a string or a datetime and
refuses a malformed one on its own terms.

**Tests.** `scripts/test_verify_conformance.py` runs the detached verifier over all 65
published conformance cases in-process, so a divergence between the two shipped verifiers
fails a test run instead of reaching an integrator. `scripts/test_verify_p9.py` covers the
P9 surface directly, including the anti-coercion property on the bytes: a holder proof's
signed statement is byte-identical whether the presented code is the ordinary one or the
duress one.

**Coverage.** The standalone artifacts under `scripts/` are shipped product living outside
the four package directories, so `--source` was silently discarding every line their tests
covered. `polaris-coverage.sh` now runs those suites unrestricted. The detached verifier
goes from 9% to 44%, and the relying-party client and verify-load harness enter the
denominator honestly rather than being invisible.

New invariants: `check_commitment_mismatch_is_a_refusal` pins the order in both verifiers
that publish members outside the signed statement, in both SDKs, and in the published
contract. `check_verifier_instant_normalised` pins the normalisation structurally, by AST,
so any future verifier that compares against a raw `now` fails the layer.

---

## v9.350 — 2026-09-10 (P9.2: a holder proves on their own device)

The membership prover was always a program a holder could run, but nothing published what
proving needs. An epoch's leaf set IS the anonymity set: a proof hides which member is proving
inside the set it is proved against, so a set only the issuer holds is not an anonymity set at
all. Without a published set a holder had to be handed one out of band, which in practice
meant the issuer proving on their behalf and learning which member asked.

- **`polaris-epoch-leaves/1`**, wire spec section 3.16: the authority's signed publication of
  an epoch's leaf set. `GET /api/v1/epoch/<id>/leaves` serves it to anyone. Public by
  construction, because a set you must authenticate to fetch tells the issuer who is about to
  prove; every requester receives identical bytes, each entry is an opaque SHA3-256 only the
  matching holder recognises, and nothing is recorded about who asked. Bounded at ten thousand
  members (C8).
- **Checkable without the proving library.** The leaves ride outside the signed statement and
  are committed to by `leaves_root_hex`, SHA3-256 over the sorted set, the same construction
  the revocation feed uses. A standalone verifier and both SDKs check the set with SHA3-256
  alone; `merkle_root` is carried only so a holder can cross-check the bundle against the
  epoch checkpoint.
- **`verify_epoch_leaves` and `member_index`** in the detached verifier: the holder finds their
  own leaf HERE, on their own device, and is never asked which index they used. Both SDKs
  verify the published set. Two conformance vectors certify a good set and one whose members
  were swapped after signing; 65 cases now pass in all three verifiers.
- **The wallet fetches and verifies before proving.** `prove-membership --from-instance
  --epoch-id N` pulls the signed set, refuses it unless the signature and the commitment hold,
  then finds its own leaf and proves locally.
- **`check_holder_side_prover`** (#194) with a six-perturbation detection test, including the
  one that matters: putting the anonymity set behind a login.

Closes P9.2.

## v9.349 — 2026-09-10 (P9.1: a holder can hold a key, not only a file)

The keystone of P9. Polaris has been issuer-centric since Version 1: a holder holds a
credential, not a key pair, so presenting the file was the whole of the proof. That single
absence is the common cause under four separate limitations, and it is why document signing
is notarial, login is by possession, no agent can be delegated to, and a presentation carries
a value stable across the verifiers it is shown to. This ship supplies the missing primitive.

**The constitutional note first.** A key the holder controls is also a key the holder can be
COMPELLED to use. The holder proof is signed over the credential, the context, the verifier's
nonce and the instant, and deliberately NOT over the presented code, so a coerced presentation
stays byte-indistinguishable from a consenting one. `check_holder_key_binding` reads the
signed key list out of both implementations and fails the build if the code ever appears in
it; the drill proves the statement bytes and the verifier's verdict are identical under
duress and under consent. A holder key that weakened the duress path would be a regression
against the vocation, not a feature.

- **`HolderKeyEvent`** (migration 010, 37 tables / 44 migrated), an append-only register of
  bound, rotated and revoked holder PUBLIC keys, with `HolderKeyCurrent` deriving the key in
  force. The private key lives on the holder's device and never reaches the database. A hash
  index serves the key lookup, since an ML-DSA-65 public key exceeds a btree row.
- **Two routes**, `POST /api/v1/holder-key` and `POST /api/v1/holder-binding`, authenticated
  by POSSESSION of the credential exactly as the status assertion is: no session, no bearer,
  no operator. An operator cannot bind a key to a credential they do not hold. A revoked
  binding is published rather than withdrawn, so a verifier sees the holder has no usable key
  instead of inferring it from an absence.
- **Two signed artifacts**: `polaris-holder-binding/1` (the issuer's) and
  `polaris-holder-proof/1` (the holder's), wire spec section 3.15, both pinned by the
  canonical-equivalence oracle (103 cases).
- **Every verifier decides the chain.** `verify_holder_binding`, `verify_holder_proof` and
  `verify_presentation(..., expected_nonce=, require_holder_proof=)` in the detached verifier;
  `verify_holder` and `verifyHolder` in the two SDKs. Seven published vectors and seven
  conformance cases certify the chain proved and the three ways it fails: a stranger's key, a
  replayed nonce, a revoked binding. 63 cases now pass in all three verifiers.
- **The wallet holds the key.** `polaris-wallet holder-keygen` generates it and binds the
  public half; `present --holder-nonce` signs a proof against the verifier's own nonce.
- **`scripts/polaris-holder-key-drill.py`**, in CI, exercises nine cases under real ML-DSA
  including the two constitutional ones.
- **`check_holder_key_binding`** (#193) with a six-perturbation detection test. Counts
  restamped to 193 checks, 37 tables, 121 routes.

Closes P9.1, which unblocks P9.2, P9.3, P9.4 and P9.8.

## v9.348 — 2026-09-10 (P9.5: a trust edge is signed by the agency that made it)

The trust graph was the one load-bearing joint of federation that rested on an operator's
word. The federation manifest that publishes an attestation was always signed, but the ROW
was recorded by a human and the next publication signed whatever the table held, so an edge
inserted straight into a database was indistinguishable from one made through the ceremony.
The architecture's whole argument is do not trust the application, and here it was asking
exactly that.

- **`polaris-trust-attestation/1`**, the twenty-first signed wire artifact: the attesting
  agency's signature over `attesting_agency_id`, `attested_agency_id`,
  `attested_public_key_hex`, `context_id`, `attested_date`, `valid_until` and `algorithm`.
  The edge is bound to the attested KEY, not only to the agency, because an attestation
  naming an agency alone keeps meaning what the attester meant after that agency rotates to
  a key the attester never saw. The context is signed, so an edge cannot be widened later.
- **The schema** (migration 009) carries the signature all-or-nothing, and
  `enforce_attestation_immutability` refuses to let a recorded signature be replaced.
  The columns are nullable: rows made before this version stay verifiable as unsigned legacy
  for one major, and a verifier reports which it saw.
- **The ceremony signs what it records.** `/api/federation/attest` signs the edge in the same
  request that creates it, under the attesting agency's own key; the manifest publishes the
  signature beside each edge.
- **Every verifier checks it.** The detached verifier gains `verify_attestation` and
  `verify_cross_authority(..., require_signed_attestation=)`; both SDKs gain the same. A
  present-but-invalid signature refuses the edge, which is stricter than an absent one. The
  canonical-equivalence oracle pins app and verifier byte for byte (91 cases), the wire spec
  gains section 3.14, and three conformance vectors certify a binding edge, one re-pointed at
  another key, and one widened to another context. 56 cases now pass in all three verifiers.
- **`check_attestation_signed`** (#192) requires the whole path, with a seven-perturbation
  detection test. Counts restamped to 192.

Closes P9.5.

## v9.347 — 2026-09-10 (P9.7: the recovery ceremony is enforced at the schema)

The audit-of-record principle says a row whose own history is the record must be append-only,
or bounded one way, AT THE SCHEMA rather than by the discipline of whoever writes to it.
Thirteen of the fourteen instances were. `RecoveryRequest` was not, and it was named rather
than glossed for eight versions: `uc9_complete_recovery` was the only sanctioned writer, but
a raw UPDATE from a database session was accepted. This closes it.

- **`enforce_recovery_request_immutability`** (migration 008, in the shape of
  `enforce_attestation_immutability`). Everything it permits moves one way: identity and
  request fields never change; `status` leaves `PENDING` exactly once for a terminal value
  and never moves again; the three out-of-band channels may be recorded while `PENDING` and
  not after a decision, and a verified biometric never returns to false; the four decision
  fields are written once, never rewritten and never withdrawn; `DELETE` is refused outright.
  The sanctioned procedure writes exactly inside that envelope and is unaffected.
- **`check_aor_append_only_triggers` now names all fourteen tables** instead of counting
  triggers, because a count nobody reads can fall by one silently, and it reads migrations
  as well as `06_triggers.sql` because that is how later tables arrive. Its first detection
  test lands with it: four perturbations, including the removal of this very trigger.
- **Six database-backed tests** in `test_check_constraints.py` exercise each refusal and
  prove the sanctioned envelope still writes, run against a live database.
- **The design record** (`docs/design/audit-of-record.md`) replaces "the one that is not
  fully enforced" with how it was closed, and its count is corrected from thirteen to the
  fourteen the table has listed for some time.

Closes P9.7.

## v9.346 — 2026-09-10 (P9.6: an outsider can check an anchored timestamp)

The first row of P9. Long-term validation asks whether a signature was valid at the instant
it was made, and a timestamp alone does not settle it: whoever holds the timestamp
authority's key can mint a backdated one. An ANCHORED timestamp is different, because its
digest is an entry in an append-only log whose head is published and cosigned by independent
witnesses, so a forgery has to be absent from every witnessed head of its claimed era. Until
now only `scripts/polaris-verify.py` could decide that, which reserved the strongest form of
long-term validation for whoever runs Polaris's own tooling. Both SDKs now decide it.

- **Python SDK** (`sdk/python/polaris_verify/`): `timestamp_hash`, `verify_inclusion` (RFC
  6962 section 2.1.1, total on hostile input), `verify_cosignature`, and
  `verify_timestamp_anchor(ts, log_key=, trusted_witnesses=, threshold=)` returning an
  `AnchorVerdict`.
- **TypeScript SDK** (`sdk/typescript/src/index.ts`): `timestampHash`, `verifyInclusion`,
  `verifyCosignature`, `verifyTimestampAnchor`, the same verdicts, type-checked.
- **The conformance contract**: a new `artifact: timestamp-anchor` case shape in both
  verifier CLIs, the runner and `conformance/SPEC.md`, with four published vectors generated
  and pre-verified by `conformance/make_anchor_vectors.py` under real ML-DSA-65: a valid
  anchor, a head cosigned by two witnesses, a fabricated head signed by a stolen log key
  (`anchored: true, witnessed: false`, which is the verdict that matters), and a path that
  does not reconstruct its head. 53 cases now pass in all three verifiers, and the
  TypeScript SDK independently accepts Python-signed anchors.
- **Checks**: `check_conformance_suite` and `check_typescript_sdk` now require the anchor
  decision in both SDKs and require the cases to cover a witnessed head, an unwitnessed one
  and a broken proof; four new perturbations in the detection tests.

Closes P9.6, carried since v9.341 as a follow-up sentence inside a completed row.

## v9.345 — 2026-09-09 (Engine and tool only)

The measurement apparatus of v9.343 and v9.344 is cut: the viewer, the fits, the dimensions,
the cost table, the companion rules and the CI history are gone, because none of them changed
what a developer does. What stays is one tool, `scripts/polaris-ship.py`, with the three commands
that do.

- **`run`: the product suite in 103 seconds end to end instead of 266.** The four database-backed
  modules (673 tests) run as test classes sharded across eight processes, each against its own
  freshly loaded database (the schema and the up migrations, as CI loads them), its own Redis and
  its own state directory; the classes that spawn processes or bind ports run one after another
  in a serial shard. Heaviest classes first, to the least-loaded shard: 555 seconds of test time
  in 78 seconds of wall clock, plus the loads. The same 673 tests and the same three skips as the
  sequential runner; the shard databases are dropped afterwards, whatever happened.
- **`plan`, printed by preflight.** The verification a change needs: the release recipe as code,
  selected by the paths that moved since the last tag, plus the drills that mention a route whose
  handler changed, directly or through a helper it calls. The v9.334 lesson, a changed verdict
  shipped without its drills, as a line of output before the ship.
- **`triage`.** A red CI run classified against the known flake signatures (the runner's apt
  index hash mismatch, the Go module proxy in the Caddy build): the rerun command, or the first
  failing lines per job.
- **Check #191 `check_ship_tool`** replaces the two regression checks: known answers for the
  changed-route selection through a helper, the drill matching on a parameterised path, the
  verification map, the flake classifier, the shard distribution with the serial classes pinned,
  and the failure-block parser; preflight and CLAUDE.md must carry the commands; the viewer, the
  regression script and its document must stay cut.

## v9.344 — 2026-09-09 (The instrument)

The measurement of v9.343 pointed at the moments where a version goes wrong, after asking
the record whether it carries a signal. No wrapper: the viewer is unchanged.

- **The deltas refuse a regression.** Checks added against routes, tables and tests added,
  per version since v9.60, fits at R² 0.09. The ship discipline is a per-version habit, so the
  instrument reads the record as frequencies: a companion is a rule when every version that
  moved the trigger moved it too (routes bring tests, 29 of 29; tables bring checks and tests,
  12 of 12), and a note at seventy percent (routes bring checks, 21 of 29).
- **`delta`, inside preflight.** The working tree, uncommitted and untracked files included,
  measured against the last tag: what moved, which companion the record expects that did not
  move, and the verification the change needs. The verification is the release recipe as code,
  selected by the moved paths (the schema, the app, custody and signing, the verifiers and wire
  formats, authentication, the prover, the checks, the CLI, the templates, the drills, the
  deployment), plus the drills that mention a route whose handler changed, directly or through
  a helper it calls. The v9.334 lesson, a changed verdict shipped without its drills, becomes a
  line of output before the ship.
- **`ci triage`.** A red run classified against the known flake signatures: the Go module
  proxy stream error in the Caddy build, and the runner's apt index hash mismatch that turned
  v9.343's run red in five jobs within a minute. A known flake gets the rerun command; anything
  else gets the first failing lines per job. `ci extract` keeps the run history in
  `docs/reference/regression/ci.json`: 342 runs on main, 285 green on the first try, 14 green
  after a rerun, 43 red. The apt flake itself is removed at the source: the runner's Chrome
  package list, which this workflow never uses, is dropped before apt runs in every install step.
- **`cost`.** Minutes between consecutive tags by the size of the change, for estimates
  grounded in the record: a median of 20 minutes per version since v9.60, 12 for a version
  with no product lines, 36 for one adding a few hundred.
- **Check #192 `check_regression_instrument`.** Known answers on synthetic records for the
  rules, the flags, the cost, the changed-route selection through a helper, the drill matching
  on a parameterised path, the verification map and the flake classifier; preflight and
  CLAUDE.md must carry `delta` and `ci triage`; a warning when the committed record lags the
  version by more than six releases.

## v9.343 — 2026-09-09 (Polaris as data)

The system described by measurement rather than prose, modelled on a small pair of
regression notebooks: least squares from scratch, then the same over real points, with the
outlier lesson kept.

- **Every tagged version measured the same way.** `scripts/polaris-regression.py extract` reads
  the tree at each of the tags and counts invariant checks, routes, tables, tests, product lines,
  documentation lines, drills, CI jobs and conformance cases, with the tag's date and day count;
  the dataset ships as `docs/reference/regression/dimensions.json` and `.csv`.
- **Least squares in closed form, no numeric library.** Simple (slope, intercept) and multiple
  (the normal equations solved by elimination), with R², adjusted R² and a standard error per
  coefficient; `fit` writes `fits.json` and the table in `docs/reference/REGRESSION.md`, which
  states the model and reads the results honestly (growth against time is a velocity, pairs that
  move together were built together, five points describe a table and nothing more).
- **The measured performance tables, in the same shape.** The baseline's latency against load
  and the scaling document's render time against event count (a power law in log-log space).
- **A viewer, on the project site.** `site/regression.html`: pick two dimensions, see the points
  (the versions themselves), the fitted line and its equation in the repository's own units, the
  residuals beneath, the strongest pairs and the multiple-regression models; click a point to
  exclude it and watch the fit move. Data embedded, no library, no network.
- **What the data says at v9.342.** Checks against the version number: 0.62 per version,
  R² 0.99. Checks against days since the first tag: about one a day, R² 0.76, because the tags
  cluster on working days. Over the whole series, documentation lines against checks fit at
  R² 0.18 and tests against checks at 0.62; from v9.60 on, after the apparatus and archive
  removal had taken a thousand tests and 55,000 documentation lines out of the tree, the same
  pairs fit at 0.98. The fits are reported both ways and the viewer has the switch; the
  baseline's negative latency slope is read as what it is (the heavier route was offered the
  lower rate), not as latency falling under load.
- **The arithmetic is a gate.** `check_regression_tool` (#191) imports the tool and requires
  exact answers on an exact line, an exact plane and the reference notebook's nine points, and
  requires the dataset, fits and viewer to agree on the tag they were generated from.

## v9.342 — 2026-09-09 (The edge image build retries a transient checksum-database failure)

Twice today a CI job failed inside the self-built Caddy edge image: `xcaddy build` fetches Go
modules and verifies each against the public checksum database, and the database answered
mid-download with an HTTP/2 stream error. That is a transient network failure, not a
verification failure, and it reddened a job with no code change behind it. The build now
retries the same command a bounded four times with a growing pause before declaring the image
broken. Verification is never weakened: the checksum database stays on and no module flag is
relaxed; only the fetch is retried. The Caddy image was rebuilt locally with the change and the
rate-limit plugin confirmed compiled in.

## v9.341 — 2026-09-09 (Timestamp transparency: anchoring as the caller's choice, P8.5b)

The maintainer's decision on the one design question the review series left open. Long-term
validation trusted a timestamp authority's key; a stolen key could mint a timestamp dated a
year ago and nothing could tell. Every remedy retains something, and the authority was built
to retain nothing, so retention is now the caller's choice, per timestamp, visible in the verdict.

- **Anchoring, opt-in.** `anchor: true` at `POST /api/v1/timestamp/<id>` (and `anchor_timestamp`
  at signing) appends the timestamp's SHA3-256 to `TimestampLog`, an append-only transparency
  log (migration 007), published as `polaris-timestamp-log` with signed heads, and returns the
  inclusion evidence stapled. The default request still retains nothing; the anchored one
  retains one digest and one instant, never a document or a requester.
- **Verified offline, witnessed when it matters.** `verify_timestamp_anchor` checks the proof,
  the head and the reconstruction; with trusted witnesses named it requires the head cosigned,
  because a thief with the authority's key can sign a fresh head over a fabricated log but
  cannot make a witness have cosigned it at the claimed time.
- **Long-term validation gains its policies.** `require_anchored` (with witnesses), a
  `timestamp_quorum` of distinct independent authorities (the no-retention alternative,
  `attach_ltv` taking further timestamps), and the timestamp authority's key status per the
  trust list, checked at the instant like the signer's.
- **Drilled under a stolen key.** A backdated forgery is authentic and trusted, so a verifier
  with no anchoring policy still accepts it (the residual risk, stated) and one that requires
  an anchor does not; a forged anchor is unwitnessed and a caught split view; the trust list
  refuses forgeries dated after the compromise; a quorum of two refuses the lone forgery. The
  two-instance drill anchors over HTTP and shows the unanchored request leaving no row.
- **Stated everywhere.** The timestamp authority's design record, the readiness ledger, the
  API reference, the data model and the wire spec (timestamp 1.1, signed document 1.1,
  registry 1.4) say what is retained and when. `check_timestamp_transparency` (#190) pins it.
  Limit: anchor verification is in the detached verifier, not yet the SDKs (P8.5c).

## v9.340 — 2026-09-09 (The comparison table names its subjects)

At the maintainer's direction, the README's "Where Polaris sits" comparison table names the
system it compares against again (the row that read "federated national eID" since v9.319
carries the name it did before). A comparison that hides its subjects is a weaker claim,
not a stronger one. The rule that the tree describes the class rather than the instance stands
everywhere else: `check_no_named_reference_systems` exempts exactly the rows of that table, not
the prose around it, not the site, not the documentation or the code, and its detection test
proves each of those boundaries.

## v9.339 — 2026-09-09 (The same-key timestamp guard applies to real keys)

v9.336 made the signing route refuse a `timestamp_agency_id` whose key custody on the instance
is the signer's own key. Under the test profile's placeholder signing neither side has a key,
so the guard compared two empty values and refused a legitimate request; CI's product suite was
red for v9.336 through v9.338 on the route test v9.334 added, while the real-PQC and
two-instance jobs were green. The guard now applies to real keys only (under placeholders no
independence claim exists either way); the two-instance drill still shows the refusal under
B's real key. The full product suite (691 tests) was run locally before this release, which
is the discipline the previous three releases skipped.

## v9.338 — 2026-09-09 (The drills catch up with the stricter verifier, and the catch-up is gated)

v9.334 tightened long-term validation (a trusted, signer-independent timestamp authority is
required) and shipped on the document-signing drill alone. Two other drills asserted the old
outcome: the trust-lifecycle drill ("a document timestamped before the compromise stays valid
long term") and the two-instance drill ("valid long term from B's embedded evidence"), so CI's
real-PQC job was red from v9.334 through v9.337 and its two-instance job from v9.334 through
v9.335. The two-instance drill was restated in v9.336; this release restates the other.

- **The trust-lifecycle drill trusts the publisher for time.** Its documents were always
  timestamped by the publisher, a key distinct from the issuer signers; the drill now passes
  those anchors, and every long-term verdict it asserts holds again under the stricter rule.
- **Gated.** `check_ltv_timestamp_trust` (#186) now also requires the trust-lifecycle drill to
  decide long-term validity with timestamp anchors, so a verifier rule change that outruns a
  drill fails the gate locally rather than CI later.
- Every drill CI's real-PQC job runs was re-run locally before this release.

## v9.337 — 2026-09-09 (The roadmap cannot contradict itself)

The outside review's last finding: within a day of the previous drift fix, the roadmap's
"Do not have" paragraph still listed the exchange gateway, the registry, the auth broker,
document signing and the wire specification, all marked complete in the P8 table below it;
its check stamp read v9.317; and the gateway's done row opened with "IN PROGRESS". A class of
drift that returns that fast needs a gate, not a habit.

- **The roadmap agrees with itself.** The "Have" paragraph names the protocol layer; "Do not
  have" names what honestly remains there (an external team's docs-only integration, timestamp
  transparency anchoring as a design decision, a relying-party-signed authorization request,
  native wallet applications) and no longer the fabric that shipped; the gateway row reads done
  with its version trail.
- **`check_roadmap_consistent` (#189).** A subsystem whose row is done may not sit under "Do not
  have"; a done row may not open its notes with IN PROGRESS, NEXT or TODO; the invariant-check
  stamp must name the real count and a version within twenty minors of the tree; and with P8 done
  the "Have" paragraph must say so. Each rule has a detection case.

This closes the review-driven series (v9.333 to v9.337); every finding it made is now either a
released fix with its own invariant or a named design decision on the roadmap.

## v9.336 — 2026-09-09 (The auth broker binds the relying party's policy and hides the code)

The outside review found that the broker's step-up (`require_zk`) and enrollment requirement
arrived only in the holder-side authorize request, so nothing bound the authorization server
to what the relying party actually demands; and that the authorization code, signed but not
encrypted, let any bearer read the subject hash, the relying party, the context and the
assurance inside it.

- **The registered policy binds.** `RelyingParty` gains `require_zk`, `required_enrollment`
  (CHECK-constrained) and `required_context_id` (reversible migration 006). The authorize
  route applies the stored policy first; a request may add a requirement, never remove one;
  a context other than the registered one is `403 policy_violation`. `polaris rp-register`
  takes the policy flags and `polaris rp-policy` sets them later.
- **The code is opaque.** Fernet encryption under a key derived from the instance secret and a
  code-only salt replaces the decodable signed blob; a wrong key, a tamper, an expiry or a
  malformation are all "not ours". Tests prove the stored policy overrides the request in all
  three dimensions and that a code reveals nothing and opens under no other key.
- `check_broker_policy_bound` (#188) pins the columns, the migration, the route's three rules,
  the encryption, the tests, the CLI and the docs; the design record states what is not built
  (a relying-party-signed authorization request).
- **The two-instance drill catches up with v9.334.** Its document cases now state B's own
  embedded timestamp as authentic but not long-term valid, attach A's timestamp over HTTP to
  make the container valid with A trusted for time, and show the signing route refusing a
  `timestamp_agency_id` whose custody on the instance is the signer's own key (the route now
  guards that). v9.334 and v9.335 shipped without this drill re-run; their two-instance CI
  job was red for that reason and is green from here.

## v9.335 — 2026-09-09 (The QR decoder is resource-bounded)

The outside review found that the QR frame decoder, total on hostile input, inflated the
reassembled payload with no output limit: up to 9,999 frames of a highly compressible payload
could expand far beyond the transfer, a classic decompression bomb against the detached
verifier and the wallet.

- **Three bounds, each before the work it guards.** At most 9,999 frames (the index is four
  digits), at most 512 KiB of compressed payload, at most 2 MiB inflated; the decompressor runs
  with an output limit and a payload that would exceed it is refused at the limit, not inflated.
  A JSON recursion or memory error on the parsed payload is a clean refusal like any other.
- **Drilled with a real bomb.** 64 MiB of zeros compresses into some forty frames inside the
  compressed bound; the presentation drill shows it refused at the decompressed bound in well
  under a second, an incompressible 1 MiB payload refused at the compressed bound before hashing,
  and a flood of frames refused before parsing. `check_qr_resource_bounds` (#187) pins the
  bounds, forbids an unbounded inflate, and requires the drill and the wire spec's new
  normative bounds.

## v9.334 — 2026-09-09 (Long-term validation trusts the timestamp authority)

The same outside review found a hole in long-term validation: the verifier checked that a
document's timestamp was cryptographically authentic and bound to the signature, but never
that the timestamp authority was one the verifier trusts, and accepted the signer's own
timestamp. Anyone can mint a key and sign an authentic timestamp, and whoever holds a signing
key can backdate a timestamp with it; time evidence of that kind establishes nothing against
a stolen key.

- **Two anchor sets, and independence.** `verify_signed_document` takes `timestamp_anchors`,
  distinct from the signer anchors; `valid_long_term` now requires the timestamp authority
  trusted per that set AND its key distinct from the signing key. Without anchors the verdict
  reports the facts (`timestamp_authentic`, `timestamp_binds`) and claims nothing.
- **The signing route can timestamp elsewhere.** `timestamp_agency_id` names another
  federated agency of the instance to issue the container's timestamp; the default self-issued
  one is stated as convenience evidence in the API reference and the design record.
- **Drilled.** Untrusted, self-issued and anchorless time evidence each fail to claim long-term
  validity under real ML-DSA; the retirement and holder-authorized cases pass with the trusted
  second authority. `check_ltv_timestamp_trust` (#186) pins the verifier, the route, the drill
  and the wire spec, which now states the rule normatively.
- **What remains is recorded, not hidden.** A timestamp authority whose own key is compromised
  could still manufacture backdated timestamps; anchoring each timestamp's digest in an
  append-only log would expose that, at the cost of the authority retaining a digest and an
  instant per timestamp, which today it deliberately does not. That is roadmap item P8.5b, a
  design decision to take, not a change made quietly.

## v9.333 — 2026-09-09 (The gateway's trust is directional)

An outside review of v9.331 found that the exchange gateway and the receipt minter authorized a
requester by ANY valid attestation of its key in the context, whichever agency on the instance
had made it. On a multi-agency instance that let agency C's attestation of M authorize M at
agency B, which B never trusted: transitive in effect, against the federation principle.

- **The responder's own attestation, and nothing else.** `_exchange_attestation` now takes the
  responding agency and constrains `attesting_agency_id` to it; the receipt builder and the
  gateway both pass the agency that answers. The refusal says why (trust is directional).
  Proven by a three-authority database test (C attests M, B does not: M at B refused; B attests
  M: allowed, by B's attestation and no other; a revoked attestation authorizes nothing) and by
  the two-instance drill over HTTP under real ML-DSA (a third authority's attestation of X does
  not authorize X at B, 403; once B attests X, 200 via B). `check_exchange_trust_directional`
  (#185) pins the query, both call sites, the test and the drill.
- **A receipt is stated for what it is.** The same review noted the claim "the receipt alone
  proves the exchange occurred" was too strong: a receipt is signed by the responder alone, so
  it proves the responder's attestation; the requester-signed envelope beside it proves the
  requester's side, and `exchange_evidence` checks the pair. The verifier, the app, the check,
  the drill, the design record and the API reference now say exactly that.
- The roadmap's check stamp read v9.317; it is re-stamped with the count it states.

## v9.332 — 2026-09-09 (The front door restated)

What an outside observer sees, brought to the tree it describes, without a new claim.

- **The shareable surfaces say the same thing.** The repository description and the site's
  social description now say "issuer-unlinkable" as the README does (the unlinkability is
  issuer-side and scoped to the default verification mode); the citation's title drops
  "national", its abstract names the protocol layer, and its release date is current.
- **The README and the site know the protocol layer.** One paragraph on the institutional
  protocol (registry, trust list, exchange receipts, timestamp authority, document signing,
  the credential-bound login token, offline wallet presentations), ML-DSA-87 named beside
  the default wherever ML-DSA-65 was named alone, the compatibility suite in the run block,
  the protocol drills in the CI paragraph.
- **The measured numbers are re-measured.** The product suites pass 755 tests today (15 skip
  without optional backends) and the crypto witnesses 84 of 89 collected (5 need a PKCS#11
  token or a KMS key); the previous figures were a v9.215 and v9.237 measurement, and the
  "grown since, not shrunk" clause is gone because one figure did not grow. Stamped v9.332.
- Repository topics gained `post-quantum`, `postgresql`, `zero-knowledge`, `conformance-suite`.

## v9.331 — 2026-09-09 (The P8 sweep: every protocol artifact certified, the map redrawn)

The closing pass over the protocol arc. Nothing new is designed; everything built is now
certified everywhere it should be and described where a reader looks.

- **The exchange receipt and the mint statement in both SDKs.** Both were verified only by
  the detached verifier; `verify_signed_artifact` / `verifySignedArtifact` now cover them,
  the detached verifier gains `verify_exchange_mint` (the mint's `algorithm` rides unsigned,
  so the declared value or the key's length picks the parameter set), four new conformance
  vectors (`conformance/make_exchange_vectors.py`) bring the suite to 48 cases passing in all
  three verifiers, the fuzzer holds 14 signed types (1714 cases) under both parameter sets,
  and the compatibility suite maps both (the pinned v9.317 verifier agrees on the receipt,
  predates the mint). `check_typescript_sdk` and `check_conformance_suite` pin them.
- **The reference documents know the protocol layer.** SYSTEM-MAP gains the protocol-layer
  table (nine subsystems, each with its routes, verifier functions and design record) and
  the directories the tree had grown (`sdk/`, `conformance/`, `vectors/`, `attacks/`);
  ARCHITECTURE-OVERVIEW gains the protocol layer beside the pages; both SDK READMEs state
  what they verify and which parameter sets they accept; PRODUCTION-READINESS is restamped
  with P8's bearing on it (none); the conformance spec's count is current.

## v9.330 — 2026-09-09 (Protocol versioning, negotiation and cross-version compatibility, P8.8b)

Compatibility was a belief; now it is a rule with a proof on every push, and P8 is complete.

- **Major in the format string, minor in the registry.** A minor may add fields nested
  inside an existing signed structure or unsigned top-level fields a verifier ignores; it
  may never touch a top-level signed field or canonicalization. `_PROTOCOL_MINORS` records
  minors per format and the registry advertises every format as `major.minor` under
  `instance.protocol.versions` (the registry itself is at 1.3). A verifier never needs a
  minor.
- **Negotiation is a rule, not a handshake.** Reject an unknown major, accept any minor,
  never emit or send an unadvertised version (`registry_speaks` decides from a registry).
  The interactive routes answer a known format at another major with
  `400 unsupported_format_version`, the `supported` list and where versions are advertised,
  through one `_format_check`, before any nonce is spent or signature checked; drilled over
  HTTP across two instances.
- **Version 1 is frozen and the freeze is enforced.** `conformance/frozen/v1` holds the 44
  cases, the 41 vectors and the vendored v9.317 detached verifier under `SHA256SUMS`, which
  `check_protocol_versioning` (#184) and the suite recompute: a changed frozen file fails
  CI. Every case now carries `since`.
- **Both directions, every push.** `scripts/polaris-compat-suite.py`: the current detached
  verifier and both SDKs hold all 44 frozen cases; the pinned v9.317 verifier agrees on 26
  current cases, predates 16 artifact types, declines the 2 newer ML-DSA-87 cases
  fail-closed, and violates nothing. It runs in the pqc-real job and, TypeScript-only, in
  the SDK job. Wire spec section 6 carries the normative text; 184 checks.

## v9.329 — 2026-09-09 (Algorithm agility and migration, P8.8a)

Before this ship every signature was ML-DSA-65 by construction, in the signer, in every
signed body (written by hand before signing) and in every verifier. Now the key decides.

- **Two accepted parameter sets, one floor.** ML-DSA-65 (the default) and ML-DSA-87 are
  accepted by the signer, the detached verifier, both SDKs and the app's two witnesses;
  ML-DSA-44 and any unknown value are refused without guessing, and the acceptance
  predicate is total (the fuzzer found that a hostile dict in `algorithm` raised a
  `TypeError` at the new gate; it now fails closed).
- **The key decides, before signing.** A key file names its parameter set and the file
  custody driver signs under it (`POLARIS_PQC_ALGORITHM` picks the set for new keys). No
  signed body hardcodes its algorithm any more: `_signing_algorithm(agency_id)` reads it
  from the custodied key before signing, since `algorithm` is a signed field and the old
  code overwrote it from the signing result afterwards, which would have broken every
  signature under another set. The registry advertises the accepted set
  (`instance.protocol.algorithms`) and its own signing set; each listed key carries its
  algorithm; the app's two-witness checks verify under each statement's declared set.
- **Migration is a key-lifecycle event.** `key-register --algorithm ML-DSA-87` (the set is
  inferred from the key length when not given) makes the new key current; the old one is
  retired from an instant (P8.7b). A trust list signed by a retired key is refused.
- **Proven.** `--selftest` signs under ML-DSA-87 and refuses a genuine ML-DSA-44 pack; six
  new conformance vectors (`conformance/make_algorithm_vectors.py`: an ML-DSA-87 pack valid
  and tampered, a genuine ML-DSA-44 pack that MUST be refused, a status assertion under
  ML-DSA-87, a trust list recording a migration and the same list signed by the retired
  key) and both SDKs pass all 44 cases; the fuzzer runs under both sets in CI; the
  two-instance drill federates a mixed pair by default (A under ML-DSA-87, B under
  ML-DSA-65) and B reports each key under its real algorithm. Wire spec sections 2 and 6
  carry the normative rule; `check_algorithm_agility` (#183) pins it all; 183 checks.
- **Limits stated.** The PKCS#11 and KMS custody drivers remain ML-DSA-65 (a ceremony
  change, not a code change); SLH-DSA stays a registered row without a signer.

## v9.328 — 2026-09-09 (The trust-service lifecycle: compromise recovery, P8.7b)

Before this ship an authority had one key and every surface said "active". Now a key's whole
life is recorded, published, and decided at any instant.

- **The register.** `AuthorityKeyEvent` is append-only and one-way: `registered`, `retired`
  (an orderly rotation), `compromised` (untrusted from an instant that may predate the
  discovery); `AuthorityKeyCurrent` derives each key's status and instants. The CLI records
  events (`key-register` also makes the key the agency's current signing key). 35 tables (42
  migrated), reversible migration 005, C1 by trigger and privilege.
- **Honest surfaces.** The federation manifest's `anchors` list every key of the authority with
  its real status; the registry's `authorities` report the current key's real status and
  carry the register itself (`keys`, the same builder as the anchors and the trust list, so
  all three reflect one register; `registry_key_status` reads a key's status from it); an
  instance with no events reports its single key active, exactly as before. The register is
  indexed by hash: an ML-DSA-65 public key is 3904 hex characters, past a btree row's limit,
  which the short keys of the unit tests hid and the real keys of the two-instance drill
  exposed.
- **`polaris-trust-list/1` at `GET /api/v1/trust-list/<id>`.** Every key the instance knows --
  its own and its federated peers' -- with statuses and instants, signed by a key the list
  carries as ACTIVE for its publisher (an impostor cannot publish one; a publisher cannot sign
  one under a retired key). `key_status_at(list, key, instant)` decides status at an instant.
- **Compromise recovery, decided independently of the compromised party.** Given a trust list
  it trusts, `verify_cross_authority` rejects a credential under a compromised issuer key
  regardless of the issuer's own manifest, and `verify_signed_document` requires the signer key
  active at the evidence's instant per the list: a document timestamped before the compromise
  stays valid, one after does not. Without a list nothing changes shape.
- **Proven.** `scripts/polaris-trust-lifecycle-drill.py` (`pqc-real`, 15 cases: authentic /
  impostor / retired-key / tampered lists; status at instants across registration, retirement
  and a compromise predating its recording; accepted before, rejected after, re-issued key
  accepted; documents before and after; the fallback; hostile input). The two-instance drill
  records A's key compromised on B and watches the same relying party flip from accept to
  reject over HTTP with no change to A; B's registry reports the status. Fourteenth oracle
  pair; wire spec 3.15; three conformance vectors (valid, tampered, impostor) in BOTH SDKs,
  which apply the publisher rule; the fuzzer holds `verify_trust_list` total; a DB test
  proves the register append-only and one-way. `check_trust_lifecycle` (#182). 182 checks,
  114 routes.

## v9.327 — 2026-09-09 (The wallet protocol surface: offline presentation and QR framing, P8.6)

The wallet is a protocol, not a product; this ship makes the protocol complete on the
holder's side and says plainly what is not built.

- **`polaris-presentation/1`, decidable offline.** The unsigned wrapper a holder hands a
  verifier: the issuer-signed credential, a stapled issuer-signed status assertion (fetched
  when connected) so authorization needs no connectivity, an optional ZK proof, the context
  and disclosure level, and an opaque presentation code. `verify_presentation` decides it:
  credential authentic and issuer trusted; assertion authentic, fresh, ACTIVE and BOUND to this
  credential (same token, same signing key -- a stranger's or another credential's assertion
  buys nothing); the expected context. The presentation code is reported present or absent
  and never interpreted: a duress presentation is indistinguishable at the verifier.
- **`polaris-qr/1`, transfer without a key.** A credential is about ten kilobytes of JSON,
  several QR symbols' worth; the presentation is compressed, base64url-encoded and split into
  frames each naming the SHA3-256 of the whole payload, reassembled in any order and refused
  before parsing when mixed, missing, duplicated inconsistently, or altered. Transport
  integrity only, which is the point. The wallet's `present` gains `--qr --frame-bytes`,
  `--status-assertion`, `--zk-proof`, `--context`, `--disclosure-level`; the detached
  verifier's CLI gains `--presentation` and `--qr-frames`.
- **Boundaries, recorded.** The WebAuthn browser bridge waits on a holder-key binding the
  issuer-centric model deliberately lacks (which is why signing is notarial and login is by
  possession); native clients and card middleware are product engineering, not a reference
  implementation's. `docs/design/wallet-protocol.md` says so, and the check requires it to.
- **Proven.** `scripts/polaris-presentation-drill.py` (in `pqc-real`, 16 cases): usable offline;
  frames under budget, any order; missing, mixed and altered frames refused; unbound, expired,
  revoked and stranger-signed assertions refused; no assertion not decidable; wrong context;
  the code never interpreted; the full wallet round trip (`enroll`, `present --qr
  --status-assertion`, decide with `--qr-frames`); hostile input. The fuzzer holds the verifier
  and the frame decoder total. Wire spec section 3.14; the registry advertises both formats.
  `check_wallet_presentation` (#181). 181 checks.

## v9.326 — 2026-09-09 (The auth broker: log in with a credential, no login record, P8.4)

The one constitutional question of the P8 arc, answered in the open. The relying-party layer
was pinned "verify-only, never a login product"; an auth broker is authentication. The scope
bound is widened deliberately -- at the schema, to exactly `verify | authenticate | verify
authenticate` -- and every guard that made the old wording true is kept and pinned: identity
never becomes a login RECORD.

- **Authorization code + PKCE, the protocol core.** `POST /api/v1/auth/authorize`: the holder
  presents its credential by possession (as for a status assertion) with the relying party's
  client id, nonce and S256 challenge, the context, the disclosure level and, for step-up, a ZK
  membership proof verified and nonce-consumed through the same path as `/api/zk/verify`;
  the instance answers with a signed, stateless, 60-second code and writes nothing.
  `POST /api/v1/auth/token`: the relying party exchanges the code with its client credentials
  and the PKCE verifier; the code's hash is consumed in the new append-only `AuthCodeConsumed`
  register (single use across workers; the register holds no subject and no relying party) and
  the instance mints a `polaris-id-token/1` signed by the holder's ISSUING AGENCY: `iss, sub,
  aud, nonce, context_id, disclosure_level, acr, enrollment, auth_time, iat, exp`. The subject
  is the credential hash -- stable per credential, correlatable across relying parties by
  design, never a person. No claim beyond the vocabulary. Duress is served identically and
  recorded silently. The wallet's new `login` command drives the authorize step.
- **Shared machinery, honestly rewritten.** Client-credential authentication and ZK
  verification are now shared functions; `rp_auth` treats scope as a set and issues codes
  under a salt distinct from access tokens; `rp-register --scope`; the schema, migration,
  CLI and check comments say "never a login record". `check_relying_party_api` pins the widened
  set exactly, so a fourth scope value is a constitutional change; the AC-6 adversary now
  proves a verify bearer cannot reach the broker's token endpoint.
- **Proven.** The two-instance drill runs the whole flow over HTTP with B's real-signed
  credential and verifies the ID token offline under B's key, then refuses replay, a wrong
  verifier, a verify-only relying party, a wrong presentation and an unmet step-up, and shows
  the register holding exactly the consumed hashes. `scripts/polaris-auth-broker-drill.py`
  (`pqc-real`, 11 cases) drives the relying party's contract; DB tests cover the flow under
  the placeholder profile and duress indistinguishability (identical response, one recorded
  event). Thirteenth oracle pair; wire spec 3.13; two conformance vectors in BOTH SDKs, each
  of which gained an ID-token helper; the fuzzer holds `verify_id_token` total.
  `check_auth_broker` (#180). 180 checks, 113 routes, 34 tables (41 migrated).

## v9.325 — 2026-09-09 (Document signing with long-term validation, P8.5)

Polaris signed identity artifacts; now it signs anything, and the signature stays valid after
the key that made it is gone.

- **`polaris-signed-document/1`.** A digest-bound, portable container: the document's SHA3-256
  (never the document), a media type, a name, a purpose and the instant, signed under an
  agency's registered ML-DSA-65 key. Two signers: the institution itself
  (`POST /api/v1/sign/<id>`, operator path), or -- on behalf of a holder who proved possession
  of an issued, ACTIVE credential exactly as a status assertion requires -- the holder's issuing
  authority (`/sign/<id>/holder`, no session), which records the holder as
  `on_behalf_of.credential_hash` (the SHA3-256 of the token value, the same leaf a revocation
  feed lists) and never the token. The wallet's new `sign` command hashes the file locally and
  drives that route: the document never leaves the wallet. A Polaris-native container, no
  foreign formats.
- **Long-term validation.** At signing the container gains evidence fixed at that instant,
  outside the signed statement: this instance's timestamp over the statement AND the signature
  (so the signature provably existed then), and the signer's manifest, epoch checkpoint and
  revocation feed as of then. `verify_signed_document` decides `valid_long_term` at that
  instant -- timestamp authentic and binding the signature material; manifest authentic and
  fresh at the instant and listing the key active; for a holder-authorized signature, the feed
  at the instant not listing the credential -- so a container timestamped while the key was
  active stays valid after the key is retired, and one whose evidence shows the key already
  retired does not. `attach_ltv` adds a second authority's timestamp for time independent of
  the signer. The possession proof, the manifest builder and the timestamp builder are now
  shared functions.
- **Proven.** `scripts/polaris-document-signing-drill.py` (in `pqc-real`, 15 cases): authentic,
  binds its bytes and nothing else, valid long term; a re-signed container is not covered by
  the old evidence; key retirement in both directions; holder-authorized with an unrevoked and
  a revoked credential; no evidence; tampered; hostile input. The two-instance drill gives one
  of B's credentials a real signature, has the holder sign through B by possession, verifies
  the container offline with B's embedded evidence, refuses a wrong presentation, and signs
  again through the wallet. Twelfth oracle pair; wire spec 3.12; two conformance vectors in
  BOTH SDKs; the fuzzer holds `verify_signed_document` total; a DB test covers the holder
  route. `check_document_signing` (#179). 179 checks, 111 routes.

## v9.324 — 2026-09-09 (The exchange gateway: institutions exchange through Polaris trust, P8.2d)

The flagship of the exchange fabric, and the completion of P8.2. Two institutions exchange a
request through Polaris trust, with evidence and without retention.

- **`POST /api/v1/exchange/<id>`.** A requesting institution signs a `polaris-exchange-request/1`
  envelope under its registered ML-DSA-65 key -- the SHA3-256 of the body's canonical JSON, the
  target agency and service kind, the context, a never-reused nonce, the time -- and posts it
  with the body to the target's instance. The order of operations is the security argument, and
  `check_exchange_gateway` pins it: real ML-DSA required; envelope bound to this target and to
  the body; the kind one this instance forwards to; fresh; requester authenticated by a key the
  instance already KNOWS and verified two-witness; **authorized through the in-context trust
  graph before anything is forwarded**; nonce consumed in the append-only replay register
  `ExchangeNonce` (409 on replay, any worker; a failed upstream still consumes it, so a retry
  needs a new nonce); forwarded only to an operator-configured upstream
  (`POLARIS_EXCHANGE_UPSTREAMS`, a JSON map of kind to URL -- a URL never comes from a request);
  the response returned with a receipt carrying the envelope's signed time as `occurred_at`,
  its hash logged. The receipt IS the response envelope. No body is ever persisted or logged.
- **Evidence without retention, completed.** (envelope, receipt) is the evidence of one
  exchange: `verify_exchange_request` proves the requester's signed intent (authentic, expected
  requester, authorized in-context, bound to a body it holds), `verify_exchange_receipt` the
  responder's account, and `exchange_evidence` that they agree on requester, context, hash and
  instant -- all offline, with no access to either body.
- **Proven across two instances.** The drill runs an echo upstream behind B, launches B with it
  configured, and from A: a mediated exchange whose receipt is B-signed, requester-authorized
  and binds both bodies; the envelope verified offline; one consistent chain; the receipt in
  B's log; the same envelope replayed (409); a new nonce (200); an unknown requester (401); an
  unbound body (400); a tampered signature (401); an unknown kind (404); a stale envelope
  (401); the registry advertising the gateway and its kinds; no body in B's process log; the
  replay register holding exactly the delivered nonces. Eleventh oracle pair; wire spec 3.11;
  two conformance vectors in BOTH SDKs; the fuzzer holds `verify_exchange_request` total; a
  DB test proves the gateway fails closed; C1 tests cover `ExchangeNonce`. 178 checks, 109
  routes, 33 tables (40 migrated). **P8.2 complete.**

## v9.323 — 2026-09-09 (The signed registry: discovery over the authority layer, P8.3)

A consumer should learn what an instance offers and trusts from the instance itself, signed,
and not from configuration handed over out of band.

- **`GET /api/v1/registry/<id>` and `polaris-registry/1`.** One machine-readable artifact: the
  protocol formats and algorithms the instance speaks (the format list is pinned to the wire
  spec's by `check_registry`, so it can neither advertise a format the spec lacks nor omit one
  it defines), its services with path templates and how each authenticates, its transparency
  logs, the federated authorities it knows with their keys, the verification contexts and the
  proof each requires, the in-context trust graph, and the relying parties it serves (name and
  scope only). Every fact is a view over Athena; the registry adds no truth of its own.
  Institutional data, never personal.
- **Signed by a publisher that must list itself.** `verify_registry` requires the signing key to
  be the active key the registry lists for its own publisher, so a stranger cannot publish a
  registry in an authority's name; freshness and anchor trust as everywhere. Then discovery:
  `registry_service`, `registry_authority`, `registry_trusts` (non-transitive, in-context).
- **Discovery proven, not described.** The two-instance drill fetches B's registry, verifies it
  offline under B's key, reads the timestamp service's path out of it and calls THAT, reads B's
  attestation of A from the trust graph, and after B revokes the attestation sees the
  re-fetched registry drop it. `scripts/polaris-registry-drill.py` (in `pqc-real`) drives
  authentic/discovered/impostor/tampered/expired/untrusted/hostile. Tenth oracle pair; wire
  spec section 3.10; three conformance vectors (valid, tampered, impostor) verified by BOTH
  SDKs, which now apply the publisher self-consistency rule; the fuzzer holds `verify_registry`
  total. `check_registry` (#177). 177 checks, 108 routes.

## v9.322 — 2026-09-09 (The receipt set is a transparency log, P8.2c)

Evidence without retention had a gap: an instance that keeps nothing can later deny a
receipt existed, and no one can see how many receipts an institution minted. Now the SET of
receipts is transparent while every receipt stays in the hands of its parties.

- **`ExchangeReceiptLog`.** At mint time only the receipt's SHA3-256 -- a commitment that
  reveals nothing -- is appended (`seq, receipt_hash, minted_at`; `chk_receipt_log_hash` admits
  nothing but a 64-hex digest). Strictly append-only by trigger (`trg_receipt_log_append_only`,
  no GUC carve-out: a transparency log that can be rewritten is not one) and by privilege
  (`polaris_app` may INSERT, never UPDATE or DELETE; the C1 privilege-boundary check and tests
  cover it). Canonical in `01_schema.sql`, reversible migration for deployed databases. 32
  tables (39 migrated).
- **A second RFC-6962 log, same machinery.** `/api/v1/transparency/receipts/{sth,consistency,
  proof,entries}` publish the sequence as `log_id polaris-exchange-receipt-log`; the anchor
  log's routes are unchanged and both now share one set of helpers. Every minted receipt
  carries its `log_index`; `GET /api/v1/exchange-receipt/inclusion/<hash>` returns the
  inclusion proof plus the current signed head, and the detached verifier's
  `verify_receipt_inclusion` proves offline that a held receipt is in the log (entry matches,
  proof reconstructs the head, head authentic and signed by the expected log, proof and head
  describe the same tree). The monitor and witness daemons watch the receipt log with
  `--log receipts`, so a dropped or rewritten receipt is a fork they alert on.
- **Proven.** The two-instance drill mints, fetches inclusion evidence, verifies it offline
  under B's key, mints again and proves the earlier head is a prefix of the later (append-only,
  offline), runs the independent monitor against the receipt log before and after, and shows a
  fabricated hash is not in the log and a tampered proof fails. DB tests cover the hash-only
  CHECK, the strict trigger, the privilege boundary, and the public surface.
  `check_receipt_transparency` (#176). 176 checks, 107 routes.

## v9.321 — 2026-09-09 (The timestamp authority: time evidence for anything, P8.7a)

The first piece of the trust-service lifecycle, and the time primitive document signing will
build on.

- **`POST /api/v1/timestamp/<id>` and `polaris-timestamp/1`.** An authority binds an arbitrary
  SHA3-256 digest to an instant under its registered ML-DSA-65 key. The route accepts a digest,
  never content, so the authority learns nothing about what it timestamps, and it keeps no
  per-request record (a timestamp authority that logs every request is a store of who
  timestamped what, when); the requester's nonce is echoed in the signed statement so it can tie
  the response to its request. RFC-3161-class, in Polaris's canonical-JSON discipline.
- **Verified offline, and bound to the data.** `verify_timestamp` confirms the signature (two
  witnesses) and that the instant parses; `timestamp_binds(ts, data)` checks the binding against
  data the verifier holds. With anchor keys it reports whether the authority is trusted. A
  timestamp records a past instant and carries no freshness window.
- **Independent time evidence.** A receipt's `occurred_at` is the responder's word. Timestamp the
  receipt's canonical bytes at a second authority and a third party has time from a key other
  than the responder's; the drill does exactly this, alongside tampered signature / swapped
  digest / rewritten instant / untrusted authority / hostile input.
- **Held to the full machinery.** The ninth pair in the canonical-equivalence oracle; wire spec
  section 3.9; two published conformance vectors verified by BOTH SDKs (`artifact: timestamp`);
  the metamorphic fuzzer holds `verify_timestamp` total; `scripts/polaris-timestamp-drill.py` in
  `pqc-real`, and the two-instance federation drill exercises the route over HTTP (mint, verify offline under
  the instance's key, bind, refuse a non-digest); `check_timestamp_authority` (#175). `_exchange_responder` is now `_federated_agency`,
  shared by every route that signs as an agency. 175 checks, 102 routes.

## v9.320 — 2026-09-09 (Service-to-service minting: the signature is the institution, P8.2b)

A gateway is worthless if only an operator can mint. The responder's own service now mints
an exchange receipt with no session.

- **`POST /api/v1/exchange-receipt/<id>/signed`.** The caller signs a `polaris-exchange-mint/1`
  statement (the receipt's hash-only fields plus its own agency id and the time) under the
  responder agency's REGISTERED ML-DSA-65 key; the instance rebuilds the canonical bytes and
  verifies the signature two-witness under that key. Post-quantum institutional auth with no
  shared secret, no schema change, and no nonce store: the statement is bound to the addressed
  agency and a 300-second freshness window, and the signed `occurred_at` is carried into the
  receipt unchanged, so a captured request can only re-mint an identical receipt, never re-time
  the exchange. Without real ML-DSA-65 the route refuses (`503`): a placeholder signature is not
  authentication. Chosen over an OAuth bearer deliberately -- an institution in the fabric
  already holds a key the trust graph knows, and this is the signed-envelope pattern the
  mediating gateway (P8.2d) generalizes.
- **Held to the same machinery.** The client-side builder `_exchange_mint_canonical` lives in the
  detached verifier and the canonical-equivalence oracle holds it byte-equal to the instance's
  `_exchange_mint_statement` (the oracle's eighth pair, this one client-built and
  instance-verified); wire spec section 3.8.1; the two-instance federation drill now mints over
  HTTP with no session under real ML-DSA and drives accept / wrong key / tampered signature /
  stale time / unattested requester; a DB-backed unit test proves the fail-closed refusal.
  `check_exchange_mint_signed_auth` (#174) pins all of it. 174 checks, 101 routes.
- The operator path (login + CSRF) is unchanged; the mint core is factored so both paths share
  one validation and one signer.

## v9.319 — 2026-09-09 (P8 on its own terms: a positioning invariant and the build plan)

Two things, both about how Polaris describes itself and what it builds next.

- **A positioning invariant.** The tree now describes the CLASS of any system Polaris relates
  itself to, never a named country or its digital-state products: "a federated national eID",
  "an exchange-fabric-class system", "an evidentiary message log". The P8 arc was informed by a
  gap analysis against a mature national digital-identity ecosystem, and Polaris must stand on
  its own terms rather than read as a derivative -- the same discipline as the rule against
  naming external models. Every prior mention (the roadmap, a design record, three code
  comments, the README comparison row, the paper's prior-art section, and this changelog) is
  restated as the class. `check_no_named_reference_systems` (#173) scans every text file in the
  tree and fails CI on the first named reference, with the short acronyms matched as whole words
  and the spellings word-bounded so ordinary words ("sixteen", "criteria") cannot trip it.
  Residue in git history is fine; the working tree is clean.
- **The P8 build plan, fixed.** ROADMAP.md's P8 section now carries the order and its
  dependencies: P8.2b/c (service-to-service auth and a transparency anchor for the receipt) ->
  P8.7a (a timestamp authority, which signing needs and which gives every receipt independent
  time evidence) -> P8.3 (the signed registry the gateway routes through) -> P8.2d (the mediating
  gateway, the flagship) -> P8.5 (document signing) -> P8.4 (the auth broker's protocol core) ->
  P8.6 (the wallet PROTOCOL surface) -> P8.7b (trust-service lifecycle: trust list, compromise
  recovery, algorithm migration) -> P8.8 (versioning and cross-version compatibility). Two scope
  decisions are recorded: the wallet ships as a protocol the detached verifier checks, not as
  native clients; the operator control-plane console is wrap that stays behind the engine. P8.7
  and P8.8 are new rows; P8.6 is rescoped. 173 checks.

## v9.318 — 2026-09-09 (The local gate type-checks the TypeScript SDK)

v9.316 shipped with the `sdk-typescript` CI job red: a type-only regression the local pre-ship
gate could not see. The gate now sees it.

- **`polaris-preflight.sh` runs CI's `sdk-typescript` steps locally.** When node is present, the
  gate now runs `tsc --noEmit`, `node --test`, and the conformance suite against the TypeScript
  verifier -- the same offline steps CI runs -- and fails on any of them. It is guarded on node
  availability, so a node-less environment still runs the rest of the gate (an honest SKIP line,
  never a false pass).
- **Why.** `tsc --noEmit` is a TYPE gate the Python check layer cannot see. v9.315's
  `verifyCrossAuthority` fed an anchor-set element inferred `unknown` into a `Set<string>`
  membership test; it passed `polaris-checks`, `node --test`, and every conformance case, yet
  failed the CI type-check and shipped red at v9.316. That class of failure now surfaces at the
  local gate instead of in CI.
- **Pinned.** `check_preflight_typechecks_ts_sdk` (#172) asserts preflight runs `tsc --noEmit`
  against `sdk/typescript`, guarded on node, so the gate step cannot silently regress. 172 checks.

## v9.317 — 2026-09-09 (The exchange receipt: evidence without retention, P8.2)

The first primitive of the P8 exchange fabric, and its defining idea: a way to prove an
institutional exchange occurred and was authorized without becoming the message log a
surveillance system would keep.

- **`polaris-exchange-receipt/1`.** When a responder serves an authenticated, authorized
  request, it signs a receipt committing to the `SHA3-256` of the request and of the response,
  the parties, the context, the time, and which attestation authorized the requester. The
  bodies never appear. Minted at `POST /api/v1/exchange-receipt/<id>`, which accepts ONLY the
  hashes (each a 64-char SHA3-256 hex digest) and mints only if the requester is authorized (an
  `AgencyTrustAttestation` attests its key in the context), else 403. The app cannot retain a
  body it is never given.
- **Evidence without retention.** `verify_exchange_receipt` (detached, standalone) proves,
  from the receipt alone, that the exchange occurred (the responder's ML-DSA-65 signature) and
  that the requester was authorized (a trusted manifest attests its key in-context, the same
  non-transitive trust as a foreign credential) -- with no access to the payload. A party that
  holds a body may confirm the commitment binds (`request_hash == SHA3-256(request)`); a party
  that does not still gets the proof. This is the anti-surveillance inversion of an evidentiary
  message log.
- **Pinned and proven.** The receipt is in the normative wire spec (section 3.8) and the
  canonical-equivalence oracle (the seventh app-signed type, app and verifier byte-identical);
  `scripts/polaris-exchange-receipt-drill.py` drives the accept/reject/without-payload/binding
  matrix under real ML-DSA every release; `check_exchange_receipt` (#171) pins the whole path.
  171 checks, 100 routes.
- **Also greens `sdk-typescript`.** The v9.315 `verifyCrossAuthority` addition left a `tsc --noEmit` error that turned the `sdk-typescript` CI job red at v9.315-v9.316: an anchor-set element inferred as `unknown` was passed to a `Set<string>` membership test. Pinned that set's element type to `string`. The SDK's unit tests and all 24 conformance cases were already green; only the type-check gate failed.
- P8.2 continues: transparency-anchoring the receipt set, service-to-service mint auth, and the
  mediation layer that produces a receipt per exchange.

## v9.316 — 2026-09-09 (P8.1 complete: the federation trust decision certified)

The last piece of P8.1. The conformance suite now certifies the composite federation trust
decision, so an implementation importing no Polaris code is certified against the FULL
protocol -- every signed artifact AND the cross-authority decision -- in both Python and
TypeScript.

- **`verify_cross_authority` (Python) / `verifyCrossAuthority` (TypeScript).** Given a foreign
  credential's authenticity pack, the federation manifests a relying party trusts, a trusted
  anchor set, and a presented context (and an optional revocation feed), each SDK decides
  accept or reject offline: the pack must be authentic, some trusted manifest (authentic,
  fresh, signed by a trusted anchor) must attest the credential's key in that context
  non-transitively, and, with a feed supplied, the credential must not be revoked (the feed
  authentic, fresh, and bound to the issuer key).
- **A new multi-input case shape.** `artifact: cross-authority` carries a pack, a list of
  manifests, a trusted-anchor set (`"manifest"` resolves to the supplied manifests' own
  anchors), a context, and an optional revocation feed. Four cases (accept, untrusted issuer,
  wrong context, revoked), verified against committed vectors (a credential from authority A, a
  manifest from authority B attesting A, and A's revocation feed). Both SDKs pass all
  twenty-four conformance cases.
- **Pinned.** `check_conformance_suite` and `check_typescript_sdk` now require both SDKs to
  decide the trust decision and the cases to certify it. P8.1 is complete: the docs-only
  integration path the P3 exit gate needs now exists in two languages.

## v9.315 — 2026-09-09 (All seven signed artifacts certified, P8.1b)

Every app-signed artifact's authenticity is now certified by the conformance suite in both
SDKs, not just the pack and the status assertion.

- **One generic verifier for the signed statements.** `verify_signed_artifact` (Python) and
  `verifySignedArtifact` (TypeScript) verify the epoch checkpoint, revocation feed, federation
  manifest, status bundle, and transparency STH through one path: look up the signed-field list
  for the artifact's `format`, verify the ML-DSA-65 signature over `SHA3-256(canonical)`, check
  freshness for a windowed artifact, and check the artifact's own commitment (the feed's
  `revoked_root`, the bundle's `members_root`) or self-consistency (the manifest signed by one of
  its own active anchors).
- **The TypeScript proof gets stronger.** These artifacts carry NESTED values (an epoch object,
  an anchors array, a members list), which `JSON.stringify` does not sort recursively. The TS SDK
  now builds the canonical JSON with a recursive sorted-key serializer, and an independent TS
  verifier accepting a Python-signed manifest, checkpoint, feed, and bundle confirms it is
  byte-identical to Python's `json.dumps(sort_keys=True)`.
- **Certified end to end.** Twelve published vectors under `conformance/vectors/` (a valid and a
  tampered one per artifact), and both SDKs pass all twenty conformance cases. `check_conformance_suite`
  and `check_typescript_sdk` now require the generic verifier and that the cases certify at least
  six distinct artifact types.
- Remaining for P8.1: the composite federation trust decision (a foreign credential accepted
  across authorities), which is a multi-input case rather than a single artifact.

## v9.314 — 2026-09-09 (Conformance beyond the pack, P8.1b)

The conformance suite and both SDKs certified exactly one signed artifact, the authenticity
pack. This generalizes the harness and certifies a second, the status assertion, so an
implementation importing no Polaris code is held to more of the protocol.

- **The harness is now typed.** A conformance case names the `artifact` it is about (default
  `authenticity-pack`), and the runner checks every key the case's expected verdict names, so a
  new artifact is new cases and a verifier entry point, not new plumbing. Backward compatible:
  the existing pack cases are unchanged.
- **The status assertion is certified end to end.** `verify_status_assertion` is now a
  standalone function in the Python SDK and `verifyStatusAssertion` in the TypeScript SDK: each
  recomputes the canonical statement of `{format, token_value, status, issued_at, expires_at}`,
  verifies the ML-DSA-65 signature over its SHA3-256, and reports authentic / fresh / active
  (with `now` pinned by the case). Three published vectors (a genuine ACTIVE assertion, a genuine
  one evaluated past its window, and a tampered one) live under `conformance/vectors/`, and both
  SDKs pass all ten cases. The independent TypeScript verifier accepting a status assertion the
  Python reference signed is the proof that the wire spec's canonical construction is
  language-agnostic.
- **Pinned.** `check_conformance_suite` and `check_typescript_sdk` now require both SDKs to verify
  the status assertion and the cases to certify it. Remaining (P8.1b continues): the other five
  app-signed artifacts and the federation trust decision.

## v9.313 — 2026-09-08 (Normative wire specification, P8.1)

The first step of the P8 exchange fabric: a normative wire specification so an implementation
importing no Polaris code can produce and verify the protocol's artifacts and interoperate as a
first-class peer. This is the P3 exit gate ("an external team integrates docs-only").

- **The spec.** `docs/reference/WIRE-SPEC.md` (RFC-2119) specifies the signature envelope and the
  canonical-signing discipline (SHA3-256 over sorted-keys compact JSON), then each of the seven
  app-signed artifacts with its exact signed-field list, canonical construction, and verification
  MUSTs; the authenticity pack's special construction (a signature over `SHA3-256(token_value)`,
  not a JSON statement); the federation trust decision (non-transitive, in-context, revocation
  fail-closed); the three transparency-infrastructure artifacts; and the `format /N` versioning
  and algorithm-agility rule. The scattered per-artifact design notes are lifted into one
  authoritative document.
- **Pinned to the signer.** `check_wire_spec_matches_code` (#170) fails CI when a format string or
  a signed-field list in the spec diverges from the app's canonical builders, so a from-spec
  implementation cannot silently drift from the code. It also closes real pinning gaps: the
  canonical-equivalence oracle statically covered five types and omitted the status bundle, and
  covered the pack and the transparency-infra types with neither mechanism; the spec check
  requires every protocol format string.
- **A latent hole, closed.** `_signed_statement_keys` returned nothing on the multi-line
  `for k in (...)` builders, so the oracle's static key-list comparison was silently vacuous; its
  regex now matches the real code, and the static check genuinely compares the ordered key lists
  again (both `check_canonical_equivalence` and the new spec check).
- Extending the conformance cases and the SDKs to certify all artifacts (not just the pack) is
  P8.1b. 170 checks.

## v9.312 — 2026-09-08 (Offline cross-authority epoch-bound ZK, P3.2d)

A holder proves, in zero knowledge, that its credential is included in an issuing authority's
epoch tree, and a relying party that trusts that authority through the federation graph accepts
it OFFLINE, learning nothing about which credential. It composes two things that already
existed, with zero circuit changes.

- **The composition.** The Plonky2 circuit already binds a proof to the epoch's Merkle root (a
  public input), which is exactly `TokenStateEpoch.merkle_root`; and that root already travels
  the federation signed in the epoch checkpoint. `verify_cross_authority_zk` in
  `scripts/polaris-verify.py` joins them: (1) TRUST the foreign checkpoint (authentic, fresh,
  and attested in-context by a trusted authority, non-transitive, the hardened
  `verify_cross_authority` path) to obtain the trusted epoch root; (2) BIND the proof's public
  inputs to that root, epoch number, and context (and a challenge nonce, if issued); (3) verify
  the Plonky2 proof.
- **Why a binary, still offline.** Checking a Plonky2 FRI proof is the one thing the standalone
  pure-Python verifier cannot do, so it shells to the `polaris-zk` binary as a LOCAL subprocess.
  There is no network, so the decision stays offline. If the binary is absent the decision
  ABSTAINS (trust and binding established, proof unverifiable here), never a false accept, and
  the verifier stays import-standalone (a subprocess is not an import). The verdict carries no
  credential.
- **What runs.** Because generating a proof needs the prover and signing a checkpoint needs
  liboqs, the artifacts are generated once and committed as a fixture
  (`polaris_zk/fixtures/cross-authority-zk.json`), like the ML-DSA `vectors/`.
  `scripts/polaris-cross-authority-zk-drill.py` verifies it every release in the CI test job
  (which has the binary and the cryptography ML-DSA witness): accept the genuine foreign proof;
  reject a wrong root, a forged checkpoint, an untrusted issuer, a wrong context, and a tampered
  proof; abstain with no binary. A `--zk-proof` CLI mode runs the decision from the command
  line; `check_cross_authority_zk` (#169) pins the path; the metamorphic fuzzer holds the new
  decision total on hostile input. Spec: [cross-authority-zk.md](docs/design/cross-authority-zk.md).
  169 checks.

## v9.311 — 2026-09-08 (ROADMAP honesty pass, and the P8 exchange-fabric arc)

Docs only. The ROADMAP "Where we are" inventory had drifted: fresh agents use it to choose
what to build, and it still listed shipped work as missing.

- **Inventory corrected.** HA automation, monthly partitioning, a read replica, a holder
  wallet, the versioned relying-party API with Python and TypeScript SDKs and a conformance
  suite, offline verification, the inter-authority federation protocol proven across two
  independent instances, the transparency log with witnesses and external-ledger publication,
  and the fuzzer-hardened detached verifier all move from "Do not have" to "Have". The header
  and the invariant-count stamp are restamped current.
- **Phase P8 added: the exchange fabric, the Polaris way.** The largest code-level gap between
  Polaris and a mature national digital-identity ecosystem is not more identity crypto; it is the general
  service-to-service exchange layer around the identity core. P8 records it, built as the
  anti-surveillance INVERSION of an evidentiary message log: an exchange is provable to a third party WITHOUT
  retaining the payload (a signed receipt plus a transparency commitment, not a logged message
  body). Six items ordered by leverage: P8.1 a normative wire spec plus conformance for
  independent, non-Polaris implementations (the keystone, and exactly the standing P3 exit
  gate); P8.2 the evidence-without-retention gateway (the flagship); P8.3 a service-and-authority
  registry; P8.4 an auth/SSO broker; P8.5 general document signing; P8.6 a wallet client
  platform. Buildable now, extends P3, not gated on the P4-P7 deployment phases; every primitive
  it composes already ships.

## v9.310 — 2026-09-08 (Federation status bundle: the aggregator holds no member key)

The P3.2c status-bundle endpoint modeled federation aggregation wrongly. It built each
partner's feed by signing with that partner's key, which only works when one instance holds
every hosted agency's private key. A real aggregator has no partner's key; making it look
like it does inverts the whole point of the design, which is that the aggregator is untrusted.

- **The fix.** `GET /api/v1/federation-status-bundle/<id>` now mirrors exactly the publishing
  authority's OWN feed and checkpoint, under the publisher's own signature, and mirrors no one
  else. It never signs a partner's feed. `StatusBundleTests` pins the self-only behavior.
- **The correct aggregation, proven across independent instances.** A federation hub aggregates
  many authorities by FETCHING each one's already-signed feed and checkpoint from that
  authority's own endpoint, VERIFYING them against the authority's public key, embedding them
  VERBATIM, and signing only the outer envelope with its own key. The two-instance federation
  drill now does exactly this over real HTTP under real ML-DSA: instance B (holding no key of
  A's) fetches A's signed feed, bundles it, and a relying party accepts A's active credential
  and rejects a revoked one through the single bundle, with an omitted authority fail-closed.
- **Pinned.** `check_federation_status_bundle` now requires the cross-instance aggregation to
  run every release. The spec ([federation-status-bundle.md](docs/design/federation-status-bundle.md))
  gains a section on how the aggregator obtains member feeds (fetch, verify, preserve, never
  re-sign). The verify side was already correct; this only corrects how feeds are produced.

## v9.309 — 2026-09-08 (Metamorphic verifier fuzzer, and the hardening it drove)

The detached verifier grew a decision function per signed type across the federation and
transparency work, plus two composed decisions. The per-type drills test hand-picked cases.
This adds a fuzzer that generalizes them into one property, and it found real gaps.

- **The property.** For every signed type (authenticity pack, manifest, epoch checkpoint,
  revocation feed, status assertion, transparency STH, status bundle) and both composed
  decisions, the fuzzer builds a genuine, real-ML-DSA object, confirms it is accepted, then a
  deterministic battery (signature and key bit-flips, mutation of each signature-bound field,
  non-hex and dropped fields, adversarial values, and cross-type confusion) must ALL be
  rejected FAIL-CLOSED, with no exception. 670 cases, one fixed seed so a break reproduces.
- **What it found.** The verifier is fed hostile input by design, and it crashed on some of
  it: a non-dict object, or a field of the wrong type (a `revoked_root_hex` that is an int,
  a `revoked_leaves` that is not a list, `anchors` or `members` that are not lists), raised an
  `AttributeError`/`TypeError` instead of returning a clean reject verdict. A security verifier
  must be **total** on hostile input.
- **The hardening.** Each `verify_*` now coerces a non-dict object to a rejectable empty one,
  and the commitment and membership helpers (`revoked_root`, `bundle_members_root`,
  `is_revoked`) and the manifest anchor/attestation handling coerce wrong-typed fields instead
  of raising. Behavior on genuine, well-formed input is unchanged: the canonical builders are
  untouched, and every drill, the canonical-equivalence oracle, and the verifier self-test
  stay green.
- **It runs every release.** `scripts/polaris-verifier-fuzz.py` runs under real ML-DSA in the
  pqc-real CI job; `check_verifier_fuzz` (#168) pins the coverage, the mutation classes, the
  both-failure-modes assertion, the fixed seed, the CI wiring, and the verifier's standalone
  constraint, with a detection test. 168 checks.

## v9.308 — 2026-09-08 (Aggregate mirrored status feed, P3.2c)

P3.2b let a relying party check a foreign credential's non-revocation against the issuer's own
signed feed, offline. That is one fetch per authority. P3.2c aggregates them: a publisher mirrors
many authorities' signed revocation feeds and epoch checkpoints into ONE short-lived, signed
status bundle, so a relying party fetches it once and checks any member's credential offline. The
point of the design is that the publisher is untrusted for correctness.

- **The mirror.** `polaris-federation-status-bundle/1` at `GET /api/v1/federation-status-bundle/<id>`
  carries, per member authority, that authority's own revocation feed and epoch checkpoint
  **verbatim**, each still under the member's own ML-DSA-65 signature. The member set is committed by
  `members_root_hex` (SHA3-256 over the sorted per-member digests), so it cannot be tampered after
  signing. The publisher's own signature is only a freshness and set-integrity envelope.
- **The aggregator cannot lie.** The detached verifier decides a foreign credential offline
  (`verify_status_bundle` + `verify_cross_authority_via_bundle`): the envelope must be authentic and
  fresh, the issuer must be **present** (an omitted authority is fail-closed, not verifiable), and the
  trust and revocation decision **delegates** to the P3.2b `verify_cross_authority` against the
  member's own feed. The headline, proven in the drill: an aggregator in **full control** of the
  bundle, recomputing the commitment and re-signing the envelope, **still** cannot forge a member's
  status, because it cannot re-sign as the member. The bundle adds availability, not trust.
- **No new mutation path, byte-identical builders.** A bundle is a view assembled from the
  per-authority feeds over the append-only tables; the endpoint reuses the same
  `_revocation_feed_body` / `_epoch_checkpoint_body` builders (the two P3.2b endpoints were refactored
  onto them). The app statement builder and the standalone verifier produce identical signed bytes,
  pinned as the sixth type in the canonical-equivalence oracle.
- **It runs and is tested.** `scripts/polaris-federation-status-bundle-drill.py` drives the two-
  authority accept / revoked / omission / stale / tampered-set / forge-resistance matrix under real
  ML-DSA every release (pqc-real). `check_federation_status_bundle` (#167) pins the whole path with a
  detection test; `StatusBundleTests` validates the published shape, the commitment, and the canonical
  byte equality against a real server-built bundle. Spec in
  [federation-status-bundle.md](docs/design/federation-status-bundle.md). 167 checks, 99 routes.

## v9.307 — 2026-09-08 (Dead-code sweep)

v9.306 made unused imports and dead locals fail fast in CI. This sweep clears the dead code
that predates that enforcement and that the pyflakes rules do not reach: unreferenced
functions and unused unpacked bindings.

- **A dead function, removed.** `replica_configured()` in `app.py` returned whether a read
  replica was configured (`DB_CONFIG_REPLICA is not None`). Nothing in the tree referenced it.
  Removed.
- **An unused binding, removed.** The federation-topology check unpacked a short name it never
  read from each grounding tuple; the tuples now carry only the `(condition, description)` pair
  they actually use.
- **The sweep, recorded.** vulture at 70% confidence reports no dead code. At 60% the remaining
  candidates are all live through indirection: gunicorn lifecycle hooks, `BaseHTTPRequestHandler`
  and `urllib` overrides, the module run entrypoint, a CI-called smoke test, Jinja `finalize`, the
  detached verifier's reference-API proof generators, and `__init__`-time config attributes. These
  are kept deliberately, not dead.
- **`ruff.toml`, placed with its siblings.** v9.306 added `ruff.toml`; it is a linter config like
  `.pre-commit-config.yaml` and `.coveragerc`, so it joins them in the system map's ignored-config
  set rather than taking its own tree line.

## v9.306 — 2026-09-08 (Enforce import + dead-code hygiene: ruff)

The v9.305 cleanup removed the unused imports it found by hand; this makes that hygiene
continuous. Ruff runs the pyflakes correctness rules in CI and in pre-commit, so an unused
import, a dead local, an undefined name, or a placeholder-free f-string fails fast rather
than accumulating.

- **Config, scoped on purpose.** `ruff.toml` selects `F` (the pyflakes family) only, not
  style: the codebase's long-lined formatting is deliberate and reflowing it would be churn
  with no safety benefit. The line length is set generously and the formatter is not used.
- **It actually runs.** ruff is a dev dependency (`requirements-dev.txt`), a local (no-network)
  pre-commit hook, and a CI step in the product-test job before the DB setup, so lint failures
  are fast. `check_lint_enforced` (#166) pins the config, the dependency, the hook, and the CI
  step together, so a lint that is configured but never runs cannot slip in.
- **Cleaned to green.** Getting the tree to pass surfaced sixteen findings ruff catches that a
  bare pyflakes pass did not: five placeholder-free f-strings, six unused imports (of which the
  four test-discovery imports in test_app.py are kept with `# noqa: F401`, since they exist for
  unittest.main() to discover the property suites), and five dead local assignments removed
  (including a vestigial env dict and a superseded results collector).

166 machine-checked invariants.

---

## v9.305 — 2026-09-08 (Repo hygiene: unused imports, CODEOWNERS)

A cleanup pass against golden-standard repository organization. The audit found the codebase
already meets it -- all standard top-level files (README, LICENSE, CONTRIBUTING,
CODE_OF_CONDUCT, SECURITY, CHANGELOG, CITATION, NOTICE, .gitignore), full .github community
health (FUNDING, dependabot, issue and PR templates), no orphaned scripts (every script in
scripts/ is referenced), zero dangling TODO/FIXME markers in source, and intentional-only
duplication (the standalone detached verifier and the two-witness design) -- so the changes
are deliberately small rather than a restructure of a working, heavily pinned tree.

- Removed four genuinely unused imports found by pyflakes: a redundant `prometheus_client`
  and an unused `CustodyError` in app.py, three unused flask names (`render_template`,
  `flash`, `g`) in security.py, and an unused `os` in scripts/polaris_authz_audit.py. The two
  remaining flagged imports are intentional side-effect imports marked `# noqa: F401` (an oqs
  preload in the dyno, a psycopg2 availability guard in a drill) and are kept.
- Added .github/CODEOWNERS, the one missing golden-standard community-health file, naming the
  security- and constitution-critical paths explicitly (the schema, the crypto core, the
  detached verifier, the invariant layer, MISSION.md, and CI).
- Removed local .DS_Store cruft (already gitignored, never tracked).

No behavior change: only unused names removed and one review-routing file added. 165 checks.

---

## v9.304 — 2026-09-08 (Front-door honesty pass, and a flaky-benchmark fix)

An audit of the outward surfaces against three internal points, plus a CI-reliability fix.

- **"Unlinkable" is now qualified where the claim is made.** The tagline, title, and social
  card said "unlinkable-by-default", which reads as covering the holder-to-verifier hop; they
  now say "issuer-unlinkable", so the qualifier the README body already carried sits beside the
  claim. `check_public_claims_honest` pins it: the shareable title and social card must say
  "issuer-unlinkable", not a bare "unlinkable".

- **Cross-relying-party correlation stays a documented boundary.** A full-credential
  presentation carries a stable `token_value`, so unrelated relying parties can correlate a
  holder; this is a permanent, out-of-scope design decision, not a bug, and the README already
  states it positively (no pairwise/blinded/one-time/anonymous presentation). Restated, unchanged.

- **Offline authorization keeps authenticity and currency mechanically distinct.** A stapled
  presentation can be cryptographically authentic and still not certainly ACTIVE at this
  instant; the detached verifier already returns them as separate fields (`authentic` versus
  the `decision`/`status`), and a high-risk relying party sets a `max_age` of seconds. The
  README now says so explicitly beside the tradeoff.

- **The witness point is phrased carefully.** v9.302 shipped the protocol for independent
  transparency witnesses; institutionally independent witnesses actually running it are a
  deployment step, not a software one. docs/design/transparency-log.md now says so.

- **A flaky benchmark is fixed.** The polaris_sim single-vs-two-witness micro-benchmark is
  overhead-dominated, so the two rates hover near parity and swing under CI noise (measured
  ratios ~0.94 at v9.295 and ~0.77 at v9.302 both reddened the build against an 80% floor).
  The ordering is not a reliable regression signal at this scale and is no longer asserted; the
  test now only trips if single-witness falls below half the two-witness rate, which is a broken
  path rather than noise.

165 machine-checked invariants.

---

## v9.303 — 2026-09-08 (Transparency external-ledger publication, P3.3c)

Witnesses (P3.3b) attest the heads they were shown; an external ledger is the complete,
ordered, public record. P3.3c publishes each of the log's heads into an independent
append-only ledger, so the log cannot use a head it has not publicly committed and the full
set of published heads is publicly enumerable.

- **The publication receipt.** A log publishes a head into an independent append-only ledger
  and gets a `polaris-transparency-publication/1` receipt: the ledger's own signed tree head
  plus an inclusion proof that the head's entry is a leaf in it. The detached verifier's
  `verify_publication` confirms both, standalone. A ledger is itself an append-only log, so
  this reuses the RFC-6962 machinery, and the ledger's own append-only-ness is monitored the
  same way (a ledger that drops a recorded head fails its consistency proof).

- **A backend driver.** `scripts/polaris-transparency-ledger.py` is a file-backed append-only
  ledger; `POLARIS_LEDGER_BACKEND` selects it (`file`, implemented and CI-tested) or a
  declared chain driver (`algorand-pq`, `hyperledger-indy`) that waits on its API -- the same
  honest shape as key custody and the audit anchor's external chain. The receipt does not
  change with the backend.

- **Proven under attack.** `scripts/polaris-transparency-publication-drill.py` runs the actual
  ledger under real ML-DSA-65 every release: it records a log's heads and the verifier
  confirms each; a forged, wrong-key, or unrecorded-head receipt is rejected; and the ledger
  dropping a head it recorded is caught. `check_transparency_publication` pins it; the receipt
  is exempt from the canonical oracle (its only signed part is the ledger's STH, itself a
  covered type), with agreement proven by the drill.

165 machine-checked invariants.

---

## v9.302 — 2026-09-08 (Transparency witnesses and the split-view defence, P3.3b)

The transparency log's monitor (P3.3) catches a log that rewrites its own history. It
cannot, alone, catch a split view: a log that shows one head to one observer and a
different head at the same size to another. P3.3b closes that with witnesses and a
non-repudiable equivocation proof.

- **Witness cosignatures and witnessed checkpoints.** The detached verifier gains
  `verify_cosignature` (an independent witness's signature over a head,
  `polaris-transparency-cosignature/1`) and `verify_witnessed_checkpoint`: a relying party
  accepts a head only if it carries cosignatures from at least K distinct trusted witnesses,
  so a split view needs K witnesses to equivocate, not just the log.

- **The equivocation proof.** `verify_equivocation` takes two Signed Tree Heads for one log,
  both validly signed by the log key, at the same size with different roots, and declares a
  proven, non-repudiable equivocation. It is what two gossiping observers produce the moment
  they compare the heads they were shown.

- **The witness daemon, and a split-view drill.** `scripts/polaris-transparency-witness.py`
  is the independent witness anyone runs: it cosigns consistent heads, refuses a fork,
  gossips the head it saw, and alerts with a written proof on a rewrite or a gossip-detected
  split view. `scripts/polaris-transparency-gossip-drill.py` proves it under real ML-DSA
  every release: three witnesses cosign a head to a threshold, and a fork is caught both by a
  witness refusing it and by two witnesses gossiping. `check_transparency_gossip` pins it.
  The cosignature is signed by the witness, not the app, so its witness-vs-verifier byte
  agreement is proven by the gossip drill rather than the canonical-signing oracle;
  external-ledger publication remains a deployment integration.

164 machine-checked invariants.

---

## v9.301 — 2026-09-08 (The transparency log, P3.3)

The audit anchor (docs/design/anchoring.md) proves the rows under one Merkle root; it does
not, alone, prove the operator did not later drop a root and publish a different one. P3.3
closes that: the append-only AnchorBatch root sequence becomes a public, independently
verifiable transparency log in the style of RFC 6962, using SHA3-256.

- **The log, as a signed view over AnchorBatch.** `GET /api/v1/transparency/sth` publishes a
  Signed Tree Head (`polaris-transparency-sth/1`), `/consistency/<m>/<n>` an append-only
  consistency proof, `/proof/<index>` an inclusion proof, and `/entries` the entries for
  replication. The Merkle math is anchoring.py's `log_*` helpers; there is no new mutable
  state and no personal data. The STH joins the four other signed statements in the
  canonical-signing oracle, which now covers five types.

- **The detached verifier proves append-only.** `scripts/polaris-verify.py` gains the
  RFC-6962 log verification (`merkle_tree_head`, `verify_consistency`, `verify_inclusion`,
  `verify_sth`, `verify_log_consistency`): it accepts an append-only extension and rejects a
  rewrite, a fork (two roots at one size), a shrink, and a wrong-key head. The math is
  self-tested exhaustively across tree sizes with inclusion and consistency proofs and their
  tamper-rejection, and it stays standalone.

- **An independent monitor, and a tampering drill.** `scripts/polaris-transparency-monitor.py`
  is the daemon anyone runs: it caches the last head it saw and ALERTs (non-zero) on any
  tampering. `scripts/polaris-transparency-drill.py` proves the whole thing end to end under
  real ML-DSA-65 every release: the detection matrix, AND the actual monitor run over HTTP
  against a live log that is then rewritten, forked, shrunk, and wrong-key-signed, exiting 0
  while the log only appends and alerting the moment it is tampered. `check_transparency_log`
  pins it; the spec is docs/design/transparency-log.md. Cross-monitor gossip and
  external-ledger publication are P3.3b.

163 machine-checked invariants; 98 routes.

---

## v9.300 — 2026-09-08 (The canonical-signing equivalence oracle)

Every signed statement in Polaris is signed by the application over a canonical byte
string and reconstructed independently by the offline verifier. If the two sides ever
disagree on a single byte, the application keeps signing while every offline verification
fails, silently. It is the subtlest, highest-impact failure mode in the system, and until
now it was caught only by hand and by the per-format drills. This ship makes introducing
it unnoticed impossible.

- **A differential + metamorphic oracle.** `polaris_web/test_canonical_equivalence.py`
  treats the app-side statement builder and the verify-side canonical builder for each of
  the four canonical-JSON signed types (federation manifest, epoch checkpoint, revocation
  feed, status assertion) as two implementations of one spec, and asserts over
  Hypothesis-generated inputs (unicode that forces escaping, key reorderings, nested
  structures, integer boundaries, stray keys) the properties that must hold:
  cross-implementation byte equality, determinism, key-order invariance, signature-envelope
  exclusion (the signature can never sign itself), JSON round-trip stability, and canonical
  form. It is crypto-free and runs in the ordinary product-test job; the real ML-DSA-65
  round-trip is proven per type by the pqc-real drills. Writing it, Hypothesis at once found
  a flawed assumption in the test itself, that a value merely containing ", " is not a
  separator, which the oracle now handles by re-canonicalization rather than a substring check.

- **A static guard and a coverage guard.** `check_canonical_equivalence` extracts and
  compares the ordered key list on both sides for all four types, requires the compact
  sorted-key form on each, and requires the oracle to exist and run in CI. A coverage
  property in the oracle fails if a fifth canonical-JSON signed type is ever added without an
  oracle case, so the invariant cannot be outgrown silently.

162 machine-checked invariants.

---

## v9.299 — 2026-09-08 (Federation proven across two instances, P3.10)

The federation protocol was proven in one process by the crypto drills. P3.10 proves it
across the deployment boundary: two independent instances, each its own database and its
own real ML-DSA-65 root, talking only over HTTP.

- **The federation-two-instances CI job.** The repo's first CI job with both a database and
  real liboqs. It loads two authority databases and runs the two-instance drill under real
  ML-DSA-65 every release.

- **Two instances federate over HTTP.** `scripts/polaris-federation-instances-drill.py`
  boots an instance (gunicorn) against each database and drives the cross-authority matrix
  over the wire. Cross-verification: authority B publishes a manifest attesting to A's key
  in a context, and a relying party that trusts B accepts A's credential in that context
  from B's manifest, fetched over HTTP. Attestation revocation: B revokes the attestation,
  and the re-fetched manifest no longer accepts A. Anchor cross-checks: A's signed epoch
  checkpoint and revocation feed are fetched over HTTP and verified, and A's feed rejects a
  revoked credential. The adversarial cases (wrong context, forged credential) reject
  throughout. Red on any wrong decision.

- **Pinned.** `check_federation_two_instances` requires the drill to boot two instances,
  drive the federation endpoints over HTTP under real ML-DSA, prove the attestation and
  revocation lifecycle, and run in its own CI job. This completes the first clause of the P3
  exit gate (two instances interoperate in CI); the second (an external team integrating
  docs-only) is external.

161 machine-checked invariants; 18 CI jobs.

---

## v9.298 — 2026-09-08 (Epoch alignment and revocation propagation across authorities, P3.2b)

The inter-authority protocol (P3.2) let two authorities publish their anchors and
attestations and a relying party accept a foreign credential offline. It carried the
epoch and revocation state only as references. P3.2b makes those references consumable,
as two more signed objects an authority publishes and the standalone verifier consumes
offline, both views over the append-only TokenStateEpoch and RevocationList with no new
mutation path.

- **The epoch checkpoint.** `GET /api/v1/epoch-checkpoint/<agency_id>` publishes a signed
  `polaris-epoch-checkpoint/1`: the authority's commitment to the latest point on its
  append-only epoch chain, the epoch number and Merkle root and the prior epoch it
  extends. The detached verifier gains `verify_epoch_checkpoint` (authenticity, two
  witnesses, freshness, issuer binding), `check_epoch_chain` (monotonicity, and a FORK
  when two different roots are signed at one epoch number, which is cryptographic proof
  the authority equivocated about its own history), and `epoch_aligned` (a checkpoint
  cross-checked against the epoch its authority's own manifest commits to).

- **The revocation feed.** `GET /api/v1/revocation-feed/<agency_id>` publishes a signed
  `polaris-revocation-feed/1`: the sorted revoked-credential leaves (SHA3-256(token_value))
  for the credentials the authority issued that are now revoked, plus a commitment over
  them. A relying party checks a foreign credential's non-revocation against it offline
  with no issuer contact: `verify_cross_authority` folds in the feed fail-closed (genuine,
  fresh, and bound to the issuer key, or reject), `verify_revocation_feed` and `is_revoked`
  test membership, and `check_revocation_progression` catches a ROLLBACK (a newer feed that
  drops a published revocation), monotone because RevocationList is append-only. It is a
  CRL of revoked leaves, not the active population: a leaf is derivable only by a holder of
  the credential, and no token_value is published.

- **It runs, and it is specified and tested.** `scripts/polaris-epoch-revocation-drill.py`
  stands up two authorities with distinct real ML-DSA-65 roots and drives the whole matrix
  (a clean chain and an aligned checkpoint accept; a fork, a rollback, a stranger-signed or
  tampered feed, and a revoked foreign credential all reject) under real ML-DSA every
  release in the pqc-real CI job. The endpoints' shape, the commitment, the byte-match
  between the app's signed statements and the verifier's canonical bytes, and the
  no-personal-data rule are covered by `EpochRevocationTests`, and
  `check_epoch_revocation_propagation` pins it. The protocol is specified in
  [inter-authority-protocol.md](docs/design/inter-authority-protocol.md).

160 machine-checked invariants; 94 routes.

---

## v9.297 — 2026-09-08 (Retire the freeze line from the constitution)

The v9.27 freeze line was a definition-of-done: it limited the work that followed the
core to hardening, measurement and thesis evidence, and required a named owner trigger to
open a new arc. That trigger fired on 2026-08-31, the project entered its deployment arc,
and the freeze line stopped describing how the project runs. On the owner's recorded
direction, it is retired from MISSION.md.

- **MISSION.md opens on the vocation.** The `## Freeze line` section is removed, so the
  constitution now leads with `## Vocation`, its deepest constraint, rather than a
  definition-of-done that no longer holds. The `## Amending this document` section records
  the retirement, its authorizing act (the owner's recorded direction, the same authority
  that removed the Sanctum apparatus at v9.55), and where the honesty it named now lives.

- **The thesis-terminus honesty is unaffected.** The one durable claim the freeze line
  narrated, that the strong thesis is retired past the v9.40 terminus, lives in
  [docs/THESIS.md](docs/THESIS.md) and is pinned by `check_thesis_terminus_honest`, which
  reads THESIS.md and the version and never depended on MISSION.md's freeze line. No check
  required the removed section; all 159 pass unchanged.

- **The two external references are corrected.** ROADMAP.md's decision-record preamble no
  longer frames the deployment arc as acting under a live freeze line, and the comment on
  `check_thesis_terminus_honest` no longer cites the freeze line as its authority. Both now
  name the version at which the freeze line was retired.

---

## v9.296 — 2026-09-08 (Inter-authority protocol v1: the signed federation manifest, P3.2)

The federation topology (P3.1) says each authority is its own root; this is how two
of them interoperate. An authority publishes what another party needs to verify its
credentials, signed, with no central service.

- **The federation manifest.** `GET /api/v1/federation-manifest/<agency_id>` publishes
  a signed `polaris-federation-manifest/1`: the authority's own anchors (its trust
  roots) and the attestations it has made (from `AgencyTrustAttestation`: who it
  accepts, in which context, carrying the attested key so a verifier can bind it to a
  foreign credential's signature). It is public trust data with no personal content,
  signed with the authority's own key over `SHA3-256(canonical)`, and short-lived so
  anchors and attestations do not go stale. Epoch and revocation are carried as
  references; their alignment and propagation protocols are named and deferred to P3.2b.

- **Cross-authority verification, offline.** The detached verifier gains `verify_manifest`
  and `verify_cross_authority` (still standalone: no Polaris code, no database, no
  network). A manifest is honored only if it is self-consistent (signed by one of its
  own declared active anchors, never a stranger key), authentic (two witnesses), fresh
  (window-bounded), and from an authority the relying party trusts. A FOREIGN credential
  is accepted iff a trusted authority attests to its signing key in the presented
  context. Trust flows along published attestation edges, never a transitive closure.

- **It runs, and it is specified.** `scripts/polaris-federation-manifest-drill.py` stands
  up two authorities with distinct real ML-DSA-65 roots, has one attest to the other, and
  drives the whole matrix (right context accepts; wrong context, un-attested issuer,
  untrusted authority, stranger-signed manifest, expired manifest, forged credential all
  reject) under real ML-DSA every release in the pqc-real CI job. The protocol is in
  [inter-authority-protocol.md](docs/design/inter-authority-protocol.md); the endpoint's
  shape, the attestation exchange, and the no-personal-data rule are covered by
  `FederationManifestTests`; `check_inter_authority_protocol` pins it. The manifest the
  endpoint builds was confirmed byte-compatible with the offline verifier under real crypto.

This unblocks P3.10 (two instances interoperating end to end in CI).

159 machine-checked invariants; 92 routes.

---

## v9.295 — 2026-09-08 (Say what unlinkability does NOT cover, and split the witness claim)

A technical-honesty review of the claims the front door makes. Three were imprecise;
each is now stated to reality and, where it can regress, pinned.

- **Relying-party linkability, stated positively.** "Unlinkable by default" is
  issuer-side and scoped to zero-knowledge mode: a ZK-mode verification stores no token
  identifier, so the issuer's database cannot reconstruct that graph. It does NOT cover
  the holder-to-verifier hop. A full-credential presentation carries a stable
  `token_value`, so two relying parties who both see a credential can join their logs by
  it, with no name required; and even without `token_value`, any stable handle shown to
  every verifier (a reused public key, a reused membership proof) is the same correlator.
  The README now says this and names the linkability-resistant systems Polaris does NOT
  implement (pairwise identifiers, blinded/derived presentations, one-time tokens,
  anonymous credentials). This is a **permanent, documented property, not a pending
  feature**: Polaris is a full-credential presentation system, so a credential is
  correlatable across the verifiers it is shown to, by design; linkability-resistant
  presentation is out of scope. `check_public_claims_honest` requires the statement.

- **Offline authorization is a tradeoff.** The signed status assertion buys issuer
  non-observation at the cost of revocation latency: a revoked credential's last ACTIVE
  assertion stays valid until it expires (one hour by default, a policy number, not a
  law), and a verifier tightens that window with its own shorter `max_age`. Stated as a
  pick-two: issuer non-observation, offline availability, revocation freshness.

- **The two-witness claim is split to reality.** It read "two independent witnesses for
  every cryptographic verdict", which flattened two different guarantees. Now: issuance
  requires two independent ML-DSA-65 implementations and fails closed on disagreement;
  verify-at-use is single-witness with continuous mandatory second-witness sampling and a
  SEV page on disagreement. The old absolute is an overclaim phrase the check now forbids.

- **The Atlas globe is gone from the README.** It taught a movie, not the system. The
  logo stays; the one visual is now a verify verdict showing `authentic: true` with
  `currently_authoritative: false` on a revoked credential, which teaches the
  authenticity/authorization split the front door leads with.

- **Also stabilized a flaky test.** The national simulation's throughput benchmark
  asserted single-witness verify is at least as fast as the two-witness check; on a
  shared CI runner the two micro-benchmark rates can invert by a few percent under
  scheduling noise (it reddened v9.293's run). The assertion now allows a 20% tolerance,
  still tripping on a real throughput regression.

Presentation, two check extensions, and one flaky-test stabilization; no schema or
CI-job change.

158 machine-checked invariants; the claims match what the code guarantees.

---

## v9.294 — 2026-09-08 (Front door opens on the engine, with proof-of-life)

A second surface review: the v9.293 fixes landed (the site title dropped "national";
the comparison marks Polaris neither deployed nor issuing at national scale, pinned so
CI fails on a regression), but the first screen still taught the constitution, the
Atlas, and the six-cards motivation rather than the verification engine the repository
now is. Reordered to open on the engine, and added a runnable demonstration.

- **The README and the site open on the engine.** "What Polaris is" now leads with the
  post-quantum credential verification engine (issue, hold, present; authenticity offline
  via the detached verifier; authorization online via the relying-party API or offline
  via the signed status assertion; the Python and TypeScript SDKs and the conformance
  suite; explicit non-transitive federation), then the schema backbone, then the
  six-cards motivation. The Atlas moved from the top hero to the Architecture section,
  where the operator's surface belongs.

- **Proof-of-life a stranger can run.** A new "See it run" section gives three commands
  that need no database and no server: the detached verifier's self-test, its re-check of
  the published authenticity packs (a genuine one passes, every tampered one fails), and
  the conformance suite against the reference SDK. They are the same code a third party
  integrates and the same code CI runs every push, so "clone and see the engine work" is
  now on the page, not only in the changelog.

Presentation only; no code, schema, or CI-job change. The comparison tick and the
"national"-free title were verified on the raw files, not assumed from the changelog.

158 machine-checked invariants; the first screen now teaches the engine.

---

## v9.293 — 2026-09-08 (Front door: state reality, and pin it)

A review of the live surfaces found them drifting from the code and, in a few places,
overstating what exists. Fixed toward reality, and pinned so the surfaces cannot drift
again.

- **The site drops the "national" category.** The `<title>`, social card, and headline
  called Polaris a "national identity-token system", which reads as a deployment; the
  repository calls it an identity-token reference implementation. The site now matches:
  a reference implementation, no "national". `check_public_claims_honest` forbids
  "national" in the title and social card.

- **The comparison stops awarding Polaris national-scope issuance.** The "Where Polaris
  sits" table marked Polaris with national-scope issuance while the prose said its ticks
  are design properties, not a deployment. The table and the paragraph no longer argue:
  Polaris is now marked neither deployed nor issuing at national scale, and the check
  fails if either leading column awards it a tick.

- **The README describes the system it is the README for.** It led with schema, Flask,
  Atlas, and CLI and named the verification product only in passing. The opening now
  foregrounds the engine: ML-DSA-65 issuance and signing, offline authenticity (the
  detached verifier) and authorization online (the relying-party API) or offline (the
  signed status assertion), the Python and TypeScript verify SDKs and the conformance
  suite, and explicit non-transitive federation. `sdk/`, `conformance/`, and the
  holder/verifier tools are in the component table.

- **The readiness ledger's cover is current, and stays current.** PRODUCTION-READINESS.md
  presented as v9.237 while the tree was far ahead. Restamped, and
  `check_presentation_surface` now stamps the ledger's cover like the other policies, so
  it fails CI when it drifts more than twenty minors.

- **One key-custody line, not two.** The README's Scope listed "HSM key custody" as a gap
  while Cryptography described the Kryoptic software module, reading as both having and
  lacking an HSM. It now reads once: the production key-custody choice (HSM, KMS, or
  software module), since no production HSM is chosen here.

- **CLAUDE.md records two standing directives** (VANTA): build the ENGINE over the
  WRAPPER (the cryptographic paths that run, not the presentation around them), and keep
  the front door stating reality or understating, never overstating.

158 machine-checked invariants; the presented artifact matches the code.

---

## v9.292 — 2026-09-08 (Federation topology decision record, P3.1)

The federation track needs a topology before an inter-authority protocol can be
specified. This records the decision, and grounds it so it cannot drift into prose.

- **The ADR.** [docs/design/federation-topology.md](docs/design/federation-topology.md)
  records that Polaris is FEDERATED per-authority, not central: each authority is its
  own ML-DSA-65 trust root, cross-authority trust is explicit and non-transitive
  (`AgencyTrustAttestation`, resolved by a single non-recursive lookup), and a relying
  party verifies against published keys with no central service in the path. There is
  no central identity database, no central trust root, and no central verification
  service.

- **The choice is not free.** The ADR derives the federated shape from the constitution,
  not from engineering taste: the vocation names the federation graph with "no agency
  holds a monopoly", and Polaris is "NOT a surveillance backbone" with population-scale
  aggregation "refused ... structural". A central instance is a monopoly and a single
  store of every person, which those clauses forbid, so it is not an available option.
  The threat-model delta (breach blast radius, aggregation, coercion, trust semantics,
  and the cost the federated choice accepts) is documented.

- **Kept honest against the code.** `check_federation_topology` will not pass the ADR
  unless the primitives it cites are actually present: `AgencyTrustAttestation`, the
  non-transitive resolver `_federation_trust_holds`, per-authority keys
  (`Agency.signing_public_key_hex`), and the detached verifier. The record therefore
  cannot claim a federated model the code has drifted away from. It is grounded in what
  already runs (PE.2 detached verifier, PE.3 two-issuer drill, PE.3b federation in the
  app), which this decision merely names and fixes.

This unblocks P3.2 (the inter-authority protocol) and P3.10 (two instances
interoperating in CI). It reopens no non-goal and does not soften the constitution.

158 machine-checked invariants.

---

## v9.291 — 2026-09-08 (Offline verification: authorization with no connectivity, P3.6)

The last connectivity gap in the holder<->verifier flow. Authenticity was already
offline (the detached verifier), but "is this authoritative right now?" needed an
online call. This makes authorization verifiable with no connectivity, within a
bounded freshness window — and, because verification touches no issuer, the issuer
never learns a verification happened. Offline verification is *more* private than online.

- **A short-lived signed status assertion.** `POST /api/v1/status-assertion` mints an
  issuer-signed statement — the sorted-keys canonical JSON of `{format, token_value,
  status, issued_at, expires_at}`, signed with the issuing agency's ML-DSA-65 key over
  `SHA3-256(canonical)`. A holder fetches it when connected (possession-authenticated:
  it presents the genuine credential signature, same uniform `not_verifiable` on a
  bad/unknown one as `/verify`; no bearer, so a holder refreshes its own status without
  being a registered relying party), staples it to a presentation, and presents offline.
  No personal data, no record of who fetched it.

- **The reference verifier decides it offline.** `scripts/polaris-verify.py --pack …
  --status-assertion …` accepts iff the credential is authentic AND the assertion is
  authentic, bound to that credential, `ACTIVE`, and fresh — `now` within
  `[issued_at, expires_at)` and the window no longer than a ceiling the verifier accepts
  (`--max-window`), so a verifier never trusts an arbitrarily long window an issuer
  declares. A revoked token's stale `ACTIVE` assertion is usable only until it expires;
  the window (`POLARIS_STATUS_ASSERTION_TTL`, default 3600s) bounds staleness. The
  verifier stays standalone: no Polaris code, no database, no connectivity.

- **Freshness and replay bounds specified and run.** The protocol, and exactly what a
  verifier MUST reject (expired, over-long window, wrong binding, non-`ACTIVE`, bad
  signature), are in [docs/design/offline-verification.md](docs/design/offline-verification.md).
  `scripts/polaris-offline-status-drill.py` signs a credential and assertions with one
  real ML-DSA-65 key and drives the whole matrix every release in the `pqc-real` CI job,
  red on any wrong decision. `check_offline_verification` pins it; the endpoint's
  possession proof, assertion shape, current-status reflection, and no-personal-data
  rule are covered by `OfflineStatusAssertionTests`.

Deferred to P3.6b: an aggregate signed status bundle, holder-wallet stapling and the
SDK offline-status methods, and epoch binding.

157 machine-checked invariants; 91 routes.

---

## v9.290 — 2026-09-08 (TypeScript verify SDK: P3.5 complete across two languages)

The other half of P3.5. The conformance suite (v9.289) is the contract; this adds a
second implementation in a second language and proves it passes the SAME runner, so
"conformant" is not a claim about one SDK but about the contract itself. It also
fixes a CI failure the conformance work surfaced.

- **A TypeScript SDK, held to the same contract.** `sdk/typescript/` (`@polaris/verify`)
  is the counterpart of the Python reference SDK: offline ML-DSA-65 authenticity over
  `SHA3-256(token_value)` via `@noble/post-quantum` — a third independent implementation
  that agrees with liboqs and OpenSSL on the published vectors — plus the online status
  check via OAuth2 client-credentials and `/api/v1/verify`. Standalone (only `@noble`
  plus the platform's `fetch`/`btoa`; Node, Deno, Bun, browsers), erasable TypeScript
  that Node >= 22.6 runs directly, type-checked with `tsc` and unit-tested.

- **Proven across both languages by one runner.** `conformance/run_conformance.py
  --verifier "node sdk/typescript/src/conformance.ts"` drives the TypeScript verifier
  over the identical cases the Python SDK passes — genuine, tampered, placeholder, and
  the genuine-but-untrusted-issuer verdict — in the repo's first Node CI job
  (`sdk-typescript`: `npm ci`, `tsc --noEmit`, `node --test`, then the conformance
  runner). `check_typescript_sdk` pins that the SDK is standalone, verifies real
  ML-DSA (not a flag), ships a committed lockfile, and runs the shared runner in CI.

- **Fixed: the end-to-end drill failed the pqc-real CI job (red since v9.287).** The
  drill guarded on `POLARIS_USE_REAL_PQC=1` being set in its step's environment, but
  that flag was set per-step elsewhere in the job, so the drill exited 3 (a skip that
  fails the build) instead of running. It now declares the real-PQC profile itself —
  as the federation drill already did — and guards on LIBRARY availability (liboqs +
  the cryptography witness), so it runs wherever the real crypto is present. The
  matrix (accept / reject-on-revoke / reject-tampered / reject-foreign / provisional /
  duress-indistinguishable) runs green again.

P3.5 is complete: a callable API, two reference SDKs, and a self-certification suite
that certifies any verifier in any language — the docs-only integration path the P3
exit gate asks for.

156 machine-checked invariants; 17 CI jobs.

---

## v9.289 — 2026-09-08 (Verification conformance suite + Python SDK: the integration contract, P3.5a)

P3.4 gave a relying party an API to call; this makes "correctly verifying a Polaris
credential" a runnable, publishable contract, with a reference implementation that
passes it. It is what lets an external team integrate from the docs alone (the P3
exit gate).

- **The conformance suite is the contract.** `conformance/` publishes the cases a
  conformant verifier must decide and a LANGUAGE-AGNOSTIC runner that checks any
  implementation against them. A verifier is any command that reads a case on stdin
  (`{pack, anchors}`) and prints a verdict (`{authentic, issuer_trusted}`);
  `run_conformance.py --verifier "<cmd>"` drives it over every case and exits non-zero
  on any mismatch. The cases (`cases.json`, built on the CI-verified `vectors/`) cover
  a genuine signature, a tampered signature, a genuine signature over a different
  token, a signature against an unrelated key, the dev placeholder, and — the case a
  simple "does it verify" check misses — a genuine signature by an UNTRUSTED issuer
  (authentic, but `issuer_trusted: false`, which a relying party must reject).
  `SPEC.md` is the published contract.

- **A Python reference SDK that passes it.** `sdk/python/` (`polaris-verify`) is a
  standalone, pip-installable library — only `cryptography` plus the standard library,
  no Polaris code — that a relying party drops into its backend. It verifies the
  ML-DSA-65 signature over `SHA3-256(token_value)` offline (with liboqs as a second
  witness when present), optionally against trusted issuer anchors, and does the
  online status check by authenticating as an organization (OAuth2 client-credentials)
  and calling `/api/v1/verify`. `accept` needs both; offline it is `provisional`. The
  online path is proven end to end against a live server.

- **It runs, it does not merely describe.** The conformance runner drives the bundled
  SDK (`--self`) in the pqc-real CI job every release, alongside the SDK's own unit
  tests; `check_conformance_suite` pins that the SDK is standalone, verifies real
  ML-DSA (not a flag), the runner can drive any language, the cases carry the
  untrusted-issuer verdict, and the suite runs in CI. An external SDK — in any
  language — is conformant exactly when it passes the same runner.

The TypeScript SDK (P3.5b) is the remaining half of P3.5: the repo has no Node
toolchain yet, so it is a clean separate ship against this now-locked contract.

155 machine-checked invariants; verifying a Polaris credential is now a contract
anyone can hold their own code to.

---

## v9.288 — 2026-09-08 (Relying-party API v1: a bounded verification oracle)

P3.4. The holder can present a credential (v9.287); this gives the other side a way
to check it as a real organization, over a stable versioned API, without ever
becoming a login product. It is the first PROGRAMMATIC (non-operator) authentication
path in Polaris, and it is deliberately narrow.

- **A relying party authenticates as itself.** `polaris rp-register "<org>"` mints a
  `client_id` and `client_secret` (only the scrypt hash is stored, the secret shown
  once). `POST /api/v1/oauth/token` is OAuth2 client-credentials (RFC 6749 §4.4):
  present the credential by HTTP Basic and receive a short-lived, signed, verify-scoped
  bearer token. The token is stateless and salted distinctly from the operator session
  cookie, verified in constant time so the endpoint is not a client-id oracle.

- **API-access auth ONLY, enforced at the schema.** `RelyingParty.scope` is
  CHECK-constrained to `'verify'` — there is no other scope the table can hold. A
  relying party can confirm a credential and nothing else; identity never becomes a
  login-as-a-person product (the vocation), and that is a database constraint, not a
  policy the app could relax.

- **`POST /api/v1/verify`: a verdict, never a person.** The relying party submits the
  credential the holder presented (the `token_value` and the issued `signature_hex`)
  and gets back `authentic`, `currently_authoritative`, `usable`, and a `decision` —
  with no personal data in any branch. Authenticity is the immutable signature;
  authorization is read fresh from the primary; a revoked credential stays authentic
  but is not authoritative.

- **No enumeration, no existence oracle.** The caller must present the GENUINE issued
  signature (a constant-time possession proof against the stored signature), so it can
  only verify credentials actually presented to it — it cannot forge a signature to
  walk the population. A not-found value or a mismatched signature returns the same
  uniform "not a verifiable presentation" verdict, so existence never leaks, and the
  sequential `token_id` is never accepted here. No who-verified-whom record is kept: a
  per-verification log would itself be a surveillance store, so bounding is rate limit
  plus aggregate metrics, never a trail.

- **The bound is a running adversary.** An RP bearer establishes no operator session,
  so it reaches nothing but `/api/v1/verify`; two new controls-as-attacks adversaries
  run every release and turn CI red if an RP credential ever reaches an operator surface
  or if a verdict ever carries personal data (`attack_controls.py`, AC-6). The v9.287
  relying-party tool gains an `--oauth` mode and now authenticates as an org end to end.

Tested at every level: `RelyingPartyApiTests` (auth, the scope boundary, the uniform
not-verifiable verdict, the no-PII verdict, accept/revoke) and the two AC-6 adversaries,
pinned by `check_relying_party_api` (#1 of 154), detection-tested.

154 machine-checked invariants; the holder now has someone to present to, and that
someone can only ever verify.

---

## v9.287 — 2026-09-08 (The holder-to-verifier flow, run end to end)

The pieces existed in isolation: the wallet holds and presents a credential (PE.7),
the detached verifier checks a signature offline with no server (PE.2), and /verify
reports whether a token is authoritative right now. This ship makes them one runnable
path, and adds the piece that was missing: the relying party that decides.

- **A relying-party verifier.** `scripts/polaris-relying-party.py` takes a holder's
  presentation and returns ACCEPT or REJECT by combining the two questions Polaris
  keeps deliberately apart. Authenticity is offline and cacheable: it runs the
  detached verifier over the credential, optionally against a published issuer anchor
  set. Authorization is online and fresh: it asks the issuer's
  `GET /api/tokens/<id>/verify` whether the token is authoritative now. ACCEPT needs
  both; without a reachable issuer the verdict is PROVISIONAL, never a full accept.
  It is standalone the way the detached verifier is: only stdlib and the verifier, no
  Polaris code and no database, because a bank or a border kiosk runs it, not the issuer.

- **The whole matrix runs end to end.** `scripts/polaris-e2e-drill.py` issues a real
  ML-DSA-65 credential, has the wallet present it, and drives the relying party through
  the decision matrix: an active own-issuer credential is accepted, a revoked one is
  rejected on status, a tampered signature and a foreign issuer are rejected, an offline
  check is only provisional, and a presentation made under duress is accepted exactly
  like a normal one. It fails the build if any decision is wrong, and runs every release
  in the `pqc-real` CI job next to the detached verifier and the federation drill.

- **The anti-coercion property, end to end.** A duress presentation is byte-for-byte a
  normal accept from the relying party's side. The relying party cannot tell the two
  apart; the distress signal is matched silently by the issuer, out of its sight. The
  drill and the tests both assert the verdict is indistinguishable.

- **Tested at every level.** The relying party's decision logic is unit-tested with
  injected verdicts (`scripts/test_relying_party.py`, run under the coverage gate); the
  full issue-to-present-to-accept-to-revoke-to-reject flow is tested against the real
  database status service under real ML-DSA (`test_app.py` `EndToEndFlowTests`), and the
  whole path is pinned by `check_holder_verifier_flow` (#1 of 153), detection-tested.

153 machine-checked invariants; the holder now has someone to present to.

---

## v9.286 — 2026-09-08 (Federation in the running app: each agency signs its own tokens)

PE.3b. PE.3 proved the cryptographic federation boundary with a standalone drill;
this puts it in the app. An agency's identity is now cryptographically its own, not
a database field on top of one shared signing key.

- **Each agency registers its own key.** A new nullable `Agency.signing_public_key_hex`
  (migration + schema) holds the agency's published ML-DSA-65 verification key. NULL
  = not federated / single global key.
- **Issuance signs with the issuing agency's key.** Custody gains
  `get_custody_for_agency(agency_id)`: it loads the agency's key from
  `POLARIS_AGENCY_KEYS_DIR/<agency_id>.json`, falling back to the global key when
  absent — so single-key deployments are unchanged. `pqc_signing.sign` /
  `signature_with_key_for_token` thread `agency_id`; `/uc1/issue` signs with the
  issuing agency's key.
- **Issuance refuses a cross-key token.** When the agency has a registered key and
  the signature is real, `/uc1/issue` REFUSES to issue a token whose signature was
  produced by a different key — an agency cannot issue a token signed by a
  non-agency key.
- **/verify reports the binding.** A new `issuer_authentic` field: the token was
  signed by its issuing agency's registered key (`true`/`false`; `null` when it
  cannot be decided — a placeholder signature, or an agency with no registered key).
  Distinct from `signature_valid` (the signature is genuine) and
  `currently_authoritative` (usable now).
- **Proven both ways.** `test_custody.PerAgencyCustodyTests` proves per-agency
  signing under real ML-DSA (two agencies, distinct keys, each signs its own);
  `test_app.FederationInAppTests` proves `/verify`'s `issuer_authentic` at the field
  level in the placeholder suite; the full real-PQC issue→verify→refuse flow runs
  where liboqs is present. `check_federation_in_app` (#152) pins the whole chain,
  detection-tested. Backward compatible: single-key issuance and verify are
  unchanged (the existing suites pass).

Constitutional note: no change to C1-C10 or the vocation. This binds an agency's
tokens to the agency's own key; it adds no personal-data path.

---

## v9.285 — 2026-09-08 (Controls as attacks: IA + SC join AC + AU)

The second batch of controls-as-attacks. The `controls` suite adds the two families
that cover authentication and transport/session protection, again as running
adversaries against the real app and database — not a mapping document.

- **IA-5 (authenticator management):** the stored `password_hash` is a one-way scrypt
  hash, never the plaintext or a reversible form.
- **IA-2 (identification):** a forged/tampered `polaris_session` cookie does not
  authenticate — the request is treated as anonymous and redirected.
- **SC-5 (denial-of-service protection):** per-IP login attempts are rate-limited;
  past the limit the server answers 429.
- **SC-23 (session authenticity):** a state-changing POST (`/individuals/new`)
  without a valid CSRF token is rejected with 403.

All nine controls (AC-3 ×2, AU-9 ×2, AC-7, IA-5, IA-2, SC-5, SC-23) hold locally
against the real system and run in CI's `test` job every release.
`check_controls_as_attacks` (#151) now pins the AC/AU/IA/SC families and that the IA
adversaries read the real password hash and forge the real session cookie, and the
SC adversaries drive a real CSRF-protected POST and check the rate-limit 429 —
detection-tested.

That's four NIST 800-53 families enforced by attack. The same shape extends to more
families when useful; each control stays an adversary that fails, never a checkbox.

Constitutional note: no change to C1-C10 or the vocation. The adversaries use a
non-existent username for the rate-limit probe and a fresh client for the forged
cookie; nothing writes real state.

---

## v9.284 — 2026-09-08 (Security controls as attacks: NIST 800-53 AC + AU)

The honest, engine-shaped answer to "apply the standards": not a control-mapping
document (that would be wrap, and claiming HIPAA/ISO on notional data would
overclaim), but the applicable controls turned into RUNNING adversaries that try to
violate them against the real app and database and must fail. First batch — the two
families that map most directly to Polaris's mechanisms.

- **`attacks/attack_controls.py`** (a new `controls` suite) — five adversaries:
  - **AC-3 (access enforcement):** an unauthenticated request to protected data is
    redirected/denied (HTTP 302), and a logged-in **operator** gets **403** on an
    admin/auditor-only route (`/api/atlas/subject`) — authenticated is not authorized.
  - **AU-9 (audit protection):** an audit-of-record row (`TokenLifecycleEvent`) can
    be neither DELETEd nor UPDATEd — the append-only trigger refuses, and the attempt
    is rolled back so it never actually touches the audit table.
  - **AC-7 (unsuccessful logon attempts):** five failed logins lock the account (the
    failure counter enforces; the attack resets the lock afterward).
- All five hold locally against the real system. The suite runs in CI's `test` job
  every release; `run_attacks.py` goes red if any control is violated.
- **`check_controls_as_attacks` (#151)** pins that the AC/AU adversaries exist,
  attack the real routes and the real append-only audit table (safely rolled back),
  and are wired into CI — with a detection test.

This is "apply NIST" as displacement: every control is an adversary that fails, not
a checkbox. AC + AU first; more families can follow the same shape.

Constitutional note: no change to C1-C10 or the vocation — these adversaries prove
the existing constitution (append-only audit, role gates, lockout) holds under
attack. The one that writes resets its own lock and rolls back its own mutation.

---

## v9.283 — 2026-09-08 (The KAT covers context strings too)

Closes the scope line v9.282 left open. The conformance set had excluded the 7
Wycheproof vectors that use a non-empty ML-DSA context string, because the default
verify path uses an empty context. Both witnesses do expose a context-aware verify
(liboqs `verify_with_ctx_str`, cryptography `verify(..., context=)`), so they are
now wired in.

- **`vectors/kat/mldsa_65_verify.json` now carries the context-string tests** (a
  `ctx` field): tc3 (a 7-byte context) and tc4 (a 255-byte context) that must
  verify, and tc5/tc153-156 (a 256-byte context, one over ML-DSA's 255-byte cap)
  that must be REJECTED as an invalid context. `polaris-fetch-kat.py` always keeps
  the context tests and records their `ctx`; the set is now 58 vectors (23 valid,
  35 invalid, 7 with a context).
- **`polaris-kat-verify.py` is context-aware:** each vector is verified with its
  context under both witnesses. Proven locally: 58/58 conformant, including the
  256-byte-context vectors correctly rejected. `check_kat_conformance` (#150) now
  also pins that the vectors include a context-string case and that the verifier
  actually uses the context-aware APIs — so they cannot be silently dropped again.

The ML-DSA-65 conformance is now over the whole Wycheproof verify surface (both the
empty-context and the context-string cases), under both production witnesses.

Constitutional note: no change to C1-C10 or the vocation.

---

## v9.282 — 2026-09-08 (ML-DSA-65 conformance against Project Wycheproof)

The companion to the witness fuzzing, and the item the previous ship parked. The
published `vectors/` prove three implementations agree with EACH OTHER; this proves
something stronger — that Polaris's two production witnesses agree with an
INDEPENDENT authority's known answers.

- **`vectors/kat/mldsa_65_verify.json`** — a curated, empty-context subset of
  Project Wycheproof's ML-DSA-65 verify vectors (Apache-2.0), pinned to a source
  commit and capped per flag-set so every edge case Wycheproof exercises is
  represented (51 vectors: 21 valid, 30 invalid — bit-flipped signatures, boundary
  conditions, zero public keys, wrong lengths, infinity-norm violations). The
  invalid vectors are the point: they catch a verifier that accepts a bad signature.
- **`scripts/polaris-kat-verify.py`** verifies every vector under BOTH witnesses —
  liboqs and cryptography/OpenSSL — and asserts each matches Wycheproof's expected
  valid/invalid verdict. Proven locally: 51/51 conformant under both. It runs in
  CI's `pqc-real` job; a non-conformance fails the job.
- **`scripts/polaris-fetch-kat.py`** regenerates the committed subset from the
  pinned Wycheproof commit, so the vectors are auditable and refreshable, not
  hand-made. `check_kat_conformance` (#150) pins the provenance, both directions
  (valid AND invalid), both witnesses, and the CI wiring — with a detection test.

This closes the follow-up noted in v9.281: earlier the official vectors could not be
fetched; the network was in fact reachable, so the true known-answer test is now
wired against Wycheproof (empty-context tests; the few context-string vectors are
excluded pending a context-aware verify).

Constitutional note: no change to C1-C10 or the vocation. The KAT verifies public
test vectors and touches no identity data.

---

## v9.281 — 2026-09-08 (Differential fuzzing of the two witnesses)

With Phase E complete, a frontier hardening of the crypto the whole engine rests
on. Verify-at-use runs a SINGLE witness (liboqs) and trusts it because issuance
already two-witnessed the signature — so the entire throughput-soundness argument
depends on liboqs and cryptography/OpenSSL never disagreeing. This ship hunts for
the input where they would.

- **`attacks/attack_crypto.py` gains `witnesses_disagree_under_fuzz`.** Across many
  random rounds — genuine signatures, a flipped signature bit, an altered message,
  an unrelated key, garbage of the right length — it verifies each case under the
  two witnesses INDEPENDENTLY and asserts they return the same verdict. A single
  disagreement is the break, and the failing case is printed so it reproduces.
  Fresh randomness each run widens coverage release over release
  (`POLARIS_WITNESS_FUZZ_ROUNDS` fuzzes deeper). Proven locally over hundreds of
  rounds: zero disagreements. It runs in the `pqc-real` job via the attack suite.
- **`check_witness_fuzz` (#149)** pins that the fuzzer is real — it verifies under
  both witnesses separately, compares their verdicts, and is registered so the
  runner (and CI) exercises it — with a detection test.

Note on scope: a true NIST FIPS 204 Known-Answer-Test against the official published
vectors is the natural companion, but it needs those vectors fetched from NIST/
Wycheproof, which this environment cannot pull reliably; it is a good follow-up
where there is network access. Differential fuzzing needs no external vectors and
strengthens the same property — that the two witnesses cannot be made to diverge.

Constitutional note: no change to C1-C10 or the vocation. The fuzzer signs and
verifies its own throwaway keys and touches no identity data.

---

## v9.280 — 2026-09-08 (The default boot is the real motor — Phase E complete)

Phase E, PE.1 — and with it the whole engine phase. The one place the engine could
still quietly be a placeholder was the boot: `POLARIS_USE_REAL_PQC` defaulted off,
so a misconfigured deployment could sign with the SHA3-256 development placeholder,
whose bytes verify against no key. This ship closes that.

- **Production fails closed at boot.** When `POLARIS_ENV=production` and real
  ML-DSA-65 signing is not actually available (`pqc_signing.is_enabled()` — the flag
  set AND liboqs importable), the app refuses to start (exit 2) rather than issue
  tokens that authenticate against nothing. The prod compose and Helm already set
  the flag and bake in liboqs; this guard catches a hand-rolled deploy that missed
  it or shipped a broken liboqs, at boot instead of at first issuance.
- **The placeholder is now a named dev profile, not a silent default.** The boot
  announces which signing profile is active (`boot.pqc_profile`), and running the
  placeholder without naming it warns loudly that these are not real signatures. The
  canonical dev/CI paths — the CI test job, `scripts/polaris-test.sh`, and the dev
  `docker-compose.yml` — declare `POLARIS_PQC_PROFILE=placeholder` explicitly.
- **Scoped to production fail-closed** rather than flipping the global default, so
  the many CI jobs that boot the app in placeholder mode keep running. Every
  production context (prod compose, Helm, the prod-image CI jobs) already has real
  PQC, so the guard breaks nothing. `check_real_pqc_default_boot` (#148) pins the
  guard, the named profile and its warning, and the canonical naming;
  `RealPqcDefaultBootTests` exercises the boot refusal.

**Phase E is complete.** All eight engine items shipped: a detached verifier a
relying party runs offline (PE.2), an offline authenticity pack (PE.6), federation
with distinct cryptographic roots (PE.3), the HSM as the sole signer with in-token
rotation (PE.4), attacks that must fail every release (PE.5), a holder wallet that
proves membership in zero knowledge (PE.7), published dyno numbers from a real box
(PE.8), and now a fail-closed real-motor boot (PE.1). The engine runs, detached and
under attack, and every path is exercised — not documented.

Constitutional note: no change to C1-C10 or the vocation. This hardens how the
issuer signs; no identity data path changes.

---

## v9.279 — 2026-09-08 (Real numbers from the box: the engine on a dyno, measured not extrapolated)

Phase E, PE.8. "Ten times faster" is not a number. `scripts/polaris-dyno.py`
measures the engine's real primitives on the machine it runs on and prints them
with that machine's spec and a version stamp: ML-DSA-65 signing and verification
(single-witness verify-at-use and two-witness issuance-grade) and ZK membership
prove/verify at the configured tree depth. If it is slow on your box, it prints
slow.

- **A committed run** (`docs/reference/DYNO.md`), Apple Silicon, 8 cores, one core:
  ML-DSA-65 sign ~2,110/s, verify single-witness ~7,840/s, verify two-witness
  ~740/s; ZK membership prove ~35 ms and verify ~13 ms at depth 14 (a 16,384-leaf
  anonymity set). Every sampled signature verified (2,000/2,000). The single- and
  two-witness figures cross-check the national-simulation run in BENCHMARK.md
  (~7,848 and ~745/s), measured by a different harness — two independent
  measurements agreeing.
- **Measured, not extrapolated.** Every figure is a single process on a single
  core. The fleet arithmetic stays in BENCHMARK.md, labelled a projection. The dyno
  and DYNO.md both keep that distinction, and `check_dyno_published` (#147) fails
  the build if the honesty, the ZK measurement, the box spec, or the CI wiring goes
  missing.
- **Re-measured every release.** CI runs the dyno so the numbers cannot rot: the
  ML-DSA half in the `pqc-real` job (which has liboqs), the ZK half in the `test`
  job (which builds the polaris-zk binary). The liboqs import banner is swallowed so
  `--json` stays parseable (the v9.139 hazard).

Constitutional note: no change to C1-C10 or the vocation. The dyno signs and
verifies its own throwaway keys and touches no identity data.

---

## v9.278 — 2026-09-08 (The holder gets a surface: a wallet that holds, presents, and proves in zero knowledge)

Phase E, PE.7. Everything in Polaris until now was operator-facing — an agency
issues, an operator verifies. `scripts/polaris-wallet.py` is the first tool a
PERSON runs. It is deliberately plain (stdlib plus the detached verifier and the
polaris-zk binary), and it is genuinely holder-side: no server code, no database.

- **Hold a credential as a file.** `enroll --pack` stores an authenticity pack in
  the wallet (`~/.polaris-wallet`, `0700`); `show` displays it offline.
- **Verify it offline.** `verify` runs the detached verifier (PE.2) on the held
  credential — the holder confirms their own credential is authentic with no server.
- **Present it, deniably.** `present` emits a presentation for a relying party.
  `present --duress` produces a presentation that is byte-identical in structure to
  a normal one — same keys, same credential — so an observer cannot tell which was
  used; only the opaque code value differs, and the server matches it out of sight.
  This is the holder's side of the anti-coercion vocation. The vocation-preserving
  default is not to store the duress code on the device; `test_wallet.py` proves the
  indistinguishability.
- **Prove membership in zero knowledge.** `prove-membership --epoch` derives the
  holder's epoch leaf with the issuer's exact recipe
  (`SHA3-256("{token_id}|{token_value}|{context_id}")`), finds its index in the
  published anonymity set, and produces a real Plonky2 proof via the polaris-zk
  binary — a proof that its token is in the set WITHOUT revealing which member. The
  proof round-trips through `polaris-zk verify` (`{"verified":true}`); a non-member
  is refused with nothing to prove.
- **Pinned and exercised.** `check_holder_wallet` (#146) pins the wallet is
  standalone, offers the four capabilities, derives the leaf correctly, and verifies
  through the detached verifier; `test_wallet.py` (in the coverage suite) proves the
  deniability property and the ZK round-trip, both detection-tested.

Constitutional note: no change to C1-C10 or the vocation — this extends it to the
holder. The wallet holds only the holder's own credential and secrets, on the
holder's own machine, and reaches no Polaris server or database.

---

## v9.277 — 2026-09-08 (The HSM is the sole signer: a fail-closed profile and in-token key rotation)

Phase E, PE.4. Polaris already signs inside a PKCS#11 token (ML-DSA-65, in-token,
non-extractable, both witnesses verified in CI), and the trust-anchor set that
makes rotation possible was tested for the file key. Two things were missing to
make the HSM genuinely "the only production signing path": nothing forced the HSM
to be the sole signer, and rotation was never drilled INSIDE the token.

- **A fail-closed sole-signer profile.** `POLARIS_REQUIRE_HSM_SOLE_SIGNER=1` makes
  the app refuse to boot (exit 2) unless the HSM is genuinely the only signer: the
  `pkcs11` driver, `POLARIS_PQC_SIGNING_KEY_FILE` UNSET (no file key sitting in the
  environment as a latent fallback a flipped driver would use), and real PQC on.
  `custody.get_custody()` already never falls back; this guard removes the one
  thing it cannot see, a stray file key, and proves the profile's intent at startup
  instead of at first issuance. `HsmSoleSignerBootTests` exercises the boot refusal
  on all three misconfigurations; `check_prod_fail_closed` pins the guard.
- **In-token key rotation, drilled.** `test_in_token_rotation_old_token_still_verifies_new_key_signs`
  mints a SECOND ML-DSA-65 key inside a real Kryoptic token under a new label,
  signs a token under the old in-token key, rotates (new key current, old key a
  listed trust anchor), and proves the old token STILL verifies while new issuance
  signs under the new key — then drops the old anchor and confirms the old token
  no longer verifies (retirement complete). Runs against the real token in the
  `custody-pkcs11` job; `check_key_rotation_drilled` (#145) pins it.
- **Docs.** `docs/operator/KEY-CEREMONY.md` gains the HSM-sole-signer profile and
  the in-token rotation drill.
- **Note.** The software token is Kryoptic (the ML-DSA-capable PKCS#11 v3.2 module;
  SoftHSMv2 does not implement ML-DSA). PE.4 does not depend on PE.1 after all: the
  profile enforces real PQC itself.

Constitutional note: no change to C1-C10 or the vocation. This hardens how the
issuer key is held and rotated; it changes no identity data path.

---

## v9.276 — 2026-09-08 (Two issuers on one box: federation with distinct roots, proven cryptographically)

Phase E, PE.3. Polaris already carried a federation trust graph
(`AgencyTrustAttestation`, `_federation_trust_holds`), but on its own that is
administrative: DB rows saying agency A trusts agency B, on top of a SINGLE signing
key. Every token shared one cryptographic root, so "issuer" was not something a
relying party could check without trusting Polaris's database — a diagram. This
ship puts the root underneath it.

- **`scripts/polaris-federation-drill.py`** — two issuers on one box, each a
  DISTINCT ML-DSA-65 root, plus a third issuer outside the federation. It issues a
  genuine token under each through the real signing path and proves, with the
  detached verifier, the full trust matrix: a relying party accepts its own issuer,
  REJECTS a foreign issuer, and rejects the outsider — decided on the signing KEY
  (`issuer_trusted` against a published anchor set), not an `agency_id` row. A
  relying party trusting the set `{A, B}` accepts both and still rejects the
  outsider. The drill exits non-zero if any accept/reject is wrong, so a broken
  federation boundary turns CI red. It runs in the `pqc-real` job under real
  ML-DSA-65.
- **The boundary is also an attack.** `attacks/attack_crypto.py` gains
  `outsider_accepted_by_federation_set`: an issuer outside a two-issuer trust set
  is internally valid but must be rejected (the multi-key anchor path must not
  accept a non-member). Eight crypto adversaries now, all held.
- **`check_federation_real` (#144)** pins that the drill is cryptographic (distinct
  roots, the detached issuer anchor, a verdict keyed on `issuer_trusted`), that it
  tests REJECTION and not only acceptance, that it is fail-closed, that CI runs it,
  and that the cross-issuer adversary lives in attacks/. Detection-tested.
- **Honest scope.** This makes the federation boundary real and running at the
  cryptographic layer. Binding each Agency to its own key INSIDE the app, so
  `/uc1/issue` and `/verify` are federation-aware end to end above the existing
  administrative trust graph, is noted as PE.3b (not blocking).

Constitutional note: no change to C1-C10 or the vocation. The drill is self-contained
crypto (its own temporary keys); it touches no database and no personal data.

---

## v9.275 — 2026-09-08 (Attacks that must fail: an adversary suite run every release, not greps)

Phase E, PE.5. The engine is only as strong as what it rejects, so this ship adds
`attacks/`: adversaries that actively try to break a real defense against the real
code. An attack SUCCEEDS when the defense fails to stop it, and the rule is simple:
run every release, and if any attack succeeds the build goes red. This is the
opposite of a grep. A grep proves a line exists; an attack proves the defense holds
when something hostile is thrown at it.

- **`attacks/run_attacks.py`** — the runner. Exit 0 iff every attack failed to break
  its defense; exit 1 if any attack SUCCEEDED; exit 3 if a requested suite could not
  run or an attack crashed (a hard error, never a silent green, so a 0 always means
  the defenses actually held).
- **The crypto suite (`attack_crypto.py`, real ML-DSA-65).** Seven adversaries thrown
  at the detached verifier's `verify_pack` and the app's own two-witness
  `verify_stored_signature`: a forgery signed with an attacker key (rejected as
  not-issuer against the anchor), a one-byte-tampered signature, a genuine signature
  against an altered token, a wrong key, the SHA3 placeholder relabeled as a real
  signature, an empty signature, and a tamper thrown at the app's two-witness verify.
  All must fail; all do. Runs in CI's `pqc-real` job.
- **The db suite (`attack_db.py`, app + Postgres).** The replay defense: issue a real
  signed token, revoke it through the real `uc8` procedure, and present it to
  `/verify`. The signature stays authentic (permanent) while `currently_authoritative`
  and `usable` go False — an authentic-but-revoked credential is not current. Runs in
  CI's `test` job.
- **`check_attacks_run` (#143) does not grep the runner — it EXECUTES its contract.**
  It loads `run_attacks.py`, drives it with an in-process canary, and asserts a
  succeeding attack yields exit 1, an all-held run yields 0, and a non-runnable suite
  yields 3. A runner that stopped failing on a successful attack fails this check.
  It also pins that CI runs both suites and that the key adversaries (forge, tamper,
  revoked) are not silently removed, each with a detection test.

Constitutional note: no change to C1-C10 or the vocation. The attacks read and
verify; the one that writes (the db suite) issues and revokes through the real
authorized procedures on the test database, exactly as an operator would.

---

## v9.274 — 2026-09-08 (The engine, not the wrap: a detached verifier a relying party runs offline)

The owner called it: too much effort on the wrap of the car (consoles, ontology,
presentation), too little on the engine (the cryptographic primitives as things
that run detached, for real, under attack). The test of engine work is
displacement, a path that runs without anyone watching, not a document that says
the path exists. The roadmap is remade engine-first (a new active Phase E), and
this ship is its flagship: Polaris's ML-DSA-65 signatures can now be verified by
someone other than Polaris, offline, with no Polaris code and no database.

- **A detached verifier (`scripts/polaris-verify.py`).** A standalone CLI a
  relying party runs with only a standard ML-DSA-65 library; it imports no Polaris
  code and no database driver. It reads an authenticity pack, reconstructs
  `SHA3-256(token_value)`, and verifies the signature under two independent
  witnesses (liboqs and cryptography/OpenSSL), exactly as issuance does. Exit 0
  iff the signature is valid; a placeholder is reported as not-authenticatable,
  never as a green check.
- **An authenticity pack the app exports (`GET /api/tokens/<id>/authenticity-pack`).**
  The deliberate opposite of `/export`, which strips the signature and key bytes:
  this route EXPORTS them (token_value, signature, public key, algorithm, and a
  `digest_construction` field) so there is something to verify offline. It carries
  authenticity, never authorization; whether a token is usable now stays the
  online `/verify` question.
- **Published test vectors (`vectors/`).** Five fixed authenticity packs anyone
  can re-verify offline: a genuine one, three tampered ones (a flipped signature,
  an altered token, a wrong key) that must fail, and the placeholder. They were
  produced by an INDEPENDENT FIPS-204 implementation (dilithium-py), and CI's
  `pqc-real` job re-verifies every one under liboqs AND cryptography/OpenSSL on
  every release: three implementations agreeing, not one agreeing with itself.
- **Exercised, not merely present.** CI runs `polaris-verify.py --selftest` (a
  live ML-DSA-65 round-trip: a genuine pack verifies; a flipped signature, an
  altered token and a wrong key each fail; the placeholder is refused) and
  `--verify-dir vectors`. `check_detached_verifier` (#142) pins that the verifier
  is standalone (no Polaris or DB imports), does the real crypto, that the pack
  route exports the signature, that the vectors carry their expectations, and that
  CI runs it, each with a detection test. `AuthenticityPackTests` proves the DB
  round-trip: issue a token, export its pack, run the real detached script on it,
  and get the correct verdict.
- **Roadmap remade engine-first.** A new active Phase E carries the eight engine
  items in order: the real default boot; the detached verifier (this ship); two
  issuers on one machine; the HSM as the sole production signer with rotation;
  attacks that must fail every release; the offline pack (this ship); a holder
  CLI; and published numbers. The wrap is frozen behind it: further Atlas and
  Athena and ontology surface, invariants that only read a file, and any
  "national"-scale expansion yield until Phase E's exit gate is met.

Constitutional note: no change to C1-C10 or the vocation. The pack exports only
authenticity material a logged-in operator can already see; it is audit-logged
and replica-routed like `/verify`, and carries no authorization state. C6 holds
(zero-knowledge verifications carry no token id, so nothing in this path can
locate one).

---

## v9.273 — 2026-09-08 (Honesty pass: shrink every claim to what the code does now)

Before continuing the scale work, a pass over every outward-facing surface to
make sure it states what Polaris is NOW, and never overstates. Polaris models a
national identity-token system; it is a reference implementation on notional
data, not a deployment. Underclaim over overclaim, macro to micro.

- **The social card and browser tab.** The site `<title>`, `og:title` and
  `og:site_name` presented Polaris AS a national identity system; they now name
  it a reference implementation (the visible page already did).
- **"Where Polaris sits."** The comparison gains a "Deployed to a real
  population" column where Polaris is the sole X, so its design ticks read as
  design properties, not deployment parity with Real ID / Aadhaar / mDL.
- **Hardware honesty.** "one physical token per person" -> "one token per
  person" (the physical artifact is modeled, not manufactured); the "PKCS#11
  token" is now named a software module (Kryoptic), not a hardware HSM.
- **Scoped absolutes.** The unlinkability claim is scoped to zero-knowledge
  events (SELECTIVE and FULL carry a token id); the duress "pixel-identical /
  every surface shows success" is qualified as a tested property of the modeled
  flow, not an audited side-channel guarantee; "the complete working system" and
  "production stack" become "a reference implementation" and "the production
  profile"; "hundred million events" ties to the measured ten million.
- **The edge-reload claim matches the measurement.** "an edge reload with no
  window at all" was disproven by the window drill itself (a graceful Caddy
  reload occasionally drops one in-flight request at a listener swap). The drill
  now asserts a small transient budget instead of an absolute zero, and the
  README / PRODUCTION-READINESS claims say so. This also ends a CI flake that hit
  every recent ship.
- **De-"certification" carried into the benchmark doc; drill latencies labeled
  CI/single-host; count and image drift reconciled (five images, 30/37 tables).**

`check_public_claims_honest` (with a detection test) guards the title, the
comparison column, and the retired overclaim phrases from creeping back. 141
checks (was 140).


## v9.272 — 2026-09-07 (The two-witness availability clause: continuous sampling)

P1.18 item 5. Single-witness verify-at-use is ~10x the two-witness issuance
check, but that speed is only sound while the fast witness stays trustworthy.
This makes that assumption continuously checked rather than trusted on faith.

`GET /api/tokens/<id>/verify` now replays a random fraction of successful
single-witness checks (`POLARIS_VERIFY_SAMPLE_RATE`) through the SECOND witness.
Any disagreement increments `polaris_verify_witness_disagreements_total` and fires
`PolarisWitnessDisagreement` (a SEV-1 with a runbook) — a paging event, not a log
line, because a fast witness diverging from the two-witness reference breaks the
throughput soundness argument. Every response names which witness set actually
ran (`witnesses`: `single` on the fast path, `both` when sampled, plus a
`sampled` flag). Sampling is MANDATORY in production: the rate is floored above
zero there, so two-witness verification can never be silently disabled. The
sampling read is read-only — the fast path never changes authorization state.

`check_verify_witness_sampling` (with a detection test) pins the whole clause
(sampling through the second witness, the paging metric + alert, the witness-set
naming, and the production floor); `VerifyWitnessSamplingTests` proves the naming
and that a forced disagreement pages. 140 checks (was 139).
docs/design/verification-scaling.md and the PolarisWitnessDisagreement runbook.


## v9.271 — 2026-09-07 (Verify-at-use: an explicit authenticity/authorization split)

P1.18 item 4, the highest-value backend change: make the verify endpoint's
freshness contract explicit, so a relying party can never confuse a genuine
signature with a currently-usable token. Builds on v9.264 (which already read
authorization from the primary); this names the two verdicts and states their
freshness.

`GET /api/tokens/<id>/verify` now returns two clearly-separated verdicts:
- **Authenticity** — `signature_valid` with `signature_cacheable: true`. Immutable
  material (the signed token value, the signature bytes, the stored key), so it
  is replica-safe and a relying party MAY cache it.
- **Authorization** — `currently_authoritative` (status is ACTIVE), read fresh
  from the primary, carrying `as_of` (the primary clock at the read) and
  `max_staleness_seconds: 0` (primary-backed, no replica lag). A caller must NOT
  cache this; the `as_of` / `max_staleness_seconds` pair states exactly how fresh
  the verdict is. If a deployment ever routes the authorization read to a replica
  for scale, that is the single field it raises — the API shape is stable.

`usable` is kept as a back-compat convenience (`signature_valid` AND
`currently_authoritative`). `check_pqc_signing_wired` now pins the split (the
endpoint must expose `signature_cacheable`, `currently_authoritative`, `as_of`
and `max_staleness_seconds`), and `TokenVerifyTests` proves a revoked token stays
authentic (cacheable) while ceasing to be currently authoritative.
docs/design/verification-scaling.md and the API reference document the contract.
No new check (139).


## v9.270 — 2026-09-07 (The constitution, layered: constitutional vs engineering)

P1.18 item 3: split the ten constraints into two tiers beneath the vocation, so
different classes of guarantee stop looking equivalent. This is a MISSION.md
amendment, kept deliberately shallow — two levels, not a governance hierarchy.

- **Constitutional (rights guarantees, C1, C2, C3, C6, C10):** append-only
  accountability, anti-linkability, one identity per person, disclosure
  sovereignty, and identity-is-not-money. Relaxing one changes what Polaris *is*;
  they may not be moved without the amendment process.
- **Engineering invariants (C4, C5, C7, C8, C9):** an atomic failed-login
  counter, a no-inline-scripts CSP, cryptography named in a registry, bounded
  aggregation, and concurrency proven with real threads. Load-bearing and
  machine-checked, but best-practice controls, not rights guarantees.

The only substantive reclassification is **C6 (server-side disclosure)**, promoted
from the engineering discipline into the constitutional tier: a person controlling
what a verifier learns is a rights guarantee, not a convenience.

MISSION.md's hard-constraints table gains a **Tier** column; the README guarantees
table mirrors it; and Athena's `athena_constitutional_rule` gains a `layer`
column (surfaced in the `/athena` Constitution tab as a tier badge). The new
`check_constitution_layered` (with a detection test) fails the build if MISSION.md
and Athena disagree on any rule's tier, or if a rule is reclassified between tiers
without it being a visible change. The hierarchy is one line deep — vocation, then
constitutional, then engineering — with no deeper apparatus (see v9.55). 139
checks (was 138).


## v9.269 — 2026-09-07 (Schema quarantine: the science-fiction scaffolds are gone)

P1.18 item 2: remove the two science-fiction scaffold tables that served no
current guarantee or milestone, continuing the v9.55 apparatus-removal discipline.

**GenomicAnchor** (a per-token hash commitment framed as DNA/genomic anchoring,
with a `{A,C,G,T,U,N}` "genomic alphabet" CHECK) and **QuantumObserverBinding**
(a "quantum-observer measurement" scaffold with a `wavefunction-collapse` hash,
`BB84-WITNESS` protocol vocabulary, and — by its own documentation — no planned
use) are removed from the live schema. Neither was read by any procedure,
trigger, view, or application path; a national-identity schema should not carry
DNA-alphabet or wavefunction vocabulary without an extraordinary reason.

Removed from `01_schema.sql`, `02_indexes.sql`, `04_data.sql`, the substrate
manifest (`13_substrate.sql`, where the reserved quantum-observer slot is
replaced by the real hardware dependency it always had — PKCS#11 HSM / KMS key
custody), the DB test suites, and the operator/reference docs;
`docs/design/quantum-observer.md` is deleted. A reversible migration
(`2026-09-07-002-drop-scifi-scaffold`) drops them from existing deployments.
The academic report's Appendix F, which discusses genomic and quantum-observer
binding as explicitly *speculative future work*, is untouched — it never claimed
these were implemented.

`check_no_scifi_schema` (with a detection test) fails the build if either table
or its vocabulary returns to the live schema. **30 tables** (was 32); **37 in a
migrated deployment** (was 39); **138 checks** (was 137). Full DB suites green.


## v9.268 — 2026-09-07 (Public claim pass: precise zero-knowledge, no "certification")

P1.18 item 1, the claim-and-proof season's first step: fix the nouns before
adding features. The system's public claims now say exactly what the
implementation proves, no more.

**Zero-knowledge, split into three precise things.** The README title and the
site drop the umbrella phrase "post-quantum, zero-knowledge ... system" (which
reads as general anonymous credentials) for "post-quantum, unlinkable-by-default,
compulsion-resistant." The body states the boundary explicitly: (1) *unlinkable
verification records* — a default zero-knowledge-mode verification stores no
token identifier, so the verification graph cannot be rebuilt from the database
(C2); (2) a *Merkle-membership proof* (a Plonky2 SNARK) that proves a token was
in a published ledger and nothing else; and Polaris is **not** a general
selective-disclosure or anonymous-credential system, and does not claim to be.
The "Where Polaris sits" comparison relabels its column "Unlinkable verification
default" and corrects the W3C VC row to method-dependent. `check_zk_claim_precise`
(with a detection test) keeps the umbrella from creeping back and requires the
boundary sentence to stay.

**Extrapolation is no longer called "certification."** P2.9 is renamed "10M-
profile capacity model (single-node measured, multi-node projected)"; its verbs
soften from "certifies" to "demonstrates," matching the row's existing honesty
that the 10M multi-node figure is extrapolated from single-node numbers. The FIPS
/ 800-63 external-certification uses of the word are untouched — those are real
certifications, granted by others.

137 checks (was 136). The README was already clean of mythology and national-
rollout framing above the fold (the v9.194-v9.205 rework), so no narrative
surgery was needed here. The rest of the season (schema quarantine, the
constitutional split, the verify-API and two-witness contracts, one measured HA
report, the proof-of-life artifacts, the external-review packet) is tracked under
ROADMAP P1.18.


## v9.267 — 2026-09-07 (Athena console: the authority-and-constitution surface)

The operator-facing console for the v9.266 Athena layer (roadmap P6.8's next
step). `/athena` is a read-only, four-tab surface that turns the SQL layer into
something an operator clicks. `docs/design/athena.md`.

**Constitution** (server-rendered): C1-C10 and the Vocation as cards, each with
its live enforcement mechanisms shown as kind-badged chips (trigger / index /
CHECK / check_* / procedure). **Authority**: pick an agency and an algorithm and
"Explain" resolves the authority chain (a red "Not authorized to issue" when no
`may_issue` grant exists); pick an algorithm and see the deprecation blast radius
(authorized agencies, served contexts, post-quantum successors). **Proof policy**:
a context's requirements and the three C6-enforced disclosure levels.
**Trust graph**: the current attestations (revoked and expired excluded).

Three drill-down endpoints (`/api/athena/authority-chain`,
`/api/athena/affected-by-algorithm`, `/api/athena/explain-proof`), all
login-gated and replica-routed. The console reads only the person-free Athena
layer — no Individual, token, or event table — and renders every result with
`createElement` (never `innerHTML` with markup), so `script-src 'self'` stays
strict (C5). `check_athena_console` pins all of that with an adversarial
detection test, and the headless-browser UI drill now opens `/athena` and asserts
the 11 rules, their 18 live mechanisms, and a resolving authority chain in a real
browser. 87 routes (was 83); 136 checks (was 135). Full suite green.


## v9.266 — 2026-09-07 (Athena: the authority-and-constitution layer)

Roadmap P6.8, the constrained ontology the assessment endorsed. Athena is a
read-only semantic and provenance layer over the *authority* tables, plus a
first-class model of the constitution: C1-C10 and the Vocation as queryable
rows, each linked to the exact live mechanism that enforces it.
[`polaris_sql/16_athena.sql`](polaris_sql/16_athena.sql),
[docs/design/athena.md](docs/design/athena.md).

**Governance questions become mechanical.** Ten object and eight edge views over
`Agency`, `AgencyAlgorithmAuth`, `CryptographicAlgorithm`, `VerificationContext`,
`AgencyTrustAttestation`, and `RetentionPolicy`, and four functions:
`athena_authority_chain` (why may this agency issue under this algorithm),
`athena_explain_proof` (what disclosure policy bounds this context),
`athena_affected_by_algorithm` (the blast radius of a deprecation — authorized
agencies, served contexts, post-quantum successors), and
`athena_rule_enforcement` (which mechanism enforces a constitutional rule). Each
view is a SELECT over an existing table, so Athena has no independent authority
store; it describes and orchestrates authority, never manufactures it.

**The constitution stops drifting from the code.** `athena_rule_enforcement`
maps every rule to the exact trigger, partial unique index, named CHECK
constraint, `check_*` function, or stored procedure that enforces it, and
`check_athena_rule_enforcement_resolves` fails the build if any named mechanism
no longer exists — closing the prose-drift gap `meta/constraint-lattice.md` has
today. `AthenaOntologyTests.test_rule_enforcement_map_matches_live_catalog`
proves each mechanism is present in the running catalog.

**Person-legibility is structurally impossible.** Five checks, each with an
adversarial detection test: `check_athena_no_person` (no person table/column, no
per-person surrogate), `check_athena_read_only` (STABLE, non-mutating, never
SECURITY DEFINER), `check_athena_functions_bounded` (every function LIMIT-capped;
an event-touching one inherits the Atlas C8 window), `check_athena_non_sovereign`
(authority edges resolve to real tables, current views exclude revoked authority,
only descriptive curated tables), and the rule-enforcement resolver. The same
ship removed the v9.19 `v_ontology_individual` / `v_ontology_individual_tokens`
person-aggregating views; that single-entity data now lives only on the audited,
login-gated `/investigate/individual/<id>` route. 135 checks (was 130); 39 tables
in a migrated deployment (was 36, the three descriptive curated Athena tables).


## v9.265 — 2026-09-07 (Atlas Trends: temporal rhythm + composition over time)

Ship 7 of the Atlas rebuild (P2.3): a Trends tab that answers "when does the
nation verify, and how is the activity composed" — two bounded, non-geographic
aggregates, hand-rolled SVG (so script-src 'self' stays strict, C5), driven by
the same global filter as the rest of the console.

**Temporal-rhythm heatmap.** `atlas_heatmap` bins events by ISO weekday x hour of
day into at most 7 x 24 = 168 cells (C8), rendered as a green-intensity grid.
The business-hours ridge and the weekend trough are visible at a glance; a
zero-knowledge verification is counted in its cell but never located (C6).

**Composition over time.** `atlas_series_stacked` breaks volume out by one
whitelisted dimension (context / outcome / disclosure / agency / jurisdiction),
top-K by volume with the rest folded into a single 'Other' band, rendered as a
stacked-area chart with a dimension selector. A band widening or a context
surging shows immediately. Bounded to buckets x (K+1) (C8).

Both window on `event_timestamp >= COALESCE(p_since, '-infinity')`, so a windowed
query prunes the monthly partitions under the generic plan (the v9.260
discipline); both are `@replica_reads` and cached; the endpoints
(`GET /api/atlas/heatmap`, `GET /api/atlas/stacked`) reject a bad dimension or
bucket count with 400.

Verified in a real browser: the UI drill (v9.262-263) now also opens the Trends
tab and asserts the heatmap renders 168 cells and the composition chart renders
its stacked bands. `check_atlas_console` pins the two aggregates (bounded +
partition-pruned), the two replica-routed endpoints, the whitelisted stacked
dimensions, and the Trends tab's mounts; the detection test perturbs each. New
DB tests cover the endpoint shapes, the C8 bounds, the C6 ZK counting, and the
400s. `AtlasTrendsAPITests`. 83-route application (was 81). Full suite green.

---

## v9.264 — 2026-09-07 (Two integrity fixes: issuance can't degrade to one witness; usable is decided on fresh state)

Two soundness gaps in the verification claims, found in review, are closed here.

**Issuance may not silently degrade to one witness.** The claim is that every
stored production signature was independently verified by two implementations
(liboqs AND OpenSSL/cryptography). But `verify_both` falls back to the lone
primary when the second witness library is unavailable — fine for the
re-verification and display paths, where the signature was already two-witnessed
at issuance, but NOT for issuance itself, where the claim is made. If the witness
were missing at issuance time, a signature could be stored as "two-witnessed"
having been checked by only one implementation. Fixed: issuance passes
`verify_both(..., require_witness=True)` (a missing witness is a refusal, not a
downgrade) and `signature_with_key_for_token` refuses up front when
`second_witness_available()` is false. Real ML-DSA-65 is only persisted when the
second witness genuinely ran. The verify-at-use and display paths still tolerate
a missing witness, since they only re-confirm an already-two-witnessed signature.

**`usable` is decided on fresh state, not a stale replica.** `GET
/api/tokens/<id>/verify` is replica-routed for throughput. Signature authenticity
is a property of IMMUTABLE material (the signed value, the signature bytes, the
stored key), so reading it from a replica is safe. But `usable` also asks "is
this token authorized NOW?", and a revocation flips `status` to REVOKED on the
primary; a replica inside its staleness window could still show ACTIVE for a
just-revoked token. Fixed by separating the two: the signature material stays
replica-eligible, but the `status` that decides `usable` is pinned to the PRIMARY
(`query(..., primary=True)`, a new option), and the response carries
`status_source: primary`. The primary read is a tiny indexed point-lookup and the
ML-DSA verify touches no database, so throughput is preserved.

`check_pqc_signing_wired` now pins both: issuance requires the witness
(`require_witness=True` + the up-front refusal), and the verify endpoint decides
`usable` on a primary-read status. The detection test perturbs each. New tests
prove issuance refuses without the witness, that `require_witness=True` refuses a
missing witness while the default path still tolerates it, and that the verify
response is `status_source: primary`. Full suite green.

---

## v9.263 — 2026-09-07 (The UI harness runs on every push)

v9.262 built the headless-browser UI harness but left it on demand. This wires it
into CI as its own job, so the Atlas UI is verified in a real browser on every
push — not just when someone remembers to run it.

A new `ui-drill` job (Playwright, headless Chromium) mirrors the product suite's
setup — Postgres 16, the app stack, the schema and migrations loaded — then runs
`scripts/polaris-ui-drill.sh`, which boots the app with SIM_MODE on and drives
the Atlas: log in, click Simulate, and assert the console actually streams (the
sim counter climbs AND the Overview aggregate grows). It runs in its own job with
its own database because the simulation streams events into it, and the
screenshots upload as an artifact either way, so a run can be looked at. Chromium
is installed with `playwright install --with-deps chromium`, the same as the
existing Atlas e2e step; the Playwright package already ships in
`requirements-dev.txt`.

`check_ui_drill` now also pins that `ci.yml` runs the drill in a `ui-drill` job
(not just that the script exists), and the detection test confirms it fails when
the CI wiring is removed. 16 CI jobs (was 15). Full suite green.

---

## v9.262 — 2026-09-07 (A headless-browser harness to watch the UI, and the live-sim cache fix it drove)

v9.261 shipped the Atlas live simulation mode but with a gap: its endpoint was
tested, its live UI never watched running. This closes that with an instrument
that lets a UI ship be verified end to end in a real browser — and, on its first
run, that instrument earned its keep.

**The harness.** `scripts/polaris-ui-drill.py` drives the real Atlas in a bundled
headless Chromium (Playwright), and `scripts/polaris-ui-drill.sh` boots the app
with SIM_MODE on and runs it — installing Playwright + Chromium on demand (like
the PKCS#11 drill installs Kryoptic), so there is no standing dependency. It logs
in, opens the Atlas, clicks Simulate, and ASSERTS the console actually streams:
the sim counter climbs AND the Overview 'Verifications' aggregate grows, with
screenshots captured as evidence. A real pass/fail test of the JavaScript, the
fetches and the live DOM — not a screenshot dump.

**What it caught, and the fix.** On its first run the counter climbed to 288
while the Overview KPI sat at 8: the 30 s aggregate cache was serving the
pre-simulation state, so the charts lagged the stream badly. The live view is
supposed to be live. Fixed by bypassing the aggregate cache under SIM_MODE
(`_atlas_cache_get` returns None) — dev/demo only, and the roll-ups are bounded
and partition-pruned (v9.260), so recomputing each refresh is cheap. Production
is untouched: SIM_MODE is force-off there. The harness now asserts the aggregate
grows, so the lag cannot come back unnoticed.

`check_ui_drill` (invariant #130, was 129) pins the harness (a real browser, the
sim control, the climb + growth assertions, the on-demand Chromium install) and
the SIM_MODE cache bypass; the detection test removes each and confirms it turns
red. Full suite green.

---

## v9.261 — 2026-09-07 (Atlas live simulation mode)

The national simulation could already load a synthetic nation and stream its
life through the real system (S1-S3), and the benchmark drove the first hardening
ship (v9.260). This closes the other half of what was asked for — "a test
simulation mode for atlas ... things happening ... in real time": a live control
in the Atlas that streams notional national activity and lets an operator watch
the console light up (roadmap P2.14 S4).

**Client-driven, by design.** An operator clicks *Simulate* and the browser
drives the stream: each tick POSTs a bounded batch to `/api/sim/tick`, which
writes through the SAME `polaris_sim` path the benchmark uses (the real
`INSERT INTO VerificationEvent` and `uc8_revoke_token` procedures, ZK rows
carrying no location, C6), and then the console refreshes — the volume series
climbs, the breakdown shifts, the map lights up. Because the loop lives in the
browser, there is no server-side background thread: correct for the multi-worker
gunicorn model, where an in-process streamer would fork into every worker and its
start/stop state would not be shared. The map refreshes live too, off a new
`polaris:atlas-refresh` event.

**Triple-gated out of production.** `SIM_MODE` is `_env_flag('POLARIS_SIM_MODE',
False) and not _PRODUCTION` — explicit opt-in, and force-off under
`POLARIS_ENV=production` like `DEMO_MODE`. The `/api/sim/tick` route `abort(404)`s
when `SIM_MODE` is off, so the control is never rendered and the route is
effectively absent. And the writer itself gained the hard isolation gate the
harness was missing: `polaris_sim.assert_expendable()` refuses
`POLARIS_ENV=production`, and `run_stream` / `build_nation` call it before any
write, so even a direct CLI invocation cannot touch a production database. Sim
events, like all events, are append-only (C1) — there is no delete — so this runs
on an expendable database.

`check_sim_mode_gated` (invariant #129, was 128) pins all three gates; the
detection test removes each and confirms the check turns red.
`AtlasSimulationModeTests` proves the tick streams events through the real path,
is bounded, requires login, and 404s when the gate is off; `IsolationGateTests`
proves the writer refuses production. 81-route application (was 80). Full suite
green. See [DEVNOTES/national-simulation.md](DEVNOTES/national-simulation.md).

---

## v9.260 — 2026-09-07 (Atlas roll-ups prune the partitioned event table)

The national benchmark's first hardening lead was the scan-based Atlas roll-ups.
Chasing it found the real cause: the roll-ups did not PRUNE the monthly-partitioned
event table, so a windowed query ("last 24h") scanned every month of history
instead of one partition. This ship closes that, benchmark-driven — the first
ship of the P2.14 hardening loop.

**The bug was invisible in a custom plan and real in the generic one.** The
roll-ups reached the window through `p_since IS NULL OR event_timestamp >= p_since`
(and, in the time-series functions, through a `params` CTE column). With a
literal `since`, PostgreSQL prunes; but a parameterized statement gets a GENERIC
plan after a few executions — the path the app actually runs — and under it both
shapes defeat pruning entirely. A forced-generic EXPLAIN showed a recent-window
`atlas_breakdown` scanning all N monthly partitions. At a year of history that is
a 12x read amplification; at the national retention horizon, far more.

**One predicate shape fixes every roll-up.** `event_timestamp >= COALESCE(p_since,
'-infinity'::timestamp)` prunes a concrete window to its partitions under the
generic plan, while a NULL (all-time) query resolves to `>= -infinity` and
correctly scans them all. The results are identical to before — only the plan
changed — so every existing Atlas test passes unchanged. Applied across
`atlas_timeline`, `atlas_volume_series`, `atlas_breakdown`, `atlas_crosstab`,
`atlas_geo_jurisdictions`, `atlas_hexbin`, `atlas_records` and `atlas_agency_facet`;
it deploys through `polaris-migrate.sh --sync-objects` like any object change.

**Proven, and re-benchmarked.** `check_atlas_rollups_prune` (invariant #128)
forbids either pruning-defeating shape from returning; `AtlasPartitionPruningTests`
proves the pruning under a *forced generic plan* (a far-future window drops every
month partition; an all-time query keeps them all); and the national benchmark
now measures the partitions a recent window scans versus an all-time query and
fails the run if pruning regresses (`atlas_windowed_query_prunes`). An all-time
aggregate is still O(events) — a materialized roll-up remains the next lever if
all-time reports become hot — but the operational windowed queries now stay flat
as history grows. See [docs/design/atlas-scaling.md](docs/design/atlas-scaling.md).

---

## v9.259 — 2026-09-07 (Verification holds through HA: rolling deploy drops zero, failover recovers)

v9.258 made real ML-DSA-65 verification fast (single-witness verify-at-use) and
projected it fans out across an HA fleet. This ship proves the fleet claim where
it is hardest to fake: both CI HA drills now hold a REAL, authenticated
verification load on `GET /api/tokens/<id>/verify` across the transition, so the
survival of the verification path through a rolling deploy and a database
failover is measured, not asserted. This closes the roadmap's P2.9.

**A new load generator, `scripts/polaris-verify-load.py`.** Pure stdlib, so it
runs on a bare CI runner. It logs in once, keeps the session, and re-verifies a
set of active tokens at a steady rate, with STRICT accounting: only HTTP 200 is
served; 429 is the edge rate limiter (tolerated); everything else — a 302 (the
session was lost), a 5xx (a backend gap during a failover), a transport error —
is a DROP. A `--once` mode is the post-failover recovery probe. The accounting
policy (`classify`) and the login/recovery flow are unit-tested against an
in-process stub server (`scripts/test_verify_load.py`), run under coverage.

**Two honest claims, because the two operations differ.** The rolling deploy is
app-tier: a colour is always up behind the retrying edge, so the drill certifies
**zero dropped verifications** across the rollover, the bar its health traffic
already meets. A database failover is different: a verify request is a read, and
during the failover window reads drop exactly as writes do, because a promoted
replica or a healed partition takes a bounded time. So the failover drill does
not assert zero — it asserts **recovery**: under a continuous verification load
it induces four failures (a leader crash, a lease partition, a switchover, an
etcd crash) and confirms verification returns 200 again after every one, and
kept serving at rate throughout.

**Bootstrapping a real operator.** Production disables the demo accounts, so each
drill computes an scrypt hash inside the app container (which carries werkzeug;
the CI runner does not) and inserts a real admin the load authenticates against.

`check_verification_load_certified` pins the load generator's strict accounting,
its test being run under coverage, and both drills' use of it (the rolling drill
asserting zero verification drops, the failover drill probing recovery after
each of the four scenarios plus a served floor); the detection test perturbs
each. 127 invariant checks (was 126). Full suite green; coverage held.

---

## v9.258 — 2026-09-07 (Single-witness verify-at-use: real PQ verification from hundreds to thousands/sec)

The v9.257 benchmark established the honest cryptographic-verification number:
real ML-DSA-65 at ~740/s on one core, because every check ran two witnesses
(liboqs AND OpenSSL, both must agree). A national deployment needs thousands per
second, sustained through failover and rolling deploys. This ship takes it there
without weakening the guarantee that matters, and it is the first step of the
national-deployment-readiness path (P2.9).

**The two-witness cost belongs at issuance, not at every use.**
`signature_with_key_for_token` already two-witnesses the signature it produces
and refuses to persist it unless both implementations accept it, so a stored real
signature is, by construction, known to verify under both. Verification *at use*
therefore does not need to re-run both: one witness (liboqs) re-confirms
authenticity and detects any tampering or substitution. A tampered or forged
signature still fails single-witness verification; only the redundant second
implementation of the same check is dropped on the throughput path.

**`verify_stored_signature(..., witnesses="single")`** is the opt-in. The
two-witness path stays the default and remains the strict display path, so
nothing silently weakens. Measured on this machine: single-witness ~7,800/s vs
two-witness ~740/s per core, ~10x. Because verification needs only the public
key (no custody, no HSM, no private key) it is embarrassingly parallel: it fans
out across gunicorn workers and HA replicas with no shared secret, ~62,000/s
projected on an 8-core node before adding replicas.

**`GET /api/tokens/<id>/verify`** (login-gated, replica-routed) is the
throughput-oriented verification capability: it cryptographically verifies a
token's active signature single-witness and returns whether the signature is
authentic, whether the token is currently usable (valid AND ACTIVE), and the
per-signature result, a seed of the roadmap's P3.4 relying-party API. The
`docs/design/verification-scaling.md` note records the security rationale, the
numbers, and the fan-out model; [BENCHMARK.md](docs/reference/BENCHMARK.md) and
the `polaris_sim` benchmark now report both witness rates and the fleet
projection.

**Proven.** `check_pqc_signing_wired` now also pins that issuance two-witnesses
(`verify_both`), that the verify-at-use endpoint exists, and that it uses
`witnesses='single'`; the detection test perturbs each (issuance weakened to one
witness, the endpoint removed, the endpoint switched back to two-witness) and
confirms the check turns red. Under HA, failover and rolling deploys the verify
path inherits the read-only replica-routed properties the existing drills prove;
certifying the throughput specifically through an induced failover and a rolling
deploy is the next step (closes P2.9).

---

## v9.257 — 2026-09-07 (Bulk signatures are real; event vs cryptographic verification)

Two integrity gaps were found in the scale work and are closed here. First, the
bulk pipeline stored a `BULK_ISSUE_<id>` placeholder literal with no public key:
the database believed a signature existed while the token was cryptographically
unsigned, so the national simulation's mass-issued identities were not actually
valid. Second, the benchmark's "verifications/s" measured verification-EVENT
ingestion (audit-row writes), not cryptographic signature verification, and the
two are an order of magnitude apart. Neither should be claimed as more than it
is.

**Bulk enrollment signs for real.** `BulkEnrollmentStaging` gains
`signature_bytes` + `signing_public_key_hex`; every bulk caller (the simulator's
loader, the `bulk-enroll` CLI, the drill) now signs each token_value through the
same `pqc_signing` path single issuance uses, and `uc_bulk_issue` stores the
staged signature and REFUSES any unsigned row. It no longer fabricates a
placeholder literal. Real ML-DSA-65 under `POLARIS_USE_REAL_PQC=1` (verified
against the stored key), a deterministic verifiable sha3-256 placeholder
otherwise, exactly like single issuance. A migration adds the columns and
redefines the procedure; the down reverts.

**The benchmark exercises the real verify path and names its numbers honestly.**
It now measures three distinct things, no longer conflated: enrollment (issue +
sign, signing-bound under real PQC), verification-event ingestion (audit writes),
and cryptographic signature verification (`verify_stored_signature`, two
witnesses). A new invariant, `signatures_cryptographically_verify`, samples the
mass-issued tokens and fails the run if any does not verify. The certified
numbers are recorded in [docs/reference/BENCHMARK.md](docs/reference/BENCHMARK.md):
at 1:10000 with real ML-DSA-65, enrollment ~372 tokens/s, event ingestion
~25,970/s, and cryptographic verification ~743/s, a ~35x gap that the old
wording hid. This corrects the wording committed in v9.256.

**Proven, including a red-team injection.** `check_pqc_signing_wired` now also
pins that `uc_bulk_issue` stores a staged signature and refuses an unsigned row
(no placeholder literal), with detection perturbations that inject a fabricated
bulk signature and confirm the check turns red; `check_national_simulation` pins
that the loader signs and the benchmark measures crypto verification; the drill
gains an "unsigned row is refused" case; and a test proves a fabricated
signature does not verify while a real one does. Check layer 126; app 79 routes.

---

## v9.256 — 2026-09-06 (National simulation, ship 3: benchmark and load certification)

Roadmap P2.14, ship 3, and the roadmap's P2.9 load certification. A benchmark is
only worth the numbers it produces by running the real system, and only worth
trusting if the invariants still hold under the load. This ship measures Polaris
at scale and commits the result.

**The harness.** `polaris_sim/benchmark.py` runs the substrate build and the
life-event stream as timed phases, then measures three things a certification
needs: the p50/p95/p99 latency of a single verification write, the time each
bounded Atlas aggregate takes over the loaded event set, and whether C3, C6, and
the C1 append-only boundary still hold after the load. `python3 -m polaris_sim
benchmark`. It exits non-zero if any invariant broke under load, so a regression
fails loudly rather than being buried in a throughput number.

**The certified run.** At a state-sized 1:1000 scale, one million verifications
over a 24-hour window on the development host: 331,423 enrollments at ~2,640/s,
the verifications at ~19,800/s, a single verification write at p50 0.18 ms / p95
0.22 ms / p99 0.35 ms, and C3, C6, and C1 all holding at a million events. The
full table is committed in [docs/reference/BENCHMARK.md](docs/reference/BENCHMARK.md).

**What it found.** The scan-based Atlas roll-ups run 0.4 to 1.1 seconds at a
million events because each scans the whole set, while the keyset-paginated
`atlas_records` stays at 2.8 ms at the same scale. That is the benchmark earning
its keep: the roll-ups are the first thing to harden (a materialized rollup or a
covering index), the keyset design is vindicated, and the write path has ample
headroom. These are recorded as the hardening leads for a later ship.

**Proven.** `check_national_simulation` now also pins the benchmark harness, that
it certifies invariants under load (`check_invariants`), and the committed
report, with detection perturbations. A benchmark test in the coverage suite
drives a tiny end-to-end run in a rolled-back transaction and asserts the report
is well-formed and every invariant held. This realizes the single-node half of
P2.9; the remaining integration is to run the same harness against the HA
topology during a rolling deploy and a failover. The check layer is 126; the app
is 79 routes; schema unchanged.

---

## v9.255 — 2026-09-06 (National simulation, ship 2: the life-event stream)

Roadmap P2.14, ship 2. The enrolled nation from ship 1 was static. This ship
makes it alive: a realistic flow of national life-events, verifications and
token revocations, written through the real system, so the nation is not a
frozen roster but a running country.

**Verifications, through the real path.** `polaris_sim/events.py` generates a
stream of verifications spread over a time window and writes them with the same
direct `INSERT INTO VerificationEvent` the application's verification route uses
(there is no stored procedure for a verification). The database's disclosure
constraint is the boundary: a zero-knowledge verification carries no token and
no location (C6), a full-disclosure event carries a token, and a disclosing
event is placed near its holder's state, so the activity falls where the
population is. The mix is realistic, zero-knowledge dominant, success dominant,
everyday contexts out-numbering rare ones.

**Lifecycle, through the real procedures.** Token revocations go through the
real `uc8_revoke_token`, which writes the REVOKED lifecycle row itself. Driving
it surfaced exactly the kind of thing the simulation exists to exercise: a
revocation above a rate bound requires a co-signer, and the co-signer must hold
algorithm authorization, so the stream co-signs with a second authorized agency
and wraps each call in a savepoint. It never writes a token or lifecycle row
directly.

**The Atlas comes alive.** Because the events are real rows, the existing Atlas
(the Overview, the Breakdown, and the Map v2 regions and density) now shows a
populated national picture, zero-knowledge counted by jurisdiction but never
located, located activity spread across the states.

**A benchmark point.** Five hundred thousand verifications over a 24-hour window
wrote at roughly 20,000 verifications/s on the development host, with the
disclosure mix landing on its target weights.

**Use.** `python3 -m polaris_sim run --events 500000 --lifecycle 200 --window 24`.

**Proven.** `check_national_simulation` now also pins that the event stream
writes verifications to the real table and drives lifecycle through
`uc8_revoke_token`, with no direct token or lifecycle writes, plus detection
perturbations. Six new harness tests: the generator is deterministic and
C6-correct (zero-knowledge events carry no token or location), and a
database-backed test drives a stream over a small nation in a rolled-back
transaction and asserts the verifications land, C6 holds, and the revocations
wrote REVOKED lifecycle rows through the procedure. The check layer is 126; the
app is 79 routes; schema unchanged.

---

## v9.254 — 2026-09-06 (National simulation, ship 1: the synthetic nation)

Roadmap P2.14, ship 1 of a new arc: a national-scale simulation of Polaris. The
goal is to exercise the real system at a scale no unit test reaches, benchmark
it, and turn the findings into hardening. This first ship builds the substrate,
the synthetic United States, and loads it through the real enrollment path.

**A synthetic nation, seeded and deterministic.** The new `polaris_sim` package
carries the real United States as data (all 50 states + DC with Census
populations) and a pure generator: `plan_nation(scale, seed)` builds every ID
bureau in the country, one state office per state plus county and municipal
bureaus scaled by population, and streams the people each enrolls. Same inputs,
identical plan, which is what makes a benchmark comparable. Every state keeps a
bureau footprint at any scale, so the whole country is represented even in a
small run.

**Loaded through the real pipeline, not around it.** The loader inserts each
bureau as an agency, grants it the algorithm authorization the pipeline
requires, then issues every person a token set-based through `uc_bulk_issue`, so
each synthetic enrollee passes exactly the constraint set a real one does. It
never writes a token or a lifecycle row directly. `check_national_simulation`
enforces that: cover all 51 jurisdictions, be deterministic, and go through
`uc_bulk_issue` with no direct token writes.

**A first benchmark point.** A 1:1000 run, 331,423 enrollments across all 51
jurisdictions through the real pipeline, held C3 (one active token per person)
across the whole load and sustained roughly 3,200 enrollments/s on the
development host. That number, and where the per-bureau batching costs
throughput against one large batch, is the first thing a later hardening ship
can act on.

**Use.** `python3 -m polaris_sim build --scale 1000 --seed 42` builds and
enrolls a downscaled nation; `--plan-only` prints the plan without a database.

**Proven.** Eight harness tests: the generator is deterministic, covers every
state, and its people streams match the plan; a database-backed test loads a
small nation through the real pipeline in a rolled-back transaction and asserts
the tokens are issued, activated, C3-consistent, and carry real lifecycle
events. The suite runs in the coverage job, so CI exercises it. The check layer
is 126; the app is 79 routes; schema unchanged.

---

## v9.253 — 2026-09-06 (Atlas Map v2: aggregation first, globe optional)

Roadmap P2.3, ship 6: the map stops being an always-on globe strewn with raw
points and becomes an aggregation-first thematic map, the way an operations map
works when there are millions of events and thousands of agencies.

**Three layers, a default that scales.** A layer-mode control sits on the map:
Regions, Density, Points. **Regions** is the new default: one proportional
symbol per requesting-agency jurisdiction, at that jurisdiction's activity
centroid, sized by volume and tinted when the failure rate runs high. It is not
viewport-bound, so it shows the whole national picture at a glance instead of
whatever happens to be on screen. **Density** is a pointy-top hexbin surface of
located activity, graduated by count, honest where thousands of raw points would
be a smear. **Points** is the existing cluster-to-point drill. Click any
aggregate to fly in and drop to Points.

**The globe is now an option, not the view.** The map opens flat and legible; a
Globe toggle switches to the sphere projection for those who want it. The
spinning globe is no longer the thing you fight to read data through.

**Zero-knowledge, counted or excluded, never located.** The Density surface
excludes zero-knowledge events entirely, exactly like the cluster and point
layers (a hex holding one ZK event would pin it). The Regions layer is the
interesting case: a jurisdiction is a regulatory grouping, not a coordinate, so
a zero-knowledge verification is **counted** in its jurisdiction's total, yet
its centroid is built only from located, non-ZK events. A jurisdiction whose
activity is entirely zero-knowledge is reported as counted-but-unplaceable and
surfaced in the legend, never placed on the map (C6).

**Bounded and server-side, like everything else.** Two new aggregates,
`atlas_hexbin` (the standard pixel→axial→cube-round hex binning, done in SQL)
and `atlas_geo_jurisdictions`, both replica-routed and capped
(`_ATLAS_MAX_CLUSTERS`, and a new `_ATLAS_MAX_REGIONS`, C8). Their endpoints are
`/api/atlas/hexbin` and `/api/atlas/geo/jurisdictions`.

**Proven.** `check_atlas_console` now pins the three map modes, the projection
toggle, both aggregates, and both replica-routed endpoints;
`check_c6_atlas_redacts_zk_location` pins the hexbin ZK exclusion and the
jurisdiction centroid's located-only derivation; `check_c8_atlas_caps` gains the
regions cap; all with detection perturbations. Six new `AtlasConsoleAPITests`
cover the hexbin shape/bbox/ZK-exclusion and the jurisdiction
counts-but-never-locates contract, including a ZK-only jurisdiction proven
unplaceable; a new Playwright e2e opens the map on Regions/flat, switches modes,
and toggles the globe. Schema unchanged; the check layer is 125; the app is 79
routes.

---

## v9.252 — 2026-09-06 (Atlas: the records grid, and click to filter)

Roadmap P2.3, ship 5: the console gains the view every operator eventually
needs, the raw rows behind the charts, built to survive millions of them.

**A records data grid that scales.** The new Records tab is a server-paginated
stream of the events matching the global filter, one row per verification or
lifecycle event with its agency, category, outcome, disclosure, subject, and
location. Paging is keyset, not offset: each page carries a cursor
(`TIMESTAMP|EVENT_ID`) and the next page resumes from it, so page one thousand
costs the same as page one instead of making the database count past everything
before it. The new `atlas_records` function does the same two-stage top-N it
does for the map, and the `/api/atlas/records` endpoint is replica-routed and
capped at the event limit (C8). Zero-knowledge rows are real rows, but their
subject reads `(zero-knowledge)` and they carry no location, exactly as the map
never plots them (C6).

**Click a category to filter.** Every category bar in the Overview is now a
filter control. Click the Banking context or the FAILURE outcome and the whole
console narrows to it, chip and all, the way cross-filtering works in a real
analytics workbench. The agency dimension stays a typeahead (it needs an id, not
a label), but every value-based dimension filters on click.

**A latent corruption, fixed.** The cross-tab lookup key in `atlas-console.js`
had been built with a literal NUL byte as its separator (a `\0` that a heredoc
wrote as a raw `0x00`), which made the served script a binary blob to every text
tool that touched it. The separator is now a `\u0000` escape: the same key at
runtime, a clean ASCII source file.

**Proven.** `check_atlas_console` now pins the Records tab, the grid, the keyset
`atlas_records` (cursor, not offset) with its ZK redaction, and the
replica-routed endpoint, with detection perturbations for each; five new
`AtlasConsoleAPITests` cover the shape, keyset pagination, the ZK redaction, the
filter coordination, and the cap; a new Playwright e2e opens the tab, renders the
grid, and pages it. Schema unchanged; the check layer is 125; the app is 77
routes.

---

## v9.251 — 2026-09-06 (Atlas: one coordinated, faceted query)

Roadmap P2.3, ship 4: the step where the console stops being separate views
with their own controls and becomes one coordinated operational tool, the way a
real analytics workbench works.

**A global filter bar drives every view.** Stream, time window, and facets
(context, outcome, disclosure, agency) now live in one persistent query state
above the tabs. Change a filter and the Overview and the Breakdown both re-fetch
against it. Each facet dropdown lists its values with live counts (computed with
every other active facet applied but not itself, standard faceting), the agency
facet is a server typeahead that survives thousands of agencies, and every
selection appears as a removable chip with a Clear all.

**It is all bounded and server-side.** The filters serialize into the same
params every atlas aggregate already accepts, so filtering stays O(bounded)
regardless of scale. One new aggregate, `atlas_agency_facet`, returns agencies
with `(id, name, count)` for the typeahead; its endpoint
`/api/atlas/facet/agencies` is replica-routed and capped, and it is
non-geographic so a zero-knowledge verification counts toward its agency but is
never located (C6). The per-view stream/window controls are gone; the Breakdown
keeps only its own slice/sort/search options.

**Proven.** `check_atlas_console` now pins the global filter bar, the agency
typeahead, the facet endpoint, and `atlas_agency_facet` (location-free), with
detection perturbations; four new `AtlasConsoleAPITests` cover the facet and
that a filter narrows every aggregate; a new Playwright e2e opens a facet,
selects a value, and asserts the chip and Clear all appear. Schema unchanged;
the check layer is 125; the app is 76 routes.

---

## v9.250 — 2026-09-06 (Atlas Breakdown, scale-hardened)

Roadmap P2.3, ship 3. Direction came in to raise the whole Atlas to
professional, production grade, built for millions of tokens and
thousands-plus of agencies (see the rewritten arc in
[DEVNOTES/atlas-redesign.md](DEVNOTES/atlas-redesign.md) and the `ui-quality-bar`
standard). Testing the Breakdown at 54 agencies proved the point: it became a
flat 30-plus row list that shoved the cross-tabs off-screen. This ship fixes
that offender; the wider professional pass and the coordinated global-filter
foundation follow in later ships.

**The Breakdown is now a scale-ready explorer.** The sliced-dimension list moved
into its own card with a **filter box** and an **internal scroll** (a sticky
header), and the two cross-tabs sit **beside** it, always visible. Type to find
one agency among thousands; the list never buries the analysis. A footer states
the scope honestly ("Top 40 by volume, refine the filter to narrow", or the
exact match count).

**Server-side search.** `atlas_breakdown` gained a `p_search` label filter
(case-insensitive), and `/api/atlas/breakdown` accepts `?search=` and returns a
`truncated` flag, so search is a bounded server aggregate like everything else
(C8) and finds low-volume slices the top-K list would never show.

**Proven.** `check_atlas_console` now pins the searchable, internally-scrolling
Breakdown and `atlas_breakdown`'s label filter (+ detection perturbations); two
new `AtlasConsoleAPITests` cover search and the truncated flag; the Breakdown
e2e case now types a search and asserts the footer reflects it. Schema
unchanged; the check layer is 125; the app is 75 routes.

---

## v9.249 — 2026-09-06 (Atlas Breakdown: find the anomalous slice)

Roadmap P2.3, ship 2 of the Atlas rebuild. The Overview answers "how is it
doing"; the Breakdown answers "which slice is wrong". It is the investigative
view an operator reaches for when a failure rate climbs.

**Slice, then cross-tab.** Pick a dimension to slice by (agency, context,
jurisdiction, algorithm) and the Breakdown shows a ranked table (volume,
failure rate, share, sortable by either) plus two cross-tabs: the sliced
dimension against outcome, and against disclosure. Each cross-tab cell is
shaded by its share of the row and tinted by column (success green, failure
red, zero-knowledge purple, and so on), so an anomalous profile jumps out: an
agency with an unusually red Failure column, or a context skewed to full
disclosure, is visible at a glance rather than buried in a list.

**One new bounded aggregate.** `atlas_crosstab(row_dim, col_dim, ...)` in
11_atlas.sql: the top-K rows of the row dimension (capped at
_ATLAS_MAX_CATEGORIES) crossed with a low-cardinality column dimension, so the
cell count is bounded by construction (C8). Non-geographic, so a zero-knowledge
verification is counted in its agency/context/disclosure cell but never located
(C6). Its endpoint `/api/atlas/crosstab` is replica-routed and both dimensions
are whitelisted per stream.

**A hidden-attribute bug, fixed.** The error banners (`.ov-error`, flex-display)
overrode the HTML `hidden` attribute at equal specificity, so they showed even
when idle. One authoritative rule (`.atlas-shell [hidden]{display:none}`) now
makes every `hidden` in the console obey it; this also corrected the Overview,
where the same banner was showing below the fold.

**Proven.** `check_atlas_console` now pins the Breakdown tab, the crosstab
endpoint, atlas_crosstab (location-free, C6), and the row/column whitelists
(+ detection test); four new `AtlasConsoleAPITests` cover the endpoint; a new
Playwright e2e case renders the table and a cross-tab and asserts no error
banner. Schema unchanged; the check layer is 125; the app is 75 routes. Plan in
[DEVNOTES/atlas-redesign.md](DEVNOTES/atlas-redesign.md).

---

## v9.248 — 2026-09-06 (the Atlas becomes an analytical console)

Roadmap P2.3, ship 1 of the Atlas rebuild ([DEVNOTES/atlas-redesign.md](DEVNOTES/atlas-redesign.md)).
The Atlas was a globe you looked at: an always-on canvas of server-clustered
event bubbles that, at national scale, read as overlapping "40k" circles and
buried the operational insight the page exists for. It is now a console you ask
questions of.

**Overview is the default.** The Atlas opens on a bounded, non-geographic
analytics view: a volume time-series with failures overlaid, KPI cards with
sparklines (verifications, failure rate, zero-knowledge share, active tokens,
post-quantum coverage), and top breakdowns by context, agency, disclosure and
outcome. Every figure is a server-side aggregate, so it survives the 2M-row
stress set and beyond; the browser never receives more than a few hundred rows.

**The globe is a tab.** The former map moves behind a Map tab, cleaned of the
cockpit theatrics (the fake heading/pitch/zoom readouts, the waveform, Spin),
and boots lazily the first time it is shown. It keeps everything it was good at:
the live event feed, the per-subject investigation journey, the drill to street
level.

**Two new bounded aggregates**, both non-geographic and location-free:
`atlas_volume_series` (total volume over time, counting EVERY event unlike the
located-only timeline) and `atlas_breakdown` (top-K by one whitelisted
dimension). Their endpoints `/api/atlas/series` and `/api/atlas/breakdown` are
replica-routed and capped by a new `_ATLAS_MAX_CATEGORIES` (50).

**The invariants hold, and one is now a feature.** C8: the category cap joins
the cluster/point/event caps (`check_c8_atlas_caps`). C6: zero-knowledge
verifications are COUNTED in volume, disclosure and every roll-up but never
located or attributed: "37% of activity is zero-knowledge and unmappable" is
the privacy posture on display. C5: the charts are hand-rolled inline SVG and
CSS bars, self-hosted, so `script-src 'self'` is never relaxed and no charting
CDN is added.

**Proven.** `check_atlas_console` (+ detection test) pins the structure; seven
`AtlasConsoleAPITests` pin the aggregates; the Playwright e2e suite gains two
cases (Overview is the default, the Map tab reveals the globe) and stays
CSP-clean. The schema is unchanged; the check layer is 125; the app is 74
routes.

---

## v9.247 — 2026-09-06 (bulk enrollment)

Roadmap P2.4. Onboarding an authority's existing population is the one workload
at a scale nothing else in Polaris meets: every other issuance path is one
person at a time, and a migration is millions. Running the single-issue path a
million times is a million transactions and a million chances for a partial
failure to leave the import half done. This ships the set-based path.

**Stage, then issue whole.** Records stage with `COPY` into the new
`BulkEnrollmentStaging` (a batch is one issuing agency under one algorithm,
recorded in `BulkEnrollmentBatch`), and `uc_bulk_issue` issues the whole batch
in one transaction: the `uc1` authorization gate checked once for the batch,
the keys pre-assigned, then one `INSERT ... SELECT` per table (Individual,
IdentityToken in RESERVE, TokenSignature, the ISSUED events) and one `UPDATE`
to ACTIVE. Every row runs the same per-row triggers, foreign keys, CHECKs, and
unique constraints a single issuance runs. Because it is one transaction, a
single violating row rolls back every row: the import lands whole, or not at
all.

**C3 reachable across a batch.** A staged `individual_id` left NULL is a new
person; set, it correlates a re-card to an existing one, and the Individual
insert skips a person who already exists. That is what puts C3
(`uq_one_active_per_person`) genuinely in the path: two staged rows for one
person, or a re-card of someone still holding an active token, produce two
active tokens for one individual, which the partial unique index rejects at
activation, which rolls the batch back. The bulk path retires nothing on its
own.

**Operator surface.** `polaris-id bulk-enroll <extract> --agency N --algorithm
N` stages a pipe-delimited extract with client-side `COPY` and issues the
batch, with `--dry-run` to stage and validate without issuing. An unauthorized
agency or a duplicate serial takes the whole batch down with exit 3 and leaves
no trace.

**Measured, and proven every push.** On the development database at v9.247,
5000 records staged and issued in about 1.1 seconds (~4500 rows/s), every token
active, signed, and event-logged. `polaris-bulk-drill.sh` (new, in the
`product-test` job) re-measures the rate over a deliberately low CI floor and
proves the batch is all-or-none: a duplicate serial and two rows for one person
each roll the whole batch back, and the already-issued, unauthorized, and
empty-batch refusals all hold. Every test rolls back, so the drill mints no
append-only events to clean up. Pinned by `check_bulk_enrollment` (with a
detection test) and four `bulk-enroll` cases in the CLI suite. The schema is
now 32 tables (36 migrated); the check layer is 124.

---

## v9.246 — 2026-09-06 (read-replica routing)

Roadmap P2.2. The HA profile (v9.243) keeps a streaming replica behind the
router's `/replica` endpoint; nothing read from it. Now the read-only surfaces
do.

**What routes.** The analytical reads with no read-your-writes requirement: the
atlas API, the verification list, the token export. They carry a
`@replica_reads` decorator that marks their SELECTs eligible for the replica; a
committing query is never routed there. Correctness-critical reads (a
verification decision, issuance, a token's current state) stay on the primary,
untouched.

**The staleness contract, explicit.** A read routed to the replica is at most
`POLARIS_REPLICA_MAX_LAG_S` seconds behind the primary (default 10). Beyond
that, or if the replica is unreachable, the read falls back to the primary
(fresh) and the surface stays up; the fallback is counted on
`polaris_replica_failback_total`. Every routed response says where it was
served (`X-Polaris-Data-Source`) and how far behind (`X-Polaris-Replica-Lag-
Seconds`); `/api/health` gains a `database_replica` component (lag, serving),
informational so a lagging replica never degrades overall health.

**The path.** The app dials the pooler's `polaris_ro` database, which the
entrypoint serves onward to `POLARIS_DB_REPLICA_HOST:PORT`; on the HA profile
that is `pg-router:5433`, so a failover moves the replica the router picks and
the app's read path follows without a reconnect to a named member. Same
pooler, same pinned certificate. Single node (no replica configured) is
unaffected: every read uses the primary, no header, no behaviour change.

**Proven.** Six new tests: single node unchanged, a replica serving and
reporting its source and lag, failback when the replica is unreachable, a
write never routed to the replica, and the health component present-or-absent
without degrading the roll-up. `polaris-failover-drill.sh` asserts the app
serves reads from the replica (`database_replica` healthy) on the booted HA
stack. `check_read_replica_routing` pins the routing, the contract, the pooler
read database, the HA wiring and the drill. All 471 app tests pass unchanged.
123 checks.

---

## v9.245 — 2026-09-05 (event-table partitioning)

Roadmap P2.1, the first of the scale-architecture rows. The four append-only
event tables grow without bound in a national deployment and C1 forbids
deleting a row except through the audited retention purge. They are now
monthly range-partitioned on `event_timestamp`, so an old month detaches in
O(1) instead of a DELETE scan of millions of rows.

**The tables** (the four the retention engine purges): TokenLifecycleEvent,
VerificationEvent, EnrollmentStatusEvent, AuthAuditLog. Nothing references them
by foreign key, which is what makes an in-place conversion possible. Each has a
composite primary key `(id, event_timestamp)`, monthly partitions, and a
DEFAULT catch-all so an insert never fails. An INSERT routes automatically; a
SELECT reads across partitions; the tables are append-only, so there is no
UPDATE/DELETE path to complicate routing.

**The manager** (`01_schema.sql`, redefined by the migration for existing
databases): `uc_ensure_event_partitions(months_ahead)` premakes the current
month plus a buffer, at the end of the schema load (before any row is
inserted, so the enrollment trigger's `now()` rows land in a monthly
partition), on every deploy, and monthly via
`polaris-partition-maintenance.timer`.
`uc_detach_event_partitions_before(cutoff)` detaches whole old months and
**re-creates the append-only trigger on each detached table**, because a
detached partition loses the parent-propagated trigger — the C1-across-detach
hole the roadmap warned about, closed.

**The online migration** (`2026-09-05-003`) converts a pre-v9.245 database in
place: it attaches the existing table as the DEFAULT partition (its rows stay
physically in place, no copy), then re-creates the indexes and the append-only
trigger on the parent. It is idempotent (a no-op on an already-partitioned
database, so it is safe on a fresh one) and transparent (the rename is atomic
inside its transaction). The down migration departitions, preserving every
row. The one honest cost is stated in [docs/design/partitioning.md](docs/design/partitioning.md):
the index re-creation on the attached partition is the conversion's only
non-instant step, and a very large table should build them CONCURRENTLY first.

**Proven.** `scripts/polaris-partition-drill.sh` (the product-test job) shows a
future row landing in a monthly partition, append-only rejecting UPDATE/DELETE
on a partition and across an attach and a detach, the online conversion
preserving rows and the trigger, and the retention DELETE carve-out still
routing across partitions. `check_event_table_partitioning` pins the schema,
the manager, the migration, the drill and the standing timer. All 471 app
tests, the 99 constraint/invariant/redaction tests, the SQL self-tests and the
retention drill pass unchanged: partitioning is transparent to the whole
application. 122 checks.

---

## v9.244 — 2026-09-05 (HA on Kubernetes: the same members, the cluster's API as the lease store)

Roadmap P2.13. The Helm reference profile ran one postgres replica while the
compose stack had automated failover since v9.243. It now runs the same
Patroni members under the same entrypoint, with the Kubernetes API as the
lease store: no etcd of its own, the lease in the annotations of the leader
Endpoints, the leader Service's endpoints filled by Patroni. A ServiceAccount
and a Role grant exactly what Patroni needs (pods, endpoints, configmaps, one
service create). `postgres.replicas` (2) and `postgres.patroni.*` in values;
a selector-less leader Service, a headless members Service for the
StatefulSet's pod DNS, a replicas Service on the `role` label Patroni
maintains; NetworkPolicies for member-to-member replication and REST and for
the API server, whose addresses the chart reads from the `kubernetes`
Endpoints at install time (`networkPolicy.apiServer.cidrs` when it cannot).
The postgres pods are the one workload that mounts a token; every other one
still does not.

**The router, on Kubernetes too.** pgbouncer dials `pg-router`, the same
HAProxy as the compose profile, rather than the leader Service, because of
what the kind drill found: a member whose process is frozen still has a
kernel that acknowledges TCP, so no socket timeout fires on a query sent to
it, and the pool's established connections to a frozen leader hung until it
thawed; only the router's Patroni health check notices, marks the member
down and cuts the sessions. Member names are fully qualified
(`clusterDomain`), since HAProxy's resolvers apply no search path.

**The kind drill** (`polaris-helm-drill.sh`, the `helm-kind` job) gained the
failover under a writer with the app's labels inserting through pgbouncer.
Local reference run at v9.244:

| Induced | Held | Measured |
|---|---|---|
| the leader pod deleted | it returns under the same name inside its lease and keeps the role: a restart in place | 3.2 s write outage; one leader, one streaming replica again in 1 s |
| the leader's container frozen through the node's runtime (a hung node) | the other member holds the lease; the thawed leader demotes and rejoins | lease moved at 21 s; the pool's query cancelled at the 15 s query_timeout for a 15.8 s write outage; demoted and streaming 6 s after thawing |
| a planned switchover | the candidate leads; the old leader follows | 3.5 s write outage; followed at 3 s |

and every acknowledged insert present on the leader afterwards.

**What the first runs found.**

1. A deleted StatefulSet pod is not a lost node: it comes back under the
   same name inside the lease and Patroni treats it as the same member
   restarting. A lost node on a cluster is a hung one, so the drill freezes
   the leader's container through the node's runtime; and a frozen pod
   keeps a stale `role` label, so the drill reads the lease from the
   Endpoints annotation, never the label.
2. A recreated pod's old sessions hung under a router that stayed up (the
   address changed, the check kept passing on the new one) until TCP gave
   up, minutes later: the router now closes a session whose peer stops
   acknowledging within 3 s (`tcp-ut`) and probes idle server connections
   with keepalives (3 s idle, 1 s interval, 3 misses), on both profiles.
   The pooler got the same two timeouts (`PGBOUNCER_TCP_USER_TIMEOUT` and
   keepalives, pinned by `check_pgbouncer_self_built`).
3. The compose profile was measured again under the changed router: a lost
   leader is promoted at 21 s with a 21.0 s write outage and rejoins 3 s
   after starting; a leader cut off from the lease store demotes at 5 s and
   the lease moves at 11 s (13.2 s outage, the pool's queries to the
   demoting member now failing fast instead of stalling); a switchover is
   3.3 s; an etcd member crash is a 0.3 s stall. FAILOVER.md carries them.

**Also.** `check_helm_reference_profile` pins the Role, the lease store, the
router, the member count from values and the three drill scenarios;
KUBERNETES.md and FAILOVER.md carry the topology, the numbers and the
Kubernetes placement note; the readiness ledger's Postgres HA row covers
both substrates. 121 checks, 15 CI jobs.

---

## v9.243 — 2026-09-05 (automated database failover: the HA profile)

Roadmap P2.7, and the database half of the one engineering limit the
readiness ledger carried. Until now the standby and the promotion were the
operator's: a runbook with `pg_basebackup` and `pg_promote`, and "Patroni or
repmgr stay operator choices". The choice is made and shipped.

**The HA profile**, `polaris_web/docker-compose.ha.yml` on top of the
production stack: the same database image run by Patroni (pinned in
`requirements-patroni.txt`, installed by `Dockerfile.postgres`; a container
started with `postgres` never touches the layer), two members, a leader
lease in a three-member etcd self-built from Alpine's package
(`Dockerfile.etcd`, non-root, on an internal network only the members join),
and HAProxy (`pg-router`, digest-pinned) forwarding 5432 to whichever member
answers Patroni's `/primary`. pgbouncer dials `pg-router`; the application
is unchanged. Patroni's `post_init` hook runs the same `docker-init.sh` the
single node runs, in a managed mode that leaves TLS, replication and
archiving to Patroni's parameters, so a fresh database is the same on both
profiles. `failsafe_mode` is off: a leader that cannot renew its lease
demotes itself, which is the property the split-brain analysis relies on.

**The drill**, `scripts/polaris-failover-drill.sh`, on every push (job
`ha-failover`), under a writer inserting through the real client path four
times a second. Local reference run at v9.243:

| Induced | Held | Measured |
|---|---|---|
| the leader node lost (killed, kept down) | the replica takes the lease; the old node rejoins on start | promoted at 20 s; 20.0 s write outage, queries fail fast at the query timeout and are retried, none lost; rejoined 3 s after start |
| the leader cut off from the lease store, clients still reaching it | it demotes itself; the other member takes the lease | demoted at 9 s; lease moved at 10 s; 12.3 s write outage, no insert failed |
| a planned switchover | the candidate leads; the old leader follows | 3.4 s write outage, no insert failed; followed at 2 s |
| one etcd member crashed | the quorum carries the lease; the leader does not change | 0.3 s longest stall, no insert failed |

**What the first runs found.**

1. A pooler connect that started in the two seconds before HAProxy marked
   the old leader down hung for PgBouncer's default 15 s
   `server_connect_timeout`, every client queued behind it. The pooler now
   abandons a backend connect after 3 s (`PGBOUNCER_SERVER_CONNECT_TIMEOUT`,
   compose and chart), HAProxy redispatches a failed backend connect to
   another member and checks every half second; `check_pgbouncer_self_built`
   fails a default above 5 s.
2. A leader whose process crashes and restarts inside its lease is not a
   failover: Patroni restarts it in place and keeps the lease. The drill's
   first scenario is a lost node (killed and kept down), not a process crash.
3. Queued writes stall rather than fail, so a failed-insert count alone
   reported a 19 s outage as zero; the drill reports the longest stall and
   asserts on the larger of the two, stamping each insert with its
   completion time (a start-time stamp made a 20 s queue wait look like a
   0.3 s one).
4. The partition scenario has a second honest outcome, found by the first
   CI run: when the surviving member is a few WAL records behind (the
   demoting leader's final records never reached it), Patroni will not
   promote it while the member that is ahead is reachable, and that member
   cannot take the lease without the store. Nobody holds the lease until the
   partition heals; integrity is kept, availability is not. The drill
   settles to zero lag before every scenario, accepts both outcomes,
   asserts that no insert was acknowledged while nobody held the lease, and
   after every scenario asserts that every insert acknowledged since it
   began is present on the leader. FAILOVER.md's analysis carries the
   outcome and the operator's override.

**Also.** The Patroni entrypoint starts as root and drops to `postgres`
with gosu, like the stock one: the superuser password is a root-only 0600
file on the host by design, and on Linux a non-root container cannot read it
(the first CI run found it; Docker Desktop had hidden it locally).
`FAILOVER.md` is rewritten around the supervisor: what ships, what
is placement, the measured table, the split-brain analysis partition by
partition, `patronictl` operations. `check_ha_automation` pins the lease
semantics, the routing, the drill's scenarios and ceilings, the CI job and
the analysis; `check_replication_scaffolding` now asks for the lease-based
promotion instead of `pg_promote`. The SBOM and the image CVE scan cover the
fifth self-built image. The readiness ledger carries the database half of
the window limit as closed; the edge half (a 0.3 s recreation window)
remains, and is placement. The Helm chart still runs one postgres replica:
roadmap P2.13. SECURITY.md re-read and restamped. 121 checks, 15 CI jobs.

---

## v9.242 — 2026-09-05 (the standing chaos program, and what its first run found)

Roadmap P2.11 asked for scheduled chaos runs with paging verified and
findings feeding checks. The fail-closed harness (`polaris-chaos-test.sh`,
v9.27) had never run anywhere but a contributor's terminal, and nothing
induced a failure in the assembled stack. Both halves ship, and the first
runs of the second found three things.

**On every push:** the product-test job runs the harness. The database gone
mid-recovery, the prover binary absent, an epoch close interrupted: each must
end in a refusal, never a silent success.

**Weekly, and on demand:** `scripts/polaris-chaos-drill.sh` runs against the
booted blue-green stack under continuous traffic, with a Prometheus scraping
the real app containers on the shipped rules, the shipped Alertmanager
routing, and a webhook sink for the pager. Five scenarios, each against a
ceiling; the local reference run at v9.242:

| | Induced | Held | Measured |
|---|---|---|---|
| A | one app colour crashed | the other carries every request; the container restarts on its own | 0 of 152 dropped; back healthy in 5 s |
| B | both colours stopped for 150 s | the generator sees the outage; `PolarisAppDown` reaches the sink | paged 121 s in; service back 3 s after start |
| C | redis crashed | the app keeps serving; redis returns on its own | 0 of 228 dropped; back in 10 s |
| D | postgres crashed | crash recovery; the app containers are not replaced | 0.6 s window, 6 of 95 dropped; healthy 2 s after the crash |
| E | pgbouncer partitioned for 15 s | the database path recovers on reconnect | healthy at the first probe after the reconnect |

`.github/workflows/chaos.yml` builds the images, boots the stack, runs the
drill with `--record`, and commits the row to
[docs/operator/CHAOS-DRILLS.md](docs/operator/CHAOS-DRILLS.md) pass or fail,
Mondays 05:47 UTC and on dispatch. `check_chaos_program` pins the harness in
CI, the five scenarios and their ceilings, the paging assertion, the
schedule, and the ledger.

**What the first runs found.**

1. *A Postgres crash was a 16 s outage for the application.* The database
   itself was back in half a second (a container restart in 0.15 s, redo in
   0.00 s). PgBouncer's defaults wait 15 s before retrying a failed backend
   connect (`server_login_retry`) and cache a failed name lookup for 15 s
   (`dns_nxdomain_ttl`; Docker unregisters a container's name while it
   restarts), and every client was fast-failed with the cached error until
   the retry. Measured against the running pooler: 16.2 s on the defaults,
   1.8 s with the retry at 1 s, 1.9 s with both at 1 s. The entrypoint now
   sets both from `PGBOUNCER_SERVER_LOGIN_RETRY` and
   `PGBOUNCER_DNS_NXDOMAIN_TTL`, default 1, listed in the compose and the
   Helm chart; `check_pgbouncer_self_built` fails a default above 2 s. The
   drill's scenario D went from a 14.6 s window to 0.6 s.
2. *`polaris_web/pgbouncer.ini` was not the pooler's configuration.* Nothing
   consumed it; the entrypoint generates the ini at container start, and the
   file claimed a 5 s retry the running pooler never had. Deleted, and the
   check fails if a file by that name returns.
3. *Two of the drill's own primitives measured nothing.* `docker kill` is a
   manual stop to Docker, so the restart policy never fired and a "crashed"
   container stayed down; the drill now delivers SIGKILL to the container's
   init from the host pid namespace. `docker network connect` without
   `--alias` reattaches a container under its container name only, so the
   app could never resolve `pgbouncer` again; the reconnect restores the
   aliases it captured and proves the app resolves the name before the
   recovery clock is read. Both are in the drill's header so the next author
   does not rediscover them.

Also: README, the roadmap and the site count 120 checks; the system map,
the operator index, RUNBOOKS (PolarisAppDown), OPERATIONS, DEPLOYMENT and the
observability README point at the ledger; CI ignores the ledger path on push
so the weekly row does not spend a run.

---

## v9.241 — 2026-09-05 (the SLIs and the error budget are recorded series)

The P1 exit gate reads "SLOs met". SLOS.md states three objectives over a
rolling 30-day window and an error budget, and said the budget was
"observable on a dashboard". It was not: the overview dashboard had no SLO or
budget panel, and the SLIs existed only as expressions in the document. The
same class of claim this readiness work keeps finding, closed the same way.

- `deploy/observability/polaris-slo.yml` records the 30-day availability
  ratio, the fraction of the month's budget spent, the 1-hour and 6-hour burn
  rates in multiples of the sustainable pace, and the two 30-day p99s (request
  latency and the health probe's database round-trip), evaluated every five
  minutes. A deployment that has never served an error records 100%, not an
  empty result.
- `prometheus.yml` loads it, the observability overlay mounts it, the page
  drill validates it with promtool, and the alert unit-test suite now loads it
  too: one thousand requests with one 5xx must record 99.9% exactly and a
  budget exactly spent; a latency histogram whose 99th request sits on the
  1-second boundary must record a p99 of 1 s; a deployment with no errors
  must record 100% and nothing spent.
- The overview dashboard gains an SLO row: the three objectives as stats with
  their thresholds, the budget spent, and the burn rate over both windows
  with the line at 1.
- Polaris still ships no burn-rate alert, because how fast a deployment may
  spend its budget before someone is paged is the operator's policy. The
  series to page on are recorded, so SLOS.md now carries the standard
  multi-window rule as one block to paste.
- `check_alert_rules` fails the build if the file, any of the five recorded
  series SLOS.md names, the Prometheus wiring, the overlay mount, the unit
  tests or the dashboard panel goes missing.

Proven locally with the pinned Prometheus image: `promtool check rules` on
both files, `promtool check config` loading both, and `promtool test rules`
green across the alerts and the recording rules.

---

## v9.240 — 2026-09-05 (edge configuration changes are live reloads; the two remaining windows are measured)

The readiness ledger's last engineering limit read "edge and database
recreation are window operations under the blue-green deploy". This ship does
not close it, which takes a hot standby with automated failover (roadmap
P2.7), but it removes the most frequent case from it and puts numbers on the
rest.

**An edge configuration change is no longer a window.** All three Caddyfiles
expose Caddy's admin API on a unix socket inside the container
(`/config/admin.sock`, owned by the edge's own user, never on the network), and
`polaris-deploy.sh` applies an edited Caddyfile with `caddy reload` through it
as its step 5a. The listeners never close. Until now compose did not recreate
the container for a change inside a bind-mounted file, so an edited Caddyfile
was silently not applied until the next recreation; a Caddyfile that fails to
adapt is now refused loudly while the previous configuration keeps serving.

**The windows are measured.** `scripts/polaris-window-drill.sh` runs on every
push after the rolling drill, against the same booted blue-green stack and the
same traffic generator, and asserts hard ceilings:

- A real Caddyfile change (a new listener inside the container) is applied
  live, verified through it, and reverted, under traffic: zero dropped
  requests, or the drill fails.
- Recreating the edge: the window from the first dropped request to the last,
  ceiling 30 s. Measured locally at v9.240: 0.3 s, 6 of 95 requests.
- Restarting the database: ceiling 60 s, the container's start time must
  change (a restart that did not happen would make the scenario vacuous), and
  the app containers must not be replaced. Measured: no failed request at all.
  pgbouncer queues a query while its server connection is re-established, so
  a short restart reaches clients as latency (slowest request 0.94 s), not as
  errors, and the app recovers without a restart because every request opens
  its own connection through the pooler.

The numbers are in DEPLOYMENT.md with the ceilings; the runbook says how to
change the edge or database configuration; the ledger's limit paragraph states
what remains and where it closes. `check_zero_downtime_deploy` now fails the
build without the admin socket, without the deploy's reload step, without the
drill and its three scenarios, or without CI running it.

Also found: the CI edge's local CA tried to install its root certificate into
the OS trust store on every load, which the non-root edge cannot do and does
not need; `skip_install_trust` silences it.

---

## v9.239 — 2026-09-05 (the edge runs as a non-root user on every substrate)

The readiness ledger carried two engineering limits openly. This closes the
first: the Caddy edge in the compose stack, which is what the single-host and
Linux-server paths run, was the one production container still running as
root, holding `NET_BIND_SERVICE` so it could bind 80 and 443. The Kubernetes
profile had run it as uid 1000 on 8080/8443 since v9.186; now every substrate
does.

- `Dockerfile.caddy` creates uid 1000, owns `/data` (the ACME account and
  certificates) and `/config` to it, and ends with `USER caddy`. The file
  capability on the binary was already stripped; nothing adds one back.
- The compose edge drops `cap_add` entirely and publishes host 80/443 onto
  8080/8443. The CI overlay maps 8443 onto 8443. Firewall rules and every
  URL an operator or CI uses are unchanged, because the host ports are.
- Both Caddyfiles set `http_port 8080` and `https_port 8443`. Caddy's
  automatic HTTP-to-HTTPS redirect names `:8443` in its Location header
  when `https_port` is not 443, so it is disabled and the explicit `http://`
  site redirects to the domain on the port the client used. The Helm chart
  had exactly that latent defect since v9.186 and gets the same fix.
- The edge logs to stdout rather than to a file under `/var/log/caddy`,
  which needed a host directory writable by the container's user. The
  json-file driver already caps and rotates it; `docker compose logs caddy`
  reads it.
- A deployment created before this change has root-owned edge volumes the
  new user could not read or write. `polaris-deploy.sh` re-owns them once
  before the edge starts; the runbook's upgrade section carries the manual
  command for anyone bringing the stack up another way.
- `check_container_hardening` now fails the build if the caddy service adds
  a capability back, if it stops publishing 80/443 onto 8080/8443, or if
  `Dockerfile.caddy` runs as root or sets no user.

Also: the duress-page drill now pulls its three digest-pinned images up front
with retries (five attempts, backing off from 15 s), because a registry error
on the runner turned this ship's first CI run red before the drill had proven
anything. The edge jobs had all passed; the rerun passed.

Proven locally with the built image: `caddy validate` accepts the production
Caddyfile, the process runs as uid 1000 with its state directories writable,
listens on 8080 and 8443, answers HTTP with a 301 to `https://<domain>/…`
with no port, and terminates TLS on 8443. CI proves the rest on every push:
the full production stack boots through the edge, the post-quantum handshake
is negotiated against it, and the Linux install drill brings it up on Debian
and Rocky.

---

## v9.238 — 2026-09-05 (the dashboard is an operations page)

The dashboard is remade. The previous page opened with the row counts of
twelve schema tables, carried a roster of active tokens that duplicated
`/tokens`, explained every panel in a paragraph, and gave the agency-by-
algorithm authorization matrix the most prominent position on the page. None
of that is what an operator opens the console to learn.

The new page reports state an operator acts on, in the order it matters:

- **Service.** The readiness roll-up as a strip of components (database,
  rate limiter, ZK verifier, key custody, disk, Atlas cache) with each one's
  latency or note, plus the signer: which algorithm, whether it is the real
  ML-DSA-65 through liboqs or the development placeholder, and which custody
  driver holds the key. The placeholder shows amber outside production and
  red inside it.
- **Tokens.** The population by state, issued and revoked in the last 24
  hours and 7 days, how many active tokens expire within 30 days, and the
  active and reserve counts by issuing agency.
- **Verifications.** Volume in the last 24 hours and 7 days, the share that
  did not succeed, the disclosure mix as one bar (zero-knowledge, selective,
  full), and a per-context table with the 7-day count and its failures.
- **Needs attention.** A list with a count, a link and a next step for each
  thing that wants a human: duress signals in the last 24 hours (admin and
  auditor only, as before), recovery requests awaiting a decision, privileged
  accounts past their WebAuthn deadline, active tokens past expiry, active
  tokens still under a classical algorithm, locked operator accounts, failed
  logins, tokens expiring soon, anchor batches not yet on a chain, and a
  missing closed epoch. Zero items dim; the page says so when nothing is open.
- **Cryptographic posture.** The post-quantum share of active tokens as a
  bar, and per algorithm the active tokens, how many agencies may issue and
  verify under it, and its deprecation date. The full authorization matrix
  is still here, collapsed under a summary line.
- **Audit of record.** ZK epochs, anchor batches, duress signals on record,
  the retention in force per class from the engine, the last archive purge,
  and the last ten lifecycle events as a table.

Every figure is a bounded aggregate; the page never enumerates a population
(C8). The stat-card grid and the data-viz stylesheet section the old page
used are removed with it. The tests that pinned the old content are replaced
by tests of the new: the service strip, the population without row counts,
the absence of the roster, the attention list, the role gate on duress, the
posture table, the collapsed matrix, and the audit panel.

---

## v9.237 — 2026-09-05 (a production readiness pass over every surface, and what it found)

A full readiness audit of the repository at v9.236: every stated number
re-measured, every deployment artifact validated, every operator page walked
in a real browser at desktop and laptop widths, and the site rendered as a
visitor sees it. What was already true stays true and is listed at the end.
What was not is fixed here.

**The application, as an operator sees it.**

- Every page but the landing page printed "Version" with nothing after it,
  and every static asset was served as `polaris.css?v=` with an empty
  cache-buster, because `polaris_version` reached only one template. It is
  injected for all of them now.
- On a 1366-pixel laptop the dashboard's `CryptographicAlgorithm` card label
  ran past its card: a single CamelCase word cannot wrap. A `camel_wbr` filter
  gives every schema identifier a break point at each case boundary, with
  `overflow-wrap` as the fallback.
- Twenty-six cells across eight templates printed the word `None` for a
  missing value, and the dashboard's algorithm table printed it in a
  hard-coded deprecation column that never read the data. A raw `None` can no
  longer reach a page (a Jinja `finalize` blanks it), each deliberate absence
  now says what it is (`not yet`, `no expiry`, `not recorded`, `pending`,
  `none scheduled`), and the deprecation column reads `deprecation_date`.
- The Atlas subject search field had no id, which Chrome reports as an
  accessibility issue.
- A deep link never survived the login. The redirect to `/login` carried the
  absolute `request.url` as `?next=`, and the login's open-redirect guard
  accepts only a relative path, so the app refused its own parameter and
  every operator landed on the dashboard. The redirect now carries the path
  and query; `test_login_returns_to_the_page_that_required_it` pins it, and
  the guard is unchanged.

**The Atlas basemap is a deployment setting.** Its style and tiles were
hard-coded to CARTO, so the operator's browser fetched them from a third party
on that page, and PRIVACY.md said the browser only ever talked to the Polaris
instance, which was not true there. `POLARIS_ATLAS_BASEMAP_STYLE_URL` points the
Atlas at a self-hosted MapLibre style; the page's Content-Security-Policy
follows the configured origin, and a relative URL leaves the page self-only
apart from `blob:`. Plumbed through compose, the systemd environment file and
the chart guidance; documented in the runbook, SECURITY-CONTROLS.md and
PRIVACY.md; three tests in `F04b_AtlasBasemapCspTests`.

**Two claims in the readiness ledger that the code did not hold.**

- "Third-party images are digest-pinned" was true of the one image the prod
  compose pulls and false of the bases under the four it builds: the app
  image pulled `python:3.12-slim-bookworm` and a rust nightly by tag, and the
  pooler pulled `alpine:3.24` by tag. All pinned;
  `check_prod_images_digest_pinned` now reads every `FROM` of every Dockerfile
  the prod compose names.
- The yearly audit-log rotation the cron installer sets up could never have
  run: the installed line omitted the `--actor-user-id` the purge requires, so
  it exited with a usage error, and the wrapper archived at a fixed 1825-day
  cutoff that ignored the retention engine shipped at v9.234. The wrapper now
  archives `--from-policy` by default (`--cutoff-days` is an explicit
  override), the installed line carries the destination and the actor, and
  `check_retention_engine` pins both. Proven with a dry run of the whole
  pipeline.

**Documents that had drifted from the code.**

- PRODUCTION-READINESS.md was stamped v9.196, counted eight operator
  decisions while listing nine, and its engineering record stopped at the
  pre-P1 gaps. It is stamped v9.237, counts nine, and carries the P1 rows.
  The site and docs/design/observability.md counted eight as well; the site
  gained the retention decision.
- PRIVACY.md and DATA-MODEL.md said passwords are argon2id; the code uses
  scrypt. DATA-MODEL's `AppUser` rows described a key and a column that do
  not exist; rewritten from the schema.
- PRIVACY.md called the four purgeable audit tables permanent and described
  the purge cutoff as a number the operator types; both now describe the
  retention engine.
- observability/README.md said six alert rules; there are ten. DEPLOYMENT.md
  and INSTALL.md carried test counts from v9.194.
- The evidence numbers on the README, the site and SECURITY-CONTROLS.md were
  measured at v9.215 and v9.194. Re-measured today: 649 product tests passing
  (661 collected, 12 skip without optional backends), 95 crypto witnesses of
  99 collected (3 need a PKCS#11 token, 1 a real KMS key), 91 SQL self-tests,
  119 invariants.
- The chart gained `icon`, `home` and `sources`.

**Verified clean, and recorded as such:** pip-audit finds no known
vulnerability in the pinned requirements; the Rust toolchain is pinned; Helm
lint and the prod compose validate; all four workflows are green; no
TODO/FIXME markers and no secret material in the tracked tree; the GitHub
metadata is current; every operator route redirects to login when
unauthenticated, `/demo` and `/api/quit` are unreachable in production, the
login `next=` parameter ignores an off-host target, authenticated pages are
`no-store`, and the security headers are as SECURITY-CONTROLS.md states.

Proven: 582 web tests (570 passed, 12 skipped), 79 CLI, 91 SQL, 99 crypto
witnesses (95 passed), 119 detection tests, 119 invariants, and the pages
themselves in a browser.

---

## v9.236 — 2026-09-05 (the retention decision gets an operator surface; P1.11 closes)

Roadmap P1.11, third of three ships, and the row closes. The engine and the
per-class purge landed at v9.234 and v9.235; until now the only way to read or
change a retention decision was to write the SQL by hand, which is not a
surface an operator should be asked to use for a decision an assessor will
read.

`polaris-id retention-show` prints what is in force per class, the cutoff each
resolves to, and with `--history` the decisions those replaced, with their
justifications. `polaris-id retention-set` records a decision or adopts a named
template. Both take `--jurisdiction`; omitting it means the deployment default.

The command refuses what the database refuses, before the round trip and in the
operator's language: retention below the 365-day floor, a justification under
twenty characters, a non-admin actor, and `--template` mixed with an explicit
class. Setting a decision supersedes rather than edits, so the previous
decision and its reasoning stay readable.

Proven by eight CLI tests in `RetentionCommandTests`, including that a
superseded decision stays visible and that a jurisdiction with one class set
falls back to the deployment default for the rest.

**P1.11 is closed.** The retention decision is data with a floor no
configuration reaches, append-only with one-way supersession, resolved per
class, enforced by the purge, carried end to end by the archive chain, recorded
in the checkpoint, drilled in CI, and operable from the CLI.

---

## v9.235 — 2026-09-05 (the retention schedule reaches the purge, and the chain is finally drilled)

Roadmap P1.11, second of three ships. v9.234 made retention a per-class
decision but left the purge taking one cutoff for all four classes. Under
MINIMIZED that meant a five-year purge left two years of verification history
the schedule said could go, and a two-year purge was refused because it fell
inside the civic record's window. Half the engine was unusable.

**Per class, end to end.** `polaris-archive.sh --from-policy` resolves
`retention_cutoff` for each class and exports each table at its own boundary,
recording all four in the manifest under `cutoff_by_class` alongside the
jurisdiction. `polaris-purge.sh` reads them back and passes them to
`uc_archive_purge` as `p_class_cutoffs`; the coverage pre-check counts per
class at that class's own cutoff. The scalar `cutoff_iso` stays, set to the
oldest of the four, so a reader that ignores per-class cutoffs cannot delete a
row the archive does not hold.

**The procedure takes the archive's numbers rather than resolving its own**,
because `retention_cutoff()` advances with `now()` and would drift past the
archive between the archive run and the purge. It checks what it is given:
each cutoff must be in the past, must not be inside its class's retention
window, and must not be older than the manifest scalar. An archive taken under
a longer-lived policy than the one in force is refused. Called without
`p_class_cutoffs` the procedure behaves exactly as at v9.234, refusal included.

**The checkpoint says what happened.** `LifecycleArchiveCheckpoint` gains
`cutoff_source`, `jurisdiction`, and the four cutoffs that applied. It is the
audit of record for the deletion carve-out, and one scalar no longer describes
a purge.

**A gap the drill found.** The purge hashed the tarball for the checkpoint but
never checked its contents against the manifest, so an archive whose CSVs had
been edited was accepted and the rows it no longer held were deleted anyway.
`polaris-archive.sh --verify-latest` did this check; the step that actually
deletes did not. It does now, before anything is deleted. The manifest is still
unsigned, and the record says so: what catches an edit to both the CSVs and
their hashes is the coverage pre-check against the live database.

**The chain is drilled.** `scripts/polaris-retention-drill.sh` adopts
MINIMIZED, archives from policy, proves an edited archive is refused, purges,
and checks that a three-year-old lifecycle row is held while a three-year-old
verification row goes. It runs on every CI push. The archive-then-purge chain
shipped at v8.87 and until now had never run in CI at all: the scripts were
reviewed, the procedure was unit-tested, and the two had never been put end to
end by anything but a human at a terminal.

Also: `polaris-archive.sh` and `polaris-purge.sh` no longer use `declare -A`,
which macOS's bash 3.2 does not have, so both run on the machine the operator
is actually sitting at.

Proven: 13 SQL self-tests in Section S (suite 91), 11 DB-backed tests in
`TestRetentionEngine`, the drill itself, and `check_retention_engine` extended
to fail the build if the per-class path, the archive verification or the drill
goes missing.

Ship 3 of P1.11 remains: the operator CLI surface.

---

## v9.234 — 2026-09-05 (retention becomes a recorded decision with a floor)

Roadmap P1.11, first of three ships. The archive-then-purge chain has been
audited since v8.87 in every part except the number that mattered: the cutoff
was whatever the operator typed. The database accepted a purge at "older than
one hour" as readily as one at five years, and nothing recorded who had decided
the retention window or why. That is a coercion vector, and the same vocation
that refuses unbounded retention refuses retention short enough to erase the
record.

**The decision is data.** `RetentionPolicy` (the 30th table) holds one
effective row per (table class, jurisdiction): the days, a justification of at
least twenty characters, the operator, and when it took effect. A partial
unique index keeps two effective policies from disagreeing about one class.

**The floor is a constraint.** `CHECK (retention_days >= 365)`. No
configuration path reaches below a year; lowering it means editing the schema
and answering for it. `check_retention_engine` (invariant 119) fails the build
if the floor is lowered or removed, if the purge stops consulting the policy,
or if it reads the policy and narrows silently instead of refusing.

**The purge obeys it.** `uc_archive_purge` gains a `p_jurisdiction` parameter,
resolves the effective retention for every class it would delete from, and
raises if the cutoff is inside any of those windows, naming the class and the
earliest cutoff it would accept.

**The decision is append-only.** `trg_retention_policy_immutable` refuses
DELETE, permits only `superseded_at` to change, and refuses to un-set or
backdate it. `polaris_app` is revoked UPDATE and DELETE, the same privilege
boundary the other append-only tables have. Changing a retention decision
appends a row; the previous decision and its justification stay readable.

`uc_apply_retention_template` adopts `STANDARD-5Y` or `MINIMIZED` for a
jurisdiction in one admin-gated transaction. A fresh database ships with five
years for every class, and the migration seeds the same for an existing
deployment, so nothing runs unbounded while waiting for an operator.

Proven: nine SQL self-tests (Section S, suite now 87), seven DB-backed tests in
`TestRetentionEngine`, the privilege boundary asserted for the new table from a
real `polaris_app` connection, and the upgrade path rehearsed on a database
loaded from the previous schema and migrated forward. Documented in
[docs/design/retention.md](docs/design/retention.md), the DATA-MODEL entry, and
a runbook section in OPERATIONS.md. Table counts restamped 29 to 30 (33 to 34
migrated) across every surface that states them; the procedure count in
`polaris_sql/README.md` was stale at 15 against 16 and is now 18, measured.

Ships 2 and 3 of P1.11 remain: per-class cutoffs driven end to end from the
archive script, and the operator CLI surface.

---

## v9.233 — 2026-09-05 (the design index says what the pass found, and the last three stamps are re-verified)

Closing the voice pass. The index's note said a voice pass was recorded as
deferred; it now says what the pass actually turned up, so a reader arriving
at `docs/design/` knows the records were checked against the code rather than
merely tidied.

- **Three version stamps survive, and all three earn it**: the note that these
  documents moved out of `DEVNOTES/` at v9.224, the measured ZK performance
  table, and the SLH-DSA status, which is re-verified and restamped at this
  version rather than left reading v9.194.
- **The last shouted negative is restated.** The substrate's storage row said
  Polaris does NOT do application-level encryption at rest; it now says what
  is true, that the operator's filesystem encryption is the layer that
  matters, and points at the decision that owns it.

## v9.232 — 2026-09-05 (the voice pass, part three: the last six records, and the substrate manifest stops listing a deleted library)

The six largest records, and the end of the pass. Every one of the
twenty-two design documents now opens with its reader, states what it
describes in present tense, and cites only objects that exist.

- **`substrate.md` listed d3 as a required dependency.** The atlas globe it
  powered was deleted at v9.221, along with the vendored library itself. The
  row is now MapLibre GL, with the basemap tile service named as the separate
  external dependency it is, and the note that the Atlas degrades to markers
  rather than failing when that service is unreachable. Its opening also
  stopped deferring to an appendix of the report for the argument it is
  making, and now makes it.
- **`concurrency.md` said the rate limiter was in-process only**, with a
  multi-worker deployment as an acknowledged limitation and Redis as future
  work. Redis is the production backend and has been for versions. Its six
  lock-pattern headings had lost their subjects to the identifier sweep and
  read `## Advisory-lock pattern: UC-8 / (added v8.15)`.
- **`threat-model.md` carried the same stale deferral**, listing the
  multi-worker rate limit as an open backlog item and rating the residual risk
  as deferred. That row is removed and the residual risk restated.
- **`duress-codes.md` referenced a watcher channel** in the apparatus removed
  at v9.55, and closed with a mission-completion section whose counts, 23
  tables, 13 procedures, 14 triggers, were each wrong. The rewrite keeps every
  technical claim and drops the ceremony.
- **`federation.md` and `zk-snark.md`** were organised around numbered audit
  refinements, R1 through R9, which meant nothing to a reader who had not seen
  the audit. Both are reorganised by what the mechanism does, with the
  refinements folded into the prose that needed them.
- **The remaining `v1` and `v2` vocabulary is gone.** Those numbers referred
  to a schema generation, not to any version this repository ships, and a
  reader had no way to know which.

With this the pass is complete: twenty-two records, four ships, no em-dashes,
no mission identifiers, and every cited SQL object, test and route verified
against the tree.

## v9.231 — 2026-09-05 (the voice pass, part two: nine more records, and a rule catalogue that described a system removed at v9.55)

Nine documents rewritten. As in part one, the rereading found claims that had
quietly stopped being true.

- **`rasp-rules.md` was cataloguing a system that no longer exists.** Its
  anomaly rules were channels in `polaris_hydra/watchers/`, removed at v9.55,
  and one of them watched a foresight acceptance log removed with it. It
  listed the Caddy rate limit as a gap, though the edge has shipped a
  compiled-in `rate_limit` zone for versions; it counted seven of twelve rules
  in a list of eleven; and it was stamped as current at v9.23. The rewrite
  states what enforces each bound today, names the alert rules that carry the
  detection half, and reduces the open list to three real items, the largest
  being that nothing bounds how often one agency may verify one individual.
- **`audit-of-record.md` listed nine instances and then thirteen**, in a table
  that had split in half and lost its header, with four ship identifiers
  truncated to `(v8.21 /`. It now lists all fourteen surfaces against the
  trigger that enforces each, including `TokenStateEpochLeaf`, which it had
  never mentioned, and states plainly that `RecoveryRequest` is the one
  instance resting on procedure discipline rather than on the schema.
- **`multi-sig-migration.md` said signatures were placeholder bytes.** Real
  ML-DSA-65 signing has been wired into issuance since v9.58 and both
  production paths use it; the placeholder is the seed-data path, and it
  labels itself so the two cannot be confused.
- **`tiered-enrollment.md`, `issuer-discretion.md` and `recovery-ceremony.md`**
  had lost sentence subjects to the identifier sweep: a heading merged with a
  sentence, a paragraph beginning "implements the schema's answer", a
  cross-reference reading "the constraint calibrates against". All three cited
  `proposals/`, a directory that does not exist, and `issuer-discretion.md`
  attributed the append-only audit to C5, which is the constraint about inline
  scripts.
- **`observability.md` told the operator to write their own exporter.**
  Prometheus text format, ten alert rules, promtool tests, Alertmanager
  routing and Grafana dashboards all ship; the document predated every one of
  them, listed two log events where seven exist, and closed with pseudocode
  telling an implementer to wire up call sites that have been wired for
  versions.
- **`atlas-scaling.md` described the d3 globe** deleted at v9.221, down to the
  enter-update-exit render path and the reticle ornaments, and carried a
  truncated heading and two stale roadmap references.
- **`zk-soundness.md` and `anchoring.md`** are corrected rather than rewritten:
  both were accurate. The soundness ledger drops its citations to a sibling
  project a reader cannot open, and states the signing default the way the
  code actually behaves.

## v9.230 — 2026-09-05 (the voice pass over the design records, part one of five: five documents, and three claims that had gone false)

The twenty-two design records moved into `docs/design/` at v9.224 with a
reader, a job and no mission identifiers. Their bodies still read as working
notes, and rereading them line by line is finding drift, not just tone.

- **`two-witness-principle.md` said the signature path had no second witness.**
  It has had one since v9.133: liboqs is cross-checked against
  `cryptography`'s independent FIPS 204 implementation, and
  `check_pqc_second_witness` pins both halves. The abstention row is now the
  history it was, rather than the current state.
- **`token-signature.md` described a table that does not exist.** It called
  the relation one to one, cited a partial unique index and a
  `tg_tokensignature_ordering` trigger that appears nowhere in the schema, and
  put a 4096-byte ceiling on a `BYTEA` column that has none. What is actually
  there is one signature per algorithm during a migration window, a partial
  index over the non-deprecated rows, and two triggers. The record now
  describes that, including `signing_public_key_hex`, which is why
  verification survives a key rotation and which the record had never
  mentioned. The schema comment that named the phantom trigger is corrected in
  the same commit.
- **`webauthn.md` said attestation was not checked.** The policy has been
  environment-driven since v9.189: conveyance, an authenticator allow-list, a
  refusal of `none` attestation, user verification on both ceremonies, and
  hardware-only enrolment, all validated at boot. It also counted four states
  as three, cited a test file that does not exist, and explained the
  no-bypass recovery path by invoking the constitutional clause about money,
  which has nothing to do with it.
- **`rate-limiter.md` and `abuse-controls.md`** carried sentences the v9.207
  em-dash sweep had broken mid-clause, including one that lost its subject and
  one that lost a closing parenthesis. Both are rewritten in declarative
  prose, with the log event renamed to `quota.refused` as v9.210 left it.
- **The em-dash hook stops exempting a directory that no longer exists.**
  `DEVNOTES/ships/` was exempt as a verbatim record; its contents are
  published documentation now, and the exemption went with the directory.

## v9.229 — 2026-09-05 (the last two indexes stop describing themselves by what they are not)

`meta/README.md` and `meta/tla/README.md` were the two survivors of the
"What this directory is NOT" pattern the pass removed everywhere else, and the
TLA+ index carried a run command for a file that does not exist.

- **Both open with a reader and a job**, list what they hold, and point at
  `docs/design/` for the mechanism records that moved there, rather than
  defining themselves against three other directories.
- **The TLA+ run instructions work.** The spec ships without a TLC
  configuration; the previous command named a `.cfg` and a `.tla` that are not
  in the directory. The README now writes the configuration out, from the
  comment at the foot of the spec, and says why it is not committed: nothing
  re-runs it, so creating it is part of choosing to check the spec.

## v9.228 — 2026-09-05 (the README routes a reader to the design records)

The design set moved into the published documentation at v9.224 and the front
page never learned about it: a reader asking why a mechanism works the way it
does had no row in the routing table, only the six links inside the hard-parts
section.

- The Documentation table gains the row, between operating a deployment and
  reading the report.

## v9.227 — 2026-09-04 (the sticky masthead stops showing the page through itself)

Read on the published site rather than in a local file: the navigation bar
added at v9.217 carried a 12 percent transparent background, so scrolled
content, code blocks especially, bled through it. Anchor links also landed
their heading underneath the bar.

- The bar is opaque, and every anchored section carries a scroll margin the
  height of the bar, so a link from the navigation lands its heading in view
  rather than behind it.

## v9.226 — 2026-09-04 (the presentation pass is closed: twenty-nine ships, five roadmap rows, three defects nobody had seen)

The rework the owner authorized on 2026-09-02 covered every human-facing
surface: the documentation, the GitHub presence, the demo site, the
repository's organization, and the software's own interface. It decomposed
into twenty-nine ships across five roadmap rows, and all of them have shipped.

- **ROADMAP.md marks P1.13 through P1.17 done**, each with the version range
  that closed it, and the standing rule that authorized the pass now says it
  does not expire with those rows: a surface that drifts again is reworked
  under it rather than re-authorized.
- **The sub-roadmap records the outcome**, including the three defects the
  audit had not found and the pass did: the System Dashboard rendering blank
  from v9.211 to v9.220, the Atlas legend naming a colour for events it never
  plots, and an image build that shipped the whole repository to the daemon
  because no `.dockerignore` existed.
- **What was deferred is named with its reason**: a voice pass over the design
  records now published under `docs/design/`, a second image format for the
  Atlas captures (measured, not adopted), and the two Phase 1 rows that are
  engineering and external work rather than presentation.

The pass added fourteen invariant checks, from 104 at v9.193 to 118 here, each
with a detection test that proves it fails on a broken fixture.

## v9.225 — 2026-09-04 (P1.16 ship 6: the map recomputes itself, the build context stops shipping the repository, and the report proves it is current)

The last ship of the repository row, and the last of the presentation pass. Three
documents that described the tree were maintained by hand and had drifted; one
build input was never bounded at all.

- **The system map is enforced.** `check_system_map_covers_the_tree` compares
  the At a glance tree against the tracked top-level paths and the CI job list
  against the workflow's job keys, failing in both directions: a path the map
  omits, a path it lists that no longer exists, a job that has drifted. It
  caught two omissions immediately, the code of conduct and the citation file.
  The map now says which parts of itself are recomputed and which are prose.
- **There was no `.dockerignore`.** Every image build sent the whole
  repository to the daemon: the git history, the site captures, the report PDF,
  the test suites, and, on a developer machine, whatever sat in
  `polaris_web/secrets/`. The build context is now an allowlist by exclusion,
  and the full production image was rebuilt against it to prove nothing an
  image copies was cut.
- **The rendered report proves it is current.** `docs/paper/` ships a LaTeX
  source and its PDF with nothing forcing them to move together.
  `rendered-from.txt` records the SHA-256 of the source the PDF came from, and
  `check_paper_pdf_is_current` fails on divergence. Rendering in CI would need
  a LaTeX toolchain and byte-reproducible output; the stamp catches the same
  failure, which is a reader citing text the repository has since changed.
- **The schema loader stops lying about itself.** Its ALL FILES LOADED banner
  sat four files before the end, so the two files that print assertions after
  the test summary looked like they had run before it. The banner moves to the
  end and says where to read; the one silently sourced file gets its own line;
  the numeric prefixes are explained as identifiers, with the three places the
  load order deliberately departs from them; and the superuser prerequisite is
  stated without the incident narrative.
- **`.gitignore` is rewritten** without release numbers, decision-class labels
  or the incident story, keeping the one rule that matters: a pattern must not
  carry a trailing inline comment, because git does not strip them. Every
  ignore was verified to still bind after the rewrite. `CONTRIBUTING.md` gains
  the command that cleans the artifacts the suites leave behind.
- **`docs/operator/SECURITY.md` becomes `SECURITY-CONTROLS.md`**, so the root
  policy is the only file carrying the name GitHub reads, with a pointer
  between them and 31 references repointed.
- **The naming convention is corrected**: it listed `DEVNOTES/` as both a
  plural container and an ALL_CAPS exception, and its rule against renaming a
  top-level directory now states the test a rename has to pass.

## v9.224 — 2026-09-04 (P1.16 ship 5: the design records move into the published documentation)

The threat model, the concurrency catalogue, the substrate manifest, the ZK
soundness ledger, the two-witness principle and one record per mechanism were
filed under `DEVNOTES/`, a directory whose name tells an assessor not to look
there. They are exactly the documents an assessor reads.

- **Twenty-two documents move to `docs/design/`**, flattened: the ten
  cross-cutting records and the twelve per-mechanism ones, with the `ships/`
  subdirectory gone. The index states a reader and a job for each.
- **Two duplications resolve.** The redaction proof existed twice; the longer
  copy under `meta/` carries the adversary model, so the shorter one is
  deleted and its inbound links repointed. The two quantum-observer notes,
  one speculative and one honest, merge into a single document that says
  plainly what the table is: a reserved scaffold, inert, with the three
  conditions that would reopen the decision.
- **Every record opens with its reader and its job**, and the internal
  mission identifiers (`R11-3`, `M2-8`, the `Ships with` and `Introduced`
  headers) are stripped. A full voice pass over the bodies is recorded in the
  plan rather than done here, so that the move stayed reviewable.
- **209 references were rewritten across 61 files**, each resolved against its
  own directory rather than string-replaced, and the link checker confirms all
  845 resolve. `test_prose_and_sql_forms_agree`, which compares the substrate
  manifest against the `SystemDependency` view, was skipping silently on the
  moved path and now runs again.
- **`DEVNOTES/` keeps the four notes that are genuinely internal**: the house
  style, the gotcha list, the project record and the plan of this pass. Its
  README says so, and the v8.26 reorganization receipt it carried is gone.

## v9.223 — 2026-09-04 (P1.16 ship 4: every top-level directory says who it is for)

Three directories held load-bearing material with no way in: the invariant
layer that gates every push, the three deployment substrates, and the
published page. A reader had to open files and infer.

- **`polaris_checks/README.md`** states what a check is, why every check is
  paired with a detection test that proves it can fail, and maps each of the
  ten constraints to the function that asserts it. Every check name in the
  table was verified against the source, and the procedure for adding one ends
  where it should: the stated-count check tells you which documents to
  restamp.
- **`deploy/README.md`** names the three substrates with their status in the
  first table: the Linux host under systemd is supported and exercised on
  Debian and Rocky in CI; the Kubernetes profile is a reference that runs one
  PostgreSQL replica, so high availability is roadmap work rather than a
  shipped feature; the observability directory is a configuration, not a
  deployment, because the pager and the rotation belong to the operator. It
  also says where the compose stack actually lives, which is beside the
  application it composes.
- **`site/README.md`** landed with P1.15 ship 3, and **`scripts/README.md`**
  with the rename ship. With those, every package and top-level directory in
  the tree carries a README that names its reader in the first sentence.
- **The map and the hub point at them**: the system map's tree and rows, and a
  new closing paragraph in the documentation hub listing all eight package
  READMEs, since they are the one part of the documentation set that does not
  live under `docs/`.

## v9.222 — 2026-09-04 (P1.16 ship 3: the scripts are named for their job, and indexed by their reader)

Seven scripts carried an `ai-` prefix that said who wrote them rather than who
runs them. Two of the seven are contributor gates that CI invokes on every
push, one is the assessor tool the red-team scope points at, and one renders
every release body. None of that is agent tooling, and an operator opening
`scripts/` should not have to decide which half of the directory is meant for
them.

- **One naming rule.** `ai-coverage.sh` becomes `polaris-coverage.sh`,
  `ai-link-check.sh` becomes `polaris-link-check.sh`, `ai-test.sh` becomes
  `polaris-test.sh`, `ai-done.sh` becomes `polaris-preflight.sh` (named for
  what it is rather than for the state it announces),
  `ai-release-notes.sh` becomes `polaris-release-notes.sh`,
  `ai-authz-audit.sh` becomes `polaris-authz-audit.sh`, and its Python half
  becomes `polaris_authz_audit.py`. Every caller moves in the same commit: two
  workflows, the pre-commit configuration, the coverage configuration, the
  check layer and its tests, the web test suite, the version file's own bump
  procedure, and nine documents.
- **`scripts/README.md` is the index.** Forty scripts in four tables by reader:
  operator, CI, contributor, and the two Python helpers. Each row states what
  the script does and who calls it.
- **The naming convention is rewritten.** `docs/CONVENTIONS.md` described an
  agent layer and an operator layer; there is one layer now, and the reader of
  a script is stated in its header rather than encoded in its name.
- **Four headers lose their archaeology.** The pre-ship gate no longer opens
  by naming the apparatus removed at v9.55, and three others drop version
  stamps that described when they were written rather than what they do.

## v9.221 — 2026-09-04 (P1.16 ship 1: delete what nothing calls, and prove the one property a deleted script was carrying)

Subtractive, with one addition: the schema loader's idempotency claim moves
from a script nobody ran into the CI job that already builds the database.

- **The d3 globe is gone from the tree.** `atlas-globe.js` was replaced by the
  MapLibre renderer and has been unreachable since; with it go the three
  vendored assets it alone used, 395 KB of d3, topojson and a world topology
  file. The four documents that described the page as a WebGL globe with
  reticles now describe the map that ships, including the end-to-end test's
  own docstring.
- **Four scripts are deleted.** `ai-bootstrap.sh` was a session-start helper
  for an agent, which is not an operational surface.
  `polaris-concurrency-harness.sh` measured a property the threaded product
  tests already assert. `polaris-doctor.sh` was a one-line wrapper around the
  macOS launcher, sitting in the operator directory and naming a caller that
  does not exist; the runbooks now point at `/api/health` and at the
  launcher's own subcommand. `polaris-idempotency-test.sh` is deleted only
  because its property is now asserted on every push.
- **The loader's idempotency is a CI assertion.** After the schema loads and
  the migrations apply, CI reloads the schema, re-applies the migrations, and
  fails if the table, trigger or seed-row counts moved. The measurement caught
  the nuance the script's name obscured: a reload *without* re-migrating drops
  the migration-created tables by design, so the assertion covers the
  documented path, not the loader alone.
- **`nginx.conf.example` is deleted.** The native nginx path was retired at
  v9.176 for bypassing the container hardening, the pgbouncer and postgres TLS
  hops, pgBackRest and the secrets layout. A committed sample of it was a live
  route to an insecure deployment; its two referrers now name the Caddy edge.
- **One copy of the license.** The Apache text was carried three times, byte
  identical. The packages are parts of one work rather than separately
  distributed projects, so the root copy is the only one, `polaris_zk`
  declares the SPDX field its consumers read, and NOTICE states the rule.
- **The agent settings file is untracked**, its hook target having been
  deleted deliberately at an earlier pass, and a stray host-named coverage
  artifact is removed. The `.gitignore` and TLA+ comments that cited removed
  apparatus now state their own reasoning.

## v9.220 — 2026-09-04 (the System Dashboard was blank, and the stylesheet stops carrying a renderer that no longer exists)

**The dashboard rendered nothing.** v9.211 deleted the post-login boot overlay
and its keyframes, but left behind the stagger rules that faded the dashboard
panels in behind it. Those rules set every panel to `opacity: 0` and animated
it back with `scifi-reveal-fade`, which no longer existed, so from v9.211 to
this version the System Dashboard showed its title and nothing else. Every
element was in the DOM at full size, which is why 467 tests and the invariant
layer all passed: the content was present and invisible.

- **The orphaned reveal apparatus is deleted**, including the reduced-motion
  block that existed only to undo it. The dashboard now renders when the page
  does, which is what v9.211 intended.
- **`check_css_animations_resolve` is check 116.** Every animation name a
  stylesheet uses must have a `@keyframes` in that stylesheet. Run against the
  previous release it fails with the exact diagnosis; run against this one it
  passes. Its detection test covers the orphan, the timing and fill keywords
  that are not animation names, and a missing stylesheet.
- **The stylesheet loses 38 selectors and 282 lines** left by the d3 globe the
  Atlas replaced: the globe toolbar, the node and reticle families with their
  label and pulse rules, the two unused HUD corners, the live indicator, the
  notice rows, and the filter chip. Every removal was checked against the
  templates and the live scripts first, and the file parses with no errors
  before and after each one.

## v9.219 — 2026-09-04 (P1.15 ship 4: the page cannot publish a number or a link that has stopped being true)

The site claimed its own claims were gated. They were not: the link checker
never read an `href` or a `src`, and the Pages workflow only ran when something
under `site/` changed, which is never the commit that makes the page wrong. A
new table, a new check or a renamed document would publish silently.

- **The link checker reads HTML.** Every `href` and `src` in plain HTML now
  resolves against the tree, with Flask templates skipped because their
  attributes are `url_for()` calls. Every
  `github.com/EgorKhaklin/polaris-id/blob/main/...` link, from any file, is
  stripped back to the path it names and checked too, which is what the site's
  outbound links have to be: a relative link would 404 on the published page.
  808 references now, up from 771, and a probe with a broken image and a broken
  document link is reported as two failures.
- **Pages verifies before it publishes.** A verify job runs the invariant layer
  and the link check, and the deploy job needs it. A page whose numbers no
  longer match the repository, or whose images no longer exist, is not
  deployed.
- **The path filter is gone.** The workflow ran only on changes under `site/`
  and to itself, which made it structurally blind: the counts it publishes are
  measured from the schema, the check layer and the CI file. It now runs on
  every push to main.
- **The evidence lede is restored to the strong form**, because it is now true:
  every number and every link on the page is checked before publication, and
  either one failing stops the deployment. The two test counts stay named as a
  per-release measurement.

## v9.218 — 2026-09-04 (P1.15 ship 3: one copy of every image, a logo that is not a megabyte, and one palette)

The repository carried each published image twice, byte for byte, in `assets/`
and in `site/`, with nothing to keep the pair in step. The emblem was a
1024-pixel, 942 KB PNG drawn at 180 to 220 pixels. And the page forked the
application's palette under its own token names, so a colour change in the
product could not be seen to have skipped the site.

- **One copy of every binary, in `site/`.** The published page, the images and
  the logo now live in one directory, and the README links into it. The
  alternative the plan recorded, keeping `assets/` canonical and copying it
  into the Pages artifact at build time, was rejected on use: it leaves the
  page broken when opened from a clone, which is exactly when someone is
  editing it. `assets/` is deleted, and `site/README.md` states the rule.
- **The emblem is 44 KB.** Re-exported at 440 pixels, the size it is actually
  drawn at on both surfaces, and quantised to 256 colours with no visible
  loss at that scale. A 95 percent reduction.
- **Every image declares its dimensions**, the emblem is fetched at high
  priority, and the captures decode asynchronously, so the layout no longer
  shifts as they arrive.
- **One palette, one set of names.** `site/tokens.css` carries the tokens under
  the same names `polaris_web/static/polaris.css` uses, the page and the 404
  page both link it, and `check_site_tokens_match_app` fails if a name or a
  value diverges or if the page redeclares the palette inline. Check 115, with
  its detection test.
- **The capture sizes were measured rather than assumed.** Re-exporting the two
  paired captures at 1600 pixels saves about a tenth of their bytes, because
  the source encoder is already efficient; quantising them halves the bytes but
  drops legend hues the images exist to explain. Both are recorded in the plan
  and neither is applied.

## v9.217 — 2026-09-04 (P1.15 ship 2: the site becomes a front door instead of a poster)

The page opened on a hero and went straight to screenshots. A reader who did
not already know what an identity token is had to infer the premise, an
assessor had no path from the page to the documents that bound its claims, and
the one paragraph admitting what this is not sat at twelve pixels above the
footer.

- **It states its premise first.** A What Polaris is section carries the
  credential-consolidation argument the rest of the page assumed: six to eight
  credentials that do not talk to each other, one token per person, disclosure
  scoped by context, and the rule that the guarantees live in the database.
- **What this is not is a section, at heading weight.** The readiness ledger's
  own status line, the eight decisions that belong to the deploying
  organization named one by one, and the first link from this page to the
  ledger. The Seton Hill scope note folds into it, where a reader will see it.
- **Run it names the four paths that actually ship**: evaluate locally,
  the single-host compose profile, a Linux server under systemd, and the
  Kubernetes reference profile, each carrying its own limit. The compose
  subhead stops saying Production, in the README too, since a profile name is
  not a readiness claim.
- **An Evaluate it row** puts ten assessor documents one click away: the
  ledger, the constitution, the post-quantum posture, the security and privacy
  postures, the system map, the API and data-model references, the operator
  runbooks and the roadmap.
- **The page is navigable and announced.** A skip link, a `main` landmark, a
  sticky masthead styled like the application's own, ids on all nine sections
  and an `aria-labelledby` on each.
- **Three duplications are gone**: the internal use-case numbers on the threat
  cards, a second duress claim in the cryptography grid, and the motto printed
  twice.
- **The head is complete**: canonical URL, theme colour, colour scheme, site
  name, image alt and dimensions, and a Twitter card. The site gains a
  `robots.txt` and a `404.html` in its own styling.

## v9.216 — 2026-09-04 (P1.15 ship 1: the project site says only what the repository can support)

The Pages site is one of the two front doors, and it had drifted since v9.194:
numbers measured twenty-one versions ago, a claim about its own gating that was
broader than the gate, a marketing word standing in for a real access control,
and three screenshots of invented data with nothing on the page saying so.

- **The evidence numbers are re-measured at this version.** 645 product tests
  passing on the reference machine, up from 640, and 76 crypto witnesses of 80
  collected, unchanged. The method is the one the README states: `pytest -q`
  per suite, with the skips named and their reason given.
- **The lede says which numbers are gated and which are measured.** The check,
  job, route and schema-table counts are recomputed from the repository on
  every push and fail the build on a mismatch; the two test counts are a
  per-release measurement. The stronger sentence returns when the site's own
  link and count gate lands in P1.15 ship 4.
- **The launcher tile is gone.** A double-click convenience sat in the evidence
  grid beside CI counts, where nothing could gate it and it measured nothing.
- **Subject focus loses "warrant-grade" for the control that exists**: it is
  restricted to the admin and auditor roles and writes an audit row on every
  use. That is the enforceable statement; the other one was a posture.
- **Every capture is labelled notional on the page**, in the caption, in the
  alt text, and in a corner badge over the figure so the label survives a
  crop. The images are not re-baked: a stamp inside a full-width PNG renders
  at about four pixels and cannot be read.
- **Two cryptography claims narrow to what the code does.** The registry claim
  now says which algorithm signed a token is data, rather than that nothing is
  hardcoded anywhere, which the shipped ML-DSA-65 signer contradicts. The
  signing cell states that both production paths sign with real liboqs bytes
  and that a development run records a deterministic placeholder under a label
  that says so.

## v9.215 — 2026-09-04 (every image is built one way: retried, and stamped with the version that shipped it)

Three releases in a row were marked red by outages nobody here can fix. A
Docker Hub token endpoint reset the connection during v9.212. A Docker Hub
manifest fetch reset during the same run's rebuild. A Debian mirror mid-sync
served a package of the wrong size during v9.213, which is why that release's
green run had to be dispatched by hand. None was a defect in Polaris, and each
one cost a release the run that is supposed to be its evidence.

- **One helper builds every image.** `scripts/polaris-image-build.sh` takes a
  Dockerfile and a tag, or `--stack <suffix>` for the whole four-image
  production set, and retries three times with a doubling backoff. Every image
  build in both workflows goes through it, which also collapsed twelve
  scattered build lines into five calls.
- **The buildx build keeps its cache and gains a second attempt.** It cannot
  move into the script without losing the GitHub Actions layer cache, so the
  step is marked `continue-on-error` and repeated once on failure.
- **apt survives a mirror mid-sync.** Both apt stages in the production image
  now pass `Acquire::Retries=3`, which is the exact failure that stopped the
  v9.213 run.
- **Every image says which version it is.** The production image labelled
  itself `8.77`, a literal frozen 137 versions ago, and pointed its source
  label at `github.com/polaris-id/polaris`, a repository that is not this one.
  The version now comes from `polaris_web/__version__.py` through a build
  argument the helper passes, the source label names this repository, and the
  three images that carried no provenance labels at all now carry the same
  set.
- **A check keeps it that way.** `check_image_builds_are_retried` fails on a
  bare `docker build` in any workflow, on an image whose version label is a
  literal, on an `apt-get` without a mirror retry, and on a buildx step with no
  second attempt. It is check 114, and it has its detection test.

## v9.214 — 2026-09-04 (the map's colours say what they mean)

The Atlas legend named cyan zero-knowledge, and the map drew every clean
verification cluster cyan. A zero-knowledge verification is never plotted:
`polaris_sql/11_atlas.sql` excludes it from the cluster layer and from the
precise-point layer, so a cyan marker could not have meant what the legend
said it meant. Cyan meant "an aggregate with no failures in it".

- **Cyan is the colour of a cluster.** The tone is renamed from zk to cluster
  at its definition and at every use, and a cluster is drawn in it whichever
  event kind it aggregates. Colouring lifecycle clusters gold said nothing,
  because the map shows one kind at a time, and it collided with gold meaning
  full disclosure at the point layer.
- **The legend states the absence rather than mislabelling it.** Four colours,
  each named for what it marks: a cluster of events, a selective disclosure, a
  full disclosure, a failure or revocation. Beside them, in the muted weight,
  the guarantee itself: zero-knowledge verifications are never plotted.
- **The point layer says so if it is ever wrong.** A zero-knowledge row cannot
  reach it through the shipped queries, so one that arrives means the server
  broke C6. It is drawn in the aggregate colour, never as a disclosure level,
  and the console carries the warning.
- **Both front doors state the mechanism.** The README and the site said
  zero-knowledge verifications "carry no location, by construction", which the
  schema contradicts: `polaris_sql/01_schema.sql` gives every verification
  event nullable coordinates and the seed populates them for zero-knowledge
  rows too. What is true is that the map's queries exclude them and that a
  zero-knowledge event carries no token id to attribute it by, which is C2.
- **The three Atlas captures are re-taken** so the shipped images show the
  corrected legend.

## v9.213 — 2026-09-04 (the Atlas screenshots show the Atlas that ships, and the corner readouts stay readable)

The three Atlas images in the README and on the project site were captured at
v9.205. Six ships later the surface they show no longer exists: the menu, the
dock tab names and the marker vocabulary all changed at v9.211, and the
subject-focus frame carried a caption the picture did not support. A
screenshot that misrepresents the running software is a claim the repository
cannot back, so all three are re-taken against this version.

- **The corner readouts get a contrast scrim.** They float directly on the
  basemap, which draws its own place labels in a similar weight, so over a
  populated metro the active-token and anomaly figures were competing with
  town names for the same pixels. A soft radial halo behind each readout,
  plus a text shadow on the values, restores the contrast without drawing a
  panel around the numbers. This is a fix to the product; the new captures
  simply show it.
- **The subject-focus capture now shows what its caption claims.** The
  previous frame was taken against the two-million-event synthetic log, where
  every holder carries a quarter-million events scattered worldwide, so the
  view fitted to a whole hemisphere and drew no path at all. It is re-taken
  against the ordinary seed: one holder, four disclosed events, the gold path
  from the issuance in Manhattan to a travel check at the airport and back,
  with the selected event's disclosure level, agency and coordinate open in
  the detail panel beside it.
- **Two site captions stop claiming a feature that does not exist.** The
  street-level pair said the map "flattens into a 3D street map" with "3D
  buildings"; there is no extrusion layer in the Atlas and never has been.
  The caption now says what the image shows, which is clusters resolving into
  single events on their own coordinates. The hero caption drops "globe" and
  "orbit" for the flat map it is, and says marker rather than reticle, the
  word the interface itself stopped using at v9.211.
- **The README caption carries the new capture stamp**, so the version that
  produced the picture is still on the page next to it.

## v9.212 — 2026-09-04 (the freeze line is recorded closed, on the owner's direction)

The constitution's freeze line was written as a definition of done with an
expiry: six mechanically verifiable conditions, three permitted classes of
work after them, and an abandonment clause for the thesis. All six conditions
are met, the abandonment clause fired at the v9.40 terminus, and the external
trigger the section requires for a new arc occurred on 2026-08-31. Until now
MISSION.md carried that as a note appended by an agent; the owner directed
that it be recorded as what it is.

- **Nothing in the freeze line is edited.** The six conditions, the three
  classes of permitted work, the new-arc rule, the abandonment clause and the
  tamper paragraph stand byte for byte. The section's own mechanism, its
  amendment log, carries the change.
- **The note above the log becomes a closure statement**: which condition is
  met and by what command, that the abandonment clause fired and that a check
  keeps `THESIS.md` from drifting back to the open framing, that the arc is
  national deployment under ROADMAP.md's phases with the constitution as a
  hard gate on each, and that `docs/PRODUCTION-READINESS.md` is the bound on
  every claim the repository makes.
- **The amendment log gains its second row**, dated today: pending to closed,
  cost none because no condition changed, authority the owner's recorded
  direction. Its header column is renamed from Sanctum to Authority, since
  the Sanctum apparatus it named was removed at v9.55; the first row keeps
  its own authority verbatim.
- **The amendment rule at the end of the document** now says the conditions
  are never edited (rather than that the section is never edited, which the
  log contradicted), and states plainly that "production ready" is not a
  phrase this project applies to itself until the decisions in the readiness
  ledger are recorded as made for a named deployment.
- **ROADMAP.md's decision record** is restated to match: the freeze line is
  closed, the trigger is named, the constitution still gates every phase, and
  the readiness ledger bounds the claims.

## v9.211 — 2026-09-04 (P1.17 ship 6: the chrome stops performing, and the seed stops naming its author)

The last ship of row P1.17, and of the presentation pass.

- **The post-login boot overlay is gone.** A 1.6-second "ACCESS GRANTED"
  curtain, with a scan line and a progress bar, stood between an operator
  and their dashboard on every sign-in, and the panels behind it faded in
  on a stagger. The stylesheet's own contract, three lines into the file,
  is an intelligence-report aesthetic with no decorative flourishes. The
  overlay, the stagger, their five keyframe animations and the
  `--reveal-delay` inline styles are deleted; the masthead already shows
  the operator's name and role permanently.
- **The footer states the version instead of two things that were not
  true**: a schema version literal with no referent, and a Latin motto on
  the chrome of the duress queue.
- **One cache-bust value.** Eleven hand-maintained `?v=` stamps across six
  templates (`v9145a`, `heart002`, `flash001`, and so on) become the
  shipped version, so a release busts every cached asset at once and no
  stamp can go stale on its own.
- **The Atlas speaks operations, not surveillance.** "Node Console"
  becomes "Event detail", reticles become markers in the legend and the
  help text, the feed's `god-notice` class names become `atlas-feed-item`,
  and the detail kicker reads LIFECYCLE EVENT and VERIFICATION EVENT.
- **The stylesheet is renumbered and de-archived.** Its section markers now
  match physical order (the file had 13, 16, 14, 15 in that sequence and
  four sections that never appeared in the index), the index is regenerated
  from them, five orphaned keyframes and three subsection comments carried
  from a merged skin file are deleted, and the section titles carry no
  version numbers. 3769 lines to 3662, with the brace balance verified.
- **The pager reads as a page size**, not as an internal mode name; its
  three assertions now pin the cursor parameter in the Next link, which is
  the behaviour that matters.
- **The seed's first individual is a synthetic name.** The sample database
  named the author as person #1; it now reads Adrian Vasquez, in the same
  shape as the other holders, with the SQL comments, the seed-data
  reference and five assertions moved with it.
- **The landing page tells the truth about deployment.** "Arc B (May 2026)
  closed the gap" becomes what a reader needs: the deployment path ships
  and is scripted end to end, Polaris is a reference implementation and is
  not yet a system to run with real identity data, and the readiness ledger
  is linked twice. The ML-DSA cell names the gate (real signing under the
  production default, a labelled placeholder otherwise) and the reading
  list gains the post-quantum posture.
- **The em-dash sweep finishes in the application.** The stylesheet's 19 and
  the JavaScript's 77 are converted under the same rules the documentation
  used, so no human-facing surface in the repository carries one outside the
  audit-of-record files. Every script still parses.
- **The v9.210 CI failure is fixed here.** The new metrics-ACL drill named
  its stub upstream `aclup` and told Caddy to proxy to `upstream`, so the
  in-network probe read a 502 from a hostname that did not resolve; the
  step now points at the right host, waits for the stub to answer before
  probing, and retries each probe with the edge's log on failure. Run
  verbatim on the maintainer's machine: in-network 200 on both paths,
  outside 404 on both, ordinary routes 200 either way. (The same run also
  hit a transient Docker Hub pull failure in the test job, unrelated to
  the ship.)

## v9.210 — 2026-09-03 (P1.17 ship 5: the metrics surfaces are closed at the edge, and the log stream is namespaced)

The duress signal rides on two unauthenticated routes. Until this ship the
control over who could read it existed only in prose.

- **Both shipped edges now refuse `/metrics` and `/api/metrics` from outside
  the monitoring network.** The compose `Caddyfile` and the Helm chart's
  Caddy config answer 404 on those two paths to any client outside
  `POLARIS_METRICS_ALLOW` (chart value `edge.metricsAllow`), which defaults
  to Caddy's `private_ranges`: an in-network Prometheus scrapes, the public
  internet does not, and a 404 does not even confirm the surface exists.
  Every other route is unaffected.
- **Exercised, not asserted.** The `caddy-edge` CI job now runs the edge
  image against a stub upstream and probes both branches: in-network gets 200
  on both paths, a client outside the range gets 404 on both, and an ordinary
  route serves 200 either way. Run locally against the built image before
  shipping, with the same result. `check_metrics_edge_acl` (113 checks) fails
  the build if either edge stops refusing, if a matcher stops covering both
  paths, if the operator loses the knob, or if CI stops exercising it.
- **One statement about access, in three places that agree.** The two route
  docstrings contradicted each other (one said no auth is fine because the
  counters carry no per-user data, the other said the surface must be
  ACL'd); both now say the same thing and point at
  `deploy/observability/README.md`, which describes the shipped control, the
  override, and the CI proof.
- **`observability.py` is written for an operator**: what the log stream
  emits, what each of the four counters means, why `duress_events_total` is
  the load-bearing one, and the single operational instruction. The lineage
  narrative moves to this CHANGELOG.
- **Event names are namespaced by subject**, so an operator can select a
  family from the log stream: `auth.failure`, `duress.signal`,
  `quota.refused`, `db.error`, and the start-up announcements
  `boot.session_policy`, `boot.tracing_enabled`,
  `boot.tracing_unavailable`. The inventory is published in the module
  docstring. Every consumer moved in the same commit: the abuse drill's
  grep, two runbooks, the observability note, the tracing check and its
  detection-test fixture.

## v9.209 — 2026-09-03 (P1.17 ship 4: the CLI documents itself, and it has one name)

- **The command list is generated from the registry.** Six of the twenty
  commands were missing from the module docstring, including `revoke` and
  both halves of the recovery ceremony: an operator reading `--help` did not
  know they existed. The docstring now carries all twenty with their help
  strings, and `check_cli_help_lists_every_command` (112 checks) fails the
  build in both directions, so the list cannot drift from the registry again.
- **Examples and exit codes render.** They sat in the docstring, where
  `--help` never showed them; they are now the parser's epilog, which the
  raw-description formatter prints: seven worked examples, the four exit
  codes in the operator's words, and the connection variables.
- **`--version`** reads `polaris_web/__version__.py`, so the CLI reports the
  same version as the application and the release.
- **One name.** The console script has always installed as `polaris-id`
  (`polaris-cli` belongs to an unrelated project on PyPI), while every
  runbook told the operator to type `polaris`. The documentation now says
  `polaris-id`, in 21 places across the operator runbooks, the red-team
  scope and the data model, and `--help` says it too. From a checkout, the
  help names `python3 polaris_cli/polaris.py`.
- The reference to the academic report is gone from the docstring, and the
  ticket identifiers are gone from the quota-command comments.

## v9.208 — 2026-09-03 (P1.17 ship 3: one voice for every message the operator reads)

- **One flash rule, applied to all 44 call sites:** a complete declarative
  sentence with terminal punctuation, the object named before the outcome,
  and no colon-prefixed status word. "Created individual #7" becomes
  "Individual #7 is created."; "Transitioned token #2 to DORMANT" becomes
  "Token #2 is now DORMANT."; "Issuance blocked: ..." and "Migration blocked:
  ..." become "The token could not be issued." and "The migration could not
  be completed.", each carrying the database's own sentence after it;
  "Federation trust missing: ..." states what is missing and what to do about
  it. The WebAuthn countdown pluralizes its days instead of writing "day(s)".
- **A warning now looks like a warning.** `.flash-warning` has its own style
  and glyph; before this, the enrollment-deadline countdown rendered as a
  neutral notice because no rule matched its category.
- **Errors and warnings stay until dismissed.** The 4.5-second timer erased
  the only report an operator got of a failed write. Success flashes still
  fade; error and warning flashes carry a dismiss control.
- **The error page tells the operator what happened and gives them the one
  string to quote.** The headline is derived from the status code in the
  template (nothing ever passed the `status_word` it used to read, so every
  error page said "Something went wrong"), the request id is rendered and
  matches the `X-Request-ID` header and the log line, the hints address the
  operator directly and point at the runbooks, and the 503 branch is deleted:
  no handler could ever have reached it.
- **The SQL console describes this deployment**, not the development
  database: the hardcoded `polaris_test` and `polaris_app` names are gone,
  and the read-only connection is stated alongside the keyword rule and the
  caps.
- **The login form speaks in sentences**: "Enter your username." rather than
  "OPERATOR ID REQUIRED", and the format rule is spelled out.
- Ten flash assertions repinned in the same commit. Suite 467 passed.

## v9.207 — 2026-09-03 (P1.17 ship 2: the application names things for the operator, not for the backlog)

Every internal identifier is gone from what an operator reads, and the
application's prose carries no em-dashes.

- **No ticket numbers on screen.** The nav menu is PROOFS with Merkle, ZK and
  Trust kickers instead of SUBSTRATE with R10-2, R10-1 and R11-3; the
  dashboard section is "Proofs and trust" instead of "v2 Substrate" and its
  five tiles describe what they count; the token page's section is
  "Signatures, anchors and proofs" and its three tables and four cards lost
  their R-numbers. The duress queue, the epoch list, the enrollment summary,
  the anchor list, the federation viewer and the three use-case banners
  (bounded revocation, algorithm migration, recovery) say what the mechanism
  does; the R1 to R6 labels in the duress explainer are the plain properties
  they always described (constant-time comparison, identical observable
  behaviour, audit of record, anti-revealing).
- **No citation of documents the reader does not have.** Every "PDF §9",
  "Appendix A" and "Appendix E and F" reference is replaced by the fact it
  was standing in for. The Sanctum parenthetical on the verification form and
  the exploration footnote on the epoch page are gone; the epoch page's
  "Substrate-D closure" item, which described a mission roster rather than
  the system, is deleted.
- **The demo walkthrough is rewritten in the same register.** Eleven inline
  version citations and every R-number are gone; C1, C2, C3 and C7 stay,
  because they are the one identifier scheme the page defines for its reader.
  Its claim is narrowed to what it can support: the procedures, triggers and
  constraints named are the ones this repository ships and its tests
  exercise, and the data is synthetic.
- **The duress explainer now ends with the operator's next action** (the
  metric, the alert that pages, and the response runbook) instead of a
  pointer to a design note.
- **The em-dash sweep reaches the application.** 137 conversions across 22
  templates under the same rules the documentation used, plus 52 placeholder
  glyphs repaired: an em-dash standing in for an empty table cell or a select
  prompt is now "None", "All", "Select" or the two-hyphen readout the Atlas
  JavaScript overwrites, so no page renders a comma where a value is absent.
- Assertions repinned in the same commit: the dashboard section heading, the
  token page's section and three table headings, the nav menu label, and the
  federation page's transitive-trust sentence. Suite 467 passed.

## v9.206 — 2026-09-03 (P1.17 ship 1: the demo and the launcher beacon exist only where they belong)

- **Two presentation gates, on separate axes, derived from state that
  already exists.** `POLARIS_DEMO_MODE` defaults to "not production" and
  can never be turned on under `POLARIS_ENV=production` (the boot log says
  so if asked), so a production deployment cannot advertise notional data
  over real records and a dev checkout cannot lose its honest label.
  `POLARIS_LAUNCHER_WATCH` defaults off; the macOS launcher and the dev
  compose set it. Both reach the templates through the context processor,
  never from env in Jinja.
- **The demo surface is gated.** `/demo` answers 404 outside demo mode, and
  the landing page's call-to-action pair becomes a single Sign in button.
- **The launcher beacon is gated.** `/api/heartbeat` and `/api/quit` exist
  only in launcher mode (still unauthenticated by design, still guarded
  against cross-site POSTs, still exempt from the write rate limit only
  there); the beacon script that every rendered page, including the login
  page, used to POST every ten seconds is included only in launcher mode.
  `GET /api/since-heartbeat` is deleted: nothing called it (the launcher
  reads the state files directly) and it answered anyone. 72 routes.
- **The Atlas tells the truth about its provenance from one flag.** The
  id strip and the status-bar tag render `NOTIONAL DATA` outside production
  and the operator's `POLARIS_DEPLOYMENT_LABEL` in production (or nothing);
  the "Collection / OP / POLARIS-LIVE" readout, which never changed value,
  is gone. A test exercises the production branch.
- Tests repinned and added: the Atlas provenance assertions, HeartbeatTests
  and CrossSiteGuardTests run against a launcher-mode client and prove the
  routes are absent otherwise, DemoGateTests cover both modes and the
  production refusal. API.md's launcher section now says what the two
  routes do (204, no body, no auth, cross-site refused, launcher mode only)
  instead of an authenticated admin-only quit and a timestamp-returning
  heartbeat that never existed. DEPLOYMENT.md documents the three variables.

## v9.205 — 2026-09-03 (P1.14 ship 5: the release shape, and a check on the front door)

The last ship of row P1.14. Every release now has the same body; the
community surface is pinned by a check; and two corrections the owner asked
for land with it.

- **A fixed release shape.** `scripts/ai-release-notes.sh MAJOR.MINOR`
  renders the release body from the CHANGELOG entry: the title and summary,
  Breaking changes (or None), Upgrade (the compose roll and the systemd
  restart, with the roadmap row named), Verify this release (the SBOM
  artifact names and the `gh attestation verify` command), Details (the
  entry's items and a link to the CHANGELOG). Releases v9.188 to v9.192 are
  retitled by what changed for the reader and their bodies regenerated in the
  shape; the "next opener" and check-count tallies are gone from the public
  bodies.
- **`check_presentation_surface`** (111 checks) pins the front door from
  inside the tree: CODE_OF_CONDUCT.md, CITATION.cff, the issue-form config
  with blank issues disabled and the private-advisory route, the pull-request
  template and the release-notes script exist; SECURITY.md names the private
  advisory and keeps the verification command; SECURITY.md and CONTRIBUTING.md
  carry a stamp within twenty minors of the version. Repository settings are
  not probed (the default token cannot see them) and FUNDING.yml is pinned
  neither way.
- **Code of Conduct 3.0.** The Contributor Covenant 3.0 text replaces 2.1,
  with the reporting path filled in (the project mailbox, read only by the
  maintainer, acknowledged within five business days).
- **The README's Atlas capture is current.** The image was three versions of
  the Atlas old (the D3 globe). It is re-taken from the running application
  at v9.205 against a two-million-event synthetic log, at 2400 by 1470 through
  a scripted browser at device scale 2, and installed for the README and the
  site with a truthful alt text and caption. The chrome it shows changes in
  P1.17; that ship re-captures.


## v9.204 — 2026-09-03 (P1.14 ship 4: CONTRIBUTING in public voice; the README above the fold)

- **CONTRIBUTING.md rewritten for a stranger.** The persona, the slogans,
  the "standing instructions" framing, the gotcha-ordinal pointers and the
  agent credit line are gone; the AI-assistance disclosure, the constitutional
  refusal (stated once), the merge-readiness list (now including the version,
  chart, citation and CHANGELOG bump), the check-plus-detection-test rule,
  the will-not-accept list and the SECURITY.md pointer stay. It links the
  proposal form and the pull-request template, says in one line what
  `ai-test.sh` and `ai-done.sh` do, inlines the CSP rule, and is restamped.
- **The README above the fold.** "It is not a slide deck" becomes the plain
  capability statement (CI builds and boots the stack, proves the handshake
  and the backup round trip, runs the DR drill). A fourth badge reads
  "reference implementation, not production" and links the readiness ledger;
  one line under the badges points at the SBOMs, the SLSA provenance and the
  verification command. The architecture diagram no longer carries counts;
  the single stamped evidence table owns them (`check_stated_counts` still
  requires the README to state the check and CI-job counts, which the table
  does).

## v9.203 — 2026-09-03 (P1.14 ship 3: the community files a reader expects)

- **CODE_OF_CONDUCT.md** (Contributor Covenant 2.1, enforcement through the
  project mailbox), linked from CONTRIBUTING.md's opening.
- **Issue forms.** `.github/ISSUE_TEMPLATE/config.yml` disables blank issues
  and routes security reports to the private advisory and operator questions
  to the runbooks; a bug-report form captures the component, the version from
  `/api/health`, the reproduction, the expectation and the document that set
  it; a change-proposal form captures the need, the change, the C1 to C10 and
  vocation alignment CONTRIBUTING asks for, and the blast radius, with a
  required acknowledgement that the proposal is not a monetary (C10) or
  aggregation feature.
- **PULL_REQUEST_TEMPLATE.md** with motivation, change, blast radius,
  constraints, and the test-discipline checklist (checks READY, the DB-backed
  suites, the link checker, a test or check for new behaviour, the version
  and CHANGELOG bump, the documentation).
- **CITATION.cff** with the version pinned to `polaris_web/__version__.py`;
  `check_helm_chart_version_current` now fails when the citation lags the
  version, and the README's report row points at it.
- **`.github/FUNDING.yml` stays.** The plan proposed deleting it as
  contradicting the no-bounty statement; the owner set up Sponsors across
  the project repositories deliberately, and sponsoring a project is not
  payment for findings. The ruling is recorded in the sub-roadmap.

## v9.202 — 2026-09-03 (P1.14 ship 2: one sentence on all four surfaces)

- **The About** on github.com/EgorKhaklin/polaris-id is the project's own
  canonical sentence, mirrored by hand from CLAUDE.md: "A working reference
  implementation of a post-quantum, zero-knowledge, compulsion-resistant
  national identity-token system. Educational; notional data only." The
  README heading, the site's hero, `<title>` and description, and CLAUDE.md
  now carry the same words; the README and the site said "identity system"
  and the About said something else again. The About lives in repository
  settings outside version control, so it is a manual mirror, not a
  drift-proof one.
- **Topics** pruned to twelve that place the project among identity and
  post-quantum work rather than next to framework tutorials: added
  `reference-implementation`, `ml-dsa`, `fips-204`, `slsa`, `digital-identity`;
  dropped `flask`, `postgresql`, `rust`, `mfa`, `audit-log`, `merkle-tree`,
  `snark`, `identity-management`.

## v9.201 — 2026-09-03 (P1.14 ship 1: the repository's security features are on, and the policy says what is true)

- **Repository settings, in dependency order, by the owner:** Dependabot
  alerts, then Dependabot security updates, then private vulnerability
  reporting, then secret scanning, then push protection; the empty Projects
  tab is off. None of these can be observed from inside the repository, so no
  check pins them and no document states them as a standing guarantee; the
  policy names the private-reporting path because the button now exists.
- **SECURITY.md rewritten** for the researcher and the reviewer: GitHub's
  private advisory as the primary reporting path with the mailbox as
  fallback, the do-not-file-a-public-issue line kept, the plaintext demo
  credential replaced by a description and a pointer to the quickstart, the
  empty Hall of fame retitled Credit with the no-bounty statement folded in,
  a Dependencies section stating the merge policy so a reviewer can reconcile
  the 33 closed Dependabot PRs with the commit history and the CVE gates that
  run regardless, the `gh attestation verify` verification kept verbatim, the
  archaeology (`v8.95+`, "shipped v9.13") gone, and a restamp.
- **`.github/dependabot.yml`** loses its 26-line internal decision record.
  Its header now says what the file does (weekly version updates) and what it
  does not (security advisories come from the repository setting), the merge
  policy in four lines, and the rule that removing an ignore block is the
  record of taking a major; the per-version history it carried is already in
  this CHANGELOG.

## v9.200 — 2026-09-02 (P1.13 ship 7: the indexes and the voice gate)

The last ship of row P1.13. Every document under `docs/` is reachable from the
index of its own directory, and a check keeps it so; the prose across the
documentation carries no em-dash; the hook that stops new ones covers every
human-facing surface.

- **docs/README.md is a hub.** One row per document in the directory
  (PRODUCTION-READINESS first, named as the bound on every claim), one row
  per sub-directory delegating to its own index. The false scripts-grep
  rationale, the "Added v8.59" archaeology, the M2 enumeration, the
  "semantic memory" framing and the re-evaluation triggers are gone.
  `check_docs_index_coverage` (110 checks) walks `docs/` and fails when a
  Markdown document is not linked from the README of its directory or a
  sub-directory is not delegated; the link checker proves links resolve but
  could never see an omission.
- **docs/story/ is gone; PRINCIPLES.md merged.** Its constraint table
  duplicated MISSION.md, its audit-of-record table duplicated
  DEVNOTES/audit-of-record.md, and its vocation section duplicated MISSION.md;
  the one argument that lived nowhere else, substitutability of the
  implementation under a fixed constitution, is now in
  ARCHITECTURE-OVERVIEW.md §X. README, CLAUDE.md, CONVENTIONS §14, the paper
  index, SYSTEM-MAP, the SQL READMEs and the checks that scanned it are
  repointed.
- **NOTICE, CONVENTIONS, CONTRIBUTING, SECURITY.** NOTICE's About is two
  factual sentences and its attribution clause no longer cites a "strategic
  moment framing" or a "nine instances" count. CONVENTIONS drops the journal
  entry spec and the `journal/` and `archive/` directory rows (neither exists
  in the tree), states the real bump procedure (version, chart appVersion,
  CHANGELOG, gate) instead of a five-step one that named a journal, and
  restates the em-dash rule as a project standard with its exemptions.
  CONTRIBUTING keeps one statement of the constitutional refusal instead of
  three, corrects "a fourth uniqueness-pattern convention" (there are two),
  carries the pre-commit section moved from OPERATIONS.md in v9.199, and is
  restamped; the root SECURITY.md is restamped.
- **The em-dash sweep.** 499 em-dashes converted across 51 files: `docs/`,
  `DEVNOTES/` (except the verbatim record and the per-ship notes), `meta/`,
  the package READMEs, CLAUDE.md, NOTICE, CONTRIBUTING, SECURITY.md,
  `assets/README.md` and the comments in `deploy/`. Rules, not judgment per
  sentence: a term followed by an explanation takes a colon; a paired aside
  takes commas; headings and table cells take a colon. CHANGELOG.md,
  DEVNOTES/record.md, DEVNOTES/ships/, the machine-written DR-DRILLS.md and
  MISSION.md's frozen section are exempt by the standard. The application's
  templates and scripts (173 and 102) are P1.17's, not this ship's.
- **The hook.** `.pre-commit-config.yaml`'s `em-dash-block-new` now inspects
  every staged Markdown file, `docs/`, `DEVNOTES/`, `meta/`, `site/`,
  `deploy/`, the templates and NOTICE, with the same exemptions, instead of
  five root files.


## v9.199 — 2026-09-02 (P1.13 ship 5: the operator surface has one owner per subject)

Seventeen runbooks, one owner per subject, every claim re-verified against
the code, and no em-dash, arc, wave, Sanctum, ticket or version token left in
any of them. Rewritten in parallel, one agent per document, then reconciled.

- **DR.md owns recovery.** It leads with the targets table (RPO 300 s, RTO
  14400 s) and names the measurement: `polaris-dr-drill.sh` on every push
  and monthly, with the machine-appended ledger in DR-DRILLS.md. The S3 and
  pgBackRest configuration is its own section, every command verified against
  docker-init, the drills and CI. Gone: the "honest status" blockquote, every
  "≤1-min RPO" phrase (FAILOVER.md's copy too), the unmeasured MTTR row, and a
  set of procedures that named flags and files that do not exist
  (`--force-rotate-all`, `--restart-secrets`, `--rebuild`,
  `POLARIS_BACKUP_BUCKET`, `polaris-LATEST.tarball`, a logrotate file, an
  `occurred_at` column). The restore invocation is now the one the drill runs.
- **SECRETS.md is renumbered and re-measured.** Monotonic sections; the
  matrix regenerated from the generator and the production compose (adds the
  replicator password, the signing key, both TLS pairs and the pgBackRest
  credentials file; drops two secrets nothing reads); rotation described as
  `polaris-rotate-secret.sh` performs it. The WebAuthn enrollment and
  recovery runbook, the disabling-MFA procedure and the relying-party knobs
  moved to WEBAUTHN-ROLLOUT.md, which also loses its reference to a
  `/auth/recovery` route that does not exist. Every inbound "SECRETS.md
  section N" reference (OPERATIONS, LINUX-SERVER, DR, PRIVACY, RED-TEAM-SCOPE,
  the Linux env example) now links a named anchor.
- **DEPLOYMENT.md is the router.** Four paths (laptop, single host, Linux
  under systemd, Kubernetes), then the single-host compose procedure exactly
  as `polaris-deploy.sh` runs it, the blue-green overlay, the first operator
  account, the environment-variable table with every row re-verified, and the
  stamped verification block. The retirement paragraph, the duplicated demo
  credentials and the contradictory "Operational" table are gone. The sizing
  and network requirements moved here from OPERATIONS.md.
- **OPERATIONS.md is day 2 only.** Its install-shaped opening (quick start,
  system requirements, deploy, verify, initial admin login) collapsed to a
  pre-deploy checklist and a description of the running stack, with links to
  DEPLOYMENT.md for the rest; the PITR recipe, the stale RPO/RTO paragraph,
  the duplicated health payload and the two alert tables are pointers to
  DR.md, API.md, the alert rules and RUNBOOKS.md; the LUKS/TDE/fscrypt
  recipes merged into ENCRYPTION-AT-REST.md section 6 (rewritten against the
  named volume, with a real verification step instead of a wrong `df -T`
  claim); the pre-commit section moved to CONTRIBUTING.md; four false claims
  corrected (`polaris-backup.sh` has no S3 destination, the compose volume is
  project-prefixed, the prover is not "single-threaded", the archive default
  is 365 days). The table of contents is regenerated.
- **SECURITY.md is present-tense posture** for an assessor: every control,
  its enforcement point and its pinning check (all 27 check names and 24 test
  classes verified to exist, with counts), with the F-01 to F-14 engagement
  as a dated appendix. **RED-TEAM-SCOPE.md** is written for the firm to be
  commissioned: engagement type, three threat actors with success criteria,
  in-scope surfaces regenerated against the current tree (the PQ edge,
  PKCS#11 and KMS custody, the session registry and network policy, quotas,
  pgBackRest and DR, the Helm profile), the DoS carve-out, deliverables,
  disclosure timeline, and the five maintainer commitments.
- **The rest of the set:** FAILOVER, RUNBOOKS and SLOS lose their status
  blockquotes; PRIVACY's rotation table now agrees with SECRETS.md and no
  longer cites two tests that do not exist; HARDENING, LINUX-SERVER, INSTALL,
  KUBERNETES and KEY-CEREMONY carry the reader-and-job opening; the operator
  index is rewritten with one row per runbook and three reading orders.
- **Four defects found on the way, fixed and pinned.** The deploy script
  created the pgBackRest repository as root, which the server (archiving as
  `postgres`) could not write to; it now runs as the postgres user like the
  drills and CI. The production compose never set `POLARIS_TRUST_PROXY`, so
  behind Caddy every client shared the edge's address: one rate-limit bucket,
  one `AuthAuditLog` ip, a per-role network policy that could never match
  (the Helm profile had it right); the compose sets it, and
  `check_prod_compose_trusts_edge` (109 checks) pins the variable together
  with the Caddyfile's `X-Forwarded-For` rewrite. The recovery-code script's
  header described a `--recovery-code` invocation the recover script rejects;
  the recover script's header claimed it does not clear a lockout when it
  does. Both headers now say what the scripts do.
- **Reviewed before it shipped.** A read-only factual lens per rewritten
  runbook (eight in all) re-verified every command, flag, path, variable,
  default, role rule and check name against the source after the writing
  agents' own verification, and found 74 claims that were wrong or
  unsupported: a `caddy reload` the edge's `admin off` makes impossible, a
  bare `polaris-rotate-logs.sh` that exits 4, an `age-keygen` pipeline that
  produced an empty recipients file, a `--target=docker-stack` restore that
  exits 6 without `--force`, pgbouncer `SHOW` commands the least-privilege
  entrypoint disables, "sessions live in Redis" (they are signed cookies
  checked against the Postgres registry), an "8-hour absolute" lifetime that
  is an inactivity lifetime, a `/sql` console described as admin-only that
  auditors may use, a LUKS recipe whose key file was never created, and the
  rest of that kind. Every one is corrected in the shipped text.
- **Two more defects from the review lenses, fixed and exercised.**
  `polaris-backup.sh --verify-latest` and the quarterly cron dry-run globbed
  `polaris-*.tar.gz` only, so on any deployment that sets
  `POLARIS_BACKUP_KEY_FILE` (which deletes the plaintext after encrypting)
  they reported "no backups found" or verified a stale plaintext; both now
  see `.tar.gz.enc`, and verify decrypts with the key before re-hashing the
  manifest (exercised: good key passes, wrong key and missing key exit 1).
  `POLARIS_WEBAUTHN_RP_NAME` was documented as a compose knob but the compose
  never passed it; it does now, and the Linux env example lists it.
- **The sub-roadmap.** `DEVNOTES/presentation-plan.md` holds the plan inside
  the plan for rows P1.13 to P1.17: every ship the audit decomposed them
  into, its status, the ordered changes, deletions and risks per row, the
  critic's findings, and the rulings that reconcile them. The five roadmap
  rows are marked in progress and point at it; later sessions take one ship
  at a time from its status table.
- **Open, recorded for the next rows:** the shipped Caddyfile proxies
  `/metrics` and `/api/metrics` to the public internet with no ACL, and
  neither route authenticates; OPERATIONS.md now says so and gives the
  operator the edge matcher to add, and the software fix with its CI proof
  is the first item of P1.17's observability ship. Documentation invokes the
  CLI as `polaris` while the package installs it as `polaris-id` (P1.17, the
  CLI ship); `Dockerfile.prod` and `Dockerfile.pgbouncer` base images are tag-
  pinned, not digest-pinned (RED-TEAM-SCOPE states the split).


## v9.198 — 2026-09-02 (P1.13 ship 6: the reference set describes the running code)

- **API.md is complete in both directions, and a check keeps it so.**
  `check_api_routes_documented` (108 checks) compares every
  `@app.route('/api/...')` in `app.py` with the route headings in
  `docs/reference/API.md`, ignoring converters and parameter names, and
  fails when a route is undocumented or a documented route does not exist.
  The six routes it found undocumented are now described: `/api/health/live`
  and `/api/health/ready` (the liveness and readiness contracts), `/metrics`
  and `/api/metrics` under a new Observability section that states plainly
  that both are unauthenticated and must be restricted at the edge,
  `/api/atlas/subject` and `/api/atlas/subjects/search` (roles, caps, the
  withheld-count rule for ZERO_KNOWLEDGE events), and `/api/tokens/<id>/export`.
  The two phantom routes (`POST /tokens/new`, `POST /tokens/<id>/edit`) are
  gone; the token section names the routes that exist. The stored-procedure
  table named seven procedures that do not exist (`issue_token`,
  `verify_token`, ...); it now lists the fifteen that do. The rate-limit
  table is the real policy (10 logins per 60 s per IP; one shared 60-per-60-s
  write bucket per IP; GETs unlimited at the application; the
  `POLARIS_RATE_LIMIT_*` overrides; the backend selection). The health
  contract gains the `custody` component and a version placeholder instead
  of a literal. The two `docs/BACKLOG.md` references, the false pre-commit
  claim and every ticket tag in a heading are gone.
- **DATA-MODEL.md covers every table.** Sections added for
  `OperatorWebauthnCredential`, `AuditAccessLog`, `IndividualErasureEvent`,
  `ZkVerificationNonce` and the `schema_version` registry; the heading tags
  (`M2-2 / R10-2, added v8.21` and the like) are stripped.
- **SCALING.md is retitled around its 10-million-event measurement**, with the
  reader and job up front. **GLOSSARY.md** loses the internal vocabulary
  (the G27/G28/G29 guard IDs, done-list, larping, patterns, semantic memory
  and the rest of the governance section; STRIDE stays under "Threat
  modelling"). **docs/reference/README.md** is rewritten as a short index
  whose conventions state the stamp rule instead of a versioning-marker
  convention. **SYSTEM-MAP.md** is regenerated from the tree: `deploy/`,
  `site/` and every workflow file appear, all seventeen operator documents
  and all eight reference documents are listed, the constitutional spine is
  MISSION, the checks, the readiness ledger, the roadmap and the CHANGELOG,
  and the reading orders name the reader.

## v9.197 — 2026-09-02 (P1.13 ship 4: the architecture document ends at the architecture)

- **docs/ARCHITECTURE-OVERVIEW.md rewritten around what exists.** It opens with
  its reader and its job. §IX names the four deployment paths that actually
  exist, each as a Markdown link the link checker covers (the macOS launcher,
  single-host compose with the blue-green profile, the scripted Linux install,
  the Helm reference profile) with the chart's stated limits quoted from
  KUBERNETES.md rather than invented; the old "Helm chart deferred" and
  "bare-metal documented but not automated" lines were false. §XI (steady
  state) and §XII (where the project stands) are deleted; they described a
  May 2026 posture the roadmap has replaced. Every R*, M2* and vX.Y tag in
  the layer, flow and crypto sections is gone; the line counts are gone; the
  D3/topojson claim becomes the vendored MapLibre over CARTO tiles that the
  CSP actually allows; the disclosure levels are the three the schema CHECKs
  (ZERO_KNOWLEDGE, SELECTIVE, FULL), not four; the operator-script list names
  the scripts that exist today; §VI gains SLH-DSA (registered, not wired) and
  the PQ edge; the constraint-lattice sentence and its dangling `meta/lineage`
  citation are gone.
- **docs/QUICKSTART.md deleted and absorbed.** Nothing linked it except the
  architecture document's own header. Its two durable parts moved into that
  document: the constraint-refusal SQL walkthrough is now §XI, with the third
  block rewritten as an INSERT that was run against a scratch database and
  raises `uq_one_active_per_person` as advertised (the old UPDATE matched no
  row, because the seed has no RESERVE token for an active holder), and the
  route table is now §XII, regenerated against `@app.route` so every path
  exists. The README quickstart and INSTALL.md remain the "get it running"
  surfaces.
- **Facts-lens follow-through from the v9.194 review.** Eleven more stale
  sites corrected: the web README's phantom `test_structural_invariants.py`
  (three references, an 882-test count) and its per-class test counts; the
  web and SQL READMEs' stored-procedure lists (now fifteen names for fifteen
  procedures); the CLI README's 53 tests (71); the reference index's "20
  routes"; SECURITY.md's F01 count (13); the SQL README's "sections A to R"
  (the file has ten sections); `meta/tla/README.md`'s phantom test file. Two
  claims narrowed to the code: C8 in MISSION and PRINCIPLES now says which
  Atlas endpoints carry `_ATLAS_MAX_*` LIMITs (clusters, points, events), the
  240-bucket timeline cap and the 20-row search cap, and that the rest return
  aggregates; the operator index no longer credits WEBAUTHN-ROLLOUT.md with a
  network-policy section it does not have. The README and SECURITY.md state
  the crypto-witness row as 76 passing of 80 collected with the skip reasons;
  PQC-POSTURE says the SLH-DSA signer is not yet scheduled (it was wrongly
  tied to a certificate item); PRINCIPLES says why `schema_version` is not
  counted as an audit-of-record surface; DATA-MODEL describes RecoveryRequest
  and LifecycleArchiveCheckpoint by what the schema says they are.
  `docs/reference/README.md` joins the stated-count guard.

## v9.196 — 2026-09-02 (P1.13 ship 3: the ledger opens with what is open, and the roadmap's shipped rows shrink to their pins)

- **docs/PRODUCTION-READINESS.md inverted.** It now opens with its reader and
  its job, then the status line, then the eight decisions only a deploying
  organization can make, each paired with what ships today for it (the custody
  drivers, the replication runbook, the at-rest posture, the S3 archive and the
  monthly drill, the pager wiring, the pseudonymization mechanism, the red-team
  pack). The operator-gated caveats that were buried inside closed bullets
  (HSM/KMS custody, the non-root Caddy edge, one postgres replica, the offsite
  bucket and schedule, the Alertmanager backend and pager URL) live in that
  table or in the two openly carried limits. A new section says plainly that
  the ledger never tracked deployment scale and points at the roadmap phases
  that do. The 250 lines of per-wave narrative are compressed to a claim /
  shipped / pinned-by table (37 rows, every check name verified to exist). The
  unreproducible 49/45/10 assessment counts and the uncitable v9.101
  assessment reference are gone. The closing rule no longer implies that
  checked boxes make the system production-ready; the status line changes only
  when the eight decisions are recorded for a named deployment and the P1 exit
  gate is met.
- **ROADMAP.md inventory regenerated at v9.196.** "Have" covers what shipped
  through P1.10 (custody drivers, four deployment paths, the sealed secrets
  store, tracing, SBOM and provenance, the coverage floor, the monthly DR
  drill); "Do not have" drops HSM/KMS custody and SBOM/provenance (closed) and
  gains the honest residuals (no hardware HSM in CI, no published registry
  images, one postgres replica); the P0 carrying-debts paragraph is empty and
  says so. The P0 exit gate reads as met (v9.175, P0.11 `[EXT]`).
- **Every `[x]` row collapsed** to its pinning check, keeping in-row only the
  clauses that are deferrals or open follow-ups: P0.6's image-signing
  deferral, P0.7's sibling-path witness follow-up, P1.2's scope note and
  limits, P1.4's window operations, P1.5's one-replica and no-registry limits.
  P0.4 names its four checks; P0.3 names its policy file and CHANGELOG range.
  The descriptions of finished work those cells carried remain in the
  CHANGELOG entries the item column's version stamp points at.

## v9.195 — 2026-09-02 (P1.13 ship 2: the constitution carries only the constitution)

MISSION.md is rewritten from 589 lines to 318 so that it holds purpose,
vocation, C1-C10 with enforcement objects that resolve, the freeze line,
the permanent non-goals and an amendment rule, and nothing else.

- **The freeze-line section is untouched** below its heading. One dated,
  additive status note is appended directly under the heading: the
  abandonment clause fired at the v9.40 terminus (docs/THESIS.md records the
  strong claim as retired), and the external trigger the section requires
  occurred on 2026-08-31 (ROADMAP.md's decision record, CHANGELOG v9.158). The
  active arc is national deployment; the constitution is a hard gate through it.
- **Moved, not deleted.** The v1 and v2 done-lists, the retired Arc D/E/F/G
  narrative and the Arc B phase log (lines 321-589) now live verbatim in
  `DEVNOTES/record.md`, with its reader named in the first sentence; the only
  edits are two citations of files that no longer exist
  (`memory/deferred_items.md`, `meta/arc-b-production.md`) and a closing
  note that Arc B's deferred phases have since shipped. `docs/README.md`,
  `docs/SEED_DATA.md` and the DEVNOTES index point at the new home.
- **Cut from the constitution:** the v8.8 constraint-lattice section (it
  cited `meta/lineage.md`, which does not exist, and described a topology no
  check enforces), the v9.55 apparatus retrospective (CHANGELOG has it), the
  course framing (provenance lives in NOTICE, and the same paragraph is
  removed from ARCHITECTURE-OVERVIEW.md, docs/paper/README.md and GLOSSARY.md),
  and every M2-* / R11-* ticket label in the vocation's primitive list, which
  now names the primitives in plain words.
- **Corrected in place:** the constitution no longer calls SLH-DSA a
  fallback signer, no longer says C2 is enforced by trigger (it is a CHECK
  constraint), and no longer cites the paper's NFR-4 label. Prose outside the
  frozen section carries no em-dashes.
- **Added:** a short "Why each constraint exists" section (C1, C2, C3, C10
  kept from the old text; C4-C9 summarized in one sentence) and the amendment
  rule at the end. Both `landing.html` deep links (`#vocation`,
  `#the-hard-constraints-do-not-violate`) resolve unchanged.

## v9.194 — 2026-09-02 (P1.13 ship 1: every stated count and constitution object is true, and stays true)

The first ship of the presentation pass. Nothing is deleted; every number and
every object name a reviewer meets first is re-measured and then guarded.

- **Three enforcement checks** in `polaris_checks` (107 checks total, each with a
  detection test):
  - `check_table_count_matches_doc` is widened from two documents to eleven
    (README, CLAUDE, ROADMAP, MISSION, ARCHITECTURE-OVERVIEW, DATA-MODEL,
    SYSTEM-MAP, the three package READMEs, the demo site). It accepts exactly two
    numbers: the tables `01_schema.sql` creates (29) and that plus the tables
    migrations add to a running deployment, 33 with the `schema_version`
    registry. It reads through HTML tags and
    catches the "(N total" phrasing that slipped past the old regex.
  - `check_stated_counts` measures invariant checks, CI jobs (the keys under
    `jobs:` in `ci.yml`), routes (`@app.route` decorators) and stored procedures
    from the artifacts, then fails any stated count in thirteen documents that
    disagrees. The README must keep stating the check and CI-job counts.
  - `check_c1c10_objects_resolve` parses the `file::object` anchors in
    MISSION.md's C1-C10 table and every function-shaped or trigger-shaped name
    in CLAUDE.md, PRINCIPLES.md, PRIVACY.md and ARCHITECTURE-OVERVIEW.md, and
    fails when the code defines no such object.
- **Counts corrected everywhere they were stale.** 77 or 102 checks became 107;
  7 CI jobs became 14 (SYSTEM-MAP now names all fourteen plus the monthly
  `dr-drill.yml`); 72 routes became 73; 26, 27 or 28 tables became 29 (33 migrated);
  11 or 14 stored procedures became 15; "twelve runbooks" became seventeen.
  DATA-MODEL.md's six groups now list all 29 tables. The README's "Verified,
  not asserted" table and the site's numbers are re-measured at v9.194 (640
  product tests, 76 crypto-witness tests). SECURITY.md's 156-test block, INSTALL's
  "~342 tests", DEPLOYMENT's "36/36" and the SQL README's "171 assertions" are
  replaced by measured, stamped figures (78 assertions in `08_tests.sql`).
  KUBERNETES.md no longer hardcodes an image tag; it reads `$V` from
  `polaris_web/__version__.py`.
- **Constitution objects repaired.** MISSION.md named four objects that do not
  exist (`reject_update_delete`, `disclosure_consistency`, `secure_headers`,
  `enforce_zk_typing`); they are now `reject_audit_modification`,
  `chk_disclosure_token_consistency`, `apply_security_headers`, and C6 is
  described by its real mechanism (route coercion, the C2 CHECK constraint, the
  Atlas redaction check). PRIVACY.md and ARCHITECTURE-OVERVIEW.md no longer
  claim a C2 trigger; it is a CHECK constraint, and that is the stronger
  statement. PRINCIPLES.md's audit-of-record table now lists all thirteen
  surfaces under their real trigger names.
- **SLH-DSA ruled once, on every surface.** Both SLH-DSA parameter sets are
  registry rows, so a rotation away from lattices is a row update (C7), but no
  SLH-DSA signer is wired: `pqc_signing.py` signs ML-DSA-65 only, so the seed
  token filed under SLH-DSA-128s can never be re-signed (every seed signature
  row is a placeholder; real signatures appear at issuance). README, the site,
  PQC-POSTURE (new gap row, `REGISTERED_NOT_WIRED`) and the seed comments now
  say exactly that.
- **Claims trimmed to the code.** The site no longer says FIDO2 keys are the
  only path to admin and auditor roles; admins enroll against a per-account
  deadline and auditors are exempt, which is what `webauthn_auth.py` does.
  The operator index gains its two unindexed documents (DR-DRILLS, WEBAUTHN-ROLLOUT)
  and states the real DR targets (RPO 300 s, RTO 4 h).

## v9.193 — 2026-09-02 (Roadmap amended: the national-deployment presentation pass, P1.13 to P1.17, with wholesale rework pre-authorized)

An owner decision, recorded where decisions live. Five rows join P1 and a
standing rule joins the list:

  - **P1.13** human-facing documentation reworked for the national-deployment
    reader (a named reader and one job per document, one voice, no version
    archaeology, duplicates merged or deleted, the index matching the tree, an
    observer-confusion read-through recorded); **P1.14** the GitHub presence as
    the front door; **P1.15** the demo website, accurate and professional;
    **P1.16** repository organization matched to reality (every committed
    artifact kept with a stated reader, moved, or deleted); **P1.17** the
    software's own presentation, visually and structurally (web UI, CLI, health
    and metrics naming, messages, the log stream), demo-only surfaces removed
    or gated.
  - **Standing rule 8:** presentation is a deliverable, and on 2026-09-02 the
    owner authorized wholesale rework of any human-facing surface wherever it
    serves national-deployment readiness, including removal of bloat, unneeded
    material, and anything that could confuse an observer. The five rows are
    autonomous-eligible despite their medium risk; the constitution and the
    honesty ledger still bound them.

---

## v9.192 — 2026-09-02 (Roadmap P1.10: DR to targets, on a schedule; RPO and RTO measured by a drill that kills the primary, monthly with the row committed)

DR.md carried targets; nothing measured them, and one setting that decides
the recovery point was never set. P1.10 makes both numbers a measurement.

  - **The RPO is bounded now.** `docker-init.sh` sets `archive_timeout=60s`
    alongside `archive_mode` when `POLARIS_PGBACKREST_ENABLED=1`. Without it
    a quiet primary archives a WAL segment only when 16 MB fills, which on a
    small authority can be hours behind: the "≤1 minute" line in DR.md was
    not what the configuration delivered. With it, a partially filled
    segment is switched and pushed within a minute.
  - **`scripts/polaris-dr-drill.sh` measures, on a scratch stack.** A
    pgBackRest-archiving primary (the shipped image with the schema and
    migrations baked in, `archive_timeout=60s`) takes a full backup, then
    commits one timestamped marker a second for 90 seconds. Disaster: the
    primary is killed with SIGKILL and its data volume destroyed; nothing
    survives but the repo. Recovery: a fresh container restores from the
    repo, replays every archived segment, promotes, and the application is
    started against it and polled until `/api/health` reports the database
    healthy. RPO is the age of the newest recovered marker at the kill; RTO
    is the time from the kill to a healthy service (and, separately, to the
    database accepting queries); the token count and the schema_version rows
    must equal the pre-disaster values. Pass is RPO ≤ 300 s and RTO ≤ 14400
    s, the roadmap targets; the result is a JSON file and, with `--record`,
    a row appended to `docs/operator/DR-DRILLS.md`, pass or fail alike.
  - **Measured here (v9.192, Apple M3, the local repo):** RPO 41.6 s (54 of
    90 markers recovered: the last segment switched at 60 s, the kill came
    at 90), RTO 2.8 s to the database and 4.7 s to a healthy application,
    full backup 1.5 s. Both targets hold with two orders of magnitude to
    spare on sample data; the ledger's first row is that run.
  - **On a schedule, with committed results.** `.github/workflows/dr-drill.yml`
    runs the drill on the first of every month (and on demand) with
    `--record` and commits the row to `main` as github-actions[bot]; the CI
    workflow ignores that path on push so the monthly row does not spend a
    run. The new `dr-drill` CI job runs the same drill on every push without
    recording. On a Linux host, `polaris-dr-drill.timer` (installed and
    enabled by `install.sh`) runs it monthly into
    `/var/lib/polaris/dr-drills.md`; it uses scratch containers and never
    touches the production stack.
  - DR.md's targets table states the proven numbers with the ledger as their
    source (RPO ≤ 5 min with archiving, ~24 h with dumps only; RTO ≤ 4 h
    envelope, seconds on sample data) and the drill cadence gains the
    automated row; PRODUCTION-READINESS.md moves "the real RPO/RTO targets"
    out of the operator-gated column; LINUX-SERVER.md lists the unit.
  - `check_dr_drill_scheduled` pins the archive_timeout, the drill's kill,
    restore, targets, integrity checks, and ledger row, the ledger header,
    the monthly cron with write permission and the push, the CI job, the
    docs-only path filter, the timer units and their installation, and
    DR.md's pointer to the ledger. 104 checks, 101 check-layer tests. Next
    opener: P1.11, the retention and lifecycle engine.

---

## v9.191 — 2026-09-02 (Roadmap P1.9: the performance baseline, published; issuance/s, verification/s, and atlas p95 measured end to end and re-run by CI)

The numbers an authority sizing a deployment starts from, measured rather
than estimated, stamped rather than asserted, and re-run on every push.

  - **`docs/reference/PERFORMANCE-BASELINE.md`.** One script,
    `scripts/polaris-perf-baseline.sh`, resets the sample data, starts the
    production WSGI server (gunicorn, 4 sync workers) against PostgreSQL,
    and drives three flows through the app's own routes with the load
    generator as a logged-in operator, 60 seconds per stage: issuance
    (`POST /uc1/issue`, the full `uc1_issue_and_activate` procedure with a
    real ML-DSA-65 signature per token), verification
    (`POST /verifications/new`), and the atlas (`/api/atlas/clusters` on a
    zoomed bbox, warm and cold, and `/api/atlas/stats` whole-world). It
    rewrites the doc's measured block with the table and a stamp: version,
    commit (marked `+dirty` when the tree is uncommitted), date, CPU, cores,
    memory, OS, Postgres, Python, workers, signing mode, topology.
  - **Measured on this ship's reference hardware** (Apple M3, 8 cores, 16 GB,
    macOS 26.3, PostgreSQL 16.14, app and database on the same host, no TLS
    edge, no pgbouncer): issuance sustained 40 requests a second with every
    one of 2400 succeeding at p95 28 ms; verification 80 a second, 4800 of
    4800, p95 18.5 ms; the atlas at 100 requests a second with p95 14.5 ms
    warm and 17.8 ms cold on a street bbox and 13.8 ms for the whole-world
    stats. The offered rates are below saturation by design: the baseline is
    what one host sustains cleanly, not where it breaks.
  - **CI re-runs it.** The test job runs `--smoke` (5 s per stage, low rates)
    on every push and uploads `perf-baseline.json` as an artifact; a shared
    runner is a procedure check, never a baseline, and the script gates only
    on SLO-boundary floors (issuance at least 2/s and verification at least
    5/s at 95% success, atlas warm p95 at or under the 2 s latency SLO).
  - **The load generator** gains `{seq}` (a per-request sequence number, so
    every issuance carries a unique serial and every cold atlas request a
    different bbox) and `{run}`, and its JSON summary now carries the
    latency percentiles and achieved rate the table is built from.
  - **The F-03 rate limits read the environment** (`POLARIS_RATE_LIMIT_WRITE_MAX`,
    `_WRITE_WINDOW`, `_LOGIN_MAX`) with the defaults of 60, 60, and 10
    unchanged and pinned: a benchmark from one client address is impossible
    under 60 writes a minute, so the script raises the cap on the scratch
    server it starts and nowhere else. DEPLOYMENT.md and SECURITY.md say what
    raising them in production costs.
  - **Found by the first full run:** after 4004 verifications the last 796
    answered HTTP 431. Every form POST adds a flash message to the signed
    session cookie and a browser consumes them on the next rendered page, but
    a client that never renders the redirect target (a script, an
    integration, this benchmark) grows the cookie one message per write
    until the Cookie header passes gunicorn's field-size limit and every
    further request is refused, a lockout the client cannot see coming. The
    app now keeps the most recent 20 flashes (`FLASH_LIMIT`), which costs a
    browser nothing; `FlashBoundTests` pins it. The second run then recorded
    4800 of 4800. Also found: the abuse drill's ledger parser summed every
    value of the load generator's summary, which the richer JSON broke; it
    reads the total now.
  - `check_performance_baseline` pins the doc's stamped measured block, the
    script's stages and floors, the CI smoke re-run and artifact, the load
    generator's templating, the rate-limit defaults, and the reference index.
    103 checks, 100 check-layer tests. Next opener: P1.10, DR to targets on
    a schedule.

---

## v9.190 — 2026-09-01 (Roadmap P1.8: abuse controls; per-agency quotas bound at the database, velocity alerts against each agency's own baseline, drilled under real load, and the redis-py 8.x major with a real Redis in CI)

R11-6 bounded one thing an agency can do to its own tokens: revoke them too
fast. P1.8 extends that leg to everything an agency does through Polaris,
in two layers: a hard, opt-in bound (quotas) and an always-on signal
(velocity alerts). Both are keyed on agencies, never on people; the
constitutional note is that these controls bound what an authority may do
and count what it does, and touch no holder attribute at all.

  - **Per-agency quotas, enforced by the database.** `AgencyQuota` holds up
    to three caps per agency: issuances per rolling day, revocations per
    rolling day (of that agency's tokens), verifications per rolling hour
    (as the requesting agency). NULL is no cap of that kind and no row is no
    caps, so an unconfigured deployment is unchanged. `enforce_agency_quota`
    is a BEFORE trigger on IdentityToken (insert = issue, update into REVOKED
    = revoke) and VerificationEvent (insert = verify): the stored procedures,
    the SQL console, and a bulk loader all meet the same bound, and there is
    deliberately no opt-out GUC. A capped write is serialized per (kind,
    agency) by a transaction-scoped advisory lock, so the cap is exact under
    concurrent writers (twelve threads racing a cap of five leave exactly five
    rows, C9); an uncapped agency pays one primary-key lookup and returns
    before any lock. The windows are counted from the audit-of-record tables
    (never a side counter) over two new indexes. Migration
    `2026-09-01-002-agency-quota` (up, down, idempotent re-up drilled).
    `polaris quota-set <agency> --issue-per-day N --revoke-per-day N
    --verify-per-hour N --justification "..."` (0 clears a cap; the
    justification has the R11-6 twenty-character floor) and `quota-show`.
  - **The refusal is loud everywhere.** The trigger's own sentence
    (`quota exceeded: agency 5 has reached its verify quota of 25 per hour`)
    is the HTTP 429 body on the issue, revoke, and verify routes, a
    `quota_refused` structured log line with the request id, a
    `polaris_quota_refusals_total{kind,agency_id}` increment, and the
    `PolarisQuotaRefusals` page (SEV-3, no wait: one refusal is a fact, and
    both readings of it, abuse held back or a cap set too low, need a human).
  - **Velocity alerts against each agency's own week.**
    `polaris_agency_events_total{kind,agency_id}` is recorded on the issue,
    revoke (by the token's issuing agency), and verify routes.
    `PolarisIssuanceVelocity`, `PolarisRevocationVelocity`, and
    `PolarisVerificationVelocity` fire when one agency's last hour exceeds an
    absolute floor (20 / 5 / 200) AND four times that agency's trailing 7-day
    hourly mean, offset one hour so the burst is not in its own baseline: a
    large agency's normal day never trips a small agency's threshold, and a
    young or quiet agency's first actions stay under the floor. Each has a
    runbook; the rules are unit-tested with `promtool test rules`
    (`polaris-alerts.test.yml`: a steady agency never fires, a 60-in-an-hour
    burst fires, a 12-in-an-hour burst stays under the floor, one refusal
    pages); the overview dashboard gains the velocity and refusal panels.
    Found on the way: `polaris_verifications_total` had been defined since
    v8.93 and never incremented, so the dashboard panel on it was always
    empty; it counts now, and the drill asserts it moves.
  - **Exercised with the load generator, on the redis backend.**
    `polaris_load_gen.py` gains an operator-flow mode (`--login USER:PASS`,
    `--method POST`, repeatable `--form`, `--csrf-from PATH`, redirects not
    followed so the form's own answer lands in the ledger). The new CI step
    `scripts/polaris-abuse-drill.sh` validates and unit-tests the rules,
    caps agency 5 at 25 verifications an hour, logs in as an operator, POSTs
    50 verifications at 10 rps through the app's own form route, and asserts
    exactly 25 recorded (302) and the rest refused (429), 25 rows in the
    database, `/metrics` agreeing on events, refusals, and the verification
    counter, and the log line present. It runs with
    `POLARIS_RATE_LIMIT_BACKEND=redis` against a Redis service and refuses to
    pass unless `/api/health` reports the redis backend live.
  - **redis-py 5.x to 8.1.0, with its own test pass.** The CI test job gains
    a Redis service and `POLARIS_TEST_REDIS_URL`, so the Redis-backed
    rate-limiter tests (contract + multiprocess) RUN instead of skipping, as
    they had since v9.40; locally they passed against redis-server 8.x. Two
    behaviour changes of the major matter here and are pinned: redis-py 6+
    retries three times with exponential jitter by default, which on the
    request hot path turns a Redis outage into multi-second stalls before the
    fail-closed deny, so `RedisRateLimiter` sets the one-attempt contract it
    was written against (`Retry(NoBackoff(), 0)`); and 8.x speaks RESP3 by
    default, which the Lua sliding window, `ping`, `scan_iter`, and `delete`
    are indifferent to, proven by the same tests. The exact pin replaces the
    open range; the separate `redis==5.0.*` install in `Dockerfile.prod` (a
    second source of truth) is gone; the Dependabot ignore is removed, which
    is the record of the decision.
  - Docs: OPERATIONS.md (the quotas subsection and the metrics table),
    RUNBOOKS.md (four sections), SLOS.md, DATA-MODEL.md, SECURITY.md,
    PRODUCTION-READINESS.md, the observability README, and
    `DEVNOTES/ships/abuse-controls.md` (the policy choices and the adversary
    walk). The schema is 29 tables now, stated so everywhere the count lives.
  - `check_abuse_controls` pins it: the table in the schema and its drop
    list, the trigger with its lock, its cheap exit before the lock, its
    refusal sentence and no bypass GUC, the migration pair and the indexes,
    the app's counters, 429s, and the verification counter, the four alerts
    with the offset baseline and their unit tests, the drill and its CI step
    on the redis backend with a Redis service, the load generator's mode, the
    redis pin and retry contract, the CLI, the tests, and the docs, with a
    discrimination test per failure mode. 102 checks, 99 check-layer tests;
    the product suite runs 473 web (Redis tests included), 71 CLI, and 88
    constraint and property tests green. Next opener: P1.9 performance
    baseline v1, which the operator-flow load generator now makes possible.

---

## v9.189 — 2026-09-01 (Roadmap P1.7: session and origin hardening; the webauthn 3.x major with its own ceremony test pass, ML-DSA-65 offered first, per-role network policy, and a server-side session registry)

A Polaris session was, until this ship, a signed cookie and nothing else:
the server could not count, expire, or revoke one, a deactivated account
kept its live session until the cookie aged out, and the second factor's
library had a major waiting since P0.3 that nobody had exercised. P1.7
closes all of it, and every new control is on by configuration only,
validated at boot, announced in the log stream, and audited.

  - **webauthn 2.7.1 to 3.0.0, with its own test pass.** The API Polaris
    calls is unchanged; what changed underneath is that malformed client
    payloads now surface as `InvalidRegistrationResponse` /
    `InvalidAuthenticationResponse` instead of raw parser errors, duplicate
    CBOR keys are rejected, the Android and TPM attestation roots are
    refreshed, and the library gained the ML-DSA COSE algorithms (-48/-49/
    -50) verified through cryptography's ML-DSA implementation. The pass is
    `WebAuthnCeremonyTests`: a synthetic authenticator (a real P-256 key, or
    a real ML-DSA-65 key) driven through the app's OWN register/begin,
    register/finish, login, assert/begin, and assert/finish routes, so the
    full verification path runs on both ceremonies; then the refusals:
    a replayed signature counter, a wrong origin, a stale challenge, and a
    malformed payload that is a 400, never a 500. `pyasn1-modules` joins
    the runtime pins; pip-audit strict is clean; the Dependabot ignore block
    is gone (removing it is the decision record).
  - **Post-quantum ready on the relying-party side.** ML-DSA-65 (COSE -49),
    the token signature's own parameter set, is offered FIRST in the
    registration options and accepted at verification, ahead of ES256,
    EdDSA, and RS256. An authenticator that implements ML-DSA enrolls a
    post-quantum credential with no Polaris change; the settings page now
    labels every credential's algorithm ("ML-DSA-65 (post-quantum)",
    "ES256 (ECDSA P-256)", ...). PQC-POSTURE.md stays honest: no shipping
    authenticator implements it as of 2026-09, so WebAuthn remains in the
    still-classical section, with the gate now stated as hardware-only.
  - **Attestation policy** (`docs/operator/WEBAUTHN-ROLLOUT.md` Phase 6):
    `POLARIS_WEBAUTHN_USER_VERIFICATION=required` demands the PIN or
    biometric on enrollment AND every assertion (the UV flag is checked
    server-side on both ceremonies; it was hardcoded off before);
    `POLARIS_WEBAUTHN_ATTESTATION` sets the conveyance asked of the browser;
    `POLARIS_WEBAUTHN_REQUIRE_ATTESTATION=1` refuses an enrollment whose
    attestation format is `none`; `POLARIS_WEBAUTHN_ALLOWED_AAGUIDS` pins
    the fleet to listed authenticator models. Refusals are audited as
    `WEBAUTHN_REGISTRATION_REFUSED`. The stored attestation format is now
    the wire name (`none`, `packed`, ...) rather than the enum repr the old
    code wrote, which the rollout doc's Phase 5 filter had always assumed.
  - **Per-role network policy.** `POLARIS_NETWORK_POLICY_<ROLE>` is a
    comma-separated allow-list of CIDRs or addresses. Enforced inside
    `authenticate()` only once the password is right and answered with the
    generic error, so it is not a password oracle (audited
    `NETWORK_POLICY_DENIED`, no failed-login bump), and on every live
    session, so a cookie replayed from outside the range, or a range
    tightened after login, ends the session on that request. Always on the
    proxy-aware `client_ip()`: X-Forwarded-For counts only behind
    `POLARIS_TRUST_PROXY`, and the tests prove a spoofed header is ignored
    without it. A malformed entry raises at boot instead of allowing all.
  - **Server-side session registry.** `OperatorSession` (migration
    `2026-09-01-001`): one row per login, consulted on every authenticated
    request. `POLARIS_SESSION_MAX_<ROLE>` caps concurrent sessions per
    account by evicting the least-recently-seen one (never the new login;
    the account row is locked per login so the cap is exact under real
    threads, C9); `POLARIS_SESSION_IDLE_MINUTES_<ROLE>` idles a session out;
    a deactivated account's session ends on its next request; logout,
    `polaris user-passwd`, and `polaris user-deactivate` revoke rows
    themselves; a cookie without a live row is anonymous (every operator
    re-authenticates once after this upgrade). Admin defaults: 3 sessions,
    30 minutes idle; other roles unlimited unless configured. `last_seen_at`
    is written at most once a minute; rows purge after 30 days. The
    registry is working state; every eviction, expiry, and denial is an
    `AuthAuditLog` row (`SESSION_EVICTED`, `SESSION_EXPIRED`,
    `SESSION_REVOKED`), which stays append-only. The CLI's `audit-log
    --event-type` now knows all twenty-one event types.
  - Found by exercising the reload path while proving the migration
    (up, down, idempotent re-up, and the refusal while v9.189 audit rows
    exist): `01_schema.sql`'s drop list was missing `ZkVerificationNonce`
    (a plain CREATE TABLE further down the same file) and `AuditAccessLog`
    (a plain CREATE TABLE in migration 2026-05-15-003), so a
    `00_load_all.sql` re-run on a non-empty database stopped at the first,
    and `polaris-migrate.sh --up` after a reload (which resets
    `schema_version` and re-applies every migration) failed on the second.
    Both are in the list; `check_schema_reload_idempotent` pins every table
    created by the schema or a migration against it, and the reload plus a
    full re-migration was run on a populated database to prove it.
  - Plumbing and docs: the prod compose passes every knob through from
    `polaris.env` (which also, for the first time, makes the documented
    `POLARIS_WEBAUTHN_HARDWARE_ONLY` reach the container); the Helm chart
    gains `app.extraEnv`; `polaris.env.example` documents the block;
    HARDENING.md section 13, WEBAUTHN-ROLLOUT.md Phase 6, DEPLOYMENT.md,
    SECRETS.md, SECURITY.md (events and recommendations 9 and 10),
    DATA-MODEL.md, KUBERNETES.md, PRODUCTION-READINESS.md, PQC-POSTURE.md.
  - `check_session_origin_hardening` pins the whole shape (the 3.x pin
    and the removed ignore, the policy knobs and the UV wiring on both
    ceremonies, the login and live-session policy enforcement on
    `client_ip()`, the registry's boot validation, hook, migration, CLI
    revocation, tests, docs, and compose pass-through) with a
    discrimination test per failure mode. 101 checks, 98 check-layer
    tests; the product suite runs 463 web, 66 CLI, and 88 constraint and
    property tests green on the migrated database. Next opener: P1.8
    abuse controls, where the redis-py major waits the same way.

---

## v9.188 — 2026-09-01 (P0.9 follow-through: readiness probes were answered by postgres's temporary init server; every probe now goes over TCP)

The v9.187 push went red on the offsite S3 drill, a job that ship never
touched: pgBackRest 2.58.0 aborted the full backup with `[101]: NULL result
required to complete request` one step after `check archive for prior
segment`, and the same binary against the same digest-pinned MinIO had
passed three hours earlier. Run locally, the drill failed one command
EARLIER, with `FATAL: the database system is shutting down`. Both are one
bug, and it is ours. The official postgres image's entrypoint first runs a
TEMPORARY init-only server bound to the Unix socket alone
(`listen_addresses=''`) while POSTGRES_DB and the init scripts load, stops
it, and only then starts the real server. The drill's readiness loop
(`docker exec ... psql -tAc 'SELECT 1'`, over that socket) passed against
the temporary server, so stanza-create and the backup began while the
entrypoint restarted postgres underneath them. Whether the next command
met "shutting down" or a connection terminated mid-query (pgBackRest's
libpq wrapper asserts `PQgetResult == NULL` after every query and throws
[101] when the server ends the connection instead) is only a matter of
where the restart landed. Measured on the built image: the socket answers
at +0.9s, the temporary server stops at +1.5s, TCP answers at +1.6s; on a
CI runner loading the full schema the window is seconds wide.

  - Every probe of a containerised postgres now goes over TCP (`-h
    127.0.0.1`), which only the real server listens on: the offsite drill;
    the four other CI readiness loops (the backup/restore round trip, the
    verify-ca hop, the replication primary, the pgBackRest archive check),
    which carried a comment believing `psql -d polaris` beat `pg_isready`
    here, when both reach the temporary server; the CI service container's
    health command; the compose healthchecks (dev and prod); the Helm
    StatefulSet's startup and readiness probes; and `polaris-deploy.sh`'s
    wait before it migrates. The compose and Helm fixes matter beyond CI: a
    first boot loads the schema for tens of seconds, during which postgres
    reported healthy and pgbouncer and the app were started against a
    server about to restart. That is the plausible cause of the v9.183
    Linux-install failure at `systemctl start polaris.service` that v9.185
    could not confirm and widened the app healthcheck window for; the
    window stays, the false "healthy" underneath it is gone.
  - `polaris-offsite-drill.sh` dumps the primary's last 40 log lines on any
    failing command and on every `fail()` (the v9.186 rule: a drill that
    dies without its logs is unfixable from CI).
  - `check_postgres_probes_use_tcp` pins the class: every `pg_isready` and
    every `docker exec` / `compose exec` psql readiness loop across ci.yml,
    the scripts, the compose files, and the Helm templates must pass `-h`,
    and the drill must keep its log dump; its discrimination test fails the
    check on a socket healthcheck, a socket CI loop, a socket Helm probe,
    and a drill without the dump, and passes a commented-out probe. 99
    checks, 96 check-layer tests.
  - Exercised before pushing: the fixed offsite drill run locally to a
    PASSED restore (twice), `helm lint` + `helm template` on the chart, both
    compose files rendered, and the socket-vs-TCP window measured on the
    built image as above.

---

## v9.187 — 2026-09-01 (Roadmap P1.6: opt-in distributed tracing and dashboards-as-code, the correlation id joining logs to traces)

The v9.27 "no tracing system" constraint held while Polaris had no operators;
this ship supersedes it for deployments that need cross-request latency
attribution, keeping what made the refusal right: nothing traces unless the
operator switches it on, the switch announces itself in the log stream, and
nothing identity-shaped leaves the app.

  - `polaris_web/tracing.py`: opt-in OpenTelemetry tracing, gated on
    `POLARIS_OTEL` (off = the request hooks are inert no-ops; on = a
    `tracing_enabled` log line at startup, `tracing_unavailable` if the
    packages are missing — a silent no-op in either direction is the
    invisible-telemetry failure mode). The server span is HAND-ROLLED, not
    auto-instrumented, so its attribute surface is exactly what the vocation
    allows: the route template as the span name (unmatched paths collapse to
    `UNMATCHED`, the v9.130 cardinality rule), the query-stripped path in
    `http.target` (filters and cursors stay out of telemetry), the v9.122
    correlation id as `polaris.request_id`, and on exceptions the CLASS name
    only (messages can embed user input or DB coordinates). psycopg2 client
    spans ride inside the request trace carrying the parameterized statement
    template, never values. An inbound `traceparent` is honoured only behind
    `POLARIS_TRUST_PROXY`, symmetric with X-Request-ID: an untrusted client
    does not choose how its requests correlate. gunicorn workers each build
    their own provider post-fork (no preload, no dead-exporter-thread hazard).
  - The correlation id now joins logs to traces BOTH ways:
    `observability.structured_log` lines carry `trace_id`/`span_id` while a
    span is recording (via a provider hook — observability.py still imports
    no telemetry backend), and the id a caller quotes finds its trace with
    TraceQL `{span.polaris.request_id="<id>"}`. The id's own v9.122 semantics
    are untouched: ephemeral, minted per request, never in a DB row.
  - Dashboards as code: `deploy/observability/grafana/` provisions the
    Prometheus and Tempo datasources plus two committed dashboards —
    `polaris-overview` (the /metrics headliners with the alert thresholds of
    polaris-alerts.yml drawn in; the duress panel is the alarm on a wall) and
    `polaris-traces` (TraceQL panels keyed on the correlation id, slow and
    errored requests). `docker-compose.observability.yml` runs Prometheus,
    Alertmanager, Tempo, and the provisioned Grafana as an overlay on the
    production stack, images digest-pinned, Grafana on 127.0.0.1:3000 only
    (it can display the duress signal: the /metrics access rule applies).
    `deploy/observability/tempo.yml` bounds trace retention to 7 days.
  - CI job `trace-drill` runs `scripts/polaris-trace-drill.sh` with the
    RUNTIME requirements only (tracing must work with exactly what the prod
    image ships): dashboards validated as provisionable JSON querying the
    real metric names, the overlay rendered against the production compose
    file, and the OTLP wire path proven — the exported span's payload
    carries the caller's exact X-Request-ID and the request's query string
    is asserted ABSENT from the bytes. The DB half (client spans inside the
    request trace, template-only statements) is `DistributedTracingTests`
    (12 tests) in the product suite, which also proves the log join on a
    real `auth_failure` line and both traceparent postures.
  - The check layer caught the ship's one real bug before CI did:
    `check_dockerfile_modules` flagged that the prod image COPYs modules
    explicitly and `tracing.py` was not among them (a startup
    ModuleNotFoundError in the container). Fixed; `check_distributed_tracing`
    (with its discrimination test) pins the rest: the opt-in gate, the proxy
    gate on traceparent, the duress panel on the overview dashboard, the
    wire-scrub assertion in the drill, and the app wiring. 98 checks, 95
    check-layer tests. Next opener: P1.7 session and origin hardening.

---

## v9.186 — 2026-09-01 (Roadmap P1.5: the Kubernetes/Helm reference profile, boots to healthy on kind with enforced policies and the restricted standard)

Compose on one Linux host stays the single-node path (P1.1); this gives an
authority whose platform is a cluster the same topology under Kubernetes'
own controls, and proves it on a stock cluster in CI.

  - `deploy/helm/polaris`: caddy (uid 1000, 8080/8443 behind a Service on
    80/443, `tls: internal` or ACME, the same headers, rate limit, and
    liveness-based retry as the compose edge), app (2 replicas,
    `maxUnavailable: 0`, readiness on /api/health/live, a
    PodDisruptionBudget: the Kubernetes-native form of P1.4), pgbouncer,
    postgres (a StatefulSet running as uid 70 with PGDATA in a subdirectory of
    the volume, TLS on), redis. Every pod satisfies the restricted Pod
    Security Standard (numeric non-root user, RuntimeDefault seccomp, all
    capabilities dropped, no privilege escalation). NetworkPolicies
    default-deny both directions for every pod and allow only the topology's
    edges, DNS for all, ACME egress only with `edge.tls=acme`, S3 egress for
    postgres only with pgBackRest enabled. Secrets: the same generator as
    compose (`existingSecret`, including the ML-DSA-65 signing key) or a
    chart-generated Secret with random passwords and self-signed certificates
    kept across upgrades.
  - The postgres image is now self-contained: the schema and migrations, the
    init script, and pgbackrest.conf are baked in (build context is the
    repository root; compose keeps bind-mounting the live copies). Every build
    site updated, including sbom.yml.
  - `scripts/polaris-helm-drill.sh`, run by the new `helm-kind` CI job: a kind
    cluster with the default CNI DISABLED and Calico installed, because
    kindnet does not enforce NetworkPolicy and a green run on it would prove
    nothing about the policies; the four self-built images loaded (pull policy Never for them,
    redis pulled by its pinned digest); the namespace labelled restricted and a privileged pod REJECTED by the API
    server; the real secrets as a Secret; `helm lint` and `helm install
    --wait`; /api/health through the edge with database, redis, zk_binary, and
    custody healthy; a probe pod outside the topology DENIED on postgres,
    pgbouncer, and app; and a rolling restart that keeps the edge healthy.
  - `docs/operator/KUBERNETES.md`: prerequisites (an enforcing CNI, storage,
    a LoadBalancer for ACME, images in a registry), install, verify, operate
    (upgrade, migrations, rotation, backups, metrics), limits. README and the
    operator index link it.

Found by running the drill locally: `kind load` of a digest-referenced
manifest list (the pinned redis) fails inside the node with "content digest
not found" for the platforms it does not have, so the drill loads only the
four self-built images (pull policy Never for them) and the node pulls redis
by its pinned digest; the chart gained a per-image `redisPullPolicy` for
exactly that. The second run then showed postgres crash-looping on a
missing server.crt: the StatefulSet passed `-c ssl=on` as an argument, which
the official entrypoint also applies to the TEMPORARY server it starts to run
the init scripts, before docker-init.sh has copied the certificate in; init
aborted half-way and every restart skipped it. docker-init.sh turns TLS on
itself (as on compose), so the argument is gone. The third run, with every
pod's logs dumped on failure, showed the last two: the app could not start
because kubelet needs /var/run/secrets/kubernetes.io/serviceaccount for the
projected API token and the Secret mount had made /run/secrets read-only,
so every workload now sets automountServiceAccountToken: false (none of them
talks to the API; one credential fewer in every pod); and caddy died with
"exec /usr/bin/caddy: operation not permitted" because the runtime base
image sets cap_net_bind_service on the binary as a FILE capability, which a
non-root process with all capabilities dropped cannot exec at all. The
profile listens on 8080/8443, so Dockerfile.caddy strips the file capability;
the compose edge, root with NET_BIND_SERVICE from cap_add, still binds 80/443
(proven), and `check_helm_reference_profile` pins both.

Stated limits: one postgres replica (HA PostgreSQL is P2), `tls: internal`
and a single node in CI, no registry images published yet (the operator
builds and pushes; P0.6's image-signing deferral stands until there is a
registry). 97 checks, 94 check-layer tests. Next opener: P1.6 distributed
tracing and dashboards-as-code.

---

## v9.185 — 2026-09-01 (P1.4 follow-through: a wider app healthcheck window for cold starts)

v9.184 was green on all eleven jobs with no product change since v9.183, so
the v9.183 Linux-install failure at `systemctl start polaris.service` did not
reproduce and its cause is unconfirmed (that run predates the journal dump).
What v9.183 introduced at start time is the app healthcheck, which caddy's
`depends_on: condition: service_healthy` now genuinely waits on: `compose up`
fails the unit if the app is not healthy within the window. A cold start on
a slow host (fresh image, first gunicorn boot, liboqs initialisation) is the
plausible way to exceed the first window (20s start period, 12 retries at
5s). The window is now 40s + 36 retries; the rolling deploy still waits on
the same healthcheck, so nothing else changes. If the failure recurs, the
v9.184 diagnostics will show the journal. 96 checks, 93 check-layer tests.

---

## v9.184 — 2026-09-01 (P1.4 follow-through: the installer now shows WHY polaris.service failed)

The v9.183 run was green on ten of eleven jobs, including the first run of
the rolling-deploy drill on a GitHub runner (264 served, 0 drops, both
colours replaced, control detected the outage). The Linux install job failed
at `systemctl start polaris.service` and the log holds only systemd's one-line
summary, because the installer never dumped the journal; this is the second
time that gap has cost a round trip. install.sh now prints the last 60
journal lines, the compose state, and the tail of every polaris container's
log when the unit fails to start. No product change; the next run diagnoses
itself.

---

## v9.183 — 2026-09-01 (Roadmap P1.4: zero-downtime deploys; blue-green behind a retrying edge, expand-contract enforced, zero drops proven with a control)

OPERATIONS.md called the deploy a "blue-green swap"; it was `docker compose up
-d`, which recreates the single app container and serves 502s for the seconds
gunicorn takes to boot. Now:

  - Blue-green profile (`docker-compose.bluegreen.yml`): `app` and
    `app-green` behind Caddy. Both Caddyfiles take their upstream list from
    POLARIS_UPSTREAMS, retry a request onto the other colour for up to 15s
    while one is being recreated (lb_try_duration), poll /api/health/live
    every 2s, and skip a failed upstream for 10s. The app service gains a
    healthcheck (the roll waits on it) and a 35s stop_grace_period so
    gunicorn drains in-flight requests on SIGTERM.
  - `polaris-deploy.sh` honours POLARIS_COMPOSE_EXTRA (the variable
    polaris.service already used), brings infrastructure up WITHOUT touching
    the app containers, applies migrations (the expand phase, against the
    code still running), then recreates app-green, waits for its healthcheck,
    then app; on failure the previous image is re-tagged and every colour is
    recreated from it. `polaris-rotate-secret.sh` recreates the colours the
    same way, so rotation is zero-downtime too.
  - Expand-contract policy in polaris_sql/migrations/README.md, enforced by
    `check_migrations_expand_contract`: an .up.sql containing destructive DDL
    (DROP TABLE/COLUMN, ALTER COLUMN TYPE, RENAME, SET NOT NULL) must declare
    `-- phase: contract` and `-- expands: <id>` naming an EARLIER migration;
    reverts are exempt; comments are not DDL. All 17 existing migrations
    comply with no grandfathering.
  - `scripts/polaris-rolling-drill.sh`, run by the new `rolling-deploy` CI job
    against the booted blue-green stack: a traffic generator (8 threads,
    continuous GETs at the TLS edge; every non-200 and every transport error
    is a drop) runs while `polaris-deploy.sh prod` performs a full deploy;
    the drill asserts zero drops with a meaningful request count and that
    BOTH app containers were replaced. Then the negative control: both
    colours stopped for 20s (longer than the retry window) under the same
    traffic must show drops, so a generator that could not see an outage
    would fail the drill rather than pass it (the P0.4 vacuous-scenario
    lesson, applied in advance).

Found by running the drill locally before shipping: `mapfile` does not exist
in macOS's bash 3.2, so the new roll step killed polaris-deploy.sh silently
right after the migrations (CI's bash 5 would have hidden that from a script
the repo says runs on macOS); it is a portable read loop now, and the drill
shows the deploy's full output instead of a grep for the lines expected. And
the first generator ran at ~160 rps, above the edge's own 1000/min rate limit,
so two thirds of its requests were 429s: the edge enforcing policy, not
drops; the generator now stays under the limit and counts 429 separately
while still requiring a meaningful number of served requests.
The third local run then failed its own preflight on the session's oldest
defect family: `compose config --services | grep -qx app-green` under
pipefail, where grep exits on the first match and compose gets SIGPIPE, so
the pipeline read as failed at random (it had passed the run before). The
drill captures then tests, and `check_zero_downtime_deploy` refuses a
`| grep -q` pipeline in it.

Stated limits: recreating caddy (edge config changes) or postgres is still a
service interruption; this makes app deploys and rotations, the routine
operations, drop nothing. Both Caddyfiles validate on the self-built edge
with two upstreams. 96 checks, 93 check-layer tests. Next opener: P1.5
Kubernetes/Helm reference profile.

---

## v9.182 — 2026-09-01 (P1.3 follow-through: rotating the DB password never restarted pgbouncer)

v9.181 cleared both earlier failures: the Linux install is green (with the
custody component healthy in the payload) and the live rotation drill got
through both rotations with write-through. It then failed on health, and the
app log says exactly why: `connection to server at "pgbouncer" ... FATAL: SASL
authentication failed`. pgbouncer (in the stack since v8.83) generates its
userlist.txt from the secret at container start; polaris-rotate-secret.sh
(written v8.77, before pgbouncer) recreated only the app after ALTER USER, so
pgbouncer kept authenticating with the old password and every connection
failed. On a real deployment, rotating the DB password would have taken the
stack down. The script now recreates pgbouncer before the app, SECRETS.md
section 3.3 says so, and `check_secrets_lifecycle_sealed` refuses a
polaris_db_password branch that does not recreate pgbouncer. This is the
third pre-P1.3 defect the sealed-secrets drill has surfaced, all in the
rotation path nobody had run against the production topology. 94 checks, 91
check-layer tests.

---

## v9.181 — 2026-09-01 (P1.3 follow-through: two latent Linux defects the new drills exposed)

The v9.180 run proved the sealed boot on CI: secrets sealed to a throwaway
age identity, the plaintext directory deleted, the store unsealed into a
tmpfs, the full production stack booted from it and healthy through the TLS
edge. Two jobs then failed on defects that predate P1.3 and had never been
reachable before:

  1. The rotation drill died on the first command of polaris-rotate-secret.sh:
     `CUR_MODE=$(stat -f '%Lp' ... || stat -c '%a' ...)`. GNU stat treats -f as
     file-system status and EXITS 0 with a multi-line report, so on Linux the
     fallback never ran and chmod received garbage. The script had only ever
     been exercised on macOS (BSD stat). The dialect is now chosen by
     capability (`stat --version`), the result is validated as octal, and
     `check_rotate_secret_preserves_mode` refuses the `stat -f ... ||` chain
     on executable lines (a comment naming it does not trip the check). Proven
     on GNU stat in a Debian container and on BSD stat locally. Same family as
     grep -q, psql -f, and `_out=$(cmd); _rc=$?`: an exit code judged instead
     of the outcome.
  2. The Linux installer's polaris.service failed at start because
     polaris.env.example set POLARIS_SECRETS_DIR=/run/polaris/secrets
     unconditionally, so with the file backend compose resolved every secret
     to a directory nothing populates. The variable is now left empty there
     (the unseal defaults it only for a sealed backend), and
     `check_secrets_lifecycle_sealed` pins that.

No product change beyond the rotation script's mode detection. 94 checks,
91 check-layer tests.

---

## v9.180 — 2026-09-01 (Roadmap P1.3: production secrets from a sealed store, materialized into a tmpfs; rotation drilled live in CI)

Until now every production secret (the session key, the DB and replicator
passwords, the signing key file, the TLS keys, the pgBackRest key pair) was a
plaintext file in polaris_web/secrets/ and nowhere else. That directory is now
the MATERIALIZED form only; the source of truth is a sealed store.

  - `polaris_web/secretstore.py`: `age` (each secret encrypted to the
    operator's age recipients; the identity that decrypts can live on a
    hardware token) and `awskms` (envelope encryption: per file, KMS
    GenerateDataKey gives an AES-256 data key and its KMS-wrapped form, the
    file is AES-256-GCM encrypted with the file name as AAD; Decrypt pins
    KeyId, so a store re-wrapped under a new key is refused through a stale
    backend rather than silently read). `file` keeps the old layout for
    development. MANIFEST.json records per-file sha256 and MODE, and unseal
    restores the mode (the v9.140 lesson: uid-70 containers must read them).
    Operations: seal, unseal, verify (sealed == materialized, no drift),
    rotate-wrapping (a new identity or key; values unchanged; the previous
    generation kept beside it).
  - `scripts/polaris-secrets.sh` wraps it; `unseal-if-configured` mounts a
    root-only tmpfs (mode=0700,nosuid,nodev,noexec) at POLARIS_SECRETS_DIR and
    unseals into it. `polaris-deploy.sh` runs it before its preflight and
    `polaris.service` runs it as ExecStartPre, so plaintext exists only in RAM
    while the stack runs. The compose files read every secret and certificate
    through `${POLARIS_SECRETS_DIR:-./secrets}` (15 references; none bare).
  - `polaris-rotate-secret.sh` rotates the materialized copy and WRITES THROUGH
    to the sealed store (previous blob kept as .prev), so a reboot re-unseals
    the new value; `polaris-secrets.sh verify` asserts that invariant.
  - SECRETS.md section 8 is rewritten around the store (adoption, rotation of
    a secret and of the wrapping key, what CI drills); the old Vault / AWS
    envelope / GSM launch-wrapper recipes are replaced by one sentence: an
    external store is the same unseal hook. LINUX-SERVER.md and
    polaris.env.example carry the four POLARIS_SECRETS_* settings.

Drilled, not asserted. `test_secretstore.py` (19 tests, both backends real:
age through the CLI, KMS through the wire-faithful stand-in whose envelope
cryptography is real AES-GCM): round-trip with modes, stale-file removal,
drift detection, tampered blob and manifest refused, seal --only write-through,
wrapping rotation (old key refused, new key opens, .prev intact), backend
mismatch refused. In CI, prod-stack-boot now seals the generated secrets to a
throwaway age identity, DELETES the plaintext directory, unseals into a tmpfs,
boots the full production stack from it, asserts health through the TLS edge,
then rotates polaris_db_password and polaris_secret_key on the LIVE stack with
polaris-rotate-secret.sh, asserts health again, verifies the sealed store
matches the tmpfs byte for byte, and proves a fresh unseal returns the rotated
password. The KMS stand-in moved to `kms_standin.py`, shared with
test_custody.

Found by running: age-keygen prints "Public key:" capitalised (the parser
matched nothing); KMS Decrypt resolves the key from the ciphertext, so
without KeyId a stale backend would open a re-wrapped store; and a global
`./secrets/` replace rewrote a comment I then asserted on. Stated limits: on
macOS or as non-root the materialized dir is a plain 0700 directory with a
warning, not a tmpfs; the KMS backend is drilled against the stand-in, with
the same driver wire path a real key would see. 94 checks, 91 check-layer
tests. Next opener: P1.4 zero-downtime deploys.

---

## v9.179 — 2026-09-01 (P1.2 follow-through: the PKCS#11 CI recipe moves out of an inline bash -c block)

The v9.178 run was green on nine of ten jobs, including test_custody in
pqc-real with both witnesses (file driver real, KMS stand-in, rotation, env
refusals). The new custody-pkcs11 job failed before touching the driver:
its recipe was a single-quoted `bash -c '...'` block in ci.yml, and two
comments inside it contained an apostrophe ("Fedora's"), which ended the
quoted string, so `dnf` ran on the Ubuntu runner ("dnf: command not found").

The recipe is now `scripts/polaris-custody-pkcs11-drill.sh`, run by the job
and locally with the identical `docker run ... bash /src/scripts/...` line
(the same shape as the offsite and page drills). Quoting is not a place to
be clever.

Running that script locally, exactly as CI does, then found a second thing the
one-off experiment had not: Pkcs11CustodyTests generated its in-token key
under a per-PROCESS label, so with all three tests in one process the second
setUp tripped the driver's own duplicate-label refusal (the refusal working as
designed; the test's label was wrong). The label is now per test method, and
the PIN file handle is closed. No product change; the driver itself was proven
against Kryoptic before v9.178 shipped. 93 checks, 90 check-layer tests.

---

## v9.178 — 2026-09-01 (Roadmap P1.2: the issuer signing key behind a custody interface, HSM/PKCS#11 and AWS KMS drivers)

Polaris has one long-lived private key, the issuer's ML-DSA-65 token-signing
key, and until now it was a JSON file the app read into memory. That is now
the `file` driver of a custody interface, and two more drivers put the key
where a national authority keeps it.

  - `polaris_web/custody.py`: `KeyCustody` with `public_key()` and
    `sign(digest)` returning raw ML-DSA-65 bytes, so nothing downstream can
    tell which driver signed. `FileCustody` (the JSON file, liboqs in-process);
    `Pkcs11Custody` (a PKCS#11 v3.2 token: the key is generated IN the token by
    the ceremony helper, sensitive and non-extractable, and every signature is
    `CKM_ML_DSA` inside it); `AwsKmsCustody` (KeySpec `ML_DSA_65`, `Sign` with
    `MessageType RAW` and `ML_DSA_SHAKE_256`, the public key parsed from KMS's
    SPKI; wrong key spec or a disabled key is refused at load). Selection by
    `POLARIS_CUSTODY_DRIVER`; the PKCS#11 PIN comes only from a file and the
    app refuses to start if it finds the PIN in env.
  - `pqc_signing.sign()` obtains signatures from the custody driver; the
    two-witness verification (liboqs and OpenSSL must agree) is byte-for-byte
    unchanged and still gates every signature before it is stored, whichever
    driver produced it. `verify_token_signature` now accepts the current key
    or any previous key listed in `POLARIS_PQC_TRUST_ANCHORS_FILE`, which is
    what makes rotation possible; a malformed anchors file fails loud.
  - `/api/health` gains a `custody` component (driver, key id, public-key
    fingerprint; degraded when real PQC is on with only ephemeral keys,
    unhealthy when the backend fails to load); `polaris-pqc-status.sh` prints
    the same. The prod compose passes the non-secret custody env through, and
    two overlay templates (`docker-compose.custody-pkcs11.yml`,
    `docker-compose.custody-awskms.yml`) mount the vendor module / PIN file /
    credentials file; the app image takes `--build-arg POLARIS_CUSTODY_EXTRAS=1`
    for the optional drivers (`requirements-custody.txt`: python-pkcs11,
    boto3, pinned).
  - `docs/operator/KEY-CEREMONY.md`: what a witnessed ceremony records, the
    ceremony per driver, rotation with trust anchors, and the compromise case.
    SECRETS.md, PQC-POSTURE.md, and the operator index point at it.

Exercised, not asserted. `test_custody.py`: the file driver for real; the KMS
driver through its real botocore wire path (JSON 1.1, SigV4, base64 blobs,
SPKI) against a stand-in that implements DescribeKey / GetPublicKey / Sign and
signs with OpenSSL's ML-DSA-65, so the only fake is the remote service, plus
an opt-in live test; rotation end to end (a token signed under the old key
stops verifying after the switch and verifies again once the old key is an
anchor); the env refusals. The PKCS#11 driver runs against a REAL PKCS#11 v3.2
token: Kryoptic (a software token with ML-DSA, Fedora 43) in the new
`custody-pkcs11` CI job, key generated in-token, signatures verified by both
witnesses, duplicate labels refused. Building it found the usual things:
`MLDSAParameterSet` lives in `pkcs11.mechanisms`, not `constants`; liboqs-python
builds liboqs from source when Fedora's 0.12 is older than it wants, and needs
git for that; and the dev Dockerfile's per-module COPY list did not include the
new module (caught by `check_dockerfile_modules` before it could ship).

Scope, honestly: epoch anchors are hash-chained, not signed, so the issuer key
is the only key under custody; anything signed later goes through the same
interface. No hardware HSM is exercised in CI; the PKCS#11 conformance surface
is exercised against a software token. AWS is the cloud driver shipped; GCP and
Azure ML-DSA are preview-stage and follow the same shape.
`check_key_custody_abstraction` pins all of it. 93 checks, 90 check-layer
tests.

---

## v9.177 — 2026-09-01 (P1.1 follow-through: the CI assertion could not read the backup directory it was checking)

The v9.176 `linux-install` job proved the substance of P1.1 on a real Linux
host: both package stages executed (deb and rpm keys verified, docker-ce
installed), the full installer reached a healthy stack under real systemd
(database, redis, zk_binary, atlas_cache, disk all healthy through the TLS
edge), `polaris.service` was active, both timers were scheduled, and
`systemctl start polaris-backup.service` succeeded. It then failed on my own
assertion: a non-root `ls` of `/var/backups/polaris`, which is 0750 root-owned
on purpose (HARDENING.md). The listing now runs under sudo and the backup
unit's journal is printed; the tarball and the post-restart health assertions
that follow it get their first real run in this version's CI. No product
change. 92 checks, 89 check-layer tests.

---

## v9.176 — 2026-09-01 (Roadmap P1.1: a fresh Linux server to a healthy production stack, under systemd)

P1 opens. Until now the production path was "any Docker host" plus a deploy
script, and DEPLOYMENT.md still carried a native gunicorn+nginx recipe that
bypassed the container hardening, the TLS hops, pgBackRest, and the secrets
layout. Now one script takes a fresh Debian 12+, Ubuntu 22.04+, or RHEL 9
family host to the full stack owned by systemd, and CI proves it.

  - `deploy/linux/install.sh`: Docker Engine + the compose plugin from Docker's
    OFFICIAL apt or dnf repository, after verifying the signing key's
    fingerprint with gpg; it never pipes a download into a shell. Then the repo
    at /opt/polaris, the production images, secrets (if-missing),
    /etc/polaris/polaris.env (0600), the systemd units installed and enabled,
    the stack started, migrations and DB objects synced, and /api/health
    asserted healthy through the TLS edge. Idempotent; `--stage`, `--no-start`,
    `--skip-build` for partial runs.
  - `deploy/linux/polaris.service` (Requires=docker.service, EnvironmentFile,
    compose up/down), `polaris-backup.timer` (daily 03:00 UTC) and
    `polaris-backup-verify.timer` (Sunday 04:00 UTC) driving the existing
    backup script, and `polaris.env.example` as the only configuration surface.
  - `docs/operator/LINUX-SERVER.md`: requirements, the three-command install,
    what is installed, operate, upgrade (polaris-deploy.sh on the same compose
    project), offsite backups, paging, uninstall, caveats (SELinux labels,
    ufw and Docker, no public DNS yet), and how it is tested.
    `docs/operator/HARDENING.md`: the host around Polaris as copy-paste
    commands for both families: SSH, updates, firewall and Docker's iptables
    bypass, chrony, daemon.json, permissions and separate volumes, sysctl,
    auditd on the secrets, fail2ban, /metrics exposure, backups off-host, RHEL
    specifics. DEPLOYMENT.md's native path is retired in favour of these;
    README, OPERATIONS, and the operator index link them.
  - CI job `linux-install`: the packages stage executes for real inside
    digest-pinned Debian 12 and Rocky Linux 9 containers, then the full
    installer runs on the Ubuntu runner with real systemd: /opt/polaris,
    secrets, units, `systemctl start polaris`, migrations, health through the
    TLS edge, `systemctl start polaris-backup` producing a tarball, and health
    again after `systemctl restart polaris`. Stated limit: ACME against a
    public domain cannot run in CI; the edge uses Caddy's internal CA
    (docker-compose.citest.yml), which differs from production only in who
    signs the certificate. `check_linux_server_deployment` pins all of it.

Three things found by running it that reading would not have found:

  1. Docker signs its deb and rpm repositories with DIFFERENT keys. The first
     Rocky run refused the rpm key against the deb fingerprint, which is
     exactly what verification is for; the installer now carries both
     fingerprints (deb 9DC85822...0EBFCD88, rpm 060A61C5...621E9F35, both from
     Docker's docs) and the check requires both.
  2. RHEL 9 ships curl-minimal, which conflicts with the full curl package;
     `dnf install curl` fails on a stock Rocky 9. curl is installed only if
     absent.
  3. The check's "never curl | sh" regex matched the installer's own header
     comment saying never to do that. Checks judge executable lines, not
     comments.

92 checks, 89 check-layer tests. P1.1 done; P1.2 (key custody, HSM/KMS) is
the next opener.

---

## v9.175 — 2026-09-01 (Roadmap P0.10: pager integration, and the duress page path proven end to end)

Polaris shipped alert rules and a scrape config, but the Alertmanager side was
a commented-out block, no receiver existed, "promtool-validated" was a claim in
a comment that no CI step ever checked, and nothing proved that a duress event
reaches a human. Now:

  - `deploy/observability/alertmanager.yml`: routing and a `pager` receiver.
    PolarisDuressEvent is routed with `group_wait: 0s` and re-paged every 15
    minutes until a human resolves the situation (the alert clearing is not
    resolution); other SEV-1 page immediately with hourly repeats; SEV-2/3 are
    batched. PolarisAppInfoAbsent is inhibited while PolarisAppDown fires. The
    default route is the pager: an alert with no route is the wrong failure
    mode. The pager URL is read from a mounted file (`url_file`), never written
    into config, because it usually embeds the integration key; the native
    PagerDuty/Opsgenie/Slack blocks are sketched with file-based keys too, and
    `check_pager_integration` fails on any inline url/routing_key/api_key.
  - `prometheus.yml` is wired to that Alertmanager instead of carrying a
    commented example.
  - `scripts/polaris-page-drill.sh`, run by the new `page-drill` CI job:
    promtool checks the rules and config, amtool checks the receiver config,
    then real Prometheus and real Alertmanager (digest-pinned) run on the
    SHIPPED files against a stub /metrics and a webhook sink. The drill asserts
    silence while polaris_duress_events_total is 0, flips it to 1, and asserts
    the PolarisDuressEvent page arrives at the webhook with receiver=pager,
    severity=sev1, status=firing. Measured time-to-page: 2 seconds. The app
    half, a duress-code match incrementing that counter, is the existing
    `test_duress_increments_prometheus_counter` (v9.128), which the check now
    requires to stay; the two halves together cover the path from a holder's
    duress code to the pager URL.
  - RUNBOOKS.md gains "Paging: wiring the receiver": mount the URL file, run
    `amtool alert add alertname=PolarisDuressEvent ...` through the real
    receiver before you need it for real, what the page payload carries (and
    does not: no token, no holder), and the routing as shipped. The
    observability README, OPERATIONS.md checklist, and PRODUCTION-READINESS
    are updated; the stale "five rules" count is fixed to six.

Scope, honestly: the drill's pager is a webhook sink, not PagerDuty; the on-call
product and its URL remain operator-supplied. What is no longer a claim is
everything between the counter and that URL. 91 checks, 88 check-layer tests.
P0 buildable rows are now complete (P0.11 is externally gated).

---

## v9.174 — 2026-09-01 (P0.9 follow-through: generate-secrets called its new function before defining it)

The v9.173 CI prod-stack boot died in "Generate secrets + certs" with
`write_pgbackrest_creds_if_missing: command not found` (exit 127). The v9.173
edit inserted the function's DEFINITION just above the closing banner, which
is after the line that CALLS it; bash resolves functions at call time, and
`bash -n` (the only thing v9.173 ran on this script) passes on that. Every other
v9.173 step was green, including both pgBackRest round-trips and the offsite
drill on the runner.

The definition now sits with the other write_*_if_missing definitions, the
script was actually run this time (template created, non-empty so the deploy
preflight's `-s` passes, parsed as empty by pgBackRest), and
`check_offsite_backup_env_driven` asserts the definition precedes the call so a
future move cannot repeat it.

The lesson is the session's standing one, applied to my own change: `bash -n`
is syntax, not execution. A script I edit gets RUN before it ships, not linted.
90 checks, 87 check-layer tests.

---

## v9.173 — 2026-09-01 (Roadmap P0.9: offsite backup by env alone, drilled against S3 in CI)

The pgBackRest offsite repo was documented as a hand-edit of pgbackrest.conf
plus a hand-mounted credentials file, and only the LOCAL repo was ever
exercised. Now three env settings on the postgres service switch the repo to an
S3-compatible bucket, and CI backs up into a bucket and restores from it on
every push.

  - `polaris_web/pgbackrest-conf.sh`, run by a new image entrypoint wrapper on
    EVERY container start (not just first init, which is all initdb.d gets, so
    the fragment survives container recreation), renders
    /etc/pgbackrest/conf.d/repo.conf: the local repo when
    POLARIS_PGBACKREST_S3_BUCKET is unset, an S3 repo (endpoint, region, path,
    port, URI style, CA file) when it is set. A read-only operator-mounted
    repo.conf is left alone (Azure, GCS, SFTP repos).
  - The S3 key pair is NEVER env. It lives in secrets/pgbackrest_repo_creds.conf
    (created as a commented template by polaris-generate-secrets.sh, mounted
    read-only by the prod compose, required by polaris-deploy.sh's preflight),
    and the container refuses to start if it finds the pair in its environment.
  - `scripts/polaris-offsite-drill.sh`: MinIO (digest-pinned) over TLS with a
    throwaway certificate handed to pgBackRest as its CA file, so verification
    stays ON as against real S3. Proves the env refusal, the rendered
    repo1-type=s3, backup objects present in the bucket, WAL archived after the
    backup, and a fresh postgres restored from the bucket alone with the
    post-backup row replayed. ci.yml runs it after the local round-trip.

Two defects the drill found that reading could not, both recorded so they stay
found:

  1. pgBackRest refuses an option that appears in more than one config file
     ("option 'repo1-path' cannot be set multiple times"). The first design put
     the S3 fragment in conf.d assuming later files override earlier ones; they
     do not. The repo location now lives in exactly one rendered file, and
     `check_offsite_backup_env_driven` fails if repo1-path ever returns to
     pgbackrest.conf.
  2. The restore readiness loop died on its first probe: psql exits 2 while the
     restored server is still replaying WAL, and under `set -euo pipefail` that
     status aborted the loop with no message (stderr was discarded). The probe
     is now tolerated and only the final value is judged. Same family as the
     grep -q / psql -f / `_out=$(cmd); _rc=$?` defects: a collapsed exit code
     judged instead of the outcome.

Scope, honestly: the drill's endpoint is MinIO, a real S3 API but not a real
cloud bucket; the bucket, its key pair, and the schedule are still operator
supplied, and DR.md keeps the RPO claim gated on `pgbackrest check` passing
against the real repo. 90 checks, 87 check-layer tests.

---

## v9.172 — 2026-09-01 (Roadmap P2.12: a Plonky2 to Plonky3 evaluation, framed honestly)

Prompted by an outside suggestion that Plonky3 is a newer/better version to
migrate to. Verified against crates.io first, and the premise needed
correcting before it went on the plan:

  - There is no `plonky3` crate. It ships as modular `p3-*` components
    (`p3-field`, `p3-uni-stark`, `p3-merkle-tree`), a STARK/AIR TOOLKIT, at
    0.7.0-rc.1 (a release candidate, active as of 2026-08).
  - Plonky2 is stable at 1.1.0 but last released 2025-05 (16 months quiet).
  - So it is not a version bump: Plonky3 has no drop-in for Plonky2's
    ready-made recursive-SNARK CircuitBuilder + Merkle gadget, so adopting it
    rewrites polaris_zk as an AIR and re-anchors the two-witness from scratch.

The real signal (Plonky2 staleness vs. Plonky3 momentum) is a legitimate
long-term supply-chain question for a national system, so it is added as
P2.12: an EVALUATION SPIKE with a keep-or-migrate decision record, NOT a
committed migration. It sits in P2 deliberately, because you do not rewrite a
prover before Plonky3 stabilizes past RC and before the scale requirements
(P2.5) justify the cost. The nearer-term ZK step stays the sibling-path witness
optimization named in P0.7. Roadmap-only change; 89 checks, all references
resolve.

---

## v9.171 — 2026-09-01 (Roadmap P0.8: coverage measured, and a floor that fails CI on a regression)

There was no coverage measurement at all; a refactor that stopped exercising a
module would have read as green. Now both surfaces are measured and gated.

`scripts/ai-coverage.sh` runs the Python suites under coverage.py in
parallel-append mode, combines them across their different working directories
(a pinned absolute `COVERAGE_FILE`, since test_app runs from polaris_web/ and
test_cli from polaris_cli/), reports, and fails below a floor. CI runs it with
`COVERAGE_FLOOR=72`; the measured baseline is 78%, so there is honest headroom
and a real drop fails while noise does not. The floor is a ratchet: raise it as
coverage climbs, never silently lower it.

The measurement found its own blind spot. `polaris_cli/polaris.py` (664 lines)
first reported 0% despite 64 passing CLI tests, because test_cli shells into it
as a subprocess that the parent's coverage cannot see. Wiring the coverage
subprocess pattern (a sitecustomize on PYTHONPATH calling
`coverage.process_startup()` under `COVERAGE_PROCESS_START`) makes the child
record its own data: polaris.py is actually 77% covered, and the combined total
rose from a misleading 66% to a true 78%. Measuring honestly changed the number
by twelve points.

Rust: CI gates the crypto library (lib.rs: circuit, prover, verifier) at
`cargo llvm-cov --fail-under-lines 85`, baseline ~92%. main.rs (thin CLI
dispatch) is excluded because it is exercised by the prove-verify roundtrip and
the app shell-out, not by `cargo test`, so counting it would understate the
tested surface. Both coverage numbers are published to the CI step summary.

Scope note, recorded honestly: the DoD said "published per release." A coverage
run needs the Postgres the release workflow does not have, so publication is
the CI step summary on every run, not a per-release asset. The load-bearing
half (the floor gate that fails on regression) is fully delivered.

The four scattered Python test steps were consolidated into the one
coverage-instrumented step so nothing runs twice; the script prints
`::error::suite failed: <which>` so a red suite fails CI with granularity, and
SUITE_FAIL gates the exit alongside the floor (an early version swallowed suite
failures and would have passed CI on a broken test as long as coverage held).
`check_coverage_gated` pins both gates. 89 checks, 86 check-layer tests.

---

## v9.170 — 2026-09-01 (Roadmap P0.7 part 2: the plonky2 0.2 to 1.x major, evaluated then taken)

The proving-system major Dependabot proposed and v9.161 deferred as unevaluated
is now taken, after the evaluation P0.7 called for came back clean.

The revalidation, all on the real crate (0.2 to 1.x) rather than trusting the
version number: the crate builds, the eight Rust crate tests pass, a Merkle
root over a fixed leaf set is BIT-IDENTICAL to the 0.2-era root (Poseidon and
Goldilocks parameters unchanged across the major, so the constants extracted
from 0.2.2 remain valid and needed no regeneration), and the full two-witness
differential re-passes 31/31 against the 1.x binary. The second witness is the
load-bearing check here: if 1.x had altered the hash, the encoding, or the tree
ordering, the independent Python re-derivation would have diverged, and it did
not.

Plonky2 1.x made `PartialWitness::set_*` return a `Result` (it errors on a
double-set), which surfaced as seven "unused Result that must be used"
warnings. These were handled with `?`, not silenced: `prove()` already returns
`Result`, and a dropped set error could leave a circuit target unconstrained,
so the error is propagated. Zero warnings remain.

The soundness ledger, the Poseidon-constants provenance note, and the
dependabot posture were all updated to reflect 1.x. A future 2.x stays
`ignore`d for the same reason 1.x was: a proving-system major gets a bit-for-bit
revalidation, not a blind merge. ROADMAP P0.7 is done across v9.169 (profile +
benchmarks) and this ship (the major). 88 checks, 85 check-layer tests.

---

## v9.169 — 2026-09-01 (Roadmap P0.7 part 1: the ZK tree is parameterized and, for the first time, benchmarked)

The ZK layer's tree depth was a hardcoded `const TREE_DEPTH = 14`; the
soundness ledger admitted its prove/verify cost was "aspirational until
measured." Both are now fixed.

**Parameterized.** Depth is read at runtime from `POLARIS_ZK_TREE_DEPTH`
(default 14, range 4..=32), once, via OnceLock in Rust and an env read in the
Python second witness. Plonky2 is transparent, so a depth change is a config
change, not a trusted-setup ceremony. The two sides MUST share a depth or the
verifier rejects a valid proof (fails safe), so both read the one env var and
`check_zk_tree_depth_synced` pins their defaults together. The full two-witness
differential passes 31/31 at the default depth: the parameterization changed
nothing observable, which is the point.

**Benchmarked.** Measured across depths 10-24 (the ledger now carries the
table). Two facts set the production profile:

  depth 14 (default): prove ~36 ms, verify ~10 ms, proof 76 KB, 16,384 leaves
  depth 24:           prove ~11 s,  verify ~11 ms, proof 76 KB, 16.7M leaves

Verify time and proof size are effectively CONSTANT across depth (FRI
succinctness doing its job); a verifier's cost does not grow with the anonymity
set. Prove time grows superlinearly, but the cost is `pad_leaves_to_full_depth`
rebuilding the entire 2^depth-leaf tree per proof, NOT the SNARK (which is
O(depth) hashes). So depth 14 is production-ready at 36 ms, and larger
anonymity sets are gated on a sibling-path-only witness, not on the proof
system. The ledger's FRI bit-security caveat stays honest: performance is now
measured, but the concrete soundness-bit number is still not re-derived here.

**Plonky2 1.x pre-evaluated (bump ships next as v9.170).** In an isolated
worktree, plonky2 + plonky2_field 0.2 to 1.x builds clean, produces
bit-identical Merkle roots (Poseidon/Goldilocks semantics preserved), and the
full two-witness differential passes 18/18 against the 1.x binary. So the major
Dependabot deferred in v9.161 is safe; it ships as its own coherent change
(handling seven new must-use-Result warnings) rather than bundled here.

`check_zk_tree_depth_synced` pins prover/witness depth agreement. 88 checks,
85 check-layer tests.

---

## v9.168 — 2026-09-01 (Roadmap P0.6: keyless SLSA provenance signs every release SBOM)

The SBOM workflow from v9.167 now also signs what it produces. Each release
SBOM gets an SLSA build-provenance attestation via
`actions/attest-build-provenance@v4`, keyless through GitHub's OIDC identity
and Sigstore (Fulcio certificate, Rekor transparency log). There is no
long-lived signing key to leak or rotate; the signer identity is the release
workflow itself. An SBOM tells you what is in a release; the attestation proves
the SBOM was built by this repo and not forged. A consumer verifies both in one
command, now documented in SECURITY.md:

    gh attestation verify sbom-python.spdx.json --repo EgorKhaklin/polaris-id

**The DoD was amended honestly, in the roadmap row and here.** It asked for
"images and release artifacts cosign-signed." The four container images are
built and CVE-scanned in CI but published to no registry, so there is no
registry digest to sign; cosign image signing is not actionable without first
deciding to publish the images, which is separate work paired with the P1.5
Kubernetes/registry profile. Signing what actually ships (the release SBOMs)
with keyless SLSA provenance is the correct scope for today, and the deferral
is recorded rather than silently skipped.

The action was pinned to the current major v4, not the v2 that first came to
mind: the latest release is v4.2.2, and a signing control two majors behind is
the wrong default. Because the OIDC/Fulcio/Rekor flow only exists inside GitHub
Actions, this ship cannot be dry-run locally; like v9.167 it self-demonstrates,
and the release's attestation is verified after the fact with the documented
command.

`check_release_provenance` pins the attestation step, the id-token +
attestations write permissions keyless signing needs, and the presence of the
verify command in SECURITY.md. 87 checks, 84 check-layer tests.

---

## v9.167 — 2026-09-01 (Roadmap P0.5: an SPDX bill of materials attached to every release)

A new `.github/workflows/sbom.yml` fires on every published release and
attaches five SPDX-2.3 SBOMs to it: one for the Python runtime surface
(requirements.txt) and one each for the four self-built images (app, caddy,
pgbouncer, postgres). A downstream operator can now answer "what is in this
exact release" from a signed, versioned document instead of rebuilding and
inspecting.

The generator is the SAME Trivy the image-cve-scan job already pins (0.58.1),
not a new tool. One tool for the CVE gate and the SBOM means the bill of
materials describes the exact package set the scanner evaluated, and
`check_sbom_trivy_matches_scan` fails CI if the two versions ever drift, which
is the v9.155 duplicated-pin lesson applied to workflows instead of
requirements.

Both surfaces were exercised locally against the real Trivy image before
wiring: the Python SBOM captures 20 packages (Flask, Werkzeug, cryptography,
the runtime pins), an image SBOM captures 60 (the Alpine OS package set), and
the workflow's own SPDX-version + package-count validation step was run by hand
against the generated files. The job self-demonstrates: this very release is
the first to carry the attached SBOMs.

`check_sbom_workflow` pins that the workflow exists, triggers on release,
covers the Python surface plus all four images in SPDX, and attaches the
documents. 86 checks, 83 check-layer tests.

---

## v9.166 — 2026-09-01 (Roadmap P0.4: the last four operator tools exercised, four real defects)

The final un-swept tier from the ops-reliability arc. All four tools run end to
end; all four had a runtime defect invisible to reading, and two were security
tools that could not do their stated job.

**polaris_load_gen.py counted failures twice and exited green on a dead
backend.** It kept an independent `errors` counter alongside `statuses['err:*']`
and summed both, so a dead target reported 2x the real request count with all
rates halved. It also routed every HTTP error away from the status ledger,
which made the "rate-limited" counter (`statuses.get(429)`) permanent dead code
and meant a run of 100% 5xx exited 0, against the header's own stated purpose
("serves expected RPS without 5xx"). Now one ledger, errors derived, exit
gated on transport errors AND 5xx. Proven across the matrix: healthy (exit 0),
dead port (counts once, exit 1), 404 (ledgered by code), 100% 500 (exit 1).

**The chaos zk_binary_absent scenario was VACUOUS from day one.** It spawned
bare `python3`; where that is 3.9 the import of zk.py raises on its 3.10+
annotations before any verification runs, and the classifier counted ANY raise
as a fail-safe pass. So the security scenario reported a permanent all-clear
from a probe that never reached the verifier: a planted binary answering
verified=true still produced FAIL-SAFE. Fixed to run under sys.executable, gate
on a WRAPPER_READY sentinel (a pre-verifier raise is now INCONCLUSIVE, never a
pass), and strip POLARIS_ZK_BINARY so a stale override can't point past the
simulated absence. Now proven both directions: a fail-open verify_proof makes
the scenario exit 1.

**polaris-ct-monitor.sh was untestable and would parse an error page as
certs.** crt.sh is a flaky single-operator service (six live 502s in a row
during this sweep), and the whole tool was verifiable only against it; a
non-array 200 body would flow into the jq cert filters. Added a
POLARIS_CT_FIXTURE seam (the anomaly path is now exercised offline: a rogue-CA
cert with an un-allowlisted fingerprint alerts at exit 5, allowlisting it
clears to exit 0), retry-with-backoff so a transient flap self-heals, and a
JSON-array-type guard that fails closed to inconclusive.

**polaris-rotate-secret.sh regressed container-readable secret perms.** It
hardcoded chmod 0600 on every rotated secret, but generate-secrets.sh sets
polaris_db_password (and others) to 0644-inside-a-0700-dir on purpose: the
non-root app/pgbouncer containers cannot read a host-owned 0600 bind-mount on
Linux (the v9.140 fix). A rotated db password would crash-loop the prod stack
on next deploy, exactly the failure v9.140 shipped to prevent. Now the rotation
captures and reapplies the existing file mode; proven that 0644 stays 0644 and
0600 stays 0600.

Four detection-tested checks: load_gen_ledger, chaos_probe, ct_monitor,
rotate_mode. 84 checks, 81 check-layer tests. The exercise-don't-read rule from
the ops-reliability arc now stands at 19 real defects across the tools swept,
none ever visible to a static read.

---

## v9.165 — 2026-09-01 (Wave five: two floors taken, one minor caught narrowing its deps, one major caught sneaking past the filter)

Four PRs in the fifth wave, and two of them earned their scrutiny.

The pytest 9.1.1 and playwright 1.62 floors were taken per policy, along with
the prometheus floor already applied in v9.164.

**webauthn 2.8.0 was attempted and REVERTED on evidence.** The minor looked
routine, and the running venv even accepted it. The clean-resolve check told
the truth: 2.8.0 tightened its dependency cap to cbor2<6 while this surface
pins cbor2 6.x (current), so requirements.txt stopped resolving in a fresh
environment; CI's own pip install would have failed. Taking a minor is not
worth forcing a direct dependency backward. Reverted to the proven
webauthn 2.7.1 + cbor2 6.1.4 pair (clean resolve, audit clean, 440-test suite
green), and 2.8.0 is version-ignored in dependabot.yml with the reason; it is
taken when a release lifts the cap, or with the 3.x major in P1.7.

**The redis major came back through a side door.** The semver-major ignore
does not catch RANGE-requirement updates, and Dependabot proposed
>=8.1.0,<9.0 straight past it. Declined per the recorded P1.8 decision, and
the ignore hardened to all update forms for redis, with the observation
documented in the config: patches inside 5.x resolve automatically because
the range is open, so ignoring redis PRs costs nothing.

---

## v9.164 — 2026-09-01 (Wave four: one floor line, and the tide goes out)

Dependabot's fourth wave was a single PR: the prometheus-client floor to
>=0.26.0, chasing the range v9.161 set. Applied per policy (import verified,
pip-audit clean). Floors have now converged on current across every range in
both requirements files, so there is nothing left for the throttle to release:
the queue is empty by exhaustion, not by snapshot.

---

## v9.163 — 2026-09-01 (P0.3 closed for real: the queue drains to structural zero)

The v9.162 closes opened a third wave from behind the 5-PR throttle, so this
pass took the whole remaining surface at once instead of chasing waves:
typing_extensions 4.16.0, cbor2 6.1.4, cffi 2.1.1, packaging 26.3, the
hypothesis floor, and a full `cargo update` (29 compatible transitives,
build + tests green on the pinned nightly). The webauthn 2.x to 3.x major was
declined into P1.7 (the operator-MFA library deserves its own test pass, not
a batch merge) and the redis-py major preemptively ignored into P1.8, both
with roadmap rows amended and dependabot.yml ignore blocks so neither is
re-proposed weekly.

The full app suite passed at 440 tests, UP from 419: the cffi/cbor2 refresh
unskipped WebAuthn-path tests that had been silently dormant on the old
wheels. pip-audit strict stays clean.

After this ship the queue is structurally empty: every compatible bump is
current, and every declined major has a recorded home on the roadmap plus a
config-level ignore. Zero open dependency PRs is now a steady state, not a
snapshot.

---

## v9.162 — 2026-08-31 (P0.3 epilogue: the policy's first live test, three fresh bumps in one pass)

Dependabot processed the v9.161 push within seconds: it closed the ignored
majors on its own (the ignore blocks worked) and opened three fresh PRs for
bumps that had accrued since the June pins: click 8.5.0, gunicorn 26.2.0, and
a postgres 16-alpine DIGEST refresh, which the ignore rule correctly still
allows because it stays inside the pinned major. All three taken per the
documented policy as one batch: pip-audit strict clean, gunicorn imports, the
postgres image builds on the new digest, and the 64-test CLI suite passes on
click 8.5. Queue at zero.

---

## v9.161 — 2026-08-31 (Roadmap P0.3: nineteen Dependabot PRs resolved, fifteen taken, four declined on the record)

The backlog had accumulated since June across four ecosystems. Blind-merging
would have meant nineteen sequential CI runs and at least three breakages, so
the split was decided per PR and everything landed as one verified batch.

**Fifteen taken** (patch, minor, actions majors, same-tag digest refreshes):
anyhow 1.0.104, serde 1.0.229, serde_json 1.0.151 (Cargo.lock, precise);
click 8.4.1 and the prometheus-client floor on the runtime surface; the
hypothesis, pytest 9, and playwright floors on the dev surface;
actions/checkout 7, setup-python 7, configure-pages 6, deploy-pages 5,
upload-pages-artifact 5 across both workflows; the caddy 2.11.4
builder+runtime digest refreshes; alpine 3.24 for the self-built pgbouncer.
Verified before pushing: cargo build + tests on the pinned nightly, the
64-test CLI suite (click's biggest consumer), pip-audit strict clean, both
container images rebuilt locally (the caddy rate-limit assert and the
x/crypto floor still hold on the new digests), all three YAMLs parse, 80
checks READY.

**Four declined, with the reasons recorded where they gate:** postgres
16→18-alpine (the entire stack, CI, and docs pin PostgreSQL 16; a database
major is a migration project, not a Tuesday merge; revisit in the P2 scale
phase), python 3.12→3.14-slim (runtime pinned and tested on 3.12), and
plonky2 + plonky2_field 0.2→1.x (the proving system itself: proof-format
compatibility and two-witness revalidation required, folded into P0.7's ZK
production profile, whose roadmap row was amended accordingly).

**The policy is now config, not memory.** dependabot.yml documents the merge
policy and carries `ignore` blocks for the declined majors so they are not
re-proposed weekly; removing an ignore block is the decision record for
taking that major. ROADMAP P0.3 is done at v9.161.

---

## v9.160 — 2026-08-31 (Roadmap P0.1 + P0.2: the dated nightly, and the e2e suite that rotted because it never ran)

The first two deployment-roadmap items, shipped together as the S-sized batch
the execution protocol allows.

**P0.1: the ZK toolchain is pinned to nightly-2026-05-10.** A floating
`channel = "nightly"` re-resolves on every toolchain install, so an upstream
nightly change could break the ZK build with zero repo changes, and two
machines building the same commit could disagree. The pin is the nightly this
crate has been building against locally; `cargo build --release` (21s, clean)
and `cargo test --release` were proven on it before pinning, and rustup
auto-selects it from the file inside the crate directory. CI now DERIVES its
toolchain from rust-toolchain.toml instead of carrying its own floating
`toolchain: nightly` (the v9.155 lesson: a duplicated pin is a second source
of truth). `check_rust_toolchain_pinned` enforces the dated form and the
derivation.

**P0.2: the Atlas e2e suite runs in CI, after being repaired.** The suite
(v9.33) was wired to no CI job and had rotted in exactly the way it existed to
catch: the v9.146 MapLibre rewrite renamed every element it selected
(#atlas-globe is now #atlas-map; the #atlas-hud figure classes are now the
data-atlas-* hooks of the v9.142 test-pinned-markup contract), so the suite
would have failed on a perfectly healthy app. A suite that only ever skips
reads as green while it decays. Repairs: selectors moved to #atlas-map, the
#atlas-globe-data island, and the four data-atlas-* headline hooks (asserting
server-rendered values on first paint); the login helper made idempotent
(pages share one browser context, so a previous test's session cookie made
/login redirect past the form and the unconditional fill timed out); stale
atlas-globe.js comments corrected.

The suite gained POLARIS_E2E_REQUIRE=1: with it set, an unreachable app or a
missing browser is a hard FAILURE instead of a skip, so "ran zero tests" can
never read as green again. Operator behavior without the var is unchanged
(graceful skip). CI runs the suite in the docker-image job against the stack
it just booted, chromium installed on the spot.

Every leg was proven live before wiring: 3 passed against the healthy stack in
3.2s; a sabotaged page (id renamed inside the running container, restart,
sabotage confirmed present in the served HTML) failed the selector test;
restore returned 3 green; a dead port under REQUIRE produced 3 errors, and
without REQUIRE produced 3 skips. `check_ci_runs_atlas_e2e` pins the job, the
guard, and that the suite still honors the guard. 80 checks, 77 check-layer
tests.

---

## v9.159 — 2026-08-31 (ATLAS FEED INTERRUPTED, again: the v9.152 fix never covered the launcher's default path)

VANTA hit the atlas error chip on a fresh launch: all four spatial endpoints
500 with `UndefinedFunction`, the container database still carrying the
pre-v9.146 five-argument atlas signatures. v9.152 shipped "the launcher
refreshes code objects on every launch" for exactly this failure. It did not.

**The refresh only ever existed on the NATIVE path.** The v9.152 block runs
host psql against localhost, inside `launch_native`. `launch_docker`, the
launcher's DEFAULT, applied no migrations and refreshed nothing; a persistent
dev volume served whatever schema it was initialized with (here: functions
from before v9.146, and 6 of 9 migrations). The check that pinned v9.152,
`check_launcher_refreshes_code`, was a bare "11_atlas.sql appears in the file"
grep, so it passed for months on the native block while the default path
shipped the exact bug it existed to prevent. Presence is not coverage.

**The fix is one list, one tool, both paths.** `polaris-migrate.sh` gains
`--target=dev-stack` (dev compose, service db, polaris_test; files streamed
over stdin). `launch_docker` now calls `sync_db_docker`, which runs
`--target=dev-stack --up` then `--target=dev-stack --sync-objects`, in BOTH
branches (fresh boot and the already-running short-circuit). The native path's
inline five-file loop is replaced by the same `--sync-objects` call, which
also closes a quiet gap: the inline list had silently missed 03_view,
07_queries, and 14_foresight_helpers, which the tool's canonical OBJECT_FILES
covers.

**Fixing it surfaced a second, nastier bug.** The first dev-stack `--up`
reported "no pending migrations" while three were pending. `docker compose
exec -T` attaches and DRAINS the caller's stdin, and `do_up` checks pending
names inside a `while read` loop: the first exec swallowed the rest of the
loop's input, so the scan ended after one name, silently, exit 0. This is
latent in the prod `--target=docker-stack` path too. Both docker-exec branches
of `run_psql` now take stdin from `/dev/null` (`run_psql_file` is exempt: its
stdin is the payload). With the redirect in place the same command found and
applied the three pending migrations. `do_sync_objects` also now executes each
file once and judges the captured result instead of re-running on failure (the
v9.153 double-execution pattern, harmless here only because the files are
idempotent).

Verified end to end on the machine that failed: the launcher reports the sync,
the container reaches all 8 on-disk migrations applied (9 registry events; one
records a migration whose file was removed in the v9.55 apparatus deletion)
plus the six-argument atlas functions, and all four endpoints return 200 with
live JSON through an authenticated session.

`check_launcher_refreshes_code` is rewritten from presence to coverage: the
object list must live in the migrate tool and include the atlas file, the
launcher must sync through that tool, and `launch_docker`'s body must call a
`sync_db_docker` that applies BOTH halves against the dev stack.
`check_migrate_docker_stdin_safe` pins the stdin drain. 78 checks, 75
check-layer tests.

---

## v9.158 — 2026-08-31 (The deployment roadmap: a recorded decision opening the path to national scale)

ROADMAP.md is rewritten as the complete build plan from the current reference
implementation to real national deployment. This is a recorded owner decision:
VANTA directed the plan on 2026-08-31, which is the named operator trigger the
v9.32 freeze line required to open a new arc. The constitution is not softened;
every phase carries C1-C10 and the vocation as hard gates.

The plan is eight phases with 69 work items, each carrying a size, a delivery
risk, explicit blockers, and a verifiable definition of done. P0 closes the
known debt ledger (floating nightly, un-run e2e suite, Dependabot backlog, the
four still-unswept operator tools, SBOM/signing/provenance, ZK production
profile). P1 makes a single authority able to run Polaris on Linux without the
author (systemd deployment, HSM/KMS custody, zero-downtime deploys, pen test).
P2 is state scale: partitioning, HA automation, multi-region DR, and a
10M-person load certification with published numbers. P3 is federation and the
relying-party ecosystem: the inter-authority protocol, a transparency service,
SDKs with a conformance suite, and offline verification. P4, parallel from P1,
is the physical layer: card profile, emulator, personalization, the enrollment
station, and the honest constraint that ML-DSA on secure elements arrives via
the schema's own UC-6 dual-signature migration. P5 through P7 are the
institutionally gated phases (pilots, certification, national rollout), each
listing the buildable readiness artifact so no external gate ever waits on us.

Three earlier scope decisions are handled explicitly rather than silently:
Linux deployment and narrow relying-party API authentication are reopened with
reasons recorded inline (the retirements were about demo scope; deployment
changes the question), and banking/payments is made a permanent non-goal
(C10 is not a phase). The old roadmap's operator-gated ledger, deferred items,
and PQC gate all map into P0-P2 rows; nothing was dropped.

The file ends with the execution protocol: how a fresh session picks the next
item, what marks mean, and the standing rules (constitution gates everything;
exercise, never just read; numbers carry stamps; every capability ships with a
detection-tested check). 77 checks, READY; all 296 cross-references resolve.

---

## v9.157 — 2026-08-31 (A nondeterministic CI assertion: the verify-ca probe lost a coin flip on a healthy stack)

The v9.156 push went red on `docker-image` while every other job stayed green,
and the failing step's own log showed the property under test holding:
`SSL established: TLSv1.3` on the pgbouncer-to-postgres hop, twice.

The probe queried `SELECT ssl FROM pg_stat_ssl ... WHERE usename='polaris_app'`
and compared the whitespace-stripped output against the literal `t`. That query
returns one row per backend, and PgBouncer legitimately holds a variable number
of pooled server connections at snapshot time. This run held two, both SSL; the
rows concatenated to `tt`; the scalar compare failed a healthy stack. Every
prior green run of this step had simply rolled a single connection.

The fix aggregates in SQL, so the shell sees exactly one boolean regardless of
pool size: `COALESCE(bool_and(ssl), false) AND count(*) >= 1`, true iff at
least one polaris_app backend exists and every one is SSL. Verified against all
three cardinalities (two SSL rows, a mixed pair, zero rows) before pushing.

`check_ci_ssl_probe_aggregated` pins the class: any workflow probe of
`pg_stat_ssl` must aggregate with `bool_and` before comparing. The front-page
counts stamped at v9.156 move to 77 checks, measured at v9.157. 77 checks,
74 check-layer tests.

---

## v9.156 — 2026-08-31 (Front-page redesign: the README and the site now lead with the macro)

Full rewrite of the two surfaces an outside observer sees first: `README.md`
(423 lines to ~300) and `site/index.html`. The v9.149 "cinematic" framing is
replaced by a professional macro-first story, and everything internal-facing is
gone from the front page.

**What the new front page says, in order:** what Polaris is (with the
educational, notional-data framing in the header, not buried at the bottom),
the ten guarantees as a table (the constitution was previously never shown as
C1-C10 on the README at all), the six adversarial hard parts, the architecture,
the cryptography, what CI actually proves, how to run it, where it sits against
Real ID / mDL / Aadhaar / a federated national eID / DIDs, a by-audience documentation index,
and an honest scope section.

**Removed as insider-facing or stale:** the double nav of internal links above
the fold, the tech-badge wall, the v9.55 cognitive-substrate confession, the
"trick" section, the 14-subcommand launcher reference (now one `--help`
pointer), the token-model column dump, the duplicate stats boxes, and every
drifted number: the README and site claimed 68 invariant checks (now 76), 562
and 572 product tests (571 measured), and "as of v9.148". Numbers now appear
once, stamped "measured at v9.156", except the schema-table count, which
`check_table_count_matches_doc` pins to the real schema.

**The site gained the constitution.** A ten-card guarantees grid now sits
between the Atlas showcase and the threat cards; the hero states the
educational scope in monospace under the definition; the stale production
section merged into "Verified, not asserted" with the five CI proof points.

Both files carry zero em-dashes (the pre-commit rule previously only guarded
new diffs; the rewrite made the whole files clean). All 291 cross-references
resolve; the guarantees table renders at a uniform four columns; the site
parses with zero unbalanced tags. 76 checks, READY.

---

## v9.155 — 2026-08-31 (CVE sweep: the Python surface, the Caddy image, and the CI pin that would have undone it)

Two independent CVE gates went red on the v9.154 push: `cve-scan` (pip-audit)
and `image-cve-scan` (Trivy). Everything else was green, including the product
test suite, the full prod-stack boot, real PQC, and the Caddy PQ KEX proof.

**The Caddy image (Trivy).** `polaris-caddy` shipped `golang.org/x/crypto`
below v0.55.0, carrying CVE-2026-56854 (CRITICAL) in
`golang.org/x/crypto/ssh`. Three things were checked before choosing a fix.
The existing `apk upgrade` cannot reach it, because the dependency is compiled
into the Go binary rather than installed as an apk package. Bumping the base
does not fix it either: the newest published builder tag
(`caddy:2.11-builder-alpine`) still resolves x/crypto to a vulnerable version,
so there is no upstream image to move to. And it is not unreachable, so
`.trivyignore` would have been dishonest: `strings` finds 227
`golang.org/x/crypto/ssh` references in the built binary, more than chacha20
(58), which Caddy demonstrably uses. The ssh package is genuinely linked in.
`--with` cannot express a floor for it (x/crypto has no importable root
package, so it fails with "cannot find module providing package"), so the build
now passes `--replace golang.org/x/crypto=golang.org/x/crypto@v0.55.0`, which
is what xcaddy documents for this exact case. Verified locally: the image
builds, the `rate_limit` plugin assertion still passes, the binary reports
`v0.54.0 => v0.55.0`, and the real Trivy gate exits 0 where it previously
reported `Total: 1 (CRITICAL: 1)`.

**The Python runtime surface (pip-audit).** `pip-audit --strict` found 8 known
vulnerabilities across 2 pinned runtime packages: `cryptography 48.0.0`
(PYSEC-2026-3552, PYSEC-2026-3553, PYSEC-2026-3554, GHSA-537c-gmf6-5ccf) and
`pyasn1 0.6.3` (PYSEC-2026-3455, PYSEC-2026-3456, PYSEC-2026-3457). All were
disclosed after the 2026-05-14 pin date; nothing in v9.153 or v9.154 caused
them. Clearing the whole set requires `cryptography>=50.0.0`, which
`pyOpenSSL 26.2.0` refuses, so the runtime surface moves together:
cryptography 50.0.1, pyOpenSSL 26.4.0, pyasn1 0.6.4. `pip-audit --strict` is
clean.

`cryptography` 48 to 50 crosses two major versions and it is the OpenSSL-backed
second witness for ML-DSA-65 (v9.133), so the bump was verified rather than
assumed: the `mldsa` module, `MLDSA65PublicKey`/`MLDSA65PrivateKey` and
`InvalidSignature` all survive, `second_witness_available()` reports True, and a
real keygen/sign/verify round-trip produces a correct 3309-byte ML-DSA-65
signature, verifies it, and rejects both a tampered payload and a forged
signature.

The bump alone would not have held. The `pqc-real` CI job carried its own
`pip install "cryptography==48.0.0"` — a second copy of a pin that
requirements.txt already owns. It had drifted silently, and after this bump it
would have reinstalled the exact vulnerable version `cve-scan` had just
rejected, then exercised the second witness at a version no deployment ships.
CI now derives the pin from requirements.txt, and `pqc_signing.py`'s comment no
longer repeats the literal either. This is the same defect as the archive
MANIFEST's hardcoded `polaris_version` in v9.153: a duplicated literal is a
second source of truth, and it drifts.

`check_ci_does_not_duplicate_pins` fails any `pip install pkg==X` in a workflow
that requirements.txt already pins. 76 checks, 73 check-layer tests.

---

## v9.154 — 2026-08-31 (The local test runner never worked: a silent reload turned one permission error into 200)

`scripts/ai-test.sh` could not pass. Running it reported 200 errors and 14
failures, and every one of them was the same defect, three layers deep.

`reload_sample_data()` runs `10_auth.sql`, whose first statement is
`TRUNCATE TABLE AuthAuditLog, AppUser`. TRUNCATE is a distinct Postgres
privilege and `09_grants.sql` deliberately withholds it from `polaris_app`: the
app role must never be able to truncate an audit table (C1). The runner
hardcoded `POLARIS_DB_USER=polaris_app`, so the truncate was refused, `AppUser`
was never cleared, the re-seed hit a duplicate key, and the admin row was never
restored. Every subsequent test then died in `setUp` on a 401 from
`_login('admin')`, an error that points nowhere near its cause.

None of that surfaced because `psql -f` exits 0 even when every statement in the
file failed. `reload_sample_data()` checked `returncode`, saw success, and
carried on: the same "judge the exit code, not the outcome" defect fixed in
v9.100 and again across the operator scripts in v9.153. A reload that silently
does nothing is worse than no reload, because it fakes test isolation. It now
runs psql under `ON_ERROR_STOP` and raises with the failing role named.

CI never caught this because `ci.yml` runs as `POLARIS_DB_USER: postgres`. The
runner now resolves the database owner (`pg_get_userbyid(datdba)`, falling back
to the invoking user) and matches CI. That is not a convenience: the append-only
tests assert the C1 TRIGGER's "append-only" message, and under a least-privilege
role the DELETE is refused by GRANT before the trigger ever runs. Relaxing those
assertions to accept "permission denied" would let a broken C1 trigger pass
silently, so the connection changes and the assertions stand. `test_app.py` also
gained `POLARIS_TEST_RELOAD_USER` / `POLARIS_TEST_RELOAD_PASSWORD` so a
least-privilege app connection can still be paired with an owner-level reload;
both default to `POLARIS_DB_*`, leaving the CI path unchanged.

Verified by breaking it on purpose: with `admin` deactivated beforehand,
`scripts/ai-test.sh` now heals the row and reports PASS on 419 tests.
`check_test_reload_fails_loudly` pins the ON_ERROR_STOP contract. 75 checks,
72 check-layer tests.

---

## v9.153 — 2026-08-31 (Operator-tooling sweep: exercising the un-swept scripts found seven runtime defects)

Resumed the ops-reliability sweep at the tier it left open: archive/purge,
recover-admin, and create-operator. The standing lesson held. Every defect below
was runtime-only and invisible to a static read, and the worst were found by
running the tools against scratch databases rather than by reading them.

**C1 carve-out: purge accepted a foreign archive.** `polaris-purge.sh` issues the
only legitimate DELETE against the audit tables, and its constitutional
justification is that the archive reconstitutes every purged row. Nothing bound
an archive to the database it came from. Demonstrated by archiving DB1, planting
a canary row in DB2 that was provably absent from that archive, and purging DB2
with it: the canary was destroyed and the checkpoint recorded
`rows_purged_total=11` against a 10-row manifest. The system held the evidence of
its own inconsistency and never looked. `polaris-archive.sh` now records
`source_database` and `source_system_identifier` in the MANIFEST, and
`polaris-purge.sh` refuses on a database or cluster mismatch, refuses archives
that predate the binding, and pre-counts exactly what `uc_archive_purge` would
delete, requiring it to equal the archive's row counts before deleting anything.

**create-operator reported failure on success, intermittently.** The insert was
piped into `grep -q`, which exits at its first match and SIGPIPEs psql
mid-transaction, so the COMMIT never ran and pipefail reported failure for a
rolled-back transaction. Exit was 141, not one of the script's documented codes.
The error arm then re-ran the same SQL to "capture the error", and that second
run is what actually created the account. It now executes once under
`ON_ERROR_STOP` and judges the outcome, which is the v9.100 restore lesson.

**create-operator could never create an admin.** Exposed immediately by the fix
above. `WEBAUTHN_DEADLINE_SQL` is a SQL expression containing quotes
(`now() + interval '30 days'`) and was interpolated into the quoted audit-detail
literal, terminating it early. The AppUser insert succeeded, the audit insert
raised a syntax error, and the transaction rolled back, so `--role admin` had
never worked. The audit text now carries a quote-free description.

**recover-admin allowed self-pairing.** The authorizer was validated only as an
active admin and never compared to the target, so one admin could authorize
their own MFA-bypass window while the banner asserted "second-admin pairing".
Now refused. Solo-admin deployments are unaffected: `--recovery-code` is
self-pairing by design and remains the documented path.

**recover-admin's fail-safe-never-open refusal was unreachable.** `_out=$(psql
...)` followed by `_rc=$?` does not work under `set -e`: the shell exits at the
assignment and the status is never read. The v9.27 T8#10 posture therefore never
fired, and a failed emergency-window write exited with no output at all. Status
is now captured with `|| _rc=$?`, and the write call no longer redirects the
wrapper's diagnostics to /dev/null.

**create-operator died silently on an unreachable database.** psql returns 2 on
a connection failure, `set -e` killed the script at the idempotency check, and
`2>/dev/null` swallowed the reason, so the operator got a bare exit 2 that
collides with the documented usage code. A connectivity preflight now reports
the host, user, and database and exits with the database code.

**Archive provenance was false in two ways.** The MANIFEST hardcoded
`polaris_version: "8.84"` while the product shipped 9.152, and
`TokenStateEpochLeaf` exported unfiltered while the banner said "older than
cutoff" and the manifest recorded a cutoff. The version is now derived from the
canonical `__version__.py`, and leaves inherit their parent epoch's `valid_from`
so the manifest describes what the archive actually holds.

Five checks pin the classes, each with a detection test: `purge_archive_binding`,
`archive_version`, `no_grep_q_psql`, `psql_status_set_e`, and
`recover_admin_self_pair`. 74 checks, 71 check-layer tests.

---

## v9.152 — 2026-06-12 (Fix "ATLAS FEED INTERRUPTED": the launcher now refreshes code objects on every launch)

Root-caused a real operator report. The atlas error chip fires when
`/api/atlas/clusters` returns a 500, and reproducing it showed the cause: in
v9.146 the atlas SQL function signatures changed (the agency-filter param),
but the launcher only loads the schema on a *fresh* database (to preserve
data) and otherwise applies migrations — and no migration updated the atlas
functions. So an existing database kept the old function signatures while the
new app called them with the extra argument: a 500, every time. Simulated a
stale 9-arg function against the current app and got the exact failure.

- **The fix: the launcher re-applies idempotent code objects every launch.**
  After migrations, `polaris_mac_launch.sh` now re-runs 05_procedures.sql,
  06_triggers.sql, 09_grants.sql, 11_atlas.sql, and 15_ontology.sql — all
  CREATE OR REPLACE / DROP+CREATE / GRANT, so they touch no data but bring the
  database's functions, triggers, views, and grants current. Migrations cover
  schema/data deltas; this covers code drift. (All five verified to re-run
  clean on a loaded DB.)
- **The error chip is now self-diagnosing.** A 500 from the atlas feed shows a
  detail line naming the likely cause and the fix ("the atlas database
  functions may be out of date — reload the schema") instead of a bare
  "ATLAS FEED INTERRUPTED".
- **Pinned against regression.** `check_launcher_refreshes_code` (69th check)
  fails if the launcher stops re-applying 11_atlas.sql, with a detection test.

Immediate fix for an already-broken instance: `./polaris_mac_launch.sh up`
(now refreshes the functions), or `reset` to fully reload. 572 web + 64 CLI
green, 69 checks.

## v9.151 — 2026-06-12 (Subject-focus bug fix + activation events on the map + token data export + richer node detail)

Four things from a real bug report, all browser-verified.

- **Bug fixed: a subject with only an activation event read as empty.** Egor
  Khaklin has zero verifications and one ISSUED (activation) lifecycle event;
  the focus view built its zoom and its empty-hint only from VERIFICATION
  coordinates, so his activation event plotted but the map never framed it,
  the banner said "1 event" while a "nothing here / zero-knowledge" chip
  fired on top of it, and the two overlapped. Now: verification AND lifecycle
  events are combined in time order, the map frames all of them, a single
  event auto-opens its node console, and in focus mode the banner is the sole
  status line (the empty chip never shows), so nothing overlaps. Banner count
  and wording corrected ("N located events").
- **Activation (and all lifecycle) events appear on the map.** The same fix
  makes a token's issuance/activation/revocation events plot at their exact
  location and the map zoom to them — verified on Egor's ISSUED event at
  Pittsburgh (40.4406°N, 79.9959°W).
- **Download all viewable token data.** A new `/api/tokens/<id>/export`
  endpoint (and ⤓ buttons on the token-detail page and the map node console)
  downloads everything the operator can already see for a token as a JSON
  file: token record, lifecycle, verifications, devices, anchors, revocations,
  permissions, signatures. Login-gated like the detail page, audit-logged, and
  carries no secret material (duress hash → boolean; signature/key bytes
  dropped). C2 holds for free: a token's verification set never contains a
  ZERO_KNOWLEDGE row. New TokenExportTests pin all of this.
- **Richer node console.** Selecting a reticle now shows event type, event id,
  token, agency, algorithm (PQ/classical), outcome, disclosure, reason, the
  free-text location AND the exact coordinates, and the timestamp — every
  field available, none that breaks a rule (ZK events are still never plotted).

572 web + 64 CLI green (4 new export tests), 68 checks.

## v9.150 — 2026-06-12 (Scale proof: the Atlas measured at 10 million events)

"It should handle millions" is now measured, not asserted. Generated a real
10,000,009-event PostgreSQL table (2.75 GB) and timed the atlas aggregation
functions the live map calls per viewport. Reproducible:
`scripts/polaris-atlas-benchmark.sh 10000000`.

At 10M events on a developer laptop:
- **Street-block points (operator zoomed in): 2.6 ms warm.** Tight bbox
  through the (latitude, longitude) index; bounded by the viewport, not the
  table, so it holds at 10M and at 100M. This is the operator's real
  workflow — investigation, not staring at an un-aggregated planet.
- **Whole-world overview (raw): 2.9 s.** EXPLAIN confirms it sorts/groups every
  non-ZK row — no index avoids reading rows you aggregate.
- **Whole-world from a materialized grid rollup: 0.04 ms (~70,000× faster).**
  The ~2.6 s build runs on a refresh schedule, off the request path; the live
  API also caches cluster results, so the cold overview computes once per
  viewport then serves from cache.

The honest conclusion: the path operators actually use is millisecond and
scales by construction; the whole-world overview is solved by a rollup (and,
where available, the GiST geography index from 13_postgis.sql), with the new
benchmark as the acceptance harness. Recorded in docs/reference/SCALING.md;
no schema or app change.

## v9.149 — 2026-06-12 (Cinematic README + GitHub page: the Atlas, on the front page)

The Atlas is the most striking thing Polaris does, so it now leads. Real
hero captures (committed under assets/): the dark globe with live clusters,
the 3D street view with buildings, and the subject-focus gold path.

- **README** opens with the globe hero, then a new "The Atlas" section pairing
  the street and subject shots with the three things that make it more than
  eye candy: it scales by construction (C8 viewport aggregation), the privacy
  default is visible in the cartography (ZK events never appear, C2/C6), and
  investigation is governed not casual (subject focus is UC-7, the schema
  carries no attribute to profile by).
- **GitHub Pages site** (site/) gains the same Atlas showcase (globe hero +
  street/subject two-up), and the social-preview image (og:image) is now the
  globe, so shared links render the console instead of the logo.
- **Counts refreshed** everywhere to the current build: 72 routes (the two
  subject endpoints), 68 checks, 572 product tests. A duplicated opening
  paragraph in the README was removed.

No code change; checks + link integrity green.

## v9.148 — 2026-06-12 (Subject-focus: single-subject investigation on the map, and the privacy guarantee it demonstrates)

"Signal in the noise" for an operator with cause: search a specific subject
and the map drops everything else, plotting only that person's disclosed
events as a gold path of "what they did". This is the warrant-audit use case
(UC-7), NOT population profiling — and it is built to demonstrate the
constitution rather than breach it. Browser-verified focusing James Chen (4
disclosed events on a connected path, operational clusters hidden); 5 new
governance tests green, 68 checks.

The line, enforced in code:
- **By identity, never by attribute.** You reach a subject by their specific
  individual_id (found via a name typeahead), never by filtering the
  population. The schema carries no gender/ethnicity/religion/politics to
  filter on, and none was added.
- **Governed.** `/api/atlas/subject` and `/api/atlas/subjects/search` are
  admin/auditor only (operators are denied — an operator must not be able to
  pull a holder's movement map). Verified: operator → 403.
- **Audit-logged.** Every focus writes an AuditAccessLog row naming the
  individual investigated (record_audit_access) — warrant-grade access leaves
  a trace.
- **C6 holds, and is shown.** A ZERO_KNOWLEDGE verification carries
  token_id = NULL (C2), so it cannot be joined to any individual at all: the
  subject's zero-knowledge activity is not merely location-withheld, it is
  *unattributable*. The map shows only what the holder chose to disclose; the
  banner states it plainly. A test asserts no subject ever returns a ZK row.

Implementation: two read-only endpoints over existing tables (no schema
change), a gold trajectory line + sequence-numbered reticles layer in
atlas-map.js, an admin/auditor-gated subject search box, and an INVESTIGATING
banner. The operational viewport fetch stands down while a subject is focused;
Reset or Clear exits. AtlasSubjectFocusTests pins the four guarantees above.

## v9.147 — 2026-06-12 (Atlas fixes: open over the data, no false "feed interrupted", no HUD overlap)

Three issues in the v9.146 MapLibre atlas, all fixed and browser-verified.

- **Verifications now show on load.** The default view was centered on the
  empty mid-Atlantic, so the US-only notional events sat at the globe's limb
  and looked absent. The view now opens over North America (center ≈ US, zoom
  3.2), where the verification clusters are immediately visible. Reset returns
  to the same HOME view.
- **No spurious "ATLAS FEED INTERRUPTED".** The MapLibre `error` handler was
  raising the data-feed error chip on any basemap hiccup (a single tile 404, a
  font-range miss), so a momentary CARTO hiccup read as a data failure. Basemap
  errors are now logged only; the chip is reserved for actual /api/atlas fetch
  failures.
- **Bottom-right no longer overlaps.** The MapLibre NavigationControl was
  dropped at bottom-right, on top of the PQ/ZK HUD readout. Removed it (the
  command bar already has zoom +/- / Reset / Spin / Fullscreen), and moved the
  required OSM/CARTO attribution to the free top-right corner.

## v9.146 — 2026-06-12 (Atlas becomes a real street-level map: MapLibre globe→street, OpenStreetMap basemap, operational agency filter)

Learning from the ADL Global A.T.L.A.S. (which is Mapbox GL + OpenStreetMap),
the Polaris Atlas is rebuilt on a real tile-map engine: a MapLibre GL globe
that flattens into a street-level map with buildings as you zoom. Verified in
the browser: globe sphere at world view, 116 building features at zoom 16 over
Houston with the event reticle on its exact coordinate, agency filter cutting
5 events to 2, ZERO ZK rows ever returned to the spatial layer, bad agency id
→ 400. 503 web + 64 CLI green, 68 checks.

- **MapLibre GL, self-hosted, no Mapbox token.** maplibre-gl v5.24 is vendored
  in static/vendor (like d3/topojson). The basemap is CARTO's free dark-matter
  vector tiles (OpenStreetMap data, no API key), which match the console
  palette. The new atlas-map.js replaces the bespoke D3 globe's rendering;
  the per-viewport fetch architecture is unchanged, so it scales the same way
  (the browser only ever holds the aggregates for the visible viewport, C8).
- **Globe → street.** A 3D globe projection at world view that zooms down to
  streets and 3D building footprints; pan/zoom/pitch/rotate are MapLibre-
  native; the +/- chips, Reset, Spin, Fullscreen (F), and the live CUR lat/lon
  readout all wire to the map. This is the "zoom to street view, see buildings"
  ask, done properly.
- **CSP scoped to the one page.** apply_security_headers relaxes img/connect to
  the two CARTO tile origins and allows a blob: worker ONLY when the atlas view
  sets g.atlas_tiles; every other response keeps the strict self-only CSP, and
  script-src stays 'self' (the engine is self-hosted). C5 still passes.
- **Privacy held constant.** ZERO_KNOWLEDGE verifications are never plotted on
  any spatial layer (C6, enforced server-side in 11_atlas.sql); the prettier
  basemap is cartography, not new exposure. Confirmed: the points endpoint
  returns zero ZK and zero null-token rows.
- **Operational AGENCY filter** (the v9.146 SQL groundwork): all six atlas
  functions (clusters/points/stats/timeline, verification + lifecycle) gained
  a p_agencies CSV param; _parse_atlas_filters validates agency ids as integers
  and threads them through every call site and the cluster cache key; a new
  Agency chip picker drives it. This is an operational pivot (which issuer/
  actor), never an attribute of a person — the demographic/name surveillance
  filtering remains declined on constitutional grounds.
- NOTICE updated for MapLibre (BSD-3-Clause) + CARTO/OpenStreetMap (ODbL)
  attribution; the on-map attribution control credits both.

## v9.145 — 2026-06-12 (Atlas futurization: fullscreen, ultra zoom to 40x, pinpoint coordinates)

The console becomes a real targeting surface. Lighthouse atlas 96 perf /
100 a11y / 100 best-practices / 100 SEO (the 4-point perf dip is d3 bootup
under simulated throttle; TBT is 10ms). 503 web + 64 CLI green;
browser-verified drilling a cluster to 40x and reading exact coordinates.

- **Fullscreen.** A ⛶ command-bar chip and the `F` key take the whole
  console fullscreen via the Fullscreen API; the ResizeObserver re-measures
  the globe when the box jumps. The chip reflects state (⛶ Full / ✕ Exit).
- **Ultra zoom to 40x** with frame-eased motion. setZoom() now sets a
  TARGET that the animate loop approaches exponentially each frame, so
  wheel, +/- chips, keyboard, and cluster drill-down all glide instead of
  stepping. Wheel and buttons step multiplicatively (uniform feel across
  the whole 0.7x-40x range); clusters double the zoom on click. The fetch
  fires once when the zoom settles, not every frame.
- **Pinpoint locations.** chooseGrid() extends to 0.01-degree (~1 km) cells
  at depth so the cluster pipeline hands over to exact-position point
  reticles; a live CUR lat/lon readout in the status bar streams the
  coordinate under the cursor (inverts the projection; 4-decimal precision
  past 8x). This is how an operator reads the exact location of an event.
- **Smoothness + scale hygiene.** projection.clipExtent() clips paint to
  the viewport (at 40x the projected world is hundreds of thousands of
  pixels wide; without it d3 paths every offscreen arc); the globe SVG
  clips at its box (overflow hidden) so deep zoom never stalls the
  compositor; the ultra-zoom bbox clamps at the antimeridian instead of
  bailing to a heavy whole-world fetch.
- **Future-tech ambience.** A slow conic radar sweep behind the globe
  (transform-only, GPU-cheap, killed by reduced-motion) and a crosshair
  cursor mark the stage as a targeting surface.

## v9.144 — 2026-06-11 (Atlas console rework: full-viewport command surface)

The Atlas was a 700px-capped globe widget floating inside the 1480px content
column; on a large display most of the screen was empty page background. It
is now a true full-viewport console. Lighthouse (desktop): a perfect
100 perf / 100 a11y / 100 best-practices / 100 SEO with CLS 0 (up from 98
perf); 503 web + 64 CLI green; verified in the browser at 2560, 1440, and
390 widths.

- **Layout: command bar / stage + dock / status bar.** `body-atlas` unlocks
  full bleed (no content max-width, footer hidden, page does not scroll;
  the masthead widens to align with the console edges). All controls
  consolidate into ONE command-bar row (view, window, modifiers, context,
  zoom, spin/reset, LIVE) instead of two stacked toolbar rows.
- **The globe is sized by its stage box, no pixel cap.** The stage is
  flex:1 of the viewport; `baseRadius = min(w,h)/2` so a 5K display gets a
  display-sized globe, not a 700px disc. A ResizeObserver re-measures and
  refetches when the stage box changes (dock stacking, flash messages),
  not just on window resize.
- **The node console no longer covers the globe.** It docks beside the
  event feed in a tabbed right dock (Event Feed / Node Console); selecting
  a reticle auto-switches the dock to the console. The feed gets real
  width (clamp 320px..460px) instead of a cramped 320px rail.
- **Heading/pitch/zoom readouts and the activity histogram move to a
  bottom status bar** alongside the classification banner and the Z-clock;
  the stage keeps only the two HUD clusters that matter at a glance
  (tokens/anomalies, PQ/ZK). Inline style attributes on the HUD are gone
  (hud-stack-gap / hud-label-tight classes).
- **Dead v8-era layout CSS removed** (god-view shell, god-rail,
  notification-rail, globe-command, the old fullbleed negative margins and
  their media queries); responsive now stacks stage-over-dock below 1100px
  and restores page scroll there.
- All pinned markup survives (atlas-id-strip OPERATIONAL, atlas-fullbleed,
  atlas-globe-data, HUD signal texts, Event Feed, OPERATIONAL ATLAS), every
  data-atlas-* hook is unchanged, and the role-crawler suite stays green.

## v9.143 — 2026-06-11 (the Atlas becomes fully operational + a role-gate/alignment sweep, proven by crawler tests and Lighthouse)

A production-grade pass over the whole UI with the proof to back the words.
Lighthouse (desktop): landing 100/100/100/100, dashboard 100/100/100/100,
atlas 98 perf / 100 a11y / 100 best-practices / 100 SEO. Suites: 503 web +
64 CLI green, 68 checks, 65 detection tests.

- **The Atlas now ships data on first load.** The default time window was
  24H, but the notional events are months old, so the globe rendered EMPTY
  on every first visit; the default is now ALL (live deployments narrow it).
  An empty viewport explains itself with a hint chip instead of silently
  showing nothing, and a fetch failure raises an ATLAS FEED INTERRUPTED chip
  with a Retry control (a console.warn is invisible to an operator).
- **The globe is operable, not just watchable.** Clusters actually zoom in on
  click (their tooltip promised it; the handler never did it); +/− zoom chips
  join Spin/Reset; the globe is keyboard-operable (tabindex + arrows rotate,
  Shift accelerates, +/− zoom, space toggles spin); a tone legend names the
  color code (zero-knowledge / selective / full / alert) instead of making
  operators guess; LIVE means live: reticles, HUD stats, and the histogram
  refresh every 60s while the tab is visible and immediately on tab return.
  One setZoom() now serves wheel, chips, keyboard, and cluster drill-down.
- **Role-gate sweep (the "buttons lead to error pages" class).** A
  three-role crawl found controls rendered for roles that 403 on click:
  operator/auditor-visible New-Agency/New-Individual/Edit/Delete buttons,
  auditor-visible Record-Verification and Issue-Token buttons, the
  state-transition form and Delete Token on token detail, and an edit link
  on the investigate page. Every control now sits behind the same role gate
  its route enforces.
- **Orphaned pages wired in.** /investigate/token/N and
  /investigate/individual/N were reachable only from each other; Investigate
  buttons now exist on the tokens list, token detail, and individuals list.
- **Overscroll seam fixed.** Rubber-banding past the top showed a visible
  border: the browser canvas (html background) restarted the body gradient.
  The canvas is now a solid tone matched to the masthead, and
  overscroll-behavior stops the bounce where supported.
- **Alignment fixes.** td.actions used display:flex, which detaches a table
  cell from the row border/baseline grid and visibly misaligned every
  actions column; buttons/pills now align inline (vertical-align: middle).
- **Proof, permanent:** (1) UiLinkIntegrityTests crawls every <a href>
  reachable as EACH role and fails if anything a user can see renders an
  error page — it caught a leak (investigate-page edit link) on its first
  run; plus pinned tests for the investigate navigation and each role-gated
  control. (2) check_template_endpoints_resolve (68th check) statically
  verifies every url_for() in templates names a real @app.route function,
  with detection tests. (3) A meta description fixed the one failing
  Lighthouse SEO audit.

## v9.142 — 2026-06-10 (full UI redesign, README rewrite, GitHub Pages site, and an 11-bug fix sweep)

The whole presentation layer, rebuilt, plus every confirmed finding from a
26-agent discovery sweep fixed. Verified by the full suites (498 web + 64 CLI,
green), all 67 checks, and a 12-surface visual pass in a real browser.

- **One unified stylesheet.** The two-layer CSS stack (light `polaris.css` +
  the v8.14 `polaris-scifi.css` skin, ~6.5k lines of override-the-override)
  is replaced by ONE dark mission-console design system (`polaris.css`,
  ~3.3k lines): deep-navy surfaces, gold command accents, cyan live data,
  per the DEVNOTES/style.md visual contract. The battle-tested Atlas globe
  internals carried over re-tokenized; everything else (masthead, nav,
  buttons, forms, tables, pills, cards, login, landing, demo, errors) is
  fresh. Coverage proven mechanically: every class referenced by templates/JS
  resolves in the new sheet. A11y: `:focus-visible` rings everywhere,
  `aria-checked`/`aria-pressed` on the atlas chips, reduced-motion kills all
  animation, print styles for warrant audits, responsive breakpoints (the
  old UI had none). The dashboard boot overlay + staggered reveal are now
  scoped to the dashboard (`body-dashboard`); pre-v9.142 they leaked onto
  every page. New SVG favicon. Every test-pinned selector and string survived:
  the full app suite passed unchanged.
- **Recovery queue state is finally readable**: `.channel-tick` (B/S/W
  out-of-band channels), `.pill-warn/-pending/-approved/-rejected`, and the
  `.info-panel`/`.kv`/`.muted`/`.footnote` structural classes had NO rule in
  either old stylesheet; an admin could not read the three-channel state. All
  styled now.
- **Bug sweep (19 confirmed findings + 1 loader bug, all fixed):** static UC
  prerequisite notices no longer vanish after 4.5s (flash dismisser scoped to
  `.flash-region`); the WebAuthn credential Remove button's `data-confirm`
  actually fires (moved to the form, matching every other destructive form);
  `/atlas` dropped ~190 lines of dead per-request work (3 queries + node
  assembly for a JSON island the v6 architecture never reads — and the C6
  check now reflects that the strongest redaction is not reading location at
  all); non-numeric `?page=`/`?page_size=`/`?individual_id=` on the HTML list
  routes return a styled 400 instead of a 500 (new `_int_arg` + 400 handler);
  the atlas fetch dedupe key resets on failure so a transient error no longer
  freezes the globe for a viewport; the event-feed counter populates; three
  dead JS hooks deleted; `#batch-N` deep links from token detail now land on
  an anchored row; demo step nav dropped bogus tab roles;
  `investigate_token` stopped fetching a 4-subquery ontology row it never
  rendered; and `01_schema.sql` gained the missing
  `DROP TABLE IF EXISTS IndividualErasureEvent`, which broke `00_load_all.sql`
  re-loads on any DB that had applied the erasure migration.
- **README rewritten** against ground truth: 28 tables / 11 procedures /
  70 routes / 67 checks / 562 tests (the old one said 26/14/67/17 in various
  places, claimed "current as of v9.63", and never mentioned the entire
  production arc: prod stack, PQ TLS edge, two-witness signing, CVE gates,
  pgBackRest DR). New "Production posture" section; quickstart now covers the
  prod deploy path. `check_table_count_matches_doc` hardened to validate EVERY
  stated table count (re.findall), with a detection test for the
  first-right-later-drifted case that v9.141 actually shipped.
- **GitHub Pages site** (`site/` + `.github/workflows/pages.yml`):
  a single-page project site in the same design language at
  https://egorkhaklin.github.io/polaris-id/. Pages enabled
  (build_type=workflow), repo homepage set, stale `swarm-intelligence` topic
  removed (dead since the v9.55 apparatus cut).
- **Doc rot fixed** (all adversarially verified first): dead
  `DR-SINGLE-REGION.md` references → `DR.md` (7 files); QUICKSTART/generator
  header no longer describe the pre-v9.140 "3 files, 0600" secrets posture
  that would re-break a Linux prod boot if "restored"; SYSTEM-MAP refreshed
  from its v9.08 freeze (deploy/, prod Dockerfiles, all 7 CI jobs, false
  test claim removed); NOTICE corrected (CM cut in v9.55, nine AoR triggers
  not eight, no more empty-sanctum citation); ROADMAP's PQC pointer updated
  (client-to-edge hybrid KEX shipped v9.136); landing page's "~350 legible
  lines" check-layer claim was 6x stale, reworded without rot-prone counts.

## v9.141 — 2026-06-09 (container hardening: every prod service drops all Linux capabilities)

With the prod-stack-boot job now able to prove the stack still serves, the prod
containers can be hardened safely. Every service in `docker-compose.prod.yml` now
drops ALL Linux capabilities and forbids privilege escalation
(`security_opt: no-new-privileges:true`), adding back only the few capabilities
each entrypoint genuinely needs.

- **The app + pgbouncer run with ZERO capabilities** (verified at runtime:
  `CapEff: 0000000000000000`). They are non-root and bind ports above 1024, so
  they need nothing.
- **The public Caddy edge** keeps only `NET_BIND_SERVICE` (to bind :80/:443) and
  drops everything else, so even though it is uid 0 it can do nothing but bind
  ports.
- **postgres and redis** keep only the five capabilities their root-then-drop
  init needs (`CHOWN`, `DAC_OVERRIDE`, `FOWNER` for the data dir, `SETGID`,
  `SETUID` for the gosu/setpriv drop to the unprivileged service user). Getting
  this wrong is silent: an early draft with `cap_drop: ALL` and no add crashed
  redis with `setpriv: setresuid failed: Operation not permitted` — caught by
  booting the hardened stack, not by reading the compose.
- **Proven, not asserted.** The `prod-stack-boot` CI job boots the HARDENED stack
  and asserts it still serves `/api/health` end to end. `check_container_hardening`
  (67th check) requires every service to drop ALL caps + forbid escalation, and
  requires the boot job to exist so a capability mistake fails CI, not production.
  (Full non-root `USER` for the Caddy edge, which needs careful volume-ownership
  handling the citest boot would not fully exercise, is a noted follow-up.)

## v9.140 — 2026-06-06 (the full production stack now boots end to end, and a prod-down init bug it found)

Booting the FULL production compose for the first time (only the dev compose and
per-image tests ran in CI before) found that the prod stack had never actually
come up. `polaris_sql/09_grants.sql` hardcoded `GRANT CONNECT ON DATABASE
polaris_test` — the dev/CI database name. Production uses `polaris`, so init hit
`ERROR: database "polaris_test" does not exist`, and under `ON_ERROR_STOP=1` +
`set -e` the whole `docker-init.sh` aborted BEFORE it enabled TLS. Result:
postgres came up with `ssl=off`, pgbouncer's verify-ca backend connection was
refused, the app could not reach the DB, gunicorn workers hung and crash-looped,
and nothing served. Every existing test uses the `polaris_test` name, so this was
invisible until the prod stack was booted as a whole.

- **The fix.** `09_grants.sql` now grants CONNECT on `current_database()` via
  dynamic SQL, the same pattern the file already uses for its ALTER DATABASE GUC
  settings. It loads correctly into `polaris` (prod), `polaris_test` (dev/CI), or
  any DB name. Verified: the prod stack boots, postgres comes up `ssl=on`, and
  `/api/health` serves 200 through the Caddy TLS edge with database (41 tables,
  ~18ms through the verify-ca hop), redis, and zk_binary all healthy.
- **The keystone test.** A new `prod-stack-boot` CI job generates real secrets +
  certs, builds the prod images, boots `docker-compose.prod.yml` +
  `docker-compose.citest.yml` (the only change from prod is Caddy's internal CA
  instead of ACME, since CI has no public domain), and asserts the stack serves
  `/api/health` end to end with the DB-backed components healthy and postgres
  `ssl=on`. This is the gap that let v9.135 and v9.140 ship; it is now closed.
- **A second prod-down bug it found: unreadable secrets.** With postgres fixed,
  the Linux CI boot surfaced another deploy-blocker the macOS boot had hidden:
  `polaris-generate-secrets.sh` wrote the file-mounted secrets 0600, but docker
  compose mounts file secrets with the source file's perms (it ignores the secret
  `mode`/`uid`), so on Linux the non-root app/pgbouncer containers (uid 1000)
  could not read a 0600 host-owned secret — pgbouncer exited "password file
  unreadable" and crash-looped, and with that fixed postgres's docker-init (which
  runs as the non-root postgres user) could not `cp` the 0600 server key
  ("Permission denied") and silently skipped replication readiness. EVERY secret a
  non-root container process reads is now 0644 inside the 0700 dir (the dir is the
  host boundary, the same model v9.131 used for the pgbouncer key):
  `polaris_secret_key`, `polaris_db_password`, `polaris_signing_key`,
  `polaris_replicator_password`, and `postgres_server.key`. Only
  `polaris_db_root_password` stays 0600 (the postgres entrypoint reads it as root).
  `SECRETS.md` is corrected so an operator does not `chmod 0600 secrets/*` and
  re-break it. macOS Docker Desktop uid-maps bind mounts, which hid all of this;
  the Linux CI boot found each layer.
- **Pinned.** `check_prod_stack_boot` (66th check) requires the boot harness
  (`Caddyfile.citest`, `docker-compose.citest.yml`) and a CI job that generates
  secrets, boots the full prod compose, and probes `/api/health`. Because the job
  boots on a Linux runner with non-root containers, it catches exactly this class.

## v9.139 — 2026-06-06 (fix a real deploy-blocker: the liboqs banner corrupted the generated signing key)

Exercising the full production-stack bring-up found a genuine production bug.
`polaris-generate-secrets.sh` mints the ML-DSA-65 signing key by capturing the
stdout of a `python -c "...print(json.dumps(generate_keypair()))"` (run via the
prod image when liboqs is not local, the common operator path). But liboqs-python
prints `liboqs-python faulthandler is disabled` to STDOUT at import, so the
capture prepended that banner to the JSON and wrote a malformed key file. With
`POLARIS_USE_REAL_PQC=1` (the production default since v9.116), the app then
refuses to load it (`RuntimeError: ...malformed`), so real-PQC token issuance
would have been broken on first deploy and only discovered there.

- **Clean capture.** The generator now swallows stdout during the pqc import
  (`sys.stdout = io.StringIO()`), so no import-time banner can leak into the key
  JSON. Verified end to end: the regenerated key parses, and the app signs with it
  (public key matches the trust anchor).
- **Fail loud, never write a malformed key.** The captured output is now validated
  to parse as ML-DSA-65 key JSON (both key halves present) before it is written;
  contamination fails generation rather than shipping a broken key.
- **Empty files regenerate.** The secret existence guards were `-e` (exists), so a
  0-byte file from an interrupted prior run silently blocked regeneration and could
  ship an empty secret. They are now `-s` (non-empty).
- **Pinned three ways.** `check_signing_key_generation` (65th check) asserts the
  stdout swallow, the JSON validation, and the `-s` guards; a detection test
  covers it; and the `pqc-real` CI job now runs the generator's snippet under real
  liboqs and asserts it emits clean ML-DSA-65 JSON.

## v9.138 — 2026-06-06 (scan the container images for CVEs, and patch the fixable ones)

A repo-grounded production-readiness gap analysis found a real, standard control
entirely absent: container IMAGE CVE scanning. pip-audit covers Python deps and
bandit covers our code, but the OS packages baked into every base image were
never scanned. They shipped real, fixable, CRITICAL CVEs. Measured with Trivy:
the app's Debian Bookworm base carried 2 fixable CRITICAL + 3 HIGH, and
postgres:16-alpine carried 1 CRITICAL + 16 HIGH. This adds the scan AND patches
what is fixable, so the control is not just reporting.

- **Patch the bases.** The four self-built Dockerfiles now upgrade their base
  packages: `apt-get -y upgrade` (Dockerfile.prod) and `apk upgrade --no-cache`
  (Dockerfile.caddy / pgbouncer / postgres). Measured result: the app image drops
  to 0 fixable CRITICAL and 0 HIGH; caddy, pgbouncer, postgres to 0 fixable
  CRITICAL.
- **Gate on fixable CRITICAL.** A new `image-cve-scan` CI job builds every prod
  image and runs Trivy, gating on fixable CRITICAL (`--severity CRITICAL
  --ignore-unfixed --exit-code 1`) and reporting HIGH informationally (base-image
  HIGHs churn daily and are mostly unfixable, so gating on them would flake).
- **One documented exception.** `.trivyignore` carries CVE-2025-68121 (a Go
  crypto/tls CVE in the postgres base image's `gosu` binary) with justification:
  gosu is the entrypoint's privilege-drop helper and opens no TLS, so the
  vulnerable session-resumption path is unreachable; it rides in across
  postgres:16/17-alpine and is not addressable by apk upgrade. Re-evaluate when
  the base ships a rebuilt gosu.
- **Pinned.** `check_image_cve_scanning` (64th check): CI must Trivy-scan the
  images gating on fixable CRITICAL with `--ignore-unfixed`, the self-built
  Dockerfiles must patch their bases, and exceptions must be documented in
  `.trivyignore`. Image CVEs cannot ship silently again.

## v9.137 — 2026-06-06 (precision: the internal-hop PQ gate is measured, and it is two limiters not one)

A small honesty correction to the v9.134/v9.136 audit, grounded in measurement.
The audit credited pgbouncer as "the" limiter holding the two internal TLS hops
classical. Measuring the actual OpenSSL versions of every component shows that is
incomplete: ML-KEM needs OpenSSL 3.5 on both ends of a hop, and the app's libpq
is OpenSSL 3.0.20 (Debian Bookworm base), pgbouncer is 3.3.7 (Alpine 3.20), and
postgres is already 3.5.6 (Alpine 3.23). So the app-to-pgbouncer hop is held
classical by BOTH ends, with the app's Bookworm libpq the older limiter, not just
the pooler. The doc, gap table, and roadmap P2 now state this precisely: closing
the internal hops needs TWO image base bumps (the app and pgbouncer), and the app
bump (Bookworm to Trixie or a 3.13 image) is a deliberate refresh with its own
regression surface, low priority given the notional, internal-only exposure.

This also records the honest conclusion of probing the next buildable transport
item: the internal-hop PQ KEX (audit P2) is gated on base-image upgrades and is
low value (notional data inside the trust boundary), not a quick win. No code
change; the security claim is simply made more accurate.

## v9.136 — 2026-06-06 (proven: the client-to-edge TLS hop does post-quantum hybrid key exchange)

The v9.134 audit called the client-to-edge TLS hop classical. Continuing down the
honest path, I tested it instead of assuming, and it was wrong in our favor: the
self-built Caddy edge (v9.135, Go 1.24+ TLS stack) negotiates the hybrid
post-quantum group X25519MLKEM768. This closes the audit's P1 gap (the
highest-priority transport item) with proof, not inference.

- **Proven off a real handshake.** Booting the edge with `tls internal` and
  connecting with an OpenSSL 3.5 client, the negotiated group is
  `X25519MLKEM768`, both when the client forces it AND with the client's default
  groups (so the server offers and selects the hybrid by default). A classical
  X25519-only client still completes the handshake, so it negotiates classical
  X25519. The KEX group is cert-independent, so the production Let's Encrypt path
  negotiates the same group as the test. A new `caddy-edge` CI step asserts all of
  this on every push.
- **Honest scope (adversarially reviewed).** A review panel checked the claim for
  overclaim and caught real qualification gaps, all fixed: the protection is
  OPPORTUNISTIC (the edge cannot require the hybrid without breaking pre-ML-KEM
  clients), so harvest-now-decrypt-later is closed only for connections from
  modern clients; old clients and active group-downgrade keep classical exposure.
  The gap-table status is `PQ_SECURE (modern clients)`, not unconditional. The
  toolchain claim is "Go 1.24+" (what the build supports), not a precise version
  the build does not pin.
- **The internal hops stay classical, precisely.** The audit now records that the
  two internal hops (app to pgbouncer, pgbouncer to postgres) remain classical
  because pgbouncer's image is on OpenSSL 3.3.7 (ML-KEM landed in 3.5); postgres
  is already on 3.5.6, so the pooler is the limiter. P2 is gated on rebuilding
  pgbouncer against an OpenSSL 3.5+ base.
- **Pinned.** `check_edge_pq_kex` (63rd check) keeps the claim honest: if
  `PQC-POSTURE.md` names the hybrid group, the `caddy-edge` CI job must read the
  negotiated group off a real handshake and gate on it. The doc can never drift
  ahead of the proof.

## v9.135 — 2026-06-06 (the production TLS edge actually starts: self-built Caddy with the rate_limit plugin)

The prod stack's TLS front door would not come up. The Caddyfile uses the
`rate_limit` directive (edge brute-force defense, 200 req/min/IP), which is the
third-party caddy-ratelimit plugin and is NOT compiled into the stock
`caddy:2-alpine` image the compose pinned. Validating the real Caddyfile against
the pinned image proves it:

    Error: adapting config: Caddyfile:85: unrecognized directive: rate_limit

So the edge container crash-looped on startup and nothing reached the app. This
is the same class as the bitnami/pgbouncer removal (v9.110): a latent prod-down
breakage CI never caught because the docker boot job runs the DEV compose, which
has no Caddy.

- **Self-built edge.** `polaris_web/Dockerfile.caddy` compiles Caddy from source
  with `xcaddy --with github.com/mholt/caddy-ratelimit`, both FROM stages
  digest-pinned (the runtime stage is the same image the compose pinned before),
  with an in-build `caddy list-modules` guard so a plugin-less build fails the
  image, not production. The compose `caddy` service now builds it
  (`image: polaris-caddy:prod`) instead of pulling the stock image, exactly like
  the self-built pgbouncer. Verified locally: the real Caddyfile reports "Valid
  configuration" against the built image and `http.handlers.rate_limit` is present.
- **CI regression guard.** A new `caddy-edge` job builds `Dockerfile.caddy` and
  runs `caddy validate` on the real Caddyfile against it, plus asserts the plugin
  module is present. A future unbacked directive or a broken plugin build fails in
  CI, not at deploy. This closes the blind spot that let the bug ship.
- **Pinned.** `check_caddy_self_built` (62nd check): if the Caddyfile uses a
  third-party directive, the edge must build from `Dockerfile.caddy` with that
  plugin compiled in, and CI must validate the Caddyfile against the built image.
  The stock image can never silently return.

## v9.134 — 2026-06-06 (an honest post-quantum posture audit: what is PQ, what is still classical)

Polaris's thesis is a "post-quantum identity system." That is true of the token
core and false of the transport, and an honest system has to say which is which.
This audits the entire cryptographic surface against the NIST timeline and writes
the result down without softening either side.

- **The audit.** `docs/reference/PQC-POSTURE.md` separates the layers. Post-quantum
  today: the ML-DSA-65 token signature (FIPS 204, two-witnessed since v9.133), the
  SHA3 binding and anchor hashing, the Plonky2 FRI-based ZK inclusion proof (which
  reduces to Poseidon collision-resistance, no Shor-breakable assumption), and the
  scrypt / symmetric session layer. Still classical: TLS key exchange on all three
  hops (classical ECDHE, harvest-now-decrypt-later), the RSA/ECDSA cert signatures,
  and the WebAuthn operator-MFA algorithms (ES256/EdDSA/RS256). Each classical
  surface states its real threat and its bounded exposure (the internal hops carry
  only notional data; the WebAuthn key never leaves the authenticator; WebAuthn and
  public-PKI migration are gated on third parties, not on Polaris).
- **Mapped to the NIST clock.** Every primitive is tagged against FIPS 203/204/205
  and IR 8547 (deprecate classical public-key after 2030, disallow after 2035),
  with a prioritized migration roadmap led by hybrid X25519+ML-KEM-768 on the
  client-to-edge hop.
- **Grounded, not asserted.** The inventory is built from the real code (an
  adversarial review caught and corrected a draft that presented BLAKE3/BLAKE2b as
  live anchor hashes when `anchoring.py` falls back to SHA3-256, and that mislabeled
  cert-signature forgery as harvest-now-decrypt-later). The audit reflects what the
  code actually does.
- **Pinned.** `check_pqc_posture` (61st check) keeps the audit honest: it must keep
  BOTH the post-quantum AND the still-classical sections, name the classical
  surfaces (TLS, WebAuthn) as classical, map to the 2030/2035 NIST clock, and
  disclaim production-readiness. The doc cannot be quietly softened into an
  overclaim. Linked from the reference index and the production-readiness ledger.

## v9.133 — 2026-06-06 (the ML-DSA-65 verify path is two-witnessed, like the ZK path)

Real ML-DSA-65 is the production signing default (v9.116), but every signature
verdict came from ONE library: liboqs. A bug or compromise in that single
implementation could silently accept a forged token, and a lone verifier would
never know. The ZK path already guards against exactly this with an independent
second witness (`polaris_zk/witness2/`); the PQC path did not. This brings the
same discipline to signing.

- **A second, independent witness.** `cryptography==48.0.0` (already pinned)
  ships an OpenSSL-backed ML-DSA-65 — a DIFFERENT FIPS 204 implementation than
  liboqs. `pqc_signing._verify_second_witness()` verifies the same SHA3-256
  digest through it. Interop is real, not assumed: a liboqs signature verifies
  under cryptography/OpenSSL (proven in tests and the pqc-real CI job).
- **The two must AGREE.** `verify_both()` runs both and returns valid only when
  they concur. A DISAGREEMENT — one accepts, one rejects — is a cryptographic red
  flag (a library bug, a compromise, or tampering a lone verifier would miss), so
  the verdict is False and the disagreement is logged loudly. Every real-PQC
  verify site routes through it: the issuance self-verify (refuses to issue a
  signature that fails the two-witness check), `verify_stored_signature`
  (token-detail), and `verify_token_signature` (verify-at-use). The smoke test
  exercises it too.
- **Graceful, honest degradation.** When the witness library is too old to
  provide ML-DSA, `verify_both` falls back to the lone primary — no worse than
  before v9.133 — and `availability_report()` surfaces whether the witness is
  live so operators are never misled about which guarantee is in force.
- **Pinned + proven.** `check_pqc_second_witness` (60th check) asserts
  `verify_both`/`_verify_second_witness` exist, the witness is cryptography's
  MLDSA65 (not a second liboqs call), a disagreement is refused, all three verify
  sites route through `verify_both`, and CI runs the agreement tests. New
  `SecondWitnessTests` prove the two implementations agree on a valid signature,
  both reject a tampered one, a forced disagreement is refused, and the path
  degrades to the primary when the witness is absent. The pqc-real CI job
  installs the witness and asserts cross-implementation agreement.

## v9.132 — 2026-06-06 (hardening: ENFORCE verify-ca at startup, from a review of v9.131)

A focused adversarial review of the v9.131 verify-ca ship found the pinning was
not ENFORCED: a hand-rolled deploy that set `verify-ca` but forgot the cert would
boot and fail confusingly at the first DB connection (it fails CLOSED — no
plaintext leak — but late and cryptically). The review also confirmed the key
posture is sound (the 0700 dir gates the 0644 key; no leak in logs/layers/git).
This makes the misconfigurations fail loud and early, like the v9.129 guards.

- **App: whitelist + require the pin.** The production startup guard now
  WHITELISTS `POLARIS_DB_SSLMODE` (must be `require`/`verify-ca`/`verify-full` — a
  typo like `verifyca` that the old blacklist let through is now rejected), and
  when the mode is verify-*, REQUIRES `POLARIS_DB_SSLROOTCERT` to point at a
  readable file. Refuses to start otherwise.
- **pgbouncer: require the CA + pair the cert/key.** The entrypoint now refuses
  to start when `server_tls_sslmode` is verify-* but no CA file is set, and when
  the client cert/key are half-set (one without the other, which would silently
  fall back to a generated cert the app cannot pin). Cert/CA paths are checked for
  control chars (they are interpolated into pgbouncer.ini).
- **Pinned + proven.** `check_prod_fail_closed` asserts the verify-* sslrootcert
  guard; `check_app_db_tls` asserts the entrypoint's CA-required enforcement.
  Subprocess tests prove the app refuses verify-ca-without-sslrootcert and a
  typo'd mode; the entrypoint enforcement (verify-ca-without-CA, cert-without-key)
  was proven against the built image.

## v9.131 — 2026-06-06 (hardening: both DB hops now VERIFY the pinned certs, not just encrypt)

The last review item: v9.121 encrypted both prod DB hops with `require`, which
defeats passive sniffing but not an active in-network MITM (it does not validate
the peer's cert). This raises both hops to verify-ca, pinning the self-signed
certs — no real CA needed.

- **The app pins pgbouncer.** `DB_CONFIG` gains `sslrootcert` from
  `POLARIS_DB_SSLROOTCERT`, and the prod compose sets `POLARIS_DB_SSLMODE=verify-ca`
  pointing at pgbouncer's cert. A MITM presenting a different cert on the
  app->pgbouncer hop is rejected.
- **pgbouncer pins postgres.** The entrypoint gains `server_tls_ca_file`; the
  prod compose sets `PGBOUNCER_SERVER_TLS_SSLMODE=verify-ca` with postgres's cert
  as the CA. The backend hop verifies, not just encrypts.
- **A stable, pinnable pgbouncer cert.** pgbouncer's client cert was regenerated
  per start (unpinnable). `polaris-generate-secrets.sh` now mints a STABLE
  `pgbouncer_server.crt/.key`; the entrypoint uses the mounted cert when present.
  Both files are 0644 inside the 0700 `secrets/` dir, so the non-root pgbouncer
  user reads the key across a Linux bind mount while the directory gates host
  access (a self-signed cert is its own CA for verify-ca, which skips hostname
  checks; `verify-full` + a real CA + hostname stays the operator's upgrade).
- **Proven on Linux in CI.** A new verify-ca pinning round-trip stands up
  postgres(ssl) + the pooler with both hops verify-ca and asserts: the correct
  pin connects, the backend hop is SSL (`pg_stat_ssl`), and a WRONG cert is
  rejected (`certificate verify failed`). Validated locally end to end first.
  `check_app_db_tls` now asserts verify-ca + the pinning wiring on both hops.

## v9.130 — 2026-06-06 (hardening: pgBackRest operational safety, from the v9.121-v9.128 review)

Three concrete operational gaps the review found in the v9.127 pgBackRest ship:
an operator could enable archiving but never bootstrap the stanza (WAL fills the
disk), run against a local repo thinking it was offsite, or leak S3 keys via the
compose environment.

- **Deploy auto-bootstraps the stanza.** When `POLARIS_PGBACKREST_ENABLED=1`,
  `polaris-deploy.sh` now runs `pgbackrest --stanza=polaris stanza-create` +
  `check` against the running stack (idempotent). A failure WARNS loudly but does
  not block the deploy. Closes the "enabled but unbootstrapped -> archive-push
  fails every WAL -> disk fills" gap.
- **Loud local-repo warning.** `docker-init.sh` warns when archiving is enabled
  but the repo is local (no `repo1-type=s3`) — a local repo does not survive host
  loss, so it is not the offsite durability an operator usually expects.
- **Secure S3-credential guidance.** pgBackRest has no `*_FILE` env convention, so
  `pgbackrest.conf` + `DR.md` now show the correct pattern: write the keys into a
  0600 file under `polaris_web/secrets/` (gitignored) and mount it at
  `/etc/pgbackrest/conf.d/`, NOT as compose `environment:` literals (which leak
  via `docker inspect`).
- **Pinned.** `check_pgbackrest_scaffolding` now also asserts the deploy
  auto-bootstrap, the local-repo warning, and the file-mounted-credential
  guidance; detection tests cover each.

## v9.129 — 2026-06-06 (hardening: fail closed on production misconfiguration, from a review of this session's ships)

A multi-agent adversarial review of v9.121-v9.128 surfaced silent-failure and
silent-misconfiguration gaps (each verified by hand; the speculative ones —
"force duress sync in prod", a trigger that would break rectification — were
discarded). This closes the four concrete ones.

- **Refuse a plaintext DB hop in production.** `POLARIS_DB_SSLMODE` defaults to
  `prefer`, which silently falls back to plaintext if the server lacks TLS. The
  prod compose sets `require`, but a hand-rolled deployment could miss it. app.py
  now refuses to start when `POLARIS_ENV=production` and `POLARIS_DB_SSLMODE` is
  `prefer`/`allow`/`disable` (mirrors the default-`SECRET_KEY` guard).
- **Refuse the duress timing side-channel in production.** `POLARIS_DURESS_SYNC=1`
  records the duress event on the request thread, reintroducing the v9.82 timing
  side-channel (a coerced operator's match becomes measurable). It is a test-only
  knob; app.py now refuses to start with it set in production.
- **The duress page can't fail silently.** `_METRICS_DURESS.inc()` was
  `try/except: pass`; a lost increment (mmap permission, corrupt multiproc file)
  would mean `PolarisDuressEvent` never fires and no one knows. It now logs the
  failure to stderr (safe: off the request thread, and prod sync is refused).
- **`/metrics` carries the duress signal — say so.** As of v9.128 a `/metrics`
  scraper can observe that a duress alarm fired. The route docstring and
  `deploy/observability/README.md` now state plainly that `/metrics` MUST be
  reachable only by the operator's monitoring, never the public internet.
- **Pinned.** `check_prod_fail_closed` (59th check) asserts both startup guards;
  subprocess tests prove production boot is refused on a plaintext sslmode and on
  `POLARIS_DURESS_SYNC=1`, and permitted on `require`.

## v9.128 — 2026-06-06 (production-readiness: the duress signal is now alertable)

`observability.py` calls duress "the headline metric": a coerced operator's
duress code raises a silent `DuressEvent`, and an unread one is the
coercion-cover failure mode (the whole mechanism is decorative if no one reads
the row). The signal lived only in the JSON `/api/metrics`, which Prometheus does
not scrape, so it could not page anyone. This makes it page-able.

- **`polaris_duress_events_total` on `/metrics`.** A new Prometheus counter,
  incremented in `_record_duress_async` right where the silent `DuressEvent` is
  written (best-effort, never raises into the duress path). Multiprocess-
  aggregated (v9.120), so the count is whole-app.
- **`PolarisDuressEvent` alert (SEV-1, immediate).** `increase(...) > 0` fires on
  any new duress event with no `for` window — duress cannot wait out a debounce.
- **A response runbook.** `RUNBOOKS.md` gains a `PolarisDuressEvent` section that
  is deliberately NOT a system-fix runbook: it is the coercion-response procedure
  (read the event out of band, never tip off a coercer, do NOT revoke or alter
  the holder's record in reaction, preserve the append-only evidence). The human
  response is operator-defined; Polaris's job ends at recording + paging.
- **Pinned + proven.** `check_duress_alertable` (58th check) fails the build if
  the counter is removed, stops being incremented at the record site, or loses
  its alert (a dead alert on a never-moving counter is worse than none). A
  DB-backed test drives a real duress-code match and asserts the `/metrics`
  counter increments; `check_alert_runbooks` enforces the new runbook section.

## v9.127 — 2026-06-06 (production-readiness: continuous WAL archiving with pgBackRest)

DR.md named continuous WAL archiving (pgBackRest) as the path to the ≤1-min RPO
but called it "not yet configured." This ships the configuration, leaving only
the operator's offsite repo.

- **pgBackRest in the DB image.** `Dockerfile.postgres` extends the
  digest-pinned `postgres:16-alpine` with pgBackRest (the `archive_command` runs
  inside the postgres process, so it must live on the DB host); the prod compose
  builds it (`polaris-postgres:prod`).
- **The stanza config.** `polaris_web/pgbackrest.conf` defines the `polaris`
  stanza with a local filesystem repo by default and documents the S3 swap (the
  keys stay in the environment, never the file). It is honest up front that a
  local repo is not offsite.
- **Opt-in archiving.** `docker-init.sh` enables `archive_mode` + the
  `archive_command` only when `POLARIS_PGBACKREST_ENABLED=1`, so a deployment
  with no provisioned repo never accumulates unarchivable WAL. `DR.md` is
  reconciled (config ships; the operator points the repo at S3 and runs
  `stanza-create`).
- **Proven end to end in CI.** A new `pgBackRest archive + backup + restore`
  round-trip builds the image, archives WAL, takes a full backup, then RESTORES
  into a fresh container and asserts a row written AFTER the backup comes back
  via WAL replay (the whole point of continuous archiving). Pinned by
  `check_pgbackrest_scaffolding` (57th check), which also fails the build if the
  config stops documenting the offsite repo or archiving stops being opt-in.

## v9.126 — 2026-06-05 (production-readiness: streaming-replication readiness + a failover runbook)

The single Postgres node was an unmitigated SPOF. This ships the buildable HA
scaffolding — a replication-ready primary, the standby bootstrap + promotion
runbook, and a CI proof — leaving only the operator-supplied standby host.

- **Replication-ready primary.** When the operator mounts the
  `polaris_replicator_password` secret, `docker-init.sh` sets the WAL params a
  standby needs (`wal_level=replica`, `max_wal_senders`, `max_replication_slots`,
  `hot_standby`, `wal_log_hints` via `ALTER SYSTEM`), creates a least-privilege
  `polaris_replicator` role (`LOGIN REPLICATION` only — it can stream WAL, not
  read application data), and adds the `pg_hba` entry
  (`POLARIS_REPLICATION_CIDR`, default `samenet`).
  `polaris-generate-secrets.sh` mints the password; the prod compose mounts it.
- **`docs/operator/FAILOVER.md`.** The standby bootstrap (`pg_basebackup -R`,
  which writes `standby.signal` + `primary_conninfo`), the promotion runbook
  (fence the old primary, `pg_promote`, repoint the app/pgbouncer), re-establishing
  redundancy, and the RPO/RTO story (async streaming meets the ≤1-min RPO far
  more tightly than the backup interval for the standby-survives class). Honest:
  the standby HOST and the failover decision are operator-gated; promotion is
  manual, not an automated controller.
- **Proven in CI.** A new `Streaming-replication primary -> standby` round-trip
  stands up a primary with the shipped config, clones a standby with
  `pg_basebackup -R`, and asserts a row written AFTER the clone replicates, the
  standby is in recovery, and `pg_stat_replication` sees it. Pinned by
  `check_replication_scaffolding` (56th check), which also fails the build if
  `FAILOVER.md` overclaims a running standby. DR.md + PRODUCTION-READINESS.md
  reconciled (HA scaffolding ships; standby host operator-supplied).

## v9.125 — 2026-06-05 (production-readiness: right-to-erasure that respects the audit)

PRIVACY.md said pseudonymizing a holder's name was "operationally supported,"
but nothing implemented it. This ships the mechanism, designed so erasure cannot
become a path around C1 (the append-only audit) or around non-repudiation.

- **`uc_pseudonymize_individual(individual_id, actor_user_id, reason)`.** Replaces
  `Individual.legal_name` with a deterministic `PSEUDONYMIZED-<id>` marker. The
  Individual row stays, so every audit and token reference to its `individual_id`
  remains whole. It is gated to an ACTIVE admin by parameter and issues NO
  `DELETE` (it is not SECURITY DEFINER and cannot be a covert deletion path). It
  refuses to double-erase by consulting the authoritative `IndividualErasureEvent`
  log (not the current name, which has no format constraint), and it writes no
  server-log line about the holder (the DB row is the record).
- **`IndividualErasureEvent`, append-only.** The pseudonymization is itself
  audit-of-record: a row records who erased, when, and why — but deliberately
  NOT the prior name or a hash of it (storing either would defeat the erasure).
  The table joins the append-only set: the `reject_audit_modification` trigger
  rejects UPDATE/DELETE, and `09_grants.sql` REVOKEs them from `polaris_app`
  (the v9.85 boundary, so even the GUC carve-out cannot reach it).
- **Operator entry point.** `scripts/polaris-pseudonymize-individual.sh`
  validates argv (numeric ids; the reason is SQL-literal-escaped) and calls the
  procedure. PRIVACY.md now points at the real mechanism.
- **Proven + pinned.** `ErasureTests` (DB-backed) proves the name is replaced,
  the act is recorded, the append-only audit and token bindings are untouched,
  the erasure log rejects UPDATE/DELETE, and double-erase + non-admin are
  refused. `check_erasure_procedure` (55th check) pins the wiring and that the
  procedure never DELETEs; `check_aor_privilege_boundary` now covers the new
  table. Schema is 28 tables (docs reconciled). A four-axis adversarial review
  (C1-bypass, Vocation-leak, injection/privilege, correctness) hardened the
  double-erase guard, added the active-admin check, and dropped the server-log
  line before ship; its name-leak "blockers" were verified false (the marker
  carries only the non-secret structural `individual_id`, and no table copies
  `legal_name`).

## v9.124 — 2026-06-05 (production-readiness, wave 3: the at-rest posture, documented and pinned)

The last agent-buildable Wave 3 item. Polaris encrypts backups (v9.102) and the
app<->DB path (v9.121), but the live database files are not encrypted by Polaris,
and `TokenStateEpochLeaf.proof_path` is plaintext JSONB the schema itself flags
("v1 stores proof_path in plaintext"). This ships the honest posture, not a false
claim that the live DB is encrypted.

- **`docs/operator/ENCRYPTION-AT-REST.md`.** Enumerates the plaintext-sensitive
  surfaces (`Individual.legal_name`, `Individual.date_of_birth`,
  `TokenStateEpochLeaf.proof_path`); records what is already protected (encrypted
  backups, in-transit TLS) and what is not (the live data files + WAL); and
  explains why the right control is host volume encryption (LUKS / dm-crypt /
  fscrypt), not field-level: encrypting `legal_name` / `date_of_birth` breaks the
  C3 one-identity partial unique index, and encrypting `proof_path` breaks the ZK
  second witness that recomputes the Merkle path. Data minimization is named as
  the strongest control: biometric / genomic plaintext never enters the DB.
- **`check_encryption_at_rest_posture` (54th check).** Grounds the doc in the
  schema: it must name `proof_path` / `legal_name` / `date_of_birth`, must say
  `plaintext` while the schema still stores `proof_path` that way (drift guard),
  must name the host-level path, and must NOT claim the live DB is encrypted at
  rest (honesty guard). Detection test covers each branch.
- **The agent-buildable arc converges here.** With this ticked, every remaining
  item in `docs/PRODUCTION-READINESS.md` is operator-gated (the host encryption
  layer + key custodian, the offsite/WAL store, and the legal/HA/HSM/pen-test
  decisions) — organizational calls, not code.

## v9.123 — 2026-06-05 (production-readiness, wave 4: SLOs + alert runbooks, grounded and honest)

Wave 4 shipped the alert rules (v9.115) but left the SLO targets and the
response runbooks open. This closes both, grounded only in metrics Polaris
actually exposes, and refuses to overclaim that any of it is enforced.

- **`docs/operator/SLOS.md`, reference SLO targets.** Availability (≥ 99.9%
  non-5xx, the exact complement of the `PolarisHigh5xx` ratio), request-latency
  p99 < 2s, and DB-round-trip p99 < 5s, each computed from a metric the app
  emits (`polaris_requests_total`, `polaris_request_latency_seconds`,
  `polaris_db_query_latency_seconds`) over a 30-day window. Error budget stated
  (0.1% of requests, ~43 min/30d). Honesty discipline up front: these are
  reference targets for a notional deployment, not a measured guarantee, and the
  Prometheus + Alertmanager backend is operator-gated. `duress_events_total` and
  `auth_failures_per_minute` are deliberately excluded as SLIs (security
  signals, not reliability budget; per-identity SLOs would be an aggregation
  vector, vocation).
- **`docs/operator/RUNBOOKS.md`, one runbook per shipped alert.** A section
  for each of the five alerts (`PolarisAppDown`, `PolarisAppInfoAbsent`,
  `PolarisHigh5xx`, `PolarisHighDBLatency`, `PolarisHighRequestLatency`), each
  with Trigger / Likely cause / Diagnosis / Remediation, cross-linked to the DR
  failure-class procedures and the SLO thresholds.
- **`check_alert_runbooks` (53rd check).** Parses the `- alert: <Name>` lines
  out of `polaris-alerts.yml` and asserts a one-to-one mapping with the
  `## <name>` runbook headings: FAIL if an alert has no runbook (a page with no
  runbook is a 03:00 dead end), FAIL on an orphan section (stale guidance).
  Detection test covers missing-runbook, one-to-one-OK, orphan, and
  missing-file cases.
- **Production-readiness ledger.** The Wave 4 "SLOs; runbooks" item is now
  ticked.

## v9.122 — 2026-06-05 (production-readiness, wave 4: request-correlation ids that cannot become a surveillance key)

Production debugging needs to tie a log line to the request a caller saw, but in
a privacy-first identity system a correlation id is a hazard: persist it into the
audit trail and it becomes a permanent, reconstructable record of one person's
activity. This ships the id with that failure mode designed out.

- **Per-request, ephemeral by construction.** `observability.py` holds the id in
  a `contextvars.ContextVar` set in `before_request` and cleared in
  `teardown_request`, so it never leaks into the next request a worker serves.
  It lives only in that contextvar and the `X-Request-ID` response header. There
  is no DB column, cookie, cache, or global registry.
- **Stamped into the logs, echoed to the caller.** Every `structured_log` line
  carries `request_id`, and the unhandled `[db_error]` path now routes through
  `structured_log` so the single most useful line to correlate is tagged. The id
  is echoed in `X-Request-ID` on every response produced through the normal
  pipeline, including handled error responses (404/403/413/429).
- **Bounded and mint-always.** An inbound id is accepted only if it matches
  `\A[A-Za-z0-9-]{8,64}\Z` (safe charset, bounded length, newline-proof anchors);
  anything else is replaced by `uuid4().hex`. An inbound id is honoured only
  behind a trusted proxy (`POLARIS_TRUST_PROXY`, symmetric with
  `X-Forwarded-For`); otherwise the server always mints its own, so an untrusted
  client cannot choose its correlation token.
- **Vocation, enforced.** The id is never derived from identity and never written
  to the append-only audit-of-record. `check_correlation_id` (52nd check) fails
  the build if `observability.py` gains DB access, if `security.py` references
  the id, if it co-occurs with an audit call, if `set_request_id` is fed anything
  but the validator, or if it is seeded from a session/user. The proof a static
  check cannot give is a DB-backed test: it drives failed logins (which write
  audit rows) while a trusted operator-chosen id is in context, then asserts no
  `AuthAuditLog` row contains it. Useful for live debugging, inert as an
  aggregation vector. That asymmetry is the anti-coercion property.

## v9.121 — 2026-06-05 (production-readiness, wave 3: the app<->DB path is encrypted on both hops)

The prod stack routes the app through pgbouncer to Postgres, and both hops moved
plaintext: a tap on the pod network (or a compromised sidecar) could read every
query and the SCRAM exchange in the clear. Wave 3 turns on TLS end to end.

- **Postgres hop.** `docker-init.sh` copies a server cert mounted at
  `/etc/polaris-pg-certs/` into `PGDATA` (key 0600, cert 0644) and runs
  `ALTER SYSTEM SET ssl = on` with `ssl_cert_file`/`ssl_key_file`, then reloads
  (`ssl` is SIGHUP-reloadable). `scripts/polaris-generate-secrets.sh` mints the
  self-signed cert (`/CN=postgres`, 825 days) at deploy time if absent, alongside
  the signing key — it never enters the repo (secrets/ is gitignored).
- **Both pgbouncer hops.** The self-built pooler now reads
  `PGBOUNCER_SERVER_TLS_SSLMODE` (pgbouncer -> postgres) and
  `PGBOUNCER_CLIENT_TLS_SSLMODE` (app -> pgbouncer); for the client hop the
  entrypoint mints its own `/CN=pgbouncer` cert with openssl (added to
  `Dockerfile.pgbouncer`). Both sslmodes are validated against the pgbouncer
  enum before they reach `pgbouncer.ini`. The prod compose sets both to
  `require`; both default OFF so dev and the existing CI round-trip stay plaintext.
- **App hop.** `DB_CONFIG` gains `sslmode` from `POLARIS_DB_SSLMODE` (default
  `prefer` for dev; the prod compose sets `require`), so the psycopg2 connection
  negotiates TLS to the pooler. `require` encrypts without pinning a CA, which a
  self-signed cert satisfies; `verify-full` against a real CA stays an
  operator-gated step (documented, not claimed).
- **Proven + pinned.** A local docker stack brought all three containers up with
  TLS and confirmed `SSL established: TLSv1.3` on both hops (backend_ssl=t). CI
  gains a `client_tls` round-trip: a pooler with `CLIENT_TLS=require` must mint
  its cert and serve an `sslmode=require` client. `check_app_db_tls` (51st check)
  asserts the wiring across app.py, the prod compose, docker-init, and the
  pgbouncer entrypoint so a hop cannot silently revert to plaintext.

## v9.120 — 2026-06-05 (production-readiness, wave 4: Prometheus metrics aggregate across workers)

The `/metrics` endpoint used a per-worker Prometheus registry, so a scrape
reported only the gunicorn worker that happened to serve it — a 4x undercount
of every counter under the prod default of 4 workers. Any absolute-count alert
or dashboard built on it would read low by the worker count.

- **Multiprocess mode.** When `PROMETHEUS_MULTIPROC_DIR` is set (now the prod
  default), each worker file-backs its samples into that directory and the
  `/metrics` scrape aggregates ALL of them through a fresh
  `MultiProcessCollector` — so a counter reflects the whole app. The dedicated
  single-process registry path is preserved for dev. The `polaris_app_info`
  gauge gets `multiprocess_mode='max'` to collapse cleanly to one line.
- **Worker lifecycle.** `gunicorn.conf.py` clears the metric directory at master
  start (`on_starting`, before workers fork, so a previous run's files don't
  pollute) and reaps a dead worker's files on `child_exit`
  (`mark_process_dead`), so a cycled worker stops contributing to the aggregate.
- **Proven across real processes.** `MetricsMultiprocessTests` increments a
  counter in one process and scrapes `/metrics` from a SEPARATE process, which
  must see the increment — the genuine cross-worker property, not a single-
  process stand-in. The CI prod smoke-boot now sets the dir so the gunicorn
  multiprocess path boots cleanly.
- **Pinned + reconciled.** `check_prometheus_multiprocess` (50th check) asserts
  the collector + `child_exit` + the dir; the alert-rules README no longer warns
  about per-worker undercounting. Ticks the Prometheus box in
  `docs/PRODUCTION-READINESS.md` Wave 4.

## v9.119 — 2026-06-05 (production-readiness, wave 2 COMPLETE: uc6 migration routes through the signing module)

The last hardcoded signature. uc6 algorithm-migration wrote
`f"UC6_OPERATOR_MIGRATE_{token_id}_{new_algorithm}"` directly into
`TokenSignature.signature_bytes` — a non-signature that bypassed the signing
module entirely, so a migrated token's new signature verified as neither real
nor a valid placeholder.

- **uc6 now signs like issuance.** The `/uc6/migrate` route fetches the token's
  value, calls `pqc_signing.signature_with_key_for_token()` (real ML-DSA-65 when
  enabled, else the deterministic SHA3-256 placeholder), and passes the bytes +
  the issuer public key to `uc6_migrate_algorithm`, which now takes
  `p_signing_public_key_hex` and stores it in `signing_public_key_hex` — so a
  migrated signature is self-contained and verifies on the token-detail page
  exactly like an issued one. Signing failures block the migration.
- **No new migration needed.** The column already exists (v9.117); the procedure
  change reaches upgraded DBs via the v9.118 `--sync-objects` re-sync.
- **Tested + pinned.** `test_uc6_route_signature_routes_through_signing_module`
  proves the route stores `sha3(token_value)`, not the old string;
  `check_pqc_wired` now also fails if `UC6_OPERATOR_MIGRATE` reappears. All 17
  multi-signature tests pass.

**Wave 2 (the cryptographic core) is complete:** real ML-DSA-65 testable →
persistent-key trust anchor → verification enforced → real PQC the production
default → issuer key stored as a DB trust anchor, verification surfaced at use →
every signing path (issuance and migration) routes through the module.

## v9.118 — 2026-06-05 (production-readiness: procedure/trigger changes reach an UPGRADED database, not just a fresh one)

A latent deploy bug, surfaced while wiring uc6: `docker-init.sh` loads the full
schema + all procedures/triggers/grants and applies migrations — but only on a
**fresh** data volume (postgres init scripts never re-run on an existing one).
On an **upgrade**, `polaris-deploy.sh` brought the stack up and did nothing
else: no migrations, no procedure re-sync. So a changed stored procedure never
reached the running DB — concretely, **v9.117's `uc1_issue_and_activate`
signature change would be absent on an upgraded prod DB and issuance would fail**
(the app passes one more argument than the stale procedure accepts). It is
systemic: it applies to every procedure/trigger/view/grant change.

- **`polaris-migrate.sh --sync-objects`** re-applies the idempotent object files
  (views, procedures, triggers, queries, atlas/foresight/ontology helpers,
  grants) — all verified safe to re-apply to a populated DB. A dropped-then-
  synced procedure round-trip proves it restores the current definition.
- **Migrations now apply over the containerized stack.** `--up`/`--down` inline
  the migration body (via `cat`) instead of `\i <host-path>`, which a psql
  running *inside* the postgres container cannot resolve — so
  `--target=docker-stack` works by piping the SQL over stdin (verified the
  `$$`-quoted trigger migration survives the inlining; up/down round-trips).
- **The deploy now updates the DB.** `polaris-deploy.sh` runs `--up` +
  `--sync-objects` against the running stack after bring-up — idempotent on a
  fresh deploy, the fix on an upgrade.
- **Pinned** by `check_deploy_syncs_db_objects` (the 49th check).

## v9.117 — 2026-06-05 (production-readiness, wave 2: the issuer public key is a DB trust anchor, verification is surfaced at use)

v9.113 enforced verification but left it dependent on the live
`POLARIS_PQC_SIGNING_KEY_FILE`, and `TokenSignature` recorded only the crypto
algorithm — not the signature SCHEME — so a verifier could not tell a real
ML-DSA-65 signature from the SHA3-256 placeholder, nor verify after a key
rotation. v9.117 stores the issuer public key WITH each signature and shows the
verification result on the token-detail page.

- **`TokenSignature.signing_public_key_hex`** (migration
  `2026-06-05-001`): the issuer public key (hex) that produced the signature,
  NULL for a placeholder. Self-contained — verification needs no live key file —
  and null-vs-not captures the scheme. Write-once: the immutability trigger now
  protects it (`IS DISTINCT FROM`, since it is nullable; verified by a refused
  UPDATE).
- **Threaded through issuance.** `signature_with_key_for_token()` surfaces the
  public key; `uc1_issue_and_activate` takes `p_signing_public_key_hex` and
  stores it; the placeholder path stores NULL.
- **Verified at use.** The token-detail page calls
  `verify_stored_signature(token_value, bytes, key)` for each signature and
  renders a Verification column — *verified* (real, checks against the stored
  key), *INVALID*, *placeholder*, or *verifier offline* — without the raw bytes
  or key ever reaching the response.
- **Tested + pinned.** DB-backed `test_token_detail_surfaces_signature_verification`,
  two new `pqc_signing` unit tests, and the migration's up/down + write-once
  proven against a throwaway DB. `check_signature_self_contained_verify` (the
  48th check) pins the column + procedure param + the token-detail verify.
  Advances the Wave 2 box in `docs/PRODUCTION-READINESS.md` (only uc6 remains).

## v9.116 — 2026-06-05 (production-readiness, wave 2: real ML-DSA-65 is the production default)

Real post-quantum signing was testable (v9.103) and verification was enforced
(v9.113), but production still signed with the SHA3-256 placeholder: liboqs was
not in the prod image, so `POLARIS_USE_REAL_PQC=1` there would have failed to
import. This ship makes real ML-DSA-65 the actual default in production.

- **liboqs ships in the prod image.** `Dockerfile.prod`'s Python builder now
  builds liboqs from source (the `liboqs-python` install triggers it) and the
  runtime stage copies the prebuilt library into the `polaris` user's home — no
  compiler or build tools in the runtime layer. Validated by building the image
  and signing inside it: `available: True, enabled: True, ML-DSA-65, 3309-byte
  signature, verify-at-use True`, all as the non-root user.
- **The flag is on, with a real trust anchor.** `docker-compose.prod.yml` sets
  `POLARIS_USE_REAL_PQC=1` and mounts a new `polaris_signing_key` secret (the
  ML-DSA keypair), pointed to by `POLARIS_PQC_SIGNING_KEY_FILE` — so the public
  key is the stable anchor `verify_token_signature` checks against.
- **Key minting.** `polaris-generate-secrets.sh` mints the signing keypair (via a
  local liboqs or the built `polaris-app:prod` image) into the gitignored
  secrets dir, mode 0600. Operators custodying key material in an HSM/KMS supply
  their own loader instead — that custody stays operator-gated.
- **CI proves it in the image.** The `docker-image` job now runs real ML-DSA-65
  sign + verify-at-use inside the built prod image, so a broken liboqs copy fails
  CI, not a deploy. Pinned by `check_prod_real_pqc`. Closes the Wave 2 prod-
  default box in `docs/PRODUCTION-READINESS.md` (DB trust-anchor table +
  use-surface wiring + uc6 remain).

## v9.115 — 2026-06-05 (production-readiness, wave 4: alerting rules are a shipped, validated artifact)

`DR.md` told operators that "PolarisHigh5xx and related Prometheus alerting
rules" classify incidents automatically — but those rules existed only as a
snippet inside `OPERATIONS.md`. There was nothing an operator could actually
deploy: a doc-overclaim with no shipped artifact behind it.

- **A real, promtool-validated bundle.** `deploy/observability/` now ships
  `polaris-alerts.yml` (five rules: `PolarisAppDown`, `PolarisAppInfoAbsent`,
  `PolarisHigh5xx`, `PolarisHighDBLatency`, `PolarisHighRequestLatency`,
  severity-labelled to the DR.md SEV ladder), a `prometheus.yml` scrape config
  that loads them, and a README. Both pass `promtool check`.
- **Honest about the metric limitation.** The app's `/metrics` uses a per-worker
  registry, so absolute counters are per-gunicorn-worker until multiprocess
  aggregation lands. The shipped alerts are deliberately **ratios** (5xx share)
  and **quantiles** (latency percentiles), which stay valid per worker — the
  README warns against absolute-count thresholds until aggregation exists.
- **Docs reconciled.** `DR.md` and `OPERATIONS.md` now point at the shipped file
  instead of implying rules that did not exist. The alerting backend
  (Alertmanager + pager) stays operator-provided.
- **Pinned** by `check_alert_rules` (the 45th check): the rules + scrape config
  must ship and be wired. Ticks the alert-rules box in
  `docs/PRODUCTION-READINESS.md` Wave 4.

## v9.114 — 2026-06-05 (production-readiness, wave 4: prod images are pinned by digest, not a mutable tag)

The prod compose pulled `caddy:2-alpine`, `postgres:16-alpine`, and
`redis:7-alpine` by tag. A tag is a mutable pointer: upstream can repoint it at
different content, or retire it entirely — exactly what happened to
`bitnami/pgbouncer:1.22` (v9.110). Pulling by tag means the deploy can silently
run something other than what was reviewed.

- **Digest-pinned.** All three third-party prod images are now
  `name:tag@sha256:<digest>` — the tag stays for readability, the digest makes
  the image immutable. The deploy runs exactly the bytes that were vetted; a
  mutated or deleted upstream tag cannot change that. (The locally-built
  `polaris-app` / `polaris-pgbouncer` images have no registry digest to pin.)
- **Kept current.** A frozen digest never receives security updates on its own,
  so the `docker` ecosystem was added to `.github/dependabot.yml` — it opens PRs
  to bump a pinned digest when the upstream tag moves.
- **Pinned** by `check_prod_images_digest_pinned` (the 44th check): every
  third-party `image:` in the prod compose must carry `@sha256:` and Dependabot
  must track docker. Ticks the image-digest box in
  `docs/PRODUCTION-READINESS.md` Wave 4.

## v9.113 — 2026-06-05 (production-readiness, wave 2: signature verification is enforced, not just possible)

The signing core could produce a real ML-DSA-65 signature (v9.103), but
`verify()` was never called on any live path — a signature nothing ever checks
is theater. v9.113 makes verification a live, enforced obligation.

- **Issuance self-verifies.** `signature_bytes_for_token()` now verifies the
  real signature it just produced against its own public key before handing it
  to the DB, and raises `SigningError` (issuance blocked, surfaced to the
  operator) if it does not check out. A broken key or liboqs can no longer
  persist an unverifiable signature.
- **A use-path verification primitive.** `verify_token_signature(token_value,
  signature_bytes, algorithm_label)` checks a stored `TokenSignature` against
  its token. For a real `ML-DSA-65` signature it verifies against the published
  **trust anchor** (`trust_anchor_public_key_hex()`, the persistent signing
  key's public key) — a genuine authenticity proof; without a configured anchor
  it returns False (cannot prove authenticity). For the placeholder it is an
  integrity recompute. Dispatch is on the algorithm recorded WITH the signature,
  so a token verifies correctly regardless of the verifier's current mode.
- **Exercised in CI.** The `pqc-real` job now asserts the trust anchor matches,
  a real signature verifies at use, tamper/forgery is rejected, and the issuance
  self-check refuses a signature that fails to verify. Eight new unit tests in
  `test_pqc_signing.py` cover both the placeholder and real paths.
- **Pinned.** `check_verify_enforced` (the 35th check, after `check_pqc_real_signing`)
  asserts issuance self-verifies and CI exercises `verify_token_signature`.
  Advances the Wave 2 box in `docs/PRODUCTION-READINESS.md` (still owed: a DB
  trust-anchor table, wiring verification to a use surface, real PQC as the prod
  default, and uc6 through the signing module).

## v9.112 — 2026-06-05 (production-readiness, wave 4: SAST in CI catches a world-writable state dir)

Dependency CVEs were scanned (v9.105) but our own source never was. Adding
bandit (SAST) immediately surfaced a real HIGH: `_ensure_state_dir()` did
`chmod 0o777` on `POLARIS_STATE_DIR` — world-writable — and that directory can
hold sensitive state (in the dev launcher path, the persisted Flask
`secret_key`). On a shared host any local account could replace those files
(session forgery) or drop the `quit` file to tear the stack down.

- **The state dir is locked down in production.** `_ensure_state_dir()` now
  `chmod`s `0o700` when `POLARIS_ENV=production` — the container owns the
  directory and no host launcher shares it, so owner-only is correct. The looser
  `0o777` survives only outside production, where the watch-mode launcher runs as
  a different uid and genuinely needs the cross-uid share (carrying an inline
  `# nosec B103` with the rationale).
- **SAST gates the build.** The `cve-scan` job (now "Dependency CVE scan + SAST")
  runs `bandit` over `polaris_web` + `polaris_cli`, gating on HIGH severity +
  medium confidence. Lower-severity findings (bind-all inside the container,
  parameterized SQL flagged as string-building, the dev `/tmp` default) are
  reported but do not block.
- **Pinned + tested.** `check_sast_scanning` (43rd check) asserts CI runs bandit
  gating on high severity; `StateDirPermsTests` proves the dir is `0o700` in
  production and `0o777` only in dev. Ticks the SAST box in
  `docs/PRODUCTION-READINESS.md` Wave 4.

## v9.111 — 2026-06-05 (production-readiness: CI builds + round-trips the self-built pgbouncer image)

v9.110 made pgbouncer self-built but nothing in CI built or ran that image — the
same blind spot that let a broken app image (v9.40, v9.58) and an unbuildable
prod image (v9.98) ship green. A regression in `Dockerfile.pgbouncer` or the
entrypoint would only surface at deploy, when the stack cannot reach the
database.

- **Real round-trip in CI.** The `docker-image` job now builds the pgbouncer
  image and exercises the actual path: a Postgres (scram) backend, a
  `polaris_app` role, the file-mounted secret, then a client query through
  `pgbouncer:6432` asserting `PB-OK` — proving SCRAM works on both hops in CI,
  not just on a developer's machine. A negative check confirms the container
  fails closed when the secret is not mounted.
- **Pinned.** `check_pgbouncer_self_built` now also requires CI to build
  `Dockerfile.pgbouncer`, so the coverage cannot be silently dropped.

## v9.110 — 2026-06-05 (production-readiness: the prod stack's pgbouncer is self-built, not a vanished vendor image)

The production compose pinned `bitnami/pgbouncer:1.22` for connection pooling.
Bitnami retired their free Docker Hub catalogue in August 2025: that tag now
404s and the whole `bitnami/pgbouncer` repo has zero tags (the `bitnamilegacy`
mirror is gone too). `docker compose -f docker-compose.prod.yml up` could no
longer pull the pooler, and since the app reaches Postgres only through
`pgbouncer:6432`, the entire stack was unstartable — a latent outage waiting for
the next clean deploy, the same class as the v9.98 unbuildable-image bug.

- **Self-built pooler, no third-party catalogue.** `polaris_web/Dockerfile.pgbouncer`
  builds pgbouncer from `alpine` + the distro package (PgBouncer 1.22.1, same
  version as before). Nothing external can disappear out from under the stack
  again.
- **Secret stays a file, SCRAM on both hops.** `pgbouncer-entrypoint.sh`
  generates `pgbouncer.ini` + `userlist.txt` at start, reading the DB password
  from the file-mounted Docker secret (`POLARIS_DB_PASSWORD_FILE`) — it never
  enters the environment, the image, or `docker inspect`. The password is stored
  plaintext in a `0600` userlist with `auth_type = scram-sha-256`, so pgbouncer
  runs SCRAM both verifying the app and authenticating onward to Postgres.
  Embedded quotes are doubled per pgbouncer's userlist grammar so an exotic
  password cannot break or inject a second entry.
- **Least privilege + validated config.** No `admin_users`/`stats_users`, so the
  app role cannot issue pgbouncer admin commands (PAUSE/RELOAD/SHUTDOWN); the
  backend user is pinned in the `[databases]` entry so a client cannot have a
  claimed identity forwarded; control-character passwords and malformed numeric/
  enum/identifier settings are rejected at start rather than corrupting the
  generated config. (These came out of an adversarial review of the change.)
- **Healthcheck + ordering.** The pgbouncer service gets a TCP healthcheck and
  the app now waits on `pgbouncer: service_healthy`.
- **Verified with real containers.** Built the image and ran the full path —
  Postgres (scram) -> pgbouncer -> client through `:6432` — with both an ordinary
  and an adversarial (`"`/`\`) password, confirmed transaction pooling, the
  healthy healthcheck, and a loud failure when the secret is missing.
- **Pinned.** `check_pgbouncer_self_built` (42nd check) fails if bitnami/pgbouncer
  reappears, the self-built Dockerfile/entrypoint goes missing, or the password
  moves to an env var.

## v9.109 — 2026-06-05 (production-readiness, wave 4: every prod container bounds its memory, CPU, and logs)

The production compose set no resource limits and no log rotation on any
service. So one container with a memory leak could consume all host RAM and
take the whole stack down with it (no cgroup ceiling), and the default
json-file log driver grows without bound until it fills the disk — a slow
outage that looks like nothing until `df` hits 100%.

- **Resource limits on all five services.** caddy, app, pgbouncer, postgres,
  and redis each get `deploy.resources.limits` (memory + cpu) and a memory
  reservation, sized to role (postgres 1G, app 768M, redis 256M, caddy +
  pgbouncer 128M). Compose v2 honors these for `docker compose up`, so a runaway
  container is OOM-killed by its own cgroup instead of starving its neighbors.
- **Log rotation on all five.** Each service uses the `json-file` driver capped
  at `max-size: 10m` x `max-file: 5` (50 MB/container ceiling), so logs roll
  over instead of filling the disk.
- **Pinned.** `check_compose_resource_limits` (41st check) parses the compose by
  text (the check layer runs on system python, no PyYAML) and fails unless every
  service has both a limit block and a rotating log driver. `docker compose
  config` resolves the file cleanly. Ticks the resource-limits box in
  `docs/PRODUCTION-READINESS.md` Wave 4.

## v9.108 — 2026-06-05 (production-readiness, wave 4: liveness and readiness are separate probes)

`/api/health` ran the full dependency roll-up (database, redis, ZK binary,
disk) and the container HEALTHCHECK keyed on it returning `"status":"healthy"`.
That conflates two different production signals. A liveness probe answers "is
this process alive?" and its failure should RESTART the container; a readiness
probe answers "can this instance serve traffic?" and its failure should STOP
routing without a restart. Keying the container HEALTHCHECK on the dependency
roll-up means a transient DB or redis blip marks the container unhealthy and can
trigger a restart that cannot bring the dependency back — a restart storm.

- **Two probes, split by cost.** `/api/health/live` is the liveness probe:
  deliberately cheap, it touches no external dependency and returns 200
  `{"status":"alive"}` whenever the worker can answer. `/api/health/ready` is
  the readiness probe: it runs the dependency checks and returns 503 when a
  critical dependency is down. `/api/health` is unchanged (the readiness
  payload) for backwards compatibility; the shared roll-up moved into
  `_compute_readiness()`.
- **The container HEALTHCHECK now uses liveness.** `Dockerfile.prod` probes
  `/api/health/live`, so a dependency outage no longer marks the container
  unhealthy; readiness is left for the reverse proxy / orchestrator to gate
  traffic on.
- **Pinned + tested.** `check_health_liveness_readiness_split` (40th check)
  asserts both routes exist, the liveness handler does not run the dependency
  roll-up, and the prod HEALTHCHECK uses liveness. Two new `HealthEndpointTests`
  prove liveness is cheap (no `checks` key, always 200) and readiness carries
  the dependency checks. Ticks the liveness/readiness box in
  `docs/PRODUCTION-READINESS.md` Wave 4.

## v9.107 — 2026-06-05 (production-readiness, wave 4: WEB_CONCURRENCY is no longer an inert knob)

`Dockerfile.prod` and `docker-compose.prod.yml` both advertise
`WEB_CONCURRENCY` as the worker-count knob (gunicorn's own convention), but
`gunicorn.conf.py` read only `POLARIS_WORKERS`. So an operator scaling the
stack with `WEB_CONCURRENCY=8` silently got the default 4 workers — and, with
no Redis configured, a per-worker in-memory rate limiter at 4x the intended
per-IP cap. The knob the deploy surface tells you to use did nothing.

- **The config honors both knobs.** `gunicorn.conf.py` now resolves
  `POLARIS_WORKERS` (explicit Polaris override) > `WEB_CONCURRENCY` (the deploy
  knob) > 4. The resolved count is still re-exported to `POLARIS_WORKERS` so
  `security.py`'s multi-worker detection (which warns when >1 worker runs
  without Redis) stays accurate regardless of which knob was set.
- **Bad values fall back, they don't crash.** A non-integer worker count
  resolves to 4 rather than raising during every worker boot.
- **Pinned + tested.** `check_web_concurrency_honored` (39th check) asserts the
  config reads `WEB_CONCURRENCY`; `GunicornConfigTests` (4 cases, in the CI app
  suite) proves the resolution: WEB_CONCURRENCY honored, POLARIS_WORKERS wins,
  default 4, bad value falls back. Ticks the WEB_CONCURRENCY box in
  `docs/PRODUCTION-READINESS.md` Wave 4.

## v9.106 — 2026-06-05 (production-readiness, wave 4: migrations bound their lock + statement time so one ALTER cannot stall the site)

A schema migration that needs an ACCESS EXCLUSIVE lock — most `ALTER TABLE`
forms — queues behind any open transaction and, once it acquires the lock,
blocks every read and write on that table until it finishes. The runner set no
timeouts, so the wait was unbounded: one slow background query in front of a
migration could stall all traffic on the table indefinitely. This is one of the
classic ways a routine deploy takes down a live database.

- **`lock_timeout` + `statement_timeout`, SET LOCAL in the apply transaction.**
  `polaris-migrate.sh` now sets both inside the `BEGIN; … COMMIT;` for every
  apply and revert. `lock_timeout` (default `3s`) makes a blocking migration
  ERROR fast and release the line instead of queueing in front of all other
  traffic; `statement_timeout` (default `60s`) caps a runaway migration. Both
  reset automatically at COMMIT (SET LOCAL) and are overridable for long,
  legitimate work via `POLARIS_MIGRATE_LOCK_TIMEOUT` /
  `POLARIS_MIGRATE_STATEMENT_TIMEOUT` (e.g. a big in-transaction index build).
- **Validated, not interpolated blindly.** The two values are interpolated into
  the SQL, so they are checked against `^[0-9]+(ms|s|min|h)?$` and the script
  refuses anything else (a `3s; DROP TABLE …` attempt exits with a usage error).
- **Pinned.** `check_migration_timeouts` (38th check) asserts the runner SET
  LOCALs both timeouts. Ticks the migration-timeout box in
  `docs/PRODUCTION-READINESS.md` Wave 4.

## v9.105 — 2026-06-05 (production-readiness, wave 4: no test frameworks in the prod image; dependency CVE scanning gates the build)

The dependency surface was pinned but never audited, and a single
`requirements.txt` mixed runtime packages with test tooling (pytest,
hypothesis, playwright). Both Docker images installed the whole file, so the
production image shipped a test framework that carried a CVE — `pip-audit`
flags pytest 8.4.2 (CVE-2025-71176). Test frameworks in a production image are
dead weight and pure extra attack surface.

- **Runtime / dev split.** `requirements.txt` is now the runtime surface only
  (what the images install); pytest, hypothesis, and playwright moved to a new
  `requirements-dev.txt` that pulls the runtime in via `-r requirements.txt`.
  The Docker images install `requirements.txt` — the production image no longer
  carries any test framework. CI and the macOS launcher's `test` path install
  the dev file (they run the suites); the launcher's run path stays lean.
- **CVE scanning, gating on what ships.** A new `cve-scan` CI job runs
  `pip-audit --strict` against `requirements.txt` — a known CVE in the
  production dependency surface now **fails the build**. The dev tooling is
  audited informationally (a test-tool CVE is surfaced but does not gate or
  ship). With pytest out of the runtime file, the gating audit is clean today.
- **Dependabot.** `.github/dependabot.yml` opens weekly update PRs for pip, the
  Rust ZK crate, and the GitHub Actions, so a new advisory is one review away.
- **Pinned.** `check_prod_image_no_test_deps` (asserts no test packages in the
  runtime file and that the images install it, not the dev file) and
  `check_cve_scanning` (asserts the gating `--strict` audit + Dependabot) are
  the 36th and 37th checks. Ticks the CVE-scanning box in
  `docs/PRODUCTION-READINESS.md` Wave 4.

## v9.104 — 2026-06-05 (production-readiness, wave 4: the /sql console is read-only at the engine, not just the keyword gate)

The operator SQL console refused writes with a first-keyword whitelist: only
`SELECT` and `WITH` were accepted. But `WITH` admits a data-modifying CTE —
`WITH gone AS (DELETE FROM Individual WHERE ... RETURNING *) SELECT * FROM gone`
starts with `WITH`, sails past the gate, and deletes. `polaris_app` holds DELETE
on the non-audit tables, so nothing below the app stopped it. The console was
write-capable through a CTE.

- **The session is now read-only at the database.** `sql_query` calls
  `conn.set_session(readonly=True)` immediately after connect, before any
  statement opens a transaction, so Postgres itself refuses every write —
  "cannot execute DELETE in a read-only transaction" — regardless of how the SQL
  is shaped. The keyword whitelist stays as a friendly early error; it is no
  longer the boundary.
- **The subtlety that needed a DB-backed test.** The first attempt issued `SET
  default_transaction_read_only = on` mid-transaction. It did nothing: psycopg2
  had already opened the transaction on the prior `SET statement_timeout`, and
  that GUC only binds transactions that begin after it. The CTE-DELETE still
  succeeded ("0 rows"). The new `test_data_modifying_cte_refused_by_db_readonly`
  caught it — it failed (write executed), then passed once the fix moved to
  `set_session(readonly=True)` before any statement. A static check alone would
  have green-lit the non-fix.
- **Pinned both ways.** `check_sql_console_readonly` (35th check) asserts the
  handler calls `set_session(readonly=True)`; the DB-backed test proves the
  engine actually refuses the CTE write. Ticks the SQL-console box in
  `docs/PRODUCTION-READINESS.md` Wave 4.

## v9.103 — 2026-06-05 (production-readiness, wave 2: real ML-DSA-65 signing, persistent key, tested in CI)

The defining gap between reference and reality: token signing was not real. The
default signed with a `sha3_256(token_value)` placeholder that authenticates
nothing, real ML-DSA-65 was never exercised in CI, and even with the flag on
`sign()` generated a fresh ephemeral keypair per call and threw the private key
away — so the public key was never stable and the signature was unverifiable
against any known anchor. This wave lays the real foundation:

- **Real ML-DSA-65 is now tested.** A dedicated `pqc-real` CI job installs
  liboqs-python and proves the real path end to end: it generates a keypair,
  signs with a persistent key, verifies (True), and confirms a forged message
  and a wrong key both fail. Real signatures are 3309 bytes, public keys 1952
  bytes (FIPS 204). liboqs builds and runs.
- **Persistent signing key.** `sign()` loads a long-lived keypair from
  `POLARIS_PQC_SIGNING_KEY_FILE` (JSON `{algorithm, secret_key_hex,
  public_key_hex}`) when set, so every signature uses the same key and its public
  key is a stable, publishable **trust anchor**. The ephemeral per-call keypair
  remains only as the dev/test fallback. A malformed key file fails loud (never
  silently degrades). `generate_keypair()` mints one; the real private key
  belongs in an HSM/KMS (operator-custodied) — this is the loading mechanism.

Still ahead in Wave 2 (tracked in `docs/PRODUCTION-READINESS.md`): store the
issuer public key as a DB trust anchor, store the real signature at issuance and
**enforce verification at use**, make real PQC the prod default (liboqs in the
prod image), and route uc6 through the signing module.

- `polaris_web/pqc_signing.py` — `_load_persistent_keypair`, `generate_keypair`,
  persistent-key `sign()`.
- `.github/workflows/ci.yml` — `pqc-real` job (real ML-DSA sign+verify).
- `polaris_web/test_pqc_signing.py` — `PersistentKeyTests` (skip without liboqs).
- `polaris_checks/checks.py` — `check_pqc_real_signing` (34th check).

## v9.102 — 2026-06-05 (production-readiness, wave 3: backups are encrypted at rest, DR doc made honest)

A database backup is a full `pg_dump` of the (would-be) national-identity
database. Shipping it as plaintext on local disk is a BLOCKER. `polaris-backup.sh`
now encrypts the tarball with AES-256-CBC (PBKDF2) when `POLARIS_BACKUP_KEY_FILE`
is set, removes the plaintext, and warns loudly when no key is configured;
integrity is covered by the SHA-256 MANIFEST inside, which the restore verifies
after decryption. `polaris-restore.sh` transparently decrypts `.enc` backups with
the same key and **fails closed** when the key is missing or wrong. Verified
end-to-end locally and in CI: the DR round-trip step now dumps → encrypts →
(negative: refuses without the key) → decrypts → restores → confirms the data.

`DR.md` is also reconciled: it had claimed a wired ≤1-minute RPO via
pgbackrest/WAL/S3 that does not exist. It now states the real RPO (the encrypted
`pg_dump` interval, ~24h) and presents continuous WAL archiving as the
not-yet-configured target (an operator-gated offsite-store decision).

- `scripts/polaris-backup.sh` — optional AES-256 at-rest encryption.
- `scripts/polaris-restore.sh` — decrypt `.enc` backups; fail closed without the key.
- `.github/workflows/ci.yml` — encrypted DR round-trip + no-key negative check.
- `docs/operator/DR.md` — honest RPO; `docs/PRODUCTION-READINESS.md` — Wave 3 ticks.
- `polaris_checks/checks.py` — `check_backup_encryption` (33rd check).

## v9.101 — 2026-06-05 (production-readiness, wave 1: no default credentials, real rate limiting, honest roadmap)

The maintainer asked to make Polaris production-ready. A six-dimension assessment
found 49 properties already production-grade (the seven review passes built a real
base), 45 engineering gaps an agent can close, and 10 that need operator/legal
decisions. The honest gap ledger is now `docs/PRODUCTION-READINESS.md` — nothing
here flips the project to "production-ready"; that claim only becomes true as the
boxes are checked. Wave 1 closes the two BLOCKERs that are pure default-hygiene:

**Demo credentials no longer reach a production database.** The SQL seed loads
`admin/Admin@123!`, `operator/Operator@123!`, `auditor/Auditor@123!` and a demo
duress code — fine for dev, an instant full compromise in production. In
`POLARIS_ENV=production`, `docker-init.sh` now disables those accounts
(is_active=FALSE), scrambles their passwords (so re-enabling can't restore the
known password), locks them, and clears the demo duress enrollment. Rows are
disabled, not deleted, because the append-only audit tables FK to AppUser. The
operator bootstraps the first real admin with `scripts/polaris-create-operator.sh`;
no default credentials ship and `/login` refuses everyone until then.

**The rate limiter actually uses Redis in production.** The prod compose ran a
Redis service but never set `POLARIS_REDIS_URL`, so `security.py` silently fell
back to per-worker in-memory buckets — and prod runs 4 gunicorn workers, so per-IP
brute-force limits fragmented 4x. Now wired to `redis://redis:6379/0`, so the
atomic cross-worker Redis limiter is used.

- `polaris_web/docker-init.sh` — neutralize demo accounts + demo duress code in
  production.
- `polaris_web/docker-compose.prod.yml` — `POLARIS_REDIS_URL`; `POLARIS_ENV` to
  the postgres init container.
- `polaris_checks/checks.py` — `check_prod_hardening` (32nd check) pins both.
- `docs/PRODUCTION-READINESS.md` — the honest roadmap; linked from ROADMAP.

## v9.100 — 2026-06-05 (a successful restore looked like a failure — DR path fixed + CI-validated)

Applying the prod-image lesson (untested operator tooling is silently broken) to
the disaster-recovery path: a backup -> restore round-trip against the test DB
revealed that **a successful restore reported failure**. `pg_restore` returns a
non-zero exit for benign reasons — the `--clean --if-exists` DROPs of
not-yet-existing objects, and version-specific SET directives a newer `pg_dump`
emits that an older target rejects (e.g. `SET transaction_timeout` from a PG17+
dump into PG16). `polaris-restore.sh` treated that exit code as a hard failure
and aborted with "✗ pg_restore failed — DB state may be partial," even though all
30 tables and every row had restored. For a DR tool, that false alarm is the
worst kind: an operator mid-disaster sees "failed," and may discard a perfectly
good restore or thrash.

The restore now judges success by **verifying the outcome** — the core schema
(`identitytoken`) must be present after `pg_restore` — not by the exit code. A
real failure (no schema) still aborts; a benign-warning success reports complete
with a one-line note that the data is verified present. Verified locally: the
same PG18-dump-into-PG16 case now reports success, exit 0.

And the DR path joins the images in CI: a new round-trip step dumps the loaded
DB, restores it into a fresh database, and asserts the data came back — so a
broken backup or restore fails CI, not a real recovery.

- `scripts/polaris-restore.sh` — verify the restored schema; do not fail on
  benign `pg_restore` warnings.
- `.github/workflows/ci.yml` — backup + restore round-trip in the test job.

## v9.99 — 2026-06-05 (launcher: tear the stack down exactly once)

The last of the launcher-audit robustness items. Watch mode has three teardown
paths — the browser quit beacon, the stale-heartbeat timeout, and the
INT/TERM/HUP trap — and the trap was not self-disabling, so a second signal
during teardown (a double Ctrl+C) or a beacon racing the trap re-entered
`stop_all`, printing a spurious banner and a misleading "Nothing running." A new
`_teardown_once` guard runs the teardown once and disarms the trap as soon as it
begins; all three paths route through it. Verified: a second call is a clean
no-op.

(The other audit item — `preflight_port` whitelisting any `python` listener — is
left as is on purpose: the broad match is what lets the launcher recognise and
restart its own prior gunicorn, and tightening it via PID matching would risk
breaking that common relaunch path for a rare edge case.)

- `polaris_mac_launch.sh` — `_teardown_once` guard; the trap and both watch-loop
  teardown paths use it.

## v9.98 — 2026-06-05 (the production image could not be built — fixed and CI-validated)

Investigating whether CI should validate the prod image surfaced that the prod
image **could not be built at all**. `Dockerfile.prod`'s Rust stage COPYs
`polaris_zk/` (a sibling of `polaris_web/`, so it needs the repo root as the
build context), while its app stages COPY bare `app.py` / `static/` / `templates/`
(which only resolve from a `polaris_web/` context). Docker COPY cannot escape its
context, so no single context satisfies both — and `polaris-deploy.sh prod`
(which runs `docker compose -f docker-compose.prod.yml build`, context
`polaris_web/`) failed at the Rust stage. The deploy artifact was broken.

The fix: build from the repo root, with repo-root-relative app paths.
`docker-compose.prod.yml` now sets `context: ..` + `dockerfile:
polaris_web/Dockerfile.prod`, and every app-file COPY in `Dockerfile.prod` is
prefixed `polaris_web/`. Verified: the prod image now builds (multi-stage Rust +
Python) and boots — gunicorn brings up all four workers with no import crash.

To keep it that way, the `docker-image` CI job now also builds the prod image
(buildx + gha cache, so the Rust layer stays warm) and smoke-boots it (asserts
the gunicorn workers come up and the logs carry no `ModuleNotFoundError` /
`ImportError` / `Traceback`). Both Polaris images — dev (built + booted + route-
smoked) and prod (built + boot-smoked) — are now validated on every push.

- `polaris_web/Dockerfile.prod` — repo-root-relative app COPY paths + a context note.
- `polaris_web/docker-compose.prod.yml` — `context: ..`, `dockerfile: polaris_web/Dockerfile.prod`.
- `.github/workflows/ci.yml` — build + boot-smoke the prod image (buildx@v4,
  build-push@v7, current majors).

## v9.97 — 2026-06-05 (the launcher is honest about the Docker ZK degradation)

The Docker dev image ships without the Rust ZK prover by design (README: "the
compiled binary does not ship; the app degrades gracefully"). The native path
builds it (v9.93), but on the Docker path that degradation was silent — a user
only found out when `/api/zk/verify` returned a 400. The project's discipline is
no silent degradation, so the launcher now says it at bring-up: the Docker dev
image has no ZK prover, every page serves and `/epochs` renders the seeded
epochs, only NEW epoch close/verify need it, and `up --native` gives the full ZK
demo. Nothing is hidden; the user knows exactly what works and how to get the
rest.

Also: `--help` no longer leads with the machine-readable `AI-context:` line. It
starts at the human title (the audit flagged this).

- `polaris_mac_launch.sh` — docker post-launch hints state the ZK degradation +
  the `--native` path to it; `usage()` skips the AI-context header line.

## v9.96 — 2026-06-05 (the launcher tells you WHY it failed)

When the v9.94 Docker crash happened, the launcher printed "Web app failed to
start. View logs: ./polaris_mac_launch.sh logs app" and stopped there. The actual
cause (`ModuleNotFoundError: No module named 'pqc_signing'`) was one `logs app`
command away, but the launcher made you go find it. A launch tool should hand you
the error, not a place to look for it.

The docker bring-up failure path now prints the diagnosis inline: the app
container state (including restart count, the crash-loop tell), and the last 30
lines of the app log — which is exactly where the real startup error lives. It
also distinguishes the two failure modes that used to collapse into one opaque
message: it no longer proceeds to wait for the web app when the database never
became healthy (the app cannot start without it), and it shows the db logs in
that case. The native path got the same treatment — on a gunicorn boot failure it
prints the last 30 log lines instead of just telling you to tail them.

Verified end-to-end: a fresh `up --docker` still brings the stack up clean
(database healthy → LIVE → 200), and the diagnostic dump surfaces the container
state + recent logs.

- `polaris_mac_launch.sh` — `_wait_db_healthy` + `_report_docker_bringup_failure`
  helpers; the heal path gates the app wait on real DB health; native failure
  dumps the log tail.

## v9.95 — 2026-06-05 (CI now builds and boots the Docker image)

v9.94 fixed the missing-module crash and added a static check that the COPY list
covers `app.py`'s imports. But the deeper reason a broken image shipped green for
~36 versions is that **CI never built or ran the image** — the `test` job
exercises the app code against a native Postgres. A bad build step, a runtime
import error from a transitive module, or a broken entrypoint would still pass.

A new `docker-image` CI job builds the dev image, brings up the full stack
(`docker compose up -d --build`), waits for the app to serve `/api/health`, and
smoke-tests `/login`, `/api/health`, and `/metrics` (all 200), then tears down.
It runs in parallel with the `test` job. The exact v9.94 failure
(`ModuleNotFoundError` crash-loop) now fails this job with the container logs
attached, instead of surfacing on a user's machine.

- `.github/workflows/ci.yml` — new `docker-image` build + boot smoke-test job.
- `polaris_web/docker-compose.yml` — drop the obsolete top-level `version: '3.9'`
  key (Compose v2 ignores it and warns; it showed up in the crash logs).

## v9.94 — 2026-06-05 (the Docker image was missing pqc_signing.py — crash-loop fixed and guarded)

The Docker path crash-looped on startup: `ModuleNotFoundError: No module named
'pqc_signing'`. `app.py` has imported `pqc_signing` since v9.58, but neither
`Dockerfile` nor `Dockerfile.prod` was updated to COPY it into the image, so the
gunicorn worker failed to boot and the container restarted forever. The native
path was unaffected (it runs `app.py` from the source tree), which is why this
stayed latent until a Docker launch hit it — the launcher's default when Docker
Desktop is installed.

Both Dockerfiles now COPY `pqc_signing.py`. Verified: a rebuilt image comes up
healthy and serves `/login`, `/metrics`, and `/api/health` (all 200).

This is the same class of bug that bit `observability.py` in v9.40 — a local
module added to `app.py`'s imports but not to the image COPY — and the only guard
was a narrow doctor check hard-coded to `security.py`. A new machine check closes
the class generally:

- `polaris_web/Dockerfile`, `polaris_web/Dockerfile.prod` — COPY `pqc_signing.py`.
- `polaris_checks/checks.py` — `check_dockerfile_copies_app_modules` (31st check)
  resolves every LOCAL module `app.py` imports (tolerating trailing comments, the
  v9.40 failure mode) and asserts BOTH images COPY each one. `test_checks.py`
  discriminates across the dev-missing, prod-missing, and complete cases.

## v9.93 — 2026-06-05 (the macOS launcher: current, faster, and pinned)

The launcher (`polaris_mac_launch.sh`, header was v2.5 / 2026-05-08) had drifted
~37 ships behind the stack. A six-dimension audit (deps, ZK binary, test runner,
startup speed, stack parity, robustness) surfaced the gaps; the load-bearing ones
are fixed and pinned with a check.

**Native dependencies (HIGH).** The native path hard-coded `pip install flask
psycopg2-binary gunicorn werkzeug webauthn` — 5 unpinned packages — while the
Docker image and CI both install from `requirements.txt` (23 pinned). It missed
`prometheus_client` (so `/metrics` was dead), `redis` (so cross-worker rate
limiting fell back to per-worker in-memory under the 2 workers it runs), and
`hypothesis` + `pytest` (so the property and ZK two-witness suites ImportError'd).
The native path now installs from `requirements.txt`, skipping the install when
the file is unchanged (sha256 marker). The venv is recreated when it is not
Python 3.12 (an older interpreter cannot install the pinned set).

**ZK prover (HIGH).** Neither launch path built the Rust `polaris-zk` binary, so
`/api/zk/*` was silently dead on a fresh extraction — the headline
zero-knowledge feature off with no warning. A new `build_zk_binary()` builds it
when cargo is present (mtime-cached so warm relaunches pay nothing), exports
`POLARIS_ZK_BINARY`, and degrades cleanly with a clear message when Rust is
absent. (The dev Docker image still omits it by design — a macOS host binary
cannot run in the Linux container; `doctor` says so.)

**Test runner (HIGH).** `test` ran only `test_app.py` + `test_cli.py`. It now runs
the canonical suite from CLAUDE.md/CI: `polaris_checks.run`, the four DB web
suites (constraints, invariants, redaction, app), the CLI suite, the ZK
two-witness pytest suites, and the cargo circuit tests — in the venv, via
`-m unittest`, against the loaded DB (no live app needed).

**Startup speed + safety (MEDIUM).** `brew install` runs only for missing
formulae; the schema reload is skipped when the DB is already loaded (the old
code re-ran `00_load_all.sql` on every launch, which TRUNCATEs every table and
wiped user data); native gunicorn now connects as the unprivileged `polaris_app`
role (explicit creds), so the native run exercises the same v9.85 append-only
boundary as production instead of leaning on localhost trust as a superuser.

- `polaris_mac_launch.sh` — all of the above + `doctor` now reports venv-vs-
  requirements, the ZK binary, and the Rust toolchain; `reset` drops the native
  DB so the next `up` reloads; header bumped to v2.6.
- `polaris_web/docker-compose.yml` — drop a stale `soldier_log_tail` comment
  (removed v9.55 apparatus).
- `polaris_checks/checks.py` — `check_launcher_current` (30th check) pins the
  three properties that drifted: deps from requirements.txt, the canonical test
  suite, and the ZK build. `test_checks.py` discriminates across four cases.

## v9.92 — 2026-06-04 (un-stale the README table count, and guard it)

The honesty pass turned up one more drift: `README.md` said "26 schema tables"
while the schema reached 27 in v9.89 (the `ZkVerificationNonce` anti-replay
store). `check_table_count_matches_doc` only guarded
`docs/ARCHITECTURE-OVERVIEW.md`, so the README count drifted unchecked — the
same class of stale-doc defect this honesty pass exists to close.

- `README.md` — "26 schema tables" → "27 schema tables".
- `polaris_checks/checks.py` — `check_table_count_matches_doc` now guards BOTH
  the architecture doc ("N tables") and the README ("N schema tables") against
  the real `CREATE TABLE` count, so neither can drift unnoticed again.
  `test_checks.py` covers the new README path (architecture-doc-correct-but-
  README-drifts now FAILs).

## v9.91 — 2026-06-04 (honesty: the thesis terminus passed, so the docs now say so)

With the forward roadmap's actionable items shipped, a multi-agent honesty audit
swept every headline claim (thesis, post-quantum, zero-knowledge, compulsion-
resistance, general "production/validated/proven" language) against what the code
actually does. The verified finding is the one the ROADMAP already flagged as an
**active dishonesty**: the thesis terminus.

`MISSION.md`'s freeze line carries a mechanical abandonment clause: "if no
cold-read attempt occurs by v9.40 ... the thesis is documented as inconclusive
and the strong claim is retired permanently." No external cold read ever happened
(only the author's own walkthrough, which `docs/THESIS.md` itself admits is not a
cold read), and the repository is now far past v9.40. So the outcome was already
decided by the constitution. But `docs/THESIS.md` still read as an *open*
experiment: status `HYPOTHESIS-NOT-VERIFIED`, "the thesis is not refuted, it is
unverified," "keep the status honest until a real cold read happens." Leaving the
softer wording past the deadline is itself the dishonesty the project forbids.
`THESIS.md` also never actually stated the v9.40 terminus that `MISSION.md` cites
it for.

`docs/THESIS.md` now reflects the terminal state the constitution mandates: status
**INCONCLUSIVE**, the strong legibility claim **retired permanently**, the v9.40
terminus stated explicitly, and the disposition closed by default (a future cold
read could reopen it only through an explicit, recorded maintainer decision, never
an automatic flip). The falsification test stays documented for anyone who later
runs it. `MISSION.md`'s freeze line is untouched (it is un-amendable here); this
only makes `THESIS.md` honor it.

Two README accuracy fixes rode along: a hardcoded "Now shipping v9.63" that had
gone 28 versions stale is now a non-versioned "the latest release" link, and the
"the operational default is already post-quantum" line is scoped to the algorithm
of record (the real ML-DSA-65 signature bytes need `POLARIS_USE_REAL_PQC=1`; the
default build records a deterministic placeholder, as the crypto section already
disclosed six lines down).

- `docs/THESIS.md` — status + terminus + retirement, reconciled throughout.
- `README.md` — un-stale the version link; scope the post-quantum-default claim.
- `polaris_checks/checks.py` — `check_thesis_terminus_honest` (29th check):
  past v9.40, `THESIS.md` must read as retired/inconclusive, never the open
  framing. Version-aware; `test_checks.py` discriminates across five cases.

## v9.90 — 2026-06-04 (CI: bump the deprecated Node 20 actions ahead of the deadline)

CI was annotating every run: `actions/checkout@v4` and `actions/setup-python@v5`
run on Node.js 20, which GitHub force-migrates to Node 24 on **2026-06-16** and
removes on **2026-09-16**. Bumped both to the current major (verified latest via
the GitHub API: `checkout@v6.0.3`, `setup-python@v6.2.0`), which run on Node 24:

- `.github/workflows/ci.yml` — `actions/checkout@v4` → `@v6`,
  `actions/setup-python@v5` → `@v6`.

A pure CI-hygiene change; the workflow's own green run on the bumped actions is
the verification. Clears ROADMAP "Next ships" #3.

## v9.89 — 2026-06-04 (real anti-replay: /api/zk/verify consumes a single-use nonce)

The review arc converged at v9.88, so this picks up the top of the forward
ROADMAP. `/api/zk/verify` binds a proof to `(epoch_id, context_id, nonce)`. That
binding prevents proof *substitution*, but on its own it does NOT prevent
*replay*: a verified bundle, captured off the wire, verifies again every time it
is resubmitted. The R2 "replay resistance" claim was only true for substitution.

`/api/zk/verify` now consumes the nonce. On a verified result it inserts
`(epoch_id, context_id, nonce)` into a new single-use store; a second submission
of the same tuple hits the primary key (`INSERT ... ON CONFLICT DO NOTHING`
returns no row) and is rejected with `verified: false, reason: "nonce already
consumed (replay)"`. Consumption happens only *after* a true verify, so a failed
proof never burns a nonce a legitimate later proof might use, and the insert is
atomic so two concurrent replays serialize on the PK — exactly one wins. Closes
threat-model T-T2; makes R2 hold in code.

The store holds **no identity** — only the spent `(epoch, context, nonce)` tuple
and the consume time, so it cannot say *who* verified, only that this tuple was
spent (Vocation). It is append-only at the privilege layer: `09_grants.sql`
revokes UPDATE/DELETE on it from `polaris_app`, because a consumed nonce must
never be un-consumed (that re-opens the replay window).

- `polaris_sql/01_schema.sql` — new `ZkVerificationNonce` table (27 tables now).
- `polaris_sql/migrations/2026-06-04-001-zk-verification-nonce.{up,down}.sql` —
  the table + append-only REVOKE for already-deployed databases.
- `polaris_sql/04_data.sql` — added to the reload TRUNCATE set (test isolation).
- `polaris_sql/09_grants.sql` — UPDATE/DELETE revoked from `polaris_app`.
- `polaris_web/app.py` — `/api/zk/verify` consumes the nonce, rejects replays.
- `polaris_checks/checks.py` — `check_zk_verify_anti_replay` (28th check).
- `polaris_web/test_app.py` — `test_api_zk_verify_replay_is_rejected` (e2e:
  first verify succeeds, the identical bundle is rejected, nonce recorded once).

## v9.88 — 2026-06-04 (pass 7 converges: a false redaction comment, and a Vocation guard for the evidence trail)

A seventh adversarial review pass over six surfaces no prior pass had swept:
template/DOM XSS, crypto-correctness (the ML-DSA-65 vs SHA3 placeholder path),
C6 disclosure on the non-atlas read paths, the multi-step token state machine,
the witness2 second-witness math, and audit-record content through the
anti-coercion lens. **Zero security defects survived verification** — the
hardening arc has converged. The one actionable item was a documentation defect.

**A schema comment falsely claimed a column was ZK-redacted (LOW).**
`VerificationEvent.requesting_purpose_text` (the operator-supplied reason for a
verification) carried the inline comment "Like requestor_location, it is
identifying-disclosure and is redacted for ZERO_KNOWLEDGE rows at read." That is
false on both counts. The column is written on every disclosure level and is
redacted *nowhere* — by design: it is the anti-coercion evidentiary trail (a
coerced verification leaves the coercer's stated purpose on the permanent
record; see migration `2026-05-15-002` and the verifications form's own help
text). `requestor_location`, by contrast, genuinely *is* ZK-redacted at the read
paths (C6, pass-3). A future engineer trusting the comment would either assume a
protection that does not exist or "fix" the missing redaction and silently
destroy the Vocation feature.

The comment is corrected to describe the deliberate retention (and to note it
does not weaken C2 — a ZERO_KNOWLEDGE row still carries no `token_id`). To stop
the confusion from recurring as a real regression, a new Vocation check now
guards the evidence trail:

- `polaris_sql/01_schema.sql` — accurate comment on `requesting_purpose_text`.
- `polaris_checks/checks.py` — `check_coercion_evidence_retained` (27th check):
  fails if the schema falsely documents the trail as ZK-redacted, or if any read
  path NULLs it for ZERO_KNOWLEDGE rows (which would destroy the anti-coercion
  evidence). `test_checks.py` discriminates across four cases.

With pass 7 returning no security findings, the multi-pass adversarial review
(v9.64–v9.88, ~37 real findings fixed across seven passes) has converged.

## v9.87 — 2026-06-04 (pass 6: close the two trust-boundary gaps prior passes left)

A sixth adversarial review pass (six surfaces not deeply covered before: the
un-reviewed procedures, the ZK subprocess boundary, session/auth internals,
transaction-isolation concurrency, route input/authz, migration/AoR integrity).
Four of six dimensions came back clean; two findings survived independent
verification. Both are cases where an earlier pass closed a *class* of issue but
left exactly one path uncovered.

**`verify()` panicked on a malformed proof (MEDIUM).** v9.84 added a bounds
check to `prove()` and the CHANGELOG claimed "compute-root/compute-leaves/verify
all return clean Errs for malformed input." `verify()` did not. It ran
`ProofWithPublicInputs::from_bytes(...)?` and then indexed
`proof.public_inputs[0..4]` (and `[4]`, `[5]`, `[6]`) with no length check.
Plonky2's `from_bytes` reads the public-input *count* straight from the
caller-supplied buffer and does not constrain it to the circuit's count until
the cryptographic verify, so a crafted proof deserializes `Ok` with a short
`public_inputs` vector and the slice panics — process abort (exit 101).
Reproduced deterministically: an all-zero `proof_hex` the length of a real proof
(155600 hex chars) crashed at `lib.rs:329`. Reachable by any authenticated user
via `POST /api/zk/verify`. It is fail-closed (the panic is before
`verifier_data.verify()`, so it can never make an invalid proof verify true) and
each verify is an isolated per-request subprocess (the crash is contained to that
child, HTTP 400 — not a worker DoS), hence MEDIUM. `verify()` now returns
`Ok(false)` when `public_inputs.len() < 7`. Confirmed: the same input now returns
`{"verified":false}`, exit 0.

**Inactive-account login was a timing oracle (LOW).** `authenticate()` defends
the unknown-user path with a dummy scrypt verify so a not-found username costs
the same as an active account with a wrong password. But the inactive-account
branch (`if not user['is_active']`) returned *before* any hashing — ~0ms vs
~scrypt — so an unauthenticated attacker could enumerate deactivated accounts by
response time (CWE-208), the exact leak the dummy hash closes for not-found
users. The password verify now runs *before* the inactive/locked branching, so
every existing-user path does the same scrypt work.

- `polaris_zk/src/lib.rs` — `verify()` length guard + `verify_rejects_malformed_proof_without_panicking` (8 ZK tests).
- `polaris_web/security.py` — hash before the account-state branch.
- `polaris_web/test_app.py` — `test_inactive_account_is_not_a_timing_oracle` (spies on the hash call; deterministic, not wall-clock).

## v9.86 — 2026-06-04 (prod syncs the polaris_app role password to the generated secret)

A deploy finding from the fifth review pass. In the production stack the app and
pgbouncer both authenticate as `polaris_app` using the file-mounted secret
`/run/secrets/polaris_db_password`. But `09_grants.sql` creates the role with the
dev default `'polaris_dev_password'`, and the **postgres** service never set
`POLARIS_APP_PASSWORD`, so `docker-init.sh` skipped its rotation block: the role
kept the dev password while every client presented the generated one. The result
is either a broken prod stack (authentication fails) or — if a deployer papered
over it by reusing the dev string — the dev password live in production.

`docker-init.sh` already had the ALTER-ROLE machinery; it was simply never fed
the secret. Now:

- **docker-compose.prod.yml** — the postgres service sets
  `POLARIS_APP_PASSWORD_FILE: /run/secrets/polaris_db_password`, the SAME secret
  the app reads. (The secret was already mounted into the service.)
- **docker-init.sh** — reads `POLARIS_APP_PASSWORD_FILE` (the `*_FILE` convention
  the rest of the stack uses, G28) and ALTERs `polaris_app` to it. `cat` strips
  the trailing newline, matching the app's `_read_secret_file().read().strip()`,
  so the role password and the clients' password compare byte-for-byte.
- The complexity gate is now entropy-aware: the absolute floor is 16 chars; a
  password under 24 chars must still mix digit + letter + symbol, but a 24+ char
  secret passes on length alone — the generated secret is 48 hex chars
  (`openssl rand -hex 24`, ~192 bits) and has no symbol by construction, so the
  old blanket symbol rule would have rejected our own secret.
- **polaris_checks** — `check_prod_app_password_synced` (26th check) asserts the
  compose role-password secret matches the app's and that docker-init reads it
  and ALTERs the role. `test_checks.py` discriminates across five failure modes.

## v9.85 — 2026-06-04 (C1 append-only becomes a privilege boundary, not only a trigger)

The thesis finding from the fifth review pass. C1 — audit-of-record, enforced at
the database level — was enforced only by the `reject_audit_modification()`
trigger, and that trigger has a carve-out: it permits UPDATE/DELETE when the
custom GUC `polaris.purge_in_progress` is `'TRUE'`. Any role can `SET` a custom
GUC. So the application role could bypass the whole append-only invariant:

```sql
-- as polaris_app, before v9.85:
SET LOCAL polaris.purge_in_progress = 'TRUE';
DELETE FROM TokenLifecycleEvent WHERE event_id = ...;   -- DELETE 1  (forged history)
```

Confirmed empirically against the live role. The trigger was the only thing
standing between `polaris_app` and a rewritten audit-of-record — exactly the
property C1 exists to make impossible.

**The grant model now backs the trigger.** `polaris_app` keeps SELECT + INSERT
(append-only IS insert-allowed) but loses UPDATE/DELETE on every append-only
table: TokenLifecycleEvent, VerificationEvent, EnrollmentStatusEvent, AnchorBatch,
TokenStateEpochLeaf, DuressEvent, AuthAuditLog, and AuditAccessLog. Now the
carve-out is unreachable from the app role — the ACL refuses the statement before
the trigger ever fires:

```sql
-- as polaris_app, v9.85:
SET LOCAL polaris.purge_in_progress = 'TRUE';
DELETE FROM TokenLifecycleEvent WHERE event_id = ...;   -- ERROR: permission denied
```

The one legitimate DELETE path, `uc_archive_purge`, is now `SECURITY DEFINER`
(with a pinned `search_path`) so it runs the purge with the procedure owner's
rights inside its existing admin-gated, checkpoint-writing transaction. It
authenticates the actor by the `p_actor_user_id` PARAMETER against `AppUser.role`
— never `current_user`/`session_user` — so elevating to the owner does not weaken
the admin gate. Verified: an admin purge still deletes; `polaris_app` calling it
still works; direct UPDATE/DELETE stays denied; INSERT still succeeds.

- `polaris_sql/09_grants.sql` — REVOKE UPDATE, DELETE on the base append-only
  tables from `polaris_app` (to_regclass-guarded loop, robust to load order).
- `polaris_sql/migrations/2026-05-15-003-audit-access-log.up.sql` — carries the
  matching REVOKE for the table it adds.
- `polaris_sql/05_procedures.sql` — `uc_archive_purge` is SECURITY DEFINER.
- `polaris_checks/checks.py` — `check_aor_privilege_boundary` (C1, 25th check):
  asserts the REVOKEs and the SECURITY DEFINER declaration. `test_checks.py`
  discriminates across five failure modes.
- `polaris_web/test_check_constraints.py` — `TestC1PrivilegeBoundary` opens an
  explicit `polaris_app` connection and proves the boundary end to end.

## v9.84 — 2026-06-04 (uc1 refuses deprecated algorithms; the ZK prover bounds-checks its index)

Two findings from a fifth review pass (the procedures uc1-uc6 and the Rust crate).

**uc1 minted tokens under a deprecated algorithm (MEDIUM).** `uc1_issue_and_activate`
validated only that the issuing agency held ISSUE/BOTH authorization on the
algorithm — never its `deprecation_date`. So a brand-new ACTIVE token could be
issued under a retired/weakened (potentially pre-quantum) algorithm.
`uc6_migrate_algorithm` already refuses to migrate a token *to* a deprecated
algorithm, so the system already treats "deprecated" as a state that must block new
signatures — uc1 was the asymmetric gap. uc1 now performs the same deprecation
check before any writes.

**The ZK prover panicked on an out-of-range index (LOW).** `polaris_zk::prove`
used the caller-supplied `leaf_index` (`all_leaves_hex[leaf_index]`, and inside
plonky2) with no bounds check, so an index past the real leaf count aborted the
process (exit 101) instead of returning an error — `compute-root`/`compute-leaves`/
`verify` all return clean `Err`s for malformed input. `prove` now validates
`leaf_index < all_leaves_hex.len()` and returns the crate's `Result` error.

- `polaris_sql/05_procedures.sql` — uc1 deprecation guard.
- `polaris_zk/src/lib.rs` — `prove` index bounds check.
- `polaris_web/test_check_constraints.py` — `TestUC1Issuance` (deprecated rejected,
  live succeeds). Rust: the 7 circuit tests pass; the binary returns a clean error.

## v9.83 — 2026-06-04 (bound three unbounded resources an attacker could grow)

The fourth review pass found three places where memory or metric cardinality grew
without bound, the last two reachable by an unauthenticated / IP-rotating client.

- **Prometheus `/metrics` cardinality (MEDIUM, memory DoS).** The per-request
  metric label was `request.endpoint or request.path or 'unknown'`. On a 404,
  `request.endpoint` is None, so the label fell back to the raw, attacker-controlled
  URL path — every `GET /<random>` minted a new label series (~1 counter + ~15
  histogram buckets) that the Prometheus client retains for the process lifetime.
  Now the label is `request.endpoint or 'unmatched'` (a bounded set; no path).
- **In-memory rate-limiter key map (LOW, slow memory leak).** `_buckets` was a
  `defaultdict(deque)` that accrued one entry per distinct `login:<ip>` /
  `write:<ip>` key forever (an attacker rotating IPs, or spoofing `X-Forwarded-For`
  under `POLARIS_TRUST_PROXY`, leaks one entry each). It is now an LRU-ordered
  `OrderedDict` capped at 50,000 keys, evicting least-recently-used beyond the cap.
- **Dashboard `ActiveTokens` query (LOW).** The default post-login landing page ran
  `SELECT * FROM ActiveTokens` with no bound, materializing every active token on
  every load — the exact national-scale hazard `individuals_list` paginates against.
  Capped to the 200 most recent.

- `polaris_web/app.py` — metric label bounded; dashboard query capped.
- `polaris_web/security.py` — `InMemoryRateLimiter` is an LRU-capped `OrderedDict`.
- `polaris_web/test_app.py` — `ResourceBoundTests`: the key map stays bounded; a
  404 path never appears as a metric label.

## v9.82 — 2026-06-04 (duress: record off the request thread so the response time reveals nothing)

The whole point of the duress mechanism is that a coerced verification is
indistinguishable from a normal one. But the duress-match branch did strictly
more synchronous work than a non-match: on a match it opened a SECOND database
connection and committed (a WAL fsync) before the request returned, a
deterministic added latency a coercer timing the response could measure to
distinguish a duress code from a real one. The docstring's claim that the variance
was "dominated by Flask overhead" understated this.

Fix: the silent DuressEvent is recorded on a background daemon thread by default,
so the synchronous response time is identical whether or not a duress code
matched (the request returns after a microsecond-scale thread spawn regardless of
outcome). Durability is verified by a test that polls for the async write;
operators who prefer the alarm committed before the response returns can set
`POLARIS_DURESS_SYNC=1` (tests use it for deterministic assertions).

Also documented honestly that duress is inherently token-bound (the silent alarm
must identify the token to look up its enrolled hash), so it cannot apply to a
pure ZERO_KNOWLEDGE verification that deliberately hides the token — the form
field now notes it applies only with a token reference, rather than implying it
works everywhere.

- `polaris_web/app.py` — `_record_duress_async` + the default-async dispatch; the
  R2 timing note corrected; the ZK-duress limitation documented at the call site.
- `polaris_web/templates/verifications_form.html` — the duress field notes it
  applies only with the token reference (kept obfuscated, no "duress" wording).
- `polaris_web/test_app.py` — sync-mode determinism + an async-durability test.

## v9.81 — 2026-06-04 (the no-cascade invariant now covers migrations, and the one live cascade is resolved)

The fourth review pass found that `check_no_fk_cascade` — which enforces the
no-`ON DELETE/UPDATE CASCADE` invariant (no silent cascade deletion) — globbed only
top-level `polaris_sql/*.sql`, not `migrations/`. The one cascade in the whole tree,
`OperatorWebauthnCredential.user_id REFERENCES AppUser ON DELETE CASCADE` (migration
2026-05-14-002), was therefore live and unflagged — and the gap let any future
migration smuggle in a genuinely destructive cascade (e.g. on an audit-of-record FK)
past a green check.

Fix: `check_no_fk_cascade` now scans the base schema AND every migration, and the
cascade is resolved to `ON DELETE NO ACTION` (the schema-wide default). Deletion of
an operator with enrolled WebAuthn credentials is now explicit — the credentials
must be removed first — rather than a silent cascade; operators are deactivated, not
deleted, in normal operation, and credential lookup is unaffected.

- `polaris_checks/checks.py` — `check_no_fk_cascade` scans `migrations/` too
  (+ detection test placing a cascade in a migration fixture).
- `polaris_sql/migrations/2026-05-14-002-operator-webauthn.up.sql` — the FK is
  `ON DELETE NO ACTION`. Verified: a fresh build's FK is NO ACTION, webauthn green.

## v9.80 — 2026-06-04 (operator scripts: validate argv to close four SQL injections)

A fourth review pass (residual surfaces: anchoring, dashboard, duress, schema
constraints, observability, operator scripts) found the operator shell scripts
interpolate unvalidated argv straight into superuser `psql -c` statements. Since
`psql -c` runs multiple semicolon-separated statements, a crafted argument
executes arbitrary SQL as `postgres`:

- **`polaris-recover-admin.sh --target`** (HIGH) — the emergency password-login
  recovery flow; `--target` was only checked non-empty, then interpolated into
  three `psql -c` statements (the recovery-code hash lookup, the admin check, the
  audit INSERT). A value like `x'; <SQL>; --` injects, and an `' OR '1'='1`-style
  value could subvert which row's recovery hash is compared.
- **`polaris-purge.sh --actor-user-id`** (HIGH) — the one script whose job is to
  DELETE from audit tables; `--actor-user-id` was interpolated bare into the
  destructive `CALL uc_archive_purge(...)`.
- **`polaris-migrate.sh --actor-user-id`** (MEDIUM) — interpolated into the
  append-only `schema_version` INSERT.
- **`polaris-archive.sh --cutoff-days`** (MEDIUM) — interpolated into an
  `interval '... days'` literal it could break out of.

Fix: each SQL-bound argument is now regex-validated immediately after parsing —
usernames against `^[a-z0-9._-]{3,50}$`, ids/days against `^[0-9]+$` (migrate
also allows the `NULL` default) — and the script exits with a usage error before
any psql runs. `check_operator_scripts_validate_argv` guards all four (the check
layer is now 24).

- `scripts/polaris-recover-admin.sh`, `polaris-purge.sh`, `polaris-migrate.sh`,
  `polaris-archive.sh` — argv validation.
- `polaris_checks/checks.py` — `check_operator_scripts_validate_argv` + detection.

## v9.79 — 2026-06-04 (schema completeness: 01_schema.sql declares every column the app writes)

The review noted that `VerificationEvent.requesting_purpose_text` existed only in
a migration, not in `01_schema.sql`'s `CREATE TABLE` — so a fresh build from
`01_schema.sql` alone lacked a column the app writes. A sweep found two more in
the same state: `AppUser.webauthn_required_after` and `AppUser.recovery_code_hash`.
The supported build (`00_load_all` + migrations) was always complete, but the
canonical schema file read on its own was not, and a cold reader would miss them.

Fix: all three columns (and their CHECK constraints) are now declared in
`01_schema.sql`, and the three migrations that add them are idempotent
(`ADD COLUMN IF NOT EXISTS`, guarded `ADD CONSTRAINT`), so on a fresh load the
column already exists and the migration is a no-op, while on an older deployed
database the migration still adds it. `check_no_migration_column_drift` cross-checks
every migration `ADD COLUMN` against `01_schema.sql`, so this drift cannot recur
(the check layer is now 23).

This also closes the review's note that `requesting_purpose_text` and
`requestor_location` are identifying-disclosure: both are documented as such in the
schema, and v9.77 already redacts `requestor_location` for ZERO_KNOWLEDGE rows at
every read path (`requesting_purpose_text` is an intentional anti-coercion
evidentiary field that no read path exposes).

- `polaris_sql/01_schema.sql` — the three columns + CHECKs declared.
- `polaris_sql/migrations/*.up.sql` — the three column migrations made idempotent.
- `polaris_checks/checks.py` — `check_no_migration_column_drift` + detection test.

## v9.78 — 2026-06-04 (atlas event feed: a full-precision cursor stops dropping sub-second events)

The atlas event feed (`/api/atlas/events`) paginates by the keyset cursor
`(event_timestamp, event_id)`, but built the cursor's timestamp from
`to_char(event_timestamp, 'HH24:MI:SS')` — whole seconds, floored. `atlas_recent_events`
then filters with a strict `(event_timestamp, event_id) < (cursor_ts, cursor_id)`.
So if the last row of a page had true timestamp `S.f` (f>0), the cursor became
`S.000000`, and every event in the open band `(S.000000, S.f)` was excluded from
the next page even though it was never shown on the previous one — silently
dropped from the feed. The infinite-scroll frontend re-feeds the cursor, and no
test exercised cross-page pagination.

Fix: the route now emits the cursor from a full-microsecond
`to_char(event_timestamp, 'HH24:MI:SS.US')` value (the human-readable whole-second
display column is unchanged), matching the full-precision pattern `/verifications`
already uses. The internal cursor field is kept out of the JSON body.

- `polaris_web/app.py` — `api_atlas_events` builds the cursor at microsecond
  precision.
- `polaris_web/test_app.py` — `AtlasEventCursorTests` inserts five events in one
  whole second with distinct microseconds: the full-precision cursor skips none,
  and a whole-second cursor demonstrably drops the sub-second band (proving why
  the fix is needed).

## v9.77 — 2026-06-04 (C6: a ZK verification's location is redacted at every read path, not just the warrant audit)

A third review pass (fresh dimensions: templates/XSS, C6 redaction, migrations,
atlas/C8, ZK circuit soundness, substrate SQL) returned clean on four of six —
notably the Plonky2 inclusion circuit is properly constrained — but found a
HIGH C6 disclosure escalation.

`uc7_warrant_audit` (admin/auditor only) deliberately NULLs `requestor_location`
for `ZERO_KNOWLEDGE` verifications, because a precise location is exactly the
spatial side-channel that de-anonymizes a ZK holder (co-locate it with a
SELECTIVE/FULL event). But that redaction lived in *one* place. Every other read
path — all reachable by any authenticated user with no role gate — exposed the
exact ZK location:

- `/verifications` (`verifications_list`) selected `ve.*` and printed
  `requestor_location` for ZK rows.
- `/api/atlas/points` (`atlas_points_verifications`) returned ZK lat/lon +
  location; the map plotted each ZK event at its exact coordinates.
- `/api/atlas/clusters` averaged ZK coordinates into grid cells (a single-ZK cell
  leaks the exact point).
- `/api/atlas/events` (`atlas_recent_events`) returned ZK lat/lon + the location
  subtitle.
- `/atlas` ran its own globe query selecting `requestor_location` for ZK events.

Fix: ZERO_KNOWLEDGE verifications never appear on the spatial map and never carry
a location anywhere. The points and cluster layers exclude ZK; the event feed and
the globe NULL its coordinates and location text; the `/verifications` list
projects `requestor_location` through the same redaction CASE uc7 uses (it stopped
using `ve.*`). ZK activity is still counted non-spatially by `atlas_stats`.
`check_c6_atlas_redacts_zk_location` guards every path against regression.

- `polaris_sql/11_atlas.sql`, `polaris_web/app.py` — redaction at all five paths.
- `polaris_checks/checks.py` — `check_c6_atlas_redacts_zk_location` (22 checks).
- `polaris_web/test_app.py` — `ZKLocationRedactionTests` seeds a ZK event with a
  secret location and asserts it appears nowhere across the atlas + list paths.

## v9.76 — 2026-06-04 (/api/health stops leaking infrastructure detail to anonymous callers)

The last finding from the deeper review's error-disclosure pass. `/api/health`
is intentionally unauthenticated (load-balancer and uptime probes), but its
per-component checks echoed operator-only detail to anyone: `_health_check_database`
and `_health_check_redis` returned `str(exc)[:160]` on failure — and a psycopg2
connection error embeds the DB host, port, and database name — while
`_health_check_zk_binary` returned the binary's absolute path on every call and
`_health_check_disk` returned the state-dir probe path. Any anonymous client could
read internal topology, especially during an outage (CWE-209).

Fix: `_sanitize_health_checks` strips the sensitive keys (`error`, `path`,
`mount_probe`) from the response and logs them to stderr for operators instead.
The per-component `status` tokens — which is all a probe needs — are preserved, so
load balancers still see healthy/degraded/unhealthy.

- `polaris_web/app.py` — `_sanitize_health_checks`, applied in `api_health`; also
  corrected the stale "27 tables" comment to 26.
- `polaris_web/test_app.py` — `test_health_does_not_leak_paths_or_error_detail`:
  no check carries `error`/`path`/`mount_probe`, and the state-dir probe appears
  nowhere in the body.

## v9.75 — 2026-06-04 (CLI: the read-only query is actually read-only, and bad args fail cleanly)

Three CLI robustness/safety findings from the review's CLI pass.

**The "read-only" `query` command was only read-only by accident.** Its sole
enforcement was a prefix check (`first in ('SELECT','WITH')`), but PostgreSQL
allows data-modifying CTEs, so `WITH x AS (UPDATE ... RETURNING ...) SELECT * FROM
x` passed the guard and the UPDATE executed. Only the absence of a `commit()` in
`cmd_query` kept it from persisting — a future edit adding a commit would silently
turn it into an authenticated arbitrary-write hole (the CLI's `polaris_app` role
has full DML). The command now runs in a `set_session(readonly=True)` transaction,
so the engine rejects any write outright, regardless of commit behavior.

**Two uncaught-traceback paths.** `cmd_query` connected with a bare
`psycopg2.connect` outside any try block, so a connection failure dumped a full
traceback instead of the documented exit-2 error; it now mirrors the `connect()`
helper's clean message + exit 2. And `cmd_issue` parsed `--contexts` with
`[int(c) for c in ...]` before its try block, so a non-integer value raised an
uncaught `ValueError`; it now exits 1 with a usage message.

- `polaris_cli/polaris.py` — `query` runs read-only; `query`/`issue` connection
  and `--contexts` parsing fail cleanly.
- `polaris_cli/test_cli.py` — a writable CTE is rejected by the read-only
  transaction (and leaves no write); a non-integer `--contexts` exits 1 with no
  traceback.

## v9.74 — 2026-06-04 (the lockout message is no longer a username oracle)

`authenticate()` returned the generic "Invalid username or password." for an
unknown user, an inactive user, and a wrong password — but a distinct "Account is
temporarily locked. Try again later." for a known user whose `locked_until` was in
the future. Since an unknown user never enters the locked state (it returns before
any failure counter is touched), an attacker could enumerate usernames: send a few
wrong-password attempts to trip the lockout on a real account, and the distinct
"locked" string on the next attempt confirmed the account exists. `SECURITY.md`
affirmatively claims username enumeration is prevented, so this was an unmet
documented invariant.

Fix: verify the password *before* the lockout check, and reveal the lockout only
to a caller who supplied the correct password. A wrong-password attacker — whether
the account is unknown, wrong-password, or locked — now gets the identical generic
string, so the response no longer distinguishes a real account. A legitimate user
who types the right password still learns the account is temporarily locked. The
account stays locked either way (no login, no counter bump), and every known user
now runs one password hash, which also evens out the timing side channel.

- `polaris_web/security.py` — password verified before the lockout branch; locked
  response is generic unless the password is correct.
- `polaris_web/test_app.py` — `test_locked_account_is_not_an_enumeration_oracle`:
  the locked + wrong-password response equals the unknown-user response and never
  says "lock"; the correct-password caller still sees the lockout.

## v9.73 — 2026-06-04 (uc4 / uc10: validate under the lock, not before it)

Two validate-before-lock TOCTOU races from the concurrency review pass. Both
procedures took a lock for serialization but read the state they guard on
*before* the lock, so the guard ran against a stale snapshot.

**uc4_activate_reserve** validated the lost/reserve token statuses at the top,
then acquired its per-holder `Individual` lock and never re-read. Two concurrent
calls on the same tokens both passed the pre-lock check; the second then re-ran
`UPDATE ... LOST` (a no-op the state machine waves through on
`OLD.status = NEW.status`) and inserted a SECOND `RevocationList` row for the
already-revoked token (the table has no unique constraint on `token_id`). The
status reads now happen again UNDER the lock with the token rows `FOR UPDATE`, so
a stale second caller fails cleanly with "Token N is not ACTIVE" and publishes no
duplicate CRL row.

**uc10_revoke_attestation** checked "already revoked" before taking its
per-agency advisory lock — unlike `uc8_revoke_token`, which locks first. Two
concurrent revokes both passed the pre-lock guard and the second silently
overwrote the first's reason and timestamp. Reordered to lock first, then re-read
`revocation_date` under the lock (row `FOR UPDATE`) and reject the double-revoke.

- `polaris_sql/05_procedures.sql` — uc4 re-validates under the lock; uc10 is
  lock-first then guard.
- `polaris_web/test_app.py` —
  `test_uc4_concurrent_same_tokens_one_winner_no_duplicate_crl` races the actual
  procedure (the prior uc4 concurrency test raced raw UPDATEs) and asserts one
  winner, a clean loser, and exactly one CRL row.

## v9.72 — 2026-06-04 (WebAuthn second factor can actually complete)

The deeper review's WebAuthn pass found that the assertion (second-factor login)
ceremony could never complete for a real authenticator. Registration stores the
credential id as `_b64url_encode(raw)`, which keeps base64url padding, so the
stored primary key carries a trailing `=` for any credential whose byte length is
not a multiple of 3 — i.e. essentially every real authenticator (16/20/32/64/65
bytes). But at assertion the browser sends `PublicKeyCredential.id` / `rawId`
WITHOUT padding (the WebAuthn spec, and `webauthn-assert.js`, strip it), and
`fetch_credential` did an exact-equality lookup. The padded stored key never
matched the unpadded browser id, so the row was not found and the route returned
401 "invalid credential". Net effect: any admin who enrolled a credential became
permanently locked out, and a control meant to add a second factor became a hard
denial-of-service against the privileged role. No WebAuthn integration test
existed, so it shipped undetected.

Fix: a `_canonical_credential_id` helper round-trips any incoming id (padded or
unpadded) through the padding-tolerant decoder back to the stored padded form,
applied in `fetch_credential`, `update_credential_after_use`, and
`delete_credential`. No migration needed (no credential is seeded; new rows are
unchanged).

- `polaris_web/webauthn_auth.py` — `_canonical_credential_id`, applied to all
  three credential lookups.
- `polaris_web/test_app.py` — `WebAuthnCredentialLookupTests`: the helper maps
  both forms to the padded key, and a padded-store / unpadded-lookup round trip
  resolves (the exact-match path misses, proving the regression).

## v9.71 — 2026-06-04 (recovery ceremony: works for reserve-only holders, and three channels means three actors)

A deeper second review pass (procedure suite + compulsion-resistance dimensions)
found two HIGH issues in the UC-9 catastrophic-loss recovery ceremony.

**Recovery aborted for the exact holder it serves.** `uc9_complete_recovery`'s
APPROVED loop transitioned *every* non-terminal token to `LOST`, but the state
machine only permits `ACTIVE→LOST`; `RESERVE→LOST` is illegal and raised, aborting
the whole recovery. And `uc9_initiate_recovery` requires that no ACTIVE token
exist — so the realistic catastrophic-loss case is a holder whose only surviving
token is a RESERVE, which is exactly the case the blanket `→LOST` loop broke. (Same
class as the v9.64 uc4 bug: a procedure driving a transition the state machine
forbids.) The loop now transitions by source status: `ACTIVE→LOST`,
`RESERVE→REVOKED` (the only legal terminal edge from RESERVE, with the
velocity-bound opt-out uc4/uc8 use). A reserve-only holder now recovers cleanly.

**The "three independent channels" collapsed to one actor.** The ceremony's
anti-impersonation guarantee rests on three independent out-of-band channels:
biometric, sworn statement, and a witness co-signer. But nothing required
`witness_co_sign_user_id` to differ from the approver or the requester — so one
compromised admin could self-witness *and* self-approve, reducing the
"multiplicative cost" to a single actor. `uc8_revoke_token` already enforces
co-signer-must-differ on the revocation leg; recovery (the entry leg) omitted it.
Added the check in `uc9_complete_recovery` plus a `witness_differs_from_parties`
CHECK on `RecoveryRequest` (mirroring `approver_differs_from_requester`), and moved
the demo seed and test helpers to a distinct third actor (auditor) for the witness.

- `polaris_sql/05_procedures.sql` — uc9 loop transitions by status; witness
  separation-of-duties check.
- `polaris_sql/01_schema.sql` — `witness_differs_from_parties` CHECK.
- `polaris_sql/10_auth.sql` — demo recovery witness is now the auditor, distinct
  from the operator requester and the admin approver.
- `polaris_web/test_app.py` — reserve-only recovery succeeds; witness≠approver and
  witness≠requester both rejected. `CatastrophicLossRecoveryTests` is now 18 tests.

## v9.70 — 2026-06-04 (close the cross-site drive-by on the launcher control endpoints)

The last finding from the auth-security pass. `/api/quit` and `/api/heartbeat`
are unauthenticated launcher-control endpoints — no session, no CSRF token (the
launcher beacon is anonymous by design). `/api/quit` writes the file the desktop
launcher polls to tear the stack down. So any page the user merely visited could
`fetch('http://localhost:2222/api/quit', {method:'POST', mode:'no-cors'})` and
shut down their local instance (a cross-site drive-by; low impact for a
single-user dev tool, but a real gap).

Added `security.reject_cross_site`, applied to both endpoints. It rejects only
requests whose `Sec-Fetch-Site` header is `cross-site` (a header browsers set on
every request). Same-origin browser calls (`same-origin` — the heartbeat beacon
sends this) and header-less callers (the native launcher, curl, an operator) are
unaffected, so nothing breaks. `CrossSiteGuardTests` covers all four cases.

- `polaris_web/security.py` — `reject_cross_site` decorator.
- `polaris_web/app.py` — applied to `/api/quit` and `/api/heartbeat`.
- `polaris_web/test_app.py` — `CrossSiteGuardTests` (cross-site rejected;
  same-origin and header-absent allowed).

## v9.69 — 2026-06-04 (ZK verify route: local-clock epoch boundary, honest replay scope)

Completing the review by re-running the two dimensions that had hit a session
limit (crypto-soundness, app-disclosure). Both surfaced a real issue in the ZK
verify route.

**Epoch boundary used the wrong clock (R4).** `/api/zk/verify` rejected proofs
against expired epochs with `epoch['valid_until'] < datetime.utcnow()`, but
`TokenStateEpoch.valid_until` is a `TIMESTAMP`-without-zone stored as local wall
clock (app and DB are co-located), and every other Python boundary in `app.py`
compares against `datetime.now()` — the atlas code even carries a comment that
`utcnow()` is the wrong reference here. On any server not in UTC the epoch
boundary shifted by the server's offset: valid proofs rejected early, or expired
epochs accepted late. Fixed to `datetime.now()`, and added
`check_local_clock_convention` (app.py must not reference `utcnow`) so the
convention can't drift back. The check layer is now 21.

**The "replay resistance" claim was an overclaim.** `zk-snark.md` R2 was titled
"Replay resistance via nonce binding" and said "each verification request includes
a fresh nonce," and `lib.rs` claimed the binding "defeats within-epoch replay." But
the verifier reads the nonce from the same request that carries the proof and never
issues or consumes nonces, so the identical bundle resubmitted verifies again. The
binding prevents proof *substitution* (re-labelling a proof under a different
`(epoch, context, nonce)`), not bundle replay — which the project's own
`threat-model.md` T-T2 already lists as deferred. Corrected R2, the `lib.rs`
header, and `zk-soundness.md` to state exactly what the binding does, and added the
single-use nonce store to `ROADMAP.md` as the concrete hardening that would make
the claim hold in code.

- `polaris_web/app.py` — epoch-boundary check uses `datetime.now()`.
- `polaris_checks/checks.py` — `check_local_clock_convention` + detection test.
- `DEVNOTES/ships/zk-snark.md`, `polaris_zk/src/lib.rs`, `DEVNOTES/zk-soundness.md`
  — replay claim scoped to proof substitution; bundle replay noted as deferred.
- `ROADMAP.md` — ZK verify single-use nonce store added under Next ships.

## v9.68 — 2026-06-04 (consistency: a true table count, a version module that points only at live things)

The review's recent-regressions pass found two honesty gaps the earlier cleanups
left, both the kind a cold reader trips on.

- **`docs/ARCHITECTURE-OVERVIEW.md` said "27 tables"; the schema defines 26.**
  Every other doc that states a count says 26, and the SQL self-tests are built
  around 26. Fixed the doc, and added `check_table_count_matches_doc`: it counts
  `CREATE TABLE` in the schema and fails if the architecture doc states a
  different number, so this exact drift cannot recur. The check layer is now 20.
- **`polaris_web/__version__.py` still cited deleted things.** Its docstring named
  the deleted `meta/polaris-self-roadmap-2026-05-14.md` as a provenance pointer,
  the deleted `ai-status.sh`, a deleted `test_polaris_version_is_canonical`, and a
  bump procedure with steps (journal entry, meta + coherence run) for tooling that
  no longer exists. Rewrote the docstring to reference only what is live: the
  `polaris_checks` version/changelog checks and the `ai-done.sh` gate. The v9.63
  ship claimed "no source comment points at a deleted file"; this makes that true.
- Reworded two historical mentions (`scripts/ai-done.sh`,
  `polaris_web/test_check_constraints.py`) so they describe the removed checks
  without naming deleted scripts.

## v9.67 — 2026-06-04 (test rigor: fail-loud PQC and an externally-anchored second witness)

Two test-coverage gaps the review's test-rigor pass found, where a test could
pass while the thing it implies was broken.

**PQC fail-loud was untested.** `pqc_signing`'s load-bearing safety property —
with `POLARIS_USE_REAL_PQC=1` but liboqs missing, raise rather than silently
downgrade to the deterministic placeholder — had no direct test. Only the
flag-unset DB path was exercised (via `test_app`) and the static wiring grep
(`check_pqc_signing_wired`). A regression that let the flag-set-but-unavailable
branch fall through to the placeholder digest — a silent downgrade of an operator
who asked for real PQC — would have passed the whole suite. New
`polaris_web/test_pqc_signing.py` (9 cases, no DB, no liboqs needed): the
placeholder is exactly `sha3_256(token_value)` with the non-signature label, and
every entry point (`signature_bytes_for_token`, `sign`, `verify`) raises
`PQCUnavailableError` when the flag is set but liboqs is forced unavailable. Wired
into CI alongside `test_app`.

**The second witness's positive Merkle tests were self-referential.**
`test_witness2.py`'s membership/ACCEPT cases computed the committed root with the
same `root_from_path` they then checked against — `f(x) == f(x)`, true for any
deterministic implementation including a wrong one (wrong MDS, flipped index bits,
wrong padding). The only value anchor (`test_root_agreement_bit_identical`) is
gated behind the Rust binary, so when the differential is skipped the standalone
suite could not catch a wrong-but-deterministic Python witness. Added value-pinned
tests against roots produced by the **independent Rust witness** (captured
constants): `build_root` for a fixed multi-leaf and single-leaf set, and a
membership check whose committed root is the external anchor constant, not a
self-recompute. The Python witness's Merkle math is now anchored to external
ground truth even with no binary present.

- `polaris_web/test_pqc_signing.py` — new (9 tests).
- `polaris_zk/witness2/test_witness2.py` — 4 externally-anchored Merkle tests
  (13 total); the weak length-only single-leaf assertion now pins the value.
- `.github/workflows/ci.yml` — runs `test_pqc_signing` in the app-suite step.

## v9.66 — 2026-06-04 (harden the login redirect and the session cookie)

Two security findings from the review's auth-security pass.

**Open redirect (CWE-601).** All three post-login redirect sites (password
login, the WebAuthn partial-auth redirect, and the assertion completion)
validated the attacker-controlled `?next=` with `startswith('/') and not
startswith('//')`. That misses backslash variants like `/\evil.com`: browsers
normalize a backslash to a forward slash when parsing a URL or `Location`
header, so it becomes the protocol-relative `//evil.com`, but werkzeug emits the
backslash verbatim, so the guard passed it and the browser navigated off-site. A
victim who clicked `…/login?next=/\evil.com` and authenticated was redirected to
the attacker's domain.

The three sites now route `?next=` through one helper,
`security.is_safe_next_url`, which rejects backslashes, protocol-relative URLs,
anything `urlsplit()` reads as carrying a scheme or netloc, and embedded control
characters (CR/LF header-splitting). `NextUrlSafetyTests` (6 cases) pins the
attacks the old guard let through.

**Session cookie Secure flag (CWE-614).** `SESSION_COOKIE_SECURE` was set only
from `POLARIS_COOKIE_SECURE`, independent of `POLARIS_ENV=production`. An operator
who set production but forgot the cookie flag shipped `polaris_session` without
`Secure`, so a single downgraded request could leak the session over plaintext.
It is now forced on in production (`_PRODUCTION or …`), mirroring the secret-key
guard — production removes the foot-gun rather than trusting the operator.

- `polaris_web/security.py` — new `is_safe_next_url` helper.
- `polaris_web/app.py` — three redirect sites use it; `SESSION_COOKIE_SECURE`
  forced on under `_PRODUCTION`.
- `polaris_checks/checks.py` — `check_open_redirect_guard` (the naive `//`-only
  guard must not survive) and `check_cookie_secure_in_production`, with detection
  tests. The check layer is now 19 checks.

## v9.65 — 2026-06-04 (the demo ZK epoch verifies, and CI proves it)

The same review surfaced a second regression, this one hidden from CI. When the
ZK anonymity set grew from a 16-leaf demo to a full epoch (v9.60, `TREE_DEPTH`
4 to 14), `zk.py`, `merkle.py`, and `lib.rs` all moved to depth 14, but the
hardcoded demo epoch in `polaris_sql/10_auth.sql` was left at depth 4: a stale
Merkle root and three 4-sibling inclusion paths where depth 14 needs 14 siblings.
The demo ZK verification (`test_demo_epoch_root_verifies_via_python`) actually
failed at depth 14.

It stayed invisible because CI ran `test_app` *before* building the Rust ZK
binary, and the whole `ZKSnarkTests` class skips when the binary is absent. So the
masking hid not just this stale-data bug but every ZK proof round-trip test:
honest-prover acceptance, cross-epoch / cross-context / wrong-nonce rejection, and
the demo-epoch verification, 20 tests, none of them running in CI.

- `polaris_sql/10_auth.sql` — regenerated the demo epoch's root and the three
  per-leaf proof paths at depth 14 via the Rust witness (`zk.compute_epoch_leaves`).
  The leaf hashes are `derive_leaf_seed` (plain SHA3-256, depth-independent) and
  were already correct; only the root and the path lengths were stale.
- `.github/workflows/ci.yml` — set up Rust and build the ZK binary *before* the
  app suite, with `POLARIS_ZK_BINARY` in the job env so `zk._binary_path()` finds
  it. `ZKSnarkTests` now runs in CI instead of skipping. The reorder un-masks 20
  ZK tests; the demo-epoch verification is the standing guard against future depth
  or seed drift.

Verified: the full `test_app` suite is green with the binary present (all 20
`ZKSnarkTests` pass, demo epoch verifies), and the two-witness differential still
agrees at depth 14.

## v9.64 — 2026-06-04 (uc4 reserve activation works for every reason code)

A multi-agent review of the schema boundary found a HIGH-severity functional
regression in `uc4_activate_reserve`. The v8.15 belt-and-suspenders trigger
`enforce_revocation_velocity_bound` refuses any `UPDATE` that transitions an
`IdentityToken` into `REVOKED` unless the session GUC `polaris.revoke_check_done`
is set, so that the rate-limited `uc8_revoke_token` is the only entry point. But
`uc4_activate_reserve` also transitions the lost token to `REVOKED` whenever the
reason code is `COMPROMISED`, `SUPERSEDED`, or `ADMINISTRATIVE` (the terminal-status
`CASE` maps all three to `REVOKED`), and it never set the GUC. The trigger therefore
aborted the whole procedure with `Direct UPDATE to status=REVOKED is not allowed`,
so three of the five reason codes the UC-4 page offers were unusable. `LOST` and
`STOLEN` map to terminal status `LOST` and dodge the trigger, which is why nothing
caught it.

The fix: `uc4_activate_reserve` now sets `polaris.revoke_check_done` on its REVOKED
branch, opting the sanctioned 1-for-1 reserve swap out of the velocity bound exactly
the way `uc8_revoke_token` does. uc4 is inherently bounded (it consumes one
pre-provisioned reserve and produces one active token per call), so it is not a
mass-revocation vector and the anti-coercion property the bound protects is intact.

- `polaris_sql/05_procedures.sql` — guarded `set_config('polaris.revoke_check_done',
  '1', true)` on the REVOKED branch, before the lost-token `UPDATE`.
- `polaris_web/test_check_constraints.py` — new `TestUC4ReserveActivation` runs uc4
  end to end for all four reason codes and asserts the lost token reaches its correct
  terminal status. The three REVOKED-mapping cases fail against the unfixed schema
  (detection proven) and pass against the fix. Suite is 66 tests, all green.

## v9.63 — 2026-06-04 (reference-clean: no source comment points at a deleted file)

The de-larp and the cleanups deleted a lot, but ~30 source-code comments still cited
the deleted record by path: `sanctum/<date>.md` decision files, the `patterns/`
how-to playbook, `ai-where.sh`, and `test_structural_invariants.py`. Those are dead
references that a reviewer cloning the repo would find pointing at nothing.

Scrubbed them across 27 source files (Python, SQL, JS, HTML, shell):

- `sanctum/<date>-<name>.md` path citations in comments, docstrings, and the
  backup-manifest field became "a recorded decision" (the substance stays; the dead
  path is gone). These only ever appeared in comments and string literals, never in
  executable logic.
- The "Read before editing" / "canonical recipe" header blocks dropped their dead
  `patterns/*.md` and `ai-where.sh` lines, keeping the surviving doc pointers
  (`DEVNOTES/concurrency.md`, `docs/reference/SCALING.md`, `DEVNOTES/atlas-scaling.md`).
- The one `test_structural_invariants.py` reference (in a `test_check_constraints`
  docstring) was reworded to the surviving `pg_constraint` catalog check.

Verified after the scrub: the schema loads (78/78 SQL self-tests), the app imports
and `/dashboard` `/atlas` `/demo` render, `test_check_constraints` 62 OK,
`polaris_checks` 17 ok READY, `ai-link-check` resolves all 222 references. No logic
changed. The tree now references no deleted file anywhere, in docs or in source.

---

## v9.62 — 2026-06-04 (ROADMAP: a forward roadmap, not a ship archive)

`ROADMAP.md` had grown to 862 lines, but only the OPEN-NOW backlog and three gated
deferred items were forward-looking. The other ~770 lines were a shipped-items
archive (R7-* through R16-*, all ✅) that duplicates the CHANGELOG. A roadmap is
where the project is going, not a log of what shipped.

Cut it to ~75 lines: the flagged decision item, the next ships (PQC second witness,
the PQC-posture audit, the GitHub Actions deprecation), the production-scale deferred
items (multi-instance scaling, multi-region, distributed tracing, each gated), and
the explicitly out-of-scope items (OIDC, banking-on-Polaris, cross-platform
launchers). Shipped history stays in the CHANGELOG and the git log.

`ai-link-check` resolves all 222 references; `polaris_checks` 17 ok READY.

---

## v9.61 — 2026-06-04 (polaris_checks: complete the C1-C10 coverage)

The flat invariant layer directly checked C1, C3, C5, and C7; the other
constitutional constraints were enforced in the schema and app but not asserted by
the check layer. Added five checks, so 9 of the 10 constraints are now directly
machine-checked, each with tested detection correctness:

- **C2** — a CHECK constraint forbids `ZERO_KNOWLEDGE` verifications from carrying a
  `token_id`.
- **C4** — the failed-login counter increments atomically in a single UPDATE (no
  TOCTOU read-then-write).
- **C8** — the `/api/atlas/*` endpoints carry hard result-set caps.
- **C9** — concurrency hazards are tested with real threading (`ConcurrencyTests`).
- **C10** — the schema carries no monetary primitives (identity is not money).

C6 (server-side disclosure enforcement) stays covered behaviorally by the
redaction-property test, where it is meaningfully exercised rather than
string-matched.

`polaris_checks` is now 17 checks; each new check provably FAILs on a broken fixture
(`polaris_checks/test_checks.py`, now 13 detection tests). Verified: 17 ok / READY,
all detection tests pass.

---

## v9.60 — 2026-06-04 (ZK anonymity set: from a 16-leaf demo to a full epoch)

The zero-knowledge Merkle-inclusion circuit shipped at `TREE_DEPTH=4` (a 16-leaf
tree) while the schema caps an epoch at 10,000 leaves, so the proof's anonymity set
was at most 16 — far smaller than a real epoch. This raises the circuit to
`TREE_DEPTH=14` (16,384 leaves), which covers the 10,000-leaf cap, so the anonymity
set is now a full epoch.

Plonky2 is a transparent SNARK (FRI-based, no trusted setup), so the change is a
single constant in two files (`polaris_zk/src/lib.rs` and the Python second witness
`polaris_zk/witness2/merkle.py`) plus a recompile — no ceremony, no key
regeneration.

Verified at depth 14: the 7 Rust circuit tests pass, and the independent two-witness
differential (the Python re-checker vs the Rust prover) passes all 27 of its cases
bit-for-bit, including prove-verify roundtrips and tampered-root rejection. That
differential is exactly what would fail if the two implementations disagreed on the
new depth.

Docs updated: the ZK soundness ledger (`DEVNOTES/zk-soundness.md`) no longer lists
tree size as a demo-scale limitation (the not-audited and placeholder-PQC caveats
stand), the ship note, and the ROADMAP backlog item is closed.

---

## v9.59 — 2026-06-04 (professional cleanup: cut the agent-governance scaffolding)

Made the repository a clean, normal software project: removed the apparatus cruft,
fixed the broken tooling, pruned the dev-script sprawl, and cut the remaining
"how-an-AI-built-this" governance scaffolding that made it read as unusual rather
than professional. The thesis is untouched: C1-C10 and the anti-coercion Vocation,
the product, and the `polaris_checks` invariant layer.

**Removed:**

- Apparatus cruft left on disk: `polaris_swarm/` (the orphaned civitas JSON), plus
  `.DS_Store` and `.pytest_cache` (gitignored; were never tracked).
- 15 vestigial / methodology scripts (`scripts/` went 43 to 29): the session
  helpers (`ai-prime`, `ai-help`, `ai-recall`, `ai-snapshot`, `ai-cache-bust`,
  `ai-coverage`, `ai-where`, `ai-journal`), the agent-governance scripts
  (`ai-sanctum`, `ai-propose`, `ai-mission`, `ai-status`, `ai-test-counts`), and
  the `polaris-ai-done-hook` wrapper.
- The agent-governance meta docs: `meta/sanctum-protocol.md`,
  `meta/autonomy-architecture.md`, `meta/freeze-amendment-protocol.md`.

**Fixed:**

- `.pre-commit-config.yaml` was broken: it invoked three deleted scripts (`ai-meta`,
  `ai-coherence`, the structural-invariants suite) and a deleted doc. Rewritten to
  run `polaris_checks` + `ai-link-check` + the real hooks.
- `MISSION.md` (793 to 589 lines): cut the "agent contract" and "agent's
  relationship to this mission" methodology sections and the strategic-posture
  subsection. The constitution (C1-C10, the Vocation, the freeze line, the
  architectural soul, the done-lists) is unchanged.
- `CONTRIBUTING.md`: replaced the Sanctum / risk-class governance with a normal
  change-review process.
- De-methodologized the rest of the doc tree (`CLAUDE`, `SECURITY`, `README`,
  `ROADMAP`, and ~32 docs via two parallel cleanup passes): removed the dead
  Sanctum / risk-class references and the provenance citations to the deleted
  record.
- Corrected two now-false items in the live backlog (the full product suite is in
  CI as of v9.56; PQC issuance is wired as of v9.58).

Verified: `polaris_checks` 12 ok READY, `ai-link-check` resolves all 225
references, every script parses, the pre-commit config is valid YAML.

---

## v9.58 — 2026-06-04 (post-quantum signing wired into issuance)

Closes the one honesty gap the codebase itself flagged as "the most damning
critique" (`pqc_signing.py`'s own docstring): the headline post-quantum claim was,
at the data level, a hardcoded SQL string. The `uc1_issue_and_activate` procedure
wrote `TokenSignature.signature_bytes = 'UC1_ISSUE_PLACEHOLDER_<id>'`, and the
real-signing module was an unused island.

**The wiring.** The `uc1_issue` route now calls the new
`pqc_signing.signature_bytes_for_token(token_value)` and passes the result to the
procedure via a new trailing `p_signature_bytes BYTEA DEFAULT NULL` parameter. So
every token issued through the app gets its signature from the signing module:

- **Default (flag unset, including CI):** a deterministic SHA3-256 binding of the
  token value. Not a cryptographic signature (no private key), but a real binding
  produced by the signing module, single-sourced and reproducible, not a magic
  string.
- **`POLARIS_USE_REAL_PQC=1` + liboqs:** a real ML-DSA-65 (FIPS 204) signature.
- **Flag set but liboqs missing:** the route fails loud (`PQCUnavailableError`),
  never silently downgrading an operator who asked for real PQC.

**Backward-compatible.** The new parameter defaults to NULL, and the procedure
`COALESCE`s to the legacy placeholder string when no signature is supplied, so
every existing SQL caller and test is unchanged (the 12-argument call still works;
the function is dropped and recreated because adding a parameter changes its
signature).

**Guarded.** A new flat check, `polaris_checks.check_pqc_signing_wired`, asserts the
procedure accepts `p_signature_bytes` and the app routes issuance through
`signature_bytes_for_token`, with a detection test that FAILs if either regresses.
A DB-backed `test_app` test issues a token through the route and asserts the stored
`signature_bytes` equals `sha3_256(token_value)`, proving the path end to end.

Verified: schema loads (78/78 SQL self-tests), `test_check_constraints` 62 OK, the
issuance/signature suites green, `polaris_checks` 12 ok READY.

---

## v9.57 — 2026-06-04 (documentation prune: less is more)

The de-larp removed the apparatus *code*; this removes the documentation bloat it
left behind. The repository went from 216 markdown files (~66.7k lines) to 72
(~26k lines) by deleting what is no longer needed to understand, run, or extend
Polaris.

**Deleted (143 files):**

- The build-history audit-of-record: `sanctum/` (68 decision records), `journal/`
  (30 daily logs), and `archive/CHANGELOG-FULL.md` (the 18.8k-line full changelog).
  The complete history remains in the git log.
- The design-and-methodology record: `proposals/` (14 shipped-feature design docs)
  and `patterns/` (the 11-file how-to playbook).
- The apparatus-era meta snapshots: the three `polaris-self-roadmap-*` files,
  `cognitive-architecture-v2`/`v3`, `cold-read-walkthrough-v9.27`,
  `missions-considered`, `lineage`, `sanctum-index`, `arc-b-production`, the
  leftover `brain-map/`, and `cognitive-threat-review-due.txt`.
- `DEVNOTES/prior-art-analysis.md` + `DEVNOTES/plugin-policy.md`, `docs/BACKLOG.md`
  (ROADMAP covers it), `docs/story/STORY.md`, and the over-elaborate compliance/ops
  docs `docs/operator/{SOC2,PENTEST,DR-SINGLE-REGION}.md`.

**Kept:** the constitution (`MISSION.md`), `ROADMAP.md`, `CHANGELOG.md`, `CLAUDE.md`,
`CONTRIBUTING.md`, `SECURITY.md`; the `docs/reference` set, the operator runbooks,
the `DEVNOTES` engineering notes and ship records, the `meta/` constitution-support
docs (constraint-lattice, sanctum-protocol, autonomy-architecture, redaction-proof,
the TLA+ spec), `docs/story/PRINCIPLES.md`, and `docs/THESIS.md`.

**Re-linked:** every broken reference left by the prune was fixed across README,
MISSION, CLAUDE, ROADMAP, the CHANGELOG header, the landing page, and the surviving
`docs/`/`meta/`/`DEVNOTES` index and map files. The landing footer was repointed off
the deleted story doc and onto the real GitHub repo. `ai-link-check --ci` resolves
all 225 remaining references.

---

## v9.56 — 2026-06-03 (residual de-larp sweep + the full product suite goes green in CI)

Two things close here: the residual apparatus references left in the documentation
and dev scripts, and the CI regression that v9.55 introduced.

**Residual de-larp sweep.** v9.55 cut the apparatus code; this sweep cuts its
shadow in the docs and scripts. Deleted 15 more pure-apparatus files with no
surviving purpose: `meta/architect.md`, `meta/anti-architect.md`,
`meta/cognitive-loop.md`, `meta/watcher-predicates.md`,
`meta/foresight-predicate-audit.md`, `meta/swarm-mttr.json`,
`meta/swarm-scorecard.json`, `meta/sanctum-scorecard.json`,
`meta/structural-constants.json`, `meta/claude-90s.md`, `meta/swarm-map/`,
`meta/brain-map/`, plus `scripts/pre-commit-scope-check.sh` +
`meta/scope-rule-baseline.json` (rule-b referenced the deleted `polaris_swarm/`)
and `scripts/test_implants.sh` (smoke-tested the deleted scripts). De-larped the
surviving active-reference surface in place: the active `meta/` docs, the `ai-*`
and `polaris-*` dev/ops scripts, `ROADMAP.md`, and the `docs/` tree (the glossary,
operations runbook, architecture overview, system map, the story, the data model,
and the rest). The dated historical snapshots (the self-roadmaps,
`cognitive-architecture-v2/v3`, the cold-read walkthrough) and the development
record (`journal/`, `sanctum/`, `archive/`, prior `CHANGELOG` entries) are kept
as history.

**CI: the full product suite now runs green.** v9.55's rewritten `ci.yml` added an
"Application + CLI suites" step that ran `test_app` + `test_cli` for the first time
(v9.54's workflow never ran them), and they failed: `reload_sample_data()` shelled
out via `su - postgres -c`, which cannot authenticate against a service-container
Postgres. Fixed by reloading through the `POLARIS_DB_*` connection settings with
`psql` directly (works in CI, on macOS, and on Linux; `POLARIS_TEST_RELOAD_VIA=su`
still forces the legacy path). Added the missing "Apply migrations" CI step so
`webauthn_required_after` exists at test time. Then fixed the long-standing stale
tests the step surfaced: the dashboard / RBAC / substrate-UI tests that GET `/`
while logged in (where `home()` correctly 302-redirects authenticated users to
`/dashboard`), the health-check assertions that expected the old `db` /
`rate_limiter` keys instead of `database` / `redis`, the logout test that pulled
its CSRF token from a redirecting `/`, and the anchor-batch tests whose
`commitment_hash` test data did not satisfy the hex CHECK constraint. `test_app`
(329 tests) and `test_cli` (62 tests) now pass end to end.

---

## v9.55 — 2026-06-03 (the swap · sever the whole apparatus web at once)

scope: cognitive-rebuild · ship_marker: apparatus-swap · vocation: trustworthiness — the product is the thesis; the theater was never load-bearing · pattern20_instance: build-the-replacement-then-swap (v9.54 built the replacement; v9.55 severs the web)

v9.54 built the clean replacement (`polaris_checks/`). v9.55 is the Alexander cut:
with the replacement standing and CI wired onto it, the entire legacy apparatus is
**deleted wholesale in one stroke** — no surgical extraction, no cascade, because
nothing in the product imports it and it all leaves together.

**Deleted (~18,150 LOC + the mythology):**

- `polaris_swarm/`, `polaris_hydra/`, `polaris_foresight/` — the ant swarm, the nine
  HYDRA watchers + CM, the foresight engine.
- `polaris_web/test_structural_invariants.py`, `test_hydra_property.py`,
  `test_hydra_revamp.py` — the ~900 self-referential invariants that asserted the
  apparatus's claims about itself (Sanctum integrity, HYDRA shape, freeze line).
- 36 `ai-swarm-*` / `ai-hydra` / `ai-meta` / `ai-coherence` / `polaris-swarm-*`
  scripts.
- The mythology docs: `meta/civitas.md`, `meta/denarius.md`, `meta/twelfth-legion.md`,
  `meta/ant-predicates.md`, the arc-D/E/F/G files, `DEVNOTES/threat-model-cognitive.md`,
  `DEVNOTES/swarm-tier-vocabulary.md`, and the pheromone/observer/cadence notes.

**Rewired onto the product + the flat layer:**

- `.github/workflows/ci.yml` — product-only: schema load, `polaris_checks` + its
  detection-correctness tests, the CHECK-constraint regression suite, the Hypothesis
  property tests, `test_app` + `test_cli`, link-check, the ZK crate + the independent
  second-witness differential. Every apparatus step removed.
- `scripts/ai-done.sh` — a thin, honest gate: `polaris_checks.run` + link-check, with
  a reminder to run the DB-backed product suites. The HYDRA findings-gate, the swarm
  scorecard, and the `ai-meta`/`ai-coherence`/CM steps are gone.
- `CLAUDE.md`, `README.md`, `MISSION.md` — de-larped to the real product: identity
  tokens, zero-knowledge verification, post-quantum signing, the schema-level
  constraint lattice, and `polaris_checks` as the one invariant layer.

**What stood unchanged through the cut:** the product — `polaris_web/` (Flask app, the
use cases, the atlas API), `polaris_cli/`, `polaris_sql/` (the C1-C10 constraints,
triggers, partial unique indexes), `polaris_zk/` (the Plonky2 SNARK + the Python
second witness). All product test suites stayed green across the swap. The thesis was
always the product; the apparatus was scaffolding, and the scaffolding is down.

---

## v9.54 — 2026-06-03 (polaris_checks · the flat, themeless check layer — the apparatus-rebuild anchor)

scope: cognitive-rebuild · ship_marker: polaris-checks-anchor · vocation: trustworthiness — a check is a check; legibility is honesty · pattern20_instance: build-the-replacement-then-swap (cut the whole knot, do not untie it strand by strand)

VANTA authorized breaking the audit-of-record discipline and redoing the cognitive
layer ("take any radical approach ... like Alexander cutting the knot"). Two surgical
attempts (the de-theme rename and the civitas deletion) were executed and **reverted**:
they proved the apparatus is one self-referential web (code ↔ tests ↔ docs ↔ frozen-AoR
↔ pinned counts) where any single cut cascades endlessly. That entanglement IS the larp.

The Alexander move is not to untie the knot strand by strand — it is to build the clean
replacement and sever the whole web at once. **v9.54 builds the replacement:**

`polaris_checks/` — a flat, themeless module. Each check is a plain `check_*(repo_root)
-> list[Finding]` function mapping to the C1-C10 constitution (CSP/C5, one-active-token/
C3, append-only-AoR/C1, crypto-as-data/C7, FK-discipline, version-canonical, secrets
hygiene, the ZK two-witness, debug-artifact hygiene). No legions, no pheromones, no
treasury, no mythology. ~350 legible LOC doing the conceptual job of ~18k LOC of
apparatus. `python3 -m polaris_checks.run` gates CI directly (exit non-zero on FAIL).

**Detection correctness is TESTED** — each check provably FAILs on a broken fixture
(`polaris_checks/test_checks.py`), the gap the old apparatus never closed. The build
loop itself caught two real bugs in the checks (a version-regex and a CSP false-positive
that would have flagged the acceptable `style-src 'unsafe-inline'`), which the fixtures
now pin.

**Next (the swap):** wire callers onto polaris_checks, then delete the entire old
apparatus (swarm/HYDRA/civitas/legions/soldiers/foresight + their ~400 tests + the
mythology docs) wholesale — the cut with no cascade because it all goes together.

**Tests** (TestWave54V954, 3 cases): polaris_checks present + clean on the repo; the
layer is themeless (no mythology vocabulary); detection tests + CI wiring present.

**Personas.** Architect: build-replacement-then-swap is the correct refactor for a
self-referential web. Anti-Architect: ~350 LOC that a second engineer reads in minutes
vs 18k LOC of in-joke — this is the de-larp. Risk LOW (new module + CI step; nothing
deleted yet). Authorized under the 2026-06-03 heavy-production + take-over directive.

## v9.53 — 2026-06-03 (Apparatus-reduction · remove the orphaned economy tier-counting from HYDRA)

scope: apparatus-reduction · ship_marker: hydra-tier-counting-removed · vocation: trustworthiness — finish the cut; orphaned theater left behind is still theater · pattern20_instance: complete-the-removal (the economy cut in v9.50, finished in its HYDRA consumer)

Completes v9.50's economy removal. HYDRA's `ant_colony_watcher` kept its OWN copy of
the tier thresholds (DENARII_PLEB_MAX/EQUES_MAX), counted ants into
pleb/eques/patrician, and emitted a dead "patrician-class ant(s)" finding that
referenced the F4 Cursus Honorum multiplier retired in v9.50 and never fired (no ant
ever approached the threshold — max balance 50 vs 10,001). v9.53 removes that orphaned
theater.

KEPT (the load-bearing parts the audit flagged): the treasury-roll **integrity probe**
(missing/malformed -> `alert`), which is HYDRA's liveness wire into the ship gate; and
the "skewed strongly negative (post-rebalance)" drift signal, which reads balance
values (not tiers) and reflects the reward ledger v9.50 preserved. HYDRA keeps its name
per VANTA — only the dead economy references inside it are gone.

**Tests** (TestWave53V953, 2 cases): the tier thresholds + pleb/eques/patrician keys
stay removed from the watcher; the roll-integrity alert path survives.

**Personas.** Anti-Architect (reviewer of record): a partial cut that leaves orphaned
references is half-honest; finish it. Architect: complete-the-removal. Risk LOW
(removed a dead finding + orphaned constants; watcher + hydra suites + structural suite
all verified green). Heavy-production authorized.

## v9.52 — 2026-06-03 (Apparatus-reduction Phase 2 · the HYDRA findings-gate now actually gates)

scope: apparatus-reduction · ship_marker: findings-gate-freshness · vocation: trustworthiness — a gate that does not gate is worse than no gate · pattern20_instance: harden-the-real-thing (the part of the apparatus that IS load-bearing, made honest)

Phase 2 of the apparatus-reduction arc: the genuinely product-improving part. The
audit found `ai-done.sh`'s step-14 HYDRA findings-gate grepped the newest
`journal/hydra/*.md` brief by mtime with **no freshness check** — so a long-stale
brief (the audit found an 18-day-old one) reported "0 ALERT" as if it described the
current state. A gate passing vacuously off stale data.

v9.52 adds a freshness guard (portable `find -mtime`, not `stat -f/-c` per gotcha #4):
a brief older than 24h can no longer confirm a clean gate — it warns ("0 ALERT is
NOT confirmed against current state; run ai-hydra.sh --full --save") instead of
falsely passing. The positive path is preserved: a fresh brief with 0 ALERT still
reports ok.

The fix is self-demonstrating: with the genuinely-stale brief on disk, the gate now
honestly WARNS. And a fresh `ai-hydra.sh` run confirms why the honesty matters — the
current state actually carries findings the vacuous gate was hiding (incl. a
`trajectory: ship-rate burst (mission-creep signal)` — the watcher independently
corroborating the v9.51-repaired release-velocity ant).

**Tests** (TestWave52V952, 2 cases): the gate has a freshness check (find -mtime;
stale → NOT confirmed); the fresh-brief positive path still reports ok.

**Personas.** Anti-Architect (reviewer of record): harden the part of the apparatus
that earns its place rather than only cutting. Architect: a measurement that lies is
worse than none. Risk LOW (gate is honest-er; warns don't block; the ship machinery
is verified by running ai-done.sh). Heavy-production authorized.

## v9.51 — 2026-06-03 (Apparatus-reduction Phase 1b · repair the bit-rotted version regexes — repair, not delete)

scope: apparatus-reduction · ship_marker: changelog-ant-regex-repair · vocation: trustworthiness — a dead check wearing live-check costume is its own larping; make it real or remove it · pattern20_instance: verify-before-cut (the audit said delete 5; live verification found 2 functional + 3 fixable)

Phase 1b of the apparatus-reduction arc. The audit flagged "5 bit-rotted ants" for
deletion. Live verification corrected it: `ant_unbumped_version` (hunts stale v8.X
refs — its job) and `ant_sanctum_outcome` (accepts CHANGELOG/journal links) are
**correctly silent and still functional** — deleting them would have cut working
checks. The genuinely bit-rotted three hardcoded `## v8\.` to parse CHANGELOG
headers and silently matched NOTHING once CHANGELOG went all-v9.x:
`ant_changelog_gap`, `ant_release_velocity`, `ant_ship_burst`.

**Repaired, not deleted** — repointed each to a version-agnostic `## v\d+\.` pattern.
This restores real function AND avoids the load-bearing 33-ant count cascade (the
count is pinned across MISSION/ROADMAP/CHANGELOG/sanctum-index). The repair is
self-validating: on the current repo `release_velocity` and `ship_burst` immediately
and correctly fire a **mission-creep signal** — "7 ships landed on 2026-06-03
(threshold 6)" and "median inter-ship gap 0.00d; sustained mission-creep territory."
The swarm now honestly observes its own heavy-production cadence; before, it was dead.

**Tests** (TestWave51V951, 2 cases): the three ants' HEADER_RE matches the current
vMAJOR.MINOR scheme; a regression guard forbids re-anchoring a CHANGELOG-header regex
to a single major.

**Personas.** Anti-Architect (reviewer of record): "repair-not-delete" is the
loyal-opposition refinement — the audit's "delete 5" over-reached; verify each before
cutting. Architect: the bit-rot was itself a form of the larping the arc targets (the
illusion that all 33 ants are live). Risk LOW (regex repair + behavioral test; no
count change). Heavy-production authorized.

## v9.50 — 2026-06-03 (Apparatus-reduction Phase 1a · retire the inert Denarius "Cursus Honorum" economy)

scope: apparatus-reduction · ship_marker: cursus-economy-retired · vocation: trustworthiness — elaborate machinery whose load-bearing output is permanently zero is theater; name it and cut it · pattern20_instance: cut-deeper (the project's own apparatus-DOMINANT signal, acted on)

First ship of the apparatus-reduction arc (Sanctum `2026-06-03-apparatus-reduction`),
opened after VANTA questioned whether the ants/citizens/Roman-tactics layer earns its
place. A function-vs-theme audit confirmed the project's own standing "cut-deeper"
signal (`polaris-sanctum-status.sh` ratio 0.29, APPARATUS-DOMINANT). Scope chosen by
VANTA: **dead-weight + harden + de-theme the swarm layer; HYDRA keeps its name.**

**Phase 1a — the clearest larping instance, removed:** the Denarius "Cursus Honorum"
tier economy was provably inert. Across all operation the maximum ant balance ever
reached was **50 against a 1001 tier threshold**, so every intensity multiplier was
permanently 1.0x, no ant ever rose above pleb, and Sanctum-chair eligibility was never
met. The project's own journal already called it "vestigial" and "empirically broken."

Removed: `multiplier_for` / `property_class` / `is_sanctum_chair_eligible` /
`patrician_ants` / `CURSUS_MULTIPLIER` / the tier thresholds from `civitas/treasury.py`;
the cosmetic Cursus multiplier from `ai_swarm_bloom.py`; the `property_class` display
from `quaestor_treasurer.py`; and **`denarii_scheduler.py`** — the one attempt to make
the economy load-bearing, which was dead (zero non-test callers) AND broken (read JSON
keys that don't exist). Kept: the reward **ledger** (the +10/-1 drift signal + the roll)
as the swarm's activity/liveness record, which HYDRA's ant_colony_watcher reads as an
integrity probe (the load-bearing wire the audit flagged — cut the economy, keep the
liveness signal).

**Tests** (TestWave50V950, 3 cases): the inert Cursus apparatus stays removed; the dead
scheduler stays deleted; the reward ledger + roll (HYDRA's liveness input) survive.
Removed 4 now-orphaned tests (F4 G19 multipliers, F4 G20 chair-eligibility, 2 scheduler
existence tests).

**Constitutional clearance:** C1-C10 + the Vocation never move (the apparatus only
OBSERVES them; grep confirms no core code imports the swarm). Audit-of-record preserved
(forward-only deletion; the treasury-roll history stays).

**Personas.** Anti-Architect is reviewer of record — it pre-named AP8 "Larping" and AP1
"loving the cognitive layer's growth more than the product's"; this cut is the
loyal-opposition position. Architect: cut-deeper, acted on the project's own signal.
Risk MEDIUM (touches the civitas + a HYDRA-read liveness file; verified import-clean +
full structural suite green). Heavy-production authorized.

## v9.49 — 2026-06-03 (Swarm coverage · every ant's scan() contract is tested, not just the E10 cohort)

scope: test-coverage · ship_marker: all-ants-scan-contract · vocation: trustworthiness — an unobserved watcher is an untrusted watcher · pattern20_instance: close-the-coverage-gap (smoke loop over ALL_ANTS, not a subset)

The gap audit found 14 of the 33 ants had no individual behavioral coverage: the
only blanket smoke test looped over the 10-ant ACCELERATION+CONSCIOUSNESS cohort
(`ALL_E10_ANTS`), not `ALL_ANTS`. v9.49 extends the `scan()` contract to every
registered ant.

- `TestWave49V949` instantiates every ant in `ALL_ANTS` with the repo root and
  asserts `scan()` returns a `list[AntFinding]` and does not raise.
- Verified DB-free: all 33 ants' `scan()` pass with no Postgres, so the test is
  CI-safe (no new service dependency). This supersedes the E10-only smoke loop.
- Plus a registry-hygiene guard: no duplicate ant `NAME`s in `ALL_ANTS`.

**Tests** (TestWave49V949, 2 cases): all-33-ant scan() contract; unique ant names.

**Personas.** Architect: close the coverage gap with a structural invariant, not a
one-off. Anti-Architect: kept it DB-free and verified (33/33 pass locally) rather
than blind-adding a fragile suite. Risk LOW (test-only). Heavy-production authorized.

## v9.48 — 2026-06-03 (Honest-accounting · ai-swarm-validate.sh header matches its body)

scope: honest-accounting · ship_marker: swarm-validate-dangling-deadline · vocation: trustworthiness — a script must not claim a computation it does not perform · pattern20_instance: drift→test promotion (dangling-deadline overclaim becomes a standing guard)

`scripts/ai-swarm-validate.sh`'s header claimed it "reports precision + recall per
ant" and "auto-flags PREDICATE_PENDING for sub-threshold ants". The body does
neither: it emits only the EXPECTED-firing matrix and deferred the observed pass
(run_colony() + Pheromone reads -> precision/recall) to "v9.25" — a follow-through
that never landed (we are at v9.48). `observed_*` counts are 0 by construction.

v9.48 rewrites the header to the honest scope (fixture inventory + expected-firing
matrix; observed precision/recall NOT computed) and removes the dangling "v9.25"
version promise from the header, the JSON `note`, and the status print.

**Tests** (TestWave48V948, 2 cases): no dangling "v9.25" version promise survives;
the header states the honest scope. The first is a class-shaped guard against
re-introducing a deadline that has already passed.

**Personas.** Architect: drift→test promotion — same honest-accounting discipline
as v9.47 (PQC ABSTAIN), applied to a swarm script. Anti-Architect: the right fix
was (b) honest header, not (a) implement-the-deferred-feature, under the v9.31
freeze. Risk LOW (docstring + test). Heavy-production authorized.

## v9.47 — 2026-06-03 (Honest-accounting · the PQC verdict is a recorded two-witness ABSTAIN)

scope: crypto-honesty · ship_marker: pqc-lone-verifier-abstain · vocation: trustworthiness — name the gap, do not let a lone verifier ship silently · pattern20_instance: drift→test promotion (the island-claim is now a standing invariant)

The two-witness principle (v9.44) says shipping a lone cryptographic verifier is
a finding, not a feature. The ML-DSA-65 signature verdict (`pqc_signing.verify`)
has a single liboqs impl and no independent second witness. v9.47 records it as
an explicit **ABSTAIN** instance (rule 4) in `DEVNOTES/two-witness-principle.md`
rather than leaving the gap silent.

It also corrects a docstring overclaim: `pqc_signing`'s activation procedure
implied that flag-on (`POLARIS_USE_REAL_PQC=1`) makes issuance write real
signatures. In fact `app.py` never imports the module and the issuance route
(`uc1_issue`) never calls `sign()` — the module is an integration *island*, so
flag-on enables the `sign()`/`verify()` primitive but does not change issuance
behavior. The docstring now says so plainly.

**Tests** (TestWave47V947, 3 cases): PQC verdict recorded as ABSTAIN; docstring
states the wiring status; and an island-guard that FAILS ON PURPOSE if
`pqc_signing` is ever imported by `app.py` — forcing whoever wires it to update
the honesty note and promote the verdict from ABSTAIN to two-witnessed.

**Personas.** Architect: drift→test promotion — the "island" claim becomes a
standing invariant. Anti-Architect: this is exactly the AP8 (larping) discipline
the PQC module itself cites — the honest move is to name the gap, not paper over
it. Risk LOW (docs + test). Heavy-production authorized.

## v9.46 — 2026-06-03 (CI hardening · the ZK two-witness differential now gates CI)

scope: ci-hardening · ship_marker: ci-two-witness-wiring · vocation: trustworthiness — a verifier that never runs in CI is not a safety net · pattern20_instance: close-the-loop (ship a check, then make it gate)

The flagship v9.44 deliverable — `test_zk_second_witness.py`, the differential
that cross-checks the Rust ZK verdict against the independent `witness2`
implementation — never ran in CI, even though CI already builds the exact
`polaris-zk` binary it needs. v9.46 wires it in.

- **pytest** added to `requirements.txt`. The header comment already promised
  it but it was absent, so the pytest-style ZK suites (`witness2/test_witness2.py`,
  `test_zk_second_witness.py`) ImportError'd on a clean install / in CI.
- **CI steps added** (`.github/workflows/ci.yml`): the ZK two-witness
  differential (after the existing prove-verify roundtrip, reusing the built
  binary via `POLARIS_ZK_BINARY`), and the pure HYDRA watcher suites
  (`test_hydra_property`, `test_hydra_revamp`; verified locally 44 pass / 9 skip).
- Refreshed the stale CI header (claimed "273 tests / 7 ZK adversarial tests";
  now descriptive, not a drifting hardcoded count).

**Follow-up (ROADMAP §OPEN NOW):** wire `test_app.py` + `test_cli.py` into CI
once confirmed green against the CI sample DB (deferred: not verifiable from the
local env, which lacks psycopg2).

**Tests** (TestWave46V946, 3 cases): pytest is a declared dependency; CI runs the
ZK two-witness differential + witness2 self-tests; CI runs the HYDRA suites.

**Personas.** Architect: close-the-loop — a shipped check that never gates is
half a ship. Anti-Architect: held the wiring to suites verified locally (ZK +
hydra), refusing to blind-add the DB-backed suites I cannot confirm from here.
Risk LOW (CI config + test). Authorized under the 2026-06-03 heavy-production
directive.

## v9.45 — 2026-06-03 (Repo hygiene · secret-leak gitignore fix · foresight log integrity)

scope: hygiene-security · ship_marker: gitignore-secret-leak · vocation: trustworthiness — operator secrets must not be one `git add` from disclosure · pattern20_instance: drift→test promotion (security regression guard)

Heavy-production session cleanup (Sanctum `2026-06-03-heavy-production-authorization`).
A repo audit surfaced a latent **secret-leak**: `.gitignore` used trailing inline
comments on `polaris.env` (operator secrets) and `.claude/`:

    polaris.env   # v9.34: sourced by polaris-mycelium-wake.sh

git does NOT honor trailing inline comments — the `# ...` becomes part of the
pattern, so `polaris.env` matched nothing and was NOT ignored by the repo. The
file holds operator secrets; a `git add -A` with it present would have committed
them. Only the file's non-existence saved the tree. v9.45 moves the comments to
their own lines above bare patterns. Verified with `git check-ignore`.

**Other hygiene:**
- `.playwright-mcp/` (158 stale browser-console logs) gitignored + removed.
- Foresight acceptance-log path parameterized: `promote_foresight_candidates`
  now takes `acceptance_log_path`, so the idempotency test stops leaking the
  fixture `"Test idempotent candidate xyz123"` into the real empirical-graduation
  tracker (`promotion.py` previously hardcoded `_REPO_ROOT`). Scrubbed the leaked
  FS-FBAEC2B8 entry.

**Tests** (TestWave45V945, 6 cases): security regression guards (polaris.env +
.claude gitignored via `git check-ignore`; no trailing-comment patterns in
.gitignore), .playwright-mcp ignored, acceptance-log path parameterized, no
fixture in the real log.

**Personas.** Architect: drift→test promotion — the secret-leak becomes a
standing invariant, not a one-time fix. Anti-Architect: no scope dissent; pure
hygiene + integrity. Risk class LOW (hygiene + test; security-positive).
Authorized under the 2026-06-03 heavy-production directive.

## v9.44 — 2026-06-03 (Glass bounded-integration · the ZK verdict is two-witnessed · decline the complete rework)

scope: zk-substrate · ship_marker: glass-bounded-integration · vocation: trustworthiness — a cryptographic verdict only one program can produce is a promise, not a proof · pattern20_instance: import-the-method-not-the-chassis (additive cross-check beside the audited substrate)

VANTA proposed reworking Polaris with the Glass language. An adversarial
fit analysis (Sanctum `2026-06-03-glass-bounded-integration`) found the
philosophical rhyme real but the rework wrong: Glass's own ledger says
*"do not use Glass to protect real value"* and it is *"not
production-hardened"*; Polaris's security boundary is the Postgres engine
(C1-C10 as triggers / partial-unique-indexes / CHECK), which Glass's
pure-functional, compile-to-C effect surface cannot host. The
decline-and-surface posture held; VANTA authorized the bounded plan:
*"go ahead with the bounded integration plan."*

**What shipped.** The one genuinely transferable asset. Glass and
`polaris_zk` both live on the Goldilocks field (2^64) with the Poseidon
hash family, which makes a second, independent verifier known-shaped
rather than research. `polaris_zk/witness2/` is a from-scratch Python
Goldilocks + Poseidon + Merkle witness that re-derives the
Merkle-inclusion verdict and must agree with the Rust `verify()`:

- Shares no code with the Rust crate or with Glass; plain `int mod p`,
  not the crate's limbs (the Pentecost discipline, borrowed from Glass).
- Anchored independently on Plonky2's own published Poseidon test vectors
  (all-zeros, 0..11, all -1) in `poseidon_constants.py`.
- Agrees bit-for-bit with the live Rust binary on root computation across
  every cohort size 1..16, and on ACCEPT/REJECT across the honest +
  adversary corpus (nonce / epoch / context / root tamper, multi-field
  replay).
- ABSTAINS, by construction, on proof-byte integrity (that axis stays
  with the Rust decoder) and says so rather than bluffing.

**Docs.** `DEVNOTES/zk-soundness.md` is the honest ledger (demo-scale
`TREE_DEPTH = 4`, placeholder PQC by default, statement-level witness
scope), modeled on Glass's own `docs/soundness.md`.
`DEVNOTES/two-witness-principle.md` makes "every cryptographic verdict
must be two-witnessed" a standing Polaris obligation.

**Tests** (TestWave44V944, 9 cases, no Rust binary needed at CI time):
package presence; 360 Poseidon constants + MDS matrices; Plonky2 vector
self-test; golden root bit-for-bit vs Rust; verdict ACCEPT/REJECT; ledger
+ principle docs honest; Sanctum recorded + indexed; no Glass coupling.
The full Rust-vs-Python differential is
`polaris_web/test_zk_second_witness.py` (18 cases; runs when the binary is
built).

**Personas.** Architect: import the method, not the chassis — the
additive cross-check strengthens C2/C7 without touching the substrate.
Anti-Architect: held the line against chassis replacement (the v9.08
showroom precedent) and against routing identity crypto through an
educational substrate (the Vocation). Risk class: HIGH Sanctum
(adjudicated a complete-rework request); the shipped work is hardening
within the v9.31 freeze envelope. Glass folder untouched; no production
substrate changed.

