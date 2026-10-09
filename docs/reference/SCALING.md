# Scaling Polaris: measured at 10 million events

**Reader:** the operator or reviewer asking whether the Atlas and the
verification log stay interactive at national volumes. **Job:** the
measurements, the indexes and caps behind them, and the concurrency
hardening that ships alongside. The headline measurement is the Atlas on its
activity rollups at ten million verifications (step 4 of lab/strategy/009); the
event-table measurements of v9.150 and the 2-million-event era follow it, kept as
taken.
These are developer-laptop numbers; tuned PostgreSQL, pooling and edge caching
have not been measured against them.

**Since 2026-10-02** the Atlas returns counts only
([lab/strategy/009](../../lab/strategy/009-atlas-athena-rework.md), step A0):
the map's single-event points, the event feed, the records grid and the person
focus were withdrawn, with `atlas_points_*`, `atlas_recent_events` and
`atlas_records`. Measurements of those paths below are kept as taken and say
they were withdrawn.

**Since step 4 of the same record** the Atlas reads no event table at all. Every figure is a sum
over the activity rollups (hourly and daily totals kept as events are recorded), so a reader costs
the hours a window spans and not the rows loaded; the cluster, hexagon and timeline layers were
withdrawn with `atlas_clusters_*`, `atlas_hexbin` and `atlas_timeline`, and every count below five
is withheld. The design is [atlas-scaling.md](../design/atlas-scaling.md); the event-table
measurements below are kept as taken.

---

## Measured at 10 million verifications, on the rollups (lab/strategy/009, step 4)

Two million people and 10,000,010 verifications in one PostgreSQL 16 on a developer laptop (Apple
M3, 8 cores), warm, in process through the Flask test client:

| Route | On the event tables | On the rollups |
|---|---:|---:|
| `/atlas` (the page and its headline figures) | 6,728 ms | **31 ms** |
| `/api/atlas/series?window=all` | 5,738 ms | **26 ms** |
| `/api/atlas/geo/jurisdictions?window=all` | 5,649 ms | **17 ms** |

Every other Atlas route runs at 1.0 to 2.4 times its cost on the ten-verification seed database,
except `/api/atlas/heatmap?window=30d` at 3.4 times (43.1 ms against 12.6 ms): it reads hours,
and at this load nearly every combination is active in nearly every hour, so its rows saturate
at hours x combinations. The deferred fix is in
[atlas-scaling.md](../design/atlas-scaling.md#measured).
[`scripts/polaris-atlas-benchmark.sh`](../../scripts/polaris-atlas-benchmark.sh) reproduces the
reader timings (`scripts/polaris-atlas-benchmark.sh 10000000`).

---

## Measured at 10 million events on the event tables (v9.150, superseded)

Re-run on a developer laptop against a single PostgreSQL 16 with
**10,000,009 verification events** (a 2.75 GB table), with the benchmark script of the time:

| Atlas query (per viewport) | Latency @ 10M | What it is |
|---|---:|---|
| Street-block points (`atlas_points_*`, tight bbox, limit 500) | **2.6 ms** (warm) | The operator zoomed in to a block. Withdrawn 2026-10-02. |
| Regional clusters (CONUS bbox, 1° grid) | 2.7 s | Full aggregation of the ~9M rows inside the bbox. |
| Whole-world clusters (10° grid) | 2.9 s | The heaviest path: aggregate the entire table. |
| Whole-world from a materialized rollup | **0.04 ms** | Pre-computed grid cells, refreshed on a schedule. |

Two facts decide whether this scales, and both are measured above:

1. **The operator's real workflow is index-served and bbox-bounded.** Zooming
   to a region, a city, a street, or one subject reads a tight bounding box
   through the `(latitude, longitude)` partial index and returns in single-digit
   milliseconds: at 10M events, and at 100M, because the bbox bounds the scan,
   not the table size. This is the path that matters: nobody investigates by
   staring at an un-aggregated planet.

2. **The whole-world overview is a full aggregation, and the remedy is a
   rollup, not an index.** `EXPLAIN` shows the overview sorting and grouping
   every non-ZK row (no index can avoid reading rows you are aggregating). At
   10M that is ~2.9 s cold. A materialized grid rollup pre-computes those cells;
   reading the overview from it is **0.04 ms, roughly 70,000× faster**, and
   the ~2.6 s build runs on a refresh schedule, off the request path. The live
   API also caches cluster results (`_atlas_cache`), so even without the rollup
   the cold overview is computed once per viewport and then served from cache.

The rollups of step 4 are that remedy, made general: every Atlas view, not only the overview,
reads pre-computed totals, and they are kept as events arrive rather than refreshed on a schedule.

---

## The problem

The original Atlas inlined every event as JSON in the page template:

```jinja
<script id="atlas-globe-data" type="application/json">{{ globe_nodes|tojson }}</script>
```

| Events  | Payload  | Render time | Notes |
|--------:|---------:|------------:|-------|
|      17 |    8 KB  |       50 ms | sample, fine |
|     1 K |  300 KB  |      100 ms | acceptable |
|    10 K |    3 MB  |       1.2 s | sluggish |
|   100 K |   30 MB  |      ~12 s  | unusable |
|     1 M |  300 MB  |       OOM   | browser tabs out |
|     2 M |  600 MB  |       OOM   | architecturally infeasible |

The fix is server-side spatial aggregation, not optimization of the
client-side rendering loop. No amount of D3 cleverness solves a 600 MB
JSON payload arriving over the wire.

---

## Architecture

```
                            +------------------------------------+
                            |  PostgreSQL 16                     |
                            |                                    |
                            |  VerificationEvent ---- statement  |
                            |  TokenLifecycleEvent    triggers   |
                            |        | append counts per insert  |
                            |        v                           |
                            |  *RollupDelta --fold--> *Rollup    |
                            |                        (hourly)    |
                            |                    --> *RollupDaily|
                            |                                    |
                            |  Functions (11_atlas.sql), each a  |
                            |  sum over the rollups, never an    |
                            |  event table                       |
                            +-----------------+------------------+
                                              | a few KB of counts per call,
                                              | whatever the population
                                              v
                            +------------------------------------+
                            |  atlas_routes.py  /api/atlas/*     |
                            |   whitelist + clamp (C8)           |
                            |   withhold counts below 5          |
                            |   log a narrow question            |
                            |   30 s cache, keyed by scope       |
                            +-----------------+------------------+
                                              v
                            +------------------------------------+
                            |  atlas-console.js, atlas-map.js    |
                            |   SVG charts; regions placed from  |
                            |   reference data, never an event   |
                            +------------------------------------+
```

The browser never receives an event. A breakdown of ten million verifications is a few dozen
rows of counts.

---

## Storage

`VerificationEvent` and `TokenLifecycleEvent` gained `latitude` and
`longitude` columns in v6 (`01_schema.sql`):

```sql
latitude   DOUBLE PRECISION CHECK (latitude  IS NULL OR (latitude  BETWEEN  -90 AND  90)),
longitude  DOUBLE PRECISION CHECK (longitude IS NULL OR (longitude BETWEEN -180 AND 180))
```

Nullable so legacy rows without recorded location remain valid. Since step 4 of
lab/strategy/009 the Atlas reads no location; the columns serve the verification log and an
investigation under warrant.

Indexes (`02_indexes.sql`):

| Index                                | Purpose                                  |
|--------------------------------------|------------------------------------------|
| `idx_verificationevent_time_id`      | Keyset pages of the verification log     |
| `idx_tokenlifecycleevent_time`       | Time-ordered reads of lifecycle events   |

The v6 location indexes (`idx_verificationevent_geo`, `idx_verificationevent_geo_time`,
`idx_tokenlifecycleevent_geo`) served the Atlas's bounding-box layers, and the optional
`13_postgis.sql` built GiST indexes on a generated `geo` column beside them. No query filters or
sorts by a coordinate since step 4 of lab/strategy/009, so step 4c withdrew all five (migration
2026-10-02-005): each cost every located insert an update and served no query.

---

## Server-side aggregation (`11_atlas.sql`)

Every reader sums the activity rollups through three shared helpers: the cells of a window (the
hourly or daily rows and the delta not yet folded), the cells under the filters, and the window's
combinations summed over its hours with names joined last. The readers and their bounds are in
[atlas-scaling.md](../design/atlas-scaling.md#the-readers-11_atlassql). Until step 4 the map's
`atlas_clusters_verifications` binned located events by grid cell and `atlas_stats` aggregated a
bounding box in a single pass (511 ms at 2M events, from 1428 ms); both read the event table.

---

## API endpoints

The Atlas endpoints are login-gated and replica-routed, and take no bounding box: they count by
window, category and jurisdiction. The reference is [API.md](API.md), Atlas API.

| Endpoint | Hard cap | Purpose |
|---|---|---|
| `GET /api/atlas/stats` | one row | the headline figures |
| `GET /api/atlas/series` | 240 buckets | volume over the window |
| `GET /api/atlas/breakdown` | 50 categories | counts by one dimension |
| `GET /api/atlas/crosstab` | 50 rows | a dimension by a fixed one |
| `GET /api/atlas/heatmap` | 168 cells | weekday by hour |
| `GET /api/atlas/stacked` | 240 x 7 | volume by the top six categories |
| `GET /api/atlas/facet/agencies` | 50 | the authority typeahead |
| `GET /api/atlas/geo/jurisdictions` | 500 regions | counts per jurisdiction, the map's only layer |

---

## Frontend (atlas-map.js)

The map is a MapLibre GL canvas with one layer: counts per jurisdiction, each region placed at a
reference point for the jurisdiction. It fetches on a change of window or filter, not on a pan:
the regions are not bound to the viewport. Nothing drawn is a single event.

---

## Performance at 2M scale (the event-table Atlas, superseded)

Measured against the live API (Flask + Postgres) with 2,000,009
synthetic verification events distributed across 30 cities globally, before step 4:

| Endpoint                          | Latency  | Notes |
|-----------------------------------|---------:|-------|
| `/api/atlas/clusters` whole world | 1176 ms  | Worst case; one-time init |
| `/api/atlas/clusters` continent   |  645 ms  | 5° grid, 700K events scanned |
| `/api/atlas/clusters` metro       |  282 ms  | 0.1° grid, 60K events |
| `/api/atlas/points` metro top-100 |   35 ms  | Withdrawn 2026-10-02 |
| `/api/atlas/stats` continent      |  537 ms  | Single-pass aggregation |
| `/api/atlas/events` first page    |   31 ms  | Withdrawn 2026-10-02 |

The cluster and stats paths were withdrawn with step 4; the measurements stay as taken.

---

## List page pagination

`/tokens` and `/verifications` previously rendered every row, which
would produce a 2M-row HTML table at scale and OOM the browser. Both
now use page-based pagination (`?page=N&page_size=100`) with hard caps:
`page_size ∈ [10, 500]`, default 100.

The implementation uses `LIMIT N+1 OFFSET (page-1)*N`, where the +1
detects whether a next page exists without a separate `count(*)`
query. **Limitation**: deep pages are slow because OFFSET has to scan
past skipped rows. Page 1 is 62 ms; page 100 is 1.6 s; page 20000 is
13.6 s. Cursor pagination would make all pages O(log n): that's a
clean follow-up. Filtering (the typical operator workflow) reduces the
row set so deep pages are rare.

---

## Concurrency hardening

v6 also fixes three race conditions found while doing the scaling work.

### Atomic `failed_login_count` increment (`security.py`)

The previous code was a textbook TOCTOU:

```python
new_count = user['failed_login_count'] + 1     # read
cur.execute("UPDATE AppUser SET failed_login_count=%s ...", (new_count,))   # write
```

Two simultaneous failed logins both read N, both wrote N+1, losing one
failure. An attacker could spam concurrent failed logins and never trip
the lockout. The fix:

```python
cur.execute("UPDATE AppUser SET failed_login_count = failed_login_count + 1 "
            "WHERE user_id = %s RETURNING failed_login_count", (uid,))
new_count = cur.fetchone()['failed_login_count']
```

`UPDATE … SET col = col + 1` is atomic in PostgreSQL and resolves under
row lock. The lockout `UPDATE` is now also conditional on
`locked_until IS NULL` so threshold-crossing concurrent failures can't
double-apply the lockout interval.

Test: `ConcurrencyTests.test_failed_login_count_is_atomic_under_concurrent_load`
fires 8 parallel failed logins and asserts the counter shows exactly 8.

### `SELECT FOR UPDATE` in `uc4_activate_reserve` (`05_procedures.sql`)

UC-4 now locks the holder row first:

```sql
PERFORM 1 FROM Individual WHERE individual_id = v_lost_individual_id FOR UPDATE;
```

Two operators running UC-4 simultaneously for the same holder queue at
this lock; the second observes the post-T1 state and either succeeds
or fails cleanly with a domain error.

### `activation_sequence` race fix

The previous code hardcoded `activation_sequence = 2` (functionally
wrong past a holder's second active token, regardless of concurrency).
The fix computes `MAX(activation_sequence) + 1` inside the row-locked
region above, eliminating both the always-2 bug and the TOCTOU race.

### Unique partial index: the bullet-proof guarantee

Already present pre-v6. `uq_one_active_per_person` on
`IdentityToken(individual_id) WHERE status = 'ACTIVE'` enforces the
one-active-token invariant at the database level. Two parallel attempts
to set status=ACTIVE for the same individual: exactly one succeeds, the
other gets `psycopg2.errors.UniqueViolation`. Test:
`ConcurrencyTests.test_partial_unique_index_blocks_double_active`.

---

## Stress test reproduction

`polaris_sql/_stress_seed.sql` generates 2M synthetic verification
events distributed across 30 cities globally with realistic outcome
and disclosure distributions. To run:

```bash
psql -d polaris_test -f polaris_sql/_stress_seed.sql
```

Expect ~90 seconds for the INSERT (pure CPU; no I/O bottleneck).
`ANALYZE` runs at the end to give the query planner accurate stats.

---

## The end-to-end baseline

The atlas numbers above are SQL-function timings at ten million events. The
application-path numbers (issuance/s, verification/s, and atlas p95 through
gunicorn, on stated hardware, with stamps) are the published baseline in
[`PERFORMANCE-BASELINE.md`](PERFORMANCE-BASELINE.md), measured by hand on stated
hardware. CI runs the same script's five-second smoke on every push, a check of
the procedure rather than a baseline (v9.191, roadmap P1.9).

## Sizing a deployment

What one online verification costs, from the throughput measurement in
[`PERFORMANCE-BASELINE.md`](PERFORMANCE-BASELINE.md#through-the-production-path-per-vcpu-and-across-replicas)
(`POST /api/v1/verify` through the TLS edge, the app with its pool, pgbouncer, PostgreSQL and Redis,
every answer read, weekly in CI): on a 4-vCPU AMD EPYC 7763 host, one replica at 1 vCPU, about 18 ms
of CPU across the stack. Per 100 verifications a second at peak, that is:

| Tier | vCPU per 100 verifications a second |
|---|---:|
| PostgreSQL | 0.80 |
| App | 0.56 |
| pgbouncer | 0.24 |
| Edge | 0.15 |
| Redis | 0.03 |
| All | 1.77 |

The other configurations agree within 10%. A newer EPYC 9V74 spent about 12 ms instead of 18.

- **Size the database first.** It is the largest share and the one tier that does not scale out:
  Patroni runs one leader, and a verification reads the leader.
- **App replicas add capacity while the app tier is what binds.** Two replicas at 0.5 vCPU served
  1.93 times one. On one 4-vCPU host a second replica at 1 vCPU added 13%, because the database
  had taken the rest of the host.
- **Leave headroom.** The measured hosts ran at their CPU limit, at p95 latencies of 200 to 400 ms
  with 32 clients waiting.

For example, the ten-times peak of a hundred million people verified twelve times a year
([`COST-MODEL.md`](COST-MODEL.md)) is 381 a second. At these costs that needs about 3 vCPU of
PostgreSQL, 2 of app, 1 of pgbouncer and half of edge: about 7 vCPU before headroom.

Not measured: hosts larger than 4 vCPU, a database on its own host, more than two replicas,
scaling across hosts, and other hardware than the runners named. The measurement runs anywhere
Docker does: run `scripts/polaris-throughput-measure.sh` on the hardware you will deploy.

## What's not yet covered

- - **Cursor-based deep pagination** on the list pages: current
  implementation uses OFFSET, which is slow past page 100.
- **API-layer caching**: a Redis cache keyed by `(bbox, grid, kind)`
  with 30s TTL would push p95 latency for repeat views to <50 ms.
- **Frontend zoom-aware grid auto-sizing**: currently a fixed sliding
  scale; could be adaptive based on visible cluster density.
- **Stress test scheduling**: `_stress_seed.sql` is a one-shot script;
  a proper benchmark suite would run the full curl matrix against
  multiple data sizes (10K, 100K, 1M, 10M) and produce a regression
  table.

These are clean follow-ups, not blockers.
