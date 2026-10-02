# Scaling Polaris: measured at 10 million events

**Reader:** the operator or reviewer asking whether the Atlas and the
verification log stay interactive at national volumes. **Job:** the
measurements, the indexes and caps behind them, and the concurrency
hardening that ships alongside. The headline measurement below was taken
at 10 million verification events (v9.150); the later sections describe
the architecture that was first proven at 2 million and still holds.
Production deployments with tuned Postgres, connection pooling and edge
caching are faster than these developer-laptop numbers.

**Since 2026-10-02** the Atlas returns counts only
([lab/strategy/009](../../lab/strategy/009-atlas-athena-rework.md), step A0):
the map's single-event points, the event feed, the records grid and the person
focus were withdrawn, with `atlas_points_*`, `atlas_recent_events` and
`atlas_records`. Measurements of those paths below are kept as taken and say
they were withdrawn.

---

## Measured at 10 million events (v9.150)

Re-run on a developer laptop against a single PostgreSQL 16 with
**10,000,009 verification events** (a 2.75 GB table), reproducible with
[`scripts/polaris-atlas-benchmark.sh`](../../scripts/polaris-atlas-benchmark.sh)
(`scripts/polaris-atlas-benchmark.sh 10000000`):

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

The architecture below already delivers (1). Wiring the atlas overview onto a
materialized rollup (and, where PostGIS is available, the GiST geography index
from [`13_postgis.sql`](../../polaris_sql/13_postgis.sql)) is the standing
upgrade for instant whole-world rendering at hundreds of millions of rows; the
benchmark above is the acceptance harness for it.

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
                            ┌────────────────────────────┐
                            │  PostgreSQL 16             │
                            │                            │
                            │  VerificationEvent         │
                            │   ─ latitude               │
                            │   ─ longitude              │
                            │   ─ idx_..._geo            │
                            │   ─ idx_..._geo_time       │
                            │   ─ idx_..._time_id        │
                            │                            │
                            │  Functions:                │
                            │   ─ atlas_clusters_*()     │
                            │   ─ atlas_hexbin()         │
                            │   ─ atlas_stats()          │
                            │   ─ atlas_geo_*()          │
                            └────────────┬───────────────┘
                                         │ ≤ a few KB JSON per call
                                         │ regardless of table size
                                         ▼
                            ┌────────────────────────────┐
                            │  Flask app.py              │
                            │   /api/atlas/clusters      │
                            │   /api/atlas/hexbin        │
                            │   /api/atlas/stats         │
                            │   /api/atlas/geo/...       │
                            │  + bbox validation         │
                            │  + hard caps               │
                            └────────────┬───────────────┘
                                         ▼
                            ┌────────────────────────────┐
                            │  atlas-map.js              │
                            │   ─ currentBbox()          │
                            │   ─ chooseGrid(zoom)       │
                            │   ─ debounced fetcher      │
                            │   ─ cluster→point switch   │
                            │   ─ HUD signal updater     │
                            │   ─ event-feed paginator   │
                            └────────────────────────────┘
```

The browser never sees more than a few hundred markers at a time.
Server-side aggregation collapses a million events in a 5° grid cell
into a single cluster row carrying only the centroid + summary counts:

```json
{ "lat": 40.71, "lon": -74.01, "n_total": 66693,
  "n_failure": 5311, "n_pq": 39958, "n_zk": 26677, "n_full": 16678 }
```

That's ~120 bytes regardless of whether the cluster represents 100
events or 10 million.

---

## Storage

`VerificationEvent` and `TokenLifecycleEvent` gained `latitude` and
`longitude` columns in v6 (`01_schema.sql`):

```sql
latitude   DOUBLE PRECISION CHECK (latitude  IS NULL OR (latitude  BETWEEN  -90 AND  90)),
longitude  DOUBLE PRECISION CHECK (longitude IS NULL OR (longitude BETWEEN -180 AND 180))
```

Nullable so legacy rows without recorded location remain valid; cluster
aggregation excludes NULL coordinates so stats stay accurate.

Indexes (`02_indexes.sql`):

| Index                                | Purpose                                  |
|--------------------------------------|------------------------------------------|
| `idx_verificationevent_geo`          | Bbox queries from `atlas_clusters_*()`   |
| `idx_verificationevent_geo_time`     | Time-bounded bbox queries (rare path)    |
| `idx_verificationevent_time_id`      | Keyset pages of the verification log     |
| `idx_tokenlifecycleevent_geo`        | Bbox queries on lifecycle events         |
| `idx_tokenlifecycleevent_time`       | Time-ordered reads of lifecycle events   |

All geo indexes are partial (`WHERE latitude IS NOT NULL`) so they
don't include legacy data points and stay small.

PostGIS would give us proper spatial indexes (GiST on a `geography`
type, R-tree on `geometry`) and allow polygon queries, but plain B-tree
composite indexes on (lat, lon) are sufficient for bbox queries: the
only spatial primitive Atlas needs.

---

## Server-side aggregation (`11_atlas.sql`)

### `atlas_clusters_verifications(min_lat, min_lon, max_lat, max_lon, grid)`

Bins events by `floor(lat / grid), floor(lon / grid)` and returns one
row per cell with the centroid + diagnostic counts. STABLE function so
PostgreSQL caches the plan.

```sql
SELECT avg(ve.latitude), avg(ve.longitude),
       count(*),
       count(*) FILTER (WHERE ve.outcome = 'FAILURE'),
       count(*) FILTER (WHERE ca.quantum_resistant),
       ...
FROM VerificationEvent ve
LEFT JOIN IdentityToken t  ON ve.token_id = t.token_id
LEFT JOIN CryptographicAlgorithm ca ON ...
WHERE ve.latitude  BETWEEN p_min_lat AND p_max_lat
  AND ve.longitude BETWEEN p_min_lon AND p_max_lon
GROUP BY floor(ve.latitude / p_grid), floor(ve.longitude / p_grid)
```

### `atlas_stats(bbox)`

Computes the four HUD signals in a **single pass** with FILTER
aggregates. The first iteration referenced a CTE 8 times and ran in
1428 ms; the rewrite is 511 ms.

---

## API endpoints

The map's endpoints are auth-required. Bbox parameter format:
`min_lat,min_lon,max_lat,max_lon` decimal degrees. Antimeridian-spanning bboxes are supported as of v7 via a wrap-aware
longitude predicate (see Antimeridian section below).

| Endpoint                    | Hard cap          | Purpose |
|-----------------------------|-------------------|---------|
| `GET /api/atlas/clusters`   | 5000 clusters     | Aggregated bins for low-zoom |
| `GET /api/atlas/stats`      | one row           | HUD signals scoped to bbox |
| `GET /api/atlas/hexbin`     | 5000 hexagons     | Density surface |
| `GET /api/atlas/geo/jurisdictions` | 500 regions | Counts per jurisdiction (the default layer) |

---

## Frontend (atlas-map.js)

The map is a MapLibre GL canvas with two aggregate layers: counts per
jurisdiction (the default) and a hexagon density surface. Nothing is drawn in
the DOM, and nothing drawn is a single event: a click on a region or a hexagon
zooms in.

`scheduleFetch()` is debounced at 200 ms: pan and zoom trigger one batched
API call rather than one per frame, and an AbortController cancels the
previous fetch when a new one starts.

---

## Performance at 2M scale

Measured against the live API (Flask + Postgres) with 2,000,009
synthetic verification events distributed across 30 cities globally:

| Endpoint                          | Latency  | Notes |
|-----------------------------------|---------:|-------|
| `/api/atlas/clusters` whole world | 1176 ms  | Worst case; one-time init |
| `/api/atlas/clusters` continent   |  645 ms  | 5° grid, 700K events scanned |
| `/api/atlas/clusters` metro       |  282 ms  | 0.1° grid, 60K events |
| `/api/atlas/points` metro top-100 |   35 ms  | Withdrawn 2026-10-02 |
| `/api/atlas/stats` continent      |  537 ms  | Single-pass aggregation |
| `/api/atlas/events` first page    |   31 ms  | Withdrawn 2026-10-02 |

User-perceptible latency at 1M+ scale would benefit from caching at the
API layer (Redis) keyed by `(bbox, grid, kind)` with a short TTL: a
typical operator's pan/zoom oscillates over a small set of common views.

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
[`PERFORMANCE-BASELINE.md`](PERFORMANCE-BASELINE.md), re-run by CI on every
push (v9.191, roadmap P1.9).

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
