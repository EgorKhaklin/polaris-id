# Atlas scaling

**Reader:** an engineer or an assessor. **Job:** How the map stays bounded as the event log grows.

The short version. The measured numbers and the full treatment are in
[../reference/SCALING.md](../reference/SCALING.md).

## Why the architecture is what it is

At a million events the map cannot be sent to the browser: the payload is
gigabytes. So the aggregation happens in the database. The browser sends the
visible bounding box and a grid size, the server returns one cluster summary
per occupied grid cell, each a centroid and its counts, and never more than
`_ATLAS_MAX_CLUSTERS` (5,000) however fine a grid the client asks for, and the browser draws those instead
of the events. When a zoom brings the count in view down to a handful, the
client fetches the individual events instead.

## The analytical console (v9.248, roadmap P2.3)

As of v9.248 the Atlas opens on an **Overview**, not the globe. The Overview is
a bounded, non-geographic analytics surface: a volume time-series with failures
overlaid, KPI cards, and top-K breakdowns by context, agency, disclosure and
outcome. The globe is a **Map** tab, kept for what a map is actually good at (where
activity is, by region and by density) and booted lazily. It follows no one: the
single-subject view was withdrawn with lab/strategy/009.

The scaling principle is the same as the map's, applied to every view: the
answer is a bounded server-side aggregate, never the raw events. Two functions
back the Overview, both in `11_atlas.sql` and both deliberately **non-spatial**,
so they count a zero-knowledge verification (in volume, in the disclosure and
agency tallies) without ever carrying its location (C6):

| Function | Purpose | Bound |
|---|---|---|
| `atlas_volume_series(since, buckets, kind, …)` | total-volume time series (counts EVERY event, unlike `atlas_timeline` which is located-only for the map strip) | ≤240 buckets |
| `atlas_breakdown(dimension, since, limit, kind, …)` | top-K roll-up by one whitelisted dimension | `_ATLAS_MAX_CATEGORIES` (50) |
| `atlas_crosstab(row_dim, col_dim, since, limit, kind, …)` | 2-D pivot (Breakdown view): top-K rows x a low-cardinality column dimension | `_ATLAS_MAX_CATEGORIES` rows |
| `atlas_agency_facet(since, limit, kind, search, …)` | the global filter's agency facet: agencies with (id, name, count) for the typeahead, honouring the other active facets | `_ATLAS_MAX_CATEGORIES` |
| `atlas_hexbin(minlat, minlon, maxlat, maxlon, size, limit, since, kind, …)` | Map v2 Density layer: located verification events binned into a pointy-top hex grid, top-K densest centres by count; excludes ZK entirely like the cluster layer (C6) | `_ATLAS_MAX_CLUSTERS` |
| `atlas_geo_jurisdictions(since, limit, kind, …)` | Map v2 Regions layer (default): volume by requesting-agency jurisdiction (ISO 3166-2); COUNTS ZK (n_zk) but the centroid derives from located non-ZK events only, so a ZK-only jurisdiction is counted yet unplaceable (C6) | `_ATLAS_MAX_REGIONS` |

Their endpoints (`/api/atlas/series`, `/api/atlas/breakdown`) are
`@replica_reads` and capped, and the charts are hand-rolled inline SVG / CSS
bars in `atlas-console.js` (no charting library, so `script-src 'self'` stays
strict).

### Partition pruning under the generic plan (v9.260, benchmark-driven)

The event tables are monthly-partitioned by `event_timestamp` (P2.1), so a
windowed roll-up ("last 24h", "last 7d") should read only the relevant
partitions, not every month of history. The national benchmark (P2.14) found
that it didn't: the roll-ups reached the window through
`p_since IS NULL OR event_timestamp >= p_since` (or, in the time-series
functions, through a `params` CTE column). Both shapes read fine as SQL, but
they **defeat partition pruning under the generic plan** a parameterized
statement gets after a few executions — the path the app actually runs — so a
recent-window query scanned all N monthly partitions instead of one or two. At a
year of history that is a 12× read amplification; at the national retention
horizon, far more.

The fix is one predicate shape, applied across every windowed roll-up:

```sql
event_timestamp >= COALESCE(p_since, '-infinity'::timestamp)
```

A concrete `p_since` now prunes to the window's partitions under the generic
plan; a `NULL` (all-time) query still resolves to `>= -infinity`, which
correctly matches every partition. The results are identical to before — only
the plan changed. `check_atlas_rollups_prune` forbids either pruning-defeating
shape from returning, `test_app.AtlasPartitionPruningTests` proves the pruning
under a *forced* generic plan, and the benchmark reports the partitions a recent
window scans versus an all-time query (see
[../reference/BENCHMARK.md](../reference/BENCHMARK.md)).

## Data path (the Map view)

The map draws counts only: counts per jurisdiction (the default) or a hexagon
density surface. Since 2026-10-02 it draws no single event and names no one
([lab/strategy/009](../../lab/strategy/009-atlas-athena-rework.md), step A0); the
point layer, the event feed and the person focus were withdrawn.

```
a pan or zoom in the browser
  → atlas-map.js scheduleFetch(), debounced at 200 ms
    → currentBbox() derives [min_lat, min_lon, max_lat, max_lon]
    → chooseHexSize(zoom) maps the zoom level to a hexagon size in degrees
    → GET /api/atlas/hexbin?bbox=…&size=…&kind=…  (or /api/atlas/geo/jurisdictions)
      → the route validates the bbox and applies the cap
        → atlas_hexbin(...) in SQL
          → the geo index serves the bbox filter
          → counts per hexagon, zero-knowledge events excluded (C6)
          → at most 5000 rows
      → JSON
    → the GeoJSON source is replaced and MapLibre redraws its layers
  → the corner readouts update from /api/atlas/stats, fetched in parallel
```

## What's in 11_atlas.sql

The map's STABLE functions. STABLE = same input + same data → same output, no
side effects. PostgreSQL caches plans for STABLE functions.

| Function | Purpose | Worst-case at 2M |
|---|---|---|
| `atlas_clusters_verifications(bbox, grid)` | Aggregated bins, verification kind | 1.2 s whole world |
| `atlas_clusters_lifecycles(bbox, grid)` | Aggregated bins, lifecycle kind | <100 ms (small table) |
| `atlas_stats(bbox)` | HUD signals, single-pass aggregation | 511 ms |

## API contract

The map's `/api/atlas/*` endpoints:
- Require `@security.login_required`
- Accept `bbox=min_lat,min_lon,max_lat,max_lon` decimal degrees where they are viewport-bound
- Validate via `_parse_bbox()` (see atlas_routes.py)
- Return counts, never an event row
- Hard-capped: clusters and hexagons ≤ 5000, regions ≤ 500

## Crossing the antimeridian

`_parse_bbox()` accepts a bbox where `min_lon > max_lon`. The atlas SQL
functions use a wrap-aware predicate of the form:

```sql
(p_min_lon <= p_max_lon AND longitude BETWEEN p_min_lon AND p_max_lon)
OR (p_min_lon  > p_max_lon AND (longitude >= p_min_lon OR longitude <= p_max_lon))
```

PostgreSQL's planner uses bitmap OR over the partial geo indexes, so
performance is comparable to non-wrapping bboxes.


## Constants that were tuned, not chosen

Each of these was set against a real distribution, and changing one without
measuring undoes that.

1. **The hexagon size in `chooseHexSize(zoom)`.** A finer lattice means more
   hexagons and more work per frame. Changing it needs a check on pan and zoom
   responsiveness at a realistic event count.
2. **The 200 millisecond debounce.** Below about 150 the API takes a request
   per frame during a smooth pan; above about 400 the map feels late.
3. **The caps: 5000 clusters or hexagons, 500 regions.** Past those, JSON
   serialisation and the redraw dominate the response.

The switch from clusters to single events, tuned at a count of thirty, went with
the point layer (lab/strategy/009).

## Performance regression checks

Run these and compare to the table in docs/reference/SCALING.md:

```bash
# After loading stress data:
psql -d polaris_test <<'SQL'
\timing on
SELECT count(*) FROM atlas_clusters_verifications(-90,-180,90,180,10);
SELECT count(*) FROM atlas_clusters_verifications(20,-130,50,-65,5);
SELECT * FROM atlas_stats(20,-130,50,-65);
SQL
```

Target latencies (warm cache, 2M events):
- clusters whole-world: <1500 ms
- clusters continent: <800 ms
- stats: <600 ms

If any are 2× off, run `EXPLAIN ANALYZE` and check whether an index
got dropped or whether the planner picked a seq scan when an index
scan was expected.

## The optional PostGIS path

The default schema uses composite B-tree indexes on
`(latitude, longitude)` for atlas spatial queries. B-tree starts to
break down past ~10M events because the index doesn't model
2-dimensional proximity natively: a bbox query degrades toward a
range scan over one dimension.

An optional migration, `polaris_sql/13_postgis.sql`, adds, when the `postgis`
extension is available, a generated
`geography(Point, 4326)` column to `VerificationEvent` and
`TokenLifecycleEvent` plus a GiST index on each. GiST models 2D
proximity correctly; bbox + radius queries return a logarithmic
fraction of the index instead of a linear scan.

### When the PostGIS path is active

```sql
-- Detect mode
SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='postgis') AS postgis_loaded;
```

When `postgis_loaded` is `t`, two new columns + indexes exist:

| Table | Column | Index | Type |
|---|---|---|---|
| `VerificationEvent` | `geo geography(Point, 4326)` (generated, stored) | `gix_verification_geo` | GiST |
| `TokenLifecycleEvent` | `geo geography(Point, 4326)` (generated, stored) | `gix_lifecycle_geo` | GiST |

The columns are `GENERATED ALWAYS AS (... STORED)` from
`(latitude, longitude)` so they stay in sync without app-code
changes.

### Sample GiST-aware query (operator-side)

The atlas functions still take the B-tree path. Rewriting them to use the
GiST index is gated on two things that do not exist yet: a PostGIS-enabled
environment to develop against, and a ten-million-event dataset to measure the
threefold improvement the rewrite would have to show. Until then an operator
can query the GiST index directly:

```sql
-- All verifications within 50km of Pittsburgh
SELECT event_id, event_timestamp, latitude, longitude
FROM VerificationEvent
WHERE geo IS NOT NULL
  AND ST_DWithin(
          geo,
          ST_SetSRID(ST_MakePoint(-79.9959, 40.4406), 4326)::geography,
          50000   -- meters
      );
```

### When to leave it off

The extension is around fifty megabytes and sits behind a paid tier on some
managed PostgreSQL providers. Below roughly five million events the B-tree
path is operationally complete, so there is nothing to gain. A deployment
whose role cannot run `CREATE EXTENSION postgis` once gets a notice from the
migration and keeps the B-tree path.

### What the rewrite would look like

The atlas functions would branch on whether the extension is present and emit
either the GiST or the B-tree query at call time. The acceptance criterion is
a threefold improvement at ten million events or more, measured with
`scripts/polaris-load-test.sh` against both modes. Until that is measured the
branch is not worth its complexity.
