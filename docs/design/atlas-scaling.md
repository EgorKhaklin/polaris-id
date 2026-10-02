# Atlas scaling

**Reader:** an engineer or an assessor. **Job:** How the Atlas costs the same at any population.

The short version. The measured numbers and the wider treatment are in
[../reference/SCALING.md](../reference/SCALING.md); what the Atlas may and may not show is
[lab/strategy/009](../../lab/strategy/009-atlas-athena-rework.md).

## Why the architecture is what it is

At a national population the event tables hold billions of rows, and any view that reads them
costs in proportion to them, however well it filters: partition pruning bounded a window to its
months, and a year's window still read a year of events. So the Atlas reads none of them. Every
figure it shows is a sum over the **activity rollups**, totals kept as events are recorded, and
a rollup's rows number the hours a window spans times the authorities, contexts, outcomes,
disclosure levels and algorithms active in them. A question about the last week costs about the
same at five million events as at five billion (lab/strategy/009, step 4).

The rollups hold no person, no credential, no event and no coordinate, so the Atlas cannot show
one: C6 holds for it by construction rather than by a filter each function has to remember.

## The rollups

Six tables in `01_schema.sql`:

| Table | Holds | Kept by |
|---|---|---|
| `VerificationRollup` | verifications per hour, requesting authority, context, outcome, disclosure level, algorithm | the fold |
| `VerificationRollupDaily` | the same per day | the fold |
| `VerificationRollupDelta` | counts appended per insert statement, not yet folded | a statement trigger on `VerificationEvent` |
| `LifecycleRollup`, `LifecycleRollupDaily`, `LifecycleRollupDelta` | lifecycle events per hour (day), acting authority, event type | the same, on `TokenLifecycleEvent` |

A statement trigger with a transition table appends one row per combination an `INSERT`
touched, so a bulk load of a million events adds a handful of delta rows, and writers never
contend on a counter. `uc_fold_activity_rollups()` moves the delta into the hourly and daily
totals under a try-lock (a fold that finds another running skips rather than waits); the
retention purge folds first, then deletes hourly rows before its cutoff and keeps the daily
ones, so `all` reads days back to the first event while hours go as far as retention keeps
them. `uc_rebuild_activity_rollups()` recounts everything from the event tables, owner-only.
Row-level security scopes each table by authority, as the event tables are scoped.

## The readers (`11_atlas.sql`)

Every reader sums the rollups. Three helpers carry the shared work, and the readers sum their
output:

| Function | Does | Bound |
|---|---|---|
| `atlas_verification_cells`, `atlas_lifecycle_cells` | the hourly (or daily) rows and the unfolded delta from a window's start | hours x combinations |
| `atlas_verification_matching`, `atlas_lifecycle_matching` | the cells under the filters, matched by id | the same |
| `atlas_verification_combos`, `atlas_lifecycle_combos` | the window summed over its hours, names joined last | the combinations in use |
| `atlas_stats` | the headline: verifications, not successful, full, zero-knowledge, quantum-resistant, lifecycle, active credentials | one row |
| `atlas_volume_series` | volume per bucket | 240 buckets (`_ATLAS_MAX_BUCKETS`) |
| `atlas_breakdown` | counts by one whitelisted dimension | `_ATLAS_MAX_CATEGORIES` (50) |
| `atlas_crosstab` | a row dimension by a fixed column dimension | 50 rows |
| `atlas_heatmap` | weekday by hour | 168 cells |
| `atlas_series_stacked` | volume per bucket by the top six categories and Other | 240 x 7 |
| `atlas_agency_facet` | every authority matching a search, in name order | 50 |
| `atlas_geo_jurisdictions` | counts by jurisdiction | `_ATLAS_MAX_REGIONS` (500) |

Each cell reader windows every branch on `bucket >= COALESCE(p_since, '-infinity'::TIMESTAMP)`,
the shape a generic plan can serve from the rollups' leading key; `p_since IS NULL OR ...`
would not be. `check_atlas_rollups_prune` pins that no `atlas_*` function reads an event table
and that every branch is windowed so; `test_app.AtlasReadsNoEventTableTests` proves the first
by privilege, revoking the application role's SELECT on both event tables in a rolled-back
transaction and calling every reader; and the national benchmark does the same under load.

## What a response shows

The routes in `atlas_routes.py` withhold every count below `_ATLAS_MIN_CELL` (5), as a part of
its window's scope: a part is withheld when it or the rest of its scope is below the minimum.
Fixed dimensions are zero-filled, open lists fold their small categories into one row, and a
question whose scope holds fewer than `_ATLAS_NARROW_SCOPE` (50) events is logged with who asked.
The API reference has the rules in full ([../reference/API.md](../reference/API.md), Atlas API).

Windows are the rollups': a window starts at the top of the hour (or, past a week, the day)
that holds its nominal start, and a series bucket is whole hours or days, since the rollups hold
nothing finer.

## Data path

```
a view opens or a filter changes in the browser
  -> atlas-console.js (Overview, Breakdown, Trends) or atlas-map.js (Map)
    -> GET /api/atlas/series | breakdown | crosstab | heatmap | stacked | facet/agencies
           | geo/jurisdictions | stats
      -> the route parses and whitelists the filters, clamps every count (C8)
      -> the cache answers a repeated question for the same scope (30 s)
      -> else atlas_*() in SQL, as the caller's role, under row-level security
        -> the rollups from the window's start; the delta not yet folded
        -> summed by the combinations in use, names joined last
      -> the counts withheld below the minimum; a narrow question logged
      -> JSON
    -> inline SVG and CSS bars; a withheld count reads "<5", never zero
```

The map places a region from `static/atlas-regions.json`, reference data about the
jurisdiction (a capital's coordinates, roughly), never from where anyone was verified.

## Measured

On one laptop (Apple M3, 8 cores), PostgreSQL 16, two million people and ten million
verifications, warm, through the Flask test client (`polaris_scale`):

| Route | Before (event tables) | After (rollups) |
|---|---|---|
| `/atlas` (the page, its headline figures) | 6,728 ms | 31 ms |
| `/api/atlas/series?window=all` | 5,738 ms | 26 ms |
| `/api/atlas/geo/jurisdictions?window=all` | 5,649 ms | 17 ms |

Against the same routes on the seed database (ten verifications), the readers run at 1.0 to 2.4
times their seed cost at ten million verifications, with one exception:
`/api/atlas/heatmap?window=30d` runs at 3.4 times (43.1 ms against 12.6 ms). The heatmap reads
hours, not days, so a thirty-day window reads up to 720 hours times the combinations active in
each, and at this load nearly every combination is active in nearly every hour: the hourly
rollup saturates at hours x authorities x contexts x outcomes x disclosure levels x algorithms.
The fix, when a deployment needs it, is a per-authority hourly total without the other
dimensions, which the heatmap's filters do not need when they are unset; it is recorded as
deferred in lab/strategy/009 rather than built ahead of a need.

`scripts/polaris-atlas-benchmark.sh N` reproduces the reader timings on a throwaway database.

## Constants that were chosen

1. **The minimum cell, 5.** Lab/strategy/009 (option c). A count of one at a known authority,
   context and hour tells someone who knows who was there what happened to them.
2. **The narrow scope, 50.** Below it a question is logged: it is answered, withheld as any,
   and leaves a trace, as a read of the verification log does.
3. **The caps: 50 categories, 500 regions, 240 buckets.** Past those, serialisation and the
   redraw dominate, and none of them is a question an operator needs answered at once.
4. **The top six bands of the stacked series.** More than six colours stop reading as categories.

## The optional PostGIS path

`polaris_sql/13_postgis.sql` adds, when the `postgis` extension is available, a generated
`geography(Point, 4326)` column to each event table with a GiST index, for operators who query
locations directly (the verification log's own filters, an investigation under warrant). The
Atlas no longer reads a location, so it gains nothing from the path; whether the event tables
keep their location indexes at all, now that the Atlas does not read them, is the next step of
lab/strategy/009 (each costs every insert something).

An operator with PostGIS active can query the GiST index directly, for example every
verification within 50 km of a point:

```sql
SELECT event_id, event_timestamp, latitude, longitude
FROM VerificationEvent
WHERE geo IS NOT NULL
  AND ST_DWithin(
          geo,
          ST_SetSRID(ST_MakePoint(-79.9959, 40.4406), 4326)::geography,
          50000   -- meters
      );
```

That query reads events and is a read of the event log, not of the Atlas.

**When to leave it off.** The extension is around fifty megabytes and sits behind a paid tier
on some managed PostgreSQL providers; a deployment whose role cannot run
`CREATE EXTENSION postgis` gets a notice from the migration and keeps the B-tree indexes.
