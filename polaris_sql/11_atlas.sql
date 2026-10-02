-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Egor Khaklin and the Polaris contributors
-- ============================================================================
-- AI-context: read these before editing this file:
--     ../lab/strategy/009-atlas-athena-rework.md    <- what the Atlas may and may not show
--     ../docs/design/atlas-scaling.md               <- how it stays the same cost at any size
-- ============================================================================

-- ============================================================================
-- POLARIS - IDENTITY TOKEN SYSTEM
-- 11_atlas.sql : what the Atlas counts, read from the activity rollups
--
-- The Atlas shows the system and never a person (lab/strategy/009): counts over fixed windows,
-- categories and regions. Every function here reads the activity rollups (01_schema.sql), which
-- count verifications by hour (and day), requesting authority, context, outcome, disclosure level
-- and algorithm, and lifecycle events by hour, acting authority and type. None reads an event
-- table, so each costs in proportion to the hours a window spans and the authorities and contexts
-- active in them, whatever the population. None returns an event, a person, a credential or a
-- coordinate: the rollups hold none, so a zero-knowledge verification is counted and cannot be
-- located (C6).
--
-- WINDOWS. p_since is the start of the hour (or, with p_daily, the day) that holds the window's
-- nominal start; the route computes it and the page says it. p_daily reads the daily rollup, for
-- windows longer than a week. A series groups its rows into buckets of p_width from p_since.
--
-- Every function is STABLE and runs as its caller, so the rollups' row-level security scopes an
-- operator bound to one authority to that authority's counts. The routes cap every caller-chosen
-- count before it arrives here (C8), and withhold every count below the minimum cell size.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Per-event reads, withdrawn (lab/strategy/009, step A0)
--
-- atlas_points_verifications, atlas_points_lifecycles, atlas_recent_events and
-- atlas_records returned one row per event with the holder's name and the
-- credential number (the points with coordinates too), to any signed-in role,
-- and the routes calling them wrote no AuditAccessLog row. The Atlas shows
-- counts and never a person; a single event is read on the verification log,
-- which records the read. This file is object-synced, so the functions are
-- dropped here, not only deleted from it.
-- ----------------------------------------------------------------------------
DROP FUNCTION IF EXISTS atlas_points_verifications(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    INTEGER, TIMESTAMP, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_points_verifications(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    INTEGER, TIMESTAMP, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_points_lifecycles(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    INTEGER, TIMESTAMP, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_points_lifecycles(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    INTEGER, TIMESTAMP, TEXT);
DROP FUNCTION IF EXISTS atlas_recent_events(TIMESTAMP, INTEGER, INTEGER);
DROP FUNCTION IF EXISTS atlas_records(
    TIMESTAMP, TIMESTAMP, INTEGER, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT);


-- ----------------------------------------------------------------------------
-- Location layers and event reads, withdrawn (lab/strategy/009, step 4)
--
-- The cluster and hexagon functions binned events by coordinate, and at street zoom a bin of one
-- is a point; the timeline counted located events in a box. Every remaining function reads the
-- rollups, which hold no coordinate. The earlier signatures of the functions below read the
-- event tables, and are dropped so that a synced database keeps no overload of them.
-- ----------------------------------------------------------------------------
DROP FUNCTION IF EXISTS atlas_clusters_verifications(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    DOUBLE PRECISION, TIMESTAMP, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_clusters_verifications(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    DOUBLE PRECISION, TIMESTAMP, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_clusters_lifecycles(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    DOUBLE PRECISION, TIMESTAMP, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_clusters_lifecycles(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    DOUBLE PRECISION, TIMESTAMP, TEXT);
DROP FUNCTION IF EXISTS atlas_hexbin(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    DOUBLE PRECISION, INTEGER, TIMESTAMP, TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_timeline(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    TIMESTAMP, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_timeline(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    TIMESTAMP, INTEGER, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_stats(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, TIMESTAMP, TEXT);
DROP FUNCTION IF EXISTS atlas_stats(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, TIMESTAMP);
DROP FUNCTION IF EXISTS atlas_volume_series(TIMESTAMP, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_stats(TIMESTAMP, BOOLEAN, TEXT);
DROP FUNCTION IF EXISTS atlas_volume_series(TIMESTAMP, BOOLEAN, INTERVAL, TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_breakdown(TEXT, TIMESTAMP, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_breakdown(TEXT, TIMESTAMP, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_crosstab(TEXT, TEXT, TIMESTAMP, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_heatmap(TIMESTAMP, TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_series_stacked(
    TIMESTAMP, INTEGER, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_agency_facet(TIMESTAMP, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_geo_jurisdictions(TIMESTAMP, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_verification_filtered(TIMESTAMP, BOOLEAN, TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS atlas_lifecycle_filtered(TIMESTAMP, BOOLEAN, TEXT);


-- ----------------------------------------------------------------------------
-- The cells a window reads: the totals from p_since, hourly or daily, and the counts the
-- triggers appended that no fold has moved yet, at the same grain.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_verification_cells(p_since TIMESTAMP, p_daily BOOLEAN)
RETURNS TABLE (
    bucket               TIMESTAMP,
    requesting_agency_id INTEGER,
    context_id           INTEGER,
    outcome              TEXT,
    disclosure_level     TEXT,
    algorithm_id         INTEGER,
    n                    BIGINT
)
LANGUAGE sql
STABLE
AS $$
    SELECT r.bucket, r.requesting_agency_id, r.context_id, r.outcome::TEXT,
           r.disclosure_level::TEXT, r.algorithm_id, r.n
      FROM VerificationRollup r
     WHERE NOT p_daily AND r.bucket >= COALESCE(p_since, '-infinity'::TIMESTAMP)
    UNION ALL
    SELECT r.bucket, r.requesting_agency_id, r.context_id, r.outcome::TEXT,
           r.disclosure_level::TEXT, r.algorithm_id, r.n
      FROM VerificationRollupDaily r
     WHERE p_daily AND r.bucket >= COALESCE(p_since, '-infinity'::TIMESTAMP)
    UNION ALL
    SELECT CASE WHEN p_daily THEN date_trunc('day', d.bucket) ELSE d.bucket END,
           d.requesting_agency_id, d.context_id, d.outcome::TEXT, d.disclosure_level::TEXT,
           d.algorithm_id, d.n
      FROM VerificationRollupDelta d
     WHERE d.bucket >= COALESCE(p_since, '-infinity'::TIMESTAMP);
$$;

CREATE OR REPLACE FUNCTION atlas_lifecycle_cells(p_since TIMESTAMP, p_daily BOOLEAN)
RETURNS TABLE (
    bucket          TIMESTAMP,
    actor_agency_id INTEGER,
    event_type      TEXT,
    n               BIGINT
)
LANGUAGE sql
STABLE
AS $$
    SELECT r.bucket, r.actor_agency_id, r.event_type::TEXT, r.n
      FROM LifecycleRollup r
     WHERE NOT p_daily AND r.bucket >= COALESCE(p_since, '-infinity'::TIMESTAMP)
    UNION ALL
    SELECT r.bucket, r.actor_agency_id, r.event_type::TEXT, r.n
      FROM LifecycleRollupDaily r
     WHERE p_daily AND r.bucket >= COALESCE(p_since, '-infinity'::TIMESTAMP)
    UNION ALL
    SELECT CASE WHEN p_daily THEN date_trunc('day', d.bucket) ELSE d.bucket END,
           d.actor_agency_id, d.event_type::TEXT, d.n
      FROM LifecycleRollupDelta d
     WHERE d.bucket >= COALESCE(p_since, '-infinity'::TIMESTAMP);
$$;

-- The cells a question selects, filtered by id: no name is joined until the cells are few. A
-- context filter is matched through VerificationContext's few rows, an authority by its id. The
-- filters are CSV, matched whole; the routes accept one context and one authority at a time
-- (lab/strategy/009, step 4).
CREATE OR REPLACE FUNCTION atlas_verification_matching(
    p_since      TIMESTAMP,
    p_daily      BOOLEAN,
    p_outcomes   TEXT DEFAULT NULL,
    p_disclosure TEXT DEFAULT NULL,
    p_contexts   TEXT DEFAULT NULL,
    p_agencies   TEXT DEFAULT NULL
) RETURNS TABLE (
    bucket               TIMESTAMP,
    requesting_agency_id INTEGER,
    context_id           INTEGER,
    outcome              TEXT,
    disclosure_level     TEXT,
    algorithm_id         INTEGER,
    n                    BIGINT
)
LANGUAGE sql
STABLE
AS $$
    SELECT c.bucket, c.requesting_agency_id, c.context_id, c.outcome, c.disclosure_level,
           c.algorithm_id, c.n
      FROM atlas_verification_cells(p_since, p_daily) c
     WHERE (p_outcomes   IS NULL OR c.outcome = ANY(string_to_array(p_outcomes, ',')))
       AND (p_disclosure IS NULL OR c.disclosure_level = ANY(string_to_array(p_disclosure, ',')))
       AND (p_contexts   IS NULL OR c.context_id IN (
                SELECT vc.context_id FROM VerificationContext vc
                 WHERE vc.context_type = ANY(string_to_array(p_contexts, ','))))
       AND (p_agencies   IS NULL OR c.requesting_agency_id::TEXT = ANY(string_to_array(p_agencies, ',')));
$$;

CREATE OR REPLACE FUNCTION atlas_lifecycle_matching(
    p_since    TIMESTAMP,
    p_daily    BOOLEAN,
    p_agencies TEXT DEFAULT NULL
) RETURNS TABLE (
    bucket          TIMESTAMP,
    actor_agency_id INTEGER,
    event_type      TEXT,
    n               BIGINT
)
LANGUAGE sql
STABLE
AS $$
    SELECT c.bucket, c.actor_agency_id, c.event_type, c.n
      FROM atlas_lifecycle_cells(p_since, p_daily) c
     WHERE p_agencies IS NULL OR c.actor_agency_id::TEXT = ANY(string_to_array(p_agencies, ','));
$$;

-- The window's combinations, summed over its hours: an authority, a context, an outcome, a
-- disclosure level and an algorithm, with names joined only now, onto rows numbering the
-- combinations in use rather than the hours times them. The readers that need no time read
-- these.
CREATE OR REPLACE FUNCTION atlas_verification_combos(
    p_since      TIMESTAMP,
    p_daily      BOOLEAN,
    p_outcomes   TEXT DEFAULT NULL,
    p_disclosure TEXT DEFAULT NULL,
    p_contexts   TEXT DEFAULT NULL,
    p_agencies   TEXT DEFAULT NULL
) RETURNS TABLE (
    agency_id         INTEGER,
    agency_name       TEXT,
    jurisdiction      TEXT,
    context_type      TEXT,
    outcome           TEXT,
    disclosure_level  TEXT,
    algorithm_id      INTEGER,
    algorithm_name    TEXT,
    quantum_resistant BOOLEAN,
    n                 BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH c AS (
        SELECT requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id,
               sum(n) AS n
          FROM atlas_verification_matching(p_since, p_daily, p_outcomes, p_disclosure,
                                           p_contexts, p_agencies)
         GROUP BY requesting_agency_id, context_id, outcome, disclosure_level, algorithm_id
    )
    SELECT c.requesting_agency_id, ag.name::TEXT, ag.jurisdiction::TEXT, vc.context_type::TEXT,
           c.outcome, c.disclosure_level, c.algorithm_id, ca.name::TEXT,
           COALESCE(ca.quantum_resistant, FALSE), c.n::BIGINT
      FROM c
      JOIN Agency ag ON ag.agency_id = c.requesting_agency_id
      JOIN VerificationContext vc ON vc.context_id = c.context_id
      LEFT JOIN CryptographicAlgorithm ca ON ca.algorithm_id = c.algorithm_id;
$$;

-- A transition no authority made (actor 0) has no name and no jurisdiction; the readers call it
-- 'System / device' and '(system)'.
CREATE OR REPLACE FUNCTION atlas_lifecycle_combos(
    p_since    TIMESTAMP,
    p_daily    BOOLEAN,
    p_agencies TEXT DEFAULT NULL
) RETURNS TABLE (
    actor_agency_id INTEGER,
    agency_name     TEXT,
    jurisdiction    TEXT,
    event_type      TEXT,
    n               BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH c AS (
        SELECT actor_agency_id, event_type, sum(n) AS n
          FROM atlas_lifecycle_matching(p_since, p_daily, p_agencies)
         GROUP BY actor_agency_id, event_type
    )
    SELECT c.actor_agency_id, ag.name::TEXT, ag.jurisdiction::TEXT, c.event_type, c.n::BIGINT
      FROM c LEFT JOIN Agency ag ON ag.agency_id = c.actor_agency_id;
$$;

-- The start of the bucket of width p_width, counted from p_since, that holds p_at.
CREATE OR REPLACE FUNCTION atlas_bucket(p_at TIMESTAMP, p_since TIMESTAMP, p_width INTERVAL)
RETURNS TIMESTAMP
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT p_since + floor(extract(epoch FROM (p_at - p_since))
                           / extract(epoch FROM p_width))::DOUBLE PRECISION * p_width;
$$;


-- ----------------------------------------------------------------------------
-- atlas_stats: the window's headline counts. Active credentials are the population counts'
-- (PopulationCount), the rest the window's activity. n_named counts the verifications that named
-- a credential, and n_pq those whose credential's algorithm is quantum-resistant: the route makes
-- shares of them, and withholds a share as it withholds a small count.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_stats(
    p_since    TIMESTAMP,
    p_daily    BOOLEAN,
    p_agencies TEXT DEFAULT NULL
) RETURNS TABLE (
    n_active_tokens BIGINT,
    n_verifs        BIGINT,
    n_failures      BIGINT,
    n_full          BIGINT,
    n_zk            BIGINT,
    n_named         BIGINT,
    n_pq            BIGINT,
    n_lifecycles    BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH v AS (
        SELECT COALESCE(sum(n), 0)                                                    AS total,
               COALESCE(sum(n) FILTER (WHERE outcome = 'FAILURE'), 0)                 AS failures,
               COALESCE(sum(n) FILTER (WHERE disclosure_level = 'FULL'), 0)           AS fulls,
               COALESCE(sum(n) FILTER (WHERE disclosure_level = 'ZERO_KNOWLEDGE'), 0) AS zks,
               COALESCE(sum(n) FILTER (WHERE algorithm_id <> 0), 0)                   AS named,
               COALESCE(sum(n) FILTER (WHERE algorithm_id <> 0 AND quantum_resistant), 0) AS pq
          FROM atlas_verification_combos(p_since, p_daily, NULL, NULL, NULL, p_agencies)
    ), l AS (
        SELECT COALESCE(sum(n), 0) AS total
          FROM atlas_lifecycle_matching(p_since, p_daily, p_agencies)
    ), active AS (
        SELECT COALESCE(sum(n), 0) AS n
          FROM (SELECT n FROM PopulationCount
                 WHERE facet = 'credential_status' AND item = 'ACTIVE'
                UNION ALL
                SELECT n FROM PopulationCountDelta
                 WHERE facet = 'credential_status' AND item = 'ACTIVE') a
    )
    SELECT active.n::BIGINT, v.total::BIGINT, v.failures::BIGINT, v.fulls::BIGINT,
           v.zks::BIGINT, v.named::BIGINT, v.pq::BIGINT, l.total::BIGINT
      FROM v, l, active;
$$;


-- ----------------------------------------------------------------------------
-- atlas_volume_series: volume over the window in buckets of p_width. Sparse: a bucket with
-- nothing in it has no row, and the route fills it. scope_total, scope_failure and scope_zk are
-- the whole window's counts under the filters, on every row: the route's totals, and how it
-- tells a narrow question (step 4).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_volume_series(
    p_since      TIMESTAMP,
    p_daily      BOOLEAN,
    p_width      INTERVAL,
    p_kind       TEXT DEFAULT 'verification',
    p_outcomes   TEXT DEFAULT NULL,
    p_disclosure TEXT DEFAULT NULL,
    p_contexts   TEXT DEFAULT NULL,
    p_agencies   TEXT DEFAULT NULL
) RETURNS TABLE (
    bucket_ts     TIMESTAMP,
    n_total       BIGINT,
    n_failure     BIGINT,
    n_zk          BIGINT,
    scope_total   BIGINT,
    scope_failure BIGINT,
    scope_zk      BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH b AS (
        SELECT atlas_bucket(bucket, p_since, p_width) AS bucket_ts,
               sum(n) AS n_total,
               COALESCE(sum(n) FILTER (WHERE outcome <> 'SUCCESS'), 0) AS n_failure,
               COALESCE(sum(n) FILTER (WHERE disclosure_level = 'ZERO_KNOWLEDGE'), 0) AS n_zk
          FROM atlas_verification_matching(p_since, p_daily, p_outcomes, p_disclosure,
                                           p_contexts, p_agencies)
         WHERE p_kind = 'verification'
         GROUP BY 1
        UNION ALL
        SELECT atlas_bucket(bucket, p_since, p_width),
               sum(n),
               COALESCE(sum(n) FILTER (WHERE event_type IN ('REVOKED', 'LOST')), 0),
               0
          FROM atlas_lifecycle_matching(p_since, p_daily, p_agencies)
         WHERE p_kind = 'lifecycle'
         GROUP BY 1
    )
    SELECT bucket_ts, n_total::BIGINT, n_failure::BIGINT, n_zk::BIGINT,
           (sum(n_total) OVER ())::BIGINT, (sum(n_failure) OVER ())::BIGINT,
           (sum(n_zk) OVER ())::BIGINT
      FROM b
     ORDER BY bucket_ts;
$$;


-- ----------------------------------------------------------------------------
-- atlas_breakdown: the window's counts by one dimension, top p_limit by volume. The dimension is
-- whitelisted by the route before it reaches the CASE.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_breakdown(
    p_dimension  TEXT,                -- verification: agency|context|outcome|disclosure|algorithm|jurisdiction; lifecycle: agency|event_type
    p_since      TIMESTAMP,
    p_daily      BOOLEAN,
    p_limit      INTEGER,
    p_kind       TEXT DEFAULT 'verification',
    p_outcomes   TEXT DEFAULT NULL,
    p_disclosure TEXT DEFAULT NULL,
    p_contexts   TEXT DEFAULT NULL,
    p_agencies   TEXT DEFAULT NULL,
    p_search     TEXT DEFAULT NULL
) RETURNS TABLE (
    label       TEXT,
    n_total     BIGINT,
    n_failure   BIGINT,
    scope_total BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH g AS (
        SELECT CASE p_dimension
                   WHEN 'agency'       THEN agency_name
                   WHEN 'context'      THEN context_type
                   WHEN 'outcome'      THEN outcome
                   WHEN 'disclosure'   THEN disclosure_level
                   WHEN 'jurisdiction' THEN jurisdiction
                   WHEN 'algorithm'    THEN COALESCE(algorithm_name, 'No credential named')
                   ELSE outcome
               END AS label,
               sum(n) AS n_total,
               COALESCE(sum(n) FILTER (WHERE outcome <> 'SUCCESS'), 0) AS n_failure
          FROM atlas_verification_combos(p_since, p_daily, p_outcomes, p_disclosure,
                                         p_contexts, p_agencies)
         WHERE p_kind = 'verification'
         GROUP BY 1
        UNION ALL
        SELECT CASE p_dimension
                   WHEN 'agency' THEN COALESCE(agency_name, 'System / device')
                   ELSE event_type
               END,
               sum(n),
               COALESCE(sum(n) FILTER (WHERE event_type IN ('REVOKED', 'LOST')), 0)
          FROM atlas_lifecycle_combos(p_since, p_daily, p_agencies)
         WHERE p_kind = 'lifecycle'
         GROUP BY 1
    ), s AS (
        SELECT label, n_total, n_failure, sum(n_total) OVER () AS scope_total
          FROM g
         WHERE label IS NOT NULL
    )
    SELECT label, n_total::BIGINT, n_failure::BIGINT, scope_total::BIGINT
      FROM s
     WHERE p_search IS NULL OR label ILIKE '%' || p_search || '%'
     ORDER BY n_total DESC, label ASC
     LIMIT p_limit;
$$;


-- ----------------------------------------------------------------------------
-- atlas_crosstab: a row dimension by a column dimension, the top p_limit rows by volume. The
-- column dimension is low-cardinality, so the cells are bounded (C8).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_crosstab(
    p_row_dim    TEXT,                -- verification: agency|context|jurisdiction|algorithm; lifecycle: agency|event_type
    p_col_dim    TEXT,                -- verification: outcome|disclosure; lifecycle: event_type
    p_since      TIMESTAMP,
    p_daily      BOOLEAN,
    p_limit      INTEGER,
    p_kind       TEXT DEFAULT 'verification',
    p_outcomes   TEXT DEFAULT NULL,
    p_disclosure TEXT DEFAULT NULL,
    p_contexts   TEXT DEFAULT NULL,
    p_agencies   TEXT DEFAULT NULL
) RETURNS TABLE (
    row_label   TEXT,
    col_label   TEXT,
    n_total     BIGINT,
    scope_total BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH base AS (
        SELECT CASE p_row_dim
                   WHEN 'agency'       THEN agency_name
                   WHEN 'context'      THEN context_type
                   WHEN 'jurisdiction' THEN jurisdiction
                   WHEN 'algorithm'    THEN COALESCE(algorithm_name, 'No credential named')
                   ELSE agency_name
               END AS rl,
               CASE p_col_dim
                   WHEN 'disclosure' THEN disclosure_level
                   ELSE outcome
               END AS cl,
               n
          FROM atlas_verification_combos(p_since, p_daily, p_outcomes, p_disclosure,
                                         p_contexts, p_agencies)
         WHERE p_kind = 'verification'
        UNION ALL
        SELECT CASE p_row_dim
                   WHEN 'agency' THEN COALESCE(agency_name, 'System / device')
                   ELSE event_type
               END,
               event_type,
               n
          FROM atlas_lifecycle_combos(p_since, p_daily, p_agencies)
         WHERE p_kind = 'lifecycle'
    ), top_rows AS (
        SELECT rl FROM base WHERE rl IS NOT NULL
         GROUP BY rl ORDER BY sum(n) DESC, rl ASC LIMIT p_limit
    )
    SELECT b.rl, b.cl, sum(b.n)::BIGINT,
           (SELECT COALESCE(sum(n), 0) FROM base)::BIGINT
      FROM base b JOIN top_rows t ON t.rl = b.rl
     WHERE b.cl IS NOT NULL
     GROUP BY b.rl, b.cl
     ORDER BY b.rl, b.cl;
$$;


-- ----------------------------------------------------------------------------
-- atlas_heatmap: the window's counts by ISO weekday (1 Monday .. 7 Sunday) and hour of day, at
-- most 7 x 24 cells (C8). Always the hourly rollup: a day holds no hour of day. The hours are
-- summed first, so the weekday and hour are read once an hour rather than once a cell.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_heatmap(
    p_since      TIMESTAMP,
    p_kind       TEXT DEFAULT 'verification',
    p_outcomes   TEXT DEFAULT NULL,
    p_disclosure TEXT DEFAULT NULL,
    p_contexts   TEXT DEFAULT NULL,
    p_agencies   TEXT DEFAULT NULL
) RETURNS TABLE (
    dow         INTEGER,
    hour        INTEGER,
    n           BIGINT,
    n_failure   BIGINT,
    scope_total BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH hours AS (
        SELECT bucket, sum(n) AS n,
               COALESCE(sum(n) FILTER (WHERE outcome <> 'SUCCESS'), 0) AS n_failure
          FROM atlas_verification_matching(p_since, FALSE, p_outcomes, p_disclosure,
                                           p_contexts, p_agencies)
         WHERE p_kind = 'verification'
         GROUP BY bucket
        UNION ALL
        SELECT bucket, sum(n), COALESCE(sum(n) FILTER (WHERE event_type IN ('REVOKED', 'LOST')), 0)
          FROM atlas_lifecycle_matching(p_since, FALSE, p_agencies)
         WHERE p_kind = 'lifecycle'
         GROUP BY bucket
    ), g AS (
        SELECT EXTRACT(ISODOW FROM bucket)::INTEGER AS dow,
               EXTRACT(HOUR FROM bucket)::INTEGER   AS hour,
               sum(n) AS n, sum(n_failure) AS n_failure
          FROM hours
         GROUP BY 1, 2
    )
    SELECT dow, hour, n::BIGINT, n_failure::BIGINT, (sum(n) OVER ())::BIGINT
      FROM g
     ORDER BY dow, hour;
$$;


-- ----------------------------------------------------------------------------
-- atlas_series_stacked: volume over the window in buckets of p_width, broken out by one
-- dimension: the top p_limit categories by volume, the rest folded into 'Other'. At most
-- buckets x (p_limit + 1) rows (C8). Summed by bucket and id first, named after.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_series_stacked(
    p_since      TIMESTAMP,
    p_daily      BOOLEAN,
    p_width      INTERVAL,
    p_dimension  TEXT,                -- verification: context|outcome|disclosure|agency|jurisdiction; lifecycle: agency|event_type
    p_kind       TEXT DEFAULT 'verification',
    p_limit      INTEGER DEFAULT 6,
    p_outcomes   TEXT DEFAULT NULL,
    p_disclosure TEXT DEFAULT NULL,
    p_contexts   TEXT DEFAULT NULL,
    p_agencies   TEXT DEFAULT NULL
) RETURNS TABLE (
    bucket_ts   TIMESTAMP,
    label       TEXT,
    n           BIGINT,
    scope_total BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH v AS (
        SELECT atlas_bucket(bucket, p_since, p_width) AS bt, requesting_agency_id, context_id,
               CASE p_dimension WHEN 'outcome' THEN outcome
                                WHEN 'disclosure' THEN disclosure_level END AS value,
               sum(n) AS n
          FROM atlas_verification_matching(p_since, p_daily, p_outcomes, p_disclosure,
                                           p_contexts, p_agencies)
         WHERE p_kind = 'verification'
         GROUP BY 1, 2, 3, 4
    ), l AS (
        SELECT atlas_bucket(bucket, p_since, p_width) AS bt, actor_agency_id,
               CASE WHEN p_dimension = 'agency' THEN NULL ELSE event_type END AS value,
               sum(n) AS n
          FROM atlas_lifecycle_matching(p_since, p_daily, p_agencies)
         WHERE p_kind = 'lifecycle'
         GROUP BY 1, 2, 3
    ), base AS (
        SELECT v.bt,
               CASE p_dimension
                   WHEN 'context'      THEN vc.context_type::TEXT
                   WHEN 'agency'       THEN ag.name::TEXT
                   WHEN 'jurisdiction' THEN ag.jurisdiction::TEXT
                   ELSE v.value
               END AS cat,
               v.n
          FROM v
          JOIN Agency ag ON ag.agency_id = v.requesting_agency_id
          JOIN VerificationContext vc ON vc.context_id = v.context_id
        UNION ALL
        SELECT l.bt,
               CASE WHEN p_dimension = 'agency' THEN COALESCE(ag.name::TEXT, 'System / device')
                    ELSE l.value END,
               l.n
          FROM l LEFT JOIN Agency ag ON ag.agency_id = l.actor_agency_id
    ), top_cats AS (
        SELECT cat FROM base WHERE cat IS NOT NULL
         GROUP BY cat ORDER BY sum(n) DESC, cat ASC LIMIT GREATEST(p_limit, 1)
    )
    SELECT b.bt,
           CASE WHEN t.cat IS NOT NULL THEN b.cat ELSE 'Other' END AS label,
           sum(b.n)::BIGINT,
           (SELECT COALESCE(sum(n), 0) FROM base)::BIGINT
      FROM base b LEFT JOIN top_cats t ON t.cat = b.cat
     WHERE b.cat IS NOT NULL
     GROUP BY b.bt, 2
     ORDER BY b.bt, 2;
$$;


-- ----------------------------------------------------------------------------
-- atlas_agency_facet: authorities matching a name or jurisdiction search, in name order, each
-- with its count in the window under the other filters (not the authority selection itself).
-- Every matching authority is listed, active or not, and in name order rather than by volume:
-- a list of only the active ones, or one ranked by count, would say which small authorities
-- had activity even where the route withholds how much (lab/strategy/009, step 4).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_agency_facet(
    p_since      TIMESTAMP,
    p_daily      BOOLEAN,
    p_limit      INTEGER,
    p_kind       TEXT DEFAULT 'verification',
    p_search     TEXT DEFAULT NULL,
    p_outcomes   TEXT DEFAULT NULL,
    p_disclosure TEXT DEFAULT NULL,
    p_contexts   TEXT DEFAULT NULL
) RETURNS TABLE (
    agency_id   INTEGER,
    name        TEXT,
    n_total     BIGINT,
    scope_total BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH activity AS (
        SELECT requesting_agency_id AS agency_id, sum(n) AS n
          FROM atlas_verification_matching(p_since, p_daily, p_outcomes, p_disclosure,
                                           p_contexts, NULL)
         WHERE p_kind = 'verification'
         GROUP BY requesting_agency_id
        UNION ALL
        SELECT actor_agency_id, sum(n)
          FROM atlas_lifecycle_matching(p_since, p_daily, NULL)
         WHERE p_kind = 'lifecycle' AND actor_agency_id <> 0
         GROUP BY actor_agency_id
    )
    SELECT ag.agency_id, ag.name::TEXT, COALESCE(a.n, 0)::BIGINT,
           (SELECT COALESCE(sum(n), 0) FROM activity)::BIGINT
      FROM Agency ag
      LEFT JOIN activity a ON a.agency_id = ag.agency_id
     WHERE p_search IS NULL OR ag.name ILIKE '%' || p_search || '%'
                            OR ag.jurisdiction ILIKE '%' || p_search || '%'
     ORDER BY ag.name ASC, ag.agency_id ASC
     LIMIT p_limit;
$$;


-- ----------------------------------------------------------------------------
-- atlas_geo_jurisdictions: the window's counts by the requesting authority's jurisdiction (the
-- acting authority's, for the lifecycle; '(system)' when none acted), top p_limit by volume. A
-- jurisdiction is a regulatory grouping, not a coordinate: the page places it from reference
-- data about the jurisdiction, never from where anyone was verified.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_geo_jurisdictions(
    p_since      TIMESTAMP,
    p_daily      BOOLEAN,
    p_limit      INTEGER,
    p_kind       TEXT DEFAULT 'verification',
    p_outcomes   TEXT DEFAULT NULL,
    p_disclosure TEXT DEFAULT NULL,
    p_contexts   TEXT DEFAULT NULL,
    p_agencies   TEXT DEFAULT NULL
) RETURNS TABLE (
    jurisdiction TEXT,
    n_total      BIGINT,
    n_failure    BIGINT,
    n_zk         BIGINT,
    scope_total  BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH g AS (
        SELECT jurisdiction,
               sum(n) AS n_total,
               COALESCE(sum(n) FILTER (WHERE outcome = 'FAILURE'), 0) AS n_failure,
               COALESCE(sum(n) FILTER (WHERE disclosure_level = 'ZERO_KNOWLEDGE'), 0) AS n_zk
          FROM atlas_verification_combos(p_since, p_daily, p_outcomes, p_disclosure,
                                         p_contexts, p_agencies)
         WHERE p_kind = 'verification'
         GROUP BY jurisdiction
        UNION ALL
        SELECT COALESCE(jurisdiction, '(system)'),
               sum(n),
               COALESCE(sum(n) FILTER (WHERE event_type IN ('REVOKED', 'LOST')), 0),
               0
          FROM atlas_lifecycle_combos(p_since, p_daily, p_agencies)
         WHERE p_kind = 'lifecycle'
         GROUP BY 1
    )
    SELECT jurisdiction, n_total::BIGINT, n_failure::BIGINT, n_zk::BIGINT,
           (sum(n_total) OVER ())::BIGINT
      FROM g
     ORDER BY n_total DESC, jurisdiction ASC
     LIMIT GREATEST(p_limit, 0);
$$;
