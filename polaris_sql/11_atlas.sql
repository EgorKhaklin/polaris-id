-- ============================================================================
-- AI-context: this file is performance-critical and the architecture decisions
--   in it are NON-OBVIOUS. Read these before editing:
--     ../docs/reference/SCALING.md                          ← architectural treatment
--     ../docs/design/atlas-scaling.md           ← what NOT to change without measuring
-- ============================================================================

-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 11_atlas.sql : Server-side spatial aggregation for /atlas at scale
--
-- The Atlas page renders potentially millions of verification and lifecycle
-- events on a globe. Sending every event to the browser is infeasible:
--
--   100 events:    ~30 KB JSON, renders in 50 ms          ← current sample
--   10,000:        ~3 MB JSON, renders in ~1 second
--   100,000:       ~30 MB JSON, renders in ~10 seconds
--   1,000,000:     ~300 MB JSON, browser hangs / OOMs
--   2,000,000:     completely impossible client-side
--
-- The fix is server-side spatial aggregation. The browser sends the visible
-- bounding box and a target grid resolution; the server returns at most a
-- few hundred CLUSTERS (centroid + summary stats) at low zoom, and switches
-- to individual reticles only when the user has zoomed close enough that
-- the cluster count drops below the cluster threshold.
--
-- CONTRACT
--   atlas_clusters_verifications(min_lat, min_lon, max_lat, max_lon, grid)
--     RETURNS TABLE (lat, lon, n_total, n_failure, n_pq, n_zk, n_full)
--   atlas_clusters_lifecycles(min_lat, min_lon, max_lat, max_lon, grid)
--     RETURNS TABLE (lat, lon, n_total, n_revoked, n_lost, n_issued, n_activated)
--
-- The grid argument is a granularity in DECIMAL DEGREES. Pick it to keep
-- the cluster count at the desired density (the API layer maps zoom level
-- to grid size).
--
-- ALL FUNCTIONS ARE STABLE: same args + same data → same result, no side
-- effects. PostgreSQL can therefore inline them and cache plans.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- atlas_clusters_verifications
--
-- Bins verification events by (floor(lat / grid), floor(lon / grid)) and
-- returns the centroid + count + diagnostic flag counts per bin. Excludes
-- rows with NULL coordinates (legacy data without recorded location).
--
-- Filtering by event_type is done client-side via the kind=verification
-- filter chip; this function returns ALL verifications in the bbox so the
-- browser can drive its own filter chips without re-querying. (Filter-aware
-- variants would multiply API surface; the bbox alone reduces volume by 10⁵
-- in practice.)
-- ----------------------------------------------------------------------------

-- v8.3 (A+C): bin function gained four optional filters used by the v8.3
-- temporal/filter UI. Each is NULL = "no filter" so existing callers that
-- still pass 5 positional args work unchanged via DEFAULT NULL.
-- v9.146 added p_agencies, changing the signature. DROP the pre-v9.146 full
-- signature so an in-place reload replaces it cleanly instead of leaving an
-- ambiguous overload (a bare name has two arities otherwise).
DROP FUNCTION IF EXISTS atlas_clusters_verifications(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    DOUBLE PRECISION, TIMESTAMP, TEXT, TEXT, TEXT);

CREATE OR REPLACE FUNCTION atlas_clusters_verifications(
    p_min_lat   DOUBLE PRECISION,
    p_min_lon   DOUBLE PRECISION,
    p_max_lat   DOUBLE PRECISION,
    p_max_lon   DOUBLE PRECISION,
    p_grid      DOUBLE PRECISION,
    p_since     TIMESTAMP DEFAULT NULL,        -- only events ≥ this time
    p_outcomes  TEXT      DEFAULT NULL,         -- CSV: 'FAILURE,UNAUTHORIZED'
    p_disclosure TEXT     DEFAULT NULL,         -- CSV: 'FULL'
    p_contexts  TEXT      DEFAULT NULL,         -- CSV: 'BANKING,TRAVEL'
    p_agencies  TEXT      DEFAULT NULL          -- CSV of agency_id, e.g. '1,4'
) RETURNS TABLE (
    lat        DOUBLE PRECISION,
    lon        DOUBLE PRECISION,
    n_total    BIGINT,
    n_failure  BIGINT,
    n_pq       BIGINT,
    n_zk       BIGINT,
    n_full     BIGINT
)
LANGUAGE sql
STABLE
AS $$
    SELECT
        avg(ve.latitude)                                   AS lat,
        avg(ve.longitude)                                  AS lon,
        count(*)                                           AS n_total,
        count(*) FILTER (WHERE ve.outcome = 'FAILURE')     AS n_failure,
        count(*) FILTER (WHERE ca.quantum_resistant)       AS n_pq,
        count(*) FILTER (WHERE ve.disclosure_level = 'ZERO_KNOWLEDGE') AS n_zk,
        count(*) FILTER (WHERE ve.disclosure_level = 'FULL')           AS n_full
    FROM      VerificationEvent ve
    LEFT JOIN IdentityToken          t  ON ve.token_id     = t.token_id
    LEFT JOIN CryptographicAlgorithm ca ON t.algorithm_id  = ca.algorithm_id
    LEFT JOIN VerificationContext    vc ON ve.context_id   = vc.context_id
    WHERE ve.latitude  IS NOT NULL
      AND ve.longitude IS NOT NULL
      -- C6: ZERO_KNOWLEDGE verifications must not appear on the spatial map at
      -- all. A grid cell containing a single ZK event would otherwise leak its
      -- exact location via avg(lat/lon), and the GROUP BY itself pins each ZK
      -- event to a cell. ZK activity is reported non-spatially by atlas_stats.
      -- (n_zk is therefore structurally 0 in this aggregate.)
      AND ve.disclosure_level <> 'ZERO_KNOWLEDGE'
      AND ve.latitude  BETWEEN p_min_lat AND p_max_lat
      AND (
            (p_min_lon <= p_max_lon AND ve.longitude BETWEEN p_min_lon AND p_max_lon)
         OR (p_min_lon  > p_max_lon AND (ve.longitude >= p_min_lon OR ve.longitude <= p_max_lon))
      )
      AND (ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
      AND (p_outcomes   IS NULL OR ve.outcome         = ANY(string_to_array(p_outcomes, ',')))
      AND (p_disclosure IS NULL OR ve.disclosure_level = ANY(string_to_array(p_disclosure, ',')))
      AND (p_contexts   IS NULL OR vc.context_type     = ANY(string_to_array(p_contexts, ',')))
      AND (p_agencies   IS NULL OR ve.requesting_agency_id::text = ANY(string_to_array(p_agencies, ',')))
    GROUP BY floor(ve.latitude  / p_grid),
             floor(ve.longitude / p_grid);
$$;

COMMENT ON FUNCTION atlas_clusters_verifications IS
  'Bins VerificationEvent rows in the bbox into a grid of size p_grid '
  '(decimal degrees). Returns centroid + total + diagnostic flag counts per '
  'bin. Used by GET /api/atlas/clusters when kind=verification.';


-- ----------------------------------------------------------------------------
-- atlas_clusters_lifecycles
--
-- Same idea for TokenLifecycleEvent. The flag counts surface terminal
-- transitions (REVOKED, LOST) which are operationally interesting at the
-- aggregate level — a cluster with high revocation rate tells the operator
-- to investigate that area.
-- ----------------------------------------------------------------------------

DROP FUNCTION IF EXISTS atlas_clusters_lifecycles(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    DOUBLE PRECISION, TIMESTAMP, TEXT);

CREATE OR REPLACE FUNCTION atlas_clusters_lifecycles(
    p_min_lat     DOUBLE PRECISION,
    p_min_lon     DOUBLE PRECISION,
    p_max_lat     DOUBLE PRECISION,
    p_max_lon     DOUBLE PRECISION,
    p_grid        DOUBLE PRECISION,
    p_since       TIMESTAMP DEFAULT NULL,
    p_event_types TEXT      DEFAULT NULL,   -- CSV: 'REVOKED,LOST'
    p_agencies    TEXT      DEFAULT NULL    -- CSV of agency_id (actor agency)
) RETURNS TABLE (
    lat          DOUBLE PRECISION,
    lon          DOUBLE PRECISION,
    n_total      BIGINT,
    n_revoked    BIGINT,
    n_lost       BIGINT,
    n_issued     BIGINT,
    n_activated  BIGINT
)
LANGUAGE sql
STABLE
AS $$
    SELECT
        avg(latitude)                                          AS lat,
        avg(longitude)                                         AS lon,
        count(*)                                               AS n_total,
        count(*) FILTER (WHERE event_type = 'REVOKED')         AS n_revoked,
        count(*) FILTER (WHERE event_type = 'LOST')            AS n_lost,
        count(*) FILTER (WHERE event_type = 'ISSUED')          AS n_issued,
        count(*) FILTER (WHERE event_type = 'ACTIVATED')       AS n_activated
    FROM TokenLifecycleEvent
    WHERE latitude  IS NOT NULL
      AND longitude IS NOT NULL
      AND latitude  BETWEEN p_min_lat AND p_max_lat
      AND (
            (p_min_lon <= p_max_lon AND longitude BETWEEN p_min_lon AND p_max_lon)
         OR (p_min_lon  > p_max_lon AND (longitude >= p_min_lon OR longitude <= p_max_lon))
      )
      AND (event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
      AND (p_event_types IS NULL OR event_type      = ANY(string_to_array(p_event_types, ',')))
      AND (p_agencies    IS NULL OR actor_agency_id::text = ANY(string_to_array(p_agencies, ',')))
    GROUP BY floor(latitude  / p_grid),
             floor(longitude / p_grid);
$$;

COMMENT ON FUNCTION atlas_clusters_lifecycles IS
  'Bins TokenLifecycleEvent rows in the bbox into a grid of size p_grid '
  '(decimal degrees). Used by GET /api/atlas/clusters when kind=lifecycle.';


-- ----------------------------------------------------------------------------
-- atlas_points_verifications
--
-- Returns INDIVIDUAL verification events in a bbox, hard-capped at p_limit.
-- Used at high zoom (city / neighborhood) where the user wants every
-- reticle. The cap protects the wire and the renderer.
-- ----------------------------------------------------------------------------

DROP FUNCTION IF EXISTS atlas_points_verifications(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    INTEGER, TIMESTAMP, TEXT, TEXT, TEXT);

CREATE OR REPLACE FUNCTION atlas_points_verifications(
    p_min_lat   DOUBLE PRECISION,
    p_min_lon   DOUBLE PRECISION,
    p_max_lat   DOUBLE PRECISION,
    p_max_lon   DOUBLE PRECISION,
    p_limit     INTEGER,
    p_since     TIMESTAMP DEFAULT NULL,
    p_outcomes  TEXT      DEFAULT NULL,
    p_disclosure TEXT     DEFAULT NULL,
    p_contexts  TEXT      DEFAULT NULL,
    p_agencies  TEXT      DEFAULT NULL          -- CSV of agency_id, e.g. '1,4'
) RETURNS TABLE (
    event_id         BIGINT,
    lat               DOUBLE PRECISION,
    lon               DOUBLE PRECISION,
    event_timestamp   TIMESTAMP,
    token_id          INTEGER,
    holder_name       TEXT,
    agency_name       TEXT,
    context_type      TEXT,
    outcome           TEXT,
    disclosure_level  TEXT,
    algorithm_name    TEXT,
    pq                BOOLEAN,
    requestor_location TEXT
)
LANGUAGE sql
STABLE
AS $$
    SELECT
        ve.event_id,
        ve.latitude,
        ve.longitude,
        ve.event_timestamp,
        ve.token_id,
        i.legal_name::TEXT             AS holder_name,
        ag.name::TEXT                  AS agency_name,
        vc.context_type::TEXT          AS context_type,
        ve.outcome::TEXT               AS outcome,
        ve.disclosure_level::TEXT      AS disclosure_level,
        ca.name::TEXT        AS algorithm_name,
        COALESCE(ca.quantum_resistant, FALSE) AS pq,
        ve.requestor_location::TEXT    AS requestor_location
    FROM      VerificationEvent ve
    JOIN      Agency               ag ON ve.requesting_agency_id = ag.agency_id
    JOIN      VerificationContext  vc ON ve.context_id           = vc.context_id
    LEFT JOIN IdentityToken         t ON ve.token_id             = t.token_id
    LEFT JOIN Individual            i ON t.individual_id         = i.individual_id
    LEFT JOIN CryptographicAlgorithm ca ON t.algorithm_id        = ca.algorithm_id
    WHERE ve.latitude  IS NOT NULL
      AND ve.longitude IS NOT NULL
      -- C6: a ZERO_KNOWLEDGE verification proves validity without revealing the
      -- holder; its precise location is exactly the spatial side-channel that
      -- would de-anonymize it (especially co-located with a SELECTIVE/FULL
      -- event). uc7_warrant_audit redacts requestor_location for ZK rows; the
      -- precise-points layer must not plot them at all. Aggregate/count layers
      -- may still include ZK without a precise location.
      AND ve.disclosure_level <> 'ZERO_KNOWLEDGE'
      AND ve.latitude  BETWEEN p_min_lat AND p_max_lat
      AND (
            (p_min_lon <= p_max_lon AND ve.longitude BETWEEN p_min_lon AND p_max_lon)
         OR (p_min_lon  > p_max_lon AND (ve.longitude >= p_min_lon OR ve.longitude <= p_max_lon))
      )
      AND (ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
      AND (p_outcomes   IS NULL OR ve.outcome         = ANY(string_to_array(p_outcomes, ',')))
      AND (p_disclosure IS NULL OR ve.disclosure_level = ANY(string_to_array(p_disclosure, ',')))
      AND (p_contexts   IS NULL OR vc.context_type     = ANY(string_to_array(p_contexts, ',')))
      AND (p_agencies   IS NULL OR ve.requesting_agency_id::text = ANY(string_to_array(p_agencies, ',')))
    ORDER BY ve.event_timestamp DESC
    LIMIT p_limit;
$$;


-- ----------------------------------------------------------------------------
-- atlas_points_lifecycles
-- ----------------------------------------------------------------------------

DROP FUNCTION IF EXISTS atlas_points_lifecycles(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    INTEGER, TIMESTAMP, TEXT);

CREATE OR REPLACE FUNCTION atlas_points_lifecycles(
    p_min_lat     DOUBLE PRECISION,
    p_min_lon     DOUBLE PRECISION,
    p_max_lat     DOUBLE PRECISION,
    p_max_lon     DOUBLE PRECISION,
    p_limit       INTEGER,
    p_since       TIMESTAMP DEFAULT NULL,
    p_event_types TEXT      DEFAULT NULL,
    p_agencies    TEXT      DEFAULT NULL          -- CSV of agency_id (actor agency)
) RETURNS TABLE (
    event_id       BIGINT,
    lat             DOUBLE PRECISION,
    lon             DOUBLE PRECISION,
    event_timestamp TIMESTAMP,
    token_id        INTEGER,
    event_type      TEXT,
    reason_code     TEXT,
    holder_name     TEXT,
    agency_name     TEXT,
    algorithm_name  TEXT,
    pq              BOOLEAN
)
LANGUAGE sql
STABLE
AS $$
    SELECT
        le.event_id,
        le.latitude,
        le.longitude,
        le.event_timestamp,
        le.token_id,
        le.event_type::TEXT,
        le.reason_code::TEXT,
        i.legal_name::TEXT,
        ag.name::TEXT,
        ca.name::TEXT,
        COALESCE(ca.quantum_resistant, FALSE) AS pq
    FROM      TokenLifecycleEvent le
    LEFT JOIN Agency               ag ON le.actor_agency_id = ag.agency_id
    JOIN      IdentityToken         t ON le.token_id        = t.token_id
    JOIN      Individual            i ON t.individual_id    = i.individual_id
    JOIN      CryptographicAlgorithm ca ON t.algorithm_id    = ca.algorithm_id
    WHERE le.latitude  IS NOT NULL
      AND le.longitude IS NOT NULL
      AND le.latitude  BETWEEN p_min_lat AND p_max_lat
      AND (
            (p_min_lon <= p_max_lon AND le.longitude BETWEEN p_min_lon AND p_max_lon)
         OR (p_min_lon  > p_max_lon AND (le.longitude >= p_min_lon OR le.longitude <= p_max_lon))
      )
      AND (le.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
      AND (p_event_types IS NULL OR le.event_type      = ANY(string_to_array(p_event_types, ',')))
      AND (p_agencies    IS NULL OR le.actor_agency_id::text = ANY(string_to_array(p_agencies, ',')))
    ORDER BY le.event_timestamp DESC
    LIMIT p_limit;
$$;


-- ----------------------------------------------------------------------------
-- atlas_stats — bbox-scoped HUD signals
--
-- Computes the four operational ratios shown in the Atlas HUD scoped to the
-- visible bounding box. So as the user pans / zooms, the numbers update to
-- reflect what they're actually looking at — not the global aggregates.
-- ----------------------------------------------------------------------------

DROP FUNCTION IF EXISTS atlas_stats(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    TIMESTAMP);

CREATE OR REPLACE FUNCTION atlas_stats(
    p_min_lat DOUBLE PRECISION,
    p_min_lon DOUBLE PRECISION,
    p_max_lat DOUBLE PRECISION,
    p_max_lon DOUBLE PRECISION,
    p_since   TIMESTAMP DEFAULT NULL,
    p_agencies TEXT     DEFAULT NULL          -- CSV of agency_id (operational filter)
) RETURNS TABLE (
    n_active_tokens BIGINT,
    n_anomalies     BIGINT,
    n_failures      BIGINT,
    n_full          BIGINT,
    pq_pct          NUMERIC,
    zk_pct          NUMERIC,
    n_verifs        BIGINT,
    n_lifecycles    BIGINT
)
LANGUAGE sql
STABLE
AS $$
    -- Single-pass aggregation. The previous version had a CTE referenced 8
    -- times; PostgreSQL re-scanned it on each reference (~70ms × 8). The
    -- rewritten version joins once and computes everything via FILTER
    -- aggregates in a single SELECT. At 2M rows this takes ~250ms instead
    -- of ~1400ms.
    WITH
    v_agg AS (
        SELECT
            count(*)                                                   AS total,
            count(*) FILTER (WHERE ve.outcome = 'FAILURE')             AS failures,
            count(*) FILTER (WHERE ve.disclosure_level = 'FULL')       AS fulls,
            count(*) FILTER (WHERE ve.disclosure_level = 'ZERO_KNOWLEDGE') AS zks,
            count(*) FILTER (WHERE ve.token_id IS NOT NULL)            AS with_token,
            count(*) FILTER (WHERE ve.token_id IS NOT NULL AND ca.quantum_resistant) AS pq_count
        FROM      VerificationEvent ve
        LEFT JOIN IdentityToken          t  ON ve.token_id    = t.token_id
        LEFT JOIN CryptographicAlgorithm ca ON t.algorithm_id = ca.algorithm_id
        WHERE ve.latitude  IS NOT NULL
          AND ve.longitude IS NOT NULL
          AND ve.latitude  BETWEEN p_min_lat AND p_max_lat
          AND (
            (p_min_lon <= p_max_lon AND ve.longitude BETWEEN p_min_lon AND p_max_lon)
         OR (p_min_lon  > p_max_lon AND (ve.longitude >= p_min_lon OR ve.longitude <= p_max_lon))
      )
          AND (ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_agencies IS NULL OR ve.requesting_agency_id::text = ANY(string_to_array(p_agencies, ',')))
    ),
    l_agg AS (
        SELECT count(*) AS total
        FROM TokenLifecycleEvent
        WHERE latitude  IS NOT NULL
          AND longitude IS NOT NULL
          AND latitude  BETWEEN p_min_lat AND p_max_lat
          AND (
            (p_min_lon <= p_max_lon AND longitude BETWEEN p_min_lon AND p_max_lon)
         OR (p_min_lon  > p_max_lon AND (longitude >= p_min_lon OR longitude <= p_max_lon))
      )
          AND (event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_agencies IS NULL OR actor_agency_id::text = ANY(string_to_array(p_agencies, ',')))
    )
    SELECT
        (SELECT count(*) FROM IdentityToken WHERE status = 'ACTIVE')::BIGINT AS n_active_tokens,
        (v.failures + v.fulls)::BIGINT                              AS n_anomalies,
        v.failures::BIGINT                                          AS n_failures,
        v.fulls::BIGINT                                             AS n_full,
        CASE WHEN v.with_token > 0
             THEN ROUND(100.0 * v.pq_count / v.with_token, 0)
             ELSE 0 END::NUMERIC                                     AS pq_pct,
        CASE WHEN v.total > 0
             THEN ROUND(100.0 * v.zks / v.total, 0)
             ELSE 0 END::NUMERIC                                     AS zk_pct,
        v.total::BIGINT                                              AS n_verifs,
        l.total::BIGINT                                              AS n_lifecycles
    FROM v_agg v, l_agg l;
$$;

COMMENT ON FUNCTION atlas_stats IS
  'Returns the four operational ratios in the Atlas HUD, scoped to the '
  'currently visible bounding box. Active Tokens is global (system-wide '
  'authoritative count); Anomalies, PQ %, ZK % are bbox-scoped so they '
  'change as the user pans and zooms.';


-- ----------------------------------------------------------------------------
-- atlas_recent_events — paginated event feed for the Atlas right rail
--
-- Cursor pagination by (event_timestamp DESC, event_id DESC). The cursor
-- format is ISO-8601 timestamp + event_id, both ascending or both
-- descending. Passing NULL for the cursor returns the first page.
--
-- Returns up to p_limit events, mixing verifications and lifecycle events
-- in time order with a discriminator column so the client can render each
-- with the appropriate visual treatment.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION atlas_recent_events(
    p_cursor_ts TIMESTAMP DEFAULT NULL,
    p_cursor_id INTEGER   DEFAULT NULL,
    p_limit     INTEGER   DEFAULT 50
) RETURNS TABLE (
    kind            TEXT,    -- 'verification' or 'lifecycle'
    event_id       BIGINT,
    event_timestamp TIMESTAMP,
    token_id        INTEGER,
    holder_name     TEXT,
    agency_name     TEXT,
    label           TEXT,    -- e.g. "BANKING verification" or "REVOKED"
    detail          TEXT,    -- subtitle: location or reason
    tone            TEXT,    -- 'alert' | 'full' | 'zk' | 'selective' | etc.
    lat             DOUBLE PRECISION,
    lon             DOUBLE PRECISION
)
LANGUAGE sql
STABLE
AS $$
    -- Two-stage top-N + late join. The previous version did UNION ALL of
    -- both tables INCLUDING JOINs to Agency/Context/Token/Individual, then
    -- top-N sorted the result. At 2M rows this materialized 2M joined rows
    -- (~2.4 seconds) just to take 50.
    --
    -- The rewrite: first pull top-N IDs from each table using the
    -- (event_timestamp DESC, event_id DESC) indexes — that's O(N log N)
    -- with N being the limit, not the table size. Each side returns ≤
    -- p_limit rows. Then UNION ALL gives at most 2*p_limit rows; JOIN
    -- metadata only for THOSE rows. At 2M rows this drops to <30ms.
    WITH
    top_v AS (
        SELECT event_id, event_timestamp, token_id, requesting_agency_id,
               context_id, outcome, disclosure_level, requestor_location,
               latitude, longitude
        FROM VerificationEvent
        WHERE p_cursor_ts IS NULL
           OR (event_timestamp, event_id) < (p_cursor_ts, COALESCE(p_cursor_id, 2147483647))
        ORDER BY event_timestamp DESC, event_id DESC
        LIMIT p_limit
    ),
    top_l AS (
        SELECT event_id, event_timestamp, token_id, actor_agency_id,
               event_type, reason_code, latitude, longitude
        FROM TokenLifecycleEvent
        WHERE p_cursor_ts IS NULL
           OR (event_timestamp, event_id) < (p_cursor_ts, COALESCE(p_cursor_id, 2147483647))
        ORDER BY event_timestamp DESC, event_id DESC
        LIMIT p_limit
    ),
    merged AS (
        SELECT
            'verification'::TEXT AS kind,
            tv.event_id,
            tv.event_timestamp,
            tv.token_id,
            COALESCE(i.legal_name::TEXT, '(zero-knowledge)') AS holder_name,
            ag.name::TEXT                                    AS agency_name,
            (vc.context_type || ' verification')::TEXT       AS label,
            -- C6: redact the location of ZERO_KNOWLEDGE verifications in the
            -- feed — no subtitle location and no map coordinates — so a ZK
            -- event appears as activity but never reveals where it happened.
            CASE WHEN tv.disclosure_level = 'ZERO_KNOWLEDGE'
                 THEN NULL ELSE tv.requestor_location::TEXT END AS detail,
            CASE
                WHEN tv.outcome = 'FAILURE'                 THEN 'alert'
                WHEN tv.disclosure_level = 'FULL'           THEN 'full'
                WHEN tv.disclosure_level = 'ZERO_KNOWLEDGE' THEN 'zk'
                                                            ELSE 'selective'
            END::TEXT                                        AS tone,
            CASE WHEN tv.disclosure_level = 'ZERO_KNOWLEDGE'
                 THEN NULL ELSE tv.latitude END              AS lat,
            CASE WHEN tv.disclosure_level = 'ZERO_KNOWLEDGE'
                 THEN NULL ELSE tv.longitude END             AS lon
        FROM      top_v tv
        JOIN      Agency             ag ON tv.requesting_agency_id = ag.agency_id
        JOIN      VerificationContext vc ON tv.context_id          = vc.context_id
        LEFT JOIN IdentityToken      t  ON tv.token_id             = t.token_id
        LEFT JOIN Individual         i  ON t.individual_id         = i.individual_id

        UNION ALL

        SELECT
            'lifecycle'::TEXT AS kind,
            tl.event_id,
            tl.event_timestamp,
            tl.token_id,
            i.legal_name::TEXT                              AS holder_name,
            COALESCE(ag.name::TEXT, '—')                    AS agency_name,
            tl.event_type::TEXT                             AS label,
            COALESCE(tl.reason_code::TEXT, '')              AS detail,
            CASE
                WHEN tl.event_type IN ('REVOKED', 'LOST') THEN 'alert'
                WHEN tl.event_type = 'ACTIVATED'          THEN 'zk'
                                                          ELSE 'full'
            END::TEXT                                        AS tone,
            tl.latitude                                      AS lat,
            tl.longitude                                     AS lon
        FROM      top_l tl
        LEFT JOIN Agency        ag ON tl.actor_agency_id = ag.agency_id
        JOIN      IdentityToken  t ON tl.token_id        = t.token_id
        JOIN      Individual     i ON t.individual_id    = i.individual_id
    )
    SELECT *
    FROM merged
    ORDER BY event_timestamp DESC, event_id DESC
    LIMIT p_limit;
$$;

COMMENT ON FUNCTION atlas_recent_events IS
  'Paginated unified feed of verifications + lifecycle events. Cursor is '
  '(event_timestamp, event_id) descending. Pass NULL cursor for first page.';


-- ----------------------------------------------------------------------------
-- atlas_timeline (v8.3 / A) — bucket counts for the histogram strip
--
-- Buckets the events in [p_since, NOW()] into p_buckets equal time slices
-- and returns one row per bucket: bucket_ts (start of slice), n_total, and
-- n_anomaly (FAILURE outcomes + FULL disclosures + REVOKED/LOST lifecycle).
--
-- Used by GET /api/atlas/timeline to render the small density strip below
-- the toolbar. The strip lets the operator see at a glance whether the
-- selected time window contains a spike — a brief 100x bar in an
-- otherwise flat 24h is much louder than scrubbing through 24h of
-- individual reticles. This is the temporal-lens half of v8.3 V3 plan A.
--
-- Filters mirror the cluster functions so the timeline reflects whatever
-- the operator has selected up-toolbar (e.g., "anomalies-only, last 7d"
-- shows the histogram of just anomalies).
-- ----------------------------------------------------------------------------

DROP FUNCTION IF EXISTS atlas_timeline(
    DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION, DOUBLE PRECISION,
    TIMESTAMP, INTEGER, TEXT, TEXT, TEXT, TEXT);
-- (pre-v9.146 timeline signature; the CREATE below adds p_agencies)

CREATE OR REPLACE FUNCTION atlas_timeline(
    p_min_lat   DOUBLE PRECISION,
    p_min_lon   DOUBLE PRECISION,
    p_max_lat   DOUBLE PRECISION,
    p_max_lon   DOUBLE PRECISION,
    p_since     TIMESTAMP,
    p_buckets   INTEGER,
    p_kind      TEXT      DEFAULT 'verification',  -- or 'lifecycle'
    p_outcomes  TEXT      DEFAULT NULL,
    p_disclosure TEXT     DEFAULT NULL,
    p_contexts  TEXT      DEFAULT NULL,
    p_agencies  TEXT      DEFAULT NULL          -- CSV of agency_id (operational filter)
) RETURNS TABLE (
    bucket_ts   TIMESTAMP,
    n_total     BIGINT,
    n_anomaly   BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH params AS (
        SELECT
            p_since                                  AS t_start,
            CURRENT_TIMESTAMP                        AS t_end,
            GREATEST(p_buckets, 1)                   AS buckets,
            (extract(epoch FROM (CURRENT_TIMESTAMP - p_since))
             / GREATEST(p_buckets, 1))::DOUBLE PRECISION AS bucket_secs
    ),
    bucketed_v AS (
        SELECT
            (params.t_start
                + (floor(extract(epoch FROM (ve.event_timestamp - params.t_start))
                         / params.bucket_secs) * params.bucket_secs
                  ) * INTERVAL '1 second'
            )::TIMESTAMP                                            AS bucket_ts,
            count(*)                                                AS n_total,
            count(*) FILTER (WHERE
                ve.outcome = 'FAILURE'
             OR ve.disclosure_level = 'FULL'
            )                                                       AS n_anomaly
        FROM VerificationEvent ve
        LEFT JOIN VerificationContext vc ON ve.context_id = vc.context_id,
             params
        WHERE p_kind = 'verification'
          AND ve.latitude  IS NOT NULL
          AND ve.longitude IS NOT NULL
          AND ve.latitude  BETWEEN p_min_lat AND p_max_lat
          AND (
            (p_min_lon <= p_max_lon AND ve.longitude BETWEEN p_min_lon AND p_max_lon)
         OR (p_min_lon  > p_max_lon AND (ve.longitude >= p_min_lon OR ve.longitude <= p_max_lon))
          )
          AND ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp)
          AND ve.event_timestamp < CURRENT_TIMESTAMP
          AND (p_outcomes   IS NULL OR ve.outcome         = ANY(string_to_array(p_outcomes, ',')))
          AND (p_disclosure IS NULL OR ve.disclosure_level = ANY(string_to_array(p_disclosure, ',')))
          AND (p_contexts   IS NULL OR vc.context_type     = ANY(string_to_array(p_contexts, ',')))
          AND (p_agencies   IS NULL OR ve.requesting_agency_id::text = ANY(string_to_array(p_agencies, ',')))
        GROUP BY 1
    ),
    bucketed_l AS (
        SELECT
            (params.t_start
                + (floor(extract(epoch FROM (le.event_timestamp - params.t_start))
                         / params.bucket_secs) * params.bucket_secs
                  ) * INTERVAL '1 second'
            )::TIMESTAMP                                            AS bucket_ts,
            count(*)                                                AS n_total,
            count(*) FILTER (WHERE le.event_type IN ('REVOKED', 'LOST'))
                                                                    AS n_anomaly
        FROM TokenLifecycleEvent le, params
        WHERE p_kind = 'lifecycle'
          AND le.latitude  IS NOT NULL
          AND le.longitude IS NOT NULL
          AND le.latitude  BETWEEN p_min_lat AND p_max_lat
          AND (
            (p_min_lon <= p_max_lon AND le.longitude BETWEEN p_min_lon AND p_max_lon)
         OR (p_min_lon  > p_max_lon AND (le.longitude >= p_min_lon OR le.longitude <= p_max_lon))
          )
          AND le.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp)
          AND le.event_timestamp < CURRENT_TIMESTAMP
          AND (p_agencies IS NULL OR le.actor_agency_id::text = ANY(string_to_array(p_agencies, ',')))
        GROUP BY 1
    )
    SELECT bucket_ts, n_total, n_anomaly FROM bucketed_v
    UNION ALL
    SELECT bucket_ts, n_total, n_anomaly FROM bucketed_l
    ORDER BY bucket_ts;
$$;

COMMENT ON FUNCTION atlas_timeline IS
  'Bucket counts for the Atlas histogram strip. Slices [p_since, NOW()] '
  'into p_buckets equal time bins and counts events per bin. Returns '
  'sparse rows (no row for empty buckets — the client zero-fills).';


-- ----------------------------------------------------------------------------
-- atlas_volume_series  (roadmap P2.3, v9.248 — the analytical console)
--
-- The NON-geographic companion to atlas_timeline. atlas_timeline counts only
-- LOCATED events (lat/lon NOT NULL) because it drives the map's histogram
-- strip; the Overview needs the TRUE total volume, including the ~40% of
-- verifications that are zero-knowledge and carry no plottable location.
--
-- C6 holds: this is a pure count over time with no location, so a
-- zero-knowledge event is COUNTED (n_zk, the privacy-posture signal) but never
-- located or attributed. Slices [p_since, NOW()] into p_buckets equal bins;
-- returns sparse rows (the client zero-fills). Bounded by p_buckets (the API
-- caps it at 240).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_volume_series(
    p_since      TIMESTAMP,
    p_buckets    INTEGER,
    p_kind       TEXT      DEFAULT 'verification',   -- or 'lifecycle'
    p_outcomes   TEXT      DEFAULT NULL,
    p_disclosure TEXT      DEFAULT NULL,
    p_contexts   TEXT      DEFAULT NULL,
    p_agencies   TEXT      DEFAULT NULL
) RETURNS TABLE (
    bucket_ts   TIMESTAMP,
    n_total     BIGINT,
    n_failure   BIGINT,
    n_zk        BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH params AS (
        SELECT
            p_since                                  AS t_start,
            CURRENT_TIMESTAMP                        AS t_end,
            GREATEST(p_buckets, 1)                   AS buckets,
            (extract(epoch FROM (CURRENT_TIMESTAMP - p_since))
             / GREATEST(p_buckets, 1))::DOUBLE PRECISION AS bucket_secs
    ),
    bucketed_v AS (
        SELECT
            (params.t_start
                + (floor(extract(epoch FROM (ve.event_timestamp - params.t_start))
                         / NULLIF(params.bucket_secs, 0)) * params.bucket_secs
                  ) * INTERVAL '1 second'
            )::TIMESTAMP                                            AS bucket_ts,
            count(*)                                                AS n_total,
            count(*) FILTER (WHERE ve.outcome <> 'SUCCESS')         AS n_failure,
            count(*) FILTER (WHERE ve.disclosure_level = 'ZERO_KNOWLEDGE') AS n_zk
        FROM VerificationEvent ve
        LEFT JOIN VerificationContext vc ON ve.context_id = vc.context_id,
             params
        WHERE p_kind = 'verification'
          AND ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp)
          AND ve.event_timestamp < CURRENT_TIMESTAMP
          AND (p_outcomes   IS NULL OR ve.outcome         = ANY(string_to_array(p_outcomes, ',')))
          AND (p_disclosure IS NULL OR ve.disclosure_level = ANY(string_to_array(p_disclosure, ',')))
          AND (p_contexts   IS NULL OR vc.context_type     = ANY(string_to_array(p_contexts, ',')))
          AND (p_agencies   IS NULL OR ve.requesting_agency_id::text = ANY(string_to_array(p_agencies, ',')))
        GROUP BY 1
    ),
    bucketed_l AS (
        SELECT
            (params.t_start
                + (floor(extract(epoch FROM (le.event_timestamp - params.t_start))
                         / NULLIF(params.bucket_secs, 0)) * params.bucket_secs
                  ) * INTERVAL '1 second'
            )::TIMESTAMP                                            AS bucket_ts,
            count(*)                                                AS n_total,
            count(*) FILTER (WHERE le.event_type IN ('REVOKED', 'LOST')) AS n_failure,
            0::BIGINT                                               AS n_zk
        FROM TokenLifecycleEvent le, params
        WHERE p_kind = 'lifecycle'
          AND le.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp)
          AND le.event_timestamp < CURRENT_TIMESTAMP
          AND (p_agencies IS NULL OR le.actor_agency_id::text = ANY(string_to_array(p_agencies, ',')))
        GROUP BY 1
    )
    SELECT bucket_ts, n_total, n_failure, n_zk FROM bucketed_v
    UNION ALL
    SELECT bucket_ts, n_total, n_failure, n_zk FROM bucketed_l
    ORDER BY bucket_ts;
$$;

COMMENT ON FUNCTION atlas_volume_series IS
  'Non-geographic total-volume time series for the Atlas Overview. Counts ALL '
  'events in [p_since, NOW()] (located or not), so it includes zero-knowledge '
  'verifications in n_total and n_zk without ever locating them (C6). Bounded '
  'by p_buckets (API-capped at 240).';


-- ----------------------------------------------------------------------------
-- atlas_breakdown  (roadmap P2.3, v9.248 — the analytical console)
--
-- Top-K categorical roll-up for the Overview and Breakdown views: counts all
-- events in the window grouped by one whitelisted dimension, ordered by volume,
-- capped at p_limit (the API caps it at _ATLAS_MAX_CATEGORIES). Non-geographic,
-- so zero-knowledge events are counted like any other (C6): a ZK verification
-- contributes to the agency/context/outcome/disclosure/jurisdiction tallies
-- (jurisdiction is the REQUESTING agency's, always known) but the 'algorithm'
-- dimension folds untokened ZK rows into a single labelled bucket.
--
-- p_dimension is whitelisted by the API before it reaches here; the CASE below
-- maps only known values, so there is no dynamic SQL and no injection surface.
-- ----------------------------------------------------------------------------
-- v9.250 added p_search, changing the arity. DROP the pre-v9.250 8-arg
-- signature so an in-place reload (--sync-objects) replaces it cleanly instead
-- of leaving an ambiguous overload.
DROP FUNCTION IF EXISTS atlas_breakdown(
    TEXT, TIMESTAMP, INTEGER, TEXT, TEXT, TEXT, TEXT, TEXT);

CREATE OR REPLACE FUNCTION atlas_breakdown(
    p_dimension  TEXT,                              -- verification: agency|context|outcome|disclosure|algorithm|jurisdiction ; lifecycle: agency|event_type
    p_since      TIMESTAMP,
    p_limit      INTEGER,
    p_kind       TEXT      DEFAULT 'verification',
    p_outcomes   TEXT      DEFAULT NULL,
    p_disclosure TEXT      DEFAULT NULL,
    p_contexts   TEXT      DEFAULT NULL,
    p_agencies   TEXT      DEFAULT NULL,
    p_search     TEXT      DEFAULT NULL   -- v9.250: case-insensitive label filter (find one slice among thousands)
) RETURNS TABLE (
    label       TEXT,
    n_total     BIGINT,
    n_failure   BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH breakdown_v AS (
        SELECT
            CASE p_dimension
                WHEN 'agency'       THEN ag.name::TEXT
                WHEN 'context'      THEN vc.context_type::TEXT
                WHEN 'outcome'      THEN ve.outcome::TEXT
                WHEN 'disclosure'   THEN ve.disclosure_level::TEXT
                WHEN 'jurisdiction' THEN ag.jurisdiction::TEXT
                WHEN 'algorithm'    THEN COALESCE(ca.name::TEXT, 'Zero-knowledge (no token)')
                ELSE ve.outcome::TEXT
            END                                                     AS label,
            count(*)                                                AS n_total,
            count(*) FILTER (WHERE ve.outcome <> 'SUCCESS')         AS n_failure
        FROM VerificationEvent ve
        JOIN      Agency               ag ON ve.requesting_agency_id = ag.agency_id
        JOIN      VerificationContext  vc ON ve.context_id           = vc.context_id
        LEFT JOIN IdentityToken         t ON ve.token_id             = t.token_id
        LEFT JOIN CryptographicAlgorithm ca ON t.algorithm_id        = ca.algorithm_id
        WHERE p_kind = 'verification'
          AND (ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_outcomes   IS NULL OR ve.outcome         = ANY(string_to_array(p_outcomes, ',')))
          AND (p_disclosure IS NULL OR ve.disclosure_level = ANY(string_to_array(p_disclosure, ',')))
          AND (p_contexts   IS NULL OR vc.context_type     = ANY(string_to_array(p_contexts, ',')))
          AND (p_agencies   IS NULL OR ve.requesting_agency_id::text = ANY(string_to_array(p_agencies, ',')))
        GROUP BY 1
    ),
    breakdown_l AS (
        SELECT
            CASE p_dimension
                WHEN 'agency'     THEN COALESCE(ag.name::TEXT, 'System / device')
                WHEN 'event_type' THEN le.event_type::TEXT
                ELSE le.event_type::TEXT
            END                                                     AS label,
            count(*)                                                AS n_total,
            count(*) FILTER (WHERE le.event_type IN ('REVOKED', 'LOST')) AS n_failure
        FROM TokenLifecycleEvent le
        LEFT JOIN Agency ag ON le.actor_agency_id = ag.agency_id
        WHERE p_kind = 'lifecycle'
          AND (le.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_agencies IS NULL OR le.actor_agency_id::text = ANY(string_to_array(p_agencies, ',')))
        GROUP BY 1
    )
    SELECT label, n_total, n_failure FROM (
        SELECT * FROM breakdown_v
        UNION ALL
        SELECT * FROM breakdown_l
    ) rolled
    WHERE label IS NOT NULL
      AND (p_search IS NULL OR label ILIKE '%' || p_search || '%')
    ORDER BY n_total DESC, label ASC
    LIMIT p_limit;
$$;

COMMENT ON FUNCTION atlas_breakdown IS
  'Top-K categorical roll-up for the Atlas Overview/Breakdown. Groups events in '
  'the window by one whitelisted dimension, ordered by volume, capped at '
  'p_limit (API-capped at _ATLAS_MAX_CATEGORIES). Non-geographic; counts '
  'zero-knowledge events like any other (C6), never locating them.';


-- ----------------------------------------------------------------------------
-- atlas_crosstab  (roadmap P2.3, v9.249 — the Breakdown view)
--
-- A 2-D categorical pivot for the "which slice is anomalous?" question: counts
-- the window's events grouped by a ROW dimension and a COLUMN dimension, so an
-- operator can read a failure or disclosure profile per agency/context/etc. at
-- a glance. The rows are the top-K categories of the row dimension by volume
-- (capped at p_limit == _ATLAS_MAX_CATEGORIES); the column dimension is a
-- low-cardinality categorical (outcome/disclosure/event_type), so the cell
-- count is bounded by construction (C8).
--
-- Non-geographic: a zero-knowledge verification is counted in its agency /
-- context / jurisdiction row and its disclosure column, but never located (C6).
-- Both dimensions are whitelisted by the API before they reach the CASE, so
-- there is no dynamic SQL and no injection surface.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_crosstab(
    p_row_dim    TEXT,       -- verification: agency|context|jurisdiction|algorithm ; lifecycle: agency|event_type
    p_col_dim    TEXT,       -- verification: outcome|disclosure ; lifecycle: event_type
    p_since      TIMESTAMP,
    p_limit      INTEGER,
    p_kind       TEXT      DEFAULT 'verification',
    p_outcomes   TEXT      DEFAULT NULL,
    p_disclosure TEXT      DEFAULT NULL,
    p_contexts   TEXT      DEFAULT NULL,
    p_agencies   TEXT      DEFAULT NULL
) RETURNS TABLE (
    row_label   TEXT,
    col_label   TEXT,
    n_total     BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH base AS (
        SELECT
            CASE p_row_dim
                WHEN 'agency'       THEN ag.name::TEXT
                WHEN 'context'      THEN vc.context_type::TEXT
                WHEN 'jurisdiction' THEN ag.jurisdiction::TEXT
                WHEN 'algorithm'    THEN COALESCE(ca.name::TEXT, 'Zero-knowledge (no token)')
                ELSE ag.name::TEXT
            END AS rl,
            CASE p_col_dim
                WHEN 'outcome'    THEN ve.outcome::TEXT
                WHEN 'disclosure' THEN ve.disclosure_level::TEXT
                ELSE ve.outcome::TEXT
            END AS cl
        FROM VerificationEvent ve
        JOIN      Agency               ag ON ve.requesting_agency_id = ag.agency_id
        JOIN      VerificationContext  vc ON ve.context_id           = vc.context_id
        LEFT JOIN IdentityToken         t ON ve.token_id             = t.token_id
        LEFT JOIN CryptographicAlgorithm ca ON t.algorithm_id        = ca.algorithm_id
        WHERE p_kind = 'verification'
          AND (ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_outcomes   IS NULL OR ve.outcome         = ANY(string_to_array(p_outcomes, ',')))
          AND (p_disclosure IS NULL OR ve.disclosure_level = ANY(string_to_array(p_disclosure, ',')))
          AND (p_contexts   IS NULL OR vc.context_type     = ANY(string_to_array(p_contexts, ',')))
          AND (p_agencies   IS NULL OR ve.requesting_agency_id::text = ANY(string_to_array(p_agencies, ',')))
        UNION ALL
        SELECT
            CASE p_row_dim
                WHEN 'agency'     THEN COALESCE(ag.name::TEXT, 'System / device')
                WHEN 'event_type' THEN le.event_type::TEXT
                ELSE le.event_type::TEXT
            END AS rl,
            le.event_type::TEXT AS cl
        FROM TokenLifecycleEvent le
        LEFT JOIN Agency ag ON le.actor_agency_id = ag.agency_id
        WHERE p_kind = 'lifecycle'
          AND (le.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_agencies IS NULL OR le.actor_agency_id::text = ANY(string_to_array(p_agencies, ',')))
    ),
    top_rows AS (
        SELECT rl FROM base WHERE rl IS NOT NULL
        GROUP BY rl ORDER BY count(*) DESC, rl ASC LIMIT p_limit
    )
    SELECT b.rl AS row_label, b.cl AS col_label, count(*)::BIGINT AS n_total
    FROM base b JOIN top_rows tr ON b.rl = tr.rl
    WHERE b.cl IS NOT NULL
    GROUP BY b.rl, b.cl
    ORDER BY b.rl ASC, b.cl ASC;
$$;

COMMENT ON FUNCTION atlas_crosstab IS
  'Roadmap P2.3 (Breakdown view): a 2-D categorical pivot (row dimension x '
  'column dimension) for spotting an anomalous slice. Rows are the top-K of '
  'the row dimension by volume (p_limit == _ATLAS_MAX_CATEGORIES); columns are '
  'a low-cardinality categorical, so the cells are bounded (C8). Non-geographic '
  '(C6): zero-knowledge events are counted, never located.';


-- ----------------------------------------------------------------------------
-- atlas_heatmap  (roadmap P2.3 ship 7, v9.264 — the Trends view)
--
-- The temporal-rhythm view: events binned by ISO weekday (1=Mon..7=Sun) x hour
-- of day (0..23), so an operator reads WHEN the nation verifies (business-hours
-- ridge, weekend trough, an off-hours anomaly). Bounded by construction to at
-- most 7 x 24 = 168 cells per kind (C8). Non-geographic, so a zero-knowledge
-- verification is counted in its weekday/hour cell but never located (C6).
-- Windows on event_timestamp >= COALESCE(p_since, '-infinity') so a concrete
-- window prunes the monthly partitions under the generic plan (v9.260).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_heatmap(
    p_since      TIMESTAMP,
    p_kind       TEXT      DEFAULT 'verification',
    p_outcomes   TEXT      DEFAULT NULL,
    p_disclosure TEXT      DEFAULT NULL,
    p_contexts   TEXT      DEFAULT NULL,
    p_agencies   TEXT      DEFAULT NULL
) RETURNS TABLE (
    dow         INTEGER,
    hour        INTEGER,
    n           BIGINT,
    n_failure   BIGINT
)
LANGUAGE sql
STABLE
AS $$
    SELECT
        EXTRACT(ISODOW FROM ve.event_timestamp)::INTEGER            AS dow,
        EXTRACT(HOUR   FROM ve.event_timestamp)::INTEGER            AS hour,
        count(*)                                                    AS n,
        count(*) FILTER (WHERE ve.outcome <> 'SUCCESS')             AS n_failure
    FROM VerificationEvent ve
    LEFT JOIN VerificationContext vc ON ve.context_id = vc.context_id
    WHERE p_kind = 'verification'
      AND (ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
      AND (p_outcomes   IS NULL OR ve.outcome          = ANY(string_to_array(p_outcomes, ',')))
      AND (p_disclosure IS NULL OR ve.disclosure_level = ANY(string_to_array(p_disclosure, ',')))
      AND (p_contexts   IS NULL OR vc.context_type      = ANY(string_to_array(p_contexts, ',')))
      AND (p_agencies   IS NULL OR ve.requesting_agency_id::text = ANY(string_to_array(p_agencies, ',')))
    GROUP BY 1, 2
    UNION ALL
    SELECT
        EXTRACT(ISODOW FROM le.event_timestamp)::INTEGER,
        EXTRACT(HOUR   FROM le.event_timestamp)::INTEGER,
        count(*),
        count(*) FILTER (WHERE le.event_type IN ('REVOKED', 'LOST'))
    FROM TokenLifecycleEvent le
    WHERE p_kind = 'lifecycle'
      AND (le.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
      AND (p_agencies IS NULL OR le.actor_agency_id::text = ANY(string_to_array(p_agencies, ',')))
    GROUP BY 1, 2;
$$;

COMMENT ON FUNCTION atlas_heatmap IS
  'Roadmap P2.3 ship 7 (Trends): events binned by ISO weekday x hour of day, the '
  'temporal-rhythm view. Bounded to 7x24=168 cells per kind (C8); non-geographic '
  'so zero-knowledge events are counted in their cell, never located (C6).';


-- ----------------------------------------------------------------------------
-- atlas_series_stacked  (roadmap P2.3 ship 7, v9.264 — the Trends view)
--
-- Volume over time BROKEN OUT by one dimension: for each time bucket, the count
-- per category, but only for the top-K categories by total volume; everything
-- else folds into a single 'Other' band. So a stacked-area chart shows how the
-- composition of activity shifts over the window (a context surging, a failure
-- band widening) without unbounded series. Bounded to p_buckets x (p_limit + 1)
-- rows (C8). Non-geographic (C6). Windows via COALESCE(p_since, '-infinity') and
-- references the parameter directly in the WHERE so the generic plan prunes.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_series_stacked(
    p_since      TIMESTAMP,
    p_buckets    INTEGER,
    p_dimension  TEXT,       -- context | outcome | disclosure | agency | jurisdiction
    p_kind       TEXT      DEFAULT 'verification',
    p_limit      INTEGER   DEFAULT 6,
    p_outcomes   TEXT      DEFAULT NULL,
    p_disclosure TEXT      DEFAULT NULL,
    p_contexts   TEXT      DEFAULT NULL,
    p_agencies   TEXT      DEFAULT NULL
) RETURNS TABLE (
    bucket_ts   TIMESTAMP,
    label       TEXT,
    n           BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH params AS (
        SELECT (extract(epoch FROM (CURRENT_TIMESTAMP - p_since))
                / GREATEST(p_buckets, 1))::DOUBLE PRECISION AS bucket_secs
    ),
    base AS (
        SELECT
            (p_since
                + (floor(extract(epoch FROM (ve.event_timestamp - p_since))
                         / NULLIF(params.bucket_secs, 0)) * params.bucket_secs
                  ) * INTERVAL '1 second'
            )::TIMESTAMP                                            AS bt,
            CASE p_dimension
                WHEN 'context'      THEN vc.context_type::TEXT
                WHEN 'outcome'      THEN ve.outcome::TEXT
                WHEN 'disclosure'   THEN ve.disclosure_level::TEXT
                WHEN 'agency'       THEN ag.name::TEXT
                WHEN 'jurisdiction' THEN ag.jurisdiction::TEXT
                ELSE ve.outcome::TEXT
            END                                                     AS cat
        FROM VerificationEvent ve
        JOIN      Agency              ag ON ve.requesting_agency_id = ag.agency_id
        JOIN      VerificationContext vc ON ve.context_id           = vc.context_id,
             params
        WHERE p_kind = 'verification'
          AND ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp)
          AND ve.event_timestamp <  CURRENT_TIMESTAMP
          AND (p_outcomes   IS NULL OR ve.outcome          = ANY(string_to_array(p_outcomes, ',')))
          AND (p_disclosure IS NULL OR ve.disclosure_level = ANY(string_to_array(p_disclosure, ',')))
          AND (p_contexts   IS NULL OR vc.context_type      = ANY(string_to_array(p_contexts, ',')))
          AND (p_agencies   IS NULL OR ve.requesting_agency_id::text = ANY(string_to_array(p_agencies, ',')))
        UNION ALL
        SELECT
            (p_since
                + (floor(extract(epoch FROM (le.event_timestamp - p_since))
                         / NULLIF(params.bucket_secs, 0)) * params.bucket_secs
                  ) * INTERVAL '1 second'
            )::TIMESTAMP                                            AS bt,
            CASE p_dimension
                WHEN 'agency'     THEN COALESCE(ag.name::TEXT, 'System / device')
                WHEN 'event_type' THEN le.event_type::TEXT
                ELSE le.event_type::TEXT
            END                                                     AS cat
        FROM TokenLifecycleEvent le
        LEFT JOIN Agency ag ON le.actor_agency_id = ag.agency_id,
             params
        WHERE p_kind = 'lifecycle'
          AND le.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp)
          AND le.event_timestamp <  CURRENT_TIMESTAMP
          AND (p_agencies IS NULL OR le.actor_agency_id::text = ANY(string_to_array(p_agencies, ',')))
    ),
    top_cats AS (
        SELECT cat FROM base WHERE cat IS NOT NULL
        GROUP BY cat ORDER BY count(*) DESC, cat ASC LIMIT GREATEST(p_limit, 1)
    )
    SELECT
        b.bt                                                        AS bucket_ts,
        CASE WHEN tc.cat IS NOT NULL THEN b.cat ELSE 'Other' END    AS label,
        count(*)                                                    AS n
    FROM base b
    LEFT JOIN top_cats tc ON b.cat = tc.cat
    WHERE b.cat IS NOT NULL
    GROUP BY b.bt, CASE WHEN tc.cat IS NOT NULL THEN b.cat ELSE 'Other' END
    ORDER BY b.bt, label;
$$;

COMMENT ON FUNCTION atlas_series_stacked IS
  'Roadmap P2.3 ship 7 (Trends): volume over time broken out by one dimension, '
  'top-K categories with the rest folded into Other, for a stacked-area chart. '
  'Bounded to p_buckets x (p_limit + 1) rows (C8); non-geographic (C6).';


-- ----------------------------------------------------------------------------
-- atlas_agency_facet  (roadmap P2.3, v9.251 — the global faceted filter)
--
-- The agency facet needs (agency_id, name, count): the id to drive the filter
-- (the filter param is a CSV of agency_id) and the count so the operator sees
-- how much activity each agency carries in the current filter context. Counts
-- honour every OTHER active facet (outcome/disclosure/context) but NOT the
-- agency selection itself, which is standard faceting (you can still see and
-- add other agencies). A name/jurisdiction search makes it a typeahead that
-- survives thousands of agencies. Top-K by volume (capped at the API).
--
-- Non-geographic (C6): a zero-knowledge verification counts toward its
-- requesting agency, never a location.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_agency_facet(
    p_since      TIMESTAMP,
    p_limit      INTEGER,
    p_kind       TEXT      DEFAULT 'verification',
    p_search     TEXT      DEFAULT NULL,
    p_outcomes   TEXT      DEFAULT NULL,
    p_disclosure TEXT      DEFAULT NULL,
    p_contexts   TEXT      DEFAULT NULL
) RETURNS TABLE (
    agency_id   INTEGER,
    name        TEXT,
    n_total     BIGINT
)
LANGUAGE sql
STABLE
AS $$
    SELECT agency_id, name, n_total FROM (
        SELECT ag.agency_id, ag.name::TEXT AS name, count(*)::BIGINT AS n_total
        FROM VerificationEvent ve
        JOIN Agency ag ON ve.requesting_agency_id = ag.agency_id
        LEFT JOIN VerificationContext vc ON ve.context_id = vc.context_id
        WHERE p_kind = 'verification'
          AND (ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_outcomes   IS NULL OR ve.outcome         = ANY(string_to_array(p_outcomes, ',')))
          AND (p_disclosure IS NULL OR ve.disclosure_level = ANY(string_to_array(p_disclosure, ',')))
          AND (p_contexts   IS NULL OR vc.context_type     = ANY(string_to_array(p_contexts, ',')))
          AND (p_search     IS NULL OR ag.name ILIKE '%' || p_search || '%'
                                    OR ag.jurisdiction ILIKE '%' || p_search || '%')
        GROUP BY ag.agency_id, ag.name
        UNION ALL
        SELECT ag.agency_id, ag.name::TEXT AS name, count(*)::BIGINT AS n_total
        FROM TokenLifecycleEvent le
        JOIN Agency ag ON le.actor_agency_id = ag.agency_id
        WHERE p_kind = 'lifecycle'
          AND (le.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_search IS NULL OR ag.name ILIKE '%' || p_search || '%'
                                OR ag.jurisdiction ILIKE '%' || p_search || '%')
        GROUP BY ag.agency_id, ag.name
    ) facet
    ORDER BY n_total DESC, name ASC
    LIMIT p_limit;
$$;

COMMENT ON FUNCTION atlas_agency_facet IS
  'Roadmap P2.3 (global filter): agencies with (id, name, count) for the agency '
  'facet/typeahead, honouring the other active facets but not the agency '
  'selection, searchable by name/jurisdiction, top-K by volume. Non-geographic '
  '(C6). Capped at the API (_ATLAS_MAX_CATEGORIES).';


-- ----------------------------------------------------------------------------
-- atlas_records  (roadmap P2.3, v9.252 — the records grid)
--
-- The drill from the aggregates into the actual events, one stream at a time,
-- honouring the global filter and keyset-paginated so it survives millions of
-- rows (never an offset scan, never all-at-once). The two-stage top-N + late
-- join keeps it in the millisecond range: filter + top-N off the
-- (event_timestamp DESC, event_id DESC) index first, join metadata only for
-- the <=p_limit rows returned. The context filter resolves its names to ids in
-- a tiny subquery so the scan stays index-friendly without a metadata join.
--
-- C6: a zero-knowledge verification appears as a row (activity is real) but its
-- subject and its location are withheld — the grid shows '(zero-knowledge)' and
-- no location, exactly as the map never plots it.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_records(
    p_since      TIMESTAMP,
    p_cursor_ts  TIMESTAMP,
    p_cursor_id  INTEGER,
    p_limit      INTEGER,
    p_kind       TEXT      DEFAULT 'verification',
    p_outcomes   TEXT      DEFAULT NULL,
    p_disclosure TEXT      DEFAULT NULL,
    p_contexts   TEXT      DEFAULT NULL,
    p_agencies   TEXT      DEFAULT NULL
) RETURNS TABLE (
    event_id       BIGINT,
    event_timestamp TIMESTAMP,
    agency_name     TEXT,
    category        TEXT,     -- verification: context; lifecycle: event_type
    outcome         TEXT,     -- verification: outcome; lifecycle: reason_code
    disclosure      TEXT,     -- verification: disclosure_level; lifecycle: NULL
    subject         TEXT,     -- holder name, or '(zero-knowledge)'
    location        TEXT,     -- requestor_location, or NULL for ZK (C6)
    tone            TEXT
)
LANGUAGE sql
STABLE
AS $$
    WITH top_v AS (
        SELECT ve.event_id, ve.event_timestamp, ve.token_id, ve.requesting_agency_id,
               ve.context_id, ve.outcome, ve.disclosure_level, ve.requestor_location
        FROM VerificationEvent ve
        WHERE p_kind = 'verification'
          AND (ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_cursor_ts IS NULL OR (ve.event_timestamp, ve.event_id) < (p_cursor_ts, COALESCE(p_cursor_id, 2147483647)))
          AND (p_outcomes   IS NULL OR ve.outcome          = ANY(string_to_array(p_outcomes, ',')))
          AND (p_disclosure IS NULL OR ve.disclosure_level  = ANY(string_to_array(p_disclosure, ',')))
          AND (p_contexts   IS NULL OR ve.context_id IN (
                 SELECT context_id FROM VerificationContext WHERE context_type = ANY(string_to_array(p_contexts, ','))))
          AND (p_agencies   IS NULL OR ve.requesting_agency_id::text = ANY(string_to_array(p_agencies, ',')))
        ORDER BY ve.event_timestamp DESC, ve.event_id DESC
        LIMIT p_limit
    ),
    top_l AS (
        SELECT le.event_id, le.event_timestamp, le.token_id, le.actor_agency_id,
               le.event_type, le.reason_code
        FROM TokenLifecycleEvent le
        WHERE p_kind = 'lifecycle'
          AND (le.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_cursor_ts IS NULL OR (le.event_timestamp, le.event_id) < (p_cursor_ts, COALESCE(p_cursor_id, 2147483647)))
          AND (p_agencies IS NULL OR le.actor_agency_id::text = ANY(string_to_array(p_agencies, ',')))
        ORDER BY le.event_timestamp DESC, le.event_id DESC
        LIMIT p_limit
    )
    SELECT event_id, event_timestamp, agency_name, category, outcome, disclosure, subject, location, tone
    FROM (
        SELECT tv.event_id, tv.event_timestamp,
               ag.name::TEXT                                   AS agency_name,
               vc.context_type::TEXT                           AS category,
               tv.outcome::TEXT                                AS outcome,
               tv.disclosure_level::TEXT                       AS disclosure,
               COALESCE(i.legal_name::TEXT, '(zero-knowledge)') AS subject,
               CASE WHEN tv.disclosure_level = 'ZERO_KNOWLEDGE' THEN NULL
                    ELSE tv.requestor_location::TEXT END        AS location,
               CASE WHEN tv.outcome <> 'SUCCESS'                THEN 'alert'
                    WHEN tv.disclosure_level = 'FULL'           THEN 'full'
                    WHEN tv.disclosure_level = 'ZERO_KNOWLEDGE' THEN 'zk'
                    ELSE 'selective' END::TEXT                  AS tone
        FROM      top_v tv
        JOIN      Agency               ag ON tv.requesting_agency_id = ag.agency_id
        JOIN      VerificationContext  vc ON tv.context_id           = vc.context_id
        LEFT JOIN IdentityToken         t ON tv.token_id             = t.token_id
        LEFT JOIN Individual            i ON t.individual_id         = i.individual_id
        UNION ALL
        SELECT tl.event_id, tl.event_timestamp,
               COALESCE(ag.name::TEXT, 'System / device')       AS agency_name,
               tl.event_type::TEXT                              AS category,
               COALESCE(tl.reason_code::TEXT, '')               AS outcome,
               NULL::TEXT                                       AS disclosure,
               i.legal_name::TEXT                               AS subject,
               NULL::TEXT                                       AS location,
               CASE WHEN tl.event_type IN ('REVOKED', 'LOST')   THEN 'alert'
                    WHEN tl.event_type = 'ISSUED'               THEN 'selective'
                    ELSE 'full' END::TEXT                       AS tone
        FROM      top_l tl
        LEFT JOIN Agency        ag ON tl.actor_agency_id = ag.agency_id
        JOIN      IdentityToken  t ON tl.token_id        = t.token_id
        JOIN      Individual     i ON t.individual_id    = i.individual_id
    ) rows
    ORDER BY event_timestamp DESC, event_id DESC
    LIMIT p_limit;
$$;

COMMENT ON FUNCTION atlas_records IS
  'Roadmap P2.3 (records grid): one stream of events matching the global '
  'filter, keyset-paginated by (event_timestamp, event_id) DESC so it scales to '
  'millions. C6: a zero-knowledge verification is a row but its subject and '
  'location are withheld. Capped at the API (_ATLAS_MAX_EVENTS).';


-- ----------------------------------------------------------------------------
-- atlas_geo_jurisdictions (v9.253, Map v2 "Regions" layer — the DEFAULT view)
--
-- Verification (or lifecycle) volume rolled up by the REQUESTING AGENCY's
-- jurisdiction (ISO 3166-2), the same non-locating grouping atlas_breakdown
-- already offers for its 'jurisdiction' dimension. A jurisdiction is a
-- regulatory grouping, NOT a coordinate, so a zero-knowledge verification IS
-- counted in its jurisdiction's total (n_zk) exactly like the breakdown, yet is
-- NEVER located: the centroid is the average position of the jurisdiction's
-- LOCATED, non-ZK events only. A jurisdiction whose activity is entirely
-- zero-knowledge has a NULL centroid — counted but unplaceable, which is the
-- whole point (C6). Top-K by volume, capped by the API (C8).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_geo_jurisdictions(
    p_since      TIMESTAMP DEFAULT NULL,
    p_limit      INTEGER   DEFAULT 200,
    p_kind       TEXT      DEFAULT 'verification',
    p_outcomes   TEXT      DEFAULT NULL,
    p_disclosure TEXT      DEFAULT NULL,
    p_contexts   TEXT      DEFAULT NULL,
    p_agencies   TEXT      DEFAULT NULL
) RETURNS TABLE (
    jurisdiction TEXT,
    n_total      BIGINT,
    n_failure    BIGINT,
    n_zk         BIGINT,
    n_located    BIGINT,
    centroid_lat DOUBLE PRECISION,
    centroid_lon DOUBLE PRECISION
)
LANGUAGE sql
STABLE
AS $$
    WITH geo_v AS (
        SELECT
            ag.jurisdiction::TEXT AS jurisdiction,
            count(*)                                                       AS n_total,
            count(*) FILTER (WHERE ve.outcome = 'FAILURE')                 AS n_failure,
            count(*) FILTER (WHERE ve.disclosure_level = 'ZERO_KNOWLEDGE') AS n_zk,
            count(*) FILTER (WHERE ve.disclosure_level <> 'ZERO_KNOWLEDGE'
                              AND ve.latitude IS NOT NULL
                              AND ve.longitude IS NOT NULL)                AS n_located,
            avg(ve.latitude)  FILTER (WHERE ve.disclosure_level <> 'ZERO_KNOWLEDGE'
                              AND ve.latitude IS NOT NULL)                 AS centroid_lat,
            avg(ve.longitude) FILTER (WHERE ve.disclosure_level <> 'ZERO_KNOWLEDGE'
                              AND ve.longitude IS NOT NULL)                AS centroid_lon
        FROM VerificationEvent ve
        JOIN      Agency              ag ON ve.requesting_agency_id = ag.agency_id
        JOIN      VerificationContext vc ON ve.context_id           = vc.context_id
        WHERE p_kind = 'verification'
          AND (ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_outcomes   IS NULL OR ve.outcome            = ANY(string_to_array(p_outcomes, ',')))
          AND (p_disclosure IS NULL OR ve.disclosure_level   = ANY(string_to_array(p_disclosure, ',')))
          AND (p_contexts   IS NULL OR vc.context_type        = ANY(string_to_array(p_contexts, ',')))
          AND (p_agencies   IS NULL OR ve.requesting_agency_id::text = ANY(string_to_array(p_agencies, ',')))
        GROUP BY ag.jurisdiction
    ),
    geo_l AS (
        SELECT
            COALESCE(ag.jurisdiction::TEXT, '(system)')                  AS jurisdiction,
            count(*)                                                     AS n_total,
            count(*) FILTER (WHERE le.event_type IN ('REVOKED','LOST'))  AS n_failure,
            0::BIGINT                                                    AS n_zk,
            0::BIGINT                                                    AS n_located,
            NULL::DOUBLE PRECISION                                       AS centroid_lat,
            NULL::DOUBLE PRECISION                                       AS centroid_lon
        FROM TokenLifecycleEvent le
        LEFT JOIN Agency ag ON le.actor_agency_id = ag.agency_id
        WHERE p_kind = 'lifecycle'
          AND (le.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_agencies IS NULL OR le.actor_agency_id::text = ANY(string_to_array(p_agencies, ',')))
        GROUP BY COALESCE(ag.jurisdiction::TEXT, '(system)')
    )
    SELECT g.jurisdiction, g.n_total, g.n_failure, g.n_zk, g.n_located, g.centroid_lat, g.centroid_lon
    FROM (
        SELECT * FROM geo_v
        UNION ALL
        SELECT * FROM geo_l
    ) g
    ORDER BY g.n_total DESC
    LIMIT GREATEST(p_limit, 0);
$$;

COMMENT ON FUNCTION atlas_geo_jurisdictions IS
  'Map v2 Regions layer: volume by requesting-agency jurisdiction (ISO 3166-2). '
  'Counts zero-knowledge events in the jurisdiction total like atlas_breakdown, '
  'but the centroid derives from located non-ZK events only, so ZK is counted '
  'and never located (C6). Top-K by volume, API-capped (C8).';


-- ----------------------------------------------------------------------------
-- atlas_hexbin (v9.253, Map v2 "Density" layer)
--
-- Bins located verification events into a POINTY-TOP hexagonal grid of size
-- p_size (circumradius, in degrees of lon/lat) and returns the top-K densest
-- hex centres with their counts. A hexagonal lattice tiles the plane without
-- the axis-aligned artefacts of a square grid, so a density surface reads
-- honestly. The binning is the standard pixel->axial->cube-round->axial
-- (Red Blob Games) done in lon/lat space. C6 is identical to atlas_clusters:
-- ZERO_KNOWLEDGE events are excluded entirely (a hex holding a single ZK event
-- would pin it), so the surface is of located, non-ZK activity only. Top-K by
-- count caps the wire and renderer (C8) however fine p_size is.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION atlas_hexbin(
    p_min_lat    DOUBLE PRECISION,
    p_min_lon    DOUBLE PRECISION,
    p_max_lat    DOUBLE PRECISION,
    p_max_lon    DOUBLE PRECISION,
    p_size       DOUBLE PRECISION,
    p_limit      INTEGER,
    p_since      TIMESTAMP DEFAULT NULL,
    p_kind       TEXT      DEFAULT 'verification',
    p_outcomes   TEXT      DEFAULT NULL,
    p_disclosure TEXT      DEFAULT NULL,
    p_contexts   TEXT      DEFAULT NULL,
    p_agencies   TEXT      DEFAULT NULL
) RETURNS TABLE (
    lat        DOUBLE PRECISION,   -- hex centre latitude
    lon        DOUBLE PRECISION,   -- hex centre longitude
    n_total    BIGINT,
    n_failure  BIGINT
)
LANGUAGE sql
STABLE
AS $$
    WITH src AS (
        SELECT ve.latitude AS y, ve.longitude AS x, ve.outcome AS outcome
        FROM VerificationEvent ve
        JOIN VerificationContext vc ON ve.context_id = vc.context_id
        WHERE p_kind = 'verification'
          AND ve.latitude IS NOT NULL AND ve.longitude IS NOT NULL
          AND ve.disclosure_level <> 'ZERO_KNOWLEDGE'          -- C6
          AND ve.latitude BETWEEN p_min_lat AND p_max_lat
          AND (
                (p_min_lon <= p_max_lon AND ve.longitude BETWEEN p_min_lon AND p_max_lon)
             OR (p_min_lon  > p_max_lon AND (ve.longitude >= p_min_lon OR ve.longitude <= p_max_lon))
          )
          AND (ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))
          AND (p_outcomes   IS NULL OR ve.outcome            = ANY(string_to_array(p_outcomes, ',')))
          AND (p_disclosure IS NULL OR ve.disclosure_level   = ANY(string_to_array(p_disclosure, ',')))
          AND (p_contexts   IS NULL OR vc.context_type        = ANY(string_to_array(p_contexts, ',')))
          AND (p_agencies   IS NULL OR ve.requesting_agency_id::text = ANY(string_to_array(p_agencies, ',')))
    ),
    frac AS (
        SELECT outcome,
               (sqrt(3.0)/3.0 * x - 1.0/3.0 * y) / p_size AS qf,
               (2.0/3.0 * y) / p_size                     AS rf
        FROM src
    ),
    diffs AS (
        SELECT outcome, qf, rf,
               round(qf)        AS rx0,
               round(-qf - rf)  AS ry0,
               round(rf)        AS rz0,
               abs(round(qf)        - qf)         AS dx,
               abs(round(-qf - rf)  - (-qf - rf)) AS dy,
               abs(round(rf)        - rf)         AS dz
        FROM frac
    ),
    hexed AS (
        SELECT
            CASE WHEN dx > dy AND dx > dz THEN (-ry0 - rz0) ELSE rx0 END          AS q,
            CASE WHEN (dx > dy AND dx > dz) OR (dy > dz) THEN rz0 ELSE (-rx0 - ry0) END AS r,
            outcome
        FROM diffs
    )
    SELECT
        p_size * (3.0/2.0 * r)                             AS lat,
        p_size * (sqrt(3.0) * q + sqrt(3.0)/2.0 * r)       AS lon,
        count(*)                                           AS n_total,
        count(*) FILTER (WHERE outcome = 'FAILURE')        AS n_failure
    FROM hexed
    GROUP BY q, r
    ORDER BY n_total DESC
    LIMIT GREATEST(p_limit, 0);
$$;

COMMENT ON FUNCTION atlas_hexbin IS
  'Map v2 Density layer: located verification events binned into a pointy-top '
  'hex grid of size p_size (degrees), top-K densest centres by count. Excludes '
  'ZERO_KNOWLEDGE entirely (C6), API-capped (C8).';
