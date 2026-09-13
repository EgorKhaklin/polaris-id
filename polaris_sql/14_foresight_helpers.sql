-- ============================================================================
-- 14_foresight_helpers.sql — Layer-1 surface for foresight signals (v9.12)
--
-- v9.12, Position B: a Layer-1
-- bundle was committed as part of the same composite ship that introduced
-- the foresight surface. This file is that bundle.
--
-- Three SQL functions surface time-based signals from the existing schema:
--
--   1. foresight_token_age_distribution()
--      Returns histogram of token ages (0-30d, 30-90d, 90-365d, 365d+)
--      Foresight signal: long-tail accumulation of old tokens may indicate
--      a missing renewal or migration nudge.
--
--   2. foresight_verification_dormancy(p_days INTEGER)
--      Returns count of ACTIVE tokens with no verification in last p_days.
--      Foresight signal: dormant active tokens may be candidates for
--      proactive re-verification or revocation prompting.
--
--   3. foresight_audit_volume_trend(p_weeks INTEGER)
--      Returns weekly TokenLifecycleEvent + VerificationEvent counts for
--      last p_weeks. Foresight signal: capacity-planning trend; sudden
--      acceleration may surface scaling needs ahead of operational pain.
--
-- All three are read-only, additive, return SETOF rows. They graceful no-op
-- on empty data. The ForesightAgent calls them when DB is reachable
-- (currently only documents their availability; future iteration may
-- include their output in §IV).
--
-- Constitutional contract:
--   - C1 / C9 / G1: read-only; never write
--   - Audit-of-record: queries are observational only
--   - Vocation: signals enumerated above all serve anti-coercion
--     (dormancy detection helps surface tokens that may be recoverable
--     before they expire silently; capacity trend prevents ops failure
--     that would compromise availability of identity verification)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. foresight_token_age_distribution
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION foresight_token_age_distribution()
RETURNS TABLE (
    age_bucket    VARCHAR(20),
    token_count   BIGINT,
    pct_of_total  NUMERIC(5,2)
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_total BIGINT;
BEGIN
    SELECT COUNT(*) INTO v_total FROM IdentityToken;

    IF v_total = 0 THEN
        -- Return empty result; caller decides how to handle
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        bucket::VARCHAR(20)              AS age_bucket,
        bucket_count                     AS token_count,
        ROUND((bucket_count::NUMERIC / v_total::NUMERIC) * 100, 2)
            AS pct_of_total
    FROM (
        SELECT
            CASE
                WHEN issued_date >= CURRENT_TIMESTAMP - INTERVAL '30 days' THEN '0-30d'
                WHEN issued_date >= CURRENT_TIMESTAMP - INTERVAL '90 days' THEN '30-90d'
                WHEN issued_date >= CURRENT_TIMESTAMP - INTERVAL '365 days' THEN '90-365d'
                ELSE '365d+'
            END                          AS bucket,
            COUNT(*)                     AS bucket_count
          FROM IdentityToken
         GROUP BY 1
    ) hist
    ORDER BY
        CASE bucket
            WHEN '0-30d'   THEN 1
            WHEN '30-90d'  THEN 2
            WHEN '90-365d' THEN 3
            WHEN '365d+'   THEN 4
        END;
END;
$$;

COMMENT ON FUNCTION foresight_token_age_distribution IS
    'v9.12 / Position B Layer-1 bundle. Returns histogram of token ages '
    '(four buckets). Empty result = empty IdentityToken table. Read-only.';


-- ----------------------------------------------------------------------------
-- 2. foresight_verification_dormancy(p_days INTEGER)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION foresight_verification_dormancy(p_days INTEGER DEFAULT 90)
RETURNS TABLE (
    days_threshold INTEGER,
    dormant_active_token_count BIGINT,
    total_active_token_count BIGINT,
    dormancy_pct NUMERIC(5,2)
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_dormant BIGINT;
    v_total   BIGINT;
BEGIN
    IF p_days < 1 OR p_days > 3650 THEN
        RAISE EXCEPTION 'p_days must be between 1 and 3650 (got %)', p_days
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    SELECT COUNT(*) INTO v_total
      FROM IdentityToken
     WHERE status = 'ACTIVE';

    IF v_total = 0 THEN
        RETURN QUERY SELECT p_days, 0::BIGINT, 0::BIGINT, 0::NUMERIC(5,2);
        RETURN;
    END IF;

    SELECT COUNT(*) INTO v_dormant
      FROM IdentityToken t
     WHERE t.status = 'ACTIVE'
       AND NOT EXISTS (
           SELECT 1 FROM VerificationEvent v
            WHERE v.token_id = t.token_id
              AND v.event_timestamp >= CURRENT_TIMESTAMP - (p_days || ' days')::INTERVAL
       );

    RETURN QUERY SELECT
        p_days,
        v_dormant,
        v_total,
        ROUND((v_dormant::NUMERIC / v_total::NUMERIC) * 100, 2)::NUMERIC(5,2);
END;
$$;

COMMENT ON FUNCTION foresight_verification_dormancy(INTEGER) IS
    'v9.12 / Position B Layer-1 bundle. Counts ACTIVE tokens with no '
    'verification in last p_days. Default 90 days. Range: 1..3650. '
    'Foresight signal for proactive re-verification campaigns.';


-- ----------------------------------------------------------------------------
-- 3. foresight_audit_volume_trend(p_weeks INTEGER)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION foresight_audit_volume_trend(p_weeks INTEGER DEFAULT 12)
RETURNS TABLE (
    week_start                DATE,
    lifecycle_event_count     BIGINT,
    verification_event_count  BIGINT,
    total_audit_volume        BIGINT
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    IF p_weeks < 1 OR p_weeks > 520 THEN
        RAISE EXCEPTION 'p_weeks must be between 1 and 520 (got %)', p_weeks
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN QUERY
    WITH weeks AS (
        SELECT (DATE_TRUNC('week', CURRENT_DATE) - (n || ' weeks')::INTERVAL)::DATE AS week_start
          FROM generate_series(0, p_weeks - 1) n
    ),
    lifecycle_per_week AS (
        SELECT DATE_TRUNC('week', event_timestamp)::DATE AS w,
               COUNT(*) AS c
          FROM TokenLifecycleEvent
         WHERE event_timestamp >= CURRENT_DATE - (p_weeks * 7 || ' days')::INTERVAL
         GROUP BY 1
    ),
    verification_per_week AS (
        SELECT DATE_TRUNC('week', event_timestamp)::DATE AS w,
               COUNT(*) AS c
          FROM VerificationEvent
         WHERE event_timestamp >= CURRENT_DATE - (p_weeks * 7 || ' days')::INTERVAL
         GROUP BY 1
    )
    SELECT
        w.week_start,
        COALESCE(l.c, 0)::BIGINT  AS lifecycle_event_count,
        COALESCE(v.c, 0)::BIGINT  AS verification_event_count,
        (COALESCE(l.c, 0) + COALESCE(v.c, 0))::BIGINT AS total_audit_volume
      FROM weeks w
 LEFT JOIN lifecycle_per_week l    ON l.w = w.week_start
 LEFT JOIN verification_per_week v ON v.w = w.week_start
  ORDER BY w.week_start ASC;
END;
$$;

COMMENT ON FUNCTION foresight_audit_volume_trend(INTEGER) IS
    'v9.12 / Position B Layer-1 bundle. Returns weekly audit-table volume '
    'for last p_weeks. Default 12 weeks. Range: 1..520. Foresight signal '
    'for capacity-planning + scaling-need detection.';


-- ----------------------------------------------------------------------------
-- Smoke test (idempotent; runs at end of file load)
-- ----------------------------------------------------------------------------
DO $foresight_smoke$
DECLARE
    v_age_rows   INTEGER;
    v_dormant    RECORD;
    v_audit_rows INTEGER;
BEGIN
    -- Smoke: each function returns without error on the current DB
    SELECT COUNT(*) INTO v_age_rows
      FROM foresight_token_age_distribution();
    -- v_age_rows may be 0 (empty table) or 1-4 (buckets present)
    IF v_age_rows < 0 OR v_age_rows > 4 THEN
        RAISE EXCEPTION '14_foresight_helpers.sql smoke: age distribution returned unexpected row count %', v_age_rows;
    END IF;

    SELECT * INTO v_dormant FROM foresight_verification_dormancy(90);
    IF v_dormant.days_threshold <> 90 THEN
        RAISE EXCEPTION '14_foresight_helpers.sql smoke: dormancy returned wrong threshold %', v_dormant.days_threshold;
    END IF;

    SELECT COUNT(*) INTO v_audit_rows
      FROM foresight_audit_volume_trend(4);
    IF v_audit_rows <> 4 THEN
        RAISE EXCEPTION '14_foresight_helpers.sql smoke: audit-volume returned % rows, expected 4', v_audit_rows;
    END IF;

    RAISE NOTICE '14_foresight_helpers.sql: 3 foresight helpers loaded + smoke-tested.';
END;
$foresight_smoke$;

-- ============================================================================
-- END OF 14_foresight_helpers.sql
-- ============================================================================
