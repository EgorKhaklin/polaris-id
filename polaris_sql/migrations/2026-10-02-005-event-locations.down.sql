-- 2026-10-02-005 down: rebuild the event tables' location indexes as 02_indexes.sql built them
-- before step 4c, and the GiST indexes as 13_postgis.sql did wherever its `geo` columns exist,
-- and restore the audit trigger's previous body (2026-09-24-013), which copied the
-- polaris.event_lat and event_lon settings into each lifecycle row. A plain CREATE INDEX blocks
-- writes to each table while it scans it.
CREATE INDEX IF NOT EXISTS idx_verificationevent_geo
    ON VerificationEvent (latitude, longitude)
    WHERE latitude IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_verificationevent_geo_time
    ON VerificationEvent (event_timestamp DESC, latitude, longitude)
    WHERE latitude IS NOT NULL;
COMMENT ON INDEX idx_verificationevent_geo IS
  'Bbox queries from atlas_clusters_verifications(). Predicate excludes '
  'NULL latitude rows (legacy / unrecorded location) so the index stays small.';
CREATE INDEX IF NOT EXISTS idx_tokenlifecycleevent_geo
    ON TokenLifecycleEvent (latitude, longitude)
    WHERE latitude IS NOT NULL;

-- The `geo` columns exist only where 13_postgis.sql added them, with the extension, before 4c.
DO $postgis_geo$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'verificationevent'
                  AND column_name = 'geo') THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS gix_verification_geo
                     ON VerificationEvent USING GIST (geo) WHERE geo IS NOT NULL';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'tokenlifecycleevent'
                  AND column_name = 'geo') THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS gix_lifecycle_geo
                     ON TokenLifecycleEvent USING GIST (geo) WHERE geo IS NOT NULL';
    END IF;
END $postgis_geo$;

CREATE OR REPLACE FUNCTION audit_token_state_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_event_type    VARCHAR(40);
    v_actor         INTEGER;
    v_reason        VARCHAR(60);
    v_lat           DOUBLE PRECISION;
    v_lon           DOUBLE PRECISION;
BEGIN
    -- No status change: nothing to audit.
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    -- Map (OLD,NEW) to the event_type column on TokenLifecycleEvent.
    v_event_type := CASE NEW.status
        WHEN 'ACTIVE'  THEN 'ACTIVATED'
        WHEN 'DORMANT' THEN 'DEACTIVATED'
        WHEN 'REVOKED' THEN 'REVOKED'
        WHEN 'LOST'    THEN 'LOST'
        WHEN 'EXPIRED' THEN 'EXPIRED'
        ELSE 'STATUS_CHANGED'
    END;

    -- Optional session-level actor, reason, and location. current_setting
    -- returns '' when the GUC is unset (with missing_ok = true).
    v_actor  := NULLIF(current_setting('polaris.actor_agency_id', true), '')::INTEGER;
    v_reason := NULLIF(current_setting('polaris.reason_code',     true), '');
    v_lat    := NULLIF(current_setting('polaris.event_lat',       true), '')::DOUBLE PRECISION;
    v_lon    := NULLIF(current_setting('polaris.event_lon',       true), '')::DOUBLE PRECISION;

    -- If the application has ALREADY inserted a matching event in this
    -- transaction (the legacy pattern from before this trigger existed,
    -- still used by some stored procedures during the migration window),
    -- skip duplicating. We detect this by looking for a matching event
    -- created within the last 100ms.
    IF EXISTS (
        SELECT 1 FROM TokenLifecycleEvent
        WHERE token_id = NEW.token_id
          AND event_type = v_event_type
          AND event_timestamp >= CURRENT_TIMESTAMP - INTERVAL '100 milliseconds'
    ) THEN
        RETURN NEW;
    END IF;

    -- Append the audit row. The append-only trigger will not block this
    -- because it only fires on UPDATE or DELETE.
    INSERT INTO TokenLifecycleEvent (
        token_id, actor_agency_id, event_type, reason_code, event_timestamp,
        latitude, longitude
    )
    VALUES (
        NEW.token_id, v_actor, v_event_type,
        COALESCE(v_reason, 'AUTO_AUDIT_TRIGGER'),
        CURRENT_TIMESTAMP,
        v_lat, v_lon
    );

    RETURN NEW;
END;
$$;
