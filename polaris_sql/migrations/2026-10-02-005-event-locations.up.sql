-- 2026-10-02-005: the event tables' location indexes and the last writer of a coordinate,
-- withdrawn (lab/strategy/009, step 4c).
--
-- DROP: idx_verificationevent_geo, idx_verificationevent_geo_time and
-- idx_tokenlifecycleevent_geo, B-trees on (latitude, longitude) built in v6 for the Atlas's
-- bounding-box layers, and gix_verification_geo and gix_lifecycle_geo, the GiST indexes the
-- optional 13_postgis.sql built on its generated `geo` columns where PostGIS was installed (a
-- database without PostGIS has neither, hence IF EXISTS). Since step 4 the Atlas sums the
-- activity rollups, and no query filters or sorts by a coordinate, which is all an index serves.
-- Each B-tree cost every located insert an update and grew with the population.
--
-- EXPAND: dropping an index changes no query's result; a previous release still serving during
-- a rolling deploy reads the same answers, more slowly.
-- LOCK: DROP INDEX holds an ACCESS EXCLUSIVE lock on the table for as long as the catalog change
-- takes, and builds nothing; an index on a partitioned table cannot be dropped CONCURRENTLY.
--
-- REPLACE: audit_token_state_change(), the trigger that appends a lifecycle row on a status
-- change, without the polaris.event_lat and event_lon settings it copied into that row. Nothing
-- set them, so every row it wrote carried NULL; a session that set them could have started a
-- location trail with no change to the schema. The body is 06_triggers.sql's, so a database
-- built by load-then-migrate runs the same function as one synced from the load files.
--
-- REVERSIBLE: yes; the down file rebuilds the three B-trees, a full scan of each table, and the
-- two GiST indexes wherever the `geo` columns exist, and restores the function's previous body.
DROP INDEX IF EXISTS idx_verificationevent_geo;
DROP INDEX IF EXISTS idx_verificationevent_geo_time;
DROP INDEX IF EXISTS idx_tokenlifecycleevent_geo;
DROP INDEX IF EXISTS gix_verification_geo;
DROP INDEX IF EXISTS gix_lifecycle_geo;

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

    -- Optional session-level actor and reason. current_setting returns '' when the GUC is
    -- unset (with missing_ok = true). The row carries no location: the polaris.event_lat and
    -- event_lon settings it once read were set by nothing, and since lab/strategy/009 step 4c
    -- nothing shows a coordinate, so a session can no longer start a location trail here.
    v_actor  := NULLIF(current_setting('polaris.actor_agency_id', true), '')::INTEGER;
    v_reason := NULLIF(current_setting('polaris.reason_code',     true), '');

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
        token_id, actor_agency_id, event_type, reason_code, event_timestamp
    )
    VALUES (
        NEW.token_id, v_actor, v_event_type,
        COALESCE(v_reason, 'AUTO_AUDIT_TRIGGER'),
        CURRENT_TIMESTAMP
    );

    RETURN NEW;
END;
$$;
