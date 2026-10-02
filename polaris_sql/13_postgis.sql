-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Egor Khaklin and the Polaris contributors
-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 13_postgis.sql : Optional PostGIS migration for atlas spatial queries (R8-4)
-- ============================================================================
--
-- v8.88 / Architect+HYDRA Top-4 — proposed in proposals/R8-4-postgis-migration.md.
-- VANTA in-chat 2026-05-14: "proceed with the next one" (i.e., R8-4).
--
-- AT SCALE (10M+ events) the composite B-tree on (latitude, longitude) is
-- the bottleneck for atlas bbox + cluster queries. PostGIS's GiST index
-- over a geography(Point, 4326) column materially outperforms B-tree
-- here. The proposal calls for ≥3× improvement at 10M+ events.
--
-- This file is OPTIONAL by design:
--
--   - If the postgis extension is available AND can be created, this
--     file adds a generated `geo` column to VerificationEvent +
--     TokenLifecycleEvent and indexes them with GiST.
--
--   - If postgis is unavailable (no extension installed, or current role
--     lacks superuser to install it), this file is a no-op and emits a
--     NOTICE. The schema continues to work via the existing B-tree
--     indexes on (latitude, longitude).
--
-- The optional-dependency design lets Polaris deploy on managed Postgres
-- tiers that don't bundle PostGIS (some providers gate it behind paid
-- tiers) without forcing operators to choose between "PostGIS or
-- nothing."
--
-- v8.88 SCOPE: schema foundation only. The Atlas's located layers were never rewritten to use
-- the GiST index, and since lab/strategy/009 (steps A0 and 4) the Atlas reads no location at
-- all: it sums the activity rollups, which hold none. The columns and the index serve an
-- operator who queries locations directly, such as an investigation under warrant.
-- ============================================================================

DO $postgis_setup$
DECLARE
    v_postgis_available BOOLEAN;
    v_postgis_installed BOOLEAN;
    v_ve_geo_present    BOOLEAN;
    v_tle_geo_present   BOOLEAN;
BEGIN
    -- 1. Detect availability without trying CREATE EXTENSION (avoids
    --    permission-denied noise when the role isn't superuser).
    SELECT EXISTS (
        SELECT 1 FROM pg_available_extensions WHERE name = 'postgis'
    ) INTO v_postgis_available;

    IF NOT v_postgis_available THEN
        RAISE NOTICE
            '13_postgis.sql: PostGIS extension not available on this server. '
            'Schema is using the existing (latitude, longitude) B-tree '
            'indexes. To enable the GiST-backed spatial path at scale, '
            'install the postgis extension on the Postgres server, then '
            're-run 00_load_all.sql.';
        RETURN;
    END IF;

    -- 2. Try to create the extension. If we lack permission, fall back
    --    gracefully.
    SELECT EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'postgis'
    ) INTO v_postgis_installed;

    IF NOT v_postgis_installed THEN
        BEGIN
            CREATE EXTENSION postgis;
            v_postgis_installed := TRUE;
        EXCEPTION WHEN insufficient_privilege OR OTHERS THEN
            RAISE NOTICE
                '13_postgis.sql: PostGIS is available but cannot be created '
                'by the current role (%). Ask a superuser to run '
                '"CREATE EXTENSION postgis;" once, then re-run this script.',
                SQLERRM;
            RETURN;
        END;
    END IF;

    RAISE NOTICE '13_postgis.sql: PostGIS extension active; adding geo columns + GiST indexes.';

    -- 3. VerificationEvent: add geo column + GiST index (idempotent).
    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name   = 'verificationevent'
          AND column_name  = 'geo'
    ) INTO v_ve_geo_present;

    IF NOT v_ve_geo_present THEN
        EXECUTE $sql$
            ALTER TABLE VerificationEvent
                ADD COLUMN geo geography(Point, 4326)
                GENERATED ALWAYS AS (
                    CASE
                        WHEN latitude IS NOT NULL AND longitude IS NOT NULL
                        THEN ST_SetSRID(
                                ST_MakePoint(longitude, latitude),
                                4326
                             )::geography
                        ELSE NULL
                    END
                ) STORED
        $sql$;
        RAISE NOTICE '13_postgis.sql: added VerificationEvent.geo column.';
    END IF;

    EXECUTE $sql$
        CREATE INDEX IF NOT EXISTS gix_verification_geo
            ON VerificationEvent USING GIST (geo)
            WHERE geo IS NOT NULL
    $sql$;

    -- 4. TokenLifecycleEvent: same shape (it also carries latitude /
    --    longitude per atlas-design).
    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name   = 'tokenlifecycleevent'
          AND column_name  = 'geo'
    ) INTO v_tle_geo_present;

    IF NOT v_tle_geo_present THEN
        EXECUTE $sql$
            ALTER TABLE TokenLifecycleEvent
                ADD COLUMN geo geography(Point, 4326)
                GENERATED ALWAYS AS (
                    CASE
                        WHEN latitude IS NOT NULL AND longitude IS NOT NULL
                        THEN ST_SetSRID(
                                ST_MakePoint(longitude, latitude),
                                4326
                             )::geography
                        ELSE NULL
                    END
                ) STORED
        $sql$;
        RAISE NOTICE '13_postgis.sql: added TokenLifecycleEvent.geo column.';
    END IF;

    EXECUTE $sql$
        CREATE INDEX IF NOT EXISTS gix_lifecycle_geo
            ON TokenLifecycleEvent USING GIST (geo)
            WHERE geo IS NOT NULL
    $sql$;

    RAISE NOTICE '13_postgis.sql: setup complete. Atlas functions can be '
                 'rewritten in a v8.x follow-up to use the GiST path.';
END $postgis_setup$;

-- ============================================================================
-- Operator notes:
--
--  - Check what mode the schema is in:
--      SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='postgis') AS postgis_loaded;
--
--  - Once PostGIS is active, a sample GiST-aware atlas query (operator
--    can run this directly; the application-layer functions still use
--    the B-tree path until the v8.x follow-up rewrites them):
--      SELECT * FROM VerificationEvent
--      WHERE geo IS NOT NULL
--        AND ST_DWithin(
--                geo,
--                ST_SetSRID(ST_MakePoint(-79.9959, 40.4406), 4326)::geography,
--                50000   -- 50km radius around Pittsburgh
--            );
--
--  - docs/design/atlas-scaling.md documents the design trade-off.
--  - Acceptance criterion (≥3× improvement at 10M+ events) is verified
--    in a v8.x follow-up — requires a real PostGIS server + a 10M-row
--    stress dataset (the v8.80 polaris-load-test.sh scaffold can help
--    here).
-- ============================================================================
