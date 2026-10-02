-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Egor Khaklin and the Polaris contributors
-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 13_postgis.sql : the optional PostGIS path, withdrawn (R8-4; lab/strategy/009 step 4c)
-- ============================================================================
--
-- v8.88 (proposals/R8-4-postgis-migration.md) created the postgis extension where it could and
-- added a generated geography column, `geo`, to VerificationEvent and TokenLifecycleEvent with a
-- GiST index on each, for the Atlas's bounding-box layers at 10M+ events.
--
-- lab/strategy/009 withdrew every use of it. Since step 4 the Atlas reads no location: it sums
-- the activity rollups, which hold none. Step 4c stopped the last writer of a coordinate and
-- dropped every index on one; migration 2026-10-02-005 drops the two GiST indexes wherever they
-- were built. So this file creates nothing. A spatial extension and columns that are NULL on
-- every row Polaris writes would add attack surface and serve no query.
--
-- It reports what a database built by an earlier release still carries. The contract step that
-- drops latitude and longitude drops those `geo` columns, and this file, with them.
-- ============================================================================

DO $postgis_withdrawn$
DECLARE
    v_geo_tables TEXT;
BEGIN
    SELECT string_agg(table_name::TEXT, ', ' ORDER BY table_name) INTO v_geo_tables
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name IN ('verificationevent', 'tokenlifecycleevent')
       AND column_name = 'geo';

    IF v_geo_tables IS NULL THEN
        RAISE NOTICE '13_postgis.sql: withdrawn (lab/strategy/009 step 4c); nothing to create.';
    ELSE
        RAISE NOTICE '13_postgis.sql: withdrawn (lab/strategy/009 step 4c). % keep the generated '
                     'geo column an earlier release added, unindexed and NULL on every row Polaris now writes, '
                     'until the contract step drops it with latitude and longitude.', v_geo_tables;
    END IF;
END $postgis_withdrawn$;
