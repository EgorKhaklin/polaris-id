-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Egor Khaklin and the Polaris contributors
-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 00_load_all.sql : Master loader
--
-- Loads all files in the correct order, producing a fully populated
-- and validated database in one command:
--
--   psql -d polaris_test -f 00_load_all.sql
--
-- Each file is idempotent (DROP IF EXISTS before CREATE), so this script
-- can be re-run any number of times against an existing database.
--
-- PREREQUISITE: run as a superuser.
-- This file sources 12_v7_constraints.sql, which creates triggers, an index
-- and a view in the public schema. The polaris_app role has no DDL privileges
-- by design (see the comment block in 09_grants.sql), so loading as that role
-- leaves a database that looks loaded and is missing the cross-individual
-- succession trigger, the revocation-status trigger, the composite index and
-- the TokensWithLifecycleSummary view, with no error to say so.
--
-- Always load as the macOS default superuser (`vanta` on dev) or the
-- Postgres superuser (`postgres` on Linux/Docker):
--
--   psql -d polaris_test -f 00_load_all.sql       # inherits OS user
--   su postgres -c "psql -d polaris_test -f ..."  # Linux/Docker pattern
--
-- DO NOT load as polaris_app (e.g., via PGUSER=polaris_app). The
-- application role connects to the loaded database; it does not load it.
--
-- Output: a fully working schema with 73 sample rows, plus 36 test results
-- printed at the end. A clean run shows "Total: 36 tests, 36 passed, 0 failed".
-- ============================================================================

-- The numeric prefixes are file identifiers, not a load order. The sequence of
-- \i below is authoritative, and it deviates from the numbers in three places:
-- 11_atlas.sql loads before 09_grants.sql because the grants cover its
-- functions; 09_grants.sql is sourced twice, the second time to cover the
-- tables 10_auth.sql creates; and 12_v7_constraints.sql loads after the tests
-- because it hardens a schema the tests have already exercised.

\timing on
\set ECHO queries

\echo Loading 00_migrations_table.sql (the migration registry)...
\i 00_migrations_table.sql

\echo Loading 01_schema.sql...
\i 01_schema.sql

\echo Loading 02_indexes.sql...
\i 02_indexes.sql

\echo Loading 03_view.sql...
\i 03_view.sql

\echo Loading 04_data.sql...
\i 04_data.sql

\echo Loading 05_procedures.sql...
\i 05_procedures.sql

\echo Loading 06_triggers.sql...
\i 06_triggers.sql

\echo Loading 11_atlas.sql (spatial aggregation functions)...
\i 11_atlas.sql

\echo Loading 09_grants.sql...
\i 09_grants.sql

\echo Loading 10_auth.sql...
\i 10_auth.sql

\echo Re-applying grants (covers the new auth tables)...
\i 09_grants.sql

\echo Running 07_queries.sql (output displayed below)...
\i 07_queries.sql

\echo Running 08_tests.sql...
\i 08_tests.sql

\echo Loading 12_v7_constraints.sql (the v7 hardening triggers, index and view)...
\i 12_v7_constraints.sql

\echo Loading 13_substrate.sql (the substrate-dependency manifest)...
\i 13_substrate.sql

\echo Loading 13_postgis.sql (optional PostGIS migration; a no-op without postgis)...
\i 13_postgis.sql

\echo Loading 14_foresight_helpers.sql (three SQL helper functions)...
\i 14_foresight_helpers.sql

\echo Loading 15_ontology.sql (single-entity semantic views over the schema)...
\i 15_ontology.sql

\echo Loading 16_athena.sql (authority-and-constitution layer)...
\i 16_athena.sql

\echo
\echo ============================================================================
\echo ALL FILES LOADED. The test summary above is from 08_tests.sql; the files
\echo sourced after it (12_v7_constraints.sql and 13_substrate.sql) print their
\echo own assertions below that summary, so read to the end.
\echo ============================================================================
