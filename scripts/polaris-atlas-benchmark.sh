#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-atlas-benchmark.sh — prove the Atlas holds at millions of events.
#
# Builds a throwaway database, loads the schema, generates N synthetic
# verification events with a realistic spatial spread, and times the atlas
# aggregation functions the live map calls per viewport:
#
#   - zoomed-in (street/regional bbox) — the operator's common case
#   - whole-world overview            — the heaviest aggregation
#   - a materialized grid rollup      — the whole-world remedy at scale
#
# The point it demonstrates: zoomed queries are index-served and bbox-bounded,
# so they stay in the millisecond range regardless of ledger size; the
# whole-world overview is a full aggregation that a pre-computed rollup
# collapses to sub-millisecond. See docs/reference/SCALING.md for recorded
# numbers.
#
# Usage:  scripts/polaris-atlas-benchmark.sh [N_EVENTS] [DB_NAME]
#   N_EVENTS  default 5000000
#   DB_NAME   default polaris_scale  (created and dropped unless KEEP_DB=1)
#
# Env: standard psql connection vars (PGHOST/PGUSER/...) or local defaults.
# ============================================================================
set -euo pipefail

N="${1:-5000000}"
DB="${2:-polaris_scale}"
SQL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../polaris_sql" && pwd)"

echo "── Polaris Atlas scale benchmark ──"
echo "  events: $N   db: $DB"

dropdb --if-exists "$DB" >/dev/null 2>&1 || true
createdb "$DB"
psql -d "$DB" -q -v ON_ERROR_STOP=1 -f "$SQL_DIR/00_load_all.sql" >/dev/null
echo "  schema loaded"

echo "  generating $N events…"
psql -d "$DB" -q -v ON_ERROR_STOP=1 <<SQL
INSERT INTO VerificationEvent
    (token_id, requesting_agency_id, context_id, event_timestamp, outcome,
     disclosure_level, latitude, longitude, requestor_location)
SELECT 2, 1 + (g % 6), 1 + (g % 7),
    TIMESTAMP '2026-01-01' + (floor(random()*160)::int) * INTERVAL '1 day',
    (ARRAY['SUCCESS','SUCCESS','SUCCESS','SUCCESS','FAILURE'])[1 + floor(random()*5)],
    (ARRAY['SELECTIVE','SELECTIVE','SELECTIVE','FULL'])[1 + floor(random()*4)],
    CASE WHEN random() < 0.9 THEN 25 + random()*24 ELSE  -55 + random()*125 END,
    CASE WHEN random() < 0.9 THEN -125 + random()*58 ELSE -180 + random()*360 END,
    'gen'
FROM generate_series(1, $N) AS g;
SQL
psql -d "$DB" -q -c "ANALYZE VerificationEvent;"
echo "  total events: $(psql -d "$DB" -tA -c 'SELECT count(*) FROM VerificationEvent;')"

echo
echo "── query latency ──"
psql -d "$DB" <<'SQL'
\timing on
\echo '[1] street bbox points (limit 500) — operator zoomed in'
SELECT count(*) FROM atlas_points_verifications(29.7,-95.4,29.8,-95.3, 500, NULL,NULL,NULL,NULL,NULL);
\echo '[2] regional clusters (CONUS bbox, grid 1)'
SELECT count(*) FROM atlas_clusters_verifications(25,-125,49,-67, 1, NULL,NULL,NULL,NULL,NULL);
\echo '[3] whole-world clusters (grid 10) — heaviest, full aggregation'
SELECT count(*) FROM atlas_clusters_verifications(-89.9,-179.9,89.9,179.9, 10, NULL,NULL,NULL,NULL,NULL);
\echo '[4] materialized grid rollup: build once…'
CREATE MATERIALIZED VIEW atlas_rollup_demo AS
  SELECT floor(latitude/10) AS cy, floor(longitude/10) AS cx,
         avg(latitude) AS lat, avg(longitude) AS lon, count(*) AS n_total
  FROM VerificationEvent
  WHERE disclosure_level <> 'ZERO_KNOWLEDGE' AND latitude IS NOT NULL
  GROUP BY 1,2;
\echo '    …then whole-world read FROM the rollup (refreshed on a schedule, not per request)'
SELECT count(*) FROM atlas_rollup_demo;
SQL

if [ "${KEEP_DB:-0}" != "1" ]; then
    dropdb --if-exists "$DB" >/dev/null 2>&1 || true
    echo
    echo "  dropped $DB (set KEEP_DB=1 to retain)"
fi
