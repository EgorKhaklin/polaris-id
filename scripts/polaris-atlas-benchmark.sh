#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
# ============================================================================
# polaris-atlas-benchmark.sh: prove the Atlas holds at millions of events.
#
# Builds a throwaway database, loads the schema, generates N synthetic
# verification events spread over the last 160 days, folds the activity
# rollups as the purge schedule does, and times the Atlas readers the console
# calls: the headline, the series, a breakdown, a cross-tab, the heatmap, the
# stacked series and the regions.
#
# The point it demonstrates (lab/strategy/009, step 4): no reader reads an
# event table. Each sums the activity rollups, whose rows number the hours a
# window spans times the authorities, contexts, outcomes, disclosure levels
# and algorithms active in them, so a reader costs the same at five million
# events as at five billion. See docs/reference/SCALING.md for recorded
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

echo "-- Polaris Atlas scale benchmark --"
echo "  events: $N   db: $DB"

dropdb --if-exists "$DB" >/dev/null 2>&1 || true
createdb "$DB"
# 00_load_all.sql includes its files by relative path, so it runs from their directory.
(cd "$SQL_DIR" && psql -d "$DB" -q -v ON_ERROR_STOP=1 -f 00_load_all.sql >/dev/null)
echo "  schema loaded"

echo "  generating $N events..."
psql -d "$DB" -q -v ON_ERROR_STOP=1 <<SQL
INSERT INTO VerificationEvent
    (token_id, requesting_agency_id, context_id, event_timestamp, outcome,
     disclosure_level, requestor_location)
SELECT 2, 1 + (g % 6), 1 + (g % 7),
    LOCALTIMESTAMP - random() * INTERVAL '160 days',
    (ARRAY['SUCCESS','SUCCESS','SUCCESS','SUCCESS','FAILURE'])[1 + floor(random()*5)],
    (ARRAY['SELECTIVE','SELECTIVE','SELECTIVE','FULL'])[1 + floor(random()*4)],
    'gen'
FROM generate_series(1, $N) AS g;
SQL
psql -d "$DB" -q -v ON_ERROR_STOP=1 -c "SELECT uc_fold_activity_rollups();" >/dev/null
psql -d "$DB" -q -c "ANALYZE VerificationEvent; ANALYZE VerificationRollup; ANALYZE VerificationRollupDaily;"
echo "  total events: $(psql -d "$DB" -tA -c 'SELECT count(*) FROM VerificationEvent;')"
echo "  hourly rollup rows: $(psql -d "$DB" -tA -c 'SELECT count(*) FROM VerificationRollup;')"

echo
echo "-- query latency --"
psql -d "$DB" <<'SQL'
\timing on
\echo '[1] headline, every day recorded'
SELECT count(*) FROM atlas_stats(NULL, TRUE);
\echo '[2] series, the last 7 days in 4-hour buckets'
SELECT count(*) FROM atlas_volume_series(date_trunc('hour', LOCALTIMESTAMP) - INTERVAL '7 days', FALSE, INTERVAL '4 hours');
\echo '[3] breakdown by authority, every day recorded'
SELECT count(*) FROM atlas_breakdown('agency', NULL, TRUE, 50);
\echo '[4] cross-tab authority by outcome, the last 7 days'
SELECT count(*) FROM atlas_crosstab('agency', 'outcome', date_trunc('hour', LOCALTIMESTAMP) - INTERVAL '7 days', FALSE, 50);
\echo '[5] heatmap, the last 30 days of hours (the heaviest: it reads hours, not days)'
SELECT count(*) FROM atlas_heatmap(date_trunc('day', LOCALTIMESTAMP) - INTERVAL '30 days');
\echo '[6] stacked series by context, the last 7 days'
SELECT count(*) FROM atlas_series_stacked(date_trunc('hour', LOCALTIMESTAMP) - INTERVAL '7 days', FALSE, INTERVAL '4 hours', 'context');
\echo '[7] regions, every day recorded'
SELECT count(*) FROM atlas_geo_jurisdictions(NULL, TRUE, 500);
SQL

if [ "${KEEP_DB:-0}" != "1" ]; then
    dropdb --if-exists "$DB" >/dev/null 2>&1 || true
    echo
    echo "  dropped $DB (set KEEP_DB=1 to retain)"
fi
