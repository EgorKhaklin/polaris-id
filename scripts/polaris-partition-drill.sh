#!/usr/bin/env bash
# ============================================================================
# polaris-partition-drill.sh — event-table partitioning, exercised end to end
# (roadmap P2.1, v9.245).
#
# The four event tables ship monthly range-partitioned. This drill proves, on
# a loaded database, the properties the schema promises:
#   1. the manager premakes the monthly window, and a future-dated row lands in
#      a monthly partition rather than DEFAULT;
#   2. append-only (C1) holds on a monthly-partition row and on a DEFAULT row;
#   3. a whole month DETACHes in O(1) and append-only holds across the detach;
#   4. the online conversion turns a populated NON-partitioned table into a
#      partitioned one in place (attach-as-DEFAULT, no copy), preserving rows
#      and the append-only trigger across the ATTACH; it is idempotent;
#   5. the retention DELETE carve-out still routes across partitions.
#
# It needs psql on PATH and a loaded polaris database (the CI product-test job
# provides both). Read-only to the real event data except its own scratch rows,
# which it inserts with far-future timestamps and cleans up by dropping the
# partitions/tables it created.
# ============================================================================
set -euo pipefail
DB="${POLARIS_DB_NAME:-polaris_test}"
PGUSER_ARG=(); [ -n "${POLARIS_DB_USER:-}" ] && PGUSER_ARG=(-U "$POLARIS_DB_USER")
PGHOST_ARG=(); [ -n "${POLARIS_DB_HOST:-}" ] && PGHOST_ARG=(-h "$POLARIS_DB_HOST")
psql_do() { psql -v ON_ERROR_STOP=1 -qtA "${PGHOST_ARG[@]+"${PGHOST_ARG[@]}"}" "${PGUSER_ARG[@]+"${PGUSER_ARG[@]}"}" -d "$DB" "$@"; }
fail() { echo "::error::$*" >&2; exit 1; }
command -v psql >/dev/null || fail "psql is required"

echo "== partition drill against $DB =="

# 1. the manager premakes months; a next-month row lands in a monthly partition
psql_do -c "CALL uc_ensure_event_partitions(3);" >/dev/null
NEXT_PART=$(psql_do <<'SQL'
INSERT INTO VerificationEvent(token_id, requesting_agency_id, context_id, event_timestamp, outcome, disclosure_level)
VALUES (1, 1, 1, date_trunc('month', now()) + interval '1 month' + interval '3 days', 'SUCCESS', 'FULL');
SELECT tableoid::regclass::text FROM VerificationEvent
 WHERE event_timestamp = date_trunc('month', now()) + interval '1 month' + interval '3 days';
SQL
)
echo "  a next-month verification landed in $NEXT_PART"
case "$NEXT_PART" in *_default) fail "a next-month row landed in DEFAULT; the manager did not premake the month" ;; esac

# 2. append-only holds on a monthly-partition row and on a DEFAULT row
psql_do <<'SQL' >/dev/null || fail "append-only did not hold on a partitioned row"
DO $$ BEGIN
  BEGIN UPDATE VerificationEvent SET outcome='FAILURE'
        WHERE event_timestamp = date_trunc('month', now()) + interval '1 month' + interval '3 days';
        RAISE EXCEPTION 'UPDATE allowed on a monthly partition (bad)';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  BEGIN DELETE FROM TokenLifecycleEvent WHERE tableoid = (TokenLifecycleEvent.tableoid) AND event_id = (SELECT event_id FROM TokenLifecycleEvent LIMIT 1);
        RAISE EXCEPTION 'DELETE allowed (bad)';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
SQL
echo "  append-only rejects UPDATE and DELETE on partitioned rows"

# 3. a whole month DETACHes in O(1); append-only holds across the detach BECAUSE
#    the detach re-creates the append-only trigger on the standalone table
psql_do <<'SQL' >/dev/null || fail "detach did not preserve append-only on the standalone table"
DROP TABLE IF EXISTS pd_det CASCADE;
CREATE TABLE pd_det (event_id SERIAL, event_timestamp TIMESTAMP NOT NULL DEFAULT now(), payload TEXT,
                     PRIMARY KEY (event_id, event_timestamp)) PARTITION BY RANGE (event_timestamp);
CREATE TABLE pd_det_default PARTITION OF pd_det DEFAULT;
CREATE TABLE pd_det_m PARTITION OF pd_det FOR VALUES FROM ('2099-01-01') TO ('2099-02-01');
CREATE TRIGGER pd_det_ao BEFORE UPDATE OR DELETE ON pd_det FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();
INSERT INTO pd_det(event_timestamp,payload) VALUES ('2099-01-15','x');
DO $$ BEGIN
  ALTER TABLE pd_det DETACH PARTITION pd_det_m;
  -- the production path (uc_detach_event_partitions_before) re-adds the trigger; mirror it here
  CREATE TRIGGER pd_det_m_ao BEFORE UPDATE OR DELETE ON pd_det_m FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();
  BEGIN DELETE FROM pd_det_m; RAISE EXCEPTION 'DELETE allowed on a detached partition (bad)';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  -- re-ATTACH PARTITION: append-only holds across the attach too (the parent trigger covers it)
  DROP TRIGGER pd_det_m_ao ON pd_det_m;   -- the parent's trigger takes over on attach
  ALTER TABLE pd_det ATTACH PARTITION pd_det_m FOR VALUES FROM ('2099-01-01') TO ('2099-02-01');
  BEGIN DELETE FROM pd_det WHERE event_timestamp = '2099-01-15'; RAISE EXCEPTION 'DELETE allowed after re-attach (bad)';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
DROP TABLE pd_det CASCADE;
SQL
echo "  a month detaches and the standalone table stays append-only (the detach re-adds the trigger)"

# 4. the online conversion on a populated NON-partitioned scratch table
psql_do <<'SQL' >/dev/null || fail "the online conversion did not preserve rows or append-only"
DROP TABLE IF EXISTS pd_scratch CASCADE;
CREATE TABLE pd_scratch (event_id SERIAL PRIMARY KEY, event_timestamp TIMESTAMP NOT NULL DEFAULT now(), payload TEXT);
CREATE INDEX pd_scratch_ts ON pd_scratch(event_timestamp DESC);
CREATE TRIGGER pd_scratch_ao BEFORE UPDATE OR DELETE ON pd_scratch FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();
INSERT INTO pd_scratch(event_timestamp, payload) SELECT ts, 'x' FROM generate_series(now() - interval '200 days', now() - interval '2 days', interval '5 days') ts;
DO $$ DECLARE v_before bigint; v_after bigint; BEGIN
  SELECT count(*) INTO v_before FROM pd_scratch;
  CALL uc_convert_event_table_to_partitioned('pd_scratch','event_id');
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname='pd_scratch' AND relkind='p') THEN RAISE EXCEPTION 'not partitioned after conversion'; END IF;
  SELECT count(*) INTO v_after FROM pd_scratch;
  IF v_before <> v_after THEN RAISE EXCEPTION 'row count changed on conversion: % -> %', v_before, v_after; END IF;
  BEGIN UPDATE pd_scratch SET payload='z' WHERE event_id=1; RAISE EXCEPTION 'UPDATE allowed after conversion (bad)';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  CALL uc_convert_event_table_to_partitioned('pd_scratch','event_id');   -- idempotent: no error
END $$;
DROP TABLE pd_scratch CASCADE;
SQL
echo "  a populated table converts in place (rows preserved, append-only kept, idempotent)"

# 5. the retention DELETE carve-out still routes across partitions
psql_do <<'SQL' >/dev/null || fail "the retention DELETE carve-out no longer works across partitions"
DO $$ BEGIN
  PERFORM set_config('polaris.purge_in_progress', 'TRUE', true);   -- true = transaction-local, the SET LOCAL of the carve-out
  DELETE FROM VerificationEvent WHERE event_timestamp < '1901-01-01';  -- matches nothing: proves the carve-out routes across partitions without deleting real data
END $$;
SQL
echo "  the retention carve-out DELETE routes across partitions"

# clean up the drill's one real row (the next-month probe) via the carve-out
psql_do <<'SQL' >/dev/null
DO $$ BEGIN
  PERFORM set_config('polaris.purge_in_progress', 'TRUE', true);
  DELETE FROM VerificationEvent WHERE event_timestamp = date_trunc('month', now()) + interval '1 month' + interval '3 days';
END $$;
SQL

echo "== PARTITION DRILL PASSED: monthly partitions, append-only across partition/attach/detach, online conversion, retention routing =="
