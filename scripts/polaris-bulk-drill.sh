#!/usr/bin/env bash
# ============================================================================
# polaris-bulk-drill.sh — bulk enrollment, exercised end to end
# (roadmap P2.4, v9.247).
#
# Onboarding an authority's existing population one IdentityToken at a time is
# millions of round trips through uc1_issue_and_activate. The bulk path stages
# the records with COPY and issues them SET-BASED in one transaction through
# uc_bulk_issue. This drill proves, on a loaded database, the properties that
# path promises:
#   1. THROUGHPUT + CORRECTNESS: a real COPY of N records into staging, then
#      one uc_bulk_issue, mints N ACTIVE tokens, each signed, each with an
#      ISSUED and an ACTIVATED lifecycle event. The set-based issuance rate is
#      measured and floored (a catastrophic-regression guard, not a benchmark).
#   2. ATOMICITY: a batch with a single duplicate physical_serial issues NONE
#      of its rows: the whole batch rolls back (all rows are issued, or none).
#   3. C3 ACROSS THE BATCH: two staged rows correlated to one person violate
#      uq_one_active_per_person (C3) at activation and roll the whole batch
#      back. C3 is enforced on bulk output exactly as on single issuance.
#   4. ALREADY-ISSUED: re-issuing a batch that already issued is refused.
#   5. AUTHORIZATION: a batch under an agency that lacks ISSUE on the algorithm
#      is refused (the same AgencyAlgorithmAuth gate uc1 applies), issuing none.
#   6. EMPTY BATCH: a batch with no staged rows is refused.
#
# Every test runs inside a transaction that is ROLLED BACK, so the drill mints
# no persistent tokens (their append-only lifecycle events, C1, could not be
# deleted afterward) and is safe to re-run locally. It needs psql on PATH and a
# loaded polaris database (the CI product-test job provides both).
# ============================================================================
set -euo pipefail
DB="${POLARIS_DB_NAME:-polaris_test}"
ROWS="${POLARIS_BULK_DRILL_ROWS:-5000}"
FLOOR="${POLARIS_BULK_DRILL_FLOOR:-200}"   # rows/s; conservative for shared CI runners
PGUSER_ARG=(); [ -n "${POLARIS_DB_USER:-}" ] && PGUSER_ARG=(-U "$POLARIS_DB_USER")
PGHOST_ARG=(); [ -n "${POLARIS_DB_HOST:-}" ] && PGHOST_ARG=(-h "$POLARIS_DB_HOST")
psql_do() { psql -v ON_ERROR_STOP=1 -qtA "${PGHOST_ARG[@]+"${PGHOST_ARG[@]}"}" "${PGUSER_ARG[@]+"${PGUSER_ARG[@]}"}" -d "$DB" "$@"; }
fail() { echo "::error::$*" >&2; exit 1; }
command -v psql >/dev/null || fail "psql is required"
command -v python3 >/dev/null || fail "python3 is required to synthesize the extract"

echo "== bulk drill against $DB ($ROWS rows, floor ${FLOOR} rows/s) =="

# A batch-agnostic extract: exactly what a source authority hands over (name,
# DOB, jurisdiction, biometric type, the token value + physical serial of the
# blank credential, and the contexts it may verify in). The operator stages it
# and attaches it to a batch; individual_id is left to uc_bulk_issue.
CSV="$(mktemp -t polaris-bulk.XXXXXX.csv)"
trap 'rm -f "$CSV"' EXIT
python3 - "$ROWS" "$CSV" <<'PY'
import sys, hashlib
n = int(sys.argv[1]); path = sys.argv[2]
with open(path, "w") as f:
    for g in range(1, n + 1):
        tok = f"BULKDRILL-TOK-{g}"
        # v9.257: bulk issuance stores a REAL signature the caller staged.
        # In the default config that is the deterministic sha3-256 of token_value
        # (exactly what pqc_signing.signature_with_key_for_token returns when
        # POLARIS_USE_REAL_PQC is unset), with a NULL public key. uc_bulk_issue
        # refuses an unsigned row, so a placeholder LITERAL can never reach it.
        sig = hashlib.sha3_256(tok.encode()).hexdigest()
        # name|dob|juris|biometric|token|serial|contexts|signature(bytea \x..)|pubkey(NULL)
        f.write(f"Bulk Enrollee {g}|1990-01-01|US-PA|FINGERPRINT|{tok}|BULKDRILL-SER-{g}|{{}}|\\x{sig}|\n")
PY

# ---------------------------------------------------------------------------
# 1. THROUGHPUT + CORRECTNESS. Stage via COPY (the real ingest), then one
#    uc_bulk_issue; assert every row landed ACTIVE, signed, and event-logged;
#    report the set-based rate. Rolled back, nothing persists.
# ---------------------------------------------------------------------------
set +e
OUT="$(sed "s|__CSV__|$CSV|g" <<'SQL' | psql -v ON_ERROR_STOP=1 -q "${PGHOST_ARG[@]+"${PGHOST_ARG[@]}"}" "${PGUSER_ARG[@]+"${PGUSER_ARG[@]}"}" -d "$DB" 2>&1
BEGIN;
INSERT INTO BulkEnrollmentBatch (issuing_agency_id, algorithm_id, note)
  VALUES (1, 1, 'bulkdrill-perf') RETURNING batch_id \gset
CREATE TEMP TABLE bulk_in (legal_name text, date_of_birth date, jurisdiction text,
  biometric_binding_type text, token_value text, physical_serial text, permitted_contexts int[],
  signature_bytes bytea, signing_public_key_hex text);
\copy bulk_in FROM '__CSV__' WITH (FORMAT csv, DELIMITER '|')
INSERT INTO BulkEnrollmentStaging
  (batch_id, legal_name, date_of_birth, jurisdiction, biometric_binding_type, token_value, physical_serial, permitted_contexts, signature_bytes, signing_public_key_hex)
  SELECT :batch_id, legal_name, date_of_birth, jurisdiction, biometric_binding_type, token_value, physical_serial, permitted_contexts, signature_bytes, signing_public_key_hex
    FROM bulk_in;
DO $$
DECLARE v_b int; t0 timestamptz; secs float8; n int; a int; sg int; ev int; iss int;
BEGIN
  SELECT batch_id INTO v_b FROM BulkEnrollmentBatch WHERE note = 'bulkdrill-perf';
  t0 := clock_timestamp();
  CALL uc_bulk_issue(v_b, n);
  secs := extract(epoch FROM clock_timestamp() - t0);
  SELECT count(*) INTO a  FROM IdentityToken   WHERE token_value LIKE 'BULKDRILL-TOK-%' AND status = 'ACTIVE';
  SELECT count(*) INTO sg FROM TokenSignature ts JOIN IdentityToken t USING (token_id)
                          WHERE t.token_value LIKE 'BULKDRILL-TOK-%';
  SELECT count(*) INTO ev FROM TokenLifecycleEvent e JOIN IdentityToken t USING (token_id)
                          WHERE t.token_value LIKE 'BULKDRILL-TOK-%' AND e.event_type = 'ACTIVATED';
  SELECT count(*) INTO iss FROM TokenLifecycleEvent e JOIN IdentityToken t USING (token_id)
                          WHERE t.token_value LIKE 'BULKDRILL-TOK-%' AND e.event_type = 'ISSUED';
  IF a <> n OR sg <> n OR ev <> n OR iss <> n THEN
    RAISE EXCEPTION 'DRILL FAIL: staged n=% but active=% signed=% issued=% activated=%', n, a, sg, iss, ev;
  END IF;
  RAISE NOTICE 'BULK_THROUGHPUT rows=% secs=% rate=%', n, round(secs::numeric, 3),
    CASE WHEN secs > 0 THEN round((n / secs)::numeric) ELSE 0 END;
END $$;
ROLLBACK;
SQL
)"
RC=$?
set -e
[ $RC -eq 0 ] || fail "throughput block errored (rc=$RC): $OUT"
echo "$OUT" | grep -q 'BULK_THROUGHPUT' || fail "throughput block did not report; output: $OUT"
LINE="$(echo "$OUT" | sed -n 's/.*\(BULK_THROUGHPUT[^\\]*\).*/\1/p' | head -1)"
RATE="$(echo "$LINE" | sed -n 's/.*rate=\([0-9]*\).*/\1/p')"
NROWS="$(echo "$LINE" | sed -n 's/.*rows=\([0-9]*\).*/\1/p')"
SECS="$(echo "$LINE" | sed -n 's/.*secs=\([0-9.]*\).*/\1/p')"
[ -n "$RATE" ] || fail "could not parse the issuance rate from: $LINE"
echo "  $NROWS records staged by COPY, issued set-based in ${SECS}s = ${RATE} rows/s; all ACTIVE, signed, ISSUED+ACTIVATED"
if [ "$RATE" -lt "$FLOOR" ]; then fail "set-based issuance ${RATE} rows/s is below the ${FLOOR} rows/s floor"; fi
echo "  throughput ${RATE} rows/s clears the ${FLOOR} rows/s regression floor"

# ---------------------------------------------------------------------------
# 2-6. The refusals and the invariant, each self-contained and rolled back.
#      Each stages a small batch, calls uc_bulk_issue inside a subtransaction,
#      and asserts the EXACT failure (or, for C3, that the batch rolls back);
#      a regression that lets the batch through raises DRILL FAIL and the
#      ON_ERROR_STOP psql exits non-zero.
# ---------------------------------------------------------------------------
set +e
INV="$(psql -v ON_ERROR_STOP=1 -q "${PGHOST_ARG[@]+"${PGHOST_ARG[@]}"}" "${PGUSER_ARG[@]+"${PGUSER_ARG[@]}"}" -d "$DB" 2>&1 <<'SQL'
-- 2. ATOMICITY: one duplicate physical_serial rolls the whole batch back.
BEGIN;
DO $$
DECLARE v_b int; v_n int;
BEGIN
  INSERT INTO BulkEnrollmentBatch (issuing_agency_id, algorithm_id, note) VALUES (1, 1, 'atomic') RETURNING batch_id INTO v_b;
  INSERT INTO BulkEnrollmentStaging (batch_id, legal_name, date_of_birth, jurisdiction, biometric_binding_type, token_value, physical_serial, permitted_contexts, signature_bytes, signing_public_key_hex)
  SELECT v_b, 'Atom '||g, '1990-01-01', 'US-PA', 'FINGERPRINT', 'ATOMD-TOK-'||g,
         CASE WHEN g = 4 THEN 'ATOMD-SER-3' ELSE 'ATOMD-SER-'||g END,  -- row 4 collides with row 3
         '{}', '\x00'::bytea, NULL   -- a non-null stand-in; this test exercises atomicity and rolls back
    FROM generate_series(1, 6) g;
  BEGIN
    CALL uc_bulk_issue(v_b, v_n);
    RAISE EXCEPTION 'DRILL FAIL: a batch with a duplicate physical_serial was issued';
  EXCEPTION WHEN unique_violation THEN
    IF EXISTS (SELECT 1 FROM IdentityToken WHERE token_value LIKE 'ATOMD-TOK-%') THEN
      RAISE EXCEPTION 'DRILL FAIL: atomicity broken, some rows survived a failed batch';
    END IF;
    RAISE NOTICE 'OK: atomicity, a duplicate serial rolled the whole batch back (%)', SQLSTATE;
  END;
END $$;
ROLLBACK;

-- 3. C3 ACROSS THE BATCH: two rows correlated to one person violate C3 at activation.
BEGIN;
DO $$
DECLARE v_b int; v_i int; v_n int;
BEGIN
  INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) VALUES ('C3 Target', '1985-05-05', 'US-CA') RETURNING individual_id INTO v_i;
  INSERT INTO BulkEnrollmentBatch (issuing_agency_id, algorithm_id, note) VALUES (1, 1, 'c3') RETURNING batch_id INTO v_b;
  INSERT INTO BulkEnrollmentStaging (batch_id, legal_name, date_of_birth, jurisdiction, biometric_binding_type, token_value, physical_serial, permitted_contexts, individual_id, signature_bytes, signing_public_key_hex)
  VALUES (v_b, 'C3 Target', '1985-05-05', 'US-CA', 'FINGERPRINT', 'C3D-TOK-A', 'C3D-SER-A', '{}', v_i, '\x00'::bytea, NULL),
         (v_b, 'C3 Target', '1985-05-05', 'US-CA', 'FINGERPRINT', 'C3D-TOK-B', 'C3D-SER-B', '{}', v_i, '\x00'::bytea, NULL);
  BEGIN
    CALL uc_bulk_issue(v_b, v_n);
    RAISE EXCEPTION 'DRILL FAIL: two active tokens for one person were issued (C3 breached)';
  EXCEPTION WHEN unique_violation THEN
    IF EXISTS (SELECT 1 FROM IdentityToken WHERE token_value LIKE 'C3D-TOK-%') THEN
      RAISE EXCEPTION 'DRILL FAIL: C3 breach left tokens behind';
    END IF;
    RAISE NOTICE 'OK: C3, two staged rows for one person rolled the whole batch back (%)', SQLSTATE;
  END;
END $$;
ROLLBACK;

-- 4. ALREADY-ISSUED: a second issue of the same batch is refused.
BEGIN;
DO $$
DECLARE v_b int; v_n int;
BEGIN
  INSERT INTO BulkEnrollmentBatch (issuing_agency_id, algorithm_id, note) VALUES (1, 1, 'twice') RETURNING batch_id INTO v_b;
  INSERT INTO BulkEnrollmentStaging (batch_id, legal_name, date_of_birth, jurisdiction, biometric_binding_type, token_value, physical_serial, permitted_contexts, signature_bytes, signing_public_key_hex)
  VALUES (v_b, 'Twice', '1990-01-01', 'US-PA', 'FINGERPRINT', 'TWICE-TOK-1', 'TWICE-SER-1', '{}', '\x00'::bytea, NULL);
  CALL uc_bulk_issue(v_b, v_n);
  BEGIN
    CALL uc_bulk_issue(v_b, v_n);
    RAISE EXCEPTION 'DRILL FAIL: an already-issued batch was issued again';
  EXCEPTION WHEN invalid_parameter_value THEN
    RAISE NOTICE 'OK: an already-issued batch is refused (%)', SQLSTATE;
  END;
END $$;
ROLLBACK;

-- 5. AUTHORIZATION: agency 4 holds only VERIFY on algorithm 1; issuing is refused.
BEGIN;
DO $$
DECLARE v_b int; v_n int;
BEGIN
  INSERT INTO BulkEnrollmentBatch (issuing_agency_id, algorithm_id, note) VALUES (4, 1, 'unauth') RETURNING batch_id INTO v_b;
  INSERT INTO BulkEnrollmentStaging (batch_id, legal_name, date_of_birth, jurisdiction, biometric_binding_type, token_value, physical_serial, permitted_contexts, signature_bytes, signing_public_key_hex)
  VALUES (v_b, 'Unauth', '1990-01-01', 'US-PA', 'FINGERPRINT', 'UNAUTH-TOK-1', 'UNAUTH-SER-1', '{}', '\x00'::bytea, NULL);
  BEGIN
    CALL uc_bulk_issue(v_b, v_n);
    RAISE EXCEPTION 'DRILL FAIL: an agency without ISSUE minted a batch';
  EXCEPTION WHEN insufficient_privilege THEN
    IF EXISTS (SELECT 1 FROM IdentityToken WHERE token_value LIKE 'UNAUTH-TOK-%') THEN
      RAISE EXCEPTION 'DRILL FAIL: unauthorized batch left tokens behind';
    END IF;
    RAISE NOTICE 'OK: an agency without ISSUE on the algorithm is refused (%)', SQLSTATE;
  END;
END $$;
ROLLBACK;

-- 6. EMPTY BATCH: a batch with no staged rows is refused.
BEGIN;
DO $$
DECLARE v_b int; v_n int;
BEGIN
  INSERT INTO BulkEnrollmentBatch (issuing_agency_id, algorithm_id, note) VALUES (1, 1, 'empty') RETURNING batch_id INTO v_b;
  BEGIN
    CALL uc_bulk_issue(v_b, v_n);
    RAISE EXCEPTION 'DRILL FAIL: an empty batch was issued';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM LIKE '%DRILL FAIL%' THEN RAISE; END IF;
    RAISE NOTICE 'OK: an empty batch is refused (%)', SQLSTATE;
  END;
END $$;
ROLLBACK;

-- 7. UNSIGNED ROW: a staged row with no signature is refused (v9.257). A
--    mass-issued token can never claim a signature it does not have.
BEGIN;
DO $$
DECLARE v_b int; v_n int;
BEGIN
  INSERT INTO BulkEnrollmentBatch (issuing_agency_id, algorithm_id, note) VALUES (1, 1, 'unsigned') RETURNING batch_id INTO v_b;
  INSERT INTO BulkEnrollmentStaging (batch_id, legal_name, date_of_birth, jurisdiction, biometric_binding_type, token_value, physical_serial, permitted_contexts, signature_bytes)
  VALUES (v_b, 'Unsigned', '1990-01-01', 'US-PA', 'FINGERPRINT', 'UNSIGNED-TOK-1', 'UNSIGNED-SER-1', '{}', NULL);
  BEGIN
    CALL uc_bulk_issue(v_b, v_n);
    RAISE EXCEPTION 'DRILL FAIL: an UNSIGNED token was bulk-issued (signature bypass)';
  EXCEPTION WHEN invalid_parameter_value THEN
    IF EXISTS (SELECT 1 FROM IdentityToken WHERE token_value LIKE 'UNSIGNED-TOK-%') THEN
      RAISE EXCEPTION 'DRILL FAIL: an unsigned batch left tokens behind';
    END IF;
    RAISE NOTICE 'OK: an unsigned staged row is refused (%)', SQLSTATE;
  END;
END $$;
ROLLBACK;
SQL
)"
RC=$?
set -e
[ $RC -eq 0 ] || fail "invariant block errored (rc=$RC): $INV"
OKN="$(echo "$INV" | grep -c 'OK:')"
[ "$OKN" -eq 6 ] || fail "expected 6 invariant confirmations, got $OKN: $INV"
echo "$INV" | grep 'OK:' | sed 's/NOTICE:  //; s/^/  /'

echo "== BULK DRILL PASSED: set-based issuance at ${RATE} rows/s, atomic all-or-none, C3 across the batch, and the issue/auth/empty/unsigned refusals =="
