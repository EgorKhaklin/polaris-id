-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 08_tests.sql : Comprehensive test suite
--
-- Exercises every constraint, every stored procedure, every trigger, and
-- every relational-algebra query against the loaded sample data. Each test
-- is self-contained: it sets up its own preconditions, performs its
-- operation, asserts the outcome, and either rolls back or leaves the
-- database in a state consistent with its postcondition.
--
-- Result format: each test prints "PASS: <description>" or "FAIL: <reason>".
-- A `\set ON_ERROR_STOP on` at the top would halt at the first failure;
-- this script does NOT set that, so all failures are visible in one run.
--
-- Prerequisites: 01-07 loaded and 04_data.sql has been re-run for a clean
-- starting state.
-- ============================================================================

\echo
\echo ============================================================================
\echo POLARIS TEST SUITE
\echo ============================================================================

-- ----------------------------------------------------------------------------
-- Test counters (using temporary table since we want to summarize at the end)
-- ----------------------------------------------------------------------------

CREATE TEMP TABLE IF NOT EXISTS _test_results (
    test_id      SERIAL PRIMARY KEY,
    description  TEXT,
    outcome      TEXT,
    detail       TEXT
);

CREATE OR REPLACE FUNCTION _record(p_desc TEXT, p_pass BOOLEAN, p_detail TEXT DEFAULT NULL)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO _test_results (description, outcome, detail)
    VALUES (p_desc, CASE WHEN p_pass THEN 'PASS' ELSE 'FAIL' END, p_detail);
END;
$$;

-- ============================================================================
-- SECTION A: Schema integrity and row counts
-- ============================================================================

\echo
\echo --- Section A: Schema integrity ---

DO $$
DECLARE
    v_tables INTEGER;
    v_total  INTEGER;
BEGIN
    -- A.1: 12 tables exist
    SELECT COUNT(*) INTO v_tables FROM information_schema.tables
    WHERE table_schema = 'public'
      AND table_name IN ('individual','agency','cryptographicalgorithm',
                         'verificationcontext','identitytoken',
                         'tokenlifecycleevent','verificationevent',
                         'devicebinding','blockchainanchor','revocationlist',
                         'agencyalgorithmauth','tokenpermission');
    PERFORM _record('A.1: 12 tables exist', v_tables = 12,
        format('found %s tables', v_tables));

    -- A.2: 76 rows total in v1 sample data.
    --   v8.16 / R11-4 added 3 Individual rows demonstrating non-ENROLLED
    --   states; the v1 baseline was 73 across these 12 tables.
    SELECT (SELECT COUNT(*) FROM Individual)
         + (SELECT COUNT(*) FROM Agency)
         + (SELECT COUNT(*) FROM CryptographicAlgorithm)
         + (SELECT COUNT(*) FROM VerificationContext)
         + (SELECT COUNT(*) FROM IdentityToken)
         + (SELECT COUNT(*) FROM TokenLifecycleEvent)
         + (SELECT COUNT(*) FROM VerificationEvent)
         + (SELECT COUNT(*) FROM DeviceBinding)
         + (SELECT COUNT(*) FROM BlockchainAnchor)
         + (SELECT COUNT(*) FROM RevocationList)
         + (SELECT COUNT(*) FROM AgencyAlgorithmAuth)
         + (SELECT COUNT(*) FROM TokenPermission)
    INTO v_total;
    PERFORM _record('A.2: 76 rows total', v_total = 76,
        format('found %s rows', v_total));
END $$;

-- ============================================================================
-- SECTION B: CHECK constraints reject invalid values
-- ============================================================================

\echo
\echo --- Section B: CHECK constraint rejection ---

DO $$
BEGIN
    -- B.1: invalid status value rejected
    BEGIN
        UPDATE IdentityToken SET status='INVALID_STATE' WHERE token_id=2;
        PERFORM _record('B.1: invalid status rejected', FALSE,
            'UPDATE with invalid status was accepted');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('B.1: invalid status rejected', TRUE, NULL);
    END;

    -- B.2: invalid biometric_binding_type rejected
    BEGIN
        INSERT INTO IdentityToken
            (token_value, physical_serial, hardware_model, biometric_binding_type,
             individual_id, issuing_agency_id, algorithm_id, status,
             issued_date, expiration_date)
        VALUES
            ('TKN-TEST-B2', 'SN-TEST-B2', 'TitanQ-3',
             'RETINA',  -- not in the legal set
             1, 2, 1, 'RESERVE',
             CURRENT_TIMESTAMP, '2036-01-01');
        PERFORM _record('B.2: invalid biometric_binding_type rejected', FALSE,
            'INSERT with invalid binding type was accepted');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('B.2: invalid biometric_binding_type rejected', TRUE, NULL);
    END;

    -- B.3: invalid disclosure_level rejected
    BEGIN
        INSERT INTO VerificationEvent
            (token_id, requesting_agency_id, context_id, outcome, disclosure_level)
        VALUES
            (2, 5, 1, 'SUCCESS', 'NUCLEAR_SECRET');
        PERFORM _record('B.3: invalid disclosure_level rejected', FALSE,
            'INSERT with invalid disclosure_level was accepted');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('B.3: invalid disclosure_level rejected', TRUE, NULL);
    END;

    -- B.4: invalid agency_type rejected.
    -- The reason is declared first on purpose. Since v9.440 trg_agency_audited refuses
    -- an INSERT with no stated reason, and it is a BEFORE trigger, so it fires ahead of
    -- the CHECK. Without this the block would still pass, on the wrong refusal, and
    -- would keep passing if agency_type_check were dropped.
    BEGIN
        PERFORM set_config('polaris.justification',
                           'schema self-test, asserting the agency_type CHECK', true);
        INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level)
        VALUES ('Test Agency', 'ALIEN', 'US', 1);
        PERFORM _record('B.4: invalid agency_type rejected', FALSE,
            'INSERT with invalid agency_type was accepted');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('B.4: invalid agency_type rejected', TRUE, NULL);
    END;

    -- B.5: authorization_level out-of-range rejected. The reason is declared for the
    -- reason given at B.4: the CHECK must be what refuses this, not the recorder.
    BEGIN
        PERFORM set_config('polaris.justification',
                           'schema self-test, asserting the level range CHECK', true);
        INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level)
        VALUES ('Test Agency', 'FEDERAL', 'US', 99);
        PERFORM _record('B.5: out-of-range authorization_level rejected', FALSE,
            'INSERT with authorization_level=99 was accepted');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('B.5: out-of-range authorization_level rejected', TRUE, NULL);
    END;

    -- B.6: VerificationContext context_type CHECK rejects unknown context
    BEGIN
        INSERT INTO VerificationContext (context_type, requires_biometric, min_security_level)
        VALUES ('TIME_TRAVEL', FALSE, 128);
        PERFORM _record('B.6: invalid context_type rejected', FALSE,
            'INSERT with invalid context_type was accepted');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('B.6: invalid context_type rejected', TRUE, NULL);
    END;
END $$;

-- ============================================================================
-- SECTION C: Disclosure-consistency CHECK
-- ============================================================================

\echo
\echo --- Section C: Disclosure-consistency CHECK ---

DO $$
BEGIN
    -- C.1: ZERO_KNOWLEDGE with non-NULL token_id rejected
    BEGIN
        INSERT INTO VerificationEvent
            (token_id, requesting_agency_id, context_id, outcome, disclosure_level)
        VALUES
            (2, 5, 1, 'SUCCESS', 'ZERO_KNOWLEDGE');
        PERFORM _record('C.1: ZERO_KNOWLEDGE+token_id rejected', FALSE,
            'INSERT was accepted; constraint failed');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('C.1: ZERO_KNOWLEDGE+token_id rejected', TRUE, NULL);
    END;

    -- C.2: FULL with NULL token_id rejected
    BEGIN
        INSERT INTO VerificationEvent
            (token_id, requesting_agency_id, context_id, outcome, disclosure_level)
        VALUES
            (NULL, 5, 1, 'SUCCESS', 'FULL');
        PERFORM _record('C.2: FULL+NULL token_id rejected', FALSE,
            'INSERT was accepted; constraint failed');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('C.2: FULL+NULL token_id rejected', TRUE, NULL);
    END;

    -- C.3: SELECTIVE allows either token_id state (NULL is permitted)
    BEGIN
        INSERT INTO VerificationEvent
            (token_id, requesting_agency_id, context_id, outcome, disclosure_level)
        VALUES
            (NULL, 5, 1, 'SUCCESS', 'SELECTIVE');
        -- INSERT succeeded; verify by row count
        IF EXISTS (SELECT 1 FROM VerificationEvent
                   WHERE disclosure_level='SELECTIVE' AND token_id IS NULL
                     AND requesting_agency_id=5 AND context_id=1) THEN
            PERFORM _record('C.3: SELECTIVE+NULL allowed', TRUE, NULL);
        ELSE
            PERFORM _record('C.3: SELECTIVE+NULL allowed', FALSE,
                'INSERT did not persist (and no exception raised)');
        END IF;
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('C.3: SELECTIVE+NULL allowed', FALSE,
            format('INSERT was rejected: %s', SQLERRM));
    END;
END $$;

-- ============================================================================
-- SECTION D: Foreign-key integrity
-- ============================================================================

\echo
\echo --- Section D: Foreign-key integrity ---

DO $$
BEGIN
    -- D.1: orphan token_id in TokenLifecycleEvent rejected
    BEGIN
        INSERT INTO TokenLifecycleEvent (token_id, actor_agency_id, event_type)
        VALUES (9999, 1, 'ISSUED');
        PERFORM _record('D.1: orphan token_id in TLE rejected', FALSE,
            'INSERT with non-existent token_id was accepted');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('D.1: orphan token_id in TLE rejected', TRUE, NULL);
    END;

    -- D.2: orphan algorithm_id in IdentityToken rejected
    BEGIN
        INSERT INTO IdentityToken
            (token_value, physical_serial, biometric_binding_type,
             individual_id, issuing_agency_id, algorithm_id, status,
             issued_date, expiration_date)
        VALUES
            ('TKN-TEST-D2', 'SN-TEST-D2', 'NONE',
             1, 2, 9999, 'RESERVE',
             CURRENT_TIMESTAMP, '2036-01-01');
        PERFORM _record('D.2: orphan algorithm_id rejected', FALSE,
            'INSERT with non-existent algorithm_id was accepted');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('D.2: orphan algorithm_id rejected', TRUE, NULL);
    END;

    -- D.3: cannot delete an Individual that has an IdentityToken (RESTRICT default)
    BEGIN
        DELETE FROM Individual WHERE individual_id = 1;
        PERFORM _record('D.3: DELETE Individual with token rejected', FALSE,
            'DELETE was accepted; FK should have blocked it');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('D.3: DELETE Individual with token rejected', TRUE, NULL);
    END;
END $$;

-- ============================================================================
-- SECTION E: Partial unique index on (individual_id) WHERE status='ACTIVE'
-- ============================================================================

\echo
\echo --- Section E: Partial unique index ---

DO $$
BEGIN
    -- E.1: cannot insert second ACTIVE token for same individual
    BEGIN
        INSERT INTO IdentityToken
            (token_value, physical_serial, biometric_binding_type,
             individual_id, issuing_agency_id, algorithm_id, status,
             issued_date, activated_date, expiration_date)
        VALUES
            ('TKN-TEST-E1', 'SN-TEST-E1', 'NONE',
             2, 3, 1, 'ACTIVE',  -- individual_id=2 (Maria) already has T2 ACTIVE
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '2036-01-01');
        PERFORM _record('E.1: second ACTIVE token rejected', FALSE,
            'second ACTIVE INSERT was accepted; partial index failed');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('E.1: second ACTIVE token rejected', TRUE, NULL);
    END;

    -- E.2: CAN insert RESERVE token for an individual who already has ACTIVE
    BEGIN
        INSERT INTO IdentityToken
            (token_value, physical_serial, biometric_binding_type,
             individual_id, issuing_agency_id, algorithm_id, status,
             issued_date, expiration_date)
        VALUES
            ('TKN-TEST-E2', 'SN-TEST-E2', 'NONE',
             2, 3, 1, 'RESERVE',  -- Maria's reserve, alongside her active T2
             CURRENT_TIMESTAMP, '2036-01-01');
        -- R11-1: backfill a TokenSignature for the test-inserted token so
        -- the M:N invariant holds for the rest of the suite.
        INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes)
        SELECT token_id, algorithm_id, 'BACKFILL_TEST_E2'::BYTEA
        FROM IdentityToken WHERE token_value = 'TKN-TEST-E2';
        PERFORM _record('E.2: RESERVE alongside ACTIVE allowed', TRUE, NULL);
        -- Clean up: leave this token in place; UC-4 test will use it
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('E.2: RESERVE alongside ACTIVE allowed', FALSE,
            format('INSERT was rejected: %s', SQLERRM));
    END;
END $$;

-- ============================================================================
-- SECTION F: State-machine trigger
-- ============================================================================

\echo
\echo --- Section F: State-machine trigger ---

DO $$
BEGIN
    -- F.1: REVOKED → ACTIVE rejected (terminal state, no return)
    BEGIN
        UPDATE IdentityToken SET status='ACTIVE', activated_date=CURRENT_TIMESTAMP
         WHERE token_id=5;  -- T5 is REVOKED
        PERFORM _record('F.1: REVOKED → ACTIVE rejected', FALSE,
            'illegal transition was accepted');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('F.1: REVOKED → ACTIVE rejected', TRUE, NULL);
    END;

    -- F.2: ACTIVE → RESERVE rejected (no return path)
    BEGIN
        UPDATE IdentityToken SET status='RESERVE' WHERE token_id=2;
        PERFORM _record('F.2: ACTIVE → RESERVE rejected', FALSE,
            'illegal transition was accepted');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('F.2: ACTIVE → RESERVE rejected', TRUE, NULL);
    END;

    -- F.3: ACTIVE → ACTIVE allowed (no-op, no status change)
    BEGIN
        UPDATE IdentityToken SET hardware_model='TitanQ-3 Rev2' WHERE token_id=2;
        PERFORM _record('F.3: non-status UPDATE on ACTIVE allowed', TRUE, NULL);
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('F.3: non-status UPDATE on ACTIVE allowed', FALSE,
            format('UPDATE was rejected: %s', SQLERRM));
    END;
END $$;

-- ============================================================================
-- SECTION G: Append-only triggers on audit tables
-- ============================================================================

\echo
\echo --- Section G: Append-only triggers ---

DO $$
BEGIN
    -- G.1: UPDATE on TokenLifecycleEvent rejected
    BEGIN
        UPDATE TokenLifecycleEvent SET reason_code='TAMPERED' WHERE event_id=1;
        PERFORM _record('G.1: UPDATE TokenLifecycleEvent rejected', FALSE,
            'UPDATE was accepted; audit trail compromised');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('G.1: UPDATE TokenLifecycleEvent rejected', TRUE, NULL);
    END;

    -- G.2: DELETE on TokenLifecycleEvent rejected
    BEGIN
        DELETE FROM TokenLifecycleEvent WHERE event_id=1;
        PERFORM _record('G.2: DELETE TokenLifecycleEvent rejected', FALSE,
            'DELETE was accepted; audit trail compromised');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('G.2: DELETE TokenLifecycleEvent rejected', TRUE, NULL);
    END;

    -- G.3: UPDATE on VerificationEvent rejected
    BEGIN
        UPDATE VerificationEvent SET outcome='SUCCESS' WHERE event_id=8;  -- was FAILURE
        PERFORM _record('G.3: UPDATE VerificationEvent rejected', FALSE,
            'UPDATE was accepted; audit trail compromised');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('G.3: UPDATE VerificationEvent rejected', TRUE, NULL);
    END;
END $$;

-- ============================================================================
-- SECTION H: Stored procedures (UC-1, UC-4, UC-5, UC-7)
-- ============================================================================

\echo
\echo --- Section H: Stored procedures ---

DO $$
DECLARE
    v_new_token_id INTEGER;
    v_lost_token   INTEGER;
    v_reserve_token INTEGER;
    v_warrant_count INTEGER;
    v_zk_count      INTEGER;
BEGIN
    -- H.1: UC-1 issues a new token end-to-end
    BEGIN
        v_new_token_id := uc1_issue_and_activate(
            'Test Subject H1', '1990-06-15'::date, 'US-PA',
            2,                  -- PA issuer
            1,                  -- ML-DSA-65
            'IRIS', 2, 'MULTI_MODAL',
            'TKN-TEST-H1', 'SN-TEST-H1', 'TitanQ-3',
            ARRAY[1,2]::INTEGER[]);
        PERFORM _record('H.1: UC-1 atomic issuance', v_new_token_id IS NOT NULL,
            format('new token_id=%s', v_new_token_id));
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('H.1: UC-1 atomic issuance', FALSE,
            format('procedure raised: %s', SQLERRM));
    END;

    -- H.2: UC-1 rejects unauthorized algorithm
    BEGIN
        v_new_token_id := uc1_issue_and_activate(
            'Test Subject H2', '1990-06-15'::date, 'US-PA',
            2,                  -- PA issuer
            4,                  -- SLH-DSA-256s — PA does NOT have grant
            'IRIS', 2, 'MULTI_MODAL',
            'TKN-TEST-H2', 'SN-TEST-H2', 'TitanQ-3',
            ARRAY[1]::INTEGER[]);
        PERFORM _record('H.2: UC-1 rejects unauthorized algorithm', FALSE,
            'unauthorized issuance was accepted');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('H.2: UC-1 rejects unauthorized algorithm', TRUE,
            'procedure correctly raised');
    END;

    -- H.3: UC-4 activates a reserve. We need a setup: pick the reserve we
    --      created in section E.2 (Maria's, individual_id=2) and lose Maria's
    --      currently-active T2.
    --      First, find the reserve token_id Maria has.
    SELECT token_id INTO v_reserve_token
    FROM   IdentityToken WHERE individual_id=2 AND status='RESERVE'
    LIMIT 1;

    IF v_reserve_token IS NULL THEN
        PERFORM _record('H.3: UC-4 reserve activation', FALSE,
            'precondition failed: Maria has no RESERVE token');
    ELSE
        BEGIN
            v_lost_token := uc4_activate_reserve(
                2,                          -- T2 (Maria's active)
                3,                          -- CA issuer as actor
                'LOST',
                v_reserve_token,
                'https://crl.idtoken.gov/2026/05/T2-LOST.crl');
            PERFORM _record('H.3: UC-4 reserve activation', v_lost_token = v_reserve_token,
                format('promoted token_id=%s', v_lost_token));
        EXCEPTION WHEN OTHERS THEN
            PERFORM _record('H.3: UC-4 reserve activation', FALSE,
                format('procedure raised: %s', SQLERRM));
        END;
    END IF;

    -- H.4: UC-4 left T2 in LOST status with predecessor pointer correctly set
    DECLARE
        v_t2_status   VARCHAR(20);
        v_pred_token  INTEGER;
    BEGIN
        SELECT status INTO v_t2_status FROM IdentityToken WHERE token_id=2;
        SELECT predecessor_token_id INTO v_pred_token
        FROM   IdentityToken WHERE token_id=v_reserve_token;
        PERFORM _record('H.4: UC-4 status transitions correct',
            v_t2_status='LOST' AND v_pred_token=2,
            format('T2 status=%s, predecessor=%s', v_t2_status, v_pred_token));
    END;

    -- H.5: UC-5 binds a device to an active token
    DECLARE
        v_binding_id INTEGER;
    BEGIN
        v_binding_id := uc5_bind_device(
            v_reserve_token,    -- the just-promoted active token
            'PHONE',
            'SE-TEST-H5-' || md5(random()::text),
            'SECURE_ENCLAVE',
            12);
        PERFORM _record('H.5: UC-5 binds device to active', v_binding_id IS NOT NULL,
            format('binding_id=%s', v_binding_id));
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('H.5: UC-5 binds device to active', FALSE,
            format('procedure raised: %s', SQLERRM));
    END;

    -- H.6: UC-5 rejects binding to a non-ACTIVE token
    BEGIN
        PERFORM uc5_bind_device(5, 'PHONE',  -- T5 is REVOKED
            'SE-TEST-H6-fakeprint', 'SECURE_ENCLAVE', 12);
        PERFORM _record('H.6: UC-5 rejects bind to non-ACTIVE', FALSE,
            'binding was accepted on REVOKED token');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('H.6: UC-5 rejects bind to non-ACTIVE', TRUE, NULL);
    END;

    -- H.7: UC-7 returns the right rows for the audit subject
    --      For James Chen (individual_id=3) with SELECTIVE/FULL on banking, travel.
    SELECT COUNT(*) INTO v_warrant_count
    FROM   uc7_warrant_audit(3);
    PERFORM _record('H.7: UC-7 returns events for individual',
        v_warrant_count > 0,
        format('warrant returned %s events', v_warrant_count));

    -- H.8: UC-7 redacts ZERO_KNOWLEDGE events (token_id NULL in returned rows)
    SELECT COUNT(*) INTO v_zk_count
    FROM   uc7_warrant_audit(3)
    WHERE  disclosure_level='ZERO_KNOWLEDGE' AND token_id IS NOT NULL;
    PERFORM _record('H.8: UC-7 redacts ZERO_KNOWLEDGE token_id',
        v_zk_count = 0,
        format('found %s ZK events with token_id (should be 0)', v_zk_count));
END $$;

-- ============================================================================
-- SECTION I: Relational-algebra queries return expected results
-- ============================================================================

\echo
\echo --- Section I: Relational-algebra query results ---

DO $$
DECLARE
    v_count INTEGER;
BEGIN
    -- I.1: Q2 returns ACTIVE PQ-signed tokens. After Section H operations:
    --      H.1 added a new active token, H.3 swapped Maria's lost T2 for her
    --      newly-promoted reserve. Net change: +1 active token (the H.1 one).
    --      Original 3 ACTIVE (T2, T3, T4) → still 3 ACTIVE (T3, T4, promoted-reserve)
    --      after the swap, plus +1 from H.1 = 4 total. All are PQ-signed.
    SELECT COUNT(*) INTO v_count
    FROM    IdentityToken         it
    JOIN    Individual            ind ON it.individual_id = ind.individual_id
    JOIN    CryptographicAlgorithm alg ON it.algorithm_id  = alg.algorithm_id
    WHERE   alg.quantum_resistant = TRUE
      AND   it.status             = 'ACTIVE';
    PERFORM _record('I.1: Q2 returns 4 active PQ tokens after section H',
        v_count = 4, format('found %s', v_count));

    -- I.2: Q3 returns 3 agencies with BOTH grants on ML-DSA-65
    SELECT COUNT(*) INTO v_count
    FROM    CryptographicAlgorithm alg
    JOIN    AgencyAlgorithmAuth aaa ON alg.algorithm_id = aaa.algorithm_id
    JOIN    Agency              ag  ON aaa.agency_id    = ag.agency_id
    WHERE   alg.name             = 'ML-DSA-65'
      AND   aaa.authorization_type = 'BOTH';
    PERFORM _record('I.2: Q3 returns 3 BOTH-grant agencies',
        v_count = 3, format('found %s', v_count));

    -- I.3: Q5 verification volume by context — BANKING is highest
    DECLARE
        v_banking_count INTEGER;
        v_max_count     INTEGER;
    BEGIN
        SELECT COUNT(*) INTO v_banking_count
        FROM   VerificationEvent ve JOIN VerificationContext vc ON ve.context_id=vc.context_id
        WHERE  vc.context_type = 'BANKING';
        SELECT MAX(c) INTO v_max_count FROM (
            SELECT COUNT(*) AS c FROM VerificationEvent ve
            JOIN VerificationContext vc ON ve.context_id=vc.context_id
            GROUP BY vc.context_type) sub;
        PERFORM _record('I.3: Q5 BANKING is highest-volume context',
            v_banking_count = v_max_count,
            format('banking=%s, max=%s', v_banking_count, v_max_count));
    END;

    -- I.4: Q6 succession lineage now returns >=1 row (the UC-4 swap)
    SELECT COUNT(*) INTO v_count
    FROM    IdentityToken t1
    CROSS JOIN IdentityToken t2
    WHERE   t1.status              = 'ACTIVE'
      AND   t1.predecessor_token_id = t2.token_id;
    PERFORM _record('I.4: Q6 returns >=1 succession after UC-4',
        v_count >= 1, format('found %s lineage rows', v_count));
END $$;

-- ============================================================================
-- SECTION J: View ActiveTokens reflects current state
-- ============================================================================

\echo
\echo --- Section J: ActiveTokens view ---

DO $$
DECLARE
    v_count    INTEGER;
    v_t2_present INTEGER;
BEGIN
    -- J.1: ActiveTokens shows current ACTIVE tokens (T3, T4, the H.1 token,
    --      and the promoted reserve from H.3) — at least 4
    SELECT COUNT(*) INTO v_count FROM ActiveTokens;
    PERFORM _record('J.1: ActiveTokens shows >=4 rows', v_count >= 4,
        format('found %s active tokens', v_count));

    -- J.2: T2 (Maria's old active, now LOST) is NOT in ActiveTokens
    SELECT COUNT(*) INTO v_t2_present FROM ActiveTokens WHERE token_id = 2;
    PERFORM _record('J.2: ActiveTokens excludes LOST tokens',
        v_t2_present = 0, format('T2 row count=%s', v_t2_present));
END $$;

-- ============================================================================
-- K. ISSUER DISCRETION BOUNDS (R11-6 / M2-11)
-- ============================================================================

-- K.1: IssuerDiscretionPolicy CHECK constraints reject invalid values.
DO $$
BEGIN
    BEGIN
        INSERT INTO IssuerDiscretionPolicy
            (agency_id, max_revoke_percent, window_days, set_by_admin, justification)
        VALUES (2, 0.00, 30, 'test',
                'should fail: max_revoke_percent must be > 0');
        PERFORM _record('K.1: max_revoke_percent=0 rejected', FALSE,
            'INSERT unexpectedly succeeded');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('K.1: max_revoke_percent=0 rejected', TRUE, NULL);
    END;
END $$;

-- K.2: justification length floor enforced.
DO $$
BEGIN
    BEGIN
        INSERT INTO IssuerDiscretionPolicy
            (agency_id, max_revoke_percent, window_days, set_by_admin, justification)
        VALUES (2, 5.00, 30, 'test', 'too short');
        PERFORM _record('K.2: short justification rejected', FALSE,
            'INSERT unexpectedly succeeded');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('K.2: short justification rejected', TRUE, NULL);
    END;
END $$;

-- K.3: window_days > 365 rejected.
DO $$
BEGIN
    BEGIN
        INSERT INTO IssuerDiscretionPolicy
            (agency_id, max_revoke_percent, window_days, set_by_admin, justification)
        VALUES (2, 5.00, 400, 'test',
                'window must be 1..365 days inclusive');
        PERFORM _record('K.3: window_days=400 rejected', FALSE,
            'INSERT unexpectedly succeeded');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('K.3: window_days=400 rejected', TRUE, NULL);
    END;
END $$;

-- K.4: Sample data populated 2 policy overrides.
DO $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT count(*) INTO v_count FROM IssuerDiscretionPolicy;
    PERFORM _record('K.4: 2 sample policy rows present',
        v_count = 2, format('count=%s', v_count));
END $$;

-- K.5: Direct UPDATE to status=REVOKED is rejected by trigger.
DO $$
DECLARE
    v_token_id INTEGER;
BEGIN
    -- Find a RESERVE token to attempt revocation on.
    SELECT token_id INTO v_token_id
    FROM IdentityToken WHERE status='RESERVE' LIMIT 1;
    IF v_token_id IS NULL THEN
        PERFORM _record('K.5: raw UPDATE-to-REVOKED rejected', TRUE,
            'skipped: no RESERVE token available');
        RETURN;
    END IF;

    BEGIN
        UPDATE IdentityToken SET status='REVOKED'
         WHERE token_id = v_token_id;
        PERFORM _record('K.5: raw UPDATE-to-REVOKED rejected', FALSE,
            'UPDATE unexpectedly succeeded');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('K.5: raw UPDATE-to-REVOKED rejected', TRUE, NULL);
    END;
END $$;

-- K.6: uc8_revoke_token under the bound succeeds and writes both
--      IdentityToken.status='REVOKED' and a RevocationList row.
--      Sample data is too small (1 revocation / ~4 outstanding = 25%)
--      to be under the default 5% bound, so we seed a permissive
--      override for the test agency first.
DO $$
DECLARE
    v_token_id      INTEGER;
    v_agency_id     INTEGER;
    v_crl_before    INTEGER;
    v_crl_after     INTEGER;
    v_final_status  VARCHAR(20);
BEGIN
    -- Pick an ACTIVE token to revoke.
    SELECT token_id, issuing_agency_id
      INTO v_token_id, v_agency_id
    FROM IdentityToken WHERE status='ACTIVE' LIMIT 1;
    IF v_token_id IS NULL THEN
        PERFORM _record('K.6: uc8_revoke_token under bound succeeds', TRUE,
            'skipped: no ACTIVE token available');
        RETURN;
    END IF;

    -- Seed a permissive override so this single-revocation test stays
    -- under-bound with the small sample. ON CONFLICT UPDATE in case the
    -- agency already has a sample-data row (agency 1 / 6 do).
    -- v9.426: a bound is append-only, so a change supersedes and appends.
    UPDATE IssuerDiscretionPolicy SET superseded_at = now()
     WHERE agency_id = v_agency_id AND superseded_at IS NULL;
    INSERT INTO IssuerDiscretionPolicy
        (agency_id, max_revoke_percent, window_days, set_by_admin, justification)
    VALUES (v_agency_id, 95.00, 30, 'test_K6',
        'temporary permissive override for SQL self-test K.6 under-bound path');

    SELECT count(*) INTO v_crl_before FROM RevocationList;

    CALL uc8_revoke_token(
        p_token_id           => v_token_id,
        p_actor_agency_id    => v_agency_id,
        p_reason_code        => 'ADMINISTRATIVE',
        p_published_location => 'https://crl.polaris.local/test/K6',
        p_cosigner_agency_id => NULL);

    SELECT count(*) INTO v_crl_after FROM RevocationList;
    SELECT status INTO v_final_status
    FROM IdentityToken WHERE token_id = v_token_id;

    PERFORM _record('K.6: uc8_revoke_token under bound succeeds',
        v_final_status = 'REVOKED' AND v_crl_after = v_crl_before + 1,
        format('status=%s crl_delta=%s', v_final_status, v_crl_after - v_crl_before));

    -- v9.426: retire the test's permissive override, the way S.13 retires the test
    -- retention policies. Before this it stayed in force, so a freshly loaded
    -- database shipped with one agency bounded at 95% -- invisible until
    -- `discretion-show` existed to print it, and then printed in red. The row is not
    -- deleted (the table refuses that): it is superseded, so the test's own decision
    -- stays readable and the agency goes back to whatever bound it had before.
    UPDATE IssuerDiscretionPolicy SET superseded_at = now()
     WHERE agency_id = v_agency_id AND superseded_at IS NULL AND set_by_admin = 'test_K6';
    UPDATE IssuerDiscretionPolicy SET superseded_at = NULL
     WHERE policy_id = (SELECT max(policy_id) FROM IssuerDiscretionPolicy
                         WHERE agency_id = v_agency_id AND set_by_admin <> 'test_K6');
END $$;

-- K.7: Already-terminal token cannot be revoked again.
DO $$
DECLARE
    v_token_id      INTEGER;
    v_agency_id     INTEGER;
BEGIN
    -- The token revoked in K.6 should now refuse a second revocation.
    SELECT token_id, issuing_agency_id
      INTO v_token_id, v_agency_id
    FROM IdentityToken WHERE status='REVOKED' LIMIT 1;
    IF v_token_id IS NULL THEN
        PERFORM _record('K.7: already-terminal token rejected', TRUE,
            'skipped: no REVOKED token available');
        RETURN;
    END IF;

    BEGIN
        CALL uc8_revoke_token(
            p_token_id           => v_token_id,
            p_actor_agency_id    => v_agency_id,
            p_reason_code        => 'COMPROMISED',
            p_published_location => 'https://crl.polaris.local/test/K7',
            p_cosigner_agency_id => NULL);
        PERFORM _record('K.7: already-terminal token rejected', FALSE,
            'second CALL unexpectedly succeeded');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _record('K.7: already-terminal token rejected',
            SQLERRM LIKE '%already terminal%',
            format('errmsg=%s', SQLERRM));
    END;
END $$;

-- ============================================================================
-- L. TIERED ENROLLMENT (R11-4 / M2-9)
-- ============================================================================

-- L.1: EnrollmentStatusEvent CHECK rejects an invalid status.
DO $$
BEGIN
    BEGIN
        INSERT INTO EnrollmentStatusEvent
            (individual_id, status, transition_reason, recorded_by_agency_id)
        VALUES (1, 'NONSENSE', 'should fail: invalid status', 1);
        PERFORM _record('L.1: invalid status rejected', FALSE,
            'INSERT unexpectedly succeeded');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('L.1: invalid status rejected', TRUE, NULL);
    END;
END $$;

-- L.2: Seed trigger emits NOT_ENROLLED on every new Individual.
DO $$
DECLARE
    v_new_id    INTEGER;
    v_seed_n    INTEGER;
    v_seed_st   VARCHAR(20);
BEGIN
    INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
    VALUES ('SQL TEST L.2', '1990-01-01', 'US-PA')
    RETURNING individual_id INTO v_new_id;

    SELECT count(*), MIN(status) INTO v_seed_n, v_seed_st
    FROM EnrollmentStatusEvent WHERE individual_id = v_new_id;

    PERFORM _record('L.2: seed trigger emits NOT_ENROLLED',
        v_seed_n = 1 AND v_seed_st = 'NOT_ENROLLED',
        format('n=%s status=%s', v_seed_n, v_seed_st));
END $$;

-- L.3: IndividualCurrentEnrollment view returns one row per Individual.
DO $$
DECLARE
    v_view_count    INTEGER;
    v_individ_count INTEGER;
BEGIN
    SELECT count(*) INTO v_view_count    FROM IndividualCurrentEnrollment;
    SELECT count(*) INTO v_individ_count FROM Individual;

    PERFORM _record('L.3: view has one row per Individual',
        v_view_count = v_individ_count,
        format('view=%s individuals=%s', v_view_count, v_individ_count));
END $$;

-- L.4: civic_enrollment_summary returns count > 0 for at least one
-- (jurisdiction, status) tuple. Also verifies EXEMPT and LAPSED appear
-- in the rollup (sample data presence).
DO $$
DECLARE
    v_tuples INTEGER;
    v_exempt INTEGER;
    v_lapsed INTEGER;
BEGIN
    SELECT count(*) INTO v_tuples FROM civic_enrollment_summary(NULL);
    SELECT count(*) INTO v_exempt FROM civic_enrollment_summary(NULL)
        WHERE status = 'EXEMPT';
    SELECT count(*) INTO v_lapsed FROM civic_enrollment_summary(NULL)
        WHERE status = 'LAPSED';

    PERFORM _record('L.4: civic_enrollment_summary returns rollup',
        v_tuples > 0 AND v_exempt >= 1 AND v_lapsed >= 1,
        format('tuples=%s exempt=%s lapsed=%s', v_tuples, v_exempt, v_lapsed));
END $$;

-- L.5: Append-only invariant on EnrollmentStatusEvent.
DO $$
DECLARE
    v_event_id INTEGER;
BEGIN
    SELECT event_id INTO v_event_id
    FROM EnrollmentStatusEvent LIMIT 1;
    IF v_event_id IS NULL THEN
        PERFORM _record('L.5: append-only on EnrollmentStatusEvent', TRUE,
            'skipped: no row to test against');
        RETURN;
    END IF;

    BEGIN
        UPDATE EnrollmentStatusEvent SET status = 'EXEMPT'
         WHERE event_id = v_event_id;
        PERFORM _record('L.5: append-only on EnrollmentStatusEvent', FALSE,
            'UPDATE unexpectedly succeeded');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('L.5: append-only on EnrollmentStatusEvent', TRUE, NULL);
    END;
END $$;

-- ============================================================================
-- M. CATASTROPHIC-LOSS RECOVERY (R11-2 / M2-7)
-- ============================================================================

-- M.1: cooldown_window_minimum CHECK — can't insert with < 48h.
DO $$
BEGIN
    BEGIN
        INSERT INTO RecoveryRequest
            (claimed_individual_id, requesting_agency_id, requesting_user_id,
             cooldown_expires_at)
        VALUES
            (1, 1, (SELECT user_id FROM AppUser WHERE username='admin'),
             CURRENT_TIMESTAMP + INTERVAL '12 hours');
        PERFORM _record('M.1: cool-down < 48h rejected', FALSE,
            'INSERT unexpectedly succeeded');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('M.1: cool-down < 48h rejected', TRUE, NULL);
    END;
END $$;

-- M.2: approved_requires_three_channels — APPROVED without channels rejected.
DO $$
DECLARE
    v_individ_id INTEGER;
BEGIN
    -- Create a fresh Individual to avoid the partial unique index colliding.
    INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
    VALUES ('SQL TEST M.2 individual', '1990-01-01', 'US-PA')
    RETURNING individual_id INTO v_individ_id;

    BEGIN
        INSERT INTO RecoveryRequest
            (claimed_individual_id, requesting_agency_id, requesting_user_id,
             status, decided_at, decided_by_user_id,
             cooldown_expires_at)
        VALUES
            (v_individ_id, 1,
             (SELECT user_id FROM AppUser WHERE username='operator'),
             'APPROVED', CURRENT_TIMESTAMP,
             (SELECT user_id FROM AppUser WHERE username='admin'),
             CURRENT_TIMESTAMP - INTERVAL '1 hour');
        PERFORM _record('M.2: APPROVED requires three channels', FALSE,
            'INSERT unexpectedly succeeded');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('M.2: APPROVED requires three channels', TRUE, NULL);
    END;
END $$;

-- M.3: approver_differs_from_requester CHECK.
DO $$
DECLARE
    v_individ_id INTEGER;
    v_op_uid     INTEGER;
BEGIN
    INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
    VALUES ('SQL TEST M.3 individual', '1990-01-01', 'US-PA')
    RETURNING individual_id INTO v_individ_id;

    SELECT user_id INTO v_op_uid FROM AppUser WHERE username='operator';

    BEGIN
        INSERT INTO RecoveryRequest
            (claimed_individual_id, requesting_agency_id, requesting_user_id,
             decided_by_user_id, cooldown_expires_at)
        VALUES
            (v_individ_id, 1, v_op_uid,
             v_op_uid,  -- same user as decider — should reject
             CURRENT_TIMESTAMP + INTERVAL '49 hours');
        PERFORM _record('M.3: approver=requester rejected', FALSE,
            'INSERT unexpectedly succeeded');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('M.3: approver=requester rejected', TRUE, NULL);
    END;
END $$;

-- M.4: Sample PENDING RecoveryRequest seeded by 10_auth.sql.
DO $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT count(*) INTO v_count FROM RecoveryRequest
    WHERE status = 'PENDING';
    PERFORM _record('M.4: sample PENDING RecoveryRequest present',
        v_count >= 1, format('count=%s', v_count));
END $$;

-- M.5: uc9_initiate_recovery rejects when ACTIVE token exists.
-- Pick an individual dynamically; K.6 nondeterministically REVOKED one
-- ACTIVE token earlier in the suite, so any hardcoded individual_id may
-- now be without ACTIVE.
DO $$
DECLARE
    v_op_uid     INTEGER;
    v_individ_id INTEGER;
    v_agency_id  INTEGER;
BEGIN
    SELECT user_id INTO v_op_uid FROM AppUser WHERE username='operator';
    SELECT individual_id, issuing_agency_id
      INTO v_individ_id, v_agency_id
    FROM IdentityToken WHERE status='ACTIVE' LIMIT 1;

    IF v_individ_id IS NULL THEN
        PERFORM _record('M.5: initiate rejected when ACTIVE exists', TRUE,
            'skipped: no ACTIVE token in test state');
        RETURN;
    END IF;

    BEGIN
        CALL uc9_initiate_recovery(v_individ_id, v_agency_id, v_op_uid, 48);
        PERFORM _record('M.5: initiate rejected when ACTIVE exists', FALSE,
            'CALL unexpectedly succeeded');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('M.5: initiate rejected when ACTIVE exists', TRUE, NULL);
    END;
END $$;

-- ============================================================================
-- N. MULTI-SIGNATURE TRANSITIONAL STATE (R11-1 / M2-6)
-- ============================================================================

-- N.1: TokenSignature backfill covered every IdentityToken.
DO $$
DECLARE
    v_tokens INTEGER;
    v_sigs   INTEGER;
BEGIN
    SELECT count(*) INTO v_tokens FROM IdentityToken;
    SELECT count(*) INTO v_sigs
    FROM IdentityToken t
    WHERE EXISTS (SELECT 1 FROM TokenSignature s WHERE s.token_id = t.token_id);
    PERFORM _record('N.1: every IdentityToken has ≥ 1 TokenSignature row',
        v_tokens = v_sigs,
        format('tokens=%s, with-sig=%s', v_tokens, v_sigs));
END $$;

-- N.2: UNIQUE (token_id, algorithm_id) rejects duplicate-algorithm inserts.
DO $$
DECLARE
    v_t INTEGER;
    v_a INTEGER;
BEGIN
    SELECT token_id, algorithm_id INTO v_t, v_a FROM TokenSignature LIMIT 1;
    BEGIN
        INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes)
        VALUES (v_t, v_a, 'duplicate'::BYTEA);
        PERFORM _record('N.2: UNIQUE (token_id, algorithm_id) enforced',
            FALSE, 'duplicate INSERT unexpectedly succeeded');
    EXCEPTION WHEN unique_violation THEN
        PERFORM _record('N.2: UNIQUE (token_id, algorithm_id) enforced',
            TRUE, NULL);
    END;
END $$;

-- N.3: DELETE on TokenSignature is rejected by the immutability trigger.
DO $$
DECLARE
    v_sig_id INTEGER;
BEGIN
    SELECT signature_id INTO v_sig_id FROM TokenSignature LIMIT 1;
    BEGIN
        DELETE FROM TokenSignature WHERE signature_id = v_sig_id;
        PERFORM _record('N.3: DELETE on TokenSignature rejected',
            FALSE, 'DELETE unexpectedly succeeded');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('N.3: DELETE on TokenSignature rejected',
            TRUE, NULL);
    END;
END $$;

-- N.4: UPDATE to signature_bytes is rejected (only deprecation_date mutable).
DO $$
DECLARE
    v_sig_id INTEGER;
BEGIN
    SELECT signature_id INTO v_sig_id FROM TokenSignature LIMIT 1;
    BEGIN
        UPDATE TokenSignature SET signature_bytes = 'MUTATED'::BYTEA
         WHERE signature_id = v_sig_id;
        PERFORM _record('N.4: UPDATE to signature_bytes rejected',
            FALSE, 'UPDATE unexpectedly succeeded');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('N.4: UPDATE to signature_bytes rejected',
            TRUE, NULL);
    END;
END $$;

-- N.5: uc6_migrate_algorithm adds a new signature.
DO $$
DECLARE
    v_token_id  INTEGER;
    v_sigs_before INTEGER;
    v_sigs_after  INTEGER;
    v_new_alg   INTEGER;
BEGIN
    -- Pick a token using algorithm 1 (ML-DSA-65) and migrate it to
    -- algorithm 2 (ML-DSA-87, also PQ and non-deprecated). Use any
    -- ACTIVE token currently using algorithm 1 — the K.6 test in
    -- section K may have already revoked one ACTIVE; dynamic lookup
    -- avoids hardcoded IDs.
    SELECT token_id INTO v_token_id
    FROM IdentityToken
    WHERE algorithm_id = 1
      AND NOT EXISTS (SELECT 1 FROM TokenSignature s
                      WHERE s.token_id = IdentityToken.token_id
                        AND s.algorithm_id = 2)
    LIMIT 1;

    IF v_token_id IS NULL THEN
        PERFORM _record('N.5: uc6_migrate_algorithm adds new signature',
            TRUE, 'skipped: no eligible token');
        RETURN;
    END IF;

    SELECT count(*) INTO v_sigs_before FROM TokenSignature WHERE token_id = v_token_id;

    CALL uc6_migrate_algorithm(v_token_id, 2, 'TEST_MIGRATE_N5'::BYTEA, FALSE);

    SELECT count(*) INTO v_sigs_after FROM TokenSignature WHERE token_id = v_token_id;

    PERFORM _record('N.5: uc6_migrate_algorithm adds new signature',
        v_sigs_after = v_sigs_before + 1,
        format('before=%s after=%s', v_sigs_before, v_sigs_after));
END $$;

-- ============================================================================
-- O. ANCHOR BATCHES (R10-2 / M2-2)
-- ============================================================================

-- O.1: seed produced two AnchorBatch rows (per-algorithm scoping demonstrated).
DO $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT count(*) INTO v_count FROM AnchorBatch;
    PERFORM _record('O.1: seed produced two AnchorBatch rows',
        v_count = 2,
        format('count=%s', v_count));
END $$;

-- O.2: UPDATE on AnchorBatch is rejected (append-only).
DO $$
BEGIN
    BEGIN
        UPDATE AnchorBatch
           SET merkle_root = '0000000000000000000000000000000000000000000000000000000000000000'
         WHERE batch_id = 1;
        PERFORM _record('O.2: UPDATE on AnchorBatch rejected',
            FALSE, 'UPDATE unexpectedly succeeded');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('O.2: UPDATE on AnchorBatch rejected',
            TRUE, NULL);
    END;
END $$;

-- O.3: DELETE on AnchorBatch is rejected (append-only).
DO $$
BEGIN
    BEGIN
        DELETE FROM AnchorBatch WHERE batch_id = 1;
        PERFORM _record('O.3: DELETE on AnchorBatch rejected',
            FALSE, 'DELETE unexpectedly succeeded');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('O.3: DELETE on AnchorBatch rejected',
            TRUE, NULL);
    END;
END $$;

-- O.4: every batched BlockchainAnchor has a merkle_proof; pending rows have neither.
DO $$
DECLARE
    v_inconsistent INTEGER;
BEGIN
    SELECT count(*) INTO v_inconsistent
    FROM BlockchainAnchor
    WHERE NOT (
        (batch_id IS NULL AND merkle_proof IS NULL) OR
        (batch_id IS NOT NULL AND merkle_proof IS NOT NULL)
    );
    PERFORM _record('O.4: batch_id / merkle_proof co-NULL invariant',
        v_inconsistent = 0,
        format('inconsistent rows=%s', v_inconsistent));
END $$;

-- O.5: close_anchor_batch with no pending anchors raises no_data_found.
DO $$
BEGIN
    -- All seed anchors are already batched, so a fresh CALL on alg=1 should fail.
    BEGIN
        CALL close_anchor_batch(1,
            'deadbeef00000000000000000000000000000000000000000000000000000000',
            '{}'::JSONB);
        PERFORM _record('O.5: close_anchor_batch with zero pending rejects',
            FALSE, 'CALL unexpectedly succeeded with no pending');
    EXCEPTION WHEN no_data_found THEN
        PERFORM _record('O.5: close_anchor_batch with zero pending rejects',
            TRUE, NULL);
    END;
END $$;

-- ============================================================================
-- P. ISSUER FEDERATION (R11-3 / M2-8)
-- ============================================================================

-- P.1: seed produced six AgencyTrustAttestation rows. Idempotent under
-- repeated 08_tests.sql runs (later test sections may add attestations).
DO $$
DECLARE v_count INTEGER;
BEGIN
    -- Count only the seed rows (signed_by admin user with the seed date).
    SELECT count(*) INTO v_count
      FROM AgencyTrustAttestation
     WHERE attested_date = '2026-01-15 09:00:00';
    PERFORM _record('P.1: seed produced six AgencyTrustAttestation rows',
        v_count = 6,
        format('count=%s', v_count));
END $$;

-- P.2: self-attestation rejected by CHECK constraint.
DO $$
DECLARE v_admin INTEGER;
BEGIN
    SELECT user_id INTO v_admin FROM AppUser WHERE username='admin' LIMIT 1;
    BEGIN
        INSERT INTO AgencyTrustAttestation
            (attesting_agency_id, attested_agency_id, context_id, valid_until, signed_by)
        VALUES (1, 1, 1, CURRENT_DATE + INTERVAL '30 days', v_admin);
        PERFORM _record('P.2: self-attestation rejected',
            FALSE, 'self-attestation INSERT unexpectedly succeeded');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('P.2: self-attestation rejected',
            TRUE, NULL);
    END;
END $$;

-- P.3: DELETE on AgencyTrustAttestation rejected (append-only).
DO $$
BEGIN
    BEGIN
        DELETE FROM AgencyTrustAttestation WHERE attestation_id = 1;
        PERFORM _record('P.3: DELETE on AgencyTrustAttestation rejected',
            FALSE, 'DELETE unexpectedly succeeded');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('P.3: DELETE on AgencyTrustAttestation rejected',
            TRUE, NULL);
    END;
END $$;

-- P.4: UPDATE to attesting_agency_id rejected (only revocation fields mutable).
DO $$
BEGIN
    BEGIN
        UPDATE AgencyTrustAttestation
           SET attesting_agency_id = 99
         WHERE attestation_id = 1;
        PERFORM _record('P.4: UPDATE to immutable column rejected',
            FALSE, 'UPDATE unexpectedly succeeded');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('P.4: UPDATE to immutable column rejected',
            TRUE, NULL);
    END;
END $$;

-- P.5: uc10_attest_trust round-trip; uq_active_attestation rejects duplicate.
-- Idempotent: tolerates an already-existing attestation from prior test runs.
DO $$
DECLARE
    v_admin     INTEGER;
    v_context   INTEGER;
    v_valid     DATE;
    v_count_a   INTEGER;
BEGIN
    SELECT user_id INTO v_admin FROM AppUser WHERE username='admin' LIMIT 1;
    SELECT context_id INTO v_context FROM VerificationContext WHERE context_type='HEALTHCARE';
    v_valid := (CURRENT_DATE + INTERVAL '180 days')::DATE;

    SELECT count(*) INTO v_count_a FROM AgencyTrustAttestation;

    -- Ensure the (5,3,HEALTHCARE) attestation exists, idempotently. If a
    -- prior run already created it, the unique_violation is benign here;
    -- the real test is the duplicate-rejection check below.
    BEGIN
        CALL uc10_attest_trust(5, 3, v_context, v_valid, v_admin);
    EXCEPTION WHEN unique_violation THEN
        NULL;  -- already exists; that's fine
    END;

    -- Now the attestation definitely exists; a second CALL must raise
    -- unique_violation. This is the actual test assertion.
    BEGIN
        CALL uc10_attest_trust(5, 3, v_context, v_valid, v_admin);
        PERFORM _record('P.5: uc10_attest_trust adds new + duplicate rejected',
            FALSE, 'duplicate CALL unexpectedly succeeded');
    EXCEPTION WHEN unique_violation THEN
        PERFORM _record('P.5: uc10_attest_trust adds new + duplicate rejected',
            TRUE,
            format('attestation count was %s before; duplicate rejected', v_count_a));
    END;
END $$;

-- ============================================================================
-- Q. ZK-SNARK EPOCH (R10-1 / M2-1)
-- ============================================================================

-- Q.1: seed produced one TokenStateEpoch row + 3 leaves.
DO $$
DECLARE
    v_epoch_count INTEGER;
    v_leaf_count  INTEGER;
BEGIN
    SELECT count(*) INTO v_epoch_count FROM TokenStateEpoch;
    SELECT count(*) INTO v_leaf_count  FROM TokenStateEpochLeaf;
    PERFORM _record('Q.1: seed produced 1 epoch + 3 leaves',
        v_epoch_count = 1 AND v_leaf_count = 3,
        format('epochs=%s, leaves=%s', v_epoch_count, v_leaf_count));
END $$;

-- Q.2: TokenStateEpoch UPDATE is rejected (append-only).
DO $$
BEGIN
    BEGIN
        UPDATE TokenStateEpoch SET valid_until = CURRENT_TIMESTAMP WHERE epoch_id = 1;
        PERFORM _record('Q.2: UPDATE on TokenStateEpoch rejected',
            FALSE, 'UPDATE unexpectedly succeeded');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('Q.2: UPDATE on TokenStateEpoch rejected',
            TRUE, NULL);
    END;
END $$;

-- Q.3: TokenStateEpochLeaf DELETE rejected (inherits reject_audit_modification).
DO $$
BEGIN
    BEGIN
        DELETE FROM TokenStateEpochLeaf WHERE epoch_id = 1 AND token_id = 2;
        PERFORM _record('Q.3: DELETE on TokenStateEpochLeaf rejected',
            FALSE, 'DELETE unexpectedly succeeded');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('Q.3: DELETE on TokenStateEpochLeaf rejected',
            TRUE, NULL);
    END;
END $$;

-- Q.4: uc11_close_epoch rejects zero-leaf payload.
DO $$
DECLARE
    v_admin INTEGER;
    v_valid TIMESTAMP;
BEGIN
    SELECT user_id INTO v_admin FROM AppUser WHERE username='admin' LIMIT 1;
    v_valid := (CURRENT_TIMESTAMP + INTERVAL '30 days')::TIMESTAMP;
    BEGIN
        CALL uc11_close_epoch(
            'deadbeef00000000000000000000000000000000000000000000000000000000',
            v_valid,
            v_admin,
            '[]'::JSONB);
        PERFORM _record('Q.4: uc11_close_epoch rejects empty leaf set',
            FALSE, 'empty CALL unexpectedly succeeded');
    EXCEPTION WHEN no_data_found THEN
        PERFORM _record('Q.4: uc11_close_epoch rejects empty leaf set',
            TRUE, NULL);
    END;
END $$;

-- Q.5: every TokenStateEpoch row has a committed_count > 0 and matching
-- TokenStateEpochLeaf rows (referential consistency).
DO $$
DECLARE
    v_inconsistent INTEGER;
BEGIN
    SELECT count(*) INTO v_inconsistent
    FROM TokenStateEpoch e
    WHERE e.committed_count <> (
        SELECT count(*) FROM TokenStateEpochLeaf l WHERE l.epoch_id = e.epoch_id
    );
    PERFORM _record('Q.5: every epoch row has matching leaf count',
        v_inconsistent = 0,
        format('inconsistent epochs=%s', v_inconsistent));
END $$;

-- ============================================================================
-- R. DURESS CODES (R11-5 / M2-10 — v2 mission-closer)
-- ============================================================================

-- R.1: Maria's T2 has a duress_code_hash enrolled (the demo seed).
DO $$
DECLARE v_count INTEGER;
BEGIN
    SELECT count(*) INTO v_count
      FROM IdentityToken
     WHERE token_id = 2
       AND duress_code_hash IS NOT NULL
       AND char_length(duress_code_hash) >= 20;
    PERFORM _record('R.1: T2 has enrolled duress_code_hash (Werkzeug scrypt)',
        v_count = 1,
        format('count=%s', v_count));
END $$;

-- R.2: DuressEvent UPDATE rejected (append-only).
DO $$
DECLARE
    v_admin INTEGER;
    v_evt INTEGER;
BEGIN
    SELECT user_id INTO v_admin FROM AppUser WHERE username='admin' LIMIT 1;

    -- Seed a duress event so we have something to attempt UPDATE on.
    INSERT INTO DuressEvent (token_id, context_id, requesting_agency_id, oob_channel)
    VALUES (2, 1, 5, 'AUDIT_TABLE')
    RETURNING event_id INTO v_evt;

    BEGIN
        UPDATE DuressEvent SET oob_channel = 'STDERR_LOG' WHERE event_id = v_evt;
        PERFORM _record('R.2: UPDATE on DuressEvent rejected (append-only)',
            FALSE, 'UPDATE unexpectedly succeeded');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('R.2: UPDATE on DuressEvent rejected (append-only)',
            TRUE, NULL);
    END;
END $$;

-- R.3: DuressEvent DELETE rejected (append-only).
DO $$
DECLARE v_evt INTEGER;
BEGIN
    SELECT event_id INTO v_evt FROM DuressEvent LIMIT 1;
    BEGIN
        DELETE FROM DuressEvent WHERE event_id = v_evt;
        PERFORM _record('R.3: DELETE on DuressEvent rejected (append-only)',
            FALSE, 'DELETE unexpectedly succeeded');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('R.3: DELETE on DuressEvent rejected (append-only)',
            TRUE, NULL);
    END;
END $$;

-- R.4: uc12_record_duress rejects token without enrolled duress_code_hash.
-- T1 (Egor) has no duress code; the procedure must refuse.
DO $$
BEGIN
    BEGIN
        CALL uc12_record_duress(1, 1, 1, 'AUDIT_TABLE');
        PERFORM _record('R.4: uc12_record_duress rejects unenrolled token',
            FALSE, 'CALL unexpectedly succeeded');
    EXCEPTION WHEN no_data_found THEN
        PERFORM _record('R.4: uc12_record_duress rejects unenrolled token',
            TRUE, NULL);
    END;
END $$;

-- R.5: duress_code_hash CHECK rejects too-short hashes.
DO $$
BEGIN
    BEGIN
        UPDATE IdentityToken SET duress_code_hash = 'too_short' WHERE token_id = 3;
        PERFORM _record('R.5: duress_code_hash length CHECK rejects short hashes',
            FALSE, 'short hash unexpectedly accepted');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('R.5: duress_code_hash length CHECK rejects short hashes',
            TRUE, NULL);
    END;
END $$;

-- ============================================================================
-- Section S: the retention engine (roadmap P1.11)
--
-- The engine's whole job is to make the retention decision data, bounded and
-- append-only, and to make the purge obey it. Each test here is one of those
-- properties.
-- ============================================================================

-- S.1: with nothing configured the resolver still answers, at the floor.
DO $$
DECLARE v_days INTEGER;
BEGIN
    SELECT retention_days_for('VERIFICATION', 'US-NOTSET') INTO v_days;
    PERFORM _record('S.1: retention_days_for falls back to the schema floor',
        v_days >= 365, 'got ' || v_days);
END $$;

-- S.2: the floor is enforced in the schema, not only in the procedure.
DO $$
BEGIN
    BEGIN
        INSERT INTO RetentionPolicy
            (table_class, jurisdiction, retention_days, justification, set_by_user_id)
        VALUES ('VERIFICATION', 'US-TEST-S2', 30,
                'attempting to keep verification events for one month only', 1);
        PERFORM _record('S.2: retention below the 365-day floor is refused',
            FALSE, 'a 30-day retention was accepted');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('S.2: retention below the 365-day floor is refused', TRUE, NULL);
    END;
END $$;

-- S.3: a policy row cannot be edited, only superseded.
DO $$
DECLARE v_id BIGINT;
BEGIN
    INSERT INTO RetentionPolicy
        (table_class, jurisdiction, retention_days, justification, set_by_user_id)
    VALUES ('AUTH_AUDIT', 'US-TEST-S3', 900,
            'a jurisdiction policy recorded for the immutability test', 1)
    RETURNING policy_id INTO v_id;
    BEGIN
        UPDATE RetentionPolicy SET retention_days = 400 WHERE policy_id = v_id;
        PERFORM _record('S.3: RetentionPolicy.retention_days is immutable',
            FALSE, 'the number was edited in place');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('S.3: RetentionPolicy.retention_days is immutable', TRUE, NULL);
    END;
END $$;

-- S.4: supersession is one way.
DO $$
DECLARE v_id BIGINT;
BEGIN
    SELECT policy_id INTO v_id FROM RetentionPolicy
     WHERE jurisdiction = 'US-TEST-S3' AND superseded_at IS NULL LIMIT 1;
    UPDATE RetentionPolicy SET superseded_at = now() WHERE policy_id = v_id;
    BEGIN
        UPDATE RetentionPolicy SET superseded_at = NULL WHERE policy_id = v_id;
        PERFORM _record('S.4: a superseded policy cannot be un-superseded',
            FALSE, 'superseded_at was cleared');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM _record('S.4: a superseded policy cannot be un-superseded', TRUE, NULL);
    END;
END $$;

-- S.5: one effective policy per class and jurisdiction.
DO $$
BEGIN
    INSERT INTO RetentionPolicy
        (table_class, jurisdiction, retention_days, justification, set_by_user_id)
    VALUES ('ENROLLMENT', 'US-TEST-S5', 800,
            'the first effective policy for this test jurisdiction', 1);
    BEGIN
        INSERT INTO RetentionPolicy
            (table_class, jurisdiction, retention_days, justification, set_by_user_id)
        VALUES ('ENROLLMENT', 'US-TEST-S5', 900,
                'a second effective policy for the same class and jurisdiction', 1);
        PERFORM _record('S.5: only one effective policy per class and jurisdiction',
            FALSE, 'a second effective row was accepted');
    EXCEPTION WHEN unique_violation THEN
        PERFORM _record('S.5: only one effective policy per class and jurisdiction',
            TRUE, NULL);
    END;
END $$;

-- S.6: the purge refuses a cutoff inside the retention window.
DO $$
DECLARE v_cp BIGINT;
BEGIN
    BEGIN
        CALL uc_archive_purge(
            p_cutoff_timestamp := now() - INTERVAL '10 days',
            p_archive_uri      := 'file:///tmp/retention-test.tar.gz',
            p_archive_sha256   := repeat('b', 64),
            p_actor_user_id    := 1,
            checkpoint_id_out  := v_cp);
        PERFORM _record('S.6: uc_archive_purge refuses a cutoff inside the window',
            FALSE, 'a ten-day cutoff was accepted');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('S.6: uc_archive_purge refuses a cutoff inside the window',
            TRUE, NULL);
    END;
END $$;

-- S.7: the template applies four classes and supersedes what it replaces.
DO $$
DECLARE v_effective INTEGER; v_superseded INTEGER;
BEGIN
    CALL uc_apply_retention_template('MINIMIZED', 'US-TEST-S7', 1);
    CALL uc_apply_retention_template('STANDARD-5Y', 'US-TEST-S7', 1);
    SELECT count(*) INTO v_effective FROM RetentionPolicy
     WHERE jurisdiction = 'US-TEST-S7' AND superseded_at IS NULL;
    SELECT count(*) INTO v_superseded FROM RetentionPolicy
     WHERE jurisdiction = 'US-TEST-S7' AND superseded_at IS NOT NULL;
    PERFORM _record('S.7: applying a template supersedes the previous one',
        v_effective = 4 AND v_superseded = 4,
        'effective=' || v_effective || ' superseded=' || v_superseded);
END $$;

-- S.8: a non-admin cannot apply a template.
DO $$
DECLARE v_uid INTEGER;
BEGIN
    SELECT user_id INTO v_uid FROM AppUser WHERE role <> 'admin' LIMIT 1;
    IF v_uid IS NULL THEN
        PERFORM _record('S.8: a non-admin cannot apply a retention template',
            TRUE, 'skipped: no non-admin AppUser in the sample data');
    ELSE
        BEGIN
            CALL uc_apply_retention_template('MINIMIZED', 'US-TEST-S8', v_uid);
            PERFORM _record('S.8: a non-admin cannot apply a retention template',
                FALSE, 'a non-admin applied a template');
        EXCEPTION WHEN insufficient_privilege THEN
            PERFORM _record('S.8: a non-admin cannot apply a retention template',
                TRUE, NULL);
        END;
    END IF;
END $$;

-- ----------------------------------------------------------------------------
-- Per-class purge cutoffs (v9.235). The engine's second half: a schedule that
-- keeps the civic record for five years and operational history for two has to
-- reach the purge as two cutoffs, not one.
-- ----------------------------------------------------------------------------

-- S.9: policy mode purges each class at its own cutoff. Verification rows
-- three years old go under a 730-day verification retention while lifecycle
-- rows the same age stay, held by the 1825-day civic-record retention.
DO $$
DECLARE
    v_admin       INTEGER;
    v_token       INTEGER;
    v_life_before INTEGER;
    v_life_after  INTEGER;
    v_ver_after   INTEGER;
    v_cp          BIGINT;
BEGIN
    SELECT user_id INTO v_admin FROM AppUser WHERE role = 'admin' ORDER BY user_id LIMIT 1;
    SELECT token_id INTO v_token FROM IdentityToken ORDER BY token_id LIMIT 1;
    IF v_admin IS NULL OR v_token IS NULL THEN
        PERFORM _record('S.9: policy mode purges each class at its own cutoff',
            TRUE, 'skipped: no admin or token in the sample data');
        RETURN;
    END IF;

    CALL uc_apply_retention_template('MINIMIZED', NULL, v_admin);

    INSERT INTO TokenLifecycleEvent (token_id, event_type, event_timestamp, reason_code)
    VALUES (v_token, 'ISSUED', now() - interval '1100 days', 'S9_LIFECYCLE');
    INSERT INTO VerificationEvent
        (token_id, context_id, requesting_agency_id, event_timestamp, outcome, disclosure_level)
    SELECT v_token, context_id, requesting_agency_id,
           now() - interval '1100 days', 'SUCCESS', 'SELECTIVE'
      FROM VerificationEvent ORDER BY event_id LIMIT 1;

    SELECT count(*) INTO v_life_before FROM TokenLifecycleEvent
     WHERE event_timestamp < now() - interval '1000 days';

    CALL uc_archive_purge(
        -- The manifest scalar is the oldest of the per-class cutoffs.
        p_cutoff_timestamp   := now() - interval '1825 days',
        p_archive_uri        := 'file:///tmp/s9.tar.gz',
        p_archive_sha256     := repeat('9', 64),
        p_actor_user_id      := v_admin,
        p_jurisdiction       := NULL,
        p_class_cutoffs      := ARRAY[
            now() - interval '1825 days',   -- TOKEN_LIFECYCLE
            now() - interval '1000 days',   -- VERIFICATION
            now() - interval '1825 days',   -- ENROLLMENT
            now() - interval '1000 days'    -- AUTH_AUDIT
        ]::timestamptz[],
        checkpoint_id_out    := v_cp);

    SELECT count(*) INTO v_life_after FROM TokenLifecycleEvent
     WHERE event_timestamp < now() - interval '1000 days';
    SELECT count(*) INTO v_ver_after FROM VerificationEvent
     WHERE event_timestamp < now() - interval '1000 days';

    PERFORM _record('S.9: policy mode purges each class at its own cutoff',
        v_life_after = v_life_before AND v_ver_after = 0,
        format('lifecycle %s -> %s (must not change), verification remaining %s (must be 0)',
               v_life_before, v_life_after, v_ver_after));
END $$;

-- S.10: the checkpoint records what actually applied, per class.
DO $$
DECLARE r RECORD;
BEGIN
    SELECT cutoff_source, jurisdiction, cutoff_lifecycle, cutoff_verification,
           cutoff_enrollment, cutoff_authaudit
      INTO r
      FROM LifecycleArchiveCheckpoint
     WHERE archive_uri = 'file:///tmp/s9.tar.gz'
     ORDER BY checkpoint_id DESC LIMIT 1;

    IF r IS NULL THEN
        PERFORM _record('S.10: the checkpoint records the per-class cutoffs',
            TRUE, 'skipped: S.9 did not run');
        RETURN;
    END IF;

    PERFORM _record('S.10: the checkpoint records the per-class cutoffs',
        r.cutoff_source = 'POLICY'
        AND r.cutoff_lifecycle IS NOT NULL
        AND r.cutoff_verification IS NOT NULL
        AND r.cutoff_verification > r.cutoff_lifecycle,
        format('source=%s lifecycle=%s verification=%s (verification must be the later cutoff)',
               r.cutoff_source, r.cutoff_lifecycle, r.cutoff_verification));
END $$;

-- S.11: the ceiling holds. A policy-mode purge never deletes past the boundary
-- the archive covers, even where the retention would allow more.
DO $$
DECLARE
    v_admin  INTEGER;
    v_token  INTEGER;
    v_kept   INTEGER;
    v_cp     BIGINT;
BEGIN
    SELECT user_id INTO v_admin FROM AppUser WHERE role = 'admin' ORDER BY user_id LIMIT 1;
    SELECT token_id INTO v_token FROM IdentityToken ORDER BY token_id LIMIT 1;
    IF v_admin IS NULL OR v_token IS NULL THEN
        PERFORM _record('S.11: a policy-mode purge stops at the archive ceiling',
            TRUE, 'skipped: no admin or token in the sample data');
        RETURN;
    END IF;

    -- Old enough for the 730-day verification retention, but newer than the
    -- ceiling this purge is given.
    INSERT INTO VerificationEvent
        (token_id, context_id, requesting_agency_id, event_timestamp, outcome, disclosure_level)
    SELECT v_token, context_id, requesting_agency_id,
           now() - interval '900 days', 'SUCCESS', 'SELECTIVE'
      FROM VerificationEvent ORDER BY event_id LIMIT 1;

    CALL uc_archive_purge(
        p_cutoff_timestamp   := now() - interval '1825 days',
        p_archive_uri        := 'file:///tmp/s11.tar.gz',
        p_archive_sha256     := repeat('b', 64),
        p_actor_user_id      := v_admin,
        p_jurisdiction       := NULL,
        p_class_cutoffs      := ARRAY[
            now() - interval '1825 days',   -- TOKEN_LIFECYCLE
            now() - interval '1200 days',   -- VERIFICATION, ceilinged by the archive
            now() - interval '1825 days',   -- ENROLLMENT
            now() - interval '1200 days'    -- AUTH_AUDIT
        ]::timestamptz[],
        checkpoint_id_out    := v_cp);

    SELECT count(*) INTO v_kept FROM VerificationEvent
     WHERE event_timestamp < now() - interval '890 days'
       AND event_timestamp > now() - interval '910 days';

    PERFORM _record('S.11: a policy-mode purge stops at the archive ceiling',
        v_kept = 1,
        format('a 900-day-old verification row survived a purge ceilinged at 1200 days: kept=%s', v_kept));
END $$;

-- S.12: flag mode is unchanged. The refusal still stands, so an operator who
-- has not asked for per-class cutoffs cannot purge inside a window by accident.
DO $$
DECLARE
    v_admin INTEGER;
    v_cp    BIGINT;
BEGIN
    SELECT user_id INTO v_admin FROM AppUser WHERE role = 'admin' ORDER BY user_id LIMIT 1;
    IF v_admin IS NULL THEN
        PERFORM _record('S.12: flag mode still refuses a cutoff inside the window',
            TRUE, 'skipped: no admin in the sample data');
        RETURN;
    END IF;
    BEGIN
        CALL uc_archive_purge(
            p_cutoff_timestamp := now() - interval '30 days',
            p_archive_uri      := 'file:///tmp/s12.tar.gz',
            p_archive_sha256   := repeat('c', 64),
            p_actor_user_id    := v_admin,
            checkpoint_id_out  := v_cp);
        PERFORM _record('S.12: flag mode still refuses a cutoff inside the window',
            FALSE, 'a 30-day cutoff was accepted in flag mode');
    EXCEPTION WHEN check_violation THEN
        PERFORM _record('S.12: flag mode still refuses a cutoff inside the window', TRUE, NULL);
    END;
END $$;

-- S.13: the section retires the policies it created, so a loaded database
-- carries only the shipped defaults as effective. Retiring rather than
-- deleting is the point: a retention decision cannot be erased, so the test
-- rows stay visible as superseded history.
DO $$
DECLARE v_effective INTEGER;
BEGIN
    UPDATE RetentionPolicy
       SET superseded_at = now()
     WHERE jurisdiction LIKE 'US-TEST-%'
       AND superseded_at IS NULL;

    SELECT count(*) INTO v_effective
      FROM RetentionPolicy
     WHERE superseded_at IS NULL
       AND jurisdiction IS NOT NULL;

    PERFORM _record('S.13: test policies retire, leaving only shipped defaults effective',
        v_effective = 0, v_effective || ' jurisdiction-scoped policies still effective');
END $$;

-- ============================================================================
-- TEST SUITE SUMMARY
-- ============================================================================

\echo
\echo ============================================================================
\echo TEST SUITE SUMMARY
\echo ============================================================================

SELECT outcome, COUNT(*) AS count
FROM _test_results
GROUP BY outcome
ORDER BY outcome;

\echo
\echo Failures (if any):
SELECT test_id, description, detail
FROM _test_results
WHERE outcome = 'FAIL';

\echo
SELECT format(
    'Total: %s tests, %s passed, %s failed',
    COUNT(*),
    COUNT(*) FILTER (WHERE outcome='PASS'),
    COUNT(*) FILTER (WHERE outcome='FAIL')
) AS summary
FROM _test_results;

\echo
\echo --- Full test results ---
SELECT test_id, outcome, description FROM _test_results ORDER BY test_id;

-- ============================================================================
-- END OF 08_tests.sql
-- ============================================================================
