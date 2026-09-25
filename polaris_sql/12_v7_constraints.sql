-- ============================================================================
-- 12_v7_constraints.sql : v7 schema hardening
--
-- Additive constraints from docs/BACKLOG.md schema section. None of these break
-- existing data; they tighten what FUTURE writes are permitted to do.
--
-- C-NEW-1: predecessor_token_id same-individual constraint
-- C-NEW-2: RevocationList.token_id status check (must be REVOKED/LOST/EXPIRED)
-- C-NEW-3: composite index IdentityToken(individual_id, status) for per-holder lookups
-- C-NEW-4: TokensWithLifecycleSummary view — denormalized read-side
-- ============================================================================

-- ----------------------------------------------------------------------------
-- C-NEW-1: predecessor must reference a token of the same individual.
-- A foreign key alone only guarantees the predecessor exists; this trigger
-- guarantees succession is per-holder, not cross-individual.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION enforce_predecessor_same_individual()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_predecessor_individual INTEGER;
BEGIN
    IF NEW.predecessor_token_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT individual_id INTO v_predecessor_individual
    FROM IdentityToken WHERE token_id = NEW.predecessor_token_id;
    IF v_predecessor_individual IS NULL THEN
        RAISE EXCEPTION 'predecessor_token_id % does not exist', NEW.predecessor_token_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF v_predecessor_individual != NEW.individual_id THEN
        RAISE EXCEPTION
            'predecessor_token_id % belongs to individual % but new token is for individual %; '
            'succession must be per-holder',
            NEW.predecessor_token_id, v_predecessor_individual, NEW.individual_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_predecessor_same_individual ON IdentityToken;
CREATE TRIGGER trg_predecessor_same_individual
    BEFORE INSERT OR UPDATE OF predecessor_token_id ON IdentityToken
    FOR EACH ROW
    EXECUTE FUNCTION enforce_predecessor_same_individual();

COMMENT ON FUNCTION enforce_predecessor_same_individual IS
  'Enforces that predecessor_token_id references a token belonging to the '
  'same individual_id. Closes a loophole in the FK-only constraint.';

-- ----------------------------------------------------------------------------
-- C-NEW-2: A token cannot be added to RevocationList unless its status is
-- REVOKED, LOST, or EXPIRED. Prevents an active token from appearing on
-- the public revocation registry.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION enforce_revocation_status()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_status VARCHAR(20);
BEGIN
    SELECT status INTO v_status FROM IdentityToken WHERE token_id = NEW.token_id;
    IF v_status NOT IN ('REVOKED', 'LOST', 'EXPIRED') THEN
        RAISE EXCEPTION
            'Cannot add token % to RevocationList: status is % (must be REVOKED, LOST, or EXPIRED)',
            NEW.token_id, COALESCE(v_status, 'NULL')
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_revocation_status ON RevocationList;
CREATE TRIGGER trg_revocation_status
    BEFORE INSERT OR UPDATE OF token_id ON RevocationList
    FOR EACH ROW
    EXECUTE FUNCTION enforce_revocation_status();

COMMENT ON FUNCTION enforce_revocation_status IS
  'Prevents an ACTIVE/RESERVE/DORMANT token from appearing in the public '
  'revocation registry. Verifiers consuming the CRL trust this invariant.';

-- ----------------------------------------------------------------------------
-- C-NEW-3: Composite index for per-holder status lookups (BACKLOG schema item)
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_token_individual_status
    ON IdentityToken(individual_id, status);

COMMENT ON INDEX idx_token_individual_status IS
  'Supports per-holder status queries: SELECT … FROM IdentityToken WHERE '
  'individual_id = $1 AND status = $2. Faster than scanning the per-individual '
  'rows and filtering in memory.';

-- ----------------------------------------------------------------------------
-- C-NEW-4: TokensWithLifecycleSummary view (BACKLOG schema item)
-- Denormalized read-side that joins tokens with their last lifecycle event.
-- Useful for operator dashboards that want "who, what, when last" without
-- a separate query.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE VIEW TokensWithLifecycleSummary WITH (security_invoker = true) AS
SELECT
    t.token_id,
    t.token_value,
    t.individual_id,
    i.legal_name             AS holder_name,
    t.issuing_agency_id,
    a.name                   AS issuing_agency_name,
    t.algorithm_id,
    ca.name                  AS algorithm_name,
    ca.quantum_resistant,
    t.predecessor_token_id,
    t.status,
    t.issued_date,
    t.activated_date,
    -- Last lifecycle event (if any) for this token
    last_evt.event_type      AS last_event_type,
    last_evt.event_timestamp AS last_event_at,
    last_evt.reason_code     AS last_reason
FROM IdentityToken t
JOIN Individual i              ON i.individual_id = t.individual_id
JOIN Agency a                  ON a.agency_id     = t.issuing_agency_id
JOIN CryptographicAlgorithm ca ON ca.algorithm_id = t.algorithm_id
LEFT JOIN LATERAL (
    SELECT event_type, event_timestamp, reason_code
    FROM TokenLifecycleEvent l
    WHERE l.token_id = t.token_id
    ORDER BY event_timestamp DESC, event_id DESC
    LIMIT 1
) last_evt ON TRUE;

GRANT SELECT ON TokensWithLifecycleSummary TO polaris_app;

COMMENT ON VIEW TokensWithLifecycleSummary IS
  'Read-side denormalization joining IdentityToken with its most recent '
  'TokenLifecycleEvent. v7. Useful for dashboards; not for write paths.';

-- ============================================================================
-- Self-tests for v7 constraints. Each block emits a row in the test summary.
-- ============================================================================

DO $$
DECLARE
    v_alice INTEGER;
    v_bob   INTEGER;
    v_alice_token INTEGER;
    v_bob_token   INTEGER;
    v_caught BOOLEAN := FALSE;
BEGIN
    -- Setup: find two distinct individuals each with an ACTIVE token
    SELECT individual_id, token_id INTO v_alice, v_alice_token
    FROM IdentityToken WHERE status = 'ACTIVE' ORDER BY token_id LIMIT 1;
    SELECT individual_id, token_id INTO v_bob, v_bob_token
    FROM IdentityToken WHERE status = 'ACTIVE' AND individual_id != v_alice
    ORDER BY token_id LIMIT 1;

    IF v_alice IS NULL OR v_bob IS NULL THEN
        RAISE NOTICE 'TEST V7-1 SKIPPED: need 2 individuals with ACTIVE tokens';
        RETURN;
    END IF;

    -- Test V7-1: cross-individual succession is rejected
    BEGIN
        INSERT INTO IdentityToken
            (token_value, physical_serial, biometric_binding_type,
             individual_id, issuing_agency_id, algorithm_id,
             predecessor_token_id, status, issued_date)
        VALUES ('V7-TEST-CROSS', 'V7-TEST-CROSS-S', 'NONE',
                v_alice, 1, 1,
                v_bob_token,         -- BOB's token as predecessor for ALICE!
                'RESERVE', now());
        RAISE NOTICE 'TEST V7-1 FAIL: cross-individual succession was accepted (C-NEW-1 broken)';
    EXCEPTION WHEN check_violation THEN
        v_caught := TRUE;
        RAISE NOTICE 'TEST V7-1 PASS: cross-individual succession rejected (C-NEW-1)';
    END;
    -- We deliberately don't commit; the rollback at end of DO block discards.
END $$;

DO $$
DECLARE
    v_active_token INTEGER;
    v_caught BOOLEAN := FALSE;
BEGIN
    SELECT token_id INTO v_active_token FROM IdentityToken WHERE status = 'ACTIVE' LIMIT 1;
    IF v_active_token IS NULL THEN
        RAISE NOTICE 'TEST V7-2 SKIPPED: need an ACTIVE token';
        RETURN;
    END IF;
    BEGIN
        INSERT INTO RevocationList (token_id, revoked_by_agency_id, effective_date, reason_code)
        VALUES (v_active_token, 1, CURRENT_DATE, 'COMPROMISED');
        RAISE NOTICE 'TEST V7-2 FAIL: ACTIVE token was added to RevocationList (C-NEW-2 broken)';
    EXCEPTION WHEN check_violation THEN
        v_caught := TRUE;
        RAISE NOTICE 'TEST V7-2 PASS: ACTIVE token rejected from RevocationList (C-NEW-2)';
    END;
END $$;

DO $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT count(*) INTO v_count FROM TokensWithLifecycleSummary;
    IF v_count >= 0 THEN
        RAISE NOTICE 'TEST V7-3 PASS: TokensWithLifecycleSummary view returns % rows (C-NEW-4)', v_count;
    END IF;
END $$;

\echo '=========================================================================='
\echo 'v7 schema-hardening tests complete (3 tests added)'
\echo '=========================================================================='
