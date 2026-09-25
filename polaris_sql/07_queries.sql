-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 07_queries.sql : The six relational-algebra queries as SQL SELECT
--
-- Each query is the SQL realization of a relational-algebra expression from
-- report §8. The mapping is mechanical:
--   π (projection)              → SELECT column list
--   σ (selection)                → WHERE clause
--   ⋈ (natural join)             → JOIN ... ON  (PostgreSQL has NATURAL JOIN
--                                    but explicit ON is preferred for clarity
--                                    and because NATURAL JOIN's matching by
--                                    column name is brittle under renames)
--   × (Cartesian product)        → CROSS JOIN  (Q6 self-join)
--   γ (grouped aggregation)      → GROUP BY ... aggregate()  (Q5)
--
-- The queries are wrapped in named CTEs only for documentation; they can
-- each be issued as a single SELECT.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Q1: All Successful Banking Verifications for a Specific Individual
--   Serves UC-7 (warrant-authorized history review), restricted to banking.
--
--   Algebra:
--     π_event_id, event_timestamp, requestor_location (
--       σ_outcome='SUCCESS' ∧ context_type='BANKING' (
--         VerificationEvent ⋈ VerificationContext ⋈
--         (σ_legal_name='James Chen' Individual ⋈ IdentityToken)
--       )
--     )
--
--   Returns 1 row (James Chen's mortgage-application banking SELECTIVE
--   verification at First National Bank). Substituting 'Egor Khaklin'
--   returns zero rows because Egor's token (T1, RESERVE) has produced no
--   verifications.
-- ----------------------------------------------------------------------------

\echo
\echo === Q1: All Successful Banking Verifications for a Specific Individual ===
SELECT  ve.event_id,
        ve.event_timestamp,
        ve.requestor_location
FROM    VerificationEvent ve
JOIN    VerificationContext vc  ON ve.context_id   = vc.context_id
JOIN    IdentityToken       it  ON ve.token_id     = it.token_id
JOIN    Individual          ind ON it.individual_id = ind.individual_id
WHERE   ve.outcome     = 'SUCCESS'
  AND   vc.context_type = 'BANKING'
  AND   ind.legal_name  = 'James Chen'
ORDER BY ve.event_timestamp;

-- ----------------------------------------------------------------------------
-- Q2: Active Tokens Using Post-Quantum Algorithms
--   Inverse of UC-6: returns the cohort that does NOT require migration.
--
--   Algebra:
--     π_token_id, legal_name, name (
--       σ_quantum_resistant=TRUE ∧ status='ACTIVE' (
--         IdentityToken ⋈ Individual ⋈ CryptographicAlgorithm
--       )
--     )
--
--   Expected: T2, T3, T4 (the three ACTIVE tokens, all signed under PQ).
-- ----------------------------------------------------------------------------

\echo
\echo === Q2: Active Tokens Using Post-Quantum Algorithms ===
SELECT  it.token_id,
        ind.legal_name,
        alg.name AS algorithm
FROM    IdentityToken         it
JOIN    Individual            ind ON it.individual_id = ind.individual_id
JOIN    CryptographicAlgorithm alg ON it.algorithm_id  = alg.algorithm_id
WHERE   alg.quantum_resistant = TRUE
  AND   it.status             = 'ACTIVE'
ORDER BY it.token_id;

-- ----------------------------------------------------------------------------
-- Q3: Agencies Authorized to Both Issue and Verify Using ML-DSA-65
--   Drives UC-1 step 1 (the issuing officer's authorization check) for the
--   most-used post-quantum algorithm.
--
--   Algebra:
--     π_name, jurisdiction (
--       σ_name='ML-DSA-65' ∧ authorization_type='BOTH' (
--         CryptographicAlgorithm ⋈ AgencyAlgorithmAuth ⋈ Agency
--       )
--     )
--
--   Expected: Federal issuer (1), PA state issuer (2), CA state issuer (3) —
--   the three agencies with BOTH grants on ML-DSA-65.
-- ----------------------------------------------------------------------------

\echo
\echo === Q3: Agencies Authorized to Both Issue and Verify Using ML-DSA-65 ===
SELECT  ag.name,
        ag.jurisdiction
FROM    CryptographicAlgorithm alg
JOIN    AgencyAlgorithmAuth aaa ON alg.algorithm_id = aaa.algorithm_id
JOIN    Agency              ag  ON aaa.agency_id    = ag.agency_id
WHERE   alg.name             = 'ML-DSA-65'
  AND   aaa.authorization_type = 'BOTH'
ORDER BY ag.agency_id;

-- ----------------------------------------------------------------------------
-- Q4: Device Bindings for All Active Tokens
--   Operational query for verifiers that accept digital presentation.
--
--   Algebra:
--     π_legal_name, device_type, device_fingerprint, status (
--       DeviceBinding ⋈ (σ_status='ACTIVE' IdentityToken) ⋈ Individual
--     )
--
--   The selection σ_status='ACTIVE' attaches to IdentityToken (which has the
--   status column) before the natural join with Individual on individual_id.
--
--   Expected: 5 device bindings on T2, T3, T4 (all active). Bindings on
--   T1 and T5 don't exist in the sample data, so this matches naturally.
-- ----------------------------------------------------------------------------

\echo
\echo === Q4: Device Bindings for All Active Tokens ===
SELECT  ind.legal_name,
        db.device_type,
        db.device_fingerprint,
        db.status
FROM    DeviceBinding   db
JOIN    IdentityToken   it  ON db.token_id        = it.token_id
JOIN    Individual      ind ON it.individual_id   = ind.individual_id
WHERE   it.status = 'ACTIVE'
ORDER BY ind.legal_name, db.device_type;

-- ----------------------------------------------------------------------------
-- Q5: Verification Volume by Context (Aggregate)
--   Drives capacity planning and detects unusual context skew that would
--   suggest verifier abuse.
--
--   Algebra:
--     π_context_type, vol (
--       _context_type γ_COUNT(event_id)→vol (
--         VerificationEvent ⋈ VerificationContext
--       )
--     )
--
--   Expected: BANKING dominates (4 events), then EMPLOYMENT (2), TRAVEL (1),
--   GOVERNMENT_BENEFITS (1).
-- ----------------------------------------------------------------------------

\echo
\echo === Q5: Verification Volume by Context (Aggregate) ===
SELECT  vc.context_type,
        COUNT(ve.event_id) AS vol
FROM    VerificationEvent ve
JOIN    VerificationContext vc ON ve.context_id = vc.context_id
GROUP BY vc.context_type
ORDER BY vol DESC, vc.context_type;

-- ----------------------------------------------------------------------------
-- Q6: Token Succession Lineage (Self-Join on Predecessor)
--   Walks predecessor_token_id one generation back. Returns each currently
--   ACTIVE token paired with its immediate predecessor (if any).
--
--   Algebra:
--     π_T1.token_id, T1.activation_sequence, T2.token_id, T2.status (
--       σ_T1.status='ACTIVE' ∧ T1.predecessor_token_id = T2.token_id (
--         T1 × T2
--       )
--     )
--
--   With the current sample data, no ACTIVE token has a predecessor (the
--   only revoked token, T5, has no successor in the sample). To exercise
--   this query, the test in 08_tests.sql runs UC-4 first to produce a
--   succession chain.
-- ----------------------------------------------------------------------------

\echo
\echo === Q6: Token Succession Lineage (Self-Join on Predecessor) ===
SELECT  t1.token_id          AS current_token,
        t1.activation_sequence,
        t2.token_id          AS predecessor_token,
        t2.status            AS predecessor_status
FROM    IdentityToken t1
CROSS JOIN IdentityToken t2
WHERE   t1.status              = 'ACTIVE'
  AND   t1.predecessor_token_id = t2.token_id
ORDER BY t1.activation_sequence DESC, t1.token_id;

-- ----------------------------------------------------------------------------
-- Bonus query: the inverse of Q2 (the migration cohort, supporting UC-6).
-- Returns ACTIVE tokens signed under deprecated or non-PQ algorithms.
-- With sample data: empty (all sample tokens are PQ-signed).
-- ----------------------------------------------------------------------------

\echo
\echo === UC-6: Algorithm Migration Cohort ===
SELECT  it.token_id,
        ind.legal_name,
        alg.name AS algorithm,
        alg.deprecation_date,
        ag.name  AS issuing_agency
FROM    IdentityToken          it
JOIN    Individual              ind ON it.individual_id    = ind.individual_id
JOIN    CryptographicAlgorithm  alg ON it.algorithm_id     = alg.algorithm_id
JOIN    Agency                  ag  ON it.issuing_agency_id = ag.agency_id
WHERE   it.status = 'ACTIVE'
  AND   (alg.quantum_resistant = FALSE
         OR (alg.deprecation_date IS NOT NULL
             AND alg.deprecation_date < polaris_utc_date() + INTERVAL '24 months'))
ORDER BY alg.deprecation_date NULLS LAST, it.token_id;

-- ============================================================================
-- v8.16 / R11-4 / M2-9 — civic_enrollment_summary
--
-- Per-jurisdiction counts of individuals in each enrollment status.
-- The PDF §9 population-coverage problem asked: "civic queries can answer
-- 'is this person known' without requiring an active token." This function
-- is the schema's answer.
--
-- Returns COUNTS ONLY by (jurisdiction, status). Per-individual enumeration
-- is deliberately NOT a first-class query: an admin who needs it must write
-- the join against IndividualCurrentEnrollment directly, which leaves a
-- trace in AuthAuditLog. The asymmetry is the design — making the
-- aggregate-policy use case frictionless and the per-person enumeration
-- deliberate.
-- ============================================================================

CREATE OR REPLACE FUNCTION civic_enrollment_summary(
    p_jurisdiction VARCHAR(10) DEFAULT NULL  -- NULL = all jurisdictions
)
RETURNS TABLE (
    jurisdiction  VARCHAR(10),
    status        VARCHAR(20),
    n_individuals INTEGER
)
LANGUAGE plpgsql AS $$
BEGIN
    RETURN QUERY
    SELECT  ice.jurisdiction,
            ice.current_status,
            count(*)::INTEGER
    FROM    IndividualCurrentEnrollment ice
    WHERE   (p_jurisdiction IS NULL OR ice.jurisdiction = p_jurisdiction)
    GROUP BY ice.jurisdiction, ice.current_status
    ORDER BY ice.jurisdiction, ice.current_status;
END$$;

COMMENT ON FUNCTION civic_enrollment_summary IS
  'Per-jurisdiction counts of individuals in each enrollment status '
  '(R11-4 / M2-9). Counts only — per-individual enumeration is not a '
  'first-class query. Implements PDF §9 population-coverage civic-query '
  'requirement.';

-- ============================================================================
-- END OF 07_queries.sql
-- 6 relational-algebra queries (Q1-Q6) + 1 bonus migration-cohort query +
-- civic_enrollment_summary (R11-4).
-- ============================================================================
