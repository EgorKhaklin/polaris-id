-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 03_view.sql : Utility view ActiveTokens
--
-- One view supports the most common operational read pattern: human-readable
-- summaries of every active token with its holder, issuer, and algorithm.
-- Drives UC-6 (algorithm migration audit) and the operational dashboard.
-- ============================================================================

DROP VIEW IF EXISTS ActiveTokens;

CREATE OR REPLACE VIEW ActiveTokens AS
SELECT  t.token_id,
        t.token_value,
        i.legal_name,
        a.name           AS issuing_agency,
        a.jurisdiction   AS agency_jurisdiction,
        alg.name         AS algorithm,
        alg.quantum_resistant,
        alg.deprecation_date,
        t.status,
        t.activated_date,
        t.expiration_date
FROM    IdentityToken         t
JOIN    Individual             i   ON t.individual_id     = i.individual_id
JOIN    Agency                 a   ON t.issuing_agency_id = a.agency_id
JOIN    CryptographicAlgorithm alg ON t.algorithm_id      = alg.algorithm_id
WHERE   t.status = 'ACTIVE';

COMMENT ON VIEW ActiveTokens IS
  'Human-readable summary of every ACTIVE token with its holder, issuer, '
  'and signing algorithm. Joins are inner because every ACTIVE token must '
  'have a valid individual, agency, and algorithm by FK NOT NULL constraint.';

-- ----------------------------------------------------------------------------
-- IndividualCurrentEnrollment (v8.16 / R11-4 / M2-9)
--
-- Per-individual current enrollment status, derived from the latest
-- EnrollmentStatusEvent row. For individuals with zero events (a state
-- impossible under normal operation because the seed trigger fires on
-- INSERT, but possible under direct INSERT bypassing the trigger), the
-- COALESCE materializes 'NOT_ENROLLED' so the schema is honest about the
-- default state.
--
-- This view is the read-side of the enrollment vocabulary: civic queries
-- and operator UIs consult it; the underlying event log is the
-- append-only source of truth.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW IndividualCurrentEnrollment AS
WITH latest AS (
    SELECT DISTINCT ON (individual_id)
           individual_id,
           status,
           transition_reason,
           recorded_by_agency_id,
           event_timestamp
    FROM   EnrollmentStatusEvent
    ORDER BY individual_id, event_timestamp DESC, event_id DESC
)
SELECT  i.individual_id,
        i.legal_name,
        i.jurisdiction,
        COALESCE(l.status, 'NOT_ENROLLED')             AS current_status,
        COALESCE(l.event_timestamp, i.enrollment_date) AS last_status_change,
        l.transition_reason                            AS last_transition_reason,
        l.recorded_by_agency_id                        AS last_recording_agency
FROM    Individual i
LEFT JOIN latest l USING (individual_id);

COMMENT ON VIEW IndividualCurrentEnrollment IS
  'Per-individual current enrollment status (R11-4). The latest '
  'EnrollmentStatusEvent row wins; individuals with no events default to '
  'NOT_ENROLLED via COALESCE — the absence is itself the default, not a '
  'positive flag. Implements PDF §9 population-coverage civic visibility.';

-- P8.7b (v9.328): each authority key's CURRENT status from its append-only events. A key
-- is 'compromised' if any compromised event exists (from the earliest such effective_at),
-- else 'retired' if a retired event exists, else 'active' from its registration.
CREATE OR REPLACE VIEW AuthorityKeyCurrent AS
SELECT  e.agency_id,
        e.public_key_hex,
        MIN(e.algorithm)                                                     AS algorithm,
        CASE WHEN BOOL_OR(e.event = 'compromised') THEN 'compromised'
             WHEN BOOL_OR(e.event = 'retired')     THEN 'retired'
             ELSE 'active' END                                               AS status,
        MIN(e.effective_at) FILTER (WHERE e.event = 'registered')            AS registered_at,
        MIN(e.effective_at) FILTER (WHERE e.event = 'retired')               AS retired_at,
        MIN(e.effective_at) FILTER (WHERE e.event = 'compromised')           AS compromised_at
FROM    AuthorityKeyEvent e
GROUP BY e.agency_id, e.public_key_hex;

COMMENT ON VIEW AuthorityKeyCurrent IS
  'P8.7b per-key current status derived from AuthorityKeyEvent: compromised wins over '
  'retired wins over active, with the instants each took effect. Published by the signed '
  'trust list; read by the federation manifest and the registry.';

