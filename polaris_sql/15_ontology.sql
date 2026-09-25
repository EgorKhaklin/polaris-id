-- ============================================================================
-- 15_ontology.sql — Single-entity semantic views over the schema (v9.19,
--                   person-aggregating views removed v9.266 for Athena)
--
-- v9.19 / item 1 from the v9.x reference-architecture study. The schema is
-- the data; the ontology is the *meaning* — typed Objects with typed
-- Properties and typed Links. Operators query the ontology by joining
-- views rather than writing 5-table SQL each time.
--
-- Every view in this file is READ-ONLY over existing tables. No new
-- mutation paths. No GRANT changes (consumers inherit the underlying
-- table grants). No impact on audit-of-record. Pure semantic surface.
--
-- Canonical Objects (mirrors the table tier; one view per noun):
--   v_ontology_token
--   v_ontology_agency
--   v_ontology_verification
--
-- Canonical Link views (one per relationship class):
--   v_ontology_token_timeline   — chronological event union per token
--
-- Vocation alignment (per v9.11 MISSION.md §Vocation): the ontology
-- makes the system MORE legible to auditors, which is anti-coercion-
-- aligned (any operator can audit any decision is easier when the
-- system has a stable semantic vocabulary). The ontology is
-- *single-entity-focused* by construction — there are NO views that
-- aggregate across individuals (the surveillance pattern is
-- constitutionally refused).
--
-- Constitutional contract:
--   - C1 / G1 / G3: read-only; never writes
--   - Audit-of-record: queries are observational only
--   - No cross-entity link analysis (off-vocation per v9.18 study)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- v_ontology_token
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_ontology_token WITH (security_invoker = true) AS
SELECT
    t.token_id,
    t.token_value,
    t.physical_serial,
    t.individual_id,
    t.issuing_agency_id,
    t.algorithm_id,
    t.predecessor_token_id,
    t.activation_sequence,
    t.status,
    t.issued_date,
    t.activated_date,
    t.expiration_date,
    -- Anti-coercion property: does this token have a duress code enrolled?
    (t.duress_code_hash IS NOT NULL) AS has_duress_code,
    -- Computed: age in days
    EXTRACT(EPOCH FROM (NOW() - t.issued_date)) / 86400.0
        AS age_days,
    -- Computed: lifetime event counts
    (SELECT COUNT(*) FROM TokenLifecycleEvent l
      WHERE l.token_id = t.token_id) AS lifecycle_event_count,
    (SELECT COUNT(*) FROM VerificationEvent v
      WHERE v.token_id = t.token_id) AS verification_event_count,
    (SELECT COUNT(*) FROM TokenSignature s
      WHERE s.token_id = t.token_id) AS signature_count,
    -- Linked objects (resolved labels for ontology consumers)
    i.legal_name AS individual_legal_name,
    ag.name      AS issuing_agency_name,
    alg.name     AS algorithm_name,
    alg.quantum_resistant
FROM IdentityToken t
JOIN Individual            i   ON t.individual_id     = i.individual_id
JOIN Agency                ag  ON t.issuing_agency_id = ag.agency_id
JOIN CryptographicAlgorithm alg ON t.algorithm_id     = alg.algorithm_id;

COMMENT ON VIEW v_ontology_token IS
    'v9.19 ontology object: IdentityToken + computed age/event counts + '
    'resolved labels. Has has_duress_code as anti-coercion property. '
    'Single-entity focused; no cross-token aggregation.';

-- ----------------------------------------------------------------------------
-- v_ontology_agency
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_ontology_agency WITH (security_invoker = true) AS
SELECT
    a.agency_id,
    a.name,
    a.agency_type,
    a.jurisdiction,
    a.authorization_level,
    -- Computed: how many tokens this agency has issued (lifetime)
    (SELECT COUNT(*) FROM IdentityToken t
      WHERE t.issuing_agency_id = a.agency_id) AS lifetime_tokens_issued,
    -- Computed: how many of those are still ACTIVE
    (SELECT COUNT(*) FROM IdentityToken t
      WHERE t.issuing_agency_id = a.agency_id
        AND t.status = 'ACTIVE') AS active_tokens_issued,
    -- Computed: trust-attestation activity (revoked = revocation_date IS NOT NULL)
    (SELECT COUNT(*) FROM AgencyTrustAttestation ata
      WHERE ata.attesting_agency_id = a.agency_id
        AND ata.revocation_date IS NULL) AS active_attestations_made,
    (SELECT COUNT(*) FROM AgencyTrustAttestation ata
      WHERE ata.attested_agency_id = a.agency_id
        AND ata.revocation_date IS NULL) AS active_attestations_received
FROM Agency a;

COMMENT ON VIEW v_ontology_agency IS
    'v9.19 ontology object: Agency + lifetime + active token-issuance counts + '
    'trust-attestation activity. Operator-facing read-only summary.';

-- ----------------------------------------------------------------------------
-- v_ontology_verification
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_ontology_verification WITH (security_invoker = true) AS
SELECT
    v.event_id        AS verification_id,
    v.token_id,
    v.requesting_agency_id,
    v.context_id,
    v.event_timestamp,
    v.outcome,
    v.disclosure_level,
    v.proof_commitment,
    v.requestor_location,
    -- Anti-coercion property: ZERO_KNOWLEDGE verifications have NULL token_id
    -- (constitutional C2 invariant) — the ontology surfaces this explicitly
    (v.disclosure_level = 'ZERO_KNOWLEDGE') AS is_zero_knowledge,
    -- Linked-object resolution (only where token_id is non-null)
    t.individual_id,
    vc.context_type,
    rag.name AS requesting_agency_name
FROM VerificationEvent v
LEFT JOIN IdentityToken     t  ON v.token_id            = t.token_id
LEFT JOIN VerificationContext vc ON v.context_id         = vc.context_id
LEFT JOIN Agency           rag  ON v.requesting_agency_id = rag.agency_id;

COMMENT ON VIEW v_ontology_verification IS
    'v9.19 ontology object: VerificationEvent + linked context/agency + '
    'is_zero_knowledge flag (the C2 anti-coercion invariant surfaced).';

-- ----------------------------------------------------------------------------
-- v_ontology_token_timeline — UNIONed chronological events per token
-- ----------------------------------------------------------------------------
-- Foundation for the Object Card investigation page. Returns a single
-- chronologically-ordered timeline of lifecycle + verification events for
-- a given token_id (use WHERE token_id = N at the consumer).
--
-- The schema below intentionally normalizes columns across the two event
-- types so consumers can render a unified table without union'ing at
-- query time. Distinct sources keep their detail via the `detail_jsonb`
-- payload column.
CREATE OR REPLACE VIEW v_ontology_token_timeline WITH (security_invoker = true) AS
SELECT
    'lifecycle'::TEXT      AS event_kind,
    le.event_id,
    le.token_id,
    le.event_timestamp,
    le.event_type          AS event_subtype,
    le.actor_agency_id     AS actor_agency_id,
    NULL::INTEGER          AS requesting_agency_id,
    NULL::VARCHAR(20)      AS verification_outcome,
    NULL::VARCHAR(20)      AS disclosure_level,
    le.reason_code         AS reason_code,
    jsonb_build_object(
        'latitude',  le.latitude,
        'longitude', le.longitude
    )                      AS detail_jsonb
FROM TokenLifecycleEvent le
UNION ALL
SELECT
    'verification'::TEXT   AS event_kind,
    v.event_id,
    v.token_id,
    v.event_timestamp,
    v.disclosure_level     AS event_subtype,
    NULL::INTEGER          AS actor_agency_id,
    v.requesting_agency_id AS requesting_agency_id,
    v.outcome              AS verification_outcome,
    v.disclosure_level     AS disclosure_level,
    NULL::VARCHAR(60)      AS reason_code,
    jsonb_build_object(
        'context_id',       v.context_id,
        'requestor_location', v.requestor_location,
        'proof_commitment',  v.proof_commitment
    )                      AS detail_jsonb
FROM VerificationEvent v;

COMMENT ON VIEW v_ontology_token_timeline IS
    'v9.19 ontology link: chronological union of lifecycle + verification '
    'events per token. Consumer filters by token_id + orders by event_timestamp. '
    'Foundation for the Object Card investigation page.';

-- ----------------------------------------------------------------------------
-- Smoke test (runs at file load)
-- ----------------------------------------------------------------------------
DO $ontology_smoke$
DECLARE
    v_tok_count    INTEGER;
    v_ag_count     INTEGER;
    v_ver_count    INTEGER;
    v_timeline_cnt INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_tok_count    FROM v_ontology_token;
    SELECT COUNT(*) INTO v_ag_count     FROM v_ontology_agency;
    SELECT COUNT(*) INTO v_ver_count    FROM v_ontology_verification;
    SELECT COUNT(*) INTO v_timeline_cnt FROM v_ontology_token_timeline;

    -- The views must be queryable; counts >= 0 by definition (we just
    -- assert no exception was raised). The seed data should produce
    -- positive counts; empty DB is also valid (no assertion failure).
    IF v_tok_count < 0 OR v_ag_count < 0
       OR v_ver_count < 0 OR v_timeline_cnt < 0 THEN
        RAISE EXCEPTION '15_ontology.sql smoke: negative count returned (impossible)';
    END IF;

    RAISE NOTICE '15_ontology.sql: 4 single-entity views loaded + smoke-tested. '
                 'Counts: tokens=%, agencies=%, verifications=%, timeline=%.',
                 v_tok_count, v_ag_count, v_ver_count, v_timeline_cnt;
END;
$ontology_smoke$;

-- ============================================================================
-- END OF 15_ontology.sql
-- ============================================================================
