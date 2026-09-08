-- ============================================================================
-- 16_athena.sql — Athena: the authority-and-constitution layer (v9.266)
--
-- Athena is a READ-ONLY semantic and provenance layer over the *authority*
-- tables (Agency, AgencyAlgorithmAuth, CryptographicAlgorithm,
-- VerificationContext, AgencyTrustAttestation, RetentionPolicy) plus a
-- first-class, machine-checked model of the constitution: C1-C10 and the
-- Vocation as queryable rows, each linked to the mechanism that enforces it.
--
-- It answers governance questions the tree otherwise answers only by hand:
--   why may this agency issue under this algorithm?   athena_authority_chain
--   what proof/disclosure policy bounds this context?  athena_explain_proof
--   if this algorithm is deprecated, who is affected?  athena_affected_by_algorithm
--   which mechanism enforces this constitutional rule? athena_rule_enforcement
--
-- DESIGN LAW (DEVNOTES/athena-ontology-assessment.md, endorsed):
--   * Athena describes and orchestrates authority; it never manufactures it.
--     Every authority object/edge is a SELECT over an existing table, so it
--     cannot outlive its source. Athena has no independent authority store.
--   * Person-legibility is structurally impossible: NO natural-person object,
--     NO globally linkable subject surrogate, NO edge whose endpoint is a
--     natural person, NO ZK-subject traversal. Athena reads ONLY the authority
--     tables, which contain no person. It never reads Individual,
--     IdentityToken.individual_id, TokenPermission, or VerificationEvent.
--   * Non-sovereign: the database and its constitution remain the source of
--     authority. The one curated state (athena_constitutional_rule /
--     athena_rule_enforcement) is DESCRIPTIVE: a row claiming "C6 enforced by
--     X" is only true because check_athena_rule_enforcement_resolves confirms
--     X exists in the tree. The map is not the territory; a check proves it.
--   * Read-only: no Athena function writes, CALLs a mutating procedure, or is
--     SECURITY DEFINER. Bounded: any function that ever touches an event table
--     inherits the Atlas C8 ceilings (none does in this MVP).
--
-- Five machine-checked invariants gate this file (polaris_checks):
--   check_athena_no_person, check_athena_read_only,
--   check_athena_event_access_bounded, check_athena_non_sovereign,
--   check_athena_rule_enforcement_resolves — each with an adversarial
--   detection test.
--
-- Object-synced (scripts/polaris-migrate.sh --sync-objects), like 11_atlas.sql
-- and 15_ontology.sql: idempotent (CREATE ... IF NOT EXISTS / OR REPLACE,
-- ON CONFLICT upserts). No numbered migration.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Curated state (the ONLY state Athena owns) — descriptive, not authoritative.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS athena_constitutional_rule (
    rule_code   VARCHAR(16)  PRIMARY KEY,
    title       VARCHAR(80)  NOT NULL,
    statement   TEXT         NOT NULL,
    kind        VARCHAR(16)  NOT NULL
                CHECK (kind IN ('CONSTRAINT','VOCATION')),
    -- The tier beneath the vocation (v9.270): CONSTITUTIONAL rules are rights
    -- guarantees; ENGINEERING invariants keep them honest; VOCATION is above
    -- both. Mirrors MISSION.md's Tier column.
    layer       VARCHAR(16),
    source_ref  VARCHAR(160) NOT NULL
);
-- Object-synced: add the column to an already-created table on re-sync.
ALTER TABLE athena_constitutional_rule ADD COLUMN IF NOT EXISTS layer VARCHAR(16);
COMMENT ON TABLE athena_constitutional_rule IS
  'Athena (v9.266): C1-C10 + the Vocation as first-class rows. DESCRIPTIVE '
  'only; it enforces nothing. The mechanisms in athena_rule_enforcement do. '
  'source_ref is provenance (where the rule is written in prose).';

CREATE TABLE IF NOT EXISTS athena_rule_enforcement (
    rule_code       VARCHAR(16)  NOT NULL
                    REFERENCES athena_constitutional_rule(rule_code),
    mechanism_kind  VARCHAR(24)  NOT NULL
                    CHECK (mechanism_kind IN
                      ('TRIGGER','INDEX','CHECK_CONSTRAINT','CHECK_FUNCTION','PROCEDURE')),
    mechanism_name  VARCHAR(120) NOT NULL,
    note            TEXT,
    PRIMARY KEY (rule_code, mechanism_kind, mechanism_name)
);
COMMENT ON TABLE athena_rule_enforcement IS
  'Athena (v9.266): the map from a constitutional rule to the exact live '
  'mechanism (trigger / index / check constraint / check_* / procedure) that '
  'enforces it. check_athena_rule_enforcement_resolves fails the build if any '
  'mechanism_name no longer exists in the tree, closing the prose-drift gap '
  'that meta/constraint-lattice.md has today.';

CREATE TABLE IF NOT EXISTS athena_key_custody (
    driver      VARCHAR(24)  PRIMARY KEY,
    label       VARCHAR(80)  NOT NULL,
    is_hardware BOOLEAN      NOT NULL,
    source_ref  VARCHAR(160) NOT NULL
);
COMMENT ON TABLE athena_key_custody IS
  'Athena (v9.266): the supported signing-key custody drivers as descriptive '
  'reference data (no secrets, no key material). Provenance: polaris_web/custody.py.';

-- ----------------------------------------------------------------------------
-- Seed the curated state (idempotent upserts; safe under object-sync re-runs).
-- ----------------------------------------------------------------------------
INSERT INTO athena_constitutional_rule (rule_code, title, statement, kind, layer, source_ref) VALUES
  ('C1','Audit of record','Every audit table is append-only; issuance, verification, and lifecycle events cannot be modified or deleted after the fact.','CONSTRAINT','CONSTITUTIONAL','MISSION.md C1'),
  ('C2','Zero knowledge','A zero-knowledge verification proves a predicate without revealing the token; a ZERO_KNOWLEDGE event carries no token_id.','CONSTRAINT','CONSTITUTIONAL','MISSION.md C2'),
  ('C3','One identity per person','At most one ACTIVE identity token exists per person at any time.','CONSTRAINT','CONSTITUTIONAL','MISSION.md C3'),
  ('C4','Atomic failed-login counter','The failed-login counter is incremented atomically, closing the lockout-bypass race.','CONSTRAINT','ENGINEERING','MISSION.md C4'),
  ('C5','No inline scripts','The Content-Security-Policy forbids inline scripts; all script is external and integrity-controlled.','CONSTRAINT','ENGINEERING','MISSION.md C5'),
  ('C6','Server-side disclosure','Disclosure level is enforced by the server, not the client; redaction happens before a row leaves the database.','CONSTRAINT','CONSTITUTIONAL','MISSION.md C6'),
  ('C7','No hardcoded cryptography','The cryptographic algorithm is data in CryptographicAlgorithm, not a hardcoded constant; algorithms are agile and deprecable.','CONSTRAINT','ENGINEERING','MISSION.md C7'),
  ('C8','Bounded aggregation','Every /api/atlas/* result set is bounded; there is no unbounded population-aggregation surface.','CONSTRAINT','ENGINEERING','MISSION.md C8'),
  ('C9','Concurrency is tested','Concurrency-sensitive invariants are tested with real threading, not simulated serial execution.','CONSTRAINT','ENGINEERING','MISSION.md C9'),
  ('C10','Identity is not money','Identity tokens are not transferable value; there is no balance, transfer, or settlement surface.','CONSTRAINT','CONSTITUTIONAL','MISSION.md C10'),
  ('VOCATION','Anti-coercion','Above C1-C10: changes toward surveillance, centralized aggregation, or unbounded retention are refused; duress is survivable and its evidence retained.','VOCATION','VOCATION','MISSION.md Vocation')
ON CONFLICT (rule_code) DO UPDATE SET
  title = EXCLUDED.title, statement = EXCLUDED.statement,
  kind = EXCLUDED.kind, layer = EXCLUDED.layer, source_ref = EXCLUDED.source_ref;

INSERT INTO athena_rule_enforcement (rule_code, mechanism_kind, mechanism_name, note) VALUES
  ('C1','TRIGGER','reject_audit_modification','AFTER trigger rejects UPDATE/DELETE on audit tables'),
  ('C1','CHECK_FUNCTION','check_aor_append_only_triggers','pins the append-only audit triggers exist'),
  ('C2','CHECK_CONSTRAINT','chk_disclosure_token_consistency','ZERO_KNOWLEDGE row => token_id IS NULL'),
  ('C2','CHECK_FUNCTION','check_c2_zk_token_null','pins the ZK-null-token invariant'),
  ('C3','INDEX','uq_one_active_per_person','partial UNIQUE index: one ACTIVE token per person'),
  ('C3','CHECK_FUNCTION','check_one_active_token_index','pins the partial unique index exists'),
  ('C4','CHECK_FUNCTION','check_c4_atomic_failed_login','pins the atomic failed-login counter'),
  ('C4','CHECK_CONSTRAINT','chk_appuser_failed_count_nonneg','failed_login_count >= 0'),
  ('C5','CHECK_FUNCTION','check_csp_forbids_unsafe_inline','pins script-src has no unsafe-inline'),
  ('C6','PROCEDURE','uc7_warrant_audit','the disclosure/redaction path: ZK rows redact location server-side'),
  ('C6','CHECK_FUNCTION','check_c6_atlas_redacts_zk_location','pins server-side ZK-location redaction'),
  ('C7','CHECK_FUNCTION','check_crypto_algorithm_is_data','pins algorithms are table rows, not constants'),
  ('C8','CHECK_FUNCTION','check_c8_atlas_caps','pins the bounded Atlas result-set caps'),
  ('C9','CHECK_FUNCTION','check_c9_concurrency_threading','pins concurrency tests use real threads'),
  ('C10','CHECK_FUNCTION','check_c10_no_money_tables','pins there is no money/balance/transfer surface'),
  ('VOCATION','TRIGGER','trg_duress_event_append_only','the duress trail is immutable (append-only)'),
  ('VOCATION','CHECK_FUNCTION','check_coercion_evidence_retained','pins coercion evidence is retained'),
  ('VOCATION','CHECK_FUNCTION','check_duress_alertable','pins duress is alertable')
ON CONFLICT (rule_code, mechanism_kind, mechanism_name) DO UPDATE SET note = EXCLUDED.note;

INSERT INTO athena_key_custody (driver, label, is_hardware, source_ref) VALUES
  ('file','Software key file (dev / low-assurance)',FALSE,'polaris_web/custody.py'),
  ('pkcs11','PKCS#11 HSM (CKM_ML_DSA in hardware)',TRUE,'polaris_web/custody.py'),
  ('awskms','AWS KMS (managed custody)',TRUE,'polaris_web/custody.py')
ON CONFLICT (driver) DO UPDATE SET
  label = EXCLUDED.label, is_hardware = EXCLUDED.is_hardware, source_ref = EXCLUDED.source_ref;

-- ----------------------------------------------------------------------------
-- Object views (all read-only over authority tables; NONE reference a person).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_athena_jurisdiction AS
SELECT j.jurisdiction,
       (SELECT COUNT(*) FROM Agency a WHERE a.jurisdiction = j.jurisdiction) AS agency_count,
       'Agency.jurisdiction'::text AS source
  FROM (SELECT DISTINCT jurisdiction FROM Agency
        UNION
        SELECT DISTINCT jurisdiction FROM RetentionPolicy WHERE jurisdiction IS NOT NULL) j;

CREATE OR REPLACE VIEW v_athena_agency AS
SELECT a.agency_id, a.name, a.agency_type, a.jurisdiction, a.authorization_level,
       'Agency'::text AS source
  FROM Agency a;

CREATE OR REPLACE VIEW v_athena_algorithm AS
SELECT alg.algorithm_id, alg.name, alg.family, alg.quantum_resistant,
       alg.nist_standard, alg.security_level_bits,
       alg.public_key_size, alg.signature_size, alg.deprecation_date,
       (alg.deprecation_date IS NOT NULL AND alg.deprecation_date <= CURRENT_DATE) AS is_deprecated,
       'CryptographicAlgorithm'::text AS source
  FROM CryptographicAlgorithm alg;

CREATE OR REPLACE VIEW v_athena_credential_class AS
SELECT alg.algorithm_id AS class_id, alg.name AS class_name, alg.family,
       alg.quantum_resistant, alg.security_level_bits,
       (alg.deprecation_date IS NOT NULL AND alg.deprecation_date <= CURRENT_DATE) AS is_deprecated,
       COUNT(*) FILTER (WHERE aaa.authorization_type IN ('ISSUE','BOTH')) AS authorized_issuer_count,
       'CryptographicAlgorithm + AgencyAlgorithmAuth'::text AS source
  FROM CryptographicAlgorithm alg
  LEFT JOIN AgencyAlgorithmAuth aaa ON aaa.algorithm_id = alg.algorithm_id
 GROUP BY alg.algorithm_id, alg.name, alg.family, alg.quantum_resistant,
          alg.security_level_bits, alg.deprecation_date;

CREATE OR REPLACE VIEW v_athena_relying_party_class AS
SELECT vc.context_id, vc.context_type, vc.description,
       vc.requires_biometric, vc.min_security_level,
       'VerificationContext'::text AS source
  FROM VerificationContext vc;

CREATE OR REPLACE VIEW v_athena_proof_policy AS
SELECT vc.context_id, vc.context_type,
       vc.min_security_level, vc.requires_biometric,
       'VerificationContext'::text AS source
  FROM VerificationContext vc;

-- Disclosure model as class-level reference (the C6-enforced vocabulary). No
-- token, no person: a policy statement, not a per-verification record.
CREATE OR REPLACE VIEW v_athena_disclosure_policy AS
SELECT d.disclosure_level, d.semantics, d.ordinal,
       'disclosure vocabulary + C6 server-side enforcement'::text AS source
  FROM (VALUES
    ('ZERO_KNOWLEDGE','Predicate proven; no token_id, no location (C2/C6); leaves only an aggregate count.',1),
    ('SELECTIVE','Selected attributes disclosed; C6 server-side redaction.',2),
    ('FULL','Full disclosure; token_id present; C6 server-side.',3)
  ) AS d(disclosure_level, semantics, ordinal);

-- "Current" trust agreements only (revoked/expired excluded). No signer person.
CREATE OR REPLACE VIEW v_athena_trust_agreement AS
SELECT ata.attestation_id,
       ata.attesting_agency_id, aa.name AS attesting_agency_name,
       ata.attested_agency_id,  ab.name AS attested_agency_name,
       ata.context_id, vc.context_type,
       ata.attested_date, ata.valid_until,
       'AgencyTrustAttestation'::text AS source
  FROM AgencyTrustAttestation ata
  JOIN Agency aa ON ata.attesting_agency_id = aa.agency_id
  JOIN Agency ab ON ata.attested_agency_id  = ab.agency_id
  JOIN VerificationContext vc ON ata.context_id = vc.context_id
 WHERE ata.revocation_date IS NULL
   AND ata.valid_until >= CURRENT_DATE;

-- ----------------------------------------------------------------------------
-- Edge views (each a SELECT over an existing table or the curated rule state).
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW v_athena_authorizes AS
SELECT aaa.agency_id, a.name AS agency_name,
       aaa.algorithm_id, alg.name AS algorithm_name,
       aaa.authorization_type, aaa.authorized_date,
       'AgencyAlgorithmAuth'::text AS source
  FROM AgencyAlgorithmAuth aaa
  JOIN Agency a ON aaa.agency_id = a.agency_id
  JOIN CryptographicAlgorithm alg ON aaa.algorithm_id = alg.algorithm_id;

CREATE OR REPLACE VIEW v_athena_may_issue AS
SELECT aaa.agency_id, a.name AS agency_name,
       aaa.algorithm_id AS class_id, alg.name AS class_name,
       'AgencyAlgorithmAuth'::text AS source
  FROM AgencyAlgorithmAuth aaa
  JOIN Agency a ON aaa.agency_id = a.agency_id
  JOIN CryptographicAlgorithm alg ON aaa.algorithm_id = alg.algorithm_id
 WHERE aaa.authorization_type IN ('ISSUE','BOTH');

CREATE OR REPLACE VIEW v_athena_may_request AS
SELECT vc.context_id, vc.context_type, d.disclosure_level,
       'VerificationContext + C6'::text AS source
  FROM VerificationContext vc
 CROSS JOIN (VALUES ('ZERO_KNOWLEDGE'),('SELECTIVE'),('FULL')) AS d(disclosure_level);

CREATE OR REPLACE VIEW v_athena_relies_on AS
SELECT ata.attesting_agency_id AS from_agency_id, aa.name AS from_agency_name,
       ata.attested_agency_id  AS to_agency_id,   ab.name AS to_agency_name,
       ata.context_id, vc.context_type, ata.valid_until,
       'AgencyTrustAttestation'::text AS source
  FROM AgencyTrustAttestation ata
  JOIN Agency aa ON ata.attesting_agency_id = aa.agency_id
  JOIN Agency ab ON ata.attested_agency_id  = ab.agency_id
  JOIN VerificationContext vc ON ata.context_id = vc.context_id
 WHERE ata.revocation_date IS NULL
   AND ata.valid_until >= CURRENT_DATE;

CREATE OR REPLACE VIEW v_athena_constrains AS
SELECT r.rule_code, r.title, r.kind,
       'athena_constitutional_rule'::text AS source
  FROM athena_constitutional_rule r;

CREATE OR REPLACE VIEW v_athena_enforced_by AS
SELECT e.rule_code, r.title, e.mechanism_kind, e.mechanism_name, e.note,
       'athena_rule_enforcement'::text AS source
  FROM athena_rule_enforcement e
  JOIN athena_constitutional_rule r ON e.rule_code = r.rule_code;

-- approved_by reinforces non-sovereignty: a C-rule's authority comes from the
-- constitution (MISSION.md), never from Athena.
CREATE OR REPLACE VIEW v_athena_approved_by AS
SELECT r.rule_code, r.title, r.source_ref AS approved_by,
       'athena_constitutional_rule.source_ref'::text AS source
  FROM athena_constitutional_rule r;

-- supersedes: a deprecated algorithm is superseded by the non-deprecated
-- post-quantum algorithms at or above its security level.
CREATE OR REPLACE VIEW v_athena_supersedes AS
SELECT newer.algorithm_id AS supersedes_algorithm_id, newer.name AS supersedes_name,
       old.algorithm_id   AS superseded_algorithm_id, old.name  AS superseded_name,
       old.family AS superseded_family,
       'CryptographicAlgorithm deprecation'::text AS source
  FROM CryptographicAlgorithm old
  JOIN CryptographicAlgorithm newer
    ON newer.deprecation_date IS NULL
   AND newer.quantum_resistant
   AND newer.security_level_bits >= old.security_level_bits
   AND newer.algorithm_id <> old.algorithm_id
 WHERE old.deprecation_date IS NOT NULL;

-- ----------------------------------------------------------------------------
-- Functions (read-only, STABLE, SECURITY INVOKER, bounded). NONE takes or
-- emits a person; NONE reads an event, token, or individual table.
-- ----------------------------------------------------------------------------

-- Why may agency A issue under algorithm C? Returns the resolved chain; a
-- missing step-3 row means the agency is NOT authorized to issue it.
CREATE OR REPLACE FUNCTION athena_authority_chain(p_agency_id INTEGER, p_algorithm_id INTEGER)
RETURNS TABLE (step INTEGER, relation TEXT, detail TEXT, source TEXT)
LANGUAGE sql STABLE AS $athena_chain$
    SELECT 1, 'agency',
           a.name || ' (' || a.agency_type || ', ' || a.jurisdiction || ')', 'Agency'
      FROM Agency a WHERE a.agency_id = p_agency_id
    UNION ALL
    SELECT 2, 'algorithm',
           alg.name || ' (' || alg.family || ', L' || alg.security_level_bits ||
           CASE WHEN alg.deprecation_date IS NOT NULL AND alg.deprecation_date <= CURRENT_DATE
                THEN ', DEPRECATED' ELSE '' END || ')',
           'CryptographicAlgorithm'
      FROM CryptographicAlgorithm alg WHERE alg.algorithm_id = p_algorithm_id
    UNION ALL
    SELECT 3, 'may_issue',
           'authorization_type=' || aaa.authorization_type ||
           ', granted ' || to_char(aaa.authorized_date,'YYYY-MM-DD'),
           'AgencyAlgorithmAuth'
      FROM AgencyAlgorithmAuth aaa
     WHERE aaa.agency_id = p_agency_id AND aaa.algorithm_id = p_algorithm_id
       AND aaa.authorization_type IN ('ISSUE','BOTH')
    ORDER BY 1
    LIMIT 100;
$athena_chain$;

-- What proof / disclosure policy bounds this verification context?
CREATE OR REPLACE FUNCTION athena_explain_proof(p_context_id INTEGER)
RETURNS TABLE (context_type TEXT, min_security_level INTEGER, requires_biometric BOOLEAN,
               disclosure_level TEXT, disclosure_note TEXT, source TEXT)
LANGUAGE sql STABLE AS $athena_proof$
    SELECT vc.context_type::text, vc.min_security_level, vc.requires_biometric,
           d.disclosure_level, d.semantics,
           'VerificationContext + C6 disclosure'::text
      FROM VerificationContext vc
     CROSS JOIN (VALUES
        ('ZERO_KNOWLEDGE','Predicate proven; no token_id, no location (C2/C6); leaves only an aggregate count.',1),
        ('SELECTIVE','Selected attributes; C6 server-side redaction.',2),
        ('FULL','Full disclosure; token_id present; C6 server-side.',3)
       ) AS d(disclosure_level, semantics, ordinal)
     WHERE vc.context_id = p_context_id
     ORDER BY d.ordinal
     LIMIT 100;
$athena_proof$;

-- Blast radius of deprecating an algorithm. Authority-only: authorized
-- agencies, contexts it currently serves, and its post-quantum successors.
-- No token, signature, or event data (person-linkable; deliberately out of scope).
CREATE OR REPLACE FUNCTION athena_affected_by_algorithm(p_algorithm_id INTEGER)
RETURNS TABLE (impact_kind TEXT, ref_id INTEGER, ref_label TEXT, detail TEXT, source TEXT)
LANGUAGE sql STABLE AS $athena_blast$
    SELECT 'authorized_agency', a.agency_id, a.name,
           'authorization_type=' || aaa.authorization_type, 'AgencyAlgorithmAuth'
      FROM AgencyAlgorithmAuth aaa
      JOIN Agency a ON aaa.agency_id = a.agency_id
     WHERE aaa.algorithm_id = p_algorithm_id
    UNION ALL
    SELECT 'served_context', vc.context_id, vc.context_type,
           'min_security_level=' || vc.min_security_level, 'VerificationContext'
      FROM VerificationContext vc
      JOIN CryptographicAlgorithm alg ON alg.algorithm_id = p_algorithm_id
     WHERE alg.security_level_bits >= vc.min_security_level
    UNION ALL
    SELECT 'successor_algorithm', newer.algorithm_id, newer.name,
           'family=' || newer.family || ', L' || newer.security_level_bits, 'CryptographicAlgorithm'
      FROM CryptographicAlgorithm old
      JOIN CryptographicAlgorithm newer
        ON newer.deprecation_date IS NULL AND newer.quantum_resistant
       AND newer.security_level_bits >= old.security_level_bits
       AND newer.algorithm_id <> old.algorithm_id
     WHERE old.algorithm_id = p_algorithm_id
    ORDER BY 1, 2
    LIMIT 500;
$athena_blast$;

-- Which mechanism enforces a constitutional rule? The honesty layer: every row
-- returned names a mechanism check_athena_rule_enforcement_resolves has proven
-- to exist.
CREATE OR REPLACE FUNCTION athena_rule_enforcement(p_rule_code TEXT)
RETURNS TABLE (rule_code TEXT, title TEXT, statement TEXT,
               mechanism_kind TEXT, mechanism_name TEXT, note TEXT)
LANGUAGE sql STABLE AS $athena_rule$
    SELECT r.rule_code::text, r.title::text, r.statement,
           e.mechanism_kind::text, e.mechanism_name::text, e.note
      FROM athena_constitutional_rule r
      LEFT JOIN athena_rule_enforcement e ON e.rule_code = r.rule_code
     WHERE r.rule_code = upper(p_rule_code)
     ORDER BY e.mechanism_kind, e.mechanism_name
     LIMIT 100;
$athena_rule$;

-- ----------------------------------------------------------------------------
-- Smoke test (runs at file load): every view queryable, every function callable.
-- ----------------------------------------------------------------------------
DO $athena_smoke$
DECLARE n INTEGER; r INTEGER;
BEGIN
    SELECT COUNT(*) INTO n FROM v_athena_jurisdiction;
    SELECT COUNT(*) INTO n FROM v_athena_agency;
    SELECT COUNT(*) INTO n FROM v_athena_algorithm;
    SELECT COUNT(*) INTO n FROM v_athena_credential_class;
    SELECT COUNT(*) INTO n FROM v_athena_relying_party_class;
    SELECT COUNT(*) INTO n FROM v_athena_proof_policy;
    SELECT COUNT(*) INTO n FROM v_athena_disclosure_policy;
    SELECT COUNT(*) INTO n FROM v_athena_trust_agreement;
    SELECT COUNT(*) INTO n FROM v_athena_authorizes;
    SELECT COUNT(*) INTO n FROM v_athena_may_issue;
    SELECT COUNT(*) INTO n FROM v_athena_may_request;
    SELECT COUNT(*) INTO n FROM v_athena_relies_on;
    SELECT COUNT(*) INTO n FROM v_athena_constrains;
    SELECT COUNT(*) INTO n FROM v_athena_enforced_by;
    SELECT COUNT(*) INTO n FROM v_athena_approved_by;
    SELECT COUNT(*) INTO n FROM v_athena_supersedes;
    SELECT COUNT(*) INTO r FROM athena_constitutional_rule;
    PERFORM * FROM athena_authority_chain(
        (SELECT agency_id FROM Agency ORDER BY agency_id LIMIT 1),
        (SELECT algorithm_id FROM CryptographicAlgorithm ORDER BY algorithm_id LIMIT 1));
    PERFORM * FROM athena_explain_proof(
        (SELECT context_id FROM VerificationContext ORDER BY context_id LIMIT 1));
    PERFORM * FROM athena_affected_by_algorithm(
        (SELECT algorithm_id FROM CryptographicAlgorithm ORDER BY algorithm_id LIMIT 1));
    PERFORM * FROM athena_rule_enforcement('C1');
    RAISE NOTICE '16_athena.sql: % constitutional rules, 10 objects + 8 edges (16 views) + 4 functions loaded and smoke-tested.', r;
END;
$athena_smoke$;

-- ============================================================================
-- END OF 16_athena.sql
-- ============================================================================
