-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 04_data.sql : Sample data
--
-- Sample data spans every table in the schema. The original v1 baseline
-- was 73 rows across 12 core tables (counted by SQL test A.2 to 76 after
-- v8.16 / R11-4 added 3 demonstrating Individual rows). Newer tables
-- (IssuerDiscretionPolicy v8.15, EnrollmentStatusEvent
-- v8.16) carry their own seed rows on top.
--
-- v1 baseline (counted by A.2): 8 individuals, 6 agencies, 5 algorithms
-- (4 PQ + 1 deprecated classical), 7 contexts, 5 tokens, 9 lifecycle
-- events, 8 verification events, 5 device bindings, 2 blockchain anchors,
-- 1 revocation, 9 authorization grants, 11 permission grants = 76.
-- v8 additions: 2 IssuerDiscretionPolicy
-- overrides (R11-6), plus enrollment events seeded both by the trigger
-- (one NOT_ENROLLED per Individual) and explicitly here (ENROLLED /
-- LAPSED / EXEMPT transitions per R11-4).
--
-- The data is constructed so that every UC and every Q (relational-algebra
-- query) returns a non-empty, plausible result. UC-7 (warrant audit) for
-- legal_name='Adrian Vasquez' returns no rows because that token (T1) is
-- in RESERVE state and has produced no verification events yet; this is
-- intentional and demonstrates the schema's strictness.
-- ============================================================================

-- Wipe before insert. Order matters: junctions first, then records, then the
-- central artifact, then principals (FK-dependency order in reverse).
TRUNCATE TABLE ZkVerificationNonce,
               TokenStateEpochLeaf, TokenStateEpoch,
               AgencyTrustAttestation,
               TokenPermission, AgencyAlgorithmAuth,
               RevocationList,
               BlockchainAnchor, AnchorBatch, DeviceBinding,
               VerificationEvent, TokenLifecycleEvent,
               IdentityToken,
               VerificationContext, CryptographicAlgorithm, Agency, Individual
       RESTART IDENTITY CASCADE;

-- ============================================================================
-- INDIVIDUALS (5 rows)
-- Five enrolled persons across three US states. Birth dates span four
-- decades; enrollment dates are recent (the system began operating in 2026).
-- ============================================================================

INSERT INTO Individual (legal_name, date_of_birth, jurisdiction, enrollment_date) VALUES
    ('Adrian Vasquez', '2005-03-12', 'US-PA', '2026-01-15 09:30:00'),  -- 1
    ('Maria Santos',  '1988-07-22', 'US-CA', '2026-01-22 14:15:00'),  -- 2
    ('James Chen',    '1972-11-04', 'US-NY', '2026-02-03 10:45:00'),  -- 3
    ('Priya Patel',   '1995-05-18', 'US-TX', '2026-02-10 11:00:00'),  -- 4
    ('David Okafor',  '1981-09-07', 'US-FL', '2026-02-18 16:20:00');  -- 5

-- ============================================================================
-- AGENCIES (6 rows)
-- Three issuers (federal + two state) and three verifiers (TSA, a bank, a
-- county health authority). Issuers carry authorization_level=5; verifiers
-- carry lower levels reflecting their narrower scope.
-- ============================================================================

INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level) VALUES
    ('US National Identity Service',     'FEDERAL', 'US',    5),  -- 1: federal issuer
    ('Pennsylvania Identity Bureau',     'STATE',   'US-PA', 5),  -- 2: state issuer
    ('California Identity Office',       'STATE',   'US-CA', 5),  -- 3: state issuer
    ('Transportation Security Admin',    'FEDERAL', 'US',    4),  -- 4: federal verifier (travel)
    ('First National Bank',              'PRIVATE', 'US',    2),  -- 5: private verifier (banking)
    ('Allegheny County Health Auth.',    'COUNTY',  'US-PA', 3);  -- 6: county verifier (healthcare/benefits)

-- ============================================================================
-- CRYPTOGRAPHIC ALGORITHMS (5 rows)
-- Four NIST-finalized post-quantum signing algorithms (FIPS 204 and 205) plus
-- one deprecated classical algorithm retained for migration tracking.
-- ============================================================================

INSERT INTO CryptographicAlgorithm
    (name, family, quantum_resistant, nist_standard,
     security_level_bits, public_key_size, signature_size, deprecation_date)
VALUES
    -- 1: ML-DSA-65, NIST Level 3, the operational default
    ('ML-DSA-65',     'ML-DSA',  TRUE,  'FIPS 204',
     192, 1952, 3309, NULL),
    -- 2: ML-DSA-87, NIST Level 5, used for high-assurance contexts
    ('ML-DSA-87',     'ML-DSA',  TRUE,  'FIPS 204',
     256, 2592, 4627, NULL),
    -- 3: SLH-DSA-128s, hash-based; registered as a diversity hedge, no signer wired (v9.194)
    ('SLH-DSA-128s',  'SLH-DSA', TRUE,  'FIPS 205',
     128,   32, 7856, NULL),
    -- 4: SLH-DSA-256s, hash-based, very high security
    ('SLH-DSA-256s',  'SLH-DSA', TRUE,  'FIPS 205',
     256,   64, 29792, NULL),
    -- 5: ECDSA-P256, classical, DEPRECATED. Retained only so existing
    --    AgencyAlgorithmAuth grants are queryable for migration audit.
    ('ECDSA-P256',    'ECDSA',   FALSE, 'FIPS 186-4 (legacy)',
     128,   64,   72, '2027-12-31');

-- ============================================================================
-- VERIFICATION CONTEXTS (7 rows)
-- All seven contexts from FR-2. Each carries a per-context biometric
-- requirement and minimum security level.
-- ============================================================================

INSERT INTO VerificationContext
    (context_type, description, requires_biometric, min_security_level)
VALUES
    ('BANKING',
     'Financial-institution identity verification for account access and transactions.',
     FALSE, 128),
    ('EMPLOYMENT',
     'Workplace identity verification for I-9 / right-to-work attestation.',
     FALSE, 128),
    ('HEALTHCARE',
     'Patient identification at point of care; HIPAA-scoped.',
     TRUE,  192),
    ('TRAVEL',
     'TSA / CBP identity verification at security checkpoints and border crossings.',
     TRUE,  192),
    ('VOTING',
     'Polling-place identity verification under state election authority.',
     FALSE, 192),
    ('MOTOR_VEHICLE',
     'State DMV verification for license, registration, and traffic enforcement.',
     FALSE, 128),
    ('GOVERNMENT_BENEFITS',
     'Federal or state benefit-program identity verification (SNAP, Medicare, etc.).',
     FALSE, 128);

-- ============================================================================
-- IDENTITY TOKENS (5 rows)
-- One token per individual.
--   T1: Egor — RESERVE (newly provisioned, awaits biometric enrollment)
--   T2: Maria — ACTIVE, signed under ML-DSA-65
--   T3: James — ACTIVE, signed under ML-DSA-87 (high assurance)
--   T4: Priya — ACTIVE, filed under SLH-DSA-128s (registry diversity; no SLH-DSA signer is wired)
--   T5: David — REVOKED (administratively, paperwork irregularity); in RevocationList
-- All five are signed under post-quantum algorithms (none under ECDSA-P256).
-- ============================================================================

INSERT INTO IdentityToken
    (token_value, physical_serial, hardware_model,
     biometric_binding_type, biometric_enrolled_date, enrollment_witness_agency_id, liveness_check_type,
     individual_id, issuing_agency_id, algorithm_id, predecessor_token_id,
     activation_sequence, status, issued_date, activated_date, expiration_date)
VALUES
    -- T1: Egor (RESERVE, no biometric enrollment yet)
    ('TKN-PA-2026-000001', 'SN-PA-001', 'TitanQ-3',
     'NONE',    NULL,             NULL,    NULL,
     1, 2, 1, NULL,
     1, 'RESERVE', '2026-01-15 09:30:00', NULL, '2036-01-15'),
    -- T2: Maria (ACTIVE, IRIS biometric, witnessed by California issuer)
    ('TKN-CA-2026-000002', 'SN-CA-002', 'TitanQ-3',
     'IRIS',    '2026-01-22 14:30:00', 3, 'MULTI_MODAL',
     2, 3, 1, NULL,
     1, 'ACTIVE',  '2026-01-22 14:15:00', '2026-01-22 14:35:00', '2036-01-22'),
    -- T3: James (ACTIVE, FINGERPRINT biometric, ML-DSA-87 for high assurance)
    ('TKN-NY-2026-000003', 'SN-NY-003', 'TitanQ-3 Pro',
     'FINGERPRINT', '2026-02-03 11:00:00', 1, 'ACTIVE_CHALLENGE',
     3, 1, 2, NULL,
     1, 'ACTIVE',  '2026-02-03 10:45:00', '2026-02-03 11:05:00', '2036-02-03'),
    -- T4: Priya (ACTIVE, FACE biometric, SLH-DSA-128s registry row; no SLH-DSA signer)
    ('TKN-TX-2026-000004', 'SN-TX-004', 'TitanQ-3',
     'FACE',    '2026-02-10 11:30:00', 1, 'PASSIVE',
     4, 1, 3, NULL,
     1, 'ACTIVE',  '2026-02-10 11:00:00', '2026-02-10 11:35:00', '2036-02-10'),
    -- T5: David (REVOKED administratively — paperwork irregularity at enrollment)
    ('TKN-FL-2026-000005', 'SN-FL-005', 'TitanQ-3',
     'NONE',    NULL,             NULL,    NULL,
     5, 1, 1, NULL,
     1, 'REVOKED', '2026-02-18 16:20:00', NULL, '2036-02-18');

-- ============================================================================
-- TOKEN LIFECYCLE EVENTS (9 rows)
--   T1: ISSUED only (RESERVE state, never activated)
--   T2-T4: ISSUED + ACTIVATED
--   T5: ISSUED + REVOKED (admin revocation)
-- ============================================================================

INSERT INTO TokenLifecycleEvent (token_id, actor_agency_id, event_type, event_timestamp, reason_code, latitude, longitude) VALUES
    -- T1 (Adrian Vasquez, Pennsylvania): Pittsburgh, PA
    (1, 2, 'ISSUED',    '2026-01-15 09:30:00', 'INITIAL_ENROLLMENT',         40.4406,  -79.9959),
    -- T2 (Maria Santos / California) — Los Angeles, CA
    (2, 3, 'ISSUED',    '2026-01-22 14:15:00', 'INITIAL_ENROLLMENT',         34.0522, -118.2437),
    (2, 3, 'ACTIVATED', '2026-01-22 14:35:00', 'POST_BIOMETRIC_ENROLLMENT',  34.0522, -118.2437),
    -- T3 (James Chen / Federal NY) — New York, NY
    (3, 1, 'ISSUED',    '2026-02-03 10:45:00', 'INITIAL_ENROLLMENT',         40.7128,  -74.0060),
    (3, 1, 'ACTIVATED', '2026-02-03 11:05:00', 'POST_BIOMETRIC_ENROLLMENT',  40.7128,  -74.0060),
    -- T4 (Priya Patel / Federal TX) — Houston, TX
    (4, 1, 'ISSUED',    '2026-02-10 11:00:00', 'INITIAL_ENROLLMENT',         29.7604,  -95.3698),
    (4, 1, 'ACTIVATED', '2026-02-10 11:35:00', 'POST_BIOMETRIC_ENROLLMENT',  29.7604,  -95.3698),
    -- T5 (David Okafor / Federal FL) — Miami, FL
    (5, 1, 'ISSUED',    '2026-02-18 16:20:00', 'INITIAL_ENROLLMENT',         25.7617,  -80.1918),
    (5, 1, 'REVOKED',   '2026-02-19 10:00:00', 'ADMINISTRATIVE_PAPERWORK_ERROR', 25.7617, -80.1918);

-- ============================================================================
-- VERIFICATION EVENTS (8 rows)
-- Spread across four contexts (BANKING, EMPLOYMENT, TRAVEL, GOVERNMENT_BENEFITS)
-- and all three disclosure levels. ZERO_KNOWLEDGE events have token_id=NULL by
-- the disclosure-consistency CHECK constraint.
-- ============================================================================

INSERT INTO VerificationEvent
    (token_id, requesting_agency_id, context_id, event_timestamp,
     outcome, disclosure_level, proof_commitment, requestor_location,
     latitude, longitude)
VALUES
    -- 1: Maria banking, ZERO-KNOWLEDGE — San Francisco, CA
    (NULL, 5, 1, '2026-03-02 10:15:00', 'SUCCESS', 'ZERO_KNOWLEDGE',
     '0xc3f9a44b1d27c08e9a7e1ae3b8bc5e4c2d1f9a3e8b4c7d2e1f5a9b8c4d7e2f1a',
     'San Francisco, CA',                                  37.7749, -122.4194),
    -- 2: Maria employment, SELECTIVE — San Francisco, CA
    (2, 1, 2, '2026-03-05 09:00:00', 'SUCCESS', 'SELECTIVE',
     NULL, 'San Francisco, CA',                            37.7749, -122.4194),
    -- 3: James banking, ZERO-KNOWLEDGE — New York, NY
    (NULL, 5, 1, '2026-03-08 13:45:00', 'SUCCESS', 'ZERO_KNOWLEDGE',
     '0x9f2e8d4c1b7a3e5f9c8b2d1a4e7f6c3b8a5d9e2f1c4b7a3e8d5f9c2b1a4e7f3d',
     'New York, NY',                                       40.7128,  -74.0060),
    -- 4: James travel, FULL — JFK Airport, Queens NY
    (3, 4, 4, '2026-03-12 06:30:00', 'SUCCESS', 'FULL',
     NULL, 'JFK Airport, Terminal 4',                      40.6413,  -73.7781),
    -- 5: James banking, SELECTIVE — New York, NY
    (3, 5, 1, '2026-03-15 14:00:00', 'SUCCESS', 'SELECTIVE',
     NULL, 'New York, NY',                                 40.7128,  -74.0060),
    -- 6: Priya gov_benefits, FULL — Houston, TX
    (4, 6, 7, '2026-03-18 10:30:00', 'SUCCESS', 'FULL',
     NULL, 'Houston, TX',                                  29.7604,  -95.3698),
    -- 7: Priya banking, ZERO-KNOWLEDGE — Houston, TX
    (NULL, 5, 1, '2026-03-20 18:22:00', 'SUCCESS', 'ZERO_KNOWLEDGE',
     '0xa7b2c5d8e1f4a7b2c5d8e1f4a7b2c5d8e1f4a7b2c5d8e1f4a7b2c5d8e1f4a7b2',
     'Houston, TX',                                        29.7604,  -95.3698),
    -- 8: Priya employment, FAILURE / SELECTIVE — Houston, TX
    (4, 1, 2, '2026-03-22 11:15:00', 'FAILURE', 'SELECTIVE',
     NULL, 'Houston, TX',                                  29.7604,  -95.3698);

-- ============================================================================
-- DEVICE BINDINGS (5 rows)
-- T2 has 2 device bindings (phone, watch), T3 has 2 (phone, tablet), T4 has 1
-- (phone). T1 (RESERVE) and T5 (REVOKED) have no device bindings, which is
-- expected — bindings on a non-active token would be a finding.
-- ============================================================================

INSERT INTO DeviceBinding
    (token_id, device_type, device_fingerprint, binding_method,
     authorized_date, expires_date, status)
VALUES
    (2, 'PHONE',  'SE-AAPL-A18-7e3f9a4b1d27c08e9a7e1ae3b8bc5e4c', 'SECURE_ENCLAVE',
     '2026-01-23 10:00:00', '2027-01-23 10:00:00', 'ACTIVE'),
    (2, 'WATCH',  'SE-AAPL-S10-9f2e8d4c1b7a3e5f9c8b2d1a4e7f6c3b', 'SECURE_ENCLAVE',
     '2026-01-25 14:30:00', '2027-01-25 14:30:00', 'ACTIVE'),
    (3, 'PHONE',  'SE-GOOG-T8-a7b2c5d8e1f4a7b2c5d8e1f4a7b2c5d8',  'TITAN_SECURITY',
     '2026-02-04 09:15:00', '2027-02-04 09:15:00', 'ACTIVE'),
    (3, 'TABLET', 'SE-MSFT-S10-d4e7a1c8b5f2e9d6a3c0b7e4f1d8a5c2', 'TRUSTED_PLATFORM_MODULE',
     '2026-02-05 16:45:00', '2027-02-05 16:45:00', 'ACTIVE'),
    (4, 'PHONE',  'SE-AAPL-A19-c8b5f2e9d6a3c0b7e4f1d8a5c2e9d6a3', 'SECURE_ENCLAVE',
     '2026-02-11 12:00:00', '2027-02-11 12:00:00', 'ACTIVE');

-- ============================================================================
-- BLOCKCHAIN ANCHORS (2 rows)
-- T2 anchored on Algorand-PQ, T4 anchored on Hyperledger Indy. T1 (RESERVE)
-- and T5 (REVOKED) cannot be anchored. T3 chose not to anchor (anchoring is
-- optional and represents the alternative trust architecture).
-- ============================================================================

INSERT INTO BlockchainAnchor
    (token_id, did, commitment_hash, ledger_network, anchor_tx_hash, anchored_date, status)
VALUES
    (2,
     'did:polaris:algopq:1z9f2e8d4c1b7a3e5f9c8b2d1a4e7f6c3b8a5d9e2f1c4b7a3e8d5f9c2b1a4e7f3d',
     '0x3f8a2b9c4d1e7f6a3b8c5d2e9f4a7b1c8d5e2f9a4b7c1d8e5f2a9b4c7d1e8f5a',
     'ALGORAND_PQ',
     '0xtx-algopq-2026-01-23-9a7e1ae3b8bc5e4c2d1f9a3e8b4c7d2e1f5a9b8c4d7e2f1a8b3c4d5e',
     '2026-01-23 11:00:00', 'ACTIVE'),
    (4,
     'did:polaris:hlindy:4y7c1d8e5f2a9b4c7d1e8f5a3b8c5d2e9f4a7b1c8d5e2f9a4b7c1d8e5f2a9b4c',
     '0x8e5f2a9b4c7d1e8f5a3b8c5d2e9f4a7b1c8d5e2f9a4b7c1d8e5f2a9b4c7d1e8f',
     'HYPERLEDGER_INDY',
     '0xtx-hlindy-2026-02-11-c2e9d6a3c0b7e4f1d8a5c2e9d6a3c0b7e4f1d8a5c2e9d6a3c0b7e4f1d8a5c2e9',
     '2026-02-11 13:30:00', 'ACTIVE');

-- ============================================================================
-- ANCHOR BATCHES (2 rows, R10-2 / M2-2 / v8.21)
-- Two single-leaf batches demonstrating per-algorithm scoping. The two
-- BlockchainAnchor rows above belong to tokens under different signature
-- algorithms (T2: ML-DSA-65; T4: SLH-DSA-128s), so close_anchor_batch
-- groups them into separate batches.
--
-- Merkle root for each batch is pre-computed by polaris_web/anchoring.py
-- under SHA3-256 (operator-policy default). The empty proof reflects the
-- single-leaf case (the leaf hash is the root).
--
-- committed_to_chain stays FALSE: a batch row is the relational
-- audit-of-record. Pushing to an external PQ-capable ledger is operator
-- discretion, not auto-derived. See docs/design/anchoring.md.
-- ============================================================================

WITH batch_mldsa AS (
    INSERT INTO AnchorBatch (merkle_root, algorithm_id, batch_size, created_at)
    VALUES ('1944806ae3e8a2aa72659d909f7e43fe043714a920491eff05ba0a33e30bc5c8',
            1, 1, '2026-01-23 11:15:00')
    RETURNING batch_id
)
UPDATE BlockchainAnchor a
   SET batch_id     = (SELECT batch_id FROM batch_mldsa),
       merkle_proof = '[]'::JSONB
 WHERE a.token_id = 2;

WITH batch_slhdsa AS (
    INSERT INTO AnchorBatch (merkle_root, algorithm_id, batch_size, created_at)
    VALUES ('852266d0182508a66542d19dcdb8b4a05b18eb19fec1e7020b19842059d0c4c9',
            3, 1, '2026-02-11 13:45:00')
    RETURNING batch_id
)
UPDATE BlockchainAnchor a
   SET batch_id     = (SELECT batch_id FROM batch_slhdsa),
       merkle_proof = '[]'::JSONB
 WHERE a.token_id = 4;

-- ============================================================================
-- REVOCATION LIST (1 row)
-- T5 (David) was administratively revoked. The published_location is the CRL
-- distribution point that verifiers consult for freshness.
-- ============================================================================

INSERT INTO RevocationList
    (token_id, revoked_by_agency_id, revocation_timestamp, effective_date,
     reason_code, published_location)
VALUES
    (5, 1, '2026-02-19 10:00:00', '2026-02-19',
     'ADMINISTRATIVE',
     'https://crl.idtoken.gov/2026/02/T5-revoked.crl');

-- ============================================================================
-- AGENCY-ALGORITHM AUTHORIZATIONS (9 rows)
-- Three issuers (Agencies 1, 2, 3) each carry ISSUE/BOTH grants on the four
-- PQ algorithms; verifiers (4, 5, 6) carry VERIFY-only grants on the algorithms
-- their tokens encounter.
-- ============================================================================

INSERT INTO AgencyAlgorithmAuth (agency_id, algorithm_id, authorization_type, authorized_date) VALUES
    -- Federal issuer (Agency 1) holds BOTH on the two ML-DSA algorithms (the
    -- operational defaults) and ISSUE on the SLH-DSA hedges.
    (1, 1, 'BOTH',   '2026-01-01 00:00:00'),
    (1, 2, 'BOTH',   '2026-01-01 00:00:00'),
    (1, 3, 'ISSUE',  '2026-01-01 00:00:00'),
    -- PA state issuer (Agency 2) holds BOTH on ML-DSA-65 only.
    (2, 1, 'BOTH',   '2026-01-01 00:00:00'),
    -- CA state issuer (Agency 3) holds BOTH on ML-DSA-65 and ISSUE on ML-DSA-87.
    (3, 1, 'BOTH',   '2026-01-01 00:00:00'),
    (3, 2, 'ISSUE',  '2026-01-01 00:00:00'),
    -- TSA (Agency 4) holds VERIFY on the two ML-DSA algorithms (federal-context).
    (4, 1, 'VERIFY', '2026-01-01 00:00:00'),
    (4, 2, 'VERIFY', '2026-01-01 00:00:00'),
    -- Bank (Agency 5) holds VERIFY on ML-DSA-65 (the consumer-facing algorithm).
    (5, 1, 'VERIFY', '2026-01-01 00:00:00');

-- ============================================================================
-- TOKEN PERMISSIONS (11 rows)
-- T1 (RESERVE) and T5 (REVOKED) carry no permissions. T2, T3, T4 carry
-- context-scoped verification rights summing to 11.
-- ============================================================================

INSERT INTO TokenPermission (token_id, context_id, permission_level, granted_date) VALUES
    -- T2 Maria (4 contexts: banking, employment, healthcare, gov_benefits)
    (2, 1, 'VERIFY', '2026-01-22 14:35:00'),  -- BANKING
    (2, 2, 'VERIFY', '2026-01-22 14:35:00'),  -- EMPLOYMENT
    (2, 3, 'VERIFY', '2026-01-22 14:35:00'),  -- HEALTHCARE
    (2, 7, 'VERIFY', '2026-01-22 14:35:00'),  -- GOVERNMENT_BENEFITS
    -- T3 James (4 contexts: banking, employment, travel, motor_vehicle)
    (3, 1, 'VERIFY', '2026-02-03 11:05:00'),  -- BANKING
    (3, 2, 'VERIFY', '2026-02-03 11:05:00'),  -- EMPLOYMENT
    (3, 4, 'FULL',   '2026-02-03 11:05:00'),  -- TRAVEL (FULL because TSA needs full disclosure)
    (3, 6, 'VERIFY', '2026-02-03 11:05:00'),  -- MOTOR_VEHICLE
    -- T4 Priya (3 contexts: banking, employment, gov_benefits)
    (4, 1, 'VERIFY', '2026-02-10 11:35:00'),  -- BANKING
    (4, 2, 'VERIFY', '2026-02-10 11:35:00'),  -- EMPLOYMENT
    (4, 7, 'FULL',   '2026-02-10 11:35:00');  -- GOVERNMENT_BENEFITS


-- ============================================================================
-- ISSUER DISCRETION POLICY OVERRIDES (2 rows — R11-6 / M2-11)
-- Demonstrates the per-agency override mechanism in both directions. Absence
-- of a row for an agency inherits the system-wide defaults (5.00% / 30 days)
-- set in 09_grants.sql via ALTER DATABASE.
-- ============================================================================

INSERT INTO IssuerDiscretionPolicy
    (agency_id, max_revoke_percent, window_days, set_by_admin, justification) VALUES
    -- Federal issuer at higher scale: loosened to 7.00% to accommodate
    -- legitimate large-batch hardware recalls coordinated with FIPS lab.
    (1, 7.00, 30, 'admin',
     'Federal issuer requires elevated cap for coordinated hardware recall workflows'),
    -- County-level issuer: tightened to 3.00% as a defense-in-depth measure
    -- against political-pressure mass revocation at sub-state authority.
    (6, 3.00, 30, 'admin',
     'County authority restricted below default to limit single-county exposure');

-- ============================================================================
-- TIERED ENROLLMENT SAMPLE (R11-4 / M2-9)
--
-- The seed trigger (06_triggers.sql) emits a NOT_ENROLLED event for every
-- Individual row on insert. The original four token-holders need
-- subsequent ENROLLED events recorded so the IndividualCurrentEnrollment
-- view shows them honestly. R11-4 explicitly does NOT auto-derive
-- enrollment from token state — these have to be hand-recorded as the
-- policy events they represent.
--
-- Then three additional Individual rows demonstrate non-ENROLLED states:
-- a newborn (NOT_ENROLLED via seed trigger only), an EXEMPT case, and a
-- LAPSED case.
-- ============================================================================

-- Seed enrollment-state events for the five original Individual rows so
-- the IndividualCurrentEnrollment view reflects them honestly. R11-4
-- explicitly does NOT auto-derive enrollment from token state — these
-- have to be hand-recorded as the policy events they represent.
--
-- Individuals 1-4 (Egor / Maria / James / Priya) have non-terminal
-- tokens → ENROLLED.
-- Individual 5 (David Okafor) was ENROLLED, then his token was
-- administratively revoked → LAPSED.
INSERT INTO EnrollmentStatusEvent
    (individual_id, status, transition_reason, recorded_by_agency_id, notes) VALUES
    (1, 'ENROLLED', 'TOKEN_ISSUED',       2, 'Egor enrolled at PA Identity Bureau (T1 RESERVE).'),
    (2, 'ENROLLED', 'TOKEN_ISSUED',       3, 'Maria enrolled at CA Identity Office (T2 ACTIVE).'),
    (3, 'ENROLLED', 'TOKEN_ISSUED',       1, 'James enrolled at Federal Identity Service (T3 ACTIVE).'),
    (4, 'ENROLLED', 'TOKEN_ISSUED',       1, 'Priya enrolled at Federal Identity Service (T4 ACTIVE).'),
    (5, 'ENROLLED', 'TOKEN_ISSUED',       1, 'David enrolled at Federal Identity Service (T5).'),
    (5, 'LAPSED',   'TOKEN_REVOKED_ADMIN', 1, 'David lapsed after T5 administratively revoked.');

INSERT INTO Individual (legal_name, date_of_birth, jurisdiction) VALUES
    ('Newborn Sample',        '2026-04-15', 'US-PA'),
    ('Exempt Sample',         '1955-03-20', 'US-CA'),
    ('Lapsed Sample',         '1980-08-12', 'US-NY');

-- The Exempt-Sample individual: civic policy recognition recorded. This is
-- the positive-vocabulary "civic participant without token" case the PDF §9
-- second clause names.
INSERT INTO EnrollmentStatusEvent
    (individual_id, status, transition_reason, recorded_by_agency_id, notes) VALUES
    ((SELECT individual_id FROM Individual WHERE legal_name='Exempt Sample'),
     'EXEMPT', 'BIOMETRIC_INCOMPATIBILITY', 3,
     'Sample row demonstrating EXEMPT — recognized civic participation '
     'without token under local policy review.');

-- The Lapsed-Sample individual: prior enrollment, now lapsed by policy
-- event (not by token state). Both events are recorded so the state
-- machine is exercised.
INSERT INTO EnrollmentStatusEvent
    (individual_id, status, transition_reason, recorded_by_agency_id, notes) VALUES
    ((SELECT individual_id FROM Individual WHERE legal_name='Lapsed Sample'),
     'ENROLLED', 'HISTORICAL_ENROLLMENT', 1,
     'Sample seed of prior ENROLLED state.'),
    ((SELECT individual_id FROM Individual WHERE legal_name='Lapsed Sample'),
     'LAPSED', 'TOKEN_EXPIRED_NOT_RENEWED', 1,
     'Sample LAPSED transition for state-machine demonstration.');

-- ============================================================================
-- TOKEN SIGNATURE BACKFILL (R11-1 / M2-6)
--
-- Every IdentityToken needs ≥ 1 active TokenSignature row. The v1 sample
-- tokens were inserted before the TokenSignature table existed, so we
-- backfill them here. The signature_bytes are placeholders tagged
-- `BACKFILL_PLACEHOLDER` so test code can distinguish them from real
-- signatures that future production deployments would generate via
-- hardware-attested signing.
--
-- The algorithm_id matches each token's IdentityToken.algorithm_id —
-- the "originally issued under" algorithm. This preserves the v1
-- one-signature-per-token assumption; future UC-6 migrations would add
-- additional rows.
-- ============================================================================
INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, signed_at)
SELECT t.token_id, t.algorithm_id,
       ('BACKFILL_PLACEHOLDER_' || t.token_id::TEXT)::BYTEA,
       t.issued_date
FROM IdentityToken t
ORDER BY t.token_id;

-- ============================================================================
-- ----------------------------------------------------------------------------
-- Retention policy (roadmap P1.11): the shipped default, so a fresh database
-- has a recorded, justified retention decision rather than none. Five years
-- for every class, which is the floor the operator runbook documents. An
-- operator replaces it with `uc_apply_retention_template` or a policy row of
-- their own; both append, so this row survives as the starting point.
-- ----------------------------------------------------------------------------
-- Guarded, so that re-running this file (the test harness reloads it between
-- tests) leaves an existing decision alone. A retention decision is an audit
-- of record: sample data must not overwrite one.
INSERT INTO RetentionPolicy
    (table_class, jurisdiction, retention_days, justification, set_by_user_id)
SELECT c.class, NULL, 1825, c.why, 1
  FROM (VALUES
    ('TOKEN_LIFECYCLE',
     'Shipped default (STANDARD-5Y): the token lifecycle is the civic record and is kept five years.'),
    ('ENROLLMENT',
     'Shipped default (STANDARD-5Y): enrolment status is the civic record and is kept five years.'),
    ('VERIFICATION',
     'Shipped default (STANDARD-5Y): five years, replaceable by a decision recorded for the jurisdiction.'),
    ('AUTH_AUDIT',
     'Shipped default (STANDARD-5Y): five years, replaceable by a decision recorded for the jurisdiction.')
  ) AS c(class, why)
 WHERE NOT EXISTS (
        SELECT 1 FROM RetentionPolicy rp
         WHERE rp.table_class = c.class
           AND rp.jurisdiction IS NULL
           AND rp.superseded_at IS NULL);

-- END OF 04_data.sql
-- Row totals at clean load:
--   8+6+5+7+5+9+8+5+2+1+9+11+3+2+3 = 84 rows across the 15 INSERT-ing
--   tables in this file. (TokenLifecycleEvent has additional rows
--   appended by the auto-audit trigger when sample tokens transition
--   states.)
--
-- EnrollmentStatusEvent row count = 8 trigger-seeded (one per Individual)
-- + 9 explicit (4 ENROLLED for individuals 1-4, ENROLLED+LAPSED for #5,
-- 1 EXEMPT for Exempt Sample, ENROLLED+LAPSED for Lapsed Sample) = 17
-- enrollment events at clean load. See SQL section L for verification.
-- ============================================================================
