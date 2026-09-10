-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 10_auth.sql : Seed data for AppUser + AuthAuditLog (+ v2 admin-mediated rows)
--
-- The AppUser + AuthAuditLog DDL now lives in 01_schema.sql (v8.24-fix —
-- promoted there so RecoveryRequest, AgencyTrustAttestation, and
-- TokenStateEpoch can FK to AppUser on a clean-DB initial load). This
-- file is now seed-only — it TRUNCATEs the auth tables and re-inserts
-- the three demo accounts plus the v2 admin-mediated demo rows
-- (RecoveryRequest, AgencyTrustAttestation, TokenStateEpoch +
-- TokenStateEpochLeaf, IdentityToken duress enrollment).
--
-- Design notes:
-- - We DO NOT use PostgreSQL's role/login system for application users. The
--   polaris_app PG role is the sole DB connection identity; application users
--   are rows in AppUser, with passwords hashed via Werkzeug's scrypt.
-- - Three roles: 'admin', 'operator', 'auditor'. Authorization is enforced
--   in the application layer via the @require_role decorator.
-- - Account lockout: 5 failed attempts within 10 minutes locks the account
--   for 15 minutes. Failed login counter resets on a successful login.
-- - TRUNCATE CASCADE makes this file idempotent across re-runs.
-- - v8.97 (Position B WebAuthn-MFA): AppUser gains `webauthn_required_after`
--   (added by migration 2026-05-14-002-operator-webauthn). Seed admin keeps
--   it NULL so dev tests are not time-dependent. Production admin accounts
--   should be created via scripts/polaris-create-operator.sh which sets a
--   30-day deadline by default (per Sanctum §IV.4 architect-recommended
--   resolution). See a recorded decision.
-- ============================================================================

-- TRUNCATE auth tables; CASCADE clears the v2 admin-mediated seed rows
-- (RecoveryRequest, AgencyTrustAttestation, TokenStateEpoch +
-- TokenStateEpochLeaf via signed_by/closed_by_user_id FKs).
TRUNCATE TABLE AuthAuditLog, AppUser RESTART IDENTITY CASCADE;

-- ----------------------------------------------------------------------------
-- Seed three test accounts. Passwords are scrypt hashes of:
--   admin    / Admin@123!    (hash generated via werkzeug)
--   operator / Operator@123! (hash generated via werkzeug)
--   auditor  / Auditor@123!  (hash generated via werkzeug)
-- These are DEVELOPMENT-ONLY credentials. Production deployments must rotate
-- them via the polaris.py CLI (`polaris user-create`, `polaris user-passwd`)
-- or via direct SQL with a freshly-generated hash.
-- ----------------------------------------------------------------------------

INSERT INTO AppUser (username, password_hash, role) VALUES
    ('admin',
     'scrypt:32768:8:1$xpBVtRX9UqF5Ty66$0cee11c89567b0cef1e075cf4ae2dfaeccfd686406d51ab7df1db6de673190ff454f28fea576b9bd0be62d9100a1d3276bbc21b1c58c326640c5126700bfeadd',
     'admin'),
    ('operator',
     'scrypt:32768:8:1$4sRNKl66N1ykoHuB$fd43b1b5b00fdbd6a8c3e098e37e2edfdae7e5b277415b56b02cc6b351f03382c77adbb74fdddfcb1946ceeb348d61f3b9d5edc07f3a1e9a789a9254280fbd01',
     'operator'),
    ('auditor',
     'scrypt:32768:8:1$bIX6L7ow7TwaB9f5$a8b9409f573299825b49f3437148735cad5b4c6797dd3a8b50a859f4fd4c74a2594eacd512bcc3dc274b81fdd284fb09263f6db069e47d31e7e9c41a4727601d',
     'auditor');

-- ----------------------------------------------------------------------------
-- v8.17 / R11-2 / M2-7 — Sample PENDING RecoveryRequest for the
-- /uc9/queue demo. Seeded here (not in 04_data.sql) because the FK
-- requesting_user_id → AppUser needs AppUser rows to exist first;
-- 04_data.sql runs before 10_auth.sql.
--
-- Sample scenario: David Okafor (individual 5) whose T5 was
-- administratively revoked and who is now LAPSED. The operator (user 2)
-- has filed a recovery request that's past its 48h cool-down but no
-- decision has been recorded yet — a perfect queue row for admins to
-- inspect.
--
-- The OOB-channel fields are pre-populated so the demo can exercise
-- the APPROVED path end-to-end. In production these are set by the
-- out-of-band verification processes that happen between phase 1 and
-- phase 2.
-- ----------------------------------------------------------------------------
INSERT INTO RecoveryRequest
    (claimed_individual_id, requested_at, requesting_agency_id,
     requesting_user_id, biometric_verified, sworn_statement_hash,
     witness_agency_id, witness_co_sign_user_id, cooldown_expires_at)
VALUES
    (5,                                                  -- David Okafor
     CURRENT_TIMESTAMP - INTERVAL '50 hours',            -- requested 50h ago
     1,                                                  -- federal issuer
     (SELECT user_id FROM AppUser WHERE username='operator'),
     TRUE,
     '7f3a8e1b4c9d2e5f6a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f',
     3,                                                  -- CA Identity Office witnesses
     -- Witness co-signer is a DISTINCT third party (auditor), not the operator
     -- who requested nor the admin who will approve — the three channels must
     -- be three different actors (witness_differs_from_parties).
     (SELECT user_id FROM AppUser WHERE username='auditor'),
     CURRENT_TIMESTAMP - INTERVAL '2 hours');            -- cool-down past

-- ----------------------------------------------------------------------------
-- v8.22 / R11-3 / M2-8 — Federation trust graph seed (6 attestations).
-- Seeded here (not in 04_data.sql) for the same reason RecoveryRequest
-- is: signed_by → AppUser(user_id) needs AppUser to exist first.
--
-- The graph makes the existing 8 demo verification events explicable
-- through federation rather than implicit hard-coded trust:
--   TSA (Agency 4) accepts TRAVEL tokens issued by federal (1), PA (2),
--     and CA (3) issuers.
--   Bank (Agency 5) accepts BANKING tokens from the same three issuers.
-- No HEALTHCARE attestations: T2 (Maria, CA-issued) is the only token
-- with HEALTHCARE permissions, and HEALTHCARE verifications happen at
-- same-agency (CA) checkpoints in the demo data — same-agency trust
-- is implicit, no attestation row needed.
-- ----------------------------------------------------------------------------
WITH admin_user AS (SELECT user_id FROM AppUser WHERE username='admin')
INSERT INTO AgencyTrustAttestation
    (attesting_agency_id, attested_agency_id, context_id,
     attested_date, valid_until, signed_by)
VALUES
    -- TSA (4) → federal NY (1), TRAVEL
    (4, 1, (SELECT context_id FROM VerificationContext WHERE context_type='TRAVEL'),
     '2026-01-15 09:00:00', '2027-01-15',
     (SELECT user_id FROM admin_user)),
    -- TSA (4) → PA (2), TRAVEL
    (4, 2, (SELECT context_id FROM VerificationContext WHERE context_type='TRAVEL'),
     '2026-01-15 09:00:00', '2027-01-15',
     (SELECT user_id FROM admin_user)),
    -- TSA (4) → CA (3), TRAVEL
    (4, 3, (SELECT context_id FROM VerificationContext WHERE context_type='TRAVEL'),
     '2026-01-15 09:00:00', '2027-01-15',
     (SELECT user_id FROM admin_user)),
    -- Bank (5) → federal NY (1), BANKING
    (5, 1, (SELECT context_id FROM VerificationContext WHERE context_type='BANKING'),
     '2026-01-15 09:00:00', '2027-01-15',
     (SELECT user_id FROM admin_user)),
    -- Bank (5) → PA (2), BANKING
    (5, 2, (SELECT context_id FROM VerificationContext WHERE context_type='BANKING'),
     '2026-01-15 09:00:00', '2027-01-15',
     (SELECT user_id FROM admin_user)),
    -- Bank (5) → CA (3), BANKING
    (5, 3, (SELECT context_id FROM VerificationContext WHERE context_type='BANKING'),
     '2026-01-15 09:00:00', '2027-01-15',
     (SELECT user_id FROM admin_user));

-- ----------------------------------------------------------------------------
-- v8.23 / R10-1 / M2-1 — Demo ZK epoch (1 epoch over the 3 ACTIVE BANKING
-- tokens).
--
-- Pre-computed by polaris_web/zk.py against the Plonky2 Poseidon hasher:
-- the Merkle root is the commitment for an epoch covering T2 (Maria),
-- T3 (James), T4 (Priya) in context_id=1 (BANKING). Per-leaf inclusion
-- proofs are stored verbatim — the prover for token T2 would read its
-- row from TokenStateEpochLeaf, generate a SNARK proof, and the
-- verifier would check it against the Merkle root.
--
-- Regenerated at v9.354 for P9.3. A leaf is now Poseidon(secret || context_id),
-- a commitment the circuit OPENS, rather than the bare SHA3-256 seed it was
-- before; the SHA3-256 derivation became the holder's secret. An epoch closed
-- under the old derivation holds leaves the current circuit cannot open, so
-- published epochs are RE-CLOSED rather than migrated, and this seed is one of
-- them. Regenerate with polaris_web/zk.py's derive_leaf_seed + compute_epoch_leaves.
--
-- Seeded here (not in 04_data.sql) because TokenStateEpoch.closed_by_user_id
-- FKs to AppUser which is created in 10_auth.sql.
-- ----------------------------------------------------------------------------
INSERT INTO TokenStateEpoch
    (merkle_root, valid_from, valid_until, committed_count, closed_at, closed_by_user_id)
VALUES
    ('21117a445f1c449c08cb21d8e845d1101b9b7db0aa8d49c8a3a1609063a5bc72',
     '2026-02-10 12:00:00',
     '2027-02-10 12:00:00',
     3,
     '2026-02-10 12:00:00',
     (SELECT user_id FROM AppUser WHERE username='admin'));

INSERT INTO TokenStateEpochLeaf (epoch_id, token_id, leaf_hash, proof_path)
VALUES
    (1, 2, '59595eeb85b65b9e39c868f20b8d44cd123281c9ec8e81191ef9488177889e4e',
     '["72bcf89bab26df7879f17caabe5195919c8525b4482e282343e25dac6d630377","26c8813a3723ae31bf901ff0823ec4b15fe690e976785e004622ddfedad6b76f","cc4ff1aad14a1ab6cfb201991b58858df20aa362d79a8fde03e58a3241fc9621","5ae05c29f70ae06164dea29dc57c249a5fc056e9bf94fb4642a53cc70c3a7067","442646061a92545147092c2e0db3c18c274d85bff37c7d1640a088afa0ea22f5","ae615bd1c8b5e6e939d497bd349bac86970159fcf0237eb772666f68973505d0","4a61495d1a5f2225038fee8e642a1d5a10fb7dc441f7a8ddc3300d0860125649","e35508e23eed79e9f9c1c446c6429a3cb1a43aa86edac916f5790b8bfce468b7","1629fd0c72d76ffe5a7a0adbf3cf728d27a9f99551d41bd3b389294a1267d32b","4ef1c9572144a23c9e84af352cc04e9597919dee33c6f02c45f41f7935daf1fc","c340117b3fb6f7cc53eaa3e4b119e991f78d331df5717c70412aaf00468f7ec2","c3d3b50aadba6e8de39850f0b6aa1b0d4cd4d9b076acc5e17536c83b5bc78b21","219d838e168925ed168071ee6f8401fbe20458214c9ee38e4c6fd2e9698c6161","7f8f37d821f86f2969c6a1c7aed775c9f8f48845fab14108c55dcf9907a276ec"]'::JSONB),
    (1, 3, '72bcf89bab26df7879f17caabe5195919c8525b4482e282343e25dac6d630377',
     '["59595eeb85b65b9e39c868f20b8d44cd123281c9ec8e81191ef9488177889e4e","26c8813a3723ae31bf901ff0823ec4b15fe690e976785e004622ddfedad6b76f","cc4ff1aad14a1ab6cfb201991b58858df20aa362d79a8fde03e58a3241fc9621","5ae05c29f70ae06164dea29dc57c249a5fc056e9bf94fb4642a53cc70c3a7067","442646061a92545147092c2e0db3c18c274d85bff37c7d1640a088afa0ea22f5","ae615bd1c8b5e6e939d497bd349bac86970159fcf0237eb772666f68973505d0","4a61495d1a5f2225038fee8e642a1d5a10fb7dc441f7a8ddc3300d0860125649","e35508e23eed79e9f9c1c446c6429a3cb1a43aa86edac916f5790b8bfce468b7","1629fd0c72d76ffe5a7a0adbf3cf728d27a9f99551d41bd3b389294a1267d32b","4ef1c9572144a23c9e84af352cc04e9597919dee33c6f02c45f41f7935daf1fc","c340117b3fb6f7cc53eaa3e4b119e991f78d331df5717c70412aaf00468f7ec2","c3d3b50aadba6e8de39850f0b6aa1b0d4cd4d9b076acc5e17536c83b5bc78b21","219d838e168925ed168071ee6f8401fbe20458214c9ee38e4c6fd2e9698c6161","7f8f37d821f86f2969c6a1c7aed775c9f8f48845fab14108c55dcf9907a276ec"]'::JSONB),
    (1, 4, '24e15b85ee8869a9bbd582377b02a767e57a31c21100f95b0f99f9b67ccabe30',
     '["0000000000000000000000000000000000000000000000000000000000000000","9cf86f65954d7b9c14c4d7ea907eb2b9c3a9c6f06e8aa9067e0b98b74be447f5","cc4ff1aad14a1ab6cfb201991b58858df20aa362d79a8fde03e58a3241fc9621","5ae05c29f70ae06164dea29dc57c249a5fc056e9bf94fb4642a53cc70c3a7067","442646061a92545147092c2e0db3c18c274d85bff37c7d1640a088afa0ea22f5","ae615bd1c8b5e6e939d497bd349bac86970159fcf0237eb772666f68973505d0","4a61495d1a5f2225038fee8e642a1d5a10fb7dc441f7a8ddc3300d0860125649","e35508e23eed79e9f9c1c446c6429a3cb1a43aa86edac916f5790b8bfce468b7","1629fd0c72d76ffe5a7a0adbf3cf728d27a9f99551d41bd3b389294a1267d32b","4ef1c9572144a23c9e84af352cc04e9597919dee33c6f02c45f41f7935daf1fc","c340117b3fb6f7cc53eaa3e4b119e991f78d331df5717c70412aaf00468f7ec2","c3d3b50aadba6e8de39850f0b6aa1b0d4cd4d9b076acc5e17536c83b5bc78b21","219d838e168925ed168071ee6f8401fbe20458214c9ee38e4c6fd2e9698c6161","7f8f37d821f86f2969c6a1c7aed775c9f8f48845fab14108c55dcf9907a276ec"]'::JSONB);

-- ----------------------------------------------------------------------------
-- v8.24 / R11-5 / M2-10 — Demo duress-code enrollment.
--
-- Maria's T2 (BANKING-eligible ACTIVE token) gets a demo duress code
-- enrolled. The plaintext code is '911911' — documented here in the
-- reference impl because the seed is a teaching aid. The hash below is
-- the Werkzeug scrypt commitment; the constant-time check_password_hash
-- function validates a typed code against it.
--
-- Seeded here (not in 04_data.sql) for symmetry with the other v8.2x
-- post-load seeds (RecoveryRequest, AgencyTrustAttestation,
-- TokenStateEpoch). No FK to AppUser, but the convention is to keep
-- "advanced feature" enrollment in the auth/admin file.
-- ----------------------------------------------------------------------------
UPDATE IdentityToken
   SET duress_code_hash = 'scrypt:32768:8:1$Fo0c5pSq6RSNmuh6$decd33dc8ee41de9a89dc6b6acf0832df8dec18c6b052374463cf505627749a3924e827fdb3899ee9a3b1527a8d97e8dd0b1def5abed01dca00c94b9fff6df8f'
 WHERE token_id = 2;

-- ============================================================================
-- END OF 10_auth.sql
-- ============================================================================
