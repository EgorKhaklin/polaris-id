-- 2026-10-06-001: the FN-DSA family as an experimental signer.
--
-- An authority may register a Falcon-padded-1024 key (round-3 Falcon-1024 with fixed-length
-- signatures, the scheme FN-DSA, draft FIPS 206, standardises), and CryptographicAlgorithm
-- carries the set so a signature under it can be recorded and migrated like any other. Signing
-- under it stays an application decision: polaris_web/custody.py permits it only where
-- POLARIS_EXPERIMENTAL_SIGNERS names it outside POLARIS_ENV=production, because lab record 015
-- measured its signing time depending on the message. Holder keys are unchanged.

ALTER TABLE AuthorityKeyEvent DROP CONSTRAINT IF EXISTS chk_authority_key_algorithm;
ALTER TABLE AuthorityKeyEvent
    ADD CONSTRAINT chk_authority_key_algorithm
    CHECK (algorithm IN ('ML-DSA-65', 'ML-DSA-87', 'Falcon-padded-1024'));

INSERT INTO CryptographicAlgorithm
    (name, family, quantum_resistant, nist_standard,
     security_level_bits, public_key_size, signature_size, deprecation_date)
VALUES ('Falcon-padded-1024', 'FN-DSA', TRUE, 'FIPS 206 (draft)', 256, 1793, 1280, NULL)
ON CONFLICT (name) DO NOTHING;
