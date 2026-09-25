-- 2026-09-24-009: the authority-key register refuses a parameter set it does not accept.
--
-- The sibling of 2026-09-24-008. AuthorityKeyEvent checked the key's form and the event, and
-- not the algorithm, which the trust registry publishes for relying parties to verify under.
-- The CLI's --algorithm choices were the only guard. The register now refuses any other value
-- itself, as 01_schema.sql does for a fresh install. If an existing row violates it, this fails
-- rather than admit it, and that row is the thing to investigate.

ALTER TABLE AuthorityKeyEvent DROP CONSTRAINT IF EXISTS chk_authority_key_algorithm;
ALTER TABLE AuthorityKeyEvent
    ADD CONSTRAINT chk_authority_key_algorithm CHECK (algorithm IN ('ML-DSA-65', 'ML-DSA-87'));
