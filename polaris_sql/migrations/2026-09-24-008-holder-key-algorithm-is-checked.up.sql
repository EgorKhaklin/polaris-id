-- 2026-09-24-008: the holder-key register refuses a parameter set it does not accept.
--
-- HolderKeyEvent checked the key's form and the event, and not the algorithm. The route's
-- allowlist was the only thing keeping a classical holder key out of the register, and no test
-- covered it (the application mutation drill switched it off green). The register now refuses
-- one itself, as 01_schema.sql does for a fresh install. The route has admitted only these two
-- since the register was created, so no existing row violates it; if one does, this fails
-- rather than admit it, and the row is the thing to investigate.

ALTER TABLE HolderKeyEvent DROP CONSTRAINT IF EXISTS chk_holder_key_algorithm;
ALTER TABLE HolderKeyEvent
    ADD CONSTRAINT chk_holder_key_algorithm CHECK (algorithm IN ('ML-DSA-65', 'ML-DSA-87'));
