-- Reverts 2026-10-06-001. Refuses while anything still uses the set: an authority key
-- registered under it, or a signature recorded under it. Removing the row or the constraint
-- value then would orphan evidence, so the refusal names what to migrate first.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM AuthorityKeyEvent WHERE algorithm = 'Falcon-padded-1024') THEN
        RAISE EXCEPTION '2026-10-06-001 down: an authority key is registered under Falcon-padded-1024; retire and migrate it first';
    END IF;
    IF EXISTS (SELECT 1 FROM TokenSignature s JOIN CryptographicAlgorithm a USING (algorithm_id)
               WHERE a.name = 'Falcon-padded-1024') THEN
        RAISE EXCEPTION '2026-10-06-001 down: a signature is recorded under Falcon-padded-1024; migrate the credentials first';
    END IF;
END$$;

DELETE FROM CryptographicAlgorithm WHERE name = 'Falcon-padded-1024';
ALTER TABLE AuthorityKeyEvent DROP CONSTRAINT IF EXISTS chk_authority_key_algorithm;
ALTER TABLE AuthorityKeyEvent
    ADD CONSTRAINT chk_authority_key_algorithm CHECK (algorithm IN ('ML-DSA-65', 'ML-DSA-87'));
