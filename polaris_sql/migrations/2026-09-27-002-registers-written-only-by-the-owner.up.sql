-- 2026-09-27-002: authority keys, card personalization and retention policy are the owner's to write.
--
-- As the application role: a registered key for an attacker, then made the authority's signing
-- key; an attacker's keys bound to an active credential's card record; a retention policy
-- attributed to an operator, around the admin-only procedure.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT, UPDATE, DELETE ON AuthorityKeyEvent FROM polaris_app;
        REVOKE INSERT, UPDATE, DELETE ON CardPersonalization FROM polaris_app;
        REVOKE INSERT, UPDATE, DELETE ON RetentionPolicy FROM polaris_app;
    END IF;
END$$;
