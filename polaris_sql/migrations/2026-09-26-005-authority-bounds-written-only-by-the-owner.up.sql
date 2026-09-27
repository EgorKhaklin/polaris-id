-- 2026-09-26-005: the bounds on an authority's own power are the owner's to set.
--
-- As polaris_app, authority 1's revocation bound was superseded and reset to 100% a day, under
-- which uc8_revoke_token never asks for a co-signer. quota-set and discretion-set run as the owner.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT, UPDATE, DELETE ON IssuerDiscretionPolicy FROM polaris_app;
        REVOKE INSERT, UPDATE, DELETE ON AgencyQuota FROM polaris_app;
    END IF;
END$$;
