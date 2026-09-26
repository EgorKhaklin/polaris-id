-- 2026-09-25-015 down: remove the owner-only guard on IdentityToken's binding columns.

DROP TRIGGER IF EXISTS trg_token_binding_owner_only ON IdentityToken;
DROP FUNCTION IF EXISTS enforce_token_binding_owner_only();
