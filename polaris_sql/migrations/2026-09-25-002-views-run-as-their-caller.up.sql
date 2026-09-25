-- 2026-09-25-002: every view runs as its caller.
--
-- Operator isolation is row-level security: a bound operator's session carries
-- polaris.operator_agency_id and the policies on IdentityToken, VerificationEvent and
-- TokenLifecycleEvent filter every read. A view is evaluated with its OWNER's rights, and RLS on
-- the tables beneath it is applied to the owner, who bypasses it. Measured as polaris_app bound
-- to agency 1: IdentityToken showed 0 rows for agency 3's token 2, v_ontology_token showed it with
-- its 3-event timeline, and v_ontology_verification showed 8 verifications against the table's 2.
-- /investigate/token/<id> reads those views. security_invoker = true makes a view apply the
-- caller's privileges and policies; the application holds SELECT on every table, so nothing
-- else changes. The base files carry the option in every definition, because CREATE OR REPLACE
-- VIEW without it resets it; this sets it on every view a deployed database already has.

DO $$
DECLARE v_view TEXT;
BEGIN
    FOR v_view IN
        SELECT c.relname FROM pg_class c
         WHERE c.relkind = 'v' AND c.relnamespace = 'public'::regnamespace
    LOOP
        EXECUTE format('ALTER VIEW %I SET (security_invoker = true)', v_view);
    END LOOP;
END$$;
