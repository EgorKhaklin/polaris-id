-- 2026-10-04-002: the application role no longer writes TokenSignature (THREAT-MODEL).
--
-- A compromised application could INSERT a signature row for any credential: a keyless row whose
-- bytes are SHA3-256(token_value), or a row under an ML-DSA key of its own. The possession gate
-- (rp_api._possession_authenticated, 2026-10-04) refuses both under real signing because the key
-- has no registration; this removes the write. Every legitimate writer is a SECURITY DEFINER
-- procedure (uc1_issue_and_activate, uc6_migrate_algorithm, uc9_complete_recovery,
-- uc_bulk_issue) or the population migration, which runs as the schema owner
-- (polaris migrate-population; as polaris_app it is refused with exit 3).
--
-- REVOKE: INSERT, UPDATE, DELETE from polaris_app, as 09_grants.sql does after its blanket grant.
-- DELETE and most UPDATEs were already refused by enforce_token_signature_immutability; the
-- privilege now refuses them first, and INSERT, which no trigger refused, for the first time.
--
-- EXPAND/CONTRACT: no application route writes the table, so a release still serving during a
-- rolling deploy is unaffected. An operator who ran migrate-population as the application role
-- runs it as the owner.
-- REVERSIBLE: yes; the down file restores the blanket grant on this table.

REVOKE INSERT, UPDATE, DELETE ON TokenSignature FROM polaris_app;
