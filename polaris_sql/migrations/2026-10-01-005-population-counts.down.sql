-- 2026-10-01-005 down: drop the population counts, their triggers and routines. The Overview of
-- the release that added them reads PopulationCount, so roll the application back first.
DROP TRIGGER IF EXISTS trg_population_count_signature_truncate ON TokenSignature;
DROP TRIGGER IF EXISTS trg_population_count_signature_delete ON TokenSignature;
DROP TRIGGER IF EXISTS trg_population_count_signature_update ON TokenSignature;
DROP TRIGGER IF EXISTS trg_population_count_signature_insert ON TokenSignature;
DROP TRIGGER IF EXISTS trg_population_count_token_truncate ON IdentityToken;
DROP TRIGGER IF EXISTS trg_population_count_token_delete ON IdentityToken;
DROP TRIGGER IF EXISTS trg_population_count_token_update ON IdentityToken;
DROP TRIGGER IF EXISTS trg_population_count_token_insert ON IdentityToken;
DROP FUNCTION IF EXISTS population_count_truncated();
DROP FUNCTION IF EXISTS population_count_signatures();
DROP FUNCTION IF EXISTS population_count_tokens();
DROP FUNCTION IF EXISTS uc_rebuild_population_counts();
DROP FUNCTION IF EXISTS uc_fold_population_counts();
DROP TABLE IF EXISTS PopulationCountDelta;
DROP TABLE IF EXISTS PopulationCount;
