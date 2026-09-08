-- ============================================================================
-- 2026-09-07-002-drop-scifi-scaffold.up.sql
--
-- v9.269 (P1.18 item 2): remove the two science-fiction scaffold tables that no
-- current guarantee or milestone depends on. GenomicAnchor was a per-token hash
-- commitment framed as DNA/genomic anchoring; QuantumObserverBinding was a
-- 'quantum-observer measurement' scaffold explicitly documented as having no
-- planned use. Neither is read by any procedure, trigger, view, or application
-- path. Continues the v9.55 apparatus-removal discipline: a national-identity
-- schema should not carry DNA-alphabet or wavefunction-collapse vocabulary
-- without an extraordinary reason.
--
-- CASCADE drops the GenomicAnchor index with it; nothing else references either
-- table. Safe on a fresh load (IF EXISTS is a no-op there). Reversibility: the
-- .down recreates the empty table skeletons (structure only; the notional seed
-- rows are not restored).
-- ============================================================================

-- phase: contract
-- expands: 2026-05-14-001-idx-checkpoint-recent
-- (vacuous: the dropped tables were never read by any procedure, trigger, view,
--  or application path, so they have been safe to drop since the migration
--  history began; the reference names the earliest migration to satisfy the
--  contract-phase policy mechanically.)

DROP TABLE IF EXISTS QuantumObserverBinding CASCADE;
DROP TABLE IF EXISTS GenomicAnchor CASCADE;
