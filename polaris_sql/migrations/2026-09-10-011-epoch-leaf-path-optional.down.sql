-- Revert 011. Restoring NOT NULL requires every row to carry a path, so rows written since
-- the migration are backfilled with an empty array rather than the real path: the paths are
-- derivable from the published leaf set, and inventing a wrong one here would be worse than
-- an obviously empty one.
UPDATE TokenStateEpochLeaf SET proof_path = '[]'::JSONB WHERE proof_path IS NULL;
ALTER TABLE TokenStateEpochLeaf ALTER COLUMN proof_path SET NOT NULL;

COMMENT ON TABLE TokenStateEpochLeaf IS
  'Per-token witness within an epoch (R10-1 / M2-1 / v8.23). Each row '
  'is the leaf hash and inclusion proof for a token at the epoch '
  'snapshot. The Rust prover reads its row to generate a ZK proof. '
  'Note: v1 stores proof_path in plaintext; v2 would encrypt under '
  'holder key. See docs/design/zk-snark.md.';
