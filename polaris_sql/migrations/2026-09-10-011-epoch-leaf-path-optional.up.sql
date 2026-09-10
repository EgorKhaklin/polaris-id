-- 011: TokenStateEpochLeaf.proof_path becomes OPTIONAL (roadmap P2.5).
--
-- The column was written on every epoch close and read by nothing. Every query in the
-- application selects `leaf_hash`; the published anonymity set (P9.2) serves leaf hashes and
-- the holder derives their own inclusion path on their own device. A grep of the tree at
-- v9.357 finds no reader of `proof_path` outside the row that writes it.
--
-- Two costs were being paid for that. At the national depth the paths are 1,718 bytes per
-- member, so a ten-million-member epoch would materialise roughly 17 GB of JSON to close;
-- and the schema's own comment flags the column as plaintext at rest that a later version
-- would have to encrypt under the holder's key. Data nothing reads is the easiest kind to
-- stop holding.
--
-- The column is kept rather than dropped, so an epoch closed before this migration keeps the
-- paths it recorded and nothing already published becomes unreadable.
ALTER TABLE TokenStateEpochLeaf ALTER COLUMN proof_path DROP NOT NULL;

COMMENT ON TABLE TokenStateEpochLeaf IS
  'Per-token witness within an epoch (R10-1 / M2-1 / v8.23). Each row is the leaf hash for a '
  'token at the epoch snapshot. Since v9.357 (P2.5) proof_path is OPTIONAL and is not written: '
  'the holder derives their own inclusion path from the published leaf set on their own device '
  '(P9.2), so storing one path per member cost 1.7 KB of plaintext each and was read by '
  'nothing. Rows closed before v9.357 keep the paths they recorded. See '
  'docs/design/epoch-cadence.md.';
