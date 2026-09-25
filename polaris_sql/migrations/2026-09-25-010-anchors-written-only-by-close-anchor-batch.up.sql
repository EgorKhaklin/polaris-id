-- 2026-09-25-010: the anchoring layer is written only by close_anchor_batch.
--
-- The application role held INSERT on AnchorBatch and INSERT, UPDATE and DELETE on
-- BlockchainAnchor, which has no trigger: it could record a batch whose batch_size no leaves bear
-- out, or move an anchor into another batch and rewrite its Merkle proof after the batch closed.
-- The application writes neither; close_anchor_batch is already SECURITY DEFINER.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT ON AnchorBatch FROM polaris_app;
        REVOKE INSERT, UPDATE, DELETE ON BlockchainAnchor FROM polaris_app;
    END IF;
END$$;
