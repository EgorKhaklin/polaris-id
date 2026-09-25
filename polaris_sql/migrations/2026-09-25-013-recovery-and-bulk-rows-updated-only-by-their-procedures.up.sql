-- 2026-09-25-013: recovery requests and bulk-issuance batches are updated only by their procedures.
--
-- The application role held UPDATE and DELETE on RecoveryRequest, BulkEnrollmentBatch and
-- BulkEnrollmentStaging and changes none of them itself. On RecoveryRequest it could record all
-- three out-of-band channels uc9_complete_recovery requires, collapsing three independent
-- verifications into one role; on the batch it could reset issued_at and re-open a batch
-- uc_bulk_issue refuses to issue twice. Both procedures are SECURITY DEFINER.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE UPDATE, DELETE ON RecoveryRequest FROM polaris_app;
        REVOKE UPDATE, DELETE ON BulkEnrollmentBatch FROM polaris_app;
        REVOKE UPDATE, DELETE ON BulkEnrollmentStaging FROM polaris_app;
    END IF;
END$$;
