-- 2026-10-01-007 down: drop the foreign key indexes. Reading one record's rows, and deleting a
-- referenced row, go back to scanning the referencing table; nothing else changes.
DROP INDEX IF EXISTS idx_recoveryrequest_claimed;
DROP INDEX IF EXISTS idx_blockchainanchor_token;
DROP INDEX IF EXISTS idx_enrollmentcode_proofing;
DROP INDEX IF EXISTS idx_refereevouching_co_signer;
DROP INDEX IF EXISTS idx_refereevouching_applicant;
DROP INDEX IF EXISTS idx_duressevent_token;
DROP INDEX IF EXISTS idx_credentialcopy_token;
DROP INDEX IF EXISTS idx_recoveryrequest_resulting_token;
DROP INDEX IF EXISTS idx_revocationlist_token;
DROP INDEX IF EXISTS idx_devicebinding_token;
DROP INDEX IF EXISTS idx_identitytoken_predecessor;
