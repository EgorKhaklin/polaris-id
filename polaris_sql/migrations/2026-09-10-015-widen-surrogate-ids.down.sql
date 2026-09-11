-- ============================================================================
-- 2026-09-10-015-widen-surrogate-ids.down.sql
--
-- Revert the five surrogate ids to 32-bit INTEGER.
--
-- THIS REVERT CAN FAIL, AND FAILING IS THE CORRECT BEHAVIOUR. If any table has
-- issued an id above 2,147,483,647, ALTER COLUMN TYPE INTEGER raises
-- "integer out of range" and the transaction rolls back. There is no safe
-- narrowing of a value that no longer fits, and a down-migration that coped by
-- truncating would silently rewrite the identifiers of audit rows that C1 makes
-- permanent.
--
-- The sequence is narrowed back alongside the column, and that too will fail if
-- its last_value is already above the 32-bit ceiling.
--
-- This revert exists for pre-deployment rollback. After a deployment has run long
-- enough to need the width, it is not available, which is the honest shape: the
-- reason to widen early is that widening is cheap early and narrowing is never
-- cheap at all.
-- ============================================================================

BEGIN;

ALTER TABLE VerificationEvent      ALTER COLUMN event_id     TYPE INTEGER;
ALTER SEQUENCE verificationevent_event_id_seq      AS INTEGER MAXVALUE 2147483647;

ALTER TABLE TokenStateEpochLeaf    ALTER COLUMN leaf_id      TYPE INTEGER;
ALTER SEQUENCE tokenstateepochleaf_leaf_id_seq     AS INTEGER MAXVALUE 2147483647;

ALTER TABLE TokenLifecycleEvent    ALTER COLUMN event_id     TYPE INTEGER;
ALTER SEQUENCE tokenlifecycleevent_event_id_seq    AS INTEGER MAXVALUE 2147483647;

ALTER TABLE TokenSignature         ALTER COLUMN signature_id TYPE INTEGER;
ALTER SEQUENCE tokensignature_signature_id_seq     AS INTEGER MAXVALUE 2147483647;

ALTER TABLE AuthAuditLog           ALTER COLUMN audit_id     TYPE INTEGER;
ALTER SEQUENCE authauditlog_audit_id_seq           AS INTEGER MAXVALUE 2147483647;

COMMIT;
