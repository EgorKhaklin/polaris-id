-- 2026-09-25-011: duress events, archive checkpoints and erasure records are written only by their
-- procedures.
--
-- The application role held INSERT on DuressEvent, LifecycleArchiveCheckpoint and
-- IndividualErasureEvent, all append-only, and writes none of them directly. It could record a
-- duress event for a credential with no duress code, a checkpoint for a purge that never ran, or
-- an erasure that never happened, and none could be corrected. uc12_record_duress and
-- uc_archive_purge are already SECURITY DEFINER; uc_pseudonymize_individual becomes so (Individual
-- has no row-level security, so it reads nothing more as the owner).

ALTER PROCEDURE uc_pseudonymize_individual(INTEGER, INTEGER, VARCHAR) SECURITY DEFINER;
ALTER PROCEDURE uc_pseudonymize_individual(INTEGER, INTEGER, VARCHAR) SET search_path = public, pg_temp;
REVOKE EXECUTE ON PROCEDURE uc_pseudonymize_individual(INTEGER, INTEGER, VARCHAR) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        GRANT EXECUTE ON PROCEDURE uc_pseudonymize_individual(INTEGER, INTEGER, VARCHAR) TO polaris_app;
        REVOKE INSERT ON DuressEvent FROM polaris_app;
        REVOKE INSERT ON LifecycleArchiveCheckpoint FROM polaris_app;
        REVOKE INSERT ON IndividualErasureEvent FROM polaris_app;
    END IF;
END$$;
