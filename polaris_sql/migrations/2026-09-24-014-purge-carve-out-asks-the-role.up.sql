-- 2026-09-24-014: the append-only purge carve-out asks who is deleting, not only whether a
-- setting is on. Any role can set polaris.purge_in_progress; the carve-out now also requires
-- the owner of uc_archive_purge, which the purge runs as. Body copied from 06_triggers.sql.

CREATE OR REPLACE FUNCTION reject_audit_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_purge_in_progress TEXT;
BEGIN
    -- Arc B Phase 2b (v8.87) constitutional carve-out (Position B,
    -- DECIDED in a recorded decision):
    -- the uc_archive_purge() procedure sets a transaction-scoped GUC
    -- before issuing DELETE; this function honors that single carve-out.
    --
    -- Carve-out semantics:
    --   - Applies ONLY to DELETE (TG_OP = 'DELETE'). UPDATE still rejects.
    --   - The GUC is `polaris.purge_in_progress`. SET LOCAL means it
    --     evaporates at the transaction boundary; it cannot leak out of
    --     the procedure.
    --   - The procedure also writes a LifecycleArchiveCheckpoint row in
    --     the same transaction. If the row is missing for a DELETE that
    --     was committed, the audit chain is broken — but with the
    --     append-only checkpoint trigger + the v8.87 deferred-constraint
    --     setup, this is observable.
    --
    -- Outside the procedure, DELETE and UPDATE both fail with
    -- insufficient_privilege. The append-only contract still holds at
    -- the table-as-such level; the procedure is the only legitimate
    -- path through.
    IF TG_OP = 'DELETE' THEN
        v_purge_in_progress := current_setting('polaris.purge_in_progress', true);
        -- 2026-09-24 (after rc.40): the setting alone opened the carve-out, and ANY role can
        -- set a custom setting, so the append-only guarantee was only as strong as the grants
        -- beside it; rc.40 found a partition where they did not reach. The carve-out now also
        -- requires the role to be the owner of uc_archive_purge, which is what the purge runs
        -- as (SECURITY DEFINER), exactly as rc.19 did for the revocation gate. A role holding
        -- DELETE by mistake, now or on a table added later, still cannot delete here.
        IF v_purge_in_progress = 'TRUE'
           AND current_user = (SELECT pg_get_userbyid(p.proowner) FROM pg_proc p
                                WHERE p.proname = 'uc_archive_purge' LIMIT 1) THEN
            RETURN OLD;
        END IF;
    END IF;

    RAISE EXCEPTION
        '% on % is forbidden: this table is append-only (audit invariant). '
        'For Phase 2b archive-then-delete, route through uc_archive_purge().',
        TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
