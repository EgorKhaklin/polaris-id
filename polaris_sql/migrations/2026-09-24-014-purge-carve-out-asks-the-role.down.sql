-- Reverts 2026-09-24-014: the carve-out as it was, opened by the setting alone.

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
        IF v_purge_in_progress = 'TRUE' THEN
            -- The carve-out is open. Allow the DELETE.
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
