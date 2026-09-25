-- Reverts 2026-09-25-006: the procedure as it was, closing an epoch of any size. The setting is
-- left in place; nothing reads it after this revert.

CREATE OR REPLACE PROCEDURE uc11_close_epoch(
    p_merkle_root      VARCHAR(128),
    p_valid_until      TIMESTAMP,
    p_closed_by        INTEGER,
    -- token_leaves: JSON array of objects [{"token_id": int, "leaf_hash": hex, "proof_path": [...]}, ...]
    p_token_leaves     JSONB
)
LANGUAGE plpgsql AS $$
DECLARE
    v_new_epoch_id  INTEGER;
    v_count         INTEGER;
    v_user_role     TEXT;
    v_leaf          JSONB;
BEGIN
    -- C9: per-procedure advisory lock — serializes epoch closures (otherwise
    -- two concurrent calls would race on the INSERT).
    PERFORM pg_advisory_xact_lock(
        hashtext('polaris.zk.close-epoch'));

    -- Validate admin role.
    SELECT role INTO v_user_role FROM AppUser WHERE user_id = p_closed_by;
    IF v_user_role IS NULL THEN
        RAISE EXCEPTION 'AppUser % not found', p_closed_by
            USING ERRCODE = 'no_data_found';
    END IF;
    IF v_user_role <> 'admin' THEN
        RAISE EXCEPTION
            'Epoch closure requires admin role (signer % has role %)',
            p_closed_by, v_user_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- 2026-09-24: an admin whose account is DEACTIVATED held this authority as fully as a
    -- live one. uc9_complete_recovery and uc_pseudonymize_individual refused a deactivated
    -- actor; the five procedures below checked the role alone.
    IF NOT (SELECT is_active FROM AppUser WHERE user_id = p_closed_by) THEN
        RAISE EXCEPTION 'uc11_close_epoch: user % is not an active account', p_closed_by
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Count leaves.
    SELECT jsonb_array_length(p_token_leaves) INTO v_count;
    IF v_count IS NULL OR v_count = 0 THEN
        RAISE EXCEPTION
            'Cannot close an empty epoch (zero valid tokens to commit)'
            USING ERRCODE = 'no_data_found';
    END IF;
    IF v_count > 10000 THEN
        RAISE EXCEPTION
            'Epoch size (%) exceeds cap of 10000; split into multiple epochs', v_count;
    END IF;

    -- Create the epoch row. The CHECK constraints enforce hex format,
    -- valid_until > valid_from, count cap.
    INSERT INTO TokenStateEpoch
        (merkle_root, valid_until, committed_count, closed_by_user_id)
    VALUES (p_merkle_root, p_valid_until, v_count, p_closed_by)
    RETURNING epoch_id INTO v_new_epoch_id;

    -- Write per-leaf rows. Iterate over the JSON array.
    FOR v_leaf IN SELECT * FROM jsonb_array_elements(p_token_leaves)
    LOOP
        INSERT INTO TokenStateEpochLeaf
            (epoch_id, token_id, leaf_hash, proof_path)
        VALUES (
            v_new_epoch_id,
            (v_leaf ->> 'token_id')::INTEGER,
            v_leaf ->> 'leaf_hash',
            v_leaf -> 'proof_path'
        );
    END LOOP;

    RAISE NOTICE 'uc11_close_epoch: created epoch_id=%, % leaves, valid_until=%',
        v_new_epoch_id, v_count, p_valid_until;
END$$;
