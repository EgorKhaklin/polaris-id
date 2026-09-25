-- 2026-09-25-006: a zero-knowledge epoch has a minimum anonymity set.
--
-- An epoch of one member hides nobody, and until now one could close, and a proof against it was
-- verified as private. uc11_close_epoch refuses to close an epoch smaller than the database setting
-- polaris.min_epoch_anonymity_set (20 when unset); the verifier refuses a proof against a smaller
-- epoch with "privacy unavailable". This sets the floor to 20 on a database that has none; a
-- database already carrying a value (the notional sample sets 1) keeps it. Procedure body copied
-- from 05_procedures.sql.

CREATE OR REPLACE PROCEDURE uc11_close_epoch(
    p_merkle_root      VARCHAR(128),
    p_valid_until      TIMESTAMP,
    p_closed_by        INTEGER,
    -- token_leaves: JSON array of objects [{"token_id": int, "leaf_hash": hex, "proof_path": [...]}, ...]
    p_token_leaves     JSONB
)
LANGUAGE plpgsql AS $$
DECLARE
    v_floor           INTEGER;
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

    -- 2026-09-25: the minimum anonymity set. A membership proof hides which member of the epoch
    -- is proving, so an epoch of k members hides a holder among k, and an epoch of one hides
    -- nobody: the "bounded" presentation collapses to an identified one while still being called
    -- private. Until this line an epoch of one closed. Below the floor the epoch is REFUSED, not
    -- closed smaller: the authority waits for members or lengthens its cadence
    -- (docs/design/epoch-cadence.md). Epochs are not merged. The floor is the database setting
    -- polaris.min_epoch_anonymity_set, 20 when unset; the notional sample data sets 1 and says so.
    v_floor := COALESCE(NULLIF(polaris_database_setting('polaris.min_epoch_anonymity_set'), '')::INTEGER, 20);
    IF v_count < v_floor THEN
        RAISE EXCEPTION
            'uc11_close_epoch: % member(s) is below the minimum anonymity set of %: an epoch this small identifies its members by elimination. Wait for more members or lengthen the cadence.',
            v_count, v_floor
            USING ERRCODE = 'check_violation';
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

DO $$
BEGIN
    IF polaris_database_setting('polaris.min_epoch_anonymity_set') IS NULL THEN
        EXECUTE format('ALTER DATABASE %I SET polaris.min_epoch_anonymity_set = 20', current_database());
    END IF;
END$$;
