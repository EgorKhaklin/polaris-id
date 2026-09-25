-- 2026-09-24-007: an expired reserve is not activated.
--
-- uc4_activate_reserve checked that the reserve was in RESERVE and never read its
-- expiration_date, so reporting a credential lost could spend it and promote a reserve that was
-- already past its date: ACTIVE in the table, EXPIRED to every verifier, and nothing live left
-- for the holder. The refusal is in enforce_token_state_machine, the one door into ACTIVE, so it
-- holds for every path and not only that procedure. Body copied from 06_triggers.sql, which
-- carries the same change for a fresh install.

CREATE OR REPLACE FUNCTION enforce_token_state_machine()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- No status change: nothing to validate.
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    -- Validate the (OLD.status, NEW.status) transition pair against the legal set.
    IF NOT (
           (OLD.status = 'RESERVE' AND NEW.status = 'ACTIVE')
        OR (OLD.status = 'RESERVE' AND NEW.status = 'REVOKED')
        OR (OLD.status = 'ACTIVE'  AND NEW.status = 'DORMANT')
        OR (OLD.status = 'ACTIVE'  AND NEW.status = 'REVOKED')
        OR (OLD.status = 'ACTIVE'  AND NEW.status = 'LOST')
        OR (OLD.status = 'ACTIVE'  AND NEW.status = 'EXPIRED')
    ) THEN
        RAISE EXCEPTION 'Illegal token state transition: % → %. Legal transitions are listed in Appendix A.',
            OLD.status, NEW.status
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Activation invariant: ACTIVE tokens must have an activated_date.
    IF NEW.status = 'ACTIVE' AND NEW.activated_date IS NULL THEN
        RAISE EXCEPTION 'Cannot transition to ACTIVE without setting activated_date'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- 1.0.0-rc.37: nothing becomes ACTIVE past its expiration_date. Nothing moves ACTIVE to
    -- EXPIRED when the date passes, so a credential activated already expired would read
    -- ACTIVE in the table while every verifier refuses it; uc4_activate_reserve did exactly
    -- that. Asked here, the one door into ACTIVE, so no route or procedure has to remember.
    IF NEW.status = 'ACTIVE' AND NEW.expiration_date < CURRENT_DATE THEN
        RAISE EXCEPTION 'Cannot activate token %: it expired on %', NEW.token_id, NEW.expiration_date
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN NEW;
END;
$$;
