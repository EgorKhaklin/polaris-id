-- Reverts 2026-09-24-007: the function as it was, refusing no transition on its date.

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

    RETURN NEW;
END;
$$;
