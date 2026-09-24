-- Reverts 2026-09-24-006: the function as it was, checking status alone.

CREATE OR REPLACE FUNCTION uc5_bind_device(
    p_token_id           INTEGER,
    p_device_type        VARCHAR(20),
    p_device_fingerprint VARCHAR(128),
    p_binding_method     VARCHAR(40),
    p_validity_months    INTEGER DEFAULT 12
) RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_token_status VARCHAR(20);
    v_binding_id   INTEGER;
BEGIN
    -- Validate: token is ACTIVE.
    SELECT status INTO v_token_status
    FROM IdentityToken WHERE token_id = p_token_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Token % does not exist', p_token_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF v_token_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Token % is not ACTIVE (current status: %); cannot bind device',
            p_token_id, v_token_status
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    INSERT INTO DeviceBinding
        (token_id, device_type, device_fingerprint, binding_method,
         authorized_date, expires_date, status)
    VALUES
        (p_token_id, p_device_type, p_device_fingerprint, p_binding_method,
         CURRENT_TIMESTAMP,
         CURRENT_TIMESTAMP + (p_validity_months || ' months')::INTERVAL,
         'ACTIVE')
    RETURNING binding_id INTO v_binding_id;

    INSERT INTO TokenLifecycleEvent
        (token_id, actor_agency_id, event_type, reason_code)
    VALUES
        (p_token_id, NULL, 'DEVICE_BOUND',
         'DEVICE_TYPE_' || p_device_type);

    RETURN v_binding_id;
END;
$$;
