-- 2026-09-27-004: a token value is a credential serial (WIRE-SPEC 3.7).
--
-- Issuance signs SHA3-256(token_value) with no format or domain, and every other artifact the
-- authority signs is SHA3-256 of a canonical JSON statement, which begins with '{'. Any
-- authority-signed artifact, its signature re-wrapped as an authenticity pack whose token_value
-- was its canonical statement, verified as an authentic credential. The verifiers now refuse
-- such a pack; the register refuses to hold such a value, as 01_schema.sql does for a fresh
-- install: non-empty, at most 128 bytes of UTF-8, first character not '{', no control
-- character. If an existing row violates it, this fails rather than admit it, and that row is
-- the thing to investigate.

ALTER TABLE IdentityToken DROP CONSTRAINT IF EXISTS chk_token_value_is_a_serial;
ALTER TABLE IdentityToken
    ADD CONSTRAINT chk_token_value_is_a_serial CHECK (
        token_value <> ''
        AND octet_length(token_value) <= 128
        AND left(token_value, 1) <> '{'
        AND token_value !~ '[\u0001-\u001f\u007f-\u009f]'
    );
