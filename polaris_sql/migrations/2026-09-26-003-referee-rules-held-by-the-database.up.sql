-- 2026-09-26-003: the trusted-referee rules are held by the database, for every writer.
--
-- docs/design/trusted-referee.md says every limit is a database constraint. The referee's level
-- was the writer's claim, and the co-signer bound lived only in referee.py. As polaris_app: 26 vouchings by an unproofed referee, no co-signer.

CREATE OR REPLACE FUNCTION enforce_vouching_rules()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_referee_level  VARCHAR(6);
    v_cosigner_level VARCHAR(6);
    v_seen           INTEGER;
BEGIN
    SELECT derived_ial INTO v_referee_level
      FROM EnrollmentProofing
     WHERE individual_id = NEW.referee_individual_id
     ORDER BY recorded_at DESC, proofing_id DESC
     LIMIT 1;
    IF v_referee_level IS NULL THEN
        RAISE EXCEPTION 'referee % has no proofing record; a referee lends an assurance they must hold',
            NEW.referee_individual_id
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.referee_ial IS DISTINCT FROM v_referee_level THEN
        RAISE EXCEPTION 'referee_ial is %, but referee % is proofed at %; the level is derived, never chosen',
            NEW.referee_ial, NEW.referee_individual_id, v_referee_level
            USING ERRCODE = 'check_violation';
    END IF;

    IF NEW.co_signer_individual_id IS NOT NULL THEN
        SELECT derived_ial INTO v_cosigner_level
          FROM EnrollmentProofing
         WHERE individual_id = NEW.co_signer_individual_id
         ORDER BY recorded_at DESC, proofing_id DESC
         LIMIT 1;
        IF v_cosigner_level IS NULL OR v_cosigner_level < 'IAL2' THEN
            RAISE EXCEPTION 'co-signer % is not proofed at IAL2 or above; a co-signer is a second proofed person',
                NEW.co_signer_individual_id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('polaris.referee_vouching'), NEW.referee_individual_id);
    SELECT count(*) INTO v_seen
      FROM RefereeVouching
     WHERE referee_individual_id = NEW.referee_individual_id
       AND vouched_at >= CURRENT_TIMESTAMP - interval '30 days';
    IF v_seen >= 25 AND NEW.co_signer_individual_id IS NULL THEN
        RAISE EXCEPTION 'referee % has vouched % time(s) in the last 30 days, at or past the bound of 25; this vouching needs a co-signer',
            NEW.referee_individual_id, v_seen
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_vouching_rules ON RefereeVouching;
CREATE TRIGGER trg_vouching_rules
    BEFORE INSERT ON RefereeVouching
    FOR EACH ROW
    EXECUTE FUNCTION enforce_vouching_rules();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'polaris_app') THEN
        REVOKE INSERT, UPDATE, DELETE ON RefereeVouching FROM polaris_app;
    END IF;
END$$;
