-- ============================================================================
-- 2026-09-12-004-relying-party-weakened-three-valued.up.sql
--
-- v9.425 gave RelyingParty its record and `weakened` as a plain boolean. Three
-- things were measured wrong by that, all found by running them against a loaded
-- database rather than by reading the rule:
--
--   1. `scope` was ranked by STRING LENGTH. Measured: 'authenticate' -> 'verify'
--      gives the party the verify capability it did not have, and the length goes
--      DOWN, so the rule recorded a widening as harmless and required no reason.
--      Scope IS rankable -- by set containment -- so this is a wrong test, not an
--      unrankable field.
--
--   2. `required_enrollment` and `required_context_id` were FALSE on a swap.
--      /api/v1/auth/authorize compares `enrollment != required` EXACTLY, so each
--      value names one mutually exclusive population and no ordering puts one
--      above another; the same is true of contexts. FALSE drops the change out of
--      the assessor's list, TRUE asserts a ranking nothing performed. NULL says
--      what is true, which is that somebody has to look.
--
--   3. The gate asked `IF _rp_weakens(...) AND ...`. `NULL AND TRUE` is NULL, not
--      TRUE, so once the predicate could return NULL an unrankable change passed
--      with no reason at all -- and so did the ELSE NULL case, a field nobody
--      classified, which exists precisely so nobody defaults to harmless.
--
-- phase: expand. The column widens from NOT NULL to nullable; every existing row
-- keeps its value and old code reading it as a boolean still reads TRUE and FALSE.
--
-- The canonical copies live in 01_schema.sql / 06_triggers.sql.
-- REVERSIBLE: the .down.sql restores NOT NULL, which requires rewriting any NULL
-- to FALSE and therefore DISCARDS the distinction this migration adds.
-- ============================================================================

ALTER TABLE RelyingPartyEvent ALTER COLUMN weakened DROP NOT NULL;

-- The partial index supported the assessor's filter. That filter is now
-- `weakened IS NOT FALSE`, and `WHERE weakened` holds only the TRUE rows, so it
-- stopped covering the query it exists for the moment the column went three-valued.
-- The same correction v9.443 made to idx_agency_event_widened.
DROP INDEX IF EXISTS idx_rp_event_weakened;
CREATE INDEX IF NOT EXISTS idx_rp_event_weakened ON RelyingPartyEvent (recorded_at DESC)
    WHERE weakened IS NOT FALSE;

-- ---------------------------------------------------------------------------
-- The rule and the gate, carried here rather than left to the canonical file.
--
-- Migration 2026-09-11-018 embeds its own copy of _rp_weakens, which is correct for
-- what that migration did and means the OLD rule is reinstalled every time migrations
-- are applied in order. A deployment then re-runs `polaris-migrate.sh --sync-objects`,
-- which re-applies 06_triggers.sql and puts this back -- but anything that applies
-- migrations WITHOUT that step ends up with the v9.425 behaviour and no sign of it.
-- Measured: a clean load followed by migrations left string-length ranking installed,
-- and five tests that pass against the canonical file failed against that database.
--
-- So this migration carries the change it is named for. 018 is history and stays as it
-- is; this supersedes it by running after it.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION _rp_weakens(p_field TEXT, p_old RelyingParty, p_new RelyingParty)
RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    IF p_old IS NULL THEN                       -- an INSERT: standing where there was none
        RETURN TRUE;
    END IF;
    IF p_field IS NULL THEN                     -- the statement as a whole
        RETURN _rp_weakens('require_zk', p_old, p_new)
            OR _rp_weakens('required_enrollment', p_old, p_new)
            OR _rp_weakens('required_context_id', p_old, p_new)
            OR _rp_weakens('scope', p_old, p_new)
            OR _rp_weakens('enabled', p_old, p_new)
            OR _rp_weakens('rate_limit_per_min', p_old, p_new);
    END IF;
    RETURN CASE p_field
        WHEN 'require_zk'          THEN p_old.require_zk AND NOT p_new.require_zk
        -- v9.448: three-valued, for the reason AgencyEvent.widened is (v9.440). Removing
        -- the filter is a definite weakening: the party stops being restricted to one
        -- enrollment status and starts answering about every holder. Swapping ENROLLED
        -- for EXEMPT is NOT: the app compares `enrollment != required` exactly, so each
        -- value names one mutually exclusive population and no ordering puts one above
        -- another. Recording that FALSE dropped it out of the assessor's list; recording
        -- it TRUE would assert a ranking nothing performed.
        WHEN 'required_enrollment' THEN CASE
            WHEN p_old.required_enrollment IS NOT DISTINCT FROM p_new.required_enrollment
                THEN FALSE
            WHEN p_new.required_enrollment IS NULL THEN TRUE
            WHEN p_old.required_enrollment IS NULL THEN FALSE
            ELSE NULL
        END
        -- The same shape. Contexts are not ordered: TRAVEL is neither above nor below
        -- BANKING, so a swap is a change of reach the database will not rank.
        WHEN 'required_context_id' THEN CASE
            WHEN p_old.required_context_id IS NOT DISTINCT FROM p_new.required_context_id
                THEN FALSE
            WHEN p_new.required_context_id IS NULL THEN TRUE
            WHEN p_old.required_context_id IS NULL THEN FALSE
            ELSE NULL
        END
        -- v9.448: set containment, not string length. Scope IS rankable -- a party that
        -- holds a capability it did not hold before has more reach -- but `length(new) >
        -- length(old)` is not that test. Measured: 'authenticate' -> 'verify' gains the
        -- verify capability and the length goes DOWN, so the old rule called a widening
        -- harmless. The question is whether the new set contains anything the old did not.
        WHEN 'scope'               THEN NOT (string_to_array(p_new.scope, ' ')
                                             <@ string_to_array(p_old.scope, ' '))
        WHEN 'enabled'             THEN p_new.enabled AND NOT p_old.enabled
        WHEN 'rate_limit_per_min'  THEN p_new.rate_limit_per_min > p_old.rate_limit_per_min
        WHEN 'client_secret_hash'  THEN FALSE
        WHEN 'org_name'            THEN FALSE
        -- A field nobody classified must not default to "harmless". The check layer
        -- keeps this reachable only by adding a column without extending this rule.
        ELSE NULL
    END;
END;
$$;

CREATE OR REPLACE FUNCTION record_relying_party_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    v_actor  VARCHAR(100) := NULLIF(current_setting('polaris.actor', true), '');
    v_why    VARCHAR(500) := NULLIF(current_setting('polaris.justification', true), '');
BEGIN
    -- A weakening must say why, through whichever door it comes.
    --
    -- This is the half that makes the record worth keeping. An event row saying
    -- `require_zk true -> false` by `vanta` at 04:12 tells an assessor what happened
    -- and nothing about whether it should have. `polaris quota-set` has demanded a
    -- 20-character justification since v9.190 for the same reason, and enforcing it
    -- in the CLI alone would make it a convention the next caller can skip.
    --
    -- _rp_weakens() decides what counts, so the rule and the `weakened` column on the
    -- rows below cannot drift apart.
    -- v9.448: IS NOT FALSE, not a bare truth test. _rp_weakens is three-valued now, and
    -- `NULL AND TRUE` is NULL rather than TRUE, so an unrankable change -- and the ELSE
    -- NULL case, a field nobody classified -- would pass the gate without a reason. The
    -- ELSE NULL exists precisely so nobody defaults to harmless; a gate that ignores it
    -- undoes that.
    IF _rp_weakens(NULL, CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD END, NEW) IS NOT FALSE
       AND (v_why IS NULL OR length(trim(v_why)) < 20) THEN
        RAISE EXCEPTION
            'a change that reduces what a relying party must satisfy needs a '
            'justification of at least 20 characters: set polaris.justification '
            '(polaris rp-policy --justification, rp-register --justification)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF TG_OP = 'INSERT' THEN
        INSERT INTO RelyingPartyEvent (rp_id, client_id, event_type, weakened, actor,
                                       justification, new_value)
        VALUES (NEW.rp_id, NEW.client_id, 'REGISTERED',
                -- Registration grants standing where there was none, which is the
                -- widest weakening in the table. Asked of the predicate rather than
                -- written as TRUE, so the gate above and this column cannot disagree.
                _rp_weakens(NULL, NULL, NEW), v_actor, v_why,
                format('org_name=%s scope=%s require_zk=%s required_enrollment=%s '
                       'required_context_id=%s rate_limit_per_min=%s enabled=%s',
                       NEW.org_name, NEW.scope, NEW.require_zk,
                       coalesce(NEW.required_enrollment, 'none'),
                       coalesce(NEW.required_context_id::TEXT, 'none'),
                       NEW.rate_limit_per_min, NEW.enabled));
        RETURN NEW;
    END IF;

    IF NEW.require_zk IS DISTINCT FROM OLD.require_zk THEN
        INSERT INTO RelyingPartyEvent (rp_id, client_id, event_type, field, old_value,
                                       new_value, weakened, actor, justification)
        VALUES (NEW.rp_id, NEW.client_id, 'POLICY_CHANGED', 'require_zk',
                OLD.require_zk::TEXT, NEW.require_zk::TEXT,
                -- TRUE -> FALSE drops the holder from ACR zk to ACR possession.
                _rp_weakens('require_zk', OLD, NEW), v_actor, v_why);
    END IF;

    IF NEW.required_enrollment IS DISTINCT FROM OLD.required_enrollment THEN
        INSERT INTO RelyingPartyEvent (rp_id, client_id, event_type, field, old_value,
                                       new_value, weakened, actor, justification)
        VALUES (NEW.rp_id, NEW.client_id, 'POLICY_CHANGED', 'required_enrollment',
                coalesce(OLD.required_enrollment, 'none'),
                coalesce(NEW.required_enrollment, 'none'),
                _rp_weakens('required_enrollment', OLD, NEW), v_actor, v_why);
    END IF;

    IF NEW.required_context_id IS DISTINCT FROM OLD.required_context_id THEN
        INSERT INTO RelyingPartyEvent (rp_id, client_id, event_type, field, old_value,
                                       new_value, weakened, actor, justification)
        VALUES (NEW.rp_id, NEW.client_id, 'POLICY_CHANGED', 'required_context_id',
                coalesce(OLD.required_context_id::TEXT, 'none'),
                coalesce(NEW.required_context_id::TEXT, 'none'),
                _rp_weakens('required_context_id', OLD, NEW), v_actor, v_why);
    END IF;

    IF NEW.scope IS DISTINCT FROM OLD.scope THEN
        INSERT INTO RelyingPartyEvent (rp_id, client_id, event_type, field, old_value,
                                       new_value, weakened, actor, justification)
        VALUES (NEW.rp_id, NEW.client_id, 'SCOPE_CHANGED', 'scope', OLD.scope, NEW.scope,
                -- Gaining 'authenticate' lets the party use the auth broker, which is
                -- strictly more than verifying: a wider scope is a weakening.
                _rp_weakens('scope', OLD, NEW), v_actor, v_why);
    END IF;

    IF NEW.enabled IS DISTINCT FROM OLD.enabled THEN
        INSERT INTO RelyingPartyEvent (rp_id, client_id, event_type, field, old_value,
                                       new_value, weakened, actor, justification)
        VALUES (NEW.rp_id, NEW.client_id,
                CASE WHEN NEW.enabled THEN 'ENABLED' ELSE 'DISABLED' END, 'enabled',
                OLD.enabled::TEXT, NEW.enabled::TEXT,
                _rp_weakens('enabled', OLD, NEW), v_actor, v_why);
    END IF;

    IF NEW.rate_limit_per_min IS DISTINCT FROM OLD.rate_limit_per_min THEN
        INSERT INTO RelyingPartyEvent (rp_id, client_id, event_type, field, old_value,
                                       new_value, weakened, actor, justification)
        VALUES (NEW.rp_id, NEW.client_id, 'RATE_LIMIT_CHANGED', 'rate_limit_per_min',
                OLD.rate_limit_per_min::TEXT, NEW.rate_limit_per_min::TEXT,
                _rp_weakens('rate_limit_per_min', OLD, NEW), v_actor, v_why);
    END IF;

    IF NEW.client_secret_hash IS DISTINCT FROM OLD.client_secret_hash THEN
        -- The hash itself is never recorded; that it changed is the fact.
        INSERT INTO RelyingPartyEvent (rp_id, client_id, event_type, field, old_value,
                                       new_value, weakened, actor, justification)
        VALUES (NEW.rp_id, NEW.client_id, 'SECRET_ROTATED', 'client_secret_hash',
                '(redacted)', '(redacted)',
                _rp_weakens('client_secret_hash', OLD, NEW), v_actor, v_why);
    END IF;

    IF NEW.org_name IS DISTINCT FROM OLD.org_name THEN
        INSERT INTO RelyingPartyEvent (rp_id, client_id, event_type, field, old_value,
                                       new_value, weakened, actor, justification)
        VALUES (NEW.rp_id, NEW.client_id, 'RENAMED', 'org_name', OLD.org_name,
                NEW.org_name, _rp_weakens('org_name', OLD, NEW), v_actor, v_why);
    END IF;

    IF NEW.client_id IS DISTINCT FROM OLD.client_id THEN
        -- The credential's identity is not a field anybody edits; changing it would
        -- silently re-point every event row above at a party that no longer exists.
        RAISE EXCEPTION 'RelyingParty.client_id is immutable: retire the credential '
                        'and register a new one'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    RETURN NEW;
END;
$$;
