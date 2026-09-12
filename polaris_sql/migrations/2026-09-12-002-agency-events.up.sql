-- ============================================================================
-- 2026-09-12-002-agency-events.up.sql
--
-- An Agency is the root of this schema's hierarchy. It issues credentials, holds
-- signing keys, receives quotas and revocation bounds, and vouches for other
-- authorities in federation. Thirty-five foreign keys point at it.
--
-- Creating one wrote NOTHING. Verified by running the insert the /agencies/new
-- route makes: AuthAuditLog, AuditAccessLog and AuthorityKeyEvent all unchanged,
-- and the table carried zero triggers. An authority could be created, have its
-- authorization_level raised from 3 to 5, be renamed, and be deleted again, with
-- no record of any of it anywhere.
--
-- v9.424 gave AgencyQuota its history, v9.425 gave RelyingParty one, v9.426 gave
-- IssuerDiscretionPolicy one. Each of those records a decision ABOUT an authority.
-- This records the authority itself, which is the decision underneath all of them.
--
-- phase: expand. Nothing is dropped or narrowed; old code keeps working and its
-- changes start being recorded.
--
-- The canonical copies live in 01_schema.sql / 02_indexes.sql / 06_triggers.sql.
-- REVERSIBLE: the .down.sql drops the trigger and the table, which discards the
-- record. Idempotent: IF NOT EXISTS / OR REPLACE.
-- ============================================================================

CREATE TABLE IF NOT EXISTS AgencyEvent (
    event_id      SERIAL PRIMARY KEY,
    -- Deliberately NOT a foreign key, for the reason RelyingPartyEvent is not one
    -- (v9.425): the record of what an authority was must outlive the row. `name` is
    -- denormalised here so an event reads on its own afterwards.
    agency_id     INTEGER NOT NULL,
    name          VARCHAR(200) NOT NULL,
    event_type    VARCHAR(30) NOT NULL,
    field         VARCHAR(40),
    old_value     TEXT,
    new_value     TEXT,
    -- Three-valued on purpose. TRUE: the change strictly increases what this authority
    -- MAY DO, which is creation where there was none, or a rise in authorization_level.
    -- NULL: the change moved the authority's SCOPE (its jurisdiction or its type) and the
    -- database cannot tell which way, because jurisdiction is free text and 'US' is not
    -- comparable to 'Pilot County' by any ordering SQL has. FALSE: it granted nothing,
    -- which is a rename or a fall in level.
    --
    -- The assessor's filter is therefore `widened IS NOT FALSE`, not `widened`. Marking a
    -- rescope FALSE would let a county authority become a national one without appearing
    -- in the list of changes that gave an authority more reach; marking it TRUE would put
    -- a claim in the record that nothing checked. NULL says what is true, which is that
    -- someone has to look.
    widened       BOOLEAN DEFAULT FALSE,
    actor         VARCHAR(100),
    db_role       VARCHAR(100) NOT NULL DEFAULT session_user,
    justification VARCHAR(500),
    recorded_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_agency_event_type CHECK (event_type IN (
        'CREATED', 'RENAMED', 'LEVEL_CHANGED', 'TYPE_CHANGED',
        'JURISDICTION_CHANGED', 'SIGNING_KEY_CHANGED')),
    CONSTRAINT chk_agency_event_field CHECK (
        (event_type = 'CREATED' AND field IS NULL) OR
        (event_type <> 'CREATED' AND field IS NOT NULL))
);

COMMENT ON TABLE AgencyEvent IS
  'Append-only record of every decision about an authority (v9.440): its creation, '
  'its renaming, and any change to the level, type, jurisdiction or signing key it '
  'operates under. Written by trg_agency_audited from the row diff rather than by the '
  'caller, so a change made in psql is recorded on the same terms as one made through '
  'the console. `widened` marks a change that increases what the authority may do -- '
  'creation, or a raised authorization_level -- which is what an assessor filters for.';

CREATE INDEX IF NOT EXISTS idx_agency_event_agency ON AgencyEvent (agency_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_agency_event_widened ON AgencyEvent (recorded_at DESC)
    WHERE widened;

-- ----------------------------------------------------------------------------
-- record_agency_change: the writer, and the DELETE refusal.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION record_agency_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    v_actor VARCHAR(100) := NULLIF(current_setting('polaris.actor', true), '');
    v_why   VARCHAR(500) := NULLIF(current_setting('polaris.justification', true), '');
    v_wide  BOOLEAN;
    v_scope BOOLEAN;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'Agency is append-only: DELETE is refused. An authority that existed is '
            'part of the record even if it issued nothing; thirty-five tables point at '
            'it, and the ones that do not are the ones that would forget it.'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    v_wide := (TG_OP = 'INSERT')
              OR (NEW.authorization_level > OLD.authorization_level);
    -- A move of SCOPE rather than of level: the jurisdiction this authority operates in,
    -- or what kind of authority it is. The database cannot rank these, so it does not
    -- claim to: it refuses them without a reason and records them as widened = NULL.
    -- Otherwise a county office becomes a national issuer in one UPDATE, silently, and
    -- the list of changes that gave an authority more reach does not contain it.
    v_scope := (TG_OP = 'UPDATE')
               AND (NEW.jurisdiction IS DISTINCT FROM OLD.jurisdiction
                    OR NEW.agency_type IS DISTINCT FROM OLD.agency_type);
    -- Creating an authority, widening one, or rescoping one must say why. The same
    -- 20-character floor AgencyQuota has held since v9.190 and RelyingParty since
    -- v9.425: an authority is the thing all of those bound, so it is not a lighter act.
    IF (v_wide OR v_scope) AND (v_why IS NULL OR length(trim(v_why)) < 20) THEN
        RAISE EXCEPTION
            'creating an authority, raising the level it operates at, or changing the '
            'jurisdiction or type it operates as, needs a justification of at least 20 '
            'characters: set polaris.justification (polaris agency-create '
            '--justification)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF TG_OP = 'INSERT' THEN
        INSERT INTO AgencyEvent (agency_id, name, event_type, widened, actor,
                                 justification, new_value)
        VALUES (NEW.agency_id, NEW.name, 'CREATED', TRUE, v_actor, v_why,
                format('type=%s jurisdiction=%s authorization_level=%s',
                       NEW.agency_type, NEW.jurisdiction, NEW.authorization_level));
        RETURN NEW;
    END IF;

    IF NEW.agency_id IS DISTINCT FROM OLD.agency_id THEN
        RAISE EXCEPTION
            'Agency.agency_id is immutable: thirty-five tables reference it, and '
            'changing it would silently re-point every one of them.'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF NEW.name IS DISTINCT FROM OLD.name THEN
        INSERT INTO AgencyEvent (agency_id, name, event_type, field, old_value,
                                 new_value, widened, actor, justification)
        VALUES (NEW.agency_id, NEW.name, 'RENAMED', 'name', OLD.name, NEW.name,
                FALSE, v_actor, v_why);
    END IF;
    IF NEW.authorization_level IS DISTINCT FROM OLD.authorization_level THEN
        INSERT INTO AgencyEvent (agency_id, name, event_type, field, old_value,
                                 new_value, widened, actor, justification)
        VALUES (NEW.agency_id, NEW.name, 'LEVEL_CHANGED', 'authorization_level',
                OLD.authorization_level::TEXT, NEW.authorization_level::TEXT,
                NEW.authorization_level > OLD.authorization_level, v_actor, v_why);
    END IF;
    IF NEW.agency_type IS DISTINCT FROM OLD.agency_type THEN
        INSERT INTO AgencyEvent (agency_id, name, event_type, field, old_value,
                                 new_value, widened, actor, justification)
        VALUES (NEW.agency_id, NEW.name, 'TYPE_CHANGED', 'agency_type',
                OLD.agency_type, NEW.agency_type, NULL, v_actor, v_why);
    END IF;
    IF NEW.jurisdiction IS DISTINCT FROM OLD.jurisdiction THEN
        INSERT INTO AgencyEvent (agency_id, name, event_type, field, old_value,
                                 new_value, widened, actor, justification)
        VALUES (NEW.agency_id, NEW.name, 'JURISDICTION_CHANGED', 'jurisdiction',
                OLD.jurisdiction, NEW.jurisdiction, NULL, v_actor, v_why);
    END IF;
    IF NEW.signing_public_key_hex IS DISTINCT FROM OLD.signing_public_key_hex THEN
        -- The key itself is in AuthorityKeyEvent; that it changed on the agency row
        -- belongs here, so the two records can be read against each other.
        INSERT INTO AgencyEvent (agency_id, name, event_type, field, old_value,
                                 new_value, widened, actor, justification)
        VALUES (NEW.agency_id, NEW.name, 'SIGNING_KEY_CHANGED', 'signing_public_key_hex',
                left(coalesce(OLD.signing_public_key_hex, '(none)'), 16),
                left(coalesce(NEW.signing_public_key_hex, '(none)'), 16),
                FALSE, v_actor, v_why);
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_agency_audited ON Agency;
CREATE TRIGGER trg_agency_audited
    BEFORE INSERT OR UPDATE OR DELETE ON Agency
    FOR EACH ROW EXECUTE FUNCTION record_agency_change();

DROP TRIGGER IF EXISTS trg_agency_event_append_only ON AgencyEvent;
CREATE TRIGGER trg_agency_event_append_only
    BEFORE UPDATE OR DELETE ON AgencyEvent
    FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();
