-- ============================================================================
-- 2026-09-11-018-relying-party-events.up.sql
--
-- A relying party is an outside organisation that gets to ask this system about
-- people. Three decisions about one were unrecorded anywhere:
--
--   1. REGISTERING one. `polaris rp-register` minted a credential with standing to
--      call /api/v1/verify and left no row in any audit table. Verified by running
--      it: AuthAuditLog, AuditAccessLog, AuthorityKeyEvent and DuressEvent were
--      all unchanged.
--   2. WEAKENING one. `polaris rp-policy <cid> --no-require-zk` is an in-place
--      UPDATE. `require_zk` is what makes the authorize route demand a
--      zero-knowledge step-up before it will answer; with it off the holder
--      authenticates at ACR possession instead of ACR zk. After the change there
--      was no evidence anywhere that it had ever been on.
--   3. DISABLING or re-enabling one. Same: a silent boolean.
--
-- RelyingParty cannot become append-only the way AgencyQuota did in v9.424: the
-- row is live, and the application writes last_used_at on every call. So this
-- follows the shape the tree already uses for a live subject that must still be
-- accountable -- AuthorityKeyEvent beside Agency, audit_token_state_change writing
-- TokenLifecycleEvent from the diff: an append-only event table, written BY A
-- TRIGGER rather than by the caller, so a change made with psql is recorded on the
-- same terms as one made through the CLI.
--
-- phase: expand. Nothing is dropped or narrowed; old code keeps working and its
-- changes start being recorded.
--
-- The canonical copies live in 01_schema.sql / 02_indexes.sql / 06_triggers.sql.
-- REVERSIBLE: the .down.sql drops the trigger and the table. Idempotent.
-- ============================================================================

CREATE TABLE IF NOT EXISTS RelyingPartyEvent (
    event_id        SERIAL PRIMARY KEY,
    -- Deliberately NOT a foreign key to RelyingParty. A relying party is an outside
    -- organisation and a contract ends; the party row gets deleted. The record of what
    -- was decided about it must outlive it, which a restrictive FK would forbid and a
    -- cascading one would erase. client_id is denormalised here for the same reason, so
    -- an event reads on its own after its subject is gone. The only writer is the
    -- trigger, which takes both from NEW, so there is no integrity to lose.
    rp_id           INTEGER NOT NULL,
    client_id       VARCHAR(64) NOT NULL,
    event_type      VARCHAR(30) NOT NULL,
    -- What changed, as text, so the row reads on its own without joining back to
    -- a table whose current value is by definition no longer what it was.
    field           VARCHAR(40),
    old_value       TEXT,
    new_value       TEXT,
    -- TRUE when the change REDUCED what the relying party must satisfy before it
    -- learns something about a person: the zero-knowledge step-up turned off, a
    -- required enrollment status dropped, the context restriction lifted, the
    -- credential enabled, the rate limit raised. This is the column an assessor
    -- filters on, and the reason the table is worth more than a diff log.
    weakened        BOOLEAN NOT NULL DEFAULT FALSE,
    -- Who. `actor` is what the application declared for this transaction and may
    -- be absent; `db_role` is session_user and never is, so no event is anonymous.
    actor           VARCHAR(100),
    db_role         VARCHAR(100) NOT NULL DEFAULT session_user,
    justification   VARCHAR(500),
    recorded_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_rp_event_type CHECK (event_type IN (
        'REGISTERED', 'POLICY_CHANGED', 'ENABLED', 'DISABLED',
        'RATE_LIMIT_CHANGED', 'SECRET_ROTATED', 'RENAMED', 'SCOPE_CHANGED')),
    -- A change event names the field it changed; a registration does not.
    CONSTRAINT chk_rp_event_field CHECK (
        (event_type = 'REGISTERED' AND field IS NULL) OR
        (event_type <> 'REGISTERED' AND field IS NOT NULL))
);

COMMENT ON TABLE RelyingPartyEvent IS
  'Append-only record of every decision about an outside relying party (v9.425): '
  'registration, policy change, enable/disable, secret rotation, rename. Written by '
  'the trg_relying_party_audited trigger from the row diff, not by the caller, so a '
  'change made in psql is recorded on the same terms as one made through the CLI. '
  '`weakened` marks a change that reduced what the party must satisfy before it '
  'learns something about a person -- the zero-knowledge step-up turned off is the '
  'case this table exists for.';

CREATE INDEX IF NOT EXISTS idx_rp_event_rp ON RelyingPartyEvent (rp_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_rp_event_weakened ON RelyingPartyEvent (recorded_at DESC)
    WHERE weakened;

-- ----------------------------------------------------------------------------
-- _rp_weakens: does this change reduce what the relying party must satisfy before
-- it learns something about a person?
--
-- One rule per field, in one place, asked two ways: per field to stamp the
-- `weakened` column on that field's event row, and with p_field = NULL to decide
-- whether the whole statement needs a justification. Two copies of the rule would
-- drift and the drift would be silent: a row marked weakened that needed no reason,
-- or a reason demanded for a row that says it strengthened.
--
-- Registration counts: it grants standing where there was none, the widest weakening
-- available. A rate-limit increase counts: how much an outside party may ask is part
-- of what it must satisfy. A secret rotation and a rename do not: neither changes
-- what the party can learn.
-- ----------------------------------------------------------------------------
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
        WHEN 'required_enrollment' THEN p_old.required_enrollment IS NOT NULL
                                        AND p_new.required_enrollment IS NULL
        WHEN 'required_context_id' THEN p_old.required_context_id IS NOT NULL
                                        AND p_new.required_context_id IS NULL
        WHEN 'scope'               THEN length(p_new.scope) > length(p_old.scope)
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

-- ----------------------------------------------------------------------------
-- record_relying_party_change: the writer.
--
-- AFTER INSERT OR UPDATE, one event row per field that actually changed. The
-- caller cannot skip it and cannot choose what it says.
--
-- last_used_at is deliberately not audited: the application writes it on every
-- API call, it is not a decision anybody made, and recording it would bury the
-- five rows a year that matter under a million that do not.
-- ----------------------------------------------------------------------------
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
    IF _rp_weakens(NULL, CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD END, NEW)
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

DROP TRIGGER IF EXISTS trg_relying_party_audited ON RelyingParty;
CREATE TRIGGER trg_relying_party_audited
    AFTER INSERT OR UPDATE ON RelyingParty
    FOR EACH ROW EXECUTE FUNCTION record_relying_party_change();

-- The record itself is an audit of record.
DROP TRIGGER IF EXISTS trg_rp_event_append_only ON RelyingPartyEvent;
CREATE TRIGGER trg_rp_event_append_only
    BEFORE UPDATE OR DELETE ON RelyingPartyEvent
    FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();
