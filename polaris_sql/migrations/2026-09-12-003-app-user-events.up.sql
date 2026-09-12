-- ============================================================================
-- 2026-09-12-003-app-user-events.up.sql
--
-- AppUser holds the operator accounts: who may sign in, what role they hold, which
-- authority they belong to, and the date by which they must carry a hardware key.
-- It had no trigger. Verified against a loaded database: pg_trigger returned zero
-- non-internal rows for the table.
--
-- What that means in practice. AuthAuditLog records LOGIN_SUCCESS, ACCOUNT_CREATED,
-- PASSWORD_CHANGED and eighteen other events, so the system looks well recorded, but
-- every one of those rows is written by the APPLICATION and only when the application
-- chooses to. An UPDATE in psql that promotes an auditor to admin, reactivates a
-- disabled account, or pushes the WebAuthn deadline out by a year writes nothing
-- anywhere, and the account table afterwards is indistinguishable from one where that
-- never happened.
--
-- v9.425 gave RelyingParty its record and v9.440 gave Agency one. This is the third
-- and last of the tables that decide who may act: the outside organisation, the
-- issuing authority, and the operator.
--
-- phase: expand. Nothing is dropped or narrowed; old code keeps working and its
-- changes start being recorded.
--
-- The canonical copies live in 01_schema.sql / 06_triggers.sql.
-- REVERSIBLE: 2026-09-12-003-app-user-events.down.sql drops the trigger and the table,
-- which discards the record. Idempotent: IF NOT EXISTS / OR REPLACE.
-- ============================================================================

CREATE TABLE IF NOT EXISTS AppUserEvent (
    event_id      SERIAL PRIMARY KEY,
    -- Deliberately NOT a foreign key, for the reason AgencyEvent is not one (v9.440):
    -- an account is removable and the record of what it was given has to outlive it.
    user_id       INTEGER NOT NULL,
    username      VARCHAR(60) NOT NULL,
    event_type    VARCHAR(30) NOT NULL,
    field         VARCHAR(40),
    -- NEVER a secret. password_hash and recovery_code_hash are recorded as the FACT
    -- that they changed and never as a value, held by chk_app_user_event_no_secret
    -- below rather than by the trigger alone: a record of the account table is not a
    -- place to accumulate old password hashes to attack offline.
    old_value     TEXT,
    new_value     TEXT,
    -- Three-valued, for the reason AgencyEvent.widened is (v9.440). TRUE: the change
    -- gave this account more than it had -- it was created, its role rose, it was
    -- reactivated, or its hardware-key deadline moved further away. FALSE: it granted
    -- nothing. NULL: the account moved between authorities, which P3.9 makes a real
    -- boundary and which the database cannot rank, since neither agency is above the
    -- other. The assessor's filter is `widened IS NOT FALSE`.
    widened       BOOLEAN DEFAULT FALSE,
    actor         VARCHAR(100),
    db_role       VARCHAR(100) NOT NULL DEFAULT session_user,
    justification VARCHAR(500),
    recorded_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_app_user_event_type CHECK (event_type IN (
        'CREATED', 'DELETED', 'RENAMED', 'ROLE_CHANGED', 'ACTIVATED', 'DEACTIVATED',
        'WEBAUTHN_DEADLINE_CHANGED', 'AGENCY_CHANGED', 'PASSWORD_CHANGED',
        'RECOVERY_CODE_CHANGED')),
    CONSTRAINT chk_app_user_event_field CHECK (
        (event_type IN ('CREATED', 'DELETED') AND field IS NULL) OR
        (event_type NOT IN ('CREATED', 'DELETED') AND field IS NOT NULL)),
    CONSTRAINT chk_app_user_event_no_secret CHECK (
        event_type NOT IN ('PASSWORD_CHANGED', 'RECOVERY_CODE_CHANGED')
        OR (old_value IS NULL AND new_value IS NULL))
);

COMMENT ON TABLE AppUserEvent IS
    'Append-only record of every decision about an operator account (v9.443). Written '
    'by trg_app_user_audited from the row diff, never by the caller. Holds no secret: '
    'a password or recovery-code change is recorded as the fact and never as a value.';

CREATE INDEX IF NOT EXISTS idx_appuserevent_user ON AppUserEvent (user_id, event_id);
CREATE INDEX IF NOT EXISTS idx_appuserevent_widened ON AppUserEvent (recorded_at)
    WHERE widened IS NOT FALSE;

-- ---------------------------------------------------------------------------
-- The recorder. BEFORE INSERT OR UPDATE OR DELETE, so a change made in psql is
-- recorded on the same terms as one made through the console or the CLI.
--
-- Four columns are deliberately NOT recorded: last_login_at, failed_login_count,
-- locked_until and created_at. The first three are written on every sign-in and
-- every failed attempt, so recording them would put a row per request into the
-- table and bury the decisions among them. They are live state, not decisions.
-- AuthAuditLog is where the sign-ins live.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION _app_user_role_rank(p_role TEXT) RETURNS INTEGER
LANGUAGE sql IMMUTABLE AS $$
    -- The one place the role ladder is written down. An auditor reads, an operator
    -- acts, an admin changes who may do either.
    SELECT CASE p_role WHEN 'auditor' THEN 1 WHEN 'operator' THEN 2
                       WHEN 'admin' THEN 3 ELSE 0 END;
$$;

-- TRUE when the change gives this account more than it had. Taken as a whole row, so
-- the gate and the recorder cannot drift apart: both ask this one function. The shape
-- _rp_weakens established in v9.425.
CREATE OR REPLACE FUNCTION _app_user_widens(p_op TEXT, p_old AppUser, p_new AppUser)
RETURNS BOOLEAN LANGUAGE sql IMMUTABLE AS $$
    SELECT p_op = 'INSERT'
           OR _app_user_role_rank(p_new.role) > _app_user_role_rank(p_old.role)
           OR (p_new.is_active AND NOT p_old.is_active)
           -- A deadline that moves further away, or disappears, gives this account
           -- longer without a hardware key. NULL is the most permissive value it has.
           OR (p_new.webauthn_required_after IS DISTINCT FROM p_old.webauthn_required_after
               AND (p_new.webauthn_required_after IS NULL
                    OR (p_old.webauthn_required_after IS NOT NULL
                        AND p_new.webauthn_required_after > p_old.webauthn_required_after)));
$$;

-- Moving an operator between authorities. P3.9 made the agency boundary the thing that
-- bounds what an operator can see, and no ordering puts one authority above another, so
-- the database refuses it without a reason and records it as NULL rather than guessing.
CREATE OR REPLACE FUNCTION _app_user_rescopes(p_op TEXT, p_old AppUser, p_new AppUser)
RETURNS BOOLEAN LANGUAGE sql IMMUTABLE AS $$
    SELECT p_op = 'UPDATE' AND p_new.agency_id IS DISTINCT FROM p_old.agency_id;
$$;

-- The gate. BEFORE, because a refusal has to happen before the write.
CREATE OR REPLACE FUNCTION guard_app_user_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    v_why VARCHAR(500) := NULLIF(current_setting('polaris.justification', true), '');
BEGIN
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.user_id IS DISTINCT FROM OLD.user_id THEN
        RAISE EXCEPTION
            'AppUser.user_id is immutable: ten foreign keys reference it, and changing '
            'it would silently re-attribute every action recorded against this operator.'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF (_app_user_widens(TG_OP, OLD, NEW) OR _app_user_rescopes(TG_OP, OLD, NEW))
       AND (v_why IS NULL OR length(trim(v_why)) < 20) THEN
        RAISE EXCEPTION
            'creating an operator account, raising its role, reactivating it, moving '
            'its hardware-key deadline further away, or moving it to another authority '
            'needs a justification of at least 20 characters: set polaris.justification '
            '(polaris user-create --justification)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;

-- The recorder. AFTER, and that is load-bearing rather than stylistic.
--
-- `INSERT ... ON CONFLICT DO UPDATE` fires a BEFORE INSERT trigger SPECULATIVELY: the
-- trigger runs, the conflict is then detected, and the row is updated instead. A BEFORE
-- recorder therefore writes a CREATED event for a row that already existed, and its
-- write is not rolled back. Five callers in this tree use that form. AFTER INSERT fires
-- only when an insert actually happened, so the record says what occurred.
CREATE OR REPLACE FUNCTION record_app_user_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    v_actor VARCHAR(100) := NULLIF(current_setting('polaris.actor', true), '');
    v_why   VARCHAR(500) := NULLIF(current_setting('polaris.justification', true), '');
    v_dead  BOOLEAN;
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Recorded, not refused, which is the deliberate difference from Agency
        -- (v9.440). An authority that issued credentials cannot be unmade; an account
        -- created by mistake before it ever acted can be. An operator who DID act is
        -- already held by the ten foreign keys that point here, so the database
        -- refuses that deletion on its own and does not need a rule of its own.
        INSERT INTO AppUserEvent (user_id, username, event_type, widened, actor,
                                  justification, old_value)
        VALUES (OLD.user_id, OLD.username, 'DELETED', FALSE, v_actor, v_why,
                format('role=%s active=%s agency_id=%s',
                       OLD.role, OLD.is_active, coalesce(OLD.agency_id::TEXT, 'none')));
        RETURN NULL;
    END IF;

    IF TG_OP = 'INSERT' THEN
        INSERT INTO AppUserEvent (user_id, username, event_type, widened, actor,
                                  justification, new_value)
        VALUES (NEW.user_id, NEW.username, 'CREATED', TRUE, v_actor, v_why,
                format('role=%s active=%s agency_id=%s webauthn_required_after=%s',
                       NEW.role, NEW.is_active, coalesce(NEW.agency_id::TEXT, 'none'),
                       coalesce(NEW.webauthn_required_after::TEXT, 'none')));
        RETURN NULL;
    END IF;

    v_dead := _app_user_widens('UPDATE', OLD, NEW)
              AND (NEW.webauthn_required_after IS DISTINCT FROM OLD.webauthn_required_after)
              AND NEW.role = OLD.role AND NEW.is_active = OLD.is_active;

    IF NEW.username IS DISTINCT FROM OLD.username THEN
        INSERT INTO AppUserEvent (user_id, username, event_type, field, old_value,
                                  new_value, widened, actor, justification)
        VALUES (NEW.user_id, NEW.username, 'RENAMED', 'username', OLD.username,
                NEW.username, FALSE, v_actor, v_why);
    END IF;
    IF NEW.role IS DISTINCT FROM OLD.role THEN
        INSERT INTO AppUserEvent (user_id, username, event_type, field, old_value,
                                  new_value, widened, actor, justification)
        VALUES (NEW.user_id, NEW.username, 'ROLE_CHANGED', 'role', OLD.role, NEW.role,
                _app_user_role_rank(NEW.role) > _app_user_role_rank(OLD.role),
                v_actor, v_why);
    END IF;
    IF NEW.is_active IS DISTINCT FROM OLD.is_active THEN
        INSERT INTO AppUserEvent (user_id, username, event_type, field, old_value,
                                  new_value, widened, actor, justification)
        VALUES (NEW.user_id, NEW.username,
                CASE WHEN NEW.is_active THEN 'ACTIVATED' ELSE 'DEACTIVATED' END,
                'is_active', OLD.is_active::TEXT, NEW.is_active::TEXT,
                NEW.is_active AND NOT OLD.is_active, v_actor, v_why);
    END IF;
    IF NEW.webauthn_required_after IS DISTINCT FROM OLD.webauthn_required_after THEN
        INSERT INTO AppUserEvent (user_id, username, event_type, field, old_value,
                                  new_value, widened, actor, justification)
        VALUES (NEW.user_id, NEW.username, 'WEBAUTHN_DEADLINE_CHANGED',
                'webauthn_required_after',
                coalesce(OLD.webauthn_required_after::TEXT, 'none'),
                coalesce(NEW.webauthn_required_after::TEXT, 'none'),
                NEW.webauthn_required_after IS NULL
                OR (OLD.webauthn_required_after IS NOT NULL
                    AND NEW.webauthn_required_after > OLD.webauthn_required_after),
                v_actor, v_why);
    END IF;
    IF NEW.agency_id IS DISTINCT FROM OLD.agency_id THEN
        INSERT INTO AppUserEvent (user_id, username, event_type, field, old_value,
                                  new_value, widened, actor, justification)
        VALUES (NEW.user_id, NEW.username, 'AGENCY_CHANGED', 'agency_id',
                coalesce(OLD.agency_id::TEXT, 'none'), coalesce(NEW.agency_id::TEXT, 'none'),
                NULL, v_actor, v_why);
    END IF;
    -- The fact, never the value. chk_app_user_event_no_secret holds the same line at
    -- the table, so a future caller cannot put a hash here by writing a row directly.
    IF NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN
        INSERT INTO AppUserEvent (user_id, username, event_type, field, widened, actor,
                                  justification)
        VALUES (NEW.user_id, NEW.username, 'PASSWORD_CHANGED', 'password_hash', FALSE,
                v_actor, v_why);
    END IF;
    IF NEW.recovery_code_hash IS DISTINCT FROM OLD.recovery_code_hash THEN
        INSERT INTO AppUserEvent (user_id, username, event_type, field, widened, actor,
                                  justification)
        VALUES (NEW.user_id, NEW.username, 'RECOVERY_CODE_CHANGED', 'recovery_code_hash',
                FALSE, v_actor, v_why);
    END IF;

    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_app_user_guarded ON AppUser;
CREATE TRIGGER trg_app_user_guarded
    BEFORE INSERT OR UPDATE OR DELETE ON AppUser
    FOR EACH ROW EXECUTE FUNCTION guard_app_user_change();

DROP TRIGGER IF EXISTS trg_app_user_audited ON AppUser;
CREATE TRIGGER trg_app_user_audited
    AFTER INSERT OR UPDATE OR DELETE ON AppUser
    FOR EACH ROW EXECUTE FUNCTION record_app_user_change();

-- A database this migration runs against already has operator accounts and no record
-- of any of them. Backfill exactly what the trigger would have written, idempotently,
-- so a migrated deployment does not show operators with no origin. A FRESH load needs
-- none: 06_triggers.sql runs before 10_auth.sql, so the recorder is already installed
-- when the seed accounts are created and writes these rows itself.
INSERT INTO AppUserEvent (user_id, username, event_type, widened, actor, justification,
                          new_value)
SELECT u.user_id, u.username, 'CREATED', TRUE, 'migration',
       'account predates the recorder; backfilled by 2026-09-12-003-app-user-events',
       format('role=%s active=%s agency_id=%s', u.role, u.is_active,
              coalesce(u.agency_id::TEXT, 'none'))
  FROM AppUser u
 WHERE NOT EXISTS (SELECT 1 FROM AppUserEvent e
                    WHERE e.user_id = u.user_id AND e.event_type = 'CREATED');

DROP TRIGGER IF EXISTS trg_app_user_event_append_only ON AppUserEvent;
CREATE TRIGGER trg_app_user_event_append_only
    BEFORE UPDATE OR DELETE ON AppUserEvent
    FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();
