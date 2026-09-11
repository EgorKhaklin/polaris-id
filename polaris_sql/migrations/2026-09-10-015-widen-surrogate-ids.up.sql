-- ============================================================================
-- 2026-09-10-015-widen-surrogate-ids.up.sql
--
-- v9.384 (roadmap P7.3) — widen the surrogate ids that run out of integers
-- before the national targets are reached.
--
-- SERIAL is a 32-bit integer with a sequence capped at 2,147,483,647. The
-- capacity model (polaris_web/capacity.py) computes, from this schema and the
-- roadmap's own stated planning targets, how long each sequence lasts:
--
--   VerificationEvent.event_id      5.0 days at the stated 5,000 verifications/s
--                                   sustained target; 11.9 HOURS at the 50,000/s
--                                   peak. Neither figure rests on an assumption:
--                                   one row per verification, and the target is
--                                   quoted from the roadmap.
--   TokenStateEpochLeaf.leaf_id     6.1 EPOCH CLOSURES over a 350M-credential
--                                   population. The table holds one row per token
--                                   per epoch, so this needs no assumption about
--                                   cadence at all: the sixth closure fails.
--   TokenLifecycleEvent.event_id    ~5.9 years
--   TokenSignature.signature_id     ~6.1 years (one row per credential per
--                                   algorithm migration; P7.6 re-signs the whole
--                                   population, so a quantum event consumes 350M
--                                   ids in one pass)
--   AuthAuditLog.audit_id           ~6.8 years
--
-- Nothing is slow and nothing is overloaded when a sequence is exhausted. Every
-- insert on the path simply fails, and on the verification path that is the whole
-- service. The throughput targets are met more than ten times over; this is what
-- actually stops the system reaching them.
--
-- WHY NOW RATHER THAN WHEN IT MATTERS. ALTER COLUMN TYPE rewrites the table and
-- every index on it, and for the partitioned VerificationEvent it rewrites every
-- partition. Run against a national deployment holding two billion rows that is a
-- multi-hour outage on the busiest table in the system. Run against a deployment
-- that has not started, it is instant. The right time to widen an id column is
-- before there is anything in it.
--
-- SAFETY. None of these five columns is referenced by a foreign key anywhere in
-- the schema (they are pure surrogates), so widening them cannot break a join or
-- orphan a row. INTEGER values are a subset of BIGINT, so no value changes and no
-- row is lost. The sequence must be widened alongside the column: a SERIAL's
-- sequence is declared AS integer and keeps the 32-bit ceiling even after the
-- column becomes BIGINT, which would leave the exhaustion exactly where it was
-- while looking fixed.
--
-- NOT INCLUDED. IdentityToken.token_id and Individual.individual_id are also
-- SERIAL and last ~29 years at the stated enrollment rate -- outside the model's
-- 25-year horizon, and both are referenced by foreign keys across the schema, so
-- widening them is a wider change than this one and is a decision to take on its
-- own. The capacity model reports them rather than this migration silently
-- deciding for the operator.
-- Each widening is declared so the expand-contract check can grade it rather than
-- infer it. An ALTER names only the target type, and 01_schema.sql carries the NEW
-- type once this lands, so the old type exists nowhere the checker can read it: the
-- author states the claim and the checker verifies the target matches, the pair is a
-- recognised widening, and no foreign key references the column.
--
-- widens: VerificationEvent.event_id INTEGER -> BIGINT
-- widens: TokenStateEpochLeaf.leaf_id INTEGER -> BIGINT
-- widens: TokenLifecycleEvent.event_id INTEGER -> BIGINT
-- widens: TokenSignature.signature_id INTEGER -> BIGINT
-- widens: AuthAuditLog.audit_id INTEGER -> BIGINT
--
-- The COLUMN change is an EXPAND, not a contract. Old code reading a wider column
-- reads the same values, none of the five is referenced by a foreign key, and the
-- new values old code may now see are surrogate integers it passes through.
-- Narrowing is the direction that breaks a deploy, and the down-migration below is
-- exactly that, which is why it can fail and should.
--
-- BUT THIS MIGRATION IS NOT A ZERO-DOWNTIME OPERATION, and saying so is more useful
-- than a declaration implying it is. Two reasons:
--
--   1. The functions dropped at the end do not exist until the object sync recreates
--      them, so between `polaris-migrate.sh --up` and `--sync-objects` a call to
--      uc7_warrant_audit or the four atlas readers errors. polaris-deploy.sh runs
--      both before rolling either colour, so the gap is seconds, but it is not zero.
--   2. ALTER COLUMN TYPE rewrites the table and every index on it, and for the
--      partitioned VerificationEvent it rewrites every partition. Against a
--      populated national deployment that is hours on the busiest table in the
--      system, which is the whole argument for running this before there is
--      anything in it.
--
-- Run it in a maintenance window. The reason to run it EARLY is that early it costs
-- nothing and late it costs an outage.
-- ============================================================================

-- DEPENDENT VIEWS. PostgreSQL refuses ALTER COLUMN TYPE while a view depends on
-- the column, and three do (TokensWithLifecycleSummary, v_ontology_verification,
-- v_ontology_token_timeline). They are dropped and recreated around the change.
--
-- Their definitions and their GRANTS are read out of the LIVE CATALOG rather than
-- copied from a .sql file. A copy in this migration would be a second source of
-- truth that is correct on the day it is written and wrong the first time somebody
-- edits the view. Dropping a view also drops its grants, and polaris_app holds real
-- privileges on all three, so losing them would take the application down in a way
-- that looks nothing like a migration problem.
--
-- IDEMPOTENT. The column work runs only when a target column is still `integer`,
-- so applying this to a database loaded from the current 01_schema.sql (which now
-- declares BIGSERIAL) touches no view at all. The sequence widening runs
-- unconditionally because it has no dependents and because a sequence left at the
-- 32-bit ceiling under a 64-bit column is exactly the half-finished state this
-- migration exists to avoid.

BEGIN;

-- Sequences first: no dependencies, and this is the half everybody forgets.
ALTER SEQUENCE verificationevent_event_id_seq      AS BIGINT MAXVALUE 9223372036854775807;
ALTER SEQUENCE tokenstateepochleaf_leaf_id_seq     AS BIGINT MAXVALUE 9223372036854775807;
ALTER SEQUENCE tokenlifecycleevent_event_id_seq    AS BIGINT MAXVALUE 9223372036854775807;
ALTER SEQUENCE tokensignature_signature_id_seq     AS BIGINT MAXVALUE 9223372036854775807;
ALTER SEQUENCE authauditlog_audit_id_seq           AS BIGINT MAXVALUE 9223372036854775807;

DO $widen$
DECLARE
    targets  TEXT[][] := ARRAY[
        ARRAY['verificationevent',   'event_id'],
        ARRAY['tokenstateepochleaf', 'leaf_id'],
        ARRAY['tokenlifecycleevent', 'event_id'],
        ARRAY['tokensignature',      'signature_id'],
        ARRAY['authauditlog',        'audit_id']
    ];
    t            TEXT[];
    v            RECORD;
    view_defs    TEXT[] := '{}';
    view_grants  TEXT[] := '{}';
    stmt         TEXT;
    needed       BOOLEAN := FALSE;
BEGIN
    FOREACH t SLICE 1 IN ARRAY targets LOOP
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = t[1] AND column_name = t[2]
                     AND data_type = 'integer') THEN
            needed := TRUE;
        END IF;
    END LOOP;
    IF NOT needed THEN
        RAISE NOTICE 'widen-surrogate-ids: every target column is already 64-bit; '
                     'sequences widened, no view touched';
        RETURN;
    END IF;

    -- Capture, then drop.
    FOR v IN
        SELECT DISTINCT dep.relname AS viewname
        FROM   pg_depend d
        JOIN   pg_rewrite   r   ON r.oid = d.objid
        JOIN   pg_class     dep ON dep.oid = r.ev_class AND dep.relkind = 'v'
        JOIN   pg_class     src ON src.oid = d.refobjid
        JOIN   pg_attribute a   ON a.attrelid = src.oid AND a.attnum = d.refobjsubid
        WHERE  src.relname IN ('verificationevent','tokenstateepochleaf',
                               'tokenlifecycleevent','tokensignature','authauditlog')
          AND  a.attname IN ('event_id','leaf_id','signature_id','audit_id')
    LOOP
        view_defs := view_defs || format('CREATE VIEW %I AS %s', v.viewname,
                                         pg_get_viewdef(v.viewname::regclass, true));
        FOR stmt IN
            SELECT format('GRANT %s ON %I TO %I', g.privs, v.viewname, g.grantee)
            FROM  (SELECT grantee, string_agg(privilege_type, ', ') AS privs
                   FROM   information_schema.role_table_grants
                   WHERE  table_name = v.viewname AND grantee <> current_user
                   GROUP  BY grantee) g
        LOOP
            view_grants := view_grants || stmt;
        END LOOP;
        EXECUTE format('DROP VIEW %I', v.viewname);
    END LOOP;

    -- The widening itself. Partitioned tables rewrite every partition.
    ALTER TABLE VerificationEvent   ALTER COLUMN event_id     TYPE BIGINT;
    ALTER TABLE TokenStateEpochLeaf ALTER COLUMN leaf_id      TYPE BIGINT;
    ALTER TABLE TokenLifecycleEvent ALTER COLUMN event_id     TYPE BIGINT;
    ALTER TABLE TokenSignature      ALTER COLUMN signature_id TYPE BIGINT;
    ALTER TABLE AuthAuditLog        ALTER COLUMN audit_id     TYPE BIGINT;

    FOREACH stmt IN ARRAY view_defs   LOOP EXECUTE stmt; END LOOP;
    FOREACH stmt IN ARRAY view_grants LOOP EXECUTE stmt; END LOOP;
END
$widen$;

-- The row-returning functions that expose these ids declare their result columns
-- explicitly, and CREATE OR REPLACE CANNOT CHANGE A FUNCTION'S RETURN TYPE, so a
-- function left in place fails its very next call with "structure of query does not
-- match function result type". That is how this migration first broke CI, and the
-- failure surfaced in nine unrelated jobs because every one of them loads the schema.
--
-- They are found rather than listed. A TABLE-returning function's result columns are
-- OUT arguments in the catalog, so the ones exposing a widened id as 32-bit can be
-- asked for by name and type. A hand-written list of signatures is worse than useless
-- here: DROP FUNCTION IF EXISTS with a signature that does not match reports "does not
-- exist, skipping" and moves on, leaving exactly the broken function it was meant to
-- remove. Four of the five in the first draft did that.
--
-- The object sync recreates them (polaris-migrate.sh --sync-objects, which
-- polaris-deploy.sh runs after migrating).
DO $drop_stale_fns$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT DISTINCT p.oid::regprocedure AS sig
        FROM   pg_proc p
        JOIN   pg_namespace n ON n.oid = p.pronamespace
        CROSS  JOIN LATERAL unnest(p.proargnames, p.proallargtypes, p.proargmodes)
                     AS a(argname, argtype, argmode)
        WHERE  n.nspname = 'public'
          AND  a.argmode IN ('t', 'o')          -- TABLE columns and OUT parameters
          AND  a.argname IN ('event_id', 'leaf_id', 'signature_id', 'audit_id')
          AND  a.argtype = 'integer'::regtype
    LOOP
        RAISE NOTICE 'widen-surrogate-ids: dropping % (returns a widened id as int4)',
                     r.sig;
        EXECUTE format('DROP FUNCTION %s', r.sig);
    END LOOP;
END
$drop_stale_fns$;

COMMIT;
