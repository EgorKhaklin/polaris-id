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
-- This is an EXPAND, not a contract. A rolling deploy runs the old code against this
-- schema and nothing breaks: every value the old column could hold this one holds,
-- none of the five is referenced by a foreign key, and the new values old code may
-- now see are surrogate integers it passes through. Narrowing is the direction that
-- breaks a deploy, and the down-migration below is exactly that, which is why it can
-- fail and should.
-- ============================================================================

BEGIN;

-- The verification path. Partitioned: this rewrites every partition.
ALTER TABLE VerificationEvent      ALTER COLUMN event_id     TYPE BIGINT;
ALTER SEQUENCE verificationevent_event_id_seq      AS BIGINT MAXVALUE 9223372036854775807;

-- One leaf per credential per epoch: the sixth closure of a national population
-- exhausts the 32-bit space.
ALTER TABLE TokenStateEpochLeaf    ALTER COLUMN leaf_id      TYPE BIGINT;
ALTER SEQUENCE tokenstateepochleaf_leaf_id_seq     AS BIGINT MAXVALUE 9223372036854775807;

-- The append-only lifecycle record: C1 makes it permanent, so it only grows.
ALTER TABLE TokenLifecycleEvent    ALTER COLUMN event_id     TYPE BIGINT;
ALTER SEQUENCE tokenlifecycleevent_event_id_seq    AS BIGINT MAXVALUE 9223372036854775807;

-- A quantum event (P7.6) writes one row per credential in a single pass.
ALTER TABLE TokenSignature         ALTER COLUMN signature_id TYPE BIGINT;
ALTER SEQUENCE tokensignature_signature_id_seq     AS BIGINT MAXVALUE 9223372036854775807;

-- Operator authentication, append-only.
ALTER TABLE AuthAuditLog           ALTER COLUMN audit_id     TYPE BIGINT;
ALTER SEQUENCE authauditlog_audit_id_seq           AS BIGINT MAXVALUE 9223372036854775807;

COMMIT;
