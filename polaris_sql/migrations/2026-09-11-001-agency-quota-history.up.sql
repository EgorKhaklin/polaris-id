-- ============================================================================
-- 2026-09-11-001-agency-quota-history.up.sql
--
-- v9.424: AgencyQuota keeps its history and stops being editable in place.
--
-- The table has always carried set_by_admin, set_at and a justification of at
-- least twenty characters, and its own COMMENT says a cap is "auditable from
-- the row alone". It was not. agency_id was the primary key and `polaris
-- quota-set` wrote ON CONFLICT DO UPDATE, so every change OVERWROTE who set the
-- previous cap, when, and why. The question "who raised this agency's issuance
-- cap last month, and what reason did they give" had no answer, and nothing
-- stopped the surviving row being edited or deleted either.
--
-- A quota is a bound on the authority's own power: how many credentials an
-- agency may issue and revoke per day. RetentionPolicy, which is the same shape
-- of decision, has had supersede-and-append plus an immutability trigger since
-- P1.11. This gives AgencyQuota the same treatment, deliberately mirroring it.
--
-- CHANGES (1): quota_id SERIAL becomes the primary key; agency_id becomes an
-- ordinary NOT NULL column, so one agency may hold many rows over time.
-- CHANGES (2): superseded_at, and uq_effective_agency_quota, a PARTIAL unique
-- index over agency_id WHERE superseded_at IS NULL. Exactly one live row per
-- agency, enforced by the database rather than by the writer remembering.
-- ADDS (3): enforce_agency_quota_immutability(), modelled line for line on the
-- retention trigger: DELETE refused, UPDATE confined to superseded_at, and
-- superseded_at moves NULL -> timestamp once and never back.
-- CHANGES (4): enforce_agency_quota() reads the LIVE row. A superseded cap must
-- not bind, and without this filter the lookup would find several.
--
-- The canonical copies live in 01_schema.sql / 02_indexes.sql / 06_triggers.sql.
-- REVERSIBLE: the .down.sql restores agency_id as the primary key, which is
-- LOSSY by nature -- it keeps the live row per agency and drops the history,
-- because the old shape cannot hold it. Idempotent: IF NOT EXISTS / OR REPLACE.
-- ============================================================================

-- phase: contract
-- expands: 2026-09-01-002-agency-quota
--
-- Contract, not expand, and the distinction is real rather than paperwork. The
-- previous CLI wrote `INSERT ... ON CONFLICT (agency_id) DO UPDATE`, which needs a
-- unique constraint on agency_id ALONE as its arbiter. After this migration the only
-- uniqueness on agency_id is PARTIAL (WHERE superseded_at IS NULL), and Postgres will
-- not accept a partial index as an arbiter unless the statement repeats the predicate.
-- So during a rolling deploy an old app instance's quota-set raises
-- `there is no unique or exclusion constraint matching the ON CONFLICT specification`
-- and refuses the write. Nothing else reads or writes this table: no route, no stored
-- procedure, no foreign key, and the enforce_agency_quota trigger only SELECTs from it.
-- The blast radius is one operator command, refusing loudly, for the length of one
-- rollout. Deploy the CLI change with this migration, not after it.

ALTER TABLE AgencyQuota ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMP;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'agencyquota' AND column_name = 'quota_id') THEN
        ALTER TABLE AgencyQuota ADD COLUMN quota_id SERIAL;
        ALTER TABLE AgencyQuota DROP CONSTRAINT agencyquota_pkey;
        ALTER TABLE AgencyQuota ADD PRIMARY KEY (quota_id);
        ALTER TABLE AgencyQuota ALTER COLUMN agency_id SET NOT NULL;
    END IF;
END $$;

-- One LIVE cap per agency; the superseded ones stay and do not collide.
CREATE UNIQUE INDEX IF NOT EXISTS uq_effective_agency_quota
    ON AgencyQuota (agency_id) WHERE superseded_at IS NULL;

COMMENT ON TABLE AgencyQuota IS
  'Opt-in per-agency caps (v9.190 / P1.8): issuances per rolling day, '
  'revocations per rolling day, verifications per rolling hour. Enforced by '
  'the enforce_agency_quota trigger on every write path. NULL = no cap of '
  'that kind; no live row = no caps. justification >= 20 chars so any cap is '
  'auditable from the row alone -- and since v9.424 the row survives the next '
  'change: setting a cap supersedes the live row and appends a new one, the '
  'table is immutable apart from that, and uq_effective_agency_quota keeps '
  'exactly one live row per agency. Set with `polaris quota-set`.';

-- ----------------------------------------------------------------------------
-- enforce_agency_quota_immutability (v9.424)
--
-- The sibling of enforce_retention_policy_immutability, and for the same
-- reason: a decision about how much an authority may do is an audit of record,
-- and editing it in place erases the thing it exists to prove.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_agency_quota_immutability()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'AgencyQuota is append-only: DELETE is refused. A quota is a bound '
            'on an agency''s own power and its history is an audit of record; '
            'supersede it instead.'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF NEW.quota_id      IS DISTINCT FROM OLD.quota_id
       OR NEW.agency_id     IS DISTINCT FROM OLD.agency_id
       OR NEW.issue_per_day   IS DISTINCT FROM OLD.issue_per_day
       OR NEW.revoke_per_day  IS DISTINCT FROM OLD.revoke_per_day
       OR NEW.verify_per_hour IS DISTINCT FROM OLD.verify_per_hour
       OR NEW.set_by_admin    IS DISTINCT FROM OLD.set_by_admin
       OR NEW.set_at          IS DISTINCT FROM OLD.set_at
       OR NEW.justification   IS DISTINCT FROM OLD.justification THEN
        RAISE EXCEPTION
            'AgencyQuota is append-only: only superseded_at may be updated. '
            'Changing a cap appends a row; it does not rewrite the old one.'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF OLD.superseded_at IS NOT NULL
       AND NEW.superseded_at IS DISTINCT FROM OLD.superseded_at THEN
        RAISE EXCEPTION
            'AgencyQuota row % was superseded at %; that cannot be moved or undone.',
            OLD.quota_id, OLD.superseded_at
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_agency_quota_immutable ON AgencyQuota;
CREATE TRIGGER trg_agency_quota_immutable
    BEFORE UPDATE OR DELETE ON AgencyQuota
    FOR EACH ROW EXECUTE FUNCTION enforce_agency_quota_immutability();
