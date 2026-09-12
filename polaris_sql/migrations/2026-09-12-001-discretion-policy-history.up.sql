-- ============================================================================
-- 2026-09-12-001-discretion-policy-history.up.sql
--
-- IssuerDiscretionPolicy is the per-agency bound on the share of its own tokens
-- one issuing agency may revoke in a rolling window. The system default is 5.00%
-- over 30 days; a row here overrides it, up to 100%.
--
-- docs/operator/SECURITY-CONTROLS.md says the override carries "a justification of
-- at least 20 characters so any loosening is auditable". The justification column
-- exists and the floor is real. The sentence was still false: agency_id was the
-- PRIMARY KEY, so a change overwrote max_revoke_percent, set_by_admin, set_at and
-- justification in place. Verified by raising an agency's bound from 5% to 80% --
-- afterwards one row held 80%, "second-admin" and a new reason, the baseline and the
-- name of whoever set it were gone, and no audit table anywhere had gained a row.
--
-- A loosening from 5% to 80% is the single most consequential per-agency setting in
-- the schema: it is what stands between one authority and mass revocation of the
-- credentials it issued. It is now kept the way RetentionPolicy (v9.379) and
-- AgencyQuota (v9.424) are kept: append, supersede, never edit.
--
-- phase: contract
-- expands: 2026-09-11-001-agency-quota-history
--
-- Contract because agency_id stops being unique on its own. Nothing in the tree
-- writes this table outside seed data and tests, and the only reader is
-- uc8_revoke_token, whose lookup this migration narrows in the same step, so the
-- blast radius during a rolling deploy is nil. Declared as contract regardless
-- because the primary key is being replaced.
--
-- The canonical copies live in 01_schema.sql / 02_indexes.sql / 05_procedures.sql
-- / 06_triggers.sql. REVERSIBLE and LOSSY: the .down.sql keeps the live row per
-- agency and drops the history, because the old shape cannot hold it. Idempotent.
-- ============================================================================

ALTER TABLE IssuerDiscretionPolicy ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMP;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'issuerdiscretionpolicy'
                      AND column_name = 'policy_id') THEN
        ALTER TABLE IssuerDiscretionPolicy ADD COLUMN policy_id SERIAL;
        ALTER TABLE IssuerDiscretionPolicy DROP CONSTRAINT issuerdiscretionpolicy_pkey;
        ALTER TABLE IssuerDiscretionPolicy ADD PRIMARY KEY (policy_id);
        ALTER TABLE IssuerDiscretionPolicy ALTER COLUMN agency_id SET NOT NULL;
    END IF;
END $$;

-- One bound in force per agency; the superseded ones stay and do not collide.
-- uc8_revoke_token reads exactly one row, so which row it is must not depend on
-- insertion order.
CREATE UNIQUE INDEX IF NOT EXISTS uq_effective_discretion_policy
    ON IssuerDiscretionPolicy (agency_id) WHERE superseded_at IS NULL;

COMMENT ON TABLE IssuerDiscretionPolicy IS
  'Per-agency override of the revocation-share bound (P-R11.6): the share of its '
  'own tokens one issuing agency may revoke in a rolling window, against a system '
  'default of 5.00% over 30 days. justification >= 20 chars, and since v9.426 the '
  'row survives the next change: setting a bound supersedes the live row and appends '
  'a new one, uq_effective_discretion_policy allows exactly one in force per agency, '
  'and trg_discretion_policy_immutable refuses any other edit. So a LOOSENING is '
  'auditable in fact and not only in intent: who raised the bound, from what, when, '
  'and the reason they gave all survive. Set with polaris-id discretion-set; read '
  'with discretion-show --history.';

-- ----------------------------------------------------------------------------
-- enforce_discretion_policy_immutability (v9.426)
--
-- The third instance of the same guard, for the same reason: a decision about how
-- much an authority may do is an audit of record, and editing it in place erases
-- the thing it exists to prove.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_discretion_policy_immutability() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'IssuerDiscretionPolicy is append-only: DELETE is refused. A revocation '
            'bound is what stands between one authority and mass revocation of the '
            'credentials it issued; supersede it instead.'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF NEW.policy_id          IS DISTINCT FROM OLD.policy_id
       OR NEW.agency_id          IS DISTINCT FROM OLD.agency_id
       OR NEW.max_revoke_percent IS DISTINCT FROM OLD.max_revoke_percent
       OR NEW.window_days        IS DISTINCT FROM OLD.window_days
       OR NEW.set_by_admin       IS DISTINCT FROM OLD.set_by_admin
       OR NEW.set_at             IS DISTINCT FROM OLD.set_at
       OR NEW.justification      IS DISTINCT FROM OLD.justification THEN
        RAISE EXCEPTION
            'IssuerDiscretionPolicy is append-only: only superseded_at may be '
            'updated. Changing a bound appends a row; it does not rewrite the old one.'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF OLD.superseded_at IS NOT NULL
       AND NEW.superseded_at IS DISTINCT FROM OLD.superseded_at THEN
        RAISE EXCEPTION
            'IssuerDiscretionPolicy row % was superseded at %; that cannot be moved '
            'or undone.', OLD.policy_id, OLD.superseded_at
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_discretion_policy_immutable ON IssuerDiscretionPolicy;
CREATE TRIGGER trg_discretion_policy_immutable
    BEFORE UPDATE OR DELETE ON IssuerDiscretionPolicy
    FOR EACH ROW EXECUTE FUNCTION enforce_discretion_policy_immutability();
