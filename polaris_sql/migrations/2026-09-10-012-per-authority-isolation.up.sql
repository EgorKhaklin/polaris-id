-- 012: per-authority operator isolation (roadmap P3.9).
--
-- THE REVIEW'S FINDING, in the migration that acts on it. A Polaris instance can hold many
-- agencies: the schema permits it and the shipped seed demonstrates six. An operator was
-- global, with no agency binding on AppUser and no scoping on any of the 74 operator routes;
-- sixteen of them read credential or holder data with no issuing-agency filter at all. In the
-- topology the ADR chose, each authority runs its OWN instance, which makes a global operator
-- correct. Nothing enforced that assumption.
--
-- Patching sixteen query bodies would be exactly the application-level policy this schema
-- exists to refuse. So the isolation is a database guarantee: a session setting the
-- application sets per request, and policies that filter on it.
--
-- WHERE IT IS WELL-DEFINED, AND WHERE IT IS NOT. A credential belongs to the authority that
-- issued it, and an event to the authority that requested it, so those isolate cleanly. An
-- INDIVIDUAL does not belong to an authority: a person is a person, and two authorities may
-- both have issued to them over time. There is no honest per-authority policy for
-- Individual, and inventing one would assert an ownership the model does not have.
--
-- The consequence is stated rather than papered over: in a shared instance these policies
-- bound what an operator sees, and do not achieve isolation, because holder identity remains
-- visible. That is why the one-authority-per-instance topology is load-bearing rather than
-- stylistic. See docs/design/per-authority-isolation.md.
--
-- The setting is UNSET by default, and every policy is permissive when it is unset, so a
-- single-authority deployment, the unauthenticated API paths and the test suites are
-- unaffected.

ALTER TABLE AppUser
    ADD COLUMN IF NOT EXISTS agency_id INTEGER REFERENCES Agency(agency_id);

COMMENT ON COLUMN AppUser.agency_id IS
  'The authority this operator acts for (P3.9). NULL means unscoped, which is correct for a '
  'single-authority instance and is the default. When set, the application puts it in '
  'polaris.operator_agency_id for the request and the row-level policies below filter on it.';

-- IdentityToken: the anchor. Everything credential-bearing joins through it, so a row this
-- operator cannot see contributes nothing to any join.
ALTER TABLE IdentityToken ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS token_authority_isolation ON IdentityToken;
CREATE POLICY token_authority_isolation ON IdentityToken
    USING (
        -- The cast must never see an empty string. An OR does not guarantee short-circuit
        -- evaluation in Postgres, so a guard of the form `setting = '' OR col = setting::int`
        -- still evaluates the cast and raises on an unscoped session. NULLIF turns the empty
        -- or missing setting into NULL, and the coalesce then compares the column with itself,
        -- which is true for every row. The isolation drill caught this before it shipped.
        issuing_agency_id = coalesce(
            NULLIF(current_setting('polaris.operator_agency_id', true), '')::INTEGER,
            issuing_agency_id)
    );

-- Verification events belong to the authority that REQUESTED the verification, which is a
-- different relation from issuance and is scoped on its own column.
ALTER TABLE VerificationEvent ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS verification_authority_isolation ON VerificationEvent;
CREATE POLICY verification_authority_isolation ON VerificationEvent
    USING (
        requesting_agency_id = coalesce(
            NULLIF(current_setting('polaris.operator_agency_id', true), '')::INTEGER,
            requesting_agency_id)
    );

-- A lifecycle event's authority column is `actor_agency_id`: who ACTED, not who issued, and
-- it is nullable because some transitions have no agency actor. A NULL actor is visible to
-- every operator rather than to none: hiding a transition nobody is recorded as having made
-- would make the audit trail read as if it never happened, which is the opposite of what an
-- append-only audit of record is for.
ALTER TABLE TokenLifecycleEvent ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS lifecycle_authority_isolation ON TokenLifecycleEvent;
CREATE POLICY lifecycle_authority_isolation ON TokenLifecycleEvent
    USING (
        actor_agency_id IS NULL
        OR actor_agency_id = coalesce(
            NULLIF(current_setting('polaris.operator_agency_id', true), '')::INTEGER,
            actor_agency_id)
    );
