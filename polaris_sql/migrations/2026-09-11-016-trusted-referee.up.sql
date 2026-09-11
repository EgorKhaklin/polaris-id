-- ============================================================================
-- 2026-09-11-016-trusted-referee.up.sql
--
-- v9.394 (roadmap P4.4) — RefereeVouching: how a person who CANNOT present the
-- usual evidence still gets a credential.
--
-- This is the anti-exclusion mechanism in the enrollment path and the most
-- obvious forgery channel in it, and those are the same table. Somebody with no
-- documents -- no fixed address, fleeing a household, a care leaver, a refugee,
-- an adult who never held a passport -- fails every 800-63A evidence combination
-- and would otherwise be unenrollable. A trusted referee vouches for them.
--
-- A referee who can vouch without limit is a credential factory, so the limits
-- are in the schema rather than in the application that writes to it:
--
--   NOBODY VOUCHES FOR THEMSELVES, and a co-signer is a third person. Obvious,
--   and obvious things are what a direct INSERT gets wrong.
--
--   A VOUCHING CANNOT EXCEED THE REFEREE'S OWN PROOFED LEVEL. You cannot give
--   what you do not have. The levels compare lexicographically ('IAL1' < 'IAL2'
--   < 'IAL3'), which is an accident of the naming worth using rather than
--   working around.
--
--   A VOUCHING CANNOT REACH IAL3, EVER. IAL3 needs a live biometric OF THE
--   APPLICANT in a supervised session. A referee can attest to who somebody is;
--   a referee cannot be that person's face. Capping this in the database rather
--   than the application is the difference between a rule and a habit.
--
-- WHAT THIS TABLE DELIBERATELY DOES NOT DO is reach the credential. IdentityToken
-- gains no column, no flag and no reference here. A credential asserts an
-- assurance LEVEL; it does not assert how the holder arrived at it, and a person
-- who needed a referee is not marked for life in the thing they show at a
-- counter. The authority keeps the full record for accountability. The holder
-- carries a credential that looks like everybody else's.
--
-- Append-only, the eighteenth audit-of-record instance: a vouching is the
-- evidence that an assurance level rests on a named person's word, and an
-- authority that could quietly delete one could quietly unmake the accountability
-- for every credential that referee touched.
--
-- BIGSERIAL from the first line. v9.384 found five 32-bit surrogate ids that
-- exhaust before the national targets are reached; a table added after that
-- lesson does not repeat it.
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS RefereeVouching (
    vouching_id             BIGSERIAL    PRIMARY KEY,
    proofing_id             INTEGER      NOT NULL
                            REFERENCES EnrollmentProofing(proofing_id),
    referee_individual_id   INTEGER      NOT NULL
                            REFERENCES Individual(individual_id),
    applicant_individual_id INTEGER      NOT NULL
                            REFERENCES Individual(individual_id),

    -- The referee's OWN proofed level at the moment of vouching, copied rather
    -- than joined: their level may be re-proofed downward later, and that must
    -- not silently rewrite what this vouching was worth when it was made.
    referee_ial             VARCHAR(6)   NOT NULL
        CHECK (referee_ial IN ('IAL2', 'IAL3')),

    -- Why this person is in a position to vouch. A closed vocabulary, because
    -- "knows the applicant" covers a social worker and a stranger paid fifty
    -- pounds, and the difference is the whole control.
    relationship            VARCHAR(32)  NOT NULL
        CHECK (relationship IN ('LEGAL_GUARDIAN', 'SOCIAL_WORKER', 'MEDICAL_PROFESSIONAL',
                                'NOTARY', 'EDUCATIONAL_INSTITUTION', 'SHELTER_OR_REFUGE',
                                'RELIGIOUS_INSTITUTION', 'EMPLOYER', 'COMMUNITY_LEADER')),

    -- The vocabulary is the full one; the CAP is a named constraint below, so the
    -- error an operator sees says vouching_never_reaches_ial3 rather than
    -- refereevouching_vouched_ial_check. One of those teaches the rule.
    vouched_ial             VARCHAR(6)   NOT NULL
        CHECK (vouched_ial IN ('IAL1', 'IAL2', 'IAL3')),

    -- Required past the rolling bound. NULL below it.
    co_signer_individual_id INTEGER
                            REFERENCES Individual(individual_id),
    vouched_at              TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT referee_is_not_the_applicant
        CHECK (referee_individual_id <> applicant_individual_id),
    CONSTRAINT co_signer_is_a_third_person
        CHECK (co_signer_individual_id IS NULL
               OR (co_signer_individual_id <> referee_individual_id
                   AND co_signer_individual_id <> applicant_individual_id)),
    -- You cannot give what you do not have.
    CONSTRAINT cannot_vouch_above_own_level
        CHECK (vouched_ial <= referee_ial),
    -- A referee cannot be the applicant's face.
    CONSTRAINT vouching_never_reaches_ial3
        CHECK (vouched_ial <> 'IAL3')
);

-- The compromise query: every enrollment one referee touched, in one index scan.
-- A referee found to have vouched falsely makes every credential they touched a
-- question, and an authority that cannot enumerate them cannot answer it.
CREATE INDEX IF NOT EXISTS idx_vouching_by_referee
    ON RefereeVouching (referee_individual_id, vouched_at DESC);
CREATE INDEX IF NOT EXISTS idx_vouching_by_proofing
    ON RefereeVouching (proofing_id);

COMMENT ON TABLE RefereeVouching IS
  'v9.394 / P4.4. How somebody who cannot present the usual evidence still gets a '
  'credential, and the record that an assurance level rests on a named person''s '
  'word. Append-only. Nothing here reaches IdentityToken: a credential asserts a '
  'level, never the circumstances the holder was in when they got it.';

REVOKE UPDATE, DELETE ON RefereeVouching FROM polaris_app;

COMMIT;
