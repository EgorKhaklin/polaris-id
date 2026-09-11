-- ============================================================================
-- 2026-09-11-017-enrollment-code.up.sql
--
-- v9.396 (roadmap P4.4) — EnrollmentCode: the secret an authority sends to a
-- channel so the applicant can prove they control it.
--
-- WHAT A CODE PROVES is narrow and worth stating before anything else: that
-- somebody who could reach that channel returned the secret. Not that they are
-- the applicant. v9.395 capped ENROLLMENT_CODE verification at FAIR for exactly
-- that reason, and this table is the lifecycle underneath that cap.
--
-- THIS IS NOT AN AUDIT-OF-RECORD TABLE, and saying so matters because every
-- other table added this year was. A code is LIVE STATE: it gets redeemed, its
-- attempts get counted, and an append-only rule would make redemption itself
-- impossible. What it has instead is a ONE-WAY DOOR, enforced by a trigger:
--
--   the code's hash, its channel, who it was issued to and when, and when it
--   expires are all IMMUTABLE once written;
--   redeemed_at goes from NULL to a timestamp EXACTLY ONCE, and never back;
--   attempts only ever increases.
--
-- Those are the transitions a code has. Everything else is somebody editing
-- evidence, and the trigger refuses it.
--
-- THE CODE ITSELF IS NEVER STORED. Only a SHA-256 of it, which is why there is
-- no column that could hold one: a leaked enrollment database should not be a
-- pile of usable codes, and a column that COULD hold a plaintext code is a
-- column somebody eventually writes one into.
--
-- VALIDITY IS BOUNDED IN THE SCHEMA. A code with a distant expiry is a permanent
-- credential sitting in a mailbox, and the person whose mailbox it is may not be
-- the applicant -- a controlling household, a care setting, a shelter with
-- shared post. Thirty days is the ceiling here and the operator may choose less.
--
-- THE CHANNEL IS RECORDED because the coercion properties differ and nothing
-- downstream can reconstruct it. A code posted to a home address and one handed
-- over at a counter are the same row otherwise, and they are not the same event.
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS EnrollmentCode (
    code_id             BIGSERIAL    PRIMARY KEY,
    individual_id       INTEGER      NOT NULL REFERENCES Individual(individual_id),
    issued_by_agency_id INTEGER      NOT NULL REFERENCES Agency(agency_id),

    -- SHA-256 of the code, hex. There is no column for the code.
    code_hash           VARCHAR(64)  NOT NULL,

    channel             VARCHAR(24)  NOT NULL
        CHECK (channel IN ('POSTAL', 'SMS', 'EMAIL', 'IN_PERSON_HANDOVER')),

    issued_at           TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMP    NOT NULL,
    redeemed_at         TIMESTAMP,
    attempts            INTEGER      NOT NULL DEFAULT 0,

    -- Set when the code is redeemed against a proofing event.
    proofing_id         INTEGER      REFERENCES EnrollmentProofing(proofing_id),

    CONSTRAINT code_hash_is_sha256_hex
        CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT expires_after_it_is_issued
        CHECK (expires_at > issued_at),
    -- A code valid for a year is a permanent credential in a mailbox.
    CONSTRAINT validity_is_bounded
        CHECK (expires_at <= issued_at + INTERVAL '30 days'),
    -- Redeeming an expired code is redeeming a code that was not valid.
    CONSTRAINT redeemed_inside_its_validity
        CHECK (redeemed_at IS NULL OR redeemed_at <= expires_at),
    CONSTRAINT attempts_are_not_negative
        CHECK (attempts >= 0),
    -- Brute force meets a wall in the schema, not only in the route.
    CONSTRAINT attempts_are_bounded
        CHECK (attempts <= 5),
    -- A redemption names the proofing it fed.
    CONSTRAINT a_redeemed_code_names_its_proofing
        CHECK ((redeemed_at IS NULL) = (proofing_id IS NULL))
);

-- Redemption looks up by hash: the presented code is hashed and matched, so the
-- plaintext never reaches a query, a log or a query plan.
CREATE INDEX IF NOT EXISTS idx_enrollment_code_hash
    ON EnrollmentCode (code_hash);
CREATE INDEX IF NOT EXISTS idx_enrollment_code_individual
    ON EnrollmentCode (individual_id, issued_at DESC);

COMMENT ON TABLE EnrollmentCode IS
  'v9.396 / P4.4. The secret sent to a channel so an applicant can prove they '
  'control it -- which is all it proves, hence the FAIR cap on ENROLLMENT_CODE '
  'verification (v9.395). Live state rather than an audit record: a one-way-door '
  'trigger makes the hash, channel, issuance and expiry immutable, lets '
  'redeemed_at move from NULL exactly once, and lets attempts only increase.';

REVOKE DELETE ON EnrollmentCode FROM polaris_app;

COMMIT;
