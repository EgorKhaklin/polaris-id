-- 2026-10-01-007: an index on every foreign key between tables that grow with the population
-- (lab/strategy/008, step 3).
--
-- ADD, each on the referencing columns of a key whose referenced table also grows:
--   idx_identitytoken_predecessor        IdentityToken (predecessor_token_id) WHERE NOT NULL
--   idx_devicebinding_token              DeviceBinding (token_id, binding_id)
--   idx_revocationlist_token             RevocationList (token_id)
--   idx_recoveryrequest_resulting_token  RecoveryRequest (resulting_token_id) WHERE NOT NULL
--   idx_credentialcopy_token             CredentialCopy (token_id)
--   idx_duressevent_token                DuressEvent (token_id)
--   idx_refereevouching_applicant        RefereeVouching (applicant_individual_id)
--   idx_refereevouching_co_signer        RefereeVouching (co_signer_individual_id) WHERE NOT NULL
--   idx_enrollmentcode_proofing          EnrollmentCode (proofing_id) WHERE NOT NULL
--   idx_blockchainanchor_token           BlockchainAnchor (token_id)
--   idx_recoveryrequest_claimed          RecoveryRequest (claimed_individual_id)
-- The last two keys had only a partial index on another condition (a pending anchor, a pending
-- request), which serves neither the key's check nor a credential's or a person's own rows.
-- Without one, reading one record's rows scans the whole referencing table (a credential's page
-- read its device bindings and revocations that way, and the investigation page found a
-- credential's successor by a parallel scan of every credential: 904 ms at 3.6 million), and
-- deleting a referenced row scans the table to check the key.
--
-- REVERSIBLE: yes (the .down.sql drops all eleven).
-- ADDITIVE:   yes; an expand step. Code that does not use them is unaffected.
-- LOCK:       CREATE INDEX, not CONCURRENTLY: the runner applies a migration in one transaction.
--             On a populated database, build them first outside the runner with CONCURRENTLY,
--             and IF NOT EXISTS makes this a no-op.

CREATE INDEX IF NOT EXISTS idx_identitytoken_predecessor
    ON IdentityToken (predecessor_token_id)
    WHERE predecessor_token_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_devicebinding_token
    ON DeviceBinding (token_id, binding_id);

CREATE INDEX IF NOT EXISTS idx_revocationlist_token
    ON RevocationList (token_id);

CREATE INDEX IF NOT EXISTS idx_recoveryrequest_resulting_token
    ON RecoveryRequest (resulting_token_id)
    WHERE resulting_token_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_credentialcopy_token
    ON CredentialCopy (token_id);

CREATE INDEX IF NOT EXISTS idx_duressevent_token
    ON DuressEvent (token_id);

CREATE INDEX IF NOT EXISTS idx_refereevouching_applicant
    ON RefereeVouching (applicant_individual_id);

CREATE INDEX IF NOT EXISTS idx_refereevouching_co_signer
    ON RefereeVouching (co_signer_individual_id)
    WHERE co_signer_individual_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_enrollmentcode_proofing
    ON EnrollmentCode (proofing_id)
    WHERE proofing_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_blockchainanchor_token
    ON BlockchainAnchor (token_id);

CREATE INDEX IF NOT EXISTS idx_recoveryrequest_claimed
    ON RecoveryRequest (claimed_individual_id);
