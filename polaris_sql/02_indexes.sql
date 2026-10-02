-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Egor Khaklin and the Polaris contributors
-- ============================================================================
-- POLARIS — IDENTITY TOKEN SYSTEM
-- 02_indexes.sql : Secondary indexes
--
-- Defines the five secondary indexes documented in Appendix B (report) plus
-- the partial unique index enforcing the one-active-token-per-person
-- invariant. Each index is justified by a specific access pattern: a use
-- case, a query in §8, or a constraint requirement.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- The one-active-token-per-person invariant.
-- Partial unique index on (individual_id) where status='ACTIVE'. Allows
-- multiple non-active tokens per individual (RESERVE, DORMANT, terminal
-- states), enforces single ACTIVE per individual.
-- ----------------------------------------------------------------------------

DROP INDEX IF EXISTS uq_one_active_per_person;
CREATE UNIQUE INDEX uq_one_active_per_person
    ON IdentityToken (individual_id)
    WHERE status = 'ACTIVE';

COMMENT ON INDEX uq_one_active_per_person IS
  'Enforces one ACTIVE IdentityToken per individual. Partial uniqueness '
  'allows multiple RESERVE/DORMANT/terminal tokens per holder. UC-4 reserve '
  'activation transitions the lost token to its terminal status before '
  'promoting the reserve, so this index never blocks a legitimate swap.';

-- ----------------------------------------------------------------------------
-- The five secondary indexes from Appendix B.
-- Each name encodes table + column for grep-ability.
-- ----------------------------------------------------------------------------

-- High cardinality (1 per holder). Drives UC-7 history reconstruction.
-- Also benefits the partial unique index above for fast active-token lookup.
DROP INDEX IF EXISTS idx_identitytoken_individual;
CREATE INDEX idx_identitytoken_individual
    ON IdentityToken (individual_id);

-- Low cardinality (6 distinct values). The ActiveTokens view scans tokens
-- with status='ACTIVE' only; index used for filtering before join.
DROP INDEX IF EXISTS idx_identitytoken_status;
CREATE INDEX idx_identitytoken_status
    ON IdentityToken (status);

-- Very high cardinality. Capacity-planning queries (Q5), audit history
-- retrieval (UC-7), and time-bounded subscription windows.
DROP INDEX IF EXISTS idx_verificationevent_timestamp;
CREATE INDEX idx_verificationevent_timestamp
    ON VerificationEvent (event_timestamp);

-- Low cardinality (7 distinct values). Per-context analytics (Q5);
-- per-context fraud detection.
DROP INDEX IF EXISTS idx_verificationevent_context;
CREATE INDEX idx_verificationevent_context
    ON VerificationEvent (context_id);

-- Moderate cardinality. Reconstructing a single token's lifecycle on demand
-- (UC-4 reserve activation, UC-7 audit).
DROP INDEX IF EXISTS idx_tokenlifecycle_token;
CREATE INDEX idx_tokenlifecycle_token
    ON TokenLifecycleEvent (token_id);

-- ----------------------------------------------------------------------------
-- END OF 02_indexes.sql
-- 1 partial unique index + 5 secondary indexes = 6 indexes total.
-- The 6 indexes documented in the report's Schema Overview table count
-- the partial unique as separate from the 5 access-pattern indexes; the
-- count in 03_view.sql ('5 indexes') refers only to the access-pattern set.
-- ----------------------------------------------------------------------------

-- ----------------------------------------------------------------------------
-- Temporal indexes for the event tables' time-ordered reads.
--
-- v6 also built B-trees on (latitude, longitude) for the Atlas's bounding-box layers:
-- idx_verificationevent_geo, idx_verificationevent_geo_time and idx_tokenlifecycleevent_geo.
-- Since lab/strategy/009 step 4 the Atlas reads the activity rollups and no query filters or
-- sorts by a coordinate, so each cost every located insert a B-tree update and served no query.
-- Step 4c withdrew them, with the GiST indexes 13_postgis.sql built on its generated `geo`
-- columns (migration 2026-10-02-005); a database upgraded from before it loses them there.
-- ----------------------------------------------------------------------------

DROP INDEX IF EXISTS idx_tokenlifecycleevent_time;
CREATE INDEX idx_tokenlifecycleevent_time
    ON TokenLifecycleEvent (event_timestamp DESC);

-- Verification feed pagination uses (timestamp DESC, event_id DESC) cursor.
DROP INDEX IF EXISTS idx_verificationevent_time_id;
CREATE INDEX idx_verificationevent_time_id
    ON VerificationEvent (event_timestamp DESC, event_id DESC);

-- ----------------------------------------------------------------------------
-- v8.15 / R11-6 / M2-11 — Rolling-window REVOKED count by issuing agency.
-- The uc8_revoke_token procedure joins TokenLifecycleEvent to IdentityToken
-- to count REVOKED events per agency in the last W days. This partial index
-- shaves the scan to REVOKED rows only (a small minority of lifecycle
-- events) and orders by event_timestamp DESC so the window predicate prunes
-- early. Without this, the rate check on a populated cluster is O(N) over
-- ALL lifecycle events.
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS idx_lifecycle_revoked_time;
CREATE INDEX idx_lifecycle_revoked_time
    ON TokenLifecycleEvent (event_timestamp DESC, token_id)
    WHERE event_type = 'REVOKED';

-- ----------------------------------------------------------------------------
-- v8.16 / R11-4 / M2-9 — Enrollment-status event indexes.
--
-- The IndividualCurrentEnrollment view uses DISTINCT ON (individual_id)
-- ordered by event_timestamp DESC, event_id DESC. The first index supports
-- this directly: per-individual scan in reverse-time order picks the latest
-- row without sorting.
--
-- The civic_enrollment_summary function rolls up counts by (jurisdiction,
-- status). The second index lets the per-status filter prune before the
-- join to Individual when a single status is queried.
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS idx_enrollment_event_individual_time;
CREATE INDEX idx_enrollment_event_individual_time
    ON EnrollmentStatusEvent (individual_id, event_timestamp DESC, event_id DESC);

DROP INDEX IF EXISTS idx_enrollment_event_status;
CREATE INDEX idx_enrollment_event_status
    ON EnrollmentStatusEvent (status);

-- ----------------------------------------------------------------------------
-- v8.17 / R11-2 / M2-7 — Recovery-queue index + one-PENDING-per-individual.
--
-- (a) idx_recovery_request_status_individual: the /uc9/queue route lists
--     PENDING recoveries. We don't make it partial-on-status='PENDING'
--     because EXPIRED rows are also useful to query (the queue can show
--     recently-expired requests too).
-- (b) uq_one_pending_recovery_per_individual: partial unique index — at
--     most one PENDING request per individual at a time. Prevents two
--     operators initiating concurrent recovery ceremonies for the same
--     claimed identity (different question from C9 concurrency on a single
--     PENDING; that one is solved by the per-individual advisory lock in
--     uc9_complete_recovery).
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS idx_recovery_request_status_individual;
CREATE INDEX idx_recovery_request_status_individual
    ON RecoveryRequest (status, claimed_individual_id);

DROP INDEX IF EXISTS uq_one_pending_recovery_per_individual;
CREATE UNIQUE INDEX uq_one_pending_recovery_per_individual
    ON RecoveryRequest (claimed_individual_id)
    WHERE status = 'PENDING';

-- ----------------------------------------------------------------------------
-- v8.18 / R11-1 / M2-6 — Active-signature lookup for verification.
--
-- Every verification reads "give me the active signatures for token X".
-- Partial index on TokenSignature(token_id) WHERE deprecation_date IS NULL
-- shrinks the index to just the active set (typically 1-2 rows per token
-- even during migration windows), so verification is O(1) again rather
-- than O(total signatures including deprecated history).
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS idx_token_signature_active;
CREATE INDEX idx_token_signature_active
    ON TokenSignature (token_id)
    WHERE deprecation_date IS NULL;

-- ----------------------------------------------------------------------------
-- v8.21 / R10-2 / M2-2 — AnchorBatch + BlockchainAnchor indexes.
--
-- (a) idx_blockchain_anchor_batch: every proof-fetch query joins
--     BlockchainAnchor → AnchorBatch on batch_id. The FK already creates an
--     index on the referenced PK side; this index supports the reverse
--     direction (find all anchors in a given batch).
-- (b) idx_blockchain_anchor_pending: the close_anchor_batch procedure
--     scans WHERE batch_id IS NULL to find the pending leaf set. A partial
--     index keeps this O(pending) rather than O(all anchors).
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS idx_blockchain_anchor_batch;
CREATE INDEX idx_blockchain_anchor_batch
    ON BlockchainAnchor (batch_id)
    WHERE batch_id IS NOT NULL;

DROP INDEX IF EXISTS idx_blockchain_anchor_pending;
CREATE INDEX idx_blockchain_anchor_pending
    ON BlockchainAnchor (token_id)
    WHERE batch_id IS NULL;

-- ----------------------------------------------------------------------------
-- v8.22 / R11-3 / M2-8 — AgencyTrustAttestation indexes.
--
-- (a) uq_active_attestation: partial unique index enforcing "at most one
--     active attestation per (attesting, attested, context) triple."
--     Revoked rows leave the active slot free; a future re-attestation
--     creates a new row, preserving the audit trail.
-- (b) idx_attestation_lookup: the verification flow consults
--     attestations by (attesting, attested, context) for active rows.
--     The partial unique index above doubles as the read index — same
--     key columns, same WHERE clause. So we don't need a second index
--     for the read path.
-- (c) idx_attestation_revoked: queries on revocation history
--     (operator dashboards) scan WHERE revocation_date IS NOT NULL.
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS uq_active_attestation;
CREATE UNIQUE INDEX uq_active_attestation
    ON AgencyTrustAttestation (attesting_agency_id, attested_agency_id, context_id)
    WHERE revocation_date IS NULL;

COMMENT ON INDEX uq_active_attestation IS
  'Enforces at most one active attestation per (attesting, attested, '
  'context) triple, and serves the verification-flow lookup. Revoked '
  'rows fall out of the index, so a new attestation can be created '
  'without duplicate-key violation — the audit trail accumulates.';

DROP INDEX IF EXISTS idx_attestation_revoked;
CREATE INDEX idx_attestation_revoked
    ON AgencyTrustAttestation (revocation_date)
    WHERE revocation_date IS NOT NULL;

-- ----------------------------------------------------------------------------
-- v8.23 / R10-1 / M2-1 — TokenStateEpoch + Leaf indexes.
--
-- (a) idx_epoch_valid_until: the verifier reads valid_until on every
--     proof check. Index on (valid_until) supports the "is this epoch
--     still current?" check and the operator dashboard listing
--     near-expiry epochs.
-- (b) idx_leaf_token_lookup: the prover queries leaves by token_id
--     to find their witness row. (epoch_id, token_id) is already
--     uniquely indexed by the constraint; this is for the reverse
--     direction (find all epochs a given token participates in).
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS idx_epoch_valid_until;
CREATE INDEX idx_epoch_valid_until
    ON TokenStateEpoch (valid_until);

DROP INDEX IF EXISTS idx_leaf_token_lookup;
CREATE INDEX idx_leaf_token_lookup
    ON TokenStateEpochLeaf (token_id);

-- ----------------------------------------------------------------------------
-- v9.190 / roadmap P1.8 — AgencyQuota window counts. enforce_agency_quota()
-- counts an agency's issuances (IdentityToken by issuing_agency_id in the
-- last day) and verifications (VerificationEvent by requesting_agency_id in
-- the last hour) on every capped write; these keep that an index range scan
-- instead of a per-write table scan. The revocation count reuses
-- idx_lifecycle_revoked_time above.
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS idx_token_agency_issued;
CREATE INDEX idx_token_agency_issued
    ON IdentityToken (issuing_agency_id, issued_date DESC);

DROP INDEX IF EXISTS idx_verification_agency_time;
CREATE INDEX idx_verification_agency_time
    ON VerificationEvent (requesting_agency_id, event_timestamp DESC);

-- ----------------------------------------------------------------------------
-- One effective quota per agency (v9.424).
--
-- AgencyQuota keeps its history: changing a cap supersedes the row in force and
-- appends a new one, so the reason an agency's ceiling was raised survives the
-- next change. That makes agency_id non-unique, and the enforcement lookup in
-- enforce_agency_quota() reads exactly one row, so "one un-superseded row per
-- agency" has to be a database rule rather than a convention the writer keeps.
-- Without it two live caps would both be candidates and the cap in force would
-- depend on insertion order, which is the failure mode uq_effective_retention_policy
-- exists to prevent for the sibling table.
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS uq_effective_agency_quota;
CREATE UNIQUE INDEX uq_effective_agency_quota
    ON AgencyQuota (agency_id)
    WHERE superseded_at IS NULL;

-- ----------------------------------------------------------------------------
-- One effective revocation bound per agency (v9.426).
--
-- The third of the same shape, after uq_effective_retention_policy and
-- uq_effective_agency_quota, and load-bearing for the same reason:
-- uc8_revoke_token reads ONE row to decide how much of its own population an
-- agency may revoke, so two rows in force would make that answer depend on
-- insertion order.
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS uq_effective_discretion_policy;
CREATE UNIQUE INDEX uq_effective_discretion_policy
    ON IssuerDiscretionPolicy (agency_id)
    WHERE superseded_at IS NULL;

-- ----------------------------------------------------------------------------
-- One effective retention policy per (class, jurisdiction) (roadmap P1.11).
--
-- COALESCE on the jurisdiction is load-bearing: a plain partial unique index
-- over a nullable column treats every NULL as distinct, so two effective
-- deployment-default policies for the same class would both be accepted and
-- the resolver's answer would depend on insertion order.
-- ----------------------------------------------------------------------------
DROP INDEX IF EXISTS uq_effective_retention_policy;
CREATE UNIQUE INDEX uq_effective_retention_policy
    ON RetentionPolicy (table_class, COALESCE(jurisdiction, ''))
    WHERE superseded_at IS NULL;

-- ----------------------------------------------------------------------------
-- Population scale (lab/strategy/008). Each index serves a read a console page
-- makes on every view, which must cost the same at any population; without it
-- the read went through a whole table or a whole status.
-- ----------------------------------------------------------------------------

-- The Overview's expiry counts: active credentials past, or within 30 days of,
-- their expiry date, counted up to a cap. Through idx_identitytoken_status the
-- count filtered every active credential to find the few that match.
DROP INDEX IF EXISTS idx_identitytoken_active_expiry;
CREATE INDEX idx_identitytoken_active_expiry
    ON IdentityToken (expiration_date)
    WHERE status = 'ACTIVE';

-- Credentials by status, newest first, paged by key: serves
-- WHERE status = $1 AND token_id < $2 ORDER BY token_id DESC LIMIT n at any depth.
DROP INDEX IF EXISTS idx_identitytoken_status_id;
CREATE INDEX idx_identitytoken_status_id
    ON IdentityToken (status, token_id);

-- Credentials issued in a window, counted up to a cap by the Overview: the
-- same shape as idx_lifecycle_revoked_time, for ISSUED.
DROP INDEX IF EXISTS idx_lifecycle_issued_time;
CREATE INDEX idx_lifecycle_issued_time
    ON TokenLifecycleEvent (event_timestamp DESC, token_id)
    WHERE event_type = 'ISSUED';

-- One credential's verifications, newest first: the credential and
-- investigation pages and the warrant audit (UC-7). A zero-knowledge row
-- carries no token id (C2), so it is not in this index.
DROP INDEX IF EXISTS idx_verificationevent_token_time;
CREATE INDEX idx_verificationevent_token_time
    ON VerificationEvent (token_id, event_timestamp DESC)
    WHERE token_id IS NOT NULL;

-- A person found by date of birth and the beginning of the name as recorded (lookup.py): the
-- operation forms look a person up instead of listing everyone. The C collation makes a LIKE
-- prefix an index range and gives the order, so the lookup stops after its limit however many
-- people share a birthday.
DROP INDEX IF EXISTS idx_individual_birth_name;
CREATE INDEX idx_individual_birth_name
    ON Individual (date_of_birth, (lower(legal_name)) COLLATE "C", individual_id);

-- Every foreign key between tables that grow with the population has an index on its
-- referencing columns (lab/strategy/008 step 3; a test reads the catalogue for any that does
-- not). Without one, reading one record's rows scans the whole referencing table, and deleting
-- a referenced row scans it to check the key.
DROP INDEX IF EXISTS idx_identitytoken_predecessor;
CREATE INDEX idx_identitytoken_predecessor
    ON IdentityToken (predecessor_token_id)
    WHERE predecessor_token_id IS NOT NULL;

DROP INDEX IF EXISTS idx_devicebinding_token;
CREATE INDEX idx_devicebinding_token
    ON DeviceBinding (token_id, binding_id);

DROP INDEX IF EXISTS idx_revocationlist_token;
CREATE INDEX idx_revocationlist_token
    ON RevocationList (token_id);

DROP INDEX IF EXISTS idx_recoveryrequest_resulting_token;
CREATE INDEX idx_recoveryrequest_resulting_token
    ON RecoveryRequest (resulting_token_id)
    WHERE resulting_token_id IS NOT NULL;

DROP INDEX IF EXISTS idx_credentialcopy_token;
CREATE INDEX idx_credentialcopy_token
    ON CredentialCopy (token_id);

DROP INDEX IF EXISTS idx_duressevent_token;
CREATE INDEX idx_duressevent_token
    ON DuressEvent (token_id);

DROP INDEX IF EXISTS idx_refereevouching_applicant;
CREATE INDEX idx_refereevouching_applicant
    ON RefereeVouching (applicant_individual_id);

DROP INDEX IF EXISTS idx_refereevouching_co_signer;
CREATE INDEX idx_refereevouching_co_signer
    ON RefereeVouching (co_signer_individual_id)
    WHERE co_signer_individual_id IS NOT NULL;

DROP INDEX IF EXISTS idx_enrollmentcode_proofing;
CREATE INDEX idx_enrollmentcode_proofing
    ON EnrollmentCode (proofing_id)
    WHERE proofing_id IS NOT NULL;

-- A key whose only index was partial on another condition (a pending anchor, a pending request):
-- that index serves neither the key's check nor one record's own rows.
DROP INDEX IF EXISTS idx_blockchainanchor_token;
CREATE INDEX idx_blockchainanchor_token
    ON BlockchainAnchor (token_id);

DROP INDEX IF EXISTS idx_recoveryrequest_claimed;
CREATE INDEX idx_recoveryrequest_claimed
    ON RecoveryRequest (claimed_individual_id);

-- 2026-10-02 (lab/strategy/008, step 4). The duress page counts the active credentials that carry
-- a duress code. Few do, so the count read every credential to find them; through this index a
-- capped count reads at most its cap.
DROP INDEX IF EXISTS idx_identitytoken_duress_enrolled;
CREATE INDEX idx_identitytoken_duress_enrolled
    ON IdentityToken (status)
    WHERE duress_code_hash IS NOT NULL;
