-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Egor Khaklin and the Polaris contributors
--
-- scripts/pg-upgrade-drill-seed.sql: notional rows for the audit-of-record tables that
-- lab/strategy/006/try.sh leaves empty, run by scripts/polaris-pg-upgrade-drill.sh.
--
-- The drill digests every append-only table before and after moving the database to a new
-- PostgreSQL major. An empty table compares equal however the move treated it, so this gives
-- each of the eleven that try.sh leaves empty at least two rows, enough for the sorted-row digest
-- to notice a dropped or reordered row: BackupEvent, CardPersonalization, ChainAnchor,
-- CredentialCopy, EnrollmentEvidence, EnrollmentProofing, HolderKeyEvent, IndividualErasureEvent,
-- RefereeVouching, RelyingPartyEvent, RestoreRecord.
--
-- Run once, as the schema owner, on try.sh's database (the sample data and try.sh's credential in
-- place). Every row is one the schema accepts as it stands: no trigger is disabled and
-- session_replication_role is untouched. Where the schema routes a write through a routine or a
-- trigger, the seed goes through it. Ids are read from the database, never written here.
--
-- Every value is notional, and the rows record nothing that happened: no backup was taken, no
-- card personalized, no anchor reached a chain, no person asked to be erased. A throwaway drill
-- database only.
--
-- One transaction, so a failure keeps nothing. A second run stops at its first INSERT (the seed
-- account's username is unique) and keeps nothing either.

\set ON_ERROR_STOP on

BEGIN;

-- Creating an account and registering a relying party are refused without a justification of at
-- least 20 characters (trg_app_user_guarded, trg_relying_party_audited); both triggers record it.
SET LOCAL polaris.actor = 'pg-upgrade-drill-seed';
SET LOCAL polaris.justification = 'pg-upgrade-drill-seed: notional rows for the PostgreSQL major-upgrade drill';

DO $$
BEGIN
    IF (SELECT count(*) FROM IdentityToken
         WHERE status = 'ACTIVE'
           AND (expiration_date IS NULL OR expiration_date >= polaris_utc_date())) < 2 THEN
        RAISE EXCEPTION 'the seed needs two live (ACTIVE, unexpired) credentials; run lab/strategy/006/try.sh first';
    END IF;
END$$;

-- The two lowest-numbered live credentials (the sample data's, not try.sh's), and an authority.
SELECT token_id AS token_a, token_value AS token_a_value, issuing_agency_id AS token_a_agency
  FROM IdentityToken
 WHERE status = 'ACTIVE' AND (expiration_date IS NULL OR expiration_date >= polaris_utc_date())
 ORDER BY token_id LIMIT 1 \gset
SELECT token_id AS token_b, token_value AS token_b_value, issuing_agency_id AS token_b_agency
  FROM IdentityToken
 WHERE status = 'ACTIVE' AND (expiration_date IS NULL OR expiration_date >= polaris_utc_date())
 ORDER BY token_id LIMIT 1 OFFSET 1 \gset
SELECT min(agency_id) AS agency FROM Agency \gset

-- The seed's actor. uc_pseudonymize_individual acts only for an ACTIVE admin, and try.sh's
-- database has none: production mode disables the sample accounts, and try.sh's operator is not
-- an admin. This account cannot log in (its hash matches no password, as docker-init.sh does for
-- the disabled sample accounts) and is deactivated at the end of the seed.
INSERT INTO AppUser (username, password_hash, role, is_active)
VALUES ('pg-upgrade-drill-seed', 'DISABLED:pg-upgrade-drill-seed', 'admin', TRUE)
RETURNING user_id AS seed_user \gset

-- Notional people, so no person in the sample data or try.sh's is proofed, vouched for or erased.
INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
VALUES ('Seed Referee', DATE '1970-01-01', 'ZZ') RETURNING individual_id AS referee \gset
INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
VALUES ('Seed Applicant One', DATE '1980-01-01', 'ZZ') RETURNING individual_id AS applicant_one \gset
INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
VALUES ('Seed Applicant Two', DATE '1990-01-01', 'ZZ') RETURNING individual_id AS applicant_two \gset
INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
VALUES ('Seed Person One', DATE '1975-01-01', 'ZZ') RETURNING individual_id AS erasure_one \gset
INSERT INTO Individual (legal_name, date_of_birth, jurisdiction)
VALUES ('Seed Person Two', DATE '1985-01-01', 'ZZ') RETURNING individual_id AS erasure_two \gset

-- EnrollmentProofing, EnrollmentEvidence: the schema owner's to write (2026-09-26-004). Each
-- derived_ial is what polaris_web/proofing.py derive_ial gives the evidence beside it. The
-- referee: a SUPERIOR document checked by its chip signature and compared in person, and a FAIR
-- one inspected by eye, in person with no biometric: IAL2.
INSERT INTO EnrollmentProofing (individual_id, recorded_by_agency_id, presence, derived_ial)
VALUES (:referee, :agency, 'IN_PERSON', 'IAL2') RETURNING proofing_id AS referee_proofing \gset
INSERT INTO EnrollmentEvidence (proofing_id, evidence_type, strength, validation_method,
                                verification_method, issuing_authority_name, validated, verified)
VALUES (:referee_proofing, 'PASSPORT', 'SUPERIOR', 'DIGITAL_SIGNATURE_CHECK', 'PHYSICAL_COMPARISON',
        'Seed Passport Office', TRUE, TRUE),
       (:referee_proofing, 'BIRTH_CERTIFICATE', 'FAIR', 'VISUAL_INSPECTION', 'PHYSICAL_COMPARISON',
        'Seed Registry Office', TRUE, TRUE);
-- The applicants have no document to present, which is what a referee is for: no evidence, IAL1.
INSERT INTO EnrollmentProofing (individual_id, recorded_by_agency_id, presence, derived_ial)
VALUES (:applicant_one, :agency, 'IN_PERSON', 'IAL1') RETURNING proofing_id AS applicant_one_proofing \gset
INSERT INTO EnrollmentProofing (individual_id, recorded_by_agency_id, presence, derived_ial)
VALUES (:applicant_two, :agency, 'IN_PERSON', 'IAL1') RETURNING proofing_id AS applicant_two_proofing \gset

-- RefereeVouching: trg_vouching_rules requires referee_ial to be the referee's latest proofed
-- level (IAL2, above); the CHECKs hold vouched_ial at or below it and never at IAL3.
INSERT INTO RefereeVouching (proofing_id, referee_individual_id, applicant_individual_id,
                             referee_ial, relationship, vouched_ial)
VALUES (:applicant_one_proofing, :referee, :applicant_one, 'IAL2', 'SOCIAL_WORKER', 'IAL2'),
       (:applicant_two_proofing, :referee, :applicant_two, 'IAL2', 'SHELTER_OR_REFUGE', 'IAL2');

-- IndividualErasureEvent: written only by uc_pseudonymize_individual (2026-09-25-011), which
-- replaces the name with a pseudonym and records the erasure; a direct INSERT would record an
-- erasure that never happened.
CALL uc_pseudonymize_individual(:erasure_one, :seed_user, 'pg-upgrade-drill-seed: a notional erasure');
CALL uc_pseudonymize_individual(:erasure_two, :seed_user, 'pg-upgrade-drill-seed: a notional erasure');

-- HolderKeyEvent: written only through uc_record_holder_key_event (2026-10-01-003), which keeps
-- bound, rotated and revoked in order for a live credential. A binding, then a rotation signed by
-- the bound key. Notional public keys: the hex of SHA-512 of a label.
SELECT encode(sha512(convert_to('pg-upgrade-drill-seed holder key 1', 'UTF8')), 'hex') AS holder_key_one,
       encode(sha512(convert_to('pg-upgrade-drill-seed holder key 2', 'UTF8')), 'hex') AS holder_key_two \gset
SELECT uc_record_holder_key_event(:token_a, :'holder_key_one', 'ML-DSA-65', 'bound') AS holder_key_bound;
SELECT uc_record_holder_key_event(:token_a, :'holder_key_two', 'ML-DSA-65', 'rotated',
                                  :'holder_key_one') AS holder_key_rotated;

-- CredentialCopy: written by uc_issue_credential_copy, which derives the list day and number,
-- draws a free status index and refuses a credential that is not live. Only the copy's own
-- columns are shown; the routine also returns the holder's name.
SELECT copy_id, list_day, list_no FROM uc_issue_credential_copy(:'token_a_value', :token_a_agency);
SELECT copy_id, list_day, list_no FROM uc_issue_credential_copy(:'token_b_value', :token_b_agency);

-- CardPersonalization: the schema owner's to write (2026-09-27-002), in production by
-- polaris_card/personalization.py once the card accepted a verified card object. One per
-- credential, so two credentials; the slot keys differ (card_slots_differ). In production
-- credential_ref is SHA3-256("polaris-card-ref/1" || token_value) and the last digest is SHA3-256
-- of the card object. PostgreSQL has no SHA3 without pgcrypto, which the schema does not install,
-- so both are SHA-256 of a label: the length the CHECKs require, and nothing a card carries.
INSERT INTO CardPersonalization (token_id, issuing_agency_id, credential_ref, profile_version,
                                 normal_public_key, duress_public_key, card_object_sha3_256,
                                 personalized_by)
VALUES (:token_a, :token_a_agency, sha256(convert_to('pg-upgrade-drill-seed card ref 1', 'UTF8')), 1,
        sha512(convert_to('pg-upgrade-drill-seed normal slot 1', 'UTF8')),
        sha512(convert_to('pg-upgrade-drill-seed duress slot 1', 'UTF8')),
        sha256(convert_to('pg-upgrade-drill-seed card object 1', 'UTF8')), :seed_user),
       (:token_b, :token_b_agency, sha256(convert_to('pg-upgrade-drill-seed card ref 2', 'UTF8')), 1,
        sha512(convert_to('pg-upgrade-drill-seed normal slot 2', 'UTF8')),
        sha512(convert_to('pg-upgrade-drill-seed duress slot 2', 'UTF8')),
        sha256(convert_to('pg-upgrade-drill-seed card object 2', 'UTF8')), :seed_user);

-- RelyingPartyEvent: written only by trg_relying_party_audited; a direct INSERT is refused by
-- trg_relying_party_event_by_recorder. Registering a party records REGISTERED and disabling it
-- records DISABLED. Disabled, and with a hash that matches no secret, it cannot authenticate.
INSERT INTO RelyingParty (client_id, client_secret_hash, org_name)
VALUES ('rp_pg_upgrade_drill_seed', 'DISABLED:pg-upgrade-drill-seed', 'Seed Relying Party (rp.example.org)')
RETURNING rp_id AS seed_rp \gset
UPDATE RelyingParty SET enabled = FALSE WHERE rp_id = :seed_rp;

-- ChainAnchor: the schema owner's to write (polaris anchor-record, after the OpenTimestamps proof
-- verifies). checkpoint_sha256 is derived from the bytes, as chk_chain_anchor_digest requires.
-- The proof and the block header are notional and verify against nothing.
INSERT INTO ChainAnchor (checkpoint, checkpoint_sha256, chain, method, proof, block_height,
                         block_header_hex, recorded_by)
SELECT c.b, encode(sha256(c.b), 'hex'), 'BITCOIN', 'OPENTIMESTAMPS',
       convert_to('notional proof ' || c.n, 'UTF8'), c.n, repeat('0', 160), 'pg-upgrade-drill-seed'
  FROM (VALUES (1, convert_to('{"format":"polaris-chain-checkpoint/1","heads":[],"seed":1}', 'UTF8')),
               (2, convert_to('{"format":"polaris-chain-checkpoint/1","heads":[],"seed":2}', 'UTF8')))
       AS c (n, b);

-- BackupEvent: the schema owner's to write (polaris-backup.sh, after the backup succeeded).
INSERT INTO BackupEvent (kind, location, detail)
VALUES ('dump', 'https://backups.example.org/polaris/seed-dump.tar.gz',
        'notional, from scripts/pg-upgrade-drill-seed.sql: no backup was taken'),
       ('dump-verified', 'https://backups.example.org/polaris/seed-dump.tar.gz',
        'notional, from scripts/pg-upgrade-drill-seed.sql: nothing was verified');

-- RestoreRecord: the schema owner's to write (polaris-reconcile-restore.py). The archive's end
-- follows the point restored to (chk_restore_record_window); an incomplete run lists what remains.
INSERT INTO RestoreRecord (target_time, archive_end, operator, outcome, report)
VALUES (now() - interval '4 hours', now() - interval '3 hours', 'pg-upgrade-drill-seed', 'reconciled',
        '{"note": "notional, from scripts/pg-upgrade-drill-seed.sql", "reapplied": [], "remaining": []}'),
       (now() - interval '2 hours', now() - interval '1 hour', 'pg-upgrade-drill-seed', 'incomplete',
        '{"note": "notional, from scripts/pg-upgrade-drill-seed.sql", "reapplied": [], "remaining": [{"key": "seed", "what": "notional", "error": "notional", "remedy": "none"}]}');

-- The seed account acted for the seed alone.
UPDATE AppUser SET is_active = FALSE WHERE user_id = :seed_user;

COMMIT;
