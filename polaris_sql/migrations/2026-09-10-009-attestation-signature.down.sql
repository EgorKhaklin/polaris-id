-- Down: the trust graph returns to resting on an operator's word (P9.5, v9.348).
ALTER TABLE AgencyTrustAttestation DROP CONSTRAINT IF EXISTS attestation_signature_complete;
ALTER TABLE AgencyTrustAttestation
    DROP COLUMN IF EXISTS attestation_format,
    DROP COLUMN IF EXISTS attestation_signature_hex,
    DROP COLUMN IF EXISTS attestation_public_key_hex;
