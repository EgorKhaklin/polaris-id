# docs/SEED_DATA.md: what's in the demo database after a clean load

This is the answer to "what data exists if I just ran `00_load_all.sql`
or `Polaris.command` for the first time." The seed is intentionally
small (8 individuals, 6 agencies, 5 algorithms) so that every UC and
every Q (relational-algebra query) returns a non-empty, plausible
result: and so the v2 substrate primitives are observable from
clean load.

If you're investigating "where does this number come from" or "why
does Maria's T2 verify in BANKING but not HEALTHCARE", this file is
your map.

---

## Principals

### Individuals (8: `polaris_sql/04_data.sql`)

| ID | Legal name | DOB | Jurisdiction | Notes |
|---|---|---|---|---|
| 1 | Adrian Vasquez | 2005-03-12 | US-PA | Token T1 RESERVE. |
| 2 | Maria Santos | 1988-03-21 | US-CA | Token T2 ACTIVE. **Has demo duress code enrolled** (`911911`, scrypt hash in `IdentityToken.duress_code_hash`). |
| 3 | James Chen | 1979-11-04 | US-NY | Token T3 ACTIVE. Federal NY issued. |
| 4 | Priya Patel | 1992-06-17 | US-TX | Token T4 ACTIVE. Filed under SLH-DSA-128s (registry row; no SLH-DSA signer is wired). |
| 5 | David Okafor | 1985-01-28 | US-FL | Token T5 REVOKED. Demo recovery PENDING (UC-9). |
| 6 | R11-6 Test under-bound | 1990-01-01 | US-PA | Token T6 REVOKED (R11-6 demo). |
| 7 | Exempt Sample | 1950-04-10 | US-PA | Enrollment EXEMPT (R11-4 demo). |
| 8 | Lapsed Sample | 1970-09-22 | US-CA | Enrollment LAPSED (R11-4 demo). |

### Agencies (6)

| ID | Name | Type | Jurisdiction |
|---|---|---|---|
| 1 | US National Identity Service | FEDERAL | US |
| 2 | Pennsylvania Identity Bureau | STATE | US-PA |
| 3 | California Identity Office | STATE | US-CA |
| 4 | Transportation Security Admin | FEDERAL | US |
| 5 | First National Bank | PRIVATE | US |
| 6 | Allegheny County Health Auth. | COUNTY | US-PA |

### CryptographicAlgorithm (5)

| ID | Name | Family | PQ | Notes |
|---|---|---|---|---|
| 1 | ML-DSA-65 | ML-DSA | yes | Default operational |
| 2 | ML-DSA-87 | ML-DSA | yes | High-assurance |
| 3 | SLH-DSA-128s | SLH-DSA | yes | Registered hash-based rotation target; no signer wired |
| 4 | SLH-DSA-256s | SLH-DSA | yes | Registered hash-based rotation target; no signer wired |
| 5 | ECDSA-P256 | ECDSA | no | Migration semantics only (deprecation_date scheduled) |

### VerificationContext (7)

`BANKING`(1), `EMPLOYMENT`(2), `HEALTHCARE`(3), `TRAVEL`(4),
`VOTING`(5), `MOTOR_VEHICLE`(6), `GOVERNMENT_BENEFITS`(7).

### AppUser (3: `polaris_sql/10_auth.sql`)

| ID | Username | Role | Password |
|---|---|---|---|
| 1 | admin | admin | `Admin@123!` |
| 2 | operator | operator | `Operator@123!` |
| 3 | auditor | auditor | `Auditor@123!` |

Werkzeug scrypt hashes stored. Production deployments must rotate.

---

## Tokens (5)

| Token | Holder | Status | Algorithm | Biometric | Issuer | Notes |
|---|---|---|---|---|---|---|
| T1 | Egor (#1) | RESERVE | ML-DSA-65 | NONE | Agency 2 (PA) | Never activated; awaits biometric enrollment |
| T2 | Maria (#2) | ACTIVE | ML-DSA-65 | IRIS | Agency 3 (CA) | **Has duress code `911911`.** Anchored on Algorand-PQ (anchor #1) |
| T3 | James (#3) | ACTIVE | ML-DSA-87 | FINGERPRINT | Agency 1 (federal) | High-assurance |
| T4 | Priya (#4) | ACTIVE | SLH-DSA-128s | FACE | Agency 1 (federal) | Anchored on Hyperledger Indy (anchor #2). Registry-diversity row; no SLH-DSA signer is wired |
| T5 | David (#5) | REVOKED | ML-DSA-65 | NONE | Agency 1 (federal) | Administratively voided. Demo recovery request PENDING |
| T6 | R11-6 Test | REVOKED | ML-DSA-65 | IRIS | Agency 2 (PA) | R11-6 boundary-bound demo (added by tests) |

### TokenPermission grants (per token × context)

- T2 Maria: BANKING, EMPLOYMENT, HEALTHCARE, GOVERNMENT_BENEFITS
- T3 James: BANKING, EMPLOYMENT, TRAVEL, MOTOR_VEHICLE
- T4 Priya: BANKING, EMPLOYMENT, GOVERNMENT_BENEFITS

---

## v2 substrate primitives (observable from clean load)

### `AnchorBatch` (R10-2 / M2-2: v8.21)

- **Batch 1** (algorithm 1 ML-DSA-65): root
  `1944806a…0bc5c8`: single leaf for anchor #1 (T2 Maria's BANKING anchor)
- **Batch 2** (algorithm 3 SLH-DSA): root `852266d0…d0c4c9`, single leaf
  for anchor #2 (T4 Priya)

Both batches `committed_to_chain = FALSE` (operator-discretion field).

### `AgencyTrustAttestation` (R11-3 / M2-8: v8.22)

Six seed attestations explaining the 8 demo verifications:

- TSA (4) → federal NY (1) for TRAVEL
- TSA (4) → CA (3) for TRAVEL
- TSA (4) → PA (2) for TRAVEL
- Bank (5) → federal NY (1) for BANKING
- Bank (5) → CA (3) for BANKING
- Bank (5) → PA (2) for BANKING

NO transitive trust. No HEALTHCARE attestations (Maria's HEALTHCARE
verifications happen at same-agency CA: implicit trust).

### `TokenStateEpoch` (R10-1 / M2-1: v8.23)

- **Epoch 1** (BANKING context): merkle_root
  `21117a44…a5bc72` (depth-14 commitment; re-closed at v9.354 for P9.3, when the leaf became a Poseidon commitment the circuit opens rather than a bare SHA3-256 seed). Commits 3 leaves (T2, T3, T4). `valid_until =
  2027-02-10`. Closed by admin. Plonky2 verifier proves Merkle
  inclusion bound to (epoch_id, context_id, nonce).

`TokenStateEpochLeaf` has 3 rows (one per token) with pre-computed
proof paths.

### `DuressEvent` (R11-5 / M2-10: v8.24)

Empty at clean load (no duress events triggered). T2 has a
`duress_code_hash` enrolled with plaintext `911911`. A successful
match writes a DuressEvent row silently. R6 anti-revealing:
operator-visible `/verifications` doesn't surface duress; the
`/duress` admin/auditor dashboard does.

---

## Demo verification events (8 rows in `VerificationEvent`)

- 4 BANKING (3 ✓ / 1 ✕)
- 2 EMPLOYMENT (1 ✓ / 1 ✕)
- 1 TRAVEL (1 ✓)
- 1 GOVERNMENT_BENEFITS (1 ✓)
- 0 HEALTHCARE/VOTING/MOTOR_VEHICLE seed events (the Atlas filter chip
  will show empties for these contexts)

---

## Recovery / Enrollment / Other audit-of-record state

- **RecoveryRequest #1** (PENDING), David Okafor (#5); requested 50h
  ago by operator; cool-down passed; three OOB channels populated;
  awaiting admin decision. Demo for UC-9 queue.
- **EnrollmentStatusEvent**: 17 rows: 8 trigger-seeded
  (`NOT_ENROLLED` per Individual); 9 explicit (ENROLLED/LAPSED/EXEMPT
  transitions per R11-4). See SQL test L for verification.
- **TokenSignature**: backfilled, one per IdentityToken (R11-1
  contract: every ACTIVE token has ≥ 1 active signature).
- **IssuerDiscretionPolicy**: 2 rows: agency 2 (PA) and agency 3
  (CA) overrides for R11-6 revocation-velocity-bound demo.

---

## v2 mission status

**12/12 ✅**: every PDF §9 open problem structurally addressed. See
[`DEVNOTES/record.md`](../DEVNOTES/record.md) for the full done-list. Both PDF §9 triads complete:

- Holder-protection: R11-4 entry + R11-6 exit + R11-2 recovery
- Issuer-trust concentration: R11-1 crypto diversity + R11-6
  constitutional limits + R11-3 federation

Substrate-D arc closed 5/5: M2-1 + M2-2 + M2-3 + M2-4 + M2-5.

---

## When to update this file

- A new principal entity (individual, agency, algorithm, context, app
  user) → update the relevant table.
- A new demo token, signature, or verification event → update.
- A new v2 substrate primitive seed (new AnchorBatch, attestation,
  epoch, etc.) → update.
- A new audit-of-record demo → update.

This file is the *snapshot view* of a clean-load database.
`polaris_sql/04_data.sql` and `polaris_sql/10_auth.sql` are the
source of truth; this file is the navigable cheat-sheet.
