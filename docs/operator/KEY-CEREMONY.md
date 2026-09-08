# KEY-CEREMONY.md: the issuer signing key, its custody, and its rotation

**Reader:** the operator who holds the issuer's signing key, and the
witnesses to its ceremony. **Job:** how the key is created under each
custody driver, where it lives, who may touch it, and how it is rotated.

Polaris has one long-lived private key: the issuer's ML-DSA-65 (FIPS 204)
token-signing key. Every token's `TokenSignature` is produced by it, and the
public key is stored WITH each signature, so verification is self-contained and
survives rotation. Epoch anchors are hash-chained, not signed; no other private
key exists today. This page is how that key is created, where it lives, and how
it is replaced.

## Custody drivers

The app talks to the key through one interface (`polaris_web/custody.py`):
`public_key()` and `sign(digest)`, raw ML-DSA-65 bytes both ways. The two-witness
verification (liboqs and OpenSSL must agree) sees identical bytes whichever
driver signed, and checks every signature before it is stored.

| Driver | `POLARIS_CUSTODY_DRIVER` | The private key is | Use when |
|---|---|---|---|
| file | `file` (default when `POLARIS_PQC_SIGNING_KEY_FILE` is set) | a 0600 JSON file, in process memory while signing | development; small deployments that accept a file on disk |
| pkcs11 | `pkcs11` | inside a PKCS#11 v3.2 token, non-extractable; signing is `CKM_ML_DSA` in the token | an HSM (or a software token such as Kryoptic); on-premises authorities |
| awskms | `awskms` | inside AWS KMS (`KeySpec ML_DSA_65`); signing is `Sign` with `ML_DSA_SHAKE_256` | AWS-hosted authorities |

Secrets never travel through environment: the PKCS#11 PIN is read from
`POLARIS_CUSTODY_PKCS11_PIN_FILE` and the app refuses to start if
`POLARIS_CUSTODY_PKCS11_PIN` is set; KMS credentials come from the instance
role or a mounted credentials file. `python custody.py describe` and
`scripts/polaris-pqc-status.sh` show the driver, key id, and public-key
fingerprint; so does `/api/health` under `custody`.

## The ceremony

A key ceremony is a witnessed procedure with a written record. Whichever
driver, the record holds: date, the people present (two at minimum), the
driver and key identifier, the public key hex and its fingerprint
(`sha3-256`, first 16 hex characters, as `polaris-pqc-status.sh` prints it),
where the public key was published, and, for the file driver, where the
sealed backup is.

### file

```bash
cd /opt/polaris && sudo scripts/polaris-generate-secrets.sh      # writes polaris_web/secrets/polaris_signing_key (if missing)
sudo scripts/polaris-pqc-status.sh                                # custody: file  key=file:<fp>
```

The file is the key. Back it up sealed (an encrypted copy in two locations,
under dual control) before the first token is issued; a lost file means every
future token needs a new key and the old public key stays in the trust anchors
forever. Restrict the host per [`HARDENING.md`](HARDENING.md) (auditd watches
`polaris_web/secrets`).

### pkcs11

1. Initialise the token per the vendor's runbook (security-officer PIN, user
   PIN). Put the user PIN in `polaris_web/secrets/pkcs11_pin` (one line, 0600).
2. Generate the key INSIDE the token with the ceremony helper. It refuses to
   overwrite an existing label:
   ```bash
   python3 polaris_web/custody.py pkcs11-keygen \
     --module /path/to/vendor-pkcs11.so --token-label polaris \
     --pin-file polaris_web/secrets/pkcs11_pin --key-label polaris-issuer
   ```
   It prints the public key hex and fingerprint: that is the record.
3. Configure: `POLARIS_CUSTODY_DRIVER=pkcs11`, the module inside the container
   (the app image is built with `--build-arg POLARIS_CUSTODY_EXTRAS=1`, the
   vendor module and its client config mounted at `./custody/pkcs11/`), and
   layer `docker-compose.custody-pkcs11.yml` via `POLARIS_COMPOSE_EXTRA`.
4. Deploy and confirm `/api/health` reports `custody.driver = pkcs11` with the
   fingerprint from step 2; issue one test token and verify it.

Backup is the HSM's own backup/cloning procedure (a key that only exists in
one device is a single point of failure, which is the HSM vendor's domain, not
Polaris's).

### awskms

1. Create the key: `aws kms create-key --key-spec ML_DSA_65 --key-usage SIGN_VERIFY`
   with a key policy that allows the app's role `kms:Sign`, `kms:GetPublicKey`,
   and `kms:DescribeKey`, and nobody `kms:ScheduleKeyDeletion` without a second
   approver. Record the key ARN.
2. `aws kms get-public-key --key-id <arn>` and record the public key (the
   driver derives the raw key from the returned SPKI; `polaris-pqc-status.sh`
   prints the fingerprint once configured).
3. Configure `POLARIS_CUSTODY_DRIVER=awskms`, `POLARIS_CUSTODY_AWSKMS_KEY_ID`,
   `POLARIS_CUSTODY_AWSKMS_REGION`; layer `docker-compose.custody-awskms.yml`.
   Prefer an instance role over static credentials.
4. Deploy and confirm `/api/health` shows the fingerprint; issue one test token.

Enable multi-region replication or a documented restore path in KMS; a deleted
KMS key cannot be recovered after its waiting period.

## The HSM-sole-signer profile

A production authority that wants the HSM to be the ONLY thing that can ever sign
sets `POLARIS_REQUIRE_HSM_SOLE_SIGNER=1`. The app then refuses to start (exit 2)
unless:

- `POLARIS_CUSTODY_DRIVER=pkcs11` (the HSM is the signer),
- `POLARIS_PQC_SIGNING_KEY_FILE` is **unset** — no file key sits in the
  environment as a latent fallback a flipped driver could use, and
- `POLARIS_USE_REAL_PQC=1` — the deterministic placeholder is not the HSM.

It is a fail-closed boot guard: it makes the profile's intent true at startup
rather than discovering at first issuance that a file key or the placeholder was
quietly in the path. `custody.get_custody()` itself never falls back (an
unreachable token fails issuance loudly); this guard removes the one thing that
guard cannot see, a file key left in the environment. The boot refusal is tested
in `polaris_web/test_app.py` (`HsmSoleSignerBootTests`) and pinned by
`check_prod_fail_closed`.

## Rotation

Rotation is safe because every stored signature carries its public key.
Verification of existing tokens does not depend on the current key; what
depends on the current key is the trust-anchor check `verify_token_signature`
performs when a verifier asks "is this signature from a key the authority
still stands behind".

1. Perform a ceremony for the NEW key (new file, new token label, or a new KMS
   key). Do not overwrite or delete the old one yet.
2. Add the OLD public key to the trust anchors file and point
   `POLARIS_PQC_TRUST_ANCHORS_FILE` at it:
   ```json
   {"anchors": [{"public_key_hex": "<old public key>", "label": "issuer-2026", "retired": "2026-09-01"}]}
   ```
   `verify_token_signature` accepts the current key first, then every listed
   anchor; a missing or malformed anchors file fails loud rather than silently
   shrinking trust.
3. Switch the driver configuration to the new key and deploy. New tokens sign
   under the new key; old tokens keep verifying.
4. Publish the new public key wherever verifiers fetch trust anchors, with the
   old one marked retired and its date.
5. Retire the old key only after every token signed under it has expired or
   been re-issued, then remove its anchor entry and destroy the old key
   material (shred the file; delete the token object; schedule KMS deletion
   with the waiting period).

Compromise is the same procedure without the waiting: rotate at once, and
remove the compromised anchor immediately so its signatures stop verifying
(they will then read as invalid, which is the correct outcome).

## How this is tested

`polaris_web/test_custody.py`: the file driver signs and both witnesses verify;
the AWS KMS driver runs its real botocore wire path against a stand-in that
implements KMS's `DescribeKey` / `GetPublicKey` / `Sign` and signs with OpenSSL's
ML-DSA-65 (wrong key spec and a disabled key are refused at load); the PKCS#11
driver runs against a real PKCS#11 v3.2 token in CI (Kryoptic, Fedora 43, job
`custody-pkcs11`): key generated in-token, `CKM_ML_DSA` signatures verified by
liboqs and OpenSSL, duplicate labels refused. Rotation is tested end to end:
a token signed under the old key stops verifying after the switch and verifies
again once the old key is an anchor. In-token rotation is drilled too (PE.4): a
second key is generated INSIDE the token under a new label, a token signed under
the old in-token key still verifies after the switch while the new key signs, and
dropping the old anchor completes retirement
(`test_in_token_rotation_old_token_still_verifies_new_key_signs`, run against the
real Kryoptic token by the `custody-pkcs11` job; pinned by
`check_key_rotation_drilled`). An opt-in live test runs against a real
KMS key when `POLARIS_CUSTODY_AWSKMS_LIVE_KEY_ID` is set. Stated limit: no
hardware HSM is exercised in CI; the PKCS#11 conformance surface (v3.2 ML-DSA
mechanisms) is exercised against a software token.
