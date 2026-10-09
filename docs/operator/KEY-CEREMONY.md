# KEY-CEREMONY.md: the issuer signing key, its custody, and its rotation

**Reader:** the operator who holds the issuer's signing key, and the
witnesses to its ceremony. **Job:** how the key is created under each
custody driver, where it lives, who may touch it, and how it is rotated.

Polaris credentials are signed by one kind of long-lived private key: the
issuer's ML-DSA-65 (FIPS 204) token-signing key, one per agency where agencies
have their own (below). Every token's `TokenSignature` is produced by it, and the
public key is stored WITH each signature, so verification is self-contained and
survives rotation. Epoch anchors are hash-chained, not signed. An instance that
offers wallet copies holds a second kind, an ES256 key per agency that signs those
copies and nothing else ([Wallet-copy keys](#wallet-copy-keys-es256)). This page is
how each is created, where it lives, and how it is replaced.

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

With no driver configured, real ML-DSA signing falls back to a fresh key for every signature, for
development only. Nothing such an instance signs verifies against an anchor, and every verifier
refuses its stapled status assertions, because each is signed by a different key from the
credential's. That is the fallback working, not a fault: configure a driver to sign under one key.

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

The ceremony ends by registering the key in the authority key register, before the first
credential is issued under it:

    polaris key-register AGENCY_ID PUBLIC_KEY_HEX --effective-at <the ceremony's instant>

On the Docker stack the database answers only on the stack's network, so run the same statements
as the schema owner through the postgres container with
`scripts/polaris-key-event.sh register AGENCY_ID PUBLIC_KEY_HEX --effective-at <instant>` (it also
takes `retire` and `compromise`). When the key is the one the running app signs with, as on a fresh
install, `scripts/polaris-key-event.sh register AGENCY_ID --current` reads it from the app's own key
store and registers it as the authority's first key, effective from its first signature for the
authority (now, if it has signed nothing), so what it signed before the registration is authorized
too. It leaves a key already active alone and refuses everything after the first key, which this
ceremony performs by name: another active key (a rotation), a key retired or declared compromised
(never registered again, by any path), a later key once the last one ended.

Under real signing this is not optional. Every possession route (`/api/v1/verify`, the status
assertion, holder signing, the verifiable credential, the mdoc, sign-in) accepts a signature only
under a key its authority had registered at the instant the signature was made, and refuses one
whose key has no recorded history. The application role can write a signature row but cannot
register a key, so this is what keeps a planted row from being vouched for. A credential issued
before its key was registered is refused until the registration's `--effective-at` covers its
signing instant.

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
- `POLARIS_CREDENTIAL_COPY_KEYS_DIR` is **unset**: wallet-copy keys are files in
  this version, so a sole-signer deployment does not offer wallet copies.

It is a fail-closed boot guard: it makes the profile's intent true at startup
rather than discovering at first issuance that a file key or the placeholder was
quietly in the path. `custody.get_custody()` itself never falls back (an
unreachable token fails issuance loudly); this guard removes the one thing that
guard cannot see, a file key left in the environment. The boot refusal is tested
in `polaris_web/test_app.py` (`HsmSoleSignerBootTests`) and pinned by
`check_prod_fail_closed`.

## Per-agency signing keys (federation)

By default one signing key issues for every agency. To make each issuer's identity
cryptographically its own (roadmap PE.3b), give each agency its own key:

1. Perform a ceremony per agency and place its key file at
   `$POLARIS_AGENCY_KEYS_DIR/<agency_id>.json` (the same shape the file driver
   reads). Issuance signs a token with the key of the agency it is issued for; an
   agency with no key file falls back to the global key, so single-key deployments
   are unchanged.
2. Register each agency's public key so the app can bind and verify it:
   `polaris key-register <id> <hex>`, run as the schema owner, which appends the key to
   the authority's register and makes it current in one transaction. The application role
   cannot append key events (2026-09-27), so `key-register`, `key-retire` and
   `key-compromise` exit 3 under it. Since 1.0.0-rc.57 the
   application role cannot set a key the register does not hold (or holds as retired or
   compromised); a plain `UPDATE Agency` works only as the schema owner, and leaves no register
   entry, so the trust list would serve a key with no history.
3. Once registered, `/uc1/issue` REFUSES to issue a token for that agency whose real
   signature was produced by any other key, and `GET /api/tokens/<id>/verify`
   reports `issuer_authentic` — whether the token was signed by its issuing agency's
   registered key. Rotate an agency's key the same way as the global key (below),
   updating its registered `signing_public_key_hex` and keeping the old key as a
   trust anchor until its tokens expire.

## Wallet-copy keys (ES256)

A wallet copy ([design](../design/oid4vci-issuer.md)) is an SD-JWT VC signed ES256,
because the wallets it is issued into verify nothing else, so it is a classical
credential. Its key is per agency and, in this version, a file:

- `$POLARIS_CREDENTIAL_COPY_KEYS_DIR/<agency_id>.key.pem`: the P-256 private key,
  PKCS#8, mode 0600;
- `$POLARIS_CREDENTIAL_COPY_KEYS_DIR/<agency_id>.chain.pem`: the leaf certificate
  first, then any intermediates. The trust anchor stays out; wallets and relying
  parties register it.

Generate the key where it will live and have the agency's CA issue the leaf for it,
with `digitalSignature`, without the CA flag or `keyCertSign`, and with the credential
issuer URL, `https://HOST/api/v1/oid4vci/<agency_id>`, as its one https URI subjectAltName for
that path. The endpoints read the issuer identifier from there: a leaf that names none, or two,
makes every endpoint of that agency answer `503`.
`polaris_web/credential_copy_keys.py` refuses anything else when it loads the key, and
checks the chain's validity window again at every use. A replaced pair is picked up
without a restart, so rotation is: issue the new leaf, replace both files, and keep the
old anchor registered while copies signed under it are unexpired.

A compromised wallet-copy key can sign copies that verify until the leaf expires or
relying parties drop its anchor. The status list narrows such a forgery and does not
prevent it (the design record says why), so keep leaves short-lived and replace a
compromised pair at once.

`scripts/polaris-credential-copy-test-pki.py` writes a TEST chain for development and
the lab, never a deployment's. `polaris_web/test_credential_copy_keys.py` tests every
refusal, and switches each one off in turn to show that a test notices.

## Rotation

The running application decides whether a credential's issuer key was authorized from the
authority key register: a key is registered, then retired or declared compromised, each from an
instant. `GET /api/tokens/<id>/verify` reports `issuer_authorized_at_signing` (the key was
registered, and not yet retired or compromised, when it signed) and `issuer_key_current`, and
`/api/v1/trust-list/<agency>` publishes every key with its status, signed. Every stored
signature carries its public key, so a credential signed under a retired key keeps verifying.

1. Perform a ceremony for the NEW key (new file, new token label, or a new KMS key). Keep the
   old one.
2. Register the new key: `polaris key-register <agency> <new public key hex>`, or on the Docker
   stack `scripts/polaris-key-event.sh register <agency> <new public key hex>`. It becomes the
   agency's current key, and issuance for that agency refuses any other key's signature, so do
   this and step 3 together.
3. Switch the driver configuration to the new key and restart the application (on the Docker
   stack: replace `polaris_web/secrets/polaris_signing_key`, then recreate the `app` service).
4. Retire the old key: `polaris key-retire <agency> <old public key hex>` (or
   `polaris-key-event.sh retire ...`). What it signed before the retirement stays authorized at
   signing; it signs nothing new. Publish both public keys to verifiers that check offline
   (`polaris-verify --issuer-anchor`), or point them at the trust list.
5. Once every credential under the old key has expired or been re-issued, stop publishing it and
   destroy the old key material (shred the file; delete the token object; schedule KMS deletion
   with the waiting period).

Compromise: rotate at once, then `polaris key-compromise <agency> <old public key hex>
--effective-at <the earliest instant someone else may have used it>`. Credentials it signed from
that instant on read `issuer_authorized_at_signing: false`, and the trust list says compromised.

[`lab/strategy/006/rotate.sh`](../../lab/strategy/006/rotate.sh) runs all of this on the stack
[`try.sh`](../../lab/strategy/006/try.sh) starts, and CI runs it after try.sh
(`one-command.yml`): a credential under the old key and one under the new both verify, in the
application and with `polaris-verify` from PyPI against both published keys; with only one key
published, the other credential is refused; the signed trust list says retired and active; and
after the old key is declared compromised from before the first credential, that credential is
no longer authorized at signing while the second is untouched.

`POLARIS_PQC_TRUST_ANCHORS_FILE` lists earlier public keys that
`pqc_signing.verify_token_signature` accepts, which the custody tests below use. No route of
the running application reads it, so it plays no part in a rotation; the register does.

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
