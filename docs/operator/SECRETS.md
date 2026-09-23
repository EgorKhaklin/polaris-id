# Secrets

**Reader:** the SRE or security engineer who generates, custodies, and
rotates the production secrets of a Polaris deployment. **Job:** know every
secret the stack reads, where each one is read from, how to generate and
rotate it, and what the sealed store adds on top of the plaintext directory.

This document covers production. The dev launcher
([`polaris_mac_launch.sh`](../../polaris_mac_launch.sh)) uses fixed dev
credentials (`polaris_dev_password` for the database role) and generates the
session key once, persisting it in `$POLARIS_STATE_DIR/secret_key` (default
`/tmp/polaris-state`); `POLARIS_SECRET_KEY` set in the shell overrides it.
The production runbook that calls into this document is
[OPERATIONS.md](OPERATIONS.md); installation is [INSTALL.md](INSTALL.md) and
[LINUX-SERVER.md](LINUX-SERVER.md).

---

## 1. The secrets matrix

Every file below lives in the secrets directory: `polaris_web/secrets/` with
the `file` backend, or the tmpfs named by `POLARIS_SECRETS_DIR` when a sealed
store is in use ([section 5](#5-the-sealed-secret-store)). The directory is
mode 0700 and is the host-side boundary; the per-file mode is whatever the
consuming container needs. [`docker-compose.prod.yml`](../../polaris_web/docker-compose.prod.yml)
mounts each file through `${POLARIS_SECRETS_DIR:-./secrets}/<name>`.

| File | Contents | Mode | Read by | Rotated by |
|---|---|---|---|---|
| `polaris_secret_key` | 32 random bytes as 64 hex chars | 0644 | the app, via `POLARIS_SECRET_KEY_FILE=/run/secrets/polaris_secret_key` (Flask session signing) | `polaris-rotate-secret.sh` |
| `polaris_db_password` | random hex (24 bytes at generation, 32 at rotation) | 0644 | the app and pgbouncer as the `polaris_app` role; `docker-init.sh` syncs the role to it | `polaris-rotate-secret.sh` |
| `polaris_db_root_password` | random hex | 0600 | the postgres entrypoint as root, before it drops privileges | `polaris-rotate-secret.sh` |
| `polaris_replicator_password` | random hex | 0644 | `docker-init.sh` as the postgres user; creates the `polaris_replicator` role for a standby ([FAILOVER.md](FAILOVER.md)) | by hand; not covered by the rotation script |
| `polaris_signing_key` | ML-DSA-65 keypair JSON | 0644 | the app, via `POLARIS_PQC_SIGNING_KEY_FILE` (the issuer trust anchor) | the key ceremony ([KEY-CEREMONY.md](KEY-CEREMONY.md)) |
| `postgres_server.crt` / `.key` | self-signed TLS cert, CN=postgres, 825 days | 0644 | the postgres container copies them into its data dir at init | regenerate with `polaris-generate-secrets.sh` after deleting the pair, or supply a CA-issued pair |
| `pgbouncer_server.crt` / `.key` | self-signed TLS cert, 825 days; the app pins it with `sslmode=verify-ca` | 0644 | pgbouncer and the app | same as the postgres pair |
| `pgbackrest_repo_creds.conf` | S3 key pair for the offsite backup repo; ships as an empty template | 0644 | pgBackRest as the postgres user | at the object-store provider, then rewrite the file |
| Caddy ACME account key and certificates | managed by Caddy | n/a | Caddy | automatic (Let's Encrypt renewal) |

Redis runs without AUTH on the private compose network; there is no Redis
secret. The Let's Encrypt contact address is `admin@$POLARIS_DOMAIN`
([`Caddyfile`](../../polaris_web/Caddyfile)); no operator-email variable
exists.

Recommended cadence: session key and database passwords every 90 days, the
superuser password every 180 days, and any secret immediately on a suspected
compromise or when an operator with prior access leaves.

---

## 2. Generation

[`scripts/polaris-generate-secrets.sh`](../../scripts/polaris-generate-secrets.sh)
is the one-time entry point:

```bash
./scripts/polaris-generate-secrets.sh
```

It creates the 0700 directory, writes every file in the matrix that does not
already exist, and sets the modes listed above. For the hex secrets a
zero-byte file counts as missing and the mode is verified after the write; the
two TLS pairs are skipped whenever both files exist, even empty (delete both
to regenerate), and the signing key, cert pairs, and credentials template are
chmodded without verification. It never overwrites a non-empty
secret; rotation is a separate script. It echoes no secret to stdout. Random
material comes from `openssl rand -hex`, then `secrets.token_hex`, then
`/dev/urandom`, in that order of preference.

The two TLS pairs are produced with `openssl req -x509`; without `openssl` on
the host the script skips them and prints a `POLARIS_DB_SSLMODE=prefer` hint.
That hint applies to non-production runs only: the production compose file
pins `verify-ca` on both hops and the app refuses to start under
`POLARIS_ENV=production` with any sslmode other than `require`, `verify-ca`,
or `verify-full`. A production deploy needs `openssl` on the host or an
operator-supplied pair.

### Verify the file modes

```bash
stat -c '%a %n' polaris_web/secrets/* 2>/dev/null || stat -f '%A %N' polaris_web/secrets/*
```

Expect 0644 on everything except `polaris_db_root_password` (0600), and
`drwx------` on the directory. Do not blanket `chmod 0600 secrets/*`: docker
compose mounts a file secret with the source file's mode, and on Linux a
0600 host-owned file is unreadable by the non-root app (uid 1000) and
pgbouncer containers, so the stack does not boot. Re-running the generator
does not touch existing files; restore the modes by hand (`chmod 0644` on
everything except `polaris_db_root_password`) or, with a sealed backend, by
re-unsealing (modes come from `MANIFEST.json`).

---

## 3. Where secrets are read

The app reads secrets from files named by `*_FILE` environment variables
(`_read_secret_file` in [`polaris_web/app.py`](../../polaris_web/app.py)):
`POLARIS_SECRET_KEY_FILE`, `POLARIS_DB_PASSWORD_FILE`,
`POLARIS_PQC_SIGNING_KEY_FILE`. The production compose file points each at
`/run/secrets/<name>`. The plain-variable fallback (`POLARIS_SECRET_KEY`,
`POLARIS_DB_PASSWORD`) exists for the dev stack only; the production compose
file never sets one.

Non-secret configuration is passed as environment variables, from the shell
or from `/etc/polaris/polaris.env` on a systemd install
([LINUX-SERVER.md](LINUX-SERVER.md)): `POLARIS_DOMAIN`, `WEB_CONCURRENCY`
(`POLARIS_WORKERS` wins over it only inside the container; the production
compose file does not forward it), the
`POLARIS_WEBAUTHN_*` policy knobs ([WEBAUTHN-ROLLOUT.md](WEBAUTHN-ROLLOUT.md)),
the `POLARIS_SESSION_*` and `POLARIS_NETWORK_POLICY_*` knobs
([HARDENING.md](HARDENING.md)), and the `POLARIS_SECRETS_*` settings from
[section 5](#5-the-sealed-secret-store). `POLARIS_SECRETS_AGE_IDENTITY` names
a root-only key file; it is a path, not the key. `POLARIS_ZK_BINARY` is fixed
at `/opt/polaris/zk` in the production compose file and is not operator-settable
there.

---

## 4. Rotation

[`scripts/polaris-rotate-secret.sh`](../../scripts/polaris-rotate-secret.sh)
rotates one secret at a time and accepts exactly three names:

```bash
./scripts/polaris-rotate-secret.sh polaris_secret_key
./scripts/polaris-rotate-secret.sh polaris_db_password
./scripts/polaris-rotate-secret.sh polaris_db_root_password
```

Common steps, in order:

1. Copies the current file to `<secrets dir>/.archive/<name>.<UTC timestamp>`
   (mode 0600) so a broken rotation can be undone by hand.
2. Generates 32 random bytes as 64 hex chars.
3. Asks whether the stack is running, before anything changes, and asks up to five times: a
   single empty answer from `docker compose ps` is not taken as a stopped stack. For
   `polaris_db_password` and `polaris_db_root_password` a stopped stack is a refusal: the
   password lives in the database as well as in the file, the two must change together, and
   the script exits non-zero having changed nothing. For those two it then runs the `ALTER
   USER`; if that fails, it stops there, and the old password still works everywhere.
4. Writes the replacement atomically, preserving the existing file's mode
   (`check_rotate_secret_preserves_mode` in
   [`polaris_checks/checks.py`](../../polaris_checks/checks.py) pins this).
5. With a sealed backend, seals the new value through to the store
   (`polaris-secrets.sh seal --only <name>`), keeping the previous blob as
   `.prev`.
6. Applies the change to the running stack. Only `polaris_secret_key` can arrive here with
   the stack stopped; its new value takes effect when the stack next starts.
7. Prints the health-check command to run; it does not run a smoke test and
   it does not roll back.

Per-secret step 6:

- `polaris_secret_key`: recreates the app container(s) one at a time,
  waiting for each to report healthy. Every user session is invalidated;
  schedule the rotation for a low-traffic window.
- `polaris_db_password`: (the `ALTER USER polaris_app` ran at step 3) recreates pgbouncer
  BEFORE the app. pgbouncer builds its `userlist.txt` from the secret at
  container start, so recreating only the app leaves every connection
  failing with `SASL authentication failed`; `check_secrets_lifecycle_sealed`
  pins the order. If you rotate by hand, do the same.
- `polaris_db_root_password`: (the `ALTER USER postgres` ran at step 3) recreates the
  postgres container.

The database role is altered before the file is rewritten. Until 2026-09-23 it was the other
way round, and a stack the script mistook for stopped (one empty `compose ps`, CI run
35885214888) had its password file rotated with the database never told: the next app
restart failed every connection with `SASL authentication failed`. If the file write fails
after the `ALTER USER` has succeeded (a full disk, a read-only mount), the database holds the
new value and the file the old one. The script never prints a secret, so recover with the
archived one: `ALTER USER` the role back to the value in `.archive/<name>.<timestamp>`, then
retry.

Secrets the script does not cover: the signing key follows the ceremony in
[KEY-CEREMONY.md](KEY-CEREMONY.md#rotation); the replicator password and the
pgBackRest S3 credentials are rotated by hand (change the credential at its
source, rewrite the file, recreate the postgres container). Caddy renews its
certificates itself; check the served certificate's expiry and Caddy's ACME
log with:

```bash
openssl s_client -connect "$POLARIS_DOMAIN:443" -servername "$POLARIS_DOMAIN" </dev/null 2>/dev/null \
    | openssl x509 -noout -enddate
docker compose -f polaris_web/docker-compose.prod.yml exec caddy \
    grep -i -E 'certificate|acme' /var/log/caddy/caddy.log
```

`caddy validate --config /etc/caddy/Caddyfile` (run the same way through
`exec caddy`) checks the config syntax only; it says nothing about renewal.
If renewal fails, confirm outbound 80/443 and that the DNS record still
points at this host.

---

## 5. The sealed secret store

With a sealed backend, the plaintext directory is the MATERIALIZED form,
written into a root-only tmpfs at start; the source of truth is
`polaris_web/secrets.sealed/`, whose contents are useless without a key that
is not on the disk beside them. The implementation is
[`polaris_web/secretstore.py`](../../polaris_web/secretstore.py); the operator
wrapper is [`scripts/polaris-secrets.sh`](../../scripts/polaris-secrets.sh).

| `POLARIS_SECRETS_BACKEND` | Sealed with | Unsealed by | Use when |
|---|---|---|---|
| `file` (default) | nothing: the plaintext dir is the store | n/a | development; the plain layout |
| `age` | the operator's age recipients (`POLARIS_SECRETS_AGE_RECIPIENTS`) | an age identity file (`POLARIS_SECRETS_AGE_IDENTITY`), root-only, or an age plugin for a hardware token | on-premises; no cloud dependency; the identity can live on a YubiKey |
| `awskms` | envelope encryption: per file, KMS `GenerateDataKey` (AES-256) + AES-256-GCM with the file name as AAD; the KMS-wrapped data key stored beside the ciphertext | `kms:Decrypt` on `POLARIS_SECRETS_AWSKMS_KEY_ID`, an IAM decision rather than a file | AWS-hosted authorities |

The issuer signing key has its own custody layer with HSM/PKCS#11 and KMS
drivers ([KEY-CEREMONY.md](KEY-CEREMONY.md)); this section covers everything
else in the matrix.

### 5.1 Adopting a sealed store

```bash
# one-time: the plaintext is generated exactly as before, then sealed
./scripts/polaris-generate-secrets.sh
age-keygen -o /root/polaris-age.identity          # keep OUT of the repo; back it up sealed
age-keygen -y /root/polaris-age.identity > /root/polaris-age.recipients   # prints the bare recipient
export POLARIS_SECRETS_BACKEND=age POLARIS_SECRETS_AGE_RECIPIENTS=/root/polaris-age.recipients \
       POLARIS_SECRETS_AGE_IDENTITY=/root/polaris-age.identity
./scripts/polaris-secrets.sh seal                 # -> polaris_web/secrets.sealed/ (+ MANIFEST.json)
./scripts/polaris-secrets.sh verify               # every blob decrypts and matches its sha256
shred -u polaris_web/secrets/* polaris_web/secrets/.archive/* 2>/dev/null; rm -rf polaris_web/secrets
# the plaintext directory goes away; .archive/ holds prior plaintext values from
# rotations and is never sealed, so it must be destroyed too
```

Put the `POLARIS_SECRETS_*` lines in `/etc/polaris/polaris.env`
([LINUX-SERVER.md](LINUX-SERVER.md)) and leave `POLARIS_SECRETS_DIR` empty
there unless you need a non-default tmpfs path (with the `file` backend a set
value makes compose read a directory nothing populates). From then on
[`polaris.service`](../../deploy/linux/polaris.service) runs
`polaris-secrets.sh unseal-if-configured` as `ExecStartPre` and
[`polaris-deploy.sh`](../../scripts/polaris-deploy.sh) does the same before
its preflight: the store is unsealed into `POLARIS_SECRETS_DIR` (default
`/run/polaris/secrets`, a tmpfs mounted `size=16m,mode=0700,nosuid,nodev,noexec`
when the caller is root on Linux), file modes are restored from the manifest,
and compose reads every secret and certificate from there. No plaintext
touches the disk.

For `awskms`: `POLARIS_SECRETS_BACKEND=awskms POLARIS_SECRETS_AWSKMS_KEY_ID=<key arn>
POLARIS_SECRETS_AWSKMS_REGION=<region>`, host `python3` with boto3
(`pip install -r polaris_web/requirements-custody.txt`), and an instance role
allowed `kms:GenerateDataKey` and `kms:Decrypt` on that key. The store can be
kept in a PRIVATE ops repository or an object bucket; `.gitignore` excludes
`polaris_web/secrets/`, `polaris_web/secrets.sealed/`, and
`polaris_web/secrets.sealed.prev/` here.

### 5.2 Rotation with a sealed store

**A secret** (the session key, a DB password): `polaris-rotate-secret.sh
<name>` exactly as in [section 4](#4-rotation). It rotates the materialized
copy, updates the database role, recreates the affected container, and writes
through to the sealed store, keeping the previous blob as `<name>.age.prev`
(or `.kms.prev`). The store never lags the running stack, so a reboot
re-unseals the new value. `polaris-secrets.sh verify` asserts that invariant
(sealed == materialized).

**The wrapping key** (a new age identity, or a new KMS key), without changing
any secret's value:

```bash
./scripts/polaris-secrets.sh rotate-wrapping --new-recipients /root/polaris-age-2.recipients
#   or: --new-key-id <new kms key arn>
```

The previous generation is kept as `polaris_web/secrets.sealed.prev/` until you
remove it or until the next `rotate-wrapping`, which overwrites it; the old
identity or key no longer opens the live store (the KMS
driver pins `KeyId` on `Decrypt`, so a stale key is refused, not silently
accepted). Then update `polaris.env` to the new identity or key and run
`polaris-secrets.sh verify`.

### 5.3 What is drilled in CI

The `prod-stack-boot` job in
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) seals the
generated secrets to a throwaway age identity, deletes the plaintext
directory, unseals into a tmpfs, boots the full production stack from it,
asserts health through the TLS edge, then runs `polaris-rotate-secret.sh` for
`polaris_db_password` and `polaris_secret_key` against the live stack, asserts
health again, verifies the sealed store matches the tmpfs, and proves a fresh
unseal returns the rotated password.
[`test_secretstore.py`](../../polaris_web/test_secretstore.py) covers both
backends (age through the real CLI, KMS through the wire-faithful stand-in),
wrapping-key rotation, tamper and drift detection, and mode restoration.
`check_secrets_lifecycle_sealed` pins the scripts, the unit, the compose
paths, the CI drill, and this document's mention of `POLARIS_SECRETS_BACKEND`
and `rotate-wrapping`.

### 5.4 External alternatives

HashiCorp Vault, GCP Secret Manager, and Azure Key Vault are not built in.
They fit the same shape: an `unseal-if-configured` that materializes the
secrets into `POLARIS_SECRETS_DIR` from your store before the stack starts.
Write that hook in place of `polaris-secrets.sh` and keep the rest identical;
the compose file only ever sees the directory.

---

## 6. Leak prevention

### 6.1 Version control

Nothing. `.gitignore` excludes `polaris_web/secrets/`, both sealed
directories, `secrets.json`, and `polaris.env` (`check_secrets_file_ignored`
fails the invariant suite if the `polaris.env` pattern is missing or carries a
trailing comment). Verify:

```bash
git check-ignore polaris_web/secrets/polaris_secret_key
```

If a secret was ever committed: rotate it first (assume it is leaked), then
rewrite history with `git filter-repo` if the repository is private and you
control every clone. A public history keeps the value forever; rotation is
the only response.

### 6.2 Logs

- Caddy writes a JSON access log to `/var/log/caddy/access.log` (request
  metadata; no bodies) and its own log to `/var/log/caddy/caddy.log`.
- The app emits structured log lines through `observability.structured_log`;
  request bodies and secrets are not fields of those events.
- Postgres: if statement logging is on, keep `log_statement = 'mod'` rather
  than `'all'`; parameterized queries keep values out of the statement text.

If a log line does contain a secret: stop the service, rotate the secret,
purge every log destination (file, syslog, aggregator), then close the gap
that let it through.

### 6.3 Backups

[`scripts/polaris-backup.sh`](../../scripts/polaris-backup.sh) produces a
tarball holding a custom-format `pg_dump` and a `MANIFEST.json` of SHA-256
hashes. The dump carries the scrypt password hashes in `AppUser`, never the
`polaris_app` connection password. The secrets directory is not in the
backup.

Set `POLARIS_BACKUP_KEY_FILE` to a 0600 key file and the script encrypts the
tarball with AES-256-CBC (PBKDF2) and removes the plaintext; without it the
script prints a warning and leaves the tarball in the clear. Treat an
unencrypted tarball that left the host as a disclosure of the database. See
[DR.md](DR.md) for restore.

### 6.4 CI/CD

Use the platform's secret store; never inline a value in workflow YAML. Audit
who can read that store. Rotate any secret that may have surfaced in a failed
workflow's log.

---

## 7. Structural guarantees

The invariant layer ([`polaris_checks/`](../../polaris_checks/checks.py))
pins the following; `python -m polaris_checks.run` must end with `READY`
(exit 0); the summary line above it shows `0 fail`.

- Compose reads every secret through `${POLARIS_SECRETS_DIR:-./secrets}`, so
  a sealed store can be materialized anywhere (`check_secrets_lifecycle_sealed`).
- pgbouncer reads the database password from `POLARIS_DB_PASSWORD_FILE`, not
  from the environment (`check_pgbouncer_self_built`).
- The postgres service points `POLARIS_APP_PASSWORD_FILE` at the same secret
  the app reads and `docker-init.sh` alters the role to it, so the dev
  default from `09_grants.sql` is never live in production
  (`check_prod_app_password_synced`).
- Rotation preserves file modes (`check_rotate_secret_preserves_mode`).
- `polaris.env` is gitignored (`check_secrets_file_ignored`).

The dev launcher generates `POLARIS_SECRET_KEY` once and persists it in
`$POLARIS_STATE_DIR/secret_key` (default `/tmp/polaris-state`), so a dev
session cookie survives a relaunch; delete that file to force a rotation, and
a value set in the shell overrides it. Production does not auto-rotate on restart; rotation is the
operator's explicit act ([section 4](#4-rotation)).

The audit-of-record tables (`TokenLifecycleEvent`, `VerificationEvent`,
`AuthAuditLog`) carry no password, session, or key columns. The duress code
is stored as a Werkzeug scrypt commitment (`duress_code_hash`), never the
plaintext (`test_duress_code_hash_length_floor` in `test_app.py`,
`test_duress_hash_well_formed` in `test_check_constraints.py`).

---

## 8. Threat model summary

The full STRIDE analysis is [docs/design/threat-model.md](../design/threat-model.md).
For secrets specifically:

| Threat | Mitigation |
|---|---|
| Operator laptop stolen with the secrets directory on it | Full-disk encryption (operator responsibility); a sealed backend so the checkout holds only ciphertext; rotate on incident |
| Backup tarball intercepted | `POLARIS_BACKUP_KEY_FILE` so the tarball is encrypted before it leaves the host; rotate any secret an older plaintext backup could hold |
| Compromised CI/CD pipeline | Platform secret store; audit access; rotate on suspicion |
| Insider with prior secret access | Rotate on departure; record the rotation in the operator change log |
| Postgres statement log leaks a password | `log_statement = 'mod'`, never `'all'`; review log redaction quarterly |
| Dev secrets promoted to production | Separate directories and generators; `check_prod_app_password_synced` pins that the prod role is altered to the file-mounted secret. Nothing refuses a dev-valued file (`docker-init.sh` skips the `ALTER` when the file holds `polaris_dev_password`), so never copy dev secrets into the prod directory |
| Caddy compromise leaks the TLS private key | Caddy re-issues; rotate the secrets that crossed TLS-terminated traffic |
| Memory dump of a running gunicorn worker | No shared tenancy on the host; the sealed store keeps plaintext in a root-only tmpfs rather than on disk |

For each threat the response is the same: rotate, audit, postmortem. Speed
of rotation matters more than perfect forensics.

---

## 9. WebAuthn operator MFA

Enrollment, deadlines, the relying-party knobs (`POLARIS_WEBAUTHN_RP_NAME`,
`POLARIS_DOMAIN` as the relying-party ID, `POLARIS_WEBAUTHN_HARDWARE_ONLY`,
the attestation policy), recovery of a locked-out admin by second-admin
pairing or printed mnemonic, and disabling MFA on an account all live in
[WEBAUTHN-ROLLOUT.md](WEBAUTHN-ROLLOUT.md).

---

## 10. Related documents

- [OPERATIONS.md](OPERATIONS.md): production runbook (this document's parent)
- [LINUX-SERVER.md](LINUX-SERVER.md): the systemd install, `/etc/polaris/polaris.env`
- [KEY-CEREMONY.md](KEY-CEREMONY.md): signing-key custody and rotation
- [FAILOVER.md](FAILOVER.md): the replicator password and standby setup
- [DR.md](DR.md): backup and restore
- [ENCRYPTION-AT-REST.md](ENCRYPTION-AT-REST.md): disk encryption on the host
- [`polaris_web/docker-compose.prod.yml`](../../polaris_web/docker-compose.prod.yml): where each secret is mounted
- [`polaris_web/secretstore.py`](../../polaris_web/secretstore.py): the sealed-store implementation
- [docs/design/threat-model.md](../design/threat-model.md): STRIDE analysis
