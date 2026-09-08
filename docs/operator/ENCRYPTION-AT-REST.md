# ENCRYPTION-AT-REST.md: the at-rest data-protection posture

**Reader:** the operator provisioning the host that holds the Polaris database,
and the reviewer asking what sits in plaintext on that disk.
**Job:** name what is sensitive at rest, what is already protected, the gap that
remains, why the control is the volume rather than the column, and the operator
path (LUKS, managed TDE, fscrypt) with its verification step.

At rest means data sitting on disk: the live database files, the write-ahead log
(WAL), and backups. Data in transit (the app-to-pgbouncer and pgbouncer-to-Postgres
hops run TLS with certificate verification; the `POLARIS_DB_SSLMODE` contract is
in [DEPLOYMENT.md](DEPLOYMENT.md#environment-variables)) and data in use are
separate subjects.

Polaris does not encrypt the live database at the application layer. At-rest
protection of the live data files and WAL is host-level and operator-gated: it
depends on a full-disk or volume encryption layer the operator provisions (LUKS /
dm-crypt / fscrypt, or a managed provider's storage encryption) and a key
custodian. The pg_dump tarballs are encrypted by Polaris when
`POLARIS_BACKUP_KEY_FILE` is set; the pgBackRest repository is not encrypted by
Polaris ([section 3](#3-what-is-already-protected)); transit is encrypted by Polaris.
This document is the posture and the operator path, not a claim that the live
database is encrypted at rest by Polaris.

---

## Table of contents

1. [What is sensitive at rest](#1-what-is-sensitive-at-rest)
2. [What is deliberately NOT stored](#2-what-is-deliberately-not-stored)
3. [What is already protected](#3-what-is-already-protected)
4. [The gap: the live database](#4-the-gap-the-live-database)
5. [Why host-level encryption, not field-level](#5-why-host-level-encryption-not-field-level)
6. [The operator path](#6-the-operator-path)
7. [Cross-references](#7-cross-references)

---

## 1. What is sensitive at rest

Two surfaces in the schema hold data that an at-rest compromise (a stolen disk, a
copied data directory, a leaked volume snapshot) would expose:

| Surface | Column(s) | Why it matters |
|---|---|---|
| Personal data | `Individual.legal_name`, `Individual.date_of_birth` | The only direct holder PII in the system: the legal name and birth date that bind a token to a person. |
| Operator audit trail | `AuthAuditLog.username`, `AuthAuditLog.ip_address`, `AuthAuditLog.user_agent` | Operator username, client IP address, and user agent per authentication event, in plaintext and permanent under C1 (append-only). [PRIVACY.md](PRIVACY.md) lists `ip_address` as retained personal data. |
| Quasi-identifier | `Individual.jurisdiction` | An ISO 3166-2 region; low cardinality, but narrows a re-identification set. |
| ZK structural data | `TokenStateEpochLeaf.proof_path` (plaintext `JSONB`), `TokenStateEpochLeaf.leaf_hash` | The per-token Merkle inclusion path within an epoch snapshot. The schema itself flags this: `polaris_sql/01_schema.sql` comments "v1 stores proof_path in plaintext; v2 would encrypt under holder key." In aggregate the leaf table maps which tokens were members at which epoch. |

These are the surfaces the posture is about. Everything else in the schema is
either a hash, an opaque identifier, an append-only audit event, or operational
metadata (the device identifiers `IdentityToken.physical_serial` and
`hardware_model` name hardware, not a person).

---

## 2. What is deliberately NOT stored

The strongest at-rest control is the data that never lands on disk. Polaris is
built on data minimization ([PRIVACY.md](PRIVACY.md)):

- **Biometric plaintext never enters the database.** The schema stores only
  binding metadata (`IdentityToken.biometric_binding_type`,
  `biometric_enrolled_date`, `liveness_check_type`; `RecoveryRequest.biometric_verified`
  is a recovery-channel flag), never the template or sample itself.
- **Verification is zero-knowledge.** A verifier learns a yes/no membership
  answer, not the underlying attributes, so the verification path does not
  accumulate a plaintext attribute store.

A field that is never stored cannot leak from a stolen disk. This is a real part
of the posture, not a footnote.

---

## 3. What is already protected

- **pg_dump tarballs are encrypted at rest when `POLARIS_BACKUP_KEY_FILE` is
  set.** `scripts/polaris-backup.sh` encrypts the dump with AES-256-CBC (PBKDF2)
  when the key file is set and warns loudly when it is not;
  `scripts/polaris-restore.sh` fails closed without the key. A stolen backup
  tarball is ciphertext. See [DR.md](DR.md).
- **The pgBackRest repository (base backups plus the continuous WAL archive) is
  not encrypted by Polaris.** `polaris_web/pgbackrest.conf` and the rendered
  `conf.d/repo.conf` set no `repo1-cipher-type`, so the repo inherits the posture
  of where it lives: a local repo (the `pgbackrest_repo` volume, on the same host
  as `pg_data`) inherits the host volume posture and belongs on the encrypted
  volume; an S3 repo inherits the bucket's server-side encryption (SSE or KMS).
  An operator who wants pgBackRest's own cipher adds `repo1-cipher-type=aes-256-cbc`
  and `repo1-cipher-pass` to the mounted `pgbackrest_repo_creds.conf` fragment
  ([DR.md, section 5](DR.md#5-wal-archiving-and-the-offsite-repo-pgbackrest)).
- **Data in transit is encrypted and verified.** Both production hops (app to
  pgbouncer, pgbouncer to Postgres) run TLS and pin the peer certificate
  (`verify-ca`), so the data does not travel the container network in the clear
  and a peer presenting a different certificate is rejected.
- **Secrets are file-mounted, not in the image or the environment.** With the
  `file` backend the 0700 secrets directory sits on the host disk and belongs on
  the same encrypted volume as `pg_data`; with a sealed backend (age or AWS KMS)
  the plaintext is materialized only into a root-only tmpfs and the on-disk
  store is ciphertext ([SECRETS.md, section 5](SECRETS.md#5-the-sealed-secret-store)).

---

## 4. The gap: the live database

The live PostgreSQL data directory and WAL are not encrypted by Polaris. An
attacker who reads the raw data files (a stolen disk, a snapshot of an
unencrypted volume, host-level filesystem access) reads `legal_name`,
`date_of_birth`, and the `proof_path` leaves directly. PostgreSQL has no
transparent built-in data-file encryption; at-rest protection of the live
cluster is a property of the storage layer beneath it.

Closing the gap is host-level work the operator owns ([section 6](#6-the-operator-path)),
not application code.

---

## 5. Why host-level encryption, not field-level

Encrypting the columns is the tempting alternative. For Polaris it is the wrong
control:

- **The plaintext is load-bearing for queries the schema owns.** The
  warrant-audit function `uc7_warrant_audit` returns `legal_name` for
  SELECTIVE and FULL disclosure events (NULL for ZERO_KNOWLEDGE), the erasure
  procedure `uc_pseudonymize_individual` pseudonymizes it in place
  (`polaris_sql/05_procedures.sql`), and the app's holder and token pages join
  `Individual.legal_name` directly. `date_of_birth` is written by
  `uc1_issue_and_activate` and by the app's individual forms, and no procedure
  reads it. Column encryption under an application key
  either moves those reads into the app, or requires the database to hold the
  key beside the data, which is no protection against the host-level threat
  this document is about.
- **Field-encrypting `proof_path` gains nothing against the host threat.**
  `TokenStateEpochLeaf.proof_path` is the stored per-token witness a holder-side
  prover needs to build an inclusion proof; nothing shipped reads it back yet.
  The Rust binary (`polaris_zk`, wrapped by `polaris_web/zk.py`) emits it at
  epoch close and `uc11_close_epoch` stores it; `/api/zk/verify` checks a
  caller-supplied proof bundle against `TokenStateEpoch.merkle_root`, and the
  independent Python second witness (`polaris_zk/witness2/verifier.py`)
  re-derives the same verdict from that bundle. Encrypting the column under an
  application key would not break that verifier as wired today; it would,
  again, put the key beside the data.
- **Volume encryption protects every surface uniformly** (data files, WAL,
  temp files, indexes) against the actual at-rest threat (disk or snapshot
  theft) without distorting the query and ZK semantics the invariants depend
  on.

So the posture is: protect the whole volume at the host, keep the schema
queryable. The schema's own "v2 would encrypt proof_path under holder key" note
remains a future direction tied to a holder-key custody model, not a shipped
control.

---

## 6. The operator path

At-rest encryption of the live cluster is operator-gated: it needs a provisioned
host and a key custodian, which are organizational decisions, not code. The
four requirements, then the recipe for each deployment shape:

1. **Encrypt the volume that holds the PostgreSQL data directory.** LUKS /
   dm-crypt for a block device, fscrypt for a directory, or the cloud
   provider's encrypted-volume equivalent with a customer-managed key.
2. **Custody the volume key** in the same key-management posture as the other
   Polaris secrets ([SECRETS.md](SECRETS.md) describes the KMS and HSM paths).
   A key that sits unencrypted on the same host it unlocks protects against
   removal of the data disk alone, not against theft or imaging of the whole
   host.
3. **Keep backups encrypted**: set `POLARIS_BACKUP_KEY_FILE` so the pg_dump
   tarballs are ciphertext, and put the pgBackRest repository, which Polaris
   does not encrypt, on an encrypted volume or bucket; give the backup key and
   the volume key independent custody, so one compromise is not both.
4. **Verify**: a powered-off or detached volume must be ciphertext. Confirm
   before the host handles real data.

### Option A: LUKS on the host (bare metal or VM)

The production stack mounts the named volume `pg_data` at
`/var/lib/postgresql/data` (`polaris_web/docker-compose.prod.yml`). Put that
directory on a LUKS device before the first `polaris-deploy.sh prod`:

```bash
# One-time setup on a fresh host, BEFORE running polaris-deploy.sh prod
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup open /dev/sdb polaris_pg_crypt
sudo mkfs.ext4 /dev/mapper/polaris_pg_crypt
sudo mkdir -p /opt/polaris/pg_data
sudo mount /dev/mapper/polaris_pg_crypt /opt/polaris/pg_data

# Boot-time unlock and mount. A key file on the root disk gives unattended
# boot at the cost described in requirement 2; a passphrase prompt, a
# TPM-sealed key, or a key fetched from the KMS at boot avoids that cost.
# luksFormat enrolled only the interactive passphrase, so create the key file
# and enroll it as a second key slot (luksAddKey prompts for that passphrase).
sudo mkdir -p /etc/polaris
sudo dd if=/dev/urandom of=/etc/polaris/luks.key bs=64 count=1
sudo chmod 0400 /etc/polaris/luks.key
sudo cryptsetup luksAddKey /dev/sdb /etc/polaris/luks.key
echo "polaris_pg_crypt UUID=$(sudo blkid -s UUID -o value /dev/sdb) /etc/polaris/luks.key luks" | sudo tee -a /etc/crypttab
echo "/dev/mapper/polaris_pg_crypt /opt/polaris/pg_data ext4 defaults 0 2" | sudo tee -a /etc/fstab
```

Then point the `pg_data` volume at the encrypted mount with a compose overlay
(selected through `POLARIS_COMPOSE_EXTRA`, the same way the blue-green overlay
is; see [DEPLOYMENT.md](DEPLOYMENT.md#zero-downtime-deploys-blue-green-profile)):

```yaml
# docker-compose.pgdata-luks.yml
volumes:
  pg_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/polaris/pg_data
```

The LUKS key file is mode 0400, owned by root, and never enters a backup
tarball (`polaris-backup.sh` archives the database dump and its manifest, not
host files). With the key held elsewhere, a removed, imaged, or resold data disk
is inert.

### Option B: managed Postgres with storage-layer encryption

AWS RDS, Google Cloud SQL, and Azure Database for PostgreSQL Flexible Server
encrypt storage at the provider layer. Enable it at provisioning time with a
customer-managed KMS key, rotate the key per the provider's recommendation, and
confirm in the provider's console that the instance reports storage encryption
on. The shipped compose file assumes the `postgres` service: pgbouncer's
backend is `POLARIS_DB_HOST: postgres` with `verify-ca` pinned to
`secrets/postgres_server.crt`, the `app` and `pgbouncer` services `depends_on`
it, and the schema loads only through `docker-init.sh` inside that container.
A managed backend therefore needs an operator-written overlay, selected through
`POLARIS_COMPOSE_EXTRA`, that removes the `postgres` service from the run (an
unused `profiles:` entry keeps it from starting) and resets the `depends_on`
entries that reference it, points pgbouncer at the provider host and port
(`POLARIS_DB_HOST`, `POLARIS_DB_PORT`), mounts the provider's CA bundle in
place of `secrets/postgres_server.crt` at the path
`PGBOUNCER_SERVER_TLS_CA_FILE` names, and loads `polaris_sql/` by hand.
pgBackRest and the procedures in DR.md section 4 do not apply to that
deployment. Recovery point and point-in-time restore then belong to the
provider, not to the shipped pgBackRest path
([DR.md, section 1](DR.md#1-targets-rpo-and-rto)).

### Option C: filesystem-level encryption (fscrypt)

Per-directory encryption for the `pg_data` mount only. Lighter than full-disk
encryption; the same key-custody requirements apply. The bind-mount overlay
from Option A points `pg_data` at the encrypted directory.

### Verification step

Run after any of the three options, before the host handles real data:

```bash
# Is the pg_data mount on an encrypted device?
docker compose -f polaris_web/docker-compose.prod.yml exec postgres \
  df -T /var/lib/postgresql/data | tail -1
# LUKS: the device column is /dev/mapper/<name>; `lsblk -o NAME,TYPE,FSTYPE` on
# the host shows TYPE=crypt under the backing disk.
# Managed storage encryption: df shows ext4/xfs; the attestation is the
# provider's console, not the guest filesystem.
# fscrypt: `fscrypt status /opt/polaris/pg_data` on the host reports the policy.
```

Then detach or power off the volume and confirm the raw device reads as
ciphertext. Until the operator provisions this, the live database is protected
only as well as the host it runs on.

---

## 7. Cross-references

- [SECRETS.md](SECRETS.md): secret custody, the KMS and HSM paths, and the
  sealed store that keeps secret plaintext off the disk.
- [PRIVACY.md](PRIVACY.md): the data-minimization posture (what is never
  collected or stored).
- [DR.md](DR.md): backup encryption and disaster-recovery procedures.
- [HARDENING.md](HARDENING.md): the host itself, including filesystem
  permissions and backups off the host.
- [OPERATIONS.md](OPERATIONS.md#encryption-at-rest): the day-2 runbook's
  pointer to this document.
- [../PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md): the gap ledger;
  this document closes the at-rest posture item and leaves host encryption and
  its key custodian as the operator-gated remainder.
- `polaris_sql/01_schema.sql`: the `Individual` and `TokenStateEpochLeaf`
  tables, including the plaintext `proof_path` note this posture is grounded in.
