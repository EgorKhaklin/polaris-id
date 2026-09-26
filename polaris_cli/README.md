# polaris-id-cli

Command-line interface to the [Polaris Identity Token System](https://github.com/EgorKhaklin/polaris):
the use-case stored procedures, inspection and read-only queries, and the
operator records (users, authorities, quotas, revocation bounds, relying
parties, authority keys, retention), without a browser.

Not wrapped as subcommands: `close_anchor_batch` (R10-2),
`uc10_attest_trust` / `uc10_revoke_attestation` (R11-3), `uc11_close_epoch`
(R10-1), `uc12_record_duress` (R11-5). Call them through the Flask API with
`curl`.

## Install

```bash
pip install polaris-id-cli                 # every read command and use-case procedure
pip install 'polaris-id-cli[user-mgmt]'    # adds werkzeug for user-create / user-passwd
polaris-id --help
```

From source:

```bash
git clone https://github.com/EgorKhaklin/polaris.git
cd polaris/polaris_cli
pip install -e '.[user-mgmt]'

# or without installing:
pip install psycopg2-binary werkzeug
python3 polaris.py health
```

## Configuration

| Variable | Default |
|----------|---------|
| `POLARIS_DB_HOST` | `localhost` |
| `POLARIS_DB_NAME` | `polaris_test` |
| `POLARIS_DB_USER` | `polaris_app` |
| `POLARIS_DB_PASSWORD` | `polaris_dev_password` |
| `NO_COLOR` | unset (color enabled) |

## Commands

| Command | Purpose |
|---------|---------|
| **Inspect** | |
| `health` | Row counts, token-status breakdown, PQ vs classical migration, disclosure distribution |
| `list <entity>` | `individuals`, `agencies`, `tokens`, `algorithms`, `contexts`, `verifications`; filters `--status`, `--context`, `--outcome`, `--limit` (default 50) |
| `inspect <token-id>` | Token record, lifecycle history, verification events, device bindings |
| `query "SQL"` | Read-only SELECT/WITH; 5,000-character limit, 5-second timeout, no DDL |
| **Use cases** | |
| `issue` | UC-1: create the Individual, provision, bind hardware, activate, grant contexts |
| `activate-reserve` | UC-4: lose an active token, promote a reserve |
| `bind-device` | UC-5: bind a device to an active token |
| `migrate-algorithm` | UC-6: migrate a token to a new algorithm |
| `warrant-audit` | UC-7: warrant-authorized verification history (ZK events excluded: no token_id is stored) |
| `revoke` | UC-8: revoke an ACTIVE token |
| `recovery-initiate` | UC-9 phase 1: open a catastrophic-loss recovery |
| `recovery-record-channel` | UC-9: record one out-of-band channel (`BIOMETRIC`, `SWORN`, `WITNESS`) |
| `recovery-complete` | UC-9 phase 2: approve or reject a pending recovery |
| `transition <token-id> <status>` | State-machine transition with an attributed audit row |
| `bulk-enroll <file>` | P2.4: stage a pipe-delimited extract with COPY and issue the batch set-based |
| `migrate-population` | P7.6: re-sign the whole ACTIVE population under a new algorithm, resumably |
| `transparency-report` | P7.7: the public transparency report for a period |
| **Accounts** | |
| `user-list` | Application users: role, active, last login, lockout (never hashes) |
| `user-create <username> <role>` | Create an application user |
| `user-passwd <username>` | Rotate a password; clears lockout |
| `user-deactivate <username>` | Soft-delete (`is_active = FALSE`); audit history kept |
| `user-history [username]` | Every recorded decision about an operator account |
| `audit-log` | Tail the authentication audit log |
| **Authorities and policy** | |
| `agency-create <name>` | Create an authority, with the reason it exists |
| `agency-history [agency_id]` | Every recorded decision about an authority |
| `quota-set <agency_id>` / `quota-show [agency_id]` | Per-agency caps; 0 clears a cap |
| `discretion-set <agency_id>` / `discretion-show [agency_id]` | Per-agency revocation-share bound over a rolling window |
| `rp-register <org_name>` | Register a relying party for the `/api/v1` API |
| `rp-policy <client_id>` | Set a relying party's auth-broker policy |
| `rp-history [client_id]` | Every recorded decision about a relying party |
| `key-register` / `key-retire` / `key-compromise` | Authority signing-key lifecycle |
| `retention-show` / `retention-set` | Retention in force, and recording a decision |

`polaris-id <command> --help` lists every flag.

### Inspect

```bash
polaris-id health
polaris-id list tokens --status ACTIVE
polaris-id list verifications --context BANKING --outcome SUCCESS --limit 20
polaris-id inspect 2
polaris-id query "SELECT context_type, COUNT(*) FROM VerificationEvent ve JOIN VerificationContext vc USING(context_id) GROUP BY context_type ORDER BY 2 DESC"
```

### Use cases

```bash
polaris-id issue \
    --legal-name "A. Holder" --dob 1990-01-15 --jurisdiction US-PA \
    --agency 1 --algorithm 1 --token-value TKN-PA-2026-100 --serial SN-PA-100 \
    --biometric IRIS --liveness MULTI_MODAL --witness 2 --hardware TitanQ-3 \
    --contexts 1,4,6

polaris-id activate-reserve --lost-token 4 --reserve-token 7 --actor-agency 1 \
    --reason LOST --crl-url "https://crl.idtoken.gov/2026/05/T4-LOST.crl"

polaris-id bind-device --token 2 --device-type PHONE \
    --fingerprint "SE-AAPL-A19-newdevice12345" \
    --binding-method SECURE_ENCLAVE --validity-months 24

polaris-id warrant-audit --individual 3 --context BANKING \
    --window-start "2026-01-01 00:00:00" --window-end "2026-12-31 23:59:59"

polaris-id transition 2 DORMANT --actor 3 --reason QUARTERLY_REVIEW
polaris-id transition 4 LOST    --actor 1 --reason HOLDER_REPORTED_THEFT
```

| Command | Flags |
|---------|-------|
| `issue` | `--legal-name`, `--dob`, `--jurisdiction`, `--agency`, `--algorithm`, `--token-value`, `--serial`, `--contexts` (required); `--biometric` (`NONE`/`FINGERPRINT`/`FACE`/`IRIS`, default `IRIS`), `--liveness` (`PASSIVE`/`ACTIVE_CHALLENGE`/`MULTI_MODAL`), `--witness`, `--hardware` |
| `activate-reserve` | `--lost-token`, `--reserve-token`, `--actor-agency`, `--crl-url`; `--reason` (`LOST`/`STOLEN`/`COMPROMISED`/`SUPERSEDED`/`ADMINISTRATIVE`) |
| `bind-device` | `--token`, `--fingerprint`; `--device-type` (`PHONE`/`TABLET`/`WATCH`), `--binding-method` (`SECURE_ENCLAVE`/`TITAN_SECURITY`/`TRUSTED_PLATFORM_MODULE`), `--validity-months` (default 12) |
| `migrate-algorithm` | `--token`, `--new-algorithm`, one of `--signature-hex` / `--signature-file`; `--deprecate-old` (one-way) |
| `warrant-audit` | `--individual`; `--window-start`, `--window-end`, `--context` |
| `revoke` | `--token`, `--actor-agency`, `--reason` (`POLICY_VIOLATION`/`FRAUD_DETECTED`/`COMPROMISE`/`SUPERSEDED`/`ADMINISTRATIVE`/`INDIVIDUAL_REQUEST`), `--published-location`; `--cosigner-agency` (R11-6) |
| `recovery-initiate` | `--individual` (must have no ACTIVE token), `--requesting-agency`, `--requesting-user`; `--cooldown-hours` (default 48) |
| `recovery-record-channel` | `--recovery-id`, `--recording-user`, `--channel`; `--sworn-statement-hash` (SWORN only, 64 hex) |
| `recovery-complete` | `--recovery-id`, `--deciding-user`, `--decision` (`APPROVED`/`REJECTED`), `--reason`; if approved: `--new-token-value`, `--new-serial`, `--algorithm`, `--biometric-binding`, `--liveness-check`, `--published-location` |
| `transition` | `<new-status>` in `ACTIVE`/`DORMANT`/`REVOKED`/`LOST`/`EXPIRED`; `--actor`, `--reason` |
| `bulk-enroll` | File columns `legal_name\|date_of_birth\|jurisdiction\|biometric_binding_type\|token_value\|physical_serial\|permitted_contexts`; `--agency`, `--algorithm`; `--note`, `--dry-run`. The whole batch rolls back on any rejection |
| `migrate-population` | `--to` (algorithm name, e.g. `ML-DSA-87`, or id); `--batch` (default 500), `--limit`, `--dry-run`, `--deprecate-old` (second pass, refused while any credential is unmigrated), `--grace-seconds` (default 1) |
| `transparency-report` | `--period` (e.g. `2026-Q3`), `--since`; `--published` (repeatable), `--anchor-target-hours`, `--checks-total`, `--checks-passed`, `--json` |

### Accounts

Usernames match `[a-z0-9._-]{3,50}` (lowercased automatically); roles are
`admin`, `operator`, `auditor`. Passwords are read interactively with
confirmation; `--password` is for scripting and shows in process listings.
Passwords need at least 12 characters with a digit, a letter and a symbol.
`user-create` requires `--justification` (at least 20 characters, recorded);
`--actor` names who created it.

An `admin` account gets a 30-day WebAuthn deadline, the same one
`scripts/polaris-create-operator.sh --role admin` sets
([docs/design/webauthn.md](../docs/design/webauthn.md)). During the 30 days a
password alone signs in and the interface asks for enrolment; after it, a
registered credential is required, and with none the login is refused and the
recovery path named. Operator and auditor accounts get no deadline.

```bash
polaris-id user-create alice operator --justification "Night-shift issuance operator for PA."
polaris-id user-passwd alice                 # also resets failed_login_count and locked_until
polaris-id user-deactivate alice             # reactivate with a direct SQL update
polaris-id user-history alice --widened-only
```

`audit-log` shows logins, failures, lockouts, CSRF rejections, authorization
denials, rate-limit triggers, WebAuthn and session events. Rows are append-only
at the schema level.

```bash
polaris-id audit-log                                        # last 50
polaris-id audit-log --event-type LOGIN_FAILED --since-minutes 60
polaris-id audit-log --username alice --limit 100
```

### Authorities and policy

A `--justification` is stored with the decision; where one is required it must
be at least 20 characters.

| Command | Flags |
|---------|-------|
| `agency-create` | `--agency-type` (`FEDERAL`/`STATE`/`COUNTY`/`PRIVATE`/`MUNICIPAL`), `--jurisdiction`, `--justification`; `--authorization-level` (1-5, default 3), `--actor` |
| `agency-history` | `--widened-only` |
| `quota-set` | `--issue-per-day`, `--revoke-per-day`, `--verify-per-hour`, `--justification`; `--set-by` |
| `quota-show` | `--history` |
| `discretion-set` | `--max-revoke-percent` (system default 5.00), `--justification`; `--window-days` (1-365, default 30), `--set-by` |
| `discretion-show` | `--history` |
| `rp-register` | `--rate-limit-per-min` (default 120), `--scope` (`verify`/`authenticate`/both), `--require-zk`, `--required-enrollment`, `--required-context`, `--justification` |
| `rp-policy` | `--require-zk` / `--no-require-zk`, `--required-enrollment` (or `none`), `--required-context` (id or `none`), `--justification` (required when the change weakens the policy) |
| `rp-history` | `--weakened-only` |
| `key-register`, `key-retire`, `key-compromise` | `<agency_id> <public_key_hex>`; `--effective-at` (ISO-8601, default now; a compromise may predate discovery), `--note`, `--algorithm` (`ML-DSA-65`/`ML-DSA-87`, inferred from key length) |
| `retention-show` | `--jurisdiction`, `--history` |
| `retention-set` | `--actor-user-id` (an admin), `--jurisdiction`; either `--template` or `--table-class` (`TOKEN_LIFECYCLE`/`VERIFICATION`/`ENROLLMENT`/`AUTH_AUDIT`) with `--days` and `--justification` |

Retention is data in `RetentionPolicy`. `STANDARD-5Y` keeps every class five
years; `MINIMIZED` keeps the civic record five years and operational history
two. Three refusals: below 365 days (a CHECK constraint, so lowering the floor
is a schema change); editing or deleting a decision (decisions are superseded,
never changed); and a `uc_archive_purge` cutoff inside the window.
See [docs/design/retention.md](../docs/design/retention.md) and
[OPERATIONS.md](../docs/operator/OPERATIONS.md).

```bash
polaris-id retention-show --jurisdiction=US-CA --history
polaris-id retention-set --actor-user-id=7 --jurisdiction=US-CA --template=MINIMIZED
polaris-id retention-set --actor-user-id=7 --jurisdiction=US-CA \
    --table-class=AUTH_AUDIT --days=1095 \
    --justification="State retention schedule 4.2 for operator access records."
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Usage / argument error / record not found / weak password |
| 2 | Database connection or generic SQL error |
| 3 | Procedure rejected the operation (constraint or business rule) |
| 130 | Interrupted (Ctrl-C) |

## Testing

```bash
python3 test_cli.py
```

115 integration tests (v1.0.0-rc.62) cover every command, the user lifecycle (create,
authenticate, rotate, deactivate), audit-log filtering and constraint
violations. Each test resets the database to the sample state.

Expected output: `115 passed` (v1.0.0-rc.62).

## Scripting examples

```bash
# Bulk-issue from a CSV
while IFS=, read name dob jur token serial; do
    polaris-id issue \
        --legal-name "$name" --dob "$dob" --jurisdiction "$jur" \
        --agency 1 --algorithm 1 --biometric IRIS \
        --token-value "$token" --serial "$serial" \
        --contexts 1,4
done < holders.csv

# Active tokens issued by one agency
polaris-id query "SELECT t.token_id, i.legal_name FROM IdentityToken t
               JOIN Individual i ON t.individual_id = i.individual_id
               WHERE t.issuing_agency_id = 1 AND t.status = 'ACTIVE'
               ORDER BY t.token_id"

# JSON rows for jq
polaris-id query "SELECT row_to_json(t) FROM IdentityToken t WHERE token_id = 2"

# Failed logins per IP in the last hour
polaris-id query "SELECT ip_address, COUNT(*) FROM AuthAuditLog
               WHERE event_type='LOGIN_FAILED'
                 AND event_timestamp > CURRENT_TIMESTAMP - INTERVAL '1 hour'
               GROUP BY ip_address ORDER BY 2 DESC"
```
