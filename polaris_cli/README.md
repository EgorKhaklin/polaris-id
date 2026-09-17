# polaris-id-cli

Command-line interface to the [Polaris Identity Token System](https://github.com/EgorKhaklin/polaris).

A scriptable wrapper around the use-case stored procedures
(`uc1_issue_and_activate`, `uc4_activate_reserve`, `uc5_bind_device`,
`uc6_migrate_algorithm`, `uc7_warrant_audit`, `uc8_revoke_token`,
`uc9_initiate_recovery`, `uc9_complete_recovery`) plus utility
commands for health checks, listing, token inspection, ad-hoc
queries, state-machine transitions, and application-user management
(create / passwd / deactivate / audit-log).

The v2 substrate procedures shipped through Flask routes only (not yet
wrapped here): `close_anchor_batch` (R10-2), `uc10_attest_trust` /
`uc10_revoke_attestation` (R11-3), `uc11_close_epoch` (R10-1),
`uc12_record_duress` (R11-5). To invoke these from the CLI, use
`polaris-id query` with explicit `CALL` statements, or the Flask API
endpoints via `curl`. Direct CLI subcommands for them are a future
backlog item.

## Install

### From PyPI (recommended)

```bash
# Core install: every read command and every use-case procedure works:
pip install polaris-id-cli

# Optional extra for the user-management commands (lazy-imports werkzeug
# for scrypt password hashing: needed only by `user-create` and
# `user-passwd`):
pip install 'polaris-id-cli[user-mgmt]'
```

After install, the console script is `polaris-id`:

```bash
polaris-id health
polaris-id list tokens --status ACTIVE
polaris-id inspect 2
```

### From source (development)

```bash
git clone https://github.com/EgorKhaklin/polaris.git
cd polaris/polaris_cli
pip install -e '.[user-mgmt]'
polaris-id --help

# Or run the script directly without install:
pip install psycopg2-binary werkzeug
python3 polaris.py health
```

## Configuration

Same environment variables as the web app:

| Variable               | Default                |
|------------------------|------------------------|
| `POLARIS_DB_HOST`      | `localhost`            |
| `POLARIS_DB_NAME`      | `polaris_test`         |
| `POLARIS_DB_USER`      | `polaris_app`          |
| `POLARIS_DB_PASSWORD`  | `polaris_dev_password` |
| `NO_COLOR`             | unset (color enabled)  |

## Commands

### `polaris-id health`

System-wide statistics: row counts per table, token-status breakdown, PQ vs
classical migration status, disclosure posture distribution. Mirrors the
Atlas health strip in the web UI.

### `polaris-id list <entity>`

Browse principal entities. Supports filters where appropriate.

```bash
polaris-id list individuals
polaris-id list agencies
polaris-id list tokens --status ACTIVE
polaris-id list verifications --context BANKING --outcome SUCCESS --limit 20
polaris-id list algorithms
polaris-id list contexts
```

### `polaris-id inspect <token-id>`

Full detail for a single token: record, lifecycle history, verification
events, device bindings.

```bash
polaris-id inspect 2
```

### `polaris-id query "SQL"`

Read-only SQL console (SELECT or WITH only). Same hardening as the web SQL
console: 5,000-character limit, 5-second statement timeout, no DDL.

```bash
polaris-id query "SELECT context_type, COUNT(*) FROM VerificationEvent ve JOIN VerificationContext vc USING(context_id) GROUP BY context_type ORDER BY 2 DESC"
```

### `polaris-id issue ...` (UC-1)

Atomic token issuance: creates Individual record, provisions IdentityToken,
performs hardware-binding ceremony, transitions to ACTIVE, grants permissions.

```bash
polaris-id issue \
    --legal-name "A. Holder" \
    --dob 1990-01-15 \
    --jurisdiction US-PA \
    --agency 1 \
    --algorithm 1 \
    --token-value TKN-PA-2026-100 \
    --serial SN-PA-100 \
    --biometric IRIS \
    --liveness MULTI_MODAL \
    --witness 2 \
    --hardware TitanQ-3 \
    --contexts 1,4,6
```

### `polaris-id activate-reserve ...` (UC-4)

Lose an active token, promote a reserve.

```bash
polaris-id activate-reserve \
    --lost-token 4 \
    --reserve-token 7 \
    --actor-agency 1 \
    --reason LOST \
    --crl-url "https://crl.idtoken.gov/2026/05/T4-LOST.crl"
```

### `polaris-id bind-device ...` (UC-5)

Bind a device to an active token.

```bash
polaris-id bind-device \
    --token 2 \
    --device-type PHONE \
    --fingerprint "SE-AAPL-A19-newdevice12345" \
    --binding-method SECURE_ENCLAVE \
    --validity-months 24
```

### `polaris-id warrant-audit ...` (UC-7)

Warrant-authorized verification history reconstruction. ZK events are
excluded by design (token_id was never stored, so they cannot be linked
to the individual).

```bash
polaris-id warrant-audit \
    --individual 3 \
    --context BANKING \
    --window-start "2026-01-01 00:00:00" \
    --window-end   "2026-12-31 23:59:59"
```

### `polaris-id transition <token-id> <new-status>`

Apply a state-machine transition. Sets the audit-trigger context GUCs so the
auto-audit trigger writes a properly-attributed lifecycle event.

```bash
polaris-id transition 2 DORMANT --actor 3 --reason QUARTERLY_REVIEW
polaris-id transition 4 LOST    --actor 1 --reason HOLDER_REPORTED_THEFT
```

### `polaris-id user-list`

List the application user accounts (web-app authentication accounts).
Shows username, role, active/inactive status, last login time, and lockout
state. Password hashes are NEVER displayed.

```bash
polaris-id user-list
```

### `polaris-id user-create <username> <role>`

Create a new application user. Username must match `[a-z0-9._-]{3,50}` (the
CLI lowercases automatically). Role must be `admin`, `operator`, or `auditor`.

Password is read interactively (no echo) by default, with confirmation.
Pass `--password` for scripting (less secure: visible in process listings).

Password complexity is enforced: ≥12 characters, at least one digit, one
letter, and one symbol.

**An `admin` account is created with a 30-day WebAuthn deadline**, the same one
`scripts/polaris-create-operator.sh --role admin` sets, because the policy in
[docs/design/webauthn.md](../docs/design/webauthn.md) requires a second factor
for admin. During those 30 days the password alone completes a login and the
interface asks for enrolment; after the deadline with a credential registered
both are required, and after it with none the login is refused with the recovery
path named. Operator and auditor accounts get no deadline: the second factor is
optional for operator and not asked of the read-only auditor. Until 2026-09-17
this command set no deadline at all, so an admin created here never had a second
factor demanded; `check_admin_mfa_deadline` now fails the build if the two
creation paths disagree.

```bash
# Interactive (recommended):
polaris-id user-create alice operator

# Scripted (avoid in shared shells):
polaris-id user-create alice operator --password 'StrongPass123!'
```

### `polaris-id user-passwd <username>`

Rotate a user's password. Also resets `failed_login_count` and
`locked_until`, so a locked-out user is unlocked. Same complexity rules as
`user-create`.

```bash
# Interactive:
polaris-id user-passwd alice

# After detecting a credential leak: rotate immediately:
polaris-id user-passwd admin --password 'NewStrongPass456!'
```

### `polaris-id user-deactivate <username>`

Soft-deletes a user account by setting `is_active = FALSE`. The user can no
longer log in, but their AuthAuditLog history is preserved (foreign keys
remain valid). To reactivate, run a SQL update directly.

```bash
polaris-id user-deactivate alice
```

### `polaris-id retention-show` / `retention-set`

The retention decision, as an operator sees it. How long each class of audit
row is kept is data in `RetentionPolicy`, not a number typed at the purge, and
these two commands are the surface for reading and changing it.

```bash
# What is in force, and the cutoff each class resolves to:
polaris-id retention-show

# One jurisdiction, with the decisions this one replaced:
polaris-id retention-show --jurisdiction=US-CA --history

# Adopt a profile. STANDARD-5Y is five years for every class; MINIMIZED keeps
# the civic record at five years and operational history at two. Admin only.
polaris-id retention-set --actor-user-id=7 --jurisdiction=US-CA --template=MINIMIZED

# Or record a decision of your own. The justification is stored on the row and
# must be at least twenty characters: it is what an assessor reads.
polaris-id retention-set --actor-user-id=7 --jurisdiction=US-CA \
    --table-class=AUTH_AUDIT --days=1095 \
    --justification="State retention schedule 4.2 for operator access records."
```

Three refusals are worth knowing before you need them. Retention below 365 days
is refused: the floor is a CHECK constraint, so no configuration reaches under
it and lowering it is a schema change. A recorded decision cannot be edited or
deleted, only superseded, so the previous decision and its justification stay
readable. And `uc_archive_purge` refuses any cutoff inside the window,
naming the class and the earliest cutoff it would accept.

The design record is [docs/design/retention.md](../docs/design/retention.md);
the runbook section is in
[OPERATIONS.md](../docs/operator/OPERATIONS.md).

### `polaris-id audit-log`

Tail the authentication audit log. Captures every login attempt (success
and failure), every CSRF rejection, every authorization denial, every
account lockout, and every rate-limit trigger. The schema-level append-only
trigger means these rows can never be modified.

```bash
# Last 50 events (default):
polaris-id audit-log

# Recent failed logins:
polaris-id audit-log --event-type LOGIN_FAILED --limit 20

# Brute-force detection:
polaris-id audit-log --event-type LOGIN_FAILED --since-minutes 60

# Activity for one user:
polaris-id audit-log --username alice --limit 100

# Per-IP analysis (chain via query):
polaris-id query "SELECT ip_address, COUNT(*) FROM AuthAuditLog
               WHERE event_type='LOGIN_FAILED'
                 AND event_timestamp > CURRENT_TIMESTAMP - INTERVAL '1 hour'
               GROUP BY ip_address ORDER BY 2 DESC"
```

## Exit Codes

| Code | Meaning                                                      |
|------|--------------------------------------------------------------|
| 0    | Success                                                      |
| 1    | Usage / argument error / record not found / weak password    |
| 2    | Database connection or generic SQL error                     |
| 3    | Procedure rejected the operation (constraint or business rule) |
| 130  | Interrupted (Ctrl-C)                                         |

## Testing

```bash
python3 test_cli.py
```

The CLI test suite has 71 integration tests (v9.194) covering every command, including
the user-management workflow (create → authenticate → rotate → deactivate),
audit-log filtering, and constraint-violation paths. Tests reset the database
to pristine sample state before each test.

Expected output: `71 passed` (v9.194).

## Examples for Scripting

```bash
# Bulk-issue tokens from a CSV
while IFS=, read name dob jur token serial; do
    polaris-id issue \
        --legal-name "$name" --dob "$dob" --jurisdiction "$jur" \
        --agency 1 --algorithm 1 --biometric IRIS \
        --token-value "$token" --serial "$serial" \
        --contexts 1,4
done < holders.csv

# Find all active tokens issued by a specific agency
polaris-id query "SELECT t.token_id, i.legal_name FROM IdentityToken t
               JOIN Individual i ON t.individual_id = i.individual_id
               WHERE t.issuing_agency_id = 1 AND t.status = 'ACTIVE'
               ORDER BY t.token_id"

# Pipe inspection JSON-style output to jq via the query command
polaris-id query "SELECT row_to_json(t) FROM IdentityToken t WHERE token_id = 2"

# Daily audit cron
polaris-id query "SELECT date_trunc('day', event_timestamp) AS day, COUNT(*)
               FROM VerificationEvent
               WHERE event_timestamp > CURRENT_DATE - INTERVAL '7 days'
               GROUP BY day ORDER BY day"
```
