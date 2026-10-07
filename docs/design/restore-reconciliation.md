# Reconciling a restore

**Reader:** an engineer, an assessor, or an operator about to restore a database. **Job:** what a
restore to an earlier point takes back, what Polaris puts back before the application returns, and
what it leaves for a person to decide.

## What was wrong

[DR.md section 4.3](../operator/DR.md) restores to the last known-good moment with
`pgbackrest --type=time`, and until gate row OP-13 it brought the application straight back. Every
change made after the target is lost with the restore, and the losses that matter most are the ones
that withdrew something. A credential revoked as stolen reads as active again. An authority key
declared compromised is trusted again. An operator account switched off, or a relying party disabled,
is on again with its old secret. A consumed nonce or authorization code can be replayed. The sequences
rewind as well, so the next credential, wallet copy or epoch takes an identifier the archive's end had
already handed out: a new copy could take the status-list slot of one the restore lost, and the lost
copy would then read as valid. [polaris_sql/README.md](../../polaris_sql/README.md) records REVOKED as
terminal; a restore was the path that made it otherwise.

## The mechanism

[`scripts/polaris-reconcile-restore.py`](../../scripts/polaris-reconcile-restore.py) runs after the
restore and before the application takes traffic, against a second restore of the archive's end in a
scratch instance (DR.md 4.3, steps 5 and 6).

1. **Identifiers.** Each sequence moves past its value at the archive's end, plus a margin for writes
   in WAL the archive never received (100000 by default); the wallet-copy sequence moves to the start
   of the next status list, so a new copy never shares a list with a lost one. Nothing issued after
   the target is issued again.
2. **Withdrawals, replayed.** Each withdrawal the archive's end recorded after the target, and the
   restored database lacks, is re-applied in the order it was made, through the path that made it,
   with the original actor, reason and co-signer where the archive recorded them. Revocations go
   through `uc8_revoke_token`, whose rate bound and co-signer rule apply again; a loss with its
   reserve through `uc4_activate_reserve`; holder keys through `uc_record_holder_key_event`; authority
   keys through the register insert `polaris-key-event.sh` makes; attestation revocations through
   `uc10_revoke_attestation`; erasures through `uc_pseudonymize_individual`. Consumed nonces and codes
   go back into their registers, and an enrolment code redeemed after the target is exhausted.
3. **State, compared.** For operator accounts and their sessions and hardware keys, relying parties,
   agencies, algorithms, verification contexts, authorizations and permissions, whatever is looser on
   the restored database than at the archive's end is set back. The schema's own orderings judge
   looser where it has them (`_app_user_widens`, `_rp_weakens`), and the writes go through the audited
   updates, which record their own events.
4. **What is not re-made, named.** Grants made after the target (credentials issued, keys registered,
   accounts, relying parties and attestations created, devices bound) and policies set after it are
   listed with how to make them again: they are the operator's to decide. Records of things that
   happened (verifications, duress records, epochs, anchors, sign-ins) cannot happen again and are
   counted per table.
5. **Checked and recorded.** A second pass reads both databases again. Anything still looser is
   printed with its remedy and the run exits 1. Each run is one `RestoreRecord` row, append-only and
   closed to the application role.

## The rules it keeps

- **Fail-safe, never forced.** Re-applying a withdrawal can only take something away, and a grant is
  never re-made. A withdrawal its path now refuses (the rate bound wants a co-signer, an attestation
  revocation needs an admin to act as) is reported, not pushed through, so there is no new privileged
  write path to audit.
- **Every table decided.** `REGISTRY` classifies all 67 tables a migrated deployment holds as
  re-applied, listed, counted, derived or reference. The script refuses a database holding a table
  it does not name, and `check_restore_reconciled` fails when the schema gains one: a table added
  later cannot be lost by a restore without that being decided.
- **One history, not yet used.** It refuses two databases with different system identifiers, a
  migration applied after the target, and a restored database something has already written to
  (rows after the target in tables only traffic writes). Restore again, and reconcile before the
  application runs.
- **The damage can be excluded.** A restore that undoes a compromised operator should not re-apply
  that operator's withdrawals. The dry run prints a key per withdrawal, and
  `--exclude KEY --exclusion-reason` skips one and records why.

## How it is tested

`scripts/polaris-pitr-drill.sh --reconcile`, in CI's DR job, makes 24 withdrawals of every kind on
either side of a target on a real archiving primary and restores both points. The restored database
must first read looser (credential 10, revoked after the target, reads ACTIVE), then, once
reconciled, equal the archive's end apart from the one grant made after the target, which is listed.
Credential 4, expired before the target, must be untouched, every sequence must be past the archive's
end, and a second run must re-apply nothing. Removing any one of the fifteen planners, or the
identifier retirement, leaves the comparison failing (measured 2026-10-07).

## What it does not do

- It reads the archive's end, so writes in WAL the archive never received (`archive_timeout`, 60 s)
  are lost, withdrawals with them.
- It re-makes no grant, re-issues no credential and closes no epoch. Epochs and anchors closed after
  the target exist outside the database, published and anchored; the restored log continues from new
  identifiers rather than reusing theirs.
- The compose commands in DR.md 4.3 run the drill's restore and the same script, but the drill runs
  them on standalone containers; a single command that performs the whole restore is not built yet.
