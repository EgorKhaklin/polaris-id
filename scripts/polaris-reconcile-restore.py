#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-reconcile-restore.py: after a restore to an earlier point, put back what withdrew trust.

Lab record 017, gate row OP-13. A restore to a point T (docs/operator/DR.md section 4.3) brings
the database back as it stood at T, and every change made after T is lost with it, including the
ones that withdrew trust or access: a credential revoked after T reads as active again, a key
declared compromised is trusted again, an operator account switched off is on again, a consumed
nonce can be replayed. This script compares the restored database with a copy of the archive's
end (the same restore without --type=time, into a scratch instance) and, before the app takes
traffic:

  1. retires every identifier the archive's end had handed out: each sequence moves past its
     value there, so nothing issued after T is ever issued again (the wallet-copy sequence to the
     next status list, so a new copy never shares a list with one the restore lost);
  2. re-applies, in the order they were made and through the paths that made them, the
     withdrawals made after T that the restored database lacks (the kinds in REGISTRY);
  3. lists what it does not re-make: grants and policies made after T, with how to make them
     again, and the records of things that happened, counted per table;
  4. checks that nothing REGISTRY calls a withdrawal is looser on the restored database than at
     the archive's end, and records the run in RestoreRecord.

A withdrawal its path now refuses (a revocation the rate bound holds for a co-signer, an
attestation revocation with no admin to act as) is reported with its remedy, never forced. A
withdrawal made by the actor whose damage the restore undoes can be excluded, with a reason, by
the key the dry run prints.

Usage:
  polaris-reconcile-restore.py --restored DSN --archive-end DSN --target-time T --operator NAME
        [--acting-admin USERNAME] [--cosigner AGENCY_ID]
        [--exclude KEY ... --exclusion-reason TEXT] [--id-margin N] [--dry-run]
DSN is a libpq connection string for a role that owns the schema: the owner runs the paths the
withdrawals are re-applied through and writes RestoreRecord, which the application role cannot.

Exit: 0 nothing REGISTRY calls a withdrawal is looser than at the archive's end, apart from what
      was excluded (a dry run: the plan was printed); 1 something still is, printed with its
      remedy; 2 the inputs are wrong (not one history, a migration after T, the restored database
      already used, a table this script does not know).
"""
import argparse
import json
import re
import sys

import psycopg2
import psycopg2.errors
import psycopg2.extras

STATUS_LIST_SIZE = 524288      # CredentialCopy.list_no = copy_id / 524288 (chk_credential_copy_list_no)
TERMINAL = ("REVOKED", "LOST", "EXPIRED")
CODE_ATTEMPTS_MAX = 5          # EnrollmentCode: redemption needs attempts < 5 (attempts_are_bounded)
REPORT_CAP = 1000              # items kept per list in RestoreRecord.report; the rest are counted

# Every table in the schema, what a restore to T does to what was written in it after T, and the
# column that dates a row there. The script refuses a database holding a table this does not
# name: it could not say what the restore lost there (check_restore_reconciled reads this too).
#   reapplied  a withdrawal of trust or access, put back by the kind named
#   listed     a grant, or a policy, set after T: not re-made; listed with how to make it again
#   counted    a record of something that happened, which cannot happen again: counted
#   derived    rebuilt from other tables
#   reference  loaded with the schema, not written in operation
REGISTRY = {
    "agency":                     ("reapplied", None, "agency: an authorization level lowered"),
    "agencyalgorithmauth":        ("reapplied", "authorized_date", "agency-algorithm: an authorization removed or narrowed"),
    "agencyevent":                ("reapplied", "recorded_at", "agency: the re-applied change records its own event"),
    "agencyquota":                ("listed", "set_at", "a quota set after T: set it again"),
    "agencytrustattestation":     ("reapplied", "attested_date", "attestation: a revocation; attestations made after T are listed"),
    "anchorbatch":                ("counted", "created_at", "anchor batches closed after T"),
    "appuser":                    ("reapplied", "created_at", "account: deactivated, role lowered, hardware-key deadline nearer, password or recovery code changed, locked"),
    "appuserevent":               ("reapplied", "recorded_at", "account: the re-applied change records its own event"),
    "athena_constitutional_rule": ("reference", None, "the constitutional board"),
    "athena_key_custody":         ("reference", None, "the constitutional board"),
    "athena_rule_enforcement":    ("reference", None, "the constitutional board"),
    "auditaccesslog":             ("counted", "accessed_at", "reads of the audit tables after T"),
    "authauditlog":               ("counted", "event_timestamp", "sign-in records after T"),
    "authcodeconsumed":           ("reapplied", "consumed_at", "replay-register: an authorization code consumed"),
    "authoritykeyevent":          ("reapplied", "recorded_at", "authority-key: a key retired or compromised; keys registered after T are listed"),
    "backupevent":                ("counted", "completed_at", "backups recorded after T (the backups themselves are untouched)"),
    "blockchainanchor":           ("counted", "anchored_date", "credential anchors after T"),
    "bulkenrollmentbatch":        ("listed", "created_at", "bulk issuance after T: issue the batch again"),
    "bulkenrollmentstaging":      ("listed", None, "rows staged for bulk issuance after T"),
    "cardpersonalization":        ("counted", "personalized_at", "cards personalized after T"),
    "chainanchor":                ("counted", "recorded_at", "chain anchors recorded after T: their proofs exist outside the database; record them again (polaris anchor-record)"),
    "credentialcopy":             ("counted", "issued_at", "wallet copies issued after T: their status-list slots read invalid, and new copies start a new list"),
    "cryptographicalgorithm":     ("reapplied", None, "algorithm: a deprecation date set or brought nearer"),
    "devicebinding":              ("listed", "authorized_date", "devices bound after T: bind them again"),
    "duressevent":                ("counted", "event_timestamp", "duress records after T"),
    "enrollmentcode":             ("reapplied", "issued_at", "replay-register: a code redeemed after T is exhausted; codes issued after T are lost"),
    "enrollmentcount":            ("derived", None, "enrolment counts"),
    "enrollmentcountdelta":       ("derived", None, "enrolment counts"),
    "enrollmentcurrent":          ("derived", None, "enrolment counts"),
    "enrollmentevidence":         ("counted", None, "enrolment evidence recorded after T"),
    "enrollmentproofing":         ("counted", "recorded_at", "proofing sessions after T"),
    "enrollmentstatusevent":      ("counted", "event_timestamp", "enrolment transitions after T"),
    "exchangenonce":              ("reapplied", "consumed_at", "replay-register: an exchange nonce consumed"),
    "exchangereceiptlog":         ("counted", "minted_at", "exchange receipts after T"),
    "holderkeyevent":             ("reapplied", "recorded_at", "holder-key: a key revoked or rotated away; keys bound after T are listed"),
    "identitytoken":              ("reapplied", "issued_date", "credential: revoked, lost or expired; credentials issued after T are listed"),
    "individual":                 ("reapplied", "enrollment_date", "erasure: a pseudonymization"),
    "individualerasureevent":     ("reapplied", "event_timestamp", "erasure: the re-applied erasure records its own event"),
    "issuerdiscretionpolicy":     ("listed", "set_at", "a revocation bound set after T: set it again"),
    "lifecyclearchivecheckpoint": ("counted", "purged_at", "archive purges after T"),
    "lifecyclerollup":            ("derived", None, "activity rollups"),
    "lifecyclerollupdaily":       ("derived", None, "activity rollups"),
    "lifecyclerollupdelta":       ("derived", None, "activity rollups"),
    "operatorsession":            ("reapplied", "created_at", "session: an operator session revoked"),
    "operatorwebauthncredential": ("reapplied", "enrolled_at", "hardware-key: an operator's hardware key removed; keys enrolled after T are listed"),
    "populationcount":            ("derived", None, "population counts"),
    "populationcountdelta":       ("derived", None, "population counts"),
    "recoveryrequest":            ("counted", "requested_at", "recovery ceremonies begun after T: begin them again (a completed one's withdrawal is re-applied with its credential)"),
    "refereevouching":            ("counted", "vouched_at", "vouchings after T"),
    "relyingparty":               ("reapplied", "created_at", "relying-party: disabled, scope narrowed, a requirement raised, rate lowered, secret rotated"),
    "relyingpartyevent":          ("reapplied", "recorded_at", "relying-party: the re-applied change records its own event"),
    "restorerecord":              ("counted", "recorded_at", "reconciliations recorded after T"),
    "retentionpolicy":            ("listed", "effective_from", "a retention policy set after T: set it again (uc_set_retention_policy)"),
    "revocationlist":             ("reapplied", "revocation_timestamp", "credential: the re-applied revocation publishes its own entry"),
    "schema_version":             ("reference", "occurred_at", "migrations: one applied after T refuses the run"),
    "timestamplog":               ("counted", "anchored_at", "timestamp anchors after T"),
    "tokenlifecycleevent":        ("reapplied", "event_timestamp", "credential: the re-applied transition records its own event"),
    "tokenpermission":            ("reapplied", "granted_date", "permission: a permission removed or lowered"),
    "tokensignature":             ("listed", "signed_at", "signatures migrated after T: run the migration again (uc6_migrate_algorithm)"),
    "tokenstateepoch":            ("counted", "closed_at", "epochs closed after T: their ids are retired, so none is reused"),
    "tokenstateepochleaf":        ("counted", None, "the leaves of those epochs"),
    "verificationcontext":        ("reapplied", None, "context: a requirement raised"),
    "verificationevent":          ("counted", "event_timestamp", "verifications after T"),
    "verificationrollup":         ("derived", None, "activity rollups"),
    "verificationrollupdaily":    ("derived", None, "activity rollups"),
    "verificationrollupdelta":    ("derived", None, "activity rollups"),
    "zkverificationnonce":        ("reapplied", "consumed_at", "replay-register: a zero-knowledge nonce consumed"),
}

# Written only by traffic and jobs, never by this script: a row in one of these dated after T on
# the restored database means something used it before the reconciliation ran.
SENTINELS = ("verificationevent", "credentialcopy", "identitytoken", "operatorsession", "tokenstateepoch",
             "duressevent", "enrollmentstatusevent", "anchorbatch", "cardpersonalization",
             "bulkenrollmentbatch", "enrollmentproofing", "exchangereceiptlog", "authauditlog")

PERMISSION_RANK = {"READ": 1, "VERIFY": 2, "FULL": 3}
KEY_RANK = {"registered": 0, "retired": 1, "compromised": 2}


class Refused(Exception):
    """A withdrawal this script will not force: reported with its remedy."""


class Item:
    """One withdrawal to re-apply. retry, when given, is (pattern, step): the step runs only after
    the first attempt was refused with an error matching the pattern."""

    def __init__(self, key, kind, at, what, apply=None, remedy="", retry=None):
        self.key, self.kind, self.at, self.what = key, kind, at, what
        self.apply, self.remedy, self.retry = apply, remedy, retry
        self.state, self.error = "pending", ""


def rows(conn, sql, params=None):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params or {})
        return cur.fetchall()


def one(conn, sql, params=None):
    r = rows(conn, sql, params)
    return r[0] if r else None


def short(hex_value):
    return (hex_value or "")[:16]


def ts(value):
    return value.isoformat(sep=" ", timespec="seconds") if hasattr(value, "isoformat") else str(value)


# ---------------------------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------------------------

def preflight(ce, cr, t):
    """The two databases are one history, the restored one stops at T and was not used since,
    and the archive's end runs past T. Returns the archive's end; exits 2 otherwise."""
    problems = []
    try:
        se = one(ce, "SELECT system_identifier::text AS s FROM pg_control_system()")["s"]
        sr = one(cr, "SELECT system_identifier::text AS s FROM pg_control_system()")["s"]
        if se != sr:
            problems.append("the two databases are not one history (system identifiers %s and %s)" % (se, sr))
    except psycopg2.Error:
        ce.rollback(), cr.rollback()       # a role without pg_control_system(): the checks below still hold
    tables = {r["relname"] for r in rows(cr, """
        SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition""")}
    unknown = sorted(tables - set(REGISTRY))
    if unknown:
        problems.append("tables this script does not know, so it cannot say what the restore lost in them: "
                        + ", ".join(unknown))
    late = rows(ce, "SELECT name FROM schema_version WHERE occurred_at > %(t)s ORDER BY event_id", {"t": t})
    if late:
        problems.append("migrations were applied after the target (%s): apply them to the restored database "
                        "first (scripts/polaris-migrate.sh), then run this again"
                        % ", ".join(r["name"] for r in late))
    used = []
    for table in SENTINELS:
        col = REGISTRY[table][1]
        if table in tables and one(cr, "SELECT 1 AS x FROM %s WHERE %s > %%(t)s LIMIT 1" % (table, col), {"t": t}):
            used.append(table)
    if used:
        problems.append("the restored database has rows dated after the target in %s: something used it before "
                        "this reconciliation. Restore again and run this before the app takes traffic."
                        % ", ".join(used))
    end = None
    for table, (_, col, _) in REGISTRY.items():
        if col and table in tables and table not in ("schema_version", "restorerecord"):
            r = one(ce, "SELECT max(%s)::timestamptz AS m FROM %s" % (col, table))
            if r and r["m"] is not None and (end is None or r["m"] > end):
                end = r["m"]
    if end is None or end <= one(ce, "SELECT %(t)s::timestamptz AS t", {"t": t})["t"]:
        problems.append("the archive's-end copy holds nothing dated after the target: it is not the restore of the "
                        "archive's end, or the target is not before it")
    if problems:
        for p in problems:
            print("refused: " + p, file=sys.stderr)
        sys.exit(2)
    return end


def retire_identifiers(ce, cr, margin, dry_run):
    """Each sequence moves past its value at the archive's end, so no identifier handed out after T
    is handed out again; the wallet-copy sequence to the start of the next status list."""
    at_end = {r["s"]: r for r in rows(ce, """
        SELECT schemaname || '.' || sequencename AS s, coalesce(last_value, start_value) AS v
          FROM pg_sequences WHERE schemaname = 'public'""")}
    copy_seq = one(cr, "SELECT pg_get_serial_sequence('credentialcopy', 'copy_id') AS s")["s"]
    moved, copy_list = 0, None
    for r in rows(cr, """
        SELECT schemaname || '.' || sequencename AS s, coalesce(last_value, start_value) AS v, max_value AS m
          FROM pg_sequences WHERE schemaname = 'public'"""):
        e = at_end.get(r["s"])
        if e is None:
            continue
        target = e["v"] + margin
        if copy_seq and r["s"] == copy_seq:
            target = (target // STATUS_LIST_SIZE + 1) * STATUS_LIST_SIZE
            copy_list = target // STATUS_LIST_SIZE
        target = min(target, r["m"])
        if target > r["v"]:
            moved += 1
            if not dry_run:
                with cr.cursor() as cur:
                    cur.execute("SELECT setval(%s::regclass, %s, true)", (r["s"], target))
    if not dry_run:
        cr.commit()
    return {"sequences_moved": moved, "margin": margin, "copies_continue_in_list": copy_list}


# ---------------------------------------------------------------------------------------------
# The kinds. Each planner reads the archive's end (ce) and the restored database (cr) and returns
# the withdrawals still missing on the restored one, so running it again after re-applying
# returns only what is still looser. listed collects the grants not re-made.
# ---------------------------------------------------------------------------------------------

def guc(cur, name, value):
    cur.execute("SELECT set_config(%s, %s, true)", (name, str(value)))


def provenance(cur, ctx, what):
    guc(cur, "polaris.actor", ("restore reconciliation (%s)" % ctx["operator"])[:100])
    guc(cur, "polaris.justification", ("re-applied after a restore to %s: %s" % (ctx["t"], what))[:500])


def plan_credentials(ce, cr, ctx, listed):
    t = ctx["t"]
    terminal_at_end = rows(ce, """
        SELECT t.token_id, t.status, t.individual_id, ev.event_type, ev.actor_agency_id, ev.reason_code,
               ev.event_timestamp
          FROM IdentityToken t
          JOIN LATERAL (SELECT event_type, actor_agency_id, reason_code, event_timestamp
                          FROM TokenLifecycleEvent e
                         WHERE e.token_id = t.token_id AND e.event_type IN ('REVOKED', 'LOST', 'EXPIRED')
                         ORDER BY e.event_timestamp DESC, e.event_id DESC LIMIT 1) ev ON TRUE
         WHERE t.status IN ('REVOKED', 'LOST', 'EXPIRED') AND ev.event_timestamp > %(t)s""", {"t": t})
    issued_after = rows(ce, "SELECT token_id, issued_date FROM IdentityToken WHERE issued_date > %(t)s", {"t": t})
    ids = [r["token_id"] for r in terminal_at_end] + [r["token_id"] for r in issued_after]
    here = {r["token_id"]: r["status"] for r in rows(cr, "SELECT token_id, status FROM IdentityToken "
                                                         "WHERE token_id = ANY(%(ids)s)", {"ids": ids})}
    for r in issued_after:
        if r["token_id"] not in here:
            listed.setdefault("credential:%d" % r["token_id"],
                              "credential %d issued after T (%s): not at the restored database; issue it again"
                              % (r["token_id"], ts(r["issued_date"])))
    revs = {}
    for r in rows(ce, """SELECT token_id, revoked_by_agency_id, reason_code, published_location, revocation_timestamp
                           FROM RevocationList WHERE revocation_timestamp > %(t)s ORDER BY revocation_timestamp""",
                  {"t": t}):
        revs[r["token_id"]] = r
    activations = rows(ce, """SELECT e.token_id, e.event_timestamp, t.individual_id
                                FROM TokenLifecycleEvent e JOIN IdentityToken t USING (token_id)
                               WHERE e.event_type = 'ACTIVATED' AND e.event_timestamp > %(t)s""", {"t": t})
    successors = {r["predecessor_token_id"]: r["token_id"] for r in rows(ce, """
        SELECT predecessor_token_id, token_id FROM IdentityToken
         WHERE predecessor_token_id IS NOT NULL AND issued_date > %(t)s""", {"t": t})}
    items = []
    for x in terminal_at_end:
        tid = x["token_id"]
        if tid not in here or here[tid] in TERMINAL:
            continue
        rl, at = revs.get(tid), x["event_timestamp"]
        if rl is None and x["status"] == "REVOKED":
            # REVOKED reaches the table only through uc8_revoke_token and its callers, which publish
            # an entry (trg_enforce_revocation_velocity refuses any other path), so this is a row
            # the archive's end holds without one: re-apply it through uc8 all the same.
            rl = {"revoked_by_agency_id": x["actor_agency_id"] or one(
                      ce, "SELECT issuing_agency_id AS a FROM IdentityToken WHERE token_id = %(t)s", {"t": tid})["a"],
                  "reason_code": "ADMINISTRATIVE", "published_location": None, "revocation_timestamp": at}
        if rl is not None:
            pair = next((a["token_id"] for a in activations
                         if a["event_timestamp"] == rl["revocation_timestamp"]
                         and a["individual_id"] == x["individual_id"] and a["token_id"] != tid), None)
            if pair is not None and here[tid] == "ACTIVE":
                reserve_state = one(cr, "SELECT status FROM IdentityToken WHERE token_id = %(p)s", {"p": pair})
                if reserve_state and reserve_state["status"] == "RESERVE":
                    def apply(cur, tid=tid, rl=rl, pair=pair):
                        cur.execute("SELECT uc4_activate_reserve(%s, %s, %s, %s, %s)",
                                    (tid, rl["revoked_by_agency_id"], rl["reason_code"], pair,
                                     rl["published_location"]))
                    items.append(Item("credential:%d" % tid, "credential", at,
                                      "credential %d: %s at %s, and its holder's reserve %d activated in its place "
                                      "(uc4_activate_reserve)" % (tid, rl["reason_code"], ts(at), pair), apply,
                                      "re-apply it by hand with uc4_activate_reserve, then run this again"))
                    continue
            m = re.search(r"\[COSIGN:(\d+)\]\s*$", x["reason_code"] or "")
            cosigner = int(m.group(1)) if m else None
            succ = successors.get(tid)
            if succ is not None:
                listed.setdefault("credential:%d" % succ,
                                  "credential %d replaced credential %d after T (a recovery): not at the restored "
                                  "database; complete the recovery again" % (succ, tid))

            def apply(cur, tid=tid, rl=rl, cosigner=cosigner):
                cur.execute("CALL uc8_revoke_token(%s, %s, %s, %s, %s)",
                            (tid, rl["revoked_by_agency_id"], rl["reason_code"], rl["published_location"], cosigner))

            def retry(cur, tid=tid, rl=rl):
                if ctx["cosigner"] is None:
                    raise Refused("the revocation bound now needs a co-signer")
                cur.execute("CALL uc8_revoke_token(%s, %s, %s, %s, %s)",
                            (tid, rl["revoked_by_agency_id"], rl["reason_code"], rl["published_location"],
                             ctx["cosigner"]))
            items.append(Item("credential:%d" % tid, "credential", at,
                              "credential %d: revoked (%s) at %s by agency %d%s (uc8_revoke_token)"
                              % (tid, rl["reason_code"], ts(at), rl["revoked_by_agency_id"],
                                 ", co-signed by agency %d" % cosigner if cosigner else ""),
                              apply, "the revocation bound now needs a co-signer: run again with --cosigner "
                              "AGENCY_ID (an agency holding BOTH on its algorithm), or revoke it by hand",
                              ("co-signer required", retry)))
        else:
            def apply(cur, tid=tid, x=x):
                if x["actor_agency_id"] is not None:
                    guc(cur, "polaris.actor_agency_id", x["actor_agency_id"])
                guc(cur, "polaris.reason_code", x["reason_code"] or "RESTORE_RECONCILIATION")
                cur.execute("UPDATE IdentityToken SET status = %s WHERE token_id = %s", (x["status"], tid))
            items.append(Item("credential:%d" % tid, "credential", at,
                              "credential %d: %s at %s (polaris transition)" % (tid, x["status"], ts(at)), apply,
                              "re-apply it by hand (polaris transition %d %s), then run this again"
                              % (tid, x["status"])))
    return items


LIVE_HOLDER_KEYS = """SELECT DISTINCT ON (token_id) token_id, public_key_hex, algorithm, event, recorded_at
                        FROM HolderKeyEvent ORDER BY token_id, event_id DESC"""


def plan_holder_keys(ce, cr, ctx, listed):
    at_end = {r["token_id"]: r for r in rows(ce, LIVE_HOLDER_KEYS)}
    changed = {r["token_id"] for r in rows(ce, "SELECT DISTINCT token_id FROM HolderKeyEvent WHERE recorded_at > %(t)s",
                                           {"t": ctx["t"]})}
    live_tokens = {r["token_id"] for r in rows(cr, "SELECT token_id FROM IdentityToken "
                                                   "WHERE status NOT IN ('REVOKED', 'LOST', 'EXPIRED')")}
    items = []
    for r in rows(cr, LIVE_HOLDER_KEYS):
        tid = r["token_id"]
        if r["event"] == "revoked" or tid not in changed or tid not in live_tokens:
            continue
        e = at_end.get(tid)
        if e is not None and e["event"] != "revoked" and e["public_key_hex"] == r["public_key_hex"]:
            continue
        if e is not None and e["event"] != "revoked":
            listed.setdefault("holder-key:%d:%s" % (tid, short(e["public_key_hex"])),
                              "holder key %s bound to credential %d after T: the holder binds it again"
                              % (short(e["public_key_hex"]), tid))

        def apply(cur, tid=tid, r=r):
            cur.execute("SELECT uc_record_holder_key_event(%s, %s, %s, 'revoked', %s)",
                        (tid, r["public_key_hex"], r["algorithm"], r["public_key_hex"]))
        items.append(Item("holder-key:%d" % tid, "holder-key", e["recorded_at"] if e else ctx["t"],
                          "holder key %s of credential %d: %s after T; revoked (uc_record_holder_key_event)"
                          % (short(r["public_key_hex"]), tid, "rotated away" if e and e["event"] != "revoked"
                             else "revoked"), apply, "revoke it by hand, then run this again"))
    return items


def plan_authority_keys(ce, cr, ctx, listed):
    latest_sql = """SELECT DISTINCT ON (agency_id, public_key_hex) agency_id, public_key_hex, event
                      FROM AuthorityKeyEvent ORDER BY agency_id, public_key_hex, event_id DESC"""
    here = {(r["agency_id"], r["public_key_hex"]): r["event"] for r in rows(cr, latest_sql)}
    items = []
    for e in rows(ce, """SELECT event_id, agency_id, public_key_hex, algorithm, event, effective_at, note, recorded_at
                           FROM AuthorityKeyEvent WHERE recorded_at > %(t)s ORDER BY event_id""", {"t": ctx["t"]}):
        k = (e["agency_id"], e["public_key_hex"])
        if k not in here:
            if e["event"] == "registered":
                listed.setdefault("authority-key:%d:%s" % (e["agency_id"], short(e["public_key_hex"])),
                                  "authority key %s of agency %d registered after T: if the agency signs with it, "
                                  "register it again (scripts/polaris-key-event.sh)"
                                  % (short(e["public_key_hex"]), e["agency_id"]))
            continue
        if KEY_RANK[e["event"]] <= KEY_RANK[here[k]]:
            continue
        here[k] = e["event"]

        def apply(cur, e=e):
            cur.execute("INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, algorithm, event, effective_at, note) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (e["agency_id"], e["public_key_hex"], e["algorithm"], e["event"], e["effective_at"], e["note"]))
        items.append(Item("authority-key:%d:%s" % (e["agency_id"], short(e["public_key_hex"])),
                          "authority-key", e["recorded_at"],
                          "authority key %s of agency %d: %s, effective %s (the register entry "
                          "scripts/polaris-key-event.sh makes)" % (short(e["public_key_hex"]), e["agency_id"],
                                                                   e["event"], ts(e["effective_at"])),
                          apply, "record it by hand with scripts/polaris-key-event.sh, then run this again"))
    return items


def plan_attestations(ce, cr, ctx, listed):
    t = ctx["t"]
    for r in rows(ce, "SELECT attestation_id, attested_date FROM AgencyTrustAttestation WHERE attested_date > %(t)s",
                  {"t": t}):
        if not one(cr, "SELECT 1 AS x FROM AgencyTrustAttestation WHERE attestation_id = %(a)s",
                   {"a": r["attestation_id"]}):
            listed.setdefault("attestation:%d" % r["attestation_id"],
                              "trust attestation %d made after T: attest it again" % r["attestation_id"])
    items = []
    for e in rows(ce, """SELECT attestation_id, revocation_date, revocation_reason FROM AgencyTrustAttestation
                          WHERE revocation_date > %(t)s""", {"t": t}):
        r = one(cr, "SELECT revocation_date FROM AgencyTrustAttestation WHERE attestation_id = %(a)s",
                {"a": e["attestation_id"]})
        if r is None or r["revocation_date"] is not None:
            continue

        def apply(cur, e=e):
            if ctx["acting_admin_id"] is None:
                raise Refused("an attestation revocation needs an active admin to act as")
            cur.execute("CALL uc10_revoke_attestation(%s, %s, %s)",
                        (e["attestation_id"], e["revocation_reason"], ctx["acting_admin_id"]))
        items.append(Item("attestation:%d" % e["attestation_id"], "attestation", e["revocation_date"],
                          "trust attestation %d: revoked at %s (%s) (uc10_revoke_attestation)"
                          % (e["attestation_id"], ts(e["revocation_date"]), e["revocation_reason"]), apply,
                          "run again with --acting-admin USERNAME (an active admin), or revoke it by hand"))
    return items


def plan_erasures(ce, cr, ctx, listed):
    items = []
    for e in rows(ce, """SELECT individual_id, erased_by_user_id, reason, event_timestamp FROM IndividualErasureEvent
                          WHERE event_timestamp > %(t)s ORDER BY event_timestamp""", {"t": ctx["t"]}):
        if not one(cr, "SELECT 1 AS x FROM Individual WHERE individual_id = %(i)s", {"i": e["individual_id"]}):
            continue
        if one(cr, "SELECT 1 AS x FROM IndividualErasureEvent WHERE individual_id = %(i)s", {"i": e["individual_id"]}):
            continue

        def apply(cur, e=e):
            cur.execute("SELECT 1 FROM AppUser WHERE user_id = %s AND role = 'admin' AND is_active",
                        (e["erased_by_user_id"],))
            actor = e["erased_by_user_id"] if cur.fetchone() else ctx["acting_admin_id"]
            if actor is None:
                raise Refused("the admin who erased it is not an active admin here, and no --acting-admin was given")
            cur.execute("CALL uc_pseudonymize_individual(%s, %s, %s)", (e["individual_id"], actor, e["reason"]))
        items.append(Item("erasure:%d" % e["individual_id"], "erasure", e["event_timestamp"],
                          "individual %d: erased at %s (uc_pseudonymize_individual)"
                          % (e["individual_id"], ts(e["event_timestamp"])), apply,
                          "run again with --acting-admin USERNAME, or erase it by hand"))
    return items


def plan_accounts(ce, cr, ctx, listed):
    t = ctx["t"]
    cols = "user_id, username, role, is_active, webauthn_required_after, password_hash, recovery_code_hash, locked_until"
    at_end = {r["user_id"]: r for r in rows(ce, "SELECT %s FROM AppUser" % cols)}
    when = {r["user_id"]: r["m"] for r in rows(ce, "SELECT user_id, max(recorded_at) AS m FROM AppUserEvent "
                                                   "WHERE recorded_at > %(t)s GROUP BY user_id", {"t": t})}
    rank = {r["role"]: r["rank"] for r in rows(cr, "SELECT role, _app_user_role_rank(role) AS rank "
                                                   "FROM (VALUES ('auditor'), ('operator'), ('admin')) v(role)")}
    for uid, e in at_end.items():
        if not one(cr, "SELECT 1 AS x FROM AppUser WHERE user_id = %(u)s", {"u": uid}):
            listed.setdefault("account:%s" % e["username"],
                              "operator account %s created after T: create it again" % e["username"])
    now = one(cr, "SELECT now() AS n")["n"]
    items = []
    for r in rows(cr, "SELECT %s FROM AppUser" % cols):
        e, sets, said = at_end.get(r["user_id"]), {}, []
        if e is None:
            if r["is_active"]:
                sets["is_active"], said = False, ["deleted after T, so switched off"]
        else:
            if rank.get(r["role"], 0) > rank.get(e["role"], 0):
                sets["role"] = e["role"]
                said.append("role lowered to %s" % e["role"])
            if r["is_active"] and not e["is_active"]:
                sets["is_active"] = False
                said.append("switched off")
            ew, rw = e["webauthn_required_after"], r["webauthn_required_after"]
            if ew is not None and (rw is None or rw > ew):
                sets["webauthn_required_after"] = ew
                said.append("hardware-key deadline %s" % ts(ew))
            if r["password_hash"] != e["password_hash"]:
                sets["password_hash"] = e["password_hash"]
                said.append("password changed")
            if r["recovery_code_hash"] != e["recovery_code_hash"]:
                sets["recovery_code_hash"] = e["recovery_code_hash"]
                said.append("recovery code changed")
            el, rl = e["locked_until"], r["locked_until"]
            if el is not None and el > now and (rl is None or rl < el):
                sets["locked_until"] = el
                said.append("locked until %s" % ts(el))
        if not sets:
            continue
        what = "operator account %s: %s" % (r["username"], ", ".join(said))

        def apply(cur, uid=r["user_id"], sets=sets, what=what):
            provenance(cur, ctx, what)
            cur.execute("UPDATE AppUser SET %s WHERE user_id = %%s" % ", ".join("%s = %%s" % c for c in sets),
                        tuple(sets.values()) + (uid,))
        items.append(Item("account:%s" % r["username"], "account", when.get(r["user_id"], t), what, apply,
                          "make the change by hand (polaris user-update), then run this again"))
    return items


RP_FIELDS = ("require_zk", "required_enrollment", "required_context_id", "scope", "enabled", "rate_limit_per_min")


def plan_relying_parties(ce, cr, ctx, listed):
    t = ctx["t"]
    at_end = {r["rp_id"]: r for r in rows(ce, "SELECT rp_id, client_id, client_secret_hash, to_jsonb(r) AS j "
                                              "FROM RelyingParty r")}
    when = {r["rp_id"]: r["m"] for r in rows(ce, "SELECT rp_id, max(recorded_at) AS m FROM RelyingPartyEvent "
                                                 "WHERE recorded_at > %(t)s GROUP BY rp_id", {"t": t})}
    here = {r["rp_id"]: r for r in rows(cr, "SELECT rp_id, client_id, client_secret_hash FROM RelyingParty")}
    for rp, e in at_end.items():
        if rp not in here:
            listed.setdefault("relying-party:%s" % e["client_id"],
                              "relying party %s registered after T: register it again" % e["client_id"])
    items = []
    for rp, r in here.items():
        e = at_end.get(rp)
        if e is None:
            continue
        verdicts = one(cr, "SELECT %s FROM RelyingParty r WHERE rp_id = %%(rp)s" % ", ".join(
            "_rp_weakens('%s', jsonb_populate_record(NULL::RelyingParty, %%(j)s::jsonb), r) AS %s" % (f, f)
            for f in RP_FIELDS), {"rp": rp, "j": json.dumps(e["j"])})
        sets, said = {}, []
        for f in RP_FIELDS:
            if verdicts[f] is True:
                sets[f] = e["j"][f]
                said.append("%s back to %s" % (f, e["j"][f]))
            elif verdicts[f] is None:
                listed.setdefault("relying-party:%s:%s" % (r["client_id"], f),
                                  "relying party %s: %s changed after T in a way the schema does not order; "
                                  "set it again if the change was intended" % (r["client_id"], f))
        if r["client_secret_hash"] != e["client_secret_hash"]:
            sets["client_secret_hash"] = e["client_secret_hash"]
            said.append("secret rotated")
        if not sets:
            continue
        what = "relying party %s: %s" % (r["client_id"], ", ".join(said))

        def apply(cur, rp=rp, sets=sets, what=what):
            provenance(cur, ctx, what)
            cur.execute("UPDATE RelyingParty SET %s WHERE rp_id = %%s" % ", ".join("%s = %%s" % c for c in sets),
                        tuple(sets.values()) + (rp,))
        items.append(Item("relying-party:%s" % r["client_id"], "relying-party", when.get(rp, t), what, apply,
                          "make the change by hand (polaris rp-update), then run this again"))
    return items


def plan_agencies(ce, cr, ctx, listed):
    t = ctx["t"]
    at_end = {r["agency_id"]: r for r in rows(ce, "SELECT agency_id, name, authorization_level, signing_public_key_hex "
                                                  "FROM Agency")}
    when = {r["agency_id"]: r["m"] for r in rows(ce, "SELECT agency_id, max(recorded_at) AS m FROM AgencyEvent "
                                                     "WHERE recorded_at > %(t)s GROUP BY agency_id", {"t": t})}
    items = []
    for r in rows(cr, "SELECT agency_id, name, authorization_level, signing_public_key_hex FROM Agency"):
        e = at_end.get(r["agency_id"])
        if e is None:
            continue
        if e["signing_public_key_hex"] != r["signing_public_key_hex"]:
            listed.setdefault("agency-signing-key:%d" % r["agency_id"],
                              "agency %d's signing key changed after T (a rotation): register the new key again "
                              "and point the agency at it (scripts/polaris-key-event.sh)" % r["agency_id"])
        if r["authorization_level"] <= e["authorization_level"]:
            continue
        what = "agency %d (%s): authorization level lowered to %d" % (r["agency_id"], r["name"], e["authorization_level"])

        def apply(cur, aid=r["agency_id"], level=e["authorization_level"], what=what):
            provenance(cur, ctx, what)
            cur.execute("UPDATE Agency SET authorization_level = %s WHERE agency_id = %s", (level, aid))
        items.append(Item("agency:%d" % r["agency_id"], "agency", when.get(r["agency_id"], t), what, apply,
                          "lower it by hand, then run this again"))
    return items


def plan_algorithms(ce, cr, ctx, listed):
    at_end = {r["algorithm_id"]: r for r in rows(ce, "SELECT algorithm_id, name, deprecation_date FROM CryptographicAlgorithm")}
    items = []
    for r in rows(cr, "SELECT algorithm_id, name, deprecation_date FROM CryptographicAlgorithm"):
        e = at_end.get(r["algorithm_id"])
        if e is None or e["deprecation_date"] is None:
            continue
        if r["deprecation_date"] is not None and r["deprecation_date"] <= e["deprecation_date"]:
            continue
        what = "algorithm %s: deprecated from %s" % (r["name"], e["deprecation_date"])

        def apply(cur, aid=r["algorithm_id"], d=e["deprecation_date"], what=what):
            provenance(cur, ctx, what)
            cur.execute("UPDATE CryptographicAlgorithm SET deprecation_date = %s WHERE algorithm_id = %s", (d, aid))
        items.append(Item("algorithm:%s" % r["name"], "algorithm", ctx["t"], what, apply,
                          "set the deprecation date by hand, then run this again"))
    for aid, e in at_end.items():
        if not one(cr, "SELECT 1 AS x FROM CryptographicAlgorithm WHERE algorithm_id = %(a)s", {"a": aid}):
            listed.setdefault("algorithm:%s" % e["name"], "algorithm %s added after T: add it again" % e["name"])
    return items


def plan_contexts(ce, cr, ctx, listed):
    at_end = {r["context_id"]: r for r in rows(ce, "SELECT context_id, context_type, requires_biometric, "
                                                   "min_security_level FROM VerificationContext")}
    items = []
    for r in rows(cr, "SELECT context_id, context_type, requires_biometric, min_security_level FROM VerificationContext"):
        e = at_end.get(r["context_id"])
        if e is None:
            continue
        sets, said = {}, []
        if e["requires_biometric"] and not r["requires_biometric"]:
            sets["requires_biometric"], said = True, ["requires a biometric"]
        if (e["min_security_level"] or 0) > (r["min_security_level"] or 0):
            sets["min_security_level"] = e["min_security_level"]
            said.append("minimum security level %s" % e["min_security_level"])
        if not sets:
            continue
        what = "verification context %d (%s): %s" % (r["context_id"], r["context_type"], ", ".join(said))

        def apply(cur, cid=r["context_id"], sets=sets, what=what):
            provenance(cur, ctx, what)
            cur.execute("UPDATE VerificationContext SET %s WHERE context_id = %%s" % ", ".join(
                "%s = %%s" % c for c in sets), tuple(sets.values()) + (cid,))
        items.append(Item("context:%d" % r["context_id"], "context", ctx["t"], what, apply,
                          "raise it by hand, then run this again"))
    return items


def plan_agency_algorithms(ce, cr, ctx, listed):
    at_end = {(r["agency_id"], r["algorithm_id"]): r["authorization_type"]
              for r in rows(ce, "SELECT agency_id, algorithm_id, authorization_type FROM AgencyAlgorithmAuth")}
    here = {(r["agency_id"], r["algorithm_id"]): r["authorization_type"]
            for r in rows(cr, "SELECT agency_id, algorithm_id, authorization_type FROM AgencyAlgorithmAuth")}
    items = []
    for k, typ in sorted(here.items()):
        e = at_end.get(k)
        if e == typ:
            continue
        if e is not None and not (typ == "BOTH" and e in ("ISSUE", "VERIFY")):
            listed.setdefault("agency-algorithm:%d:%d" % k, "agency %d's authorization on algorithm %d changed from "
                              "%s to %s after T, which no order ranks; set it again if intended" % (k + (typ, e)))
            continue
        what = ("agency %d: authorization on algorithm %d %s" %
                (k[0], k[1], "removed" if e is None else "narrowed to %s" % e))

        def apply(cur, k=k, e=e, what=what):
            provenance(cur, ctx, what)
            if e is None:
                cur.execute("DELETE FROM AgencyAlgorithmAuth WHERE agency_id = %s AND algorithm_id = %s", k)
            else:
                cur.execute("UPDATE AgencyAlgorithmAuth SET authorization_type = %s "
                            "WHERE agency_id = %s AND algorithm_id = %s", (e,) + k)
        items.append(Item("agency-algorithm:%d:%d" % k, "agency-algorithm", ctx["t"], what, apply,
                          "change it by hand, then run this again"))
    for k in at_end:
        if k not in here:
            listed.setdefault("agency-algorithm:%d:%d" % k,
                              "agency %d authorized on algorithm %d after T: authorize it again" % k)
    return items


def plan_permissions(ce, cr, ctx, listed):
    at_end = {(r["token_id"], r["context_id"]): r["permission_level"]
              for r in rows(ce, "SELECT token_id, context_id, permission_level FROM TokenPermission")}
    items = []
    for r in rows(cr, "SELECT token_id, context_id, permission_level FROM TokenPermission"):
        k = (r["token_id"], r["context_id"])
        e = at_end.get(k)
        if e is not None and PERMISSION_RANK[e] >= PERMISSION_RANK[r["permission_level"]]:
            continue
        what = "credential %d in context %d: permission %s" % (k + ("removed" if e is None else "lowered to " + e,))

        def apply(cur, k=k, e=e, what=what):
            provenance(cur, ctx, what)
            if e is None:
                cur.execute("DELETE FROM TokenPermission WHERE token_id = %s AND context_id = %s", k)
            else:
                cur.execute("UPDATE TokenPermission SET permission_level = %s WHERE token_id = %s AND context_id = %s",
                            (e,) + k)
        items.append(Item("permission:%d:%d" % k, "permission", ctx["t"], what, apply,
                          "change it by hand, then run this again"))
    return items


def plan_sessions(ce, cr, ctx, listed):
    at_end = {r["session_id"]: r for r in rows(ce, "SELECT session_id, revoked_at, revoke_reason FROM OperatorSession")}
    items = []
    for r in rows(cr, """SELECT s.session_id, u.username FROM OperatorSession s JOIN AppUser u USING (user_id)
                          WHERE s.revoked_at IS NULL"""):
        e = at_end.get(r["session_id"])
        if e is not None and e["revoked_at"] is None:
            continue
        when, why = (e["revoked_at"], e["revoke_reason"]) if e is not None else (None, "idle")
        what = "operator session %s... of %s: %s" % (r["session_id"][:12], r["username"],
                                                     "revoked (%s) at %s" % (why, ts(when)) if when else
                                                     "gone at the archive's end, so revoked as idle")

        def apply(cur, sid=r["session_id"], when=when, why=why):
            cur.execute("UPDATE OperatorSession SET revoked_at = coalesce(%s, now()), revoke_reason = %s "
                        "WHERE session_id = %s AND revoked_at IS NULL", (when, why, sid))
        items.append(Item("session:%s" % r["session_id"][:12], "session", when or ctx["t"], what, apply,
                          "revoke it by hand, then run this again"))
    return items


def plan_hardware_keys(ce, cr, ctx, listed):
    at_end = {r["credential_id"]: r for r in rows(ce, """SELECT w.credential_id, u.username FROM OperatorWebauthnCredential w
                                                         JOIN AppUser u USING (user_id)""")}
    here = {r["credential_id"]: r for r in rows(cr, """SELECT w.credential_id, w.user_id, u.username
                                                        FROM OperatorWebauthnCredential w JOIN AppUser u USING (user_id)""")}
    items = []
    for cid, r in here.items():
        if cid in at_end:
            continue
        what = "hardware key %s... of %s: removed after T" % (cid[:12], r["username"])

        def apply(cur, cid=cid, uid=r["user_id"]):
            cur.execute("DELETE FROM OperatorWebauthnCredential WHERE credential_id = %s AND user_id = %s", (cid, uid))
        items.append(Item("hardware-key:%s" % cid[:12], "hardware-key", ctx["t"], what, apply,
                          "remove it by hand, then run this again"))
    for cid, e in at_end.items():
        if cid not in here:
            listed.setdefault("hardware-key:%s" % cid[:12], "hardware key %s... of %s enrolled after T: enrol it again"
                              % (cid[:12], e["username"]))
    return items


REGISTERS = (
    # table, its key columns, its columns, a condition its row needs on the restored database
    ("ExchangeNonce", ("requester_key_hash", "nonce"), ("requester_key_hash", "nonce", "consumed_at"), None),
    ("AuthCodeConsumed", ("code_hash",), ("code_hash", "consumed_at"), None),
    ("ZkVerificationNonce", ("epoch_id", "context_id", "nonce"), ("epoch_id", "context_id", "nonce", "consumed_at"),
     "SELECT epoch_id FROM TokenStateEpoch"),
)


def plan_registers(ce, cr, ctx, listed):
    items = []
    for table, keys, cols, needs in REGISTERS:
        late = rows(ce, "SELECT %s FROM %s WHERE consumed_at > %%(t)s" % (", ".join(cols), table), {"t": ctx["t"]})
        if not late:
            continue
        have = {tuple(r[k] for k in keys) for r in rows(cr, "SELECT %s FROM %s WHERE consumed_at > %%(t)s"
                                                         % (", ".join(keys), table), {"t": ctx["t"]})}
        allowed = {r["epoch_id"] for r in rows(cr, needs)} if needs else None
        missing = [r for r in late if tuple(r[k] for k in keys) not in have
                   and (allowed is None or r["epoch_id"] in allowed)]
        if not missing:
            continue
        what = "%s: %d consumed after T, recorded as consumed again" % (table, len(missing))

        def apply(cur, table=table, cols=cols, missing=missing):
            psycopg2.extras.execute_values(
                cur, "INSERT INTO %s (%s) VALUES %%s ON CONFLICT DO NOTHING" % (table, ", ".join(cols)),
                [tuple(r[c] for c in cols) for r in missing])
        items.append(Item("replay-register:%s" % table.lower(), "replay-register",
                          min(r["consumed_at"] for r in missing), what, apply,
                          "insert them by hand, then run this again"))
    for e in rows(ce, "SELECT code_id, redeemed_at FROM EnrollmentCode WHERE redeemed_at > %(t)s", {"t": ctx["t"]}):
        r = one(cr, "SELECT redeemed_at, attempts FROM EnrollmentCode WHERE code_id = %(c)s", {"c": e["code_id"]})
        if r is None or r["redeemed_at"] is not None or r["attempts"] >= CODE_ATTEMPTS_MAX:
            continue

        def apply(cur, cid=e["code_id"]):
            cur.execute("UPDATE EnrollmentCode SET attempts = %s WHERE code_id = %s", (CODE_ATTEMPTS_MAX, cid))
        items.append(Item("enrolment-code:%d" % e["code_id"], "replay-register", e["redeemed_at"],
                          "enrolment code %d: redeemed at %s, so exhausted here (the individual needs a new code)"
                          % (e["code_id"], ts(e["redeemed_at"])), apply, "exhaust it by hand, then run this again"))
    return items


# Withdrawals the archive's end recorded as events, replayed in the order they were made; then the
# state the other kinds compare, so a replayed event never meets a state the archive's end reached
# only later (an attestation revocation by an admin switched off afterwards).
EVENT_PLANNERS = (plan_credentials, plan_holder_keys, plan_authority_keys, plan_attestations, plan_erasures,
                  plan_registers)
STATE_PLANNERS = (plan_accounts, plan_sessions, plan_hardware_keys, plan_relying_parties, plan_agencies,
                  plan_algorithms, plan_contexts, plan_agency_algorithms, plan_permissions)


def plan(ce, cr, ctx, listed):
    events = []
    for p in EVENT_PLANNERS:
        events.extend(p(ce, cr, ctx, listed))
    events.sort(key=lambda i: (str(i.at), i.key))
    state = []
    for p in STATE_PLANNERS:
        state.extend(p(ce, cr, ctx, listed))
    return events + state


def lost_records(ce, cr, t):
    counts = {}
    for table, (handling, col, _) in sorted(REGISTRY.items()):
        if handling not in ("counted", "listed") or not col or table == "restorerecord":
            continue
        n = one(ce, "SELECT count(*) AS n FROM %s WHERE %s > %%(t)s" % (table, col), {"t": t})["n"]
        if n:
            counts[table] = n
    return counts


def attempt(cr, step):
    """Run one step in its own transaction; None when it committed, else the refusal's first line."""
    try:
        with cr.cursor() as cur:
            step(cur)
        cr.commit()
        return None
    except (psycopg2.Error, Refused) as exc:
        cr.rollback()
        msg = getattr(exc, "pgerror", None) or str(exc)
        return msg.strip().splitlines()[0].replace("ERROR:  ", "")[:300]


def apply_items(cr, items, excluded):
    for it in items:
        if it.key in excluded:
            it.state = "excluded"
            continue
        err = attempt(cr, it.apply)
        if err is not None and it.retry is not None and re.search(it.retry[0], err):
            err = attempt(cr, it.retry[1]) or None
        it.state, it.error = ("reapplied", "") if err is None else ("refused", err)


def capped(entries):
    return entries[:REPORT_CAP] + ([{"more": len(entries) - REPORT_CAP}] if len(entries) > REPORT_CAP else [])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--restored", required=True, help="libpq DSN of the database restored to the target")
    ap.add_argument("--archive-end", required=True, help="libpq DSN of a scratch restore of the archive's end")
    ap.add_argument("--target-time", required=True, help="the point restored to, as given to pgbackrest --target")
    ap.add_argument("--operator", required=True, help="who runs this, for RestoreRecord")
    ap.add_argument("--acting-admin", help="an active admin to act as where a path needs one the archive did not name")
    ap.add_argument("--cosigner", type=int, help="an agency to co-sign revocations the rate bound now holds")
    ap.add_argument("--exclude", action="append", default=[], help="a key the dry run printed (repeatable)")
    ap.add_argument("--exclusion-reason", help="why the excluded withdrawals are not re-applied")
    ap.add_argument("--id-margin", type=int, default=100000,
                    help="how far past the archive's end each sequence moves (default 100000), for identifiers "
                         "issued in WAL the archive never received")
    ap.add_argument("--dry-run", action="store_true", help="print the plan; change nothing")
    args = ap.parse_args(argv)
    if args.exclude and not (args.exclusion_reason and args.exclusion_reason.strip()):
        ap.error("--exclude needs --exclusion-reason")

    try:
        ce = psycopg2.connect(args.archive_end, application_name="polaris-reconcile-restore (archive end)")
        cr = psycopg2.connect(args.restored, application_name="polaris-reconcile-restore (restored)")
    except psycopg2.Error as exc:
        print("refused: cannot connect: %s" % str(exc).strip(), file=sys.stderr)
        return 2
    for c in (ce, cr):
        with c.cursor() as cur:
            cur.execute("SET TIME ZONE 'UTC'")
        c.commit()
    ce.set_session(readonly=True)

    end = preflight(ce, cr, args.target_time)
    t = one(cr, "SELECT %(t)s::timestamptz AS t", {"t": args.target_time})["t"]
    ctx = {"t": args.target_time, "operator": args.operator, "cosigner": args.cosigner, "acting_admin_id": None}
    if args.acting_admin:
        a = one(cr, "SELECT user_id FROM AppUser WHERE username = %(u)s AND role = 'admin' AND is_active",
                {"u": args.acting_admin})
        if a is None:
            print("refused: --acting-admin %s is not an active admin on the restored database" % args.acting_admin,
                  file=sys.stderr)
            return 2
        ctx["acting_admin_id"] = a["user_id"]

    print("reconciling the database restored to %s against the archive's end (%s)" % (ts(t), ts(end)))
    identifiers = retire_identifiers(ce, cr, args.id_margin, args.dry_run)
    print("identifiers: %d sequence(s) %s past the archive's end (+%d)%s"
          % (identifiers["sequences_moved"], "would move" if args.dry_run else "moved", args.id_margin,
             "; wallet copies continue in status list %d" % identifiers["copies_continue_in_list"]
             if identifiers["copies_continue_in_list"] is not None else ""))

    listed = {}
    items = plan(ce, cr, ctx, listed)
    excluded = set(args.exclude)
    unknown = sorted(excluded - {i.key for i in items})
    for k in unknown:
        print("note: --exclude %s matches nothing in the plan" % k)
    if args.dry_run:
        print("would re-apply (%d):" % len(items))
        for i in items:
            print("  %-34s %s%s" % (i.key, i.what, "  [excluded]" if i.key in excluded else ""))
    else:
        apply_items(cr, items, excluded)
        still = {i.key for i in plan(ce, cr, ctx, {})}
        for i in items:
            if i.state == "reapplied" and i.key in still:
                i.state, i.error = "refused", "re-applied, but still looser than at the archive's end"
    lost = lost_records(ce, cr, args.target_time)
    if not args.dry_run:
        for state in ("reapplied", "excluded", "refused"):
            chosen = [i for i in items if i.state == state]
            if chosen:
                print({"reapplied": "re-applied", "excluded": "excluded", "refused": "STILL LOOSER"}[state]
                      + " (%d):" % len(chosen))
                for i in chosen:
                    print("  %-34s %s" % (i.key, i.what))
                    if state == "refused":
                        print("  %-34s   %s; %s" % ("", i.error, i.remedy))
    if listed:
        print("not re-made (%d), each to make again if it was intended:" % len(listed))
        for k in sorted(listed):
            print("  %-34s %s" % (k, listed[k]))
    if lost:
        print("records after the target, which cannot be made again: "
              + ", ".join("%s %d" % (k, v) for k, v in sorted(lost.items())))
    if args.dry_run:
        return 0

    remaining = [i for i in items if i.state == "refused"]
    outcome = "reconciled" if not remaining else "incomplete"
    report = {
        "identifiers": identifiers,
        "reapplied": capped([{"key": i.key, "what": i.what} for i in items if i.state == "reapplied"]),
        "excluded": capped([{"key": i.key, "what": i.what} for i in items if i.state == "excluded"]),
        "exclusion_reason": args.exclusion_reason if excluded else None,
        "remaining": capped([{"key": i.key, "what": i.what, "error": i.error, "remedy": i.remedy} for i in remaining]),
        "not_remade": capped([{"key": k, "what": v} for k, v in sorted(listed.items())]),
        "lost": lost,
        "acting_admin": args.acting_admin,
        "cosigner": args.cosigner,
    }
    with cr.cursor() as cur:
        cur.execute("INSERT INTO RestoreRecord (target_time, archive_end, operator, outcome, report) "
                    "VALUES (%s, %s, %s, %s, %s) RETURNING restore_id",
                    (t, end, args.operator[:100], outcome, json.dumps(report, default=str)))
        rid = cur.fetchone()[0]
    cr.commit()
    print("outcome: %s; recorded as restore %d" % (outcome, rid))
    return 0 if outcome == "reconciled" else 1


if __name__ == "__main__":
    sys.exit(main())
