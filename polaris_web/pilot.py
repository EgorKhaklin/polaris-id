"""polaris_web/pilot.py - winding a pilot down (roadmap P5.1).

A pilot's real promise is not that it will work. It is that it can be undone. Institutions
say yes to a pilot because someone told them it could be wound back, and that promise is the
one that fails quietly: erasure is a paragraph in a consent form, nobody ever executes it, and
the answer to "what is still in there?" is discovered years later by whoever inherits the
database.

So the wind-down is a path that runs, and its most important output is not what it removed.

WHAT ERASURE CAN AND CANNOT DO HERE, because a consent form that gets this wrong is worse
than no consent form. C1 makes the audit-of-record append-only and non-negotiable, so Polaris
CANNOT delete a participant. What it can do is pseudonymize: the holder's plaintext name is
replaced, the row and every audit reference to it stay whole, and the act itself is recorded.
Telling a participant "your data will be deleted" is therefore false in this system, and
`consent_language()` below is generated from what the code actually does rather than written
from what would be reassuring.

A WIND-DOWN IS A MASS REVOCATION, AND THE SYSTEM REFUSES TO LET ONE AUTHORITY DO IT ALONE.
That is not an obstacle to work around; it is the control working. `uc8_revoke_token` bounds
the share of an agency's population that may be revoked in a rolling window and demands a
co-signing agency past it, because a lone authority able to revoke a population at will is the
coercion this system exists to make expensive. Ending a pilot is exactly that shape, so
`wind_down` REQUIRES a co-signer rather than discovering the refusal partway through. An
institution winding down a pilot needs a second authority to agree, the same way a coercive
mass revocation would.

THE RESIDUE REPORT IS THE POINT. After a wind-down, `residue()` enumerates every table that
still holds a row referencing a participant, and it does so FROM THE SCHEMA rather than from a
list somebody maintains. A hand-written list of "what remains" is a list that stops being true
the first time a table is added and nobody remembers to update it, which is precisely how a
privacy claim rots. Add a table with a foreign key to Individual and it appears in the report
on the next run, whether or not anyone thought about it.

See docs/operator/PILOT.md.
"""
from __future__ import annotations

PSEUDONYM_PREFIX = "PSEUDONYMIZED-"
WINDDOWN_REASON = "ADMINISTRATIVE"      # the RevocationList code for a pilot ending


class WindDownRefused(Exception):
    """The wind-down stopped because completing it would misrepresent what happened."""


def participants(conn, agency_id=None):
    """Everyone the pilot enrolled: an individual with at least one credential.

    `agency_id` scopes the wind-down to one authority's pilot. A pilot-in-a-box is an
    instance-per-authority deployment, so the unscoped form is the whole instance; the scoped
    form exists because a shared instance is a topology the tree supports and a wind-down that
    could only ever mean "everything here" would be unusable in one."""
    with conn.cursor() as cur:
        if agency_id is None:
            cur.execute("SELECT DISTINCT i.individual_id, i.legal_name FROM Individual i "
                        "JOIN IdentityToken t ON t.individual_id = i.individual_id "
                        "ORDER BY i.individual_id")
        else:
            cur.execute("SELECT DISTINCT i.individual_id, i.legal_name FROM Individual i "
                        "JOIN IdentityToken t ON t.individual_id = i.individual_id "
                        "WHERE t.issuing_agency_id = %s ORDER BY i.individual_id",
                        (agency_id,))
        return cur.fetchall()


def _rows(cur):
    return [r if not hasattr(r, "keys") else dict(r) for r in cur.fetchall()]


def residue(conn):
    """Every table still holding a row that references a participant, FROM THE SCHEMA.

    Derived, not listed. A hand-maintained inventory of what a wind-down leaves behind stops
    being true the first time somebody adds a table, and the failure is silent: the privacy
    claim keeps reading correctly while becoming false. This walks the foreign keys to
    Individual and to IdentityToken and counts what is actually there, so a table added next
    year appears here without anyone remembering it should."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT tc.table_name, kcu.column_name, ccu.table_name AS refs
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON kcu.constraint_name = tc.constraint_name
            JOIN information_schema.constraint_column_usage ccu
              ON ccu.constraint_name = tc.constraint_name
            WHERE tc.constraint_type = 'FOREIGN KEY'
              AND lower(ccu.table_name) IN ('individual', 'identitytoken')
            ORDER BY tc.table_name
        """)
        links = _rows(cur)

    out = []
    seen = set()
    for link in links:
        table = link["table_name"]
        if table in seen:
            continue
        seen.add(table)
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM %s" % table)  # noqa: S608 - identifier
            n = cur.fetchone()["n"]
        out.append({"table": table, "references": link["refs"], "rows": n})
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM Individual")
        out.append({"table": "individual", "references": "itself", "rows": cur.fetchone()["n"]})
    return sorted(out, key=lambda r: r["table"])


def pseudonymized_count(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM Individual WHERE legal_name LIKE %s",
                    (PSEUDONYM_PREFIX + "%",))
        return cur.fetchone()["n"]


def wind_down(conn, actor_user_id, *, agency_id=None, cosigner_agency_id=None,
              reason="pilot concluded", dry_run=False):
    """Revoke every credential the pilot issued, then pseudonymize every participant.

    In that order, and the order matters: pseudonymizing first would leave live credentials
    belonging to a holder nobody can name any more, which is worse than either state on its
    own. Idempotent, because a wind-down that could not be re-run is one nobody dares run the
    first time.

    `cosigner_agency_id` is required for the same reason the revocation bound exists: this is
    a mass revocation, and one authority must not be able to perform one alone."""
    people = participants(conn, agency_id)
    with conn.cursor() as cur:
        if agency_id is None:
            cur.execute("SELECT t.token_id, t.issuing_agency_id, t.algorithm_id "
                        "FROM IdentityToken t WHERE t.status = 'ACTIVE' ORDER BY t.token_id")
        else:
            cur.execute("SELECT t.token_id, t.issuing_agency_id, t.algorithm_id "
                        "FROM IdentityToken t WHERE t.status = 'ACTIVE' "
                        "AND t.issuing_agency_id = %s ORDER BY t.token_id", (agency_id,))
        live = _rows(cur)

    plan = {"participants": len(people), "credentials_to_revoke": len(live),
            "already_pseudonymized": pseudonymized_count(conn),
            "cosigner_agency_id": cosigner_agency_id, "agency_id": agency_id}
    if dry_run:
        plan["residue_after"] = residue(conn)
        plan["dry_run"] = True
        return plan

    # The co-signer is validated against the WHOLE population before anything is revoked.
    # uc8_revoke_token checks it per token, so a co-signer authorised for some algorithms and
    # not others would revoke part of the pilot and then raise, leaving it in a state nobody
    # designed and no procedure undoes. A mass operation that can fail halfway must find out
    # first.
    if live and cosigner_agency_id is not None:
        algorithms = {t["algorithm_id"] for t in live}
        with conn.cursor() as cur:
            cur.execute("SELECT algorithm_id FROM AgencyAlgorithmAuth "
                        "WHERE agency_id = %s AND authorization_type = 'BOTH'",
                        (cosigner_agency_id,))
            covered = {r["algorithm_id"] for r in cur.fetchall()}
        issuers = {t["issuing_agency_id"] for t in live}
        if cosigner_agency_id in issuers:
            raise WindDownRefused(
                "agency %s issued credentials in this pilot and so cannot co-sign its own "
                "wind-down. uc8_revoke_token requires the co-signer to differ from the actor, "
                "which is the whole content of co-signing: a second authority agreeing, not "
                "the same one signing twice" % cosigner_agency_id)
        missing = sorted(algorithms - covered)
        if missing:
            raise WindDownRefused(
                "agency %s cannot co-sign this wind-down: it lacks BOTH authorization on "
                "algorithm(s) %s, which credentials in this pilot use. Checked before anything "
                "was revoked, because a co-signer valid for some of the population and not the "
                "rest would leave the pilot half wound down"
                % (cosigner_agency_id, ", ".join(str(a) for a in missing)))

    if live and cosigner_agency_id is None:
        raise WindDownRefused(
            "winding down a pilot revokes %d credentials at once, which is a mass revocation. "
            "uc8_revoke_token bounds the share of an agency's population that may be revoked "
            "in a rolling window and demands a co-signing agency past it, because a lone "
            "authority able to revoke a population at will is the coercion this system exists "
            "to make expensive. Name a co-signer: ending a pilot needs a second authority to "
            "agree, the same way a coercive mass revocation would" % len(live))

    revoked = 0
    for token in live:
        with conn.cursor() as cur:
            cur.execute("CALL uc8_revoke_token(%s, %s, %s, %s, %s)",
                        (token["token_id"], token["issuing_agency_id"], WINDDOWN_REASON,
                         None, cosigner_agency_id))
        revoked += 1

    erased = 0
    for person in people:
        if str(person["legal_name"]).startswith(PSEUDONYM_PREFIX):
            continue        # already erased; re-running must not fail on it
        with conn.cursor() as cur:
            cur.execute("CALL uc_pseudonymize_individual(%s, %s, %s)",
                        (person["individual_id"], actor_user_id, reason[:200]))
        erased += 1
    conn.commit()

    plan.update({"credentials_revoked": revoked, "participants_pseudonymized": erased,
                 "residue_after": residue(conn), "dry_run": False})
    return plan


def consent_language(conn=None) -> str:
    """The paragraph a consent form may truthfully carry, derived from what the code does.

    Not a template to fill in. A pilot's consent form is where the gap between what a system
    does and what its operators believe it does becomes a promise to a person, and the usual
    failure is the word "deleted". C1 makes deletion impossible here, so this says what
    actually happens instead."""
    return (
        "When this pilot ends, your credential is revoked and your name is replaced in our "
        "records with a meaningless marker. Your name will no longer be readable by anyone "
        "operating this system.\n\n"
        "What is NOT removed, and cannot be: the record that a person was enrolled, that "
        "credentials were issued to them, and that verifications happened. Those records stay, "
        "without your name attached. They are kept append-only on purpose, so that nobody, "
        "including us, can quietly erase evidence of what this system did. That protection "
        "applies to you as much as it constrains you.\n\n"
        "We cannot promise your data will be deleted, because in this system that would not be "
        "true.\n\n"
        "Ending this pilot requires a second, independent authority to co-sign the withdrawal "
        "of every credential. No single organisation running this pilot, including the one "
        "that enrolled you, can revoke everyone on its own.")

# ---------------------------------------------------------------------------
# The DPIA input pack
# ---------------------------------------------------------------------------
def dpia_inputs(conn):
    """The facts a data-protection impact assessment needs that only the system can supply.

    NOT a DPIA, and not a template for one. A DPIA is a legal instrument that names a
    controller, a lawful basis and a jurisdiction; docs/PRODUCTION-READINESS.md says plainly
    that it is counsel's work and not an engineering task, and shipping a fill-in-the-blanks
    form would invite somebody to treat the blanks as the whole job.

    What engineering CAN supply, and what a DPIA is usually wrong about, is the factual half:
    which tables hold what, how long each class is kept, who can read it, and what survives a
    wind-down. Those answers are derived here from the live schema and the effective retention
    policy rather than transcribed, because a DPIA written from a hand-maintained inventory is
    accurate on the day it is written and wrong from the next migration onward."""
    pack = {"generated_from": "the live schema and the effective retention policy",
            "not_a_dpia": ("A DPIA names a controller, a lawful basis and a jurisdiction. "
                           "Those are counsel's and the deploying organisation's. This is the "
                           "factual half a DPIA is usually wrong about."),
            "consent_language": consent_language()}

    with conn.cursor() as cur:
        # What is held, by table, with row counts. Derived: a table added next year appears.
        cur.execute("""
            SELECT c.relname AS table_name, c.reltuples::BIGINT AS approx_rows
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r'
            ORDER BY c.relname
        """)
        pack["tables"] = [dict(r) for r in cur.fetchall()]

        # The columns that hold identifying data, found by NAME across the whole schema. A
        # DPIA that missed one of these would be missing the part that matters, and a
        # hand-written list is exactly how one gets missed.
        cur.execute("""
            SELECT table_name, column_name, data_type
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND (column_name ILIKE '%name%' OR column_name ILIKE '%birth%'
                   OR column_name ILIKE '%biometric%' OR column_name ILIKE '%serial%'
                   OR column_name ILIKE '%location%' OR column_name ILIKE '%address%'
                   OR column_name ILIKE '%token_value%' OR column_name ILIKE '%duress%')
            ORDER BY table_name, column_name
        """)
        pack["identifying_columns"] = [dict(r) for r in cur.fetchall()]

        # How long each class is kept, from the effective policy rather than from prose.
        cur.execute("""
            SELECT table_class, jurisdiction, retention_days, justification
            FROM RetentionPolicy WHERE superseded_at IS NULL
            ORDER BY table_class, jurisdiction NULLS FIRST
        """)
        pack["retention"] = [dict(r) for r in cur.fetchall()]

        # Who can read it.
        cur.execute("SELECT role, count(*) AS accounts FROM AppUser WHERE is_active "
                    "GROUP BY role ORDER BY role")
        pack["operator_roles"] = [dict(r) for r in cur.fetchall()]

    pack["residue_after_winddown"] = residue(conn)
    return pack
