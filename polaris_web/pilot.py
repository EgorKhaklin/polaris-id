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
