"""polaris_web/referee.py - how somebody who cannot present evidence still gets a credential (P4.4).

Every combination in 800-63A starts from documents. A person with none -- no fixed address, a
care leaver, somebody who left a household in a hurry, a refugee, an adult who never held a
passport -- fails all of them, and an enrollment path that stops there has decided that the
people with least are the people who go without. THE TRUSTED REFEREE IS THE ANSWER TO THAT, and
it is also the most obvious forgery channel in the whole enrollment path. Those are not two
features to be balanced. They are one mechanism, and every rule below exists because the second
thing is true of the first.

THE LIMITS ARE IN THE DATABASE, not here. `polaris_web/proofing.py` derives an assurance level
and the schema holds a floor under it; the same applies to vouching. A direct `INSERT` cannot
record a referee vouching for themselves, a vouching above the referee's own proofed level, or a
vouching at IAL3. This module refuses those earlier and WITH A REASON, which is a different job:
an operator who is told "no" re-runs the same session, and an operator who is told what is
missing goes and gets it.

A VOUCHING NEVER REACHES IAL3. IAL3 needs a live biometric of the APPLICANT in a supervised
session. A referee can attest to who somebody is. A referee cannot be that person's face, and a
system that let one stand in for the other would have made its highest assurance level the
easiest one to forge.

A VOUCHING CANNOT EXCEED THE REFEREE'S OWN PROOFED LEVEL, because you cannot give what you do
not have. A referee at IAL2 vouches at IAL2 or below. A referee at IAL1 cannot vouch at all: an
unproofed person vouching for an unproofed person is two strangers agreeing.

THE BOUND DOES NOT REFUSE. A referee who has vouched forty times this month is either a shelter
worker doing exactly what this path exists for, or a compromised channel, and NOTHING IN THE
DATABASE CAN TELL THOSE APART. Refusing would break the legitimate case, which is the exclusion
this mechanism exists to prevent; allowing silently would make the volume invisible. So past the
bound a vouching needs a CO-SIGNER: a third proofed person who also puts their name to it. The
same shape as the mass-revocation bound, for the same reason -- the answer to an action that
might be coercion is to make one person unable to do it alone.

AND THE CREDENTIAL DOES NOT SAY ANY OF THIS. `IdentityToken` gains no column, no flag and no
reference to a vouching. A credential asserts an assurance LEVEL; it does not assert the
circumstances its holder was in when they got it. The authority keeps the whole record, because
a referee found to have vouched falsely makes every credential they touched a question that has
to be answerable. The holder carries something that looks like everybody else's, because a
person who needed a referee has been through enough without carrying a mark for it.

See docs/design/trusted-referee.md.
"""
from __future__ import annotations

#: Why this person is in a position to vouch. Closed, because "knows the applicant"
#: covers a social worker and a stranger paid fifty pounds, and the difference is the
#: whole control. Institutional roles, because an institution can be asked afterwards.
RELATIONSHIPS = (
    "LEGAL_GUARDIAN",
    "SOCIAL_WORKER",
    "MEDICAL_PROFESSIONAL",
    "NOTARY",
    "EDUCATIONAL_INSTITUTION",
    "SHELTER_OR_REFUGE",
    "RELIGIOUS_INSTITUTION",
    "EMPLOYER",
    "COMMUNITY_LEADER",
)

#: The highest level a vouching can ever produce. Not a policy knob: IAL3 requires the
#: APPLICANT's live biometric, and no attestation by a third party substitutes for it.
VOUCHING_CEILING = "IAL2"

#: A referee below this has nothing to lend.
MINIMUM_REFEREE_IAL = "IAL2"

#: Past this many vouchings in the window, a co-signer is required. A judgment, and
#: stated as one: it is high enough that an ordinary caseworker month does not trip it
#: and low enough that a compromised referee meets a second pair of eyes early. Tune it
#: per deployment; what must not change is that passing it asks for a co-signer rather
#: than refusing.
VOUCHING_BOUND = 25
VOUCHING_WINDOW_DAYS = 30

IAL_ORDER = ("IAL1", "IAL2", "IAL3")


class VouchingRefused(ValueError):
    """A vouching the system will not record, carrying why.

    Always with the reason. A refusal an operator cannot act on sends them back to
    re-run the identical session with the identical result.
    """


def vouching_ceiling(referee_ial: str) -> str | None:
    """The highest level this referee can vouch at, or None if they cannot vouch.

    Derived from the referee's own proofing, never chosen. A referee at IAL3 is still
    capped at IAL2, because the ceiling is about what a third party can establish and
    not about how well the referee themselves was proofed.
    """
    if referee_ial not in IAL_ORDER:
        raise VouchingRefused(
            "unknown referee level: %r (accepted: %s)" % (referee_ial, ", ".join(IAL_ORDER)))
    if IAL_ORDER.index(referee_ial) < IAL_ORDER.index(MINIMUM_REFEREE_IAL):
        return None
    return min(referee_ial, VOUCHING_CEILING)


def check_vouching(*, referee_id, applicant_id, referee_ial, relationship,
                   vouched_ial, co_signer_id=None, vouchings_in_window=0,
                   bound=VOUCHING_BOUND):
    """Refuse a vouching that should not be recorded, naming what is wrong.

    Returns the vouched level when it stands. Raises VouchingRefused otherwise, with a
    sentence an operator can act on rather than a verdict they can only repeat.
    """
    if referee_id == applicant_id:
        raise VouchingRefused(
            "a person cannot vouch for themselves; a vouching is somebody else's word")
    if co_signer_id is not None and co_signer_id in (referee_id, applicant_id):
        raise VouchingRefused(
            "the co-signer must be a third person: past the bound the point is a second "
            "pair of eyes, and the referee's own are already on it")
    if relationship not in RELATIONSHIPS:
        raise VouchingRefused(
            "unknown relationship: %r. The vocabulary is closed (%s) because 'knows the "
            "applicant' covers a caseworker and a stranger, and the difference is the control"
            % (relationship, ", ".join(RELATIONSHIPS)))
    ceiling = vouching_ceiling(referee_ial)
    if ceiling is None:
        raise VouchingRefused(
            "a referee proofed at %s cannot vouch: they would be lending an assurance they "
            "do not hold. A referee must be proofed at %s or above"
            % (referee_ial, MINIMUM_REFEREE_IAL))
    if vouched_ial not in IAL_ORDER:
        raise VouchingRefused(
            "unknown level: %r (accepted: %s)" % (vouched_ial, ", ".join(IAL_ORDER)))
    if vouched_ial == "IAL3":
        raise VouchingRefused(
            "no vouching reaches IAL3. That level needs the APPLICANT's live biometric in a "
            "supervised session; a referee can attest to who somebody is and cannot be their "
            "face. Record the session that collected the biometric instead")
    if IAL_ORDER.index(vouched_ial) > IAL_ORDER.index(ceiling):
        raise VouchingRefused(
            "a referee proofed at %s cannot vouch at %s: the ceiling is %s. You cannot give "
            "what you do not have" % (referee_ial, vouched_ial, ceiling))
    if vouchings_in_window >= bound and co_signer_id is None:
        raise VouchingRefused(
            "this referee has vouched %d time(s) in the last %d days, at or past the bound of "
            "%d, so this vouching needs a CO-SIGNER. It is not a refusal: a caseworker with a "
            "heavy month and a compromised referee look identical from here, and refusing "
            "would break the first to catch the second"
            % (vouchings_in_window, VOUCHING_WINDOW_DAYS, bound))
    return vouched_ial


def why_refused(**kwargs) -> str:
    """The refusal as a sentence, or a statement that the vouching stands.

    For an operator surface that wants to show the reason before anybody presses a
    button, rather than after.
    """
    try:
        level = check_vouching(**kwargs)
    except VouchingRefused as exc:
        return str(exc)
    return "the vouching stands at %s" % level


def vouchings_in_window(conn, referee_id, window_days=VOUCHING_WINDOW_DAYS):
    """How many times this referee has vouched inside the window."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT count(*) AS n
            FROM   RefereeVouching
            WHERE  referee_individual_id = %s
              AND  vouched_at >= CURRENT_TIMESTAMP - (%s || ' days')::interval
        """, (referee_id, window_days))
        row = cur.fetchone()
    return int(row["n"] if isinstance(row, dict) or hasattr(row, "keys") else row[0])


def record_vouching(conn, *, proofing_id, referee_id, applicant_id, referee_ial,
                    relationship, vouched_ial, co_signer_id=None,
                    bound=VOUCHING_BOUND):
    """Record a vouching, refusing first and in the same transaction that counts.

    The window count is taken inside the caller's transaction so two concurrent
    vouchings cannot both read a count below the bound and both skip the co-signer.
    """
    seen = vouchings_in_window(conn, referee_id)
    check_vouching(referee_id=referee_id, applicant_id=applicant_id,
                   referee_ial=referee_ial, relationship=relationship,
                   vouched_ial=vouched_ial, co_signer_id=co_signer_id,
                   vouchings_in_window=seen, bound=bound)
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO RefereeVouching
                (proofing_id, referee_individual_id, applicant_individual_id,
                 referee_ial, relationship, vouched_ial, co_signer_individual_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING vouching_id
        """, (proofing_id, referee_id, applicant_id, referee_ial, relationship,
              vouched_ial, co_signer_id))
        row = cur.fetchone()
    return row["vouching_id"] if hasattr(row, "keys") else row[0]


def vouchings_by(conn, referee_id):
    """Every enrollment this referee touched, newest first.

    THE QUESTION A COMPROMISED REFEREE FORCES. One found to have vouched falsely makes
    every credential they touched a question, and an authority that cannot enumerate
    them cannot answer it -- so this is an index scan rather than a table scan, and the
    record is append-only so the list cannot be shortened after the fact.
    """
    with conn.cursor() as cur:
        cur.execute("""
            SELECT vouching_id, proofing_id, applicant_individual_id, referee_ial,
                   relationship, vouched_ial, co_signer_individual_id, vouched_at
            FROM   RefereeVouching
            WHERE  referee_individual_id = %s
            ORDER  BY vouched_at DESC, vouching_id DESC
        """, (referee_id,))
        return [dict(r) for r in cur.fetchall()]
