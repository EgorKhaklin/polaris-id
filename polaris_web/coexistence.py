"""polaris_web/coexistence.py - living beside the credential you are replacing (roadmap P7.5).

A new national credential does not arrive into an empty field. It arrives beside a driving
licence, a passport, a legacy card, and for some years it has to be the second thing somebody
carries rather than the first. That period is the whole of P7.5, and the dangerous moment in
it is not the cutover. It is the sunset.

SUNSETTING THE ALTERNATIVE IS THE MOMENT AN IDENTITY SYSTEM BECOMES COMPULSORY. Until the old
credential stops being accepted, a person who cannot or will not hold the new one still has a
way through the door. Afterwards they do not. A coexistence plan that treats sunset as a
milestone to reach, rather than a decision with a floor under it, is how a voluntary credential
becomes a mandatory one without anybody ever deciding to make it mandatory.

So this module computes readiness and REFUSES to return a verdict from what the issuer alone
can see.

WHAT THE ISSUER CAN MEASURE is the supply side: how many people hold a credential, how healthy
those credentials are, whether the artifacts an offline verifier needs are actually being
published, how far the trust list reaches. All of that comes out of the database and all of it
is about the authority's own readiness.

WHAT THE ISSUER CANNOT MEASURE is everything that decides whether sunset harms anyone: what
share of relying parties accept the credential, whether a person without one can still obtain
the services the old credential opened, whether an alternate path exists and is usable by
somebody with no smartphone, no fixed address and no appetite for a government website. None
of that is in any table here, and an authority that computed "ready to sunset" from issuance
numbers would be computing it from the half of the picture that flatters it.

`sunset_readiness` therefore takes those attestations as arguments and refuses without them.
Not as a formality: the refusal is the mechanism. An operator who has to type the answer has to
have asked the question.

See docs/design/coexistence.md.
"""
from __future__ import annotations

# The phases, in order. Naming them matters because "no flag-day" is easy to say and the
# failure is always the same: two phases collapsed into one on a date somebody had already
# announced.
PHASES = ("NOT_ISSUING", "PILOT", "ISSUING_ALONGSIDE", "PREFERRED", "SOLE")

# What an operator must attest to, because the database cannot see it. Each is phrased as the
# question it answers rather than as a field name, since a form field gets filled in and a
# question gets considered.
OPERATOR_ATTESTATIONS = {
    "relying_parties_accepting":
        "What share of relying parties that accept the legacy credential also accept this one?",
    "alternate_path_exists":
        "Can a person who does not hold this credential still obtain every service the legacy "
        "credential opened?",
    "alternate_path_is_usable":
        "Is that path usable by somebody with no smartphone, no fixed address, and no "
        "appetite for a government website, without them having to explain themselves?",
    "legacy_still_issued_to_newcomers":
        "Can somebody who arrives tomorrow still get the legacy credential?",
}


class SunsetRefused(Exception):
    """A sunset verdict was asked for without the facts that decide whether it harms anyone."""


def supply_side(conn):
    """What the issuer can see: its own readiness, and nothing about the world's."""
    out = {}
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM Individual")
        people = cur.fetchone()["n"]
        cur.execute("SELECT count(DISTINCT individual_id) AS n FROM IdentityToken "
                    "WHERE status = 'ACTIVE'")
        holders = cur.fetchone()["n"]
        cur.execute("SELECT status, count(*) AS n FROM IdentityToken GROUP BY status")
        out["credentials_by_status"] = {r["status"]: r["n"] for r in cur.fetchall()}
        cur.execute("SELECT count(*) AS n FROM AgencyTrustAttestation")
        out["trust_attestations"] = cur.fetchone()["n"]
        cur.execute("SELECT count(*) AS n FROM TokenStateEpoch")
        out["published_epochs"] = cur.fetchone()["n"]
    out["people_known"] = people
    out["people_holding"] = holders
    # Deliberately not called "coverage". This is coverage of the people this authority has
    # ALREADY ENROLLED, which is not the population: everyone it has never met is outside the
    # denominator, and they are exactly the people a sunset strands.
    out["enrolled_holding_share"] = (holders / people) if people else 0.0
    out["denominator_warning"] = (
        "This share counts people this authority has already enrolled. It says nothing about "
        "people it has never met, and they are precisely who a sunset strands.")
    return out


def sunset_readiness(conn, *, phase, attestations=None):
    """Whether the legacy credential can be withdrawn. Refuses without the operator's facts.

    Returns a verdict that separates what was measured from what was attested, because
    collapsing the two is how an issuance number becomes a decision about somebody's access to
    a bank account."""
    if phase not in PHASES:
        raise SunsetRefused("unknown phase %r (expected one of %s)"
                            % (phase, ", ".join(PHASES)))
    attestations = attestations or {}
    missing = [k for k in OPERATOR_ATTESTATIONS if k not in attestations]
    if missing:
        raise SunsetRefused(
            "a sunset verdict needs facts this database does not hold. Unanswered: %s. These "
            "are not a formality: an authority that computed readiness from issuance numbers "
            "alone would be computing it from the half of the picture that flatters it, and "
            "the half it skipped is the half that decides whether anyone is harmed"
            % "; ".join(OPERATOR_ATTESTATIONS[k] for k in missing))

    supply = supply_side(conn)
    blockers = []

    # The floor, and it is not a percentage. A sunset with no alternate path is an exclusion
    # mechanism whatever the adoption numbers say, which is why this is checked before them.
    if not attestations.get("alternate_path_exists"):
        blockers.append(
            "there is no path for a person who does not hold this credential. Withdrawing the "
            "old one now does not complete a migration, it removes somebody's way through the "
            "door")
    elif not attestations.get("alternate_path_is_usable"):
        blockers.append(
            "the alternate path exists on paper. A path that requires a smartphone, a fixed "
            "address or an explanation is a path that excludes the people most likely to need "
            "it, and counting it is how an exclusion is recorded as a success")

    share = attestations.get("relying_parties_accepting")
    if share is None or share < 1.0:
        blockers.append(
            "not every relying party that accepts the legacy credential accepts this one "
            "(%s). Until they do, withdrawing the old credential transfers the gap onto the "
            "holder, who discovers it at the counter"
            % ("unstated" if share is None else "%.0f%%" % (share * 100)))

    if phase != "PREFERRED":
        blockers.append(
            "sunset follows the PREFERRED phase, and this deployment is %s. Skipping a phase "
            "is the flag-day this plan exists to avoid" % phase)

    if not supply["published_epochs"]:
        blockers.append(
            "no epoch has been published, so offline verification has nothing to check "
            "against. A credential that only works online is not a replacement for one that "
            "works in a power cut")

    return {
        "phase": phase,
        "measured": supply,
        "attested": {k: attestations.get(k) for k in OPERATOR_ATTESTATIONS},
        "blockers": blockers,
        "may_sunset": not blockers,
        "note": ("A clear verdict here is permission from the engineering facts, not from the "
                 "people affected. Sunset remains a decision somebody makes and answers for."),
    }
