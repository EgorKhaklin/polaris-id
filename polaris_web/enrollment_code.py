"""polaris_web/enrollment_code.py - the secret sent to a channel, and what it does not prove (P4.4).

An authority sends a code to a channel the applicant nominated; the applicant returns it. What
that establishes is narrow, and stating it first keeps the rest honest: SOMEBODY WHO COULD REACH
THAT CHANNEL RETURNED THE SECRET. Not that they are the applicant. `proofing.py` caps
ENROLLMENT_CODE verification at FAIR for exactly that reason (v9.395), and this module is the
lifecycle underneath the cap rather than an argument for raising it.

THE CODE IS RETURNED ONCE AND NEVER STORED. `issue` hands back the plaintext, the caller sends
it to the channel, and after that nothing in this system can produce it again -- there is no
column that could hold one. A leaked enrollment database should be a pile of hashes, and a
column that COULD hold a plaintext code is a column somebody eventually writes one into.

THE ATTEMPT COUNTER CLIMBS ON A WRONG GUESS, which is why redemption finds the code by WHO IT
WAS ISSUED TO rather than by the hash of what was presented. Looking it up by the presented
hash would be simpler and would count nothing: a wrong guess matches no row, the counter never
moves, and the bound that is supposed to stop a brute force never sees one.

VALIDITY IS SHORT AND THE SCHEMA HOLDS THE CEILING. A code with a distant expiry is a permanent
credential sitting in a mailbox, and the mailbox may not be the applicant's -- a controlling
household, a care setting, a shelter with shared post. That population is the same one the
trusted-referee path exists for, and it is the reason a posted code is capped rather than
trusted.

See docs/design/identity-proofing.md.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

#: How the code reached the applicant. Recorded because the coercion properties differ
#: and nothing downstream can reconstruct it: a code posted to a home address and one
#: handed over at a counter are the same row otherwise, and they are not the same event.
CHANNELS = ("POSTAL", "SMS", "EMAIL", "IN_PERSON_HANDOVER")

#: 128 bits, from `secrets`. The code is read aloud, typed from a letter, or copied off a
#: screen, so it is base32 without padding: no case confusion and no characters a person
#: has to ask about.
CODE_ENTROPY_BYTES = 16

#: Wrong guesses before the code is dead. The schema holds the same ceiling, so a route
#: that forgets to count still meets it.
MAX_ATTEMPTS = 5

#: The longest a code may live. The schema refuses more.
MAX_VALIDITY_DAYS = 30


class CodeRefused(ValueError):
    """A code that will not be issued or will not be accepted, carrying why."""


def hash_code(code: str) -> str:
    """SHA-256 hex of the code as presented, normalised.

    Normalisation is upper-case with spaces and hyphens removed, because a code printed
    in groups gets typed back in groups, and an applicant who types their code correctly
    should not fail on whitespace. Normalising before hashing keeps the comparison
    constant-time: there is no second, sloppier path that a near-miss falls into.
    """
    cleaned = "".join(code.split()).replace("-", "").upper()
    if not cleaned:
        raise CodeRefused("an empty code is not a code")
    return hashlib.sha256(cleaned.encode("ascii", "strict")).hexdigest()


def generate_code() -> tuple[str, str]:
    """A fresh code and its hash. The plaintext is returned exactly once, here.

    Base32 of 128 random bits, grouped for transcription. Nothing stores the left-hand
    value: the caller sends it to the channel and lets it go.
    """
    import base64
    raw = base64.b32encode(secrets.token_bytes(CODE_ENTROPY_BYTES)).decode("ascii")
    raw = raw.rstrip("=")
    grouped = "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))
    return grouped, hash_code(grouped)


def issue(conn, *, individual_id, agency_id, channel, validity_days=14):
    """Issue a code, returning (code_id, plaintext). The plaintext is not stored.

    The caller has one chance to deliver it. That is the shape that makes "never stored"
    true rather than aspirational: there is nowhere to read it back from.
    """
    if channel not in CHANNELS:
        raise CodeRefused("unknown channel: %r (accepted: %s)" % (channel, ", ".join(CHANNELS)))
    if not 0 < validity_days <= MAX_VALIDITY_DAYS:
        raise CodeRefused(
            "validity must be between 1 and %d days; a code that lives longer is a "
            "permanent credential in a mailbox, and the mailbox may not be the "
            "applicant's" % MAX_VALIDITY_DAYS)
    plaintext, digest = generate_code()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO EnrollmentCode
                (individual_id, issued_by_agency_id, code_hash, channel, expires_at)
            VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP + (%s || ' days')::interval)
            RETURNING code_id
        """, (individual_id, agency_id, digest, channel, validity_days))
        row = cur.fetchone()
    return (row["code_id"] if hasattr(row, "keys") else row[0]), plaintext


def outstanding(conn, individual_id):
    """Codes issued to this person that are still live: unredeemed, unexpired, unlocked."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT code_id, code_hash, channel, issued_at, expires_at, attempts
            FROM   EnrollmentCode
            WHERE  individual_id = %s
              AND  redeemed_at IS NULL
              AND  expires_at > CURRENT_TIMESTAMP
              AND  attempts < %s
            ORDER  BY issued_at DESC
        """, (individual_id, MAX_ATTEMPTS))
        return [dict(r) for r in cur.fetchall()]


def redeem(conn, *, individual_id, presented, proofing_id):
    """Redeem a presented code against a proofing event, or refuse with the reason.

    Finds the code by WHO IT WAS ISSUED TO, not by the hash of what was presented, so a
    wrong guess lands on a real row and moves its counter. Comparison is
    `hmac.compare_digest` over the hashes.

    Returns the code_id on success.
    """
    digest = hash_code(presented)
    live = outstanding(conn, individual_id)
    if not live:
        raise CodeRefused(
            "no live code for this applicant: every code issued to them is redeemed, "
            "expired, or out of attempts. Issue a new one")
    for code in live:
        if hmac.compare_digest(code["code_hash"], digest):
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE EnrollmentCode
                    SET    redeemed_at = CURRENT_TIMESTAMP, proofing_id = %s
                    WHERE  code_id = %s AND redeemed_at IS NULL
                    RETURNING code_id
                """, (proofing_id, code["code_id"]))
                row = cur.fetchone()
            if row is None:
                # Another transaction redeemed it between the read and the write.
                raise CodeRefused("this code was redeemed already; a code is single use")
            return code["code_id"]

    # A wrong guess. Every live code for this applicant takes the hit, because the
    # attacker does not get a free probe per outstanding code.
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE EnrollmentCode
            SET    attempts = attempts + 1
            WHERE  individual_id = %s AND redeemed_at IS NULL
              AND  expires_at > CURRENT_TIMESTAMP AND attempts < %s
        """, (individual_id, MAX_ATTEMPTS))
    remaining = min((MAX_ATTEMPTS - c["attempts"] - 1) for c in live)
    raise CodeRefused(
        "that code does not match. %d attempt(s) remain before the code is dead and a "
        "new one has to be issued" % max(0, remaining))
