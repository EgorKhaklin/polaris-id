"""polaris_card/personalization.py - putting a credential onto a card (roadmap P4.3).

Personalization is the moment a database record becomes an object in somebody's pocket. It is
the only step where the authority's signature is applied to something that then leaves its
control, which is why the whole flow is built around two ideas.

KEY GENERATION, NOT KEY INJECTION. The card generates its own keypairs and exports only the
public halves. An injected key existed somewhere else first: on the personalization host, in
its memory, possibly in a log or a core dump, and the authority can only ASSERT that it was
destroyed. A generated key has no such history, so "the private key never left the card" is a
fact about where it was made rather than a promise about what was deleted. Nothing in this
module ever holds a private key, and there is no parameter through which one could be passed
in. That absence is the design.

EVERY PERSONALIZATION IS AN AUDIT-OF-RECORD EVENT. One append-only CardPersonalization row,
written in the same transaction as the rest, holding both slot public keys in full because the
authority has to verify a later presentation and a fingerprint cannot do that. Both slots are
generated on every card whether or not the holder ever enrolls a duress PIN: if a duress slot
only existed when one was wanted, its presence in the authority's records would be a fact
about the holder, and because every card has one the row says nothing about anybody.

The refusals matter as much as the flow, and each one is a way a card gets into the world
carrying something it should not:

  A CARD IS PERSONALIZED ONCE. The card refuses a second GENERATE KEYPAIR or PUT CARD OBJECT
  for the life of the part. A card that could be re-personalized in the field is a forgery
  machine with a legitimate serial number.

  A CREDENTIAL GETS ONE CARD. A unique index, not a check in this file. Two live cards
  answering for one credential is a revocation that only half works.

  ONLY AN ACTIVE CREDENTIAL. Personalizing a revoked or expired credential would put a signed
  object in the world for something the authority has already withdrawn.

  AND THE CARD OBJECT IS VERIFIED BEFORE IT IS RECORDED. The signature is checked against the
  issuer key that just made it, before the row is written. Recording a personalization whose
  object does not verify would put a card in the field and an authoritative-looking row in the
  audit-of-record saying it was fine.

See docs/design/card-profile.md and docs/operator/PERSONALIZATION.md.
"""
from __future__ import annotations

import hashlib

try:
    from polaris_card import card_profile as cp, emulator as em   # type: ignore
except ImportError:                      # pragma: no cover - the flat layout
    import card_profile as cp            # type: ignore
    import emulator as em                # type: ignore


class PersonalizationRefused(Exception):
    """The flow stopped because completing it would put something wrong into the world."""


def credential_for(conn, token_id):
    with conn.cursor() as cur:
        cur.execute("SELECT token_id, token_value, status, issuing_agency_id, "
                    "activation_sequence, expiration_date "
                    "FROM IdentityToken WHERE token_id = %s", (token_id,))
        return cur.fetchone()


def already_personalized(conn, token_id) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM CardPersonalization WHERE token_id = %s", (token_id,))
        return cur.fetchone() is not None


def personalize(conn, token_id, card, *, issuer_sign, issuer_verify=None, operator_user_id=None,
                expires_at=None, issued_at=None, sign_pq=None, card_key_pq=None):
    """Personalize `card` for credential `token_id`. Returns the recorded row.

    `issuer_sign(digest) -> bytes` is the authority's signing key, which lives in custody
    (P1.2) and is NOT handled here. `issuer_verify(digest, signature) -> bool` is used to check
    the object before it is recorded; skipping it is allowed but leaves the last chance to
    catch a broken signing path unused."""
    row = credential_for(conn, token_id)
    if row is None:
        raise PersonalizationRefused(f"no such credential: {token_id}")
    if row["status"] != "ACTIVE":
        raise PersonalizationRefused(
            f"credential {token_id} is {row['status']}, not ACTIVE. Personalizing it would put "
            "a signed object in the world for something the authority has withdrawn")
    if already_personalized(conn, token_id):
        raise PersonalizationRefused(
            f"credential {token_id} already has a card. A replacement is a SUCCESSION, a new "
            "credential with its own activation sequence, not a second card answering for this "
            "one: two live cards for one credential is a revocation that only half works")

    # The card makes its own keys. There is no parameter here through which a private key
    # could be supplied, which is the point rather than an omission.
    if getattr(card, "state", None) != em.STATE_BLANK:
        raise PersonalizationRefused(
            "this card is not blank. A card is personalized once for the life of the part; one "
            "that could be re-personalized in the field is a forgery machine with a legitimate "
            "serial number")
    generated = em.parse_generated_keys(card.transmit(em.generate_keypair()))
    if generated is None:
        raise PersonalizationRefused("the card did not generate a keypair")
    normal_pub, duress_pub = generated
    if normal_pub == duress_pub:
        raise PersonalizationRefused(
            "the card returned the same key for both slots; the authority would then be unable "
            "to tell a duress presentation from an ordinary one, which is the one party that "
            "must be able to")

    if issued_at is None:
        issued_at = 1_757_000_000
    if expires_at is None:
        expires_at = issued_at + 10 * 365 * 24 * 3600

    fields_kw = dict(token_value=row["token_value"],
                     issuing_authority=row["issuing_agency_id"],
                     activation_sequence=row["activation_sequence"],
                     issued_at=int(issued_at), expires_at=int(expires_at),
                     card_key_classical=normal_pub, sign_classical=issuer_sign)
    if card_key_pq is not None and sign_pq is not None:
        fields_kw["card_key_pq"] = card_key_pq
        fields_kw["sign_pq"] = sign_pq
    card_object = cp.build_card(**fields_kw)

    # Verified BEFORE it is recorded. A row in the audit-of-record saying a card was fine, for
    # a card whose signature does not check, is worse than no row.
    if issuer_verify is not None:
        verdict = cp.verify_card(card_object, verify_classical=issuer_verify)
        if not verdict["authentic"]:
            raise PersonalizationRefused(
                "the card object did not verify under the key that just signed it: %s"
                % (verdict["note"] or "no reason given"))

    response = card.transmit(em.put_card_object(card_object))
    if not em.is_ok(response):
        raise PersonalizationRefused(
            "the card refused the object (status 0x%04x)" % em.status_word(response))

    digest = hashlib.sha3_256(card_object).digest()
    with conn.cursor() as cur:
        import psycopg2
        cur.execute(
            "INSERT INTO CardPersonalization (token_id, issuing_agency_id, credential_ref, "
            "profile_version, normal_public_key, duress_public_key, card_object_sha3_256, "
            "personalized_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
            "RETURNING personalization_id, personalized_at",
            (token_id, row["issuing_agency_id"],
             psycopg2.Binary(cp.credential_ref(row["token_value"])),
             cp.PROFILE_VERSION, psycopg2.Binary(normal_pub), psycopg2.Binary(duress_pub),
             psycopg2.Binary(digest), operator_user_id))
        recorded = cur.fetchone()
    conn.commit()
    return {
        "personalization_id": recorded["personalization_id"],
        "personalized_at": recorded["personalized_at"],
        "token_id": token_id,
        "card_object": card_object,
        "normal_public_key": normal_pub,
        "duress_public_key": duress_pub,
        "card_object_sha3_256": digest,
    }


def slot_for_presentation(conn, token_id, verify_signature):
    """Which slot signed a presentation: 'normal', 'duress', or None.

    The authority's half of the duress mechanism. `verify_signature(public_key) -> bool` is the
    caller's verification against one candidate key. A verifier at the counter never calls
    this; it sees a well-formed response either way and its screen says success. This runs
    where the alert is raised, which is why an offline verifier cannot raise one."""
    with conn.cursor() as cur:
        cur.execute("SELECT normal_public_key, duress_public_key FROM CardPersonalization "
                    "WHERE token_id = %s", (token_id,))
        row = cur.fetchone()
    if row is None:
        return None
    # Both are tried, always, so the work does not depend on the answer.
    normal_ok = bool(verify_signature(bytes(row["normal_public_key"])))
    duress_ok = bool(verify_signature(bytes(row["duress_public_key"])))
    if duress_ok:
        return "duress"
    if normal_ok:
        return "normal"
    return None
