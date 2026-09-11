#!/usr/bin/env python3
"""polaris-personalization-drill.py - a record becomes an object (roadmap P4.3).

Personalization is the only step where the authority's signature is applied to something that
then leaves its control. Everything after it is downstream of whether this step was done
right, and there is no recall.

What this establishes, against a real database and a real card:

  THE PRIVATE KEY NEVER LEAVES THE CARD, AND THAT IS STRUCTURAL. The card generates its own
  keypairs and hands back only the public halves. The drill asserts that the private key the
  card kept appears NOWHERE in what personalization produced or recorded: not in the returned
  object, not in the card object, not in the audit-of-record row. An injected key would have
  existed on the personalization host first, and the authority could only assert that it was
  destroyed; a generated one has no such history to assert about.

  EVERY PERSONALIZATION IS AN AUDIT-OF-RECORD EVENT, AND THE RECORD CANNOT BE EDITED. One
  append-only row. The drill tries an UPDATE and a DELETE against it and both must be refused
  by the database rather than by the application.

  A CARD IS PERSONALIZED ONCE, AND A CREDENTIAL GETS ONE CARD. The card refuses a second
  GENERATE KEYPAIR and a second PUT CARD OBJECT for the life of the part; the database refuses
  a second row for the same credential. Two live cards answering for one credential is a
  revocation that only half works.

  ONLY AN ACTIVE CREDENTIAL IS PERSONALIZED. A revoked one is refused, because a signed object
  for something the authority has withdrawn is exactly what should not be in the world.

  EVERY CARD CARRIES A DURESS SLOT. Whether or not the holder ever enrolls a duress PIN. If a
  duress slot only existed when one was wanted, its presence in the authority's records would
  be a fact about the holder.

  AND THE CARD WORKS AFTERWARDS. The whole point: present the personalized card and have the
  authority resolve which slot signed, from the keys this flow recorded.

The drill builds and drops its OWN database. It could have cleaned up after itself in the
shared one, but the only way to delete a CardPersonalization row is to turn off the append-only
trigger, and a drill that disables the audit-of-record to tidy up is teaching the exact habit
it exists to forbid.

Run: POLARIS_DB_HOST=localhost POLARIS_DB_USER=vanta python3 scripts/polaris-personalization-drill.py
Exit 0 iff every case holds, 3 to skip.
"""
import glob
import hashlib
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SQL = os.path.join(ROOT, "polaris_sql")
sys.path.insert(0, ROOT)

DB = os.environ.get("POLARIS_PZ_DB", "polaris_pz_drill")

_ok_all = True


#: Cases this drill actually recorded. A drill whose cases are removed or
#: short-circuited in a refactor prints its whole summary and exits 0 anyway,
#: which is a guarantee reported by something that tested nothing (v9.403).
_cases_recorded = 0


def _row(label, got, want):
    global _cases_recorded
    _cases_recorded += 1
    global _ok_all
    ok = got == want
    _ok_all &= ok
    print("  %-62s %-12s %-12s %s" % (label[:62], str(got)[:12], str(want)[:12],
                                      "OK" if ok else "FAIL"))
    return ok


def main():
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
        from polaris_card import card_profile as cp, emulator as em, personalization as pz
    except ImportError as e:  # noqa: BLE001
        print("personalization drill needs psycopg2, cryptography and polaris_card: %s" % e,
              file=sys.stderr)
        return 3
    env = dict(os.environ)
    env.setdefault("PGHOST", env.get("POLARIS_DB_HOST", "localhost"))
    env.setdefault("PGPORT", env.get("POLARIS_DB_PORT", "5432"))
    env.setdefault("PGUSER", env.get("POLARIS_DB_USER", "postgres"))
    if env.get("POLARIS_DB_PASSWORD"):
        env.setdefault("PGPASSWORD", env["POLARIS_DB_PASSWORD"])
    if any(subprocess.run(["which", p_], capture_output=True).returncode != 0
           for p_ in ("psql", "createdb", "dropdb")):
        print("personalization drill needs psql/createdb/dropdb on PATH", file=sys.stderr)
        return 3
    subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)
    made = subprocess.run(["createdb", DB], env=env, capture_output=True, text=True)
    if made.returncode != 0:
        print("personalization drill needs a database it can create: %s"
              % made.stderr.strip(), file=sys.stderr)
        return 3
    for f in ["00_load_all.sql"] + sorted(glob.glob(os.path.join(SQL, "migrations", "*.up.sql"))):
        loaded = subprocess.run(["psql", "-v", "ON_ERROR_STOP=1", "-q", "-d", DB, "-f", f],
                                cwd=SQL, env=env, capture_output=True, text=True)
        if loaded.returncode != 0:
            subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)
            print("loading %s failed: %s" % (os.path.basename(f), loaded.stderr[-500:]),
                  file=sys.stderr)
            return 3
    cfg = {"host": env["PGHOST"], "port": env["PGPORT"], "dbname": DB, "user": env["PGUSER"]}
    if env.get("PGPASSWORD"):
        cfg["password"] = env["PGPASSWORD"]
    conn = psycopg2.connect(cursor_factory=RealDictCursor, **cfg)

    alg = ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()))
    issuer = ec.generate_private_key(ec.SECP256R1())

    def issuer_sign(digest):
        return issuer.sign(digest, alg)

    def issuer_verify(digest, signature):
        try:
            issuer.public_key().verify(signature, digest, alg)
            return True
        except Exception:      # noqa: BLE001
            return False

    print("a record becomes an object")
    print()
    print("  %-62s %-12s %-12s %s" % ("case", "got", "expected", "ok"))
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT token_id FROM IdentityToken t WHERE t.status = 'ACTIVE' "
                        "AND NOT EXISTS (SELECT 1 FROM CardPersonalization c "
                        "WHERE c.token_id = t.token_id) ORDER BY token_id LIMIT 2")
            free = [r["token_id"] for r in cur.fetchall()]
            cur.execute("SELECT token_id FROM IdentityToken WHERE status <> 'ACTIVE' "
                        "ORDER BY token_id LIMIT 1")
            inactive = cur.fetchone()
        if len(free) < 1:
            print("the loaded schema holds no ACTIVE credential to personalize", file=sys.stderr)
            return 3
        token_id = free[0]

        card, kept = em.new_blank_token()
        card.transmit(em.select())
        _row("a card arrives blank, with nothing to present", card.state, em.STATE_BLANK)
        _row("...and a blank card refuses to sign even after a PIN",
             em.status_word(card.transmit(em.verify_pin("1234"))) == em.SW_OK
             and em.status_word(card.transmit(em.sign_challenge("r-a", b"\x00" * 32)))
             == em.SW_CONDITIONS_NOT_SATISFIED, True)

        result = pz.personalize(conn, token_id, card, issuer_sign=issuer_sign,
                                issuer_verify=issuer_verify)
        _row("personalizing it writes one audit-of-record row",
             result["personalization_id"] > 0, True)
        _row("...and the card is now personalized", card.state, em.STATE_PERSONALIZED)

        # THE PRIVATE KEY NEVER LEAVES THE CARD.
        private_bytes = kept["normal"].private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        secret_scalar = kept["normal"].private_numbers().private_value.to_bytes(32, "big")
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM CardPersonalization WHERE token_id = %s", (token_id,))
            recorded = cur.fetchone()
        haystacks = {
            "the card object": result["card_object"],
            "what personalization returned": repr(result).encode(),
            "the audit-of-record row": b"".join(
                bytes(v) if isinstance(v, (bytes, bytearray, memoryview)) else str(v).encode()
                for v in recorded.values()),
        }
        leaked = [name for name, blob in haystacks.items()
                  if secret_scalar in blob or private_bytes in blob]
        _row("the private key the card kept appears in NOTHING it produced", leaked, [])
        _row("...and personalization has no parameter to inject one through",
             "private" in str(pz.personalize.__code__.co_varnames), False)

        # THE RECORD CANNOT BE EDITED.
        def refused(sql, params):
            try:
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                conn.rollback()
                return False
            except psycopg2.Error:
                conn.rollback()
                return True
        _row("the audit-of-record row cannot be UPDATEd",
             refused("UPDATE CardPersonalization SET personalized_by = NULL WHERE token_id = %s",
                     (token_id,)), True)
        _row("...nor DELETEd", refused("DELETE FROM CardPersonalization WHERE token_id = %s",
                                       (token_id,)), True)

        # A CARD IS PERSONALIZED ONCE.
        _row("the card refuses a second GENERATE KEYPAIR",
             em.status_word(card.transmit(em.generate_keypair())), em.SW_ALREADY_PERSONALIZED)
        _row("...and a second PUT CARD OBJECT",
             em.status_word(card.transmit(em.put_card_object(result["card_object"]))),
             em.SW_ALREADY_PERSONALIZED)

        # A CREDENTIAL GETS ONE CARD.
        second, _ = em.new_blank_token()
        second.transmit(em.select())
        try:
            pz.personalize(conn, token_id, second, issuer_sign=issuer_sign)
            second_refused = False
        except pz.PersonalizationRefused:
            second_refused = True
        _row("a second card for the same credential is refused", second_refused, True)
        _row("...and the second card was never personalized", second.state, em.STATE_BLANK)

        # ONLY AN ACTIVE CREDENTIAL.
        if inactive is not None:
            third, _ = em.new_blank_token()
            third.transmit(em.select())
            try:
                pz.personalize(conn, inactive["token_id"], third, issuer_sign=issuer_sign)
                inactive_refused = False
            except pz.PersonalizationRefused:
                inactive_refused = True
            _row("a credential that is not ACTIVE is refused", inactive_refused, True)

        # EVERY CARD CARRIES A DURESS SLOT, and it is not on the card.
        _row("the record carries a duress slot for this card",
             len(bytes(recorded["duress_public_key"])) > 0, True)
        _row("...which differs from the normal slot",
             bytes(recorded["duress_public_key"]) == bytes(recorded["normal_public_key"]), False)
        _row("...and does NOT appear in the card object itself",
             bytes(recorded["duress_public_key"]) in result["card_object"], False)
        _row("the recorded digest is the card object's",
             bytes(recorded["card_object_sha3_256"]),
             hashlib.sha3_256(result["card_object"]).digest())
        _row("...and the recorded reference is not the credential value",
             len(bytes(recorded["credential_ref"])), 32)

        # AND THE CARD WORKS AFTERWARDS.
        def present(pin, scope="reader-a"):
            card.transmit(em.select())
            card.transmit(em.verify_pin(pin))
            challenge = os.urandom(32)
            handle, sig = em.parse_signed_response(card.transmit(em.sign_challenge(scope, challenge)))
            body = cp.response_body(challenge, scope, handle)
            return hashlib.sha256(body).digest(), sig

        def slot_of(pin):
            digest, sig = present(pin)

            def verify(public_key):
                try:
                    ec.EllipticCurvePublicKey.from_encoded_point(
                        ec.SECP256R1(), public_key).verify(em.der_from_raw(sig), digest, alg)
                    return True
                except Exception:      # noqa: BLE001
                    return False
            return pz.slot_for_presentation(conn, token_id, verify)

        _row("the personalized card presents, and the authority sees the normal slot",
             slot_of("1234"), "normal")
        _row("...and sees the DURESS slot when that PIN was used", slot_of("9999"), "duress")
        card.transmit(em.select()); card.transmit(em.verify_pin("1234"))
        obj = em.payload(card.transmit(em.get_card_object()))
        _row("...and the object it hands over verifies under the issuer that made it",
             cp.verify_card(obj, verify_classical=issuer_verify,
                            now=1_757_000_001)["authentic"], True)

        print()
        if not _cases_recorded:
            print("FAIL: this drill recorded NO cases. It tested nothing and would "
                  "have printed its summary regardless.", file=sys.stderr)
            return 1
        if _ok_all:
            print("OK: a record becomes an object without the authority ever holding the key "
                  "that makes the object answer. The card generates its own pair and the "
                  "private half appears in nothing personalization produced, recorded or "
                  "returned, and there is no parameter through which one could be injected: "
                  "'the private key never left the card' is a fact about where it was made "
                  "rather than a promise about what was deleted. The personalization is one "
                  "append-only row the database will not let anyone edit or remove. The card "
                  "refuses a second personalization for the life of the part and the database "
                  "refuses a second card for the credential, so a revocation cannot half work. "
                  "A withdrawn credential is refused. Every card carries a duress slot recorded "
                  "beside the normal one and absent from the card itself, so its existence is a "
                  "fact about the system rather than about the holder. And the card presents "
                  "afterwards, with the authority resolving which slot signed from the keys "
                  "this flow wrote down.")
            return 0
        print("FAIL: at least one case did not hold", file=sys.stderr)
        return 1
    finally:
        conn.close()
        subprocess.run(["dropdb", "--if-exists", DB], env=env, capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
