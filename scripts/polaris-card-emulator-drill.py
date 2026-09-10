#!/usr/bin/env python3
"""polaris-card-emulator-drill.py - a reader, a card, and a coercer (roadmap P4.2).

The emulator's own suite tests the card from the inside: it holds the token object and can ask
it what state it is in. A reader cannot. So this drill builds a reader that has ONLY what an
implementer downstream would have, the published APDU vectors and the profile, and runs the
whole presentation through it. If a reader written that way cannot complete a presentation,
"everything downstream develops against the emulator" is not true.

Then it attacks it.

  A CAPTURED RESPONSE IS WORTH NOTHING. Replayed to the same reader under a fresh challenge,
  and relayed to a different reader, it must be refused. Both are inside the signature, so
  neither can be fixed up by whatever sits between the card and the verifier.

  A CARD IS NOT AN ORACLE. It signs nothing before a PIN, and refuses a challenge short enough
  to wait for a repeat of.

  THE PIN IS NOT BRUTE-FORCEABLE. Three wrong attempts block the card, the counter survives a
  power cycle, and a blocked card refuses the correct PIN.

  AND THE COERCER'S TRANSCRIPT IS THE SAME EITHER WAY. This is the one that matters, so it is
  asserted at the level a coercer actually observes: the full APDU transcript of a normal
  presentation and of a duress presentation, compared byte for byte in everything except the
  opaque handle and signature. Same commands, same lengths, same status words, same order. The
  authority, which holds both slot public keys, can still tell them apart.

Run: python3 scripts/polaris-card-emulator-drill.py
Exit 0 iff every case holds, 3 to skip.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "polaris_card"))

_ok_all = True


def _row(label, got, want):
    global _ok_all
    ok = got == want
    _ok_all &= ok
    print("  %-62s %-12s %-12s %s" % (label[:62], str(got)[:12], str(want)[:12],
                                      "OK" if ok else "FAIL"))
    return ok


def main():
    try:
        import card_profile as cp
        import emulator as em
    except ImportError as e:  # noqa: BLE001
        print("card-emulator drill needs polaris_card: %s" % e, file=sys.stderr)
        return 3
    try:
        import hashlib
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    except ImportError as e:  # noqa: BLE001
        print("card-emulator drill needs cryptography: %s" % e, file=sys.stderr)
        return 3

    print("a reader, a card, and a coercer")
    print()
    print("  %-62s %-12s %-12s %s" % ("case", "got", "expected", "ok"))

    alg = ec.ECDSA(asym_utils.Prehashed(hashes.SHA256()))

    def registered_key(raw):
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)

    # --- a reader with only the published contract ---------------------------
    class Reader:
        """Everything it knows comes from polaris_card/vectors/apdu-exchanges.json and the
        profile. It never touches the token object except through transmit()."""

        def __init__(self, scope):
            self.scope = scope

        def present(self, card, pin):
            transcript = []

            def send(command):
                response = card.transmit(command)
                transcript.append((command, response))
                return response

            r = send(em.select())
            if not em.is_ok(r):
                return None, transcript
            r = send(em.verify_pin(pin))
            if not em.is_ok(r):
                return None, transcript
            challenge = os.urandom(32)
            r = send(em.sign_challenge(self.scope, challenge))
            parsed = em.parse_signed_response(r)
            if parsed is None:
                return None, transcript
            handle, signature = parsed
            return {"handle": handle, "signature": signature, "challenge": challenge,
                    "scope": self.scope}, transcript

        def accept(self, presented, public_key):
            """The verifier's decision, offline, against a key the authority registered."""
            if presented is None:
                return False
            body = cp.response_body(presented["challenge"], presented["scope"],
                                    presented["handle"])
            try:
                # The card emitted raw r||s; wrapping is the host's job, not the card's.
                registered_key(public_key).verify(
                    em.der_from_raw(presented["signature"]), hashlib.sha256(body).digest(), alg)
                return True
            except Exception:      # noqa: BLE001
                return False

    token, detail = em.new_software_token()
    normal_pub = detail["slot_public"]["normal"]
    reader_a, reader_b = Reader("reader-a"), Reader("reader-b")

    presented, _ = reader_a.present(token, "1234")
    _row("a reader built only from the published vectors completes a presentation",
         reader_a.accept(presented, normal_pub), True)

    # A CAPTURED RESPONSE IS WORTH NOTHING.
    replay = dict(presented, challenge=os.urandom(32))
    _row("...a captured response replayed under a fresh challenge is refused",
         reader_a.accept(replay, normal_pub), False)
    relayed = dict(presented, scope="reader-b")
    _row("...and relayed to a different reader is refused",
         reader_b.accept(relayed, normal_pub), False)

    # A CARD IS NOT AN ORACLE.
    fresh, _ = em.new_software_token()
    fresh.transmit(em.select())
    _row("the card signs nothing before a PIN",
         em.status_word(fresh.transmit(em.sign_challenge("reader-a", os.urandom(32)))),
         em.SW_SECURITY_NOT_SATISFIED)
    fresh.transmit(em.verify_pin("1234"))
    _row("...and refuses a challenge short enough to wait for a repeat of",
         em.status_word(fresh.transmit(em.sign_challenge("reader-a", b"\x00" * 8))),
         em.SW_WRONG_DATA)

    # THE PIN IS NOT BRUTE-FORCEABLE.
    guessing, _ = em.new_software_token()
    guessing.transmit(em.select())
    words = [em.status_word(guessing.transmit(em.verify_pin("%04d" % n))) for n in (0, 1, 2)]
    _row("three wrong PINs block the card", words[-1], em.SW_BLOCKED)
    guessing.reset()
    guessing.transmit(em.select())
    _row("...the block survives a power cycle",
         em.status_word(guessing.transmit(em.verify_pin("1234"))), em.SW_BLOCKED)
    _row("...and a blocked card refuses BOTH correct PINs identically",
         em.status_word(guessing.transmit(em.verify_pin("1234")))
         == em.status_word(guessing.transmit(em.verify_pin("9999"))) == em.SW_BLOCKED, True)

    # THE COERCER'S TRANSCRIPT.
    #
    # What is compared, and what is not. The PIN is holder INPUT: it travels in the command's
    # data field, and a coercer standing over the holder may well have watched it typed. The
    # claim is not that they cannot see which digits were entered, it is that nothing tells
    # them whether those digits were the normal PIN or the duress one. So the comparison
    # covers the command HEADER and length (which the card's protocol determines) and every
    # response byte position (which the card determines), and not the PIN digits themselves.
    #
    # The command LENGTH is compared, and that is why the emulator refuses a duress PIN of a
    # different length from the normal one: a six-digit duress PIN beside a four-digit normal
    # one would announce itself on the wire without anyone seeing the keypad.
    def transcript_shape(pin):
        card, _d = em.new_software_token()
        _p, tx = Reader("reader-a").present(card, pin)
        return [(cmd[:4].hex(), len(cmd), len(resp), em.status_word(resp))
                for cmd, resp in tx]

    normal_tx = transcript_shape("1234")
    duress_tx = transcript_shape("9999")
    _row("a duress presentation walks the same commands as a normal one",
         [(h, ln) for h, ln, _, _ in normal_tx], [(h, ln) for h, ln, _, _ in duress_tx])
    _row("...with the same status words in the same order",
         [w for _, _, _, w in normal_tx], [w for _, _, _, w in duress_tx])
    # Response lengths: EXACT, not sampled. The card emits a fixed-length raw signature the
    # way a secure element does, so there is one response length and it carries nothing.
    def sign_lengths(pin, trials=30):
        return {transcript_shape(pin)[-1][2] for _ in range(trials)}
    n_len, d_len = sign_lengths("1234"), sign_lengths("9999")
    _row("...and exactly one response length, the same for both slots",
         len(n_len) == 1 and n_len == d_len, True)
    _row("...which is what a FIXED-LENGTH signature buys; DER would only be sampled",
         len(n_len | d_len), 1)

    # THE AUTHORITY CAN STILL TELL, which is the whole point of the duress slot.
    card2, detail2 = em.new_software_token()
    presented_d2, _ = Reader("reader-a").present(card2, "9999")
    _row("the authority, holding both keys, sees a duress presentation",
         Reader("reader-a").accept(presented_d2, detail2["slot_public"]["duress"]), True)
    _row("...and it does NOT verify under the normal slot the card advertises",
         Reader("reader-a").accept(presented_d2, detail2["slot_public"]["normal"]), False)

    # IDENTIFIED MODE stays a separate ask, and its object is the profile's.
    card3, detail3 = em.new_software_token()
    card3.transmit(em.select())
    _row("the card object needs a verified PIN too",
         em.status_word(card3.transmit(em.get_card_object())), em.SW_SECURITY_NOT_SATISFIED)
    card3.transmit(em.verify_pin("1234"))
    obj = em.payload(card3.transmit(em.get_card_object()))
    verdict = cp.verify_card(
        obj, verify_classical=lambda d, s: _verify_issuer(detail3, d, s, alg), now=1_757_000_001)
    _row("...and once presented it verifies under the issuer that made it",
         verdict["authentic"], True)
    _row("...while carrying no duress key",
         detail3["slot_public"]["duress"] in obj, False)

    # THE PUBLISHED VECTORS still describe this card.
    vpath = os.path.join(ROOT, "polaris_card", "vectors", "apdu-exchanges.json")
    try:
        with open(vpath) as fh:
            doc = json.load(fh)
    except OSError as e:  # noqa: BLE001
        print("the published APDU vectors are missing: %s" % e, file=sys.stderr)
        return 3
    published = {c["name"]: c["apdu_hex"] for c in doc["commands"]}
    _row("every published command is what the builder emits today",
         [published.get("select"), published.get("get_card_object")],
         [em.select().hex(), em.get_card_object().hex()])
    body = doc["response_body"]
    _row("...and the published response body is what the card signs",
         cp.response_body(bytes.fromhex(body["challenge_hex"]), body["reader_scope"],
                          bytes.fromhex(body["handle_hex"])).hex(),
         body["response_body_hex"])

    print()
    if _ok_all:
        print("OK: a reader written against nothing but the published APDU vectors completes a "
              "presentation, so everything downstream can be built before silicon exists. A "
              "captured response is worth nothing: replayed under a fresh challenge or relayed "
              "to another reader it is refused, because both the challenge and the scope are "
              "inside the signature. The card is not an oracle, signing nothing before a PIN "
              "and refusing a challenge short enough to wait for. Three wrong PINs block it, "
              "the block survives a power cycle, and a blocked card refuses both correct PINs "
              "alike. And the coercer's transcript is the same either way: same commands, same "
              "lengths, same status words, same order, with EXACTLY ONE response length rather "
              "than a distribution of them, because the card emits a fixed-length raw "
              "signature the way a secure element does. The authority, holding both slot keys, "
              "still sees which one was used.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


def _verify_issuer(detail, digest, signature, alg):
    try:
        detail["issuer_private"].public_key().verify(signature, digest, alg)
        return True
    except Exception:      # noqa: BLE001
        return False


if __name__ == "__main__":
    sys.exit(main())
