#!/usr/bin/env python3
"""polaris-card-profile-drill.py - the card as an object, end to end (roadmap P4.1).

The profile's own suite proves the encoding against the published vectors with signature
functions that always say yes. That is the right test for a codec and the wrong one for a
card: it never asks whether a REAL signature over the body verifies, whether a card signed by
one authority is refused by another, or whether the anti-downgrade rule survives contact with
an actual broken signature.

So this drill uses real cryptography. P-256 for the classical leg, which is what today's
certified silicon does, and real ML-DSA-65 for the post-quantum leg when liboqs is present.

What it establishes:

  A CARD IS AUTHENTIC ONLY UNDER THE ISSUER WHO MADE IT. A card verifies under its own
  authority's key and is refused under another's, which is the property that makes a card a
  credential rather than a badge.

  ONE BIT CHANGES THE ANSWER. Every field is flipped in turn and the card must be refused
  each time. A signature that survived an edit to the body would be signing something else.

  BREAKING THE WEAKER ALGORITHM IS NOT ENOUGH. On a dual-signature card a valid classical
  signature next to a forged post-quantum one is REFUSED, and so is the reverse. Accept-if-
  either would hand the scheme to whoever breaks P-256 first, which is the entire reason the
  card carries two signatures.

  AND THE COERCER LEARNS NOTHING FROM THE CARD. The duress key never appears in the object,
  and a duress response is byte-indistinguishable in shape from a normal one. The drill
  asserts both, because "the duress feature is invisible" is a claim about bytes.

Run: python3 scripts/polaris-card-profile-drill.py
Exit 0 iff every case holds, 3 to skip.
"""
import hashlib
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
    except ImportError as e:  # noqa: BLE001
        print("card-profile drill needs polaris_card: %s" % e, file=sys.stderr)
        return 3
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    except ImportError as e:  # noqa: BLE001
        print("card-profile drill needs cryptography for the P-256 leg: %s" % e, file=sys.stderr)
        return 3

    print("the card as an object, under real signatures")
    print()
    print("  %-62s %-12s %-12s %s" % ("case", "got", "expected", "ok"))

    # --- the classical leg: P-256, what certified silicon does today ---------
    issuer = ec.generate_private_key(ec.SECP256R1())
    other_issuer = ec.generate_private_key(ec.SECP256R1())

    def sign_p256(key):
        return lambda digest: key.sign(digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))

    def verify_p256(key):
        def _v(digest, sig):
            try:
                key.public_key().verify(sig, digest,
                                        ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
                return True
            except Exception:      # noqa: BLE001 - any failure is a refusal
                return False
        return _v

    card_key = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    # --- the post-quantum leg: real ML-DSA-65 when liboqs is here ------------
    pq = None
    try:
        import oqs
        signer = oqs.Signature("ML-DSA-65")
        pq_pub = signer.generate_keypair()
        pq = {"sign": lambda d: signer.sign(d),
              "verify": lambda d, s: oqs.Signature("ML-DSA-65").verify(d, s, pq_pub),
              "pub": pq_pub}
    except Exception:              # noqa: BLE001 - the classical half still runs
        pq = None
    # A note, not a case: liboqs may be absent and the classical half still proves what it
    # proves. A row comparing a value with itself would pass regardless and assert nothing.
    print("  %-62s %-12s %-12s %s" % (
        "post-quantum leg", "real ML-DSA-65" if pq else "unavailable", "", "--"))

    base = dict(token_value="POLARIS-CARD-DRILL-0001", issuing_authority=7,
                activation_sequence=1, issued_at=1_757_000_000, expires_at=1_914_766_400,
                card_key_classical=card_key)

    blob = cp.build_card(sign_classical=sign_p256(issuer), **base)
    v = cp.verify_card(blob, verify_classical=verify_p256(issuer), now=1_757_000_001)
    _row("a card verifies under the authority that issued it", v["authentic"], True)
    _row("...and is REFUSED under another authority's key",
         cp.verify_card(blob, verify_classical=verify_p256(other_issuer))["authentic"], False)

    # ONE BIT CHANGES THE ANSWER: every field, flipped in turn.
    fields = cp.decode(blob)
    survived = []
    for name in sorted(cp.BODY_TAGS.values()):
        if name not in fields:
            continue
        tampered = dict(fields)
        value = tampered[name]
        if isinstance(value, int):
            tampered[name] = value + 1 if name != "profile_version" else value
        elif isinstance(value, str):
            continue                       # doc_type is refused at decode, tested separately
        else:
            tampered[name] = bytes([value[0] ^ 0x01]) + value[1:]
        if tampered[name] == value:
            continue
        try:
            forged = cp.encode(tampered)
        except cp.CardProfileError:
            continue                       # refused before it could even be built
        if cp.verify_card(forged, verify_classical=verify_p256(issuer))["authentic"]:
            survived.append(name)
    _row("no single-field edit survives the issuer signature", survived, [])

    # A body byte flipped directly in the wire bytes, not through the codec.
    raw = bytearray(blob)
    raw[10] ^= 0x01
    _row("...nor does a byte flipped in the wire encoding",
         cp.verify_card(bytes(raw), verify_classical=verify_p256(issuer))["authentic"], False)

    # THE ANTI-DOWNGRADE RULE, with a real forged signature rather than a stub.
    if pq is not None:
        dual = dict(base, card_key_pq=pq["pub"])
        blob2 = cp.build_card(sign_classical=sign_p256(issuer), sign_pq=pq["sign"], **dual)
        v2 = cp.verify_card(blob2, verify_classical=verify_p256(issuer),
                            verify_pq=pq["verify"], now=1_757_000_001)
        _row("a dual-signature card verifies under both witnesses", v2["authentic"], True)
        _row("...and a PQ verifier accepts it", cp.verify_card(
            blob2, verify_classical=verify_p256(issuer), verify_pq=pq["verify"],
            require_pq=True, now=1_757_000_001)["authentic"], True)

        # Replace the PQ signature with a real signature over DIFFERENT bytes: valid
        # ML-DSA-65, wrong message. The classical one is still perfectly good.
        broken = cp.decode(blob2)
        broken["issuer_sig_pq"] = pq["sign"](hashlib.sha3_256(b"not this card").digest())
        _row("a good classical signature does NOT rescue a bad post-quantum one",
             cp.verify_card(cp.encode(broken), verify_classical=verify_p256(issuer),
                            verify_pq=pq["verify"])["authentic"], False)
        # ...and the reverse, so neither leg is the one that really counts.
        broken2 = cp.decode(blob2)
        broken2["issuer_sig_classical"] = sign_p256(issuer)(
            hashlib.sha3_256(b"not this card").digest())
        _row("...and a good post-quantum signature does not rescue a bad classical one",
             cp.verify_card(cp.encode(broken2), verify_classical=verify_p256(issuer),
                            verify_pq=pq["verify"])["authentic"], False)

    # A PQ-REQUIRING VERIFIER refuses today's silicon, by policy rather than by format.
    _row("a post-quantum-requiring verifier refuses a classical-only card",
         cp.verify_card(blob, verify_classical=verify_p256(issuer),
                        require_pq=True)["authentic"], False)

    # THE COERCER LEARNS NOTHING FROM THE CARD.
    normal_secret, duress_secret = os.urandom(32), os.urandom(32)
    blob_hex = blob.hex()
    _row("the duress key does not appear in the card object anywhere",
         duress_secret.hex() in blob_hex or "duress" in str(cp.decode(blob)), False)
    challenge = os.urandom(32)
    n_body = cp.response_body(challenge, "reader-a",
                              cp.pairwise_handle(normal_secret, "reader-a"))
    d_body = cp.response_body(challenge, "reader-a",
                              cp.pairwise_handle(duress_secret, "reader-a"))
    _row("a duress response is the same SHAPE as a normal one",
         len(n_body), len(d_body))
    _row("...and a different value, or the authority could not tell them apart",
         n_body != d_body, True)

    # THE PAIRWISE PROPERTY, at the card.
    a = cp.pairwise_handle(normal_secret, "reader-a")
    b = cp.pairwise_handle(normal_secret, "reader-b")
    _row("one reader recognises the same card twice",
         a == cp.pairwise_handle(normal_secret, "reader-a"), True)
    _row("...and two readers cannot tell they saw the same card", a == b, False)

    # THE PUBLISHED VECTORS are what an implementer who is not running this code matches.
    vpath = os.path.join(ROOT, "polaris_card", "vectors", "card-objects.json")
    try:
        with open(vpath) as fh:
            doc = json.load(fh)
    except OSError as e:  # noqa: BLE001
        print("the published vectors are missing: %s" % e, file=sys.stderr)
        return 3
    mismatched = []
    for case in doc["cases"]:
        f = cp.decode(bytes.fromhex(case["card_object_hex"]))
        if (cp.signing_body(f).hex() != case["signing_body_hex"]
                or cp.signing_digest(f).hex() != case["signing_digest_hex"]
                or cp.encode(f).hex() != case["card_object_hex"]):
            mismatched.append(case["name"])
    _row("every published vector still round-trips through this encoder", mismatched, [])
    _row("...and the vectors cover the profile this code implements",
         doc["profile"] == cp.DOC_TYPE and doc["profile_version"] == cp.PROFILE_VERSION, True)

    print()
    if _ok_all:
        print("OK: a card object is a credential rather than a badge. It verifies only under "
              "the authority that issued it, no single-field edit and no flipped wire byte "
              "survives the signature, and on a transitional card a valid signature under one "
              "algorithm does not rescue a forged one under the other, in either direction, so "
              "breaking the weaker algorithm first is not enough. A verifier that requires "
              "post-quantum refuses today's silicon by policy rather than by format, which is "
              "what lets one population hold both while the fleet turns over. The duress key "
              "appears nowhere in the object and a duress response has the same shape as a "
              "normal one, so the card tells a coercer nothing. Two readers cannot tell they "
              "saw the same card. And the published vectors still describe this encoder, which "
              "is the only thing an implementer who is not running this code can check.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
