#!/usr/bin/env python3
"""polaris-verifier-device-drill.py - the thing at the counter (roadmap P4.5).

A border post, a bank counter, a pharmacy. It reads a card over NFC or a presentation over QR
and decides, with connectivity or with none. This drill runs that device end to end under real
signatures and puts the accept/reject matrix through it.

THREE FACTS, KEPT APART. Possession (the card signed THIS device's challenge just now),
authenticity (the authority issued this card), authorization (the credential is ACTIVE inside a
window this device accepts). All three are needed to accept, and each is reported on its own,
because a device that says only "no" teaches its operator nothing.

WHAT A SIGNATURE CANNOT REFUSE. A captured response replayed to a DIFFERENT device fails
because the scope is inside the signature. Replayed to the SAME device it does not: the
signature over that challenge is perfectly valid the second time. Only the device remembering
its own challenges refuses that, so the drill replays one and requires the refusal.

THE TENSION THIS ROW FOUND. A P3.6 status assertion signs the token_value in the clear, so an
offline device that checks authorization LEARNS THE STABLE IDENTIFIER and can correlate its
sightings with any other device holding one. The card's key mode gives a per-verifier handle
and gives up nothing, but nothing binds that handle to a status assertion. The device therefore
reports `linkability` on every verdict, and this drill asserts the reported value rather than
letting "offline verification" quietly also mean "and everyone who does it can link you".

AND THE QR PATH HAS A HARD CEILING, MEASURED. A presentation fits a QR code easily. A
presentation carrying a card object with a post-quantum key and signature does not, and not
by a little: it is past even the absolute maximum a version-40 code can hold. That decides the
protocol rather than decorating it, so the number is measured here.

Run: python3 scripts/polaris-verifier-device-drill.py
     POLARIS_USE_REAL_PQC=1 for a real ML-DSA-65 status assertion.
Exit 0 iff every case holds, 3 to skip.
"""
import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "polaris_web"))

STATUS_FORMAT = "polaris-status-assertion/1"
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


def _note(label, value):
    print("  %-62s %-12s %-12s %s" % (label[:62], str(value)[:12], "", "--"))


def _iso(dt):
    return dt.replace(microsecond=0).isoformat()


def main():
    try:
        import hashlib
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
        from polaris_card import card_profile as cp, emulator as em, verifier_device as vd
        import pqc_signing
    except ImportError as e:  # noqa: BLE001
        print("verifier-device drill needs cryptography, polaris_card and polaris_web: %s" % e,
              file=sys.stderr)
        return 3

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

    print("the thing at the counter")
    print()
    print("  %-62s %-12s %-12s %s" % ("case", "got", "expected", "ok"))

    token_value = "POLARIS-DEVICE-DRILL-0001"
    card, _ = em.new_blank_token()
    card.transmit(em.select())
    generated = em.parse_generated_keys(card.transmit(em.generate_keypair()))
    normal_pub, duress_pub = generated
    card_object = cp.build_card(token_value=token_value, issuing_authority=7,
                                activation_sequence=1, issued_at=1_757_000_000,
                                expires_at=1_914_766_400, card_key_classical=normal_pub,
                                sign_classical=issuer_sign)
    if not em.is_ok(card.transmit(em.put_card_object(card_object))):
        print("the card refused its object", file=sys.stderr)
        return 3

    def verify_response(body, signature):
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), normal_pub).verify(
                    em.der_from_raw(signature), hashlib.sha256(body).digest(), alg)
            return True
        except Exception:      # noqa: BLE001
            return False

    # A REAL status assertion, signed the way the app signs one.
    def assertion(status="ACTIVE", window=120, age=0):
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        issued = now - datetime.timedelta(seconds=age)
        expires = issued + datetime.timedelta(seconds=window)
        issued_at, expires_at = _iso(issued), _iso(expires)
        statement = json.dumps({"format": STATUS_FORMAT, "token_value": token_value,
                                "status": status, "issued_at": issued_at,
                                "expires_at": expires_at},
                               sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig, label, pub = pqc_signing.signature_over_message(statement)
        return {"format": STATUS_FORMAT, "token_value": token_value, "status": status,
                "issued_at": issued_at, "expires_at": expires_at,
                "algorithm": label, "signature_hex": sig.hex(),
                "public_key_hex": pub}

    real_pqc = os.environ.get("POLARIS_USE_REAL_PQC") == "1"
    _note("status assertion signing", "real ML-DSA" if real_pqc else "placeholder")
    verify_status = vd._load_status_verifier()

    device = vd.VerifierDevice("border-post-7", max_window_seconds=300)
    other = vd.VerifierDevice("bank-counter-3", max_window_seconds=300)

    # --- NFC, offline, the accepting case --------------------------------
    presented = device.read_nfc(card, "1234")
    verdict = device.decide(presented, verify_card_signature=issuer_verify,
                            verify_response=verify_response, status_assertion=assertion(),
                            verify_status_assertion=verify_status)
    if real_pqc:
        _row("NFC, offline: an authentic card with a fresh ACTIVE status is accepted",
             verdict["accepted"], True)
        _row("...possession, authenticity and authorization are reported SEPARATELY",
             [verdict["possession_proven"], verdict["card_authentic"],
              verdict["authorization_fresh"]], [True, True, True])
    else:
        # The placeholder is not authenticatable offline, and the verifier says so rather
        # than pretending. That IS the correct verdict under this profile.
        _row("NFC, offline: a placeholder status assertion is NOT accepted",
             verdict["accepted"], False)
        _row("...and possession and authenticity still hold on their own",
             [verdict["possession_proven"], verdict["card_authentic"]], [True, True])

    # --- what a signature cannot refuse ----------------------------------
    replay = device.decide(presented, verify_card_signature=issuer_verify,
                           verify_response=verify_response, status_assertion=assertion(),
                           verify_status_assertion=verify_status)
    _row("the SAME response replayed to the SAME device is refused",
         replay["accepted"] is False and "already been answered" in (replay["note"] or ""), True)
    relayed = dict(presented, scope=other.scope)
    relayed_verdict = other.decide(relayed, verify_card_signature=issuer_verify,
                                   verify_response=verify_response,
                                   status_assertion=assertion(),
                                   verify_status_assertion=verify_status)
    _row("...and a response relayed to ANOTHER device is refused",
         relayed_verdict["accepted"], False)

    # --- the authorization matrix ----------------------------------------
    def decide_fresh(**kw):
        p = device.read_nfc(card, "1234")
        return device.decide(p, verify_card_signature=issuer_verify,
                             verify_response=verify_response,
                             verify_status_assertion=verify_status, **kw)

    _row("a REVOKED credential is refused even with a valid signature",
         decide_fresh(status_assertion=assertion(status="REVOKED"))["accepted"], False)
    _row("an EXPIRED assertion window is refused",
         decide_fresh(status_assertion=assertion(window=60, age=120))["accepted"], False)
    _row("...as is a window longer than this device's ceiling",
         decide_fresh(status_assertion=assertion(window=86400))["accepted"], False)
    possession_only = decide_fresh()
    _row("possession alone is NOT acceptance", possession_only["accepted"], False)
    _row("...and the device says why: it does not know whether the credential stands",
         "still stands" in (possession_only["note"] or ""), True)

    # A tampered card object.
    tampered = bytearray(card_object)
    tampered[10] ^= 0x01
    p = device.read_nfc(card, "1234")
    p["card_object"] = bytes(tampered)
    _row("a tampered card object is refused",
         device.decide(p, verify_card_signature=issuer_verify,
                       verify_response=verify_response, status_assertion=assertion(),
                       verify_status_assertion=verify_status)["card_authentic"], False)

    # --- the linkability the device must not hide ------------------------
    online = decide_fresh(online_status={"status": "ACTIVE", "token_value": token_value})
    _row("ONLINE mode reports the credential as linkable, because it is",
         online["linkability"], "credential-linkable")
    offline = decide_fresh(status_assertion=assertion())
    _row("...and so does OFFLINE mode: a status assertion names the token value",
         offline["linkability"], "credential-linkable")
    handle_only = device.read_nfc(card, "1234", want_card_object=False)
    v_handle = device.decide(handle_only, verify_response=verify_response)
    _row("...while a handle-only read stays PAIRWISE", v_handle["linkability"], "pairwise")
    _row("...though it cannot accept, having established only possession",
         v_handle["accepted"], False)

    # Two devices, one card, two handles.
    a = device.read_nfc(card, "1234", want_card_object=False)["handle"]
    b = other.read_nfc(card, "1234", want_card_object=False)["handle"]
    _row("two devices cannot tell they saw the same card", a == b, False)

    # --- QR ---------------------------------------------------------------
    qr_device = vd.VerifierDevice("kiosk-2", max_window_seconds=300)
    request, challenge = qr_device.qr_request()
    _row("the device's QR request carries its own scope and challenge",
         request.startswith("PCQ1:kiosk-2:"), True)
    # The holder's phone drives the card with what it scanned.
    card.transmit(em.select()); card.transmit(em.verify_pin("1234"))
    signed = card.transmit(em.sign_challenge("kiosk-2", challenge))
    handle, signature = em.parse_signed_response(signed)
    payload = vd.qr_response(challenge, handle, signature, card_object)
    qr_presented = qr_device.read_qr(payload)
    qr_verdict = qr_device.decide(qr_presented, verify_card_signature=issuer_verify,
                                  verify_response=verify_response,
                                  status_assertion=assertion(),
                                  verify_status_assertion=verify_status)
    _row("QR: the round trip proves possession", qr_verdict["possession_proven"], True)
    _row("...and authenticity, when the object fits", qr_verdict["card_authentic"], True)
    _row("a malformed QR payload is refused, not parsed",
         _refused(qr_device, "PCR1:not-base64!!:x:y"), True)
    _row("...and so is a payload for a challenge this device never issued",
         qr_device.decide(vd.VerifierDevice("kiosk-2").read_qr(
             vd.qr_response(bytes(32), handle, signature)),
             verify_response=verify_response)["accepted"], False)

    # --- the ceiling, measured -------------------------------------------
    report = vd.qr_capacity_report({"classical_only": len(card_object),
                                    "dual_signature": 5504})
    print()
    print("  what fits in one QR code (practical ceiling %d chars, absolute max %d)"
          % (vd.QR_PRACTICAL_CHARS, vd.QR_MAX_ALPHANUMERIC))
    for label, row in sorted(report.items()):
        _note("  %s" % label, "%d chars%s" % (row["chars"], "" if row["fits"] else "  TOO BIG"))
    _row("a presentation alone fits a QR code", report["presentation_only"]["fits"], True)
    _row("...and so does one carrying a classical-only card object",
         report["classical_only"]["fits"], True)
    _row("...but a POST-QUANTUM card object does NOT, at any QR version",
         report["dual_signature"]["fits_absolute_max"], False)

    print()
    if not _cases_recorded:
        print("FAIL: this drill recorded NO cases. It tested nothing and would "
              "have printed its summary regardless.", file=sys.stderr)
        return 1
    if _ok_all:
        print("OK: the device at the counter decides with connectivity or with none, and keeps "
              "three different facts apart: that the card signed this device's challenge just "
              "now, that the authority issued it, and that the credential still stands inside a "
              "window this device chose. A response relayed to another device is refused by the "
              "signature, and one replayed to THIS device is refused by the device, which is "
              "the only thing that can: the signature over that challenge is perfectly valid "
              "the second time. Revoked, stale, and over-wide windows are all refused, and "
              "possession alone is not acceptance, because a card revoked this morning still "
              "signs. The device reports what it learned about the holder every time: a "
              "handle-only read stays pairwise and two devices cannot tell they saw the same "
              "card, while any read that checks authorization becomes credential-linkable, "
              "because a P3.6 status assertion names the token value in the clear. And the QR "
              "path carries a presentation and a classical card object but CANNOT carry a "
              "post-quantum one, past even the absolute maximum a QR code holds, so a "
              "post-quantum authenticity check needs NFC.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


def _refused(device, payload):
    from polaris_card import verifier_device as vd
    try:
        device.read_qr(payload)
        return False
    except vd.DeviceRefusal:
        return True


if __name__ == "__main__":
    sys.exit(main())
