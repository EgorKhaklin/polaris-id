"""polaris_card/verifier_device.py - the reference verifier device (roadmap P4.5).

What a border post, a bank counter or a pharmacy actually runs. It reads a card over NFC or a
presentation over QR, and decides, online or with no connectivity at all.

THREE DIFFERENT FACTS, KEPT APART. A verdict that collapses them is a verdict somebody acts on
without knowing what was checked:

  POSSESSION. The holder's card signed this device's challenge just now. Establishes that the
  card is present, and nothing else.
  AUTHENTICITY. The card object carries the issuing authority's signature. Establishes that the
  authority issued this card, and says nothing about whether it still stands.
  AUTHORIZATION. The credential is ACTIVE as of an instant inside a window the device accepts.
  This is the one that changes after issuance, and the only one that can go stale.

All three are required to accept. They are reported separately because a device that says only
"accepted" teaches its operator nothing about what a failure meant.

THE TENSION THIS ROW FOUND, AND DOES NOT HIDE. A status assertion (P3.6) signs the
`token_value` in the clear, because that is what binds it to a credential. So an offline device
that checks authorization LEARNS THE STABLE IDENTIFIER, and two such devices can tell they saw
the same person. The card's key mode gives a per-verifier pairwise handle and gives up nothing,
but nothing binds that handle to a status assertion, so a device using it alone cannot check
authorization offline.

The device therefore reports `linkability` on every verdict, as one of:

  "pairwise"            the device learned only a handle scoped to itself
  "credential-linkable" the device learned a stable credential identifier, so it can correlate
                        its own sightings with any other device holding the same
  "unknown"             nothing was established

That is a property of the P3.6 protocol, not of this file, and closing it means a status
assertion keyed to something other than the token value. Reporting it is what stops "offline
verification" from quietly meaning "offline verification, and by the way everyone who does it
can now link you".

See docs/design/verifier-device.md.
"""
from __future__ import annotations

import base64
import os
import secrets

try:
    from polaris_card import card_profile as cp, emulator as em   # type: ignore
except ImportError:                      # pragma: no cover - the flat layout
    import card_profile as cp            # type: ignore
    import emulator as em                # type: ignore

CHALLENGE_BYTES = 32
QR_REQUEST_PREFIX = "PCQ1"               # device to holder: scope and challenge
QR_RESPONSE_PREFIX = "PCR1"              # holder to device: handle, signature, card object

# A QR code holds at most 2,953 bytes of binary or 4,296 alphanumeric characters, at version 40
# with the lowest error correction, which is already past what a phone screen renders and a
# handheld scanner reads reliably. The number matters: see `qr_capacity_report`.
QR_MAX_ALPHANUMERIC = 4296
QR_PRACTICAL_CHARS = 1800                # what a phone renders and a scanner reads in one go


class DeviceRefusal(Exception):
    """The device refused to proceed. Distinct from a verdict of not-accepted: this means the
    exchange itself was malformed or replayed, and no verdict was reached."""


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


class VerifierDevice:
    """One device, one scope. The scope is what makes its pairwise handles its own."""

    def __init__(self, scope: str, *, max_window_seconds: int | None = 300,
                 require_pq: bool = False):
        if not scope:
            raise ValueError("a device must have a scope, or its handles are nobody's")
        self.scope = scope
        self.max_window_seconds = max_window_seconds
        self.require_pq = require_pq
        self._open: set[bytes] = set()
        self._spent: set[bytes] = set()

    # -- the challenge ----------------------------------------------------
    def challenge(self) -> bytes:
        """A fresh challenge, remembered until it is used exactly once.

        The signature binds the challenge, which stops a captured response being replayed to a
        DIFFERENT device. Retiring it here is what stops one being replayed to THIS device,
        which the signature cannot help with because the signature over that challenge is
        perfectly valid the second time."""
        c = secrets.token_bytes(CHALLENGE_BYTES)
        self._open.add(c)
        return c

    def _retire(self, challenge: bytes):
        if challenge in self._spent:
            raise DeviceRefusal(
                "this challenge has already been answered. The signature over it is still "
                "valid, which is exactly why the device has to remember: a replay to the same "
                "device is not something a signature can refuse")
        if challenge not in self._open:
            raise DeviceRefusal("this device did not issue that challenge")
        self._open.discard(challenge)
        self._spent.add(challenge)

    # -- NFC --------------------------------------------------------------
    def read_nfc(self, card, pin: str, *, want_card_object: bool = True) -> dict:
        """Drive a card over APDUs. The PIN comes from the holder at a pinpad, not from here.

        `want_card_object` is the difference between the two modes. With it, the device asks
        for the signed object and can check authenticity itself; without it, the device gets a
        pairwise handle and a signature and nothing that identifies the credential."""
        challenge = self.challenge()
        if not em.is_ok(card.transmit(em.select())):
            raise DeviceRefusal("the card did not answer SELECT")
        pin_response = card.transmit(em.verify_pin(pin))
        if not em.is_ok(pin_response):
            # Reported, never interpreted. The device cannot tell a wrong PIN from a duress
            # one because both correct PINs answer 0x9000, and that is the design.
            raise DeviceRefusal("the card did not accept the PIN (status 0x%04x)"
                                % em.status_word(pin_response))
        signed = card.transmit(em.sign_challenge(self.scope, challenge))
        parsed = em.parse_signed_response(signed)
        if parsed is None:
            raise DeviceRefusal("the card did not produce a presentation")
        handle, signature = parsed
        card_object = None
        if want_card_object:
            response = card.transmit(em.get_card_object())
            if em.is_ok(response):
                card_object = em.payload(response)
        return {"transport": "nfc", "scope": self.scope, "challenge": challenge,
                "handle": handle, "signature": signature, "card_object": card_object}

    # -- QR ---------------------------------------------------------------
    def qr_request(self) -> tuple[str, bytes]:
        """What the device DISPLAYS: its scope and a fresh challenge. Returns (text, challenge).

        A card has no screen, so the QR path is the holder's phone: it scans this, asks the
        card to sign, and shows the answer back. The device is the one that must supply the
        challenge, because a challenge the holder chose is not a challenge."""
        challenge = self.challenge()
        return "%s:%s:%s" % (QR_REQUEST_PREFIX, self.scope, _b64(challenge)), challenge

    def read_qr(self, payload: str) -> dict:
        """Parse what the holder's phone showed back. Never trusts its length or its shape."""
        if not isinstance(payload, str) or not payload.startswith(QR_RESPONSE_PREFIX + ":"):
            raise DeviceRefusal("not a %s presentation" % QR_RESPONSE_PREFIX)
        parts = payload.split(":")
        if len(parts) not in (4, 5):
            raise DeviceRefusal("a QR presentation is prefix:challenge:handle:signature "
                                "with an optional card object")
        try:
            challenge = _unb64(parts[1])
            handle = _unb64(parts[2])
            signature = _unb64(parts[3])
            card_object = _unb64(parts[4]) if len(parts) == 5 else None
        except (ValueError, TypeError) as exc:
            raise DeviceRefusal("the QR payload is not valid base64url: %s" % exc) from exc
        return {"transport": "qr", "scope": self.scope, "challenge": challenge,
                "handle": handle, "signature": signature, "card_object": card_object}

    # -- the decision -----------------------------------------------------
    def decide(self, presented: dict, *, verify_card_signature=None, verify_response=None,
               status_assertion=None, online_status=None, verify_status_assertion=None,
               now=None) -> dict:
        """Reach a verdict. Offline when `status_assertion` is given, online with `online_status`.

        Nothing here re-implements verification: the card object goes to the profile's own
        verifier and the status assertion to the detached one, both passed in."""
        v = {"possession_proven": False, "card_authentic": None, "status": None,
             "authorization_fresh": None, "accepted": False, "mode": None,
             "linkability": "unknown", "handle": None, "note": None}
        for field in ("challenge", "handle", "signature", "scope"):
            if not presented.get(field):
                v["note"] = "the presentation is missing %s" % field
                return v
        if presented["scope"] != self.scope:
            v["note"] = ("this presentation was made for scope %r, not this device's %r. A "
                         "response relayed from another verifier is not a presentation to this "
                         "one" % (presented["scope"], self.scope))
            return v
        try:
            self._retire(presented["challenge"])
        except DeviceRefusal as exc:
            v["note"] = str(exc)
            return v

        # POSSESSION. The card signed THIS device's challenge, its scope, and the handle.
        body = cp.response_body(presented["challenge"], presented["scope"], presented["handle"])
        if verify_response is None:
            v["note"] = "no way to verify the card's response was supplied"
            return v
        if not verify_response(body, presented["signature"]):
            v["note"] = "the card's response did not verify"
            return v
        v["possession_proven"] = True
        v["handle"] = presented["handle"]
        v["linkability"] = "pairwise"

        # AUTHENTICITY, when the device asked for the object.
        if presented.get("card_object") is not None:
            verdict = cp.verify_card(presented["card_object"],
                                     verify_classical=verify_card_signature,
                                     require_pq=self.require_pq, now=now)
            v["card_authentic"] = verdict["authentic"]
            if not verdict["authentic"]:
                v["note"] = verdict["note"] or "the card object did not verify"
                return v

        # AUTHORIZATION.
        if status_assertion is not None:
            v["mode"] = "offline"
            if status_assertion.get("token_value"):
                # Recorded BEFORE the assertion is verified, and that ordering is the point.
                # The device read the token value off the assertion the moment it held it. A
                # verdict that reported linkability only when the check SUCCEEDED would be
                # accounting for what the device accepted rather than for what it learned, and
                # a failed verification does not un-disclose an identifier.
                v["linkability"] = "credential-linkable"
            if verify_status_assertion is None:
                v["note"] = "no status-assertion verifier was supplied"
                return v
            sv = verify_status_assertion(status_assertion, now=now,
                                         max_window_seconds=self.max_window_seconds)
            v["status"] = sv.get("status")
            v["authorization_fresh"] = sv.get("fresh")
            if not sv.get("status_authentic"):
                v["note"] = sv.get("note") or "the status assertion did not verify"
                return v
            if not sv.get("fresh"):
                v["note"] = sv.get("note") or "the status assertion is not fresh enough"
                return v
        elif online_status is not None:
            v["mode"] = "online"
            if online_status.get("token_value") or online_status.get("credential_ref"):
                v["linkability"] = "credential-linkable"
            v["status"] = online_status.get("status")
            v["authorization_fresh"] = True
        else:
            v["note"] = ("possession was proven and nothing else. Without a status assertion "
                         "or an online check this device does not know whether the credential "
                         "still stands, and a card that was revoked this morning still signs")
            return v

        if v["status"] != "ACTIVE":
            v["note"] = "the credential is %s" % (v["status"] or "of unknown status")
            return v
        if presented.get("card_object") is None:
            v["note"] = ("authorization holds but the device never saw a signed card object, "
                         "so it has not established that this authority issued this card")
            return v
        v["accepted"] = True
        return v


# ---------------------------------------------------------------------------
# The QR path's hard limit, measured rather than asserted
# ---------------------------------------------------------------------------
def qr_response(challenge: bytes, handle: bytes, signature: bytes, card_object=None) -> str:
    parts = [QR_RESPONSE_PREFIX, _b64(challenge), _b64(handle), _b64(signature)]
    if card_object is not None:
        parts.append(_b64(card_object))
    return ":".join(parts)


def qr_capacity_report(card_object_sizes: dict) -> dict:
    """What fits in one QR code, and what does not.

    A presentation alone is small. A presentation carrying the CARD OBJECT is not, once the
    object holds a post-quantum key and a post-quantum signature, and the difference decides
    the protocol: a device that cannot receive the card object over QR cannot establish
    authenticity over QR, and must either read the card over NFC or accept a narrower verdict.
    This is measured here so the design records a number instead of an impression."""
    base = len(qr_response(bytes(CHALLENGE_BYTES), bytes(32), bytes(64)))
    rows = {"presentation_only": {"chars": base, "fits": base <= QR_PRACTICAL_CHARS}}
    for label, size in sorted(card_object_sizes.items()):
        n = len(qr_response(bytes(CHALLENGE_BYTES), bytes(32), bytes(64), bytes(size)))
        rows[label] = {"chars": n, "card_object_bytes": size,
                       "fits": n <= QR_PRACTICAL_CHARS,
                       "fits_absolute_max": n <= QR_MAX_ALPHANUMERIC}
    return rows


def _load_status_verifier():
    """The detached verifier's verify_status_assertion, loaded by path.

    A device is allowed a heavier dependency than the profile is; what it is not allowed is a
    SECOND implementation of a decision the detached verifier already makes, which would be
    two answers to one question with nothing saying which is right."""
    import importlib.util
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "scripts", "polaris-verify.py")
    spec = importlib.util.spec_from_file_location("polaris_verify_device", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify_status_assertion
