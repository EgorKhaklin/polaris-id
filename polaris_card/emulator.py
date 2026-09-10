"""polaris_card/emulator.py - a software token implementing the card profile (roadmap P4.2).

P4.1 specified the card OBJECT: what is on the card and what is signed. This is the card's
BEHAVIOUR: what it answers, in what order, and what it refuses. Everything downstream develops
against this rather than against silicon that does not exist yet, so the interface is the one
real silicon will present rather than a convenient Python API.

That means APDUs. ISO 7816-4 command and response pairs, with real status words, because a
reader written against a comfortable method call has to be rewritten the day a card arrives,
and a reader written against APDUs does not. The exchanges are published in
polaris_card/vectors/apdu-exchanges.json for the same reason the card object's bytes are.

THE PROPERTY THIS CLASS EXISTS TO HOLD is that a coercer learns nothing. Both PINs unlock.
They return the same status word, take the same path, and move the retry counter the same way.
The retry counter is the subtle one: a duress PIN that failed to reset it would announce
itself on the next wrong attempt, so the counter is reset identically and the comparison is
constant-time on both.

WHAT AN EMULATOR CANNOT PROVE. It cannot tell you a real secure element is constant-time,
resists fault injection, or keeps a key non-extractable. Those are properties of a part and
its certification (roadmap P4.6), not of this file. What it can do is fix the protocol so
that when such a part exists, the readers and the personalization service already work.
"""
from __future__ import annotations

import hmac
import os
import secrets
import struct

try:                                     # both layouts, like the rest of the tree
    from polaris_card import card_profile as cp   # type: ignore
except ImportError:                      # pragma: no cover - the flat layout
    import card_profile as cp            # type: ignore

CLA = 0x80                               # proprietary class

INS_SELECT = 0xA4
INS_VERIFY_PIN = 0x20
INS_UNBLOCK = 0x2C
INS_GET_CARD_OBJECT = 0x30
INS_SIGN_CHALLENGE = 0x34
INS_GENERATE_KEYPAIR = 0x47              # personalization only, and only once
INS_PUT_CARD_OBJECT = 0xDA               # personalization only, and only once

# A card's lifecycle. BLANK accepts personalization; PERSONALIZED accepts nothing that would
# change what the card is. There is no path back, and that is the point: a card that could be
# re-personalized in the field is a forgery machine with a legitimate serial number.
STATE_BLANK = "BLANK"
STATE_PERSONALIZED = "PERSONALIZED"

# ISO 7816-4 status words. 0x63Cx announcing the retry count is deliberate and standard: a
# holder needs to know how many attempts are left, and it says nothing about WHICH PIN is
# right because both correct PINs answer 0x9000.
SW_OK = 0x9000
SW_WRONG_PIN = 0x63C0                    # low nibble carries the remaining tries
SW_BLOCKED = 0x6983                      # authentication method blocked
SW_SECURITY_NOT_SATISFIED = 0x6982       # PIN not verified
SW_WRONG_LENGTH = 0x6700
SW_WRONG_DATA = 0x6A80
SW_INS_NOT_SUPPORTED = 0x6D00
SW_CLA_NOT_SUPPORTED = 0x6E00
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_ALREADY_PERSONALIZED = 0x6A89         # the command would change what the card already is

MAX_PIN_TRIES = 3
MAX_PUK_TRIES = 10


def sw_bytes(sw: int) -> bytes:
    return struct.pack(">H", sw)


def _unmatchable(length: int) -> str:
    """A comparand of `length` characters that no pinpad can produce.

    Used as the duress PIN on a card whose holder has not enrolled one, so that the
    comparison always runs and always costs the same. The leading NUL is what makes it
    unmatchable rather than merely improbable: a PIN arrives as the decoded data field of a
    VERIFY command, and a keypad cannot put a NUL there."""
    filler = secrets.token_urlsafe(max(length, 1))[:max(length - 1, 0)]
    return ("\x00" + filler)[:max(length, 1)]


class SoftwareToken:
    """A card. Reset it, talk to it in APDUs, and it behaves like one.

    `sign_with_slot(slot, digest)` is injected rather than imported: the profile stays
    implementable inside a secure element's toolchain, and this class stays honest about the
    fact that it is not the thing doing the cryptography."""

    def __init__(self, *, card_object: bytes | None, normal_pin: str,
                 duress_pin: str | None = None, puk: str, slot_secret_normal: bytes,
                 slot_secret_duress: bytes | None = None, sign_with_slot=None,
                 generate_keypair=None):
        if duress_pin is not None and hmac.compare_digest(normal_pin, duress_pin):
            raise ValueError("the duress PIN must differ from the normal one")
        if duress_pin is not None and len(duress_pin) != len(normal_pin):
            # The PIN travels in the command's data field, so its LENGTH is on the wire. A
            # six-digit duress PIN beside a four-digit normal one would tell anyone watching
            # the exchange which class was entered, without their needing to see the keypad.
            raise ValueError("the duress PIN must be the same length as the normal one, or the "
                             "command APDU's length announces which one was entered")
        if duress_pin is not None and slot_secret_duress is None:
            raise ValueError("a duress PIN needs its own key slot, or the two presentations "
                             "would be identical to the AUTHORITY as well as to the coercer")
        if card_object is not None:
            cp.decode(card_object)       # refuse a card object this card could not present
        self._card_object = card_object
        self.state = STATE_PERSONALIZED if card_object is not None else STATE_BLANK
        # A card ALWAYS holds a duress comparand. When the holder has not enrolled a duress
        # PIN, it is an unguessable value of the same length that no pinpad can produce, so
        # the comparison still runs and still costs the same. Storing None here and skipping
        # the comparison would make "this holder enrolled a duress PIN" measurable from
        # outside the card, which is a fact about the holder and exactly the class of thing a
        # coercer can use: learning that a card has none tells them the PIN they just watched
        # was the real one. See docs/design/duress-on-card.md.
        self._duress_enrolled = duress_pin is not None
        self._pins = {"normal": normal_pin,
                      "duress": duress_pin if duress_pin is not None
                      else _unmatchable(len(normal_pin))}
        self._puk = puk
        self._secrets = {"normal": slot_secret_normal, "duress": slot_secret_duress}
        self._sign = sign_with_slot
        self._generate = generate_keypair
        self._generated = False
        self.reset()

    # -- state ------------------------------------------------------------
    def reset(self):
        """Power cycle. A card forgets it was unlocked; the retry counter survives, because a
        counter that reset on power cycle would make a wrong PIN free to retry forever."""
        self._selected = False
        self._unlocked_slot = None
        if not hasattr(self, "_tries"):
            self._tries = MAX_PIN_TRIES
            self._puk_tries = MAX_PUK_TRIES

    @property
    def blocked(self) -> bool:
        return self._tries <= 0

    @property
    def tries_remaining(self) -> int:
        return max(self._tries, 0)

    # -- the wire ---------------------------------------------------------
    def transmit(self, apdu: bytes) -> bytes:
        """One command APDU in, one response APDU out. Never raises on untrusted input.

        A card that threw on a malformed command would be a card whose failure mode depends on
        what the reader sent, and half of what a reader is written against is what happens when
        it gets it wrong."""
        try:
            return self._transmit(bytes(apdu))
        except Exception:                # noqa: BLE001 - a card answers, it does not crash
            return sw_bytes(SW_WRONG_DATA)

    def _transmit(self, apdu: bytes) -> bytes:
        if len(apdu) < 4:
            return sw_bytes(SW_WRONG_LENGTH)
        cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
        if cla != CLA:
            return sw_bytes(SW_CLA_NOT_SUPPORTED)
        data = b""
        if len(apdu) > 4:
            lc = apdu[4]
            if lc == 0 and len(apdu) >= 7:
                # Extended length. A card object carrying a post-quantum key runs well past
                # 255 bytes, and personalization is a bench operation where an extended APDU
                # costs nothing. A short 0x00 with no body after it stays Le=0, as SELECT
                # and GET CARD OBJECT send.
                (lc,) = struct.unpack(">H", apdu[5:7])
                if len(apdu) < 7 + lc:
                    return sw_bytes(SW_WRONG_LENGTH)
                data = apdu[7:7 + lc]
            else:
                if len(apdu) < 5 + lc:
                    return sw_bytes(SW_WRONG_LENGTH)
                data = apdu[5:5 + lc]

        if ins == INS_SELECT:
            return self._select()
        if not self._selected:
            # Everything else needs the application selected first. A card that answered
            # before SELECT would let a reader skip the one step that says which application
            # it is talking to.
            return sw_bytes(SW_CONDITIONS_NOT_SATISFIED)
        if ins == INS_VERIFY_PIN:
            return self._verify_pin(data)
        if ins == INS_UNBLOCK:
            return self._unblock(data)
        if ins == INS_GET_CARD_OBJECT:
            return self._get_card_object()
        if ins == INS_SIGN_CHALLENGE:
            return self._sign_challenge(data, p1, p2)
        if ins == INS_GENERATE_KEYPAIR:
            return self._generate_keypair()
        if ins == INS_PUT_CARD_OBJECT:
            return self._put_card_object(data)
        return sw_bytes(SW_INS_NOT_SUPPORTED)

    # -- commands ---------------------------------------------------------
    def _select(self):
        self._selected = True
        self._unlocked_slot = None       # selecting drops any previous authentication
        return (cp.DOC_TYPE.encode("utf-8") + bytes([cp.PROFILE_VERSION])
                + bytes([self.tries_remaining]) + sw_bytes(SW_OK))

    def _verify_pin(self, data):
        if self.blocked:
            return sw_bytes(SW_BLOCKED)
        try:
            supplied = data.decode("utf-8")
        except UnicodeDecodeError:
            supplied = "\x00"            # not a PIN, but it must still cost an attempt
        # BOTH comparisons run, always, and both are constant-time. Short-circuiting on the
        # normal PIN would make a duress presentation measurably slower than a normal one,
        # which is exactly the fact that must not be observable.
        normal_ok = hmac.compare_digest(supplied, self._pins["normal"])
        duress_ok = hmac.compare_digest(supplied, self._pins["duress"])
        if normal_ok or duress_ok:
            # Identical in every observable: same status word, same counter reset. A duress
            # PIN that left the counter alone would announce itself on the next wrong attempt.
            self._unlocked_slot = "duress" if duress_ok else "normal"
            self._tries = MAX_PIN_TRIES
            return sw_bytes(SW_OK)
        self._tries -= 1
        self._unlocked_slot = None
        if self.blocked:
            return sw_bytes(SW_BLOCKED)
        return sw_bytes(SW_WRONG_PIN | self.tries_remaining)

    def _unblock(self, data):
        if self._puk_tries <= 0:
            return sw_bytes(SW_BLOCKED)
        try:
            supplied = data.decode("utf-8")
        except UnicodeDecodeError:
            supplied = "\x00"
        if hmac.compare_digest(supplied, self._puk):
            self._tries = MAX_PIN_TRIES
            self._puk_tries = MAX_PUK_TRIES
            return sw_bytes(SW_OK)
        self._puk_tries -= 1
        return sw_bytes(SW_WRONG_PIN | max(self._puk_tries, 0))

    def _blank(self):
        return self._card_object is None

    def _get_card_object(self):
        """Identified mode: the whole signed object. Requires a verified PIN.

        The reader learns a stable credential reference and can link its own sightings, as with
        every physical credential that exists. That is why it is a separate command a verifier
        has to ask for, rather than what a card volunteers."""
        if self._unlocked_slot is None:
            return sw_bytes(SW_SECURITY_NOT_SATISFIED)
        if self._blank():
            return sw_bytes(SW_CONDITIONS_NOT_SATISFIED)
        return self._card_object + sw_bytes(SW_OK)

    def _sign_challenge(self, data, p1, p2):
        """Key mode: a pairwise handle and a signature over the challenge, scope and handle.

        Data is `scope_len(1) || scope || challenge`. The handle is derived from the UNLOCKED
        SLOT's secret, so a duress presentation yields a different handle and a different
        signature, and only the authority (which holds both public keys) can tell them apart.
        The reader sees a well-formed response either way."""
        if self._unlocked_slot is None:
            return sw_bytes(SW_SECURITY_NOT_SATISFIED)
        if self._blank():
            # A card with no signed object has nothing a verifier could check a response
            # against. Signing anyway would produce a response that looks like a credential.
            return sw_bytes(SW_CONDITIONS_NOT_SATISFIED)
        if not data:
            return sw_bytes(SW_WRONG_LENGTH)
        scope_len = data[0]
        if len(data) < 1 + scope_len:
            return sw_bytes(SW_WRONG_LENGTH)
        try:
            scope = data[1:1 + scope_len].decode("utf-8")
        except UnicodeDecodeError:
            return sw_bytes(SW_WRONG_DATA)
        challenge = data[1 + scope_len:]
        secret = self._secrets[self._unlocked_slot]
        handle = cp.pairwise_handle(secret, scope)
        try:
            body = cp.response_body(challenge, scope, handle)
        except cp.CardProfileError:
            # A short challenge is refused by the card, not merely by the verifier. A card that
            # signed anything a reader asked for would be an oracle.
            return sw_bytes(SW_WRONG_DATA)
        if self._sign is None:
            return sw_bytes(SW_CONDITIONS_NOT_SATISFIED)
        signature = self._sign(self._unlocked_slot, body)
        return (bytes([len(handle)]) + handle
                + struct.pack(">H", len(signature)) + signature + sw_bytes(SW_OK))

    def _generate_keypair(self):
        """Generate both slot keypairs ON THE CARD and return only the public keys.

        This is key GENERATION, not key injection, and the difference is the whole security
        argument of personalization. An injected key existed somewhere else first: on the
        personalization host, in its memory, possibly in a log or a core dump, and the
        authority can only assert that it was destroyed. A generated key has no such history,
        and the claim "the private key never left the card" is a fact about where it was made
        rather than a promise about what was deleted.

        BOTH slots are generated, always, whether or not the holder ever enrolls a duress PIN.
        A card that only got a duress slot when one was wanted would make the slot's existence
        a fact about the holder; because every card has one, the presence of a duress key in
        the authority's records says nothing about anybody."""
        if self.state != STATE_BLANK or self._generated:
            # The CARD refuses, by its own rule. Leaving this to whatever backs the slots
            # would make "a slot is generated once" a property of the personalization host,
            # which is exactly the party the rule exists to constrain.
            return sw_bytes(SW_ALREADY_PERSONALIZED)
        if self._generate is None:
            return sw_bytes(SW_CONDITIONS_NOT_SATISFIED)
        normal_pub = self._generate("normal")
        duress_pub = self._generate("duress")
        self._generated = True
        return (bytes([len(normal_pub)]) + normal_pub
                + bytes([len(duress_pub)]) + duress_pub + sw_bytes(SW_OK))

    def _put_card_object(self, data):
        """Load the signed card object. Once, on a blank card, and never again."""
        if self.state != STATE_BLANK:
            return sw_bytes(SW_ALREADY_PERSONALIZED)
        try:
            cp.decode(data)              # the card refuses an object it could not present
        except cp.CardProfileError:
            return sw_bytes(SW_WRONG_DATA)
        self._card_object = bytes(data)
        self.state = STATE_PERSONALIZED
        return sw_bytes(SW_OK)


# ---------------------------------------------------------------------------
# Command builders, so a reader is written once and works against silicon later.
# ---------------------------------------------------------------------------
def select() -> bytes:
    return bytes([CLA, INS_SELECT, 0x04, 0x00, 0x00])


def verify_pin(pin: str) -> bytes:
    raw = pin.encode("utf-8")
    return bytes([CLA, INS_VERIFY_PIN, 0x00, 0x80, len(raw)]) + raw


def unblock(puk: str) -> bytes:
    raw = puk.encode("utf-8")
    return bytes([CLA, INS_UNBLOCK, 0x00, 0x80, len(raw)]) + raw


def generate_keypair() -> bytes:
    return bytes([CLA, INS_GENERATE_KEYPAIR, 0x00, 0x00, 0x00])


def put_card_object(card_object: bytes) -> bytes:
    if len(card_object) > 0xFFFF:
        raise ValueError("a card object that large does not fit an extended APDU either")
    # Extended-length: a card object with a post-quantum key runs past 255 bytes, and
    # personalization is a bench operation where an extended APDU costs nothing.
    return (bytes([CLA, INS_PUT_CARD_OBJECT, 0x00, 0x00, 0x00])
            + struct.pack(">H", len(card_object)) + card_object)


def parse_generated_keys(response: bytes):
    """(normal_public, duress_public) from a GENERATE KEYPAIR response, or None."""
    if not is_ok(response):
        return None
    body = payload(response)
    if not body:
        return None
    n = body[0]
    if len(body) < 1 + n + 1:
        return None
    normal = body[1:1 + n]
    d = body[1 + n]
    duress = body[2 + n:2 + n + d]
    if len(duress) != d:
        return None
    return normal, duress


def get_card_object() -> bytes:
    return bytes([CLA, INS_GET_CARD_OBJECT, 0x00, 0x00, 0x00])


def sign_challenge(reader_scope: str, challenge: bytes) -> bytes:
    scope = reader_scope.encode("utf-8")
    if len(scope) > 0xFF:
        raise ValueError("a reader scope must fit in one length byte")
    data = bytes([len(scope)]) + scope + challenge
    if len(data) > 0xFF:
        raise ValueError("the command does not fit in a short APDU; use a longer challenge "
                         "only if the reader supports extended length")
    return bytes([CLA, INS_SIGN_CHALLENGE, 0x00, 0x00, len(data)]) + data


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------
def status_word(response: bytes) -> int:
    if len(response) < 2:
        raise ValueError("a response APDU carries at least a status word")
    return struct.unpack(">H", response[-2:])[0]


def payload(response: bytes) -> bytes:
    return bytes(response[:-2])


def is_ok(response: bytes) -> bool:
    return status_word(response) == SW_OK


def tries_left(sw: int):
    """The remaining attempts a 0x63Cx status word announces, or None if it is not one."""
    return (sw & 0x0F) if (sw & 0xFFF0) == SW_WRONG_PIN else None


def parse_signed_response(response: bytes):
    """(handle, signature) from a SIGN CHALLENGE response, or None if it is not one."""
    if not is_ok(response):
        return None
    body = payload(response)
    if not body:
        return None
    hlen = body[0]
    if len(body) < 1 + hlen + 2:
        return None
    handle = body[1:1 + hlen]
    (siglen,) = struct.unpack(">H", body[1 + hlen:3 + hlen])
    signature = body[3 + hlen:3 + hlen + siglen]
    if len(signature) != siglen:
        return None
    return handle, signature


RAW_SIGNATURE_LEN = 64                   # P-256 r||s, fixed


def der_from_raw(signature: bytes) -> bytes:
    """DER-wrap a raw r||s signature, for host libraries that only accept DER.

    A card emits fixed-length raw bytes because that is what a secure element does, and
    because a varying length is an observable a duress presentation must not have. Host
    verification libraries generally want DER, so the wrapping happens here on the reader's
    side, where a variable length costs nothing."""
    if len(signature) != RAW_SIGNATURE_LEN:
        raise ValueError(f"a raw P-256 signature is {RAW_SIGNATURE_LEN} bytes, "
                         f"got {len(signature)}")
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    half = RAW_SIGNATURE_LEN // 2
    return asym_utils.encode_dss_signature(
        int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big"))


# ---------------------------------------------------------------------------
# A ready-made token, for everything downstream
# ---------------------------------------------------------------------------
def new_blank_token(*, normal_pin="1234", duress_pin="9999", puk="12345678"):
    """A BLANK card: PINs set at manufacture, no keys, no object, nothing to present.

    This is what arrives at a personalization station. It generates its own keypairs when
    asked and hands back only the public halves; there is no path in this function or in
    SoftwareToken through which a private key could be supplied from outside, which is what
    makes "the private key never left the card" a fact about where it was made rather than a
    promise about what was deleted.

    Returned as `(token, slots)` where `slots` is the dict the card fills in as it generates,
    so a TEST can check what the card kept. A personalization service never sees it."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    import hashlib

    slots: dict = {}

    def generate(slot):
        if slot in slots:
            raise RuntimeError("a slot is generated once")
        slots[slot] = ec.generate_private_key(ec.SECP256R1())
        return slots[slot].public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def sign_with_slot(slot, body):
        from cryptography.hazmat.primitives import hashes
        der = slots[slot].sign(hashlib.sha256(body).digest(),
                               ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
        r, s_ = asym_utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s_.to_bytes(32, "big")

    token = SoftwareToken(card_object=None, normal_pin=normal_pin, duress_pin=duress_pin,
                          puk=puk, slot_secret_normal=os.urandom(32),
                          slot_secret_duress=os.urandom(32), sign_with_slot=sign_with_slot,
                          generate_keypair=generate)
    return token, slots


def new_software_token(*, token_value="POLARIS-EMULATOR-0001", issuing_authority=1,
                       activation_sequence=1, issued_at=1_757_000_000,
                       expires_at=1_914_766_400, normal_pin="1234", duress_pin="9999",
                       puk="12345678", issuer_sign=None):
    """A working token with fresh P-256 slot keys. Needs `cryptography`.

    Returned as `(token, detail)` where detail carries the public keys and the card object, so
    a personalization service or a verifier has what the authority would have registered."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

    slots = {"normal": ec.generate_private_key(ec.SECP256R1()),
             "duress": ec.generate_private_key(ec.SECP256R1())}

    def _pub(key):
        return key.public_key().public_bytes(serialization.Encoding.X962,
                                             serialization.PublicFormat.UncompressedPoint)

    def sign_with_slot(slot, body):
        """Raw r||s, 64 bytes, NOT DER.

        A secure element returns a fixed-length ECDSA signature; DER is something host
        software wraps around it. Emitting DER here would be unfaithful to the part AND would
        make the response length vary by a byte or two per signature, which turns "a duress
        presentation is indistinguishable" from an exact statement into a statistical one. It
        is exact: every response is the same length, always."""
        import hashlib
        digest = hashlib.sha256(body).digest()
        der = slots[slot].sign(digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
        r, s_ = asym_utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s_.to_bytes(32, "big")

    if issuer_sign is None:
        issuer = ec.generate_private_key(ec.SECP256R1())

        def issuer_sign(digest):
            return issuer.sign(digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
    else:
        issuer = None

    # Only the NORMAL slot's public key goes on the card. Carrying the duress key would make
    # the existence of a duress PIN readable off the card, which is the one fact that must not
    # be readable.
    card_object = cp.build_card(token_value=token_value, issuing_authority=issuing_authority,
                                activation_sequence=activation_sequence, issued_at=issued_at,
                                expires_at=expires_at,
                                card_key_classical=_pub(slots["normal"]),
                                sign_classical=issuer_sign)
    token = SoftwareToken(card_object=card_object, normal_pin=normal_pin, duress_pin=duress_pin,
                          puk=puk, slot_secret_normal=os.urandom(32),
                          slot_secret_duress=os.urandom(32), sign_with_slot=sign_with_slot)
    return token, {
        "card_object": card_object,
        "issuer_private": issuer,
        "slot_public": {name: _pub(k) for name, k in slots.items()},
        "slot_private": slots,
    }
