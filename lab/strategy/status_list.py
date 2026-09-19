#!/usr/bin/env python3
"""A Token Status List decision function, pure and socket-free.

LAB. Record: lab/strategy/001-token-status-list.md. Not promoted, not published, not a
product promise. It exists to find out whether the SEMANTICS are worth having, because the
parsing certainly is not: a bit array, DEFLATE'd, base64url'd, inside a signed JWT is a
weekend of work that a dozen stacks already have.

What this is trying to settle is the part those stacks treat as a footnote. A status answer
has a freshness, a provenance and a rollback story, and a verifier that returns a bare
"revoked: false" has thrown all three away. So `decide()` returns a verdict that keeps them
apart, and in particular keeps apart the two answers that are constantly conflated:

    not revoked          the issuer published a status and it says valid
    nobody asked         no status was evaluated

Those are different facts about the world and only one of them is evidence.

FAIL-CLOSED EVERYWHERE. Every refusal path returns checked=False with a code, never
status=VALID. A malformed status list is not a valid credential, and the single most likely
way to get this wrong is to treat "I could not read the revocation list" as "it was not
revoked".

NO SOCKETS. `decide()` is handed the token bytes and a signature-verifying callable. Fetching
is the caller's problem, deliberately: polaris-verify promises it opens no socket, that promise
is enforced by a check, and it is worth more than this feature. Keeping the decision pure is
what would let the pure half live there later.

Format: draft-ietf-oauth-status-list (at -20, past working group last call, not an RFC).
Spec risk is real and is written down as a falsifier in the record.
"""
from __future__ import annotations

import base64
import binascii
import json
import zlib

#: Status values the draft defines. 0x03 and 0x0B-0x0F are application-specific; everything
#: else is reserved. An unknown value is reported by number and NOT folded into "valid",
#: because a status this code does not understand is not a status it may act on.
VALID, INVALID, SUSPENDED = 0, 1, 2
_MEANING = {VALID: "VALID", INVALID: "INVALID", SUSPENDED: "SUSPENDED"}

#: The type header a Status List Token must carry. A plain JWT that happens to have a
#: status_list claim is not one, and accepting it would let any signed object this issuer ever
#: produced be replayed as a status list.
STATUS_LIST_TYP = "statuslist+jwt"

#: Bounded decompression. `lst` is attacker-influenced: it arrives over the network from a URI
#: named inside the credential. zlib will happily turn a few hundred bytes into gigabytes, and
#: a verifier that dies is a verifier that fails open for every OTHER credential in the queue.
#: 8 MiB holds a 1-bit list of 67 million credentials, which is larger than any real population
#: this would be pointed at.
MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024

#: The token itself is a JWT fetched from a URI. Same reasoning, smaller number.
MAX_TOKEN_BYTES = 2 * 1024 * 1024


class Verdict(dict):
    """A dict, so callers can treat it as data, with the two questions kept apart."""

    @property
    def checked(self):
        return self["checked"]


def _refuse(code, reason):
    return Verdict(checked=False, status=None, meaning=None, fresh=None, age_seconds=None,
                   stale=None, code=code, reason=reason)


def _b64u(value, what):
    """Decode base64url without padding, raising ValueError with a useful `what`."""
    if isinstance(value, str):
        value = value.encode("ascii", "strict")
    pad = -len(value) % 4
    try:
        return base64.urlsafe_b64decode(value + b"=" * pad)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("%s is not valid base64url: %s" % (what, exc))


def _inflate_bounded(raw, limit=MAX_DECOMPRESSED_BYTES):
    """zlib-inflate `raw`, refusing to produce more than `limit` bytes.

    decompressobj with a max_length is the only form that refuses a bomb without first
    building it. `zlib.decompress` has no bound and is the wrong call here however tidy it
    looks.
    """
    obj = zlib.decompressobj()
    out = obj.decompress(raw, limit)
    if obj.unconsumed_tail:
        raise ValueError("the status list decompresses to more than %d bytes" % limit)
    out += obj.flush()
    if len(out) > limit:
        raise ValueError("the status list decompresses to more than %d bytes" % limit)
    return out


def status_at(array, index, bits):
    """The status value at `index` in a decompressed status array.

    Bits run from the least significant end of each byte, so for bits=1 the byte 0xB9 holds
    indices 0..7 as 1,0,0,1,1,1,0,1. Getting this backwards is the classic implementation bug
    and it is silent: every status still decodes, just to the wrong credential's answer.

    Raises IndexError when the index is past the end of the array. That is deliberately not a
    status: a list that does not cover an index says nothing about it, and the caller must not
    be able to read the absence as VALID.
    """
    if bits not in (1, 2, 4, 8):
        raise ValueError("bits must be 1, 2, 4 or 8, not %r" % (bits,))
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ValueError("index must be a non-negative integer, not %r" % (index,))
    per_byte = 8 // bits
    byte_index = index // per_byte
    if byte_index >= len(array):
        raise IndexError("index %d is past the end of a %d-byte status list (%d entries)"
                         % (index, len(array), len(array) * per_byte))
    offset = (index % per_byte) * bits
    return (array[byte_index] >> offset) & ((1 << bits) - 1)


def decide(token, *, index, expected_uri, verify_signature, now, max_age_seconds=None):
    """Decide the status of one referenced credential. Total on hostile input.

    token             the Status List Token, a compact JWS (str or bytes)
    index             the `idx` from the credential's own status claim
    expected_uri      the `uri` from that same claim; must equal the token's `sub`
    verify_signature  callable(signing_input: bytes, signature: bytes, header: dict) -> bool.
                      Supplied by the caller because WHICH key is entitled to publish status
                      for this issuer is a trust-resolution question, not a parsing one, and
                      this function must not be able to answer it by accident.
    now               integer POSIX seconds
    max_age_seconds   the caller's own staleness bound, applied on top of the token's `ttl`.
                      A relying party is allowed to be stricter than the issuer.

    The verdict always carries `checked`. Everything else is meaningful only when it is True.
    """
    if isinstance(token, str):
        token = token.encode("ascii", "replace")
    if not isinstance(token, (bytes, bytearray)):
        return _refuse("malformed", "the status list token is not bytes or str")
    if not token:
        return _refuse("malformed", "the status list token is empty")
    if len(token) > MAX_TOKEN_BYTES:
        return _refuse("malformed", "the status list token is %d bytes, over the %d byte limit"
                                    % (len(token), MAX_TOKEN_BYTES))
    if not isinstance(now, int) or isinstance(now, bool):
        return _refuse("misconfigured", "now must be an integer POSIX time")

    parts = bytes(token).split(b".")
    if len(parts) != 3:
        return _refuse("malformed", "the status list token is not a compact JWS of three parts")
    try:
        header = json.loads(_b64u(parts[0], "the header"))
        payload = json.loads(_b64u(parts[1], "the payload"))
        signature = _b64u(parts[2], "the signature")
    except (ValueError, UnicodeDecodeError) as exc:
        return _refuse("malformed", "the status list token does not parse: %s" % exc)
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return _refuse("malformed", "the status list token's header or payload is not an object")

    # TYPE. A Status List Token is a distinct type of object, and the draft says so with a
    # MUST. Without this any signed JWT the issuer ever minted could be offered here, and the
    # ones that happen to carry a status_list claim would be believed.
    if header.get("typ") != STATUS_LIST_TYP:
        return _refuse("typ", "the token declares typ=%r and a status list must declare %r"
                              % (header.get("typ"), STATUS_LIST_TYP))

    # PROVENANCE, first half. `sub` binds the token to the URI the credential named. Without
    # it, a status list legitimately published for one credential population can be served in
    # answer to a query about another, and every index in it decodes to something.
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        return _refuse("sub", "the status list token carries no sub, so it is bound to no URI")
    if expected_uri is not None and subject != expected_uri:
        return _refuse("sub_mismatch",
                       "the credential points at %r and this status list is published for "
                       "%r; it is a real status list for somebody else"
                       % (expected_uri, subject))

    # PROVENANCE, second half. The caller decides which key may speak for this issuer.
    try:
        ok = verify_signature(b".".join(parts[:2]), signature, header)
    except Exception as exc:                       # a crashing resolver is not a pass
        return _refuse("signature_error",
                       "the signature check raised %s: %s" % (type(exc).__name__, exc))
    if not ok:
        return _refuse("signature", "the status list token's signature did not verify under "
                                    "the key the caller supplied")

    # FRESHNESS. Three separate facts, kept separate: the token may not be used past `exp`;
    # `iat` in the future is nonsense rather than freshness; and `ttl` is the issuer's own
    # statement of how long an answer may be reused, which is not the same as validity.
    iat, exp, ttl = payload.get("iat"), payload.get("exp"), payload.get("ttl")
    for label, value in (("iat", iat), ("exp", exp), ("ttl", ttl)):
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            return _refuse("time", "the status list token's %s is %r, which is not an integer; "
                                   "its freshness cannot be evaluated and will not be assumed"
                                   % (label, value))
    if not isinstance(iat, int):
        return _refuse("iat", "the status list token carries no iat, so its answer has no age "
                              "and staleness cannot be evaluated")
    if exp is not None and now >= exp:
        return _refuse("expired", "the status list token expired at %d and it is %d; the draft "
                                  "says it MUST NOT be used" % (exp, now))
    if iat > now:
        return _refuse("iat_future", "the status list token is dated %d, which is after the "
                                     "current time %d" % (iat, now))
    age = now - iat
    bound = min([b for b in (ttl, max_age_seconds) if b is not None], default=None)
    stale = bound is not None and age > bound

    # THE LIST ITSELF.
    sl = payload.get("status_list")
    if not isinstance(sl, dict):
        return _refuse("status_list", "the token carries no status_list object")
    bits, lst = sl.get("bits"), sl.get("lst")
    if bits not in (1, 2, 4, 8):
        return _refuse("bits", "the status list declares bits=%r; the draft allows 1, 2, 4 "
                               "or 8 and this code will not guess at another" % (bits,))
    if not isinstance(lst, str) or not lst:
        return _refuse("lst", "the status list carries no lst")
    try:
        array = _inflate_bounded(_b64u(lst, "the lst"))
    except (ValueError, zlib.error) as exc:
        return _refuse("lst", "the status list does not decompress: %s" % exc)
    if not array:
        return _refuse("lst", "the status list is empty, so it covers no credential")
    try:
        value = status_at(array, index, bits)
    except IndexError as exc:
        # NOT a status. A list that does not reach this index has said nothing about this
        # credential, and reporting that as VALID is the whole failure mode this file exists
        # to avoid.
        return _refuse("index", str(exc))
    except ValueError as exc:
        return _refuse("index", str(exc))

    return Verdict(checked=True, status=value, meaning=_MEANING.get(value),
                   fresh=not stale, stale=stale, age_seconds=age,
                   code=None,
                   reason=("status %d (%s) published %ds ago%s"
                           % (value, _MEANING.get(value, "application-specific or reserved"),
                              age, "; past the %ds bound the issuer or caller set" % bound
                              if stale else "")))


def encode_status_list(statuses, bits=1):
    """Build a `lst` value from a list of status integers. Fixtures and attacks only.

    Here rather than in a test file because both the attack harness and any future promotion
    need it, and two copies of a bit-packer is how the two stop agreeing.
    """
    if bits not in (1, 2, 4, 8):
        raise ValueError("bits must be 1, 2, 4 or 8")
    per_byte = 8 // bits
    size = (len(statuses) + per_byte - 1) // per_byte
    array = bytearray(size)
    for i, s in enumerate(statuses):
        if not 0 <= s < (1 << bits):
            raise ValueError("status %r does not fit in %d bit(s)" % (s, bits))
        array[i // per_byte] |= s << ((i % per_byte) * bits)
    return base64.urlsafe_b64encode(zlib.compress(bytes(array), 9)).rstrip(b"=").decode("ascii")
