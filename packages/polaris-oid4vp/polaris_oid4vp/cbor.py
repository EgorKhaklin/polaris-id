# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""cbor.py -- a strict, bounded CBOR decoder, and an encoder for what this package builds.

Standard library only. It reads the subset of RFC 8949 an ISO/IEC 18013-5 mdoc and its COSE
structures use, and refuses the rest with one error, `CborError`. It touches no socket and
knows nothing about mdoc: `mdoc.py` decides what a decoded value means.

WHAT IT REFUSES, each with a test in `test_mdoc.py` (`CborLimitsTests`):

    an indefinite length              a string, array or map without a stated length
    a map key that is not an integer or a text string, or one that repeats
    trailing bytes                    anything after the one data item
    a length past the end             a string, array or map longer than the bytes that follow
    a tag other than 0, 18, 24, 1004  bignums (2, 3) among them, so every integer fits 64 bits
    invalid UTF-8 in a text string
    tag 24 over anything but a byte string, or in a longer encoding than needed
    a float
    a simple value other than true, false and null
    nesting deeper than 32

WHY TAG 24 KEEPS ITS BYTES. An mdoc's digests and signatures are computed over the bytes of
tag-24 items exactly as the issuer or the device wrote them. A decoder that hands back only
the parsed value forces a re-encoding, and a re-encoding that differs by one head byte makes
a genuine credential fail or, worse, lets two byte strings stand for one value. So a tag-24
item decodes to `Tag24`: `raw` is its exact encoding, `inner` the byte string it wraps, and
the wrapper itself must be in its preferred (shortest) form, so that `raw` is the only
encoding of that item this decoder accepts.

Other items may carry a longer head than needed (`18 01` for 1). Nothing this package
computes depends on those bytes: what is hashed or signed is always a tag-24 item's `raw`, a
byte string, or a structure this module's own encoder wrote.

THE ENCODER writes the preferred serialization (shortest heads, definite lengths), map
entries in the order given. It encodes what the decoder returns and refuses everything else,
so no value this package signs over or hashes can hold a float, a bignum or an unknown tag.
"""

#: How deep arrays, maps and tags may nest. A DeviceResponse nests about nine deep down to an
#: IssuerSignedItemBytes, whose content is decoded on its own; 32 leaves room and keeps the
#: recursion far from the interpreter's limit.
MAX_DEPTH = 32

#: The tags an mdoc and its COSE structures carry: 0 (a date and time as text), 18
#: (COSE_Sign1), 24 (an embedded CBOR data item) and 1004 (a full date as text).
TAG_TDATE = 0
TAG_COSE_SIGN1 = 18
TAG_EMBEDDED = 24
TAG_FULL_DATE = 1004
ALLOWED_TAGS = (TAG_TDATE, TAG_COSE_SIGN1, TAG_EMBEDDED, TAG_FULL_DATE)

_UINT64_MAX = (1 << 64) - 1


class CborError(ValueError):
    """The input is not CBOR this package reads, or the value is not one it writes."""


class Tagged:
    """A tagged value other than tag 24: `tag` is the number, `value` what it wraps."""

    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag = tag
        self.value = value

    def __eq__(self, other):
        return isinstance(other, Tagged) and self.tag == other.tag and self.value == other.value

    def __hash__(self):
        return hash((Tagged, self.tag))

    def __repr__(self):
        return "Tagged(%d, %r)" % (self.tag, self.value)


class Tag24:
    """A tag-24 data item as it arrived: `raw` is its exact encoding, tag head included, and
    `inner` the byte string it wraps (itself CBOR, decoded by whoever needs it)."""

    __slots__ = ("raw", "inner")

    def __init__(self, raw, inner):
        self.raw = raw
        self.inner = inner

    def __eq__(self, other):
        return isinstance(other, Tag24) and self.raw == other.raw

    def __hash__(self):
        return hash((Tag24, self.raw))

    def __repr__(self):
        return "Tag24(%d bytes)" % len(self.inner)


# --------------------------------------------------------------------------- decoding

def _head(buf, i):
    """(major type, argument, index after the head) of the item at buf[i]."""
    if i >= len(buf):
        raise CborError("the input ends where a data item should start")
    initial = buf[i]
    major, info = initial >> 5, initial & 31
    i += 1
    if info < 24:
        return major, info, i
    if info < 28:
        n = 1 << (info - 24)
        if i + n > len(buf):
            raise CborError("the input ends inside a head")
        return major, int.from_bytes(buf[i:i + n], "big"), i + n
    if info == 31:
        raise CborError("an indefinite length, or a break with nothing to end")
    raise CborError("a reserved head (additional information %d)" % info)


def _item(buf, i, depth):
    """(value, index after it) of the data item at buf[i]."""
    start = i
    major, arg, i = _head(buf, i)
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        if arg > len(buf) - i:
            raise CborError("a string of %d bytes with %d left" % (arg, len(buf) - i))
        raw = bytes(buf[i:i + arg])
        if major == 2:
            return raw, i + arg
        try:
            return raw.decode("utf-8"), i + arg
        except UnicodeDecodeError:
            raise CborError("a text string that is not UTF-8") from None
    if major == 7:
        # One-byte simple values only: false, true and null. Everything else under major type 7
        # is a float, undefined, another simple value or a break.
        if buf[start] == 0xf4:
            return False, i
        if buf[start] == 0xf5:
            return True, i
        if buf[start] == 0xf6:
            return None, i
        raise CborError("a float or a simple value other than true, false and null (0x%02x)" % buf[start])
    if depth >= MAX_DEPTH:
        raise CborError("nesting deeper than %d" % MAX_DEPTH)
    # An array or a map that states more items than follow ends at the first missing one: every
    # item takes at least a byte, so the loops below run no further than the input is long.
    if major == 4:
        out = []
        for _ in range(arg):
            value, i = _item(buf, i, depth + 1)
            out.append(value)
        return out, i
    if major == 5:
        out = {}
        for _ in range(arg):
            key, i = _item(buf, i, depth + 1)
            # bool is an int to Python, and True == 1: the type is held exactly, so that no two
            # keys this decoder accepts compare equal without being the same key.
            if type(key) is not int and type(key) is not str:
                raise CborError("a map key that is not an integer or a text string")
            if key in out:
                raise CborError("a map key that repeats")
            value, i = _item(buf, i, depth + 1)
            out[key] = value
        return out, i
    # major 6: a tag
    if arg not in ALLOWED_TAGS:
        raise CborError("tag %d, which this verifier does not read" % arg)
    if arg != TAG_EMBEDDED:
        value, end = _item(buf, i, depth + 1)
        return Tagged(arg, value), end
    if buf[start] != 0xd8:
        raise CborError("tag 24 in a longer head than needed")
    inner_major, length, body = _head(buf, i)
    if inner_major != 2:
        raise CborError("tag 24 over something that is not a byte string")
    if length > len(buf) - body:
        raise CborError("a string of %d bytes with %d left" % (length, len(buf) - body))
    if body - i != len(_head_bytes(2, length)):
        raise CborError("tag 24 over a byte string whose length is written longer than needed")
    end = body + length
    return Tag24(bytes(buf[start:end]), bytes(buf[body:end])), end


def decode(data):
    """The one data item `data` holds. Raises CborError for anything this module refuses,
    trailing bytes included, and never another exception for a bytes-like input."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CborError("not bytes")
    buf = bytes(data)
    value, end = _item(buf, 0, 0)
    if end != len(buf):
        raise CborError("%d trailing bytes after the data item" % (len(buf) - end))
    return value


# --------------------------------------------------------------------------- encoding

def _head_bytes(major, arg):
    """The shortest head for a major type and an argument below 2**64."""
    if arg < 24:
        return bytes([major << 5 | arg])
    if arg < 1 << 8:
        return bytes([major << 5 | 24, arg])
    if arg < 1 << 16:
        return bytes([major << 5 | 25]) + arg.to_bytes(2, "big")
    if arg < 1 << 32:
        return bytes([major << 5 | 26]) + arg.to_bytes(4, "big")
    return bytes([major << 5 | 27]) + arg.to_bytes(8, "big")


def _encode(value, out, depth):
    if value is None:
        out.append(b"\xf6")
    elif value is True:
        out.append(b"\xf5")
    elif value is False:
        out.append(b"\xf4")
    elif type(value) is int:
        if 0 <= value <= _UINT64_MAX:
            out.append(_head_bytes(0, value))
        elif -1 - _UINT64_MAX <= value < 0:
            out.append(_head_bytes(1, -1 - value))
        else:
            raise CborError("an integer outside 64 bits")
    elif isinstance(value, (bytes, bytearray)):
        out.append(_head_bytes(2, len(value)))
        out.append(bytes(value))
    elif type(value) is str:
        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError:
            raise CborError("a text string that cannot be written as UTF-8") from None
        out.append(_head_bytes(3, len(raw)))
        out.append(raw)
    elif isinstance(value, Tag24):
        out.append(value.raw)
    elif depth >= MAX_DEPTH:
        raise CborError("nesting deeper than %d" % MAX_DEPTH)
    elif isinstance(value, (list, tuple)):
        out.append(_head_bytes(4, len(value)))
        for v in value:
            _encode(v, out, depth + 1)
    elif isinstance(value, dict):
        out.append(_head_bytes(5, len(value)))
        for k, v in value.items():
            if type(k) is not int and type(k) is not str:
                raise CborError("a map key that is not an integer or a text string")
            _encode(k, out, depth + 1)
            _encode(v, out, depth + 1)
    elif isinstance(value, Tagged):
        # The type is held exactly: False == 0 and True == 1 to Python, and neither is a tag number.
        if type(value.tag) is not int or value.tag not in ALLOWED_TAGS or value.tag == TAG_EMBEDDED:
            raise CborError("tag %r, which this module does not write this way" % (value.tag,))
        out.append(_head_bytes(6, value.tag))
        _encode(value.value, out, depth + 1)
    else:
        raise CborError("a %s, which this module does not write" % type(value).__name__)


def encode(value):
    """The preferred serialization of `value`: integers within 64 bits, byte and text strings,
    lists, dicts keyed by integers or text (entries in the order given), None, True, False,
    `Tagged` under tags 0, 18 and 1004, and `Tag24` as its own bytes. Raises CborError for
    anything else."""
    out = []
    _encode(value, out, 0)
    return b"".join(out)


def tag24(inner):
    """The tag-24 item wrapping the byte string `inner`, in its preferred encoding."""
    if not isinstance(inner, (bytes, bytearray)):
        raise CborError("tag 24 wraps a byte string")
    inner = bytes(inner)
    return Tag24(b"\xd8\x18" + _head_bytes(2, len(inner)) + inner, inner)
