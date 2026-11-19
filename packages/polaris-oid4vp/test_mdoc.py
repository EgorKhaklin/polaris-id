# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_mdoc.py -- an ISO/IEC 18013-5 mdoc DeviceResponse, decoded and refused.

READ THE LIMIT FIRST. The fixtures under testdata/mdoc were captured from a wallet this
project did not write (the EU reference wallet libraries with walt.id's mdoc library); every
other input here is built by this file. cbor2 is the decoding witness: it is a test
dependency only, and the package never imports it.

The decoder's rules, one test each (decision record 025, "Common to every milestone"):
definite lengths only; map keys that are integers or text strings, none repeated; no trailing
bytes; no length past the end of the buffer; no bignum; valid UTF-8; tags 0, 18, 24 and 1004
only; tag 24 over a byte string only, in its preferred encoding; no float; no simple value but
true, false and null; nesting at most 32 deep.
"""
import base64
import contextlib
import datetime
import hashlib
import json
import os
import pathlib
import sys
import types
import unittest
import warnings
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbor2  # noqa: E402  (the witness; a test dependency only)
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID  # noqa: E402

from polaris_oid4vp import cbor  # noqa: E402
from polaris_oid4vp.cbor import CborError, Tag24, Tagged  # noqa: E402
from polaris_oid4vp import cose, mdoc  # noqa: E402
from polaris_oid4vp.cose import CoseError  # noqa: E402
from polaris_oid4vp.mdoc import IacaRoot  # noqa: E402

#: The package's own copies of the captures (testdata/README.md): the suite reads nothing outside the package.
TESTDATA = pathlib.Path(__file__).resolve().parent / "testdata" / "mdoc"
CAPTURES = ("capture-pid", "capture-mdl", "capture-mdl-direct-post")


def capture(name):
    """One of M1's captured DeviceResponses, exactly as the wallet sent it. A missing capture
    fails the test that asks for it: a skipped fixture would read as a pass."""
    return (TESTDATA / name / "device-response.cbor").read_bytes()


def as_cbor2(value):
    """Our decoded value in cbor2's types, so that cbor2 can encode it."""
    if isinstance(value, Tag24):
        return cbor2.CBORTag(24, value.inner)
    if isinstance(value, Tagged):
        return cbor2.CBORTag(value.tag, as_cbor2(value.value))
    if isinstance(value, list):
        return [as_cbor2(v) for v in value]
    if isinstance(value, dict):
        return {k: as_cbor2(v) for k, v in value.items()}
    return value


def tag24_items(value):
    """Every Tag24 in a decoded value, in order."""
    if isinstance(value, Tag24):
        yield value
    elif isinstance(value, Tagged):
        yield from tag24_items(value.value)
    elif isinstance(value, list):
        for v in value:
            yield from tag24_items(v)
    elif isinstance(value, dict):
        for v in value.values():
            yield from tag24_items(v)


def h(text):
    return bytes.fromhex(text.replace(" ", ""))


class RefusalCase(unittest.TestCase):
    """A refusal test names the refusal it expects. `assertRefuses(E)` is assertRaises held to E:
    the call raising any other exception is an assertion failure that names both, where
    unittest's own assertRaises lets it out as an error. The mutation drill counts a run red only
    by ERROR as not caught, and a refusal removed so that a later line raises is that run."""

    @contextlib.contextmanager
    def assertRefuses(self, expected):
        caught = types.SimpleNamespace(exception=None)
        names = " or ".join(e.__name__ for e in (expected if isinstance(expected, tuple) else (expected,)))
        try:
            yield caught
        except expected as exc:
            caught.exception = exc
            return
        except self.failureException:
            raise
        except Exception as exc:
            raise self.failureException("raised %s (%s), not the refusal %s"
                                        % (type(exc).__name__, exc, names)) from exc
        raise self.failureException("%s not raised" % names)


class RefusalCaseTests(RefusalCase):
    """The two helpers a refusal test leans on: the named refusal passes, and any other exception,
    or none, is an assertion failure that says which, never an error."""

    def test_the_named_refusal_passes_and_anything_else_fails_by_assertion(self):
        with self.assertRefuses(CborError) as caught:
            raise CborError("named")
        self.assertEqual(str(caught.exception), "named")
        with self.assertRefuses((ValueError, KeyError)):
            raise KeyError("k")

        def later():
            raise TypeError("later")

        for body, words in ((later, "raised TypeError (later), not the refusal CborError"),
                            (lambda: None, "CborError not raised")):
            with self.subTest(words=words):
                with self.assertRaises(self.failureException) as failed:
                    with self.assertRefuses(CborError):
                        body()
                self.assertIn(words, str(failed.exception))

    def test_a_raise_from_the_verifier_is_reported_as_the_broken_promise(self):
        with mock.patch.object(mdoc, "verify_device_response", side_effect=TypeError("late")):
            for call in (lambda: judge(b""),
                         lambda: verify_device_response(b"", session_transcript=TRANSCRIPT, iaca_roots=ROOTS)):
                with self.assertRaises(AssertionError) as failed:
                    call()
                self.assertIn("raised TypeError (late); it returns a Verdict and never raises", str(failed.exception))


class CborTests(RefusalCase):
    """The positive half: what the decoder returns, held to cbor2 and to the bytes it was given."""

    def assertSameAsCbor2(self, data):
        ours = cbor.decode(data)
        # cbor2 reads the original and our value re-encoded by cbor2 itself: equal values mean the
        # two decoders saw the same data, tags 0 and 1004 included (cbor2 turns those into dates).
        self.assertEqual(cbor2.loads(cbor2.dumps(as_cbor2(ours))), cbor2.loads(data))
        return ours

    def test_the_decoder_agrees_with_cbor2_on_every_fixture(self):
        seen = 0
        for name in CAPTURES:
            with self.subTest(capture=name):
                data = capture(name)
                ours = self.assertSameAsCbor2(data)
                items = list(tag24_items(ours))
                self.assertTrue(items, "a DeviceResponse with no tag-24 item was not read")
                for item in items:
                    # Tag-24 items keep their exact bytes: each is a slice of what arrived, in the
                    # preferred wrapper, and its content decodes too.
                    self.assertIn(item.raw, data)
                    self.assertEqual(item.raw, cbor2.dumps(cbor2.CBORTag(24, item.inner)))
                    self.assertSameAsCbor2(item.inner)
                    seen += 1
        self.assertGreaterEqual(seen, 6)

    def test_each_major_type_decodes_to_its_value(self):
        for text, value in (
                ("00", 0), ("17", 23), ("18 18", 24), ("18 ff", 255), ("19 01 00", 256),
                ("1a 00 01 00 00", 65536), ("1b 00 00 00 01 00 00 00 00", 1 << 32),
                ("1b ff ff ff ff ff ff ff ff", (1 << 64) - 1),
                ("20", -1), ("37", -24), ("38 18", -25), ("3b ff ff ff ff ff ff ff ff", -(1 << 64)),
                ("40", b""), ("43 01 02 03", b"\x01\x02\x03"), ("60", ""), ("63 e2 82 ac", "€"),
                ("80", []), ("83 01 02 03", [1, 2, 3]), ("a0", {}),
                ("a2 01 02 61 61 82 03 04", {1: 2, "a": [3, 4]}),
                ("f4", False), ("f5", True), ("f6", None)):
            with self.subTest(hex=text):
                got = cbor.decode(h(text))
                self.assertEqual(got, value)
                self.assertIs(type(got), type(value))

    def test_a_tag_this_verifier_reads_keeps_its_number_and_value(self):
        self.assertEqual(cbor.decode(h("c0 74") + b"2026-09-30T00:00:00Z"), Tagged(0, "2026-09-30T00:00:00Z"))
        self.assertEqual(cbor.decode(h("d9 03 ec 6a") + b"1964-08-12"), Tagged(1004, "1964-08-12"))
        self.assertEqual(cbor.decode(h("d2 84 40 a0 f6 40")), Tagged(18, [b"", {}, None, b""]))

    def test_a_tag24_item_keeps_its_exact_bytes(self):
        data = h("a1 61 78 d8 18 43 82 01 02")
        item = cbor.decode(data)["x"]
        self.assertIsInstance(item, Tag24)
        self.assertEqual(item.raw, h("d8 18 43 82 01 02"))
        self.assertEqual(item.inner, h("82 01 02"))
        self.assertEqual(cbor.decode(item.inner), [1, 2])

    def test_a_longer_head_than_needed_is_read_outside_tag24(self):
        """Only a tag-24 wrapper is held to its preferred encoding: every digest and signature is
        over original bytes, so another item's longer head changes nothing this verifier computes."""
        for text, value in (("18 01", 1), ("19 00 01", 1), ("58 01 aa", b"\xaa"), ("98 01 00", [0]),
                            ("b8 01 00 00", {0: 0})):
            with self.subTest(hex=text):
                self.assertEqual(cbor.decode(h(text)), value)

    def test_the_encoder_writes_the_preferred_form(self):
        for value, text in (
                (0, "00"), (23, "17"), (24, "18 18"), (256, "19 01 00"), (65536, "1a 00 01 00 00"),
                (1 << 32, "1b 00 00 00 01 00 00 00 00"), (-1, "20"), (-25, "38 18"),
                (b"", "40"), ("a", "61 61"), ([], "80"), ({}, "a0"), (None, "f6"), (True, "f5"), (False, "f4"),
                ([None, None, ["OpenID4VPHandover", b"\x00"]], "83 f6 f6 82 71 4f70656e494434565048616e646f766572 41 00"),
                (Tagged(18, [b"", {}, None, b""]), "d2 84 40 a0 f6 40"),
                (cbor.tag24(h("82 01 02")), "d8 18 43 82 01 02")):
            with self.subTest(value=value):
                self.assertEqual(cbor.encode(value), h(text))

    def test_the_encoder_agrees_with_cbor2_and_round_trips(self):
        value = {"version": "1.0", "documents": [{"docType": "org.iso.18013.5.1.mDL", 7: -7, "b": b"\x00" * 300,
                                                  "n": [1 << 40, -(1 << 33), None, True, False]}],
                 "status": 0}
        data = cbor.encode(value)
        self.assertEqual(data, cbor2.dumps(value))
        self.assertEqual(cbor.decode(data), value)

    def test_the_encoder_refuses_what_the_decoder_would(self):
        deepest = [1]
        for _ in range(31):
            deepest = [deepest]
        too_deep = [deepest]
        for value in (1.5, {1.5: 1}, {b"k": 1}, {True: 1}, {(1, 2): 1}, 1 << 64, -(1 << 64) - 1, {1, 2},
                      object(), Tagged(2, b"\x01"), Tagged(1003, 1), Tagged(24, b"\x00"), Tagged(False, "x"),
                      Tagged(0.0, "x"), "\ud800", too_deep):
            with self.subTest(value=repr(value)[:40]):
                with self.assertRefuses(CborError):
                    cbor.encode(value)
        with self.assertRefuses(CborError):
            cbor.tag24("text")
        # The controls: the widest integers, and 32 levels, are written.
        self.assertEqual(cbor.decode(cbor.encode([(1 << 64) - 1, -(1 << 64)])), [(1 << 64) - 1, -(1 << 64)])
        self.assertEqual(cbor.encode(deepest), h("81" * 32 + "01"))

    def test_only_bytes_are_decoded(self):
        for value in ("a0", None, 1, [0xa0]):
            with self.subTest(value=value):
                with self.assertRefuses(CborError):
                    cbor.decode(value)
        self.assertEqual(cbor.decode(bytearray(b"\xa0")), {})
        self.assertEqual(cbor.decode(memoryview(b"\xa0")), {})

    def test_a_decode_error_is_the_only_thing_that_escapes(self):
        """Every single-byte change of a captured response, decoded down through its tag-24
        items, either decodes or raises CborError: no other exception leaves the decoder."""
        def deep(data):
            for item in tag24_items(cbor.decode(data)):
                deep(item.inner)

        data = capture("capture-pid")
        deep(data)  # the control: the capture as it arrived decodes all the way down
        refused = trials = 0
        for i in range(len(data)):
            for flip in (0x01, 0x80, 0xff):
                trials += 1
                try:
                    deep(data[:i] + bytes([data[i] ^ flip]) + data[i + 1:])
                except CborError:
                    refused += 1
        # Measured on capture-pid (2245 bytes, 6735 changes): 768 refused. The rest fall inside a
        # byte or text string (a certificate, a signature, a salt, a name), which the decoder has
        # no reason to refuse. The floor is there so that a decoder that stopped refusing is noticed.
        self.assertEqual(trials, 3 * len(data))
        self.assertGreater(refused, 700)


class CborLimitsTests(RefusalCase):
    """The refusals, each with the input that needs it and the reason the decoder gives. The
    reason is asserted because a malformed input is usually refused by a later rule too: a test
    that saw only "refused" would pass with its own rule removed. `malformed` is what the
    verifier answers for a CborError; here the error itself is the unit."""

    def refused(self, reason, *texts):
        self.assertTrue(texts, "a refusal test with no input measures nothing")
        for text in texts:
            with self.subTest(hex=text[:60]):
                data = h(text)
                with self.assertRefuses(CborError) as caught:
                    cbor.decode(data)
                self.assertIn(reason, str(caught.exception))

    def test_an_indefinite_length_is_refused(self):
        self.refused("an indefinite length", "9f 01 ff", "5f 41 00 ff", "7f 61 61 ff", "bf 01 02 ff", "ff",
                     "82 01 9f ff")

    def test_a_duplicate_map_key_is_refused(self):
        self.refused("a map key that repeats", "a2 01 01 01 02", "a2 61 61 01 61 61 02")
        # The control: the same maps with two distinct keys decode.
        self.assertEqual(cbor.decode(h("a2 01 01 02 02")), {1: 1, 2: 2})
        # A longer head for the same key is the same key.
        self.refused("a map key that repeats", "a2 01 01 18 01 02")

    def test_a_non_scalar_map_key_is_refused(self):
        self.refused("a map key that is not an integer or a text string",
                     "a1 81 01 02", "a1 a0 01", "a1 41 00 01", "a1 f5 01", "a1 f6 01", "a1 c0 61 61 01")

    def test_trailing_bytes_are_refused(self):
        self.refused("trailing bytes", "01 00", "a0 a0", "f6 f6")
        self.assertEqual(cbor.decode(h("01")), 1)

    def test_a_length_past_the_end_is_refused(self):
        # A string that states more bytes than follow, alone, nested and under tag 24.
        self.refused("a string of", "58 20 01 02 03", "5a ff ff ff ff 00", "7b ff ff ff ff ff ff ff ff", "62 61",
                     "82 01 43 01 02", "d8 18 43 01", "a1 00 d8 18 58 ff 00")
        # An array or a map that states more items than follow, up to the entry limit.
        self.refused("the input ends where a data item should start", "82 01", "a1 01", "", "d8 18",
                     "99 04 00 01", "b9 04 00 01 02")
        # Past it, the same kind of head is refused by the limit, before any item is looked for.
        self.refused("over the 1024 entry limit", "9a 00 01 00 00 01", "bb 00 00 00 00 00 01 00 00 01 02",
                     "9b ff ff ff ff ff ff ff ff", "bb ff ff ff ff ff ff ff ff")
        # A head whose own argument is cut short.
        self.refused("the input ends inside a head", "18", "19 01", "1a 00 00 00", "1b 00 00 00 00 00 00 00",
                     "82 01 59 01", "d8", "d9 03")
        # The control for the string rule: the same head with its bytes present.
        self.assertEqual(cbor.decode(h("43 01 02 03")), b"\x01\x02\x03")

    def test_an_integer_beyond_64_bits_is_refused(self):
        self.refused("which this verifier does not read",
                     "c2 49 01 00 00 00 00 00 00 00 00", "c3 49 01 00 00 00 00 00 00 00 00", "c2 41 01")
        # The control: the widest integers a head can state are read.
        self.assertEqual(cbor.decode(h("1b ff ff ff ff ff ff ff ff")), (1 << 64) - 1)
        self.assertEqual(cbor.decode(h("3b ff ff ff ff ff ff ff ff")), -(1 << 64))

    def test_invalid_utf8_text_is_refused(self):
        self.refused("a text string that is not UTF-8", "62 c3 28", "61 ff", "63 ed a0 80", "62 c0 80",
                     "a1 62 c3 28 01", "64 f4 90 80 80")
        # The control: the same head over valid UTF-8.
        self.assertEqual(cbor.decode(h("62 c3 a9")), "é")

    def test_an_unknown_tag_is_refused(self):
        self.refused("which this verifier does not read",
                     "d9 03 eb 01", "c1 00", "d8 20 60", "d9 d9 f7 00", "c4 82 01 02", "d8 19 41 00", "d1 80")
        # The control: the same value under a tag this verifier reads.
        self.assertEqual(cbor.decode(h("d9 03 ec 60")), Tagged(1004, ""))

    def test_a_tag24_over_anything_but_a_bstr_is_refused(self):
        self.refused("tag 24 over something that is not a byte string",
                     "d8 18 61 61", "d8 18 01", "d8 18 80", "d8 18 d8 18 41 00", "d8 18 a0", "d8 18 f6")

    def test_a_non_preferred_tag24_wrapper_is_refused(self):
        # The byte string's length written longer than needed.
        self.refused("whose length is written longer than needed",
                     "d8 18 58 01 00", "d8 18 59 00 01 00", "d8 18 59 00 18" + " 00" * 24,
                     "d8 18 5a 00 00 00 01 00", "d8 18 5b 00 00 00 00 00 00 00 01 00")
        # The tag's own head written longer than needed.
        self.refused("tag 24 in a longer head than needed",
                     "d9 00 18 41 00", "da 00 00 00 18 41 00", "db 00 00 00 00 00 00 00 18 41 00")
        # The controls: the shortest wrapper at each side of the one-byte length boundary.
        self.assertEqual(cbor.decode(h("d8 18 41 00")).inner, b"\x00")
        self.assertEqual(cbor.decode(h("d8 18 57") + bytes(23)).inner, bytes(23))
        self.assertEqual(cbor.decode(h("d8 18 58 18") + bytes(24)).inner, bytes(24))

    def test_a_float_is_refused(self):
        self.refused("a float or a simple value", "f9 3e 00", "fa 3f c0 00 00", "fb 3f f8 00 00 00 00 00 00",
                     "81 f9 00 00")

    def test_a_simple_value_other_than_true_false_null_is_refused(self):
        # undefined, unassigned simple values, and true, false and null in the two-byte form.
        self.refused("a float or a simple value", "f7", "f0", "e0", "f3", "f8 20", "f8 14", "f8 15", "f8 16",
                     "f8 ff", "a1 00 f7")
        for text, value in (("f4", False), ("f5", True), ("f6", None)):
            self.assertIs(cbor.decode(h(text)), value)

    def test_a_reserved_head_is_refused(self):
        self.refused("a reserved head", "1c", "1d", "1e", "3c", "5c", "7d", "9d", "be", "dc", "fc", "fd", "fe")

    def test_nesting_deeper_than_32_is_refused(self):
        self.assertEqual(cbor.MAX_DEPTH, 32)
        value = cbor.decode(h("81" * 32 + "01"))
        for _ in range(32):
            value = value[0]
        self.assertEqual(value, 1)
        self.refused("nesting deeper than 32", "81" * 33 + "01", "a1 00" * 33 + "01", "d2" * 33 + "01",
                     "81" * 2000 + "01", "81" * 32 + "80", "81" * 32 + "a0")
        # A tag-24 item's content is not nested CBOR to this decoder: it is a byte string, and
        # whoever decodes it starts again at depth 0.
        self.assertIsInstance(cbor.decode(h("81" * 31 + "d8 18 43 81 81 01")), list)

    def test_an_array_or_a_map_over_the_entry_limit_is_refused_as_its_head_is_read(self):
        """A head states how many entries follow. One that states more than MAX_ENTRIES is
        refused as it is read: given nothing after it, the reason is the limit's, not that the
        input ran out, which a check made anywhere after the head would give instead."""
        n = cbor.MAX_ENTRIES
        self.assertEqual(n, 1024)
        pairs = b"".join(cbor.encode(k) + b"\x00" for k in range(n + 1))
        for what, head, body, at_limit in (
                ("an array", cbor._head_bytes(4, n + 1), b"\x00" * (n + 1), [0] * n),
                ("a map", cbor._head_bytes(5, n + 1), pairs, {k: 0 for k in range(n)})):
            with self.subTest(what):
                # The head alone, and the head with every entry it states present.
                for data in (head, head + body):
                    with self.assertRefuses(CborError) as caught:
                        cbor.decode(data)
                    self.assertIn("states %d " % (n + 1), str(caught.exception))
                    self.assertIn("over the %d entry limit" % n, str(caught.exception))
                # The twin at the limit decodes, value for value.
                self.assertEqual(cbor.decode(cbor.encode(at_limit)), at_limit)

    def test_one_decode_reads_at_most_max_items_data_items(self):
        """One decode reads at most MAX_ITEMS data items, however its containers share them. An
        item counts once, as its head is read: the outermost item, each element, each key and
        each value, and a tag's content as an item of its own, so a tag-24 item is two. 63
        arrays of 64 integers in one array are 1 + 63 + 63 * 64 = 4096 items, with no container
        near the entry limit."""
        self.assertEqual(cbor.MAX_ITEMS, 4096)

        def rows(last_row):
            row = cbor._head_bytes(4, 64) + b"\x00" * 64
            return cbor._head_bytes(4, 63) + row * 62 + last_row

        at_limit = rows(cbor._head_bytes(4, 64) + b"\x00" * 64)
        self.assertEqual(cbor.decode(at_limit), [[0] * 64 for _ in range(63)])
        # Each of these is one item over: an integer more in the last array, or its last
        # integer made a tag over a text string, or a tag-24 item, each two items for one.
        for what, last_row in (
                ("an integer more", cbor._head_bytes(4, 65) + b"\x00" * 65),
                ("a tag 0 over a text string", cbor._head_bytes(4, 64) + b"\x00" * 63 + h("c0 61 61")),
                ("a tag-24 item", cbor._head_bytes(4, 64) + b"\x00" * 63 + h("d8 18 40"))):
            with self.subTest(what):
                with self.assertRefuses(CborError) as caught:
                    cbor.decode(rows(last_row))
                self.assertIn("more than 4096 data items in one decode", str(caught.exception))
        # The count is one decode's: the same bytes decoded twice, or inside a tag-24 item that
        # another decode reads, start again from nothing.
        self.assertEqual(cbor.decode(at_limit), cbor.decode(at_limit))
        wrapped = cbor.decode(cbor.encode(cbor.tag24(at_limit)))
        self.assertEqual(cbor.decode(wrapped.inner), [[0] * 64 for _ in range(63)])

    def test_each_key_and_each_value_of_a_map_counts_toward_max_items(self):
        """A map's keys and values count toward MAX_ITEMS as an array's elements do. Two maps of
        1024 pairs in one array are 1 + 2 + 2 * 2048 = 4099 items, with no container over the
        entry limit, and are refused; a map of 1024 pairs, one of 1022 and an integer, in an array
        of three, are 1 + 3 + 2 * 2046 = 4096 items and decode, value for value."""
        def a_map(pairs):
            return {k: 0 for k in range(pairs)}

        with self.assertRefuses(CborError) as caught:
            cbor.decode(cbor.encode([a_map(1024)] * 2))
        self.assertIn("more than 4096 data items in one decode", str(caught.exception))
        at_limit = [a_map(1024), a_map(1022), 0]
        self.assertEqual(cbor.decode(cbor.encode(at_limit)), at_limit)

    def test_a_response_over_either_limit_is_refused_as_malformed(self):
        """Through the verdict: a DeviceResponse that is one map head over the entry limit, or
        more items than one decode reads, is refused as malformed, and nothing raises."""
        over_items = cbor._head_bytes(4, 17) + (cbor._head_bytes(4, 1024) + b"\x00" * 1024) * 17
        for data, why in ((cbor._head_bytes(5, cbor.MAX_ENTRIES + 1), "over the 1024 entry limit"),
                          (over_items, "more than 4096 data items")):
            with self.subTest(why):
                v = judge(data)
                self.assertEqual((v.authentic, v.code), (False, "malformed"))
                self.assertIn(why, v.reason)

    def test_an_oversized_response_is_refused_before_parsing(self):
        self.assertEqual(mdoc.MAX_DEVICE_RESPONSE_BYTES, 512 * 1024)
        # A byte string of exactly the limit and of one byte more, each a well-formed CBOR item, so
        # that the size is the only thing wrong with the second.
        at_limit = b"\x5a" + (512 * 1024 - 5).to_bytes(4, "big") + bytes(512 * 1024 - 5)
        over = b"\x5a" + (512 * 1024 - 4).to_bytes(4, "big") + bytes(512 * 1024 - 4)
        self.assertEqual((len(at_limit), len(over)), (512 * 1024, 512 * 1024 + 1))
        with mock.patch.object(mdoc.cbor, "decode", wraps=cbor.decode) as decode:
            v = judge(over)
            self.assertEqual((v.authentic, v.code), (False, "malformed"))
            self.assertIn("over the %d byte limit" % (512 * 1024), v.reason)
            # The decoder has read the caller's transcript, and was never given the response.
            given = [call.args[0] for call in decode.call_args_list]
            self.assertEqual(given, [TRANSCRIPT])
            # The control: at the limit the decoder is given it, and it is refused for another reason.
            v = judge(at_limit)
            self.assertEqual((v.authentic, v.code), (False, "malformed"))
            self.assertNotIn("byte limit", v.reason)
            self.assertEqual([call.args[0] for call in decode.call_args_list], [TRANSCRIPT, TRANSCRIPT, at_limit])


# --------------------------------------------------------------------------- test material
#
# Everything below is built by this file on cbor2 and `cryptography`, never by the code under
# test: a wallet and an issuer of our own, so that the verifier's encoder and its reading of a
# structure are each held to a second implementation. The keys are made at import and live for
# the run. The material is valid at the real clock, because the live path reads no other.

MDL = "org.iso.18013.5.1.mDL"
MDL_NS = "org.iso.18013.5.1"
PID = "eu.europa.ec.eudi.pid.1"
ID_MDL_DS = x509.ObjectIdentifier("1.0.18013.5.1.2")
UTC = datetime.timezone.utc
BOOT = datetime.datetime.now(UTC).replace(microsecond=0)
DER = serialization.Encoding.DER
P256, P384, P521 = ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()


def days(n):
    return datetime.timedelta(days=n)


def seconds(n):
    return datetime.timedelta(seconds=n)


def x509_name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def key_usage(*, sign=False, cert_sign=False, encipher=False):
    return x509.KeyUsage(digital_signature=sign, content_commitment=False, key_encipherment=encipher,
                         data_encipherment=False, key_agreement=False, key_cert_sign=cert_sign,
                         crl_sign=cert_sign, encipher_only=False, decipher_only=False)


def make_cert(cn, public_key, issuer_cn, issuer_key, *, ca=None, path_length=None, usage=None, eku=None,
              ski=False, not_before=None, not_after=None, extra=()):
    """One certificate. `ca` None states no basicConstraints; `usage` is "sign", "ca", "tls" or
    None (no keyUsage); `eku` a list of OIDs or None; `extra` further (extension, critical) pairs."""
    builder = (x509.CertificateBuilder().subject_name(x509_name(cn)).issuer_name(x509_name(issuer_cn))
               .public_key(public_key).serial_number(x509.random_serial_number())
               .not_valid_before(not_before or BOOT - days(1))
               .not_valid_after(not_after or BOOT + days(365)))
    if ca is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length if ca else None), critical=True)
    if usage is not None:
        builder = builder.add_extension(
            key_usage(sign=usage == "sign", cert_sign=usage == "ca", encipher=usage == "tls"), critical=True)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=True)
    if ski:
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    for extension, critical in extra:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(issuer_key, hashes.SHA256())


def make_root(cn="Test IACA", *, path_length=0, **kw):
    key = ec.generate_private_key(P256)
    return key, make_cert(cn, key.public_key(), cn, key, ca=True, path_length=path_length, usage="ca",
                          ski=True, **kw)


def make_ca(cn, issuer_cn, issuer_key, *, path_length=0, **kw):
    key = ec.generate_private_key(P256)
    return key, make_cert(cn, key.public_key(), issuer_cn, issuer_key, ca=True, path_length=path_length,
                          usage="ca", ski=True, **kw)


def make_ds(issuer_key=None, issuer_cn="Test IACA", *, key=None, curve=P256, cn="Test Document Signer",
            usage="sign", eku=(ID_MDL_DS,), ski=True, **kw):
    """A document signer certificate. The default is the mDL profile: issued by the IACA, with a
    SubjectKeyIdentifier, the id-mdl-ds extended key usage and digitalSignature."""
    key = key or ec.generate_private_key(curve)
    return key, make_cert(cn, key.public_key(), issuer_cn, IACA_KEY if issuer_key is None else issuer_key,
                          usage=usage, eku=eku, ski=ski, **kw)


def der(cert):
    return cert.public_bytes(DER)


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def public_jwk(key):
    numbers = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(numbers.x.to_bytes(32, "big")),
            "y": b64u(numbers.y.to_bytes(32, "big")), "use": "enc", "alg": "ECDH-ES", "kid": "enc-1"}


def witness_thumbprint(jwk):
    """RFC 7638, written here on json and hashlib: the members of an EC key in lexical order."""
    text = '{"crv":"%s","kty":"%s","x":"%s","y":"%s"}' % (jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
    return hashlib.sha256(text.encode()).digest()


def witness_transcript(client_id, nonce, thumbprint, response_uri):
    """OpenID4VP 1.0 B.2.6.1 as a wallet builds it, here on cbor2: the structure, not its bytes,
    because a wallet embeds it in DeviceAuthentication."""
    info = cbor2.dumps([client_id, nonce, thumbprint, response_uri])
    return [None, None, ["OpenID4VPHandover", hashlib.sha256(info).digest()]]


IACA_KEY, IACA = make_root()
DS_KEY, DS = make_ds()
DEVICE_KEY = ec.generate_private_key(P256)
RESPONSE_KEY = ec.generate_private_key(P256)
REQUEST = {"client_id": "x509_hash:hYCOwiQt8Akv_CE2qZS6GVgh5kS9WyUVIbKa3TqGjXs",
           "nonce": "mG3v7Rz0qLw5Hc1TfYb8NdQ2xK9pJ4sV6uA1eZ0oWcI",
           "response_uri": "https://verifier.example/response"}
ENC_JWK = public_jwk(RESPONSE_KEY)
WALLET_TRANSCRIPT = witness_transcript(REQUEST["client_id"], REQUEST["nonce"], witness_thumbprint(ENC_JWK),
                                       REQUEST["response_uri"])
#: What the verifier builds for the same request, with the code under test.
TRANSCRIPT = mdoc.redirect_session_transcript(jwk_thumbprint=mdoc.jwk_thumbprint(ENC_JWK), **REQUEST)
ROOTS = [IacaRoot(IACA, [MDL, PID])]

HASH_OF_ALG = {-7: hashes.SHA256, -9: hashes.SHA256, -35: hashes.SHA384}
HASHLIB_NAME = {"SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512", "SHA-1": "sha1"}


def cose_key(public_key):
    numbers = public_key.public_numbers()
    size = (public_key.curve.key_size + 7) // 8
    crv = {"secp256r1": 1, "secp384r1": 2, "secp521r1": 3}[public_key.curve.name]
    return {1: 2, -1: crv, -2: numbers.x.to_bytes(size, "big"), -3: numbers.y.to_bytes(size, "big")}


def raw_signature(key, signed, hash_cls):
    """ECDSA as COSE carries it: r and s, each at the key's length (RFC 9053 2.1)."""
    r, s = decode_dss_signature(key.sign(signed, ec.ECDSA(hash_cls())))
    size = (key.curve.key_size + 7) // 8
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def sign1(key, protected, unprotected, payload, *, detached=False, hash_cls=None, tag=False,
          protected_bytes=None, encode_signature=raw_signature):
    """A COSE_Sign1 over `payload` (RFC 9052 4.4), as the array or under tag 18."""
    if protected_bytes is None:
        protected_bytes = cbor2.dumps(protected) if protected else b""
    signed = cbor2.dumps(["Signature1", protected_bytes, b"", payload])
    if isinstance(key, ed25519.Ed25519PrivateKey):
        signature = key.sign(signed)
    else:
        alg = protected.get(1) if isinstance(protected, dict) else None
        if alg is None and isinstance(unprotected, dict):
            alg = unprotected.get(1)
        known = HASH_OF_ALG.get(alg) if type(alg) is int else None
        signature = encode_signature(key, signed, hash_cls or known or hashes.SHA256)
    out = [protected_bytes, unprotected, None if detached else payload, signature]
    return cbor2.CBORTag(18, out) if tag else out


def tdate(when):
    return cbor2.CBORTag(0, when.strftime("%Y-%m-%dT%H:%M:%SZ"))


def el(element, value, ns=MDL_NS, *, digest_id=None, random=None):
    return {"ns": ns, "element": element, "value": value, "digest_id": digest_id, "random": random}


DEFAULT_ITEMS = (el("family_name", "Mustermann"), el("age_over_21", True))


def mint(*, doctype=MDL, items=DEFAULT_ITEMS, ds=None, ds_key=None, x5chain=None, issuer_protected=None,
         issuer_unprotected=None, issuer_hash=None, issuer_tag=False, issuer_protected_bytes=None,
         issuer_signature=raw_signature, issuer_detached=False, mso_payload=None,
         device_key=None, mso_device_key=None, device_protected=None, device_unprotected=None,
         device_hash=None, device_detached=True, device_signature=raw_signature, device_auth="signature",
         device_namespaces=b"\xa0", device_doctype=None, wallet_transcript=None,
         signed=None, valid_from=None, valid_until=None, digest_alg="SHA-256", digest_over="raw",
         edit_mso=None, edit_items=None, edit_doc=None, edit_response=None):
    """One DeviceResponse, as bytes. With no argument: an mDL the default root's document signer
    issued, two elements, an ES256 device signature over this file's request. Every knob changes
    one thing; the `edit_` hooks get the MSO before it is signed, the IssuerSigned items after the
    MSO is signed, the document and the response before they are encoded."""
    ds = DS if ds is None else ds
    ds_key = DS_KEY if ds_key is None else ds_key
    device_key = DEVICE_KEY if device_key is None else device_key
    name_spaces, digests, next_id = {}, {}, 0
    for item in items:
        digest_id = next_id if item["digest_id"] is None else item["digest_id"]
        next_id = max(next_id, digest_id) + 1
        inner = cbor2.dumps({"digestID": digest_id, "random": item["random"] or os.urandom(32),
                             "elementIdentifier": item["element"], "elementValue": item["value"]})
        tagged = cbor2.CBORTag(24, inner)
        name_spaces.setdefault(item["ns"], []).append(tagged)
        covered = cbor2.dumps(tagged) if digest_over == "raw" else inner
        digests.setdefault(item["ns"], {})[digest_id] = hashlib.new(
            HASHLIB_NAME.get(digest_alg, "sha256"), covered).digest()
    mso = {"version": "1.0", "digestAlgorithm": digest_alg, "valueDigests": digests,
           "deviceKeyInfo": {"deviceKey": cose_key(device_key.public_key())
                             if mso_device_key is None else mso_device_key},
           "docType": doctype,
           "validityInfo": {"signed": tdate(signed or BOOT - seconds(3600)),
                            "validFrom": tdate(valid_from or BOOT - seconds(3600)),
                            "validUntil": tdate(valid_until or BOOT + days(30))}}
    if edit_mso:
        edit_mso(mso)
    payload = (cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso))) if mso_payload is None else mso_payload(mso))
    chain = der(ds) if x5chain is None else x5chain
    issuer_auth = sign1(ds_key, {1: -7} if issuer_protected is None else issuer_protected,
                        {33: chain} if issuer_unprotected is None else issuer_unprotected, payload,
                        hash_cls=issuer_hash, tag=issuer_tag, protected_bytes=issuer_protected_bytes,
                        encode_signature=issuer_signature, detached=issuer_detached)
    dns = cbor2.CBORTag(24, device_namespaces)
    authentication = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps([
        "DeviceAuthentication", WALLET_TRANSCRIPT if wallet_transcript is None else wallet_transcript,
        device_doctype or doctype, dns])))
    signature = sign1(device_key, {1: -7} if device_protected is None else device_protected,
                      {} if device_unprotected is None else device_unprotected, authentication,
                      detached=device_detached, hash_cls=device_hash, encode_signature=device_signature)
    mac = [cbor2.dumps({1: 5}), {}, None, bytes(32)]
    auth = {"signature": {"deviceSignature": signature}, "mac": {"deviceMac": mac}, "none": {},
            "both": {"deviceSignature": signature, "deviceMac": mac}}[device_auth]
    if edit_items:
        edit_items(name_spaces)
    doc = {"docType": doctype, "issuerSigned": {"nameSpaces": name_spaces, "issuerAuth": issuer_auth},
           "deviceSigned": {"nameSpaces": dns, "deviceAuth": auth}}
    if edit_doc:
        edit_doc(doc)
    response = {"version": "1.0", "documents": [doc], "status": 0}
    if edit_response:
        edit_response(response)
    return cbor2.dumps(response)


def verify_device_response(response, **kw):
    """mdoc.verify_device_response, held to its docstring: it returns a Verdict and never raises on
    bad input, so an exception from it is that promise broken, and fails the calling test by
    assertion rather than as a test error. Only the call sits in the try: the caller builds the
    arguments, so a fixture's own exception is still an error."""
    try:
        return mdoc.verify_device_response(response, **kw)
    except Exception as exc:
        raise AssertionError("verify_device_response raised %s (%s); it returns a Verdict and never raises"
                             % (type(exc).__name__, exc)) from exc


def judge(response, *, roots=None, transcript=None, **kw):
    """verify_device_response with this file's transcript and roots."""
    return verify_device_response(response, session_transcript=TRANSCRIPT if transcript is None else transcript,
                                  iaca_roots=ROOTS if roots is None else roots, **kw)


def capture_case(name):
    """A capture's response, the request it answered, its captured instant and its root."""
    d = TESTDATA / name
    inputs = json.loads((d / "openid4vp-inputs.json").read_text())
    at = datetime.datetime.strptime((d / "captured-at.txt").read_text().strip(),
                                    "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    root = x509.load_pem_x509_certificate((d / "iaca-root.pem").read_bytes())
    return capture(name), inputs, at, root


def capture_transcript(inputs, **changes):
    values = {"client_id": inputs["client_id"], "nonce": inputs["nonce"], "response_uri": inputs["response_uri"],
              "jwk_thumbprint": mdoc.jwk_thumbprint(inputs["encryption_jwk"])}
    values.update(changes)
    return mdoc.redirect_session_transcript(**values)


class MdocCase(RefusalCase):
    """A refusal is asserted with its code and with words of its own reason, because most broken
    inputs are refused by a later rule too: a test that saw only "refused" would pass with its
    own rule removed."""

    def accepted(self, response, **kw):
        v = judge(response, **kw)
        self.assertTrue(v.authentic, "%s: %s" % (v.code, v.reason))
        self.assertEqual(v.code, "")
        return v

    def refused(self, code, words, response, **kw):
        v = judge(response, **kw)
        self.assertFalse(v.authentic, "accepted, where %s was expected" % code)
        self.assertEqual(v.code, code, v.reason)
        self.assertIn(words, v.reason)
        # A refusal carries nothing a caller could mistake for a result.
        self.assertEqual((v.claims, v.disclosed, v.issuer_subject, v.issuer_anchor, v.revocation),
                         ({}, frozenset(), None, None, None))
        return v


class CoseTests(MdocCase):
    """COSE_Sign1 as an mdoc uses it twice: IssuerAuth over the MSO, and the device signature
    over DeviceAuthentication, detached. The header rules are RFC 9052's; the algorithm set is
    ES256 (-7) and ESP256 (-9) on P-256 and ES384 (-35) on P-384, read from the protected header."""

    def decoded(self, value):
        return cbor.decode(cbor2.dumps(value))

    def test_each_algorithm_verifies_on_its_own_curve(self):
        """The positive controls the refusals below are measured against."""
        self.accepted(mint())
        self.accepted(mint(issuer_protected={1: -9}, device_protected={1: -9}))
        ds_key, ds = make_ds(curve=P384)
        device = ec.generate_private_key(P384)
        self.accepted(mint(ds=ds, ds_key=ds_key, issuer_protected={1: -35},
                           device_key=device, device_protected={1: -35}))
        # Under tag 18, and with the x5chain as an array of one.
        self.accepted(mint(issuer_tag=True, x5chain=[der(DS)]))

    def test_an_algorithm_outside_the_set_is_refused(self):
        self.refused("issuer_signature", "no alg in the protected header", mint(issuer_protected={}))
        ed_key = ed25519.Ed25519PrivateKey.generate()
        ed_ds = make_cert("Test Document Signer", ed_key.public_key(), "Test IACA", IACA_KEY, usage="sign",
                          eku=[ID_MDL_DS], ski=True)
        self.refused("issuer_signature", "alg is -8", mint(ds=ed_ds, ds_key=ed_key, issuer_protected={1: -8}))
        for alg in (-36, -37, -257, 0, 5, "ES256", True, None, [-7]):
            with self.subTest(alg=alg):
                self.refused("issuer_signature", "alg is %r" % (alg,), mint(issuer_protected={1: alg}))

    def test_an_alg_only_in_the_unprotected_header_is_refused(self):
        self.refused("issuer_signature", "no alg in the protected header",
                     mint(issuer_protected={}, issuer_unprotected={1: -7, 33: der(DS)}))

    def test_a_crit_header_is_refused(self):
        # Signed over these headers, so the crit parameter is the only thing wrong with each.
        self.refused("issuer_signature", "crit", mint(issuer_protected={1: -7, 2: [1]}))
        self.refused("issuer_signature", "crit", mint(issuer_unprotected={33: der(DS), 2: [1]}))

    def test_an_algorithm_on_the_wrong_curve_is_refused(self):
        p384_key, p384_ds = make_ds(curve=P384)
        self.refused("issuer_signature", "ES384 needs a key on secp384r1",
                     mint(issuer_protected={1: -35}))
        self.refused("issuer_signature", "ES256 needs a key on secp256r1",
                     mint(ds=p384_ds, ds_key=p384_key, issuer_protected={1: -7}))
        self.refused("issuer_signature", "ESP256 needs a key on secp256r1",
                     mint(ds=p384_ds, ds_key=p384_key, issuer_protected={1: -9}))

    def test_a_label_in_both_headers_is_refused(self):
        self.refused("issuer_signature", "in both the protected and the unprotected header",
                     mint(issuer_protected={1: -7, 33: der(DS)}, issuer_unprotected={33: der(DS)}))
        # The control: the x5chain may sit in either header, alone.
        self.accepted(mint(issuer_protected={1: -7, 33: der(DS)}, issuer_unprotected={}))

    def test_a_protected_header_that_is_not_one_map_is_refused(self):
        # The alg label twice, as the bytes a2 01 26 01 26, signed as those bytes.
        self.refused("issuer_signature", "the protected header is not CBOR this verifier reads",
                     mint(issuer_protected={1: -7}, issuer_protected_bytes=h("a2 01 26 01 26")))
        self.refused("issuer_signature", "the protected header is not a map",
                     mint(issuer_protected={1: -7}, issuer_protected_bytes=h("82 01 26")))

    def test_a_signature_that_is_not_r_and_s_at_the_keys_length_is_refused(self):
        def as_der(key, signed, hash_cls):
            return key.sign(signed, ec.ECDSA(hash_cls()))

        def short(key, signed, hash_cls):
            return raw_signature(key, signed, hash_cls)[:63]

        for encode in (as_der, short):
            with self.subTest(signature=encode.__name__):
                v = self.refused("issuer_signature", "ES256 on secp256r1 needs 64", mint(issuer_signature=encode))
                self.assertIn("the signature is", v.reason)

    def test_the_signature_covers_the_protected_header(self):
        # ES256 and ESP256 are the same computation on the same key: only the header bytes differ.
        response = cbor2.loads(mint())
        auth = response["documents"][0]["issuerSigned"]["issuerAuth"]
        self.assertEqual(auth[0], cbor2.dumps({1: -7}))
        auth[0] = cbor2.dumps({1: -9})
        self.refused("issuer_signature", "signature does not verify", cbor2.dumps(response))

    def test_a_cose_sign1_is_four_items_of_these_types(self):
        good = sign1(DS_KEY, {1: -7}, {33: der(DS)}, b"payload")
        parsed = cose.parse_sign1(self.decoded(good))
        self.assertEqual((parsed.alg, parsed.payload, parsed.protected, parsed.unprotected),
                         (-7, b"payload", {1: -7}, {33: der(DS)}))
        self.assertEqual(cose.verify_sign1(parsed, DS.public_key()), "ES256")
        self.assertEqual(cose.parse_sign1(self.decoded(cbor2.CBORTag(18, good))).signature, good[3])
        for words, bad in (
                ("an array of four items", good[:3]), ("an array of four items", good + [b""]),
                ("an array of four items", {1: 2}), ("an array of four items", b"x"),
                ("an array of four items", cbor2.CBORTag(18, "COSE")),
                ("an array of four items", cbor2.CBORTag(0, good)),
                ("an array of four items", cbor2.CBORTag(1004, good)),
                ("the protected header is not a byte string", [{1: -7}] + good[1:]),
                ("the unprotected header is not a map", [good[0], [], good[2], good[3]]),
                ("the payload is neither a byte string nor null", [good[0], good[1], "payload", good[3]]),
                ("the signature is not a byte string", good[:3] + [None])):
            with self.subTest(bad=repr(bad)[:50]):
                data = self.decoded(bad)
                with self.assertRefuses(CoseError) as caught:
                    cose.parse_sign1(data)
                self.assertIn(words, str(caught.exception))

    def test_a_detached_payload_is_supplied_by_the_caller_and_only_then(self):
        detached = cose.parse_sign1(self.decoded(sign1(DS_KEY, {1: -7}, {}, b"payload", detached=True)))
        self.assertIsNone(detached.payload)
        self.assertEqual(cose.verify_sign1(detached, DS.public_key(), b"payload"), "ES256")
        for payload, words in ((None, "no payload"), (b"other", "signature does not verify")):
            with self.assertRefuses(CoseError) as caught:
                cose.verify_sign1(detached, DS.public_key(), payload)
            self.assertIn(words, str(caught.exception))
        # A COSE_Sign1 that carries its payload is verified over that one, and a second is refused.
        attached = cose.parse_sign1(self.decoded(sign1(DS_KEY, {1: -7}, {}, b"payload")))
        with self.assertRefuses(CoseError) as caught:
            cose.verify_sign1(attached, DS.public_key(), b"payload")
        self.assertIn("carries its own payload", str(caught.exception))
        # A key that is no elliptic-curve key at all.
        with self.assertRefuses(CoseError) as caught:
            cose.verify_sign1(detached, ed25519.Ed25519PrivateKey.generate().public_key(), b"payload")
        self.assertIn("ES256 needs a key on secp256r1", str(caught.exception))

    def test_the_x5chain_is_one_certificate_or_an_array_of_them(self):
        def parsed_of(value, protected=None):
            return cose.parse_sign1(self.decoded(
                sign1(DS_KEY, protected or {1: -7}, {} if value is None else {33: value}, b"p")))

        def chain_of(value, protected=None):
            return cose.x5chain(parsed_of(value, protected))

        self.assertEqual(chain_of(b"one"), [b"one"])
        self.assertEqual(chain_of([b"one", b"two"]), [b"one", b"two"])
        self.assertEqual(chain_of(None, {1: -7, 33: b"one"}), [b"one"])
        for words, bad in (("no x5chain", None), ("neither a certificate nor an array of certificates", []),
                           ("neither a certificate nor an array of certificates", "text"),
                           ("neither a certificate nor an array of certificates", [b"one", "two"]),
                           ("neither a certificate nor an array of certificates", {1: b"one"}),
                           ("neither a certificate nor an array of certificates", b"")):
            with self.subTest(bad=bad):
                parsed = parsed_of(bad)
                with self.assertRefuses(CoseError) as caught:
                    cose.x5chain(parsed)
                self.assertIn(words, str(caught.exception))

    def test_the_device_signature_is_held_to_the_same_headers(self):
        self.refused("device_auth", "no alg in the protected header", mint(device_protected={}))
        self.refused("device_auth", "no alg in the protected header",
                     mint(device_protected={}, device_unprotected={1: -7}))
        self.refused("device_auth", "alg is -8", mint(device_protected={1: -8}))
        self.refused("device_auth", "crit", mint(device_protected={1: -7, 2: [1]}))
        self.refused("device_signature", "ES384 needs a key on secp384r1", mint(device_protected={1: -35}))
        self.refused("device_signature", "ES256 on secp256r1 needs 64",
                     mint(device_signature=lambda key, signed, hash_cls: key.sign(signed, ec.ECDSA(hash_cls()))))
        # A parameter this verifier does not read, in the unprotected header, changes nothing:
        # M1's captures carry an empty x5chain there.
        self.accepted(mint(device_unprotected={33: [], 4: b"kid"}))


class NoBackendTests(MdocCase):
    """Without the cryptography package nothing is verified, and the verdict says so rather than
    reading as a refusal of the credential. The package is present in every run of this suite,
    so its absence is the flag each module reads, set here."""

    def test_without_the_cryptography_package_nothing_is_verified(self):
        response = mint()
        with mock.patch.object(mdoc.sdjwt, "_HAVE_CRYPTO", False):
            v = self.refused("no_backend", "the cryptography package is not installed", response)
            self.assertIn("rather than reading this as a refusal of the credential", v.reason)
            with self.assertRefuses(ValueError) as caught:
                IacaRoot(IACA, [MDL])
            self.assertIn("the cryptography package is not installed", str(caught.exception))
        signed = cose.parse_sign1(cbor.decode(cbor2.dumps(sign1(DS_KEY, {1: -7}, {}, b"payload"))))
        with mock.patch.object(cose, "_HAVE_CRYPTO", False):
            with self.assertRefuses(CoseError) as caught:
                cose.verify_sign1(signed, DS.public_key())
            self.assertIn("the cryptography package is not installed", str(caught.exception))
        # The controls: the same three with the flags as they were.
        self.accepted(response)
        self.assertEqual(IacaRoot(IACA, [MDL]).certificate, IACA)
        self.assertEqual(cose.verify_sign1(signed, DS.public_key()), "ES256")


class TranscriptTests(RefusalCase):
    """The SessionTranscript of a redirect request, OpenID4VP 1.0 B.2.6.1."""

    SPEC = {"client_id": "x509_san_dns:example.com", "nonce": "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
            "response_uri": "https://example.com/response"}
    SPEC_JWK = {"kty": "EC", "crv": "P-256", "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
                "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc", "use": "enc", "alg": "ECDH-ES", "kid": "1"}
    SPEC_THUMBPRINT = "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"
    SPEC_TRANSCRIPT = ("83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b"
                       "046b11b68013722aad38ac")

    def test_the_redirect_transcript_reproduces_b261(self):
        thumbprint = mdoc.jwk_thumbprint(self.SPEC_JWK)
        self.assertEqual(thumbprint.hex(), self.SPEC_THUMBPRINT)
        got = mdoc.redirect_session_transcript(jwk_thumbprint=thumbprint, **self.SPEC)
        self.assertIsInstance(got, bytes)
        self.assertEqual(got.hex(), self.SPEC_TRANSCRIPT)

    def test_the_thumbprint_reads_the_key_and_nothing_else(self):
        # RFC 7638 3.2: only the required members of the key type, so `use`, `alg` and `kid` change nothing.
        bare = {k: self.SPEC_JWK[k] for k in ("kty", "crv", "x", "y")}
        self.assertEqual(mdoc.jwk_thumbprint(bare).hex(), self.SPEC_THUMBPRINT)
        self.assertEqual(mdoc.jwk_thumbprint(ENC_JWK), witness_thumbprint(ENC_JWK))
        for bad in (None, "jwk", [], {}, {**bare, "kty": "OKP"}, {**bare, "x": 5}, {**bare, "y": ""},
                    {k: bare[k] for k in ("kty", "crv", "x")}, {**bare, "crv": None},
                    {**bare, "x": bare["x"] + '","y":"'}):
            with self.subTest(jwk=bad):
                with self.assertRefuses(ValueError):
                    mdoc.jwk_thumbprint(bad)

    def test_the_transcript_equals_the_wallets_own_bytes(self):
        """Each encrypted capture records the SessionTranscript its wallet built; ours equals it."""
        for name in ("capture-pid", "capture-mdl"):
            with self.subTest(capture=name):
                _, inputs, _, _ = capture_case(name)
                self.assertEqual(b64u(mdoc.jwk_thumbprint(inputs["encryption_jwk"])), inputs["jwk_thumbprint"])
                self.assertEqual(capture_transcript(inputs).hex(), inputs["wallet_session_transcript_hex"])

    def test_the_transcript_equals_the_witness_encoding(self):
        self.assertEqual(TRANSCRIPT, cbor2.dumps(WALLET_TRANSCRIPT))

    def test_every_input_is_required(self):
        """No transcript is built from a missing value, and none without the response key: this
        verifier reads encrypted responses only, and B.2.6.1's null thumbprint is the unencrypted case."""
        good = {"jwk_thumbprint": bytes(32), **self.SPEC}
        self.assertIsInstance(mdoc.redirect_session_transcript(**good), bytes)
        for name, bad in (("client_id", ""), ("client_id", None), ("client_id", b"x509_hash:abc"),
                          ("nonce", ""), ("nonce", None), ("nonce", 5),
                          ("response_uri", ""), ("response_uri", None),
                          ("jwk_thumbprint", None), ("jwk_thumbprint", bytes(31)), ("jwk_thumbprint", bytes(33)),
                          ("jwk_thumbprint", "a" * 32), ("jwk_thumbprint", b"")):
            with self.subTest(name=name, bad=bad):
                with self.assertRefuses(ValueError) as caught:
                    mdoc.redirect_session_transcript(**{**good, name: bad})
                self.assertIn(name, str(caught.exception))


class IacaRootTests(RefusalCase):
    """A root is a certificate bound to the docTypes it may sign, and is refused when it is made,
    not when the first wallet answers."""

    def test_a_root_is_a_ca_certificate_bound_to_doctypes(self):
        root = IacaRoot(IACA, [MDL, PID])
        self.assertEqual(root.doctypes, frozenset((MDL, PID)))
        self.assertEqual(root.certificate, IACA)
        # PEM, as text or bytes, and DER are read too.
        pem = IACA.public_bytes(serialization.Encoding.PEM)
        for form in (pem, pem.decode(), der(IACA)):
            self.assertEqual(IacaRoot(form, (MDL,)).certificate, IACA)

    def test_a_root_without_doctypes_is_refused(self):
        for bad in ((), [], None, MDL, [""], [MDL, 5], [b"org.iso.18013.5.1.mDL"], 7):
            with self.subTest(doctypes=bad):
                with self.assertRefuses(ValueError) as caught:
                    IacaRoot(IACA, bad)
                self.assertIn("docType", str(caught.exception))

    def test_a_certificate_that_is_not_a_ca_or_does_not_parse_is_refused(self):
        with self.assertRefuses(ValueError) as caught:
            IacaRoot(DS, [MDL])
        self.assertIn("not a CA certificate", str(caught.exception))
        # A self-signed certificate that states no basicConstraints is not a CA either.
        bare_key = ec.generate_private_key(P256)
        bare = make_cert("Bare", bare_key.public_key(), "Bare", bare_key)
        with self.assertRefuses(ValueError) as caught:
            IacaRoot(bare, [MDL])
        self.assertIn("not a CA certificate", str(caught.exception))
        # Each refusal by its own words: one falls through to the next when it is taken away.
        for junk in (b"", b"not a certificate", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
                     "caf\u00e9", bytearray(b"\x30\x03\x02\x01\x01")):
            with self.subTest(junk=junk):
                with self.assertRefuses(ValueError) as caught:
                    IacaRoot(junk, [MDL])
                self.assertIn("the IACA root certificate does not parse", str(caught.exception))
        for junk in (5, None, [IACA]):
            with self.subTest(junk=junk):
                with self.assertRefuses(ValueError) as caught:
                    IacaRoot(junk, [MDL])
                self.assertIn("PEM or DER, not a %s" % type(junk).__name__, str(caught.exception))


def nested_issuer_alt_name():
    """An issuerAltName whose value is an Extension wrapped around the GeneralNames, not the
    GeneralNames themselves: SEQUENCE { OID 2.5.29.18, OCTET STRING { GeneralNames } }."""
    def tlv(tag, body):
        return bytes([tag, len(body)]) + body

    general_names = tlv(0x30, tlv(0x86, b"https://iaca.example"))
    nested = tlv(0x30, tlv(0x06, bytes.fromhex("551d12")) + tlv(0x04, general_names))
    return x509.UnrecognizedExtension(ExtensionOID.ISSUER_ALTERNATIVE_NAME, nested)


class DeviceResponseTests(MdocCase):
    """One DeviceResponse, judged against the transcript this verifier built and the roots it was
    configured with."""

    # ---- the issuer's certificate

    def test_a_document_signer_certificate_is_accepted(self):
        """The positive control every certificate refusal below is measured against: a DS issued
        directly by a test IACA, with SKI, the id-mdl-ds EKU and digitalSignature."""
        v = self.accepted(mint())
        self.assertEqual(v.reason, "")
        self.assertEqual(v.claims, {MDL_NS: {"family_name": "Mustermann", "age_over_21": True}})
        self.assertEqual(v.disclosed, frozenset(((MDL_NS, "family_name"), (MDL_NS, "age_over_21"))))
        self.assertEqual(v.issuer_subject, "CN=Test Document Signer")
        self.assertEqual(v.issuer_anchor, "CN=Test IACA")
        self.assertEqual(v.revocation["state"], "no_status_claim")
        self.assertIs(v.revocation["checked"], False)

    def test_a_tls_server_certificate_under_the_iaca_is_not_a_ds(self):
        key, tls = make_ds(usage="tls", eku=[ExtendedKeyUsageOID.SERVER_AUTH], ski=True)
        for doctype, ns in ((MDL, MDL_NS), (PID, PID)):
            with self.subTest(doctype=doctype):
                self.refused("issuer_key", "digitalSignature",
                             mint(doctype=doctype, items=(el("family_name", "x", ns),), ds=tls, ds_key=key))

    def test_the_mdl_ds_profile_is_enforced(self):
        response, inputs, at, root = capture_case("capture-mdl")
        v = verify_device_response(response, session_transcript=capture_transcript(inputs),
                                   iaca_roots=[IacaRoot(root, [MDL])], now=at)
        self.assertEqual((v.authentic, v.code), (False, "issuer_key"), v.reason)
        self.assertIn("org.iso.18013.5.1.mDL", v.reason)
        pid_items = (el("family_name", "x", PID),)
        for words, kw in (("SubjectKeyIdentifier", {"ski": False}),
                          ("1.0.18013.5.1.2", {"eku": None}),
                          # clientAuth is an extended key usage the shared rules admit for an issuer.
                          ("1.0.18013.5.1.2", {"eku": [ExtendedKeyUsageOID.CLIENT_AUTH]})):
            with self.subTest(words=words, kw=kw):
                key, ds = make_ds(**kw)
                v = self.refused("issuer_key", words, mint(ds=ds, ds_key=key))
                self.assertIn("org.iso.18013.5.1.mDL", v.reason)
                # The control: the profile is the mDL's alone. The same certificate signs a PID.
                self.accepted(mint(doctype=PID, items=pid_items, ds=ds, ds_key=key))

    def chain_of(self, length, *, root_path_length=None):
        """A root, `length` CA certificates under it one below the other, and a DS under the last."""
        root_key, root = make_root(cn="Chain Root", path_length=root_path_length)
        key, cn, cas = root_key, "Chain Root", []
        for n in range(length):
            new_key, ca = make_ca("Chain CA %d" % n, cn, key, path_length=None)
            cas.insert(0, ca)
            key, cn = new_key, "Chain CA %d" % n
        ds_key, ds = make_ds(key, cn)
        return root, cas, ds, ds_key

    def test_an_x5chain_longer_than_four_refuses(self):
        pid_items = (el("family_name", "x", PID),)
        root, cas, ds, ds_key = self.chain_of(4)
        roots = [IacaRoot(root, [PID])]
        long_chain = [der(ds)] + [der(c) for c in cas]
        self.assertEqual(len(long_chain), 5)
        self.refused("issuer_key", "x5chain carries 5 certificates; at most 4 are read",
                     mint(doctype=PID, items=pid_items, ds=ds, ds_key=ds_key, x5chain=long_chain), roots=roots)
        # Before anything is parsed or checked: six items that are not certificates get the same answer.
        self.refused("issuer_key", "x5chain carries 6 certificates; at most 4 are read",
                     mint(x5chain=[b"\x00"] * 6))
        # The control: a DS and three CA certificates are read, and chain.
        root, cas, ds, ds_key = self.chain_of(3)
        self.accepted(mint(doctype=PID, items=pid_items, ds=ds, ds_key=ds_key,
                           x5chain=[der(ds)] + [der(c) for c in cas]), roots=[IacaRoot(root, [PID])])

    def test_an_issuer_alt_name_that_is_not_general_names_refuses(self):
        """The EU age-verification reference issuer's IACA and DS certificates carry an
        issuerAltName that is not GeneralNames. A certificate with an extension that does not
        parse is refused, and never raises."""
        key, ds = make_ds(extra=((nested_issuer_alt_name(), False),))
        with self.assertRaises(ValueError):
            ds.extensions
        self.refused("issuer_key", "an extension that does not parse", mint(ds=ds, ds_key=key))
        _, iaca = make_root(cn="Nested IACA", extra=((nested_issuer_alt_name(), False),))
        with self.assertRefuses(ValueError) as caught:
            IacaRoot(iaca, [MDL])
        self.assertIn("an extension that does not parse", str(caught.exception))
        self.assertIn("issuer_alternative_name", str(caught.exception).lower().replace(" ", "_"))
        # An intermediate with the same fault is refused as well.
        root_key, root = make_root(cn="Outer Root", path_length=1)
        ca_key, ca = make_ca("Nested CA", "Outer Root", root_key, extra=((nested_issuer_alt_name(), False),))
        ds_key, ds = make_ds(ca_key, "Nested CA")
        self.refused("issuer_key", "an extension that does not parse",
                     mint(doctype=PID, items=(el("family_name", "x", PID),), ds=ds, ds_key=ds_key,
                          x5chain=[der(ds), der(ca)]), roots=[IacaRoot(root, [PID])])

    def test_a_certificate_whose_name_does_not_parse_refuses(self):
        """A certificate loads with a subject that does not parse, and raises when the name is
        first read. An intermediate is not signed for until its issuer is found, so a wallet can
        send one: every certificate's names are read once, before any path rule."""
        root, cas, ds, ds_key = self.chain_of(1)
        raw = der(cas[0])
        name = b"\x0c\x0aChain CA 0"
        self.assertEqual(raw.count(name), 1, "the subject, once: the issuer is the root's name")
        broken = raw.replace(name, b"\x0d" + name[1:])
        # ValueError under cryptography 50, KeyError under 46: whichever it is, it is not a refusal.
        with self.assertRaises((ValueError, KeyError)):
            x509.load_der_x509_certificate(broken).subject
        v = self.refused("issuer_key", "x5chain certificate 1 carries a subject that does not parse",
                         mint(doctype=PID, items=(el("family_name", "x", PID),), ds=ds, ds_key=ds_key,
                              x5chain=[der(ds), broken]), roots=[IacaRoot(root, [PID])])
        self.assertNotIn("Traceback", v.reason)

    def test_a_certificate_that_is_not_one_refuses(self):
        self.refused("issuer_key", "x5chain certificate 0 does not parse", mint(x5chain=b"\x30\x03\x02\x01\x01"))
        self.refused("issuer_key", "x5chain certificate 1 does not parse",
                     mint(x5chain=[der(DS), b"\x30\x03\x02\x01\x01"]))
        self.refused("issuer_key", "no x5chain", mint(issuer_unprotected={}))
        self.refused("issuer_key", "neither a certificate nor an array of certificates", mint(x5chain=[]))

    def test_a_ds_without_digital_signature_key_usage_refuses(self):
        for doctype, ns, eku in ((PID, PID, None), (MDL, MDL_NS, [ID_MDL_DS])):
            with self.subTest(doctype=doctype):
                key, ds = make_ds(usage="tls", eku=eku)
                self.refused("issuer_key", "does not include digitalSignature",
                             mint(doctype=doctype, items=(el("family_name", "x", ns),), ds=ds, ds_key=key))

    def test_a_ds_that_is_a_ca_refuses(self):
        key, ds = make_ds(ca=True, usage=None)
        self.refused("issuer_key", "is a CA certificate", mint(ds=ds, ds_key=key))
        # The control: basicConstraints that say it is not a CA.
        key, ds = make_ds(ca=False)
        self.accepted(mint(ds=ds, ds_key=key))

    def test_a_self_signed_ds_refuses(self):
        key = ec.generate_private_key(P256)
        ds = make_cert("Self", key.public_key(), "Self", key, usage="sign", eku=[ID_MDL_DS], ski=True)
        self.refused("issuer_key", "self-signed", mint(ds=ds, ds_key=key))

    def test_a_chain_past_its_path_length_refuses(self):
        pid_items = (el("family_name", "x", PID),)

        def answer(root, cas, ds, ds_key):
            return judge(mint(doctype=PID, items=pid_items, ds=ds, ds_key=ds_key,
                              x5chain=[der(ds)] + [der(c) for c in cas]), roots=[IacaRoot(root, [PID])])

        # The root allows no CA beneath it, and one is sent.
        v = answer(*self.chain_of(1, root_path_length=0))
        self.assertEqual((v.authentic, v.code), (False, "issuer_key"), v.reason)
        self.assertIn("does not chain to any IACA root configured for", v.reason)
        # The control: a root that allows one.
        v = answer(*self.chain_of(1, root_path_length=1))
        self.assertTrue(v.authentic, v.reason)
        # An intermediate that allows none beneath it, with one beneath it.
        root_key, root = make_root(cn="Deep Root", path_length=None)
        upper_key, upper = make_ca("Upper CA", "Deep Root", root_key, path_length=0)
        lower_key, lower = make_ca("Lower CA", "Upper CA", upper_key, path_length=0)
        ds_key, ds = make_ds(lower_key, "Lower CA")
        v = answer(root, [lower, upper], ds, ds_key)
        self.assertEqual((v.authentic, v.code), (False, "issuer_key"), v.reason)
        upper_key, upper = make_ca("Upper CA", "Deep Root", root_key, path_length=1)
        lower_key, lower = make_ca("Lower CA", "Upper CA", upper_key, path_length=0)
        ds_key, ds = make_ds(lower_key, "Lower CA")
        self.assertTrue(answer(root, [lower, upper], ds, ds_key).authentic)

    def test_an_expired_or_not_yet_valid_ds_refuses(self):
        for kw in ({"not_before": BOOT - days(30), "not_after": BOOT - days(1)},
                   {"not_before": BOOT + days(1), "not_after": BOOT + days(30)}):
            with self.subTest(**kw):
                key, ds = make_ds(**kw)
                self.refused("issuer_key", "the document signer certificate is outside its validity period",
                             mint(ds=ds, ds_key=key))

    def test_an_expired_or_not_yet_valid_iaca_root_refuses(self):
        for kw in ({"not_before": BOOT - days(700), "not_after": BOOT - days(1)},
                   {"not_before": BOOT + days(365), "not_after": BOOT + days(730)}):
            with self.subTest(**kw):
                root_key, root = make_root(cn="Dated IACA", **kw)
                key, ds = make_ds(root_key, "Dated IACA")
                self.refused("issuer_key", "the IACA root is outside its validity period",
                             mint(ds=ds, ds_key=key), roots=[IacaRoot(root, [MDL])])

    def test_a_ds_eku_naming_something_else_refuses(self):
        for eku in ([ExtendedKeyUsageOID.SERVER_AUTH], [ExtendedKeyUsageOID.TIME_STAMPING]):
            with self.subTest(eku=eku):
                key, ds = make_ds(eku=eku)
                self.refused("issuer_key", "extended key usage", mint(ds=ds, ds_key=key))
                # For a docType with no profile of its own, too: the shared rule, not the mDL's.
                self.refused("issuer_key", "extended key usage permits no",
                             mint(doctype=PID, items=(el("family_name", "x", PID),), ds=ds, ds_key=key))

    def test_an_mdl_ds_issued_through_an_intermediate_is_refused(self):
        root, cas, ds, ds_key = self.chain_of(1)
        chain = [der(ds), der(cas[0])]
        v = self.refused("issuer_key", "issued directly by its IACA",
                         mint(ds=ds, ds_key=ds_key, x5chain=chain), roots=[IacaRoot(root, [MDL, PID])])
        self.assertIn("org.iso.18013.5.1.mDL", v.reason)
        # The control: the same chain signs a docType without that rule.
        self.accepted(mint(doctype=PID, items=(el("family_name", "x", PID),), ds=ds, ds_key=ds_key,
                           x5chain=chain), roots=[IacaRoot(root, [MDL, PID])])

    def test_the_chain_refusals_speak_of_the_mdoc(self):
        """The path rules are the ones an SD-JWT VC's x5c is held to, and their reasons are written
        for it. An mdoc's refusal names the x5chain and cites no clause about x5c."""
        root_key, root = make_root(cn="Sent Root")
        sent_key, sent = make_ds(root_key, "Sent Root")
        tls_key, tls = make_ds(usage="tls")
        ca_key, ca_ds = make_ds(ca=True, usage=None)
        self_key = ec.generate_private_key(P256)
        self_ds = make_cert("Self", self_key.public_key(), "Self", self_key, usage="sign", eku=[ID_MDL_DS], ski=True)
        expired_key, expired = make_ds(not_before=BOOT - days(30), not_after=BOOT - days(1))
        eku_key, eku_ds = make_ds(eku=[ExtendedKeyUsageOID.SERVER_AUTH])
        seen = set()
        for response in (mint(ds=sent, ds_key=sent_key, x5chain=[der(sent), der(root)]),
                         mint(ds=tls, ds_key=tls_key), mint(ds=ca_ds, ds_key=ca_key),
                         mint(ds=self_ds, ds_key=self_key), mint(ds=expired, ds_key=expired_key),
                         mint(ds=eku_ds, ds_key=eku_key)):
            v = judge(response)
            self.assertEqual((v.authentic, v.code), (False, "issuer_key"), v.reason)
            self.assertNotIn("x5c ", v.reason)
            self.assertNotIn("HAIP", v.reason)
            self.assertNotIn("credential signing", v.reason)
            seen.add(v.reason)
        self.assertEqual(len(seen), 6, "six different faults, six different reasons")

    # ---- trust comes from configuration

    def test_the_pid_capture_verifies_under_its_root(self):
        response, inputs, at, root = capture_case("capture-pid")
        v = verify_device_response(response, session_transcript=capture_transcript(inputs),
                                   iaca_roots=[IacaRoot(root, [PID])], doctype=PID, now=at)
        self.assertTrue(v.authentic, "%s: %s" % (v.code, v.reason))
        self.assertEqual(v.claims, {PID: {"family_name": "Neal", "given_name": "Tyler"}})
        self.assertEqual(v.disclosed, frozenset(((PID, "family_name"), (PID, "given_name"))))
        self.assertEqual((v.issuer_subject, v.issuer_anchor), ("CN=ISSUANCE", "CN=ISSUANCE ROOT"))
        self.assertEqual(v.revocation["state"], "no_status_claim")

    def test_a_long_reason_judged_at_a_supplied_instant_is_cut_once_with_its_full_length(self):
        """The instant a refusal was judged at joins its reason before the Verdict cuts it, so the
        note counts the reason and the instant together, and says so once."""
        import re
        from polaris_oid4vp import sdjwt
        response, inputs, at, root = capture_case("capture-pid")

        def judged():
            with mock.patch.object(mdoc, "_judge",
                                   side_effect=mdoc._Refused("digest", "D" * 1000)):
                return verify_device_response(response, session_transcript=capture_transcript(inputs),
                                              iaca_roots=[IacaRoot(root, [PID])], doctype=PID, now=at)
        v = judged()
        with mock.patch.object(sdjwt, "bounded_reason", lambda text: text):
            whole = judged().reason
        self.assertEqual(v.code, "digest")
        self.assertIn("judged at the supplied instant", whole)
        self.assertLessEqual(len(v.reason), sdjwt.REASON_MAX)
        found = re.findall(r"\.\.\. \(cut at (\d+) of (\d+) characters\)", v.reason)
        self.assertEqual(len(found), 1, v.reason[-120:])
        self.assertEqual(int(found[0][1]), len(whole))

    def capture_refused(self, code, words, *, roots=None, response=None, now=None, **changes):
        captured, inputs, at, root = capture_case("capture-pid")
        v = verify_device_response(captured if response is None else response,
                                   session_transcript=capture_transcript(inputs, **changes),
                                   iaca_roots=[IacaRoot(root, [PID])] if roots is None else roots,
                                   now=at if now is None else now)
        self.assertEqual((v.authentic, v.code), (False, code), v.reason)
        self.assertIn(words, v.reason)
        self.assertEqual(v.claims, {})
        return v

    def test_no_root_refuses_and_never_skips(self):
        none = "no IACA root is configured, so nothing can be said about who signed this document"
        self.capture_refused("issuer_key", none, roots=[])
        self.capture_refused("issuer_key", none, roots=())
        v = verify_device_response(mint(), session_transcript=TRANSCRIPT, iaca_roots=None)
        self.assertEqual((v.authentic, v.code), (False, "issuer_key"), v.reason)
        self.assertIn(none, v.reason)
        self.refused("issuer_key", none, mint(), roots=[])

    def test_an_unrelated_root_refuses(self):
        _, other = make_root(cn="ISSUANCE ROOT")
        self.capture_refused("issuer_key", "does not chain to any IACA root configured for",
                             roots=[IacaRoot(other, [PID])])
        _, other = make_root()
        self.refused("issuer_key", "does not chain to any IACA root configured for",
                     mint(), roots=[IacaRoot(other, [MDL])])

    def test_a_root_not_configured_for_the_doctype_refuses(self):
        _, _, _, root = capture_case("capture-pid")
        v = self.capture_refused("issuer_key", "no IACA root is configured for", roots=[IacaRoot(root, [MDL])])
        self.assertIn(PID, v.reason)
        self.refused("issuer_key", "no IACA root is configured for", mint(), roots=[IacaRoot(IACA, [PID])])

    def test_each_root_admits_only_its_doctypes(self):
        other_key, other = make_root(cn="Other IACA")
        other_ds_key, other_ds = make_ds(other_key, "Other IACA")
        roots = [IacaRoot(IACA, [MDL]), IacaRoot(other, [PID])]
        pid_items = (el("family_name", "x", PID),)
        # A DS under the first root signs the second root's docType.
        v = self.refused("issuer_key", "does not chain to any IACA root configured for",
                         mint(doctype=PID, items=pid_items), roots=roots)
        self.assertIn(PID, v.reason)
        self.refused("issuer_key", "does not chain to any IACA root configured for",
                     mint(ds=other_ds, ds_key=other_ds_key), roots=roots)
        # The controls: each under its own root.
        self.assertEqual(self.accepted(mint(), roots=roots).issuer_anchor, "CN=Test IACA")
        self.assertEqual(self.accepted(mint(doctype=PID, items=pid_items, ds=other_ds, ds_key=other_ds_key),
                                       roots=roots).issuer_anchor, "CN=Other IACA")

    def test_a_root_sent_in_the_response_is_never_trusted(self):
        root_key, root = make_root(cn="Sent Root")
        key, ds = make_ds(root_key, "Sent Root")
        self.refused("issuer_key", "carries a trust anchor", mint(ds=ds, ds_key=key, x5chain=[der(ds), der(root)]))
        # Without the root beside it the same DS simply chains to nothing configured.
        self.refused("issuer_key", "does not chain to any IACA root configured for", mint(ds=ds, ds_key=key))

    def test_an_iaca_root_inside_the_x5chain_is_refused(self):
        self.refused("issuer_key", "carries a trust anchor", mint(x5chain=[der(DS), der(IACA)]))
        # A root configured for another docType is an anchor all the same.
        other_key, other = make_root(cn="Other IACA", path_length=1)
        cross = make_cert("Other IACA", other_key.public_key(), "Test IACA", IACA_KEY, ca=True, usage="ca")
        key, ds = make_ds(other_key, "Other IACA")
        self.refused("issuer_key", "carries a trust anchor",
                     mint(doctype=PID, items=(el("family_name", "x", PID),), ds=ds, ds_key=key,
                          x5chain=[der(ds), der(cross)]),
                     roots=[IacaRoot(IACA, [PID]), IacaRoot(other, [MDL])])

    def test_only_roots_bound_to_doctypes_are_read(self):
        for bad in ([IACA], [der(IACA)], IacaRoot(IACA, [MDL]), "roots", [None], 5, {MDL: IACA}):
            with self.subTest(roots=bad):
                v = verify_device_response(mint(), session_transcript=TRANSCRIPT, iaca_roots=bad)
                self.assertEqual((v.authentic, v.code), (False, "misconfigured"), v.reason)
                self.assertIn("IacaRoot", v.reason)

    # ---- the issuer's signature and the MSO

    def test_a_flipped_mso_signature_byte_refuses(self):
        response, _, _, _ = capture_case("capture-pid")
        decoded = cbor2.loads(response)
        signature = decoded["documents"][0]["issuerSigned"]["issuerAuth"][3]
        self.assertEqual(response.count(signature), 1)
        flipped = response.replace(signature, signature[:-1] + bytes([signature[-1] ^ 1]))
        self.capture_refused("issuer_signature", "signature does not verify", response=flipped)
        self.refused("issuer_signature", "signature does not verify", mint(ds_key=ec.generate_private_key(P256)))

    def test_a_detached_mso_refuses(self):
        self.refused("issuer_signature", "the MSO is not in the IssuerAuth payload", mint(issuer_detached=True))

    def test_an_mso_that_is_not_one_refuses(self):
        def edit(**changes):
            def apply(mso):
                for key, value in changes.items():
                    if value is KeyError:
                        del mso[key]
                    else:
                        mso[key] = value
            return apply

        self.refused("mso", "not MobileSecurityObjectBytes", mint(mso_payload=lambda mso: cbor2.dumps(mso)))
        self.refused("mso", "not MobileSecurityObjectBytes", mint(mso_payload=lambda mso: b"\xff"))
        self.refused("mso", "the MSO is not CBOR this verifier reads",
                     mint(mso_payload=lambda mso: cbor2.dumps(cbor2.CBORTag(24, b"\xa1\x01"))))
        self.refused("mso", "the MSO is not a map",
                     mint(mso_payload=lambda mso: cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps([1, 2])))))
        for words, change in (("version", {"version": "2.0"}), ("version", {"version": KeyError}),
                              ("version", {"version": 1}),
                              ("valueDigests", {"valueDigests": []}), ("valueDigests", {"valueDigests": KeyError}),
                              ("valueDigests", {"valueDigests": {MDL_NS: []}}),
                              ("valueDigests", {"valueDigests": {MDL_NS: {"0": b"\x00" * 32}}}),
                              ("valueDigests", {"valueDigests": {MDL_NS: {0: "digest"}}}),
                              ("valueDigests", {"valueDigests": {5: {}}}),
                              ("validityInfo", {"validityInfo": KeyError}), ("validityInfo", {"validityInfo": []})):
            with self.subTest(change=change):
                self.refused("mso", words, mint(edit_mso=edit(**change)))

    def test_a_validity_date_that_is_not_a_tdate_refuses(self):
        when = (BOOT + days(30)).strftime("%Y-%m-%dT%H:%M:%S")
        for bad in (when + "Z", cbor2.CBORTag(0, when), cbor2.CBORTag(0, when + "z"),
                    cbor2.CBORTag(0, when.replace("T", " ") + "Z"), cbor2.CBORTag(0, when.replace("T", "t") + "Z"),
                    cbor2.CBORTag(0, 1790000000), cbor2.CBORTag(1004, when[:10]),
                    cbor2.CBORTag(0, "2027-13-01T00:00:00Z"), cbor2.CBORTag(0, "2027-01-01T24:00:00Z"),
                    cbor2.CBORTag(0, "2027-01-01T00:00:60Z"), cbor2.CBORTag(0, when + "+25:00"),
                    cbor2.CBORTag(0, when + "Z\n"),
                    # An Arabic-Indic two, which Python's \d and int() both read as a digit.
                    cbor2.CBORTag(0, chr(0x662) + "027-01-01T00:00:00Z"),
                    cbor2.CBORTag(0, when + "+0200"), cbor2.CBORTag(0, when + "+00:60"), None, 5):
            for member in ("signed", "validFrom", "validUntil"):
                with self.subTest(member=member, bad=bad):
                    def apply(mso, member=member, bad=bad):
                        mso["validityInfo"][member] = bad
                    v = self.refused("mso", member, mint(edit_mso=apply))
                    self.assertIn("date and time", v.reason)

        def without(member):
            def apply(mso):
                del mso["validityInfo"][member]
            return apply

        for member in ("signed", "validFrom", "validUntil"):
            self.refused("mso", member, mint(edit_mso=without(member)))

    def test_the_mso_validity_window_is_held(self):
        self.refused("credential_validity", "validUntil", mint(valid_until=BOOT - seconds(3600)))
        self.refused("credential_validity", "validFrom", mint(valid_from=BOOT + seconds(3600)))
        self.refused("credential_validity", "signed", mint(signed=BOOT + seconds(3600)))
        # The allowance for clock skew is the one an SD-JWT VC's exp and nbf get: 300 s, and its
        # edges are exact. Judged at a stated instant, so that the edge does not move with the run.
        now = BOOT.timestamp()
        self.assertEqual(mdoc.DEFAULT_MAX_SKEW_SECONDS, 300)
        for kw, authentic in (({"valid_until": BOOT - seconds(300)}, True), ({"valid_until": BOOT - seconds(301)}, False),
                              ({"valid_from": BOOT + seconds(300)}, True), ({"valid_from": BOOT + seconds(301)}, False),
                              ({"signed": BOOT + seconds(300)}, True), ({"signed": BOOT + seconds(301)}, False)):
            with self.subTest(**kw):
                v = judge(mint(**kw), now=now)
                self.assertEqual(v.authentic, authentic, v.reason)
                if not authentic:
                    self.assertEqual(v.code, "credential_validity")
        v = judge(mint(valid_until=BOOT - seconds(60)), now=now, max_skew_seconds=0)
        self.assertEqual((v.authentic, v.code), (False, "credential_validity"), v.reason)

    def test_a_date_with_an_offset_or_a_fraction_is_read_as_its_instant(self):
        """RFC 3339 allows a numeric offset and a fraction of a second, and tag 0 carries RFC 3339."""
        now = BOOT.timestamp()

        def until(text):
            def apply(mso):
                mso["validityInfo"]["validUntil"] = cbor2.CBORTag(0, text)
            return apply

        def local(when, offset_hours):
            return (when + seconds(3600 * offset_hours)).strftime("%Y-%m-%dT%H:%M:%S") + "%+03d:00" % offset_hours

        # The same instant an hour ahead, written at two offsets; and an instant an hour past, whose
        # wall-clock reading is ahead.
        for text, authentic in ((local(BOOT + seconds(3600), 2), True), (local(BOOT + seconds(3600), -5), True),
                                (local(BOOT - seconds(3600), 2), False), (local(BOOT - seconds(3600), 9), False),
                                ((BOOT + seconds(3600)).strftime("%Y-%m-%dT%H:%M:%S") + ".250Z", True),
                                ((BOOT - seconds(3600)).strftime("%Y-%m-%dT%H:%M:%S") + ".999999999Z", False)):
            with self.subTest(text=text):
                v = judge(mint(edit_mso=until(text)), now=now)
                self.assertEqual(v.authentic, authentic, "%s: %s" % (v.code, v.reason))
                if not authentic:
                    self.assertEqual(v.code, "credential_validity")

    def test_a_weak_or_unknown_digest_algorithm_refuses(self):
        for name in ("SHA-1", "SHA3-256", "sha-256", "SHA256", "MD5", ""):
            with self.subTest(name=name):
                self.refused("mso", "digestAlgorithm", mint(digest_alg=name))

        def no_alg(mso):
            del mso["digestAlgorithm"]

        self.refused("mso", "digestAlgorithm", mint(edit_mso=no_alg))
        # The controls: the three the MSO may name, each computed with that function.
        for name in ("SHA-256", "SHA-384", "SHA-512"):
            self.accepted(mint(digest_alg=name))

    def test_a_mismatched_doctype_refuses(self):
        def other(doc):
            doc["docType"] = PID

        # The document says PID, its signed MSO says mDL. The root admits both, so the docType is
        # the only disagreement.
        v = self.refused("doctype", "the MSO is for", mint(edit_doc=other))
        self.assertIn(MDL, v.reason)
        self.assertIn(PID, v.reason)

        def not_text(mso):
            mso["docType"] = 5

        self.refused("doctype", "the MSO is for", mint(edit_mso=not_text))

    def test_the_requested_doctype_is_held(self):
        v = self.refused("doctype", "the request asked for", mint(), doctype=PID)
        self.assertIn(PID, v.reason)
        self.assertIn(MDL, v.reason)
        self.accepted(mint(), doctype=MDL)
        # Before anything else about the document is read: no root at all, and the answer is the docType.
        self.refused("doctype", "the request asked for", mint(), doctype=PID, roots=[])
        v = verify_device_response(mint(), session_transcript=TRANSCRIPT, iaca_roots=ROOTS, doctype=5)
        self.assertEqual((v.authentic, v.code), (False, "misconfigured"), v.reason)

    # ---- the digests

    def test_a_changed_element_value_refuses(self):
        def change(name_spaces):
            item = cbor2.loads(name_spaces[MDL_NS][1].value)
            self.assertIs(item["elementValue"], True)
            item["elementValue"] = False
            name_spaces[MDL_NS][1] = cbor2.CBORTag(24, cbor2.dumps(item))

        v = self.refused("digest", "does not match the digest the MSO signs", mint(edit_items=change))
        self.assertIn("age_over_21", v.reason)

    def test_an_injected_element_without_a_signed_digest_refuses(self):
        def inject(name_spaces):
            name_spaces[MDL_NS].append(cbor2.CBORTag(24, cbor2.dumps(
                {"digestID": 7, "random": os.urandom(32), "elementIdentifier": "age_over_18",
                 "elementValue": True})))

        v = self.refused("digest", "the MSO signs no digest", mint(edit_items=inject))
        self.assertIn("age_over_18", v.reason)

    def test_digests_over_the_inner_map_are_refused(self):
        self.refused("digest", "does not match the digest the MSO signs", mint(digest_over="inner"))

    def test_an_item_moved_to_another_namespace_refuses(self):
        second = "org.iso.18013.5.1.aamva"

        def move(name_spaces):
            name_spaces[second].append(name_spaces[MDL_NS].pop())

        # Two namespaces, each with its own digest table; the moved item's digestID is one the
        # second table does not hold, and then one it does.
        items = (el("family_name", "Mustermann"), el("age_over_21", True),
                 el("organ_donor", True, second, digest_id=5))
        v = self.refused("digest", "the MSO signs no digest", mint(items=items, edit_items=move))
        self.assertIn(second, v.reason)
        items = (el("family_name", "Mustermann"), el("age_over_21", True, digest_id=5),
                 el("organ_donor", True, second, digest_id=0), el("sex", 1, second, digest_id=5))

        def move_over(name_spaces):
            name_spaces[second].pop()
            name_spaces[second].append(name_spaces[MDL_NS].pop())

        v = self.refused("digest", "does not match the digest the MSO signs", mint(items=items, edit_items=move_over))
        self.assertIn(second, v.reason)
        # The control: both namespaces as signed.
        self.assertEqual(len(self.accepted(mint(items=items)).disclosed), 4)

    def test_a_repeated_digest_id_or_element_refuses(self):
        def twice(name_spaces):
            name_spaces[MDL_NS].append(name_spaces[MDL_NS][0])

        self.refused("digest", "digestID 0 twice", mint(edit_items=twice))
        # Two values for one element, each under a digest the MSO signs.
        items = (el("age_over_21", True), el("age_over_21", False))
        self.refused("digest", "'age_over_21' twice", mint(items=items))
        # The control: the same element name in two namespaces is two elements.
        v = self.accepted(mint(items=(el("age_over_21", True), el("age_over_21", False, "org.example"))))
        self.assertEqual(v.claims, {MDL_NS: {"age_over_21": True}, "org.example": {"age_over_21": False}})

    def test_a_short_salt_refuses(self):
        self.refused("digest", "a random of 15 bytes", mint(items=(el("family_name", "x", random=bytes(15)),)))
        self.accepted(mint(items=(el("family_name", "x", random=os.urandom(16)),)))

    def test_a_malformed_item_refuses(self):
        good = {"digestID": 0, "random": bytes(32), "elementIdentifier": "family_name", "elementValue": "x"}

        def replace(value):
            def apply(name_spaces):
                name_spaces[MDL_NS][0] = value
            return apply

        def item(**changes):
            members = {**good, **changes}
            return cbor2.CBORTag(24, cbor2.dumps({k: v for k, v in members.items() if v is not KeyError}))

        for words, bad in (
                ("not IssuerSignedItemBytes", cbor2.dumps(good)), ("not IssuerSignedItemBytes", good),
                ("not CBOR this verifier reads", cbor2.CBORTag(24, b"\xa1\x01")),
                ("not a map of digestID, random, elementIdentifier and elementValue",
                 cbor2.CBORTag(24, cbor2.dumps([1]))),
                ("not a map of digestID, random, elementIdentifier and elementValue", item(digestID=KeyError)),
                ("not a map of digestID, random, elementIdentifier and elementValue", item(random=KeyError)),
                ("not a map of digestID, random, elementIdentifier and elementValue", item(elementValue=KeyError)),
                ("not a map of digestID, random, elementIdentifier and elementValue", item(elementIdentifier=KeyError)),
                ("not a map of digestID, random, elementIdentifier and elementValue", item(extra=1)),
                ("digestID", item(digestID="0")), ("digestID", item(digestID=-1)), ("digestID", item(digestID=True)),
                ("random", item(random="0123456789abcdef0123")), ("elementIdentifier", item(elementIdentifier=5)),
                ("elementIdentifier", item(elementIdentifier=""))):
            with self.subTest(words=words, bad=repr(bad)[:60]):
                self.refused("digest", words, mint(items=(el("family_name", "x", random=bytes(32)),),
                                                   edit_items=replace(bad)))

        def shape(value):
            def apply(doc):
                doc["issuerSigned"]["nameSpaces"] = value
            return apply

        for bad in ([], {MDL_NS: {}}, {5: []}, "nameSpaces"):
            with self.subTest(name_spaces=bad):
                self.refused("digest", "nameSpaces", mint(edit_doc=shape(bad)))

    def test_an_element_value_this_verifier_does_not_read_refuses(self):
        not_text = "(tag %d over something that is not text)"
        for bad, what in ((cbor2.CBORTag(0, 1790000000), not_text % 0),
                          (cbor2.CBORTag(1004, 20261115), not_text % 1004),
                          (cbor2.CBORTag(1004, b"2026-11-15"), not_text % 1004),
                          (cbor2.CBORTag(18, [b"", {}, None, b""]), "(tag 18)"),
                          (cbor2.CBORTag(24, b"\x01"), "(an embedded CBOR item, tag 24)"),
                          ([cbor2.CBORTag(18, 1)], "(tag 18)"),
                          ({"issue_date": cbor2.CBORTag(1004, 5)}, not_text % 1004),
                          # Two keys that JSON would write as one.
                          ({5: "five", "5": "text"}, "(two keys of a map read as '5')")):
            with self.subTest(value=bad):
                v = self.refused("digest", "a value this verifier does not read " + what,
                                 mint(items=(el("odd", bad),)))
                self.assertIn("odd", v.reason)

    def test_values_are_given_as_json_can_carry_them(self):
        """Byte strings as base64url, dates as their text, a map's integer keys as text; the
        signed values themselves stay as they were for the query's `values` to be held to."""
        privileges = [{"vehicle_category_code": "B", "issue_date": cbor2.CBORTag(1004, "2020-01-01"),
                       "codes": [{"code": "01", 5: b"\x00\x01"}]}]
        items = (el("portrait", b"\xff\xd8\xff\xe0"), el("birth_date", cbor2.CBORTag(1004, "1964-08-12")),
                 el("issued", cbor2.CBORTag(0, "2026-01-01T00:00:00Z")), el("driving_privileges", privileges),
                 el("height", 180), el("nothing", None), el("age_over_21", True), el("negative", -5))
        v = self.accepted(mint(items=items))
        self.assertEqual(v.claims, {MDL_NS: {
            "portrait": "_9j_4A", "birth_date": "1964-08-12", "issued": "2026-01-01T00:00:00Z",
            "driving_privileges": [{"vehicle_category_code": "B", "issue_date": "2020-01-01",
                                    "codes": [{"code": "01", "5": "AAE"}]}],
            "height": 180, "nothing": None, "age_over_21": True, "negative": -5}})
        json.dumps(v.as_dict())
        verdict, elements = mdoc.judge_device_response(mint(items=items), session_transcript=TRANSCRIPT,
                                                       iaca_roots=ROOTS)
        self.assertTrue(verdict.authentic)
        self.assertEqual(elements[(MDL_NS, "portrait")], b"\xff\xd8\xff\xe0")
        self.assertEqual(elements[(MDL_NS, "birth_date")], Tagged(1004, "1964-08-12"))
        self.assertIs(elements[(MDL_NS, "age_over_21")], True)
        self.assertEqual(set(elements), set(v.disclosed))
        # A refusal hands back no elements.
        verdict, elements = mdoc.judge_device_response(mint(), session_transcript=TRANSCRIPT, iaca_roots=[])
        self.assertEqual((verdict.authentic, elements), (False, {}))

    def test_a_document_that_discloses_nothing_is_authentic_and_empty(self):
        def nothing(doc):
            del doc["issuerSigned"]["nameSpaces"]

        v = self.accepted(mint(edit_doc=nothing))
        self.assertEqual((v.claims, v.disclosed), ({}, frozenset()))

    # ---- the device

    def test_another_nonce_refuses(self):
        self.capture_refused("device_signature", "signature does not verify", nonce="another-nonce")
        self.refused("device_signature", "signature does not verify", mint(),
                     transcript=mdoc.redirect_session_transcript(
                         jwk_thumbprint=mdoc.jwk_thumbprint(ENC_JWK), **{**REQUEST, "nonce": "another-nonce"}))

    def test_another_client_id_or_response_uri_refuses(self):
        _, inputs, _, _ = capture_case("capture-pid")
        for change in ({"client_id": "x509_hash:" + "A" * 43}, {"client_id": inputs["client_id"][len("x509_hash:"):]},
                       {"response_uri": inputs["response_uri"] + "/"}, {"response_uri": "https://other.example/response"}):
            with self.subTest(**change):
                self.capture_refused("device_signature", "signature does not verify", **change)

    def test_the_thumbprint_must_be_this_requests_key(self):
        _, inputs, _, _ = capture_case("capture-pid")
        other = mdoc.jwk_thumbprint(public_jwk(ec.generate_private_key(P256)))
        self.capture_refused("device_signature", "signature does not verify", jwk_thumbprint=other)
        # The null thumbprint is the transcript of an unencrypted response. This verifier builds
        # none, so the witness encoding stands in for it: the capture is refused under that too.
        null = cbor2.dumps(witness_transcript(inputs["client_id"], inputs["nonce"], None, inputs["response_uri"]))
        captured, _, at, root = capture_case("capture-pid")
        v = verify_device_response(captured, session_transcript=null, iaca_roots=[IacaRoot(root, [PID])], now=at)
        self.assertEqual((v.authentic, v.code), (False, "device_signature"), v.reason)
        # And a wallet that signed over the null thumbprint is refused under this request's key.
        wallet = witness_transcript(REQUEST["client_id"], REQUEST["nonce"], None, REQUEST["response_uri"])
        self.refused("device_signature", "signature does not verify", mint(wallet_transcript=wallet))

    def test_a_device_key_other_than_the_msos_refuses(self):
        other = ec.generate_private_key(P256)
        # Signed by another key, which the response sends beside the signature; the MSO names ours.
        self.refused("device_signature", "signature does not verify",
                     mint(device_key=other, mso_device_key=cose_key(DEVICE_KEY.public_key()),
                          device_unprotected={-70001: cose_key(other.public_key())}))
        self.accepted(mint(device_key=other))

    def test_a_device_key_that_is_not_ec2_p256_or_p384_refuses(self):
        good = cose_key(DEVICE_KEY.public_key())
        p521 = cose_key(ec.generate_private_key(P521).public_key())
        for words, bad in (("EC2", {1: 1, -1: 6, -2: bytes(32)}), ("EC2", {1: 1, -1: 1, -2: good[-2], -3: good[-3]}),
                           ("P-256 or P-384", p521), ("P-256 or P-384", {**good, -1: 8}),
                           ("P-256 or P-384", {**good, -1: "P-256"}),
                           ("EC2", {**good, 1: "EC"}), ("EC2", {k: v for k, v in good.items() if k != 1}),
                           ("not a COSE_Key", [1, 2]), ("not a COSE_Key", "key"), ("not a COSE_Key", b"key"),
                           ("32 bytes", {**good, -2: b"\x00" + good[-2]}), ("32 bytes", {**good, -3: good[-3][1:]}),
                           ("32 bytes", {**good, -3: True}), ("32 bytes", {k: v for k, v in good.items() if k != -3}),
                           ("32 bytes", {**good, -2: 5}), ("32 bytes", {**good, -2: good[-2] + b"\x00"})):
            with self.subTest(words=words, key=repr(bad)[:50]):
                self.refused("device_key", words, mint(mso_device_key=bad))

        def no_info(mso):
            del mso["deviceKeyInfo"]

        def info_is_a_list(mso):
            mso["deviceKeyInfo"] = [good]

        def null_key(mso):
            mso["deviceKeyInfo"]["deviceKey"] = None

        def no_key(mso):
            del mso["deviceKeyInfo"]["deviceKey"]

        self.refused("device_key", "the MSO has no deviceKeyInfo", mint(edit_mso=no_info))
        self.refused("device_key", "the MSO has no deviceKeyInfo", mint(edit_mso=info_is_a_list))
        self.refused("device_key", "not a COSE_Key", mint(edit_mso=null_key))
        self.refused("device_key", "not a COSE_Key", mint(edit_mso=no_key))
        # The control: a key on P-384 is read (its signature is then held to ES384).
        p384 = ec.generate_private_key(P384)
        self.accepted(mint(device_key=p384, device_protected={1: -35}))

    def test_an_off_curve_device_key_refuses(self):
        good = cose_key(DEVICE_KEY.public_key())
        off = {**good, -3: ((int.from_bytes(good[-3], "big") + 1) % (1 << 256)).to_bytes(32, "big")}
        self.refused("device_key", "not a point on", mint(mso_device_key=off))
        self.refused("device_key", "not a point on", mint(mso_device_key={**good, -2: bytes(32), -3: bytes(32)}))

    def test_a_device_mac_or_no_device_auth_refuses(self):
        self.refused("device_auth", "a device MAC", mint(device_auth="mac"))
        self.refused("device_auth", "a device MAC", mint(device_auth="both"))
        self.refused("device_auth", "no device signature", mint(device_auth="none"))

        def no_auth(doc):
            del doc["deviceSigned"]["deviceAuth"]

        def no_device_signed(doc):
            del doc["deviceSigned"]

        def auth_is_a_list(doc):
            doc["deviceSigned"]["deviceAuth"] = [doc["deviceSigned"]["deviceAuth"]["deviceSignature"]]

        def another_member(doc):
            doc["deviceSigned"]["deviceAuth"]["deviceSeal"] = b""

        self.refused("device_auth", "no device signature", mint(edit_doc=no_auth))
        self.refused("device_auth", "no device signature", mint(edit_doc=no_device_signed))
        self.refused("device_auth", "no device signature", mint(edit_doc=auth_is_a_list))
        self.refused("device_auth", "deviceSeal", mint(edit_doc=another_member))
        self.refused("device_auth", "carries its payload", mint(device_detached=False))

        def not_a_sign1(doc):
            doc["deviceSigned"]["deviceAuth"]["deviceSignature"] = [b"", {}, None]

        self.refused("device_auth", "an array of four items", mint(edit_doc=not_a_sign1))

    def test_device_signed_elements_are_refused(self):
        signed = cbor2.dumps({MDL_NS: {"age_over_21": True}})
        v = self.refused("device_namespaces", "device-signed elements", mint(device_namespaces=signed))
        self.assertIn(MDL_NS, v.reason)
        # A namespace with no element in it is still a namespace the device signed.
        self.refused("device_namespaces", "device-signed elements", mint(device_namespaces=cbor2.dumps({MDL_NS: {}})))
        for words, inner in (("not a map", cbor2.dumps([])), ("not a map", cbor2.dumps("")),
                             ("not CBOR this verifier reads", b"\xa1"), ("not CBOR this verifier reads", b"")):
            with self.subTest(inner=inner):
                self.refused("device_namespaces", words, mint(device_namespaces=inner))

        def untagged(doc):
            doc["deviceSigned"]["nameSpaces"] = {}

        def missing(doc):
            del doc["deviceSigned"]["nameSpaces"]

        self.refused("device_namespaces", "not DeviceNameSpacesBytes", mint(edit_doc=untagged))
        self.refused("device_namespaces", "not DeviceNameSpacesBytes", mint(edit_doc=missing))

    def test_a_device_signature_over_another_doctype_refuses(self):
        self.refused("device_signature", "signature does not verify", mint(device_doctype=PID))

    # ---- the container

    def test_more_than_one_document_refuses(self):
        def two(response):
            response["documents"] = response["documents"] * 2

        def none(response):
            response["documents"] = []

        self.refused("malformed", "2 documents", mint(edit_response=two))
        self.refused("malformed", "0 documents", mint(edit_response=none))

    def test_a_status_other_than_zero_or_document_errors_refuse(self):
        def change(**members):
            def apply(response):
                for key, value in members.items():
                    if value is KeyError:
                        del response[key]
                    else:
                        response[key] = value
            return apply

        for words, members in (("status 10", {"status": 10}), ("status 11", {"status": 11}),
                               ("status", {"status": KeyError}), ("status", {"status": "0"}),
                               ("status", {"status": False}),
                               ("documentErrors", {"documentErrors": [{MDL: 0}]}),
                               ("documentErrors", {"documentErrors": []}),
                               ("version", {"version": "1.1"}), ("version", {"version": KeyError}),
                               ("version", {"version": 1}),
                               ("documents", {"documents": KeyError}), ("documents", {"documents": {}}),
                               ("a member this verifier does not read", {"readerAuth": b""})):
            with self.subTest(members=members):
                self.refused("malformed", words, mint(edit_response=change(**members)))

    def test_a_document_of_another_shape_refuses(self):
        def edit(**members):
            def apply(doc):
                for key, value in members.items():
                    if value is KeyError:
                        del doc[key]
                    else:
                        doc[key] = value
            return apply

        for words, members in (("errors", {"errors": {MDL_NS: {"age_over_18": 0}}}), ("errors", {"errors": {}}),
                               ("docType", {"docType": KeyError}), ("docType", {"docType": 5}),
                               ("docType", {"docType": ""}),
                               ("issuerSigned", {"issuerSigned": KeyError}), ("issuerSigned", {"issuerSigned": []}),
                               ("a member this verifier does not read", {"readerAuth": b""})):
            with self.subTest(members=members):
                self.refused("malformed", words, mint(edit_doc=edit(**members)))

        def not_a_map(response):
            response["documents"] = ["document"]

        def no_issuer_auth(doc):
            del doc["issuerSigned"]["issuerAuth"]

        def extra_issuer_member(doc):
            doc["issuerSigned"]["issuerSeal"] = b""

        self.refused("malformed", "a document is a map", mint(edit_response=not_a_map))
        self.refused("issuer_signature", "an array of four items", mint(edit_doc=no_issuer_auth))
        self.refused("malformed", "issuerSeal", mint(edit_doc=extra_issuer_member))

    def test_a_response_that_is_not_one_refuses(self):
        for words, bad in (("empty", b""), ("not bytes", "response"), ("not bytes", None),
                           ("not bytes", cbor2.loads(mint())),
                           ("not CBOR this verifier reads", b"\xff"), ("not CBOR this verifier reads", mint() + b"\x00"),
                           ("not CBOR this verifier reads", mint()[:-1]),
                           ("not a map", cbor2.dumps([1])), ("not a map", cbor2.dumps("DeviceResponse"))):
            with self.subTest(bad=repr(bad)[:40]):
                self.refused("malformed", words, bad)
        self.accepted(bytearray(mint()))

    def test_a_transcript_that_is_not_one_is_a_misconfiguration(self):
        for bad in (None, "transcript", WALLET_TRANSCRIPT, b"", b"\xff", cbor2.dumps([None, None]),
                    cbor2.dumps({"a": 1}), TRANSCRIPT + b"\x00"):
            with self.subTest(transcript=repr(bad)[:40]):
                v = verify_device_response(mint(), session_transcript=bad, iaca_roots=ROOTS)
                self.assertEqual((v.authentic, v.code), (False, "misconfigured"), v.reason)
                self.assertIn("session_transcript", v.reason)

    # ---- the clock, and what the verdict says of revocation

    def test_a_supplied_instant_is_stated_in_the_verdict(self):
        response, inputs, at, root = capture_case("capture-pid")
        kw = {"session_transcript": capture_transcript(inputs), "iaca_roots": [IacaRoot(root, [PID])]}
        v = verify_device_response(response, now=at, **kw)
        self.assertTrue(v.authentic)
        self.assertIn("judged at the supplied instant 2026-10-11T04:54:42Z", v.reason)
        # Judged at the clock, the capture's MSO has expired; the verdict says nothing of an instant.
        v = verify_device_response(response, **kw)
        self.assertEqual((v.authentic, v.code), (False, "credential_validity"), v.reason)
        self.assertNotIn("supplied instant", v.reason)
        self.assertEqual(self.accepted(mint()).reason, "")
        # A refusal at a supplied instant says so too: a day after the capture's validUntil.
        late = at + 32 * 86400
        v = verify_device_response(response, now=late, **kw)
        self.assertEqual((v.authentic, v.code), (False, "credential_validity"), v.reason)
        self.assertIn("judged at the supplied instant 2026-11-12T04:54:42Z", v.reason)
        for bad in ("2026-10-11T04:54:42Z", True, float("nan"), float("inf"), -1e30, [at]):
            with self.subTest(now=bad):
                v = verify_device_response(response, now=bad, **kw)
                self.assertEqual((v.authentic, v.code), (False, "misconfigured"), v.reason)
        v = verify_device_response(mint(), max_skew_seconds=-1, session_transcript=TRANSCRIPT, iaca_roots=ROOTS)
        self.assertEqual((v.authentic, v.code), (False, "misconfigured"), v.reason)

    def test_mso_status_is_reported_unchecked(self):
        def with_status(mso):
            mso["status"] = {"status_list": {"idx": 5, "uri": "https://issuer.example/status/1"}}

        v = self.accepted(mint(edit_mso=with_status))
        self.assertEqual((v.revocation["state"], v.revocation["checked"]), ("unsupported_status", False))
        self.assertIn("did not read", v.revocation["reason"])
        v = self.accepted(mint())
        self.assertEqual((v.revocation["state"], v.revocation["checked"]), ("no_status_claim", False))
        for verdict in (v, self.accepted(mint(edit_mso=with_status))):
            self.assertNotEqual(verdict.revocation["state"], "checked")
            self.assertNotIn("not revoked", json.dumps(verdict.as_dict()))


class MalformedInputTests(unittest.TestCase):
    """`CborTests.test_malformed_input_refuses_and_never_raises` of decision record 025, at the
    level it can be true at: the verifier, not the decoder, and "refused or unchanged", not
    "refused each time". Measured on capture-pid (2245 bytes, two changes to each byte, 4490 in
    all) under cryptography 50.0.1: 4487 refused (issuer_signature 2246, issuer_key 1366,
    malformed 368, digest 355, device_signature 128, device_auth 22, device_namespaces 2) and 3
    still authentic with every result as it was. Those three are bytes no check reads: the label
    of the device signature's unprotected x5chain parameter (byte 2168, both changes), and the
    unused-bits octet of the intermediate certificate's signature BIT STRING (byte 907, one
    change), which the X.509 parser reads as the same signature."""

    #: The only bytes of capture-pid whose change may leave the verdict authentic.
    UNREAD = {907: "the unused-bits octet of the intermediate certificate's signature",
              2168: "the label of the device signature's unprotected x5chain parameter"}

    def test_malformed_input_refuses_and_never_raises(self):
        response, inputs, at, root = capture_case("capture-pid")
        kw = {"session_transcript": capture_transcript(inputs), "iaca_roots": [IacaRoot(root, [PID])], "now": at}
        original = verify_device_response(response, **kw)
        self.assertTrue(original.authentic)
        data = bytearray(response)
        outcomes, kept = {}, []
        for i in range(len(data)):
            for mask in (0x01, 0xff):
                data[i] ^= mask
                with warnings.catch_warnings():
                    # A changed certificate can make the X.509 parser warn (a serial number of zero).
                    warnings.simplefilter("ignore")
                    v = verify_device_response(bytes(data), **kw)
                data[i] ^= mask
                outcomes[v.code] = outcomes.get(v.code, 0) + 1
                if v.authentic:
                    # A change that leaves the verdict authentic left every result as it was.
                    self.assertEqual((v.claims, v.disclosed, v.issuer_subject, v.issuer_anchor),
                                     (original.claims, original.disclosed, original.issuer_subject,
                                      original.issuer_anchor))
                    kept.append(i)
        self.assertEqual(bytes(data), response)
        self.assertEqual(sum(outcomes.values()), 2 * len(response))
        self.assertEqual(data[2167:2170], h("18 21 80"), "label 33 over an empty array, where it was measured")
        self.assertEqual(kept.count(2168), 2)
        self.assertLessEqual(set(kept), set(self.UNREAD))
        self.assertEqual(outcomes.pop(""), len(kept))
        for code in ("malformed", "issuer_signature", "issuer_key", "digest", "device_signature", "device_auth"):
            self.assertGreater(outcomes.get(code, 0), 0, outcomes)
        self.assertGreater(sum(outcomes.values()), 4480)


if __name__ == "__main__":
    unittest.main()
