# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_status.py -- the Token Status List decision function, held to its refusals.

The research version of this and its twenty-two adversaries live in
`lab/strategy/attack_status_list.py`, with the decision record at
`lab/strategy/001-token-status-list.md`. This is the half that ships, so it is written the way
the rest of this package's suites are: a positive control first, then every refusal, each
built deliberately.

THE BAR IS NARROWER THAN "it returns an error". Every refusal must land as `checked=False`,
because the one failure this exists to prevent is a verifier reading "I could not evaluate the
status" as "the credential is not revoked". A test that only asserted "not accepted" would
sleep through the version of this bug that matters, and did: a 404 page was reported as a
malformed list, which blames the issuer for the endpoint's failure.
"""
import base64
import datetime
import http.server
import ipaddress
import json
import os
import random
import shutil
import socket
import ssl
import tempfile
import threading
import time
import unittest
import zlib
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.x509.oid import NameOID

from polaris_oid4vp import status as S
from polaris_oid4vp import status_fetch
from polaris_oid4vp.sdjwt import verify_presentation
from test_sdjwt import AUDIENCE, NONCE, _x5c_presentation

NOW = 1_800_000_000
URI = "https://issuer.example/statuslists/1"
ISSUER = "https://issuer.example"
OTHER = "https://other.example"


def b64u(raw):
    if isinstance(raw, str):
        raw = raw.encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def token(payload, typ="statuslist+jwt"):
    return ".".join([b64u(json.dumps({"alg": "ES256", "typ": typ, "kid": "k1"})),
                     b64u(json.dumps(payload)), b64u(b"sig")])


def payload(statuses=(0, 1, 2, 0), bits=2, **over):
    p = {"sub": URI, "iat": NOW - 60, "exp": NOW + 3600, "ttl": 600,
         "status_list": {"bits": bits, "lst": S.encode_status_list(statuses, bits)}}
    p.update(over)
    return p


def accept(signing_input, signature, header):
    return True


def refuse(signing_input, signature, header):
    return False


AUTHORITY = S.StatedAuthority().state(
    credential_issuer=ISSUER, status_uri=URI, verify=accept,
    why="the operator recorded that this key publishes status for this issuer")


def decide(tok, index=1, uri=URI, issuer=ISSUER, **kw):
    return S.decide(tok, index=index, expected_uri=uri, authority=AUTHORITY,
                    credential_issuer=issuer, now=NOW, **kw)


class CritTests(unittest.TestCase):
    """RFC 7515 4.1.11, as for the credential and its key binding JWT: a crit naming an
    extension this implementation does not understand makes the JWS invalid."""

    def test_a_token_whose_crit_names_an_extension_is_refused(self):
        self.assertTrue(decide(token(payload()), issuer_key_verify=accept)["checked"],
                        "positive control: the same token without crit")
        header = {"alg": "ES256", "typ": "statuslist+jwt", "kid": "k1",
                  "crit": ["urn:x:must-understand"], "urn:x:must-understand": True}
        tok = ".".join([b64u(json.dumps(header)), b64u(json.dumps(payload())), b64u(b"sig")])
        v = decide(tok, issuer_key_verify=accept)
        self.assertFalse(v["checked"])
        self.assertEqual(v["code"], "crit")


class PositiveControlTests(unittest.TestCase):
    """If these fail, every refusal below passes for the wrong reason."""

    def test_each_published_status_reads_back(self):
        for idx, want in ((0, S.VALID), (1, S.INVALID), (2, S.SUSPENDED)):
            with self.subTest(idx=idx):
                v = decide(token(payload()), index=idx, issuer_key_verify=accept)
                self.assertTrue(v["checked"], v["reason"])
                self.assertEqual(v["status"], want)

    def test_bit_order_is_least_significant_first(self):
        """Silent if wrong: every status still decodes, to another credential's answer."""
        self.assertEqual([S.status_at(bytes([0xB9]), i, 1) for i in range(8)],
                         [1, 0, 0, 1, 1, 1, 0, 1])


class AuthorityTests(unittest.TestCase):
    """The draft does not settle who may publish status for whom, so this does."""

    def test_an_unstated_key_is_refused_not_believed(self):
        v = decide(token(payload()), issuer=OTHER)
        self.assertFalse(v["checked"])
        self.assertEqual(v["code"], "no_authority")

    def test_a_delegation_does_not_carry_across_issuers(self):
        v = decide(token(payload()), issuer=OTHER)
        self.assertEqual(v["code"], "no_authority")

    def test_the_two_bases_are_distinguishable(self):
        stated = decide(token(payload()))
        same = decide(token(payload()), issuer_key_verify=accept)
        self.assertEqual(stated["authority"], S.STATED)
        self.assertEqual(same["authority"], S.SAME_KEY)

    def test_a_crashing_authority_is_not_a_grant(self):
        def explode(**kw):
            raise RuntimeError("the delegation table is unreadable")
        v = S.decide(token(payload()), index=1, expected_uri=URI, authority=explode,
                     credential_issuer=ISSUER, now=NOW)
        self.assertFalse(v["checked"])
        self.assertEqual(v["code"], "authority_error")

    def test_a_delegation_needs_a_reason(self):
        for kw in ({"credential_issuer": "", "status_uri": URI, "verify": accept, "why": "x"},
                   {"credential_issuer": ISSUER, "status_uri": "", "verify": accept, "why": "x"},
                   {"credential_issuer": ISSUER, "status_uri": URI, "verify": None, "why": "x"},
                   {"credential_issuer": ISSUER, "status_uri": URI, "verify": accept, "why": ""}):
            with self.subTest(kw=sorted(k for k, v in kw.items() if not v)):
                with self.assertRaises(ValueError):
                    S.StatedAuthority().state(**kw)


class RefusalsTests(unittest.TestCase):
    """Each one must be checked=False, never a status."""

    def test_a_list_published_for_another_uri(self):
        v = decide(token(payload(sub="https://issuer.example/statuslists/99")),
                   issuer_key_verify=accept)
        self.assertFalse(v["checked"])
        self.assertEqual(v["code"], "sub_mismatch")

    def test_a_plain_jwt_is_not_a_status_list(self):
        v = decide(token(payload(), typ="JWT"), issuer_key_verify=accept)
        self.assertEqual(v["code"], "typ")

    def test_an_expired_list_must_not_be_used(self):
        v = decide(token(payload(exp=NOW - 1)), issuer_key_verify=accept)
        self.assertEqual(v["code"], "expired")

    def test_an_index_past_the_end_is_not_valid(self):
        v = decide(token(payload()), index=10_000, issuer_key_verify=accept)
        self.assertFalse(v["checked"])
        self.assertEqual(v["code"], "index")

    def test_an_unverified_signature(self):
        v = decide(token(payload()), issuer_key_verify=refuse)
        self.assertEqual(v["code"], "signature")

    def test_a_decompression_bomb_is_refused_without_expanding(self):
        """Without expanding, measured: what zlib produced stays within the bound. Asserting only
        the refusal passed with the bound removed, because the length check after flush()
        still refused, after inflating the whole bomb (the review routine's finding)."""
        bomb = base64.urlsafe_b64encode(
            zlib.compress(b"\x00" * (S.MAX_DECOMPRESSED_BYTES * 4), 9)).rstrip(b"=").decode()
        p = payload()
        p["status_list"]["lst"] = bomb
        real, produced = zlib.decompressobj, []

        class Counting:
            def __init__(self, *a, **kw):
                self._o = real(*a, **kw)

            def decompress(self, data, max_length=0):
                out = self._o.decompress(data, max_length)
                produced.append(len(out))
                return out

            def flush(self, *a):
                out = self._o.flush(*a)
                produced.append(len(out))
                return out

            @property
            def unconsumed_tail(self):
                return self._o.unconsumed_tail

        zlib.decompressobj = Counting
        try:
            v = decide(token(p), issuer_key_verify=accept)
        finally:
            zlib.decompressobj = real
        self.assertEqual(v["code"], "lst")
        self.assertTrue(produced, "control: the bounded inflate ran")
        self.assertLessEqual(sum(produced), S.MAX_DECOMPRESSED_BYTES,
                             "the bomb was built before it was refused")

    def test_an_unknown_status_is_not_folded_into_valid(self):
        v = decide(token(payload(statuses=(0, 3, 0, 0))), issuer_key_verify=accept)
        self.assertTrue(v["checked"])
        self.assertEqual(v["status"], 3)
        self.assertIsNone(v["meaning"])

    def test_a_list_that_inflates_to_nothing_covers_no_credential(self):
        """The empty-list refusal, aimed at directly (2026-09-25). Its only test used to be the
        case labelled "lst not base64" with "!!!", which the lenient decoder turned into zero
        bytes; since the decoder is canonical-only that case is refused where its label says,
        and this refusal needed a case of its own."""
        p = payload()
        empty = dict(p, status_list={"bits": 1, "lst": b64u(zlib.compress(b""))})
        v = decide(token(empty), issuer_key_verify=accept)
        self.assertFalse(v["checked"])
        self.assertEqual(v["code"], "lst")
        self.assertIn("empty", v["reason"])

    def test_the_decoder_accepts_only_canonical_base64url(self):
        self.assertEqual(S._b64u("QUI", "probe"), b"AB")
        for bad in ("QUJ", "QU!I", "Q UI"):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    S._b64u(bad, "probe")

    def test_hostile_input_never_raises_and_never_answers(self):
        p = payload()
        cases = [
            ("empty", ""), ("two parts", "a.b"),
            ("header not json", "Zm9v.%s.c2ln" % b64u(json.dumps(p))),
            ("no status_list", token({"sub": URI, "iat": NOW - 1, "exp": NOW + 1})),
            ("bits=3", token(dict(p, status_list={"bits": 3, "lst": p["status_list"]["lst"]}))),
            ("lst not base64", token(dict(p, status_list={"bits": 1, "lst": "!!!"}))),
            ("lst not zlib", token(dict(p, status_list={"bits": 1, "lst": b64u(b"nope")}))),
            ("iat a string", token(dict(p, iat="soon"))),
            ("iat in the future", token(dict(p, iat=NOW + 5000, exp=NOW + 9000))),
            ("no sub", token({k: v for k, v in p.items() if k != "sub"})),
        ]
        for label, tok in cases:
            with self.subTest(case=label):
                self.assertFalse(self._never_raises(tok)["checked"])
        for label, idx in (("negative", -1), ("boolean", True), ("string", "1"), ("float", 1.5)):
            with self.subTest(index=label):
                self.assertFalse(self._never_raises(token(p), index=idx)["checked"])

    def _never_raises(self, tok, **kw):
        # 2026-11-18: an exception here was an ERROR, which says only that something crashed;
        # the mutation drill reads a red of ERRORs alone as not caught. It is the promise broken.
        try:
            return decide(tok, issuer_key_verify=accept, **kw)
        except Exception as exc:  # noqa: BLE001
            self.fail("decide raised %r" % (exc,))


class HostileJsonTests(unittest.TestCase):
    """`decide` says "Total on hostile input" on its first line. Hold it to that.

    2026-09-19: this module was promoted out of lab/ into a published package without the
    bounds `sdjwt.py` next door had carried since 2026-09-17, and a token nesting 20,000
    objects deep raised RecursionError straight out of it. RecursionError is not a
    ValueError, so the `except (ValueError, UnicodeDecodeError)` around the parse never saw
    it. The body is fetched from a URI named in somebody else's credential, so it is exactly
    the input an attacker controls.

    Each case asserts the call RETURNED, not merely that it refused: a raise is the defect,
    and a test that only checked the verdict would error out rather than fail informatively.
    """

    def _decide(self, payload_text):
        tok = ".".join([b64u(json.dumps({"alg": "ES256", "typ": "statuslist+jwt"})),
                        b64u(payload_text), b64u(b"sig")])
        return decide(tok, issuer_key_verify=accept)

    def test_deep_nesting_is_refused_rather_than_raised(self):
        """Nested ARRAYS, two bytes a level, so this isolates the depth bound.

        Written first with `{"a":` nesting, which costs six bytes a level: at 20,000 levels
        that is 120 KB and the SIZE bound refused it, so removing the depth bound changed
        nothing and the test did not notice. Third time in one day a test passed because a
        different mechanism satisfied it. Two bytes a level keeps 30,000 levels inside the
        64 KiB budget, where only the depth bound can refuse it.
        """
        for depth in (10_000, 30_000):
            with self.subTest(depth=depth):
                text = "[" * depth + "]" * depth
                self.assertLess(len(text), S.MAX_JSON_BYTES,
                                "the fixture must stay under the size bound or it tests that "
                                "bound instead of this one")
                try:
                    v = self._decide(text)
                except RecursionError:
                    self.fail("nesting %d levels raised RecursionError out of a function "
                              "documented never to raise" % depth)
                self.assertFalse(v["checked"])

    def test_the_bare_json_constants_are_refused_at_the_door(self):
        """NaN and Infinity are floats, so they walk past isinstance(x, (int, float))."""
        for literal in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(literal=literal):
                v = self._decide('{"sub":"%s","iat":%s}' % (URI, literal))
                self.assertFalse(v["checked"])
                self.assertEqual(v["code"], "malformed")

    def test_an_oversized_header_is_refused(self):
        """The header keeps the 64 KiB bound: nothing honest puts a list in it."""
        tok = ".".join([b64u(json.dumps({"alg": "ES256", "typ": "statuslist+jwt",
                                         "pad": "A" * (200 * 1024)})),
                        b64u(json.dumps(payload())), b64u(b"sig")])
        v = decide(tok, issuer_key_verify=accept)
        self.assertFalse(v["checked"])
        self.assertEqual(v["code"], "malformed")

    def test_a_payload_the_token_bound_cannot_hold_is_refused(self):
        """The payload's size bound is the token's own (MAX_PAYLOAD_JSON_BYTES)."""
        v = self._decide(json.dumps({"sub": URI, "pad": "A" * S.MAX_PAYLOAD_JSON_BYTES}))
        self.assertFalse(v["checked"])
        self.assertEqual(v["code"], "malformed")

    def test_a_normal_token_is_not_caught_by_the_bounds(self):
        """The positive control for this class: the bounds must not refuse real tokens."""
        v = decide(token(payload()), issuer_key_verify=accept)
        self.assertTrue(v["checked"], v["reason"])


class ListSizeTests(unittest.TestCase):
    """A list the draft sizes as ordinary must decide (2026-10-04).

    The payload carries the compressed array, and it was held to the header's 64 KiB. The
    draft's Appendix B puts 2^20 entries at 10% revoked at 67.6 KB compressed; the OpenWallet
    Foundation's @sd-jwt/jwt-status-list 0.19.0 signs that list as a 97,153-byte payload, and
    this refused it as malformed. lab/interop/status-list decides the library's own tokens.
    """

    def test_a_million_entries_at_ten_percent_revoked_decide(self):
        rng = random.Random(7)
        statuses = [1 if rng.random() < 0.10 else 0 for _ in range(1 << 20)]
        p = payload(statuses=statuses, bits=1)
        self.assertGreater(len(json.dumps(p)), S.MAX_JSON_BYTES,
                           "the fixture must be past the header's bound, or it tests nothing")
        tok = token(p)
        for idx in (statuses.index(1), statuses.index(0), len(statuses) - 1):
            with self.subTest(index=idx):
                v = decide(tok, index=idx, issuer_key_verify=accept)
                self.assertTrue(v["checked"], v["reason"])
                self.assertEqual(v["status"], statuses[idx])


class RollbackTests(unittest.TestCase):
    """A stale but unexpired list un-revokes a credential, and only age can show it."""

    def test_a_day_old_list_is_reported_stale_against_the_callers_bound(self):
        old = token(payload(statuses=(0, 0, 0, 0), iat=NOW - 86_400, exp=NOW + 3600, ttl=None))
        v = decide(old, issuer_key_verify=accept, max_age_seconds=300)
        self.assertTrue(v["checked"])
        self.assertTrue(v["stale"])
        self.assertFalse(v["fresh"])
        self.assertEqual(v["age_seconds"], 86_400)

    def test_a_fresh_list_is_not_stale(self):
        v = decide(token(payload()), issuer_key_verify=accept, max_age_seconds=300)
        self.assertFalse(v["stale"])
        self.assertTrue(v["fresh"])


class FetchTests(unittest.TestCase):
    """The states a network call adds, and the one that must never read as "fine"."""

    def _fetch(self, body):
        return lambda uri: body

    def test_a_fetched_list_decides(self):
        v = S.decide_by_fetching(index=1, expected_uri=URI, authority=AUTHORITY,
                                 credential_issuer=ISSUER, issuer_key_verify=accept,
                                 fetch=self._fetch(token(payload())), now=NOW)
        self.assertTrue(v["checked"])
        self.assertEqual(v["status"], S.INVALID)

    def test_a_failed_fetch_is_unreachable_not_not_revoked(self):
        def dead(uri):
            raise ConnectionError("connection refused")
        v = S.decide_by_fetching(index=1, expected_uri=URI, authority=AUTHORITY,
                                 credential_issuer=ISSUER, issuer_key_verify=accept,
                                 fetch=dead, now=NOW)
        self.assertFalse(v["checked"])
        self.assertEqual(v["code"], S.UNREACHABLE)

    def test_a_failing_endpoint_is_not_blamed_on_the_issuer(self):
        """A 404 page is the endpoint failing, not the issuer publishing a broken list."""
        for label, body in (("empty", b""), ("404 page", b"<html>Not Found</html>"),
                            ("json error", b'{"error":"gone"}'), ("an int", 500)):
            with self.subTest(case=label):
                v = S.decide_by_fetching(index=1, expected_uri=URI, authority=AUTHORITY,
                                         credential_issuer=ISSUER, issuer_key_verify=accept,
                                         fetch=self._fetch(body), now=NOW)
                self.assertFalse(v["checked"])
                self.assertEqual(v["code"], S.UNREACHABLE)

    def test_nothing_is_requested_without_authority(self):
        """A uri inside an unvetted credential is not a place to send a request."""
        asked = []

        def spy(uri):
            asked.append(uri)
            return token(payload())
        v = S.decide_by_fetching(index=1, expected_uri=URI, authority=AUTHORITY,
                                 credential_issuer=OTHER, fetch=spy, now=NOW)
        self.assertEqual(asked, [])
        self.assertEqual(v["code"], "no_authority")

    def test_the_fetch_path_makes_every_offline_refusal(self):
        for label, p in (("another uri", payload(sub="https://x.example/9")),
                         ("expired", payload(exp=NOW - 1))):
            with self.subTest(case=label):
                v = S.decide_by_fetching(index=1, expected_uri=URI, authority=AUTHORITY,
                                         credential_issuer=ISSUER, issuer_key_verify=accept,
                                         fetch=self._fetch(token(p)), now=NOW)
                self.assertFalse(v["checked"])



def cut_once(test, text, full, limit=512):
    """`text` is at most `limit` characters and carries one note, at its end, naming `full`, the
    length the text has when nothing cuts it."""
    import re
    test.assertLessEqual(len(text), limit)
    found = re.findall(r"\.\.\. \(cut at (\d+) of (\d+) characters\)", text)
    test.assertEqual(len(found), 1, text[-120:])
    test.assertTrue(text.endswith(" characters)"), text[-120:])
    kept, length = (int(n) for n in found[0])
    test.assertEqual(length, full)
    test.assertEqual(len(text), kept + len("... (cut at %d of %d characters)" % (kept, length)))


def uncut_by(module):
    """A patch that makes `module`'s bounded_reason return its text whole, to measure the length
    a cut reason names."""
    from unittest import mock
    return mock.patch.object(module, "bounded_reason", lambda text: text)


class ReasonIsCutTests(unittest.TestCase):
    """A status verdict's reason quotes the list token's own fields, the status URI and what a
    fetch raised, so it holds at most sdjwt.REASON_MAX characters of them, with one note saying
    its full length, as a presentation verdict's reason does."""

    def check(self, call, code):
        v = call()
        with uncut_by(S):
            whole = call()["reason"]
        self.assertEqual(v["code"], code)
        self.assertGreater(len(whole), 5000)
        cut_once(self, v["reason"], len(whole))

    def test_a_field_of_the_list_token_is_cut(self):
        self.check(lambda: decide(token(payload(), typ="T" * 5000)), "typ")

    def test_the_status_uri_is_cut(self):
        self.check(lambda: decide(token(payload()), uri=URI + "/" + "u" * 5000), "sub_mismatch")

    def test_what_a_fetch_raised_is_cut(self):
        def dead(uri):
            raise ConnectionError("R" * 5000)
        self.check(lambda: S.decide_by_fetching(
            index=1, expected_uri=URI, authority=AUTHORITY, credential_issuer=ISSUER,
            issuer_key_verify=accept, fetch=dead, now=NOW), S.UNREACHABLE)

    def test_a_short_reason_is_unchanged(self):
        v = decide(token(payload()))
        self.assertTrue(v["checked"])
        with uncut_by(S):
            self.assertEqual(decide(token(payload()))["reason"], v["reason"])


class PrimitiveRefusalsTests(unittest.TestCase):
    """Each primitive refusal driven directly (2026-09-23). Inverting any of these left the
    whole package suite green, because every caller also refuses the malformed list for some
    later reason; the primitive's own promise was never asserted."""

    def refuses(self, call, msg):
        # 2026-11-18: assertRaises let another exception through as an ERROR. The primitive's
        # refusal is ValueError; anything else escaping is that refusal missing.
        try:
            call()
        except ValueError:
            return
        except Exception as exc:  # noqa: BLE001
            self.fail("%r: %r escaped where ValueError is the refusal" % (msg, exc))
        self.fail("%r: nothing was refused" % (msg,))

    def test_a_status_value_at_an_unknown_width_is_refused(self):
        self.assertEqual(S.status_at(b"\xb9", 0, 1), 1)
        for bits in (0, 3, 16, None, "1"):
            self.refuses(lambda bits=bits: S.status_at(b"\xb9", 0, bits), bits)

    def test_base64url_that_does_not_decode_is_refused(self):
        self.assertEqual(S._b64u("AQI", "list"), b"\x01\x02")
        for bad in ("a", "ab$c"):
            self.refuses(lambda bad=bad: S._b64u(bad, "list"), bad)

    def test_a_bomb_is_refused_at_the_primitive(self):
        # The first site refuses before the bomb is built; the bomb test above asserts it by
        # what zlib produced. The second is tested below: it is not the spare this said it was.
        raw = zlib.compress(b"\x00" * 150, 9)
        with self.assertRaises(ValueError):
            S._inflate_bounded(raw, limit=100)
        self.assertEqual(len(S._inflate_bounded(raw, limit=150)), 150)

    def test_a_bomb_with_its_trailer_cut_off_is_stopped_by_the_second_bound(self):
        """The review of 2026-09-30: cut the zlib trailer and no input is left unconsumed, so the
        first bound passes 776 bytes and flush() produces the other 224. Only the length check
        after flush() refuses it; removing that check returned all 1000."""
        raw = zlib.compress(b"\x00" * 1000, 9)[:-5]
        with self.assertRaises(ValueError) as caught:
            S._inflate_bounded(raw, limit=776)
        self.assertIn("more than 776 bytes", str(caught.exception))

    def test_a_stream_that_never_ends_is_refused(self):
        """A status list with its trailer cut off inflated to all its data and was accepted, while
        zlib.decompress refuses the same bytes. The list an issuer signed ends."""
        whole = zlib.compress(bytes([0b10111001]) * 64, 9)
        self.assertEqual(len(S._inflate_bounded(whole)), 64, "control: the complete stream")
        for cut in (4, 5):
            with self.subTest(cut=cut):
                with self.assertRaises(ValueError) as caught:
                    S._inflate_bounded(whole[:-cut])
                self.assertIn("truncated", str(caught.exception))
                with self.assertRaises(zlib.error):
                    zlib.decompress(whole[:-cut])

    def test_the_encoder_refuses_what_it_cannot_represent(self):
        self.assertIsInstance(S.encode_status_list([0, 1, 1], bits=1), str)
        with self.assertRaises(ValueError):
            S.encode_status_list([0, 1], bits=3)
        with self.assertRaises(ValueError):
            S.encode_status_list([0, 2], bits=1)


class EveryDecisionRefusalIsAssertedTests(unittest.TestCase):
    """Each of these branches, turned into a checked VALID answer, left the whole package
    green (2026-09-23): nothing asserted the refusal, only that nothing raised. A status
    decision that answers VALID where it should refuse is a revoked credential accepted, so
    each is pinned by its own code, never by checked alone."""

    def refused(self, v, code):
        self.assertIs(v["checked"], False)
        self.assertEqual(v["code"], code)

    def test_a_token_that_is_not_text(self):
        self.refused(decide(12345, issuer_key_verify=accept), "malformed")

    def test_a_token_over_the_size_limit(self):
        self.refused(decide("a" * (S.MAX_TOKEN_BYTES + 1), issuer_key_verify=accept), "malformed")

    def test_a_clock_that_is_not_an_integer(self):
        for now in ("1800000000", 1.8e9, True, None):
            self.refused(S.decide(token(payload()), index=1, expected_uri=URI, authority=AUTHORITY,
                                  credential_issuer=ISSUER, now=now), "misconfigured")

    def test_a_header_or_payload_that_is_not_an_object(self):
        tok = ".".join([b64u(json.dumps(["not", "an", "object"])), b64u(json.dumps(payload())), b64u(b"sig")])
        self.refused(decide(tok, issuer_key_verify=accept), "malformed")

    def test_an_authority_that_crashes_is_not_a_grant(self):
        def boom(**_):
            raise RuntimeError("resolver down")
        v = S.decide(token(payload()), index=1, expected_uri=URI, authority=boom,
                     credential_issuer=ISSUER, now=NOW)
        self.refused(v, "authority_error")

    def test_a_signature_check_that_crashes_is_not_a_pass(self):
        def crash(signing_input, signature, header):
            raise ValueError("bad key")
        crashing = S.StatedAuthority().state(credential_issuer=ISSUER, status_uri=URI, verify=crash,
                                             why="a key that throws")
        v = S.decide(token(payload()), index=1, expected_uri=URI, authority=crashing,
                     credential_issuer=ISSUER, now=NOW)
        self.refused(v, "signature_error")

    def test_a_list_with_no_issue_time_has_no_age(self):
        p = payload()
        del p["iat"]
        self.refused(decide(token(p), issuer_key_verify=accept), "iat")

    def test_a_list_with_no_list_is_not_a_status(self):
        p = payload()
        del p["status_list"]["lst"]
        self.refused(decide(token(p), issuer_key_verify=accept), "lst")

    def test_fetching_needs_a_uri(self):
        for uri in ("", None, 7):
            v = S.decide_by_fetching(index=1, expected_uri=uri, authority=AUTHORITY,
                                     fetch=lambda u: b"", now=NOW, credential_issuer=ISSUER)
            self.refused(v, "uri")

    def test_fetching_with_a_crashing_authority_asks_nothing(self):
        asked = []
        def boom(**_):
            raise RuntimeError("resolver down")
        v = S.decide_by_fetching(index=1, expected_uri=URI, authority=boom,
                                 fetch=lambda u: asked.append(u) or b"", now=NOW, credential_issuer=ISSUER)
        self.refused(v, "authority_error")
        self.assertEqual(asked, [], "nothing may be fetched when authority cannot be established")


class HeldOutBoundaryTests(unittest.TestCase):
    """2026-09-23: ten semantic mutations written after the drill was green, each moving a
    boundary rather than inverting a refusal. Four of them here survived the whole package:
    `now >= exp` as `now > exp`, a future `iat` tolerated by a minute, the staleness bound
    doubled, and the depth bound computed wrongly (which disabled it: the deep-nesting tests
    above are refused by a different layer, so they passed). Each test sits on the boundary."""

    def test_a_list_is_expired_at_its_exp_instant(self):
        v = decide(token(payload(exp=NOW)), issuer_key_verify=accept)
        self.assertIs(v["checked"], False)
        self.assertEqual(v["code"], "expired")
        self.assertTrue(decide(token(payload(exp=NOW + 1)), issuer_key_verify=accept)["checked"])

    def test_a_list_dated_past_the_clock_allowance_is_refused(self):
        """The allowance, not zero, since 2026-09-28: a list dated just ahead of this clock (an
        issuer signing at fetch time across a second boundary, or a clock running ahead) is
        decided; one dated beyond the allowance is still refused."""
        edge = NOW + S.MAX_IAT_SKEW_SECONDS
        v = decide(token(payload(iat=edge + 1, exp=edge + 3600)), issuer_key_verify=accept)
        self.assertIs(v["checked"], False)
        self.assertEqual(v["code"], "iat_future")
        at_edge = decide(token(payload(iat=edge, exp=edge + 3600)), issuer_key_verify=accept)
        self.assertTrue(at_edge["checked"], at_edge)
        self.assertEqual((at_edge["stale"], at_edge["fresh"]), (False, True),
                         "a list dated ahead is taken as just issued, not as a negative age")
        self.assertEqual(at_edge["age_seconds"], 0,
                         "a list dated ahead reports an age of zero, not a negative one")

    def test_a_list_dated_one_second_ahead_is_decided(self):
        """walt.id presenting a Polaris wallet copy (lab/strategy/005, S6): the issuer signed its
        list at fetch time, one second after the verifier read its clock, and the credential,
        VALID, read `unreachable` with code iat_future."""
        v = decide(token(payload(iat=NOW + 1)), issuer_key_verify=accept)
        self.assertTrue(v["checked"], v)
        self.assertEqual(v["status"], S.INVALID)

    def test_decide_by_fetching_reads_the_clock_once_the_token_is_in_hand(self):
        """With no `now`, the clock is read AFTER the fetch. The fetch below moves the clock
        further than any allowance and signs at the new time, as a slow issuer would: a clock
        read before the fetch would call the list dated in the future."""
        real = S.time

        class Clock:
            t = NOW

            def time(self):
                return Clock.t
        S.time = Clock()
        try:
            def slow_fetch(uri):
                Clock.t += 10 * S.MAX_IAT_SKEW_SECONDS
                return token(payload(iat=Clock.t, exp=Clock.t + 3600)).encode()
            v = S.decide_by_fetching(index=1, expected_uri=URI, authority=AUTHORITY,
                                     credential_issuer=ISSUER, issuer_key_verify=accept,
                                     fetch=slow_fetch)
        finally:
            S.time = real
        self.assertTrue(v["checked"], v)
        self.assertEqual(v["status"], S.INVALID)

    def test_a_list_is_stale_one_second_past_its_ttl(self):
        at = decide(token(payload(iat=NOW - 600, ttl=600)), issuer_key_verify=accept)
        past = decide(token(payload(iat=NOW - 601, ttl=600)), issuer_key_verify=accept)
        self.assertEqual((at["checked"], at["stale"]), (True, False))
        self.assertEqual((past["checked"], past["stale"], past["fresh"]), (True, True, False))

    def test_the_depth_bound_is_measured_and_enforced_at_its_limit(self):
        self.assertEqual(S._nesting_depth('[{"a":[1]}]'), 3)
        self.assertEqual(S._nesting_depth('["[[[", {}]'), 2, "brackets inside a string are text")
        at = "[" * S.MAX_JSON_DEPTH + "]" * S.MAX_JSON_DEPTH
        self.assertIsInstance(S._json_bounded(at, "payload"), list)
        with self.assertRaises(ValueError) as caught:
            S._json_bounded("[" + at + "]", "payload")
        self.assertIn("deeper", str(caught.exception))


class AuthorityIsBoundToIssuerAndUri(unittest.TestCase):
    """2026-09-23: two held-out mutations survived because another refusal answered first.
    A stated authority matched on the issuer alone (any URI) survived: every test passed the
    credential's URI as expected_uri, so a different `sub` was refused as a mismatch before
    authority was asked. A token with no `sub` survived for the same reason. Here the uri
    matches the token's `sub` (or the token has none), so only the rule named can refuse. These
    tests passed expected_uri=None until 2026-10-01, which skipped the `sub` binding altogether;
    None is now refused as misconfigured (test_a_missing_expected_uri_is_misconfigured)."""

    def test_a_stated_authority_holds_only_at_the_uri_it_names(self):
        tok = token(payload(sub=OTHER + "/statuslists/1"))
        v = S.decide(tok, index=1, expected_uri=OTHER + "/statuslists/1", authority=AUTHORITY,
                     credential_issuer=ISSUER, now=NOW)
        self.assertIs(v["checked"], False)
        self.assertEqual(v["code"], "no_authority")

    def test_a_status_list_with_no_subject_is_bound_to_nothing(self):
        p = payload()
        del p["sub"]
        v = S.decide(token(p), index=1, expected_uri=OTHER + "/statuslists/1", authority=AUTHORITY,
                     credential_issuer=ISSUER, now=NOW, issuer_key_verify=accept)
        self.assertIs(v["checked"], False)
        self.assertEqual(v["code"], "sub")

    def test_a_missing_expected_uri_is_misconfigured(self):
        """The review of 2026-09-30: with expected_uri None the `sub` binding was skipped, so a
        status list a trusted key signed for one population answered for any credential."""
        tok = token(payload(sub=OTHER + "/statuslists/1"))
        for missing in (None, "", 7):
            with self.subTest(expected_uri=missing):
                v = S.decide(tok, index=1, expected_uri=missing, authority=AUTHORITY,
                             credential_issuer=ISSUER, now=NOW, issuer_key_verify=accept)
                self.assertEqual((v["checked"], v["code"]), (False, "misconfigured"))


# --------------------------------------------------------------------------- anchored authority
#
# 2026-11-21. A provider whose credentials are signed under one CA and whose status lists are
# signed under a sibling CA, both under one root, its iss bound by nothing in its certificate:
# the shape of the German sandbox PID, minted here. The real artifacts stay outside the tree.

ORG = "Provider GmbH"
PREFIX = "https://tsl.provider.example/tsl/"
STATUS_URI = PREFIX + "6f1c2a04-5d3e-4b8a-9c71-0e2f8a6b4d19"
ISS = "https://provider.example"
WHY = "the trust list's entry for Provider GmbH names both anchors"


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _name(common_name, organization=None):
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization is not None:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    return x509.Name(attributes)


def _cert(subject, key, issuer=None, issuer_key=None, *, ca=False, path_length=None,
          usage="sign", not_after=None, san=None):
    """A certificate for `key` named `subject`, signed by `issuer_key` under `issuer`'s name, or
    self-signed without an issuer. A CA gets keyCertSign; a leaf gets digitalSignature ("sign"),
    keyEncipherment alone ("encipher"), or no key usage at all (None)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(subject if issuer is None else issuer.subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(not_after or now + datetime.timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True))
    if ca or usage is not None:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=not ca and usage == "sign", content_commitment=False,
            key_encipherment=not ca and usage == "encipher", data_encipherment=False,
            key_agreement=False, key_cert_sign=ca, crl_sign=ca, encipher_only=False,
            decipher_only=False), critical=True)
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(key if issuer is None else issuer_key, hashes.SHA256())


class _Pki:
    """The provider's root, its issuance CA (A) and its status-list CA (B), siblings; the
    credential signer under A and the status list signer under B, both of one organization; and
    the variants the refusals are built from."""

    def __init__(self):
        self.root_key = _key()
        self.root = _cert(_name("Provider Root Test CA"), self.root_key, ca=True)
        self.a_key, self.b_key = _key(), _key()
        self.a = _cert(_name("Provider PID-Signer Test CA"), self.a_key, self.root,
                       self.root_key, ca=True, path_length=0)
        self.b = _cert(_name("Provider Status-List-Signer Test CA"), self.b_key, self.root,
                       self.root_key, ca=True, path_length=0)
        self.leaf_key, self.signer_key = _key(), _key()
        self.leaf = _cert(_name("pid issuer", ORG), self.leaf_key, self.a, self.a_key)
        self.signer = _cert(_name("status list signer", ORG), self.signer_key, self.b, self.b_key)
        # Another provider's issuance CA, a root of its own.
        self.a2_key = _key()
        self.a2 = _cert(_name("Other PID-Signer Test CA"), self.a2_key, ca=True)
        # A status-list CA that is a root, so that one sent in x5c would chain if it were let.
        self.bs_key, self.bs_signer_key = _key(), _key()
        self.bs = _cert(_name("Status-List-Signer Root"), self.bs_key, ca=True)
        self.bs_signer = _cert(_name("status list signer", ORG), self.bs_signer_key, self.bs,
                               self.bs_key)
        # A's key and name under a second certificate: a "status anchor" that is the issuance CA.
        self.a_twin = _cert(self.a.subject, self.a_key, self.root, self.root_key, ca=True,
                            path_length=0)
        self.twin_signer_key = _key()
        self.twin_signer = _cert(_name("status list signer", ORG), self.twin_signer_key, self.a,
                                 self.a_key)

    def signer_under_b(self, **kwargs):
        organization = kwargs.pop("organization", ORG)
        key = _key()
        return key, _cert(_name("status list signer", organization), key, self.b, self.b_key,
                          **kwargs)


def _es256(key, header, claims):
    head = b64u(json.dumps(header, separators=(",", ":")))
    body = b64u(json.dumps(claims, separators=(",", ":")))
    r, s = asym_utils.decode_dss_signature(
        key.sign((head + "." + body).encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return head + "." + body + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _x5c(*certificates):
    return [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode("ascii")
            for c in certificates]


def _list_token(key, chain, *, uri=STATUS_URI, statuses=(0, 1), **over):
    """A Status List Token for `uri` signed by `key`, `chain` its x5c (None: no x5c). Index 0 is
    VALID and index 1 INVALID."""
    now = int(time.time())
    claims = {"sub": uri, "iat": now - 60, "exp": now + 6 * 86400, "ttl": 3600,
              "status_list": {"bits": 1, "lst": S.encode_status_list(list(statuses), 1)}}
    claims.update(over)
    header = {"alg": "ES256", "typ": "statuslist+jwt"}
    if chain is not None:
        header["x5c"] = _x5c(*chain)
    return _es256(key, header, claims)


def _anchored(credential_anchor, status_anchor, prefix=PREFIX):
    return S.AnchoredAuthority().state(credential_anchor=credential_anchor,
                                       status_uri_prefix=prefix, status_anchor=status_anchor,
                                       why=WHY)


class _Spy:
    """A fetch that records each URI and answers `token`."""

    def __init__(self, token_):
        self.token, self.asked = token_, []

    def __call__(self, uri):
        self.asked.append(uri)
        return self.token


class AnchoredAuthorityTests(unittest.TestCase):
    """status.AnchoredAuthority and the keyword that reaches it, against the spec's cases a-g."""

    @classmethod
    def setUpClass(cls):
        cls.pki = _Pki()

    def fetching(self, authority, token_, *, uri=STATUS_URI, index=0, anchor=None,
                 leaf=None, **kwargs):
        """decide_by_fetching through a spy; (verdict, the URIs it fetched)."""
        spy = _Spy(token_)
        verdict = S.decide_by_fetching(
            index=index, expected_uri=uri, authority=authority, fetch=spy,
            credential_anchor=self.pki.a if anchor is None else anchor,
            credential_leaf=self.pki.leaf if leaf is None else leaf, **kwargs)
        return verdict, spy.asked

    def authority(self):
        return _anchored(self.pki.a, self.pki.b)

    def signed(self, key=None, chain=None, **kwargs):
        if key is None:
            key, chain = self.pki.signer_key, [self.pki.signer]
        return _list_token(key, chain, **kwargs)

    def no_authority(self, verdict, text):
        self.assertEqual((verdict["checked"], verdict["code"]), (False, "no_authority"),
                         verdict["reason"])
        self.assertIn(text, verdict["reason"])

    # a. The German shape, end to end through verify_presentation.
    def test_a_an_unbound_iss_is_checked_under_the_anchored_entry_and_not_before_it(self):
        presentation = _x5c_presentation(self.pki.leaf, self.pki.leaf_key, iss=ISS,
                                         status={"status_list": {"uri": STATUS_URI, "idx": 0}})
        spy = _Spy(self.signed())
        stated = S.StatedAuthority().state(credential_issuer=ISS, status_uri=STATUS_URI,
                                           verify=accept, why="a statement for the iss")
        before = verify_presentation(presentation, expected_nonce=NONCE,
                                     expected_audience=AUDIENCE, trust_anchors=[self.pki.a],
                                     status_resolver=S.make_resolver(stated, spy))
        self.assertTrue(before.authentic, before.reason)
        self.assertIs(before.iss_bound, False)
        self.assertEqual(before.revocation["state"], "no_authority")
        self.assertEqual(spy.asked, [])
        after = verify_presentation(presentation, expected_nonce=NONCE,
                                    expected_audience=AUDIENCE, trust_anchors=[self.pki.a],
                                    status_resolver=S.make_resolver(self.authority(), spy))
        self.assertTrue(after.authentic, after.reason)
        rev = after.revocation
        self.assertEqual((rev["state"], rev["status"], rev["stale"], rev["authority"]),
                         ("checked", S.VALID, False, S.ANCHORED), rev["reason"])
        self.assertIn(WHY, rev["reason"])
        self.assertEqual(spy.asked, [STATUS_URI])

    def test_f_a_revoked_index_is_checked_invalid(self):
        verdict, _ = self.fetching(self.authority(), self.signed(), index=1)
        self.assertEqual((verdict["checked"], verdict["status"]), (True, S.INVALID))

    # M1. Before the fetch the entry answers only whether the URI may be fetched.
    def test_m1_the_uri_is_fetched_before_any_x5c_is_seen_and_nothing_verifies_under_that(self):
        verdict, asked = self.fetching(self.authority(), self.signed())
        self.assertEqual((verdict["checked"], verdict["status"], verdict["authority"]),
                         (True, S.VALID, S.ANCHORED))
        self.assertEqual(asked, [STATUS_URI])
        grant = self.authority()(credential_issuer=None, status_uri=STATUS_URI, header=None,
                                 credential_anchor=self.pki.a, credential_leaf=self.pki.leaf)
        self.assertEqual(grant[1], S.ANCHORED)
        self.assertIs(grant[0](b"a.b", b"\x00" * 64, {"alg": "ES256"}), False)

    # b. A list signed under the issuance CA is not the revocation service's.
    def test_b_a_list_signed_under_the_issuance_ca_is_never_valid(self):
        for label, chain in (("its leaf", [self.pki.leaf]),
                             ("its leaf and the CA", [self.pki.leaf, self.pki.a])):
            with self.subTest(x5c=label):
                verdict, _ = self.fetching(self.authority(),
                                           self.signed(self.pki.leaf_key, chain))
                self.no_authority(verdict, "not one the stated status anchor certifies")

    # b2. An anchor that certifies the other is refused when stated.
    def test_b2_anchors_that_certify_each_other_or_are_one_are_refused(self):
        for label, a, b, text in (
                ("the shared root as the status anchor", self.pki.a, self.pki.root,
                 "the status anchor certifies the credential anchor"),
                ("the root as the credential anchor", self.pki.root, self.pki.b,
                 "the credential anchor certifies the status anchor"),
                ("one certificate twice", self.pki.a, self.pki.a, "are one certificate")):
            with self.subTest(case=label):
                self.refused_with(lambda: _anchored(a, b), text)

    # c. The entry is per credential anchor.
    def test_c_a_credential_under_another_anchor_has_no_authority_and_nothing_is_fetched(self):
        verdict, asked = self.fetching(self.authority(), self.signed(), anchor=self.pki.a2)
        self.no_authority(verdict, "no anchored entry names the anchor")
        self.assertEqual(asked, [])

    # d. The URI rules: each URI is refused before anything is fetched.
    def test_d_a_status_uri_outside_the_prefix_or_not_canonical_is_never_fetched(self):
        for label, uri, text in (
                ("another host", "https://other.example/tsl/x", "under no prefix"),
                ("a host under the prefix's host", "https://a.tsl.provider.example/tsl/x",
                 "under no prefix"),
                ("a host ending in the prefix's", "https://eviltsl.provider.example/tsl/x",
                 "under no prefix"),
                ("a sibling path", "https://tsl.provider.example/tsl-other/x", "under no prefix"),
                ("the prefix's parent", "https://tsl.provider.example/x", "under no prefix"),
                ("a port", "https://tsl.provider.example:443/tsl/x", "under no prefix"),
                ("a trailing dot", "https://tsl.provider.example./tsl/x", "under no prefix"),
                ("http", "http://tsl.provider.example/tsl/x", "is not https"),
                ("userinfo", "https://u@tsl.provider.example/tsl/x", "carries userinfo"),
                ("an empty port", "https://tsl.provider.example:/tsl/x", "empty or non-numeric"),
                ("a fragment", PREFIX + "x#y", "carries a fragment"),
                ("a query", PREFIX + "x?y=1", "carries a query"),
                ("a backslash", PREFIX + "a\\b", "backslash"),
                ("a dot segment", PREFIX + "../x", "dot segment"),
                ("an encoded dot", PREFIX + "%2e%2e/x", "percent-encodes"),
                ("an encoded slash", PREFIX + "a%2Fb", "percent-encodes"),
                ("a host that is not ASCII", "https://tsl.prövider.example/tsl/x", "ASCII")):
            with self.subTest(case=label):
                verdict, asked = self.fetching(self.authority(), self.signed(uri=uri), uri=uri)
                self.no_authority(verdict, text)
                self.assertEqual(asked, [])

    def test_d_the_host_is_compared_in_lowercase(self):
        """The positive control for the URI rules: the same host in capitals is the same host."""
        uri = "https://TSL.Provider.example/tsl/x"
        verdict, asked = self.fetching(self.authority(), self.signed(uri=uri), uri=uri)
        self.assertEqual((verdict["checked"], verdict["status"]), (True, S.VALID),
                         verdict["reason"])
        self.assertEqual(asked, [uri])

    def test_d_a_prefix_that_is_not_one_is_refused_when_stated(self):
        for label, prefix, text in (
                ("no closing slash", "https://tsl.provider.example/tsl", "does not end in /"),
                ("a query", PREFIX + "?a=1", "carries a query"),
                ("not a DNS host", "https://tsl_provider.example/tsl/", "names no DNS host"),
                ("not ASCII", "https://tsl.prövider.example/tsl/", "ASCII"),
                ("http", "http://tsl.provider.example/tsl/", "is not https")):
            with self.subTest(case=label):
                self.refused_with(lambda: _anchored(self.pki.a, self.pki.b, prefix), text)

    def test_an_entry_missing_a_part_or_holding_no_certificate_is_refused(self):
        for label, kwargs, text in (
                ("no reason", {"why": ""}, "needs a credential anchor"),
                ("no status anchor", {"status_anchor": None}, "needs a credential anchor"),
                ("a status anchor that is not a certificate", {"status_anchor": "B"},
                 "is not an X.509 certificate")):
            entry = {"credential_anchor": self.pki.a, "status_uri_prefix": PREFIX,
                     "status_anchor": self.pki.b, "why": WHY}
            entry.update(kwargs)
            with self.subTest(case=label):
                self.refused_with(lambda: S.AnchoredAuthority().state(**entry), text)

    # e. The status signer's certificate.
    def test_e_a_signer_certificate_that_is_not_a_status_signers_is_refused(self):
        expired_key, expired = self.pki.signer_under_b(
            not_after=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1))
        no_sign_key, no_sign = self.pki.signer_under_b(usage="encipher")
        no_usage_key, no_usage = self.pki.signer_under_b(usage=None)
        for label, key, chain, text in (
                ("expired", expired_key, [expired], "validity period"),
                ("no digitalSignature", no_sign_key, [no_sign], "digitalSignature"),
                ("no key usage", no_usage_key, [no_usage], "states no key usage"),
                ("no x5c", self.pki.signer_key, None, "carries no x5c")):
            with self.subTest(case=label):
                verdict, _ = self.fetching(self.authority(), self.signed(key, chain))
                self.no_authority(verdict, text)

    def test_e_the_status_anchor_sent_in_x5c_is_refused(self):
        """HAIP 1.0 6.1.1 keeps the anchor out of x5c. The status anchor here is a root, so a
        chain that sends it would verify if that rule were not applied."""
        authority = _anchored(self.pki.a, self.pki.bs)
        control, _ = self.fetching(authority, self.signed(self.pki.bs_signer_key,
                                                          [self.pki.bs_signer]))
        self.assertEqual((control["checked"], control["status"]), (True, S.VALID),
                         control["reason"])
        verdict, _ = self.fetching(authority, self.signed(self.pki.bs_signer_key,
                                                          [self.pki.bs_signer, self.pki.bs]))
        self.no_authority(verdict, "is a trust anchor")

    # M5. A status anchor carrying the issuance CA's key and name.
    def test_b_a_status_anchor_above_the_credential_anchors_path_grants_nothing_under_it(self):
        """The review of 2026-11-21: a root, a policy CA under it, the credential anchor under
        that, and the root stated as the status anchor. `state` sees two certificates that do not
        sign each other and accepts the entry; a list signed under the credential anchor then
        chains to the root through the credential anchor's path, and must not be VALID."""
        root_key, policy_key, ca_key = _key(), _key(), _key()
        root = _cert(_name("Three-Level Root"), root_key, ca=True)
        policy = _cert(_name("Three-Level Policy CA"), policy_key, root, root_key, ca=True)
        ca = _cert(_name("Three-Level PID-Signer CA"), ca_key, policy, policy_key, ca=True,
                   path_length=0)
        leaf_key, other_key, status_ca_key, signer_key = _key(), _key(), _key(), _key()
        leaf = _cert(_name("pid issuer", ORG), leaf_key, ca, ca_key)
        other = _cert(_name("another signer", ORG), other_key, ca, ca_key)
        status_ca = _cert(_name("Three-Level Status-List CA"), status_ca_key, root, root_key,
                          ca=True, path_length=0)
        signer = _cert(_name("status list signer", ORG), signer_key, status_ca, status_ca_key)
        # The credential anchor's own key in an end-entity certificate the policy CA issued.
        own_key = _cert(_name("status list signer", ORG), ca_key, policy, policy_key)
        authority = _anchored(ca, root)
        control, _ = self.fetching(authority, self.signed(signer_key, [signer, status_ca]),
                                   anchor=ca, leaf=leaf)
        self.assertEqual((control["checked"], control["status"], control["authority"]),
                         (True, S.VALID, S.ANCHORED), control["reason"])
        for label, key, chain, text in (
                ("the credential signer, the path sent", leaf_key, [leaf, ca, policy],
                 "certificate 0 was signed with the credential anchor's key"),
                ("another leaf of the anchor, the path sent", other_key, [other, ca, policy],
                 "certificate 0 was signed with the credential anchor's key"),
                ("the anchor's key under the policy CA", ca_key, [own_key, policy],
                 "certificate 0 carries the credential anchor's key"),
                ("a leaf of the anchor, the anchor left out", other_key, [other, policy],
                 "does not chain to any configured trust anchor")):
            with self.subTest(x5c=label):
                verdict, _ = self.fetching(authority, self.signed(key, chain), anchor=ca,
                                           leaf=leaf)
                self.no_authority(verdict, "not one the stated status anchor certifies")
                self.assertIn(text, verdict["reason"])

    def test_m5_a_signer_that_also_chains_to_the_credential_anchor_is_refused(self):
        authority = _anchored(self.pki.a, self.pki.a_twin)
        verdict, _ = self.fetching(authority, self.signed(self.pki.twin_signer_key,
                                                          [self.pki.twin_signer]))
        self.no_authority(verdict, "also chains to the credential anchor")

    # M6. The signer's organization is the credential signer's.
    def test_m6_the_signer_is_of_the_credential_signers_organization(self):
        other_key, other = self.pki.signer_under_b(organization="Other GmbH")
        verdict, _ = self.fetching(self.authority(), self.signed(other_key, [other]))
        self.no_authority(verdict, "organizationName")
        nameless = _cert(_name("pid issuer"), _key(), self.pki.a, self.pki.a_key)
        verdict, _ = self.fetching(self.authority(), self.signed(), leaf=nameless)
        self.no_authority(verdict, "organizationName")
        verdict = S.decide(self.signed(), index=0, expected_uri=STATUS_URI,
                           authority=self.authority(), now=int(time.time()),
                           credential_anchor=self.pki.a)
        self.no_authority(verdict, "no credential signer's certificate")

    # M4. No same-key branch.
    def test_m4_the_credential_issuers_own_key_is_no_grant_here(self):
        verdict = S.decide(self.signed(), index=0, expected_uri=STATUS_URI,
                           authority=self.authority(), now=int(time.time()),
                           issuer_key_verify=accept, credential_anchor=self.pki.a2,
                           credential_leaf=self.pki.leaf)
        self.no_authority(verdict, "no anchored entry names the anchor")

    # Q3. The keyword reaches only an authority that declares it, and the anchor must be there.
    def test_q3_an_anchored_authority_without_an_anchor_is_no_authority(self):
        spy = _Spy(self.signed())
        for verdict in (
                S.decide(self.signed(), index=0, expected_uri=STATUS_URI,
                         authority=self.authority(), now=int(time.time())),
                S.decide_by_fetching(index=0, expected_uri=STATUS_URI,
                                     authority=self.authority(), fetch=spy)):
            self.no_authority(verdict, "no credential anchor reached this authority")
        self.assertEqual(spy.asked, [])

    def test_q3_only_true_declares_the_keyword(self):
        def four(*, credential_issuer, status_uri, header, issuer_key_verify=None):
            return (accept, S.STATED, "an authority of four keywords")
        for declared in ("yes", 1):
            four.takes_credential_anchor = declared
            with self.subTest(declared=declared):
                verdict = S.decide(token(payload()), index=1, expected_uri=URI, authority=four,
                                   now=NOW, credential_anchor=self.pki.a)
                self.assertEqual((verdict["checked"], verdict["status"]), (True, S.INVALID),
                                 verdict["reason"])

    # M3. The resolver hop: declare to receive.
    def test_m3_a_three_keyword_resolver_is_called_as_it_always_was(self):
        presentation = _x5c_presentation(self.pki.leaf, self.pki.leaf_key, iss=ISS,
                                         status={"status_list": {"uri": STATUS_URI, "idx": 0}})
        handed = []

        def three(*, uri, idx, issuer):
            handed.append((uri, idx, issuer))
            return {"checked": True, "status": 0, "stale": False, "authority": "same_key",
                    "code": None, "reason": "a resolver of three keywords"}
        for declared in (None, 1):
            if declared is not None:
                three.takes_credential_anchor = declared
            with self.subTest(declared=declared):
                verdict = verify_presentation(presentation, expected_nonce=NONCE,
                                              expected_audience=AUDIENCE,
                                              trust_anchors=[self.pki.a], status_resolver=three)
                self.assertEqual(verdict.revocation["state"], "checked",
                                 verdict.revocation["reason"])
        self.assertEqual(handed, [(STATUS_URI, 0, None)] * 2)

    def test_m3_a_declared_resolver_is_handed_the_anchor_and_the_signer(self):
        presentation = _x5c_presentation(self.pki.leaf, self.pki.leaf_key, iss=ISS,
                                         status={"status_list": {"uri": STATUS_URI, "idx": 0}})
        handed = []

        def declared(*, uri, idx, issuer, credential_anchor=None, credential_leaf=None):
            handed.append((credential_anchor, credential_leaf))
            return {"checked": False, "code": "no_authority", "reason": "recorded"}
        declared.takes_credential_anchor = True
        verify_presentation(presentation, expected_nonce=NONCE, expected_audience=AUDIENCE,
                            trust_anchors=[self.pki.a], status_resolver=declared)
        der = serialization.Encoding.DER
        self.assertEqual([(a.public_bytes(der), b.public_bytes(der)) for a, b in handed],
                         [(self.pki.a.public_bytes(der), self.pki.leaf.public_bytes(der))])

    def refused_with(self, call, text):
        try:
            call()
        except Exception as exc:  # noqa: BLE001  the type is asserted, so a crash is a failure
            self.assertIsInstance(exc, ValueError, exc)
            self.assertIn(text, str(exc))
        else:
            self.fail("not refused; expected %r" % text)


# --------------------------------------------------------------------------- status_fetch
#
# The README's rules for a `fetch`, held against a listener on this machine. Every case but the
# address rule hands the fetch a plain connect and a context that trusts the listener, since the
# address rule refuses this machine; the address rule is held on its own.

_LIST_BODY = b"aaa.bbb.ccc"


class _Listener:
    """An HTTPS listener on 127.0.0.1 under a certificate `client_context` trusts. It records the
    paths asked and counts the connections it accepted."""

    def __init__(self):
        # A root the client trusts and a server certificate it issued: a self-signed end-entity
        # certificate is not its own issuer to every TLS library (LibreSSL under Python 3.9).
        root_key, key = _key(), _key()
        root = _cert(_name("Listener Test Root"), root_key, ca=True)
        cert = _cert(_name("127.0.0.1"), key, root, root_key,
                     san=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
        self.folder = tempfile.mkdtemp()
        certfile = os.path.join(self.folder, "cert.pem")
        keyfile = os.path.join(self.folder, "key.pem")
        with open(certfile, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(keyfile, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        self.client_context = ssl.create_default_context(
            cadata=root.public_bytes(serialization.Encoding.PEM).decode("ascii"))
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certfile, keyfile)
        self.paths, self.connections = [], 0
        listener = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def answer(self, code, body, headers=()):
                self.send_response(code)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                listener.paths.append(self.path)
                if self.path == "/ok":
                    self.answer(200, _LIST_BODY)
                elif self.path == "/redirect":
                    self.answer(302, b"moved", (("Location", "/ok"),))
                elif self.path == "/big":
                    self.answer(200, b"a" * (S.MAX_TOKEN_BYTES + 1))
                elif self.path == "/slow":
                    self.send_response(200)
                    self.send_header("Content-Length", "2000")
                    self.end_headers()
                    try:
                        for _ in range(20):
                            self.wfile.write(b"a" * 100)
                            self.wfile.flush()
                            time.sleep(0.1)
                    except OSError:
                        pass  # the client cut the connection, as the test expects
                elif self.path == "/slow-header":
                    # The status line at once, then a header one byte every 0.15 s for 1.8 s, then
                    # a whole list: only a bound over the whole exchange ends it before the body.
                    try:
                        self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                        for _ in range(12):
                            self.wfile.write(b"a")
                            self.wfile.flush()
                            time.sleep(0.15)
                        self.wfile.write(b"\r\nContent-Length: %d\r\n\r\n%s"
                                         % (len(_LIST_BODY), _LIST_BODY))
                    except OSError:
                        pass  # the client cut the connection, as the test expects
                else:
                    self.answer(404, b"not found")

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self):
                accepted = super().get_request()
                listener.connections += 1
                return accepted

        self.server = Server(("127.0.0.1", 0), Handler)
        self.server.socket = server_context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path):
        return "https://127.0.0.1:%d%s" % (self.port, path)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.folder, ignore_errors=True)


class StatusFetchTests(unittest.TestCase):
    """status_fetch.fetch_status_list: https only, public addresses only, no redirect, a byte
    bound and a time bound."""

    @classmethod
    def setUpClass(cls):
        cls.listener = _Listener()

    @classmethod
    def tearDownClass(cls):
        cls.listener.close()

    def fetch(self, path, **kwargs):
        kwargs.setdefault("context", self.listener.client_context)
        kwargs.setdefault("connect", socket.create_connection)
        return status_fetch.fetch_status_list(self.listener.url(path), **kwargs)

    def refused_with(self, call, text):
        try:
            call()
        except Exception as exc:  # noqa: BLE001  the type is asserted, so a crash is a failure
            self.assertIsInstance(exc, ValueError, exc)
            self.assertIn(text, str(exc))
        else:
            self.fail("not refused; expected %r" % text)

    def test_a_list_is_read(self):
        """The positive control: everything below is refused by its rule, not by the setup."""
        self.assertEqual(self.fetch("/ok"), _LIST_BODY)

    def test_a_redirect_is_not_followed(self):
        asked = len(self.listener.paths)
        self.refused_with(lambda: self.fetch("/redirect"), "answered 302")
        self.assertEqual(self.listener.paths[asked:], ["/redirect"])

    def test_an_answer_but_200_is_refused(self):
        self.refused_with(lambda: self.fetch("/missing"), "answered 404")

    def test_a_body_over_the_token_bound_is_refused(self):
        self.refused_with(lambda: self.fetch("/big"), "over %d bytes" % S.MAX_TOKEN_BYTES)

    def test_a_body_that_arrives_past_the_total_is_refused(self):
        self.refused_with(lambda: self.fetch("/slow", total=0.3), "more than 0.3 seconds")

    def refused_in_time(self, total, timeout, **kwargs):
        """The /slow-header fetch, refused for its total within `total` plus one `timeout`; its
        list arrives whole after about 1.8 s, so a bound that waits for it is seen."""
        started = time.monotonic()
        self.refused_with(lambda: self.fetch("/slow-header", total=total, timeout=timeout,
                                             **kwargs), "more than %s seconds" % total)
        self.assertLess(time.monotonic() - started, total + timeout)

    def test_a_header_that_arrives_past_the_total_is_refused(self):
        """The total bounds the whole exchange, not only the body: a header sent a byte at a
        time, each byte inside the read timeout, is cut at the total."""
        self.assertEqual(self.fetch("/slow-header", total=10, timeout=0.6), _LIST_BODY)
        self.refused_in_time(0.3, 0.6)

    def test_a_connection_made_after_the_total_is_cut_at_once(self):
        """A connection that is made only after the total has passed is cut as it is made."""
        def late(address, timeout=None, source_address=None):
            time.sleep(0.4)
            return socket.create_connection(address, timeout, source_address)
        self.refused_in_time(0.2, 0.6, connect=late)

    def test_the_connection_has_one_timeout_across_every_address(self):
        """Each allowed address is tried in turn, all within one timeout; the socket returned waits
        the full timeout on each read."""
        addresses = ["93.184.215.%d" % n for n in (14, 15, 16, 17)]
        found = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 443)) for a in addresses]
        given = []

        def unanswered(attempt, connect_timeout, read_timeout, source_address):
            given.append((attempt[3][0], connect_timeout, read_timeout))
            time.sleep(connect_timeout)
            raise socket.timeout("timed out")

        with mock.patch.object(socket, "getaddrinfo", return_value=found), \
                mock.patch.object(status_fetch, "_connected", unanswered):
            started = time.monotonic()
            self.refused_with(lambda: status_fetch.connect_public(("status.example", 443), 0.3),
                              "no connection to status.example within 0.3 seconds")
            self.assertLess(time.monotonic() - started, 0.6)
        self.assertEqual([address for address, _, _ in given], addresses[:1])

        connected, given[:] = object(), []

        def second(attempt, connect_timeout, read_timeout, source_address):
            given.append((attempt[3][0], connect_timeout, read_timeout))
            if attempt[3][0] == addresses[0]:
                raise ConnectionRefusedError("refused")
            return connected

        with mock.patch.object(socket, "getaddrinfo", return_value=found), \
                mock.patch.object(status_fetch, "_connected", second):
            self.assertIs(status_fetch.connect_public(("status.example", 443), 0.3), connected)
        self.assertEqual([address for address, _, _ in given], addresses[:2])
        self.assertLess(given[1][1], 0.3)
        self.assertEqual([read for _, _, read in given], [0.3, 0.3])

    def test_a_connected_socket_waits_the_full_timeout_on_each_read(self):
        server = socket.socket()
        self.addCleanup(server.close)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        sock = status_fetch._connected(
            (socket.AF_INET, socket.SOCK_STREAM, 0, server.getsockname()), 0.5, 7, None)
        self.addCleanup(sock.close)
        self.assertEqual(sock.gettimeout(), 7)

    def test_only_https_is_fetched(self):
        connections = self.listener.connections
        self.refused_with(lambda: status_fetch.fetch_status_list(
            "http://127.0.0.1:%d/ok" % self.listener.port, connect=socket.create_connection),
            "https only")
        self.assertEqual(self.listener.connections, connections)

    def test_this_machine_is_never_connected_to(self):
        connections = self.listener.connections
        self.refused_with(lambda: status_fetch.fetch_status_list(
            self.listener.url("/ok"), context=self.listener.client_context), "loopback")
        self.refused_with(lambda: status_fetch.connect_public(("localhost", self.listener.port),
                                                             2), "no address a status list")
        self.assertEqual(self.listener.connections, connections)

    def test_each_kind_of_address_is_judged(self):
        for address, kind in (("127.0.0.1", "loopback"), ("::1", "loopback"),
                              ("::ffff:127.0.0.1", "loopback"), ("10.1.2.3", "private"),
                              ("172.16.0.1", "private"), ("192.168.0.1", "private"),
                              ("169.254.169.254", "link-local"), ("fe80::1", "link-local"),
                              ("fd00::1", "unique-local"), ("0.0.0.0", "unspecified"),
                              ("::", "unspecified"), ("224.0.0.1", "multicast"),
                              ("100.64.0.1", "not a global address")):
            with self.subTest(address=address):
                self.assertIn(kind, status_fetch.address_refusal(address))
        for address in ("93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"):
            with self.subTest(address=address):
                self.assertEqual(status_fetch.address_refusal(address), "")

    def test_an_ipv4_address_inside_ipv6_is_judged_as_the_ipv4_address(self):
        """Python 3.9 reads ::ffff:10.1.2.3 as an IPv6 address no rule above matches; the fetch
        judges, and names, the IPv4 address it carries."""
        for address, said in (("::ffff:127.0.0.1", "127.0.0.1 is a loopback address"),
                              ("::ffff:10.1.2.3", "10.1.2.3 is a private or unique-local address"),
                              ("::ffff:169.254.169.254", "169.254.169.254 is a link-local address")):
            with self.subTest(address=address):
                self.assertEqual(status_fetch.address_refusal(address), said)


if __name__ == "__main__":
    unittest.main()
