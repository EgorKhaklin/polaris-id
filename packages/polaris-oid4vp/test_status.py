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
import json
import random
import unittest
import zlib

from polaris_oid4vp import status as S

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
                v = decide(tok, issuer_key_verify=accept)
                self.assertFalse(v["checked"])
        for label, idx in (("negative", -1), ("boolean", True), ("string", "1"), ("float", 1.5)):
            with self.subTest(index=label):
                v = decide(token(p), index=idx, issuer_key_verify=accept)
                self.assertFalse(v["checked"])


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



class PrimitiveRefusalsTests(unittest.TestCase):
    """Each primitive refusal driven directly (2026-09-23). Inverting any of these left the
    whole package suite green, because every caller also refuses the malformed list for some
    later reason; the primitive's own promise was never asserted."""

    def test_a_status_value_at_an_unknown_width_is_refused(self):
        self.assertEqual(S.status_at(b"\xb9", 0, 1), 1)
        for bits in (0, 3, 16, None, "1"):
            with self.assertRaises(ValueError, msg=bits):
                S.status_at(b"\xb9", 0, bits)

    def test_base64url_that_does_not_decode_is_refused(self):
        self.assertEqual(S._b64u("AQI", "list"), b"\x01\x02")
        for bad in ("a", "ab$c"):
            with self.assertRaises(ValueError, msg=bad):
                S._b64u(bad, "list")

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

if __name__ == "__main__":
    unittest.main()
