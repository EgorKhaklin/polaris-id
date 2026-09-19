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
        bomb = base64.urlsafe_b64encode(
            zlib.compress(b"\x00" * (S.MAX_DECOMPRESSED_BYTES * 4), 9)).rstrip(b"=").decode()
        p = payload()
        p["status_list"]["lst"] = bomb
        v = decide(token(p), issuer_key_verify=accept)
        self.assertEqual(v["code"], "lst")

    def test_an_unknown_status_is_not_folded_into_valid(self):
        v = decide(token(payload(statuses=(0, 3, 0, 0))), issuer_key_verify=accept)
        self.assertTrue(v["checked"])
        self.assertEqual(v["status"], 3)
        self.assertIsNone(v["meaning"])

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


if __name__ == "__main__":
    unittest.main()
