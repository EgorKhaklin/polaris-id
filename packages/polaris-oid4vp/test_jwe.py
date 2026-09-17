"""test_jwe.py -- the encrypted response, opened, and the ways it must refuse to open.

READ THE LIMIT FIRST. Every test here encrypts with this package and decrypts with this
package. That shows the two halves agree. It does NOT show either half agrees with anybody
else, because two consistent mistakes pass a round trip just as cleanly as two correct
implementations. The evidence that settles it is a JWE produced by the conformance suite's
wallet, which `lab/interop/probe.py` obtains and this file cannot.

What these tests do establish is the refusal surface, and that is worth having on its own: a
verifier that opens a response encrypted to somebody else's key, or follows `alg` wherever the
header points it, has no confidentiality property to talk about.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from polaris_oid4vp.jwe import (  # noqa: E402
    JweError, b64u_encode, decrypt_compact, decrypt_response, encrypt_compact,
)

BODY = {"vp_token": {"pid": ["eyJ...~~kb"]}, "state": "0bf2c1"}


class RoundTripTests(unittest.TestCase):
    """The positive control. Without it every refusal below is a verifier that never opens."""

    def test_a128gcm_round_trips(self):
        key = ec.generate_private_key(ec.SECP256R1())
        token = encrypt_compact(json.dumps(BODY).encode(), key.public_key(), "A128GCM")
        self.assertEqual(decrypt_response(token, key), BODY)

    def test_a256gcm_round_trips(self):
        """Advertised in client_metadata, so it has to actually work."""
        key = ec.generate_private_key(ec.SECP256R1())
        token = encrypt_compact(json.dumps(BODY).encode(), key.public_key(), "A256GCM")
        self.assertEqual(decrypt_response(token, key), BODY)

    def test_apu_and_apv_are_bound_into_the_key(self):
        key = ec.generate_private_key(ec.SECP256R1())
        token = encrypt_compact(b"hello", key.public_key(), "A128GCM",
                                apu=b"wallet", apv=b"verifier")
        self.assertEqual(decrypt_compact(token, key), b"hello")

    def test_a_compact_jwe_has_five_parts_and_an_empty_encrypted_key(self):
        key = ec.generate_private_key(ec.SECP256R1())
        parts = encrypt_compact(b"x", key.public_key()).split(".")
        self.assertEqual(len(parts), 5)
        self.assertEqual(parts[1], "", "ECDH-ES is direct agreement: nothing to wrap")


class RefusalTests(unittest.TestCase):

    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.token = encrypt_compact(json.dumps(BODY).encode(), self.key.public_key())

    def _expect(self, token, fragment, key=None):
        with self.assertRaises(JweError) as caught:
            decrypt_compact(token, key or self.key)
        self.assertIn(fragment, str(caught.exception))

    def test_a_response_encrypted_to_another_verifier_is_refused(self):
        """The whole point of publishing a key: somebody else's response is not ours."""
        self._expect(self.token, "does not authenticate", ec.generate_private_key(ec.SECP256R1()))

    def test_a_tampered_ciphertext_is_refused(self):
        parts = self.token.split(".")
        mangled = bytearray(os.urandom(len(parts[3])))
        parts[3] = b64u_encode(bytes(mangled))
        self._expect(".".join(parts), "does not authenticate")

    def test_a_tampered_header_is_refused(self):
        """The protected header is the AAD, so editing it breaks authentication."""
        parts = self.token.split(".")
        header = json.loads(
            __import__("base64").urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
        header["apv"] = b64u_encode(b"somebody-else")
        parts[0] = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        self._expect(".".join(parts), "does not authenticate")

    def test_an_unknown_alg_is_refused_rather_than_followed(self):
        parts = self.token.split(".")
        header = json.loads(
            __import__("base64").urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
        header["alg"] = "RSA-OAEP"
        parts[0] = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        self._expect(".".join(parts), "walked onto")

    def test_an_unknown_enc_is_refused(self):
        parts = self.token.split(".")
        header = json.loads(
            __import__("base64").urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
        header["enc"] = "A128CBC-HS256"
        parts[0] = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        self._expect(".".join(parts), "accepted set")

    def test_a_present_encrypted_key_is_refused(self):
        """Direct agreement wraps nothing. A wrapped key here is another algorithm."""
        parts = self.token.split(".")
        parts[1] = b64u_encode(b"a-wrapped-key")
        self._expect(".".join(parts), "must be empty")

    def test_a_missing_epk_is_refused(self):
        parts = self.token.split(".")
        header = json.loads(
            __import__("base64").urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
        header.pop("epk")
        parts[0] = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        self._expect(".".join(parts), "requires an epk")

    def test_an_epk_on_the_wrong_curve_is_refused(self):
        parts = self.token.split(".")
        header = json.loads(
            __import__("base64").urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
        header["epk"]["crv"] = "P-384"
        parts[0] = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        self._expect(".".join(parts), "EC P-256 JWK")

    def test_structural_junk_is_refused_without_raising_something_else(self):
        for junk in ("", "a.b.c", "a.b.c.d.e.f", "....", "not a jwe", "\x00.\x00.\x00.\x00.\x00"):
            with self.assertRaises(JweError, msg="%r did not raise JweError" % junk):
                decrypt_compact(junk, self.key)

    def test_a_decrypted_non_json_body_is_refused_by_decrypt_response(self):
        token = encrypt_compact(b"not json at all", self.key.public_key())
        with self.assertRaises(JweError) as caught:
            decrypt_response(token, self.key)
        self.assertIn("not JSON", str(caught.exception))


class StructuralRefusalsCoverageFoundTests(unittest.TestCase):
    """Paths that existed with nothing reaching them, found by measuring coverage."""

    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.token = encrypt_compact(json.dumps(BODY).encode(), self.key.public_key())

    def _expect(self, token, fragment, key=None):
        with self.assertRaises(JweError) as caught:
            decrypt_compact(token, key or self.key)
        self.assertIn(fragment, str(caught.exception))

    def test_a_token_that_is_not_a_string_is_refused(self):
        for junk in (None, 42, b"bytes", ["a", "b"]):
            with self.assertRaises(JweError):
                decrypt_compact(junk, self.key)

    def test_a_protected_header_that_is_not_an_object_is_refused(self):
        parts = self.token.split(".")
        parts[0] = b64u_encode(b'["not", "an", "object"]')
        self._expect(".".join(parts), "not a JSON object")

    def test_an_epk_missing_a_coordinate_is_refused(self):
        parts = self.token.split(".")
        header = json.loads(_decode(parts[0]))
        header["epk"].pop("y")
        parts[0] = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        # The message says the coordinate is absent rather than that it "does not decode",
        # which is what it used to say because a KeyError was being caught by the decode
        # handler. An absent field and an undecodable one are different defects and the
        # operator reading the log is the one who needs them apart.
        self._expect(".".join(parts), "no string 'y' coordinate")

    def test_an_epk_coordinate_of_the_wrong_json_type_is_refused_as_a_JweError(self):
        """A number or a list where a string belongs reached b64u_decode and came back as
        TypeError, not JweError. `verifier.py` catches only JweError, so the whole response
        path aborted instead of refusing this response and moving on."""
        for bad in (1, [1, 2], {"a": 1}, None, True):
            with self.subTest(value=repr(bad)):
                parts = self.token.split(".")
                header = json.loads(_decode(parts[0]))
                header["epk"]["x"] = bad
                parts[0] = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
                self._expect(".".join(parts), "coordinate")

    def test_an_epk_that_is_not_on_the_curve_is_refused_as_a_JweError(self):
        """The first probe of an invalid-curve attack. cryptography raises ValueError for a
        point off the curve and for the point at infinity; both escaped as themselves."""
        for label, (x, y) in (("off the curve", (b"\x02" * 32, b"\x03" * 32)),
                              ("point at infinity", (b"\x00" * 32, b"\x00" * 32))):
            with self.subTest(label):
                parts = self.token.split(".")
                header = json.loads(_decode(parts[0]))
                header["epk"]["x"] = b64u_encode(x)
                header["epk"]["y"] = b64u_encode(y)
                parts[0] = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
                self._expect(".".join(parts), "P-256")

    def test_apu_and_apv_of_the_wrong_json_type_are_refused_as_a_JweError(self):
        """Both are attacker-supplied and go straight into the KDF. An object, a list or a
        number produced TypeError; non-ASCII text produced UnicodeEncodeError."""
        for field in ("apu", "apv"):
            for bad in ({"a": 1}, [1], 7, "\u00e9\u00e9\u00e9\u00e9"):
                with self.subTest(field=field, value=repr(bad)):
                    parts = self.token.split(".")
                    header = json.loads(_decode(parts[0]))
                    header[field] = bad
                    parts[0] = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
                    self._expect(".".join(parts), field)

    def test_an_epk_with_short_coordinates_is_refused(self):
        parts = self.token.split(".")
        header = json.loads(_decode(parts[0]))
        header["epk"]["x"] = b64u_encode(b"\x01" * 8)
        parts[0] = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        self._expect(".".join(parts), "32 bytes")

    def test_an_iv_of_the_wrong_length_is_refused(self):
        parts = self.token.split(".")
        parts[2] = b64u_encode(b"\x00" * 16)
        self._expect(".".join(parts), "96-bit iv")

    def test_a_segment_that_is_not_base64url_is_refused(self):
        """It has to actually reach the decode, which the obvious input does not.

        `parts[3] = "!!!!"` looks like the test and is not: base64 decoding with validation
        off STRIPS characters outside the alphabet, so four exclamation marks decode to
        empty bytes and the refusal arrives later, from the AES-GCM tag. The assertion
        passed and the line it was written for never ran. A single character cannot be
        padded to a valid length, so this is an input the decoder must refuse.
        """
        for segment in (2, 3, 4):
            parts = self.token.split(".")
            parts[segment] = "a"
            with self.assertRaises(JweError) as caught:
                decrypt_compact(".".join(parts), self.key)
            self.assertIn("not base64url", str(caught.exception),
                          "segment %d was refused for some other reason, so the decode "
                          "guard still has nothing exercising it" % segment)

    def test_a_decrypted_json_array_is_not_a_response(self):
        token = encrypt_compact(b'["vp_token"]', self.key.public_key())
        with self.assertRaises(JweError) as caught:
            decrypt_response(token, self.key)
        self.assertIn("not a JSON object", str(caught.exception))

    def test_encrypting_under_an_unsupported_enc_is_refused(self):
        with self.assertRaises(JweError) as caught:
            encrypt_compact(b"x", self.key.public_key(), "A128CBC-HS256")
        self.assertIn("not supported", str(caught.exception))


def _decode(value):
    import base64
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TheCoordinateDecodeRefusalIsAssertedTests(unittest.TestCase):
    """The mutation drill found this refusal unprotected on 2026-09-17, and why is worth
    recording: a guard added the same day made it harder to reach.

    `_public_key_from_jwk` now checks that `x` and `y` are STRINGS before decoding them, so
    every wrong-type case is refused above this line. A refusal made unreachable by a new
    guard in front of it is the quiet way a verifier loses a check.

    Measured while writing this: the branch is narrower than it looks. `urlsafe_b64decode` is
    lenient, so `"!!!!"`, `"a b c"` and `"===="` all decode to something short and are caught
    by the LENGTH check below rather than here. What actually reaches the decode refusal is a
    coordinate that is a string and is not ASCII.
    """

    GOOD = {"kty": "EC", "crv": "P-256",
            "x": b64u_encode(b"\x01" * 32), "y": b64u_encode(b"\x02" * 32)}

    def test_a_non_ascii_coordinate_is_a_JweError_from_the_decode(self):
        from polaris_oid4vp.jwe import JweError, _public_key_from_jwk
        for field in ("x", "y"):
            for bad in ("éééé", "日本語です", "\u00ff" * 43):
                with self.subTest(field=field, value=repr(bad)[:18]):
                    with self.assertRaises(JweError) as caught:
                        _public_key_from_jwk(dict(self.GOOD, **{field: bad}))
                    self.assertIn("decode", str(caught.exception))

    def test_a_short_but_decodable_coordinate_gets_past_the_decode(self):
        """The positive control, and the thing that makes the test above meaningful: these
        reach the LENGTH refusal, which proves the decode let them through."""
        from polaris_oid4vp.jwe import JweError, _public_key_from_jwk
        for bad in (b64u_encode(b"\x01" * 8), "!!!!", "===="):
            with self.subTest(value=repr(bad)[:14]):
                with self.assertRaises(JweError) as caught:
                    _public_key_from_jwk(dict(self.GOOD, x=bad))
                self.assertIn("32 bytes", str(caught.exception))

    def test_a_well_formed_coordinate_pair_builds_a_key(self):
        from polaris_oid4vp.jwe import _public_key_from_jwk
        from cryptography.hazmat.primitives.asymmetric import ec
        k = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256",
               "x": b64u_encode(k.x.to_bytes(32, "big")),
               "y": b64u_encode(k.y.to_bytes(32, "big"))}
        self.assertIsNotNone(_public_key_from_jwk(jwk))
