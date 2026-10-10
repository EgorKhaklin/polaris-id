# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The captured eudi-dev presentation, verified offline with the clock frozen at the capture.

Runs from this directory in the repository (against packages/polaris-oid4vp in the tree) or
from a copy of it anywhere (against an installed polaris-oid4vp). No network, no Docker.

    python -m unittest test_capture
"""
import base64
import hashlib
import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
# In the repository, the tree's package, so this stays true as the verifier moves; in a copy
# outside it, whatever polaris-oid4vp is installed.
try:
    _TREE = HERE.parents[3] / "packages" / "polaris-oid4vp"
except IndexError:
    _TREE = None
if _TREE is not None and (_TREE / "polaris_oid4vp" / "sdjwt.py").is_file():
    sys.path.insert(0, str(_TREE))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402

from polaris_oid4vp.jwe import decrypt_compact  # noqa: E402
from polaris_oid4vp.sdjwt import verify_presentation  # noqa: E402

#: The capture instant, POSIX seconds (2026-10-10T19:49:20Z; PROVENANCE.md). The key binding
#: JWT's freshness and the issuer certificate's validity are judged at this instant.
CAPTURE_INSTANT = 1791661760


def read(name):
    return (HERE / name).read_bytes()


def b64u_decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def jwt_parts(compact):
    header, payload, signature = compact.split(".")
    return json.loads(b64u_decode(header)), json.loads(b64u_decode(payload)), signature


def flip_signature_byte(jws):
    """The same JWS with one byte of its decoded signature flipped (XOR 0x01, at byte 10)."""
    signing_input, _, signature = jws.rpartition(".")
    raw = bytearray(b64u_decode(signature))
    raw[10] ^= 0x01
    return signing_input + "." + b64u_encode(bytes(raw))


class CapturedPresentation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.presentation = read("presentation.txt").decode("ascii")
        cls.request = json.loads(read("request.json"))
        cls.anchors = x509.load_pem_x509_certificates(read("issuer-ca.pem"))
        parts = cls.presentation.split("~")
        cls.issuer_jwt, cls.disclosures, cls.kb_jwt = parts[0], parts[1:-1], parts[-1]

    def verify(self, presentation=None, now=CAPTURE_INSTANT, anchors=None):
        return verify_presentation(
            self.presentation if presentation is None else presentation,
            expected_nonce=self.request["nonce"],
            expected_audience=self.request["client_id"],
            trust_anchors=self.anchors if anchors is None else anchors,
            expected_vct=self.request["dcql_query"]["credentials"][0]["meta"]["vct_values"],
            now=now)

    def test_the_genuine_presentation_verifies(self):
        verdict = self.verify()
        self.assertTrue(verdict.authentic, "%s: %s" % (verdict.code, verdict.reason))
        self.assertEqual(verdict.claims["given_name"], "Jean")
        self.assertEqual(verdict.claims["family_name"], "Dupont")
        self.assertEqual(verdict.claims["vct"], "urn:eudi:pid:1")
        self.assertEqual(sorted(verdict.disclosed), [("family_name",), ("given_name",)])

    def test_the_key_binding_jwt_answers_this_request(self):
        header, payload, _ = jwt_parts(self.kb_jwt)
        self.assertEqual(header["typ"], "kb+jwt")
        self.assertEqual(payload["aud"], self.request["client_id"])
        self.assertEqual(payload["nonce"], self.request["nonce"])
        self.assertLessEqual(abs(payload["iat"] - CAPTURE_INSTANT), 5)

    def test_one_flipped_byte_in_the_key_binding_signature_is_refused(self):
        tampered = "~".join([self.issuer_jwt] + self.disclosures + [flip_signature_byte(self.kb_jwt)])
        self.assertEqual(len(tampered), len(self.presentation))
        verdict = self.verify(tampered)
        self.assertFalse(verdict.authentic)
        self.assertEqual(verdict.code, "kb_signature")

    def test_one_flipped_byte_in_the_issuer_signature_is_refused(self):
        tampered = "~".join([flip_signature_byte(self.issuer_jwt)] + self.disclosures + [self.kb_jwt])
        self.assertEqual(len(tampered), len(self.presentation))
        verdict = self.verify(tampered)
        self.assertFalse(verdict.authentic)
        self.assertEqual(verdict.code, "issuer_signature")

    def test_an_unrelated_trust_anchor_is_refused(self):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "unrelated CA")])
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
              .public_key(key.public_key()).serial_number(1)
              .not_valid_before(self.anchors[0].not_valid_before_utc)
              .not_valid_after(self.anchors[0].not_valid_after_utc)
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .sign(key, hashes.SHA256()))
        verdict = self.verify(anchors=[ca])
        self.assertFalse(verdict.authentic)
        self.assertEqual(verdict.code, "issuer_key")

    def test_the_frozen_clock_is_load_bearing(self):
        # An hour after the capture the key binding JWT is stale: the clock is part of the fixture.
        verdict = self.verify(now=CAPTURE_INSTANT + 3600)
        self.assertFalse(verdict.authentic)
        self.assertEqual(verdict.code, "kb_freshness")


class CapturedExchange(unittest.TestCase):
    """The files agree with each other: the presentation is the vp_token's value, the vp_token
    is what the posted response decrypts to, and request.json is the signed request's payload."""

    def test_the_presentation_is_the_vp_token_value_verbatim(self):
        vp_raw = read("vp-token.json")
        presentation = read("presentation.txt")
        self.assertEqual(json.loads(vp_raw), {"pid": [presentation.decode("ascii")]})
        self.assertIn(b'"' + presentation + b'"', vp_raw)

    def test_the_response_decrypts_to_the_vp_token_verbatim(self):
        jwk = json.loads(read("verifier-decryption-key.test-only.jwk.json"))
        key = ec.derive_private_key(int.from_bytes(b64u_decode(jwk["d"]), "big"), ec.SECP256R1())
        plaintext = decrypt_compact(read("response.jwe").decode("ascii"), key)
        self.assertIn(b'"vp_token":' + read("vp-token.json"), plaintext)
        body = json.loads(plaintext)
        self.assertEqual(body["state"], json.loads(read("request.json"))["state"])

    def test_request_json_is_the_signed_request_objects_payload(self):
        jar = read("request.jwt").decode("ascii")
        header, payload, signature = jwt_parts(jar)
        leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
        raw = b64u_decode(signature)
        leaf.public_key().verify(
            encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
            jar.rpartition(".")[0].encode("ascii"), ec.ECDSA(hashes.SHA256()))
        digest = hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest()
        self.assertEqual(payload["client_id"], "x509_hash:" + b64u_encode(digest))
        request = json.loads(read("request.json"))
        self.assertEqual(sorted(request), sorted(["nonce", "client_id", "state", "response_mode",
                                                  "response_uri", "dcql_query"]))
        for name, value in request.items():
            self.assertEqual(payload[name], value, name)


if __name__ == "__main__":
    unittest.main()
