# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_fixture.py: the revoked-credential fixture is what make_fixture.py makes, byte for byte, and
polaris-oid4vp reads its credential as authentic with index 3 INVALID and index 2 VALID."""
import base64
import importlib.util
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "packages", "polaris-oid4vp"))
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402
from polaris_oid4vp import status as S  # noqa: E402
from polaris_oid4vp.sdjwt import verify_presentation  # noqa: E402

_spec = importlib.util.spec_from_file_location("make_fixture", os.path.join(HERE, "make_fixture.py"))
make_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_fixture)


def read(name):
    with open(os.path.join(HERE, name)) as f:
        return f.read()


FX = json.loads(read("fixture.json"))
TOKEN = read("status-list.jwt").strip()


def _leaf_verify(token):
    header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))

    def verify(signing_input, signature, header):
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        try:
            leaf.public_key().verify(utils.encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:  # noqa: BLE001: any failure is a signature that does not verify
            return False
    return verify


AUTHORITY = S.StatedAuthority().state(credential_issuer=FX["issuer"], status_uri=FX["status_uri"],
                                      verify=_leaf_verify(TOKEN), why="the fixture's issuer key publishes its status list")


def decide(index, token=TOKEN):
    return S.decide(token, index=index, expected_uri=FX["status_uri"], authority=AUTHORITY, now=FX["now"],
                    credential_issuer=FX["issuer"])


class RevokedFixture(unittest.TestCase):
    def test_the_files_are_what_the_generator_makes(self):
        built = make_fixture.build()
        self.assertEqual(sorted(built), ["credential.sd-jwt", "fixture.json", "presentation.sd-jwt",
                                         "status-list.jwt", "trust-anchor.pem"])
        for name, text in built.items():
            self.assertEqual(read(name), text, "%s drifted from make_fixture.py" % name)

    def test_the_presentation_is_authentic_and_its_status_is_invalid(self):
        root = x509.load_pem_x509_certificate(read("trust-anchor.pem").encode())
        verdict = verify_presentation(read("presentation.sd-jwt").strip(), expected_nonce=FX["nonce"],
                                      expected_audience=FX["audience"], trust_anchors=[root], now=FX["now"],
                                      expected_vct=FX["vct"],
                                      status_resolver=lambda uri, idx, issuer: decide(idx))
        self.assertTrue(verdict.authentic, verdict.reason)
        self.assertEqual((verdict.revocation["state"], verdict.revocation["idx"], verdict.revocation["status"],
                          verdict.revocation["meaning"]), ("checked", FX["revoked_index"], 1, "INVALID"))

    def test_the_control_index_is_valid(self):
        verdict = decide(FX["valid_index"])
        self.assertEqual((verdict["checked"], verdict["status"], verdict["meaning"]), (True, 0, "VALID"))

    def test_the_credential_carries_the_status_claim_and_no_key_binding(self):
        credential = read("credential.sd-jwt").strip()
        self.assertTrue(credential.endswith("~"), "an issued SD-JWT ends with ~ and carries no Key Binding JWT")
        self.assertTrue(read("presentation.sd-jwt").startswith(credential))
        payload = json.loads(base64.urlsafe_b64decode(credential.split("~")[0].split(".")[1] + "=="))
        self.assertEqual(payload["status"], {"status_list": {"idx": FX["revoked_index"], "uri": FX["status_uri"]}})


if __name__ == "__main__":
    unittest.main()
