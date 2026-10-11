# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_fixture.py: the Ed25519-holder fixture is what make_fixture.py makes, byte for byte, and each
file is what fixture.json says it is, checked with `cryptography` alone: the issuer signatures under the
test CA, the disclosures in `_sd`, the holder key in `cnf.jwk`, and the example Key Binding JWT. Every
verification here has a negative control (one flipped byte, an empty input) that must fail."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ["credential.dc+sd-jwt", "credential.vc+sd-jwt", "example-presentation.dc+sd-jwt", "fixture.json",
         "holder-private.test-only.jwk.json", "trust-anchor.pem"]


def read(name, where=HERE):
    """A fixture file's text. Missing or empty fails: a check over nothing would pass by finding nothing."""
    path = os.path.join(where, name)
    if not os.path.isfile(path):
        raise AssertionError("%s is missing" % name)
    with open(path, newline="") as f:
        text = f.read()
    if not text.strip():
        raise AssertionError("%s is empty" % name)
    return text


def b64u_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def parts(jws):
    head, body, sig = jws.split(".")
    return json.loads(b64u_decode(head)), json.loads(b64u_decode(body)), (head + "." + body).encode("ascii"), \
        b64u_decode(sig)


def flip(jws):
    """The same JWS with the first signature byte flipped: the negative control for every verify."""
    head, body, sig = jws.split(".")
    raw = bytearray(b64u_decode(sig))
    raw[0] ^= 0x01
    return head + "." + body + "." + base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def issuer_verifies(jwt, anchor, at):
    """True when the issuer JWT's x5c leaf chains to `anchor`, is valid at `at` and signs the JWT (ES256)."""
    if not jwt:
        return False
    header, _, signing_input, sig = parts(jwt)
    leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
    try:
        leaf.verify_directly_issued_by(anchor)
    except (ValueError, TypeError, InvalidSignature):
        return False
    if not leaf.not_valid_before_utc.timestamp() <= at <= leaf.not_valid_after_utc.timestamp():
        return False
    if header.get("alg") != "ES256" or len(sig) != 64:
        return False
    try:
        leaf.public_key().verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                                 signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def kb_verifies(kb_jwt, public_jwk):
    """True when the Key Binding JWT is EdDSA, typ kb+jwt, and signed by the Ed25519 key `public_jwk`."""
    if not kb_jwt:
        return False
    header, _, signing_input, sig = parts(kb_jwt)
    if header != {"alg": "EdDSA", "typ": "kb+jwt"}:
        return False
    key = ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(public_jwk["x"]))
    try:
        key.verify(sig, signing_input)
    except InvalidSignature:
        return False
    return True


def sd_digest(disclosure):
    return base64.urlsafe_b64encode(hashlib.sha256(disclosure.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


FX = json.loads(read("fixture.json"))
ANCHOR = x509.load_pem_x509_certificate(read("trust-anchor.pem").encode("ascii"))
PRIVATE = json.loads(read("holder-private.test-only.jwk.json"))
CREDENTIALS = {typ: read("credential." + typ) for typ in ("dc+sd-jwt", "vc+sd-jwt")}
PRESENTATION = read("example-presentation.dc+sd-jwt")


class Ed25519HolderFixture(unittest.TestCase):
    def test_the_files_are_the_listed_ones_in_the_stored_form(self):
        self.assertEqual(sorted(FX["files"]), FILES)
        self.assertEqual(sorted(n for n in os.listdir(HERE) if n not in ("make_fixture.py", "test_fixture.py",
                                                                         "README.md", "__pycache__")), FILES)
        for typ, cred in CREDENTIALS.items():
            with self.subTest(typ=typ):
                self.assertTrue(cred.endswith("~"), "the stored form ends with ~ and carries no Key Binding JWT")
                self.assertNotIn("\n", cred)
                self.assertEqual(len(cred.split("~")), 2 + len(FX["claims"]))

    def test_the_issuer_signatures_verify_under_the_test_ca(self):
        self.assertTrue(ANCHOR.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        for typ, cred in CREDENTIALS.items():
            jwt = cred.split("~")[0]
            with self.subTest(typ=typ):
                header, payload, _, _ = parts(jwt)
                self.assertEqual((header["alg"], header["typ"], len(header["x5c"])), ("ES256", typ, 1))
                self.assertEqual(payload["iss"], FX["issuer"])
                self.assertTrue(issuer_verifies(jwt, ANCHOR, FX["now"]))
                self.assertTrue(issuer_verifies(jwt, ANCHOR, time.time()), "the leaf is valid today too")
                self.assertFalse(issuer_verifies(flip(jwt), ANCHOR, FX["now"]), "a flipped byte must not verify")
                leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
                self.assertFalse(issuer_verifies(jwt, leaf, FX["now"]), "the leaf is not its own anchor")

    def test_the_disclosures_hash_into_sd(self):
        for typ, cred in CREDENTIALS.items():
            jwt, *disclosures = cred.split("~")[:-1]
            _, payload, _, _ = parts(jwt)
            with self.subTest(typ=typ):
                self.assertEqual(payload["_sd_alg"], "sha-256")
                self.assertEqual(sorted(payload["_sd"]), sorted(sd_digest(d) for d in disclosures))
                decoded = {}
                for d in disclosures:
                    salt, name, value = json.loads(b64u_decode(d))
                    self.assertGreaterEqual(len(b64u_decode(salt)), 16)
                    decoded[name] = value
                    self.assertNotIn(name, payload, "a disclosed claim is not also in the clear")
                self.assertEqual(decoded, FX["claims"])
                self.assertNotIn(sd_digest(disclosures[0] + "x"), payload["_sd"], "control: a changed disclosure")

    def test_cnf_jwk_is_the_public_half_of_the_published_private_key(self):
        public = {k: v for k, v in PRIVATE.items() if k != "d"}
        self.assertEqual(set(PRIVATE), {"kty", "crv", "x", "d"})
        self.assertEqual(public, FX["holder_public_jwk"])
        derived = ed25519.Ed25519PrivateKey.from_private_bytes(b64u_decode(PRIVATE["d"])).public_key()
        self.assertEqual(derived.public_bytes_raw(), b64u_decode(PRIVATE["x"]), "d derives x")
        for typ, cred in CREDENTIALS.items():
            with self.subTest(typ=typ):
                self.assertEqual(parts(cred.split("~")[0])[1]["cnf"], {"jwk": public})

    def test_the_holder_did_key_names_the_same_key(self):
        did = FX["holder_did_key"]
        self.assertTrue(did.startswith("did:key:z6Mk"), "an Ed25519 did:key starts z6Mk")
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        n = 0
        for ch in did[len("did:key:z"):]:
            n = n * 58 + alphabet.index(ch)
        self.assertEqual(n.to_bytes(34, "big"), b"\xed\x01" + b64u_decode(PRIVATE["x"]))

    def test_the_example_key_binding_jwt_verifies_and_binds_the_presentation(self):
        presented, kb_jwt = PRESENTATION[:PRESENTATION.rindex("~") + 1], PRESENTATION[PRESENTATION.rindex("~") + 1:]
        self.assertTrue(kb_verifies(kb_jwt, FX["holder_public_jwk"]))
        self.assertFalse(kb_verifies(flip(kb_jwt), FX["holder_public_jwk"]), "a flipped byte must not verify")
        other = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(32)).public_key().public_bytes_raw()
        self.assertFalse(kb_verifies(kb_jwt, {"kty": "OKP", "crv": "Ed25519",
                                              "x": base64.urlsafe_b64encode(other).rstrip(b"=").decode()}))
        _, kb, _, _ = parts(kb_jwt)
        self.assertEqual(kb["sd_hash"], sd_digest(presented))
        self.assertNotEqual(kb["sd_hash"], sd_digest(CREDENTIALS["dc+sd-jwt"]), "control: another disclosure set")
        self.assertEqual((kb["nonce"], kb["aud"], kb["iat"]), (FX["nonce"], FX["audience"], FX["now"]))
        jwt, *disclosures = presented.split("~")[:-1]
        self.assertEqual(jwt, CREDENTIALS["dc+sd-jwt"].split("~")[0], "the presentation carries the credential")
        self.assertEqual(sorted(json.loads(b64u_decode(d))[1] for d in disclosures), sorted(FX["presented_claims"]))
        self.assertTrue(set(sd_digest(d) for d in disclosures) < set(parts(jwt)[1]["_sd"]))

    def test_the_two_typ_forms_differ_only_in_typ_and_signature(self):
        dc, vc = (CREDENTIALS[t].split("~") for t in ("dc+sd-jwt", "vc+sd-jwt"))
        self.assertEqual(dc[1:], vc[1:], "the same disclosures")
        (h1, b1, s1), (h2, b2, s2) = dc[0].split("."), vc[0].split(".")
        self.assertEqual(b1, b2, "the same payload, byte for byte")
        self.assertNotEqual(s1, s2)
        head1, head2 = json.loads(b64u_decode(h1)), json.loads(b64u_decode(h2))
        self.assertEqual((head1.pop("typ"), head2.pop("typ")), ("dc+sd-jwt", "vc+sd-jwt"))
        self.assertEqual(head1, head2)

    def test_exp_is_in_the_future(self):
        for typ, cred in CREDENTIALS.items():
            with self.subTest(typ=typ):
                payload = parts(cred.split("~")[0])[1]
                self.assertEqual((payload["exp"], payload["iat"], payload["vct"]), (FX["exp"], FX["now"], FX["vct"]))
                self.assertGreater(payload["exp"], time.time() + 50 * 365 * 86400)

    def test_running_the_generator_again_reproduces_every_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(os.path.join(HERE, "make_fixture.py"), tmp)
            env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
            subprocess.run([sys.executable, "make_fixture.py"], cwd=tmp, env=env, check=True, capture_output=True)
            made = sorted(n for n in os.listdir(tmp) if n != "make_fixture.py")
            self.assertEqual(made, FILES)
            for name in FILES:
                with self.subTest(name=name), open(os.path.join(tmp, name), "rb") as a, \
                        open(os.path.join(HERE, name), "rb") as b:
                    self.assertEqual(a.read(), b.read(), "%s drifted from make_fixture.py" % name)

    def test_polaris_oid4vp_refuses_the_ed25519_holder_key_today(self):
        """The README's sentence, held: polaris-oid4vp accepts ES256 key binding only, so it verifies the issuer
        part and refuses at the holder key. When an EdDSA option is built this fails and the README changes."""
        sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "packages", "polaris-oid4vp"))
        from polaris_oid4vp.sdjwt import verify_presentation
        verdict = verify_presentation(PRESENTATION, expected_nonce=FX["nonce"], expected_audience=FX["audience"],
                                      trust_anchors=[ANCHOR], now=FX["now"], expected_vct=FX["vct"])
        self.assertFalse(verdict.authentic)
        self.assertEqual(verdict.code, "kb_cnf", verdict.reason)
        self.assertIn("kty='OKP' crv='Ed25519'", verdict.reason)

    def test_an_empty_or_missing_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            open(os.path.join(tmp, "empty"), "w").close()
            with open(os.path.join(tmp, "blank"), "w") as f:
                f.write("\n")
            for name in ("missing", "empty", "blank"):
                with self.subTest(name=name), self.assertRaises(AssertionError):
                    read(name, tmp)
        self.assertFalse(issuer_verifies("", ANCHOR, FX["now"]))
        self.assertFalse(kb_verifies("", FX["holder_public_jwk"]))


if __name__ == "__main__":
    unittest.main()
