# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_cli.py -- the entry point, and the two certificate shapes the suite refuses.

`keygen` exists because the High Assurance profile's certificate requirements are not
guessable and each one cost a failed conformance run to discover:

  * the x5c leaf must NOT be self-signed
  * the registered trust anchor must NOT be in the chain

A command that produces the right shape is only worth having if something asserts the shape
is right, so these tests check the properties the suite checked, rather than checking that
five files appeared.
"""
import base64
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509  # noqa: E402

from polaris_oid4vp.cli import FILES, keygen, main, parse_claim, verifier_from  # noqa: E402
from test_verifier import Wallet  # noqa: E402


class KeygenTests(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-cli-"))
        keygen(self.tmp, "verifier.test")
        self.leaf = x509.load_pem_x509_certificate((self.tmp / FILES["client_cert"]).read_bytes())
        self.anchor = x509.load_pem_x509_certificate((self.tmp / FILES["anchor"]).read_bytes())

    def test_it_writes_exactly_what_serve_reads(self):
        for name in FILES.values():
            self.assertTrue((self.tmp / name).is_file(), name)

    def test_the_leaf_is_not_self_signed(self):
        """"Leaf certificate in x5c chain must not be self-signed", verbatim from a run."""
        self.assertNotEqual(self.leaf.issuer, self.leaf.subject)
        self.assertEqual(self.leaf.issuer, self.anchor.subject)

    def test_the_anchor_is_a_ca_and_the_leaf_is_not(self):
        self.assertTrue(self.anchor.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca)
        self.assertFalse(self.leaf.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca)

    def test_the_anchor_is_not_in_the_chain_the_verifier_sends(self):
        """"Trust anchor certificate must not be included in x5c chain", also verbatim."""
        verifier = verifier_from(self.tmp, "verifier.test", 9443)
        self.assertEqual(len(verifier.x5c), 1, "the chain must carry the leaf alone")
        import base64
        sent = x509.load_der_x509_certificate(base64.b64decode(verifier.x5c[0]))
        self.assertEqual(sent.subject, self.leaf.subject)
        self.assertNotEqual(sent.subject, self.anchor.subject)

    def test_the_client_id_is_the_hash_of_the_leaf_it_sends(self):
        import base64
        import hashlib
        from polaris_oid4vp.jwe import b64u_encode
        verifier = verifier_from(self.tmp, "verifier.test", 9443)
        digest = hashlib.sha256(base64.b64decode(verifier.x5c[0])).digest()
        self.assertEqual(verifier.client_id, "x509_hash:" + b64u_encode(digest))

    def test_public_base_url_overrides_the_advertised_origin(self):
        """A verifier behind a tunnel or proxy advertises a public origin, not its host:port."""
        from polaris_oid4vp.serve import REQUEST_PATH, RESPONSE_PATH
        v = verifier_from(self.tmp, "verifier.test", 9443,
                          public_base_url="https://tunnel.example/")
        self.assertEqual(v.request_uri, "https://tunnel.example" + REQUEST_PATH)
        self.assertEqual(v.response_uri, "https://tunnel.example" + RESPONSE_PATH)
        default = verifier_from(self.tmp, "verifier.test", 9443)
        self.assertEqual(default.request_uri, "https://verifier.test:9443" + REQUEST_PATH)

    def test_the_leaf_asserts_digital_signature(self):
        """An unmodified walt.id Wallet API v2 refused the leaf this used to produce.

        "Certificate does not contain client Key Usage 'digitalSignature'". The CA
        carried keyCertSign/cRLSign and the leaf carried no KeyUsage at all, so the one
        certificate whose entire job is signing request objects was not marked usable
        for signing. Eleven of eleven HAIP modules in the OpenID Foundation conformance
        suite passed against it, and the four tests above assert other properties of the
        same certificate without asserting this one. It took an implementation from
        outside this repository to say so. See EXTERNAL-NOUNS.md.
        """
        ku = self.leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.digital_signature,
                        "the request-signing leaf does not assert digitalSignature")
        self.assertFalse(ku.key_cert_sign, "a leaf must not be able to sign certificates")

    def test_the_private_keys_are_not_world_readable(self):
        for name in ("client_key", "tls_key"):
            mode = (self.tmp / FILES[name]).stat().st_mode & 0o777
            self.assertEqual(mode, 0o600, "%s is %o" % (name, mode))

    def test_the_tls_certificate_may_be_self_signed(self):
        """It is the listener's, not the request object's. The suite fetched one happily."""
        tls = x509.load_pem_x509_certificate((self.tmp / FILES["tls_cert"]).read_bytes())
        self.assertEqual(tls.issuer, tls.subject)

    def test_the_tls_certificate_is_marked_for_server_authentication(self):
        """Apple's TLS policy refuses a server certificate without serverAuth, even an
        explicitly trusted one (the EU iOS OpenID4VP library's walk, 2026-10-04)."""
        tls = x509.load_pem_x509_certificate((self.tmp / FILES["tls_cert"]).read_bytes())
        eku = tls.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, list(eku))

    def test_generating_twice_does_not_reuse_a_key(self):
        second = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-cli-"))
        keygen(second, "verifier.test")
        a = verifier_from(self.tmp, "verifier.test", 9443).client_id
        b = verifier_from(second, "verifier.test", 9443).client_id
        self.assertNotEqual(a, b)


class ServeCommandTests(unittest.TestCase):

    def test_serve_refuses_a_directory_with_no_keys_in_it(self):
        empty = tempfile.mkdtemp(prefix="polaris-oid4vp-empty-")
        self.assertEqual(main(["serve", "--pki", empty]), 2)

    def test_the_command_is_reachable_as_a_module(self):
        """`python -m polaris_oid4vp.cli` is what the console script wraps."""
        out = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-m-"))
        proc = subprocess.run([sys.executable, "-m", "polaris_oid4vp.cli", "keygen",
                               "--out", str(out), "--host", "example.test"],
                              capture_output=True, text=True,
                              cwd=os.path.dirname(os.path.abspath(__file__)))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("client_id", proc.stdout)
        self.assertIn("x509_hash:", proc.stdout)

    def test_the_help_does_not_name_a_source_file(self):
        """`--help` used to open with "cli.py -- ...", the module docstring's first line.

        Every drill in this tree does that and it is harmless there. On an installed command
        it puts a filename on the first screen a stranger sees, and it says nothing about
        what the program is for.
        """
        proc = subprocess.run([sys.executable, "-m", "polaris_oid4vp.cli", "--help"],
                              capture_output=True, text=True,
                              cwd=os.path.dirname(os.path.abspath(__file__)))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(".py", proc.stdout.split("positional arguments")[0],
                         "the description names a source file")
        # Normalised, because argparse wraps the epilog and the property is that the help
        # SAYS these things, not that any particular eleven bytes stayed contiguous.
        flat = " ".join(proc.stdout.split())
        for phrase in ("OpenID4VP", "keygen", "serve", "THESE KEYS ARE FOR TESTING"):
            self.assertIn(phrase, flat, "the help does not say %r" % phrase)

    def test_a_verifier_built_from_the_keys_completes_an_exchange(self):
        """The whole point: what keygen produces has to actually work."""
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-e2e-"))
        keygen(tmp, "verifier.test")
        wallet = Wallet()
        verifier = verifier_from(tmp, "verifier.test", 9443, [wallet.issuer_jwk])
        _, jar = verifier.new_request()
        status, body, verdict = verifier.handle_direct_post(wallet.respond(jar))
        self.assertEqual(status, 200, body)
        self.assertEqual(verdict.claims["given_name"], "Jean")

    def test_an_unconfigured_verifier_refuses_and_says_so_on_stderr(self):
        """Serving with no trusted issuer refuses everything. That is correct and is a trap,
        so the command warns rather than letting it read as a verifier that works."""
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-warn-"))
        keygen(tmp, "verifier.test")
        wallet = Wallet()
        verifier = verifier_from(tmp, "verifier.test", 9443)
        _, jar = verifier.new_request()
        status, body, verdict = verifier.handle_direct_post(wallet.respond(jar))
        self.assertEqual(status, 400)
        self.assertEqual(body, verifier.REFUSAL_BODY, "the cause is on the wire")
        self.assertEqual(verdict.code, "issuer_key", "the operator was not told either")



class ClaimFlagTests(unittest.TestCase):
    """`--claim`: what an operator types, and the DCQL claim it becomes."""

    def test_the_forms(self):
        for text, claim in (
                ("given_name", {"path": ["given_name"]}),
                ("age_equal_or_over.18", {"path": ["age_equal_or_over", "18"]}),
                ("age_equal_or_over.18=true", {"path": ["age_equal_or_over", "18"], "values": [True]}),
                ("nationality=DE", {"path": ["nationality"], "values": ["DE"]}),
                ('["address","locality"]', {"path": ["address", "locality"]}),
                ('["a.b"]="x"', {"path": ["a.b"], "values": ["x"]}),
                ("birth_year=1990", {"path": ["birth_year"], "values": [1990]})):
            with self.subTest(text=text):
                self.assertEqual(parse_claim(text), claim)

    def test_what_it_cannot_ask_for_is_refused(self):
        for text in ("a..b", ".a", '["a",1]', '["a"', '["a"]x', "[nope]", "a=null", "a=[1]"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_claim(text)


class KeygenHeldOutTests(unittest.TestCase):
    """A held-out round on 2026-09-24: of twelve mutations of cli.py, ten survived every test
    in the package. These are the certificate half. Each property is one a counterparty
    checks and this command had asserted nothing about."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-cli-"))
        keygen(self.tmp, "verifier.test")
        self.leaf = x509.load_pem_x509_certificate((self.tmp / FILES["client_cert"]).read_bytes())
        self.anchor = x509.load_pem_x509_certificate((self.tmp / FILES["anchor"]).read_bytes())

    def test_the_anchor_may_sign_certificates_and_nothing_below_the_leaf(self):
        """A CA without keyCertSign cannot validate the leaf it issued, under RFC 5280; and
        path_length 0 is what stops the leaf's issuer from minting intermediates."""
        ku = self.anchor.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.key_cert_sign)
        self.assertEqual(self.anchor.extensions.get_extension_for_class(
            x509.BasicConstraints).value.path_length, 0)

    def test_the_leaf_key_usage_is_critical(self):
        """Critical means a relying party that does not understand it must refuse, which is
        what makes digitalSignature-only a restriction rather than a hint."""
        self.assertTrue(self.leaf.extensions.get_extension_for_class(x509.KeyUsage).critical)

    def test_the_leaf_names_the_host(self):
        san = self.leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), ["verifier.test"])

    def test_the_leaf_is_valid_for_a_counterparty_whose_clock_runs_behind(self):
        import datetime
        skewed = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        self.assertLess(self.leaf.not_valid_before_utc, skewed)


class ServeCommandHeldOutTests(unittest.TestCase):
    """The other half. Nothing ran `_cmd_serve` past its missing-files check, because it
    blocks forever; here `serve` is replaced and the wait interrupted, so the command runs to
    its end and what it handed the listener can be read back."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-serve-"))
        keygen(self.tmp, "verifier.test")
        from cryptography.hazmat.primitives.asymmetric import ec
        from polaris_oid4vp.jwe import b64u_encode
        n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256",
                    "x": b64u_encode(n.x.to_bytes(32, "big")),
                    "y": b64u_encode(n.y.to_bytes(32, "big"))}

    def _serve(self, *extra):
        import contextlib
        import io
        from unittest import mock
        from polaris_oid4vp import cli
        seen = {}

        class _Httpd:
            def shutdown(self):
                seen["shutdown"] = True

            def server_close(self):
                pass

        def fake_serve(verifier, **kwargs):
            seen["verifier"], seen["kwargs"] = verifier, kwargs
            return _Httpd()

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "serve", fake_serve), \
                mock.patch.object(cli.time, "sleep", side_effect=KeyboardInterrupt), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(["serve", "--pki", str(self.tmp), *extra])
        return rc, seen, out.getvalue(), err.getvalue()

    def _jwks_file(self, content):
        import json
        path = self.tmp / "issuers.json"
        path.write_text(json.dumps(content))
        return str(path)

    def test_the_claims_and_types_asked_for_reach_the_verifier(self):
        rc, seen, _, _ = self._serve("--claim", "given_name", "--claim", "age_equal_or_over.18=true",
                                     "--vct", "urn:eudi:pid:1", "--vct", "eu.europa.ec.eudi.pid.1")
        self.assertEqual(rc, 0)
        self.assertEqual(seen["verifier"].claims, [(("given_name",), None),
                                                   (("age_equal_or_over", "18"), (True,))])
        self.assertEqual(seen["verifier"].vct_values, ["urn:eudi:pid:1", "eu.europa.ec.eudi.pid.1"])

    def test_without_them_it_asks_for_the_names(self):
        rc, seen, _, _ = self._serve()
        self.assertEqual(rc, 0)
        self.assertEqual(seen["verifier"].claims, [(("given_name",), None), (("family_name",), None)])
        self.assertEqual(seen["verifier"].vct_values, ["urn:eudi:pid:1"])

    def test_verifier_info_reaches_the_request_object(self):
        import json
        path = self.tmp / "verifier-info.json"
        info = [{"format": "registration_cert", "data": "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"}]
        path.write_text(json.dumps(info))
        rc, seen, _, _ = self._serve("--verifier-info", str(path))
        self.assertEqual(rc, 0)
        _, jar = seen["verifier"].new_request()
        payload = jar.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertEqual(claims["verifier_info"], info)

    def test_verifier_info_it_cannot_send_stops_it_starting(self):
        path = self.tmp / "verifier-info.json"
        for content in ("{", "[]", '[{"format": "registration_cert"}]'):
            with self.subTest(content=content):
                path.write_text(content)
                rc, seen, _, err = self._serve("--verifier-info", str(path))
                self.assertEqual(rc, 2)
                self.assertNotIn("verifier", seen)
                self.assertIn("--verifier-info", err)

    def test_a_claim_it_cannot_judge_stops_it_starting(self):
        rc, seen, _, err = self._serve("--claim", "age_equal_or_over..18")
        self.assertEqual(rc, 2)
        self.assertNotIn("verifier", seen)
        self.assertIn("age_equal_or_over..18", err)

    def test_it_runs_to_the_end_and_shuts_the_listener(self):
        rc, seen, out, _ = self._serve()
        self.assertEqual(rc, 0)
        self.assertTrue(seen.get("shutdown"))
        self.assertIn("x509_hash:", out)

    def test_serving_with_no_issuer_warns_on_stderr(self):
        """The test above this class with that name checks the verdict, not the warning."""
        _, _, _, err = self._serve()
        self.assertIn("no --issuer-jwks", err)
        _, _, _, err = self._serve("--issuer-jwks", self._jwks_file({"keys": [self.jwk]}))
        self.assertNotIn("no --issuer-jwks", err, "the warning fires when it is configured")

    def _anchor_file(self, n=1):
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        pems, now = [], datetime.datetime.now(datetime.timezone.utc)
        for i in range(n):
            key = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issuer CA %d" % i)])
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                    .sign(key, hashes.SHA256()))
            pems.append(cert.public_bytes(serialization.Encoding.PEM))
        path = self.tmp / ("anchors-%d.pem" % n)
        path.write_bytes(b"".join(pems))
        return str(path)

    def test_issuer_trust_anchors_reach_the_verifier(self):
        """HAIP issuers sign with x5c; without this flag `serve` could verify none of them."""
        _, seen, _, err = self._serve("--issuer-trust-anchor", self._anchor_file(2),
                                      "--issuer-trust-anchor", self._anchor_file(1))
        self.assertEqual(len(seen["verifier"].issuer_trust_anchors), 3)
        self.assertNotIn("no --issuer-jwks", err, "anchors alone are a configured issuer")

    def test_no_local_tls_serves_plain_http(self):
        """Behind a terminating proxy or tunnel the listener is HTTP; the proxy provides HTTPS."""
        _, seen, out, _ = self._serve("--no-local-tls")
        self.assertIsNone(seen["kwargs"]["certfile"], "--no-local-tls must not load a listener cert")
        self.assertIsNone(seen["kwargs"]["keyfile"])
        self.assertIn("plain HTTP", out)
        _, seen2, _, _ = self._serve()
        self.assertIsNotNone(seen2["kwargs"]["certfile"], "by default the listener still serves TLS")

    def test_an_unreadable_trust_anchor_file_is_refused(self):
        bad = self.tmp / "not-a-cert.pem"
        bad.write_text("hello")
        rc, seen, _, err = self._serve("--issuer-trust-anchor", str(bad))
        self.assertEqual(rc, 2)
        self.assertNotIn("verifier", seen, "no verifier may start on an anchor it could not read")
        self.assertIn("not a readable PEM", err)

    def test_a_jwks_document_is_unwrapped_to_its_keys(self):
        _, seen, _, _ = self._serve("--issuer-jwks", self._jwks_file({"keys": [self.jwk]}))
        self.assertEqual(seen["verifier"].issuer_jwks, [self.jwk])

    def test_a_single_jwk_is_trusted_on_its_own(self):
        _, seen, _, _ = self._serve("--issuer-jwks", self._jwks_file(self.jwk))
        self.assertEqual(seen["verifier"].issuer_jwks, [self.jwk])

    def test_an_issuer_jwks_file_it_cannot_use_is_refused_before_the_listener(self):
        """2026-10-01: a file that did not parse was a traceback; a `keys` that is not a list
        was read a character at a time; and a file none of whose keys can verify started a
        verifier that refused every credential and said nothing."""
        bad = self.tmp / "broken.json"
        bad.write_text("{not json")
        enc = dict(self.jwk, use="enc", alg="ECDH-ES")
        for arg, said in ((str(bad), "not a readable JSON file"),
                          (str(self.tmp / "absent.json"), "not a readable JSON file"),
                          ({"keys": "abc"}, "not a JWK Set"),
                          ([1, 2], "not a JWK Set"),
                          ({"keys": [enc]}, "none of the 1 keys"),
                          ({"keys": []}, "none of the 0 keys"),
                          ({"kty": "RSA", "n": "AQAB", "e": "AQAB"}, "none of the 1 keys")):
            with self.subTest(said=said, arg=str(arg)[-24:]):
                path = arg if isinstance(arg, str) else self._jwks_file(arg)
                rc, seen, _, err = self._serve("--issuer-jwks", path)
                self.assertEqual(rc, 2)
                self.assertNotIn("verifier", seen, "no listener may start on keys it cannot use")
                self.assertIn(said, err)
        rc, seen, _, err = self._serve("--issuer-jwks", self._jwks_file({"keys": [enc]}),
                                       "--issuer-trust-anchor", self._anchor_file(1))
        self.assertEqual(rc, 0, "x5c issuers can still be verified, so it starts and says what it cannot do")
        self.assertIn("only issuers whose x5c chains", err)
        rc, _, _, err = self._serve("--issuer-jwks", self._jwks_file({"keys": [enc, self.jwk]}))
        self.assertEqual(rc, 0)
        self.assertNotIn("none of the", err)

    def test_a_list_of_jwks_is_trusted_as_given(self):
        _, seen, _, _ = self._serve("--issuer-jwks", self._jwks_file([self.jwk]))
        self.assertEqual(seen["verifier"].issuer_jwks, [self.jwk])

    def test_any_one_missing_file_is_refused_and_named(self):
        import contextlib
        import io
        import shutil
        for name in FILES.values():
            with self.subTest(missing=name):
                partial = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-part-"))
                for other in FILES.values():
                    if other != name:
                        shutil.copy(self.tmp / other, partial / other)
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(main(["serve", "--pki", str(partial)]), 2)
                self.assertIn(name, err.getvalue())

    def test_the_operator_line_says_what_the_verdict_was(self):
        import contextlib
        import io
        from types import SimpleNamespace
        _, seen, _, _ = self._serve()
        on_verdict = seen["kwargs"]["on_verdict"]
        cases = [
            (SimpleNamespace(authentic=True, claims={"given_name": "Jean"}),
             "authentic, claims ['given_name']"),
            (SimpleNamespace(authentic=False, code="nonce", reason="stale"),
             "refused: nonce: stale"),
            (None, "refused"),
        ]
        for verdict, expected in cases:
            with self.subTest(expected=expected):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    on_verdict(200 if verdict and verdict.authentic else 400, b"", verdict)
                self.assertIn(expected, out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
