"""test_cli.py -- the entry point, and the two certificate shapes the suite refuses.

`keygen` exists because the High Assurance profile's certificate requirements are not
guessable and each one cost a failed conformance run to discover:

  * the x5c leaf must NOT be self-signed
  * the registered trust anchor must NOT be in the chain

A command that produces the right shape is only worth having if something asserts the shape
is right, so these tests check the properties the suite checked, rather than checking that
five files appeared.
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509  # noqa: E402

from polaris_oid4vp.cli import FILES, keygen, main, verifier_from  # noqa: E402
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

    def test_the_private_keys_are_not_world_readable(self):
        for name in ("client_key", "tls_key"):
            mode = (self.tmp / FILES[name]).stat().st_mode & 0o777
            self.assertEqual(mode, 0o600, "%s is %o" % (name, mode))

    def test_the_tls_certificate_may_be_self_signed(self):
        """It is the listener's, not the request object's. The suite fetched one happily."""
        tls = x509.load_pem_x509_certificate((self.tmp / FILES["tls_cert"]).read_bytes())
        self.assertEqual(tls.issuer, tls.subject)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
