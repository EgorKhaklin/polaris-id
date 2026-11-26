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
import io
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509  # noqa: E402

from polaris_oid4vp.cli import DEFAULT_HOST, FILES, keygen, main, parse_claim, verifier_from  # noqa: E402
from test_verifier import MdocWallet, TYP_AS_FORMAT, Wallet, verifier_info_vectors  # noqa: E402
import test_mdoc as md  # noqa: E402


class KeygenTests(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-cli-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
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

    _KEYS = ("client_key", "tls_key")
    _PUBLIC = ("anchor", "client_cert", "tls_cert")

    def test_each_private_key_is_private_from_its_first_byte(self):
        """Not written and then narrowed (2026-11-18): with no umask, and no chmod or fchmod left
        to change it, the mode each file is created with is the mode it has."""
        from unittest import mock
        out = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-keymode-"))
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        old = os.umask(0)
        try:
            with mock.patch.object(pathlib.Path, "chmod", lambda self, mode, **kw: None), \
                    mock.patch.object(os, "fchmod", lambda fd, mode: None):
                keygen(out, "verifier.test")
        finally:
            os.umask(old)
        for names, want in ((self._KEYS, 0o600), (self._PUBLIC, 0o644)):
            for name in names:
                mode = (out / FILES[name]).stat().st_mode & 0o777
                self.assertEqual(mode, want, "%s was created %o" % (name, mode))

    def test_each_file_has_its_mode_whatever_the_umask(self):
        """A umask that takes more than 022 does not make the certificates private, nor one
        that takes nothing the keys readable: each file ends with exactly its mode."""
        for umask in (0o077, 0o000):
            out = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-umask-"))
            self.addCleanup(shutil.rmtree, out, ignore_errors=True)
            old = os.umask(umask)
            try:
                keygen(out, "verifier.test")
            finally:
                os.umask(old)
            for names, want in ((self._KEYS, 0o600), (self._PUBLIC, 0o644)):
                for name in names:
                    mode = (out / FILES[name]).stat().st_mode & 0o777
                    self.assertEqual(mode, want, "umask %03o: %s is %o" % (umask, name, mode))

    def test_a_second_keygen_replaces_each_key_and_follows_no_link_left_at_its_path(self):
        """A re-run into the same directory still makes new keys, and a link at a file's path,
        a key's or a certificate's, is replaced by the file, never written through to what it
        names."""
        out = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-rekey-"))
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
        keygen(out, "verifier.test")
        first = {name: (out / FILES[name]).read_bytes() for name in self._KEYS + self._PUBLIC}
        targets = {}
        for name in ("tls_key", "tls_cert"):
            target = out / ("elsewhere-" + name)
            target.write_bytes(b"not a file of keygen's\n")
            (out / FILES[name]).unlink()
            (out / FILES[name]).symlink_to(target)
            targets[name] = target
        keygen(out, "verifier.test")
        for name, target in targets.items():
            self.assertEqual(target.read_bytes(), b"not a file of keygen's\n",
                             "keygen wrote through the link at %s" % name)
        for names, want in ((self._KEYS, 0o600), (self._PUBLIC, 0o644)):
            for name in names:
                path = out / FILES[name]
                self.assertFalse(path.is_symlink(), "%s is still a link" % name)
                self.assertNotEqual(path.read_bytes(), first[name], "%s was not replaced" % name)
                self.assertEqual(path.stat().st_mode & 0o777, want, name)

    def test_the_tls_certificate_may_be_self_signed(self):
        """It is the listener's, not the request object's. The suite fetched one happily."""
        tls = x509.load_pem_x509_certificate((self.tmp / FILES["tls_cert"]).read_bytes())
        self.assertEqual(tls.issuer, tls.subject)

    def test_the_ca_and_the_leaf_carry_the_key_identifiers_rfc_5280_asks_for(self):
        """Multipaz's trust manager finds a CA by key identifier and skipped one without
        (lab/interop/multipaz, 2026-10-04)."""
        ca = x509.load_pem_x509_certificate((self.tmp / FILES["anchor"]).read_bytes())
        leaf = x509.load_pem_x509_certificate((self.tmp / FILES["client_cert"]).read_bytes())
        ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        self.assertEqual(aki.key_identifier, ski.digest)
        self.assertEqual(ski, x509.SubjectKeyIdentifier.from_public_key(ca.public_key()))
        leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)

    def test_the_tls_certificate_is_marked_for_server_authentication(self):
        """Apple's TLS policy refuses a server certificate without serverAuth, even an
        explicitly trusted one (the EU iOS OpenID4VP library's walk, 2026-10-04)."""
        tls = x509.load_pem_x509_certificate((self.tmp / FILES["tls_cert"]).read_bytes())
        eku = tls.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, list(eku))

    def test_generating_twice_does_not_reuse_a_key(self):
        second = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-cli-"))
        self.addCleanup(shutil.rmtree, second, ignore_errors=True)
        keygen(second, "verifier.test")
        a = verifier_from(self.tmp, "verifier.test", 9443).client_id
        b = verifier_from(second, "verifier.test", 9443).client_id
        self.assertNotEqual(a, b)


class ServeCommandTests(unittest.TestCase):

    def test_serve_refuses_a_directory_with_no_keys_in_it(self):
        empty = tempfile.mkdtemp(prefix="polaris-oid4vp-empty-")
        self.addCleanup(shutil.rmtree, empty, ignore_errors=True)
        self.assertEqual(main(["serve", "--pki", empty]), 2)

    def test_the_command_is_reachable_as_a_module(self):
        """`python -m polaris_oid4vp.cli` is what the console script wraps."""
        out = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-m-"))
        self.addCleanup(shutil.rmtree, out, ignore_errors=True)
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
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
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
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        keygen(tmp, "verifier.test")
        wallet = Wallet()
        verifier = verifier_from(tmp, "verifier.test", 9443)
        _, jar = verifier.new_request()
        status, body, verdict = verifier.handle_direct_post(wallet.respond(jar))
        self.assertEqual(status, 400)
        self.assertEqual(body, verifier.REFUSAL_BODY, "the cause is on the wire")
        self.assertEqual(verdict.code, "issuer_key", "the operator was not told either")

    def test_what_serve_prints_reaches_a_pipe_while_it_serves(self):
        """The launch links and each verdict line are read while the verifier runs, through a
        pipe, a file or a container log (`docker run` without -t). None is a terminal, so Python
        block-buffers stdout, and the lines waited there until the process exited: a walk on
        2026-10-15 saw nothing after 8 s, and the same run under `python -u` saw the links. The
        in-process tests above read stdout through a StringIO and could not see this."""
        import queue
        import socket
        import threading
        import time
        import urllib.error
        import urllib.request
        from polaris_oid4vp.serve import RESPONSE_PATH
        pki = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-pipe-"))
        self.addCleanup(shutil.rmtree, pki, ignore_errors=True)
        keygen(pki, "verifier.test")
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
        proc = subprocess.Popen([sys.executable, "-m", "polaris_oid4vp.cli", "serve", "--pki", str(pki),
                                 "--host", "verifier.test", "--bind", "127.0.0.1", "--port", str(port),
                                 "--no-local-tls", "--once"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env,
                                cwd=os.path.dirname(os.path.abspath(__file__)))
        lines = queue.Queue()
        threading.Thread(target=lambda: [lines.put(line) for line in proc.stdout], daemon=True).start()

        def wait_for(pred, what, seconds=30):
            seen, deadline = [], time.monotonic() + seconds
            while time.monotonic() < deadline:
                try:
                    line = lines.get(timeout=0.5)
                except queue.Empty:
                    self.assertIsNone(proc.poll(), "serve exited early: %r" % seen)
                    continue
                seen.append(line)
                if pred(seen):
                    return seen
            self.fail("%s did not reach the pipe within %d s while serve ran; read: %r"
                      % (what, seconds, seen))

        try:
            wait_for(lambda seen: sum("://?" in line for line in seen) == 3, "the three launch links")
            req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, RESPONSE_PATH),
                                         data=b"response=not-a-jwt", method="POST")
            try:
                urllib.request.urlopen(req, timeout=10)
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 400)
            wait_for(lambda seen: seen[-1].startswith("  <- 400 refused"), "the verdict line")
        finally:
            proc.terminate()
            proc.wait(timeout=10)
            proc.stdout.close()



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
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
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

    def test_an_ipv6_host_is_refused_before_any_file_is_written(self):
        """keygen writes --host into both certificates for the origin serve prints, and an IPv6
        address makes none a wallet reaches; it exits 2, writes nothing and says what to give."""
        import contextlib
        for host in ("::1", "[::1]", "2001:db8::1"):
            with self.subTest(host=host):
                pki = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-ipv6-")) / "pki"
                self.addCleanup(shutil.rmtree, pki.parent, ignore_errors=True)
                err = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    self.assertEqual(main(["keygen", "--out", str(pki), "--host", host]), 2)
                self.assertFalse(pki.exists(), "keygen may write nothing for an IPv6 --host")
                self.assertIn("--host %s is an IPv6 address; use a name or an IPv4 address such as 127.0.0.1"
                              % host, err.getvalue())
                self.assertNotIn("--public-base-url", err.getvalue(), "keygen takes no --public-base-url")

    def test_with_no_host_it_names_127_0_0_1_as_an_address_and_a_name_checking_client_connects(self):
        """2026-11-19. With no --host, keygen names 127.0.0.1, the address serve listens on and
        prints by default. Python's ssl module matches an address it connects to against
        iPAddress entries only, so both certificates name the address as one, and a client
        that checks the name completes the handshake with the listener's certificate; the same
        address written as a dNSName fails it with "IP address mismatch". A name stays a
        dNSName: test_the_leaf_names_the_host."""
        import contextlib
        import ipaddress
        import socket
        import ssl
        import threading
        pki = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-address-"))
        self.addCleanup(shutil.rmtree, pki, ignore_errors=True)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["keygen", "--out", str(pki)]), 0)
        for name in ("client_cert", "tls_cert"):
            cert = x509.load_pem_x509_certificate((pki / FILES[name]).read_bytes())
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertEqual(san.get_values_for_type(x509.IPAddress),
                             [ipaddress.ip_address("127.0.0.1")], name)
            self.assertEqual(san.get_values_for_type(x509.DNSName), [], name)

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2   # serve's floor (RFC 8996), not the library's default
        server_ctx.load_cert_chain(str(pki / FILES["tls_cert"]), str(pki / FILES["tls_key"]))
        listener = socket.socket()
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)

        def answer_one():
            try:
                conn, _ = listener.accept()
                with server_ctx.wrap_socket(conn, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass

        thread = threading.Thread(target=answer_one, daemon=True)
        thread.start()
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.minimum_version = ssl.TLSVersion.TLSv1_2   # serve's floor (RFC 8996), not the library's default
        client_ctx.load_verify_locations(str(pki / FILES["tls_cert"]))
        self.assertTrue(client_ctx.check_hostname)
        with socket.create_connection(listener.getsockname(), timeout=10) as raw:
            with client_ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                self.assertTrue(tls.version().startswith("TLSv"), tls.version())
        thread.join(10)

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
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        keygen(self.tmp, DEFAULT_HOST)
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

    def test_the_listener_binds_this_machine_only_by_default(self):
        """The README says the listener binds --bind, 127.0.0.1 by default, this machine only, with or
        without TLS. Every interface is the caller's choice."""
        for extra in ((), ("--no-local-tls",)):
            with self.subTest(extra=extra):
                _, seen, _, _ = self._serve(*extra)
                self.assertEqual(seen["kwargs"]["host"], "127.0.0.1")
        _, seen, _, _ = self._serve("--bind", "0.0.0.0")
        self.assertEqual(seen["kwargs"]["host"], "0.0.0.0")

    def test_with_no_host_it_prints_and_signs_the_address_it_listens_on(self):
        """2026-11-19. With no --host and no --public-base-url, the origin serve prints and
        puts in the request it signs is https://127.0.0.1:PORT, the address --bind listens on
        by default, with or without TLS. It was https://localhost:PORT, a name a client may
        resolve to ::1 first, where this listener does not listen."""
        import json
        from polaris_oid4vp.jwe import b64u_decode
        from polaris_oid4vp.serve import REQUEST_PATH, RESPONSE_PATH
        origin = "https://127.0.0.1:9443"
        for extra in ((), ("--no-local-tls",)):
            with self.subTest(extra=extra):
                rc, seen, out, _ = self._serve("--port", "9443", *extra)
                self.assertEqual(rc, 0)
                self.assertIn("polaris-oid4vp serving on %s (listening on 127.0.0.1:9443)" % origin,
                              out)
                self.assertNotIn("localhost", out)
                verifier = seen["verifier"]
                session, jar = verifier.new_request()
                signed = json.loads(b64u_decode(jar.split(".")[1]))
                self.assertEqual(signed["response_uri"], origin + RESPONSE_PATH)
                self.assertEqual(verifier.authorization_request_params(session)["request_uri"],
                                 "%s%s?state=%s" % (origin, REQUEST_PATH, session.state))

    def test_under_tls_a_certificate_that_does_not_name_its_host_is_refused_before_the_listener(self):
        """2026-11-19. A pki an earlier keygen made with no --host names localhost; serve, which
        now names 127.0.0.1, would print an origin its own certificate does not name, and the
        first sign would be a wallet refusing the TLS name. Under TLS it refuses to start and
        says how to make one that does; given the host the certificate names, it starts."""
        keygen(self.tmp, "localhost")
        rc, seen, _, err = self._serve("--port", "9443")
        self.assertEqual(rc, 2)
        self.assertNotIn("kwargs", seen, "no listener may start on a certificate that names another host")
        self.assertIn("names localhost in its subjectAltName, not 127.0.0.1, the host of "
                      "https://127.0.0.1:9443", err)
        self.assertIn("polaris-oid4vp keygen --out %s --host 127.0.0.1" % self.tmp, err)
        for extra in (("--host", "localhost"), ("--host", "LOCALHOST"), ("--no-local-tls",)):
            with self.subTest(extra=extra):
                rc, seen, _, err = self._serve("--port", "9443", *extra)
                self.assertEqual(rc, 0, err)
                self.assertIn("kwargs", seen)

    def test_under_tls_behind_a_public_base_url_the_listener_certificate_is_not_held(self):
        """With --public-base-url a wallet reaches the verifier through a proxy or a tunnel and
        meets that certificate, not tls.pem, and a proxy that verifies its upstream checks the
        address it dials. 1.3.0 started on this configuration, and serve still does, whatever
        host tls.pem names."""
        for host in (None, "localhost"):
            with self.subTest(tls_pem_names=host or "127.0.0.1"):
                if host:
                    keygen(self.tmp, host)
                rc, seen, _, err = self._serve("--public-base-url", "https://verifier.example")
                self.assertEqual(rc, 0, err)
                self.assertIn("kwargs", seen)

    def test_an_ipv6_host_is_refused_where_it_would_make_the_printed_origin(self):
        """The listener is IPv4 (binding ::1 fails), so nothing serve starts answers on an IPv6
        address, and a wallet reaches the origin serve would print from one only through a front.
        Without --public-base-url serve refuses an IPv6 --host before any listener, under TLS or
        not, and names both ways: a name or an IPv4 address, or a front's origin as
        --public-base-url. With --public-base-url, --host makes nothing serve prints or signs, and
        serve starts, as 1.3.0 did."""
        for host in ("::1", "[::1]", "fe80::1"):
            for extra in ((), ("--no-local-tls",)):
                with self.subTest(host=host, extra=extra):
                    rc, seen, _, err = self._serve("--host", host, *extra)
                    self.assertEqual(rc, 2)
                    self.assertNotIn("kwargs", seen, "no listener may start on an IPv6 --host")
                    self.assertIn("--host %s is an IPv6 address; use a name or an IPv4 address such as "
                                  "127.0.0.1; or, behind a proxy or tunnel, give --public-base-url" % host, err)
        rc, seen, _, err = self._serve("--host", "::1", "--public-base-url", "https://verifier.example")
        self.assertEqual(rc, 0, err)
        self.assertIn("kwargs", seen)

    @staticmethod
    def _self_signed(common_name, *names):
        import datetime
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(hours=1))
                   .not_valid_after(now + datetime.timedelta(days=1)))
        if names:
            builder = builder.add_extension(x509.SubjectAlternativeName(list(names)), critical=False)
        return builder.sign(key, hashes.SHA256()), key

    @staticmethod
    def _name_rows():
        """(the subject's common name, the subjectAltName entries, the host, whether it is named)."""
        import ipaddress
        ip = x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
        dns = x509.DNSName
        return (
            ("127.0.0.1", (ip,), "127.0.0.1", True),
            ("127.0.0.1", (dns("127.0.0.1"),), "127.0.0.1", False),
            ("127.0.0.1", (ip,), "localhost", False),
            ("127.0.0.1", (), "127.0.0.1", False),
            ("127.0.0.1", (dns("localhost"),), "LocalHost", True),
            ("127.0.0.1", (dns("verifier.example."),), "verifier.example", False),
            ("127.0.0.1", (dns("verifier.example"),), "verifier.example.", False),
            ("127.0.0.1", (dns("*.verifier.example"),), "a.verifier.example", True),
            ("127.0.0.1", (dns("*.Verifier.Example"),), "A.verifier.example", True),
            ("127.0.0.1", (dns("*.verifier.example"),), "verifier.example", False),
            ("127.0.0.1", (dns("*.verifier.example"),), "a.b.verifier.example", False),
            ("127.0.0.1", (dns("*.example"),), "verifier.example", False),
            ("127.0.0.1", (dns("f*.example"),), "foo.example", False),
            ("127.0.0.1", (dns("xn--bcher-kva.example"),), "b\u00fccher.example", True),
            ("127.0.0.1", (dns("*.xn--bcher-kva.example"),), "a.b\u00fccher.example", True),
            ("127.0.0.1", (dns("other.example"), ip), "127.0.0.1", True),
            ("127.0.0.1", (x509.IPAddress(ipaddress.ip_address("::1")),), "::1", True),
            ("verifier.example", (ip,), "verifier.example", False),
            ("verifier.example", (), "verifier.example", False))

    def test_the_name_check_reads_the_subject_alt_name_as_the_table_says(self):
        """An address only against iPAddress entries; a name against dNSName entries without
        case, its final dot kept; a wildcard for exactly one leftmost label of a name with two
        more; the subject's common name never. The next test holds the table to Python's ssl."""
        from polaris_oid4vp.cli import certificate_names
        for common_name, names, host, named in self._name_rows():
            with self.subTest(common_name=common_name, names=[str(n.value) for n in names], host=host):
                certificate, _ = self._self_signed(common_name, *names)
                self.assertIs(certificate_names(certificate, host), named)

    @unittest.skipUnless(getattr(ssl, "HAS_NEVER_CHECK_COMMON_NAME", False),
                         "this ssl cannot turn the common-name fallback off")
    def test_each_row_of_the_name_table_is_what_pythons_ssl_decides_in_a_handshake(self):
        """Each row, as a TLS handshake through memory BIOs: Python's ssl as the client, with
        check_hostname on, the common-name fallback off and the certificate as its only trust
        anchor, against a server that presents it. A refusal counts only as a name mismatch
        (verify codes 62 and 64), so a certificate the client does not trust cannot pass for one."""
        from cryptography.hazmat.primitives import serialization
        for common_name, names, host, named in self._name_rows():
            with self.subTest(common_name=common_name, names=[str(n.value) for n in names], host=host):
                certificate, key = self._self_signed(common_name, *names)
                pem = certificate.public_bytes(serialization.Encoding.PEM)
                key_pem = self.tmp / "name-row.key"
                cert_pem = self.tmp / "name-row.pem"
                key_pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                      serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))
                cert_pem.write_bytes(pem)
                server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server.minimum_version = ssl.TLSVersion.TLSv1_2   # serve's floor (RFC 8996)
                server.load_cert_chain(str(cert_pem), str(key_pem))
                client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client.minimum_version = ssl.TLSVersion.TLSv1_2   # serve's floor (RFC 8996)
                client.hostname_checks_common_name = False
                client.load_verify_locations(cadata=pem.decode("ascii"))
                self.assertTrue(client.check_hostname)
                to_server, to_client = ssl.MemoryBIO(), ssl.MemoryBIO()
                ours = client.wrap_bio(to_client, to_server, server_hostname=host)
                theirs = server.wrap_bio(to_server, to_client, server_side=True)
                accepted = None
                for _ in range(8):
                    try:
                        ours.do_handshake()
                        accepted = True
                        break
                    except ssl.SSLWantReadError:
                        pass
                    except ssl.SSLCertVerificationError as refusal:
                        self.assertIn(refusal.verify_code, (62, 64), refusal.verify_message)
                        accepted = False
                        break
                    try:
                        theirs.do_handshake()
                    except ssl.SSLWantReadError:
                        pass
                self.assertIs(accepted, named)

    def test_an_empty_bind_address_is_refused_before_the_listener(self):
        """An empty --bind would listen on every interface; every interface is named, never
        reached by leaving the address out."""
        rc, seen, _, err = self._serve("--bind", "")
        self.assertEqual(rc, 2)
        self.assertNotIn("kwargs", seen, "no listener may start on an empty address")
        self.assertIn("--bind", err)
        self.assertIn("0.0.0.0", err)

    def test_cors_origins_reach_the_listener_as_a_browser_writes_them(self):
        """Repeatable, each written as a browser writes it, and named on the startup line. Twin:
        test_without_cors_origin_the_listener_gets_none_and_no_line_is_printed."""
        rc, seen, out, _ = self._serve("--cors-origin", "HTTPS://Wallet.Example:443",
                                       "--cors-origin", "http://127.0.0.1:8080")
        self.assertEqual(rc, 0)
        self.assertEqual(seen["kwargs"]["cors_origins"],
                         ("https://wallet.example", "http://127.0.0.1:8080"))
        self.assertIn("  cors origins  https://wallet.example http://127.0.0.1:8080",
                      out.splitlines())

    def test_without_cors_origin_the_listener_gets_none_and_no_line_is_printed(self):
        """Twin: test_cors_origins_reach_the_listener_as_a_browser_writes_them."""
        rc, seen, out, _ = self._serve()
        self.assertEqual(rc, 0)
        self.assertIsNone(seen["kwargs"]["cors_origins"])
        self.assertNotIn("cors", out)

    def test_an_origin_that_is_not_one_stops_it_starting(self):
        """Each string row of test_serve's startup table, and `*` beside an origin: exit 2 naming
        the value, and nothing listens. Twin:
        test_cors_origins_reach_the_listener_as_a_browser_writes_them."""
        from test_serve import CORS_REFUSED_AT_STARTUP
        rows = [(value, reason) for value, reason in CORS_REFUSED_AT_STARTUP
                if isinstance(value, str)]
        rows.append(("*", "* beside an origin"))
        for value, reason in rows:
            with self.subTest(reason=reason):
                extra = ("--cors-origin", "https://wallet.example") if value == "*" else ()
                rc, seen, _, err = self._serve("--cors-origin", value, *extra)
                self.assertEqual(rc, 2)
                self.assertNotIn("kwargs", seen, "nothing may listen on an origin refused")
                self.assertIn("--cors-origin", err)
                self.assertIn("stands alone" if value == "*" else repr(value), err)

    def test_the_origin_is_checked_before_the_pki_is_read(self):
        """A refused origin stops it before a missing PKI does. Twin: an origin that is one, with
        the same missing PKI, stops on the PKI."""
        import contextlib
        import io
        absent = str(self.tmp / "absent")
        for origin, says in (("ftp://wallet.example", "--cors-origin"),
                             ("https://wallet.example", "is missing")):
            with self.subTest(origin=origin):
                err = io.StringIO()
                with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                    rc = main(["serve", "--pki", absent, "--cors-origin", origin])
                self.assertEqual(rc, 2)
                self.assertIn(says, err.getvalue())

    def test_the_readme_the_help_and_the_startup_line_say_what_the_listener_sends(self):
        """The mirror. The README's browser-wallet paragraph (its paths, each path's methods, the
        request headers allowed and the response headers named), the paths --cors-origin's help
        names, and the origins the startup line names, each held to what a listener started from
        the same command sends. Its twins are the docs themselves: change a constant, or a doc,
        and this goes red."""
        import contextlib
        import io
        import re
        from unittest import mock
        from polaris_oid4vp.serve import serve
        from test_serve import _cors, _exchange, _parse
        readme = pathlib.Path(__file__).with_name("README.md").read_text()
        paragraph = " ".join(re.search(r"^- Browser wallets: .*?(?=^- |^#)", readme,
                                       re.M | re.S).group(0).split())
        readme_methods = dict(re.findall(r"`(/[^`\s]+)` \(`([^`]+)`\)", paragraph))
        readme_allowed = re.search(r"`([^`]+)` as the request headers allowed", paragraph).group(1)
        readme_named = set(re.findall(r"`(Access-Control-[A-Za-z-]+|Vary)(?:: Origin)?`", paragraph))
        with mock.patch.dict(os.environ, {"COLUMNS": "1000"}), \
                contextlib.redirect_stdout(io.StringIO()) as shown, self.assertRaises(SystemExit):
            main(["serve", "--help"])
        help_text = re.search(r"^  --cors-origin ORIGIN(.*?)(?=\n  -)", shown.getvalue(),
                              re.M | re.S).group(1)
        help_paths = set(re.findall(r"(?<![\w/:])/[a-z][a-z.]*", help_text))
        _, seen, printed, _ = self._serve("--cors-origin", "https://wallet.example",
                                          "--cors-origin", "http://127.0.0.1:8080")
        startup = [line for line in printed.splitlines() if line.startswith("  cors origins  ")]
        self.assertEqual(len(startup), 1, "one startup line names the origins")
        named = startup[0].split()[2:]
        httpd = serve(seen["verifier"], host="127.0.0.1", port=0,
                      cors_origins=seen["kwargs"]["cors_origins"])
        try:
            answered = {}
            for path in ("/request.jwt", "/response", "/done", "/nope"):
                status, headers, _ = _parse(_exchange(httpd, "OPTIONS", path, [
                    ("Origin", named[0]), ("Access-Control-Request-Method", "POST")]))
                if status == 204:
                    answered[path] = dict(headers)
            self.assertEqual({path: h["Access-Control-Allow-Methods"] for path, h in answered.items()},
                             readme_methods, "the README's paths and their methods")
            self.assertEqual({h["Access-Control-Allow-Headers"] for h in answered.values()},
                             {readme_allowed}, "the README's request headers allowed")
            self.assertEqual(help_paths, set(answered), "the paths --cors-origin's help names")
            state = seen["verifier"].new_request()[0].state
            _, headers, _ = _parse(_exchange(httpd, "GET", "/request.jwt?state=%s" % state,
                                             [("Origin", named[0])]))
            self.assertEqual({name for name, _ in _cors(headers)}, readme_named,
                             "the README's response headers")
            for origin in named:
                status, headers, _ = _parse(_exchange(httpd, "OPTIONS", "/response", [
                    ("Origin", origin), ("Access-Control-Request-Method", "POST")]))
                self.assertIn(("Access-Control-Allow-Origin", origin), headers,
                              "the startup line names %s" % origin)
        finally:
            httpd.shutdown()
            httpd.server_close()

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
                self.addCleanup(shutil.rmtree, partial, ignore_errors=True)
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

    def test_once_prints_its_request_as_three_launch_links(self):
        """`openid4vp://?`, `haip-vp://?` and `eu-eaap://?` (ETSI TS 119 472-2, which WE BUILD
        CS-02 v1.2 requires): each the same three parameters of the request --once starts,
        printed after them, so what the lab walks read from the log reads as it did."""
        import re
        import urllib.parse
        rc, seen, out, _ = self._serve("--once")
        self.assertEqual(rc, 0)
        verifier = seen["verifier"]
        (session,) = verifier._sessions.values()
        request_uri = "%s?state=%s" % (verifier.request_uri, session.state)
        lines = out.splitlines()
        at = lines.index("authorization request parameters:")
        links = [(n, line.strip()) for n, line in enumerate(lines) if "://?" in line]
        self.assertEqual([urllib.parse.urlsplit(link).scheme for _, link in links],
                         ["openid4vp", "haip-vp", "eu-eaap"])
        for n, link in links:
            with self.subTest(link=link.split("?")[0]):
                parts = urllib.parse.urlsplit(link)
                self.assertEqual((parts.netloc, parts.path, parts.fragment), ("", "", ""))
                self.assertEqual(urllib.parse.parse_qs(parts.query, strict_parsing=True),
                                 {"client_id": [verifier.client_id], "request_uri": [request_uri],
                                  "request_uri_method": ["post"]})
                self.assertEqual(parts.query, urllib.parse.urlencode(
                    [("client_id", verifier.client_id), ("request_uri", request_uri),
                     ("request_uri_method", "post")]))
                self.assertGreater(n, at + 3, "a link was printed before the parameters")
        self.assertIsNotNone(verifier.request_object(session.state),
                             "the links name no outstanding request")
        # What the walks read, the same with the links as without them.
        self.assertEqual([line.split()[0] for line in lines[at + 1:at + 4]],
                         ["client_id", "request_uri", "request_uri_method"])
        self.assertEqual(re.search(r"x509_hash:[A-Za-z0-9_-]+", out).group(0), verifier.client_id)
        self.assertEqual(re.findall(r"https://\S+request\.jwt\?state=[A-Za-z0-9_-]+", out)[-1],
                         request_uri)
        self.assertEqual(re.findall(r"state=[A-Za-z0-9_-]+", out)[-1], "state=" + session.state)
        self.assertEqual(self._serve()[2].count("://?"), 0, "without --once there is no request")

    def test_a_wallet_error_is_printed_as_one_and_never_as_authentic(self):
        """A wallet's error response is answered 200 (OpenID4VP 1.0 section 8.2), and the lab
        walks grep `<- 200 authentic` for an acceptance: the line says what it is, does not
        match, and carries the wallet's text only as printable ASCII, on one line."""
        import contextlib
        import io
        _, seen, _, _ = self._serve()
        verifier, on_verdict = seen["verifier"], seen["kwargs"]["on_verdict"]
        session, _ = verifier.new_request()
        status, body, verdict = verifier.handle_direct_post({
            "error": ["access_denied"], "state": [session.state],
            "error_description": ["\x1b[32mauthentic\n  <- 200 authentic, claims ['x']"]})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            on_verdict(status, body, verdict)
        line = out.getvalue()
        self.assertTrue(line.startswith("  <- 200 wallet error: access_denied for request %s, "
                                        % session.state), line)
        self.assertNotIn("<- 200 authentic", line)
        self.assertNotIn("\x1b", line)
        self.assertEqual(line.count("\n"), 1, line)

    def test_a_refusal_is_printed_as_one_and_never_as_authentic(self):
        """A refusal's reason can quote what the wallet sent, here its credential's type: the
        line says it is a refusal, does not read as an acceptance, and holds printable ASCII on
        one line."""
        import contextlib
        import io
        from test_verifier import Wallet
        wallet = Wallet()
        _, seen, _, _ = self._serve("--issuer-jwks", str(self._jwks_file([wallet.issuer_jwk])))
        verifier, on_verdict = seen["verifier"], seen["kwargs"]["on_verdict"]
        _, jar = verifier.new_request()
        status, body, verdict = verifier.handle_direct_post(
            wallet.respond(jar, vct="urn:x\n  <- 200 authentic, claims ['x'] \u00e9"))
        self.assertEqual((status, verdict.code), (400, "vct"), verdict.reason)
        self.assertIn("<- 200 authentic", verdict.reason)
        self.assertIn("\u00e9", verdict.reason)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            on_verdict(status, body, verdict)
        line = out.getvalue()
        self.assertTrue(line.startswith("  <- 400 refused: vct: "), line)
        self.assertNotIn("<- 200 authentic", line)
        self.assertEqual(line.count("\n"), 1, line)
        self.assertTrue(all(" " <= ch <= "~" for ch in line[:-1]), line)

    def test_whatever_a_refusal_or_wallet_error_carries_its_line_holds_printable_ascii_and_no_answer(self):
        from polaris_oid4vp.cli import _operator_line
        from polaris_oid4vp.sdjwt import Verdict
        text = "x\n  <- 200 authentic, claims ['x'] \x1b[0m \u00e9"
        for verdict in (Verdict(False, "vct", text), Verdict(False, text, "reason"),
                        Verdict(False, "wallet_error", text, wallet_error={"error": "x"})):
            with self.subTest(code=verdict.code):
                line = _operator_line(verdict)
                self.assertNotIn("<", line)
                self.assertTrue(all(" " <= ch <= "~" for ch in line), line)


class ServeResultFileTests(unittest.TestCase):
    """`serve --once --result FILE`: what became of the request --once started, as one JSON
    object in a file of its own, never on the stream the log goes to. Each case hands the hooks
    `serve` was given a real verifier's answers, so the file is held to what the verifier decided
    and to the `<-` line it printed."""

    def setUp(self):
        import json
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-result-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        keygen(self.tmp, DEFAULT_HOST)
        self.wallet = Wallet()
        self.jwks = self.tmp / "issuers.json"
        self.jwks.write_text(json.dumps([self.wallet.issuer_jwk]))
        self.path = self.tmp / "result.json"

    def _serve(self, *extra):
        return ServeCommandHeldOutTests._serve(self, *extra)

    def _started(self):
        rc, seen, out, err = self._serve("--issuer-jwks", str(self.jwks), "--once",
                                         "--result", str(self.path))
        self.assertEqual(rc, 0, err)
        (session,) = seen["verifier"]._sessions.values()
        return seen, session, out

    def _read(self):
        import json
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _answer(self, seen, form):
        """One response at the response URI, as serve's handler answers it."""
        import contextlib
        import io
        status, body, verdict = seen["verifier"].handle_direct_post(form)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            seen["kwargs"]["on_verdict"](status, body, verdict)
        return status, verdict, out.getvalue()

    def test_before_any_response_it_says_nothing_was_received(self):
        seen, session, out = self._started()
        self.assertEqual(self._read(), {"outcome": "nothing_received", "state": session.state,
                                        "request_object": {"served": 0, "refused": 0},
                                        "responses": 0})
        self.assertNotIn('"outcome"', out, "the result went to the log's stream")

    def test_a_refusal_names_the_check_and_the_reason_the_line_prints(self):
        seen, session, _ = self._started()
        jar = seen["verifier"].request_object(session.state)
        status, verdict, line = self._answer(seen, self.wallet.respond(jar, nonce="wrong"))
        doc = self._read()
        self.assertEqual((status, verdict.code), (400, "nonce"))
        self.assertEqual({k: doc[k] for k in ("outcome", "response", "check", "reason", "responses")},
                         {"outcome": "refused", "response": {"status_code": 400}, "check": "nonce",
                          "reason": verdict.reason, "responses": 1})
        self.assertTrue(doc["reason"])
        self.assertEqual(line, "  <- 400 refused: %s: %s\n" % (doc["check"], doc["reason"]))
        self.assertNotIn("claims", doc)

    def test_an_accepted_presentation_is_accepted_and_stays_so(self):
        seen, session, _ = self._started()
        seen["kwargs"]["on_request_object"](200)
        form = self.wallet.respond(seen["verifier"].request_object(session.state))
        status, verdict, line = self._answer(seen, form)
        self.assertTrue(verdict.authentic)
        doc = self._read()
        self.assertEqual(doc, {"outcome": "accepted", "response": {"status_code": 200},
                               "claims": sorted(verdict.claims), "state": session.state,
                               "request_object": {"served": 1, "refused": 0}, "responses": 1})
        self.assertIn("given_name", doc["claims"])
        self.assertTrue(line.startswith("  <- 200 authentic, claims "), line)
        # The redirect's response_code redeems the result once; it is not the file's to give.
        self.assertNotIn(verdict.response_code, self.path.read_text(encoding="utf-8"))
        # The same response again is refused: the request it answered is closed.
        status, _, _ = self._answer(seen, form)
        self.assertEqual(status, 400)
        self.assertEqual({k: v for k, v in self._read().items() if k != "responses"},
                         {k: v for k, v in doc.items() if k != "responses"})
        self.assertEqual(self._read()["responses"], 2)

    def test_a_response_after_the_request_expired_leaves_the_record_as_it_was(self):
        seen, session, _ = self._started()
        jar = seen["verifier"].request_object(session.state)
        form = self.wallet.respond(jar, nonce="wrong")
        self.assertEqual(self._answer(seen, form)[1].code, "nonce")
        # Still open: a stranger's response is the latest, and the record says so.
        status, verdict, _ = self._answer(seen, {"response": "not.a.compact.jwe.token"})
        self.assertEqual((status, verdict.code, self._read()["check"]),
                         (400, "invalid_request", "invalid_request"))
        self._answer(seen, form)
        doc = self._read()
        self.assertEqual(doc["check"], "nonce")
        session.created -= seen["verifier"].request_ttl_seconds + 1
        for stranger in ({"response": "not.a.compact.jwe.token"}, form):
            status, verdict, _ = self._answer(seen, stranger)
            self.assertEqual((status, verdict.code), (400, "invalid_request"))
        self.assertEqual({k: v for k, v in self._read().items() if k != "responses"},
                         {k: v for k, v in doc.items() if k != "responses"},
                         "a response after the request expired overwrote what became of it")
        self.assertEqual(self._read()["responses"], 5)

    def test_an_acceptance_is_recorded_though_the_lifetime_ends_before_the_record(self):
        import contextlib
        import io
        seen, session, _ = self._started()
        form = self.wallet.respond(seen["verifier"].request_object(session.state))
        status, body, verdict = seen["verifier"].handle_direct_post(form)
        self.assertTrue(verdict.authentic)
        session.created -= seen["verifier"].request_ttl_seconds + 1
        with contextlib.redirect_stdout(io.StringIO()):
            seen["kwargs"]["on_verdict"](status, body, verdict)
        self.assertEqual((self._read()["outcome"], self._read()["claims"]),
                         ("accepted", sorted(verdict.claims)))

    def test_a_wallet_error_is_neither_an_acceptance_nor_a_refusal(self):
        seen, session, _ = self._started()
        jar = seen["verifier"].request_object(session.state)
        status, verdict, _ = self._answer(seen, self.wallet.respond_error(jar))
        doc = self._read()
        self.assertEqual(status, 200)
        self.assertEqual({k: doc[k] for k in ("outcome", "response", "check", "reason")},
                         {"outcome": "wallet_error", "response": {"status_code": 200},
                          "check": "wallet_error", "reason": verdict.reason})
        self.assertNotIn("claims", doc)

    def test_a_verifier_that_raised_is_a_refusal_with_no_reason_to_give(self):
        import contextlib
        import io
        seen, _, _ = self._started()
        with contextlib.redirect_stdout(io.StringIO()):
            seen["kwargs"]["on_verdict"](400, {}, None)
        doc = self._read()
        self.assertEqual({k: doc[k] for k in ("outcome", "response", "check", "reason")},
                         {"outcome": "refused", "response": {"status_code": 400}, "check": None,
                          "reason": None})

    def test_each_answer_at_the_request_uri_is_counted_and_is_not_a_response(self):
        seen, _, _ = self._started()
        for status in (200, 404, 400, 200):
            seen["kwargs"]["on_request_object"](status)
        doc = self._read()
        self.assertEqual(doc["request_object"], {"served": 2, "refused": 2})
        self.assertEqual((doc["outcome"], doc["responses"]), ("nothing_received", 0))
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir() if "result" in p.name),
                         ["result.json"], "a temporary file was left beside it")

    def test_without_once_there_is_no_request_to_report_on(self):
        rc, seen, _, err = self._serve("--issuer-jwks", str(self.jwks), "--result", str(self.path))
        self.assertEqual(rc, 2)
        self.assertIn("add --once", err)
        self.assertNotIn("verifier", seen, "it listened")
        self.assertFalse(self.path.exists())

    def test_a_file_it_cannot_write_stops_it_before_it_listens(self):
        rc, seen, _, err = self._serve("--issuer-jwks", str(self.jwks), "--once",
                                       "--result", str(self.tmp / "no-such-dir" / "result.json"))
        self.assertEqual(rc, 2)
        self.assertIn("--result", err)
        self.assertNotIn("kwargs", seen, "it listened")

    def test_a_rewrite_that_fails_removes_the_file_rather_than_leave_it_stale(self):
        import contextlib
        import io
        from unittest import mock
        from polaris_oid4vp import cli
        seen, session, _ = self._started()
        jar = seen["verifier"].request_object(session.state)
        err = io.StringIO()
        with mock.patch.object(cli.os, "replace", side_effect=OSError("disk full")), \
                contextlib.redirect_stderr(err):
            status, _, line = self._answer(seen, self.wallet.respond(jar, nonce="wrong"))
        self.assertEqual(status, 400)
        self.assertTrue(line.startswith("  <- 400 refused: nonce: "), "the verdict line was lost")
        self.assertFalse(self.path.exists(), "a result that says nothing arrived was left behind")
        self.assertIn("could not be rewritten", err.getvalue())
        self.assertEqual([p.name for p in self.tmp.iterdir() if "result" in p.name], [])

    def test_the_listener_reports_through_the_file_before_it_answers(self):
        """The real command over HTTP: each answer is in the file by the time the client has it,
        with no wait, and the log carries the `<-` line and no JSON."""
        import json
        import socket
        import time
        import urllib.error
        import urllib.request
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        log = self.tmp / "serve.log"
        with open(log, "w") as fh:
            proc = subprocess.Popen(
                [sys.executable, "-m", "polaris_oid4vp.cli", "serve", "--pki", str(self.tmp),
                 "--host", "verifier.test", "--bind", "127.0.0.1", "--port", str(port),
                 "--no-local-tls", "--issuer-jwks", str(self.jwks), "--once", "--result",
                 str(self.path)],
                stdout=fh, stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONUNBUFFERED="1"),
                cwd=os.path.dirname(os.path.abspath(__file__)))
        try:
            deadline = time.monotonic() + 30
            while not (self.path.exists() and self._read().get("state")):
                self.assertIsNone(proc.poll(), log.read_text())
                self.assertLess(time.monotonic(), deadline, "no request in the file")
                time.sleep(0.1)
            base = "http://127.0.0.1:%d" % port
            for path, data in (("/request.jwt?state=nonsense", None), ("/response", b"response=x")):
                try:
                    urllib.request.urlopen(urllib.request.Request(base + path, data=data),
                                           timeout=10)
                except urllib.error.HTTPError as e:
                    self.assertIn(e.code, (400, 404))
                doc = self._read()
                if path.startswith("/request"):
                    self.assertEqual(doc["request_object"], {"served": 0, "refused": 1})
            self.assertEqual({k: doc[k] for k in ("outcome", "response", "check", "responses")},
                             {"outcome": "refused", "response": {"status_code": 400},
                              "check": "invalid_request", "responses": 1})
        finally:
            proc.terminate()
            proc.wait(timeout=10)
        text = log.read_text()
        self.assertIn("  <- 400 refused: invalid_request: %s" % doc["reason"], text)
        self.assertNotIn('"outcome"', text)
        self.assertEqual(json.loads(self.path.read_text())["outcome"], "refused")


class TransactionDataServeTests(unittest.TestCase):
    """`serve --transaction-data FILE --once`: the entries of the request it starts, checked
    before it listens, and `--credential-query-id`, the id those entries name."""

    _serve = ServeCommandHeldOutTests._serve

    PAYMENT = {"type": "urn:eudi:sca:payment:1", "credential_ids": ["pay"],
               "payload": {"transaction_id": "polaris-test-0001",
                           "payee": {"name": "Example Shop", "id": "DE00EXAMPLE0001"},
                           "currency": "EUR", "amount": 49.99}}

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-td-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        keygen(self.tmp, DEFAULT_HOST)

    def _file(self, content):
        import json
        path = self.tmp / "transaction-data.json"
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return str(path)

    def test_the_entries_reach_the_request_once_starts(self):
        import json
        from polaris_oid4vp.jwe import b64u_encode
        raw = b64u_encode(json.dumps(self.PAYMENT, separators=(",", ":")).encode())
        rc, seen, out, _ = self._serve("--credential-query-id", "pay", "--once",
                                       "--transaction-data", self._file([raw, self.PAYMENT]))
        self.assertEqual(rc, 0)
        (session,) = seen["verifier"]._sessions.values()
        self.assertEqual([e.raw for e in session.transaction_data][0], raw)
        jar = seen["verifier"]._by_request[session.state]
        payload = jar.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertEqual(claims["transaction_data"][0], raw, "the string was not sent as given")
        self.assertEqual(len(claims["transaction_data"]), 2)
        self.assertEqual(claims["dcql_query"]["credentials"][0]["id"], "pay")
        self.assertIn("2 transaction_data entries", out)

    def test_without_once_there_is_no_request_to_carry_them(self):
        rc, seen, _, err = self._serve("--credential-query-id", "pay",
                                       "--transaction-data", self._file([self.PAYMENT]))
        self.assertEqual(rc, 2)
        self.assertNotIn("verifier", seen)
        self.assertIn("add --once", err)

    def test_entries_a_wallet_would_refuse_stop_it_starting(self):
        string_amount = dict(self.PAYMENT, payload=dict(self.PAYMENT["payload"], amount="49.99"))
        for content in ("{", "[]", [string_amount], [dict(self.PAYMENT, credential_ids=["pid"])]):
            with self.subTest(content=str(content)[:40]):
                rc, seen, _, err = self._serve("--credential-query-id", "pay", "--once",
                                               "--transaction-data", self._file(content))
                self.assertEqual(rc, 2)
                self.assertNotIn("verifier", seen)
                self.assertIn("--transaction-data", err)
        rc, _, _, err = self._serve("--once", "--transaction-data", self._file([self.PAYMENT]))
        self.assertEqual(rc, 2, "the default query is pid, and the payment names pay")

    def test_the_credential_query_id_reaches_the_query(self):
        rc, seen, _, _ = self._serve("--credential-query-id", "pay")
        self.assertEqual((rc, seen["verifier"].query_id), (0, "pay"))
        rc, seen, _, _ = self._serve()
        self.assertEqual(seen["verifier"].query_id, "pid")
        rc, seen, _, err = self._serve("--credential-query-id", "p d")
        self.assertEqual(rc, 2)
        self.assertNotIn("verifier", seen)

    def test_verifier_info_names_the_query_that_is_made(self):
        import json
        path = self.tmp / "verifier-info.json"
        path.write_text(json.dumps([{"format": "f", "data": "x", "credential_ids": ["pay"]}]))
        self.assertEqual(self._serve("--credential-query-id", "pay", "--verifier-info", str(path))[0], 0)
        self.assertEqual(self._serve("--verifier-info", str(path))[0], 2)


class VerifierInfoProfileServeTests(unittest.TestCase):
    """`serve --verifier-info-profile etsi-119472-2`: verifier_info held to ETSI TS 119 472-2
    V1.2.1 before the listener starts. A refusal names its requirement, exits 2 and never listens,
    and startup says what was checked and what was not. Without the flag, serve is as before."""

    _serve = ServeCommandHeldOutTests._serve

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-vinfo-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        keygen(self.tmp, DEFAULT_HOST)
        self.vectors = dict(verifier_info_vectors())

    def _file(self, content):
        import json
        path = self.tmp / "verifier-info.json"
        path.write_text(json.dumps(content))
        return str(path)

    def _request_payload(self, verifier):
        _, jar = verifier.new_request()
        payload = jar.split(".")[1]
        return base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))

    def test_every_vector_is_judged_before_it_listens(self):
        for name, vector in sorted(self.vectors.items()):
            s = vector["settings"]
            args = ["--credential-query-id", s["credential_query_id"]]
            for vct in s["vct_values"]:
                args += ["--vct", vct]
            for claim in s["claims"]:
                args += ["--claim", claim]
            if s["verifier_info_profile"]:
                args += ["--verifier-info-profile", s["verifier_info_profile"]]
            if vector["verifier_info"] is not None:
                args += ["--verifier-info", self._file(vector["verifier_info"])]
            with self.subTest(vector=name):
                rc, seen, _, err = self._serve(*args)
                if vector["expect"] == "accept":
                    self.assertEqual((rc, "verifier" in seen), (0, True), err)
                    continue
                self.assertEqual(rc, 2)
                self.assertNotIn("verifier", seen, "a refused verifier_info reached the listener")
                self.assertIn(vector["says"], err)
                if vector["requirement"]:
                    self.assertIn(vector["requirement"] + ":", err)

    def test_the_control_is_carried_and_startup_says_what_was_checked(self):
        import json
        info = self.vectors["accept-control.json"]["verifier_info"]
        rc, seen, out, _ = self._serve("--verifier-info-profile", "etsi-119472-2",
                                       "--verifier-info", self._file(info))
        self.assertEqual(rc, 0)
        self.assertIn(b'"verifier_info":' + json.dumps(info, separators=(",", ":")).encode(),
                      self._request_payload(seen["verifier"]))
        self.assertIn("verifier_info meets etsi-119472-2: ETSI TS 119 472-2 V1.2.1 RO-01 to RO-16, "
                      "shape and labels only (the registration certificate's signature, chain and "
                      "registry are not checked)", out)
        self.assertIn("the request asks for no more than its registration certificate registers",
                      out)
        self.assertNotIn("did not run", out)

    def test_without_a_certificate_startup_says_the_over_asking_check_did_not_run(self):
        registrar = self.vectors["accept-control.json"]["verifier_info"][:1]
        rc, seen, out, _ = self._serve("--verifier-info-profile", "etsi-119472-2",
                                       "--verifier-info", self._file(registrar))
        self.assertEqual(rc, 0)
        self.assertFalse(seen["verifier"].over_asking_checked)
        self.assertIn("no registration certificate carried; the over-asking check did not run",
                      out)
        self.assertNotIn("asks for no more than", out)

    def test_the_profile_with_no_verifier_info_does_not_start(self):
        rc, seen, _, err = self._serve("--verifier-info-profile", "etsi-119472-2")
        self.assertEqual(rc, 2)
        self.assertNotIn("verifier", seen)
        self.assertIn("OIDFVP-HAIP-COMMON-REQ-RO-01: the request carries no verifier_info", err)

    def test_a_profile_it_does_not_know_stops_the_parser(self):
        import contextlib
        import io
        err = io.StringIO()
        with self.assertRaises(SystemExit) as caught, contextlib.redirect_stderr(err):
            main(["serve", "--pki", str(self.tmp), "--verifier-info-profile", "etsi"])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("etsi-119472-2", err.getvalue())

    def test_without_the_profile_the_label_check_still_applies(self):
        """German EUDI Wallet iOS issue #38, in either mode: the certificate under its own typ
        stops serve before it listens, and the same data under registration_cert is carried."""
        jwt = self.vectors["accept-control.json"]["verifier_info"][1]["data"]
        for info in ([{"format": "rc-wrp+jwt", "data": jwt}], {"format": "rc-wrp+jwt", "data": jwt}):
            with self.subTest(info=type(info).__name__):
                rc, seen, _, err = self._serve("--verifier-info", self._file(info))
                self.assertEqual(rc, 2)
                self.assertNotIn("verifier", seen)
                self.assertIn("--verifier-info", err)
                self.assertIn(TYP_AS_FORMAT, err)
        rc, seen, out, _ = self._serve("--verifier-info", self._file(
            {"format": "registration_cert", "data": jwt}))
        self.assertEqual(rc, 0)
        self.assertNotIn("verifier_info meets", out)
        self.assertNotIn("over-asking", out)

    def test_without_the_profile_its_rules_do_not_apply(self):
        """Outside the profile, verifier_info the profile refuses is carried as given: a single
        certificate with no registrar data, and one that registers less than is asked for."""
        import json
        over = self.vectors["over-asking-claim-path.json"]["verifier_info"]
        for info in (over, over[1:], over[1]):
            with self.subTest(info=str(info)[:30]):
                rc, seen, out, _ = self._serve("--verifier-info", self._file(info))
                self.assertEqual(rc, 0)
                self.assertIsNone(seen["verifier"].verifier_info_profile)
                self.assertIn(b'"verifier_info":' + json.dumps(info, separators=(",", ":")).encode(),
                              self._request_payload(seen["verifier"]))


MDL_AGE = '["org.iso.18013.5.1","age_over_21"]=true'


class _MdocServeCase(unittest.TestCase):
    """`serve` run to its end with the listener replaced, as ServeCommandHeldOutTests runs it,
    with a file holding the IACA root the mdoc tests mint under."""

    _serve = ServeCommandHeldOutTests._serve
    _jwks_file = ServeCommandHeldOutTests._jwks_file
    _anchor_file = ServeCommandHeldOutTests._anchor_file

    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        ServeCommandHeldOutTests.setUp(self)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "iaca.pem"
        self.root.write_bytes(md.IACA.public_bytes(serialization.Encoding.PEM))

    def mdoc(self, *extra, without=()):
        args = ["--format", "mso_mdoc", "--experimental", "--doctype", md.MDL,
                "--iaca-root", str(self.root), "--claim", MDL_AGE]
        for flag in without:
            at = args.index(flag)
            del args[at:at + (1 if flag == "--experimental" else 2)]
        return self._serve(*args, *extra)

    def stopped(self, result, *says):
        """The command refused before it built a verifier, and stderr says why."""
        rc, seen, _, err = result
        self.assertEqual(rc, 2, err)
        self.assertNotIn("verifier", seen)
        for words in says:
            self.assertIn(words, err)


class PublicationRuleTests(_MdocServeCase):
    """What no outside wallet or suite has exercised is off until it is asked for by name."""

    def test_the_unexercised_paths_are_off_by_default(self):
        import json
        rc, seen, out, _ = self._serve()
        self.assertEqual(rc, 0)
        verifier = seen["verifier"]
        self.assertEqual((verifier.credential_format, verifier.doctype_value, verifier.iaca_roots),
                         ("dc+sd-jwt", None, []))
        payload = verifier.new_request()[1].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertEqual([q["format"] for q in claims["dcql_query"]["credentials"]], ["dc+sd-jwt"])
        self.assertEqual(list(claims["client_metadata"]["vp_formats_supported"]), ["dc+sd-jwt"])
        self.assertNotIn("mso_mdoc", out)
        # Asked for without the flag that turns it on, it does not start.
        self.stopped(self.mdoc(without=("--experimental",)), "--format mso_mdoc", "--experimental")
        # The flag alone asks for nothing new.
        rc, seen, _, _ = self._serve("--experimental")
        self.assertEqual((rc, seen["verifier"].credential_format), (0, "dc+sd-jwt"))

    def test_the_experimental_flag_s_help_names_every_flag_it_gates(self):
        """serve's --experimental help says what it turns on. The gates are read from the command's
        own refusals ("FLAG is experimental and off by default"), so a gate whose flag the help
        leaves out fails here, and so does a fourth gate this test has not been told of."""
        import contextlib
        import io
        import os
        import re
        from unittest import mock
        from polaris_oid4vp import cli
        source = pathlib.Path(cli.__file__).read_text(encoding="utf-8")
        gated = [flag.replace("%s", cli.MDOC_FORMAT)
                 for flag in re.findall(r'"(--[a-z-]+(?: %s)?) is experimental and off by default', source)]
        self.assertEqual(sorted(gated), ["--age-check", "--dc-api", "--format mso_mdoc"])
        with mock.patch.dict(os.environ, {"COLUMNS": "1000"}), \
                contextlib.redirect_stdout(io.StringIO()) as shown, self.assertRaises(SystemExit):
            main(["serve", "--help"])
        help_text = " ".join(re.search(r"^  --experimental\s(.*?)(?=\n  -)", shown.getvalue(),
                                       re.M | re.S).group(1).split())
        for flag in gated:
            self.assertIn(flag, help_text)

    def test_without_the_flag_a_posted_mdoc_reaches_no_mdoc_or_cbor_code(self):
        """The verifier a serve without --experimental builds is the one its listener hands every
        POST to. An mdoc DeviceResponse posted to it, as the listener parses the form, is refused on
        the SD-JWT VC path, and neither mdoc's judge nor the CBOR decoder is called. The control is
        the same form, byte for byte, to the same verifier with only its credential format changed:
        the request stays open after a refusal, and the DeviceResponse then reaches the judge and
        the decoder, so the refusal came from the format the verifier was built with and not from
        an earlier layer, and each zero is a count that can be more."""
        import urllib.parse
        from unittest import mock
        from polaris_oid4vp import cbor, mdoc
        from polaris_oid4vp.jwe import b64u_decode
        from polaris_oid4vp.verifier import Verifier
        rc, seen, _, err = self._serve()
        self.assertEqual(rc, 0, err)
        verifier = seen["verifier"]
        self.assertEqual(verifier.credential_format, "dc+sd-jwt")
        _, jar = verifier.new_request()
        query_id = Wallet.read_request(jar)[1]["dcql_query"]["credentials"][0]["id"]
        sent = []

        def vp_token(value):
            sent.append(value)
            return {query_id: [value]}

        form = urllib.parse.parse_qs(urllib.parse.urlencode(
            MdocWallet().respond(jar, vp_token=vp_token), doseq=True))
        with mock.patch.object(mdoc, "judge_device_response", wraps=mdoc.judge_device_response) as judge, \
                mock.patch.object(cbor, "decode", wraps=cbor.decode) as decode:
            status, body, verdict = verifier.handle_direct_post(form)
            self.assertEqual((status, body, verdict.authentic, verdict.code),
                             (400, Verifier.REFUSAL_BODY, False, "malformed"), verdict.reason)
            self.assertIn("the issuer-signed JWT does not parse", verdict.reason)
            self.assertEqual((judge.call_count, decode.call_count), (0, 0))
            # The control.
            verifier.credential_format = "mso_mdoc"
            verifier.handle_direct_post(form)
            self.assertEqual(judge.call_count, 1)
            self.assertEqual(judge.call_args.args[0], b64u_decode(sent[0]))
            self.assertIn(b64u_decode(sent[0]), [call.args[0] for call in decode.call_args_list])


class DcApiServeCommandTests(_MdocServeCase):
    """`serve ... --dc-api --dc-api-origin ORIGIN [--dc-api-client-metadata FILE]`: the page and
    routes of the Digital Credentials API, behind --experimental and --format mso_mdoc."""

    ORIGIN = "https://verifier.example"

    def dc_api(self, *extra, without=()):
        return self.mdoc("--dc-api", "--dc-api-origin", self.ORIGIN, *extra, without=without)

    def before_the_pki(self, *args):
        """`serve` with a PKI directory that does not exist: (rc, stderr)."""
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = main(["serve", "--pki", str(self.tmp / "absent"), *args])
        return rc, err.getvalue()

    def metadata_file(self, text):
        path = self.tmp / ("metadata-%d.json" % len(list(self.tmp.iterdir())))
        path.write_text(text)
        return str(path)

    def test_the_dc_api_path_is_off_by_default(self):
        rc, seen, out, err = self.mdoc()
        self.assertEqual(rc, 0, err)
        self.assertIsNone(seen["kwargs"].get("dc_api_origin"))
        self.assertNotIn("/dc-api/", out)
        self.assertEqual(seen["verifier"].dc_api_client_metadata, {})
        result = self.dc_api(without=("--experimental",))
        self.stopped(result, "--dc-api is experimental and off by default; add --experimental to turn it on")

    def test_dc_api_flags_are_refused_apart_and_before_the_pki_is_read(self):
        mdoc = ("--format", "mso_mdoc", "--experimental")
        good = ("--dc-api", "--dc-api-origin", self.ORIGIN) + mdoc
        cases = (
            (("--dc-api-origin", self.ORIGIN) + mdoc, "--dc-api-origin belongs to --dc-api, which this command was not given"),
            (("--dc-api-client-metadata", self.metadata_file("{}")) + mdoc,
             "--dc-api-client-metadata belongs to --dc-api, which this command was not given"),
            (("--dc-api-origin", self.ORIGIN, "--dc-api-client-metadata", self.metadata_file("{}")) + mdoc,
             "--dc-api-origin and --dc-api-client-metadata belong to --dc-api"),
            (("--dc-api", "--dc-api-origin", self.ORIGIN, "--format", "mso_mdoc"),
             "--dc-api is experimental and off by default; add --experimental to turn it on"),
            (("--dc-api", "--dc-api-origin", self.ORIGIN, "--experimental"), "--dc-api asks for an mdoc; add --format mso_mdoc"),
            (("--dc-api", "--dc-api-origin", self.ORIGIN, "--experimental", "--format", "dc+sd-jwt"),
             "--dc-api asks for an mdoc; add --format mso_mdoc"),
            (("--dc-api",) + mdoc, "--dc-api needs --dc-api-origin"),
            (("--dc-api", "--dc-api-origin", "http://rp.example") + mdoc, "--dc-api-origin 'http://rp.example'"),
            (("--dc-api", "--dc-api-origin", "*") + mdoc, "--dc-api-origin '*' is not one origin"),
            (("--dc-api", "--dc-api-origin", self.ORIGIN + "/page") + mdoc, "it carries a path"),
            (("--dc-api", "--dc-api-origin", "origin:" + self.ORIGIN) + mdoc, "--dc-api-origin"),
            (good + ("--dc-api-client-metadata", str(self.tmp / "nothing.json")), "--dc-api-client-metadata"),
            (good + ("--dc-api-client-metadata", self.metadata_file("{")), "--dc-api-client-metadata"),
            (good + ("--dc-api-client-metadata", self.metadata_file("[]")), "is a JSON object of members"),
            (good + ("--dc-api-client-metadata", self.metadata_file('{"jwks": {"keys": []}}')),
             "sets 'jwks', which this verifier writes itself"),
        )
        for args, says in cases:
            with self.subTest(args=args[:4], says=says):
                rc, err = self.before_the_pki(*args)
                self.assertEqual(rc, 2, err)
                self.assertIn(says, err)
                self.assertNotIn("is missing", err)
        self.assertIn("secure context", self.before_the_pki("--dc-api", "--dc-api-origin", "http://rp.example", *mdoc)[1])
        # The twin: the same flags, each one, and the command goes on to the missing PKI.
        for args in (good, good + ("--dc-api-client-metadata", self.metadata_file('{"x_polaris_test": 1}')),
                     ("--dc-api", "--dc-api-origin", "http://localhost:8080") + mdoc):
            with self.subTest(twin=args):
                rc, err = self.before_the_pki(*args)
                self.assertEqual(rc, 2)
                self.assertIn("is missing", err)

    def test_dc_api_does_not_combine_with_the_counting_flags(self):
        token = self.tmp / "token"
        token.write_text("t" * 40)
        token.chmod(0o600)
        for flags, named in ((("--once",), "--once"), (("--once", "--rearm"), "--once and --rearm"),
                             (("--result", str(self.tmp / "r.json")), "--result"),
                             (("--control-token-file", str(token)), "--control-token-file")):
            with self.subTest(flags=flags):
                self.stopped(self.dc_api(*flags), "--dc-api is not combined with %s" % named)
                rc, err = self.before_the_pki("--dc-api", "--dc-api-origin", self.ORIGIN, "--format", "mso_mdoc",
                                              "--experimental", *flags)
                self.assertEqual(rc, 2)
                self.assertIn("--dc-api is not combined with", err)
                self.assertNotIn("is missing", err)

    def test_the_startup_line_names_the_page(self):
        rc, seen, out, err = self.mdoc("--dc-api", "--dc-api-origin", "HTTPS://Verifier.Example:443")
        self.assertEqual(rc, 0, err)
        self.assertEqual(seen["kwargs"]["dc_api_origin"], self.ORIGIN)
        self.assertIn("\n  dc api page   %s/dc-api/ (Digital Credentials API, experimental)\n" % self.ORIGIN, out)
        rc, seen, out, err = self.mdoc("--dc-api", "--dc-api-origin", "http://127.0.0.1:8080")
        self.assertEqual(rc, 0, err)
        self.assertEqual(seen["kwargs"]["dc_api_origin"], "http://127.0.0.1:8080")
        self.assertIn("  dc api page   http://127.0.0.1:8080/dc-api/ (Digital Credentials API, experimental)", out)
        # --once is refused beside --dc-api, so the startup text does not point at it; without
        # --dc-api it still does.
        self.assertNotIn("--once", out)
        self.assertIn("\nOpen the dc api page in a browser to start a request.\n", out)
        rc, _, out, err = self.mdoc()
        self.assertEqual(rc, 0, err)
        self.assertIn("\nStart a request with --once to print the parameters a wallet is launched with.\n", out)
        self.assertNotIn("dc api page", out)

    def test_the_metadata_file_reaches_the_request_and_is_refused_as_the_verifier_refuses(self):
        import json
        from polaris_oid4vp.verifier import dc_api_client_metadata_of
        extra = {"x_polaris_test": {"note": "made up", "n": 1}}
        rc, seen, _, err = self.dc_api("--dc-api-client-metadata", self.metadata_file(json.dumps(extra)))
        self.assertEqual(rc, 0, err)
        verifier = seen["verifier"]
        self.assertEqual(verifier.dc_api_client_metadata, extra)
        payload = verifier.dc_api_request(self.ORIGIN)["data"]["request"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertEqual(claims["client_metadata"]["x_polaris_test"], extra["x_polaris_test"])
        _, jar = verifier.new_request()
        payload = jar.split(".")[1]
        redirect = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertNotIn("x_polaris_test", redirect["client_metadata"])
        for document in ([], "x", {"jwks": {}}, {"vp_formats_supported": {}, "x": 1},
                         {"x": "a" * 20000}):
            with self.subTest(document=repr(document)[:30]):
                with self.assertRaises(ValueError) as caught:
                    dc_api_client_metadata_of(document)
                path = self.metadata_file(json.dumps(document))
                self.stopped(self.dc_api("--dc-api-client-metadata", path),
                             "--dc-api-client-metadata %s: %s" % (path, caught.exception))
        # A file nested past the interpreter's recursion limit is refused with this flag's message
        # (the depth bound reads it), never ended by the parser's RecursionError; a NaN likewise.
        depth = 100000
        for text, words in (('{"x":' + '{"a":' * depth + '{}' + '}' * depth + '}', "nests deeper than"),
                            ('{"x": NaN}', "non-JSON literal NaN")):
            with self.subTest(text=text[:12]):
                path = self.metadata_file(text)
                self.stopped(self.dc_api("--dc-api-client-metadata", path),
                             "--dc-api-client-metadata %s: the file" % path, words)


class MdocServeCommandTests(_MdocServeCase):
    """`serve --format mso_mdoc --doctype D --iaca-root PEM --claim '[NS,EL]' --experimental`:
    what the flags hand the verifier, and what stops the command before it listens."""

    def test_the_flags_reach_the_verifier_and_an_mdoc_is_accepted(self):
        rc, seen, out, err = self.mdoc()
        self.assertEqual(rc, 0, err)
        verifier = seen["verifier"]
        self.assertEqual((verifier.credential_format, verifier.doctype_value, verifier.query_id),
                         ("mso_mdoc", md.MDL, "mdoc"))
        self.assertEqual(verifier.claims, [((md.MDL_NS, "age_over_21"), (True,))])
        self.assertEqual([(root.certificate, root.doctypes) for root in verifier.iaca_roots],
                         [(md.IACA, frozenset([md.MDL]))])
        self.assertEqual((verifier.issuer_jwks, verifier.issuer_trust_anchors), ([], []))
        self.assertIn("mso_mdoc, docType %s (experimental)" % md.MDL, out)
        self.assertNotIn("--iaca-root", err)
        self.assertNotIn("--issuer-jwks", err)
        _, jar = verifier.new_request()
        status, _, verdict = verifier.handle_direct_post(MdocWallet().respond(jar))
        self.assertEqual((status, verdict.authentic), (200, True), verdict.reason)

    def test_the_line_and_the_result_file_name_the_elements_accepted(self):
        """The `<-` line serve prints and the --result file, for an accepted mdoc: what was
        checked, on the line only, and each element under its namespace, as --claim names it.
        The file's outcome is `accepted`, as for an SD-JWT VC."""
        import contextlib
        import io
        import json
        path = self.tmp / "result.json"
        rc, seen, _, err = self.mdoc("--once", "--result", str(path))
        self.assertEqual(rc, 0, err)
        verifier = seen["verifier"]
        (session,) = verifier._sessions.values()
        status, body, verdict = verifier.handle_direct_post(
            MdocWallet().respond(verifier.request_object(session.state)))
        line = io.StringIO()
        with contextlib.redirect_stdout(line):
            seen["kwargs"]["on_verdict"](status, body, verdict)
        self.assertEqual(line.getvalue(),
                         "  <- 200 authentic (issuer signature chained to a configured root, element "
                         "digests, validity window, device signature), claims "
                         "[['org.iso.18013.5.1', 'age_over_21']]\n")
        doc = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual((doc["outcome"], doc["claims"]),
                         ("accepted", [["org.iso.18013.5.1", "age_over_21"]]))

    def test_a_value_the_request_does_not_accept_is_refused(self):
        _, seen, _, _ = self.mdoc()
        verifier = seen["verifier"]
        _, jar = verifier.new_request()
        status, _, verdict = verifier.handle_direct_post(
            MdocWallet().respond(jar, items=(md.el("age_over_21", False),)))
        self.assertEqual((status, verdict.code), (400, "claims"), verdict.reason)

    def test_the_query_id_named_is_the_one_asked_under(self):
        rc, seen, _, _ = self.mdoc("--credential-query-id", "licence")
        self.assertEqual((rc, seen["verifier"].query_id), (0, "licence"))

    def test_verifier_info_names_the_mdoc_query_by_its_id(self):
        """An attestation's credential_ids name this request's query: `mdoc` unless one is named."""
        import json
        path = self.tmp / "verifier-info.json"
        for query_id, flags in (("mdoc", ()), ("licence", ("--credential-query-id", "licence"))):
            with self.subTest(query_id=query_id):
                info = [{"format": "registration_cert", "data": "eyJhbGciOiJFUzI1NiJ9.e30.c2ln",
                         "credential_ids": [query_id]}]
                path.write_text(json.dumps(info))
                rc, seen, _, err = self.mdoc("--verifier-info", str(path), *flags)
                self.assertEqual(rc, 0, err)
                self.assertEqual(seen["verifier"].verifier_info, info)
        path.write_text(json.dumps([{"format": "registration_cert", "data": "x", "credential_ids": ["pid"]}]))
        self.stopped(self.mdoc("--verifier-info", str(path)), "--verifier-info", "credential queries (mdoc)")

    def test_without_a_root_it_warns_and_refuses_every_document(self):
        rc, seen, _, err = self.mdoc(without=("--iaca-root",))
        self.assertEqual(rc, 0, err)
        self.assertIn("no --iaca-root", err)
        self.assertIn("issuer_key", err)
        self.assertNotIn("no --issuer-jwks", err)
        verifier = seen["verifier"]
        self.assertEqual(verifier.iaca_roots, [])
        _, jar = verifier.new_request()
        status, _, verdict = verifier.handle_direct_post(MdocWallet().respond(jar))
        self.assertEqual((status, verdict.code), (400, "issuer_key"), verdict.reason)

    def test_every_certificate_in_a_root_file_is_a_root_for_the_doctype(self):
        from cryptography.hazmat.primitives import serialization
        _, other = md.make_root("Another IACA")
        self.root.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (md.IACA, other)))
        second = self.tmp / "second.pem"
        second.write_bytes(md.make_root("A third IACA")[1].public_bytes(serialization.Encoding.PEM))
        rc, seen, _, err = self.mdoc("--iaca-root", str(second))
        self.assertEqual(rc, 0, err)
        roots = seen["verifier"].iaca_roots
        self.assertEqual([r.certificate.subject.rfc4514_string() for r in roots],
                         ["CN=Test IACA,C=ZZ", "CN=Another IACA,C=ZZ", "CN=A third IACA,C=ZZ"])
        self.assertEqual({r.doctypes for r in roots}, {frozenset([md.MDL])})

    def test_a_root_file_it_cannot_use_stops_it_starting(self):
        from cryptography.hazmat.primitives import serialization
        absent = self.tmp / "absent.pem"
        text = self.tmp / "text.pem"
        text.write_text("hello")
        leaf = self.tmp / "leaf.pem"
        leaf.write_bytes(md.DS.public_bytes(serialization.Encoding.PEM))
        for path, says in ((absent, "not a readable PEM"), (text, "not a readable PEM"), (leaf, "not a CA")):
            with self.subTest(path=path.name):
                self.stopped(self.mdoc("--iaca-root", str(path), without=("--iaca-root",)),
                             "--iaca-root %s" % path, says)

    def test_what_an_mdoc_query_needs_is_asked_for_by_flag(self):
        self.stopped(self.mdoc(without=("--doctype",)), "--doctype")
        self.stopped(self.mdoc(without=("--claim",)), "--claim", "namespace")
        self.stopped(self.mdoc("--doctype", ""), "--doctype")

    def test_a_claim_that_is_not_a_namespace_and_an_element_stops_it_starting(self):
        for claim in ("age_over_21", "org.iso.18013.5.1.age_over_21", '["org.iso.18013.5.1"]',
                      '["org.iso.18013.5.1","driving_privileges","codes"]'):
            with self.subTest(claim=claim):
                self.stopped(self.mdoc("--claim", claim, without=("--claim",)), claim, "namespace")

    def test_an_sd_jwt_flag_with_an_mdoc_query_stops_it_starting(self):
        import json
        entries = self.tmp / "transaction-data.json"
        entries.write_text(json.dumps([{"type": "x", "credential_ids": ["mdoc"]}]))
        for flags in (("--issuer-jwks", self._jwks_file({"keys": [self.jwk]})),
                      ("--issuer-trust-anchor", self._anchor_file()),
                      ("--vct", "urn:eudi:pid:1"),
                      ("--once", "--transaction-data", str(entries))):
            with self.subTest(flag=flags[-2]):
                self.stopped(self.mdoc(*flags), flags[-2], "dc+sd-jwt")

    def test_an_mdoc_flag_without_the_format_stops_it_starting(self):
        for flags in (("--doctype", md.MDL), ("--iaca-root", str(self.root))):
            with self.subTest(flag=flags[0]):
                for more in ((), ("--experimental",)):
                    self.stopped(self._serve(*flags, *more), flags[0], "--format mso_mdoc")

    def test_a_format_it_does_not_build_is_refused_by_the_parser(self):
        import contextlib
        import io
        from unittest import mock
        from polaris_oid4vp import cli
        # The parser refuses it, so no server is ever built; one that is built ends the test at
        # once, where the real one would serve until interrupted.
        built = AssertionError("the parser admitted a format this command does not build")
        err = io.StringIO()
        with mock.patch.object(cli, "serve", side_effect=built), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err), \
                self.assertRaises(SystemExit) as caught:
            main(["serve", "--pki", str(self.tmp), "--format", "jwt_vc_json", "--experimental"])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("argument --format: invalid choice: 'jwt_vc_json'", err.getvalue())

    def test_the_help_says_the_format_is_experimental(self):
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            main(["serve", "--help"])
        flat = " ".join(out.getvalue().split())
        for phrase in ("--format {dc+sd-jwt,mso_mdoc}", "--doctype", "--iaca-root", "--experimental",
                       "experimental"):
            self.assertIn(phrase, flat)


class MdocVerdictCommandTests(unittest.TestCase):
    """`polaris-oid4vp verdict` over a captured mdoc response: the PID capture, its request, its
    root and the instant it was captured at."""

    def setUp(self):
        import json
        from cryptography.hazmat.primitives import serialization
        from polaris_oid4vp.jwe import b64u_encode
        response, inputs, self.at, root = md.capture_case("capture-pid")
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-mdoc-verdict-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.query = {"id": "pid", "format": "mso_mdoc", "meta": {"doctype_value": md.PID}}
        self.claims = {
            "client_id": inputs["client_id"], "nonce": inputs["nonce"], "response_uri": inputs["response_uri"],
            "response_mode": "direct_post.jwt",
            "client_metadata": {"jwks": {"keys": [inputs["encryption_jwk"]]}},
            "dcql_query": {"credentials": [self.query]}}
        self.request = self.write("request.json", json.dumps(self.claims))
        self.token = self.write("vp_token.json", json.dumps({"pid": [b64u_encode(response)]}))
        self.root = self.write("root.pem", root.public_bytes(serialization.Encoding.PEM).decode())

    def write(self, name, text):
        path = self.tmp / name
        path.write_text(text)
        return str(path)

    def verdict(self, *extra, experimental=True, root=True, now=True, request=None):
        import contextlib
        import io
        import json
        args = ["verdict", "--request", request or self.request, "--vp-token", self.token]
        args += ["--experimental"] if experimental else []
        args += ["--iaca-root", self.root] if root else []
        args += ["--now", str(self.at)] if now else []
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(args + list(extra))
        return rc, (json.loads(out.getvalue()) if out.getvalue() else None), err.getvalue()

    def test_the_pid_capture_verifies_at_its_instant(self):
        rc, result, err = self.verdict()
        self.assertEqual((rc, result["accepted"]), (0, True), err)
        verdict = result["verdicts"]["pid"]
        self.assertTrue(verdict["authentic"])
        self.assertIn("judged at the supplied instant 2026-10-11T04:54:42Z", verdict["reason"])
        self.assertEqual(verdict["claims"], [[md.PID, "family_name"], [md.PID, "given_name"]])

    def test_the_roots_are_trusted_for_the_doctypes_the_request_names_and_no_other(self):
        from unittest import mock
        from polaris_oid4vp import cli
        real, handed = cli.verify_response, {}

        def judge(request, token, **kwargs):
            handed.update(kwargs)
            return real(request, token, **kwargs)

        with mock.patch.object(cli, "verify_response", judge):
            rc, result, err = self.verdict()
        self.assertEqual((rc, result["accepted"]), (0, True), err)
        self.assertEqual([root.doctypes for root in handed["iaca_roots"]], [frozenset([md.PID])])

    def test_without_the_flag_a_captured_mdoc_is_not_judged(self):
        rc, result, err = self.verdict(experimental=False)
        self.assertEqual((rc, result), (2, None))
        self.assertIn("the request asks for mso_mdoc, which is experimental and off by default; "
                      "add --experimental to judge it", err)

    def test_at_this_machine_s_clock_the_capture_has_run_out(self):
        rc, result, _ = self.verdict(now=False)
        self.assertEqual((rc, result["accepted"]), (1, False))
        self.assertEqual(result["verdicts"]["pid"]["code"], "credential_validity")
        self.assertNotIn("supplied instant", result["verdicts"]["pid"]["reason"])

    def test_without_a_root_or_under_another_it_is_refused(self):
        from cryptography.hazmat.primitives import serialization
        rc, result, _ = self.verdict(root=False)
        self.assertEqual((rc, result["verdicts"]["pid"]["code"]), (1, "issuer_key"))
        other = self.write("other.pem", md.IACA.public_bytes(serialization.Encoding.PEM).decode())
        rc, result, _ = self.verdict("--iaca-root", other, root=False)
        self.assertEqual((rc, result["verdicts"]["pid"]["code"]), (1, "issuer_key"))

    def test_a_root_is_trusted_for_the_doctype_the_request_names(self):
        """The same root and response under a request asking for an mDL: the document is a PID."""
        import json
        mdl = dict(self.claims, dcql_query={"credentials": [dict(self.query, meta={"doctype_value": md.MDL})]})
        rc, result, _ = self.verdict(request=self.write("mdl.json", json.dumps(mdl)))
        self.assertEqual((rc, result["verdicts"]["pid"]["code"]), (1, "doctype"))

    def test_a_root_file_it_cannot_use_is_refused(self):
        rc, result, err = self.verdict("--iaca-root", self.write("text.pem", "hello"))
        self.assertEqual((rc, result), (2, None))
        self.assertIn("--iaca-root", err)

    def test_a_flag_no_query_of_the_request_reads_is_refused(self):
        import json
        issuers = self.write("issuers.json", json.dumps({"keys": []}))
        for flags, says in ((("--issuer-jwks", issuers), "dc+sd-jwt"),
                            (("--issuer-trust-anchor", self.root), "dc+sd-jwt")):
            with self.subTest(flag=flags[0]):
                rc, result, err = self.verdict(*flags)
                self.assertEqual((rc, result), (2, None))
                self.assertIn(flags[0], err)
                self.assertIn(says, err)
        sd_jwt = dict(self.claims, dcql_query={"credentials": [{"id": "pid", "format": "dc+sd-jwt"}]})
        rc, result, err = self.verdict(request=self.write("sd-jwt.json", json.dumps(sd_jwt)))
        self.assertEqual((rc, result), (2, None))
        self.assertIn("--iaca-root", err)
        self.assertIn("mso_mdoc", err)


class VerdictCommandTests(unittest.TestCase):
    """`polaris-oid4vp verdict`: a captured response judged against its request, over the
    two-credential vector in testdata/."""

    def setUp(self):
        import json
        here = pathlib.Path(__file__).resolve().parent
        self.v = json.loads((here / "testdata" / "transaction-data-two-credentials.json")
                            .read_text(encoding="utf-8"))
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-verdict-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.request = self._write("request.json", self.v["request"])
        self.issuers = self._write("issuers.json", {"keys": self.v["issuer_jwks"]})

    def _write(self, name, content):
        import json
        path = self.tmp / name
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return str(path)

    def _verdict(self, response="per_credential", *extra, request=None, token=None):
        import contextlib
        import io
        import json
        token = token or self._write("vp_token.json", self.v["responses"][response]["vp_token"])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(["verdict", "--request", request or self.request, "--vp-token", token,
                       "--issuer-jwks", self.issuers, "--now", str(self.v["at"]), *extra])
        return rc, (json.loads(out.getvalue()) if out.getvalue() else None), err.getvalue()

    def test_each_response_under_each_reading(self):
        for response, outcomes in self.v["outcomes"].items():
            for scope, outcome in outcomes.items():
                with self.subTest(response=response, scope=scope):
                    rc, result, _ = self._verdict(response, "--transaction-data-scope", scope)
                    accepted = outcome == "accepted"
                    self.assertEqual((rc, result["accepted"], result["scope"]),
                                     (0 if accepted else 1, accepted, scope))
                    self.assertEqual(result["expected"]["per_credential"], {"pid": [], "pay": [0]})
                    self.assertEqual(result["expected"]["all_entries"], {"pid": [0], "pay": [0]})
                    if not accepted:
                        self.assertEqual(result["verdicts"]["pid"]["code"], outcome.split()[-1])

    def test_without_a_reading_it_does_not_decide_and_says_why(self):
        rc, result, err = self._verdict("all_entries")
        self.assertEqual(rc, 2)
        self.assertIsNone(result["accepted"])
        self.assertIn("name the transaction_data scope", err)
        self.assertTrue(result["readings"]["all_entries"]["pid"]["authentic"])
        self.assertEqual(result["readings"]["per_credential"]["pid"]["code"], "transaction_data_extra")

    def test_a_request_object_jws_and_a_whole_response_body_read_as_their_contents(self):
        import json
        from cryptography.hazmat.primitives.asymmetric import ec
        from test_verifier import _jws
        jws = _jws(ec.generate_private_key(ec.SECP256R1()),
                   {"alg": "ES256", "typ": "oauth-authz-req+jwt"}, self.v["request"])
        body = self._write("body.json", json.dumps(
            {"vp_token": self.v["responses"]["per_credential"]["vp_token"], "state": "s"}))
        rc, result, _ = self._verdict("per_credential", "--transaction-data-scope", "per_credential",
                                      request=self._write("request.jwt", jws), token=body)
        self.assertEqual((rc, result["accepted"]), (0, True))

    def test_inputs_it_cannot_read_are_refused(self):
        for request in (str(self.tmp / "absent.json"), self._write("bad.json", "{"),
                        self._write("list.json", "[1]"), self._write("two.jwt", "a.b")):
            with self.subTest(request=request[-12:]):
                rc, result, err = self._verdict("per_credential", request=request)
                self.assertEqual((rc, result), (2, None))
                self.assertIn("polaris-oid4vp:", err)

    def test_issuer_keys_it_cannot_read_are_refused(self):
        """The same files `serve` refuses, refused here too (found by coverage: untested)."""
        for flag, content in (("--issuer-jwks", "{not json"), ("--issuer-trust-anchor", "hello")):
            with self.subTest(flag=flag):
                import contextlib
                import io
                token = self._write("vp_token.json", self.v["responses"]["per_credential"]["vp_token"])
                err = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    rc = main(["verdict", "--request", self.request, "--vp-token", token,
                               flag, self._write("bad-issuer", content)])
                self.assertEqual(rc, 2)
                self.assertIn(flag, err.getvalue())

    def test_judged_a_year_on_it_is_stale(self):
        rc, result, _ = self._verdict("per_credential", "--transaction-data-scope", "per_credential",
                                      "--now", str(self.v["at"] + 365 * 86400))
        self.assertEqual((rc, result["verdicts"]["pid"]["code"]), (1, "kb_freshness"))


# ---------------------------------------------------------------------------------------------
# `serve --once --rearm` (a fresh request each time one ends) and `serve --control-token-file`
# (POST /control/request). Each case runs the real command in a thread, on a listener on an
# ephemeral port, and talks to it over HTTP, so what is asserted is what a wallet and a harness
# are told and what the log and the result file say.

CONTROL_TOKEN = "control-token-" + "0123456789abcdef" * 3


def _until(test, condition, what, timeout=15.0):
    """Wait, without time.sleep (the command's wait is patched), until `condition()` holds."""
    import threading
    import time
    pause, deadline = threading.Event(), time.monotonic() + timeout
    while not condition():
        test.assertLess(time.monotonic(), deadline, "gave up waiting for " + what)
        pause.wait(0.02)


def _blocks(out):
    """What `--once` prints for a request, once per request, as the lines it printed: from
    `authorization request parameters:` to its last launch link."""
    lines, blocks, i = out.splitlines(), [], 0
    while i < len(lines):
        if lines[i] != "authorization request parameters:":
            i += 1
            continue
        end = i
        while end < len(lines) and not lines[end].startswith("launch links"):
            end += 1
        end += 1
        while end < len(lines) and "://?" in lines[end]:
            end += 1
        blocks.append("\n".join(lines[i:end]))
        i = end
    return blocks


def _state_of(block):
    import re
    return re.search(r"request_uri +\S+\?state=([A-Za-z0-9_-]+)", block).group(1)


def _launch_of(block):
    return {line.strip().split("://?")[0]: line.strip() for line in block.splitlines()
            if "://?" in line}


class _HeldAt(io.StringIO):
    """What the command prints, where the first write holding `text` first waits on `wait()`."""

    def __init__(self, text, wait):
        super().__init__()
        self._text, self._wait = text, wait

    def write(self, s):
        if self._wait is not None and self._text in s:
            wait, self._wait = self._wait, None
            wait()
        return super().write(s)


class _Clock:
    """The time a test runs on: `time.time()` stays where it is until `advance` moves it, and a
    `threading.Timer` runs when `advance` passes its interval, in the caller's thread. A test can
    hold the command up past a request's lifetime this way without waiting it out."""

    def __init__(self, test):
        import threading
        import time
        from unittest import mock
        clock = self
        self.now, self.timers = time.time(), []

        class Timer:
            def __init__(self, interval, function, args=None, kwargs=None):
                self.interval, self.function = interval, function
                self.args, self.kwargs = args or (), kwargs or {}
                self.daemon, self.due = False, None

            def start(self):
                self.due = clock.now + self.interval
                clock.timers.append(self)

            def cancel(self):
                if self in clock.timers:
                    clock.timers.remove(self)

        for patch in (mock.patch.object(time, "time", lambda: clock.now),
                      mock.patch.object(threading, "Timer", Timer)):
            patch.start()
            test.addCleanup(patch.stop)

    def advance(self, seconds):
        self.now += seconds
        for timer in [t for t in self.timers if t.due <= self.now]:
            if timer in self.timers:
                self.timers.remove(timer)
                timer.function(*timer.args, **timer.kwargs)


def _object_times(jar_text):
    """The `iat` and `exp` of a request object as the request URI served it."""
    import json
    payload = jar_text.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return claims["iat"], claims["exp"]


class _Running:
    """`polaris-oid4vp serve` run to the end of its wait in a thread: the real command, a real
    listener on an ephemeral port (`--port 0`), plain HTTP. `ttl` shortens the request lifetime
    the command's verifier is built with. `out` and `err` are what it printed."""

    def __init__(self, test, *extra, ttl=None, listening=None, held_at=None):
        import io
        import threading
        self.test, self.extra, self.ttl, self.listening = test, extra, ttl, listening
        # held_at, (text, wait): stdout as a pipe nobody reads yet, its first write holding `text`
        # waiting on `wait()` first, as the command does at the line it cannot print.
        self.out, self.err = (_HeldAt(*held_at) if held_at else io.StringIO()), io.StringIO()
        self.ready, self.stop = threading.Event(), threading.Event()
        self.rc = self.httpd = self.verifier = self.kwargs = None

    def __enter__(self):
        import contextlib
        import threading
        from unittest import mock
        from polaris_oid4vp import cli
        real_serve, real_verifier_from = cli.serve, cli.verifier_from

        def serve_(verifier, **kwargs):
            from test_serve import _stop_now
            self.kwargs = kwargs
            self.httpd = httpd = real_serve(verifier, **kwargs)
            # The command stops its listener with httpd.shutdown(), as it does outside a test; here
            # that call does not wait out the serve loop's poll (test_serve._stop_now).
            shutdown = httpd.shutdown
            httpd.shutdown = lambda: _stop_now(httpd, shutdown)
            # What reaches the listener the moment it accepts, before the command goes on.
            if self.listening is not None:
                self.listening(kwargs)
            return httpd

        def verifier_from_(*args, **kwargs):
            self.verifier = real_verifier_from(*args, **kwargs)
            if self.ttl is not None:
                self.verifier.request_ttl_seconds = self.ttl
            return self.verifier

        def park(_seconds):
            self.ready.set()
            self.stop.wait()
            raise KeyboardInterrupt

        self.stack = contextlib.ExitStack()
        for patch in (mock.patch.object(cli, "serve", serve_),
                      mock.patch.object(cli, "verifier_from", verifier_from_),
                      mock.patch.object(cli.time, "sleep", park),
                      contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.err)):
            self.stack.enter_context(patch)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.ready.wait(30)
        if self.rc is not None:
            self.__exit__(None, None, None)
            self.test.fail("it stopped at startup, rc %s: %s" % (self.rc, self.err.getvalue()))
        return self

    def _run(self):
        try:
            self.rc = main(["serve", "--pki", str(self.test.tmp), "--host", "verifier.test",
                            "--bind", "127.0.0.1", "--port", "0", "--no-local-tls", *self.extra])
        except SystemExit as exc:      # the parser refusing an option
            self.rc = exc.code
        except BaseException as exc:  # noqa: BLE001  said on stderr, not lost with the thread
            self.rc = -1
            self.err.write("%s: %s\n" % (type(exc).__name__, exc))
        finally:
            self.ready.set()

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(15)
        self.stack.close()
        if exc[0] is None:
            # The streams read whole: every line on stderr and every <- line on stdout, held to
            # a logged_line's length. The announce block's lines are the operator's own
            # parameters and launch links, whose length is the operator's URL.
            from test_serve import assert_every_line_bounded
            assert_every_line_bounded(self.test, self.err.getvalue())
            assert_every_line_bounded(self.test, "\n".join(
                line for line in self.out.getvalue().splitlines() if line.startswith("  <- ")))
        return False

    @property
    def base(self):
        return "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def _call(self, request):
        import urllib.error
        import urllib.request
        try:
            with urllib.request.urlopen(request, timeout=20) as answer:
                return answer.status, answer.read()
        except urllib.error.HTTPError as err:
            return err.code, err.read()

    def jar(self, state):
        """The request object for `state`: (status, text)."""
        import urllib.request
        status, body = self._call(urllib.request.Request("%s/request.jwt?state=%s" % (self.base, state)))
        return status, body.decode("ascii", "replace")

    def respond(self, form):
        """One response at the response URI, as a wallet posts it: (status, body)."""
        import urllib.parse
        import urllib.request
        data = urllib.parse.urlencode(form, doseq=True).encode()
        return self._call(urllib.request.Request(self.base + "/response", data=data, method="POST"))

    def control(self, body=None, token=CONTROL_TOKEN, raw=None, headers=()):
        """POST /control/request: (status, the JSON answer, or None when the body is empty)."""
        import json
        import urllib.request
        data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
        request = urllib.request.Request(self.base + "/control/request", data=data or b"",
                                         method="POST")
        if token is not None:
            request.add_header("Authorization", "Bearer " + token)
        for name, value in headers:
            request.add_header(name, value)
        status, answer = self._call(request)
        return status, (json.loads(answer) if answer else None)

    def read(self, number, token=CONTROL_TOKEN):
        """GET /control/request/{number}: (status, the JSON answer, or None when the body is
        empty, the raw body)."""
        import json
        import urllib.request
        request = urllib.request.Request("%s/control/request/%s" % (self.base, number))
        if token is not None:
            request.add_header("Authorization", "Bearer " + token)
        status, answer = self._call(request)
        return status, (json.loads(answer) if answer else None), answer

    def blocks(self):
        return _blocks(self.out.getvalue())


class _RunningCase(unittest.TestCase):
    """A directory with the keys, a wallet the verifier trusts the issuer of, and the files
    the options name."""

    def setUp(self):
        import json
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-rearm-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        keygen(self.tmp, DEFAULT_HOST)
        self.wallet = Wallet()
        self.jwks = self.tmp / "issuers.json"
        self.jwks.write_text(json.dumps([self.wallet.issuer_jwk]))
        self.path = self.tmp / "result.json"
        self.token_file = self.tmp / "control-token"
        self.token_file.write_text(CONTROL_TOKEN + "\n")
        self.token_file.chmod(0o600)

    def run_serve(self, *extra, **kw):
        return _Running(self, "--issuer-jwks", str(self.jwks), *extra, **kw)

    def read(self):
        import json
        return json.loads(self.path.read_text(encoding="utf-8"))

    def answer(self, run, state, **respond):
        """A wallet's answer to the request `state`, posted: (status, body)."""
        status, jar = run.jar(state)
        self.assertEqual(status, 200, "no such outstanding request")
        return run.respond(self.wallet.respond(jar, **respond))


class ControlEndpointMdocTests(_RunningCase):
    """`serve --format mso_mdoc ... --control-token-file FILE`: an mso_mdoc verifier asks for the
    docType and elements it was built with, so a control body that names claims or credential types
    is refused, 400 invalid_request, and makes no request; an empty body starts one."""

    def test_claims_or_types_in_the_body_are_refused_and_an_empty_body_starts_a_request(self):
        from cryptography.hazmat.primitives import serialization
        root = self.tmp / "iaca.pem"
        root.write_bytes(md.IACA.public_bytes(serialization.Encoding.PEM))
        with _Running(self, "--format", "mso_mdoc", "--experimental", "--doctype", md.MDL,
                      "--iaca-root", str(root), "--claim", MDL_AGE,
                      "--control-token-file", str(self.token_file)) as run:
            self.assertEqual(run.verifier.credential_format, "mso_mdoc")
            before = run.verifier.outstanding()
            for spec in ({"claims": ["family_name"]}, {"vct": ["urn:eudi:pid:1"]},
                         {"claims": ["family_name"], "vct": ["urn:eudi:pid:1"]}):
                with self.subTest(body=sorted(spec)):
                    status, answer = run.control(spec)
                    self.assertEqual(status, 400, answer)
                    self.assertEqual(answer["error"], "invalid_request")
                    self.assertIn("mso_mdoc", answer["error_description"])
                    self.assertEqual(run.verifier.outstanding(), before)
            status, answer = run.control({})
            self.assertEqual(status, 201, answer)
            self.assertEqual(run.verifier.outstanding(), before + 1)


class ALateAcceptanceTests(_RunningCase):
    """`_ResultFile.verdict`: "An acceptance is never judged after the close (the verifier refuses
    it), so one is recorded even when the lifetime ends before this line runs." A response judged
    across the end of its request's lifetime is refused, so `--result` keeps the outcome it had
    and `/done` has no result to show."""

    def test_a_response_judged_across_the_end_of_the_lifetime_changes_neither_result_nor_done(self):
        import json
        import urllib.request
        from unittest import mock
        from polaris_oid4vp import verifier as module
        clock, running = _Clock(self), []
        original = module.verify_presentation

        def aging(*args, **kwargs):
            verdict = original(*args, **kwargs)
            clock.advance(running[0].verifier.request_ttl_seconds + 1)
            return verdict

        running.append(self.run_serve("--once", "--result", str(self.path)))
        with running[0] as run:
            state = _state_of(run.blocks()[0])
            self.assertEqual(self.answer(run, state, nonce="wrong")[0], 400)
            earlier = self.read()
            self.assertEqual((earlier["outcome"], earlier["check"]), ("refused", "nonce"))
            status, jar = run.jar(state)
            self.assertEqual(status, 200, "the refusal closed the request")
            form = self.wallet.respond(jar)
            # The code a close would issue, fixed, so /done can be asked for it.
            with mock.patch.object(module, "verify_presentation", aging), \
                    mock.patch.object(module.secrets, "token_urlsafe", lambda *_: "a-fixed-code"):
                status, body = run.respond(form)
            doc = self.read()
            done, _ = run._call(urllib.request.Request(run.base + "/done?response_code=a-fixed-code"))
            self.assertEqual({key: doc.get(key) for key in ("outcome", "check", "reason")},
                             {key: earlier[key] for key in ("outcome", "check", "reason")})
            self.assertEqual(doc["responses"], 2)
            self.assertEqual(done, 404)
            self.assertEqual((status, json.loads(body)), (400, run.verifier.REFUSAL_BODY))


class RearmTests(_RunningCase):
    """`serve --once --rearm`: when the request closes or expires, the next one starts with the same
    specification and its parameters print exactly as --once prints them."""

    def serve_rearm(self, *extra, **kw):
        return self.run_serve("--once", "--rearm", "--result", str(self.path), *extra, **kw)

    def test_an_accepted_answer_closes_the_request_and_the_next_one_is_printed_before_the_wallet_hears(self):
        with self.serve_rearm() as run:
            (first,) = run.blocks()
            state1 = _state_of(first)
            self.assertEqual(self.read()["request"], 1)
            self.assertNotIn("previous", self.read())
            status, _ = self.answer(run, state1)
            self.assertEqual(status, 200)
            blocks = run.blocks()
            self.assertEqual(len(blocks), 2, "no successor by the time the wallet had its answer")
            state2 = _state_of(blocks[1])
            self.assertNotEqual(state1, state2)
            # Exactly as --once prints it: the same lines, the new request's state in place of the old.
            self.assertEqual(blocks[1].replace(state2, state1), blocks[0])
            self.assertEqual(sorted(_launch_of(blocks[1])), ["eu-eaap", "haip-vp", "openid4vp"])
            doc = self.read()
            self.assertEqual((doc["request"], doc["state"], doc["outcome"], doc["responses"]),
                             (2, state2, "nothing_received", 0))
            self.assertEqual(doc["request_object"], {"served": 0, "refused": 0})
            # The request that closed is no longer outstanding; the next is.
            self.assertEqual(run.jar(state1)[0], 404)
            self.assertEqual(run.jar(state2)[0], 200)
            self.assertIn("  <- 200 authentic", run.out.getvalue())

    def test_the_closed_requests_outcome_is_kept_beside_the_next_in_the_same_write(self):
        with self.serve_rearm() as run:
            state1 = _state_of(run.blocks()[0])
            self.assertEqual(self.answer(run, state1)[0], 200)
            doc = self.read()
            previous = doc["previous"]
            self.assertEqual((previous["request"], previous["state"], previous["outcome"]),
                             (1, state1, "accepted"))
            self.assertEqual(previous["response"], {"status_code": 200})
            self.assertIn("given_name", previous["claims"])
            self.assertEqual((previous["responses"], previous["request_object"]),
                             (1, {"served": 1, "refused": 0}))
            self.assertNotIn("previous", previous, "the history is one request deep")
            # The answer of the third request replaces it with the second's.
            state2 = doc["state"]
            self.assertEqual(self.answer(run, state2, nonce="wrong")[0], 400)
            doc = self.read()
            self.assertEqual((doc["request"], doc["previous"]["request"], doc["previous"]["outcome"],
                              doc["previous"]["check"]), (3, 2, "refused", "nonce"))

    def test_a_refusal_closes_the_request_under_rearm_and_starts_the_next(self):
        with self.serve_rearm() as run:
            state1 = _state_of(run.blocks()[0])
            status, _ = self.answer(run, state1, nonce="wrong")
            self.assertEqual(status, 400)
            blocks = run.blocks()
            self.assertEqual(len(blocks), 2)
            doc = self.read()
            self.assertEqual((doc["request"], doc["state"]), (2, _state_of(blocks[1])))
            self.assertNotEqual(doc["state"], state1)
            self.assertEqual((doc["previous"]["outcome"], doc["previous"]["check"]), ("refused", "nonce"))
            self.assertEqual(run.jar(state1)[0], 404)
            self.assertIn("  <- 400 refused: nonce", run.out.getvalue())

    def test_a_wallets_error_response_closes_the_request_under_rearm_too(self):
        with self.serve_rearm() as run:
            state1 = _state_of(run.blocks()[0])
            status, jar = run.jar(state1)
            self.assertEqual(run.respond(self.wallet.respond_error(jar))[0], 200)
            self.assertEqual(len(run.blocks()), 2)
            doc = self.read()
            self.assertEqual((doc["request"], doc["previous"]["outcome"]), (2, "wallet_error"))

    def test_without_rearm_a_refusal_and_a_wallet_error_leave_the_request_open_as_before(self):
        with self.run_serve("--once", "--result", str(self.path)) as run:
            state1 = _state_of(run.blocks()[0])
            self.assertEqual(self.answer(run, state1, nonce="wrong")[0], 400)
            status, jar = run.jar(state1)
            self.assertEqual(status, 200, "a refusal closed the request without --rearm")
            self.assertEqual(run.respond(self.wallet.respond_error(jar))[0], 200)
            self.assertEqual(run.jar(state1)[0], 200)
            self.assertEqual(len(run.blocks()), 1)
            self.assertNotIn("request", self.read())
            self.assertNotIn("previous", self.read())

    def test_an_answer_about_no_request_closes_nothing(self):
        with self.serve_rearm() as run:
            state1 = _state_of(run.blocks()[0])
            for form in ({"response": ["not.a.compact.jwe.token"]}, {}, {"error": ["access_denied"],
                                                                         "state": ["nonsense"]}):
                self.assertEqual(run.respond(form)[0], 400)
            self.assertEqual(len(run.blocks()), 1)
            self.assertEqual(run.jar(state1)[0], 200)
            doc = self.read()
            self.assertEqual((doc["request"], doc["state"], doc["responses"]), (1, state1, 0))

    def test_a_request_that_expires_is_replaced_with_no_wallet_asking(self):
        with self.serve_rearm(ttl=0.4) as run:
            state1 = _state_of(run.blocks()[0])
            _until(self, lambda: len(run.blocks()) >= 2, "the request that expired to be replaced")
            blocks = run.blocks()
            state2 = _state_of(blocks[1])
            self.assertNotEqual(state1, state2)
            self.assertEqual(blocks[1].replace(state2, state1), blocks[0])
            # An idle server keeps starting one each time one expires.
            _until(self, lambda: len(run.blocks()) >= 3, "the next to expire to be replaced")
            doc = self.read()
            self.assertGreaterEqual(doc["request"], 3)
            self.assertEqual(doc["previous"]["request"], doc["request"] - 1)
            self.assertEqual(doc["previous"]["outcome"], "nothing_received")
            self.assertEqual(run.jar(state1)[0], 404)

    def test_each_expiry_starts_one_successor_and_never_two_outstanding(self):
        seen = []
        with self.serve_rearm(ttl=0.3) as run:
            def settled():
                seen.append(run.verifier.outstanding())
                return len(run.blocks()) >= 4
            _until(self, settled, "four requests")
        self.assertEqual(max(seen), 1, "two requests were outstanding at once")
        states = [_state_of(b) for b in _blocks(run.out.getvalue())]
        self.assertEqual(len(states), len(set(states)))

    def test_a_late_answer_for_the_closed_request_touches_nothing_of_the_current_one(self):
        with self.serve_rearm() as run:
            state1 = _state_of(run.blocks()[0])
            status, jar1 = run.jar(state1)
            late = self.wallet.respond(jar1)
            wrong = self.wallet.respond(jar1, nonce="wrong")
            self.assertEqual(run.respond(late)[0], 200)
            state2 = self.read()["state"]
            before = self.path.read_text(encoding="utf-8")
            for form in (late, wrong, self.wallet.respond_error(jar1)):
                self.assertEqual(run.respond(form)[0], 400, form)
            self.assertEqual(run.jar(state1)[0], 404)
            self.assertEqual(self.path.read_text(encoding="utf-8"), before,
                             "a late answer changed the current request's result")
            doc = self.read()
            self.assertEqual((doc["state"], doc["outcome"], doc["responses"]), (state2, "nothing_received", 0))
            self.assertEqual(doc["previous"]["responses"], 1)
            self.assertEqual(len(run.blocks()), 2, "a late answer started another request")
            # The current request is still answerable.
            self.assertEqual(self.answer(run, state2)[0], 200)
            self.assertEqual(self.read()["request"], 3)

    def test_a_fetch_of_the_current_request_refused_for_its_wallet_nonce_is_counted_for_it(self):
        # request_uri_method=post: a wallet_nonce out of bounds is answered 400 before the
        # request object is made, which is a refused fetch of the request the URI names.
        import urllib.request
        with self.serve_rearm() as run:
            state = _state_of(run.blocks()[0])
            fetch = urllib.request.Request("%s/request.jwt?state=%s" % (run.base, state),
                                           data=b"wallet_nonce=" + b"n" * 1025, method="POST")
            self.assertEqual(run._call(fetch)[0], 400)
            self.assertEqual(self.read()["request_object"], {"served": 0, "refused": 1})
            self.assertEqual(run.jar(state)[0], 200)
            self.assertEqual(self.read()["request_object"], {"served": 1, "refused": 1})

    def test_only_the_current_requests_fetches_are_counted_for_it(self):
        with self.serve_rearm() as run:
            state1 = _state_of(run.blocks()[0])
            self.assertEqual(run.jar(state1)[0], 200)
            self.assertEqual(self.read()["request_object"], {"served": 1, "refused": 0})
            self.assertEqual(self.answer(run, state1)[0], 200)
            state2 = self.read()["state"]
            self.assertEqual(run.jar(state1)[0], 404)
            self.assertEqual(self.read()["request_object"], {"served": 0, "refused": 0})
            self.assertEqual(run.jar(state2)[0], 200)
            self.assertEqual(self.read()["request_object"], {"served": 1, "refused": 0})

    def test_the_specification_is_the_same_each_time(self):
        import json
        info = {"type": "urn:eudi:sca:payment:1", "credential_ids": ["pay"],
                "payload": {"transaction_id": "polaris-test-0001",
                            "payee": {"name": "Example Shop", "id": "DE00EXAMPLE0001"},
                            "currency": "EUR", "amount": 49.99}}
        data = self.tmp / "transaction-data.json"
        data.write_text(json.dumps([info]))
        with self.serve_rearm("--claim", "family_name", "--vct", "urn:example:own:1",
                              "--credential-query-id", "pay", "--transaction-data", str(data)) as run:
            state1 = _state_of(run.blocks()[0])
            status, jar1 = run.jar(state1)
            self.assertEqual(status, 200)
            # Closed by a refusal; the answer's own merits do not matter here.
            self.assertEqual(run.respond(self.wallet.respond(jar1, nonce="wrong"))[0], 400)
            state2 = _state_of(run.blocks()[1])
            status, jar2 = run.jar(state2)
            self.assertEqual(status, 200)
            first, second = Wallet.read_request(jar1)[1], Wallet.read_request(jar2)[1]
            query = second["dcql_query"]["credentials"][0]
            self.assertEqual((query["id"], query["claims"], query["meta"]["vct_values"]),
                             ("pay", [{"path": ["family_name"]}], ["urn:example:own:1"]))
            self.assertEqual(second["dcql_query"], first["dcql_query"])
            self.assertEqual(len(second["transaction_data"]), 1)
            self.assertEqual(second["transaction_data"], first["transaction_data"])
            self.assertEqual(run.out.getvalue().count("the request object carries 1 transaction_data"), 2)

    def test_the_race_between_a_closing_answer_and_the_expiry_starts_one_successor(self):
        """Real threads, released together at the one request: eight take the closing answer's path
        and eight the timer's. Whichever is first starts the next; the rest find the request they
        were about already closed."""
        import threading
        from polaris_oid4vp import cli
        verifier = verifier_from(self.tmp, "verifier.test", 0)
        announced = []
        requests = cli._Requests(verifier, None, None, rearm=True, announce=announced.append)
        try:
            requests.start()
            for round_ in range(25):
                state = requests.current_state()
                gate = threading.Barrier(16)
                errors = []

                def close():
                    try:
                        gate.wait(10)
                        requests.close(state)
                    except BaseException as exc:  # noqa: BLE001
                        errors.append(exc)

                def expire():
                    try:
                        gate.wait(10)
                        requests.expired(state)
                    except BaseException as exc:  # noqa: BLE001
                        errors.append(exc)

                threads = [threading.Thread(target=close if n % 2 else expire) for n in range(16)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(30)
                self.assertEqual(errors, [])
                self.assertEqual(len(announced), round_ + 1, "round %d: not one successor" % round_)
                self.assertEqual(verifier.outstanding(), 1)
                self.assertNotEqual(requests.current_state(), state)
        finally:
            requests.stop()

    def test_a_timer_for_a_request_that_closed_starts_nothing(self):
        from polaris_oid4vp import cli
        verifier = verifier_from(self.tmp, "verifier.test", 0)
        announced = []
        requests = cli._Requests(verifier, None, None, rearm=True, announce=announced.append)
        try:
            first = requests.start()
            requests.close(first.session.state)
            self.assertEqual(len(announced), 1)
            requests.expired(first.session.state)
            requests.close(first.session.state)
            self.assertEqual(len(announced), 1)
            self.assertEqual(verifier.outstanding(), 1)
        finally:
            requests.stop()

    def test_stopping_the_command_stops_the_timer(self):
        import threading
        before = threading.active_count()
        with self.serve_rearm(ttl=60) as run:
            self.assertEqual(len(run.blocks()), 1)
        self.assertEqual(run.rc, 0)
        _until(self, lambda: threading.active_count() <= before, "the timer thread to end")


class RearmRefusalTests(_RunningCase):

    _serve = ServeCommandHeldOutTests._serve

    def refused(self, *extra, says):
        rc, seen, _, err = self._serve("--issuer-jwks", str(self.jwks), *extra)
        self.assertEqual(rc, 2, err)
        self.assertNotIn("kwargs", seen, "it listened")
        for text in says:
            self.assertIn(text, err)
        return err

    def test_rearm_without_once_is_refused(self):
        self.refused("--rearm", says=["--rearm", "--once"])
        self.refused("--rearm", "--result", str(self.path), says=["--rearm", "--once"])

    def test_rearm_beside_a_control_token_file_is_refused(self):
        err = self.refused("--once", "--rearm", "--control-token-file", str(self.token_file),
                           says=["--rearm", "--control-token-file"])
        self.assertNotIn(CONTROL_TOKEN, err)

    def test_rearm_with_once_starts(self):
        rc, seen, out, _ = self._serve("--issuer-jwks", str(self.jwks), "--once", "--rearm")
        self.assertEqual(rc, 0)
        self.assertEqual(len(_blocks(out)), 1)
        self.assertEqual(len(seen["verifier"]._sessions), 1)

    def test_the_help_says_what_rearm_and_the_control_file_do_and_that_they_do_not_combine(self):
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            main(["serve", "--help"])
        # argparse wraps at a hyphen, so an option name can break across two lines.
        text = " ".join(out.getvalue().split()).replace("- ", "-")
        for phrase in ("--rearm", "--control-token-file",
                       "an idle server starts and prints a new request each time one expires",
                       "with neither --rearm nor --control-token-file a refusal leaves the request open",
                       "ends at an answer",
                       "refused with --control-token-file", "refused with --rearm",
                       "POST /control/request", "at most 64"):
            self.assertIn(phrase, text)


class ControlEndpointCommandTests(_RunningCase):
    """`serve --control-token-file FILE`: POST /control/request starts a request and answers with
    its launch parameters."""

    def serve_control(self, *extra, **kw):
        return self.run_serve("--control-token-file", str(self.token_file), *extra, **kw)

    def test_a_request_is_started_and_answered_with_what_once_prints(self):
        with self.run_serve("--once", "--control-token-file", str(self.token_file)) as run:
            (printed,) = run.blocks()
            state1 = _state_of(printed)
            status, answer = run.control({})
            self.assertEqual(status, 201)
            self.assertEqual(sorted(answer), ["client_id", "launch", "request", "request_uri", "state"])
            self.assertEqual(answer["request"], 2, "the --once request is request 1")
            state2 = answer["state"]
            self.assertNotEqual(state1, state2)
            # The same values, from the same function: what --once prints for request 1, with request
            # 2's state in place of request 1's, is what the answer carries.
            expected = {scheme: link.replace(state1, state2) for scheme, link in _launch_of(printed).items()}
            self.assertEqual(answer["launch"], expected)
            # And each link is what a wallet is launched with: the three parameters of that request.
            import urllib.parse
            for scheme, link in answer["launch"].items():
                self.assertEqual(urllib.parse.parse_qs(link.split("://?", 1)[1], strict_parsing=True),
                                 {"client_id": [answer["client_id"]],
                                  "request_uri": [answer["request_uri"]],
                                  "request_uri_method": ["post"]}, scheme)
            self.assertEqual(answer["client_id"], run.verifier.client_id)
            self.assertEqual(answer["request_uri"], "%s?state=%s" % (run.verifier.request_uri, state2))
            for line in printed.splitlines():
                parts = line.split()
                if parts and parts[0] in ("client_id", "request_uri"):
                    self.assertEqual(parts[1].replace(state1, state2), answer[parts[0]])
            # Nothing of it is printed for the harness's request: the answer is where it goes.
            self.assertEqual(len(run.blocks()), 1)
            self.assertEqual(run.jar(state2)[0], 200)

    def test_with_no_body_the_request_has_this_commands_own_specification(self):
        with self.serve_control("--claim", "family_name", "--claim", "age_equal_or_over.18=true",
                                "--vct", "urn:example:own:1") as run:
            for body, kwargs in ((None, {}), ({}, {}), (None, {"raw": b"   "})):
                status, answer = run.control(body, **kwargs)
                self.assertEqual(status, 201)
                _, claims = Wallet.read_request(run.jar(answer["state"])[1])
                query = claims["dcql_query"]["credentials"][0]
                self.assertEqual(query["claims"], [{"path": ["family_name"]},
                                                   {"path": ["age_equal_or_over", "18"],
                                                    "values": [True]}])
                self.assertEqual(query["meta"]["vct_values"], ["urn:example:own:1"])

    def test_claims_and_types_in_the_body_reach_the_request_object(self):
        with self.serve_control("--claim", "family_name") as run:
            status, answer = run.control({"claims": ["birthdate", "age_equal_or_over.21=true",
                                                     '["address","locality"]'],
                                          "vct": ["urn:example:other:1", "urn:example:other:2"]})
            self.assertEqual(status, 201, answer)
            _, claims = Wallet.read_request(run.jar(answer["state"])[1])
            query = claims["dcql_query"]["credentials"][0]
            self.assertEqual(query["claims"], [{"path": ["birthdate"]},
                                               {"path": ["age_equal_or_over", "21"], "values": [True]},
                                               {"path": ["address", "locality"]}])
            self.assertEqual(query["meta"]["vct_values"], ["urn:example:other:1", "urn:example:other:2"])
            # Only that request: the next one with no body is the command's own again.
            _, plain = Wallet.read_request(run.jar(run.control({})[1]["state"])[1])
            self.assertEqual(plain["dcql_query"]["credentials"][0]["claims"], [{"path": ["family_name"]}])
            self.assertEqual(plain["dcql_query"]["credentials"][0]["meta"]["vct_values"],
                             ["urn:eudi:pid:1"])

    def test_each_claim_is_validated_by_the_function_that_validates_dash_dash_claim(self):
        bad = ["[unclosed", '["a",1]', "a..b", "a.", '[]', "=5", '["a"]x']
        for text in bad:
            with self.assertRaises(ValueError, msg=text):
                parse_claim(text)
        with self.serve_control() as run:
            for text in bad:
                with self.subTest(claim=text):
                    try:
                        parse_claim(text)
                    except ValueError as exc:
                        reason = str(exc)
                    status, answer = run.control({"claims": ["given_name", text]})
                    self.assertEqual(status, 400, answer)
                    self.assertEqual(answer["error"], "invalid_request")
                    self.assertIn(reason, answer["error_description"])
            self.assertEqual(run.verifier.outstanding(), 0, "a refused request was started")

    def test_a_body_that_is_not_what_a_request_is_made_of_is_400_and_starts_nothing(self):
        with self.serve_control() as run:
            cases = [({"flavour": 1}, "flavour"), ({"claims": ["a"], "colour": 1}, "colour"),
                     ({"claims": "given_name"}, "claims"), ({"claims": []}, "claims"),
                     ({"claims": {"path": ["given_name"]}}, "claims"),
                     ({"claims": [7]}, "claims"), ({"claims": [["given_name"]]}, "claims"),
                     ({"claims": [{"path": ["a"]}]}, "claims"), ({"claims": [None]}, "claims"),
                     ({"vct": "urn:example:x"}, "vct"), ({"vct": []}, "vct"),
                     ({"vct": [1]}, "vct"), ({"vct": [None]}, "vct")]
            for body, names in cases:
                with self.subTest(body=body):
                    status, answer = run.control(body)
                    self.assertEqual(status, 400, answer)
                    self.assertIn(names, answer["error_description"])
            self.assertEqual(run.control(raw=b"[]")[0], 400)
            self.assertEqual(run.verifier.outstanding(), 0)

    def test_a_request_is_judged_by_its_own_claims_for_its_whole_life(self):
        with self.serve_control() as run:
            narrow = [run.control({"claims": ["given_name"]})[1] for _ in range(2)]
            plain = [run.control({})[1] for _ in range(2)]
            # Satisfies the command's own two names; the narrow request selected one: refused.
            status, _ = self.answer(run, narrow[0]["state"])
            self.assertEqual(status, 400)
            self.assertIn("  <- 400 refused: claims: ", run.out.getvalue())
            self.assertIn("family_name", run.out.getvalue())
            # Satisfies the narrow request and not the command's own: accepted by the one, refused by the other.
            status, _ = self.answer(run, narrow[1]["state"], withhold=("family_name",))
            self.assertEqual(status, 200)
            self.assertEqual(self.answer(run, plain[0]["state"], withhold=("family_name",))[0], 400)
            self.assertEqual(self.answer(run, plain[1]["state"])[0], 200)

    def test_a_request_asking_beyond_the_registration_certificate_is_refused_as_startup_would(self):
        import json
        info = dict(verifier_info_vectors())["accept-control.json"]["verifier_info"]
        path = self.tmp / "verifier-info.json"
        path.write_text(json.dumps(info))
        with self.serve_control("--verifier-info-profile", "etsi-119472-2",
                                "--verifier-info", str(path)) as run:
            self.assertIn("the request asks for no more than its registration certificate registers",
                          run.out.getvalue())
            status, answer = run.control({"claims": ["given_name", "birthdate"]})
            self.assertEqual(status, 400, answer)
            self.assertIn("the over-asking check refuses this request", answer["error_description"])
            self.assertIn("birthdate", answer["error_description"])
            self.assertEqual(run.verifier.outstanding(), 0)
            self.assertEqual(run.control({"claims": ["given_name"]})[0], 201)

    def test_the_65th_outstanding_request_is_429_until_one_ends(self):
        with self.serve_control() as run:
            states = []
            for n in range(64):
                status, answer = run.control({})
                self.assertEqual(status, 201, "request %d: %s" % (n + 1, answer))
                states.append(answer["state"])
            status, answer = run.control({})
            self.assertEqual(status, 429, answer)
            self.assertEqual(answer["error"], "too_many_requests")
            self.assertEqual(run.verifier.outstanding(), 64)
            # One expires: a new one is made. One closes: so is another.
            run.verifier._sessions[states[0]].created -= run.verifier.request_ttl_seconds + 1
            self.assertEqual(run.control({})[0], 201)
            self.assertEqual(run.control({})[0], 429)
            self.assertEqual(self.answer(run, states[1])[0], 200)
            self.assertEqual(run.control({})[0], 201)
            self.assertEqual(run.control({})[0], 429)

    def test_the_request_made_at_startup_counts_toward_the_64(self):
        with self.run_serve("--once", "--control-token-file", str(self.token_file)) as run:
            statuses = [run.control({})[0] for _ in range(64)]
            self.assertEqual(statuses, [201] * 63 + [429])

    def test_control_requests_made_while_the_command_starts_count_the_once_request(self):
        # 2026-11-18: the listener accepts from the moment serve() returns, and the request
        # --once starts is made later, where it is announced. So 64 control requests in that
        # moment and then the command's own were 65 outstanding. A place is held for it now.
        statuses = []

        def at_listening(kwargs):
            statuses.extend(kwargs["on_control"]({})[0] for _ in range(64))

        with self.run_serve("--once", "--control-token-file", str(self.token_file),
                            listening=at_listening) as run:
            self.assertEqual(statuses, [201] * 63 + [429])
            self.assertEqual(run.verifier.outstanding(), 64)

    def test_sixty_five_at_once_make_exactly_sixty_four(self):
        import threading
        with self.serve_control() as run:
            # Making a request takes a moment here, as it does with a slow key store, so a count
            # taken apart from the making would let every caller through before any had been made.
            make = run.verifier.new_request

            def slow(*args, **kwargs):
                threading.Event().wait(0.01)
                return make(*args, **kwargs)

            run.verifier.new_request = slow
            gate, statuses = threading.Barrier(65), []

            # Each caller goes straight to the function the listener hands a control request to,
            # the one that counts and makes under one lock: 65 connections opened in the same
            # instant would wait on the listener's accept queue, not on that lock.
            control = run.kwargs["on_control"]

            def post():
                gate.wait(30)
                statuses.append(control({})[0])

            threads = [threading.Thread(target=post) for _ in range(65)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(60)
            self.assertEqual(sorted(statuses), [201] * 64 + [429])
            self.assertEqual(run.verifier.outstanding(), 64)

    def test_it_needs_no_once_and_the_option_off_starts_no_endpoint(self):
        with self.serve_control() as run:
            self.assertEqual(run.verifier.outstanding(), 0)
            self.assertEqual(run.control({})[1]["request"], 1)
            self.assertEqual(run.control({})[1]["request"], 2)
        with self.run_serve() as run:
            self.assertIsNone(run.kwargs["control_token"])
            self.assertIsNone(run.kwargs["on_control"])
            status, answer = run.control({})
            self.assertEqual((status, answer), (404, {"error": "not_found"}))

    def test_a_wrong_token_starts_nothing_and_the_token_is_never_printed(self):
        with self.serve_control("--verbose") as run:
            for token in (None, "x" * len(CONTROL_TOKEN), CONTROL_TOKEN[:-1] + "x"):
                self.assertEqual(run.control({"claims": ["do-not-log-this-claim"]}, token=token)[0], 401)
            self.assertEqual(run.control({"claims": ["do-not-log-this-claim"]})[0], 201)
            self.assertEqual(run.verifier.outstanding(), 1)
        for text in (run.out.getvalue(), run.err.getvalue()):
            self.assertNotIn(CONTROL_TOKEN, text)
            self.assertNotIn("do-not-log-this-claim", text)
            self.assertNotIn("Bearer", text)

    def test_no_cors_header_on_the_control_path_under_cors_origin_star(self):
        import urllib.error
        import urllib.request
        with self.serve_control("--cors-origin", "*") as run:
            request = urllib.request.Request(run.base + "/control/request", data=b"{}", method="POST")
            request.add_header("Authorization", "Bearer " + CONTROL_TOKEN)
            request.add_header("Origin", "https://wallet.example")
            with urllib.request.urlopen(request, timeout=20) as answer:
                self.assertEqual(answer.status, 201)
                names = [name.lower() for name, _ in answer.headers.items()]
            self.assertEqual([n for n in names if n.startswith("access-control-") or n == "vary"], [])
            # The twin: the request URI of the same listener carries them.
            request = urllib.request.Request(run.base + "/request.jwt?state=x")
            request.add_header("Origin", "https://wallet.example")
            try:
                urllib.request.urlopen(request, timeout=20)
            except urllib.error.HTTPError as err:
                self.assertEqual(err.headers.get("Access-Control-Allow-Origin"), "*")


class ControlAnswerEndsTheRequestTests(_RunningCase):
    """A request the control endpoint started ends at an answer at the response URI, accepted,
    refused or a wallet's error response: the rule `--rearm` has for the current request. A refusal
    then frees its place among the 64, and a second presentation to it is refused as one to a request
    that has closed. The plain single request keeps its rule: a refusal leaves it open."""

    def serve_control(self, *extra, **kw):
        return self.run_serve("--control-token-file", str(self.token_file), *extra, **kw)

    def test_seventy_refused_requests_in_one_lifetime_never_see_429(self):
        with self.serve_control() as run:
            for n in range(70):
                status, answer = run.control({})
                self.assertEqual(status, 201, "request %d: %s" % (n + 1, answer))
                self.assertEqual(self.answer(run, answer["state"], nonce="wrong")[0], 400)
            self.assertEqual(run.verifier.outstanding(), 0)

    def test_a_second_presentation_is_refused_as_closed_whatever_the_first_answer_was(self):
        with self.serve_control() as run:
            for first in ("accepted", "refused", "wallet error"):
                with self.subTest(first=first):
                    state = run.control({})[1]["state"]
                    status, jar = run.jar(state)
                    self.assertEqual(status, 200)
                    forms = {"accepted": self.wallet.respond(jar),
                             "refused": self.wallet.respond(jar, nonce="wrong"),
                             "wallet error": self.wallet.respond_error(jar)}
                    again = self.wallet.respond(jar)
                    self.assertEqual(run.respond(forms[first])[0], 200 if first != "refused" else 400)
                    before = run.out.getvalue()
                    self.assertEqual(run.respond(again)[0], 400)
                    self.assertEqual(run.jar(state)[0], 404)
                    # The refusal --rearm gives for the answer to a request that has closed.
                    line = run.out.getvalue()[len(before):]
                    self.assertTrue(line.startswith("  <- 400 refused: invalid_request: "), line)
                    self.assertIn("answers a request that has expired", line)

    def test_an_answer_about_no_request_ends_no_control_request(self):
        with self.serve_control() as run:
            state = run.control({})[1]["state"]
            for form in ({"response": ["not.a.compact.jwe.token"]}, {},
                         {"error": ["access_denied"], "state": ["nonsense"]}):
                self.assertEqual(run.respond(form)[0], 400)
            self.assertEqual(run.jar(state)[0], 200)
            self.assertEqual(run.verifier.outstanding(), 1)

    def test_an_answer_ends_the_request_it_was_about_and_not_the_newest(self):
        with self.serve_control() as run:
            first, second = (run.control({})[1]["state"] for _ in range(2))
            self.assertEqual(self.answer(run, first, nonce="wrong")[0], 400)
            self.assertEqual((run.jar(first)[0], run.jar(second)[0]), (404, 200))

    def test_the_plain_request_keeps_its_rule_a_refusal_leaves_it_open(self):
        for control in (False, True):
            with self.subTest(control=control):
                args = ["--once"] + (["--control-token-file", str(self.token_file)] if control else [])
                with self.run_serve(*args) as run:
                    state = _state_of(run.blocks()[0])
                    self.assertEqual(self.answer(run, state, nonce="wrong")[0], 400)
                    self.assertEqual(self.answer(run, state, nonce="wrong")[0], 400)
                    status, jar = run.jar(state)
                    self.assertEqual(status, 200, "a refusal ended the request --once started")
                    self.assertEqual(run.respond(self.wallet.respond(jar))[0], 200)
                    self.assertEqual(run.verifier.outstanding(), 0)

    def test_what_is_kept_of_the_requests_it_started_holds_only_the_outstanding(self):
        with self.serve_control() as run:
            for state in [run.control({})[1]["state"] for _ in range(3)]:
                run.verifier._sessions[state].created -= run.verifier.request_ttl_seconds + 1
            run.control({})
            started = run.kwargs["on_control"].__self__
            self.assertEqual(len(started._ends_on_answer), 1)

    def test_the_bound_still_holds_for_requests_nobody_has_answered(self):
        with self.serve_control() as run:
            statuses = [run.control({})[0] for _ in range(65)]
            self.assertEqual(statuses, [201] * 64 + [429])


class AnAnswerLineNamesItsRequestTests(_RunningCase):
    """With `--rearm` or `--control-token-file` more than one request can be open, so each line
    `serve` prints for an answer at the response URI ends with the request it was about; the
    newest is not assumed."""

    def lines(self, run):
        return [x for x in run.out.getvalue().splitlines() if x.startswith("  <- ")]

    def test_with_two_open_the_line_names_the_request_answered_and_not_the_newest(self):
        with self.run_serve("--control-token-file", str(self.token_file)) as run:
            a = run.control({"claims": ["given_name"]})[1]
            b = run.control({"claims": ["family_name"]})[1]
            self.assertNotEqual(a["state"], b["state"])
            status, _ = self.answer(run, a["state"], withhold=("family_name",))
            self.assertEqual(status, 200)
            (line,) = self.lines(run)
            self.assertTrue(line.startswith("  <- 200 authentic, claims "), line)
            self.assertTrue(line.endswith(" (request %s)" % a["state"]), line)
            self.assertNotIn(b["state"], line)

    def test_a_refusal_names_its_request_and_an_answer_about_none_says_so(self):
        with self.run_serve("--control-token-file", str(self.token_file)) as run:
            a = run.control({})[1]
            run.control({})
            self.assertEqual(self.answer(run, a["state"], nonce="wrong")[0], 400)
            self.assertEqual(run.respond({"response": "not-a-response"})[0], 400)
            first, second = self.lines(run)
            self.assertTrue(first.startswith("  <- 400 refused: nonce: "), first)
            self.assertTrue(first.endswith(" (request %s)" % a["state"]), first)
            self.assertTrue(second.startswith("  <- 400 refused: "), second)
            self.assertTrue(second.endswith(" (request not known)"), second)

    def test_with_two_open_the_stderr_refusal_names_the_request_refused_and_not_the_newest(self):
        with self.run_serve("--control-token-file", str(self.token_file)) as run:
            a = run.control({})[1]
            b = run.control({})[1]
            self.assertEqual(self.answer(run, a["state"], nonce="wrong")[0], 400)
            (line,) = [x for x in run.err.getvalue().splitlines() if x.startswith("polaris-oid4vp: refused: ")]
            self.assertTrue(line.startswith("polaris-oid4vp: refused: nonce: "), line)
            self.assertTrue(line.endswith(" (request %s)" % a["state"]), line)
            self.assertNotIn(b["state"], line)

    def test_with_two_open_the_stderr_wallet_error_names_the_request_it_answered(self):
        with self.run_serve("--control-token-file", str(self.token_file)) as run:
            a = run.control({})[1]
            b = run.control({})[1]
            status, jar = run.jar(a["state"])
            self.assertEqual(status, 200)
            self.assertEqual(run.respond(self.wallet.respond_error(jar))[0], 200)
            (line,) = [x for x in run.err.getvalue().splitlines() if x.startswith("polaris-oid4vp: wallet error: ")]
            self.assertTrue(line.endswith(" (request %s)" % a["state"]), line)
            self.assertNotIn(b["state"], line)

    def test_with_one_request_the_stderr_refusal_names_none(self):
        with self.run_serve("--once") as run:
            state = _state_of(run.blocks()[0])
            self.assertEqual(self.answer(run, state, nonce="wrong")[0], 400)
            (line,) = [x for x in run.err.getvalue().splitlines() if x.startswith("polaris-oid4vp: refused: ")]
            self.assertTrue(line.startswith("polaris-oid4vp: refused: nonce: "), line)
            self.assertNotIn(" (request", line)

    def test_under_rearm_a_line_names_the_request_it_answered(self):
        with self.run_serve("--once", "--rearm", "--result", str(self.path)) as run:
            state1 = _state_of(run.blocks()[0])
            self.assertEqual(self.answer(run, state1)[0], 200)
            (line,) = self.lines(run)
            self.assertTrue(line.endswith(" (request %s)" % state1), line)


class TheOnceRequestIsMadeWhereItIsAnnounced(_RunningCase):
    """2026-11-18: the control path holds a place among the 64 for the request --once starts
    from before the listener accepts anything. The request itself is made where it is announced,
    so its lifetime, its signed request object, its --result entry and its --rearm timer start
    there, however long the command takes to get there."""

    def refused_at_listen(self, *extra, made=None):
        import contextlib
        import io
        import json
        import socket
        from unittest import mock
        from polaris_oid4vp import cli
        real = cli._Requests

        def recording(*args, **kwargs):
            requests = real(*args, **kwargs)
            if made is not None:
                made.append(requests)
            return requests

        taken = socket.socket()
        self.addCleanup(taken.close)
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        out = io.StringIO()
        with mock.patch.object(cli.time, "sleep", side_effect=AssertionError("it listened")), \
                mock.patch.object(cli, "_Requests", recording), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(OSError):
                main(["serve", "--pki", str(self.tmp), "--host", "verifier.test",
                      "--bind", "127.0.0.1", "--port", str(taken.getsockname()[1]),
                      "--no-local-tls", "--issuer-jwks", str(self.jwks), "--once",
                      "--result", str(self.path), *extra])
        return json.loads(self.path.read_text(encoding="utf-8")), out.getvalue()

    def test_a_port_that_is_taken_leaves_the_result_file_naming_no_request(self):
        doc, out = self.refused_at_listen()
        self.assertIsNone(doc["state"])
        self.assertEqual(doc["outcome"], "nothing_received")
        self.assertNotIn("://?", out)

    def test_so_it_does_with_the_control_endpoint(self):
        doc, out = self.refused_at_listen("--control-token-file", str(self.token_file))
        self.assertIsNone(doc["state"])
        self.assertEqual(doc["request"], 0)
        self.assertNotIn("://?", out)

    def test_a_port_that_is_taken_gives_back_the_place_held_for_the_request(self):
        made = []
        self.refused_at_listen("--control-token-file", str(self.token_file), made=made)
        (requests,) = made
        self.assertEqual(requests.verifier.outstanding(), 0)
        # All 64 places are open again: none is held for a request that will not be made.
        self.assertEqual([requests.control({})[0] for _ in range(65)], [201] * 64 + [429])

    def test_a_port_that_is_taken_under_rearm_leaves_nothing_running(self):
        import contextlib
        import io
        import json
        import socket
        import threading
        from unittest import mock
        from polaris_oid4vp import cli
        real = cli.verifier_from

        def short(*a, **k):
            v = real(*a, **k)
            v.request_ttl_seconds = 0.2
            return v

        taken = socket.socket()
        self.addCleanup(taken.close)
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        out = io.StringIO()
        with mock.patch.object(cli, "verifier_from", short), \
                mock.patch.object(cli.time, "sleep", side_effect=AssertionError("it listened")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(OSError):
                main(["serve", "--pki", str(self.tmp), "--host", "verifier.test",
                      "--bind", "127.0.0.1", "--port", str(taken.getsockname()[1]),
                      "--no-local-tls", "--issuer-jwks", str(self.jwks), "--once", "--rearm",
                      "--result", str(self.path)])
            threading.Event().wait(0.8)
        doc = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertIsNone(doc["state"], doc)
        self.assertNotIn("://?", out.getvalue())

    def test_the_place_is_given_back_in_the_step_that_makes_the_request(self):
        # Given back first and made after, a control request between the two takes the 64th
        # place and the request then makes 65. Threads switch every microsecond here, so that gap
        # is reached in a few rounds of the 600: each fills the endpoint, holds the place, and
        # makes the request while eight threads ask for one until it is made.
        import sys
        import threading
        from unittest import mock
        from polaris_oid4vp import cli
        made, real = [], cli._Requests

        def recording(*args, **kwargs):
            made.append(real(*args, **kwargs))
            return made[-1]

        with mock.patch.object(cli, "_Requests", recording), \
                self.run_serve("--once", "--control-token-file", str(self.token_file)) as run:
            (requests,) = made
            self.assertEqual([requests.control({})[0] for _ in range(62)], [201] * 62)
            counts, interval = [], sys.getswitchinterval()
            sys.setswitchinterval(1e-6)
            try:
                for _ in range(600):
                    requests.reserve()
                    gate, extra, done = threading.Barrier(9), [], threading.Event()

                    def knock():
                        gate.wait(10)
                        while not done.is_set():
                            status, answer = requests.control({})
                            if status == 201:
                                extra.append(answer["state"])

                    threads = [threading.Thread(target=knock) for _ in range(8)]
                    for thread in threads:
                        thread.start()
                    gate.wait(10)
                    started = requests.start(reserved=True)
                    done.set()
                    for thread in threads:
                        thread.join(10)
                    counts.append(run.verifier.outstanding())
                    for state in [started.session.state, *extra]:
                        run.verifier.close_request(state)
            finally:
                sys.setswitchinterval(interval)
            over = sum(count > 64 for count in counts)
            self.assertEqual((over, max(counts)), (0, 64), "%d of 600 rounds over 64" % over)

    # A start held up at its first printed line (stdout a pipe nobody reads yet) for longer than
    # a request's lifetime. The test's clock (_Clock) stands in for the wait: the hold moves it
    # past the lifetime, which runs every timer that came due, then makes a call that sweeps
    # ended requests (every fetch and control call makes one). What the wallet is served is read
    # from the request object itself: its iat and exp.

    def assert_served_from(self, run, state, clock):
        status, text = run.jar(state)
        self.assertEqual(status, 200, text)
        now = int(clock.now)
        self.assertEqual(_object_times(text), (now, now + run.verifier.request_ttl_seconds))

    def test_a_start_held_up_past_the_lifetime_serves_a_request_from_its_announce(self):
        clock, running = _Clock(self), []

        def held():
            clock.advance(running[0].verifier.request_ttl_seconds + 1)
            running[0].verifier.outstanding()

        running.append(self.run_serve("--once", held_at=("serving on", held)))
        with running[0] as run:
            state = _state_of(run.blocks()[-1])
            self.assert_served_from(run, state, clock)
            # One lifetime after the announce, the request has ended.
            clock.advance(run.verifier.request_ttl_seconds + 1)
            self.assertFalse(run.verifier.is_outstanding(state))

    def test_so_it_does_with_a_control_call_while_it_is_held_up(self):
        clock, running, made = _Clock(self), [], []

        def held():
            clock.advance(running[0].verifier.request_ttl_seconds + 1)
            made.append(running[0].kwargs["on_control"]({}))

        running.append(self.run_serve("--once", "--result", str(self.path), "--control-token-file",
                                      str(self.token_file), held_at=("serving on", held)))
        with running[0] as run:
            self.assertEqual(made[0][0], 201, made)
            state = _state_of(run.blocks()[-1])
            self.assert_served_from(run, state, clock)
            # The --once request is the newer of the two, and the file names it.
            self.assertEqual((self.read()["request"], self.read()["state"]), (2, state))
            self.assertEqual(run.verifier.outstanding(), 2)

    def test_under_rearm_the_log_ends_on_the_request_served_from_its_announce(self):
        import re
        clock, running = _Clock(self), []

        def held():
            clock.advance(running[0].verifier.request_ttl_seconds + 1)
            running[0].verifier.outstanding()

        def last_state(run):
            # What the lab walks read: the last `state=` the command printed.
            return re.findall(r"state=([A-Za-z0-9_-]+)", run.out.getvalue())[-1]

        running.append(self.run_serve("--once", "--rearm", "--result", str(self.path),
                                      held_at=("serving on", held)))
        with running[0] as run:
            states = [_state_of(block) for block in run.blocks()]
            self.assertEqual(len(states), 1, "a request ended before one was announced")
            self.assertEqual((last_state(run), self.read()["state"]), (states[0], states[0]))
            self.assert_served_from(run, states[0], clock)
            # Its timer runs from the announce: past the lifetime, the next request is announced,
            # and the log and the file end on that one, served from its own announce.
            clock.advance(run.verifier.request_ttl_seconds + 1)
            states = [_state_of(block) for block in run.blocks()]
            self.assertEqual(len(states), 2)
            self.assertEqual((last_state(run), self.read()["state"]), (states[1], states[1]))
            self.assert_served_from(run, states[1], clock)


class ControlResultFileTests(_RunningCase):
    """`--result` beside the control endpoint describes the newest request started."""

    def test_the_file_describes_the_newest_request_and_not_an_older_one(self):
        with self.run_serve("--once", "--result", str(self.path), "--control-token-file",
                            str(self.token_file)) as run:
            state1 = _state_of(run.blocks()[0])
            self.assertEqual((self.read()["request"], self.read()["state"]), (1, state1))
            status, answer = run.control({})
            doc = self.read()
            self.assertEqual((doc["request"], doc["state"], doc["outcome"], doc["responses"]),
                             (2, answer["state"], "nothing_received", 0))
            self.assertNotIn("previous", doc, "only --rearm keeps the previous request")
            # An answer to the older request is judged and the file is not touched by it.
            before = self.path.read_text(encoding="utf-8")
            self.assertEqual(self.answer(run, state1, nonce="wrong")[0], 400)
            self.assertEqual(run.jar(state1)[0], 200)
            self.assertEqual(self.path.read_text(encoding="utf-8"), before)
            # An answer to the newest is.
            self.assertEqual(self.answer(run, answer["state"], nonce="wrong")[0], 400)
            doc = self.read()
            self.assertEqual((doc["outcome"], doc["check"], doc["responses"]), ("refused", "nonce", 1))
            # A refusal ends a request started here, as it does under --rearm: it is not served
            # again and the file, which names it until the next request starts, keeps what became of it.
            self.assertEqual(run.jar(answer["state"])[0], 404)
            self.assertEqual((self.read()["state"], self.read()["outcome"]),
                             (answer["state"], "refused"))

    def test_with_no_once_the_file_says_no_request_has_started_until_one_does(self):
        with self.run_serve("--result", str(self.path), "--control-token-file",
                            str(self.token_file)) as run:
            self.assertEqual(self.read(), {"outcome": "nothing_received", "state": None, "request": 0,
                                           "request_object": {"served": 0, "refused": 0},
                                           "responses": 0})
            status, answer = run.control({})
            doc = self.read()
            self.assertEqual((doc["request"], doc["state"]), (1, answer["state"]))

    def test_without_the_control_file_or_once_a_result_file_is_still_refused(self):
        rc, seen, _, err = ServeCommandHeldOutTests._serve(self, "--result", str(self.path))
        self.assertEqual(rc, 2)
        self.assertIn("add --once", err)

    def test_the_fetches_of_the_newest_request_are_counted_and_a_fetch_of_none_is_not(self):
        with self.run_serve("--result", str(self.path), "--control-token-file",
                            str(self.token_file)) as run:
            status, answer = run.control({})
            self.assertEqual(run.jar(answer["state"])[0], 200)
            self.assertEqual(run.jar("nonsense")[0], 404)
            self.assertEqual(self.read()["request_object"], {"served": 1, "refused": 0})


class ControlReadCommandTests(_RunningCase):
    """`GET /control/request/{n}` beside `--control-token-file` (2026-11-18): what became of request
    n, and for an accepted SD-JWT VC presentation the claims it disclosed, returned in one read
    only, the first after the acceptance, and not after the request lifetime from the answer. The
    test wallet discloses given_name "Jean" and family_name "Dupont"."""

    def serve_control(self, *extra, **kw):
        return self.run_serve("--control-token-file", str(self.token_file), *extra, **kw)

    def started(self, run, body=None):
        status, answer = run.control({} if body is None else body)
        self.assertEqual(status, 201, answer)
        return answer["request"], answer["state"]

    def accepted(self, run):
        """A request started, presented to and accepted: (its number, its state)."""
        number, state = self.started(run)
        self.assertEqual(self.answer(run, state)[0], 200)
        return number, state

    @staticmethod
    def requests_of(run):
        return run.kwargs["on_control_read"].__self__

    def test_an_accepted_presentation_is_read_with_its_claims_once(self):
        with self.serve_control() as run:
            number, state = self.started(run)
            status, doc, _ = run.read(number)
            self.assertEqual((status, doc), (200, {"request": number, "state": state,
                                                   "outcome": "nothing_received"}))
            self.assertEqual(self.answer(run, state)[0], 200)
            status, doc, _ = run.read(number)
            self.assertEqual((status, doc["request"], doc["state"], doc["outcome"]),
                             (200, number, state, "accepted"))
            self.assertEqual(doc["response"], {"status_code": 200})
            self.assertEqual((doc["released"]["given_name"], doc["released"]["family_name"]),
                             ("Jean", "Dupont"))
            # One source: the names --result and the line give are the released claims' own.
            self.assertEqual(sorted(doc["released"]), doc["claims"])
            self.assertNotIn("released_withheld", doc)
            for _ in range(2):
                status, again, _ = run.read(number)
                self.assertEqual(status, 200)
                self.assertEqual((again.get("outcome"), again.get("claims"), again.get("released"),
                                  again.get("released_withheld")),
                                 ("accepted", doc["claims"], None, "returned"))

    def test_a_refusal_a_wallet_error_and_a_pending_request_carry_no_released(self):
        with self.serve_control() as run:
            refused, refused_state = self.started(run)
            self.assertEqual(self.answer(run, refused_state, nonce="wrong")[0], 400)
            erred, erred_state = self.started(run)
            jar = run.jar(erred_state)[1]
            self.assertEqual(run.respond(self.wallet.respond_error(jar))[0], 200)
            pending, _ = self.started(run)
            for number, outcome in ((refused, "refused"), (erred, "wallet_error"),
                                    (pending, "nothing_received")):
                for _ in range(2):
                    with self.subTest(outcome=outcome):
                        status, doc, _ = run.read(number)
                        self.assertEqual((status, doc["outcome"]), (200, outcome))
                        self.assertNotIn("released", doc)
                        self.assertNotIn("released_withheld", doc)
            self.assertEqual(run.read(refused)[1]["check"], "nonce")

    def test_the_once_request_and_a_number_never_started_are_404(self):
        with self.run_serve("--once", "--control-token-file", str(self.token_file)) as run:
            self.assertEqual(run.jar(_state_of(run.blocks()[0]))[0], 200, "the --once request is open")
            number, _ = self.accepted(run)
            self.assertEqual(number, 2, "the --once request is request 1")
            for unknown in (1, 3, 99):
                with self.subTest(number=unknown):
                    status, doc, _ = run.read(unknown)
                    self.assertEqual((status, doc["error"]), (404, "not_found"))
            self.assertEqual(run.read(number)[0], 200)

    def test_without_the_token_401_and_without_the_option_404(self):
        with self.serve_control() as run:
            number, _ = self.accepted(run)
            for token in (None, "x" * len(CONTROL_TOKEN)):
                with self.subTest(token=token):
                    self.assertEqual(run.read(number, token=token)[::2], (401, b""))
            # Unread by the refused callers: the first read with the token returns the claims.
            self.assertIn("family_name", run.read(number)[1]["released"])
        with self.run_serve("--once") as run:
            status, doc, _ = run.read(1)
            self.assertEqual((status, doc), (404, {"error": "not_found"}))

    def test_two_requests_answered_out_of_order_each_read_answers_its_own(self):
        with self.serve_control("--result", str(self.path)) as run:
            first, first_state = self.started(run)
            second, second_state = self.started(run)
            self.assertEqual(self.answer(run, second_state, nonce="wrong")[0], 400)
            self.assertEqual(self.answer(run, first_state)[0], 200)
            status, doc_first, _ = run.read(first)
            self.assertEqual((status, doc_first["state"], doc_first["outcome"]),
                             (200, first_state, "accepted"))
            self.assertIn("released", doc_first)
            status, doc_second, _ = run.read(second)
            self.assertEqual((status, doc_second["state"], doc_second["outcome"], doc_second["check"]),
                             (200, second_state, "refused", "nonce"))
            # --result follows the newest request, and says what the read of it says, from the
            # same function.
            in_file = self.read()
            for key in ("request", "state", "outcome", "response", "check", "reason"):
                self.assertEqual(in_file[key], doc_second[key], key)

    def test_the_claims_are_not_returned_after_the_request_lifetime_from_the_answer(self):
        with self.serve_control(ttl=60) as run:
            requests = self.requests_of(run)
            # Whole seconds, so the boundary is compared exactly.
            requests._clock = lambda: 1763485200
            inside, _ = self.accepted(run)
            outside, _ = self.accepted(run)
            self.assertEqual({requests._records[n].answered_at for n in (inside, outside)},
                             {1763485200})
            # At the lifetime exactly the claims are still returned, as the verifier keeps a
            # request live until it is older than its lifetime (it expires a session when
            # created < now - ttl); a second later they are not.
            requests._clock = lambda: 1763485260
            status, doc, _ = run.read(inside)
            self.assertEqual((status, (doc.get("released") or {}).get("family_name")),
                             (200, "Dupont"))
            requests._clock = lambda: 1763485261
            status, doc, _ = run.read(outside)
            self.assertEqual((status, doc.get("outcome"), doc.get("released"),
                              doc.get("released_withheld")),
                             (200, "accepted", None, "expired"))

    def test_a_start_after_the_lifetime_lets_the_claims_go_unread(self):
        with self.serve_control(ttl=60) as run:
            requests = self.requests_of(run)
            number, _ = self.accepted(run)
            record = requests._records[number]
            self.assertIsNotNone(record.released)
            answered_at = record.answered_at
            # time.time itself is moved, as the verifier's clock is: the record's is looked up at
            # each call, so it moves with it.
            from unittest import mock
            from polaris_oid4vp import cli
            with mock.patch.object(cli.time, "time", return_value=answered_at + 61):
                self.started(run)
            self.assertEqual((record.released, record.withheld), (None, "expired"))

    def test_the_oldest_record_no_longer_outstanding_is_dropped_first(self):
        from unittest import mock
        from polaris_oid4vp import cli
        self.assertEqual(cli.CONTROL_FINISHED_KEPT, cli.CONTROL_OUTSTANDING_LIMIT)
        with mock.patch.object(cli, "CONTROL_FINISHED_KEPT", 3), self.serve_control() as run:
            open_number, _ = self.started(run)
            finished = []
            for _ in range(4):
                number, state = self.started(run)
                self.assertEqual(self.answer(run, state, nonce="wrong")[0], 400)
                finished.append(number)
            newest, _ = self.started(run)
            # Four finished, one over the three kept: the oldest finished one goes at the next
            # start, and the outstanding one, older still, is kept.
            status, doc, _ = run.read(open_number)
            self.assertEqual((status, doc.get("outcome")), (200, "nothing_received"))
            self.assertEqual(run.read(finished[0])[0], 404)
            for number in finished[1:] + [newest]:
                self.assertEqual(run.read(number)[0], 200, number)

    def test_of_reads_at_once_exactly_one_gets_the_claims(self):
        import threading
        with self.serve_control() as run:
            for _ in range(5):
                number, _ = self.accepted(run)
                barrier = threading.Barrier(8)
                docs = []

                def reader():
                    barrier.wait()
                    docs.append(run.read(number)[1])

                threads = [threading.Thread(target=reader) for _ in range(8)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(30)
                self.assertEqual(len(docs), 8)
                got = [doc for doc in docs if doc["released"] is not None]
                self.assertEqual(len(got), 1, docs)
                self.assertEqual(got[0]["released"]["family_name"], "Dupont")
                self.assertEqual({doc.get("released_withheld") for doc in docs if doc is not got[0]},
                                 {"returned"})

    def test_a_read_waits_for_the_lock_every_writer_takes(self):
        """Readers at once cannot show it (the check and the set are a few bytecodes in one
        interpreter slice), so the lock is held here: the read waits for it, then decides."""
        import threading
        with self.serve_control() as run:
            requests = self.requests_of(run)
            number, _ = self.accepted(run)
            docs = []
            reader = threading.Thread(target=lambda: docs.append(requests.control_read(number)))
            with requests._lock:
                reader.start()
                reader.join(0.5)
                self.assertTrue(reader.is_alive(), "the read went ahead without the lock")
                self.assertEqual(docs, [])
            reader.join(30)
            self.assertEqual(len(docs), 1)
            status, doc = docs[0]
            self.assertEqual((status, (doc.get("released") or {}).get("family_name")),
                             (200, "Dupont"))

    def test_two_answers_about_one_request_keep_what_result_keeps(self):
        """Two answers reach one record only when they race on one outstanding request (the
        control endpoint ends it at the first), driven here by asking the verifier's
        attribution for that request twice. The read keeps what --result keeps: the latest
        answer until an acceptance, which stays."""
        import types
        from unittest import mock
        accepted = (200, types.SimpleNamespace(
            authentic=True, claims={"family_name": "Dupont", "given_name": "Jean"}))
        refused = (400, types.SimpleNamespace(authentic=False, code="nonce",
                                              reason="not this request's nonce", wallet_error=None))
        # The answers 50 s apart and the read 100 s after the first, with a 60 s lifetime: past
        # the first answer's lifetime, inside the second's. The claims are held for the lifetime
        # from the answer that carried them, which a later refusal does not extend.
        for order, family_name, withheld in (((refused, accepted), "Dupont", None),
                                             ((accepted, refused), None, "expired")):
            with self.subTest(first=order[0][1].authentic), \
                    self.serve_control("--result", str(self.path), ttl=60) as run:
                requests = self.requests_of(run)
                requests._clock = lambda: 1763485200
                number, state = self.started(run)
                with mock.patch.object(requests.verifier, "attributed_request",
                                       return_value=state):
                    for at, (status, verdict) in zip((1763485200, 1763485250), order):
                        requests._clock = lambda at=at: at
                        requests.answered(status, verdict)
                requests._clock = lambda: 1763485300
                in_file = self.read()
                status, doc, _ = run.read(number)
                self.assertEqual((status, doc.get("outcome"), in_file.get("outcome")),
                                 (200, "accepted", "accepted"))
                for key in ("response", "claims", "check"):
                    self.assertEqual(doc.get(key), in_file.get(key), key)
                self.assertEqual(((doc.get("released") or {}).get("family_name"),
                                  doc.get("released_withheld")), (family_name, withheld))

    def test_a_read_racing_the_answer_finds_it_pending_or_with_its_claims(self):
        import threading
        with self.serve_control() as run:
            for _ in range(5):
                number, state = self.started(run)
                docs, stop = [], threading.Event()

                def reader():
                    while not stop.is_set():
                        doc = run.read(number)[1]
                        docs.append(doc)
                        if doc["outcome"] != "nothing_received":
                            return

                thread = threading.Thread(target=reader)
                thread.start()
                self.assertEqual(self.answer(run, state)[0], 200)
                thread.join(30)
                stop.set()
                # Every read before the last found the request pending, and the first read to find
                # it answered found it accepted with its claims: never accepted without them.
                outcomes = [doc["outcome"] for doc in docs]
                self.assertTrue(docs)
                self.assertEqual(outcomes[:-1], ["nothing_received"] * (len(docs) - 1))
                self.assertEqual(outcomes[-1], "accepted", outcomes)
                self.assertEqual(docs[-1]["released"]["family_name"], "Dupont")

    def test_the_claims_reach_no_line_printed_and_no_result_file(self):
        with self.serve_control("--verbose", "--result", str(self.path)) as run:
            number, _ = self.accepted(run)
            # Read while the file describes the accepted request, between its answer and the next
            # start; then after a second request, the newest, rewrote it, and after the read.
            on_disk = [self.path.read_text(encoding="utf-8")]
            self.assertEqual(self.read()["outcome"], "accepted")
            self.started(run)
            on_disk.append(self.path.read_text(encoding="utf-8"))
            _, doc, raw = run.read(number)
            on_disk.append(self.path.read_text(encoding="utf-8"))
            printed = run.out.getvalue() + run.err.getvalue()
        # The positive control: the read's own answer carries the values the greps look for.
        self.assertEqual(doc["released"]["family_name"], "Dupont")
        self.assertIn(b"Dupont", raw)
        self.assertIn(b"Jean", raw)
        self.assertIn("GET /control/request/%d" % number, printed, "--verbose logged the read")
        for value in ("Dupont", "Jean"):
            self.assertNotIn(value, printed)
            for text in on_disk:
                self.assertNotIn(value, text)

    def test_under_mso_mdoc_an_accepted_presentation_is_read_without_released(self):
        from cryptography.hazmat.primitives import serialization
        root = self.tmp / "iaca.pem"
        root.write_bytes(md.IACA.public_bytes(serialization.Encoding.PEM))
        with _Running(self, "--format", "mso_mdoc", "--experimental", "--doctype", md.MDL,
                      "--iaca-root", str(root), "--claim", MDL_AGE,
                      "--control-token-file", str(self.token_file)) as run:
            number, state = self.started(run)
            self.assertEqual(run.respond(MdocWallet().respond(run.jar(state)[1]))[0], 200)
            # Not held for a read that never returns them.
            self.assertIsNone(self.requests_of(run)._records[number].released)
            for _ in range(2):
                status, doc, _ = run.read(number)
                self.assertEqual((status, doc["outcome"], doc["claims"]),
                                 (200, "accepted", [["org.iso.18013.5.1", "age_over_21"]]))
                self.assertNotIn("released", doc)
                self.assertNotIn("released_withheld", doc)

    def test_the_help_says_what_a_read_returns(self):
        import contextlib
        out = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(out):
            main(["serve", "--help"])
        text = " ".join(out.getvalue().split())
        self.assertIn("GET /control/request/N with the same token answers what became of request N, "
                      "and for an accepted SD-JWT VC presentation the claims it disclosed, returned "
                      "in one read only, the first after the acceptance, and not after the request "
                      "lifetime from the answer.",
                      text)
        self.assertIn("on Linux and macOS a FILE with any permission for others is refused (0600, "
                      "or 0640 for its group).", text)



class ControlTokenFileTests(_RunningCase):
    """The token is read from a file, at least 32 bytes after stripping, or the command stops."""

    _serve = ServeCommandHeldOutTests._serve

    def serve_with(self, content):
        if content is not None:
            self.token_file.write_bytes(content if isinstance(content, bytes) else content.encode())
        else:
            self.token_file.unlink()
        return self._serve("--issuer-jwks", str(self.jwks), "--control-token-file",
                           str(self.token_file))

    def test_a_token_that_is_empty_or_short_or_missing_stops_it_before_it_listens(self):
        for label, content in (("empty", ""), ("only whitespace", " \n\t \n"), ("one byte", "x"),
                               ("31 bytes", "x" * 31), ("31 bytes and a newline", "x" * 31 + "\n"),
                               ("31 bytes among whitespace", "  " + "x" * 31 + "  \n"),
                               ("missing", None)):
            with self.subTest(token=label):
                rc, seen, out, err = self.serve_with(content)
                self.assertEqual(rc, 2, err)
                self.assertNotIn("kwargs", seen, "it listened")
                self.assertIn("--control-token-file", err)
                self.assertNotIn("x" * 31, out + err, "the token was printed")

    def test_a_token_that_cannot_be_a_bearer_value_stops_it_too(self):
        for label, content in (("an inner space", "x" * 20 + " " + "y" * 20),
                               ("an inner newline", "x" * 20 + "\n" + "y" * 20),
                               ("not ASCII", "x" * 31 + "é"),
                               ("not text", b"\xff" * 40)):
            with self.subTest(token=label):
                rc, seen, _, err = self.serve_with(content)
                self.assertEqual(rc, 2, err)
                self.assertNotIn("kwargs", seen)
                self.assertIn("--control-token-file", err)

    def test_32_bytes_after_stripping_starts_it_and_the_listener_is_given_the_stripped_token(self):
        for content in ("x" * 32, "x" * 32 + "\n", "\n  " + "x" * 32 + " \r\n"):
            with self.subTest(content=repr(content[:6])):
                rc, seen, out, err = self.serve_with(content)
                self.assertEqual(rc, 0, err)
                self.assertEqual(seen["kwargs"]["control_token"], "x" * 32)
                self.assertTrue(callable(seen["kwargs"]["on_control"]))
                self.assertNotIn("x" * 32, out + err)
        rc, seen, out, _ = self._serve()
        self.assertEqual((rc, seen["kwargs"]["control_token"], seen["kwargs"]["on_control"]),
                         (0, None, None))

    def test_the_startup_says_the_endpoint_is_on_and_never_the_token(self):
        rc, seen, out, err = self.serve_with(CONTROL_TOKEN)
        self.assertEqual(rc, 0, err)
        self.assertIn("POST /control/request", out)
        self.assertNotIn(CONTROL_TOKEN, out + err)
        self.assertNotIn("/control/request", self._serve()[2])

    def serve_on(self, path):
        return self._serve("--issuer-jwks", str(self.jwks), "--control-token-file", str(path))

    def test_a_token_file_others_have_access_to_stops_it_before_it_listens(self):
        """2026-11-18: under umask 022 the README's line made the file 0644, and a second local
        account read the token from it. Any permission for others refuses the file before anything
        listens; the message names the mode and what to do, never what the file holds."""
        if os.name != "posix":
            self.skipTest("POSIX file modes")
        for mode in (0o644, 0o604, 0o602, 0o606, 0o666, 0o601):
            with self.subTest(mode="%04o" % mode):
                self.token_file.chmod(0o600)
                self.token_file.write_text(CONTROL_TOKEN + "\n")
                self.token_file.chmod(mode)
                rc, seen, out, err = self.serve_on(self.token_file)
                self.assertEqual(rc, 2, err)
                self.assertNotIn("kwargs", seen, "it listened")
                self.assertIn("--control-token-file", err)
                self.assertIn("%04o" % mode, err)
                self.assertIn("chmod 600", err)
                self.assertNotIn(CONTROL_TOKEN, out + err, "the token was printed")

    def test_a_token_file_only_its_owner_or_group_can_read_starts_it(self):
        """The group is the operator's route into the image (its group_add), so it may read."""
        if os.name != "posix":
            self.skipTest("POSIX file modes")
        for mode in (0o600, 0o400, 0o640, 0o440):
            with self.subTest(mode="%04o" % mode):
                self.token_file.chmod(mode)
                rc, seen, out, err = self.serve_on(self.token_file)
                self.assertEqual(rc, 0, err)
                self.assertEqual(seen["kwargs"]["control_token"], CONTROL_TOKEN)
        self.token_file.chmod(0o600)

    def test_the_mode_judged_is_the_mode_of_the_file_read(self):
        """Check and read are one file. A file others can read, replaced at its path by a private
        one once it is open, is still refused: the bytes read are the readable file's."""
        if os.name != "posix":
            self.skipTest("POSIX file modes")
        import builtins
        from unittest import mock
        self.token_file.chmod(0o644)
        private = self.tmp / "private-token"
        private.write_text(CONTROL_TOKEN + "\n")
        private.chmod(0o600)
        real_open, swapped = builtins.open, []

        def opening(file, *args, **kwargs):
            handle = real_open(file, *args, **kwargs)
            if str(file) == str(self.token_file) and not swapped:
                os.replace(private, self.token_file)
                swapped.append(True)
            return handle

        with mock.patch("builtins.open", opening):
            rc, seen, out, err = self.serve_on(self.token_file)
        self.assertEqual(swapped, [True], "the token file was not opened with open()")
        self.assertEqual(rc, 2, err)
        self.assertNotIn("kwargs", seen, "it listened on a token others could read")
        self.assertIn("0644", err)


class ReadmeControlTokenTests(unittest.TestCase):
    """What the README has an operator run with the control token (2026-11-18): the file made
    private, the token never on a command line, and a call from this machine to 127.0.0.1."""

    @classmethod
    def setUpClass(cls):
        import re
        text = pathlib.Path(__file__).with_name("README.md").read_text(encoding="utf-8")
        cls.text = " ".join(text.split())
        cls.commands = []
        for block in re.findall(r"```(?:bash|sh|shell)\n(.*?)```", text, re.S):
            for line in block.replace("\\\n", " ").splitlines():
                if line.strip() and not line.lstrip().startswith("#"):
                    cls.commands.append(" ".join(line.split()))

    def test_the_line_that_makes_the_token_file_makes_it_private(self):
        import re
        made = [c for c in self.commands if re.search(r">\s*control-token(\s|\)|$)", c)]
        self.assertTrue(made, "the README has no command that makes the token file")
        for command in made:
            self.assertRegex(command, r"\bumask 0[0-7]7\b", command)

    def test_no_control_call_carries_the_token_on_its_command_line(self):
        calls = [c for c in self.commands if "curl" in c and "/control/" in c]
        self.assertTrue(calls, "the README has no control call")
        for call in calls:
            self.assertNotIn("Bearer", call, "the token is on curl's command line: " + call)
            self.assertIn("-H @", call, call)

    def test_a_call_from_this_machine_names_127_0_0_1(self):
        self.assertIn("A call from this machine names 127.0.0.1, not localhost", self.text)
        for command in self.commands:
            if "localhost" in command:
                self.assertIn("--resolve localhost:", command, command)


class AWalletErrorSaysWhatBecameOfTheRequestTests(_RunningCase):
    """2026-11-18. Under --rearm, and for a request the control endpoint started, a wallet's error
    response ends the request, and the `<-` line and --result said the verifier's "so it does not
    close the request", true of the Verifier and of the plain rule only. They say what happened;
    the stderr line, which cannot know, names the error and the request; a line that names its
    request names it once. Under the plain rule the sentence and the open request stay."""

    PLAIN = ("access_denied for request %s, which anyone who saw the request could send, so it "
             "does not close the request")
    BY_REARM = ("access_denied, which anyone who saw the request could send, and it ended the "
                "request: under --rearm any answer about the current request ends it")
    BY_CONTROL = ("access_denied, which anyone who saw the request could send, and it ended the "
                  "request: a request the control endpoint started ends at any answer about it")

    def send_error(self, run, state):
        status, jar = run.jar(state)
        self.assertEqual(status, 200, "no such outstanding request")
        self.assertEqual(run.respond(self.wallet.respond_error(jar))[0], 200)
        out = [x for x in run.out.getvalue().splitlines() if x.startswith("  <- 200 wallet error: ")]
        err = [x for x in run.err.getvalue().splitlines() if x.startswith("polaris-oid4vp: wallet error: ")]
        self.assertEqual((len(out), len(err)), (1, 1), run.out.getvalue() + run.err.getvalue())
        return out[0], err[0]

    def test_under_rearm_the_line_and_the_file_say_the_error_ended_the_request(self):
        with self.run_serve("--once", "--rearm", "--result", str(self.path)) as run:
            state = _state_of(run.blocks()[0])
            out, err = self.send_error(run, state)
            self.assertEqual(len(run.blocks()), 2, "the next request started")
            previous = self.read().get("previous")
        self.assertIsNotNone(previous, "the request that ended is kept as previous")
        self.assertEqual(out, "  <- 200 wallet error: %s (request %s)" % (self.BY_REARM, state))
        self.assertEqual(err, "polaris-oid4vp: wallet error: access_denied (request %s)" % state)
        self.assertEqual((previous["state"], previous["outcome"]), (state, "wallet_error"))
        self.assertEqual(previous["reason"], self.BY_REARM.replace(
            "access_denied,", "access_denied for request %s," % state, 1))

    def test_a_request_the_control_endpoint_started_says_so_too(self):
        with self.run_serve("--control-token-file", str(self.token_file),
                            "--result", str(self.path)) as run:
            state = run.control({})[1]["state"]
            out, err = self.send_error(run, state)
            doc = self.read()
            self.assertEqual(run.jar(state)[0], 404, "the error ended the request")
        self.assertEqual(out, "  <- 200 wallet error: %s (request %s)" % (self.BY_CONTROL, state))
        self.assertEqual(err, "polaris-oid4vp: wallet error: access_denied (request %s)" % state)
        self.assertEqual((doc["state"], doc["outcome"]), (state, "wallet_error"))
        self.assertEqual(doc["reason"], self.BY_CONTROL.replace(
            "access_denied,", "access_denied for request %s," % state, 1))

    def test_under_the_plain_rule_the_request_stays_open_and_the_sentence_says_so(self):
        with self.run_serve("--once", "--result", str(self.path)) as run:
            state = _state_of(run.blocks()[0])
            out, err = self.send_error(run, state)
            doc = self.read()
            self.assertEqual(run.jar(state)[0], 200, "the request is still open")
        self.assertEqual(out, "  <- 200 wallet error: " + self.PLAIN % state)
        self.assertEqual(err, "polaris-oid4vp: wallet error: " + self.PLAIN % state)
        self.assertEqual((doc["outcome"], doc["reason"]), ("wallet_error", self.PLAIN % state))

    def test_beside_the_control_endpoint_the_once_request_keeps_the_plain_rule_named_once(self):
        with self.run_serve("--once", "--control-token-file", str(self.token_file)) as run:
            state = _state_of(run.blocks()[0])
            out, err = self.send_error(run, state)
            self.assertEqual(run.jar(state)[0], 200, "the request is still open")
        self.assertEqual(out, "  <- 200 wallet error: access_denied, which anyone who saw the "
                              "request could send, so it does not close the request (request %s)"
                              % state)
        self.assertEqual(err, "polaris-oid4vp: wallet error: access_denied (request %s)" % state)


#: The most characters of a reason a writer writes, as verifier.WRITTEN_REASON_MAX pins it.
REASON_BOUND = 512

#: A reason far over the bound, as a refusal that quotes what a sender sent can be: a `<` that
#: quoting turns to `?`, and a marker at its end that a cut leaves out.
LONG_REASON = "<" + "x" * 99_994 + "MARKER"


class WrittenReasonTests(unittest.TestCase):
    """A refusal's reason can quote what a sender sent, so each refused post would write as much
    of its own bytes as the verifier read. Every place `serve` and the `verdict` command write a
    reason (the lines printed, the --result file and the control read, the verdict's JSON, the
    listener's log) writes it through `written_reason`: quoted, at most REASON_BOUND characters
    of it, and its full length when it is cut. test_serve holds the listener's log the same
    way."""

    CUT = r"\.\.\. \(cut at %d of (\d+) characters\)" % REASON_BOUND

    def held(self, text, at_least=len(LONG_REASON)):
        import re
        self.assertNotIn("MARKER", text)
        self.assertNotIn("<x", text)
        self.assertLess(len(text), REASON_BOUND + 300, text[:120])
        found = re.findall(self.CUT, text)
        self.assertEqual(len(found), 1, text[-200:])
        self.assertGreaterEqual(int(found[0]), at_least)

    def test_the_bound_is_pinned(self):
        from polaris_oid4vp import verifier
        self.assertEqual(getattr(verifier, "WRITTEN_REASON_MAX", None), REASON_BOUND)
        # An accepted response's `problem` is None, and `verdict` writes it as null.
        self.assertIsNone(verifier.written_reason(None))

    def test_a_text_at_the_bound_is_written_whole_and_one_over_is_cut(self):
        """The note says a text was cut only when it was: at the bound it is written unchanged."""
        from polaris_oid4vp import verifier
        from test_serve import LINE_BOUND
        for name, bound in (("written_reason", REASON_BOUND), ("logged_line", LINE_BOUND)):
            write = getattr(verifier, name)
            with self.subTest(name):
                self.assertEqual(write("x" * bound), "x" * bound)
                self.assertEqual(write("x" * (bound + 1)), "x" * bound
                                 + "... (cut at %d of %d characters)" % (bound, bound + 1))

    def test_each_writer_writes_a_long_reason_cut_and_says_its_length(self):
        import json
        from polaris_oid4vp.cli import _operator_line, _result_of, _verdict_json
        from polaris_oid4vp.sdjwt import Verdict
        from test_serve import uncut
        refused = uncut(Verdict(False, "malformed"), LONG_REASON)
        wallet = uncut(Verdict(False, "wallet_error", wallet_error={
            "error": "access_denied", "error_description": LONG_REASON, "state": "s1"}), LONG_REASON)
        written = {
            "the refused line": _operator_line(refused),
            "the wallet error line": _operator_line(wallet),
            "the wallet error line, ended by a rule": _operator_line(wallet, "rearm"),
            "the wallet error line, its request named": _operator_line(wallet, named=True),
            "the result document, refused": json.dumps(_result_of(400, refused)),
            "the result document, a wallet error": json.dumps(_result_of(200, wallet)),
            "the result document, a wallet error ended": json.dumps(_result_of(200, wallet, "control")),
            "the verdict command": json.dumps(_verdict_json(refused)),
        }
        for name, text in written.items():
            with self.subTest(name):
                self.held(text)

    def test_the_verdict_command_writes_its_problem_and_reasons_cut(self):
        """`verdict` repeats a refused verdict's reason in `problem`, on stdout and on stderr."""
        import contextlib
        import io
        import json
        from unittest import mock
        from polaris_oid4vp import cli
        from polaris_oid4vp.sdjwt import Verdict
        here = pathlib.Path(__file__).resolve().parent
        v = json.loads((here / "testdata" / "transaction-data-two-credentials.json")
                       .read_text(encoding="utf-8"))
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-written-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "request.json").write_text(json.dumps(v["request"]))
        (tmp / "vp_token.json").write_text(json.dumps(v["responses"]["per_credential"]["vp_token"]))
        from test_serve import uncut
        result = {"accepted": None, "scope": None, "problem": LONG_REASON, "expected": {},
                  "either": {}, "verdicts": {"pid": uncut(Verdict(False, "malformed"), LONG_REASON)},
                  "readings": {}, "response_refusals": {}}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "verify_response", return_value=result) as judged, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["verdict", "--request", str(tmp / "request.json"),
                           "--vp-token", str(tmp / "vp_token.json")])
        self.assertEqual((rc, judged.call_count), (2, 1))
        written = json.loads(out.getvalue())
        for name, text in (("problem", written["problem"]),
                           ("the verdict's reason", written["verdicts"]["pid"]["reason"]),
                           ("stderr", err.getvalue())):
            with self.subTest(name):
                self.held(text)

    def test_the_verdict_command_writes_a_raised_error_cut(self):
        """What `verdict` raised while reading the files and judging them is one line on stderr,
        cut at a logged line's bound and saying its length."""
        import contextlib
        import io
        import json
        from unittest import mock
        from polaris_oid4vp import cli
        from test_serve import LINE_BOUND
        here = pathlib.Path(__file__).resolve().parent
        v = json.loads((here / "testdata" / "transaction-data-two-credentials.json")
                       .read_text(encoding="utf-8"))
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-oid4vp-written-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "request.json").write_text(json.dumps(v["request"]))
        (tmp / "vp_token.json").write_text(json.dumps(v["responses"]["per_credential"]["vp_token"]))
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "verify_response", side_effect=ValueError(LONG_REASON)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["verdict", "--request", str(tmp / "request.json"),
                           "--vp-token", str(tmp / "vp_token.json")])
        self.assertEqual((rc, out.getvalue()), (2, ""))
        lines = err.getvalue().splitlines()
        self.assertEqual(len(lines), 1, lines[:3])
        self.assertRegex(lines[0], r"^polaris-oid4vp: \?x{400}")
        self.assertTrue(lines[0].endswith("... (cut at %d of %d characters)"
                                          % (LINE_BOUND, len(LONG_REASON))), lines[0][-80:])
        self.assertNotIn("MARKER", lines[0])

    def test_a_reason_under_the_bound_is_written_as_quoting_leaves_it(self):
        import json
        from polaris_oid4vp.cli import _operator_line, _result_of, _verdict_json
        from polaris_oid4vp.sdjwt import Verdict
        head = "the nonce is not this request's <"
        reason = head + "y" * (REASON_BOUND - 6 - len(head))
        quoted = reason.replace("<", "?")
        self.assertEqual(len(quoted), REASON_BOUND - 6)
        verdict = Verdict(False, "nonce", reason)
        self.assertEqual(_operator_line(verdict), "refused: nonce: " + quoted)
        self.assertEqual(_result_of(400, verdict)["reason"], quoted)
        self.assertEqual(_verdict_json(verdict)["reason"], quoted)
        self.assertNotIn("cut at", json.dumps(_result_of(400, verdict)))

    def test_every_writer_of_a_reason_is_enumerated(self):
        """Every read of a verdict's `reason` and of a `verify_response` result's `problem` in
        cli.py and serve.py, and every call of the two functions that build a wallet error's
        reason from one, sits inside a `written_reason(...)` call; the two builders' own bodies
        are the only exception. A writer added later is held the moment it is written."""
        import ast
        from polaris_oid4vp import cli, serve
        builders = {"_wallet_error_reason", "_wallet_error_named"}
        sites, unbounded = [], []
        for module in (cli, serve):
            tree = ast.parse(pathlib.Path(module.__file__).read_text(encoding="utf-8"))
            parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
            for node in ast.walk(tree):
                read = (isinstance(node, ast.Attribute) and node.attr == "reason"
                        and isinstance(node.ctx, ast.Load)) or (
                    isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load)
                    and isinstance(node.slice, ast.Constant) and node.slice.value == "problem")
                built = (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                         and node.func.id in builders)
                if not (read or built):
                    continue
                up, function, held = node, None, False
                while up in parents:
                    up = parents[up]
                    if isinstance(up, ast.Call) and getattr(up.func, "id", None) == "written_reason":
                        held = True
                    if function is None and isinstance(up, ast.FunctionDef):
                        function = up.name
                site = "%s.%s:%d" % (module.__name__.rsplit(".", 1)[1], function, node.lineno)
                sites.append(site)
                if not held and function not in builders:
                    unbounded.append(site)
        self.assertEqual(unbounded, [])
        # The writers, by the function each sits in: a site that moves or goes changes this.
        self.assertEqual(sorted({s.split(":")[0] for s in sites}),
                         ["cli._cmd_verdict", "cli._operator_line", "cli._result_of",
                          "cli._verdict_json", "cli._wallet_error_reason", "serve._dc_api_response",
                          "serve.do_POST"])


class TheAnswerLineIsBoundedTests(_RunningCase):
    """The `<-` line `serve` prints on stdout for each answer is a logged_line: at most LINE_MAX
    characters, with its full length when it is cut, whoever composed what it carries."""

    def test_a_long_answer_line_is_printed_cut(self):
        from unittest import mock
        from polaris_oid4vp.sdjwt import Verdict
        from polaris_oid4vp.verifier import Verifier
        from test_serve import LINE_BOUND
        tail = "Polaris" + "Tail"
        refused = Verdict(False, "c" * 60_000 + tail, "r")
        with self.run_serve("--control-token-file", str(self.token_file)) as run:
            status, answer = run.control({})
            self.assertEqual(status, 201, answer)
            with mock.patch.object(run.verifier, "handle_direct_post",
                                   return_value=(400, dict(Verifier.REFUSAL_BODY), refused)):
                self.assertEqual(run.respond({"response": "x"})[0], 400)
            out = run.out.getvalue()
            lines = [x for x in out.splitlines() if x.startswith("  <- 400 ")]
            self.assertEqual(len(lines), 1, out[-300:])
            self.assertNotIn(tail, out + run.err.getvalue())
            self.assertLessEqual(len(lines[0]), len("  <- 400 ") + LINE_BOUND + 40)
            self.assertRegex(lines[0], r"\.\.\. \(cut at 1024 of \d+ characters\)$")


#: What a disclosure sent as a JSON object carries, sought in every place `serve` and `verdict`
#: write: never written there.
DISCLOSED_MARKER = "Polaris-Marker-5f1e"


class AMalformedDisclosureReachesNoSinkTests(_RunningCase):
    """README: "The values reach no file `serve` writes and no line it prints." A disclosure is a
    2- or 3-element JSON array; one sent as a JSON object was printed whole in the refusal's
    reason (2026-11-19), and so reached the line `serve` prints, its log, the --result file and
    the control read. The refusal names the kind of JSON value it got, never its content."""

    @staticmethod
    def junk():
        import json
        from polaris_oid4vp.jwe import b64u_encode
        return b64u_encode(json.dumps({"given_name": DISCLOSED_MARKER,
                                       DISCLOSED_MARKER: DISCLOSED_MARKER}).encode())

    def test_serve_writes_it_in_no_line_log_file_or_read(self):
        with self.run_serve("--result", str(self.path), "--control-token-file",
                            str(self.token_file)) as run:
            status, answer = run.control({})
            self.assertEqual(status, 201, answer)
            self.assertEqual(self.answer(run, answer["state"], extra_disclosure=self.junk())[0], 400)
            doc = self.read()
            status, read, raw = run.read(answer["request"])
            self.assertEqual(status, 200)
            sinks = {"the line printed": run.out.getvalue(), "the log": run.err.getvalue(),
                     "the --result file": self.path.read_text(encoding="utf-8"),
                     "the control read": raw.decode("utf-8")}
            # The control: each sink holds this refusal, so each is a place the marker could be.
            self.assertEqual((doc["outcome"], doc["check"], read["outcome"], read["check"]),
                             ("refused", "disclosure", "refused", "disclosure"))
            for name, text in sinks.items():
                with self.subTest(name):
                    self.assertIn("got a JSON object", text)
                    self.assertNotIn(DISCLOSED_MARKER, text)

    def test_verdict_writes_it_nowhere(self):
        import contextlib
        import io
        import json
        here = pathlib.Path(__file__).resolve().parent
        v = json.loads((here / "testdata" / "transaction-data-two-credentials.json")
                       .read_text(encoding="utf-8"))
        token = v["responses"]["per_credential"]["vp_token"]
        head, rest = token["pid"][0].split("~", 1)
        token["pid"] = [head + "~" + self.junk() + "~" + rest]
        (self.tmp / "request.json").write_text(json.dumps(v["request"]))
        (self.tmp / "vp_token.json").write_text(json.dumps(token))
        (self.tmp / "issuers.json").write_text(json.dumps({"keys": v["issuer_jwks"]}))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(["verdict", "--request", str(self.tmp / "request.json"),
                       "--vp-token", str(self.tmp / "vp_token.json"),
                       "--issuer-jwks", str(self.tmp / "issuers.json"), "--now", str(v["at"]),
                       "--transaction-data-scope", "per_credential"])
        self.assertEqual(rc, 1, err.getvalue())
        written = json.loads(out.getvalue())
        self.assertEqual(written["verdicts"]["pid"]["code"], "disclosure")
        self.assertIn("got a JSON object", written["problem"])
        self.assertNotIn(DISCLOSED_MARKER, out.getvalue() + err.getvalue())


# --------------------------------------------------------------------------- --status-anchor

STATUS_PREFIX = "https://tsl.provider.example/tsl/"


def _self_signed_ca(common_name):
    import datetime
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key, now = ec.generate_private_key(ec.SECP256R1()), datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))


def _status_anchor_file(folder, *, entries=None, **change):
    """A --status-anchor file in a folder of its own under `folder`, beside its two anchors,
    which the entry names by bare file name: two self-signed CAs, neither certifying the other.
    `change` replaces members of the one entry (None drops one); `entries` replaces the array.
    (path, the credential anchor)."""
    import json
    from cryptography.hazmat.primitives import serialization
    home = pathlib.Path(tempfile.mkdtemp(prefix="status-anchor-", dir=str(folder)))
    credential_anchor = _self_signed_ca("PID-Signer Test CA")
    for name, cert in (("a.pem", credential_anchor), ("b.pem", _self_signed_ca("Status Test CA"))):
        (home / name).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (home / "two.pem").write_bytes((home / "a.pem").read_bytes() + (home / "b.pem").read_bytes())
    entry = {"credential_anchor": "a.pem", "status_uri_prefix": STATUS_PREFIX,
             "status_anchor": "b.pem", "why": "the trust list names both anchors"}
    for member, value in change.items():
        if value is None:
            entry.pop(member)
        else:
            entry[member] = value
    path = home / "status-anchors.json"
    path.write_text(json.dumps([entry] if entries is None else entries))
    return str(path), credential_anchor


class StatusAnchorServeTests(unittest.TestCase):
    """`serve --status-anchor FILE` and `--require-status`: the entries reach the verifier as a
    resolver over the bounded fetch, and a file or a requirement it cannot use stops it starting."""

    setUp = ServeCommandHeldOutTests.setUp
    _serve = ServeCommandHeldOutTests._serve

    def stopped(self, result, *says):
        _MdocServeCase.stopped(self, result, *says)

    def test_the_entries_reach_the_verifier_over_the_bounded_fetch(self):
        from unittest import mock
        from polaris_oid4vp import status_fetch
        path, anchor = _status_anchor_file(self.tmp)
        fetched = []

        def fetch(uri):
            fetched.append(uri)
            raise OSError("not fetched in a test")
        for flags, require, said in (
                ((), False, "the revocation state is reported"),
                (("--require-status",), True, "only a checked, VALID, fresh status is accepted")):
            with self.subTest(flags=flags):
                del fetched[:]
                with mock.patch.object(status_fetch, "fetch_status_list", fetch):
                    rc, seen, out, err = self._serve("--status-anchor", path, *flags)
                self.assertEqual(rc, 0, err)
                verifier = seen["verifier"]
                self.assertIs(verifier.require_status, require)
                self.assertIs(verifier.status_resolver.takes_credential_anchor, True)
                self.assertIn("status lists  1 anchored entry from %s; %s" % (path, said), out)
                answer = verifier.status_resolver(uri=STATUS_PREFIX + "1", idx=0, issuer=None,
                                                  credential_anchor=anchor, credential_leaf=None)
                self.assertEqual(fetched, [STATUS_PREFIX + "1"])
                self.assertIs(answer["checked"], False)

    def test_require_status_without_an_anchor_stops_it_starting(self):
        self.stopped(self._serve("--require-status"), "--require-status needs --status-anchor")

    def test_a_status_anchor_file_it_cannot_use_stops_it_starting(self):
        good = {"credential_anchor": "a.pem", "status_uri_prefix": STATUS_PREFIX,
                "status_anchor": "b.pem", "why": "a reason"}
        cases = (
            ("absent", None, "is not a readable JSON file"),
            ("not JSON", "{", "is not a readable JSON file"),
            ("not an array", dict(entries={}), "is not a non-empty JSON array of entries"),
            ("an empty array", dict(entries=[]), "is not a non-empty JSON array of entries"),
            ("a member missing", dict(why=None), "entry 1 is not an object of exactly"),
            ("a member added", dict(note="x"), "entry 1 is not an object of exactly"),
            ("a path that is not a name", dict(credential_anchor=5),
             "entry 1: credential_anchor is not a file name"),
            ("a file that is not there", dict(status_anchor="absent.pem"),
             "entry 1: status_anchor absent.pem is not a readable PEM certificate file"),
            ("two certificates", dict(status_anchor="two.pem"),
             "entry 1: status_anchor two.pem holds 2 certificates, and an anchor is one"),
            ("an http prefix", dict(status_uri_prefix="http://tsl.provider.example/tsl/"),
             "entry 1: the status URI prefix"),
            ("the second entry", dict(entries=[good, dict(good, status_anchor="a.pem")]),
             "entry 2: "))
        for label, change, said in cases:
            with self.subTest(case=label):
                if change is None:
                    path = str(self.tmp / "absent.json")
                elif isinstance(change, str):
                    path = str(self.tmp / "not-json.json")
                    pathlib.Path(path).write_text(change)
                else:
                    path, _ = _status_anchor_file(self.tmp, **change)
                self.stopped(self._serve("--status-anchor", path), "--status-anchor", said)

    def test_with_an_mdoc_query_each_flag_stops_it_starting(self):
        path, _ = _status_anchor_file(self.tmp)
        self.root = self.tmp / "iaca.pem"
        from cryptography.hazmat.primitives import serialization
        self.root.write_bytes(_self_signed_ca("IACA Test Root").public_bytes(
            serialization.Encoding.PEM))
        for flags in (("--status-anchor", path), ("--require-status",)):
            with self.subTest(flag=flags[0]):
                self.stopped(_MdocServeCase.mdoc(self, *flags), flags[0], "dc+sd-jwt")


class StatusAnchorVerdictTests(unittest.TestCase):
    """`verdict --status-anchor FILE` and `--require-status`, over the two-credential vector,
    whose credentials name no status list."""

    setUp = VerdictCommandTests.setUp
    _write = VerdictCommandTests._write
    _verdict = VerdictCommandTests._verdict

    def test_a_credential_naming_no_list_is_refused_only_under_the_requirement(self):
        path, _ = _status_anchor_file(self.tmp)
        scope = ("--transaction-data-scope", "per_credential")
        rc, result, err = self._verdict("per_credential", *scope, "--status-anchor", path)
        self.assertEqual((rc, result["accepted"]), (0, True), err)
        rc, result, err = self._verdict("per_credential", *scope, "--status-anchor", path,
                                        "--require-status")
        self.assertEqual((rc, result["accepted"]), (1, False), err)
        self.assertEqual(result["verdicts"]["pid"]["code"], "status_required")
        self.assertIn("the revocation state is no_status_claim", result["verdicts"]["pid"]["reason"])

    def test_a_requirement_or_a_file_it_cannot_use_is_refused(self):
        for flags, said in ((("--require-status",), "--require-status needs --status-anchor"),
                            (("--status-anchor", self._write("bad.json", "{")), "--status-anchor")):
            with self.subTest(flag=flags[0]):
                rc, result, err = self._verdict("per_credential", *flags)
                self.assertEqual((rc, result), (2, None))
                self.assertIn(said, err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
