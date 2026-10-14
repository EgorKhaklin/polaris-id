# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The check-in example end to end: the app on a local port, the lab's stand-in wallet scanning it.

The stand-in (lab/interop/yivi/standin_wallet.py) presents what the Yivi app presents: an email
credential with `domain` = example.org disclosed and the address withheld. Here one stand-in
"attestation providers" CA certifies three provider leaves, as Yivi's certifies every Yivi
provider: the expected issuer's, another provider's, and one that names no issuer at all. Each
case reads the desk page the person at the door sees.
"""
import contextlib
import datetime
import hashlib
import io
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path[:0] = [str(HERE), str(HERE.parents[1]), str(ROOT / "lab" / "interop" / "yivi")]

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509 import load_pem_x509_certificates  # noqa: E402
from polaris_oid4vp import cli  # noqa: E402

import standin_wallet  # noqa: E402

# fastapi, uvicorn and segno come from requirements.txt here, not from the shared test venv. CI
# installs them and sets CHECKIN_REQUIRED, so there a missing one fails the run instead of skipping.
try:
    import uvicorn

    import app as checkin
    MISSING = None
except ImportError as exc:
    MISSING = exc

ISSUER = "https://is.standin.invalid"           # the one issuer the desk accepts
OTHER = "https://other-provider.standin.invalid"  # another provider under the same CA
YIVI_CA_DER_SHA256 = "0c7e79d26737cda146e77bad55f96153604a1445cb5b3417f8ca3b4b9a8cc1bf"


def _port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(url, host=None):
    req = urllib.request.Request(url, headers={"Host": host} if host else {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.geturl(), r.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, url, exc.read().decode()


def _get_status(url):
    try:
        return _get(url)[0]
    except OSError:
        return None


def _provider(out, ca, ca_key, uri, cn=None):
    """A provider leaf under the stand-in CA, laid out as standin_wallet.present reads it.
    `uri` is the leaf's URI name, the issuer it names; None names none. `cn` sets its subject."""
    out.mkdir()
    now = datetime.datetime.now(datetime.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(standin_wallet._name(cn or "provider " + str(uri)))
            .issuer_name(ca.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False,
                                         False), critical=True))
    if uri:
        leaf = leaf.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]),
                                  critical=False)
    pem = serialization.Encoding.PEM
    (out / "leaf.pem").write_bytes(leaf.sign(ca_key, hashes.SHA256()).public_bytes(pem))
    (out / "leaf-key.pem").write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
    return out


@unittest.skipIf(MISSING is not None and not os.environ.get("CHECKIN_REQUIRED"),
                 "pip install --require-hashes -r requirements.txt to run these: %s" % MISSING)
class CheckIn(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if MISSING is not None:
            raise MISSING
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = pathlib.Path(cls.tmp.name)
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["keygen", "--out", str(tmp / "pki"), "--host", "127.0.0.1"]) == 0
        cls.cert = (tmp / "pki" / "client.pem").read_bytes()
        cls.key = (tmp / "pki" / "client-key.pem").read_bytes()
        now = datetime.datetime.now(datetime.timezone.utc)
        root_key, ca_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
        root_name = standin_wallet._name("Stand-in root")
        root = standin_wallet._ca(root_name, root_key, root_name, root_key, now)
        ca = standin_wallet._ca(standin_wallet._name("Stand-in attestation providers CA"), ca_key,
                                root.subject, root_key, now)
        cls.standin_ca = [ca]
        cls.yivi_ca = load_pem_x509_certificates(
            (HERE / "yivi-attestation-providers-ca.pem").read_bytes())
        cls.expected = _provider(tmp / "expected", ca, ca_key, ISSUER)
        cls.other = _provider(tmp / "other", ca, ca_key, OTHER)
        cls.nameless = _provider(tmp / "nameless", ca, ca_key, None)
        cls.cn_only = _provider(tmp / "cn-only", ca, ca_key, None, cn=urllib.parse.urlsplit(ISSUER).hostname)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def serve(self, allowed, anchors=None, logo=None):
        port = _port()
        base = "http://127.0.0.1:%d" % port
        app = checkin.create_app(base, self.cert, self.key, allowed,
                                 self.standin_ca if anchors is None else anchors, ISSUER, logo=logo)
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.time() + 10
        while not server.started:
            self.assertLess(time.time(), deadline, "the app did not start")
            time.sleep(0.05)

        def stop():
            server.should_exit = True
            thread.join(10)
        self.addCleanup(stop)
        return base

    def scan(self, base, provider, iss):
        """Open the desk, take the link behind its QR code, and present from `provider` with
        `iss` in the credential. Returns the desk page's text and what the wallet was told."""
        status, desk, page = _get(base + "/")
        self.assertEqual(status, 200)
        self.assertIn("<svg", page)
        link = re.search(r'id="link" href="([^"]+)"', page).group(1).replace("&amp;", "&")
        self.assertTrue(link.startswith("https://open.yivi.app/-/openid4vp?"), link)
        out = io.StringIO()
        with mock.patch.object(standin_wallet, "ISS", iss), contextlib.redirect_stdout(out):
            standin_wallet.present(provider, link)
        self.last_desk = desk
        return self.desk(desk), out.getvalue()

    def junk(self, base, desk):
        """Post what anyone who saw the QR code could post: refused, 400."""
        aid = urllib.parse.urlsplit(desk).path.rsplit("/", 1)[1]
        post = urllib.request.Request(base + "/response/" + aid, data=b"response=x.y.z.w.v")
        with self.assertRaises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(post, timeout=10)
        self.assertEqual(refused.exception.code, 400)

    def desk(self, url):
        status, _, page = _get(url)
        self.assertEqual(status, 200)
        self.assertNotIn("rehearsal@example.org", page)  # the address is never shown
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page.split("</style>", 1)[1]))

    REFUSED = '400 {"error":"invalid_request","error_description":"the presentation was not accepted"}'

    def test_allowed_domain_is_checked_in(self):
        base = self.serve(["Example.ORG"])
        shown, said = self.scan(base, self.expected, ISSUER)
        self.assertIn('200 {"redirect_uri":"%s/done"}' % base, said)
        self.assertEqual(shown.split(" Next person")[0].strip(), "Checked in example.org")
        self.assertEqual(_get(base + "/done")[0], 200)

    def test_domain_off_the_list_is_refused(self):
        base = self.serve(["example.edu"])
        shown, said = self.scan(base, self.expected, ISSUER)
        self.assertIn(self.REFUSED, said)
        self.assertIn("Not checked in example.org is not on the list for this check-in.", shown)

    def test_untrusted_issuer_is_refused(self):
        base = self.serve(["example.org"], anchors=self.yivi_ca)
        shown, said = self.scan(base, self.expected, ISSUER)
        self.assertIn(self.REFUSED, said)
        self.assertIn("Not checked in refused: issuer_key", shown)
        self.assertNotIn("example.org", shown)

    def test_another_provider_as_itself_is_refused(self):
        # Authentic under the trusted CA, and its leaf names it: only the pin refuses it.
        base = self.serve(["example.org"])
        shown, said = self.scan(base, self.other, OTHER)
        self.assertIn(self.REFUSED, said)
        self.assertIn("Not checked in issued by %s, not %s" % (OTHER, ISSUER), shown)
        self.assertNotIn("example.org", shown)

    def test_another_provider_claiming_the_issuer_is_refused(self):
        # Its leaf names OTHER: polaris-oid4vp refuses an iss the leaf does not name.
        base = self.serve(["example.org"])
        shown, said = self.scan(base, self.other, ISSUER)
        self.assertIn(self.REFUSED, said)
        self.assertIn("Not checked in refused: issuer_key", shown)

    def test_a_leaf_naming_no_issuer_cannot_claim_it(self):
        # Its leaf names nobody, so nothing binds the iss: the verdict leaves it out of claims.
        # So the pin's `iss_bound is not True` clause alone is caught by nothing here: removing it
        # keeps this and the common-name case refused, by claims["iss"]. It stays as defence in
        # depth, should the verdict ever carry an iss it does not bind.
        base = self.serve(["example.org"])
        shown, said = self.scan(base, self.nameless, ISSUER)
        self.assertIn(self.REFUSED, said)
        self.assertIn("Not checked in issued by an issuer its certificate does not name, not %s"
                      % ISSUER, shown)

    def test_a_leaf_whose_common_name_is_the_issuer_cannot_claim_it(self):
        # CN=is.standin.invalid and no subjectAltName: a common name binds no iss either.
        base = self.serve(["example.org"])
        shown, said = self.scan(base, self.cn_only, ISSUER)
        self.assertIn(self.REFUSED, said)
        self.assertIn("Not checked in issued by an issuer its certificate does not name, not %s"
                      % ISSUER, shown)

    def test_a_wallets_error_response_shows_nothing_and_leaves_the_request_open(self):
        # 200 and not authentic (the holder declined): the desk keeps waiting, as for any post
        # that anyone who saw the QR code could have sent.
        base = self.serve(["example.org"])
        _, desk, page = _get(base + "/")
        link = re.search(r'id="link" href="([^"]+)"', page).group(1).replace("&amp;", "&")
        request_uri = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)["request_uri"][0]
        state = urllib.parse.parse_qs(urllib.parse.urlsplit(request_uri).query)["state"][0]
        aid = urllib.parse.urlsplit(desk).path.rsplit("/", 1)[1]
        post = urllib.request.Request(base + "/response/" + aid, data=urllib.parse.urlencode(
            {"error": "access_denied", "state": state}).encode())
        with urllib.request.urlopen(post, timeout=10) as answered:
            self.assertEqual(answered.status, 200)
        self.assertIn("Scan with the Yivi app", self.desk(desk))

    def test_a_post_after_the_check_in_changes_nothing(self):
        # The response path is in the public request object: a post after the wallet's must not
        # turn "Checked in" into a refusal.
        base = self.serve(["example.org"])
        shown, said = self.scan(base, self.expected, ISSUER)
        self.assertIn('200 {"redirect_uri":"%s/done"}' % base, said)
        self.junk(base, self.last_desk)
        self.assertEqual(self.desk(self.last_desk).split(" Next person")[0].strip(),
                         "Checked in example.org")

    def test_a_post_after_the_request_expired_changes_nothing(self):
        class OneSecond(checkin.Verifier):
            def __init__(self, **kwargs):
                super().__init__(request_ttl_seconds=1, **kwargs)
        with mock.patch.object(checkin, "Verifier", OneSecond):
            base = self.serve(["example.org"])
            _, desk, _ = _get(base + "/")
            time.sleep(1.3)
            self.junk(base, desk)
            shown = self.desk(desk)
        self.assertIn("Expired", shown)
        self.assertNotIn("Not checked in", shown)

    def test_a_domain_that_only_lowers_to_the_list_is_refused(self):
        # "\u212aexample.org".lower() == "kexample.org": the Kelvin sign is not a K.
        base = self.serve(["kexample.org"])
        real = standin_wallet._disclosure
        kelvin = lambda name, value: real(name, "\u212aexample.org" if name == "domain" else value)  # noqa: E731
        with mock.patch.object(standin_wallet, "_disclosure", kelvin):
            shown, said = self.scan(base, self.expected, ISSUER)
        self.assertIn(self.REFUSED, said)
        self.assertIn("Not checked in \u212aexample.org is not on the list for this check-in.", shown)

    def test_a_post_that_does_not_open_leaves_the_request_open(self):
        base = self.serve(["example.org"])
        _, desk, _ = _get(base + "/")
        aid = urllib.parse.urlsplit(desk).path.rsplit("/", 1)[1]
        post = urllib.request.Request(base + "/response/" + aid, data=b"response=x.y.z.w.v")
        with self.assertRaises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(post, timeout=10)
        self.assertEqual(refused.exception.code, 400)
        self.assertIn("Scan with the Yivi app", self.desk(desk))

    def test_the_server_keeps_no_access_log(self):
        # app.py as an operator runs it, its output captured through a scan: uvicorn's default access
        # log prints each request's client address, which for a real desk is an attendee's IP.
        port = _port()
        base = "http://127.0.0.1:%d" % port
        tmp = pathlib.Path(self.tmp.name)
        anchor = tmp / "standin-ca.pem"
        anchor.write_bytes(self.standin_ca[0].public_bytes(serialization.Encoding.PEM))
        env = dict(os.environ, PYTHONPATH=str(HERE.parents[1]), CHECKIN_PUBLIC_URL=base,
                   CHECKIN_PKI=str(tmp / "pki"), CHECKIN_ALLOWED="example.org",
                   CHECKIN_ISSUER_CA=str(anchor), CHECKIN_ISSUER=ISSUER, CHECKIN_PORT=str(port))
        log = tmp / "server-output.log"
        with open(log, "wb") as out:
            server = subprocess.Popen([sys.executable, str(HERE / "app.py")], env=env, stdout=out,
                                      stderr=subprocess.STDOUT)

        def stop():
            if server.poll() is None:
                server.terminate()
                server.wait(10)
        self.addCleanup(stop)
        deadline = time.time() + 20
        while _get_status(base + "/done") != 200:
            self.assertLess(time.time(), deadline, "app.py did not start: %s" % log.read_text()[-500:])
            time.sleep(0.1)
        shown, said = self.scan(base, self.expected, ISSUER)
        self.assertIn("Checked in example.org", shown)
        stop()
        output = log.read_text()
        self.assertIn("Uvicorn running on", output)  # the output really was captured
        self.assertNotIn("POST /response", output)
        self.assertNotRegex(output, r"127\.0\.0\.1:\d+ - \"")

    def test_the_desk_is_not_served_through_the_tunnel(self):
        base = self.serve(["example.org"], logo=b"x")
        self.assertEqual(_get(base + "/", host="abc.trycloudflare.com")[0], 404)
        self.assertEqual(_get(base + "/logo.webp", host="abc.trycloudflare.com")[0], 404)
        self.assertEqual(_get(base + "/")[0], 200)
        self.assertEqual(_get(base + "/logo.webp")[0], 200)

    def test_it_will_not_start_without_a_list_a_ca_or_an_issuer(self):
        for allowed, anchors, issuer in (([], self.standin_ca, ISSUER), ([" "], self.standin_ca, ISSUER),
                                         (["example.org"], [], ISSUER),
                                         (["\u212aexample.org"], self.standin_ca, ISSUER),
                                         (["example.org"], self.standin_ca, "")):
            with self.assertRaises(ValueError):
                checkin.create_app("https://x.invalid", self.cert, self.key, allowed, anchors, issuer)


class PinnedCa(unittest.TestCase):
    def test_the_yivi_ca_is_the_lab_pinned_copy(self):
        here = (HERE / "yivi-attestation-providers-ca.pem").read_bytes()
        self.assertEqual(here, (ROOT / "lab/interop/yivi/yivi-attestation-providers-ca.pem").read_bytes())
        der = load_pem_x509_certificates(here)[0].public_bytes(serialization.Encoding.DER)
        self.assertEqual(hashlib.sha256(der).hexdigest(), YIVI_CA_DER_SHA256)


if __name__ == "__main__":
    unittest.main()
