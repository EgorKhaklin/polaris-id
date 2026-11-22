#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""capture_shim.py only observes: it replaces one method and puts it back, the request objects and
the verdicts are the verifier's own, and what it keeps rebuilds the SessionTranscript the wallet
signed over.

    python -m unittest lab/interop/mdoc/test_capture_shim.py

The verifier is this tree's packages/polaris-oid4vp, driven as its own test_verifier.py drives an
mso_mdoc verifier: MdocVerifierCase's verifier, answered by MdocWallet.
"""
import base64
import importlib.util
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

import cbor2

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "packages" / "polaris-oid4vp"))

import test_mdoc as md  # noqa: E402
import test_verifier as tv  # noqa: E402
from polaris_oid4vp import cli, jwe, mdoc, serve, verifier  # noqa: E402

_spec = importlib.util.spec_from_file_location("capture_shim", HERE / "capture_shim.py")
shim = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shim)

KEPT = ["captured-at.txt", "device-response.cbor", "openid4vp-inputs.json", "verdict.json"]
#: The members of a request object that differ from one request to the next.
PER_REQUEST = ("nonce", "state", "iat", "exp", "client_metadata")


def replaced(modules, before):
    """The (owner, name) pairs whose binding is not the one `before` recorded."""
    return sorted((getattr(m, "__name__", repr(m)), name) for m, was in zip(modules, before)
                  for name in set(was) | set(vars(m)) if vars(m).get(name) is not was.get(name))


class CaptureShimTests(tv.MdocVerifierCase):

    def setUp(self):
        super().setUp()
        self.out = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.out, ignore_errors=True)

    def install(self):
        uninstall = shim.install(self.out)
        self.addCleanup(uninstall)
        return uninstall

    def answer(self, **kw):
        """One request on this test's verifier and the wallet's answer to it: (request object, result)."""
        _, jar = self.verifier.new_request()
        return jar, self.verifier.handle_direct_post(self.wallet.respond(jar, **kw))

    def test_one_method_is_replaced_and_put_back(self):
        modules = (verifier, verifier.Verifier, mdoc, jwe, cli, serve)
        before = [dict(vars(m)) for m in modules]
        uninstall = shim.install(self.out)
        try:
            self.assertEqual(replaced(modules, before), [("Verifier", "_judge_mdoc")])
        finally:
            uninstall()
        self.assertEqual(replaced(modules, before), [])

    def test_the_request_object_is_the_verifiers(self):
        """Signatures are randomized, so the request objects are compared decoded: the header
        whole, and every claim but those that differ from one request to the next. Those carry the
        same members, and the encryption key the same shape."""
        _, plain = self.verifier.new_request()
        self.install()
        _, shimmed = self.verifier.new_request()
        (h1, c1), (h2, c2) = tv.Wallet.read_request(plain), tv.Wallet.read_request(shimmed)
        self.assertEqual(h1, h2)
        self.assertEqual({k: v for k, v in c1.items() if k not in PER_REQUEST},
                         {k: v for k, v in c2.items() if k not in PER_REQUEST})
        self.assertEqual(set(c1), set(c2))
        m1, m2 = c1["client_metadata"], c2["client_metadata"]
        self.assertEqual({k: v for k, v in m1.items() if k != "jwks"}, {k: v for k, v in m2.items() if k != "jwks"})
        self.assertEqual(sorted(m1["jwks"]["keys"][0]), sorted(m2["jwks"]["keys"][0]))

    def test_the_verdicts_are_the_verifiers(self):
        """Each answer judged without the shim, then with it: the same status and the same verdict."""
        answers = {"accepted": {}, "made for another nonce": {"nonce": "another"},
                   "made for another response key": {"thumbprint": bytes(32)},
                   "made for another response_uri": {"response_uri": "https://elsewhere.test/response"},
                   "an element the query did not ask for": {"items": (md.el("age_over_21", True),
                                                                      md.el("family_name", "Mustermann"))}}
        plain = {name: self.answer(**kw)[1] for name, kw in answers.items()}
        self.install()
        shimmed = {name: self.answer(**kw)[1] for name, kw in answers.items()}
        for name in answers:
            with self.subTest(answer=name):
                (s1, b1, v1), (s2, b2, v2) = plain[name], shimmed[name]
                self.assertEqual((s1, v1.authentic, v1.code, v1.reason, v1.claims, v1.disclosed),
                                 (s2, v2.authentic, v2.code, v2.reason, v2.claims, v2.disclosed))
                self.assertEqual(sorted(b1), sorted(b2))
        self.accepted(shimmed["accepted"])
        self.assertEqual(sum(1 for v in plain.values() if v[2].authentic), 1)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), [str(n) for n in range(1, len(answers) + 1)])

    def test_what_is_kept_rebuilds_the_transcript_the_wallet_signed_over(self):
        self.install()
        jar, result = self.answer()
        self.accepted(result)
        kept = self.out / "1"
        self.assertEqual(sorted(p.name for p in kept.iterdir()), KEPT)
        inputs = json.loads((kept / "openid4vp-inputs.json").read_text())
        _, claims = tv.Wallet.read_request(jar)
        jwk = claims["client_metadata"]["jwks"]["keys"][0]
        self.assertEqual(inputs, {
            "response_mode": "direct_post.jwt", "client_id": claims["client_id"], "nonce": claims["nonce"],
            "response_uri": claims["response_uri"], "encryption_jwk": {k: jwk[k] for k in shim.JWK_MEMBERS},
            "doctype_value": md.MDL, "claims": claims["dcql_query"]["credentials"][0]["claims"]})
        # A witness has the kept bytes and the kept inputs, nothing else: they verify under the
        # transcript built from those inputs (on cbor2 and hashlib, not the package's code), and
        # not under one with another thumbprint.
        def transcript(thumbprint):
            return cbor2.dumps(md.witness_transcript(inputs["client_id"], inputs["nonce"], thumbprint,
                                                     inputs["response_uri"]))
        response = (kept / "device-response.cbor").read_bytes()
        roots = [mdoc.IacaRoot(md.IACA, [md.MDL])]
        self.assertTrue(md.judge(response, transcript=transcript(md.witness_thumbprint(inputs["encryption_jwk"])),
                                 roots=roots).authentic)
        self.assertFalse(md.judge(response, transcript=transcript(bytes(32)), roots=roots).authentic)
        self.assertEqual(json.loads((kept / "verdict.json").read_text()),
                         {"authentic": True, "code": result[2].code, "reason": result[2].reason})

    def test_a_refusal_is_kept_with_the_verifiers_reason(self):
        self.install()
        _, (status, _, verdict) = self.answer(nonce="another")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads((self.out / "1" / "verdict.json").read_text()),
                         {"authentic": False, "code": verdict.code, "reason": verdict.reason})

    def test_a_value_that_is_not_a_device_response_is_not_kept(self):
        """Not base64url; empty; base64url of bytes that are not CBOR; of a CBOR array; of a CBOR
        map without a DeviceResponse's version and status. Each is refused and none is kept."""
        def b64u(raw):
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        self.install()
        for value in ("!!", "", b64u(b"\xff\x00"), b64u(cbor2.dumps([1, 2])),
                      b64u(cbor2.dumps({"version": "1.0"})), b64u(cbor2.dumps({"status": 0}))):
            with self.subTest(value=value):
                _, (status, _, verdict) = self.answer(vp_token=lambda _, value=value: {"mdoc": [value]})
                self.assertEqual((status, verdict.authentic), (400, False))
        self.assertEqual(list(self.out.iterdir()), [])

    def test_a_failure_to_keep_changes_no_verdict(self):
        self.install()
        (self.out / "1").write_text("in the way\n")  # the first answer's directory cannot be made
        _, result = self.answer()
        self.accepted(result)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["1"])

    def test_main_refuses_an_out_that_is_not_empty(self):
        (self.out / "left").write_text("from an earlier run\n")
        for argv in ([str(self.out), "serve"], [str(self.out / "left"), "serve"]):
            with self.subTest(argv=argv[0]):
                with self.assertRaises(SystemExit) as caught:
                    shim.main(argv)
                self.assertIn("is not an empty directory", str(caught.exception.code))
        with self.assertRaises(SystemExit) as caught:
            shim.main([str(self.out), "keygen"])
        self.assertIn("capture_shim.py OUT serve", str(caught.exception.code))


if __name__ == "__main__":
    unittest.main()
