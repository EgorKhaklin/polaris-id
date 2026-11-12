# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""avp.py and serve.py hold the age-verification profile: each must-fail case is refused at its own step.

The vectors are make_vectors.py's, made with our own test keys from a public seed, and committed under vectors/.
Each case names its verdict or the check that refuses it. A test that only asked for a refusal would pass with the
check it means switched off.

    python3 -m unittest lab/interop/altid/test_avp.py
"""
import base64
import datetime
import filecmp
import hashlib
import http.client
import importlib.util
import io
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors")
UTC = datetime.timezone.utc


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, path
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


avp = _load("avp_under_test", os.path.join(HERE, "avp.py"))
mv = _load("make_vectors_under_test", os.path.join(HERE, "make_vectors.py"))
serve = _load("serve_under_test", os.path.join(HERE, "serve.py"))

with open(os.path.join(VECTORS, "manifest.json")) as _f:
    MANIFEST = json.load(_f)
CASES = {c["name"]: c for c in MANIFEST["cases"]}


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def at(text):
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))


def vector_record(**over):
    """The record of the request make_vectors' documents answer (its TXID, response_uri and nonce)."""
    record = {"txid": mv.TXID, "state": mv.TXID, "nonce": mv.NONCE, "response_uri": mv.RESPONSE_URI,
              "client_id": "redirect_uri:" + mv.RESPONSE_URI, "flow": "qr", "browser": None,
              "created": "2026-11-12T11:55:00Z", "expires": "2026-11-12T12:05:00Z", "status": "open"}
    record.update(over)
    return record


def form(raw, state=mv.TXID):
    return {"vp_token": [b64u(raw)], "state": [state]}


def vector(name):
    with open(os.path.join(VECTORS, name, "device-response.cbor"), "rb") as f:
        return f.read()


def anchors_for(name):
    case = CASES[name]
    return avp.anchors_from([os.path.join(VECTORS, "certs", p + ".pem") for p in case["pins"]], case["pins_sha256"])


GOOD = mv.mint()  # table13-array: satisfied under the Table 13-shape anchor
T13 = [mv.T13]


class VectorFiles(unittest.TestCase):
    def test_make_vectors_writes_the_committed_vectors_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as d:
            mv.write(d)
            cmp = filecmp.dircmp(d, VECTORS)
            self.assertEqual((cmp.left_only, cmp.right_only, cmp.diff_files), ([], [], []))
            for sub in cmp.common_dirs:
                c = filecmp.dircmp(os.path.join(d, sub), os.path.join(VECTORS, sub))
                self.assertEqual((sub, c.left_only, c.right_only), (sub, [], []))
                _, mismatch, errors = filecmp.cmpfiles(os.path.join(d, sub), os.path.join(VECTORS, sub),
                                                       c.common_files, shallow=False)
                self.assertEqual((sub, mismatch, errors), (sub, [], []))

    def test_the_manifest_names_every_case_once(self):
        self.assertEqual(sorted(CASES), sorted(mv.CASES))
        self.assertGreater(len(CASES), 20)


class Cases(unittest.TestCase):
    """Every vector meets its expected verdict, read from the committed files, under its pinned anchors."""


def _case_test(name):
    def test(self):
        case = CASES[name]
        if case["expected"] in ("satisfied", "not satisfied"):
            verdict = avp.verify_avp(form(vector(name)), vector_record(), anchors_for(name), at(case["at"]))
            self.assertIs(verdict["satisfied"], case["expected"] == "satisfied")
        else:
            with self.assertRaises(avp.Refused) as cm:
                avp.verify_avp(form(vector(name)), vector_record(), anchors_for(name), at(case["at"]))
            self.assertEqual(cm.exception.check, case["expected"], str(cm.exception))
    test.__doc__ = "%s: %s" % (name, CASES[name]["expected"])
    return test


for _name in mv.CASES:
    setattr(Cases, "test_" + _name.replace("-", "_"), _case_test(_name))


class Steps1to4(unittest.TestCase):
    def refused(self, frm, check, record=None):
        with self.assertRaises(avp.Refused) as cm:
            avp.verify_avp(frm, record or vector_record(), T13, mv.AT)
        self.assertEqual(cm.exception.check, check, str(cm.exception))
        return cm.exception

    def test_a_form_without_vp_token_is_refused(self):
        self.refused({"state": [mv.TXID]}, "vp_token")

    def test_a_repeated_vp_token_is_refused(self):
        self.refused({"vp_token": [b64u(GOOD), b64u(GOOD)], "state": [mv.TXID]}, "vp_token")

    def test_a_vp_token_that_is_not_base64url_is_refused(self):
        # each is of a length base64 decodes, so the alphabet, not the length, is what refuses it
        for token in ("ab+/", "oQ+B", "oQ/B", "oQ.B", "oQ=B"):
            self.refused({"vp_token": [token], "state": [mv.TXID]}, "vp_token")
        for token in ("abcde", "a==="):  # the length and padding rules
            self.refused({"vp_token": [token], "state": [mv.TXID]}, "vp_token")

    def test_a_vp_token_that_is_not_cbor_is_refused(self):
        self.refused({"vp_token": [b64u(b"\xff\x00")], "state": [mv.TXID]}, "cbor")

    def test_a_device_response_that_is_not_a_map_is_refused(self):
        import cbor2
        self.refused(form(cbor2.dumps([1, 2, 3])), "device response")

    def test_a_device_response_of_another_version_is_refused(self):
        import cbor2
        resp = cbor2.loads(GOOD)
        # the control: the same map written again with version "1.0" still verifies
        self.assertIs(avp.verify_avp(form(cbor2.dumps(dict(resp, version="1.0"))), vector_record(), T13,
                                     mv.AT)["satisfied"], True)
        for version in ("1.1", "2.0", "", 1, None):  # a float never gets here: the CBOR reader refuses one
            self.refused(form(cbor2.dumps(dict(resp, version=version))), "device response")

    def test_the_bare_string_form_verifies_and_is_recorded(self):
        verdict = avp.verify_avp(form(GOOD), vector_record(), T13, mv.AT)
        self.assertIs(verdict["satisfied"], True)
        self.assertEqual(verdict["vp_token_form"], "string")

    def test_the_openid4vp_object_form_verifies_and_is_recorded(self):
        token = json.dumps({"proof_of_age": [b64u(GOOD)]})
        verdict = avp.verify_avp({"vp_token": [token], "state": [mv.TXID]}, vector_record(), T13, mv.AT)
        self.assertIs(verdict["satisfied"], True)
        self.assertEqual(verdict["vp_token_form"], "object")

    def test_an_object_with_two_presentations_is_refused(self):
        token = json.dumps({"proof_of_age": [b64u(GOOD), b64u(GOOD)]})
        self.refused({"vp_token": [token], "state": [mv.TXID]}, "vp_token")

    def test_an_object_under_another_query_id_is_refused(self):
        token = json.dumps({"other": [b64u(GOOD)]})
        self.refused({"vp_token": [token], "state": [mv.TXID]}, "vp_token")

    def test_a_state_that_differs_from_the_record_is_refused(self):
        self.refused(form(GOOD, state="x" * 43), "state")

    def test_a_form_without_state_is_refused(self):
        self.refused({"vp_token": [b64u(GOOD)]}, "state")

    def test_the_record_nonce_is_the_one_the_transcript_binds(self):
        other = b64u(bytes(16))
        self.assertNotEqual(other, mv.NONCE)
        self.refused(form(GOOD), "device signature", vector_record(nonce=other))


class TrustList(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.t13 = os.path.join(self.d, "t13.pem")
        with open(self.t13, "w") as f:
            f.write(mv.pem(mv.T13))

    def test_a_pinned_pem_loads(self):
        self.assertEqual(avp.anchors_from([self.t13], [mv.sha256_hex(mv.T13)]), [mv.T13])

    def test_a_pem_whose_hash_is_not_pinned_is_refused_when_it_loads(self):
        with self.assertRaises(avp.Refused) as cm:
            avp.anchors_from([self.t13], [mv.sha256_hex(mv.ROOT)])
        self.assertEqual(cm.exception.check, "trust list")

    def test_no_pem_is_refused(self):
        with self.assertRaises(avp.Refused) as cm:
            avp.anchors_from([], [mv.sha256_hex(mv.T13)])
        self.assertEqual(cm.exception.check, "trust list")

    def test_the_committed_trust_list_loads_under_its_pin_and_is_self_signed(self):
        trust = os.path.join(HERE, "trust")
        anchors = avp.anchors_from([os.path.join(trust, "dktb-test.pem")], avp.read_pins(os.path.join(trust, "PINS")))
        self.assertEqual([mv.sha256_hex(a) for a in anchors],
                         ["4c3081a4c612e09906316347a7fd531097f4bcb1f920a18d9ebed6efd84ebf7a"])
        self.assertTrue(avp._self_signed(anchors[0]))

    def test_the_vectors_table13_shape_leaf_has_the_real_certificates_extensions(self):
        from cryptography import x509 as x
        real = avp.anchors_from([os.path.join(HERE, "trust", "dktb-test.pem")],
                                avp.read_pins(os.path.join(HERE, "trust", "PINS")))[0]

        def shape(cert):
            ext = {e.oid.dotted_string: e for e in cert.extensions}
            ku = ext["2.5.29.15"].value
            return {"oids": sorted(ext), "ku_critical": ext["2.5.29.15"].critical,
                    "ku": (ku.digital_signature, ku.content_commitment, ku.key_encipherment, ku.key_cert_sign),
                    "ca": ext["2.5.29.19"].value.ca,
                    "eku": sorted(o.dotted_string for o in ext["2.5.29.37"].value),
                    "aki_is_ski": ext["2.5.29.35"].value.key_identifier == ext["2.5.29.14"].value.digest,
                    "sig": cert.signature_algorithm_oid.dotted_string, "self": cert.subject == cert.issuer}
        self.assertEqual(shape(mv.T13), shape(real))
        self.assertIsInstance(real.extensions.get_extension_for_class(x.ExtendedKeyUsage).value, x.ExtendedKeyUsage)

    def test_pins_read_with_comments_and_refuse_an_empty_file(self):
        p = os.path.join(self.d, "PINS")
        with open(p, "w") as f:
            f.write("# a comment\n%s  t13.pem\n\n" % mv.sha256_hex(mv.T13).upper())
        self.assertEqual(avp.read_pins(p), {mv.sha256_hex(mv.T13)})
        with open(p, "w") as f:
            f.write("# nothing pinned\n")
        with self.assertRaises(avp.Refused):
            avp.read_pins(p)
        with open(p, "w") as f:
            f.write("not-a-hash\n")
        with self.assertRaises(avp.Refused):
            avp.read_pins(p)


class Request(unittest.TestCase):
    NOW = datetime.datetime(2026, 11, 12, 12, 0, 0, tzinfo=UTC)

    def test_the_request_carries_the_profile_parameters(self):
        params, links, record = avp.new_transaction("https://avp.example", now=self.NOW)
        self.assertEqual(params["client_id"], "redirect_uri:" + params["response_uri"])
        self.assertTrue(params["response_uri"].startswith("https://avp.example/response/"))
        self.assertEqual(params["response_uri"].rsplit("/", 1)[1], params["state"])
        self.assertEqual(len(base64.urlsafe_b64decode(params["state"] + "=")), 32)
        self.assertEqual(len(base64.urlsafe_b64decode(params["nonce"] + "==")), 16)
        self.assertEqual((params["response_type"], params["response_mode"]), ("vp_token", "direct_post"))
        self.assertEqual(json.loads(params["dcql_query"]), {"credentials": [
            {"id": "proof_of_age", "format": "mso_mdoc", "meta": {"doctype_value": "eu.europa.ec.av.1"},
             "claims": [{"path": ["eu.europa.ec.av.1", "age_over_18"]}]}]})
        self.assertFalse({"request", "request_uri", "client_metadata"} & set(params))
        for link, prefix in ((links["app"], avp.APP_LINK + "?"), (links["av"], "av://?")):
            self.assertTrue(link.startswith(prefix), link)
            self.assertEqual({k: v[0] for k, v in urllib.parse.parse_qs(link.split("?", 1)[1]).items()}, params)
        self.assertEqual((record["status"], record["nonce"], record["state"]), ("open", params["nonce"], params["state"]))
        self.assertEqual(at(record["expires"]) - at(record["created"]), datetime.timedelta(minutes=10))

    def test_two_requests_share_no_identifier(self):
        a, _, _ = avp.new_transaction("https://avp.example", now=self.NOW)
        b, _, _ = avp.new_transaction("https://avp.example", now=self.NOW)
        self.assertNotEqual(a["state"], b["state"])
        self.assertNotEqual(a["nonce"], b["nonce"])

    def test_a_client_id_other_than_redirect_uri_plus_response_uri_is_refused_at_the_request(self):
        params, _, _ = avp.new_transaction("https://avp.example", now=self.NOW)
        for bad in (params["response_uri"], "redirect_uri:" + params["response_uri"] + "/",
                    "x509_hash:" + params["response_uri"]):
            with self.assertRaises(avp.Refused) as cm:
                avp.check_request(dict(params, client_id=bad))
            self.assertEqual(cm.exception.check, "request")

    def test_the_request_rules_refuse_another_parameter_set_query_mode_or_a_short_nonce(self):
        params, _, _ = avp.new_transaction("https://avp.example", now=self.NOW)
        avp.check_request(params)  # the control: the request as made passes
        other = json.loads(params["dcql_query"])
        other["credentials"][0]["claims"][0]["path"][1] = "age_over_21"
        short = base64.urlsafe_b64encode(b"\x07" * 15).rstrip(b"=").decode()
        for bad, why in ((dict(params, request_uri="https://avp.example/r"), "differ from the profile"),
                         ({k: v for k, v in params.items() if k != "state"}, "differ from the profile"),
                         (dict(params, dcql_query=json.dumps(other)), "DCQL"),
                         (dict(params, response_mode="direct_post.jwt"), "direct_post"),
                         (dict(params, nonce=short), "128 bits")):
            with self.assertRaises(avp.Refused) as cm:
                avp.check_request(bad)
            self.assertEqual(cm.exception.check, "request")
            self.assertIn(why, str(cm.exception))

    def test_a_base_url_that_is_not_https_is_refused(self):
        for bad in ("http://avp.example", "https://", "https://avp.example/?q=1", "https://u@avp.example"):
            with self.assertRaises(ValueError):
                avp.new_transaction(bad, now=self.NOW)

    def test_a_same_device_request_keeps_the_detected_browser_only(self):
        _, _, record = avp.new_transaction("https://avp.example", flow="link", browser="firefox", now=self.NOW)
        self.assertEqual((record["flow"], record["browser"]), ("link", "firefox"))
        _, _, record = avp.new_transaction("https://avp.example", flow="link", browser="netscape", now=self.NOW)
        self.assertEqual(record["browser"], "app")

    def test_browser_detection_follows_table_6(self):
        uas = {
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/18.0 Mobile/15E148 Safari/604.1": "safari",
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36":
                "chrome",
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36 "
            "EdgA/130.0": "edge",
            "Mozilla/5.0 (Android 14; Mobile; rv:132.0) Gecko/132.0 Firefox/132.0": "firefox",
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 "
            "Chrome/122.0 Mobile Safari/537.36": "samsung",
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36 "
            "OPR/85.0": "opera",
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36 "
            "DuckDuckGo/5": "duck",
            "": "app", None: "app", "curl/8.7.1": "app",
        }
        for ua, want in uas.items():
            self.assertEqual(avp.detect_browser(ua), want, ua)


class Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


FORM = "application/x-www-form-urlencoded"


class Endpoint(unittest.TestCase):
    """Transactions.respond: step 13 and the answers, on records it made itself (so the vectors' documents, signed
    over make_vectors' transcript, are re-keyed here to each new record)."""

    def setUp(self):
        self.clock = Clock(mv.AT)
        self.runs = tempfile.mkdtemp()
        self.tx = avp.Transactions("https://avp-lab.example", T13, runs_dir=self.runs, clock=self.clock)

    def open(self, flow="qr", browser=None):
        params, links, record = self.tx.new(flow=flow, browser=browser)
        inputs = {"client_id": params["client_id"], "nonce": params["nonce"], "response_uri": params["response_uri"]}
        return record, inputs

    def response_for(self, inputs, **kw):
        return mv.mint(signed_transcript=mv.transcript(inputs), **kw)

    def post(self, txid, fields, ctype=FORM):
        return self.tx.respond(txid, ctype, urllib.parse.urlencode(fields).encode())

    def test_a_good_response_gets_200_and_an_empty_object_and_completes_the_record(self):
        record, inputs = self.open()
        status, body = self.post(record["txid"], {"vp_token": b64u(self.response_for(inputs)), "state": record["state"]})
        self.assertEqual((status, body), (200, {}))
        self.assertEqual(self.tx.record(record["txid"])["status"], "completed")
        self.assertIs(self.tx.record(record["txid"])["satisfied"], True)

    def test_age_false_is_a_200_that_is_not_satisfied(self):
        record, inputs = self.open()
        status, body = self.post(record["txid"], {"vp_token": b64u(self.response_for(inputs, age=False)),
                                                  "state": record["state"]})
        self.assertEqual((status, body), (200, {}))
        self.assertIs(self.tx.record(record["txid"])["satisfied"], False)

    def test_a_refused_response_gets_400_naming_the_step_and_fails_the_record(self):
        record, inputs = self.open()
        status, body = self.post(record["txid"], {"vp_token": b64u(mv.mint()), "state": record["state"]})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid_request")
        self.assertIn("device signature", body["error_description"])
        self.assertEqual((self.tx.record(record["txid"])["status"], self.tx.record(record["txid"])["refused"]),
                         ("failed", "device signature"))

    def test_a_second_post_on_the_same_transaction_gets_400(self):
        record, inputs = self.open()
        fields = {"vp_token": b64u(self.response_for(inputs)), "state": record["state"]}
        self.assertEqual(self.post(record["txid"], fields)[0], 200)
        status, body = self.post(record["txid"], fields)
        self.assertEqual(status, 400)
        self.assertIs(self.tx.record(record["txid"])["satisfied"], True)

    def test_an_expired_transaction_gets_400_and_its_record_stays(self):
        record, inputs = self.open()
        self.clock.now = mv.AT + datetime.timedelta(minutes=10, seconds=1)
        before = dict(self.tx.record(record["txid"]))
        status, _ = self.post(record["txid"], {"vp_token": b64u(self.response_for(inputs)), "state": record["state"]})
        self.assertEqual(status, 400)
        self.assertEqual(self.tx.record(record["txid"]), before)

    def test_an_unknown_transaction_gets_400_and_no_record_is_made(self):
        status, _ = self.post("A" * 43, {"vp_token": b64u(GOOD), "state": "A" * 43})
        self.assertEqual(status, 400)
        self.assertIsNone(self.tx.record("A" * 43))
        self.assertEqual(os.listdir(self.runs), [])

    def test_a_body_that_is_not_a_form_gets_400(self):
        record, inputs = self.open()
        status, _ = self.post(record["txid"], {"vp_token": b64u(self.response_for(inputs)), "state": record["state"]},
                              ctype="application/json")
        self.assertEqual(status, 400)
        self.assertEqual(self.tx.record(record["txid"])["status"], "failed")

    def test_two_posts_at_once_are_judged_once(self):
        record, inputs = self.open()
        fields = {"vp_token": b64u(self.response_for(inputs)), "state": record["state"]}
        real = avp.verify_avp
        judged = []

        def slow(*a, **kw):
            judged.append(1)
            time.sleep(0.2)
            return real(*a, **kw)

        start, results = threading.Barrier(2), []

        def worker():
            start.wait()
            results.append(self.post(record["txid"], fields)[0])
        with mock.patch.object(avp, "verify_avp", slow):
            threads = [threading.Thread(target=worker) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(10)
        self.assertEqual(sorted(results), [200, 400])
        self.assertEqual(len(judged), 1)

    def test_an_error_post_is_processed_with_200_and_keeps_the_code_only(self):
        record, inputs = self.open()
        status, body = self.post(record["txid"], {"error": "access_denied", "error_description": "the user said no",
                                                  "state": record["state"]})
        self.assertEqual((status, body), (200, {}))
        kept = self.tx.record(record["txid"])
        self.assertEqual((kept["status"], kept["error"]), ("failed", "access_denied"))
        self.assertNotIn("the user said no", json.dumps(kept))
        with open(os.path.join(self.runs, record["txid"], "record.json")) as f:
            self.assertNotIn("the user said no", f.read())
        status, _ = self.post(record["txid"], {"vp_token": b64u(self.response_for(inputs)), "state": record["state"]})
        self.assertEqual(status, 400)

    def test_an_error_post_with_a_malformed_code_or_another_state_gets_400(self):
        for make in (lambda state: {"error": "access denied!", "state": state},
                     lambda state: {"error": "x" * 65, "state": state},
                     lambda state: {"error": "access_denied", "state": "B" * 43},
                     lambda state: {"error": "access_denied"}):
            record, _ = self.open()
            fields = make(record["state"])
            status, body = self.post(record["txid"], fields)
            self.assertEqual(status, 400, fields)
            self.assertEqual(body["error"], "invalid_request")
            self.assertEqual(self.tx.record(record["txid"])["status"], "failed")

    def test_an_error_post_with_two_error_descriptions_gets_400(self):
        # one error_description is processed (the test above); a second one is the wallet's input refused
        record, _ = self.open()
        fields = [("error", "access_denied"), ("error_description", "a"), ("error_description", "b"),
                  ("state", record["state"])]
        status, body = self.tx.respond(record["txid"], FORM, urllib.parse.urlencode(fields).encode())
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid_request")
        self.assertEqual(self.tx.record(record["txid"])["status"], "failed")

    def test_open_requests_are_capped(self):
        with mock.patch.object(avp, "MAX_OPEN", 2):
            self.open()
            self.open()
            with self.assertRaises(avp.Refused) as cm:
                self.open()
        self.assertEqual(cm.exception.check, "request")

    def test_an_error_post_beside_a_vp_token_gets_400(self):
        record, inputs = self.open()
        status, _ = self.post(record["txid"], {"error": "access_denied", "state": record["state"],
                                               "vp_token": b64u(self.response_for(inputs))})
        self.assertEqual(status, 400)

    def test_same_device_200_carries_the_redirect_uri_with_a_code_and_the_browser(self):
        record, inputs = self.open(flow="link", browser="safari")
        status, body = self.post(record["txid"], {"vp_token": b64u(self.response_for(inputs)), "state": record["state"]})
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"redirect_uri", "browser"})
        self.assertEqual(body["browser"], "safari")
        u = urllib.parse.urlsplit(body["redirect_uri"])
        self.assertEqual((u.scheme, u.netloc, u.path), ("https", "avp-lab.example", "/done"))
        code = urllib.parse.parse_qs(u.query)["response_code"][0]
        self.assertEqual(len(base64.urlsafe_b64decode(code + "==")), 16)
        self.assertIs(self.tx.done(code)["satisfied"], True)
        self.assertIsNone(self.tx.done(code))  # one use
        self.assertIsNone(self.tx.done("C" * 22))

    def test_the_capture_is_what_verify_mdoc_reads_and_nothing_else(self):
        record, inputs = self.open()
        raw = self.response_for(inputs)
        fields = {"vp_token": b64u(raw), "state": record["state"]}
        body = urllib.parse.urlencode(fields).encode()
        self.assertEqual(self.tx.respond(record["txid"], FORM, body)[0], 200)
        d = os.path.join(self.runs, record["txid"])
        self.assertEqual(sorted(os.listdir(d)), ["captured-at.txt", "device-response.cbor", "openid4vp-inputs.json",
                                                 "post-body.sha256", "record.json", "request.txt", "verify.txt"])
        with open(os.path.join(d, "device-response.cbor"), "rb") as f:
            self.assertEqual(f.read(), raw)
        with open(os.path.join(d, "post-body.sha256")) as f:
            self.assertEqual(f.read().strip(), hashlib.sha256(body).hexdigest())
        with open(os.path.join(d, "record.json")) as f:
            self.assertNotIn(b64u(raw), f.read())
        response, inputs_read = avp.vm.load_capture(d)
        self.assertEqual(inputs_read["jwk_thumbprint"], None)
        with open(os.path.join(d, "captured-at.txt")) as f:
            when = at(f.read().strip())
        self.assertEqual(len(avp.vm.verify(response, inputs_read, T13, when)), 1)  # the existing verifier agrees


class NoAccessLog(unittest.TestCase):
    """A request to serve.py writes no client address to stderr. The control: the base class's own log_message,
    under the same capture, does write it."""

    def run_server(self, handler):
        tx = serve.avp.Transactions("https://avp-lab.example", T13, runs_dir=tempfile.mkdtemp(), clock=Clock(mv.AT))
        server = serve.make_server(0, tx, handler=handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        captured = io.StringIO()
        with mock.patch("sys.stderr", captured):
            thread.start()
            try:
                port = server.server_address[1]
                for method, path in (("GET", "/"), ("GET", "/?flow=link"), ("POST", "/response/" + "A" * 43),
                                     ("GET", "/done?response_code=x"), ("GET", "/nowhere")):
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                    c.request(method, path, body=b"vp_token=x" if method == "POST" else None,
                              headers={"Content-Type": FORM, "User-Agent": "test-agent"} if method == "POST" else
                              {"User-Agent": "test-agent"})
                    c.getresponse().read()
                    c.close()
            finally:
                server.shutdown()
                server.server_close()
        return captured.getvalue()

    def test_no_client_address_is_written(self):
        out = self.run_server(serve.Handler)
        self.assertNotIn("127.0.0.1", out)
        self.assertNotIn("test-agent", out)

    def test_control_the_default_log_message_writes_the_address(self):
        import http.server

        class Logged(serve.Handler):
            log_message = http.server.BaseHTTPRequestHandler.log_message
        self.assertIn("127.0.0.1", self.run_server(Logged))


class Pages(unittest.TestCase):
    def test_pages_carry_no_script_and_a_policy_that_forbids_one(self):
        tx = serve.avp.Transactions("https://avp-lab.example", T13, runs_dir=tempfile.mkdtemp(), clock=Clock(mv.AT))
        server = serve.make_server(0, tx)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
            c.request("GET", "/")
            r = c.getresponse()
            page = r.read().decode()
            self.assertEqual(r.status, 200)
            self.assertNotIn("<script", page.lower())
            self.assertIn("default-src 'none'", r.getheader("Content-Security-Policy") or "")
            self.assertEqual((r.getheader("Cache-Control"), r.getheader("Referrer-Policy"),
                              r.getheader("X-Content-Type-Options")), ("no-store", "no-referrer", "nosniff"))
            self.assertIn("av://?", page.replace("&amp;", "&"))
            c.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_the_server_binds_the_loopback_address_only(self):
        tx = serve.avp.Transactions("https://avp-lab.example", T13, runs_dir=tempfile.mkdtemp(), clock=Clock(mv.AT))
        server = serve.make_server(0, tx)
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
        finally:
            server.server_close()

    def test_a_post_off_the_response_path_or_over_the_size_cap_gets_400_unread(self):
        tx = serve.avp.Transactions("https://avp-lab.example", T13, runs_dir=tempfile.mkdtemp(), clock=Clock(mv.AT))
        _, _, record = tx.new()
        server = serve.make_server(0, tx)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for path, length in (("/response/short", 10), ("/response/" + record["txid"] + "/x", 10),
                                 ("/response/" + record["txid"], serve.MAX_BODY + 1)):
                c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
                c.putrequest("POST", path)
                c.putheader("Content-Type", FORM)
                c.putheader("Content-Length", str(length))
                c.endheaders()
                r = c.getresponse()
                self.assertEqual((path[:20], r.status), (path[:20], 400))
                r.read()
                c.close()
            self.assertEqual(tx.record(record["txid"])["status"], "open")
        finally:
            server.shutdown()
            server.server_close()


FAKE_CLOUDFLARED = """#!/bin/sh
echo $$ > "$FAKE_CF_PIDFILE"
echo "INF |  https://avp-lab-test.trycloudflare.com  |"
exec sleep 600
"""


class Tunnel(unittest.TestCase):
    """run_tunnel.sh with a stand-in cloudflared on PATH (no network): on Ctrl-C and on a TERM it leaves no
    listener, no tunnel process and no tunnel log, and its last line is "done"."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "bin"))
        os.makedirs(os.path.join(self.tmp, "t"))
        cf = os.path.join(self.tmp, "bin", "cloudflared")
        with open(cf, "w") as f:
            f.write(FAKE_CLOUDFLARED)
        os.chmod(cf, 0o755)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "POLARIS_"))}
        self.env.update(PATH=os.path.join(self.tmp, "bin") + os.pathsep + os.environ.get("PATH", ""),
                        TMPDIR=os.path.join(self.tmp, "t"), AVP_PYTHON=sys.executable,
                        AVP_RUNS=os.path.join(self.tmp, "runs"), FAKE_CF_PIDFILE=os.path.join(self.tmp, "cf.pid"))

    def free_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def start(self, env):
        """run_tunnel.sh in a session of its own, on a free port (never the default one a real run uses). Whatever
        the script leaves behind, its whole process group is killed at cleanup, which runs after the test's own
        assertions have judged what the script stopped by itself."""
        port = self.free_port()
        p = subprocess.Popen(["bash", os.path.join(HERE, "run_tunnel.sh"), "--port", str(port)], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
        self.addCleanup(self.kill_group, p)
        return p, port

    def kill_group(self, p):
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        p.wait(timeout=10)
        if p.stdout:
            p.stdout.close()
        try:
            with open(self.env["FAKE_CF_PIDFILE"]) as f:
                os.kill(int(f.read()), signal.SIGKILL)
        except (FileNotFoundError, ValueError, ProcessLookupError):
            pass

    def test_it_refuses_production(self):
        p, _ = self.start(dict(self.env, POLARIS_ENV="Production"))
        out, _ = p.communicate(timeout=15)
        self.assertEqual(p.returncode, 2)
        self.assertIn("production", out)
        self.assertFalse(os.path.exists(self.env["FAKE_CF_PIDFILE"]))

    def stopped_by(self, stop):
        """Start the script, wait until it serves (the control: a page answers and the tunnel log exists), stop it
        with stop(p), and return its exit status and output once it has ended."""
        p, port = self.start(self.env)
        lines, deadline = [], time.time() + 30
        assert p.stdout is not None
        try:
            while time.time() < deadline:
                line = p.stdout.readline()
                if not line:
                    break
                lines.append(line.rstrip("\n"))
                if line.startswith("ready:"):
                    break
            self.assertTrue(any(x.startswith("ready:") for x in lines), lines)
            self.assertIn("for https://avp-lab-test.trycloudflare.com", lines[-1])
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("GET", "/")
            self.assertEqual(c.getresponse().status, 200)
            c.close()
            self.assertEqual(len(os.listdir(self.env["TMPDIR"])), 1)  # the tunnel log, while it runs
        finally:
            stop(p)
            out, _ = p.communicate(timeout=30)
        self.assertEqual(out.rstrip("\n").split("\n")[-1], "done")
        with open(self.env["FAKE_CF_PIDFILE"]) as f:
            cf_pid = int(f.read())
        with self.assertRaises(ProcessLookupError):
            os.kill(cf_pid, 0)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=2).close()
        self.assertEqual(os.listdir(self.env["TMPDIR"]), [])
        return p.returncode

    def test_term_stops_both_processes_and_deletes_the_tunnel_log(self):
        self.assertEqual(self.stopped_by(lambda p: p.send_signal(signal.SIGTERM)), 143)

    def test_ctrl_c_stops_both_processes_and_deletes_the_tunnel_log(self):
        # Ctrl-C signals the whole foreground group: the script and both of its children.
        self.assertEqual(self.stopped_by(lambda p: os.killpg(p.pid, signal.SIGINT)), 130)


class WitnessResults(unittest.TestCase):
    """witness-results/, as witness.sh wrote it: the step table rebuilt from the witnesses' raw outputs is the committed
    table.txt and has no unclassified disagreement; over the committed control (O with its ECDSA verify always true)
    it has some."""

    RESULTS = os.path.join(HERE, "witness-results")

    @classmethod
    def setUpClass(cls):
        cls.wj = _load("witness_jobs_under_test", os.path.join(HERE, "witness_jobs.py"))

    def table(self, results):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            rc = self.wj.table(results)
        return rc, out.getvalue()

    def test_the_committed_table_is_rebuilt_from_the_raw_outputs(self):
        rc, text = self.table(self.RESULTS)
        self.assertEqual(rc, 0, text[-400:])
        with open(os.path.join(self.RESULTS, "table.txt")) as f:
            self.assertEqual(text, f.read())
        self.assertIn("\nRESULT: 0 disagreement(s) unclassified, over 46 cases\n", text)

    def test_the_control_shows_disagreements(self):
        with tempfile.TemporaryDirectory() as t:
            for name in ("jobs.json", "eu.jsonl", "isomdl.jsonl", "run.json"):
                shutil.copy(os.path.join(self.RESULTS, name), t)
            shutil.copy(os.path.join(self.RESULTS, "control-owf-verify-true.jsonl"), os.path.join(t, "owf.jsonl"))
            rc, text = self.table(t)
        self.assertEqual(rc, 1)
        n = int(text.rsplit("RESULT: ", 1)[1].split(" ", 1)[0])
        self.assertGreater(n, 0)

    def edited(self, t, name, edit):
        for f in ("jobs.json", "eu.jsonl", "owf.jsonl", "isomdl.jsonl", "run.json"):
            shutil.copy(os.path.join(self.RESULTS, f), t)
        with open(os.path.join(t, name)) as f:
            lines = f.read().splitlines()
        with open(os.path.join(t, name), "w") as f:
            f.write("\n".join(edit(lines)) + "\n")

    def test_a_witness_that_dropped_a_root_stops_the_table(self):
        def drop(lines):
            first = json.loads(lines[0])
            self.assertEqual(first["roots"], 1)
            return [json.dumps(dict(first, roots=0))] + lines[1:]
        with tempfile.TemporaryDirectory() as t:
            self.edited(t, "owf.jsonl", drop)
            with self.assertRaises(SystemExit) as cm, mock.patch("sys.stdout", io.StringIO()):
                self.wj.table(t)
        self.assertIn("roots", str(cm.exception.code))

    def test_a_witness_missing_a_case_stops_the_table(self):
        with tempfile.TemporaryDirectory() as t:
            self.edited(t, "eu.jsonl", lambda lines: lines[1:])
            with self.assertRaises(SystemExit) as cm, mock.patch("sys.stdout", io.StringIO()):
                self.wj.table(t)
        self.assertIn("has no result", str(cm.exception.code))


if __name__ == "__main__":
    unittest.main()
