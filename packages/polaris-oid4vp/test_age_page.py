# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The age page, `serve --age-check 18|21 --experimental` (lab/strategy/025-mdoc-dc-api.md, M5).

The page asks a wallet, over the Digital Credentials API and `openid4vp-v1-signed`, for one
element, `age_over_18` or `age_over_21`, and answers in one of three ways: N or over, under N, or
could not check. These tests drive it through the listener as a browser page would, with the test
wallet of test_verifier.py answering, and through the `serve` command with its listener replaced.
"""

import contextlib
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

import test_mdoc as md  # noqa: E402
from polaris_oid4vp import age, age_page  # noqa: E402
from polaris_oid4vp import verifier as verifier_module  # noqa: E402
from polaris_oid4vp.jwe import b64u_encode  # noqa: E402
from polaris_oid4vp.serve import AGE_PAGE_PATH, AGE_PAGE_POLICY, AGE_REQUEST_PATH, AGE_RESPONSE_PATH, \
    AGE_SCRIPT_PATH, serve  # noqa: E402
from polaris_oid4vp.verifier import DC_API_MAX_OUTSTANDING, Verifier  # noqa: E402
import test_cli  # noqa: E402
from test_serve import _exchange, _parse, _send_raw  # noqa: E402
from test_verifier import ORIGIN, DcApiWallet, _client_chain, _dc_api_request  # noqa: E402

PEM = serialization.Encoding.PEM
IDCARD = "com.google.wallet.idcard.1"
AV = "eu.europa.ec.av.1"
AV_NS = "eu.europa.ec.av.1"
IACA_PEM = md.IACA.public_bytes(PEM)
#: One label carries markup, so the page is seen to escape what it is configured with.
MARKUP_LABEL = "Test <b>AV</b> root"
LABELS = ("Test mDL IACA", "Test ID pass IACA", MARKUP_LABEL)

#: The words the page and its script never use: each would say more than the page does.
LARGER_WORDS = ("verified", "verification", "you are", "proof", "guarantee", "certified", "limit",
                "store", "keep", "retain", "zero-knowledge", "zero knowledge", "anonymous", "private",
                "privacy", "unlinkable", "untraceable", "without revealing", "secure", "safe")

#: Every line the listener may write to stderr in age mode: a refusal's code, and under --verbose
#: the method and path of a request. Nothing else, so no reason, value or address.
OPERATOR_LINE = re.compile(r"polaris-oid4vp: refused: [a-z_]+|(GET|POST) /[a-z/.-]*")


def _roots(*entries):
    """AgeRoots for (label, doctype[, pem]) entries; the default PEM is the root test_mdoc mints under."""
    return [age.AgeRoot(entry[0], entry[1], entry[2] if len(entry) > 2 else IACA_PEM) for entry in entries]


ROOTS = _roots((LABELS[0], md.MDL), (LABELS[1], IDCARD), (LABELS[2], AV))


def _age_verifier(years=18, roots=None, **kwargs):
    cert, key = _client_chain()
    return age.AgeVerifier(age=years, roots=ROOTS if roots is None else roots, client_cert_pem=cert,
                           client_key_pem=key, request_uri="https://verifier.test/request.jwt",
                           response_uri="https://verifier.test/response", **kwargs)


def _larger_words(text):
    """The words of LARGER_WORDS that `text` carries, case-insensitive, in that list's order."""
    lowered = text.lower()
    return [word for word in LARGER_WORDS if word in lowered]


def _block(text, start):
    """The text between the brace that opens at or after `start` and the brace that closes it."""
    opened = text.index("{", start)
    depth = 0
    for at in range(opened, len(text)):
        depth += {"{": 1, "}": -1}.get(text[at], 0)
        if depth == 0:
            return text[opened + 1:at]
    raise AssertionError("no closing brace after offset %d" % start)


def _catch_blocks(script):
    return [_block(script, m.end() - 1) for m in re.finditer(r"catch \(e\) \{", script)]


class AgeWallet(DcApiWallet):
    """test_verifier's wallet over the Digital Credentials API, answering the age page: one
    DeviceResponse under one of the request's query ids, or under several."""

    def query_ids(self, member):
        return [query["id"] for query in _dc_api_request(member)[1]["dcql_query"]["credentials"]]

    def query_for(self, member, doctype):
        for query in _dc_api_request(member)[1]["dcql_query"]["credentials"]:
            if query["meta"]["doctype_value"] == doctype:
                return query["id"]
        raise AssertionError("the request asks for no %s" % doctype)

    def respond(self, member, *, doctype=md.MDL, items=None, also=(), **knobs):
        """`also`: further (doctype, items) answered beside the first, each under its own query."""
        if items is None:
            items = (md.el("age_over_18", True, ns=age.AGE_DOCTYPES[doctype]),)
        vp_token = {self.query_for(member, doctype): [b64u_encode(self.device_response(
            member, doctype=doctype, items=items, **knobs))]}
        for other, other_items in also:
            vp_token[self.query_for(member, other)] = [b64u_encode(self.device_response(
                member, doctype=other, items=other_items))]
        return {"response": self.encrypt({"vp_token": vp_token}, member)}


def _posted(data, protocol="openid4vp-v1-signed"):
    return json.dumps({"protocol": protocol, "data": data}).encode()


class AgeServeTestCase(unittest.TestCase):
    """An age verifier for 18 behind a listener given age_origin=ORIGIN, its stderr captured."""

    YEARS = 18
    VERBOSE = False

    @classmethod
    def setUpClass(cls):
        cls.verifier = _age_verifier(cls.YEARS)
        cls.httpd = serve(cls.verifier, host="127.0.0.1", port=0, age_origin=ORIGIN, verbose=cls.VERBOSE)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        self.wallet = AgeWallet()
        with self.verifier._lock:
            self.verifier._dc_api.clear()
        self.err = io.StringIO()
        redirect = contextlib.redirect_stderr(self.err)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def ask(self, method, path, body=b"", origin=ORIGIN, httpd=None):
        headers = [("Origin", origin)] if origin is not None else []
        return _parse(_exchange(httpd or self.httpd, method, path, headers, body))

    def member(self, httpd=None):
        status, _, body = self.ask("POST", AGE_REQUEST_PATH, httpd=httpd)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def answer(self, data, httpd=None):
        """POST /age/response with `data`: (status, headers, the answer document)."""
        status, headers, body = self.ask("POST", AGE_RESPONSE_PATH, _posted(data), httpd=httpd)
        return status, headers, json.loads(body)

    def answered(self, httpd=None, **knobs):
        """The answer the page gets for one fresh request, the wallet answering with `knobs`."""
        member = self.member(httpd)
        status, _, document = self.answer(self.wallet.respond(member, **knobs), httpd)
        self.assertEqual(status, 200, document)
        self.assertEqual(list(document), ["answer"], document)
        return document["answer"]

    def lines(self):
        return [line for line in self.err.getvalue().splitlines() if line]

    def outstanding(self):
        with self.verifier._lock:
            self.verifier._expire_locked()
            return dict(self.verifier._dc_api)


class AgePageTests(AgeServeTestCase):

    def test_the_request_asks_for_one_age_element_and_nothing_else(self):
        """Over openid4vp-v1-signed: one query per docType in the roots, each asking for the one
        element in its docType's namespace with intent_to_retain false and no values, the queries
        alternatives of one credential set. Under 21 the element is age_over_21; with one docType
        there is one query and no credential set."""
        for years, roots in ((18, ROOTS), (21, ROOTS), (18, _roots(("Only", AV)))):
            with self.subTest(years=years, doctypes=[r.doctype for r in roots]):
                verifier = _age_verifier(years, roots)
                member = verifier.dc_api_request(ORIGIN)
                self.assertEqual(member["protocol"], "openid4vp-v1-signed")
                _, claims = _dc_api_request(member)
                self.assertEqual((claims["response_mode"], claims["expected_origins"]), ("dc_api.jwt", [ORIGIN]))
                query = claims["dcql_query"]
                doctypes = [r.doctype for r in roots]
                self.assertEqual([q["meta"] for q in query["credentials"]],
                                 [{"doctype_value": d} for d in doctypes])
                for q, doctype in zip(query["credentials"], doctypes):
                    self.assertEqual(sorted(q), ["claims", "format", "id", "meta"])
                    self.assertEqual(q["format"], "mso_mdoc")
                    self.assertEqual(q["claims"], [{"path": [age.AGE_DOCTYPES[doctype], "age_over_%d" % years],
                                                    "intent_to_retain": False}])
                ids = [q["id"] for q in query["credentials"]]
                self.assertEqual(len(set(ids)), len(ids))
                if len(ids) > 1:
                    self.assertEqual(query, {"credentials": query["credentials"],
                                             "credential_sets": [{"options": [[i] for i in ids]}]})
                else:
                    self.assertEqual(list(query), ["credentials"])
        self.assertEqual(age.AGE_DOCTYPES, {md.MDL: md.MDL_NS, IDCARD: md.MDL_NS, AV: AV_NS})

    def test_a_true_answer_shows_yes_and_a_false_one_no(self):
        for doctype in (md.MDL, IDCARD, AV):
            ns = age.AGE_DOCTYPES[doctype]
            with self.subTest(doctype=doctype):
                self.assertEqual(self.answered(doctype=doctype, items=(md.el("age_over_18", True, ns=ns),)),
                                 "18 or over")
                self.assertEqual(self.answered(doctype=doctype, items=(md.el("age_over_18", False, ns=ns),)),
                                 "under 18")
        self.assertEqual(self.lines(), [])

    def test_a_true_answer_under_21(self):
        verifier = _age_verifier(21)
        httpd = serve(verifier, host="127.0.0.1", port=0, age_origin=ORIGIN)
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        self.assertEqual(self.answered(httpd, items=(md.el("age_over_21", True),)), "21 or over")
        self.assertEqual(self.answered(httpd, items=(md.el("age_over_21", False),)), "under 21")

    def test_an_untrusted_or_broken_answer_shows_could_not_check(self):
        other_key, other = md.make_root("Unrelated IACA")
        stranger = _age_verifier(roots=_roots(("Unrelated", md.MDL, other.public_bytes(PEM))))
        httpd = serve(stranger, host="127.0.0.1", port=0, age_origin=ORIGIN)
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        self.assertEqual(self.answered(httpd), "could not check")

        def flip_mso_byte(doc):
            issuer_auth = doc["issuerSigned"]["issuerAuth"]
            payload = bytearray(issuer_auth[2])
            payload[-3] ^= 0x01
            issuer_auth[2] = bytes(payload)

        for items in ((md.el("age_over_18", True),), (md.el("age_over_18", False),)):
            with self.subTest(value=items[0]["value"]):
                self.assertEqual(self.answered(items=items, edit_doc=flip_mso_byte), "could not check")
        # The twin: the same document, unflipped, under the configured root.
        self.assertEqual(self.answered(), "18 or over")

    def test_a_nearest_true_age_element_is_refused_until_measured(self):
        self.assertEqual(self.answered(items=(md.el("age_over_21", True),)), "could not check")
        self.assertEqual(self.answered(items=(md.el("age_over_16", True),)), "could not check")

    def test_the_age_element_is_a_boolean_by_type(self):
        for value in (1, 0, "true", "false", None, b"\x01"):
            with self.subTest(value=value):
                self.assertEqual(self.answered(items=(md.el("age_over_18", value),)), "could not check")
        self.assertEqual(self.answered(items=(md.el("age_over_18", True),)), "18 or over")
        self.assertEqual(self.answered(items=(md.el("age_over_18", False),)), "under 18")

    def test_one_document_answers_one_alternative(self):
        idpass = md.mint(doctype=IDCARD, items=(md.el("age_over_18", False),))

        def second_document(response):
            response["documents"].append(cbor2.loads(idpass)["documents"][0])

        self.assertEqual(self.answered(edit_response=second_document), "could not check")
        self.assertEqual(self.answered(also=((IDCARD, (md.el("age_over_18", False),)),)), "could not check")
        self.assertEqual(self.answered(also=((AV, (md.el("age_over_18", True, ns=AV_NS),)),)), "could not check")
        # The mdoc judge reads one document (mdoc.py l.403-405), and the answer is one alternative.
        self.assertEqual(self.lines(), ["polaris-oid4vp: refused: malformed"] * 3)
        # The twin: each alone is answered.
        self.assertEqual(self.answered(), "18 or over")
        self.assertEqual(self.answered(doctype=IDCARD, items=(md.el("age_over_18", False),)), "under 18")
        self.assertEqual(len(self.lines()), 3)

    def test_an_element_not_asked_for_is_could_not_check(self):
        # The issuing_country case is refused by the mdoc judge before the query is read, with a
        # reason that quotes the disclosed value and the signer's countryName (mdoc.py l.626-627).
        cases = (
            ("family_name", (md.el("age_over_18", True), md.el("family_name", "Mustermann")), "Mustermann",
             "claims"),
            ("issuing_country", (md.el("age_over_18", True), md.el("issuing_country", "XQ")), "XQ",
             "issuing_authority"),
            ("another namespace", (md.el("age_over_18", True, ns=AV_NS),), AV_NS, "claims"),
        )
        for name, items, value, code in cases:
            with self.subTest(name):
                self.err.seek(0)
                self.err.truncate()
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    member = self.member()
                    status, headers, body = self.ask("POST", AGE_RESPONSE_PATH,
                                                     _posted(self.wallet.respond(member, items=items)))
                self.assertEqual((status, json.loads(body)), (200, {"answer": "could not check"}))
                for stream in (out.getvalue(), self.err.getvalue(), body.decode(), repr(headers)):
                    self.assertNotIn(value, stream)
                    self.assertNotIn(md.COUNTRY, stream)
                self.assertEqual(self.lines(), ["polaris-oid4vp: refused: %s" % code])

    def test_the_controls_main_already_refuses(self):
        """A self-asserted age_over_18 in DeviceSigned, and two items one true and one false."""
        self_asserted = cbor2.dumps({md.MDL_NS: {"age_over_18": True}})
        self.assertEqual(self.answered(items=(md.el("age_over_18", False),), device_namespaces=self_asserted),
                         "could not check")
        self.assertEqual(self.answered(items=(md.el("age_over_18", True), md.el("age_over_18", False))),
                         "could not check")
        self.assertEqual([line.rpartition(": ")[2] for line in self.lines()], ["device_namespaces", "digest"])

    def test_the_roots_bind_each_root_to_its_own_doctype(self):
        av_key, av_root = md.make_root("Test AV IACA")
        av_ds_key, av_ds = md.make_ds(av_key, "Test AV IACA")
        verifier = _age_verifier(roots=_roots(("mDL", md.MDL), ("AV", AV, av_root.public_bytes(PEM))))
        httpd = serve(verifier, host="127.0.0.1", port=0, age_origin=ORIGIN)
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        av_items = (md.el("age_over_18", True, ns=AV_NS),)
        # An AV document signed under the mDL root, and an mDL signed under the AV root.
        self.assertEqual(self.answered(httpd, doctype=AV, items=av_items), "could not check")
        self.assertEqual(self.answered(httpd, ds=av_ds, ds_key=av_ds_key), "could not check")
        # The twins: each under its own root.
        self.assertEqual(self.answered(httpd, doctype=AV, items=av_items, ds=av_ds, ds_key=av_ds_key),
                         "18 or over")
        self.assertEqual(self.answered(httpd), "18 or over")

    def test_no_cookie_and_no_cache(self):
        member = self.member()
        answers = [
            self.ask("GET", AGE_PAGE_PATH, origin=None),
            self.ask("GET", AGE_SCRIPT_PATH, origin=None),
            self.ask("POST", AGE_REQUEST_PATH),
            self.ask("POST", AGE_RESPONSE_PATH, _posted(self.wallet.respond(member))),
            self.ask("POST", AGE_RESPONSE_PATH, _posted(self.wallet.respond(member))),
            self.ask("POST", AGE_RESPONSE_PATH, b"{"),
            self.ask("POST", AGE_RESPONSE_PATH, b"{}", origin="https://evil.example"),
            self.ask("POST", AGE_REQUEST_PATH, origin=None),
            self.ask("GET", "/nope", origin=None),
            self.ask("GET", "/dc-api/", origin=None),
            self.ask("GET", AGE_RESPONSE_PATH, origin=None),
        ]
        for status, headers, body in answers:
            with self.subTest(status=status, body=body[:40]):
                names = [name.lower() for name, _ in headers]
                self.assertNotIn("set-cookie", names)
                self.assertEqual([v for n, v in headers if n.lower() == "cache-control"], ["no-store"])
        self.assertEqual([a[0] for a in answers], [200, 200, 200, 200, 200, 200, 403, 403, 404, 404, 404])

    def test_the_session_is_gone_after_the_verdict(self):
        for knobs, said in (({}, "18 or over"), ({"items": (md.el("age_over_18", False),)}, "under 18"),
                            ({"items": (md.el("age_over_18", 1),)}, "could not check"),
                            ({"items": (md.el("age_over_21", True),)}, "could not check")):
            with self.subTest(said=said, knobs=knobs):
                member = self.member()
                nonce = _dc_api_request(member)[1]["nonce"]
                self.assertIn(nonce, self.outstanding())
                status, _, document = self.answer(self.wallet.respond(member, **knobs))
                self.assertEqual((status, document), (200, {"answer": said}))
                self.assertNotIn(nonce, self.outstanding())
                self.assertEqual(self.outstanding(), {})
                with self.verifier._lock:
                    self.assertEqual((self.verifier._sessions, self.verifier._results), ({}, {}))

    def test_the_answer_exists_only_in_its_one_response(self):
        page = self.ask("GET", AGE_PAGE_PATH, origin=None)[2]
        member = self.member()
        data = self.wallet.respond(member)
        self.assertEqual(self.answer(data)[2], {"answer": "18 or over"})
        # No route answers it again, and the same data posted again is a replay.
        self.assertEqual(self.ask("GET", AGE_PAGE_PATH, origin=None)[2], page)
        self.assertEqual(self.ask("GET", AGE_RESPONSE_PATH, origin=None)[0], 404)
        self.assertNotIn(b"or over", self.ask("POST", AGE_REQUEST_PATH)[2])
        self.assertEqual(self.answer(data)[2], {"answer": "could not check"})
        with self.verifier._lock:
            self.verifier._dc_api.clear()
        # A request left unanswered past its lifetime is gone, and its answer is could not check.
        t0 = verifier_module.time.time()
        with mock.patch.object(verifier_module.time, "time", return_value=t0):
            member = self.member()
        late = self.wallet.respond(member)
        with mock.patch.object(verifier_module.time, "time",
                               return_value=t0 + self.verifier.request_ttl_seconds + 1):
            self.assertEqual(self.outstanding(), {})
            self.assertEqual(self.answer(late)[2], {"answer": "could not check"})
        self.assertEqual(self.verifier.request_ttl_seconds, verifier_module.DEFAULT_REQUEST_TTL_SECONDS)
        # The cap counts unanswered requests: full, the next is refused; one answered frees one.
        members = [self.member() for _ in range(DC_API_MAX_OUTSTANDING)]
        status, _, body = self.ask("POST", AGE_REQUEST_PATH)
        self.assertEqual(status, 503, body)
        self.assertEqual(self.answer(self.wallet.respond(members[0]))[2], {"answer": "18 or over"})
        self.assertEqual(self.ask("POST", AGE_REQUEST_PATH)[0], 200)
        self.assertEqual(len(self.outstanding()), DC_API_MAX_OUTSTANDING)

    def test_the_verdict_travels_in_a_body_only(self):
        for knobs in ({}, {"items": (md.el("age_over_18", False),)}):
            with self.subTest(knobs=knobs):
                member = self.member()
                status, headers, body = self.ask("POST", AGE_RESPONSE_PATH, _posted(self.wallet.respond(member, **knobs)))
                self.assertEqual(status, 200)
                names = [name.lower() for name, _ in headers]
                for name in ("location", "link", "refresh", "content-location"):
                    self.assertNotIn(name, names)
                self.assertEqual(sorted(names), ["cache-control", "content-length", "content-type", "date",
                                                 "server"])
                self.assertNotIn(b"http", body)
                self.assertEqual(sorted(json.loads(body)), ["answer"])

    def test_age_mode_serves_its_page_and_nothing_else(self):
        status, headers, body = self.ask("GET", AGE_PAGE_PATH, origin=None)
        self.assertEqual(status, 200)
        self.assertEqual([v for n, v in headers if n == "Content-Security-Policy"], [AGE_PAGE_POLICY])
        self.assertEqual(body, age_page.page(18, LABELS))
        self.assertEqual(self.ask("GET", AGE_SCRIPT_PATH, origin=None)[2], age_page.SCRIPT)
        for method, path in (("GET", "/dc-api/"), ("GET", "/dc-api/app.js"), ("POST", "/dc-api/request"),
                             ("POST", "/dc-api/response"), ("GET", "/request.jwt"), ("POST", "/response"),
                             ("POST", "/control/request")):
            with self.subTest(method=method, path=path):
                self.assertEqual(self.ask(method, path, b"{}" if method == "POST" else b"")[0], 404)
        self.assertEqual(self.outstanding(), {})

    def test_a_body_the_page_does_not_send_is_refused(self):
        """A declared length over the bound, a length that is not one and a body cut short, on
        both POST routes, as the /dc-api/ routes refuse them; and an answer that is not the
        page's, a body that is not JSON or a genuine answer posted under another protocol, is
        could not check without being judged."""
        import socket
        from polaris_oid4vp.serve import MAX_BODY_BYTES
        for path in (AGE_RESPONSE_PATH, AGE_REQUEST_PATH):
            with self.subTest(path=path):
                head = "POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: %s\r\n" % (path, ORIGIN)
                try:
                    status, _, body = _parse(_exchange(self.httpd, "POST", path, [("Origin", ORIGIN)],
                                                       declare=MAX_BODY_BYTES + 1, timeout=3))
                except socket.timeout:
                    self.fail("a declared length over the bound was waited for")
                self.assertEqual(status, 413, body)
                self.assertEqual(json.loads(body)["error"], "invalid_request")
                status, _, body = _parse(_send_raw(self.httpd, (head + "Content-Length: -1\r\n\r\n").encode()))
                self.assertEqual(status, 400, body)
                self.assertEqual(json.loads(body)["error"], "invalid_request")
                s = socket.create_connection(self.httpd.server_address[:2], timeout=6)
                try:
                    s.sendall((head + "Content-Length: 50\r\n\r\n{}").encode())
                    s.shutdown(socket.SHUT_WR)
                    data, chunk = b"", s.recv(4096)
                    while chunk:
                        data, chunk = data + chunk, s.recv(4096)
                finally:
                    s.close()
                status, _, body = _parse(data)
                self.assertEqual(status, 400, body)
                self.assertIn(b"shorter than Content-Length", body)
        self.assertEqual(self.lines(), ["polaris-oid4vp: refused: invalid_request"] * 6)
        self.assertEqual(self.outstanding(), {})
        member = self.member()
        data = self.wallet.respond(member)
        for body in (b"not json", _posted(data, protocol="openid4vp-v1-unsigned"), _posted(data, protocol=None)):
            with self.subTest(body=body[:40]):
                status, _, answer = self.ask("POST", AGE_RESPONSE_PATH, body)
                self.assertEqual((status, json.loads(answer)), (200, {"answer": "could not check"}))
        self.assertEqual(self.lines()[6:], ["polaris-oid4vp: refused: invalid_request"] * 3)
        # None of the three was judged: the request is still open, and the genuine answer under
        # its own protocol is the first verdict it gets.
        self.assertEqual(len(self.outstanding()), 1)
        self.assertEqual(self.answer(data)[2], {"answer": "18 or over"})
        self.assertEqual(self.outstanding(), {})

    def test_the_verifier_takes_only_the_ages_and_roots_it_asks_for(self):
        chain = _client_chain()
        pem = IACA_PEM
        good = dict(age=18, roots=[age.AgeRoot("Root", md.MDL, pem)],
                    client_cert_pem=chain[0], client_key_pem=chain[1],
                    request_uri="https://verifier.test/request.jwt", response_uri="https://verifier.test/response")
        self.assertEqual(age.AgeVerifier(**good).age_element, "age_over_18")

        def raised(make, *args, **kwargs):
            # Whatever escapes, so that a refusal that is not made fails here, by assertion,
            # whichever exception the code past it raises instead.
            try:
                make(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                return exc
            return None

        for change, says in (({"age": 16}, "the age is 18 or 21"), ({"age": "18"}, "the age is 18 or 21"),
                             ({"age": True}, "the age is 18 or 21"), ({"age": 18.0}, "the age is 18 or 21"),
                             ({"roots": []}, "roots is a non-empty list"), ({"roots": None}, "roots is a non-empty list"),
                             ({"roots": [object()]}, "roots is a non-empty list"),
                             ({"roots": [pem]}, "roots is a non-empty list")):
            with self.subTest(change=change):
                caught = raised(age.AgeVerifier, **dict(good, **change))
                self.assertIsInstance(caught, ValueError)
                self.assertIn(says, str(caught))
        for label, doctype, raw, says in (("", md.MDL, pem, "the label is a non-empty string"),
                                          ("  ", md.MDL, pem, "the label is a non-empty string"),
                                          (None, md.MDL, pem, "the label is a non-empty string"),
                                          ("Root", "org.example.other", pem, "is not one the page asks for"),
                                          ("Root", md.MDL, pem.decode("ascii"), "the PEM is bytes")):
            with self.subTest(label=label, doctype=doctype):
                caught = raised(age.AgeRoot, label, doctype, raw)
                self.assertIsInstance(caught, ValueError)
                self.assertIn(says, str(caught))
        caught = raised(age.AgeVerifier(**good).new_request)
        self.assertIsInstance(caught, ValueError)
        self.assertIn("over the Digital Credentials API only", str(caught))

    def test_serve_refuses_what_the_age_page_does_not_take(self):
        verifier = _age_verifier()
        chain = _client_chain()
        plain = Verifier(client_cert_pem=chain[0], client_key_pem=chain[1],
                         request_uri="https://verifier.test/request.jwt", response_uri="https://verifier.test/response",
                         credential_format="mso_mdoc", doctype_value=md.MDL, claims=[[md.MDL_NS, "age_over_18"]])
        for target, kwargs in ((plain, {}), (verifier, {"on_verdict": print}),
                               (verifier, {"dc_api_origin": ORIGIN}), (verifier, {"cors_origins": ["*"]}),
                               (verifier, {"control_token": "t" * 40, "on_control": print}),
                               (verifier, {"on_request_object": print}), (verifier, {"name_requests": True}),
                               (verifier, {"age_origin": "http://rp.example"})):
            with self.subTest(kwargs=sorted(kwargs)):
                kwargs.setdefault("age_origin", ORIGIN)
                with self.assertRaises(ValueError):
                    serve(target, host="127.0.0.1", port=0, **kwargs)

    def test_the_page_says_what_it_does_and_nothing_larger(self):
        for years in (18, 21):
            with self.subTest(years=years):
                page = age_page.page(years, LABELS).decode("utf-8")
                for said in ("The credential says: %d or over." % years, "The credential says: under %d." % years,
                             "Could not check."):
                    self.assertIn(said, page)
                for label in LABELS[:2]:
                    self.assertIn("<li>%s</li>" % label, page)
                self.assertIn("<li>Test &lt;b&gt;AV&lt;/b&gt; root</li>", page)
                self.assertNotIn("<b>", page)
                self.assertNotIn("href", page)
                self.assertEqual(_larger_words(page), [])
        self.assertEqual(_larger_words(age_page.SCRIPT.decode("utf-8")), [])
        # The positive control: each word, in a page, is found.
        for word in LARGER_WORDS:
            with self.subTest(control=word):
                self.assertEqual(_larger_words("<p>The page says %s here.</p>" % word.upper()), [word])

    def test_only_the_server_says_no(self):
        """The suite runs no script, so this holds its shape (record 025, M5; the synthesis in the
        PR). The script shows an answer only as the server gave it, under its one prefix; every
        catch, and the branch where the browser does not allow openid4vp-v1-signed, shows the one
        constant "Could not check." and nothing else. A blank page on a decline is not executed
        here."""
        script = age_page.SCRIPT.decode("utf-8")
        self.assertEqual(script.count('"Could not check."'), 1)
        self.assertIn('var COULD_NOT_CHECK = "Could not check.";', script)
        self.assertIn('var NO_ANSWER = "%s";' % age.COULD_NOT_CHECK, script)
        self.assertIsNone(re.search(r"or over|\bunder\b|\byes\b|\"no\b", script, re.I))
        # The one place a verdict is shown: the server's own answer, a string that is not NO_ANSWER.
        self.assertEqual(script.count("The credential says: "), 1)
        shown = script.index('say("The credential says: " + said + ".");')
        guard_text = 'if (typeof said !== "string" || said === NO_ANSWER) {'
        self.assertIn(guard_text, script[:shown])
        guard = script.rindex(guard_text, 0, shown)
        self.assertIn("say(COULD_NOT_CHECK);", script[guard:shown])
        # Every call of the display function, by what it shows: the constant, "Ready." and the answer.
        shows = set(re.findall(r"(?<!function )\bsay\(([^;]*)\);", script))
        self.assertEqual(shows, {"COULD_NOT_CHECK", '"Ready."', '"The credential says: " + said + "."'})
        self.assertEqual(script.count("say("), len(re.findall(r"(?<!function )\bsay\(", script)) + 1)
        # The constant is shown in eight places: fetchRequest's answer that is not ok and its catch;
        # ask's catch around the wallet, its branch with no credential, the guard before the answer
        # and its catch around the post; the branch where the protocol is not offered and its catch.
        self.assertEqual(script.count("say(COULD_NOT_CHECK);"), 8)
        # The two early returns that are not catches, each exactly as written.
        self.assertEqual(_block(script, script.index("if (!answer.ok) {")).split(),
                         ["say(COULD_NOT_CHECK);", "return;"])
        self.assertEqual(_block(script, script.index('if (!credential || typeof credential.protocol !== "string") {')).split(),
                         ["say(COULD_NOT_CHECK);", "await", "fetchRequest(false);", "return;"])
        # Every catch shows the constant and no verdict.
        catches = _catch_blocks(script)
        self.assertGreaterEqual(len(catches), 4)
        for block in catches:
            self.assertIn("say(COULD_NOT_CHECK);", block)
            self.assertNotIn("The credential says", block)
        # The protocol branch: a browser that does not allow the signed protocol is told the
        # constant, before any request is fetched or the button wired.
        self.assertIn('var PROTOCOL = "openid4vp-v1-signed";', script)
        self.assertIn("DigitalCredential.userAgentAllowsProtocol(PROTOCOL) !== false", _block(script, script.index("function offered()")))
        branch = script.index("if (!offered()) {")
        self.assertEqual(_block(script, branch).split(), ["say(COULD_NOT_CHECK);", "return;"])
        self.assertLess(branch, script.index("button.addEventListener("))
        self.assertLess(branch, script.rindex("fetchRequest(true);"))


    def test_the_age_path_reads_only_the_verifiers_clock(self):
        """An mDL whose window closed ten days ago, sent with instants inside it wherever a post
        could carry one, is could not check; the parameter sets are pinned, so a time argument
        added to either changes one."""
        import inspect
        self.assertEqual(list(inspect.signature(age.AgeVerifier.__init__).parameters),
                         ["self", "age", "roots", "client_cert_pem", "client_key_pem", "request_uri",
                          "response_uri", "request_ttl_seconds", "dc_api_client_metadata"])
        self.assertEqual(list(inspect.signature(age.AgeVerifier.age_answer).parameters), ["self", "data", "origin"])
        window = dict(signed=md.BOOT - md.days(40), valid_from=md.BOOT - md.days(40),
                      valid_until=md.BOOT - md.days(10))
        inside = (md.BOOT - md.days(20)).strftime("%Y-%m-%dT%H:%M:%SZ")
        member = self.member()
        data = dict(self.wallet.respond(member, **window), now=inside, at=inside, instant=inside)
        status, _, body = self.ask("POST", AGE_RESPONSE_PATH,
                                   json.dumps({"protocol": "openid4vp-v1-signed", "data": data,
                                               "now": inside}).encode())
        self.assertEqual((status, json.loads(body)), (200, {"answer": "could not check"}))
        self.assertEqual(self.lines(), ["polaris-oid4vp: refused: credential_validity"])
        # The control: the same, with a window that is open now.
        self.assertEqual(self.answered(), "18 or over")


class AgeLogTests(AgeServeTestCase):

    VERBOSE = True

    def runs(self):
        """stderr of a yes run, a no run and three refused runs, each its own list of lines."""
        out = {}
        for name, knobs in (("yes", {}), ("no", {"items": (md.el("age_over_18", False),)}),
                            ("country", {"items": (md.el("age_over_18", True), md.el("issuing_country", "XQ"))}),
                            ("extra", {"items": (md.el("age_over_18", True), md.el("family_name", "Mustermann"))}),
                            ("flipped", {"device_signature": lambda *a: bytes(64)})):
            self.err.seek(0)
            self.err.truncate()
            self.answered(**knobs)
            out[name] = self.lines()
        return out

    def test_logs_carry_codes_never_values(self):
        runs = self.runs()
        self.assertEqual(runs["yes"], runs["no"])
        self.assertEqual(runs["yes"], ["POST %s" % AGE_REQUEST_PATH, "POST %s" % AGE_RESPONSE_PATH])
        for name in ("country", "extra", "flipped"):
            with self.subTest(name):
                self.assertEqual([line for line in runs[name] if "refused" in line],
                                 ["polaris-oid4vp: refused: %s"
                                  % {"country": "issuing_authority", "extra": "claims",
                                     "flipped": "device_signature"}[name]])
        everything = "\n".join(line for lines in runs.values() for line in lines)
        for line in everything.splitlines():
            self.assertRegex(line, "^(%s)$" % OPERATOR_LINE.pattern)
        for value in ("XQ", "Mustermann", md.COUNTRY, "Test Document Signer", "Test IACA", "127.0.0.1",
                      "age_over_18", "true", "false"):
            self.assertNotIn(value, everything)

    def test_a_listener_without_verbose_writes_refusals_only(self):
        httpd = serve(self.verifier, host="127.0.0.1", port=0, age_origin=ORIGIN)
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        self.assertEqual(self.answered(httpd), "18 or over")
        self.assertEqual(self.lines(), [])
        self.answered(httpd, items=(md.el("age_over_18", True), md.el("family_name", "Mustermann")))
        self.assertEqual(self.lines(), ["polaris-oid4vp: refused: claims"])


#: Run in a subprocess, the package's directory as its working directory: an accepted and a
#: refused presentation through the listener's handler, on an in-memory connection, with an audit
#: hook that records any open for writing and any socket connect. Exits 0 and prints the two
#: answers when nothing was recorded. `{extra}` is the positive control's own line.
NOTHING_LEAVES = textwrap.dedent("""
    import io, json, os, sys
    sys.path.insert(0, os.getcwd())
    import test_age_page as t
    from polaris_oid4vp.serve import AGE_REQUEST_PATH, AGE_RESPONSE_PATH, serve

    class Connection:
        def __init__(self, raw):
            self.inbound, self.outbound = io.BytesIO(raw), io.BytesIO()
        def makefile(self, mode, *args, **kwargs):
            return self.inbound if "r" in mode else self.outbound
        def sendall(self, data):
            self.outbound.write(data)
        def settimeout(self, value):
            pass
        def setsockopt(self, *args):
            pass

    verifier = t._age_verifier()
    httpd = serve(verifier, host="127.0.0.1", port=0, age_origin=t.ORIGIN)
    handler = httpd.RequestHandlerClass
    wallet = t.AgeWallet()

    def post(path, body):
        raw = ("POST %s HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nOrigin: %s\\r\\nContent-Length: %d\\r\\n\\r\\n"
               % (path, t.ORIGIN, len(body))).encode() + body
        connection = Connection(raw)
        handler(connection, ("127.0.0.1", 1), httpd)
        return t._parse(connection.outbound.getvalue())

    seen = []

    def hook(event, args):
        if event == "open":
            mode, flags = args[1], args[2]
            if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
                    isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND)):
                seen.append(("open", str(args[0])))
                raise PermissionError("no write in this run")
        elif event == "socket.connect":
            seen.append(("connect", repr(args[1])))
            raise PermissionError("no connection in this run")
        elif event in ("socket.sendto", "socket.sendmsg"):
            seen.append((event.split(".")[1], repr(args[1])))
            raise PermissionError("no datagram in this run")
        elif event in ("subprocess.Popen", "os.system", "os.posix_spawn"):
            seen.append((event, repr(args[0])))
            raise PermissionError("no other process in this run")

    sys.addaudithook(hook)
    answers = []
    for items in ((t.md.el("age_over_18", True),), (t.md.el("age_over_18", True), t.md.el("family_name", "Mustermann"))):
        member = json.loads(post(AGE_REQUEST_PATH, b"")[2])
        status, _, body = post(AGE_RESPONSE_PATH, t._posted(wallet.respond(member, items=items)))
        answers.append(json.loads(body)["answer"])
    {extra}
    print(json.dumps({{"answers": answers, "seen": seen}}))
    sys.exit(1 if seen else 0)
""")


class NothingLeavesTests(unittest.TestCase):

    def run_driver(self, extra="pass"):
        here = os.path.dirname(os.path.abspath(__file__))
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([sys.executable, "-B", "-c", NOTHING_LEAVES.format(extra=extra)], cwd=here, env=env,
                              capture_output=True, text=True, timeout=300)

    def test_nothing_leaves_the_process(self):
        run = self.run_driver()
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(json.loads(run.stdout.splitlines()[-1]),
                         {"answers": ["18 or over", "could not check"], "seen": []})

    def test_the_hook_sees_a_write_a_connect_a_send_and_a_process(self):
        """The positive control: the same driver, with a write, a connect, a datagram and a child
        process of its own."""
        write = "try:\n    open(os.devnull, 'w')\nexcept OSError:\n    pass"
        connect = ("import socket\ntry:\n    socket.create_connection(('127.0.0.1', 9), timeout=1)\n"
                   "except OSError:\n    pass")
        sendto = ("import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ntry:\n"
                  "    s.sendto(b'x', ('127.0.0.1', 9))\nexcept OSError:\n    pass\nfinally:\n    s.close()")
        child = ("import subprocess\ntry:\n    subprocess.run([sys.executable, '-c', 'pass'])\n"
                 "except OSError:\n    pass")
        for extra, kind in ((write, "open"), (connect, "connect"), (sendto, "sendto"), (child, "subprocess.Popen")):
            with self.subTest(kind):
                run = self.run_driver(extra)
                self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
                self.assertEqual([k for k, _ in json.loads(run.stdout.splitlines()[-1])["seen"]], [kind])


class AgeServeCommandTests(unittest.TestCase):
    """`serve --age-check N --experimental --dc-api-origin ORIGIN --age-roots FILE`."""

    ORIGIN = "https://verifier.example"
    _serve = test_cli.ServeCommandHeldOutTests._serve

    def setUp(self):
        test_cli.ServeCommandHeldOutTests.setUp(self)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.roots = self.roots_file([{"label": "Test mDL IACA", "doctype": md.MDL, "pem": "iaca.pem"}])

    def roots_file(self, entries, pem=IACA_PEM, name="roots.json"):
        (self.tmp / "iaca.pem").write_bytes(pem)
        for entry in entries:
            entry.setdefault("sha256", hashlib.sha256(IACA_PEM).hexdigest())
        path = self.tmp / name
        path.write_text(json.dumps(entries))
        return str(path)

    def good(self, years="18"):
        return ("--age-check", years, "--experimental", "--dc-api-origin", self.ORIGIN, "--age-roots", self.roots)

    def before_the_pki(self, *args):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            from polaris_oid4vp.cli import main
            rc = main(["serve", "--pki", str(self.tmp / "absent"), *args])
        return rc, err.getvalue()

    def test_age_check_needs_experimental(self):
        good = self.good()
        without = lambda flag, n=2: tuple(a for i, a in enumerate(good)  # noqa: E731
                                          if not (good.index(flag) <= i < good.index(flag) + n))
        cases = [
            (without("--experimental", 1), "--age-check is experimental and off by default; add --experimental"),
            (without("--dc-api-origin"), "--age-check needs --dc-api-origin"),
            (without("--age-roots"), "--age-check needs --age-roots"),
        ]
        for value in ("16", "0", "18.5", "", "021", "eighteen"):
            cases.append((self.good(value), "--age-check is 18 or 21, not %r" % value))
        token = self.tmp / "token"
        token.write_text("t" * 40)
        refused = (("--claim", "given_name"), ("--vct", "urn:eudi:pid:1"), ("--doctype", md.MDL),
                   ("--iaca-root", str(self.tmp / "iaca.pem")), ("--format", "dc+sd-jwt"), ("--dc-api",),
                   ("--once",), ("--once", "--rearm"), ("--result", str(self.tmp / "r.json")),
                   ("--control-token-file", str(token)), ("--cors-origin", "*"),
                   ("--issuer-jwks", str(self.tmp / "j.json")), ("--issuer-trust-anchor", str(self.tmp / "a.pem")),
                   ("--status-anchor", str(self.tmp / "s.pem")), ("--require-status",),
                   ("--verifier-info", str(self.tmp / "vi.json")), ("--verifier-info-profile", "etsi-119472-2"),
                   ("--credential-query-id", "q"), ("--transaction-data", str(self.tmp / "td.json")))
        for flags in refused:
            cases.append((good + flags, "--age-check is not combined with %s" % flags[0]))
        for args, says in cases:
            with self.subTest(args=args, says=says):
                rc, err = self.before_the_pki(*args)
                self.assertEqual(rc, 2, err)
                self.assertIn(says, err)
                self.assertNotIn("is missing", err)
        # The twins: the good flags, under 18 and 21, with --format mso_mdoc and the metadata file
        # M3 reads, each go on to the missing PKI.
        metadata = self.tmp / "metadata.json"
        metadata.write_text('{"x_polaris_test": 1}')
        for args in (good, self.good("21"), good + ("--format", "mso_mdoc"),
                     good + ("--dc-api-client-metadata", str(metadata))):
            with self.subTest(twin=args):
                rc, err = self.before_the_pki(*args)
                self.assertEqual(rc, 2)
                self.assertIn("is missing", err)

    def test_the_command_serves_the_age_page(self):
        rc, seen, out, err = self._serve(*self.good())
        self.assertEqual(rc, 0, err)
        verifier = seen["verifier"]
        self.assertIsInstance(verifier, age.AgeVerifier)
        self.assertEqual((verifier.age, [r.label for r in verifier.age_roots]), (18, ["Test mDL IACA"]))
        self.assertEqual(seen["kwargs"]["age_origin"], self.ORIGIN)
        for name in ("on_verdict", "on_request_object", "dc_api_origin", "cors_origins", "control_token",
                     "on_control", "on_control_read"):
            self.assertIsNone(seen["kwargs"].get(name), name)
        self.assertIn("%s%s" % (self.ORIGIN, AGE_PAGE_PATH), out)
        self.assertIn("Test mDL IACA", out)
        self.assertEqual(err, "")

    def test_the_roots_file_is_pinned(self):
        sha = hashlib.sha256(IACA_PEM).hexdigest()
        cases = (
            ([{"label": "Root A", "doctype": md.MDL, "pem": "iaca.pem", "sha256": "0" * 64}],
             "entry 1 (Root A): iaca.pem has SHA-256 %s, not its pin" % sha),
            ([{"label": "Root A", "doctype": md.MDL, "pem": "iaca.pem"},
              {"label": "Root B", "doctype": "org.example.other", "pem": "iaca.pem"}],
             "entry 2 (Root B): docType 'org.example.other' is not one the page asks for"),
            ([], "holds no root"),
            ([{"label": "Root A", "doctype": md.MDL, "pem": "absent.pem", "sha256": sha}], "entry 1 (Root A): absent.pem"),
            ([{"label": "", "doctype": md.MDL, "pem": "iaca.pem"}], "entry 1: the label is a non-empty string"),
            ([{"label": "Root A", "doctype": md.MDL, "pem": "iaca.pem", "extra": 1}], "entry 1 (Root A): "),
            ({"label": "Root A"}, "is a JSON array"),
            ([5], "entry 1: an entry is an object of label, doctype, pem and sha256"),
            ([{"label": "Root A", "doctype": md.MDL, "pem": "iaca.pem", "sha256": sha.upper()}],
             "entry 1 (Root A): sha256 is 64 lowercase hex digits"),
            ([{"label": "Root A", "doctype": md.MDL, "pem": "iaca.pem", "sha256": sha[:63]}],
             "entry 1 (Root A): sha256 is 64 lowercase hex digits"),
            ([{"label": "Root A", "doctype": md.MDL, "pem": 5}], "entry 1 (Root A): pem is the path of a PEM file"),
            ([{"label": "Root A", "doctype": md.MDL, "pem": ""}], "entry 1 (Root A): pem is the path of a PEM file"),
            (b"[{", "the file is not read"),
            (None, "the file is not read"),
        )

        def raised(path):
            # Whatever escapes, so that a refusal that is not made fails here, by assertion.
            try:
                age.load_age_roots(path)
            except Exception as exc:  # noqa: BLE001
                return exc
            return None

        for entries, says in cases:
            with self.subTest(says=says):
                if isinstance(entries, list) and all(isinstance(e, dict) for e in entries):
                    path = self.roots_file(entries)
                elif entries is None:
                    path = str(self.tmp / "absent.json")
                else:
                    path = str(self.tmp / "other.json")
                    pathlib.Path(path).write_bytes(entries if isinstance(entries, bytes) else json.dumps(entries).encode())
                caught = raised(path)
                self.assertIsInstance(caught, ValueError)
                self.assertIn(says, str(caught))
                rc, err = self.before_the_pki("--age-check", "18", "--experimental", "--dc-api-origin",
                                              self.ORIGIN, "--age-roots", path)
                self.assertEqual(rc, 2, err)
                self.assertIn("polaris-oid4vp: --age-roots %s: " % path, err)
                self.assertIn(says, err)
        empty = self.tmp / "empty.json"
        empty.write_text("")
        self.assertIn("the file is not read", str(raised(str(empty))))
        # The twin: the pin as computed, and two roots for two docTypes.
        roots = age.load_age_roots(self.roots_file([{"label": "Root A", "doctype": md.MDL, "pem": "iaca.pem"},
                                                    {"label": "Root B", "doctype": AV, "pem": "iaca.pem"}]))
        self.assertEqual([(r.label, r.doctype, r.sha256) for r in roots],
                         [("Root A", md.MDL, sha), ("Root B", AV, sha)])
        self.assertEqual([sorted(r.iaca_root.doctypes) for r in roots], [[md.MDL], [AV]])


if __name__ == "__main__":
    unittest.main()
