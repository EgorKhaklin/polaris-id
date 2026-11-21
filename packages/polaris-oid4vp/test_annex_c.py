# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_annex_c.py -- ISO/IEC 18013-7 Annex C (`org-iso-mdoc`): the request, the SessionTranscript,
and the encrypted DeviceResponse opened and judged (decision record 025, M4).

The outside material is walt.id's two vectors under testdata/annex-c (testdata/README.md): the
transcript is rebuilt from each, and the deterministic one's response is opened with its key.
Every other response here is `test_mdoc.py`'s mint, signed over a transcript built on cbor2 as a
wallet builds it and sealed with `cryptography`'s HPKE to the request this package made. cbor2 is
a test dependency only.
"""
import hashlib
import inspect
import json
import os
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbor2  # noqa: E402  (the witness; a test dependency only)
from cryptography.hazmat.primitives import hpke  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from polaris_oid4vp import annexc  # noqa: E402
from polaris_oid4vp.sdjwt import b64u_decode, b64u_encode  # noqa: E402

import test_mdoc as md  # noqa: E402

ANNEX_C = pathlib.Path(__file__).resolve().parent / "testdata" / "annex-c"
DETERMINISTIC = "ANNEXC-DETERMINISTIC-001.json"
CAPTURED = "ANNEXC-REAL-001.json"
#: The files as walt.id publishes them at ed4bbfe2a5ef7d83e099737643e8216bdc0d9405 (testdata/README.md).
VECTOR_SHA256 = {DETERMINISTIC: "1a12eca214afbeefc13b988a963e768422fd6c431d4e250c089c86b9833e74d1",
                 CAPTURED: "18f86516f8fdd7ef2e7755860a9cda511e3458211bea34e99c3512eaf6e1d3b8"}

ORIGIN = "https://rp.example"
ASKED = {md.MDL_NS: ["family_name", "age_over_21"]}
#: The suite a wallet seals with, built here and not read from the package.
WALLET_SUITE = hpke.Suite(hpke.KEM.P256, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_128_GCM)


def vector(name):
    """One of walt.id's vectors, held to its published bytes first."""
    raw = (ANNEX_C / name).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != VECTOR_SHA256[name]:
        raise AssertionError("%s is not walt.id's file: SHA-256 %s" % (name, digest))
    return json.loads(raw)


def vector_key(v):
    return ec.derive_private_key(int(v["recipientPrivateKeyHex"], 16), ec.SECP256R1())


def bare_session(v, key):
    """A session for vector `v`'s request opened under `key`, built field by field: `Session` itself
    refuses a key its EncryptionInfo does not carry, and these tests need the open to try one."""
    session = object.__new__(annexc.Session)
    session.origin = v["origin"]
    session.encryption_info = v["encryptionInfoB64"]
    session.transcript = annexc.session_transcript(v["encryptionInfoB64"], v["origin"])
    session.doctype = v["expected"]["docType"]
    session.namespaces = {}
    session._recipient_key = key
    return session


def witness_transcript(encryption_info, origin):
    """ISO/IEC 18013-7 Annex C's SessionTranscript as a wallet builds it, on cbor2: the structure,
    because a wallet embeds it in DeviceAuthentication."""
    info = cbor2.dumps([encryption_info, origin])
    return [None, None, ["dcapi", hashlib.sha256(info).digest()]]


def recipient_public_key(values):
    """The recipientPublicKey the request carries, read on cbor2."""
    label, info = cbor2.loads(b64u_decode(values["encryptionInfo"]))
    key = info["recipientPublicKey"]
    return ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big"),
                                         ec.SECP256R1()).public_key()


def envelope(enc, ciphertext, *, label="dcapi", extra=None, drop=None):
    """An EncryptedResponse, base64url, with one thing changed when asked."""
    members = {"enc": enc, "cipherText": ciphertext}
    if drop:
        del members[drop]
    if extra:
        members.update(extra)
    return b64u_encode(cbor2.dumps([label, members]))


def sealed_parts(device_response, values, origin=ORIGIN):
    """`device_response` sealed as a wallet seals it to the request `values` describes: (enc,
    cipherText)."""
    info = cbor2.dumps(witness_transcript(values["encryptionInfo"], origin))
    out = WALLET_SUITE.encrypt(device_response, recipient_public_key(values), info=info)
    return out[:annexc.ENC_BYTES], out[annexc.ENC_BYTES:]


def seal(device_response, values, origin=ORIGIN):
    return envelope(*sealed_parts(device_response, values, origin))


def request(origin=ORIGIN, asked=None):
    return annexc.new_request([(md.MDL, ASKED if asked is None else asked)], origin=origin)


def mint_for(values, origin=ORIGIN, **kw):
    """test_mdoc's mDL, its device signature over this request's Annex C transcript."""
    return md.mint(wallet_transcript=witness_transcript(values["encryptionInfo"], origin), **kw)


def opened(response, session, *, iaca_roots=None):
    """annexc.open_response, held to its docstring: it returns a Verdict and never raises on bad
    input, so an exception from it fails the calling test by assertion."""
    try:
        return annexc.open_response(response, session, iaca_roots=md.ROOTS if iaca_roots is None else iaca_roots)
    except Exception as exc:
        raise AssertionError("open_response raised %s (%s); it returns a Verdict and never raises"
                             % (type(exc).__name__, exc)) from exc


class AnnexCTests(unittest.TestCase):

    def assertRefused(self, verdict, code):
        self.assertFalse(verdict.authentic, "accepted, where %r was expected" % code)
        self.assertEqual(verdict.code, code, verdict.reason)

    def assertRefusesWith(self, message, call, *args, **kw):
        """`call` raises the ValueError that names `message`. Any other exception, or none, fails by
        assertion: a guard removed so that a later line raises something else is a failure here, not
        an error."""
        try:
            call(*args, **kw)
        except Exception as exc:  # noqa: BLE001  (held to its type and message below)
            self.assertIsInstance(exc, ValueError, "raised %s (%s), not the ValueError naming %r"
                                  % (type(exc).__name__, exc, message))
            self.assertRegex(str(exc), message)
            return
        self.fail("no ValueError naming %r" % message)

    # -- walt.id's vectors --------------------------------------------------------------------

    def test_the_vectors_are_waltids_unmodified(self):
        for name in VECTOR_SHA256:
            with self.subTest(name):
                self.assertEqual(vector(name)["id"], name[:-len(".json")])

    def test_the_transcript_reproduces_waltids_deterministic_vector(self):
        v = vector(DETERMINISTIC)
        transcript = annexc.session_transcript(v["encryptionInfoB64"], v["origin"])
        self.assertEqual(v["origin"], "https://verifier.example")
        self.assertEqual(hashlib.sha256(transcript).hexdigest(),
                         "564a34efc36b9b5a5ccafb6bf2e923cd96cc4a9c3712407f887d1e84d3bb58e4")
        self.assertEqual(hashlib.sha256(transcript).hexdigest(), v["expected"]["sessionTranscriptCborSha256Hex"])
        self.assertEqual(cbor2.loads(transcript), witness_transcript(v["encryptionInfoB64"], v["origin"]))

    def test_the_transcript_reproduces_waltids_captured_vector(self):
        v = vector(CAPTURED)
        transcript = annexc.session_transcript(v["encryptionInfoB64"], v["origin"])
        self.assertEqual(v["origin"], "https://verifier.multipaz.org")
        self.assertEqual(hashlib.sha256(transcript).hexdigest(),
                         "82062c48cdfe236c908fedd252886eeedc95cc376619cf16be8725a98ceba8f4")
        self.assertEqual(hashlib.sha256(transcript).hexdigest(), v["expected"]["sessionTranscriptCborSha256Hex"])

    def test_the_deterministic_response_opens_and_is_then_refused(self):
        v = vector(DETERMINISTIC)
        session = annexc.Session(origin=v["origin"], encryption_info=v["encryptionInfoB64"],
                                 recipient_key=vector_key(v), doctype=v["expected"]["docType"],
                                 namespaces={md.MDL_NS: [v["expected"]["requestedElement"]]})
        judge = mock.Mock(wraps=annexc.mdoc.verify_device_response)
        with mock.patch.object(annexc.mdoc, "verify_device_response", judge):
            verdict = opened(v["encryptedResponseB64"], session)
        self.assertRefused(verdict, "malformed")
        (plaintext,), kw = judge.call_args
        self.assertEqual(hashlib.sha256(plaintext).hexdigest(),
                         "61ddbf1dd2e26100520b569946be8415790ec2e35a789172436ed4ac15445581")
        self.assertEqual(hashlib.sha256(plaintext).hexdigest(), v["expected"]["deviceResponseCborSha256Hex"])
        self.assertEqual(cbor2.loads(plaintext), {"version": "1.0", "status": 0})
        self.assertEqual(kw["session_transcript"], session.transcript)
        self.assertEqual(kw["doctype"], "org.iso.18013.5.1.mDL")
        self.assertNotIn("now", kw)

    def test_a_response_opened_for_another_origin_is_refused(self):
        v = vector(DETERMINISTIC)
        session = annexc.Session(origin="https://verifier.example.org", encryption_info=v["encryptionInfoB64"],
                                 recipient_key=vector_key(v), doctype=v["expected"]["docType"], namespaces=ASKED)
        self.assertRefused(opened(v["encryptedResponseB64"], session), "hpke")

    def test_a_response_for_another_key_is_refused(self):
        captured = vector(CAPTURED)
        with self.assertRaisesRegex(ValueError, "another recipientPublicKey"):
            annexc.Session(origin=captured["origin"], encryption_info=captured["encryptionInfoB64"],
                           recipient_key=vector_key(captured), doctype=md.MDL, namespaces=ASKED)
        self.assertRefused(opened(captured["encryptedResponseB64"], bare_session(captured, vector_key(captured))),
                           "hpke")
        deterministic = vector(DETERMINISTIC)
        other = bare_session(deterministic, ec.generate_private_key(ec.SECP256R1()))
        self.assertRefused(opened(deterministic["encryptedResponseB64"], other), "hpke")

    # -- the request --------------------------------------------------------------------------

    def test_each_request_has_a_fresh_key_and_nonce(self):
        infos = []
        for _ in range(2):
            session, values = request()
            label, info = cbor2.loads(b64u_decode(values["encryptionInfo"]))
            self.assertEqual(label, "dcapi")
            self.assertEqual(set(info), {"nonce", "recipientPublicKey"})
            self.assertEqual(len(info["nonce"]), 32)
            key = info["recipientPublicKey"]
            self.assertEqual((key[1], key[-1], len(key[-2]), len(key[-3])), (2, 1, 32, 32))
            recipient_public_key(values)  # on P-256, or this raises
            self.assertEqual(values["encryptionInfo"], session.encryption_info)
            infos.append(info)
        self.assertNotEqual(infos[0]["nonce"], infos[1]["nonce"])
        self.assertNotEqual(infos[0]["recipientPublicKey"], infos[1]["recipientPublicKey"])

    def test_a_request_asks_for_what_it_names(self):
        session, values = request()
        device_request = cbor2.loads(b64u_decode(values["deviceRequest"]))
        self.assertEqual(set(device_request), {"version", "docRequests"})
        self.assertEqual(device_request["version"], "1.0")
        (doc_request,) = device_request["docRequests"]
        self.assertEqual(set(doc_request), {"itemsRequest"})
        self.assertEqual(doc_request["itemsRequest"].tag, 24)
        self.assertEqual(cbor2.loads(doc_request["itemsRequest"].value),
                         {"docType": md.MDL, "nameSpaces": {md.MDL_NS: {"family_name": False, "age_over_21": False}}})
        self.assertEqual((session.origin, session.doctype), (ORIGIN, md.MDL))
        self.assertEqual(session.transcript, cbor2.dumps(witness_transcript(values["encryptionInfo"], ORIGIN)))

    def test_a_request_is_refused_what_it_cannot_ask(self):
        cases = [
            ("two documents", [(md.MDL, ASKED), (md.PID, ASKED)], "list of one"),
            ("no document", [], "list of one"),
            ("an element named twice", [(md.MDL, {md.MDL_NS: ["family_name", "family_name"]})], "named twice"),
            ("no namespace", [(md.MDL, {})], "named twice"),
            ("an empty element list", [(md.MDL, {md.MDL_NS: []})], "named twice"),
            ("a docType that is not text", [(b"mdl", ASKED)], "named twice"),
            ("an empty docType", [("", ASKED)], "named twice"),
            ("an empty namespace", [(md.MDL, {"": ["family_name"]})], "named twice"),
            ("a namespace that is not text", [(md.MDL, {7: ["family_name"]})], "named twice"),
            ("an empty element", [(md.MDL, {md.MDL_NS: [""]})], "named twice"),
            ("an element that is not text", [(md.MDL, {md.MDL_NS: [7]})], "named twice"),
            ("a document request as a map", [{"docType": md.MDL, "nameSpaces": ASKED}], "list of one"),
            ("a document request of three members", [(md.MDL, ASKED, True)], "list of one"),
            ("the document requests as a map", {0: (md.MDL, ASKED)}, "list of one"),
            ("the namespaces as a list", [(md.MDL, [md.MDL_NS])], "named twice"),
            ("the elements as one text", [(md.MDL, {md.MDL_NS: "age"})], "named twice"),
        ]
        for name, doc_requests, message in cases:
            with self.subTest(name):
                self.assertRefusesWith(message, annexc.new_request, doc_requests, origin=ORIGIN)
        with self.assertRaises(ValueError):
            annexc.new_request([(md.MDL, ASKED)], origin="http://rp.example")

    def test_a_transcript_needs_the_text_the_request_sent(self):
        for name, value in (("empty", ""), ("bytes", b"gmVkY2Fwaa"), ("absent", None)):
            with self.subTest(name):
                self.assertRefusesWith("non-empty base64url text", annexc.session_transcript, value, ORIGIN)

    def test_a_session_is_held_when_it_is_made(self):
        session, values = request()
        key = session._recipient_key
        good = dict(origin=ORIGIN, encryption_info=values["encryptionInfo"], recipient_key=key, doctype=md.MDL,
                    namespaces=ASKED)
        annexc.Session(**good)
        other_info = request()[1]["encryptionInfo"]
        cases = [
            ("a P-384 key", dict(good, recipient_key=ec.generate_private_key(ec.SECP384R1())), "P-256 private key"),
            ("no key", dict(good, recipient_key=None), "P-256 private key"),
            ("an EncryptionInfo that is not one", dict(good, encryption_info="gmVkY2Fwaa"),
             "not the base64url of an EncryptionInfo"),
            ("an EncryptionInfo as bytes", dict(good, encryption_info=values["encryptionInfo"].encode()),
             "not the base64url of an EncryptionInfo"),
            ("another request's EncryptionInfo", dict(good, encryption_info=other_info), "another recipientPublicKey"),
            ("no element", dict(good, namespaces={}), "named twice"),
        ]
        label, info = cbor2.loads(b64u_decode(values["encryptionInfo"]))
        key_members = info["recipientPublicKey"]
        for name, other in (("another label", ["dcapi2", info]),
                            ("an extra member", [label, dict(info, extra=1)]),
                            ("an empty nonce", [label, dict(info, nonce=b"")]),
                            ("a nonce as text", [label, dict(info, nonce="n" * 32)]),
                            ("kty 3", [label, dict(info, recipientPublicKey={**key_members, 1: 3})]),
                            ("crv 2", [label, dict(info, recipientPublicKey={**key_members, -1: 2})]),
                            ("a map for its array", {0: label, 1: info}),
                            ("three members", [label, info, None]),
                            ("its member names as a list", [label, ["nonce", "recipientPublicKey"]]),
                            ("a key as a list", [label, dict(info, recipientPublicKey=[2, 1])]),
                            ("an x of 31 bytes", [label, dict(info, recipientPublicKey={**key_members,
                                                                                       -2: key_members[-2][1:]})]),
                            ("an x as text", [label, dict(info, recipientPublicKey={**key_members, -2: "x" * 32})])):
            cases.append(("an EncryptionInfo with " + name, dict(good, encryption_info=b64u_encode(cbor2.dumps(other))),
                          "not the base64url of an EncryptionInfo"))
        for name, kw, message in cases:
            with self.subTest(name):
                self.assertRefusesWith(message, annexc.Session, **kw)
        self.assertNotIn(hex(key.private_numbers().private_value)[2:], repr(session))

    # -- the response -------------------------------------------------------------------------

    def test_an_annex_c_response_from_a_test_wallet_is_accepted(self):
        session, values = request()
        verdict = opened(seal(mint_for(values), values), session)
        self.assertTrue(verdict.authentic, (verdict.code, verdict.reason))

    def test_a_device_signature_over_another_handover_is_refused(self):
        session, values = request()
        handover = md.witness_dc_api_transcript(ORIGIN, "n0nce-from-another-request",
                                                md.witness_thumbprint(md.ENC_JWK))
        self.assertRefused(opened(seal(md.mint(wallet_transcript=handover), values), session), "device_signature")

    def test_a_response_sealed_for_another_origin_is_refused(self):
        session, values = request()
        other = "https://other.example"
        self.assertRefused(opened(seal(mint_for(values, other), values, other), session), "hpke")

    def test_a_bad_enc_or_an_oversized_ciphertext_is_refused_before_opening(self):
        session, values = request()
        enc, ciphertext = sealed_parts(mint_for(values), values)
        off_curve = b"\x04" + bytes(64)
        with mock.patch.object(annexc, "SUITE") as suite:
            suite.decrypt.side_effect = AssertionError("opened before its shape was held")
            self.assertRefused(opened(envelope(enc[:64], ciphertext), session), "malformed")
            self.assertRefused(opened(envelope(enc + b"\x00", ciphertext), session), "malformed")
            self.assertRefused(opened(envelope(enc, bytes(annexc.MAX_CIPHERTEXT_BYTES + 1)), session), "malformed")
        self.assertRefused(opened(envelope(off_curve, ciphertext), session), "hpke")
        for size in (0, 15, 16):
            with self.subTest(ciphertext_bytes=size):
                self.assertRefused(opened(envelope(enc, ciphertext[:size]), session), "hpke")
        self.assertTrue(opened(envelope(enc, ciphertext), session).authentic)

    def test_the_response_size_is_held_before_decoding(self):
        session, values = request()
        limit = (annexc.MAX_ENCRYPTED_RESPONSE_BYTES * 4 + 2) // 3
        with mock.patch.object(annexc, "b64u_decode", side_effect=AssertionError("decoded before its size was held")):
            self.assertRefused(opened("A" * (limit + 1), session), "malformed")
        self.assertRefused(opened("A" * (limit + 1), session), "malformed")

    def test_the_encrypted_response_shape_is_held(self):
        session, values = request()
        enc, ciphertext = sealed_parts(mint_for(values), values)
        cases = {
            "another first label": envelope(enc, ciphertext, label="dcapi2"),
            "the label as bytes": envelope(enc, ciphertext, label=b"dcapi"),
            "no enc": envelope(enc, ciphertext, drop="enc"),
            "no cipherText": envelope(enc, ciphertext, drop="cipherText"),
            "an extra member": envelope(enc, ciphertext, extra={"aad": b""}),
            "enc as text": envelope(b64u_encode(enc), ciphertext),
            "cipherText as text": envelope(enc, b64u_encode(ciphertext)),
            "a map, not an array": b64u_encode(cbor2.dumps({"dcapi": {"enc": enc, "cipherText": ciphertext}})),
            "three members": b64u_encode(cbor2.dumps(["dcapi", {"enc": enc, "cipherText": ciphertext}, None])),
            "a trailing byte": b64u_encode(cbor2.dumps(["dcapi", {"enc": enc, "cipherText": ciphertext}]) + b"\x00"),
            "not base64url": "gmVkY2Fwaa+/",
            "empty": "",
            "a map keyed 0 and 1": b64u_encode(cbor2.dumps({0: "dcapi", 1: {"enc": enc, "cipherText": ciphertext}})),
            "the second member an integer": b64u_encode(cbor2.dumps(["dcapi", 5])),
            "the second member an array of the names": b64u_encode(cbor2.dumps(["dcapi", ["enc", "cipherText"]])),
            "enc as 65 characters of text": envelope("A" * annexc.ENC_BYTES, ciphertext),
        }
        for name, response in cases.items():
            with self.subTest(name):
                self.assertRefused(opened(response, session), "malformed")
        self.assertTrue(opened(envelope(enc, ciphertext), session).authentic)

    def test_hpke_refusing_by_value_error_is_refused_as_hpke(self):
        # cryptography 50.0.2 refuses every bad input measured with InvalidTag; a ValueError from
        # a later release is refused the same way, never let out.
        session, values = request()
        with mock.patch.object(annexc, "SUITE") as suite:
            suite.decrypt.side_effect = ValueError("not a point on the curve")
            self.assertRefused(opened(seal(mint_for(values), values), session), "hpke")

    def test_a_response_that_is_not_text_is_refused(self):
        session, values = request()
        response = seal(mint_for(values), values)
        for name, value in (("bytes", response.encode()), ("none", None), ("a list", [response])):
            with self.subTest(name):
                self.assertRefused(opened(value, session), "malformed")

    def test_a_session_that_is_not_one_is_refused(self):
        session, values = request()
        response = seal(mint_for(values), values)
        for name, value in (("none", None), ("a dict", {"encryption_info": values["encryptionInfo"]})):
            with self.subTest(name):
                self.assertRefused(opened(response, value), "misconfigured")

    def test_open_response_judges_at_the_verifier_clock(self):
        # Record 025's test 14 asks this of the served path; serving arrives with the listener
        # wiring. Here: an mDL that was valid sixty days ago and expired two days ago is judged now,
        # and open_response has no parameter through which a caller could name another instant.
        session, values = request()
        expired = mint_for(values, signed=md.BOOT - md.days(60), valid_from=md.BOOT - md.days(60),
                           valid_until=md.BOOT - md.days(2))
        self.assertRefused(opened(seal(expired, values), session), "credential_validity")
        self.assertEqual(list(inspect.signature(annexc.open_response).parameters),
                         ["response", "session", "iaca_roots"])


if __name__ == "__main__":
    unittest.main()
