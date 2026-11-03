# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""verify_mdoc.py refuses each malformed input at the check that names it, with that check's reason.

The negative vectors (lab/interop/negative-vectors) reach the refusals a wallet's response can carry
past a signature; these reach the rest: the CBOR reader, the COSE_Sign1 shape, the verifier's own
OpenID4VP inputs, and the document fields read before a signature decides. Each test names the
check AND the reason: verify() turns any stray exception into a "malformed" refusal, so a test that
only asked for a refusal would pass with the check it means switched off.
(scripts/polaris-mdoc-mutation-drill.py switches each refusal off and requires a test to go red.)

A document is the vectors' valid mDL (make_mdoc_vectors.mint) with one field changed; when the
change is inside the MSO, the issuer signature is made again with the vectors' document signer,
so the check under test is the first one the document fails.

    python3 -m unittest test_verify_mdoc      (from lab/interop/mdoc)
"""
import copy
import importlib.util
import os
import unittest
from unittest import mock

import cbor2

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, path
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vm = _load("verify_mdoc_refusals", os.path.join(HERE, "verify_mdoc.py"))
mm = _load("make_mdoc_vectors_refusals", os.path.join(HERE, "..", "negative-vectors", "make_mdoc_vectors.py"))


def plain(obj):
    """The structure load_all() gives, with each Raw24 back as tag 24, for cbor2 to encode."""
    if isinstance(obj, vm.Raw24):
        return cbor2.CBORTag(24, obj.inner)
    if isinstance(obj, list):
        return [plain(v) for v in obj]
    if isinstance(obj, dict):
        return {k: plain(v) for k, v in obj.items()}
    if isinstance(obj, cbor2.CBORTag):
        return cbor2.CBORTag(obj.tag, plain(obj.value))
    return obj


class Refusals(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.valid = mm.mint(transcript=mm._rt())
        cls.inputs = copy.deepcopy(mm.REDIRECT_INPUTS)
        cls.roots = [mm.IACA]

    def refused(self, check, reason, fn, *args):
        """fn(*args) refuses with this check and a reason that begins with `reason`."""
        with self.assertRaises(vm.Refused) as cm:
            fn(*args)
        self.assertEqual(cm.exception.check, check, str(cm.exception))
        self.assertTrue(str(cm.exception).startswith("%s: %s" % (check, reason)), str(cm.exception))

    def verify(self, response, inputs=None):
        return vm.verify(response, inputs or self.inputs, self.roots, mm.AT)

    def response(self, edit_doc=None, edit_mso=None):
        """The valid response with `edit_mso(mso)` applied to the MSO (the issuer signature made again)
        and `edit_doc(document)` to the document."""
        resp = vm.load_all(self.valid)
        doc = resp["documents"][0]
        if edit_mso:
            auth = doc["issuerSigned"]["issuerAuth"]
            mso = vm.load_all(vm.load_all(auth[2]).inner)
            edit_mso(mso)
            auth[2] = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(plain(mso))))
            auth[3] = mm._sign1(mm.DS_K, auth[0], auth[2])
        if edit_doc:
            edit_doc(doc)
        return cbor2.dumps(plain(resp))

    # --- the controls ----------------------------------------------------------------------------

    def test_the_valid_response_verifies_and_survives_the_edit_path_unchanged(self):
        self.assertEqual(self.response(), self.valid)
        self.assertEqual(len(self.verify(self.valid)), 1)
        self.assertEqual(len(self.verify(self.response(edit_mso=lambda m: None))), 1)

    # --- the CBOR reader -------------------------------------------------------------------------

    def test_truncated_and_reserved_heads_are_refused(self):
        self.refused("cbor", "truncated", vm.load_all, bytes.fromhex("8201"))      # array of 2, one item
        self.refused("cbor", "truncated", vm.load_all, bytes.fromhex("1901"))      # uint16, one byte
        self.refused("cbor", "reserved additional info 28", vm.load_all, bytes.fromhex("1c"))
        self.refused("cbor", "truncated", vm.load_all, bytes.fromhex("43616263"[:6]))  # bstr of 3, two bytes

    def test_indefinite_lengths_are_refused(self):
        self.refused("cbor", "indefinite-length string", vm.load_all, bytes.fromhex("5f41ff"))
        self.refused("cbor", "indefinite-length array", vm.load_all, bytes.fromhex("9f01ff"))
        self.refused("cbor", "indefinite-length map", vm.load_all, bytes.fromhex("bf0101ff"))

    def test_map_keys_tags_simple_values_and_trailing_bytes_are_refused(self):
        self.refused("cbor", "non-scalar map key", vm.load_all, bytes.fromhex("a18001"))
        self.refused("cbor", "tag 24 over a non-bstr", vm.load_all, bytes.fromhex("d81801"))
        self.refused("cbor", "unexpected simple/float value 0xf9", vm.load_all, bytes.fromhex("f90000"))
        self.refused("cbor", "unexpected simple/float value 0xf7", vm.load_all, bytes.fromhex("f7"))
        self.refused("cbor", "1 trailing bytes", vm.load_all, bytes.fromhex("0102"))
        self.assertEqual(vm.load_all(bytes.fromhex("83f4f5f6")), [False, True, None])

    # --- COSE_Sign1 ------------------------------------------------------------------------------

    def test_a_cose_sign1_under_another_tag_or_with_a_non_map_protected_header_is_refused(self):
        sign1 = [cbor2.dumps({1: -7}), {}, b"payload", b"\x00" * 64]
        self.assertEqual(vm.cose_sign1(cbor2.CBORTag(18, sign1), "x")[1], {1: -7})
        self.refused("x", "COSE_Sign1 under tag 98", vm.cose_sign1, cbor2.CBORTag(98, sign1), "x")
        self.refused("x", "protected header is not a map", vm.cose_sign1, [cbor2.dumps([1])] + sign1[1:], "x")

    # --- the verifier's OpenID4VP inputs ---------------------------------------------------------

    def test_a_redirect_transcript_needs_each_input_and_a_key_exactly_when_encrypted(self):
        base = mm.REDIRECT_INPUTS
        for k in ("client_id", "nonce", "response_uri"):
            for gone in ({key: v for key, v in base.items() if key != k}, {**base, k: ""}):
                with self.subTest(k=k):
                    self.refused("session transcript", "no %s" % k, vm.session_transcript, gone)
        self.refused("session transcript", "response_mode 'fragment'", vm.session_transcript,
                     {**base, "response_mode": "fragment"})
        self.refused("session transcript", "direct_post with an encryption key", vm.session_transcript,
                     {**base, "response_mode": "direct_post"})
        self.refused("session transcript", "direct_post.jwt without an encryption key", vm.session_transcript,
                     {**base, "encryption_jwk": None})
        self.refused("session transcript", "the encryption key is not an EC JWK", vm.session_transcript,
                     {**base, "encryption_jwk": {"kty": "OKP", "crv": "X25519", "x": "AA", "y": "AA"}})
        unencrypted = {k: v for k, v in base.items() if k != "encryption_jwk"}
        self.assertIsNone(vm.session_transcript({**unencrypted, "response_mode": "direct_post"})[1])

    def test_a_dc_api_transcript_needs_each_input_and_a_key_exactly_when_encrypted(self):
        base = mm.DCAPI_INPUTS
        for k in ("origin", "nonce"):
            with self.subTest(k=k):
                self.refused("session transcript", "no %s" % k, vm.session_transcript,
                             {key: v for key, v in base.items() if key != k})
        self.refused("session transcript", "dc_api with an encryption key", vm.session_transcript,
                     {**base, "response_mode": "dc_api"})
        self.refused("session transcript", "dc_api.jwt without an encryption key", vm.session_transcript,
                     {**base, "encryption_jwk": None})

    def test_the_specification_examples_are_reproduced_and_a_difference_is_refused(self):
        self.assertEqual(vm.check_spec_vector(), vm.SPEC_TRANSCRIPT)
        self.assertEqual(vm.check_spec_vector_dcapi(), vm.SPEC_DCAPI_TRANSCRIPT)
        with mock.patch.object(vm, "SPEC_TRANSCRIPT", "00"):
            self.refused("session transcript", "does not reproduce the OpenID4VP 1.0 B.2.6.1 example",
                         vm.check_spec_vector)
        with mock.patch.object(vm, "SPEC_DCAPI_TRANSCRIPT", "00"):
            self.refused("session transcript", "does not reproduce the OpenID4VP 1.0 B.2.6.2 example",
                         vm.check_spec_vector_dcapi)

    # --- fields read before a signature decides --------------------------------------------------

    def test_a_tdate_needs_tag_0_and_a_time_zone(self):
        self.assertEqual(vm.tdate(cbor2.CBORTag(0, "2026-09-30T00:00:00Z"), "signed").year, 2026)
        self.refused("validity", "signed has no time zone", vm.tdate, cbor2.CBORTag(0, "2026-09-30T00:00:00"), "signed")
        self.refused("validity", "signed is not a tdate (tag 0)", vm.tdate, "2026-09-30T00:00:00Z", "signed")

    def test_a_device_key_is_an_ec2_cose_key_with_both_coordinates(self):
        self.refused("device key", "deviceKey is not an EC2 P-256/P-384 COSE_Key", vm.cose_key,
                     {1: 1, -1: 1, -2: b"\x00" * 32, -3: b"\x00" * 32})
        self.refused("device key", "deviceKey x/y missing", vm.cose_key, {1: 2, -1: 1})
        self.refused("device key", "deviceKey is not a point on secp256r1", vm.cose_key,
                     {1: 2, -1: 1, -2: b"\x00" * 32, -3: b"\x00" * 32})

    def test_device_name_spaces_and_each_namespace_in_them_are_maps(self):
        self.refused("device data", "DeviceNameSpaces is not a map", vm.device_signed_elements, cbor2.dumps([1]), {})
        self.refused("device data", "namespace 'org.example.device' in DeviceNameSpaces is not a map",
                     vm.device_signed_elements, cbor2.dumps({"org.example.device": ["device_note"]}),
                     {"deviceKeyInfo": {"keyAuthorizations": {"nameSpaces": ["org.example.device"]}}})

    def test_a_document_needs_a_doctype_and_issuer_signed(self):
        noop = lambda c, d: None  # noqa: E731
        self.refused("document", "no docType", vm.verify_document, {"docType": 1}, None, self.roots, mm.AT, noop)
        self.refused("document", "no issuerSigned", vm.verify_document, {"docType": mm.MDL}, None, self.roots, mm.AT, noop)

    def test_the_mso_version_and_its_signing_time_are_checked(self):
        self.refused("mso", "not an MSO version 1.0", self.verify,
                     self.response(edit_mso=lambda m: m.update(version="1.1")))

        def signed_later(m):
            m["validityInfo"]["signed"] = cbor2.CBORTag(0, "2027-01-01T00:00:00Z")
        self.refused("validity", "signed 2027-01-01 00:00:00+00:00 is after", self.verify,
                     self.response(edit_mso=signed_later))

    def test_disclosed_name_spaces_and_their_items_are_checked_before_their_digests(self):
        ns = mm.MDL_NS

        def name_spaces(value):
            return lambda d: d["issuerSigned"].update(nameSpaces=value)
        self.refused("digests", "no disclosed nameSpaces", self.verify, self.response(name_spaces({})))
        self.refused("digests", "namespace %r has no digests or no items" % ns, self.verify,
                     self.response(name_spaces({ns: []})))
        self.refused("digests", "namespace 'org.example.other' has no digests or no items", self.verify,
                     self.response(lambda d: d["issuerSigned"]["nameSpaces"].update({"org.example.other": [1]})))

        def item(value):
            return lambda d: d["issuerSigned"]["nameSpaces"][ns].__setitem__(0, value)
        self.refused("digests", "an item in %r is not IssuerSignedItemBytes (tag 24)" % ns, self.verify,
                     self.response(item({"digestID": 0})))
        no_value = cbor2.dumps({"digestID": 0, "random": mm._random("family_name"), "elementIdentifier": "family_name"})
        self.refused("digests", "malformed IssuerSignedItem 0 in %r" % ns, self.verify,
                     self.response(item(vm.Raw24(cbor2.dumps(cbor2.CBORTag(24, no_value)), no_value))))

    def test_an_item_whose_tag_24_wrapper_is_not_the_preferred_encoding_is_refused(self):
        first = vm.load_all(self.valid)["documents"][0]["issuerSigned"]["nameSpaces"][mm.MDL_NS][0]
        self.assertEqual(first.raw[:3], b"\xd8\x18\x58")                 # bstr length in one byte
        longer = b"\xd8\x18\x59\x00" + first.raw[3:]                      # the same length in two
        self.assertEqual(self.valid.count(first.raw), 1)
        self.refused("digests", "non-preferred tag-24 wrapper in %r" % mm.MDL_NS, self.verify,
                     self.valid.replace(first.raw, longer))

    def test_device_signed_is_checked_before_its_signature(self):
        self.refused("device signature", "no deviceSigned", self.verify, self.response(lambda d: d.pop("deviceSigned")))
        self.refused("device signature", "deviceSigned nameSpaces is not DeviceNameSpacesBytes", self.verify,
                     self.response(lambda d: d["deviceSigned"].update(nameSpaces={})))
        self.refused("device signature", "DeviceMac: out of scope for milestone 1", self.verify,
                     self.response(lambda d: d["deviceSigned"]["deviceAuth"].update(deviceMac=[b"", {}, None, b""])))

    # --- the response and the request ------------------------------------------------------------

    def test_an_empty_or_documentless_response_is_refused(self):
        self.refused("input", "empty DeviceResponse", self.verify, b"")
        self.refused("device response", "not a DeviceResponse version 1.0 with status 0", self.verify,
                     cbor2.dumps({"version": "1.0", "documents": [], "status": 10}))
        self.refused("device response", "no documents", self.verify,
                     cbor2.dumps({"version": "1.0", "documents": [], "status": 0}))

    def test_a_requested_doctype_is_a_string(self):
        self.refused("requested docType", "doctype_value is not a string", self.verify, self.valid,
                     {**self.inputs, "doctype_value": 5})

    def test_claims_values_and_claim_sets_are_well_formed(self):
        elements = self.verify(self.valid)[0]
        path = [mm.MDL_NS, "family_name"]
        self.refused("requested claims", "claims values for %r is not a non-empty array" % (path,), vm.requested_claims,
                     {"claims": [{"path": path, "values": []}]}, elements, lambda c, d: None)
        self.refused("requested claims", "claim_sets is not an array of options naming claims ids", vm.requested_claims,
                     {"claims": [{"id": "a", "path": path}], "claim_sets": [["b"]]}, elements, lambda c, d: None)


if __name__ == "__main__":
    unittest.main()
