#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Fuzz what reads a wallet's mdoc: the CBOR decoder, held to cbor2, and the verdict on a
DeviceResponse.

The decoder's promise is cbor.decode's: "Raises CborError for anything this module refuses,
trailing bytes included, and never another exception for a bytes-like input." What it does
return is held to a second reader: cbor2 reads the same bytes to the same value, type for
type and a map's entries in the order they arrived; every tag-24 item is a slice of the input
in its one accepted encoding; and this package's encoder writes the value back as cbor2 does.
cbor2 runs in its strict mode here (no indefinite length, no repeated map key, both of which
this decoder refuses) and leaves tags 0 and 1004 as tags, as this decoder does.

The verdict's promise is mdoc.verify_device_response's: "Returns a Verdict and never raises on
bad input." Bytes the decoder refuses are refused as `malformed`, a refusal names its code,
and nothing authentic differs from what the document signer signed. The signer and the device
are the suite's own (test_mdoc.mint, built on cbor2 and `cryptography`, never on the code
under test) with this directory's fixed keys, so the fuzzer reaches the Mobile Security
Object, the COSE headers and the element values that a real issuer's key would otherwise
guard: an issuer's key is not a promise that what it signed is well formed.

The first input byte picks the form, the rest is the input:

    0  the bytes, to the decoder alone
    1  the bytes, as the DeviceResponse
    2  one member replaced by a typed value (typed), picked by the next byte: of the response
       or the document after they are signed, of the Mobile Security Object, a COSE header,
       the certificate chain or the device's namespaces before
    3  one element's value, signed

    python3 fuzz_mdoc.py corpus/mdoc -max_total_time=60
"""
import json
import os
import sys
from collections.abc import Mapping

import atheris

# The package from this tree, not whatever release is installed.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

with atheris.instrument_imports(include=["polaris_oid4vp"]):
    from polaris_oid4vp import cbor, mdoc, sdjwt

import cbor2  # noqa: E402  (the oracle)

import _genuine  # noqa: E402
import test_mdoc  # noqa: E402


def _tag_kept(number):
    return lambda value, immutable: cbor2.CBORTag(number, value)


#: cbor2 as the oracle. It refuses what this decoder refuses where it can be told to, and
#: keeps the two date tags as tags instead of parsing their text, so that a difference is
#: always this decoder's.
STRICT = {"allow_indefinite": False, "allow_duplicate_keys": False,
          "semantic_decoders": {0: _tag_kept(0), 1004: _tag_kept(1004)}}

NS = test_mdoc.MDL_NS
ITEMS = (test_mdoc.el("family_name", "Mustermann", random=bytes(range(32))),
         test_mdoc.el("age_over_21", True, random=bytes(range(32, 64))))
SIGNED = {NS: {"family_name": "Mustermann", "age_over_21": True}}

IACA = test_mdoc.make_cert("Test IACA", _genuine.IACA_KEY.public_key(), "Test IACA", _genuine.IACA_KEY,
                           ca=True, path_length=0, usage="ca", ski=True)
_, DS = test_mdoc.make_ds(_genuine.IACA_KEY, key=_genuine.ISSUER_KEY)
ROOTS = [mdoc.IacaRoot(IACA, [test_mdoc.MDL])]
REQUEST = test_mdoc.REQUEST
ENC_JWK = test_mdoc.public_jwk(_genuine.VERIFIER_ENC_KEY)
WALLET_TRANSCRIPT = test_mdoc.witness_transcript(
    REQUEST["client_id"], REQUEST["nonce"], test_mdoc.witness_thumbprint(ENC_JWK), REQUEST["response_uri"])
TRANSCRIPT = mdoc.redirect_session_transcript(jwk_thumbprint=mdoc.jwk_thumbprint(ENC_JWK), **REQUEST)


def _under(hook, *paths):
    return [(hook, path) for path in paths]


_AUTH, _DEVICE = ("issuerSigned", "issuerAuth"), ("deviceSigned", "deviceAuth")
#: Each member the verifier reads, by the hook of test_mdoc.mint that reaches it and its path.
#: The response and the document are edited after the signatures; the MSO before its own.
FIELDS = (
    _under("edit_response", ("version",), ("status",), ("documents",), ("documents", 0), ("documentErrors",))
    + _under("edit_doc", ("docType",), ("errors",), ("issuerSigned",), ("issuerSigned", "nameSpaces"),
             ("issuerSigned", "nameSpaces", NS), ("issuerSigned", "nameSpaces", NS, 0), _AUTH,
             _AUTH + (0,), _AUTH + (1,), _AUTH + (2,), _AUTH + (3,), ("deviceSigned",),
             ("deviceSigned", "nameSpaces"), _DEVICE, _DEVICE + ("deviceMac",),
             _DEVICE + ("deviceSignature",), _DEVICE + ("deviceSignature", 0),
             _DEVICE + ("deviceSignature", 1), _DEVICE + ("deviceSignature", 2),
             _DEVICE + ("deviceSignature", 3))
    + _under("edit_mso", ("version",), ("digestAlgorithm",), ("docType",), ("status",), ("valueDigests",),
             ("valueDigests", NS), ("valueDigests", NS, 0), ("deviceKeyInfo",), ("deviceKeyInfo", "deviceKey"),
             ("deviceKeyInfo", "deviceKey", 1), ("deviceKeyInfo", "deviceKey", -1),
             ("deviceKeyInfo", "deviceKey", -2), ("deviceKeyInfo", "deviceKey", -3), ("validityInfo",),
             ("validityInfo", "signed"), ("validityInfo", "validFrom"), ("validityInfo", "validUntil")))
#: The arguments of test_mdoc.mint that take a value as it is and sign over it.
KNOBS = ("issuer_protected", "issuer_unprotected", "x5chain", "device_protected", "device_unprotected")
CHOICES = len(FIELDS) + len(KNOBS) + 1
#: The one member read for its presence alone: an MSO that names a status is authentic whatever
#: the status holds, and the verdict says the status was not read. Every other member holding
#: `5` is refused, which is how the controls know a replacement landed.
PRESENCE_ONLY = FIELDS.index(("edit_mso", ("status",)))


def typed(raw):
    """The fuzzer's bytes as the CBOR value they encode, when cbor2 reads them and can write the
    value back; else as a byte string.

    A value of the wrong type under the right name is this package's recurring defect. Byte
    mutations of a DeviceResponse rarely give one: a changed head misaligns everything after
    it and the decoder refuses the whole. Here `5`, `[]`, `{}`, `null` or a float is a one-byte
    input, and the lenient cbor2 gives the values this decoder refuses as well.
    """
    try:
        value = cbor2.loads(raw)
        cbor2.dumps(value)
        return value
    except Exception:
        return raw


def minted(**changes):
    """One DeviceResponse from the suite's wallet, under this directory's keys."""
    changes.setdefault("items", ITEMS)
    return test_mdoc.mint(ds=DS, ds_key=_genuine.ISSUER_KEY, device_key=_genuine.HOLDER_KEY,
                          wallet_transcript=WALLET_TRANSCRIPT, **changes)


def replaced(pick, value):
    """A minted DeviceResponse with the member `pick` names holding `value`."""
    pick %= CHOICES
    if pick < len(FIELDS):
        hook, path = FIELDS[pick]

        def edit(node):
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
        return minted(**{hook: edit})
    if pick < len(FIELDS) + len(KNOBS):
        return minted(**{KNOBS[pick - len(FIELDS)]: value})
    return minted(device_namespaces=cbor2.dumps(value))


def same(ours, theirs):
    """This decoder's value against cbor2's, type for type: True is not 1, and a map's entries
    are compared in the order the bytes gave them."""
    if isinstance(ours, cbor.Tag24):
        return (isinstance(theirs, cbor2.CBORTag) and theirs.tag == 24 and type(theirs.value) is bytes
                and theirs.value == ours.inner)
    if isinstance(ours, cbor.Tagged):
        return isinstance(theirs, cbor2.CBORTag) and theirs.tag == ours.tag and same(ours.value, theirs.value)
    if isinstance(ours, list):
        return (isinstance(theirs, (list, tuple)) and len(ours) == len(theirs)
                and all(same(a, b) for a, b in zip(ours, theirs)))
    if isinstance(ours, dict):
        return (isinstance(theirs, Mapping) and len(ours) == len(theirs)
                and all(same(k, tk) and same(v, tv)
                        for (k, v), (tk, tv) in zip(ours.items(), theirs.items())))
    return type(ours) is type(theirs) and ours == theirs


def decoded(data):
    """`data` through the decoder: refused with CborError, or read as cbor2 reads it."""
    try:
        ours = cbor.decode(data)
    except cbor.CborError:
        return
    try:
        theirs = cbor2.loads(data, **STRICT)
    except Exception as exc:
        raise AssertionError("cbor2 refuses what this decoder read as %r: %s" % (ours, exc)) from None
    if not same(ours, theirs):
        raise AssertionError("this decoder read %r and cbor2 read %r" % (ours, theirs))
    for item in test_mdoc.tag24_items(ours):
        if item.raw not in data or item.raw != cbor2.dumps(cbor2.CBORTag(24, item.inner)):
            raise AssertionError("a tag-24 item's bytes are not the ones that arrived: %r" % (item.raw,))
    written = cbor.encode(ours)
    if written != cbor2.dumps(test_mdoc.as_cbor2(ours)) or cbor.decode(written) != ours:
        raise AssertionError("the encoder wrote %r for %r" % (written, ours))


def judged(response, signed=SIGNED):
    """`response` through the verifier, held to its docstring. `signed` is what the document
    signer signed, {namespace: {element: value}}; None where the fuzzer wrote the value."""
    verdict = mdoc.verify_device_response(response, session_transcript=TRANSCRIPT, iaca_roots=ROOTS)
    if (type(verdict) is not sdjwt.Verdict or type(verdict.authentic) is not bool
            or not isinstance(verdict.code, str) or bool(verdict.code) == verdict.authentic):
        raise AssertionError("verify_device_response returned %r" % (verdict,))
    try:
        cbor.decode(response)
    except cbor.CborError:
        if verdict.code != "malformed":
            raise AssertionError("the decoder refuses these bytes and the verdict is %r: %s"
                                 % (verdict.code, verdict.reason)) from None
    if verdict.authentic:
        # What a relying party is handed: JSON, and nothing the signer did not sign.
        text = json.dumps(verdict.claims, allow_nan=False, sort_keys=True)
        said = [(namespace, element, json.dumps(value)) for namespace, elements in verdict.claims.items()
                for element, value in elements.items()]
        if signed is not None and not all(
                element in signed.get(namespace, {}) and json.dumps(signed[namespace][element]) == value
                for namespace, element, value in said):
            raise AssertionError("authentic, with claims the signer did not sign: %s" % text)
    return verdict


def TestOneInput(data):
    if not data:
        return
    form, body = data[0] % 4, data[1:]
    if form == 0:
        decoded(body)
    elif form == 1:
        decoded(body)
        judged(body)
    elif not body:
        return
    elif form == 2:
        judged(replaced(body[0], typed(body[1:])))
    else:
        value = typed(body)
        verdict = judged(minted(items=(test_mdoc.el("family_name", value, random=bytes(32)),)), signed=None)
        # A value JSON carries as it is comes back as itself: 1 is not true.
        if verdict.authentic and type(value) in (bool, int, str, type(None)):
            claim = verdict.claims[NS]["family_name"]
            if type(claim) is not type(value) or claim != value:
                raise AssertionError("signed %r, claimed %r" % (value, claim))


def controls():
    """The harness's own positive controls, at every start: a target whose genuine input is
    refused, or whose replacement never lands, fuzzes nothing and stays green."""
    # The oracle in the mode this target relies on: a cbor2 release that reads a repeated key or
    # an indefinite length, or parses a date tag's content, would agree with a decoder that
    # lost the matching refusal.
    for refused in ("a200010002", "9f01ff"):
        try:
            cbor2.loads(bytes.fromhex(refused), **STRICT)
        except cbor2.CBORDecodeError:
            continue
        raise AssertionError("cbor2 reads %s: its strict mode is not on" % refused)
    decoded(bytes.fromhex("c005"))
    genuine = judged(minted())
    if not genuine.authentic or genuine.claims != SIGNED:
        raise AssertionError("the minted DeviceResponse is not accepted: %s: %s" % (genuine.code, genuine.reason))
    codes = [judged(replaced(pick, 5)).code for pick in range(CHOICES)]
    if [pick for pick, code in enumerate(codes) if not code] != [PRESENCE_ONLY]:
        raise AssertionError("a replaced member did not land: %r" % (codes,))
    for name in test_mdoc.CAPTURES:
        decoded(test_mdoc.capture(name))
        if judged(test_mdoc.capture(name)).authentic:
            raise AssertionError("%s is accepted under a request it did not answer" % name)


def seeds():
    """Genuine inputs for each form: the wallets' captured responses and a minted one, whole and
    as their tag-24 items; one small item of each kind the decoder reads, so that one changed
    byte is another kind of item; every member replaced once; one element value of each type."""
    tag = cbor2.CBORTag
    captures = [test_mdoc.capture(name) for name in test_mdoc.CAPTURES]
    small = (0, 24, -1, -1000, b"\x01", "a", [], [1, [2, 3]], {}, {0: 1, 1: 2}, {"a": 1, "b": 2}, False, True,
             None, tag(0, "2026-01-01T00:00:00Z"), tag(1004, "2026-01-01"), tag(24, b"\x01"),
             tag(24, cbor2.dumps({"a": 1})), tag(18, [b"\xa1\x01\x26", {}, None, b""]))
    values = ("Mustermann", True, 5, None, b"\x01", [1], {"a": 1}, tag(1004, "2026-01-01"), tag(0, 5), 1.5)
    return ([bytes([form]) + raw for form in (0, 1) for raw in captures + [minted()]]
            + [bytes([0]) + item.inner for raw in captures for item in test_mdoc.tag24_items(cbor.decode(raw))]
            + [bytes([0]) + cbor2.dumps(value) for value in small]
            + [bytes([2, pick, 5]) for pick in range(CHOICES)]
            + [bytes([3]) + cbor2.dumps(value) for value in values])


if __name__ == "__main__":
    controls()
    _genuine.seed(sys.argv, seeds())
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
