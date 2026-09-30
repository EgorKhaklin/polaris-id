#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Fuzz verify_presentation with whatever string a wallet could send.

The promise under test is the function's own docstring: it "returns a Verdict and never
raises on bad input". Any exception is a crash. So is an accepted presentation whose claims
differ from what the issuer signed: bytes the fuzzer changed may still verify (a disclosure
dropped is still a valid presentation), but they must never verify to a different value.

    python3 fuzz_presentation.py corpus/presentation -max_total_time=60
"""
import os
import sys

import atheris

# The package from this tree, not whatever release is installed.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

with atheris.instrument_imports(include=["polaris_oid4vp"]):
    from polaris_oid4vp import sdjwt

import _genuine  # noqa: E402

WALLET = _genuine.wallet()
KWARGS = _genuine.verify_kwargs(WALLET)
SIGNED = {"given_name": _genuine.GIVEN, "family_name": _genuine.FAMILY,
          "address": {"locality": "Lyon"}, "nationalities": ["FR"]}


def TestOneInput(data):
    # UTF-8, so a seed is the presentation itself. surrogateescape because a wallet's JSON can
    # carry a lone surrogate as an escape ("\ud800"), and json.loads hands it through.
    presentation = data.decode("utf-8", "surrogateescape")
    verdict = sdjwt.verify_presentation(presentation, **KWARGS)
    if not isinstance(verdict, sdjwt.Verdict):
        raise AssertionError("verify_presentation returned %r, not a Verdict" % (verdict,))
    if verdict.authentic:
        for name, value in verdict.claims.items():
            if name in SIGNED and value != SIGNED[name]:
                raise AssertionError("accepted %s=%r; the issuer signed %r"
                                     % (name, value, SIGNED[name]))


if __name__ == "__main__":
    _genuine.seed(sys.argv, _genuine.presentations(WALLET))
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
