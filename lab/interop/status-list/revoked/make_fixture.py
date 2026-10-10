#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""make_fixture.py: one SD-JWT VC revoked by its Token Status List, for testing a verifier's
revocation check. Writes, beside this file:

  credential.sd-jwt      the issuer-signed SD-JWT VC; its `status` names index 3 of the list below
  presentation.sd-jwt    the same credential with a Key Binding JWT (nonce and aud in fixture.json)
  status-list.jwt        the Status List Token (1 bit per entry): index 3 is 1 (INVALID), index 2 is 0
  trust-anchor.pem       the test root the issuer's x5c chain ends at
  fixture.json           the instant, nonce, audience, status URI and the two indexes

Every key and certificate is TEST material, the same deterministic set the negative vectors use
(../../negative-vectors/make_vectors.py, derived from public seeds), so a byte here never changes
between runs and nothing here is a secret. Run it again and `git diff` must be empty.
"""
import importlib.util
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "make_vectors", os.path.join(HERE, "..", "..", "negative-vectors", "make_vectors.py"))
mv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mv)

STATUS_URI = "https://issuer.example/statuslists/1"
REVOKED_INDEX = 3
VALID_INDEX = 2
STATUSES = [0, 0, 0, 1, 0, 0, 0, 0]  # 1 = INVALID (draft-ietf-oauth-status-list, section 7.1)


def build():
    status_claim = {"status_list": {"idx": REVOKED_INDEX, "uri": STATUS_URI}}
    presentation = mv.present(payload=mv._set(status=status_claim))
    # The issuer-signed part alone, as an issuer hands it to a wallet: everything up to and
    # including the last disclosure's trailing `~`, without the Key Binding JWT.
    credential = presentation[:presentation.rindex("~") + 1]
    header = {"alg": "ES256", "typ": "statuslist+jwt", "x5c": [mv._der64(c) for c in (mv.LEAF, mv.INTERMEDIATE)]}
    payload = {"sub": STATUS_URI, "iat": mv.NOW - 3600, "exp": mv.NOW + 365 * 86400, "ttl": 43200,
               "status_list": {"bits": 1, "lst": _encode(STATUSES)}}
    token = mv._jws(header, mv._json(payload), key=mv.ISS_K)
    fixture = {"now": mv.NOW, "nonce": mv.NONCE, "audience": mv.AUDIENCE, "vct": mv.VCT, "issuer": mv.ISSUER,
               "status_uri": STATUS_URI, "revoked_index": REVOKED_INDEX, "valid_index": VALID_INDEX}
    return {"credential.sd-jwt": credential + "\n", "presentation.sd-jwt": presentation + "\n",
            "status-list.jwt": token + "\n", "trust-anchor.pem": mv._pem(mv.ROOT),
            "fixture.json": json.dumps(fixture, indent=1, sort_keys=True) + "\n"}


def _encode(statuses):
    """The `lst` value: 1-bit statuses packed little-endian per byte, zlib, base64url (section 4.1).
    Written here, not taken from polaris_oid4vp.status, so the fixture does not test that verifier
    against its own encoder."""
    import base64
    import zlib
    array = bytearray((len(statuses) + 7) // 8)
    for i, s in enumerate(statuses):
        array[i // 8] |= s << (i % 8)
    return base64.urlsafe_b64encode(zlib.compress(bytes(array), 9)).rstrip(b"=").decode("ascii")


if __name__ == "__main__":
    for name, text in build().items():
        with open(os.path.join(HERE, name), "w") as f:
            f.write(text)
    print("wrote", ", ".join(sorted(build())))
