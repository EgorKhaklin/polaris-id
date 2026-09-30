# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Genuine artifacts for the fuzz targets, built with fixed keys and a fixed clock.

Fixed so that an input the fuzzer saves reproduces on any machine: the same bytes meet the
same issuer key, holder key, verifier key, nonce, audience and time. The presentations come
from the suite's own wallet (test_sdjwt.Wallet), the one its positive control accepts, so a
target starts from what the verifier is known to say yes to and mutates outward.

Each target imports polaris_oid4vp under atheris.instrument_imports() BEFORE importing this
module, so the package modules this reuses are the instrumented ones.
"""
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE = os.path.dirname(HERE)
if PACKAGE not in sys.path:
    sys.path.insert(0, PACKAGE)

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import test_sdjwt  # noqa: E402
from polaris_oid4vp import jwe, status  # noqa: E402

NOW = 1_800_000_000
NONCE = test_sdjwt.NONCE
AUDIENCE = test_sdjwt.AUDIENCE
_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _key(label):
    return ec.derive_private_key(
        int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") % (_ORDER - 1) + 1,
        ec.SECP256R1())


ISSUER_KEY = _key("polaris-oid4vp fuzz issuer")
HOLDER_KEY = _key("polaris-oid4vp fuzz holder")
VERIFIER_ENC_KEY = _key("polaris-oid4vp fuzz verifier encryption")

GIVEN, FAMILY = "Jean", "Dupont"


def wallet():
    """The suite's wallet, with this module's keys instead of fresh random ones."""
    w = test_sdjwt.Wallet()
    w.issuer_key, w.holder_key = ISSUER_KEY, HOLDER_KEY
    w.issuer_jwk = dict(test_sdjwt._public_jwk(ISSUER_KEY), kid="issuer-1")
    return w


def verify_kwargs(w):
    """What the Verifier class passes: the nonce, the audience, the issuer keys and the type."""
    return {"expected_nonce": NONCE, "expected_audience": AUDIENCE,
            "issuer_jwks": [w.issuer_jwk], "now": NOW, "expected_vct": ["urn:eudi:pid:1"]}


def presentations(w, nonce=NONCE, audience=AUDIENCE):
    """A few genuine presentations that reach different parts of the verifier."""
    base = {"nonce": nonce, "audience": audience, "iat": NOW}
    return [
        w.present(payload_extra={"iat": NOW}, **base),
        w.present(payload_extra={"iat": NOW, "nbf": NOW - 60, "exp": NOW + 3600}, **base),
        w.present(payload_extra={"iat": NOW, "status": {"status_list": {
            "idx": 3, "uri": "https://issuer.example/statuslists/1"}}}, **base),
        w.present(payload_extra={"iat": NOW},
                  claims=(("given_name", GIVEN), ("address", {"locality": "Lyon"}),
                          ("nationalities", ["FR"])), **base),
    ]


def issuer_payload(**extra):
    """The issuer-signed payload of the first presentation, as the wallet builds it."""
    disclosures = [test_sdjwt._disclosure("salt%d" % i, name, value)
                   for i, (name, value) in enumerate((("given_name", GIVEN),
                                                      ("family_name", FAMILY)))]
    digests = [test_sdjwt.b64u_encode(hashlib.sha256(d.encode("ascii")).digest())
               for d in disclosures]
    payload = {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1", "iat": NOW,
               "_sd": digests, "_sd_alg": "sha-256",
               "cnf": {"jwk": test_sdjwt._public_jwk(HOLDER_KEY)}}
    payload.update(extra)
    return payload, disclosures


def sign(key, header_bytes, payload_bytes):
    """A compact ES256 JWS over EXACTLY these header and payload bytes, whatever they are."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    head = test_sdjwt.b64u_encode(header_bytes) + "." + test_sdjwt.b64u_encode(payload_bytes)
    r, s = asym_utils.decode_dss_signature(
        key.sign(head.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return head + "." + test_sdjwt.b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def sd_hash(presented):
    return test_sdjwt.b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())


def response_body(state, presentation):
    return {"state": state, "vp_token": {"pid": [presentation]}}


def jwe_tokens(w):
    public = VERIFIER_ENC_KEY.public_key()
    first = presentations(w)[0]
    bodies = [response_body("s" * 22, first), {"state": "x", "vp_token": {"pid": first}},
              {"error": "access_denied"}]
    return [jwe.encrypt_compact(json.dumps(b).encode(), public, enc)
            for b in bodies for enc in ("A128GCM", "A256GCM")]


STATUS_URI = "https://issuer.example/statuslists/1"
STATUS_ISSUER = "https://issuer.example"


def status_tokens():
    """Status List Tokens as test_status builds them; the fuzz authority accepts any signature."""
    out = []
    for statuses, bits in (((0, 1, 2, 0), 2), ((0, 1) * 40, 1), ((3, 0, 1), 4), ((255, 0), 8)):
        payload = {"sub": STATUS_URI, "iat": NOW - 60, "exp": NOW + 3600, "ttl": 600,
                   "status_list": {"bits": bits,
                                   "lst": status.encode_status_list(statuses, bits)}}
        header = {"alg": "ES256", "typ": "statuslist+jwt", "kid": "k1"}
        out.append(".".join([test_sdjwt.b64u_encode(json.dumps(header).encode()),
                             test_sdjwt.b64u_encode(json.dumps(payload).encode()),
                             test_sdjwt.b64u_encode(b"sig")]))
    return out


def typed(raw):
    """The fuzzer's bytes as a JSON value when they parse as one, else as a string.

    Type confusion is this package's recurring defect (a list where a string was read, NaN
    where a number was): each was a field of the right name holding a value of the wrong type.
    Byte mutations of a JSON document rarely change a value's type and keep it parseable, so
    the targets also replace one field with a value built this way, where `5`, `[]`, `{}`,
    `null` or `NaN` is a two-byte input.
    """
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        return raw.decode("utf-8", "surrogateescape")


def with_field(obj, fields, data):
    """A copy of obj with one field replaced: data[0] picks it from `fields`, the rest is typed().

    Each entry of `fields` is a path of keys; the last key is set even where it was absent.
    """
    path = fields[data[0] % len(fields)]
    out = copy.deepcopy(obj)
    node = out
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = typed(data[1:])
    return out


def seed(argv, seeds):
    """Write the seeds into the first corpus directory named on the command line, if empty.

    libFuzzer reads every positional argument as a corpus directory, or as one input to run
    once when it is a file. A fresh directory gets the genuine artifacts, so the search starts
    from inputs the verifier accepts rather than from nothing.
    """
    dirs = [a for a in argv[1:] if not a.startswith("-")]
    if not dirs or os.path.isfile(dirs[0]):
        return
    os.makedirs(dirs[0], exist_ok=True)
    if os.listdir(dirs[0]):
        return
    for item in seeds:
        raw = item if isinstance(item, bytes) else item.encode("utf-8")
        with open(os.path.join(dirs[0], hashlib.sha1(raw).hexdigest()), "wb") as f:
            f.write(raw)
