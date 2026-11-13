# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""swiyu_fixtures.py -- everything the tests and the dry run make for themselves.

Every key is made here, in the process that uses it: a verifier key and its DID log, an issuer
key and its pin, a holder key, a status list signer, trust statements. None of it is a Swiss
credential, key or DID; the DIDs below name a registry host and resolve nowhere. Nothing here
opens a socket except `Wallet.over_http`, which talks to a loopback address the caller passes.
"""
import datetime
import hashlib
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils  # noqa: E402

import swiyu_verifier as sv  # noqa: E402
from polaris_oid4vp.jwe import _public_key_from_jwk, b64u_decode, b64u_encode, encrypt_compact  # noqa: E402
from polaris_oid4vp.status import encode_status_list  # noqa: E402

REGISTRY = "identifier-reg.trust-infra.swiyu-int.admin.ch"
STATUS_HOST = "status-reg-a.trust-infra.swiyu-int.admin.ch"
VERIFIER_DID = "did:webvh:QmTestVerifierScid00000000000000000000000000000:%s:api:v1:did:00000000-0000-4000-8000-000000000001" % REGISTRY
ISSUER_DID = "did:webvh:QmTestIssuerScid0000000000000000000000000000000:%s:api:v1:did:00000000-0000-4000-8000-000000000002" % REGISTRY
OTHER_DID = "did:webvh:QmTestOtherScid00000000000000000000000000000000:%s:api:v1:did:00000000-0000-4000-8000-000000000003" % REGISTRY
STATUS_URI = "https://%s/api/v1/statuslist/00000000-0000-4000-8000-000000000004.jwt" % STATUS_HOST
PUBLIC_URL = "https://lab-verifier.test"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # loopback only, whatever the environment says


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(key, kid=None):
    n = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64u_encode(n.x.to_bytes(32, "big")),
           "y": b64u_encode(n.y.to_bytes(32, "big"))}
    if kid:
        jwk["kid"] = kid
    return jwk


def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def jws(key, header, payload):
    h = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64u_encode(json.dumps(payload, separators=(",", ":")).encode())
    r, s = asym_utils.decode_dss_signature(key.sign((h + "." + p).encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return h + "." + p + "." + b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def parts(token):
    h, p = token.split(".")[:2]
    return json.loads(b64u_decode(h)), json.loads(b64u_decode(p))


def utc(seconds=None):
    t = time.time() if seconds is None else seconds
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def did_log(did, keys):
    """A one-entry did:webvh-shaped log naming `keys` ({fragment: private key}) by publicKeyJwk."""
    methods = [{"id": "%s#%s" % (did, frag), "type": "JsonWebKey2020", "controller": did,
                "publicKeyJwk": public_jwk(key)} for frag, key in keys.items()]
    entry = {"versionId": "1-test", "versionTime": utc(), "parameters": {"method": "did:webvh:1.0"},
             "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": did, "verificationMethod": methods,
                       "authentication": [m["id"] for m in methods], "assertionMethod": [m["id"] for m in methods]},
             "proof": []}
    return json.dumps(entry, separators=(",", ":")) + "\n"


def pin(did, keys, *, resolved_at=None, log_sha256=None, resolver="didresolver 2.10.1"):
    """A pin file as a dict: the issuer's DID, the sha256 of the log it was read from, the resolver,
    the time, and the keys ({fragment: private key}, only the public halves are written)."""
    return {"did": did, "log_sha256": hashlib.sha256(b"test log").hexdigest() if log_sha256 is None else log_sha256,
            "resolver": resolver, "resolved_at": utc(resolved_at),
            "keys": [public_jwk(key, "%s#%s" % (did, frag)) for frag, key in keys.items()]}


def statement(key, typ, sub, kid="did:example:trust-registry#key-1", **payload):
    body = {"jti": "00000000-0000-4000-8000-0000000000aa", "sub": sub, "iat": int(time.time()),
            "exp": int(time.time()) + 3600}
    body.update(payload)
    return jws(key, {"alg": "ES256", "typ": typ, "kid": kid, "profile_version": "swiss-profile-trust:1.0.0"}, body)


def identity_statement(key, sub):
    return statement(key, sv.TYP_IDENTITY, sub, entity_name="Test verifier", is_state_actor=False)


def query_statement(key, sub, scope, query=None):
    return statement(key, sv.TYP_QUERY, sub, purpose_name="test", purpose_description="test",
                     request={"type": "DCQL", "scope": scope, "query": sv.lab_query() if query is None else query})


def as_info(*statements, **extra):
    return [dict({"format": "jwt", "data": s}, **extra) for s in statements]


def status_token(key, kid, uri, statuses, *, typ="statuslist+jwt", iat=None):
    bits = 2 if max(statuses) > 1 else 1
    return jws(key, {"alg": "ES256", "typ": typ, "kid": kid},
               {"sub": uri, "iat": int(time.time()) if iat is None else iat, "exp": int(time.time()) + 3600,
                "ttl": 3600, "status_list": {"bits": bits, "lst": encode_status_list(statuses, bits)}})


class Wallet:
    """A holder with a Beta-ID shaped credential: `age_over_18` selectively disclosed, a status
    claim, `typ` dc+sd-jwt, signed with the issuer key under a `kid` that is a DID URL."""

    def __init__(self, issuer_key=None, issuer_did=ISSUER_DID, kid_fragment="assert-key-01"):
        self.issuer_key = issuer_key or new_key()
        self.holder_key = new_key()
        self.issuer_did = issuer_did
        self.kid = "%s#%s" % (issuer_did, kid_fragment)

    def credential(self, *, kid="default", iss="default", typ="dc+sd-jwt", vct=sv.VCT_VALUES[0], status_idx=7,
                   status_uri=STATUS_URI, signer=None, age=True, claims=None):
        disclosure = b64u_encode(json.dumps(["salt0", "age_over_18", age], separators=(",", ":")).encode())
        payload = {"iss": self.issuer_did if iss == "default" else iss, "vct": vct, "iat": int(time.time()),
                   "_sd": [b64u_encode(hashlib.sha256(disclosure.encode("ascii")).digest())],
                   "cnf": {"jwk": public_jwk(self.holder_key)}}
        if status_idx is not None:
            payload["status"] = {"status_list": {"idx": status_idx, "uri": status_uri}}
        payload.update(claims or {})
        header = {"alg": "ES256", "typ": typ}
        if kid is not None:
            header["kid"] = self.kid if kid == "default" else kid
        return jws(signer or self.issuer_key, header, payload), disclosure

    def presentation(self, nonce, audience, **credential):
        issuer_jwt, disclosure = self.credential(**credential)
        presented = issuer_jwt + "~" + disclosure + "~"
        kb = jws(self.holder_key, {"alg": "ES256", "typ": "kb+jwt"},
                 {"iat": int(time.time()), "aud": audience, "nonce": nonce,
                  "sd_hash": b64u_encode(hashlib.sha256(presented.encode("ascii")).digest())})
        return presented + kb

    def respond(self, jar, *, enc="A256GCM", audience=None, nonce=None, vp_token=None, **credential):
        """The posted form for the request object `jar`, read as a wallet reads it."""
        _, claims = parts(jar)
        jwk = claims["client_metadata"]["jwks"]["keys"][0]
        presentation = self.presentation(claims["nonce"] if nonce is None else nonce,
                                         claims["client_id"] if audience is None else audience, **credential)
        query_id = sv.QUERY_ID
        body = {"state": claims["state"], "vp_token": {query_id: [presentation]} if vp_token is None else vp_token}
        return {"response": [encrypt_compact(json.dumps(body).encode(), _public_key_from_jwk(jwk), enc)]}

    def over_http(self, link_url, did_log_text, *, post=True):
        """The dry run's wallet: GET the request object, check its header, kid and client_id against the
        verifier's DID log, then POST the encrypted response. `link_url` is the request_uri; returns
        (the checks it made, the status and body of the POST)."""
        with OPENER.open(link_url, timeout=10) as answer:
            jar = answer.read().decode("ascii")
        header, claims = parts(jar)
        entry = json.loads(did_log_text.strip().splitlines()[-1])
        did = entry["state"]["id"]
        methods = {m["id"]: m["publicKeyJwk"] for m in entry["state"]["verificationMethod"]}
        checks = {"header": sorted(header) == ["alg", "kid", "profile_version", "typ"]
                  and header["typ"] == "oauth-authz-req+jwt" and header["alg"] == "ES256",
                  "kid": header["kid"] in methods and header["kid"].partition("#")[0] == did,
                  "client_id": claims["client_id"] == "decentralized_identifier:" + did and claims["iss"] == claims["client_id"]}
        signing_input, _, sig = jar.rpartition(".")
        raw = b64u_decode(sig)
        _public_key_from_jwk(methods[header["kid"]]).verify(
            asym_utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
            signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        checks["signature"] = True
        if not all(checks.values()):
            return checks, None
        form = self.respond(jar)["response"][0]
        base = claims["response_uri"]
        request = urllib.request.Request(base, data=("response=" + form).encode("ascii"), method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with OPENER.open(request, timeout=10) as answer:
                return checks, (answer.status, json.loads(answer.read()))
        except urllib.error.HTTPError as error:
            return checks, (error.code, json.loads(error.read()))


class World:
    """One verifier, its keys, its DID log, an issuer pin, a wallet, and a status list: all test made."""

    def __init__(self, verifier_class=None, status_list=None, **overrides):
        self.verifier_key, self.issuer_key, self.status_key = new_key(), new_key(), new_key()
        self.trust_key = new_key()
        self.verifier_did = VERIFIER_DID
        self.kid = VERIFIER_DID + "#assert-key-01"
        self.log = did_log(VERIFIER_DID, {"assert-key-01": self.verifier_key})
        self.wallet = Wallet(self.issuer_key)
        self.pin = pin(ISSUER_DID, {"assert-key-01": self.issuer_key})
        self.fetched = []
        self.status_list = [0] * 16 if status_list is None else status_list
        self.tokens = {}
        self.options = dict(did=self.verifier_did, kid=self.kid, key_pem=key_pem(self.verifier_key), did_log=self.log,
                            issuer_pin=self.pin, registry_host=REGISTRY, public_url=PUBLIC_URL,
                            status_host=STATUS_HOST, fetch=self._fetch)
        self.options.update(overrides)
        self.verifier = (verifier_class or sv.SwiyuVerifier)(**self.options)
        self.front = sv.Front(self.verifier)

    def _fetch(self, uri):
        self.fetched.append(uri)
        return self.tokens.get(uri) or status_token(self.issuer_key, self.wallet.kid, uri, self.status_list)

    def exchange(self, **credential):
        """A full round: request, response, through the front. Returns (status, body, verdict)."""
        _, jar = self.verifier.new_request()
        return self.front.handle_direct_post(self.wallet.respond(jar, **credential))

    def last(self):
        return self.verifier.records[-1]


def parent_outcome_key(result):
    status, body, verdict = result
    return status, bool(verdict.authentic), verdict.code


def write_keyfolder(folder, world, with_pin=True):
    """What did.sh and the pin step leave in the owner's folder, for the run.sh test."""
    folder = pathlib.Path(folder)
    (folder / ".didtoolbox").mkdir(parents=True, exist_ok=True)
    (folder / "did.jsonl").write_text(world.log)
    (folder / "did").write_text(world.verifier_did + "\n")
    key_file = folder / ".didtoolbox" / "assert-key-01"
    key_file.write_bytes(key_pem(world.verifier_key))
    os.chmod(key_file, 0o600)
    if with_pin:
        (folder / "issuer-pin.json").write_text(json.dumps(world.pin))
    return folder
