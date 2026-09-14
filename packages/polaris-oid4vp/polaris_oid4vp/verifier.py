"""verifier.py -- the listening half: ask for a presentation, and answer 200 or 4xx.

`sdjwt.py` decides and `jwe.py` opens. This is what puts them on a wire. It builds the
OpenID4VP 1.0 authorization request the High Assurance Interoperability Profile requires,
serves it at a `request_uri`, receives the wallet's `direct_post.jwt` POST, and answers.

**The answer IS the result.** Seven of the eleven modules in
`oid4vp-1final-verifier-haip-test-plan` are negative: the wallet sends a presentation broken
in one specific way, and the module passes automatically if the verifier responds 4xx. So
every refusal `sdjwt` or `jwe` can produce has to become a 4xx here, and a verifier that
swallows a bad presentation and returns 200 is not merely wrong, it fails seven tests at once
in a way that looks like nothing happening.

WHAT THE PROFILE PINS, none of it optional, all of it measured against the running suite
rather than read off the specification (see `lab/interop/`):

    client_id_prefix    x509_hash, so the client_id is the SHA-256 of the leaf certificate
    request_method      request_uri_signed, so the request object is a signed JAR with an
                        x5c header, fetched over HTTPS, and the trust anchor is registered
                        out of band and MUST NOT be in the chain
    response_mode       direct_post.jwt, so the response comes back encrypted
    client_metadata     exactly three keys: jwks, vp_formats_supported, and
                        encrypted_response_enc_values_supported carrying BOTH A128GCM and
                        A256GCM. A fourth key is a warning; the older
                        authorization_encrypted_response_* names are a failure
    the direct_post
    response body       HTTP 200, application/json, and ONLY a redirect_uri (HAIP 5.1)

A FRESH ENCRYPTION KEY PER REQUEST. The suite checks that the key in `client_metadata.jwks`
is not reused between tests, and it is right to: one long-lived response-encryption key makes
every presentation ever sent to this verifier readable by anybody who later obtains it.
"""
import base64
import json
import secrets
import threading
import time

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    from cryptography.x509 import load_pem_x509_certificate
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

from .jwe import JweError, b64u_encode, decrypt_response
from .sdjwt import verify_presentation

#: How long an outstanding request stays answerable. A nonce that is accepted forever is not
#: a nonce; this is the other half of the key binding JWT's own freshness check, on our side,
#: where we control it.
DEFAULT_REQUEST_TTL_SECONDS = 300

#: The audience of a request object, fixed by OpenID4VP 1.0 for a wallet that is not a
#: specific named entity.
WALLET_AUDIENCE = "https://self-issued.me/v2"


class Session:
    """One outstanding presentation request, and the secrets that make it answerable once."""

    __slots__ = ("state", "nonce", "enc_key", "created", "answered")

    def __init__(self, enc_key):
        self.state = secrets.token_urlsafe(16)
        # 256 bits. OpenID4VP 1.0 section 5.2 requires "sufficient entropy" and the suite
        # warns below 128 bits, which is a floor rather than a target.
        self.nonce = secrets.token_urlsafe(32)
        self.enc_key = enc_key
        self.created = time.time()
        self.answered = False


class Verifier:
    """Builds requests and judges responses. Holds no socket: see `serve()` for that.

    Split this way so the decision path can be tested without a network, which is also how
    the seven refusals get regression tests that do not need the conformance suite running.
    """

    def __init__(self, *, client_cert_pem, client_key_pem, request_uri, response_uri,
                 issuer_jwks=None, issuer_trust_anchors=None, redirect_uri=None,
                 request_ttl_seconds=DEFAULT_REQUEST_TTL_SECONDS,
                 vct_values=("urn:eudi:pid:1",), claims=("given_name", "family_name")):
        if not _HAVE_CRYPTO:
            raise RuntimeError("polaris-oid4vp requires the cryptography package")
        self.cert = load_pem_x509_certificate(client_cert_pem)
        self.key = serialization.load_pem_private_key(client_key_pem, password=None)
        der = self.cert.public_bytes(serialization.Encoding.DER)
        # x509_hash: the client identifier IS the leaf's digest, so the wallet can tie the
        # request object's signing certificate to the identifier without a directory.
        self.client_id = "x509_hash:" + b64u_encode(_sha256(der))
        self.x5c = [base64.b64encode(der).decode("ascii")]
        self.request_uri = request_uri
        self.response_uri = response_uri
        self.redirect_uri = redirect_uri or (response_uri.rsplit("/", 1)[0] + "/done")
        self.issuer_jwks = list(issuer_jwks or [])
        self.issuer_trust_anchors = list(issuer_trust_anchors or [])
        self.request_ttl_seconds = request_ttl_seconds
        self.vct_values = list(vct_values)
        self.claims = list(claims)
        self._sessions = {}
        self._by_request = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ the request

    def new_request(self):
        """Start one presentation request. Returns (session, the signed request object)."""
        enc_key = ec.generate_private_key(ec.SECP256R1())
        session = Session(enc_key)
        jar = self._request_object(session)
        with self._lock:
            self._expire_locked()
            self._sessions[session.state] = session
            self._by_request[session.state] = jar
        return session, jar

    def request_object(self, state):
        """The JAR for an outstanding request, served as many times as it is asked for.

        The plan has a module that fetches the `request_uri` TWICE. Making a request object
        single-use would look like prudence and would fail it, and would fail nothing real:
        the object is signed, public, and carries its own expiry.
        """
        with self._lock:
            return self._by_request.get(state)

    def _request_object(self, session):
        numbers = session.enc_key.public_key().public_numbers()
        enc_jwk = {"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES",
                   "kid": "enc-" + session.state,
                   "x": b64u_encode(numbers.x.to_bytes(32, "big")),
                   "y": b64u_encode(numbers.y.to_bytes(32, "big"))}
        now = int(time.time())
        claims = {
            "iss": self.client_id,
            "aud": WALLET_AUDIENCE,
            "client_id": self.client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post.jwt",
            "response_uri": self.response_uri,
            "nonce": session.nonce,
            "state": session.state,
            "iat": now,
            "exp": now + self.request_ttl_seconds,
            # Exactly three keys. The suite warns on a fourth and fails on the older
            # authorization_encrypted_response_alg/_enc names, which an earlier draft used.
            "client_metadata": {
                "jwks": {"keys": [enc_jwk]},
                "vp_formats_supported": {"dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"],
                                                       "kb-jwt_alg_values": ["ES256"]}},
                "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"],
            },
            "dcql_query": {"credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": self.vct_values},
                "claims": [{"path": [c]} for c in self.claims],
            }]},
        }
        header = {"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": self.x5c}
        return _sign_es256(self.key, header, claims)

    def authorization_request_params(self, session):
        """What goes in the query string the wallet is launched with."""
        return {"client_id": self.client_id,
                "request_uri": "%s?state=%s" % (self.request_uri, session.state),
                "request_uri_method": "post"}

    # ----------------------------------------------------------------- the response

    def handle_direct_post(self, form):
        """Judge one `direct_post.jwt` response. Returns (http_status, body_dict).

        200 with only a `redirect_uri` when the presentation is authentic, 400 with an OAuth
        error otherwise. Nothing returns 500: every way this can go wrong is the response
        being unacceptable, and a 5xx would tell the wallet to retry something that will
        never work.
        """
        token = (form.get("response") or [""])[0] if isinstance(form.get("response"), list) \
            else form.get("response") or ""
        if not token:
            return self._error("invalid_request", "no 'response' parameter was posted")

        session, body = None, None
        # The response is encrypted to a PER-REQUEST key, so finding the session means
        # finding the key that opens it. Trying each outstanding one is deliberate: the
        # `state` that would let us look it up directly is INSIDE the ciphertext, and
        # trusting an unauthenticated state parameter to pick a decryption key is how a
        # verifier gets steered onto the wrong session.
        with self._lock:
            self._expire_locked()
            candidates = list(self._sessions.values())
        for candidate in candidates:
            try:
                body = decrypt_response(token, candidate.enc_key)
            except JweError:
                continue
            session = candidate
            break
        if session is None:
            return self._error("invalid_request",
                               "the response did not decrypt under any outstanding "
                               "request's key: it was encrypted to somebody else, altered, "
                               "or it answers a request that has expired")

        if body.get("state") != session.state:
            return self._error("invalid_request",
                               "the response's state does not match the request its "
                               "encryption key belongs to")
        with self._lock:
            if session.answered:
                return self._error("invalid_request",
                                   "this request has already been answered; a second "
                                   "presentation for the same nonce is a replay")
            session.answered = True
            self._sessions.pop(session.state, None)
            self._by_request.pop(session.state, None)

        presentation = self._single_presentation(body.get("vp_token"))
        if presentation is None:
            return self._error("invalid_request",
                               "the vp_token is not one presentation for the one credential "
                               "the DCQL query asked for")

        verdict = verify_presentation(presentation,
                                      expected_nonce=session.nonce,
                                      expected_audience=self.client_id,
                                      issuer_jwks=self.issuer_jwks,
                                      trust_anchors=self.issuer_trust_anchors)
        if not verdict.authentic:
            # The refusal code travels into the error, because a verifier that answers every
            # bad presentation with the same opaque 400 is impossible to debug from the
            # wallet's side, and these reasons name the presentation, never a secret.
            return self._error("invalid_request", "%s: %s" % (verdict.code, verdict.reason))

        # HAIP 5.1: 200, application/json, and ONLY a redirect_uri. The suite checks that
        # last part, so anything helpful added here fails the test.
        return 200, {"redirect_uri": self.redirect_uri}, verdict

    def _single_presentation(self, vp_token):
        if not isinstance(vp_token, dict) or len(vp_token) != 1:
            return None
        value = next(iter(vp_token.values()))
        if isinstance(value, list):
            if len(value) != 1:
                return None
            value = value[0]
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _error(code, description):
        return 400, {"error": code, "error_description": description}, None

    def _expire_locked(self):
        cutoff = time.time() - self.request_ttl_seconds
        for state in [s for s, sess in self._sessions.items() if sess.created < cutoff]:
            self._sessions.pop(state, None)
            self._by_request.pop(state, None)


def _sha256(raw):
    import hashlib
    return hashlib.sha256(raw).digest()


def _sign_es256(key, header, claims):
    header_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    claims_b64 = b64u_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = (header_b64 + "." + claims_b64).encode("ascii")
    r, s = asym_utils.decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return header_b64 + "." + claims_b64 + "." + b64u_encode(
        r.to_bytes(32, "big") + s.to_bytes(32, "big"))
