#!/usr/bin/env python3
"""A minimal OpenID4VCI 1.0 issuer, pre-authorized code only, for 005 section 9 step 2.

LAB CODE. It exists to answer one question: will two wallets Polaris did not write (walt.id
Wallet API v2, Credo) take a credential from a specification-conformant pre-authorized-code
issuer through their public APIs, and what does each send or demand beyond the base
specification? It is not HAIP (no authorization code, PAR, DPoP or client attestation; see
../WALL.md) and it is not Polaris issuance: step 3 puts the Polaris issuance rules behind it.

Endpoints (OpenID4VCI 1.0 Final):
  GET  /.well-known/openid-credential-issuer    issuer metadata
  GET  /.well-known/oauth-authorization-server  authorization server metadata (RFC 8414)
  GET  /.well-known/jwt-vc-issuer               SD-JWT VC issuer metadata (the issuer JWKS)
  POST /token       grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
  POST /nonce       a fresh c_nonce
  POST /credential  {"credential_configuration_id", "proofs": {"jwt": [...]}} with a Bearer token

Every request is appended to --log as JSON, headers and body, so what a wallet actually sent
is on disk rather than inferred.

    python3 issuer.py --host localhost --port 9643 --tls-dir DIR --log wire.jsonl
Prints the credential offer URI (one pre-authorized code) and serves until killed.
"""
import argparse
import base64
import hashlib
import http.server
import json
import pathlib
import secrets
import ssl
import sys
import threading
import time
import urllib.parse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "interop" / "waltid"))
from issue_sdjwt_vc import b64u, jws, public_jwk  # noqa: E402

PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
CONFIG_ID = "pid_sd_jwt"
VCT = "urn:eudi:pid:1"
PROOF_TYP = "openid4vci-proof+jwt"
PROOF_MAX_AGE = 300


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_proof(proof, audience, nonces):
    """Refuse anything but an ES256 proof of possession of the key in its own header, aimed at
    this issuer, carrying a c_nonce this issuer handed out and has not seen used."""
    try:
        h64, p64, s64 = proof.split(".")
        header, payload, sig = json.loads(b64d(h64)), json.loads(b64d(p64)), b64d(s64)
    except (ValueError, json.JSONDecodeError) as exc:
        return None, "proof is not a compact JWS: %s" % exc
    if header.get("typ") != PROOF_TYP:
        return None, "proof typ is %r, not %s" % (header.get("typ"), PROOF_TYP)
    if header.get("alg") != "ES256":
        return None, "proof alg is %r, not ES256" % header.get("alg")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
        return None, "proof header carries no public P-256 jwk (kid and x5c binding are not offered)"
    try:
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(b64d(jwk["x"]), "big"),
                                            int.from_bytes(b64d(jwk["y"]), "big"),
                                            ec.SECP256R1()).public_key()
        if len(sig) != 64:
            return None, "proof signature is not 64 bytes of r||s"
        der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        pub.verify(der, (h64 + "." + p64).encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except Exception as exc:  # noqa: BLE001  any failure here is a refusal
        return None, "proof signature does not verify: %s" % type(exc).__name__
    if payload.get("aud") != audience:
        return None, "proof aud %r is not this issuer" % payload.get("aud")
    iat = payload.get("iat")
    if not isinstance(iat, (int, float)) or abs(time.time() - iat) > PROOF_MAX_AGE:
        return None, "proof iat is missing or more than %ds from now" % PROOF_MAX_AGE
    nonce = payload.get("nonce")
    if nonce not in nonces:
        return None, "proof nonce was not issued here, or was already used"
    nonces.discard(nonce)
    return {k: jwk[k] for k in ("kty", "crv", "x", "y")}, None


def issuer_pki(base_url):
    """A private CA and an issuer leaf under it. HAIP (and Credo 0.6.3, which resolves an
    SD-JWT VC issuer key only from a DID or `x5c`) wants the credential's `x5c` to carry a
    signing certificate that is not self-signed, with the trust anchor left out. The wallet
    registers the CA; the leaf names the issuer URL and host."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Polaris lab VCI CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    host = urllib.parse.urlsplit(base_url).hostname
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Polaris lab VCI issuer")]))
            .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(base_url),
                                                        x509.DNSName(host)]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    from cryptography.hazmat.primitives import serialization
    return leaf_key, [base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode()], \
        ca.public_bytes(serialization.Encoding.PEM).decode()


class Issuer:
    """`record`, when given, is the Polaris record this issuer answers to (step 3): a callable
    token_value -> (token_id, status) or None, and `record.all()` -> [(token_id, status)]. An
    offer then names one Polaris credential, the wallet copy is issued only while that
    credential is ACTIVE at REDEMPTION time, and the copy carries a Token Status List entry at
    idx = token_id whose bit is read from the record on every fetch of /status."""

    def __init__(self, base_url, record=None):
        self.base = base_url
        self.record = record
        self.key, self.x5c, self.ca_pem = issuer_pki(base_url)
        self.kid = "polaris-lab-vci-1"
        self.jwk = public_jwk(self.key, kid=self.kid)
        self.codes = {}          # pre-authorized code -> offer state
        self.tokens = {}         # access token -> expiry
        self.nonces = set()
        self.issued = []         # what was issued, for the record
        self.lock = threading.Lock()

    def new_offer(self, token_value=None):
        if self.record is not None and token_value is None:
            raise ValueError("with a Polaris record, an offer names the credential it copies")
        code = secrets.token_urlsafe(24)
        with self.lock:
            self.codes[code] = {"used": False, "token_value": token_value}
        offer = {"credential_issuer": self.base, "credential_configuration_ids": [CONFIG_ID],
                 "grants": {PRE_AUTH: {"pre-authorized_code": code}}}
        return "openid-credential-offer://?credential_offer=" + urllib.parse.quote(json.dumps(offer, separators=(",", ":"))), offer

    def issuer_metadata(self):
        return {"credential_issuer": self.base,
                "credential_endpoint": self.base + "/credential",
                "nonce_endpoint": self.base + "/nonce",
                "credential_configurations_supported": {CONFIG_ID: {
                    "format": "dc+sd-jwt", "vct": VCT, "scope": CONFIG_ID,
                    "cryptographic_binding_methods_supported": ["jwk"],
                    "credential_signing_alg_values_supported": ["ES256"],
                    "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
                    "credential_metadata": {
                        "display": [{"name": "Polaris lab PID", "locale": "en"}],
                        "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}]}}},
                "display": [{"name": "Polaris lab issuer", "locale": "en"}]}

    def as_metadata(self):
        return {"issuer": self.base, "token_endpoint": self.base + "/token",
                "grant_types_supported": [PRE_AUTH],
                "pre-authorized_grant_anonymous_access_supported": True,
                "response_types_supported": ["token"]}

    def status_list_token(self):
        """A Token Status List token over the whole record: bit 1 for every credential that is
        not ACTIVE, read now. Signed by the credential key, with the same x5c, so the verifier
        can take the same-key basis rather than a delegation."""
        import sys as _sys
        _sys.path.insert(0, str(HERE.parents[2].parent / "packages" / "polaris-oid4vp"))
        from polaris_oid4vp.status import encode_status_list
        rows = self.record.all()
        size = max((tid for tid, _ in rows), default=0) + 1
        bits = [0] * size
        for tid, st in rows:
            bits[tid] = 0 if st == "ACTIVE" else 1
        now = int(time.time())
        return jws(self.key, {"alg": "ES256", "typ": "statuslist+jwt", "x5c": self.x5c},
                   {"sub": self.base + "/status", "iat": now, "exp": now + 600, "ttl": 60,
                    "status_list": {"bits": 1, "lst": encode_status_list(bits)}})

    def vc_issuer_metadata(self):
        return {"issuer": self.base, "jwks": {"keys": [self.jwk]}}

    def token(self, form):
        if form.get("grant_type") != PRE_AUTH:
            return 400, {"error": "unsupported_grant_type"}
        code = form.get("pre-authorized_code")
        with self.lock:
            state = self.codes.get(code)
            if state is None or state["used"]:
                return 400, {"error": "invalid_grant"}
            if form.get("tx_code"):
                return 400, {"error": "invalid_request", "error_description": "no tx_code was offered"}
            state["used"] = True
            tok = secrets.token_urlsafe(32)
            self.tokens[tok] = (time.time() + 300, state["token_value"])
        return 200, {"access_token": tok, "token_type": "Bearer", "expires_in": 300}

    def nonce(self):
        n = secrets.token_urlsafe(24)
        with self.lock:
            self.nonces.add(n)
        return 200, {"c_nonce": n}

    def credential(self, auth, body):
        tok = auth[7:] if auth.startswith("Bearer ") else None
        with self.lock:
            entry = self.tokens.get(tok)
        if entry is None or entry[0] < time.time():
            return 401, {"error": "invalid_token"}
        token_value = entry[1]
        status_claim = None
        if self.record is not None:
            # The record decides, at redemption and not at offer: an offer made while the
            # credential was ACTIVE is worthless once it is not.
            found = self.record(token_value)
            if found is None or found[1] != "ACTIVE":
                return 400, {"error": "credential_request_denied",
                             "error_description": "the Polaris record does not hold this credential ACTIVE (%s)"
                                                  % ("absent" if found is None else found[1])}
            status_claim = {"status_list": {"idx": found[0], "uri": self.base + "/status"}}
        cid = body.get("credential_configuration_id")
        if cid != CONFIG_ID:
            return 400, {"error": "unknown_credential_configuration"}
        proofs = body.get("proofs")
        if not (isinstance(proofs, dict) and isinstance(proofs.get("jwt"), list) and len(proofs["jwt"]) == 1):
            return 400, {"error": "invalid_proof", "error_description": "expected proofs.jwt with one proof"}
        with self.lock:
            holder, why = verify_proof(proofs["jwt"][0], self.base, self.nonces)
        if holder is None:
            return 400, {"error": "invalid_proof", "error_description": why}
        with self.lock:
            self.tokens.pop(tok, None)     # one credential per token: the offer was for one
        disclosures = [b64u(json.dumps([secrets.token_urlsafe(12), n, v], separators=(",", ":")).encode())
                       for n, v in (("given_name", "Jean"), ("family_name", "Dupont"))]
        payload = {"iss": self.base, "vct": VCT, "iat": int(time.time()),
                   "exp": int(time.time()) + 86400 * 30,
                   "_sd": sorted(b64u(hashlib.sha256(d.encode("ascii")).digest()) for d in disclosures),
                   "_sd_alg": "sha-256", "cnf": {"jwk": holder}}
        if status_claim is not None:
            payload["status"] = status_claim
        credential = jws(self.key, {"alg": "ES256", "typ": "dc+sd-jwt", "x5c": self.x5c}, payload) + \
            "~" + "~".join(disclosures) + "~"
        with self.lock:
            self.issued.append({"cnf": holder, "iat": payload["iat"]})
        return 200, {"credentials": [{"credential": credential}]}


def make_handler(issuer, log_path):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _record(self, body_raw, status, answer):
            entry = {"t": time.time(), "method": self.command, "path": self.path,
                     "headers": dict(self.headers.items()),
                     "body": body_raw.decode("utf-8", "replace") if body_raw else None,
                     "status": status, "answer": answer}
            with open(log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
            print("%s %s -> %d" % (self.command, self.path, status), flush=True)

        def _send(self, status, obj, body_raw=b""):
            self._record(body_raw, status, obj)
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path.startswith("/.well-known/openid-credential-issuer"):
                return self._send(200, issuer.issuer_metadata())
            if path.startswith("/.well-known/oauth-authorization-server"):
                return self._send(200, issuer.as_metadata())
            if path.startswith("/.well-known/jwt-vc-issuer"):
                return self._send(200, issuer.vc_issuer_metadata())
            if path == "/status" and issuer.record is not None:
                token = issuer.status_list_token().encode()
                self._record(b"", 200, "<status list token>")
                self.send_response(200)
                self.send_header("Content-Type", "application/statuslist+jwt")
                self.send_header("Content-Length", str(len(token)))
                self.end_headers()
                self.wfile.write(token)
                return
            return self._send(404, {"error": "not_found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            path = urllib.parse.urlsplit(self.path).path
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            if path == "/token":
                form = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode()).items()}
                status, obj = issuer.token(form)
                return self._send(status, obj, raw)
            if path == "/nonce":
                status, obj = issuer.nonce()
                return self._send(status, obj, raw)
            if path == "/credential":
                if ctype != "application/json":
                    return self._send(400, {"error": "invalid_request", "error_description": "expected JSON"}, raw)
                try:
                    body = json.loads(raw or b"{}")
                except json.JSONDecodeError:
                    return self._send(400, {"error": "invalid_request"}, raw)
                status, obj = issuer.credential(self.headers.get("Authorization") or "", body)
                return self._send(status, obj, raw)
            return self._send(404, {"error": "not_found"}, raw)
    return H


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="localhost", help="the name wallets use to reach this issuer")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9643)
    ap.add_argument("--tls-dir", required=True, help="holds tls.pem and tls-key.pem")
    ap.add_argument("--log", required=True)
    ap.add_argument("--offer-out", help="write the offer URI here too")
    ap.add_argument("--ca-out", help="write the issuer CA certificate (PEM) here, for the wallet to register")
    a = ap.parse_args()
    base = "https://%s:%d" % (a.host, a.port)
    issuer = Issuer(base)
    uri, offer = issuer.new_offer()
    print("issuer       %s" % base, flush=True)
    print("offer        %s" % uri, flush=True)
    if a.offer_out:
        pathlib.Path(a.offer_out).write_text(uri)
    if a.ca_out:
        pathlib.Path(a.ca_out).write_text(issuer.ca_pem)
    httpd = http.server.ThreadingHTTPServer((a.bind, a.port), make_handler(issuer, a.log))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pathlib.Path(a.tls_dir) / "tls.pem", pathlib.Path(a.tls_dir) / "tls-key.pem")
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
