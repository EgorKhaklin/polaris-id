"""polaris_web/kms_standin.py — a local AWS KMS stand-in for tests.

Speaks the real TrentService JSON 1.1 wire protocol boto3 uses, so a driver's
request marshalling, base64 blobs, SPKI parsing, and error handling are
exercised for real; the only thing faked is the remote service, which cannot
be real in CI. Cryptography is real: ML-DSA-65 via OpenSSL (cryptography) for
Sign/GetPublicKey (P1.2 custody), AES-256-GCM for GenerateDataKey/Encrypt/
Decrypt (P1.3 secret store). Not shipped in any image; test infrastructure.
"""
# coverage:exempt - the stand-in itself; test_custody exercises it through the custody interface, which is the only way it is ever reached in production shape.

from __future__ import annotations

import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KmsStandIn:
    def __init__(self, key_spec="ML_DSA_65", key_usage="SIGN_VERIFY", state="Enabled", key_id=None):
        self.key_id = key_id or "1234abcd-12ab-34cd-56ef-1234567890ab"
        self.arn = f"arn:aws:kms:us-east-1:000000000000:key/{self.key_id}"
        self.key_spec, self.key_usage, self.state = key_spec, key_usage, state
        self.calls = []
        # asymmetric material (ML-DSA-65) for the custody driver
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa
            from cryptography.hazmat.primitives import serialization
            self.priv = mldsa.MLDSA65PrivateKey.generate()
            self.pub_raw = self.priv.public_key().public_bytes_raw()
            self.spki = self.priv.public_key().public_bytes(serialization.Encoding.DER,
                                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        except Exception:  # no ML-DSA in this cryptography build
            self.priv = self.pub_raw = self.spki = None
        # symmetric master (envelope) for the secret store; one per "key id"
        self.masters = {self.key_id: AESGCM.generate_key(bit_length=256)}
        standin = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                target = self.headers.get("X-Amz-Target", "")
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                standin.calls.append((target, body))
                op = target.split(".")[-1]
                try:
                    out = standin.dispatch(op, body)
                except KeyError as exc:
                    return self._send(400, {"__type": "NotFoundException", "message": f"Key not found: {exc}"})
                except ValueError as exc:
                    return self._send(400, {"__type": "InvalidCiphertextException", "message": str(exc)})
                except PermissionError as exc:
                    return self._send(400, {"__type": "InvalidParameterException", "message": str(exc)})
                self._send(200, out)

            def _send(self, code, obj):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/x-amz-json-1.1")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    # ---- operations -------------------------------------------------------
    def _resolve(self, key_id):
        for kid in self.masters:
            if key_id in (kid, f"arn:aws:kms:us-east-1:000000000000:key/{kid}"):
                return kid
        raise KeyError(key_id)

    def add_symmetric_key(self, key_id):
        self.masters[key_id] = AESGCM.generate_key(bit_length=256)

    def dispatch(self, op, body):
        if op == "DescribeKey":
            kid = self._resolve(body["KeyId"])
            spec = self.key_spec if kid == self.key_id else "SYMMETRIC_DEFAULT"
            return {"KeyMetadata": {"KeyId": kid, "Arn": f"arn:aws:kms:us-east-1:000000000000:key/{kid}",
                                    "KeySpec": spec, "KeyUsage": self.key_usage if kid == self.key_id else "ENCRYPT_DECRYPT",
                                    "KeyState": self.state, "SigningAlgorithms": ["ML_DSA_SHAKE_256"]}}
        if op == "GetPublicKey":
            self._resolve(body["KeyId"])
            return {"KeyId": self.arn, "KeySpec": self.key_spec, "KeyUsage": self.key_usage,
                    "PublicKey": base64.b64encode(self.spki).decode(), "SigningAlgorithms": ["ML_DSA_SHAKE_256"]}
        if op == "Sign":
            self._resolve(body["KeyId"])
            if body.get("SigningAlgorithm") != "ML_DSA_SHAKE_256" or body.get("MessageType") != "RAW":
                raise PermissionError("algorithm/message type")
            sig = self.priv.sign(base64.b64decode(body["Message"]))
            return {"KeyId": self.arn, "Signature": base64.b64encode(sig).decode(), "SigningAlgorithm": "ML_DSA_SHAKE_256"}
        if op == "GenerateDataKey":
            kid = self._resolve(body["KeyId"])
            if body.get("KeySpec") != "AES_256":
                raise PermissionError("KeySpec must be AES_256")
            dk = os.urandom(32)
            return {"KeyId": f"arn:aws:kms:us-east-1:000000000000:key/{kid}",
                    "Plaintext": base64.b64encode(dk).decode(),
                    "CiphertextBlob": base64.b64encode(self._wrap(kid, dk)).decode()}
        if op == "Encrypt":
            kid = self._resolve(body["KeyId"])
            pt = base64.b64decode(body["Plaintext"])
            return {"KeyId": f"arn:aws:kms:us-east-1:000000000000:key/{kid}",
                    "CiphertextBlob": base64.b64encode(self._wrap(kid, pt)).decode()}
        if op == "Decrypt":
            blob = base64.b64decode(body["CiphertextBlob"])
            kid, pt = self._unwrap(blob)
            if body.get("KeyId") and self._resolve(body["KeyId"]) != kid:
                raise ValueError("IncorrectKeyException: the ciphertext was encrypted under a different key")
            return {"KeyId": f"arn:aws:kms:us-east-1:000000000000:key/{kid}",
                    "Plaintext": base64.b64encode(pt).decode()}
        raise PermissionError(f"unknown operation {op}")

    def _wrap(self, kid, data):
        nonce = os.urandom(12)
        return kid.encode() + b"|" + nonce + AESGCM(self.masters[kid]).encrypt(nonce, data, kid.encode())

    def _unwrap(self, blob):
        try:
            kid_b, rest = blob.split(b"|", 1)
            kid = kid_b.decode()
            nonce, ct = rest[:12], rest[12:]
            return kid, AESGCM(self.masters[kid]).decrypt(nonce, ct, kid.encode())
        except Exception as exc:
            raise ValueError("ciphertext is invalid or was wrapped under another key") from exc

    def close(self):
        self.server.shutdown()
        self.server.server_close()
