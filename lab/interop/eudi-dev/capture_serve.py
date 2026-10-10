#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""`polaris-oid4vp serve`, unchanged, with the bytes of one accepted exchange written to a directory.

    python capture_serve.py CAPTURE_DIR serve --pki pki ... --once

run.sh starts this in place of `polaris-oid4vp serve` when EUDI_CAPTURE is set. It imports the
INSTALLED polaris_oid4vp and runs its own command line in-process. Two hooks, neither of which
changes what the verifier decides or answers:

  * the HTTP handler class `serve()` builds on is replaced by a subclass that records the bytes
    it writes for a request object and the bytes it reads for a response, and wraps the verdict
    callback the command line passes, so the files are written before the verdict line is printed;
  * `Verifier.new_request` is wrapped to remember each session, so the response can be opened
    afterwards with that request's own ephemeral key, through `polaris_oid4vp.jwe`, as the
    verifier opens it.

Files are written only for a response the verifier answered `200 authentic`. Every file is the
bytes as served, posted or decrypted, sliced and never re-serialised, except request.json, which
is assembled from the request object's payload (each value its exact bytes there) and says so,
and the decryption key, which is a JWK built from the key object.
"""
import base64
import datetime
import hashlib
import importlib
import json
import pathlib
import sys
import threading
import time
import traceback

OUT = None
SESSIONS = {}           # state -> Session, every request this process minted
SERVED = {}             # state -> [Served], every request object this process answered with
_SIGNING = threading.local()


#: Every file a capture writes. run.sh requires each, non-empty, before it calls a run captured.
CAPTURE_FILES = ("request.jwt", "request.json", "response.jwe", "vp-token.json",
                 "presentation.txt", "verifier-decryption-key.test-only.jwk.json",
                 "issuer-ca.pem")


class CaptureError(Exception):
    pass


class Served:
    """One request object as it left the listener, and what the wallet posted for it."""

    def __init__(self, wallet_nonce, wallet_metadata, body, signed):
        self.wallet_nonce, self.wallet_metadata = wallet_nonce, wallet_metadata
        # `body` is what was on the wire. `signed` is the signed request object inside it: the
        # same bytes, unless the wallet asked for the object encrypted to its own key, when
        # `body` is that JWE and `signed` the plaintext polaris_oid4vp encrypted.
        self.body, self.signed = body, signed


def _b64u_json(segment):
    raw = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(raw.encode("ascii")).decode("utf-8")


def raw_members(text):
    """{key: (start, end)} for each member of the top-level JSON object in `text`: the span of its
    value exactly as written, so a value can be sliced out without being re-encoded."""
    decoder = json.JSONDecoder()
    spans, i = {}, 0

    def ws(j):
        while j < len(text) and text[j] in " \t\r\n":
            j += 1
        return j
    i = ws(i)
    if text[i:i + 1] != "{":
        raise ValueError("not a JSON object")
    i = ws(i + 1)
    while text[i:i + 1] != "}":
        if text[i:i + 1] != '"':
            raise ValueError("expected a member name at %d" % i)
        key, i = json.decoder.scanstring(text, i + 1)
        i = ws(i)
        if text[i:i + 1] != ":":
            raise ValueError("expected ':' at %d" % i)
        start = ws(i + 1)
        _, end = decoder.raw_decode(text, start)
        if key in spans:
            raise ValueError("duplicate member %r" % key)
        spans[key] = (start, end)
        i = ws(end)
        if text[i:i + 1] == ",":
            i = ws(i + 1)
        elif text[i:i + 1] != "}":
            raise ValueError("expected ',' or '}' at %d" % i)
    if ws(i + 1) != len(text):
        raise ValueError("trailing data after the object")
    return spans


def _write(name, data):
    path = OUT / name
    if path.exists():
        raise CaptureError("%s exists already; one capture per directory" % path)
    path.write_bytes(data)
    print("capture: wrote %s (%d bytes)" % (name, len(data)))


def _jwk_private(key):
    n = key.private_numbers()
    b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")  # noqa: E731
    return {"kty": "EC", "crv": "P-256", "x": b(n.public_numbers.x), "y": b(n.public_numbers.y),
            "d": b(n.private_value)}


def capture(posted, instant, argv):
    """Write the files for one accepted response. `posted` is the request body as read."""
    from polaris_oid4vp.jwe import decrypt_compact, JweError
    prefix = b"response="
    jwe = posted[len(prefix):]
    if not posted.startswith(prefix) or not jwe or \
            any(c not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."
                for c in jwe):
        raise CaptureError("the posted body is not exactly response=<compact JWE>; "
                           "nothing written")
    token = jwe.decode("ascii")
    session = plaintext = None
    for candidate in SESSIONS.values():
        try:
            plaintext = decrypt_compact(token, candidate.enc_key)
        except JweError:
            continue
        session = candidate
        break
    if session is None:
        raise CaptureError("the response opens under no recorded request key")
    served = SERVED.get(session.state) or []
    if not served:
        raise CaptureError("no request object was served for state %s" % session.state)
    last = served[-1]
    jar = last.signed

    text = plaintext.decode("utf-8")
    if not text.isascii():
        raise CaptureError("the decrypted response is not ASCII; slicing by character "
                           "would not be slicing by byte")
    spans = raw_members(text)
    vp_start, vp_end = spans["vp_token"]
    vp_raw = text[vp_start:vp_end]
    vp_spans = raw_members(vp_raw)
    if list(vp_spans) != ["pid"]:
        raise CaptureError("vp_token is not keyed by the one DCQL id 'pid'")
    s, e = vp_spans["pid"]
    value = vp_raw[s:e]
    if value.startswith("["):       # one presentation in an array: take the string inside it
        inner = json.loads(value)
        if not (isinstance(inner, list) and len(inner) == 1 and isinstance(inner[0], str)):
            raise CaptureError("vp_token.pid is not one presentation")
        value = value[1:-1].strip()
    presentation = value[1:-1]
    if json.loads(value) != presentation:
        raise CaptureError("the presentation string carries JSON escapes; it cannot be "
                           "sliced verbatim")

    jar_text = jar.decode("ascii")
    payload = _b64u_json(jar_text.split(".")[1])
    pspans = raw_members(payload)
    fields = ("nonce", "client_id", "state", "response_mode", "response_uri", "dcql_query")
    request_json = "{\n" + ",\n".join(
        '  "%s": %s' % (k, payload[pspans[k][0]:pspans[k][1]]) for k in fields) + "\n}\n"
    # The assembled file must say what the signed payload says, member by member.
    signed = json.loads(payload)
    assembled = json.loads(request_json)
    if any(assembled[k] != signed[k] for k in fields) or signed["state"] != session.state \
            or signed["nonce"] != session.nonce:
        raise CaptureError("request.json does not match the served request object")

    anchors = [argv[i + 1] for i, a in enumerate(argv) if a == "--issuer-trust-anchor"]
    if len(anchors) != 1:
        raise CaptureError("the verifier was given %d --issuer-trust-anchor files; a capture "
                           "needs exactly one, its issuer-ca.pem" % len(anchors))
    key = dict(_jwk_private(session.enc_key),
               kid=signed["client_metadata"]["jwks"]["keys"][0].get("kid"),
               use="enc", alg="ECDH-ES", note="test material, never trust")
    # Every file's bytes first, then the writes: nothing above may fail with half of them on disk.
    files = {
        "request.jwt": jar,
        "request.json": request_json.encode("ascii"),
        "response.jwe": jwe,
        "vp-token.json": vp_raw.encode("ascii"),
        "presentation.txt": presentation.encode("ascii"),
        "verifier-decryption-key.test-only.jwk.json":
            (json.dumps(key, indent=2) + "\n").encode("ascii"),
        "issuer-ca.pem": pathlib.Path(anchors[0]).read_bytes(),
    }
    if sorted(files) != sorted(CAPTURE_FILES):
        raise CaptureError("the capture's file list and CAPTURE_FILES disagree")
    for name, data in files.items():
        _write(name, data)
    utc = datetime.datetime.fromtimestamp(instant, datetime.timezone.utc)
    print("capture: instant %d (%s)" % (instant, utc.strftime("%Y-%m-%dT%H:%M:%SZ")))
    print("capture: request object served %d time(s) for this state; the last: wallet_nonce %s, "
          "wallet_metadata %s, %s"
          % (len(served), "posted" if last.wallet_nonce else "not posted",
             "posted" if last.wallet_metadata else "not posted",
             "encrypted to the wallet's key (%d bytes on the wire, SHA-256 %s)"
             % (len(last.body), hashlib.sha256(last.body).hexdigest())
             if last.body != last.signed else "served signed, unencrypted"))
    if last.wallet_metadata:
        print("capture: wallet_metadata as posted: %s" % last.wallet_metadata)
    print("capture: the POST body was exactly response=<response.jwe> (%d bytes)" % len(posted))


def main(argv):
    global OUT
    if len(argv) < 2 or argv[1] != "serve":
        raise SystemExit("usage: capture_serve.py CAPTURE_DIR serve [serve options]")
    OUT = pathlib.Path(argv[0])
    OUT.mkdir(parents=True, exist_ok=True)
    serve_mod = importlib.import_module("polaris_oid4vp.serve")
    verifier_mod = importlib.import_module("polaris_oid4vp.verifier")
    cli = importlib.import_module("polaris_oid4vp.cli")
    import importlib.metadata as md
    print("capture: polaris_oid4vp %s from %s" % (md.version("polaris-oid4vp"),
                                                  pathlib.Path(serve_mod.__file__).parent))

    original_encrypt = verifier_mod.encrypt_compact

    def encrypt_compact(plaintext, *args, **kwargs):
        _SIGNING.plaintext = bytes(plaintext)
        return original_encrypt(plaintext, *args, **kwargs)
    verifier_mod.encrypt_compact = encrypt_compact

    original_new_request = verifier_mod.Verifier.new_request

    def new_request(self):
        session, jar = original_new_request(self)
        SESSIONS[session.state] = session
        return session, jar
    verifier_mod.Verifier.new_request = new_request

    class _Tee:
        def __init__(self, inner):
            self.inner, self.data = inner, bytearray()

        def write(self, b):
            self.data += b
            return self.inner.write(b)

        def read(self, n=-1):
            b = self.inner.read(n)
            self.data += b
            return b

        def __getattr__(self, name):
            return getattr(self.inner, name)

    class CaptureHandler(serve_mod._Handler):
        def _serve_request_object(self, query, wallet_nonce=None, wallet_metadata=None):
            tee = self.wfile = _Tee(self.wfile)
            _SIGNING.plaintext = None
            try:
                return super()._serve_request_object(query, wallet_nonce=wallet_nonce,
                                                     wallet_metadata=wallet_metadata)
            finally:
                self.wfile = tee.inner
                head, _, body = bytes(tee.data).partition(b"\r\n\r\n")
                if head.split(b" ", 2)[1:2] == [b"200"] and \
                        b"\r\ncontent-type: application/oauth-authz-req+jwt" in head.lower():
                    state = (query.get("state") or [""])[0]
                    SERVED.setdefault(state, []).append(
                        Served(wallet_nonce, wallet_metadata, body, _SIGNING.plaintext or body))

        def do_POST(self):
            if self.path.partition("?")[0] != serve_mod.RESPONSE_PATH:
                return super().do_POST()
            tee = self.rfile = _Tee(self.rfile)
            printed = self.on_verdict

            def on_verdict(status, body, verdict):
                if status == 200 and verdict is not None and verdict.authentic:
                    # A capture that fails must not change what the wallet is answered.
                    try:
                        capture(bytes(tee.data), int(time.time()), argv)
                    except Exception as exc:  # noqa: BLE001
                        print("capture: FAILED, nothing more written: %s" % exc)
                        traceback.print_exc()
                if printed:
                    printed(status, body, verdict)
            self.on_verdict = on_verdict
            try:
                return super().do_POST()
            finally:
                self.rfile = tee.inner

    serve_mod._Handler = CaptureHandler
    return cli.main(argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
