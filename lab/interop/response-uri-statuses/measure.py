#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/interop/response-uri-statuses/measure.py: the HTTP status polaris-oid4vp's Response URI
answers, per kind of response, measured through the listener `serve()` builds.

It drives serve.py's own request handler, the class serve() binds, over an in-memory socket: no
port is bound and nothing else runs. Each presentation is encrypted to a live request's key, as a
wallet using direct_post.jwt encrypts it, and POSTed as `response=<JWE>` to /response.

    python3 measure.py tree                   # this checkout's packages/polaris-oid4vp
    python3 measure.py installed              # the polaris-oid4vp the interpreter imports
    python3 measure.py tree --vectors FILE --json results.json

It prints one row per request and the count of each status, then "done". It exits 1 when the
vectors file holds no vectors, and when a control is not answered 200: the vectors' controls, and
the generator's own presentation (the first replay POST), which every extra class is built on.
"""
import argparse
import importlib.metadata
import io
import json
import os
import re
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.realpath(os.path.join(HERE, "..", "..", ".."))
PACKAGE = os.path.join(ROOT, "packages", "polaris-oid4vp")
VECTORS = os.path.join(HERE, "..", "negative-vectors")


def _load_package(which):
    """polaris_oid4vp from this tree or as installed; (version, path) of what was imported."""
    if which == "tree":
        sys.path.insert(0, PACKAGE)
    import polaris_oid4vp
    path = os.path.realpath(os.path.dirname(polaris_oid4vp.__file__))
    in_tree = path.startswith(os.path.realpath(PACKAGE) + os.sep)
    if which == "installed" and in_tree:
        sys.exit("measure: `installed` imported this tree's package (%s); run it from an "
                 "environment where polaris-oid4vp is installed" % path)
    if which == "tree":
        if not in_tree:
            sys.exit("measure: `tree` imported %s, not this tree's package" % path)
        with open(os.path.join(PACKAGE, "pyproject.toml"), encoding="utf-8") as fh:
            version = re.search(r'^version = "([^"]+)"', fh.read(), re.M).group(1) + " (tree)"
    else:
        version = importlib.metadata.version("polaris-oid4vp")
    return version, path


class _FakeSock:
    def __init__(self, raw):
        self._in = io.BytesIO(raw)
        self.out = bytearray()

    def settimeout(self, t):
        pass

    def setsockopt(self, *a):
        pass

    def makefile(self, mode, bufsize=-1):
        return self._in

    def sendall(self, b):
        self.out += bytes(b)


def measure(doc):
    """Every request, in order: a list of rows."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    import polaris_oid4vp.verifier as pv
    from polaris_oid4vp import serve as ps
    from polaris_oid4vp.jwe import encrypt_compact

    sys.path.insert(0, VECTORS)
    import make_vectors as mv

    s = doc["settings"]
    now = s["now"]
    # The verifier judges at the vectors' instant. handle_direct_post does not pass `now`, so the
    # function it calls is wrapped; nothing else about the decision path is touched.
    original = pv.verify_presentation
    clock = {"now": now}
    pv.verify_presentation = lambda *a, **kw: original(*a, now=clock["now"], **kw)

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "response-uri-statuses")])
    import datetime
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2026, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("verifier.test")]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    anchors = [x509.load_pem_x509_certificate(p.encode()) for p in s["trust_anchors_pem"]]

    def verifier(trust="x5c", claims=("given_name", "family_name", "birthdate"), **kw):
        v = pv.Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                        request_uri="https://verifier.test/request.jwt",
                        response_uri="https://verifier.test/response",
                        issuer_jwks=s["issuer_jwks"] if trust == "jwks" else None,
                        issuer_trust_anchors=anchors if trust != "jwks" else None,
                        vct_values=(s["vct"],), claims=claims, **kw)
        # The vectors' key binding JWTs name this audience; this certificate's x509_hash is
        # another. Only the audience the verifier expects changes.
        v.client_id = s["audience"]
        return v

    def session(v, nonce=s["nonce"]):
        sess, _ = v.new_request()
        if nonce is not None:
            sess.nonce = nonce
        return sess

    def jwe(sess, body):
        return encrypt_compact(json.dumps(body).encode(), sess.enc_key.public_key(), "A128GCM")

    def http(v, raw, handle=None):
        seen = []
        handler = type("_BoundHandler", (ps._Handler,), {
            "verifier": v, "verbose": False,
            "on_verdict": staticmethod(lambda status, body, verdict: seen.append(verdict))})
        handler.log_error = lambda self, *a, **k: None
        if handle is not None:
            v.handle_direct_post = handle
        sock = _FakeSock(raw)
        handler(sock, ("127.0.0.1", 0), object())
        head, _, body = bytes(sock.out).partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
        verdict = seen[0] if seen else None
        return {"status": int(lines[0].split()[1]), "content_type": headers.get("Content-Type"),
                "body": body.decode("utf-8", "replace"),
                "authentic": getattr(verdict, "authentic", None),
                "verdict_code": getattr(verdict, "code", None),
                "verdict_reason": getattr(verdict, "reason", None)}

    def post(form, path="/response", headers=None):
        body = form if isinstance(form, bytes) else urllib.parse.urlencode(form).encode()
        h = {"Host": "verifier.test", "Content-Type": "application/x-www-form-urlencoded",
             "Content-Length": str(len(body))}
        h.update(headers or {})
        return (("POST %s HTTP/1.0\r\n" % path + "".join("%s: %s\r\n" % kv for kv in h.items())
                 + "\r\n").encode() + body)

    rows = []

    def record(group, case, r, note=""):
        rows.append(dict(r, group=group, case=case, note=note))

    def present(group, case, presentation, trust="x5c", vkw=None, nonce=s["nonce"], note=""):
        v = verifier(trust=trust, **(vkw or {}))
        sess = session(v, nonce)
        form = {"response": jwe(sess, {"state": sess.state, "vp_token": {"pid": [presentation]}})}
        record(group, case, http(v, post(form)), note)

    # The published vectors, each inside a direct_post.jwt response.
    for vec in doc["vectors"]:
        present("vectors", vec["id"], vec["presentation"], trust=vec["trust"],
                note="expected %s" % vec["expected"])

    # Failure classes the vectors do not carry, built with the vectors' own generator.
    control = mv.present()
    h, _, rest = control.partition(".")
    p, _, rest2 = rest.partition(".")
    sig, _, tail = rest2.partition("~")
    bad = bytearray(mv.base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)))
    bad[0] ^= 0xFF
    present("extra", "issuer signature does not verify (one byte flipped)",
            h + "." + p + "." + mv.b64u(bytes(bad)) + "~" + tail)
    present("extra", "KB-JWT nonce is not the session's", control, nonce=None)
    present("extra", "KB-JWT aud is another client_id",
            mv.present(kb_payload=lambda b: b.update(aud="x509_hash:somebody-else")))
    present("extra", "credential expired (exp one hour before now)",
            mv.present(payload=mv._set(exp=now - 3600)))
    clock["now"] = now + 3600
    present("extra", "KB-JWT iat one hour old (stale)", control)
    clock["now"] = now
    present("extra", "credential type (vct) not the one requested",
            mv.present(payload=mv._set(vct="urn:example:loyalty:1")))
    present("extra", "requested claim not disclosed", mv.present(drop_claims=("birthdate",)))
    present("extra", "a claim disclosed that the request did not select", control,
            vkw={"claims": ("given_name", "family_name")})
    status_claim = {"status_list": {"uri": "https://issuer.example/sl/1", "idx": 5}}
    present("extra", "status list checked: INVALID (revoked)",
            mv.present(payload=mv._set(status=status_claim)),
            vkw={"status_resolver": lambda *, uri, idx, issuer:
                 {"checked": True, "status": 1, "meaning": "INVALID"}})

    def unreachable(*, uri, idx, issuer):
        raise OSError("status host did not answer")

    present("extra", "status list unreachable", mv.present(payload=mv._set(status=status_claim)),
            vkw={"status_resolver": unreachable})
    present("extra", "garbage presentation string", "not-an-sd-jwt")

    # The response layer.
    v = verifier()
    session(v)
    record("response", "empty POST body", http(v, post({})))
    v = verifier()
    sess = session(v)
    record("response", "plain direct_post: vp_token and state, unencrypted",
           http(v, post({"vp_token": json.dumps({"pid": [control]}), "state": sess.state})))
    v = verifier()
    sess = session(v)
    record("response", "Authorization Error Response, unencrypted (error=access_denied&state)",
           http(v, post({"error": "access_denied", "state": sess.state})),
           note="OpenID4VP 1.0 section 8.3.1 lets a wallet send an error response unencrypted")
    v = verifier()
    sess = session(v)
    record("response", "Authorization Error Response, encrypted ({error, state} in the JWE)",
           http(v, post({"response": jwe(sess, {"error": "access_denied", "state": sess.state})})))
    v = verifier()
    session(v)
    record("response", "response=garbage (not a JWE)", http(v, post({"response": "a.b.c"})))
    v = verifier()
    session(v)
    other = verifier()
    osess = session(other)
    record("response", "JWE encrypted to another request's key",
           http(v, post({"response": jwe(osess, {"state": osess.state,
                                                 "vp_token": {"pid": [control]}})})))
    v = verifier()
    sess = session(v)
    record("response", "state inside the JWE does not match its key's request",
           http(v, post({"response": jwe(sess, {"state": "some-other-request",
                                                "vp_token": {"pid": [control]}})})))
    v = verifier()
    sess = session(v)
    record("response", "vp_token missing from the decrypted response",
           http(v, post({"response": jwe(sess, {"state": sess.state})})))
    v = verifier()
    sess = session(v)
    record("response", "vp_token keyed by an id the DCQL query did not use",
           http(v, post({"response": jwe(sess, {"state": sess.state,
                                                "vp_token": {"other": [control]}})})))
    v = verifier()
    sess = session(v)
    record("response", "vp_token with two presentations",
           http(v, post({"response": jwe(sess, {"state": sess.state,
                                                "vp_token": {"pid": [control, control]}})})))
    v = verifier()
    sess = session(v)
    form = {"response": jwe(sess, {"state": sess.state, "vp_token": {"pid": [control]}})}
    record("response", "replay: first POST", http(v, post(form)))
    record("response", "replay: identical second POST", http(v, post(form)))
    v = verifier(request_ttl_seconds=0)
    sess = session(v)
    time.sleep(0.01)
    record("response", "request expired before the response arrived (TTL 0)",
           http(v, post({"response": jwe(sess, {"state": sess.state,
                                                "vp_token": {"pid": [control]}})})))

    # The transport.
    v = verifier()
    session(v)
    record("transport", "Content-Length not a decimal number",
           http(v, post({"response": "x"}, headers={"Content-Length": "+9"})))
    record("transport", "declared body over 1 MiB",
           http(v, b"POST /response HTTP/1.0\r\nHost: v\r\nContent-Length: 2000000\r\n\r\n"))
    record("transport", "POST to an unknown path", http(v, post({"response": "x"}, path="/nope")))

    def boom(form):
        raise RuntimeError("a bug in the verifier")

    record("transport", "verifier raises an exception", http(v, post({"response": "x"}),
                                                              handle=boom))
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("package", choices=("tree", "installed"),
                    help="this checkout's polaris-oid4vp, or the one the interpreter imports")
    ap.add_argument("--vectors", default=os.path.join(VECTORS, "vectors.json"),
                    help="the negative vectors to present (default: this tree's)")
    ap.add_argument("--json", help="write every row, with bodies and reasons, here")
    args = ap.parse_args(argv)
    try:
        with open(args.vectors, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        print("measure: %s is not a readable vectors file: %s" % (args.vectors, exc),
              file=sys.stderr)
        return 1
    if not isinstance(doc, dict) or not doc.get("vectors") or not doc.get("settings"):
        print("measure: %s holds no vectors, so there is nothing to measure" % args.vectors,
              file=sys.stderr)
        return 1
    version, path = _load_package(args.package)
    rows = measure(doc)
    print("polaris-oid4vp %s from %s; vectors %s (%d); Python %s"
          % (version, path, doc.get("version"), len(doc["vectors"]), sys.version.split()[0]))
    print("%-3s %-9s %-6s %-17s %-23s %s" % ("#", "group", "status", "content type", "verdict",
                                            "case"))
    for n, row in enumerate(rows, 1):
        shown = ("authentic" if row["authentic"] else row["verdict_code"]
                 if row["verdict_code"] is not None else "-")
        print("%-3d %-9s %-6d %-17s %-23s %s" % (n, row["group"], row["status"],
                                                 row["content_type"] or "-", shown, row["case"]))
    counts = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    print("%d requests: %s" % (len(rows), ", ".join("%d x%d" % (status, counts[status])
                                                     for status in sorted(counts))))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"polaris_oid4vp": version, "path": path, "python": sys.version.split()[0],
                       "vectors": doc.get("version"), "now": doc["settings"]["now"],
                       "results": rows}, fh, indent=1)
            fh.write("\n")
    controls = [r for r in rows if (r["group"] == "vectors" and r["case"].startswith("accept-"))
                or r["case"] == "replay: first POST"]
    if not rows or not controls or any(r["status"] != 200 or not r["authentic"]
                                       for r in controls):
        print("measure: a control was not accepted, so the refusals above measured nothing",
              file=sys.stderr)
        return 1
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
