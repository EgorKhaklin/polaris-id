#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-oid4vp-image-drill.py: the polaris-oid4vp image judges a presentation.

    python3 scripts/polaris-oid4vp-image-drill.py                 # build the image, then drill it
    python3 scripts/polaris-oid4vp-image-drill.py --image REF     # drill an image already built

The image (packages/polaris-oid4vp/image) holds the released package and nothing of this tree, so
what this drill exercises is the published wheel inside the container, from outside it:

  1. the image runs as a user that is not root, its entrypoint is the package's command, and the
     package inside is the version requirements.in pins;
  2. `keygen` writes the certificates into a volume;
  3. `serve --once --result` is started on them, and the package suite's own wallet (the Wallet
     of packages/polaris-oid4vp/test_verifier.py, which reads the request object over TLS and
     answers it with an encrypted direct_post.jwt response) presents a credential from an issuer
     whose key the verifier was given: the response is answered 200 and the result file says
     accepted;
  4. the same again with the wrong nonce in the key binding: answered 400, and the result file
     says refused, by the nonce check. A verifier that accepted everything fails here.

Needs docker and the `cryptography` package (the wallet signs and encrypts with it). Exit 0 and a
last line `done` when every step held; any other exit, or an exit without `done`, is a failure.
"""
import argparse
import json
import pathlib
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "packages" / "polaris-oid4vp"
IMAGE_DIR = PACKAGE / "image"
USER = "10001:10001"
ENTRYPOINT = ["polaris-oid4vp"]
START_TIMEOUT = 60.0


class Failure(Exception):
    pass


def docker(*args, text=None, timeout=600):
    """Run docker; return (exit code, stdout, stderr)."""
    done = subprocess.run(("docker",) + args, input=text, capture_output=True, text=True,
                          timeout=timeout)
    return done.returncode, done.stdout, done.stderr


def must(*args, text=None, timeout=600):
    code, out, err = docker(*args, text=text, timeout=timeout)
    if code != 0:
        raise Failure("docker %s: exit %d: %s" % (" ".join(args[:3]), code, (err or out).strip()))
    return out


def pinned_version():
    found = re.findall(r"(?m)^polaris-oid4vp==([0-9][0-9A-Za-z.]*)\s*$",
                       (IMAGE_DIR / "requirements.in").read_text(encoding="utf-8"))
    if len(found) != 1:
        raise Failure("requirements.in pins polaris-oid4vp %d times, not once" % len(found))
    return found[0]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http(url, context, form=None):
    data = None if form is None else urllib.parse.urlencode(form, doseq=True).encode()
    req = urllib.request.Request(url, data=data, method="GET" if form is None else "POST")
    if form is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=20, context=context) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def check_config(image):
    cfg = json.loads(must("image", "inspect", image, "--format", "{{json .Config}}"))
    if cfg.get("User") != USER:
        raise Failure("the image runs as %r, not the user %s" % (cfg.get("User"), USER))
    if cfg.get("Entrypoint") != ENTRYPOINT:
        raise Failure("the image's entrypoint is %r, not %r" % (cfg.get("Entrypoint"), ENTRYPOINT))
    uid = must("run", "--rm", "--entrypoint", "id", image, "-u").strip()
    if uid != USER.split(":")[0]:
        raise Failure("inside the image the user id is %s, not %s" % (uid, USER.split(":")[0]))
    want = pinned_version()
    got = must("run", "--rm", "--entrypoint", "python", image, "-c",
               "import importlib.metadata as m; print(m.version('polaris-oid4vp'))").strip()
    if got != want:
        raise Failure("the image holds polaris-oid4vp %s; requirements.in pins %s" % (got, want))
    print("the image runs as %s, its entrypoint is %s, and it holds polaris-oid4vp %s"
          % (USER, " ".join(ENTRYPOINT), got))
    return got


def present(image, volume, port, context, wallet, case, **respond):
    """Start one request, answer it with the wallet, and return (HTTP status, result file)."""
    name = "polaris-oid4vp-drill-%s" % secrets.token_hex(4)
    result = "/data/result-%s.json" % case
    must("run", "-d", "--name", name, "-p", "127.0.0.1:%d:%d" % (port, port), "-v", volume + ":/data",
         image, "serve", "--pki", "/data/pki", "--host", "localhost", "--bind", "0.0.0.0",
         "--port", str(port), "--issuer-jwks", "/data/issuers.json", "--once", "--result", result)
    try:
        request_uri = None
        deadline = time.monotonic() + START_TIMEOUT
        while request_uri is None:
            _, out, err = docker("logs", name)
            # The request --once started: the request_uri under this heading names its state.
            started = out.partition("authorization request parameters:")[2]
            found = re.search(r"(?m)^\s+request_uri\s+(https://localhost:%d/\S+)\s*$" % port, started)
            if found and "launch links" in started:
                request_uri = found.group(1)
                break
            running = must("inspect", name, "--format", "{{.State.Running}}").strip()
            if running != "true" or time.monotonic() > deadline:
                raise Failure("%s: serve did not start a request: %s" % (case, (err or out).strip()))
            time.sleep(0.5)
        status, jar = None, b""
        while status is None:
            try:
                status, jar = http(request_uri, context, form={})
            except (urllib.error.URLError, OSError) as exc:
                if time.monotonic() > deadline:
                    raise Failure("%s: the request object could not be fetched: %s" % (case, exc))
                time.sleep(0.5)
        if status != 200:
            raise Failure("%s: the request object was answered %d" % (case, status))
        jar = jar.decode("ascii")
        _, claims = wallet.read_request(jar)
        status, _ = http(claims["response_uri"], context, form=wallet.respond(jar, **respond))
    finally:
        docker("rm", "-f", name)
    doc = json.loads(must("run", "--rm", "-v", volume + ":/data", "--entrypoint", "cat", image, result))
    return status, doc


def drill(image):
    sys.path.insert(0, str(PACKAGE))
    from polaris_oid4vp.cli import FILES
    from test_verifier import Wallet

    check_config(image)
    volume = "polaris-oid4vp-drill-%s" % secrets.token_hex(4)
    port = free_port()
    must("volume", "create", volume)
    try:
        must("run", "--rm", "-v", volume + ":/data", image,
             "keygen", "--out", "/data/pki", "--host", "localhost", "--port", str(port))
        wallet = Wallet()
        must("run", "--rm", "-i", "-v", volume + ":/data", "--entrypoint", "sh", image,
             "-c", "cat > /data/issuers.json", text=json.dumps([wallet.issuer_jwk]))
        tls = must("run", "--rm", "-v", volume + ":/data", "--entrypoint", "cat", image,
                   "/data/pki/" + FILES["tls_cert"])
        context = ssl.create_default_context(cadata=tls)
        print("keygen wrote the certificates; the listener's is trusted for this run only")

        status, doc = present(image, volume, port, context, wallet, "accept")
        if status != 200 or doc.get("outcome") != "accepted" or "given_name" not in doc.get("claims", ()):
            raise Failure("a valid presentation was answered %d and recorded as %s"
                          % (status, json.dumps(doc, sort_keys=True)))
        print("a valid presentation: answered 200, recorded accepted with claims %s"
              % ", ".join(doc["claims"]))

        status, doc = present(image, volume, port, context, wallet, "wrong-nonce", nonce="wrong")
        if status != 400 or doc.get("outcome") != "refused" or doc.get("check") != "nonce":
            raise Failure("a presentation bound to the wrong nonce was answered %d and recorded as %s"
                          % (status, json.dumps(doc, sort_keys=True)))
        print("the wrong nonce: answered 400, recorded refused by the nonce check")
    finally:
        docker("volume", "rm", "-f", volume)


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    ap.add_argument("--image", default="", help="an image already built; without it the drill "
                    "builds packages/polaris-oid4vp/image first")
    a = ap.parse_args(argv)
    image = a.image
    try:
        if not image:
            image = "polaris-oid4vp:drill"
            must("build", "-t", image, str(IMAGE_DIR), timeout=1800)
            print("built %s from %s" % (image, IMAGE_DIR.relative_to(ROOT)))
        drill(image)
    except (Failure, subprocess.TimeoutExpired, OSError, ValueError, KeyError) as exc:
        print("FAIL: %s" % exc, file=sys.stderr)
        return 1
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
