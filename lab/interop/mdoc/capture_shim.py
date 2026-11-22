#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""`polaris-oid4vp serve`, keeping each DeviceResponse it judges, for the second witnesses.

    VENV/bin/python -I capture_shim.py OUT serve --format mso_mdoc --experimental ... --once

Lab only, for a wallet this lab cannot instrument: an app on a phone or an emulator. It runs the
INSTALLED package's own command line in-process and wraps one method, `Verifier._judge_mdoc`, the
verifier's judgment of one mso_mdoc answer to a direct_post.jwt request. The wrapper calls the
method and returns its verdict as it is; then it writes the answer to OUT/N, N counting the
answers kept from 1:

  device-response.cbor    the DeviceResponse: the vp_token value, base64url-decoded;
  openid4vp-inputs.json   what the SessionTranscript is built from (OpenID4VP 1.0 B.2.6.1): the
                          verifier's client_id and response_uri, the request's nonce and the
                          public members of its encryption JWK, with the response_mode and the
                          query's doctype_value and claims, under the names witness_isomdl.py
                          and witness-oid4vcgo read;
  verdict.json            the verifier's verdict on it: authentic, code and reason;
  captured-at.txt         when it was judged, UTC.

A vp_token value that is not base64url of one CBOR map carrying `version` and `status`, the two
members every DeviceResponse has, is not kept: the verifier refuses it, and there is nothing to
witness. The package's own decoder (`polaris_oid4vp.cbor`) reads it. A failure to write is printed to stderr and changes
nothing the verifier answers. test_capture_shim.py holds that this method is the only thing
replaced, and that the verdicts and request objects are the verifier's own.
"""
import datetime
import json
import pathlib
import sys
import threading

import polaris_oid4vp.cbor as cbor
import polaris_oid4vp.cli as cli
import polaris_oid4vp.verifier as verifier

#: The members of an EC public JWK that its RFC 7638 thumbprint hashes, and all a witness needs.
JWK_MEMBERS = ("kty", "crv", "x", "y")


def install(out):
    """Wrap `Verifier._judge_mdoc` so that each answer it judges is kept under `out`. Returns the
    function that puts the original back."""
    out = pathlib.Path(out)
    original = verifier.Verifier._judge_mdoc
    lock = threading.Lock()
    count = [0]

    def _judge_mdoc(self, session, presentation):
        verdict = original(self, session, presentation)
        response, document = b"", None
        try:
            response = verifier.b64u_decode(presentation) if isinstance(presentation, str) else b""
            document = cbor.decode(response) if response else None
        except ValueError:  # CborError is one
            pass
        if isinstance(document, dict) and "version" in document and "status" in document:
            try:
                with lock:
                    count[0] += 1
                    where = out / str(count[0])
                    where.mkdir(parents=True)
                _keep(where, self, session, response, verdict)
            except Exception as exc:  # noqa: BLE001  the verdict goes out whatever happens here
                print("capture_shim: answer not kept: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return verdict

    verifier.Verifier._judge_mdoc = _judge_mdoc

    def uninstall():
        verifier.Verifier._judge_mdoc = original

    return uninstall


def _keep(where, self, session, response, verdict):
    jwk = self._response_jwk(session)
    query = self._dcql_query()["credentials"][0]
    inputs = {"response_mode": verifier.RESPONSE_MODE, "client_id": self.client_id, "nonce": session.nonce,
              "response_uri": self.response_uri, "encryption_jwk": {k: jwk[k] for k in JWK_MEMBERS},
              "doctype_value": query["meta"]["doctype_value"], "claims": query["claims"]}
    (where / "device-response.cbor").write_bytes(response)
    (where / "openid4vp-inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
    (where / "verdict.json").write_text(json.dumps(
        {"authentic": verdict.authentic, "code": verdict.code, "reason": verdict.reason}, indent=2) + "\n")
    (where / "captured-at.txt").write_text(
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") + "\n")
    print("capture_shim: kept answer %s in %s (%s)" % (where.name, where, "accepted" if verdict.authentic
                                                       else "refused: " + verdict.code), file=sys.stderr)


def main(argv):
    if len(argv) < 2 or argv[1] != "serve":
        sys.exit(__doc__)
    out = pathlib.Path(argv[0])
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        sys.exit("capture_shim: OUT %s is not an empty directory; each run keeps its answers apart" % out)
    install(out)
    return cli.main(argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
