#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The second witness: isomdl-uniffi's verify_oid4vp_response over one capture, as JSON.

    VENV/bin/python -I witness_isomdl.py CAPTURE_DIR [--root PEM ...] [--nonce N]

isomdl-uniffi (Indicio, v0.2.0-indicio.2, MIT/Apache-2.0) is not on PyPI; checks.py installs its
wheel from the GitHub release into its own venv, checked against the release's published SHA-256.
Its verify_oid4vp_response takes the DeviceResponse bytes, nonce, client_id, response_uri and a
trust anchor registry (isomdl PemTrustAnchor JSON). It takes no JWK thumbprint, so it builds the SessionTranscript
with a null one, which OpenID4VP 1.0 B.2.6.1 reserves for an unencrypted response.
"""
import argparse
import json
import pathlib
import sys

import isomdl_uniffi as m


def main():
    p = argparse.ArgumentParser()
    p.add_argument("capture")
    p.add_argument("--root", action="append", default=[])
    p.add_argument("--nonce")
    a = p.parse_args()
    d = pathlib.Path(a.capture)
    response = (d / "device-response.cbor").read_bytes()
    inputs = json.loads((d / "openid4vp-inputs.json").read_text())
    if not response:
        sys.exit("empty DeviceResponse")
    # The registry takes isomdl's PemTrustAnchor as JSON: the PEM, and the purpose Iaca.
    roots = [json.dumps({"certificate_pem": pathlib.Path(r).read_text(), "purpose": "Iaca"}) for r in a.root] or None
    out = {"roots": len(a.root)}
    try:
        r = m.verify_oid4vp_response(
            response, a.nonce or inputs["nonce"], inputs["client_id"], inputs["response_uri"], roots, True)
        out.update(
            doc_type=r.doc_type,
            issuer_authentication=r.issuer_authentication.name,
            device_authentication=r.device_authentication.name,
            errors=r.errors,
            items=sorted("%s/%s" % (ns, k) for ns, v in r.verified_response.items() for k in v),
        )
    except Exception as e:  # the witness's own refusal, reported as such
        out["exception"] = "%s: %s" % (type(e).__name__, e)
    print(json.dumps(out))
    print("done", file=sys.stderr)


if __name__ == "__main__":
    main()
