#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""`polaris-oid4vp serve`, with its request object rewritten to ask for an mdoc over plain direct_post.

    VENV/bin/python -I request_shim.py DOCTYPE NAMESPACE serve --pki pki ... --once

Lab only, for capture.sh MODE=direct_post. polaris-oid4vp always asks for an SD-JWT VC over
direct_post.jwt. This runs the INSTALLED package's own command line in-process and wraps one function,
`polaris_oid4vp.verifier._sign_es256`. Just before a request object is signed, it changes four things:
  - response_mode becomes direct_post (no encryption);
  - client_metadata loses its jwks and encrypted_response_enc_values_supported, and offers mso_mdoc;
  - the DCQL query asks for format mso_mdoc, meta.doctype_value DOCTYPE, claims
    [NAMESPACE, given_name] and [NAMESPACE, family_name], under the query's own id.
Everything else (client_id, x5c, nonce, state, response_uri, the signature) is the verifier's own. The
verifier still expects a JWE at its response_uri, so it refuses the unencrypted response. The wallet
writes its capture before it sends.
"""
import sys

import polaris_oid4vp.cli as cli
import polaris_oid4vp.verifier as verifier

if len(sys.argv) < 4:
    sys.exit(__doc__)
DOCTYPE, NAMESPACE = sys.argv[1], sys.argv[2]
_sign = verifier._sign_es256


def _sign_rewritten(key, header, claims):
    if header.get("typ") == "oauth-authz-req+jwt":
        claims = dict(claims)
        claims["response_mode"] = "direct_post"
        meta = {k: v for k, v in claims["client_metadata"].items()
                if k not in ("jwks", "encrypted_response_enc_values_supported")}
        meta["vp_formats_supported"] = {"mso_mdoc": {"issuerauth_alg_values": [-7], "deviceauth_alg_values": [-7]}}
        claims["client_metadata"] = meta
        query = claims["dcql_query"]["credentials"][0]
        claims["dcql_query"] = {"credentials": [{
            "id": query["id"], "format": "mso_mdoc", "meta": {"doctype_value": DOCTYPE},
            "claims": [{"path": [NAMESPACE, "given_name"]}, {"path": [NAMESPACE, "family_name"]}],
        }]}
    return _sign(key, header, claims)


verifier._sign_es256 = _sign_rewritten
sys.exit(cli.main(sys.argv[3:]))
