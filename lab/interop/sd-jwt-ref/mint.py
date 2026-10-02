#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Mint one wallet copy with the PRODUCT's own issuer code, for the reverse-direction walk.

This is the issuer half. It imports `polaris_web/wallet_copy.py` (stdlib only, no Flask, no
database) and calls `build_copy`, the same function the OpenID4VCI endpoint calls to sign a
wallet copy for a wallet. The signing key is a TEST agency chain made by
`scripts/polaris-credential-copy-test-pki.py`; nothing here is a deployment.

    mint.py <repo_root> <work_dir>

Reads <work_dir>/keys/7.{key,chain}.pem (the agency leaf and its key), writes
<work_dir>/copy.txt (the SD-JWT VC) and <work_dir>/meta.json. The holder key is generated and
only its public JWK goes into `cnf`: the copy is the credential, not a presentation, so no
private holder key is kept.
"""
import base64
import datetime
import json
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

repo_root, work = sys.argv[1], sys.argv[2]
sys.path.insert(0, repo_root + "/polaris_web")
import wallet_copy  # noqa: E402  (the product's issuer code, stdlib only)

priv = serialization.load_pem_private_key(open(work + "/keys/7.key.pem", "rb").read(), None)
leaf = x509.load_pem_x509_certificate(open(work + "/keys/7.chain.pem", "rb").read())
leaf_der = leaf.public_bytes(serialization.Encoding.DER)


class Key:
    """Exactly the surface `build_copy` uses: an ES256 signer (raw r||s, as JWS wants it) and the
    `x5c` leaf. This mirrors polaris_web/credential_copy_keys.py:CopyKey so the copy is byte-for-
    byte what the product issues, without importing the key-loading module."""

    x5c = [base64.b64encode(leaf_der).decode("ascii")]

    def sign(self, signing_input: bytes) -> bytes:
        der = priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


holder = ec.generate_private_key(ec.SECP256R1())
num = holder.public_key().public_numbers()
b64u = lambda n: base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()
holder_jwk = {"kty": "EC", "crv": "P-256", "x": b64u(num.x), "y": b64u(num.y)}

issuer = "https://polaris.test/api/v1/oid4vci/7"
today = datetime.date.today()
claims = wallet_copy.claims_for("Ada Lovelace", datetime.date(1990, 5, 2), "POLARIS-TEST", today)
iat = int(time.time())
copy = wallet_copy.build_copy(Key(), issuer, claims, holder_jwk, iat, iat + 30 * 86400,
                             status_index=5, status_uri=issuer + "/status/0/1")

open(work + "/copy.txt", "w").write(copy)
json.dump({"issuer": issuer, "vct": wallet_copy.VCT, "claims": claims},
          open(work + "/meta.json", "w"), indent=2)
n_disc = len([p for p in copy.split("~")[1:] if p])
print("  minted: ES256 dc+sd-jwt, vct=%s, %d disclosures, %d bytes"
      % (wallet_copy.VCT, n_disc, len(copy)))
