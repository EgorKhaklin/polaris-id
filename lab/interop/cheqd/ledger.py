# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""ledger.py: what the walk reads from the cheqd localnet itself, through the node's REST API.

    python ledger.py did ISSUED_JSON OUT_JWKS [OTHER_JWKS]
    python ledger.py status ISSUED_JSON EXPECTED

Polaris resolves no DIDs. This script does, on the localnet, for the verifier:

did     reads the issuer's DID document from the ledger (GET /cheqd/did/v2/{did}), takes the
        verification method the credential's header names (Credo writes the kid as a DID URL
        relative to `iss`, "#key-1"), checks that the document lists it under assertionMethod
        and that it is an EC P-256 JsonWebKey2020, and writes it as the JWKS the verifier is
        handed (--issuer-jwks), under the kid the credential carries. With OTHER_JWKS it also
        writes control (a)'s JWKS: an unrelated P-256 key under the same kid.

status  reads the credential's own status claim (idx, uri), resolves the uri, a DID URL naming
        a DID-Linked Resource by name and type, to the resource's latest version on the ledger
        (GET /cheqd/resource/v2/{collection}/metadata, then .../resources/{id}), and decides it
        with polaris_oid4vp.status.decide_by_fetching. The stated authority is the issuer's key as
        the DID document on the ledger names it. Exits 0 only if the decision is EXPECTED.

Environment: CHEQD_REST, the node's REST API (default http://127.0.0.1:1317).
"""
import base64
import json
import os
import sys
import urllib.parse
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

REST = os.environ.get("CHEQD_REST", "http://127.0.0.1:1317")


def b64u_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def rest(path):
    with urllib.request.urlopen(REST + path, timeout=10) as response:
        return json.load(response)


def credential_parts(compact):
    """The issuer-signed header and payload of a compact SD-JWT."""
    jwt = compact.split("~")[0]
    header, payload = (json.loads(b64u_decode(p)) for p in jwt.split(".")[:2])
    return header, payload


def resolve_issuer_key(did, kid):
    """The P-256 public JWK the DID document on the ledger names for the credential's kid."""
    found = rest("/cheqd/did/v2/" + urllib.parse.quote(did, safe=":"))["value"]
    doc, meta = found["did_doc"], found["metadata"]
    if meta.get("deactivated"):
        raise SystemExit("%s is deactivated on the ledger" % did)
    vm_id = did + kid if kid.startswith("#") else kid
    vms = [vm for vm in doc["verification_method"] if vm["id"] == vm_id]
    if len(vms) != 1:
        raise SystemExit("%s names no verification method %s" % (did, vm_id))
    if vm_id not in doc["assertion_method"]:
        raise SystemExit("%s is not an assertionMethod of %s" % (vm_id, did))
    vm = vms[0]
    if vm["verification_method_type"] != "JsonWebKey2020":
        raise SystemExit("%s is a %s, not a JsonWebKey2020" % (vm_id, vm["verification_method_type"]))
    jwk = json.loads(vm["verification_material"])
    if (jwk.get("kty"), jwk.get("crv")) != ("EC", "P-256") or "d" in jwk:
        raise SystemExit("%s is not an EC P-256 public key: %r" % (vm_id, jwk))
    return {"kty": "EC", "crv": "P-256", "x": jwk["x"], "y": jwk["y"]}, vm_id, meta


def public_key(jwk):
    return ec.EllipticCurvePublicNumbers(int.from_bytes(b64u_decode(jwk["x"]), "big"),
                                         int.from_bytes(b64u_decode(jwk["y"]), "big"),
                                         ec.SECP256R1()).public_key()


def es256_verifier(key):
    def verify(signing_input, signature, header):
        if len(signature) != 64:
            return False
        der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                         int.from_bytes(signature[32:], "big"))
        try:
            key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False
        return True
    return verify


def fetch_resource(did_url):
    """A DID URL naming a resource by resourceName and resourceType, resolved to the latest
    version's bytes on the ledger. Anything else is not something this walk resolves."""
    did, _, query = did_url.partition("?")
    params = urllib.parse.parse_qs(query, strict_parsing=True)
    name, rtype = params["resourceName"][0], params["resourceType"][0]
    collection = did.split(":")[-1]
    versions = [m for m in rest("/cheqd/resource/v2/%s/metadata" % collection)["resources"]
                if m["name"] == name and m["resource_type"] == rtype]
    latest = [m for m in versions if not m["next_version_id"]]
    if len(latest) != 1:
        raise LookupError("%s: %d versions, %d without a successor" % (did_url, len(versions), len(latest)))
    found = rest("/cheqd/resource/v2/%s/resources/%s" % (collection, latest[0]["id"]))["resource"]
    print("ledger     %s -> resource %s (version %s of %d, %s)"
          % (did_url, latest[0]["id"], latest[0]["version"], len(versions), latest[0]["created"]))
    return base64.b64decode(found["resource"]["data"])


def cmd_did(issued_file, out_jwks, other_jwks=None):
    issued = json.load(open(issued_file))
    header, payload = credential_parts(issued["credential"])
    did, kid = payload["iss"], header["kid"]
    jwk, vm_id, meta = resolve_issuer_key(did, kid)
    print("ledger     %s resolves to version %s (created %s)" % (did, meta["version_id"], meta["created"]))
    print("ledger     %s: JsonWebKey2020, EC P-256, assertionMethod" % vm_id)
    json.dump([dict(jwk, kid=kid)], open(out_jwks, "w"))
    print("verifier   trusts that key under kid %r (%s)" % (kid, out_jwks))
    if other_jwks:
        n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        other = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")),
                 "y": b64u(n.y.to_bytes(32, "big")), "kid": kid}
        json.dump([other], open(other_jwks, "w"))


def cmd_status(issued_file, expected):
    from polaris_oid4vp import status as S

    issued = json.load(open(issued_file))
    header, payload = credential_parts(issued["credential"])
    did, kid = payload["iss"], header["kid"]
    claim = payload["status"]["status_list"]
    index, uri = claim["idx"], claim["uri"]
    jwk, vm_id, _ = resolve_issuer_key(did, kid)
    grant = S.StatedAuthority().state(
        credential_issuer=did, status_uri=uri, verify=es256_verifier(public_key(jwk)),
        why="the key the issuer's did:cheqd document names (%s), resolved on the localnet" % vm_id)
    verdict = S.decide_by_fetching(index=index, expected_uri=uri, authority=grant,
                                   fetch=fetch_resource, credential_issuer=did)
    print("status     index %d: checked=%s %s (%s)" % (index, verdict["checked"], verdict["meaning"],
                                                       verdict["reason"]))
    return 0 if verdict["checked"] and verdict["meaning"] == expected else 1


if __name__ == "__main__":
    if len(sys.argv) in (4, 5) and sys.argv[1] == "did":
        cmd_did(*sys.argv[2:])
    elif len(sys.argv) == 4 and sys.argv[1] == "status":
        sys.exit(cmd_status(sys.argv[2], sys.argv[3]))
    else:
        sys.exit(__doc__)
