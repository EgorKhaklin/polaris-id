#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/interop/negative-vectors/run_vectors.py: run vectors.json against a verifier and print, for each
vector, the verdict it should reach and the one it reached.

    python3 run_vectors.py vectors.json --adapter polaris-oid4vp [--json results.json]
    python3 run_vectors.py mdoc-vectors.json --adapter verify-mdoc

An adapter is one function: (vector, settings) -> ("accept" | "reject", a short reason). The run fails
(exit 1) when a control is refused, because then every refusal it reports measured nothing, when a
negative vector is accepted, when polaris-oid4vp refuses one with another code than POLARIS_OID4VP_CODES
names, and when the file holds no vectors, no control, or no negative the adapter judged, or judges a negative
in a layer whose own control (an accept-* vector of that layer) it left to its caller. Exit 2: the adapter could not run. A run that passes ends "done".

A control is a vector of class `control`. A vector with a `repaired` twin (mdoc-vectors.json) is run twice: the vector
as it stands, and its twin, the same vector with its one defect put back, which must be accepted (a refused twin means
the vector's refusal measured nothing). The `verify-mdoc` adapter is lab/interop/mdoc/verify_mdoc.py, whose refusal
check (its Refused.check) is compared for each negative.

A vector with a `status_list` (0.3.0) is judged under its `policy`: the adapter serves `status_list.response`
at `status_list.uri` from memory, opening no socket, and states the keys in settings.status_list_keys.
"""
import argparse
import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


_POLARIS_SEEN = []
# polaris-oid4vp's refusal code for each negative vector: it must refuse for the vector's reason, not for any.
POLARIS_OID4VP_CODES = {
    "issuer-crit": "crit", "kb-crit": "crit",
    "kb-aud-array": "audience", "kb-aud-no-prefix": "audience", "kb-aud-missing": "audience",
    "kb-nonce-missing": "nonce",
    "digest-twice": "disclosure", "claim-overwrite": "disclosure", "disclosed-exp": "disclosure",
    "disclosed-iss": "disclosure", "disclosure-four-elements": "disclosure", "disclosure-named-sd": "disclosure",
    "kb-typ-jwt": "kb_typ", "kb-alg-none": "kb_alg", "kb-alg-hs256": "kb_alg",
    "kb-iat-nan": "malformed", "kb-exp-string": "kb_freshness",
    "issuer-sig-der": "issuer_signature",
    "x5c-self-signed": "issuer_key", "x5c-includes-anchor": "issuer_key", "x5c-unknown-root": "issuer_key",
    "x5c-leaf-expired": "issuer_key", "x5c-intermediate-not-ca": "issuer_key",
    # 0.3.0. The issuer_key refusal for a leaf that names another issuer, as distinct from a broken chain, is
    # held by test_vectors.py's SignerIsNotTheIssuer.
    "x5c-leaf-names-other-issuer": "issuer_key", "x5c-leaf-names-other-host": "issuer_key",
    "x5c-leaf-uri-beats-host": "issuer_key",
    # 0.3.0, under the status-required policy: the revocation state polaris-oid4vp reports, and for
    # list_refused the status.py code after a slash.
    "status-list-unreachable": "unreachable", "status-list-not-a-token": "unreachable",
    "status-list-lst-truncated": "list_refused/lst", "status-list-wrong-key": "list_refused/signature",
    "status-list-no-authority": "no_authority", "status-list-expired": "list_refused/expired",
    "status-list-index-past-end": "list_refused/index",
}


def polaris_oid4vp(vector, settings):
    # The installed package when there is one (a release from PyPI), else this tree's: until
    # 2026-10-10 the tree always went first on sys.path, so a run "against a release" measured the
    # tree. The first call says which it used.
    try:
        import polaris_oid4vp
    except ImportError:
        sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "packages", "polaris-oid4vp"))
        import polaris_oid4vp
    if not _POLARIS_SEEN:
        import importlib.metadata
        try:
            version = importlib.metadata.version("polaris-oid4vp")
        except importlib.metadata.PackageNotFoundError:
            version = "this tree"
        _POLARIS_SEEN.append(version)
        print("polaris-oid4vp %s from %s" % (version, os.path.dirname(polaris_oid4vp.__file__)), file=sys.stderr)
    from cryptography import x509
    from polaris_oid4vp.sdjwt import verify_presentation
    kw = {"expected_nonce": settings["nonce"], "expected_audience": settings["audience"], "now": settings["now"],
          "max_skew_seconds": settings["max_skew_seconds"], "expected_vct": settings["vct"]}
    if vector["trust"] == "jwks":
        kw["issuer_jwks"] = settings["issuer_jwks"]
    else:
        kw["trust_anchors"] = [x509.load_pem_x509_certificate(p.encode()) for p in settings["trust_anchors_pem"]]
    if "status_list" in vector:
        kw["status_resolver"] = status_resolver(vector, settings)
    verdict = verify_presentation(vector["presentation"], **kw)
    if not verdict.authentic or "status_list" not in vector:
        return ("accept" if verdict.authentic else "reject"), "%s: %s" % (verdict.code, verdict.reason)
    return status_required(verdict.revocation or {})


def status_required(revocation):
    """The status-required policy over polaris-oid4vp's revocation state: accept only a checked VALID (0).
    A checked status that is not VALID is refused as `revoked`, the code polaris-oid4vp's Verifier gives it."""
    state = revocation.get("state")
    if state == "checked":
        if revocation.get("status") == 0:
            return "accept", "checked: VALID"
        return "reject", "revoked: status %r" % (revocation.get("status"),)
    code = "%s/%s" % (state, revocation.get("code")) if state == "list_refused" else str(state)
    return "reject", "%s: %s" % (code, revocation.get("reason"))


# verify_mdoc.py's refusal check for each negative mdoc vector: it must refuse for the vector's reason, not for any.
VERIFY_MDOC_CHECKS = {
    "md-st-nonce": "device signature", "md-st-client-id-other": "device signature",
    "md-st-client-id-no-prefix": "device signature", "md-st-response-uri": "device signature",
    "md-st-thumbprint-other-key": "device signature", "md-st-thumbprint-absent": "device signature",
    "md-st-dcapi-handover-on-redirect": "device signature", "md-st-redirect-handover-on-dcapi": "device signature",
    "md-st-dcapi-origin-prefixed": "device signature", "md-st-dcapi-origin-other": "device signature",
    "md-devicesig-other-key": "device signature", "md-devicesig-missing": "device signature",
    "md-devicesig-not-detached": "device signature", "md-devicesig-doctype-other": "device signature",
    "md-devicekey-kty-crv": "device key", "md-devicesigned-unauthorized-ns": "device data",
    "md-doctype-not-requested": "requested docType",
    "md-issuerauth-sig-flipped": "issuer signature", "md-issuerauth-sig-der": "issuer signature",
    "md-issuerauth-alg-curve": "issuer signature", "md-issuerauth-crit-unknown": "issuer signature",
    "md-issuerauth-dup-label": "issuer signature",
    "md-mso-not-tag24": "mso",
    "md-digest-value-modified": "digests", "md-digest-reencoded-item": "digests", "md-digest-id-absent": "digests",
    "md-digest-alg-sha1": "digests", "md-digest-length": "digests", "md-doctype-vs-mso": "docType",
    "md-sd-claim-absent": "requested claims", "md-sd-claim-sets-unmet": "requested claims",
    "md-sd-value-other": "requested claims",
}
_VERIFY_MDOC = []


def verify_mdoc(vector, settings):
    """lab/interop/mdoc/verify_mdoc.py (cbor2 and cryptography) over one DeviceResponse, offline, at the vector's
    instant, under its trust anchors and its inputs."""
    import datetime
    import importlib.util
    from cryptography import x509
    if not _VERIFY_MDOC:
        path = os.path.join(HERE, "..", "mdoc", "verify_mdoc.py")
        spec = importlib.util.spec_from_file_location("verify_mdoc", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _VERIFY_MDOC.append(module)
    vm = _VERIFY_MDOC[0]
    raw = base64.urlsafe_b64decode(vector["response"] + "=" * (-len(vector["response"]) % 4))
    roots = [x509.load_pem_x509_certificate(p.encode()) for p in vector["trust_anchors_pem"]]
    at = datetime.datetime.fromisoformat(vector["at"].replace("Z", "+00:00"))
    try:
        vm.verify(raw, vector["inputs"], roots, at)
    except vm.Refused as e:
        return "reject", str(e)
    return "accept", ""


def _es256_verifier(jwk):
    """verify(signing_input, signature, header) -> bool under one P-256 JWK; ES256 only, R||S (RFC 7518 s3.4)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    def coordinate(name):
        raw = jwk[name] + "=" * (-len(jwk[name]) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(raw), "big")
    key = ec.EllipticCurvePublicNumbers(coordinate("x"), coordinate("y"), ec.SECP256R1()).public_key()

    def verify(signing_input, signature, header):
        if not isinstance(header, dict) or header.get("alg") != "ES256" or len(signature) != 64:
            return False
        try:
            key.verify(encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")),
                       bytes(signing_input), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False
        return True
    return verify


def status_resolver(vector, settings):
    """polaris-oid4vp's status_resolver for one vector: the keys settings.status_list_keys states, and a fetch
    that answers `status_list.uri` with `status_list.response` from memory (None: no answer) and nothing else."""
    from polaris_oid4vp import status
    authority = status.StatedAuthority()
    for stated in settings.get("status_list_keys", []):
        authority.state(credential_issuer=stated["iss"], status_uri=stated["uri"], verify=_es256_verifier(stated["jwk"]),
                        why="stated in the vectors' settings.status_list_keys")
    served = vector["status_list"]

    def fetch(uri):
        if uri != served["uri"] or served["response"] is None:
            raise ConnectionError("no answer from %s" % uri)
        return served["response"].encode("utf-8")

    def resolve(*, uri, idx, issuer):
        return status.decide_by_fetching(index=idx, expected_uri=uri, authority=authority, fetch=fetch,
                                         now=settings["now"], credential_issuer=issuer)
    return resolve


def sd_jwt_python(vector, settings):
    """The Python reference implementation of RFC 9901 (PyPI `sd-jwt`): JOSE and SD-JWT. The SD-JWT VC
    profile, OpenID4VP and the issuer's x5c chain are its caller's to apply."""
    if vector["layer"] not in ("control", "jose", "sd-jwt"):
        return "n/a", "the %s layer is the caller's" % vector["layer"]
    from jwcrypto.jwk import JWK
    from sd_jwt.verifier import SDJWTVerifier
    key = JWK(**{k: v for k, v in settings["issuer_jwks"][0].items() if k in ("kty", "crv", "x", "y", "kid")})
    try:
        SDJWTVerifier(vector["presentation"], lambda issuer, header: key, expected_aud=settings["audience"],
                      expected_nonce=settings["nonce"]).get_verified_payload()
    except Exception as e:  # noqa: BLE001: the library refuses by raising
        return "reject", "%s: %s" % (type(e).__name__, " ".join(str(e).split())[:120])
    return "accept", ""


_JS = {}


def sd_jwt_js(vector, settings):
    """The OpenWallet Foundation's SD-JWT VC library for JavaScript, through adapters/sd_jwt_js.cjs (one
    Node run for the whole file). SD_JWT_JS_MODULES names the folder whose node_modules holds it."""
    if not _JS:
        import subprocess
        out = subprocess.run(["node", os.path.join(HERE, "adapters", "sd_jwt_js.cjs"), _JS_FILE[0]],
                             capture_output=True, text=True, check=True)
        _JS.update(json.loads(out.stdout))
    return tuple(_JS[vector["id"]])


_JS_FILE = []
ADAPTERS = {"polaris-oid4vp": polaris_oid4vp, "sd-jwt-python": sd_jwt_python, "sd-jwt-js": sd_jwt_js,
            "verify-mdoc": verify_mdoc}
CODED = {"polaris-oid4vp": POLARIS_OID4VP_CODES,  # adapters whose refusal code is compared too
         "verify-mdoc": VERIFY_MDOC_CHECKS}


def judge(adapter, vector, got, why):
    """True when the verdict (and, for a coded adapter, the refusal code) is the expected one; None for n/a."""
    if got == "n/a":
        return None
    if got != vector["expected"]:
        return False
    if got == "reject" and adapter in CODED:
        return why.split(":", 1)[0] == CODED[adapter].get(vector["id"])
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    ap.add_argument("vectors")
    ap.add_argument("--adapter", choices=sorted(ADAPTERS), required=True)
    ap.add_argument("--json", help="write the results here")
    args = ap.parse_args(argv)
    with open(args.vectors) as fh:
        doc = json.load(fh)
    if not doc.get("vectors"):
        print("%s holds no vectors: a run over none measures nothing" % args.vectors, file=sys.stderr)
        return 1
    _JS_FILE.append(os.path.abspath(args.vectors))
    run = ADAPTERS[args.adapter]
    results, wrong = [], []
    kind, layer = {}, {}  # per row id: its class and its layer
    rows = []
    for vector in doc["vectors"]:
        rows.append(vector)
        if "repaired" in vector:
            # The twin: the vector with its one defect put back, accepted (it carries its own response and inputs).
            rows.append(dict({k: v for k, v in vector.items() if k != "repaired"}, **vector["repaired"],
                             id=vector["id"] + "+repaired", expected="accept", **{"class": "repaired"}))
    for vector in rows:
        kind[vector["id"]], layer[vector["id"]] = vector["class"], vector["layer"]
        try:
            got, why = run(vector, doc["settings"])
        except Exception as e:  # noqa: BLE001: an adapter that cannot judge a vector stops the run
            print("could not run %s: %s: %s" % (vector["id"], type(e).__name__, e), file=sys.stderr)
            return 2
        ok = judge(args.adapter, vector, got, why)
        results.append({"id": vector["id"], "expected": vector["expected"], "got": got, "ok": ok, "reason": why})
        if ok is False and got == vector["expected"]:
            why = "expected code %s, got %s" % (CODED[args.adapter].get(vector["id"]), why)
        print("%-4s %-26s expected %-6s got %-6s %s" % ({True: "ok", False: "FAIL", None: "n/a"}[ok], vector["id"],
                                                       vector["expected"], got, why[:90]))
        if ok is False:
            wrong.append(vector["id"])
    # A control the adapter leaves to its caller (n/a) is not a refusal, and does not count as judged.
    controls = [r for r in results if kind[r["id"]] == "control" and r["ok"] is not None]
    negatives = [r for r in results if r["expected"] == "reject" and r["ok"] is not None]
    if not controls or not negatives:
        # No control means a verifier that refuses everything passes; no judged negative means nothing was refused.
        print("the run judged %d controls and %d negatives: it measured nothing" % (len(controls), len(negatives)),
              file=sys.stderr)
        return 1
    # A layer with its own control (accept-status-list for status-list) is measured only with that control: a
    # negative judged there while its control is left to the caller measured nothing.
    own = {}
    for r in results:
        if kind[r["id"]] == "control" and layer[r["id"]] != "control":
            own.setdefault(layer[r["id"]], []).append(r)
    for name, layer_controls in sorted(own.items()):
        judged_here = [r for r in negatives if layer[r["id"]] == name]
        if judged_here and not any(r["ok"] is not None for r in layer_controls):
            print("the %s layer: %d negatives judged and its control %s not: they measured nothing"
                  % (name, len(judged_here), ", ".join(r["id"] for r in layer_controls)), file=sys.stderr)
            return 1
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"adapter": args.adapter, "vectors_version": doc["version"], "results": results}, fh, indent=1)
    if any(r["ok"] is False for r in controls):
        print("a control was refused: the refusals above measured nothing", file=sys.stderr)
        return 1
    if any(r["ok"] is False for r in results if kind[r["id"]] == "repaired"):
        print("a repaired twin was refused: its vector's refusal measured nothing", file=sys.stderr)
        return 1
    judged = [r for r in results if r["ok"] is not None]
    print("%d of %d as expected; %d not applicable to this verifier" % (len(judged) - len(wrong), len(judged),
                                                                      len(results) - len(judged)))
    if wrong:
        return 1
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
