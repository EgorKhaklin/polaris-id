"""python -m polaris_verify.conformance -- the verifier CLI the conformance suite drives.

Reads ONE conformance case as JSON on stdin and prints a verdict as JSON on stdout. The case
names the artifact it is about; a verifier dispatches on it:

    {"artifact": "authenticity-pack", "pack": {...}, "anchors": ["<hex>", ...]}
        -> {"authentic": bool, "issuer_trusted": bool|null}
    {"artifact": "status-assertion", "assertion": {...}, "now": "<iso8601>"}
        -> {"authentic": bool, "fresh": bool|null, "active": bool|null}
    {"artifact": "<epoch-checkpoint|revocation-feed|federation-manifest|
                  federation-status-bundle|transparency-sth>", "object": {...}, "now": "<iso8601>"}
        -> {"authentic": bool, "fresh": bool|null}

For backward compatibility a case with no `artifact` is an authenticity pack. A conformant
verifier in any language implements this same stdin->stdout contract; conformance/run_conformance.py
drives it over the published cases and checks every verdict. See conformance/SPEC.md.
"""
import json
import sys

from . import (verify_authenticity, verify_cross_authority, verify_signed_artifact,
               verify_status_assertion)

_SIGNED_ARTIFACTS = {"epoch-checkpoint", "revocation-feed", "federation-manifest",
                     "federation-status-bundle", "transparency-sth", "timestamp", "registry", "exchange-request", "signed-document", "id-token"}


def main(argv=None):
    try:
        case = json.load(sys.stdin)
    except Exception as e:
        print(json.dumps({"error": "could not read case: %s" % e}))
        return 2
    if not isinstance(case, dict):
        case = {"pack": case}
    artifact = case.get("artifact", "authenticity-pack")
    if artifact == "authenticity-pack":
        pack = case.get("pack") if "pack" in case else case
        v = verify_authenticity(pack or {}, case.get("anchors"))
        print(json.dumps({"authentic": v.authentic, "issuer_trusted": v.issuer_trusted}))
        return 0
    if artifact == "status-assertion":
        v = verify_status_assertion(case.get("assertion") or {}, now=case.get("now"))
        print(json.dumps({"authentic": v.authentic, "fresh": v.fresh, "active": v.active}))
        return 0
    if artifact in _SIGNED_ARTIFACTS:
        v = verify_signed_artifact(case.get("object") or {}, now=case.get("now"))
        print(json.dumps({"authentic": v.authentic, "fresh": v.fresh}))
        return 0
    if artifact == "cross-authority":
        v = verify_cross_authority(case.get("pack") or {}, case.get("context_id"),
                                   case.get("manifests") or [], trusted_anchors=case.get("trusted_anchors"),
                                   revocation_feed=case.get("revocation_feed"), now=case.get("now"))
        print(json.dumps({"decision": v.decision, "authentic": v.authentic, "issuer_trusted": v.issuer_trusted}))
        return 0
    print(json.dumps({"error": "unknown artifact: %s" % artifact}))
    return 2


if __name__ == "__main__":
    sys.exit(main())
