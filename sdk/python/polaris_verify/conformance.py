"""python -m polaris_verify.conformance -- the verifier CLI the conformance suite drives.

Reads ONE conformance case as JSON on stdin:

    {"pack": { ...authenticity pack... }, "anchors": ["<hex>", ...]  }   # anchors optional

and prints the offline AUTHENTICITY verdict as JSON on stdout:

    {"authentic": true|false, "issuer_trusted": true|false|null}

A conformant verifier in any language implements this same stdin->stdout contract;
conformance/run_conformance.py drives it over the published cases and checks every
verdict. See conformance/SPEC.md.
"""
import json
import sys

from . import verify_authenticity


def main(argv=None):
    try:
        case = json.load(sys.stdin)
    except Exception as e:
        print(json.dumps({"error": "could not read case: %s" % e}))
        return 2
    pack = case.get("pack") if isinstance(case, dict) and "pack" in case else case
    anchors = case.get("anchors") if isinstance(case, dict) else None
    v = verify_authenticity(pack or {}, anchors)
    print(json.dumps({"authentic": v.authentic, "issuer_trusted": v.issuer_trusted}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
