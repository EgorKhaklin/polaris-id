#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the no-signed-window cases (1.1.0).

A verifier answers `fresh` from the validity window an artifact's format SIGNS. Eight published
artifact types sign none, or only one end of one: the transparency STH, the timestamp, the
exchange request, receipt and mint statement, the signed document, the grant revocation and the
agent proof. Each case takes that type's published valid vector and adds `issued_at` and
`expires_at` beside the signature, outside the signed statement, with no new signature. A field
the format signs stays as signed, so a signed `issued_at` is not replaced:

    <type>-unsigned-window    authentic true, fresh null

The signed statement is exactly the listed fields (WIRE-SPEC 2.1), and an unsigned top-level
field is one a verifier ignores for its decision (section 6), so each artifact is as authentic
as its published vector and still signs no window. A verifier that read the added fields would
answer true or false at any clock, never null, so no case pins `now`.

Before anything is written, every signed statement is checked unchanged, and every expected
value against the detached verifier and the Python SDK, beside the control that a window read
from the added fields is true inside them and false after them. Never modifies a published
vector: it refuses to run when any of its files exists.

    python3 conformance/make_unsigned_window_cases.py
"""
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
VEC = "conformance/vectors/"
SINCE = "1.1.0"
ADDED = {"issued_at": "2026-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z"}
#: Each type, with the detached verifier's function for it and the key on its verdict that
#: means authentic (the conformance harness's `_SIGNED`).
KINDS = {
    "transparency-sth": ("verify_sth", "sth_authentic"),
    "timestamp": ("verify_timestamp", "timestamp_authentic"),
    "exchange-request": ("verify_exchange_request", "request_authentic"),
    "signed-document": ("verify_signed_document", "document_authentic"),
    "exchange-receipt": ("verify_exchange_receipt", "receipt_authentic"),
    "exchange-mint": ("verify_exchange_mint", "mint_authentic"),
    "grant-revocation": ("verify_grant_revocation", "authentic"),
    "agent-proof": ("verify_agent_proof", "authentic"),
}


def main():
    # Before anything is read: every file this writes is *-unsigned-window.json.
    existing = sorted(p.name for p in OUT.glob("*-unsigned-window.json"))
    if existing:
        print("refusing: %d of these vectors are published (%s); a published vector is frozen"
              % (len(existing), ", ".join(existing)), file=sys.stderr)
        return 2
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    sys.path.insert(0, str(ROOT / "sdk" / "python"))
    import polaris_verify as P  # noqa: E402

    files, cases = {}, []
    for kind, (fn_name, key) in KINDS.items():
        base = json.loads((OUT / ("%s-valid.json" % kind)).read_text(encoding="utf-8"))
        signed = P._ARTIFACT_KEYS[base["format"]]
        if ("issued_at" in signed and "expires_at" in signed) or ("iat" in signed and "exp" in signed):
            print("%s signs a window, so it is not a case here" % kind, file=sys.stderr)
            return 1
        add = {k: v for k, v in ADDED.items() if k not in signed}
        if not add or any(k in base for k in add):
            print("%s-valid already carries %s, so the case would not isolate the added fields"
                  % (kind, ", ".join(sorted(add))), file=sys.stderr)
            return 1
        obj = dict(base, **add)
        what = " and ".join("`%s`" % k for k in ADDED if k in add)
        if "_vector" in base:
            obj["_vector"] = dict(base["_vector"], name="%s-unsigned-window" % kind,
                                  note="the genuine vector with %s added after signing" % what.replace("`", ""))
        if P._canonical(obj, signed) != P._canonical(base, signed):
            print("%s: the added fields changed the signed statement" % kind, file=sys.stderr)
            return 1
        dv = getattr(V, fn_name)(obj)
        sv, sb = P.verify_signed_artifact(obj), P.verify_signed_artifact(base)
        got = (dv.get(key) is True, dv.get("fresh"), sv.authentic, sv.fresh, sb.authentic, sb.fresh)
        if got != (True, None, True, None, True, None):
            print("%s: a verifier disagrees (detached authentic, detached fresh, SDK authentic, SDK "
                  "fresh, published SDK authentic, published SDK fresh) = %r" % (kind, got), file=sys.stderr)
            return 1
        # The control: read as a window, the added fields answer at every clock, so a verifier
        # reading them reports a boolean where the case expects null.
        reading = (P._within_window(obj, "2026-10-21T00:00:00Z"), P._within_window(obj, "2100-01-01T00:00:00Z"))
        if reading != (True, False):
            print("%s: the added fields do not read as a window (%r), so the case would not "
                  "discriminate" % (kind, reading), file=sys.stderr)
            return 1
        name = "%s-unsigned-window" % kind
        files[name + ".json"] = obj
        kept = "" if len(add) == len(ADDED) else " Its signed `issued_at` is unchanged."
        cases.append({"name": name, "artifact": kind, "object_file": VEC + name + ".json",
                      "expect": {"authentic": True, "fresh": None}, "since": SINCE,
                      "note": "The published %s-valid vector with %s added after signing, outside the "
                              "signed statement.%s It is as authentic as before and still signs no "
                              "window, so `fresh` is null." % (kind, what, kept)})

    for name, o in files.items():
        (OUT / name).write_text(json.dumps(o, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    mine = {c["name"] for c in cases}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
