#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/interop/negative-vectors/one_change.py: what differs, decoded, between a negative vector and the vector it
is measured against (its control, or for mdoc its repaired twin), as a list of paths.

    python3 one_change.py vectors.json        # each negative: the control it is pinned to and its paths
    python3 one_change.py mdoc-vectors.json   # each negative against its repaired twin

The view decodes what a verifier decodes: the issuer JWT, the disclosures and the KB-JWT of an SD-JWT; the CBOR of
a DeviceResponse with each tag 24 item, each COSE_Sign1 and its protected header; and each X.509 certificate in an
x5c or x5chain, field by field. Bytes a decoder normalises are kept beside the decoded value (a tag 24 item's
bytes, a protected header's bytes), so a re-encoding shows as a change. A list whose length changed is compared as
a multiset (elements added and removed). test_vectors.py pins each negative's paths: a second change, made on
purpose or not, adds a path.
"""
import base64
import datetime
import json
import re
import sys

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def certificate(der):
    """An X.509 certificate's fields, its signature as #SIG; None when der is not one."""
    try:
        c = x509.load_der_x509_certificate(der)
    except ValueError:
        return None
    extensions = {}
    for e in c.extensions:
        try:
            value = e.value.public_bytes().hex()
        except (AttributeError, NotImplementedError):
            value = repr(e.value)
        extensions[e.oid.dotted_string] = {"critical": e.critical, "value": value}
    return {"#cert.version": c.version.name, "#cert.serial": "%x" % c.serial_number,
            "#cert.issuer": c.issuer.rfc4514_string(), "#cert.subject": c.subject.rfc4514_string(),
            "#cert.notBefore": c.not_valid_before_utc.isoformat(), "#cert.notAfter": c.not_valid_after_utc.isoformat(),
            "#cert.spki": c.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo).hex(), "#cert.extensions": extensions,
            "#cert.sigalg": c.signature_algorithm_oid.dotted_string, "#SIG": c.signature.hex()}


def dec(x, depth=0):
    """A decoded, comparable view of one CBOR value."""
    if depth > 16:
        raise ValueError("nested deeper than 16")
    if isinstance(x, cbor2.CBORTag):
        if x.tag == 24 and isinstance(x.value, bytes):
            try:
                inner = dec(cbor2.loads(x.value), depth + 1)
            except (cbor2.CBORDecodeError, ValueError):
                return {"#tag24-raw": x.value.hex()}
            return {"#tag24": inner, "#tag24-bytes": x.value.hex()}
        return {"#tag%d" % x.tag: dec(x.value, depth + 1)}
    if isinstance(x, dict):
        return {repr(k): dec(v, depth + 1) for k, v in x.items()}
    if isinstance(x, list):
        # COSE_Sign1: [protected bstr, unprotected map, payload bstr or nil, signature bstr]
        if len(x) == 4 and isinstance(x[0], bytes) and isinstance(x[1], dict) and isinstance(x[3], bytes):
            protected = dec(cbor2.loads(x[0]), depth + 1) if x[0] else {}
            payload = x[2]
            if isinstance(payload, bytes):
                try:
                    payload = dec(cbor2.loads(payload), depth + 1)
                except (cbor2.CBORDecodeError, ValueError):
                    payload = payload.hex()
            else:
                payload = dec(payload, depth + 1)
            return {"#cose.protected": protected, "#cose.protected-bytes": x[0].hex(),
                    "#cose.unprotected": dec(x[1], depth + 1), "#cose.payload": payload, "#SIG": x[3].hex()}
        return [dec(v, depth + 1) for v in x]
    if isinstance(x, (datetime.date, datetime.datetime)):
        return x.isoformat()
    if isinstance(x, bytes):
        if x[:1] == b"\x30":
            cert = certificate(x)
            if cert is not None:
                return cert
        return x.hex()
    return x


def _canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"))


def paths(a, b, p=""):
    """Every path at which b differs from a. A key only one side has is `key(+)` (in b) or `key(-)` (in a); a list
    whose length changed is `[+N -M]`, the elements b adds and the ones it drops."""
    if type(a) is not type(b):
        return [p or "/"]
    if isinstance(a, dict):
        out = []
        for k in sorted(set(a) | set(b), key=str):
            if k not in a or k not in b:
                out.append(p + "/" + str(k) + ("(+)" if k in b else "(-)"))
            else:
                out += paths(a[k], b[k], p + "/" + str(k))
        return out
    if isinstance(a, list):
        if len(a) != len(b):
            left, right = [_canonical(v) for v in a], [_canonical(v) for v in b]
            added = sum(max(0, right.count(v) - left.count(v)) for v in set(right))
            dropped = sum(max(0, left.count(v) - right.count(v)) for v in set(left))
            return [p + "[+%d -%d]" % (added, dropped)]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += paths(x, y, p + "[%d]" % i)
        return out
    return [] if a == b else [p or "/"]


_X5C = re.compile(r"^(.*x5c(?:hain)?)\[(\d+)\]$")


def _parent(path, leaf):
    return path[: -len(leaf)] if path.endswith(leaf) else None


def _forced(path, ps):
    """True when `path` follows from another change in ps: a signature over changed content, a certificate
    re-issued for that reason (its new serial too, RFC 5280 4.1.2.2), the bytes of a decoded value that changed,
    the KB-JWT's sd_hash over a changed issuer JWT or disclosures, an _sd digest of a changed disclosure."""
    others = [q for q in ps if q != path]
    for leaf in ("/#SIG", "/sig"):
        parent = _parent(path, leaf)
        if parent is None:
            continue
        under = [q for q in others if q.startswith(parent + "/") and not q.endswith("/#cert.serial")]
        if under:
            return True
        chain = _X5C.match(parent)
        if chain:  # a certificate whose issuer, higher in the chain, changed is re-issued
            base, index = chain.group(1), int(chain.group(2))
            for q in others:
                m = re.match(re.escape(base) + r"\[(\d+)\]/(.*)$", q)
                if m and int(m.group(1)) > index and not _consequence(q):
                    return True
        return False
    parent = _parent(path, "/#cert.serial")
    if parent is not None:
        return _forced(parent + "/#SIG", ps) if parent + "/#SIG" in ps else False
    for leaf, decoded in (("/#tag24-bytes", "/#tag24"), ("/#tag24-bytes(-)", "/#tag24"),
                          ("/#cose.protected-bytes", "/#cose.protected/")):
        parent = _parent(path, leaf)
        if parent is not None:
            return any(q.startswith(parent + decoded) for q in others)
    if path == "/kb/payload/sd_hash":
        return any(q.startswith("/issuer/") or q.startswith("/disclosures") for q in others)
    if re.match(r"^/issuer/payload/_sd(\[\d+\]|\[\+\d+ -\d+\])$", path):
        return any(q.startswith("/disclosures") for q in others)
    return False


def _consequence(path):
    return bool(re.search(r"(/#SIG|/sig|/#cert\.serial|-bytes|-bytes\(-\)|^/kb/payload/sd_hash|^/issuer/payload/_sd.*)$", path))


def split(ps):
    """(changed, forced): the paths that are the vector's own change, and those that follow from it."""
    forced = [q for q in ps if _consequence(q) and _forced(q, ps)]
    return [q for q in ps if q not in forced], forced


def jwt(token):
    h, p, s = token.split(".")
    return {"header": json.loads(b64d(h)), "payload": json.loads(b64d(p)), "sig": s}


def sdjwt_view(v):
    parts = v["presentation"].split("~")
    issuer = jwt(parts[0])
    if isinstance(issuer["header"].get("x5c"), list):
        issuer["header"]["x5c"] = [certificate(base64.b64decode(c)) or c for c in issuer["header"]["x5c"]]
    out = {"issuer": issuer, "disclosures": [json.loads(b64d(d)) for d in parts[1:-1]],
           "kb": jwt(parts[-1]) if parts[-1] else None, "trust": v["trust"]}
    if "status_list" in v:
        listed = dict(v["status_list"])
        if isinstance(listed.get("response"), str) and listed["response"].count(".") == 2:
            try:
                listed["response"] = jwt(listed["response"])
            except ValueError:
                pass
        out["status_list"] = listed
    return out


def mdoc_view(v):
    return {"response": dec(cbor2.loads(b64d(v["response"]))), "inputs": v["inputs"], "at": v["at"],
            "trust_anchors_pem": v["trust_anchors_pem"]}


def reference(doc, vector, against):
    """The vector `against` names: a control's id, or "+repaired" for the vector's own repaired twin."""
    if against == "+repaired":
        return dict(vector, **vector["repaired"])
    return next(v for v in doc["vectors"] if v["id"] == against and v["class"] == "control")


def one_change(doc, vector, against):
    view = mdoc_view if "response" in vector else sdjwt_view
    return paths(view(reference(doc, vector, against)), view(vector))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    with open(argv[0]) as fh:
        doc = json.load(fh)
    controls = [v for v in doc["vectors"] if v["class"] == "control"]
    if not controls:
        print("%s holds no control" % argv[0], file=sys.stderr)
        return 1
    out = {}
    for vector in doc["vectors"]:
        if vector["expected"] != "reject":
            continue
        if "repaired" in vector:
            against = "+repaired"
        else:
            # The nearest control of the vector's own trust mode: a vector is measured under the trust it is
            # judged under.
            same = [c["id"] for c in controls if c.get("trust") == vector.get("trust")]
            if not same:
                print("%s: no control of trust mode %r" % (vector["id"], vector.get("trust")), file=sys.stderr)
                return 1
            against = min(same, key=lambda c: len(one_change(doc, vector, c)))
        changed, forced = split(one_change(doc, vector, against))
        out[vector["id"]] = {"against": against, "changed": changed, "forced": forced}
    if not out:
        print("%s holds no negative" % argv[0], file=sys.stderr)
        return 1
    json.dump(out, sys.stdout, indent=1)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
