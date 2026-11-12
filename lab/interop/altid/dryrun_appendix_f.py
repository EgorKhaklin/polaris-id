# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The dry run, with no phone: the integration guide's own Appendix F response, read from the guide's text, through
avp.py and ../mdoc/verify_mdoc.py.

    pdftotext -layout GUIDE.pdf GUIDE.txt
    python3 -I dryrun_appendix_f.py GUIDE.txt

The guide is read from the path given and is never copied into the tree; nothing is written. It prints what the
example carries, then three runs:
  1. avp.py under trust/ (the Table 13 test certificate, pinned): its x5chain leaf is not in that trust list, so step
     5 refuses it;
  2. verify_mdoc.py with the example's own leaf as its root, at 2026-04-20 (inside the example's MSO validity): the
     issuer side passes, and the run prints the step that decides;
  3. the same, with the client_id's "redirect_uri:" prefix dropped (the control on the transcript's client_id).
Last line: "done".
"""
import datetime
import hashlib
import importlib.util
import os
import re
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("avp_dryrun", os.path.join(HERE, "avp.py"))
assert _spec and _spec.loader
avp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(avp)
vm = avp.vm
AT = datetime.datetime(2026, 4, 20, tzinfo=datetime.timezone.utc)


def example(lines):
    """The Appendix F vp_token (the lines after "&vp_token=" up to the first blank one) and its 10.1 request."""
    start = next(i for i, line in enumerate(lines) if line.strip() == "&vp_token=" and i > 2800)
    token = ""
    for line in lines[start + 1:]:
        if not line.strip():
            break
        token += line.strip()
    h101 = next(i for i, line in enumerate(lines) if line.strip() == "10.1 Authorization Request")
    a0 = next(i for i in range(h101, len(lines)) if lines[i].strip() == "av://?")
    req = "\n".join(lines[a0:a0 + 40])
    m_client = re.search(r"&client_id=\s*(redirect_uri:\S+)\s*\n\s*(\S+)", req)
    m_resp = re.search(r"&response_uri=\s*(\S+)\s*\n\s*(\S+)", req)
    m_nonce = re.search(r"&nonce=(\S+)", req)
    m_state = re.search(r"&state=(\S+)", req)
    if not (m_client and m_resp and m_nonce):
        raise SystemExit("the request text of 10.1 did not parse")
    return token, {"client_id": m_client.group(1) + m_client.group(2),
                   "response_uri": m_resp.group(1) + m_resp.group(2), "nonce": m_nonce.group(1),
                   "state": m_state.group(1) if m_state else None}, start + 2


def main(argv):
    if len(argv) != 2:
        sys.exit("usage: dryrun_appendix_f.py GUIDE.txt")
    with open(argv[1], "rb") as f:
        data = f.read()
    print("guide text: %d bytes, sha256 %s" % (len(data), hashlib.sha256(data).hexdigest()))
    # split on newlines only: splitlines() also breaks at pdftotext's form feeds
    lines = data.decode("utf-8").split("\n")
    token, request, first = example(lines)
    raw = avp.b64u_decode(token, "vp_token")
    print("vp_token: from text line %d, %d characters, %d bytes, sha256 %s" % (
        first, len(token), len(raw), hashlib.sha256(raw).hexdigest()))
    print("request: client_id == \"redirect_uri:\" + response_uri: %s" % (
        request["client_id"] == "redirect_uri:" + request["response_uri"]))
    doc = vm.load_all(raw)["documents"][0]
    _, prot, unprot, _, _ = vm.cose_sign1(doc["issuerSigned"]["issuerAuth"], "issuer signature")
    leaf = x509.load_der_x509_certificate(vm.x5chain_of(prot, unprot)[0])
    print("x5chain leaf: %s, issued by %s, SHA-256 %s, self-signed: %s" % (
        leaf.subject.rfc4514_string(), leaf.issuer.rfc4514_string(),
        hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest(), avp._self_signed(leaf)))
    trust = os.path.join(HERE, "trust")
    anchors = avp.anchors_from([os.path.join(trust, "dktb-test.pem")], avp.read_pins(os.path.join(trust, "PINS")))
    record = {"client_id": request["client_id"], "nonce": request["nonce"], "response_uri": request["response_uri"],
              "state": request["state"] or ""}
    form = {"vp_token": [token], "state": [request["state"] or ""]}

    print("== 1. avp.py, trust/ (Table 13 test certificate), at %s" % AT.date())
    try:
        avp.verify_avp(form, record, anchors, AT)
        print("VERIFIED")
    except avp.Refused as e:
        print("REFUSED    %s" % e)
    for n, client_id in ((2, request["client_id"]), (3, request["response_uri"])):
        print("== %d. verify_mdoc.py, root = the example's own leaf, client_id %s, at %s" % (
            n, "as the request carries it" if n == 2 else "without its prefix", AT.date()))
        inputs = {"client_id": client_id, "response_uri": request["response_uri"], "nonce": request["nonce"],
                  "response_mode": "direct_post", "encryption_jwk": None, "doctype_value": avp.DOCTYPE,
                  "claims": [{"path": [avp.NAMESPACE, avp.CLAIM]}]}
        try:
            vm.verify(raw, inputs, [leaf], AT, log=lambda c, d: print("  ok   %-18s %s" % (c, d[:100])),
                      enforce_profile=True)
            print("VERIFIED")
        except vm.Refused as e:
            print("REFUSED    %s" % e)
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
