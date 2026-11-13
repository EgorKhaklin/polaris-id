#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The three outside witnesses over this folder's vectors, as jobs, and the step table that names, step by step, which
of them agreed with avp.py.

    python3 -I witness_jobs.py prepare WORK [--guide GUIDE.txt]   writes WORK/jobs.json, WORK/isomdl/, WORK/inputs/
    python3 -I witness_jobs.py table RESULTS                       the step table, from RESULTS (witness.sh writes it)

The jobs are in ../mdoc/witness-eudi's format, so Witness.kt and witness_owf.mjs read them unchanged. Each also names
the case's expected verdict, and has a directory under WORK/isomdl/ in the input format ../mdoc/witness_isomdl.py
reads. With --guide, two more jobs come from the integration guide's Appendix F example, read from the text given; its
bytes go only into WORK, never into the tree.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization

HERE = pathlib.Path(__file__).resolve().parent
VECTORS = HERE / "vectors"
APPENDIX_F_AT = "2026-04-20T12:00:00Z"  # inside the example's MSO validity (2026-04-07 to 2026-05-07)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, path
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


avp = _load("avp_witness", HERE / "avp.py")
vm = avp.vm


def _handover(inputs):
    return {"client_id": inputs["client_id"], "nonce": inputs["nonce"], "jwk": None,
            "response_uri": inputs["response_uri"]}


def _isomdl_case(work, n, raw, handover):
    d = work / "isomdl" / str(n)
    d.mkdir(parents=True)
    (d / "device-response.cbor").write_bytes(raw)
    (d / "openid4vp-inputs.json").write_text(json.dumps(
        {"client_id": handover["client_id"], "nonce": handover["nonce"], "response_uri": handover["response_uri"]}))
    return "/cases/%d" % n


def _has_x5chain(raw):
    """Whether the first document's IssuerAuth carries a certificate (avp.py refuses one with none before step 5's
    trust-list check)."""
    try:
        doc = vm.load_all(raw)["documents"][0]
        _, prot, unprot, _, _ = vm.cose_sign1(doc["issuerSigned"]["issuerAuth"], "issuer signature")
        return bool(vm.x5chain_of(prot, unprot))
    except vm.Refused:
        return False


def vector_jobs(work):
    manifest = json.loads((VECTORS / "manifest.json").read_text())
    if not manifest["cases"]:
        sys.exit("the manifest names no case")
    handover = _handover(manifest["inputs"])
    jobs = []
    for case in manifest["cases"]:
        name = case["name"]
        raw = (VECTORS / name / "device-response.cbor").read_bytes()
        jobs.append({
            "name": name, "capture": "vectors", "case": name, "at": case["at"], "expected": case["expected"],
            "response": "/captures/%s/device-response.cbor" % name,
            "roots": ["/captures/certs/%s.pem" % p for p in case["pins"]],
            "handover": handover, "sha256": hashlib.sha256(raw).hexdigest(),
            "isomdl_case": _isomdl_case(work, len(jobs), raw, handover),
        })
    # Each case again with no roots: E then runs its shipped fallback (IsChainTrustedForContextF.Ignored), which
    # keeps every check but trust; ours refuses at step 5, since an empty trust list trusts nothing, unless it refused
    # the case before step 5.
    for j in list(jobs):
        raw = (VECTORS / j["case"] / "device-response.cbor").read_bytes()
        before5 = j["expected"] in ("vp_token", "device response", "requested docType") or not _has_x5chain(raw)
        jobs.append(dict(j, name=j["name"] + " (no roots)", case=j["case"] + " (no roots)", roots=[],
                         expected=j["expected"] if before5 else "trust list",
                         isomdl_case=_isomdl_case(work, len(jobs), raw, handover)))
    return jobs


def appendix_f_jobs(work, guide, first):
    dry = _load("dryrun_witness", HERE / "dryrun_appendix_f.py")
    lines = pathlib.Path(guide).read_bytes().decode("utf-8").split("\n")  # newlines only, as the dry run splits
    token, request, _ = dry.example(lines)
    raw = avp.b64u_decode(token, "vp_token")
    d = work / "inputs" / "appendix-f"
    d.mkdir(parents=True)
    (d / "device-response.cbor").write_bytes(raw)
    doc = vm.load_all(raw)["documents"][0]
    _, prot, unprot, _, _ = vm.cose_sign1(doc["issuerSigned"]["issuerAuth"], "issuer signature")
    leaf = x509.load_der_x509_certificate(vm.x5chain_of(prot, unprot)[0])
    (d / "example-leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    shutil.copy(HERE / "trust" / "dktb-test.pem", d / "table13.pem")
    handover = _handover(request)
    jobs = []
    for case, root, expected in (("example leaf as root", "example-leaf.pem", "trust list"),
                                 ("Table 13 as root", "table13.pem", "trust list")):
        jobs.append({
            "name": "appendix-f: " + case, "capture": "appendix-f", "case": case, "at": APPENDIX_F_AT,
            "expected": expected, "response": "/inputs/appendix-f/device-response.cbor",
            "roots": ["/inputs/appendix-f/" + root], "handover": handover, "sha256": hashlib.sha256(raw).hexdigest(),
            "isomdl_case": _isomdl_case(work, first + len(jobs), raw, handover),
        })
    return jobs


def prepare(work, guide=None):
    work = pathlib.Path(work)
    for sub in ("isomdl", "inputs"):
        if (work / sub).exists():
            sys.exit("%s already exists: give an empty WORK" % (work / sub))
    (work / "inputs").mkdir(parents=True)
    jobs = vector_jobs(work)
    if guide:
        jobs += appendix_f_jobs(work, guide, len(jobs))
    (work / "jobs.json").write_text(json.dumps(jobs, indent=1) + "\n")
    print("prepared   %d cases" % len(jobs))


# --- the step table -------------------------------------------------------------------------------------------------

# Appendix D's steps as the table names them. 5a: the last certificate is in the trust list and the chain to it holds;
# 5b: that certificate is self-signed.
STEPS = [("transcript", "12, the SessionTranscript bytes"), ("format", "1-4, the DeviceResponse"),
         ("requested_doctype", "4, the requested docType"), ("trust", "5a, trust list and chain"),
         ("self_signed", "5b, self-signed"), ("mso_signature", "6, issuer signature"), ("digests", "7-8, digests"),
         ("doctype", "9, MSO docType"), ("validity", "10, validity"), ("status", "11, no status element"),
         ("device_signature", "12, device signature")]
OURS_STAGE = {"vp_token": "format", "device response": "format", "requested docType": "requested_doctype",
              "issuer chain": "trust", "issuer signature": "mso_signature", "digests": "digests", "docType": "doctype",
              "validity": "validity", "status": "status", "device signature": "device_signature"}
# What each witness's own code decides, and so what it is counted for. O's status check is left out: offline, it
# fails because it cannot fetch the status list, which is not the lab's rule (a Proof of Age carries no status).
COUNTED = {"O": ("format", "trust", "mso_signature", "digests", "doctype", "validity", "device_signature"),
           "E": ("format", "trust", "mso_signature", "digests", "doctype", "validity", "device_signature")}

# Every difference found, by (case pattern, stage, witness): its reason. Any other difference is a disagreement.
CLASSIFIED = {
    (r"two-documents.*", "format", "O"):
        "O verifies each document and has no one-document rule; that rule is the profile's (step 4)",
    (r"certificate-expired", "trust", "O"):
        "O judges certificate validity at the real clock: witness_owf.mjs's chain callback passes no date to verify, "
        "and skips the trusted certificate itself, so it witnesses no certificate validity at the case's instant",
    (r"empty-x5chain.*", "format", "O"): "O stops with an exception on an empty x5chain; ours refuses at the chain",
    (r"two-documents.*", "format", "E"):
        "E verifies each document and has no one-document rule; that rule is the profile's (step 4)",
    (r"no-documents.*", "format", "E"):
        "E accepts a DeviceResponse with status 0 and no documents; the one-document rule is the profile's (step 4)",
    (r"empty-x5chain.*", "format", "E"):
        "E's trust check throws on an empty x5chain (X5CNotTrusted, Missing x5Chain); ours refuses at the chain",
}


def _host(path, inputs):
    """A path the witnesses see, on this machine: /captures is vectors/, /inputs is the run's WORK/inputs."""
    for ref, base in (("/captures/", VECTORS), ("/inputs/", inputs)):
        if path.startswith(ref):
            if base is None:
                sys.exit("%s needs --inputs (the run's WORK/inputs)" % path)
            return pathlib.Path(base) / path[len(ref):]
    sys.exit("%s is neither under /captures nor under /inputs" % path)


def _ours(job, inputs):
    """avp.py on the case, as test_avp judges it: its stages, then verify_mdoc.verify_document with the last x5chain
    certificate as root for the steps after a refusal at 4 or 5 (marked "diag"), and the transcript bytes."""
    raw = _host(job["response"], inputs).read_bytes()
    if hashlib.sha256(raw).hexdigest() != job["sha256"]:
        sys.exit("%s: the response on this machine is not the one the witnesses ran" % job["name"])
    anchors = [x509.load_pem_x509_certificate(_host(r, inputs).read_bytes()) for r in job["roots"]]
    h = job["handover"]
    record = {"txid": "w", "state": "w", "nonce": h["nonce"], "response_uri": h["response_uri"],
              "client_id": h["client_id"], "flow": "qr", "browser": None, "status": "open"}
    inputs = {"client_id": h["client_id"], "nonce": h["nonce"], "response_uri": h["response_uri"],
              "response_mode": "direct_post", "encryption_jwk": None}
    transcript, _ = vm.session_transcript(inputs)
    at = datetime.datetime.fromisoformat(job["at"].replace("Z", "+00:00"))
    stages, passed = {}, []
    try:
        verdict = avp.verify_avp({"vp_token": [avp.b64u(raw)], "state": ["w"]}, record, anchors, at,
                                 log=lambda c, d: passed.append((c, d)))
        result = "satisfied" if verdict["satisfied"] else "not satisfied"
        failed = None
    except avp.Refused as e:
        result, failed = "REFUSED %s" % e.check, e
    for c, d in passed:
        if c == "trust list":
            stages.update(trust="ok", self_signed="ok")
        elif c in OURS_STAGE:
            stages.setdefault(OURS_STAGE[c], "ok")
    if failed is not None:
        if failed.check == "trust list":
            stages["self_signed" if "not self-signed" in str(failed) else "trust"] = "FAIL"
        else:
            stages[OURS_STAGE.get(failed.check, "format")] = "FAIL"
        if failed.check not in ("vp_token", "device response"):
            stages.setdefault("format", "ok")
        if failed.check not in ("vp_token", "device response", "requested docType"):
            stages.setdefault("requested_doctype", "ok")
    else:
        stages.update(format="ok", requested_doctype="ok", status="ok")
    diag = {}
    if failed is not None and failed.check in ("device response", "requested docType", "trust list"):
        try:
            doc = vm.load_all(raw)["documents"][0]
            _, prot, unprot, _, _ = vm.cose_sign1(doc["issuerSigned"]["issuerAuth"], "issuer signature")
            last = x509.load_der_x509_certificate(vm.x5chain_of(prot, unprot)[-1])
            try:
                vm.verify_document(doc, transcript, [last], at, lambda c, d: diag.setdefault(OURS_STAGE.get(c), "ok"),
                                   enforce_profile=True)
            except vm.Refused as e:
                diag[OURS_STAGE.get(e.check, "format")] = "FAIL"
        except (IndexError, KeyError, ValueError, TypeError, vm.Refused):
            pass
        diag.pop(None, None)
        diag.pop("trust", None)  # its root is the last certificate itself, so it says nothing about the case's roots
    return {"result": result, "stages": stages, "diag": diag,
            "transcript_hex": vm.cbor2.dumps(transcript).hex()}


def _o(rec, eud):
    stages = {}
    for c in rec.get("checks", []):
        s = "status" if c["check"].startswith("Status information must be valid") else eud.owf_stage(c["check"])
        if c["status"] == "FAILED":
            stages[s] = "FAIL"
        elif c["status"] == "PASSED":
            stages.setdefault(s, "ok")
    if rec["outcome"] == "exception":
        stages["format"] = "FAIL"
    return {"stages": stages, "transcript_hex": rec.get("transcript_hex"), "note": None}


def _e(rec, eud):
    if rec.get("outcome") == "exception" and "Attestation Classification" in rec.get("exception", ""):
        return {"stages": {}, "transcript_hex": rec.get("transcript_hex"),
                "note": "E has no attestation classification for this docType, and stops before any check"}
    r = eud.eu(rec)
    stages = dict(r["stages"])
    stages.update(r["waltid"])  # walt.id's checks: they count here, since walt.id built none of these inputs
    if rec.get("outcome") == "accepted":
        stages.setdefault("format", "ok")
    elif str(rec.get("error", "")).startswith("NotOkDeviceResponseStatus"):
        stages["format"] = "FAIL"
    note = None
    if any(t.get("verdict") == "NoClassification" for t in rec.get("trust", [])):
        stages.pop("trust", None)  # no attestation classification: E made no trust judgment
        note = "E has no attestation classification for this docType, so it judges no trust"
    return {"stages": stages, "transcript_hex": r["transcript_hex"], "note": note}


def _i(rec):
    if "exception" in rec:
        return {"stages": {}, "transcript_hex": None, "note": "I refuses at parsing: " + rec["exception"][:90]}
    return {"stages": {"device_signature": "ok" if rec.get("device_authentication") == "VALID" else "FAIL"},
            "transcript_hex": None, "note": "I's issuer_authentication: %s" % rec.get("issuer_authentication")}


def _classified(case, stage, witness):
    for (cp, st, w), reason in CLASSIFIED.items():
        if st == stage and w == witness and re.fullmatch(cp, case):
            return reason
    return None


def table(results, inputs=None):
    results = pathlib.Path(results)
    eud = _load("witness_eudi", HERE.parent / "mdoc" / "witness-eudi" / "test_witness_eudi.py")
    jobs = json.loads((results / "jobs.json").read_text())
    if not jobs:
        sys.exit("no cases in %s" % (results / "jobs.json"))

    def lines(name):
        out = {}
        for line in (results / name).read_text().splitlines():
            r = json.loads(line)
            out[r["name"]] = r
        return out

    raw = {"O": lines("owf.jsonl"), "E": lines("eu.jsonl"), "I": lines("isomdl.jsonl")}
    for w, recs in raw.items():
        missing = [j["name"] for j in jobs if j["name"] not in recs]
        if missing:
            sys.exit("%s has no result for %d case(s), the first %r" % (w, len(missing), missing[0]))
    for w in ("O", "E"):  # a dropped root is never agreement
        for j in jobs:
            if raw[w][j["name"]].get("roots") != len(j["roots"]):
                sys.exit("%s saw %r roots on %r, the case has %d" % (w, raw[w][j["name"]].get("roots"), j["name"],
                                                                      len(j["roots"])))
    tally = {s: {"ours": 0, "O": [0, 0, 0], "E": [0, 0, 0], "I": [0, 0, 0]} for s, _ in STEPS}
    disagreements, notes = [], set()
    print("case | step | ours | O | E | I | result")
    for j in jobs:
        o = _ours(j, inputs)
        if o["result"] != j["expected"] and not o["result"].endswith(" " + j["expected"]):
            sys.exit("ours gives %r on %r, the manifest says %r" % (o["result"], j["name"], j["expected"]))
        ws = {"O": _o(raw["O"][j["name"]], eud), "E": _e(raw["E"][j["name"]], eud), "I": _i(raw["I"][j["name"]])}
        for w, r in ws.items():
            if r["note"]:
                notes.add("%s: %s" % (w, r["note"]))
        for stage, _ in STEPS:
            if stage == "transcript":
                ov = "bytes"
                vals = {w: (None if r["transcript_hex"] is None else "equal" if r["transcript_hex"] == o["transcript_hex"]
                            else "DIFFERENT") for w, r in ws.items()}
            else:
                ov = o["stages"].get(stage) or (o["diag"].get(stage) and o["diag"][stage] + " (diag)")
                vals = {w: (r["stages"].get(stage) if w == "I" or stage in COUNTED[w] else None) for w, r in ws.items()}
            if ov is None and not any(v in ("ok", "FAIL") for v in vals.values()):
                continue
            base = None if ov is None else ov.split(" ")[0]
            agree, result = [], []
            if base in ("ok", "FAIL", "bytes"):
                tally[stage]["ours"] += 1
            for w, v in vals.items():
                if v not in ("ok", "FAIL", "equal", "DIFFERENT"):  # None, or E's "not witnessed": no judgment
                    continue
                want = "equal" if stage == "transcript" else base
                if want is None:
                    result.append("%s %s (ours not reached)" % (w, v))
                elif v == want:
                    agree.append(w)
                    tally[stage][w][0] += 1
                else:
                    reason = _classified(j["case"], stage, w)
                    if reason:
                        tally[stage][w][1] += 1
                        result.append("%s differs, classified: %s" % (w, reason))
                    else:
                        tally[stage][w][2] += 1
                        disagreements.append((j["name"], stage, w, v, ov))
                        result.append("DISAGREE: %s says %s, ours %s" % (w, v, ov))
            if agree:
                result.insert(0, "agree (%s)" % ",".join(agree))
            elif not result:
                result.append("ours only")
            print("%s | %s | %s | %s | %s | %s | %s" % (j["name"], stage, ov, vals["O"], vals["E"], vals["I"],
                                                         "; ".join(result)))
    print()
    print("step | judged by ours | O agrees, classified, DISAGREES | E the same | I the same")
    for stage, label in STEPS:
        t = tally[stage]
        print("%s | %d | %s | %s | %s" % (label, t["ours"], "%d, %d, %d" % tuple(t["O"]), "%d, %d, %d" % tuple(t["E"]),
                                          "%d, %d, %d" % tuple(t["I"])))
    for n in sorted(notes):
        print("note: " + n)
    print("RESULT: %d disagreement(s) unclassified, over %d cases" % (len(disagreements), len(jobs)))
    return 1 if disagreements else 0


def main(argv):
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("prepare")
    pp.add_argument("work")
    pp.add_argument("--guide")
    pt = sub.add_parser("table")
    pt.add_argument("results")
    pt.add_argument("--inputs", help="the run's WORK/inputs, for cases under /inputs (the Appendix F example)")
    a = p.parse_args(argv[1:])
    if a.cmd == "prepare":
        prepare(a.work, a.guide)
        return 0
    return table(a.results, a.inputs)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
