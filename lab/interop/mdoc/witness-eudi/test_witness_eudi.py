# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Plan 025 M1b: M1's three captures judged by two outside witnesses, compared with verify_mdoc.py.

    python3 -I test_witness_eudi.py prepare WORK   # the cases, as files, for run.sh
    python3 -I test_witness_eudi.py [-v]           # the comparison, over results/ (run.sh writes it)
    python3 -I test_witness_eudi.py table          # the stage table in results.md

Witnesses, each counted only for the stages its own code decides:
  eu   the EU reference verifier (eudi-srv-verifier-endpoint v0.12.0), Witness.kt: the
       SessionTranscript bytes its toHandover() builds, its PKIX trust (msoMdocIssuance), and its
       validity verdict. Its decoding, MSO signature, digests and device signature are walt.id's,
       the library that built the captures: reported, never counted.
  owf  @owf/mdoc 0.8.3, witness_owf.mjs: its own SessionTranscript.forOid4Vp bytes, and every check
       of Verifier.verifyDeviceResponse against that transcript (MSO signature, digests, validity,
       docType, device signature, the chain to the given roots, the DS certificate's countryName).

Every case carries its roots. A witness that saw fewer roots than the case holds fails the run: a
dropped root is never reported as agreement. With no roots, the EU verifier falls back to its
shipped default (IsChainTrustedForContextF.Ignored, which trusts any chain), so its trust verdict
there is "not witnessed". Every disagreement must be in CLASSIFIED; any other fails the run.
Needs cbor2 and cryptography (../requirements.txt). The witnesses' outputs are in results/.
"""
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
import unittest

from cryptography import x509

HERE = pathlib.Path(__file__).resolve().parent
MDOC = HERE.parent
RESULTS = pathlib.Path(os.environ.get("WITNESS_EUDI_RESULTS", HERE / "results"))
CAPTURES = ("capture-pid", "capture-mdl", "capture-mdl-direct-post")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vm = _load("verify_mdoc", MDOC / "verify_mdoc.py")
ck = _load("mdoc_checks", MDOC / "checks.py")  # its mutations and its unrelated root, as M1 ran them

MUTATIONS = {  # name -> (pick, offset, value), exactly checks.py's
    "flipped": (lambda d: ck.issuer_auth(d)[3], -1, None),
    "bad-der": (ck.first_cert, 0, 0x31),
    "bad-header": (ck.protected_in_context, len(ck.PROT_PREFIX), 0xFF),
}
PID, MDL = "eu.europa.ec.eudi.pid.1", "org.iso.18013.5.1.mDL"


def changed_value(buf):
    """One disclosed element's value changed and its IssuerSignedItemBytes re-encoded; the MSO,
    and so its digests and signature, kept as they are."""
    item = next(iter(vm.load_all(buf)["documents"][0]["issuerSigned"]["nameSpaces"].values()))[0]
    isi = vm.cbor2.loads(item.inner)
    if vm.cbor2.dumps(isi) != item.inner or not isinstance(isi.get("elementValue"), str):
        sys.exit("the first IssuerSignedItem does not re-encode to itself, or its value is not text")
    v = isi["elementValue"]
    isi["elementValue"] = v[:-1] + ("X" if v[-1:] != "X" else "Y")
    if buf.count(item.raw) != 1:
        sys.exit("cannot locate the IssuerSignedItemBytes uniquely")
    return buf.replace(item.raw, vm.cbor2.dumps(vm.cbor2.CBORTag(24, vm.cbor2.dumps(isi))))


def relabeled(buf):
    """The document's docType swapped between the PID's and the mDL's (both classified by the EU
    verifier, so its trust check still runs); the MSO's docType, inside the signed payload, kept."""
    doc = vm.load_all(buf)["documents"][0]
    old = vm.cbor2.dumps("docType") + vm.cbor2.dumps(doc["docType"])
    new = vm.cbor2.dumps("docType") + vm.cbor2.dumps(MDL if doc["docType"] == PID else PID)
    payload = ck.issuer_auth(doc)[2]
    start = buf.find(payload)
    hits = [i for i in range(len(buf)) if buf.startswith(old, i) and not start <= i < start + len(payload)]
    if len(hits) != 1:
        sys.exit("cannot locate the document's docType uniquely")
    return buf[:hits[0]] + new + buf[hits[0] + len(old):]


REENCODED = {"value": changed_value, "doctype": relabeled}


def mutated(capture, name, out_dir):
    """The capture's DeviceResponse with mutation `name`; returns its path."""
    dst = out_dir / capture / ("%s.cbor" % name)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if name in REENCODED:
        dst.write_bytes(REENCODED[name]((MDOC / capture / "device-response.cbor").read_bytes()))
        return dst
    pick, offset, value = MUTATIONS[name]
    with tempfile.TemporaryDirectory() as t:
        ck.mutate(MDOC / capture, pathlib.Path(t) / "m", pick, offset, value)
        shutil.copy(pathlib.Path(t) / "m" / "device-response.cbor", dst)
    return dst


def validity(capture):
    """The MSO's validFrom and validUntil."""
    doc = vm.load_all((MDOC / capture / "device-response.cbor").read_bytes())["documents"][0]
    vi = vm.load_all(vm.load_all(ck.issuer_auth(doc)[2]).inner)["validityInfo"]
    return vm.tdate(vi["validFrom"], "validFrom"), vm.tdate(vi["validUntil"], "validUntil")


def instant(d):
    return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cases(inputs_dir, captures_ref="/captures", inputs_ref="/inputs"):
    """Every case, with the paths the witnesses see (captures_ref, inputs_ref) and the host paths."""
    out = []
    for c in CAPTURES:
        d = MDOC / c
        inp = json.loads((d / "openid4vp-inputs.json").read_text())
        at = (d / "captured-at.txt").read_text().strip()
        root = ("%s/%s/iaca-root.pem" % (captures_ref, c), d / "iaca-root.pem")
        unrelated = ("%s/unrelated-root.pem" % inputs_ref, inputs_dir / "unrelated-root.pem")
        genuine = ("%s/%s/device-response.cbor" % (captures_ref, c), d / "device-response.cbor")

        def mut(n, c=c):
            return ("%s/%s/%s.cbor" % (inputs_ref, c, n), inputs_dir / c / ("%s.cbor" % n))

        day = datetime.timedelta(days=1)
        valid_from, valid_until = validity(c)
        rows = [
            ("genuine", genuine, [root], None, False, at),
            ("another nonce", genuine, [root], "x" + inp["nonce"], False, at),
            ("no root", genuine, [], None, False, at),
            ("unrelated root", genuine, [unrelated], None, False, at),
            ("flipped MSO signature byte", mut("flipped"), [root], None, False, at),
            ("bad DER x5chain certificate", mut("bad-der"), [root], None, False, at),
            ("bad protected header", mut("bad-header"), [root], None, False, at),
            ("one element value changed", mut("value"), [root], None, False, at),
            ("judged after validUntil", genuine, [root], None, False, instant(valid_until + day)),
            ("judged before validFrom", genuine, [root], None, False, instant(valid_from - day)),
            ("docType relabeled", mut("doctype"), [root], None, False, at),
        ]
        if inp["response_mode"] == "direct_post.jwt":
            rows.insert(2, ("null thumbprint", genuine, [root], None, True, at))
        for name, (resp_ref, resp_host), roots, nonce, null, when in rows:
            out.append({
                "name": "%s: %s" % (c, name), "capture": c, "case": name, "at": when,
                "response": resp_ref, "response_host": str(resp_host),
                "roots": [r for r, _ in roots], "roots_host": [str(h) for _, h in roots],
                "handover": {
                    "client_id": inp["client_id"], "nonce": nonce or inp["nonce"],
                    "jwk": None if null else inp.get("encryption_jwk"), "response_uri": inp["response_uri"],
                },
            })
    return out


def prepare(work):
    """Write WORK/inputs (the mutations and an unrelated root) and WORK/jobs.json."""
    inputs = pathlib.Path(work) / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    ck.unrelated_root(inputs / "unrelated-root.pem")
    for c in CAPTURES:
        for n in list(MUTATIONS) + list(REENCODED):
            mutated(c, n, inputs)
    jobs = cases(inputs)
    for j in jobs:
        j["sha256"] = hashlib.sha256(pathlib.Path(j["response_host"]).read_bytes()).hexdigest()
    (pathlib.Path(work) / "jobs.json").write_text(json.dumps(jobs, indent=1) + "\n")
    print("prepared   %d cases" % len(jobs))


# --- verdicts, stage by stage ----------------------------------------------------------------------

OURS_STAGE = {"issuer chain": "trust", "ds profile": "ds_profile", "issuer signature": "mso_signature",
              "docType": "doctype", "validity": "validity", "digests": "digests",
              "device signature": "device_signature"}


def ours(job):
    """verify_mdoc.py on the case: the verdict (DS profile enforced), the stages of the diagnostic
    run (profile not enforced, as M1's "profile off"), and its SessionTranscript bytes."""
    response = pathlib.Path(job["response_host"]).read_bytes()
    inputs = json.loads((MDOC / job["capture"] / "openid4vp-inputs.json").read_text())
    h = job["handover"]
    inputs = dict(inputs, nonce=h["nonce"])
    if h["jwk"] is None and inputs["response_mode"] == "direct_post.jwt":  # the null-thumbprint transcript
        inputs = dict(inputs, response_mode="direct_post", encryption_jwk=None, wallet_session_transcript_hex=None)
    at = datetime.datetime.fromisoformat(job["at"].replace("Z", "+00:00"))
    roots = [x509.load_pem_x509_certificate(pathlib.Path(r).read_bytes()) for r in job["roots_host"]]
    out = {"transcript_hex": vm.cbor2.dumps(vm.session_transcript(inputs)[0]).hex()}
    for enforce, key in ((True, "verdict"), (False, "diagnostic")):
        passed = []
        try:
            vm.verify(response, inputs, roots, at, log=lambda c, d: passed.append(c), enforce_profile=enforce)
            out[key], failed = "VERIFIED", None
        except vm.Refused as e:
            out[key], failed = "REFUSED %s" % e, e.check
        if key == "diagnostic":
            stages = {OURS_STAGE[c]: "ok" for c in passed if c in OURS_STAGE}
            if failed:
                stages[OURS_STAGE.get(failed, "format")] = "FAIL"
            out["stages"] = stages
        else:
            out["ds_profile"] = "FAIL" if failed == "ds profile" else ("ok" if "ds profile" in passed else None)
    return out


def owf_stage(check):
    if check.startswith(("Issuer certificate must be valid", "Unable to determine a trusted issuance chain")):
        return "trust"
    if check.startswith("Issuer auth signature"):
        return "mso_signature"
    if check.startswith(("The calculated digest for", "Issuer Auth must include digests")):
        return "digests"
    if check.startswith(("The MSO must be valid at the time", "The MSO signed date")):
        return "validity"
    if check.startswith("The docType of the document"):
        return "doctype"
    if check.startswith("Device signature must be valid"):
        return "device_signature"
    if check.startswith("Country name (C) must be present"):
        return "ds_country"
    return "format"


def owf(rec):
    """@owf/mdoc's verdict per stage: FAIL if any check of the stage failed, ok if all passed."""
    stages = {}
    for c in rec.get("checks", []):
        s = owf_stage(c["check"])
        if c["status"] == "FAILED":
            stages[s] = "FAIL"
        elif c["status"] == "PASSED":
            stages.setdefault(s, "ok")
    if rec["outcome"] == "exception":
        stages["format"] = "FAIL"
    return {"transcript_hex": rec.get("transcript_hex"), "stages": stages, "outcome": rec["outcome"]}


def eu(rec):
    """The EU verifier's counted stages (transcript bytes, trust, validity) and the walt.id ones."""
    stages, waltid = {}, {}
    trust = rec["trust"]
    if any(t["verdict"] == "exception" for t in trust):
        stages["format"] = "FAIL"
    elif rec["roots"] == 0:
        stages["trust"] = "not witnessed"  # the shipped fallback trusts any chain
    else:
        stages["trust"] = "ok" if all(t["verdict"] == "Trusted" for t in trust) else "FAIL"
    errors = rec.get("errors", [])
    trusted = stages.get("trust") in ("ok", "not witnessed") and not any(e.startswith("X5CNotTrusted") for e in errors)
    if rec["outcome"] == "accepted" or (rec["outcome"] == "refused" and rec.get("error") == "InvalidDocuments" and trusted):
        stages["validity"] = "FAIL" if any(e.startswith(("ExpiredValidityInfo", "MissingValidityInfo")) for e in errors) else "ok"
        for name, err in (("mso_signature", "InvalidIssuerSignature"), ("digests", "InvalidIssuerSignedItems"),
                          ("device_signature", "InvalidDeviceSignature"), ("doctype", "DocumentTypeNotMatching")):
            waltid[name] = "FAIL" if err in errors else "ok"
    return {"transcript_hex": rec.get("transcript_hex"), "stages": stages, "waltid": waltid, "outcome": rec["outcome"]}


COUNTED = {"eu": ("trust", "validity", "format"),
           "owf": ("trust", "mso_signature", "digests", "validity", "doctype", "device_signature", "format")}

# Every disagreement found, by (capture pattern, case pattern, stage, witness): its class and reason.
ONE_WITNESS = "one-witness: a check only one makes, not a fault"
FORMAT = "an input or format difference"
CLASSIFIED = {
    (r".*", r"bad .*", "format", "eu"): (
        FORMAT, "a malformed input: the EU verifier stops with an exception while decoding it; ours refuses it "
        "at a named stage (bad DER: issuer chain; bad protected header: issuer signature)."),
    (r".*", r"bad .*", "format", "owf"): (
        FORMAT, "a malformed input: @owf/mdoc stops with an exception while decoding it; ours refuses it "
        "at a named stage (bad DER: issuer chain; bad protected header: issuer signature)."),
    (r".*", r".*", "ds_country", "owf"): (
        ONE_WITNESS, "@owf/mdoc requires countryName (C) in the DS certificate's subject; the issuer's DS "
        "certificate is CN=ISSUANCE, with no C. verify_mdoc.py does not check it."),
    (r".*", r".*", "ds_profile", "ours"): (
        ONE_WITNESS, "verify_mdoc.py refuses a document whose docType is the mDL's when its DS certificate "
        "lacks SubjectKeyIdentifier and the id-mdl-ds EKU (M1); neither witness checks the DS profile."),
}


def classify(capture, case, stage, witness):
    for (cp, kp, st, w), v in CLASSIFIED.items():
        if st == stage and w == witness and re.fullmatch(cp, capture) and re.fullmatch(kp, case):
            return v
    return None


def compare(job, o, e, w):
    """Per-stage rows for one case: (stage, ours, eu, owf, result, reason)."""
    rows = []
    for stage in ("transcript", "trust", "ds_profile", "ds_country", "mso_signature", "digests", "validity",
                  "doctype", "device_signature", "format"):
        if stage == "transcript":
            vals = {x: (None if r["transcript_hex"] is None else "equal" if r["transcript_hex"] == o["transcript_hex"]
                        else "DIFFERENT") for x, r in (("eu", e), ("owf", w))}
            bad = [x for x, v in vals.items() if v != "equal"]
            rows.append((stage, "bytes", vals["eu"], vals["owf"],
                         "UNCLASSIFIED" if bad else "agree", "%s built other bytes" % ",".join(bad) if bad else ""))
            continue
        ov = o["ds_profile"] if stage == "ds_profile" else o["stages"].get(stage)
        ev = e["stages"].get(stage) if stage in COUNTED["eu"] else None
        wv = w["stages"].get(stage) if stage in COUNTED["owf"] + ("ds_country",) else None
        if ov is None and ev is None and wv is None:
            continue
        witnesses = [(x, v) for x, v in (("eu", ev), ("owf", wv)) if v in ("ok", "FAIL")]
        result, reason, notes = None, "", []
        if ev == "not witnessed":
            notes.append("eu: trust not witnessed (no roots: its shipped fallback trusts any chain)")
        if ov in ("ok", "FAIL"):
            differ = [(x, v) for x, v in witnesses if v != ov]
            if differ:
                for x, v in differ:
                    c = classify(job["capture"], job["case"], stage, "ours" if ov == "FAIL" else x)
                    if not c:
                        result, reason = "UNCLASSIFIED", "%s says %s, ours %s" % (x, v, ov)
                        break
                    result, reason = c
            elif witnesses:
                result = "agree (%s)" % ",".join(x for x, _ in witnesses)
            elif ov == "FAIL" and classify(job["capture"], job["case"], stage, "ours"):
                result, reason = classify(job["capture"], job["case"], stage, "ours")
            else:
                result = "ours only"
        else:
            failing = [x for x, v in witnesses if v == "FAIL"]
            for x in failing:
                c = classify(job["capture"], job["case"], stage, x)
                if c:
                    result, reason = c
                elif o["diagnostic"].startswith("REFUSED"):  # ours stopped at an earlier stage
                    result = "also refused by the witness (ours stopped earlier)"
                else:
                    result, reason = "UNCLASSIFIED", "%s fails a check ours passed or does not make" % x
                    break
            if result is None:
                result = "witness only (ours not reached)" if witnesses else "not evaluated"
        if notes:
            reason = "; ".join([reason] + notes if reason else notes)
        rows.append((stage, ov, ev, wv, result, reason))
    return rows


def load_results():
    jobs = json.loads((RESULTS / "jobs.json").read_text())
    def lines(name):
        recs = [json.loads(x) for x in (RESULTS / name).read_text().splitlines() if x.strip()]
        return {r["name"]: r for r in recs}
    return jobs, lines("eu.jsonl"), lines("owf.jsonl"), json.loads((RESULTS / "run.json").read_text())


class WitnessEudiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jobs, cls.eu_raw, cls.owf_raw, cls.meta = load_results()
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        # The inputs, rebuilt: the mutations are deterministic; the unrelated root is the run's own.
        shutil.copy(RESULTS / "unrelated-root.pem", cls.tmp / "unrelated-root.pem")
        for c in CAPTURES:
            for n in list(MUTATIONS) + list(REENCODED):
                mutated(c, n, cls.tmp)
        rebuilt = {j["name"]: j for j in cases(cls.tmp)}
        cls.rows = {}
        for j in cls.jobs:
            r = rebuilt[j["name"]]
            got = hashlib.sha256(pathlib.Path(r["response_host"]).read_bytes()).hexdigest()
            if got != j["sha256"]:
                raise AssertionError("%s: the rebuilt input is not the one the witnesses judged" % j["name"])
            r["roots_expected"] = len(j["roots"])
            o, e, w = ours(r), eu(cls.eu_raw[j["name"]]), owf(cls.owf_raw[j["name"]])
            cls.rows[j["name"]] = (r, o, e, w, compare(r, o, e, w))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def case(self, capture, name):
        return self.rows["%s: %s" % (capture, name)]

    def stage(self, rows, stage):
        return {r[0]: r for r in rows}[stage]

    def test_the_pid_capture_verifies_under_its_transcript(self):
        """capture-pid's own bytes, its B.2.6.1 transcript with the thumbprint, its root, its instant."""
        r, o, e, w, rows = self.case("capture-pid", "genuine")
        self.assertEqual(o["verdict"], "VERIFIED")
        self.assertEqual(e["transcript_hex"], o["transcript_hex"], "the EU verifier builds another transcript")
        self.assertEqual(w["transcript_hex"], o["transcript_hex"], "@owf/mdoc builds another transcript")
        wallet = json.loads((MDOC / "capture-pid" / "openid4vp-inputs.json").read_text())["wallet_session_transcript_hex"]
        self.assertEqual(o["transcript_hex"], wallet)
        self.assertEqual(e["stages"], {"trust": "ok", "validity": "ok"})
        self.assertEqual(self.eu_raw[r["name"]]["trust"][0]["anchor"], "CN=ISSUANCE ROOT")
        for s in ("trust", "mso_signature", "digests", "validity", "doctype", "device_signature"):
            self.assertEqual(w["stages"].get(s), "ok", s)
        self.assertEqual(w["stages"].get("ds_country"), "FAIL")  # classified: a check only @owf/mdoc makes

    def test_another_nonce_is_refused(self):
        for c in CAPTURES:
            r, o, e, w, rows = self.case(c, "another nonce")
            self.assertTrue(o["diagnostic"].startswith("REFUSED device signature"), c)
            self.assertEqual(w["stages"].get("device_signature"), "FAIL", c)
            self.assertEqual(e["transcript_hex"], o["transcript_hex"], c)
            self.assertEqual(w["transcript_hex"], o["transcript_hex"], c)

    def test_the_null_thumbprint_transcript_is_refused(self):
        for c in ("capture-pid", "capture-mdl"):
            r, o, e, w, rows = self.case(c, "null thumbprint")
            self.assertTrue(o["diagnostic"].startswith("REFUSED device signature"), c)
            self.assertEqual(w["stages"].get("device_signature"), "FAIL", c)
            self.assertEqual(e["transcript_hex"], o["transcript_hex"], c)
            self.assertEqual(w["transcript_hex"], o["transcript_hex"], c)

    def test_a_flipped_mso_signature_byte_is_refused(self):
        r, o, e, w, rows = self.case("capture-pid", "flipped MSO signature byte")
        self.assertTrue(o["verdict"].startswith("REFUSED issuer signature"))
        self.assertEqual(w["stages"].get("mso_signature"), "FAIL")
        self.assertEqual(w["outcome"], "refused")

    def test_an_unrelated_root_is_refused(self):
        r, o, e, w, rows = self.case("capture-pid", "unrelated root")
        self.assertTrue(o["verdict"].startswith("REFUSED issuer chain"))
        self.assertEqual(e["stages"].get("trust"), "FAIL")
        self.assertEqual(w["stages"].get("trust"), "FAIL")

    def test_no_root_is_refused(self):
        """Refused at trust by ours and by @owf/mdoc, never skipped. The EU verifier, given no root,
        falls back to trusting any chain: its trust there is not witnessed, and not agreement."""
        r, o, e, w, rows = self.case("capture-pid", "no root")
        self.assertTrue(o["verdict"].startswith("REFUSED issuer chain"))
        self.assertEqual(w["stages"].get("trust"), "FAIL")
        self.assertEqual(w["outcome"], "refused")
        self.assertEqual(e["stages"].get("trust"), "not witnessed")
        trust = self.stage(rows, "trust")
        self.assertEqual(trust[4], "agree (owf)")  # the EU verifier's "Trusted" here is not counted
        self.assertIn("eu: trust not witnessed", trust[5])

    # Three more, one negative per counted stage the eight above leave without one: each must be
    # refused by ours and by every witness counted for that stage, or the stage stays one-witness.

    def test_a_changed_element_value_is_refused(self):
        for c in CAPTURES:
            r, o, e, w, rows = self.case(c, "one element value changed")
            self.assertTrue(o["diagnostic"].startswith("REFUSED digests"), c)
            self.assertEqual(w["stages"].get("digests"), "FAIL", c)

    def test_an_instant_outside_validity_is_refused(self):
        for c in CAPTURES:
            for name in ("judged after validUntil", "judged before validFrom"):
                r, o, e, w, rows = self.case(c, name)
                self.assertTrue(o["diagnostic"].startswith("REFUSED validity"), (c, name))
                self.assertEqual(e["stages"].get("validity"), "FAIL", (c, name))
                self.assertEqual(w["stages"].get("validity"), "FAIL", (c, name))
                self.assertEqual(e["stages"].get("trust"), "ok", (c, name))  # judged, not stopped at trust

    def test_a_relabeled_doctype_is_refused(self):
        for c in CAPTURES:
            r, o, e, w, rows = self.case(c, "docType relabeled")
            self.assertTrue(o["diagnostic"].startswith("REFUSED docType"), c)
            self.assertEqual(w["stages"].get("doctype"), "FAIL", c)

    def test_every_capture_is_classified_against_ours(self):
        unclassified = []
        for name, (r, o, e, w, rows) in self.rows.items():
            for stage, ov, ev, wv, verdict, reason in rows:
                if verdict.startswith("UNCLASSIFIED"):
                    unclassified.append("%s / %s: ours %s, eu %s, owf %s (%s)" % (name, stage, ov, ev, wv, reason))
            # A witness that saw fewer roots than the case holds never counts as agreement.
            self.assertEqual(self.eu_raw[name]["roots"], r["roots_expected"], "%s: the EU witness lost a root" % name)
            self.assertEqual(self.owf_raw[name]["roots"], r["roots_expected"], "%s: @owf/mdoc lost a root" % name)
        self.assertEqual(len(self.rows), len(self.jobs))
        self.assertFalse(unclassified, "\n".join(unclassified))

    def test_the_run_is_offline_pinned_and_credential_free(self):
        sh = (HERE / "run.sh").read_text()
        for pin in ("EU_IMAGE=ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint@sha256:",
                    "JDK_IMAGE=gradle:8.14.3-jdk21@sha256:", "NODE_IMAGE=node:22-alpine@sha256:",
                    "KOTLINC_SHA256=", '{"auths":{"polaris.invalid":{}}}'):
            self.assertIn(pin, sh)
        first_docker = min(i for i, line in enumerate(sh.splitlines()) if re.match(r"\s*docker ", line))
        seeded = min(i for i, line in enumerate(sh.splitlines()) if "polaris.invalid" in line)
        self.assertLess(seeded, first_docker, "DOCKER_CONFIG is seeded before any docker command")
        runs = [line for line in sh.splitlines() if re.search(r"\bdocker run\b", line)]
        self.assertTrue(runs)
        for line in runs:
            self.assertTrue("--network none" in line or "PHASE1" in line, line)
        lock = json.loads((HERE / "package-lock.json").read_text())
        self.assertTrue(all(v.get("integrity") for k, v in lock["packages"].items() if k))
        # Each version run.json records is the lockfile's, and every sentence naming it says so: a bump
        # the witness was not run again on fails here.
        results_md, readme = (HERE / "results.md").read_text(), (HERE.parent / "README.md").read_text()
        named = {
            ("owf_mdoc", "@owf/mdoc"): ((results_md, "the witness is @owf/mdoc %s**"),
                                        (results_md, "| @owf/mdoc | %s and"), (readme, "@owf/mdoc %s counts")),
            ("peculiar_x509", "@peculiar/x509"): ((results_md, "@peculiar/x509 %s's `X509ChainBuilder`"),),
        }
        for (key, pkg), said in named.items():
            pinned = lock["packages"]["node_modules/" + pkg]["version"]
            self.assertEqual(self.meta[key], pinned, "run.json records the %s the lockfile pins" % pkg)
            for text, phrase in said:
                self.assertIn(phrase % pinned, text)
        # The context commit run.json records is the one witness_owf.mjs and results.md name.
        stated = re.search(r"context\.ts at identity-common-ts ([0-9a-f]{8}) ", (HERE / "witness_owf.mjs").read_text())
        self.assertTrue(stated, "witness_owf.mjs names the context commit")
        self.assertRegex(self.meta["owf_context_commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(self.meta["owf_context_commit"][:8], stated.group(1))
        self.assertIn("context.ts` at commit `%s`" % self.meta["owf_context_commit"], results_md)
        for key in ("eu_image", "eu_commit", "kotlinc_sha256", "node_image", "network", "phase1_hosts"):
            self.assertIn(key, self.meta)
        self.assertEqual(self.meta["network"], "none")
        self.assertEqual(self.meta["phase1_hosts"], ["registry.npmjs.org"])
        fetches = (RESULTS / "phase1-fetches.txt").read_text().splitlines()
        self.assertTrue(fetches)
        self.assertEqual({re.search(r"https?://([^/ ]+)", f).group(1) for f in fetches}, {"registry.npmjs.org"})
        # run.sh ran the comparison over @owf/mdoc with its ECDSA verify always true; it must have failed.
        self.assertTrue(self.meta["owf_sign1_verify_true_fails"])


def table():
    """The per-stage table, for results.md."""
    t = WitnessEudiTests
    t.setUpClass()
    print("| case | stage | ours | eu | owf | result |")
    print("|---|---|---|---|---|---|")
    for name, (r, o, e, w, rows) in t.rows.items():
        for stage, ov, ev, wv, verdict, reason in rows:
            print("| %s | %s | %s | %s | %s | %s |" % (name, stage, ov or "", ev or "", wv or "", verdict))
    t.tearDownClass()


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "prepare":
        prepare(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == "table":
        table()
    else:
        unittest.main()
