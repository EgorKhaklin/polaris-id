#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""scripts/polaris-evaluate.py: judge THIS install and write a report its reader can keep.

Run it through scripts/polaris-evaluate.sh, which reads the configuration polaris.service runs with and
names the compose project, as the other stack scripts do.

By default it changes nothing an operator would mind: the database self-test rolls back every probe, and
the verifications it makes leave their audit rows, as every verification does. With --notional, on the
operator's statement that the database holds notional data only, it also issues one credential, verifies
it online and offline, tampers with it and revokes it. Each row of the report says what was attempted,
what a sound install does, and what this one did; the report also says what the run does not establish.

Exit: 0 no probe failed (WARN, SKIP and INFO allowed); 1 a probe failed, and the last line names it;
2 nothing to evaluate, or bad arguments.
"""
import argparse
import datetime
import hashlib
import html
import http.cookiejar
import json
import os
import platform
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WEB = os.path.join(ROOT, "polaris_web")

DOES_NOT_ESTABLISH = (
    "It is not a security review, an audit or a penetration test: it runs the probes listed, and nothing else.",
    "A PASS means a probe behaved as a sound install behaves, at this moment, on this host.",
    "Notional data says nothing about handling real identity data: that needs an independent review, "
    "the operator's own data-protection assessment and a pilot.",
    "Release provenance is reported, not judged, until the images are published and signed.",
)

VERDICTS = ("PASS", "FAIL", "WARN", "SKIP", "INFO")
RELEASE_REGISTRY = "ghcr.io/egorkhaklin/"


class Report:
    def __init__(self, secrets):
        self.rows = []
        self._secrets = secrets  # values that must never reach the report

    def scrub(self, text):
        text = str(text)
        for value in self._secrets:
            if value:
                text = text.replace(value, "[secret]")
        return text

    def add(self, rid, attempted, expected, observed, verdict, evidence=""):
        assert verdict in VERDICTS, verdict
        row = {"id": rid, "attempted": attempted, "expected": expected,
               "observed": self.scrub(observed), "verdict": verdict, "evidence": self.scrub(evidence)}
        self.rows.append(row)
        print("  %-5s %-28s %s" % (verdict, rid, row["observed"]))
        return row

    def counts(self):
        return {v: sum(r["verdict"] == v for r in self.rows) for v in VERDICTS}

    def digest(self):
        """One hash over the verdicts alone: two runs of the same release compare by it, though their
        times, credential numbers and image IDs differ."""
        lines = sorted("%s=%s" % (r["id"], r["verdict"]) for r in self.rows)
        return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def compose(*args, timeout=300, stdin=None):
    extra = os.environ.get("POLARIS_COMPOSE_EXTRA", "").split()
    return subprocess.run(["docker", "compose", "-f", "docker-compose.prod.yml", *extra, *args], cwd=WEB,
                          input=stdin, capture_output=True, text=True, timeout=timeout)


def in_app(code, timeout=300):
    """Run Python inside the running app container: its own configuration, secrets and network."""
    return compose("exec", "-T", "app", "python", "-", timeout=timeout, stdin=code)


class Http:
    """A session against the stack's edge, TLS checked against the CA it was given, never switched off."""

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            return None

    def __init__(self, base, cafile):
        self.base = base.rstrip("/")
        ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                                  urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                                  self._NoRedirect)

    def call(self, path, form=None, body=None, headers=None):
        headers = dict(headers or {})
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form, doseq=True).encode()
            headers.update({"Content-Type": "application/x-www-form-urlencoded",
                            "Origin": self.base, "Referer": self.base + path})
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, headers=headers)
        try:
            with self.opener.open(req, timeout=60) as r:
                return r.status, r.headers, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as e:
            # No answer at all (refused, reset, timed out, TLS): status 0, so the probe that asked fails.
            return 0, None, "no answer from %s: %s" % (self.base, getattr(e, "reason", e))


def guarded(rep, rid, probe, *args):
    """Run one probe; one that cannot run is a FAIL row, never a silent pass or a lost report."""
    try:
        return probe(*args)
    except Exception as e:  # noqa: BLE001: any failure to run is the finding
        rep.add(rid, "run the %s probe" % rid, "it runs", "it could not run: %s: %s" % (type(e).__name__, e), "FAIL")
        return None


def _csrf(page):
    m = (re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page)
         or re.search(r'value="([^"]+)"[^>]*name="csrf_token"', page))
    return html.unescape(m.group(1)) if m else ""


def _json(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


def _flip(hexstr):
    """The same signature with one nibble changed in its middle."""
    i = len(hexstr) // 2
    return hexstr[:i] + ("0" if hexstr[i] != "0" else "1") + hexstr[i + 1:]


# --- A: the doctor ----------------------------------------------------------------------------------
def parse_doctor(stdout):
    """The doctor's findings, one per line: '  ok    <component, padded to 18> <detail>' (or WARN, FAIL)."""
    found = []
    for line in stdout.splitlines():
        m = re.match(r"^  (ok|WARN|FAIL) {2,4}(.{18}) (.*)$", line) or re.match(r"^  (ok|WARN|FAIL) {2,4}(\S+) (.*)$", line)
        if m:
            found.append((m.group(1), m.group(2).strip(), m.group(3).strip()))
    return found


def probe_doctor(rep, env):
    r = subprocess.run(["bash", os.path.join(ROOT, "scripts", "polaris-doctor.sh")], env=env,
                       capture_output=True, text=True, timeout=900)
    if r.returncode == 2:
        return False, (r.stderr or r.stdout).strip()
    found = parse_doctor(r.stdout)
    for status, comp, detail in found:
        verdict = {"ok": "PASS", "WARN": "WARN", "FAIL": "FAIL"}[status]
        rep.add("A.doctor.%s" % comp.replace(" ", "-"), "polaris-doctor.sh judges %s" % comp,
                "ok", detail, verdict)
    if r.returncode == 1 and not any(s == "FAIL" for s, _, _ in found):
        rep.add("A.doctor", "polaris-doctor.sh", "its findings agree with its exit code",
                "it exited 1 but no line says FAIL", "FAIL", r.stdout[-400:])
    if not found:
        rep.add("A.doctor", "polaris-doctor.sh", "one line per component",
                "the doctor printed no component (exit %d)" % r.returncode, "FAIL", r.stdout[-400:])
    return True, ""


# --- B: the database's own rules, on this database ----------------------------------------------------
SELFTEST = r"""
import json, sys
import app as A
import athena_selftest
conn = A.get_db()
try:
    print("POLARIS-EVALUATE " + json.dumps(athena_selftest.run(conn), default=str))
finally:
    conn.close()
"""


def probe_selftest(rep):
    r = in_app(SELFTEST)
    line = next((l for l in r.stdout.splitlines() if l.startswith("POLARIS-EVALUATE ")), None)
    if r.returncode != 0 or line is None:
        rep.add("B.selftest", "the Athena self-test inside the app container", "it runs",
                "it could not run (exit %d)" % r.returncode, "FAIL", (r.stderr or r.stdout)[-600:])
        return
    selftest_rows(rep, json.loads(line[len("POLARIS-EVALUATE "):]))


def selftest_rows(rep, res):
    """One row per probe of athena_selftest.run's result, and one for the role it ran as."""
    if res.get("is_owner"):
        rep.add("B.role", "the role the application connects as", "not the schema owner",
                "the application connects as the schema owner (%s): the rules do not bind it" % res.get("role"),
                "FAIL")
    else:
        rep.add("B.role", "the role the application connects as", "not the schema owner",
                "connects as %s" % res.get("role"), "PASS")
    for p in res.get("probes", []):
        status = p.get("status")
        verdict = {"refused": "PASS", "refused_otherwise": "WARN", "accepted": "FAIL",
                   "owner_exempt": "INFO", "inconclusive": "SKIP"}.get(status, "FAIL")
        observed = {"refused": "refused by %s" % p.get("refused_by"),
                    "refused_otherwise": "refused, but by %s, not %s" % (p.get("refused_by"), p.get("expected")),
                    "accepted": "ACCEPTED: the database let it through",
                    "owner_exempt": "not tested: the rule does not bind the schema owner",
                    "inconclusive": p.get("message") or "inconclusive"}.get(status, "unknown status %r" % status)
        rep.add("B.%s" % str(p.get("rule")).replace(" ", "-"), p.get("attempt", ""), "refused by %s" % p.get("expected"), observed,
                verdict, "sqlstate %s; rolled back" % p.get("sqlstate"))


# --- C: the published trust list holds the key this install signs with -------------------------------
CUSTODY_KEY = r"""
import sys, custody
print("POLARIS-EVALUATE " + custody.public_key_hex(int(sys.argv[1]) if len(sys.argv) > 1 else %d))
"""


def probe_trust(rep, web, agency):
    status, _, body = web.call("/api/v1/trust-list/%d" % agency)
    doc = _json(body) if status == 200 else None
    if not doc:
        rep.add("C.trust-list", "GET /api/v1/trust-list/%d" % agency, "200 and a key list",
                "HTTP %s" % status, "FAIL", body[:300])
        return None
    active = [k.get("public_key_hex") for k in doc.get("keys", [])
              if k.get("agency_id") == agency and k.get("status") == "active"]
    r = in_app(CUSTODY_KEY % agency)
    line = next((l for l in r.stdout.splitlines() if l.startswith("POLARIS-EVALUATE ")), None)
    if line is None:
        rep.add("C.trust-list", "compare the published key with custody's", "custody names its key",
                "custody could not say its key (exit %d)" % r.returncode, "FAIL", (r.stderr or "")[-400:])
        return None
    minted = line.split(" ", 1)[1].strip()
    if minted in active:
        rep.add("C.trust-list", "GET /api/v1/trust-list/%d, compared with custody's public key" % agency,
                "the key this install signs with is published as active", "published, active, the same key",
                "PASS", "key %s..." % minted[:16])
        return minted
    rep.add("C.trust-list", "GET /api/v1/trust-list/%d, compared with custody's public key" % agency,
            "the key this install signs with is published as active",
            "not published as active (%d active keys listed)" % len(active), "FAIL",
            "the fix: scripts/polaris-key-event.sh register %d --current" % agency)
    return None


# --- D: offline verification with the published detached verifier -------------------------------------
def probe_offline(rep, out, pack, anchor_hex):
    venv = os.path.join(out, "verifier-venv")
    exe = os.path.join(venv, "bin", "polaris-verify")
    if not os.path.exists(exe):
        mk = subprocess.run([sys.executable, "-m", "venv", venv], capture_output=True, text=True)
        pip = subprocess.run([os.path.join(venv, "bin", "pip"), "install", "-q", "--pre",
                              "polaris-verify[cryptography]"], capture_output=True, text=True, timeout=600) \
            if mk.returncode == 0 else mk
        if pip.returncode != 0:
            rep.add("D.verifier", "install polaris-verify from PyPI into a venv", "installed",
                    "could not install it (no network?)", "SKIP", (pip.stderr or "")[-300:])
            return
    ver = subprocess.run([os.path.join(venv, "bin", "pip"), "show", "polaris-verify"], capture_output=True, text=True)
    version = next((l.split(":", 1)[1].strip() for l in ver.stdout.splitlines() if l.startswith("Version:")), "?")
    rep.add("D.verifier", "the detached verifier, installed from PyPI", "installed",
            "polaris-verify %s" % version, "INFO")
    work = tempfile.mkdtemp(dir=out)

    def verify(name, p, anchor):
        pf, af = os.path.join(work, name + "-pack.json"), os.path.join(work, name + "-anchor.json")
        with open(pf, "w") as fh:
            json.dump(p, fh)
        with open(af, "w") as fh:
            json.dump({"public_keys_hex": [anchor]}, fh)
        r = subprocess.run([exe, "--pqc-provider", "auto", "--issuer-anchor", af, "--pack", pf, "--json"],
                           capture_output=True, text=True, timeout=120)
        return r.returncode, _json(r.stdout) or {}

    rc, v = verify("genuine", pack, anchor_hex)
    good = rc == 0 and v.get("signature_valid") is True and v.get("issuer_trusted") is True
    rep.add("D.offline.genuine", "verify the credential offline against the published key",
            "signature_valid and issuer_trusted, exit 0",
            "signature_valid %s, issuer_trusted %s, exit %d" % (v.get("signature_valid"), v.get("issuer_trusted"), rc),
            "PASS" if good else "FAIL")
    other = json.load(open(os.path.join(ROOT, "vectors", "anchors", "ml-dsa-65-issuer.json")))
    other_key = (other.get("public_keys_hex") or [other.get("public_key_hex")])[0]
    tampered = (
        ("signature-byte", "one nibble of the signature changed", dict(pack, signature_hex=_flip(pack["signature_hex"])), anchor_hex),
        ("token-altered", "the token value changed", dict(pack, token_value=pack["token_value"] + "X"), anchor_hex),
        ("other-issuer", "verified against an unrelated issuer's key", pack, other_key),
        ("hash-as-signature", "a SHA3 hash of the token presented as an ML-DSA-65 signature",
         dict(pack, signature_hex=hashlib.sha3_256(pack["token_value"].encode()).hexdigest()), anchor_hex),
        ("empty-signature", "an empty signature", dict(pack, signature_hex=""), anchor_hex),
    )
    for name, what, p, anchor in tampered:
        rc, v = verify(name, p, anchor)
        accepted = rc == 0 and v.get("signature_valid") is True and v.get("issuer_trusted") is True
        # A refusal counts only when the verifier gave a verdict: no verdict at all measured nothing.
        verdict = "FAIL" if accepted or "signature_valid" not in v else "PASS"
        rep.add("D.offline.%s" % name, "verify offline: %s" % what, "a verdict that refuses it (not both valid and trusted)",
                "signature_valid %s, issuer_trusted %s, exit %d" % (v.get("signature_valid"), v.get("issuer_trusted"), rc),
                verdict)


# --- E and F: online verification, the status assertion, revocation ------------------------------------
def rp_token(web, client_id, client_secret):
    import base64
    auth = base64.b64encode(("%s:%s" % (client_id, client_secret)).encode()).decode()
    status, _, body = web.call("/api/v1/oauth/token", form={"grant_type": "client_credentials"},
                               headers={"Authorization": "Basic " + auth})
    doc = _json(body) or {}
    return doc.get("access_token"), status


def online(web, token, pack):
    status, _, body = web.call("/api/v1/verify", body={"token_value": pack["token_value"],
                                                       "signature_hex": pack["signature_hex"]},
                               headers={"Authorization": "Bearer " + token})
    return status, _json(body) or {}


def probe_online(rep, web, token, pack, label=""):
    status, v = online(web, token, pack)
    good = v.get("decision") == "accept" and v.get("usable") is True
    rep.add("E.online.genuine" + label, "POST /api/v1/verify with the genuine credential",
            "decision accept, usable", "HTTP %s, decision %s, usable %s" % (status, v.get("decision"), v.get("usable")),
            "PASS" if good else "FAIL")
    for name, what, p in (("signature-byte", "one nibble of the signature changed",
                           dict(pack, signature_hex=_flip(pack["signature_hex"]))),
                          ("token-altered", "the token value changed", dict(pack, token_value=pack["token_value"] + "X"))):
        status, v = online(web, token, p)
        refused = status == 200 and v.get("decision") not in (None, "accept")
        rep.add("E.online.%s" % name, "POST /api/v1/verify: %s" % what, "an answer that does not accept it",
                "HTTP %s, decision %s" % (status, v.get("decision")), "PASS" if refused else "FAIL")
    status, _, body = web.call("/api/v1/status-assertion", body={"token_value": pack["token_value"],
                                                                 "signature_hex": pack["signature_hex"]})
    a = _json(body) or {}
    try:
        def ts(x):
            return datetime.datetime.fromisoformat(str(x).replace("Z", "+00:00"))
        life = int((ts(a["expires_at"]) - ts(a["issued_at"])).total_seconds())
        rep.add("E.status-assertion.lifetime", "POST /api/v1/status-assertion; measure its lifetime",
                "a number: how long a revoked credential's last assertion stays valid offline",
                "%d s (status %s)" % (life, a.get("status")), "INFO" if life <= 3600 else "WARN",
                "the documented default is 3600 s")
    except (KeyError, TypeError, ValueError):
        rep.add("E.status-assertion.lifetime", "POST /api/v1/status-assertion", "an assertion with its times",
                "HTTP %s, no assertion" % status, "FAIL", body[:300])


def notional_issue(rep, web, args, password):
    _, _, page = web.call("/login")
    status, headers, _ = web.call("/login", form={"username": args.operator, "password": password,
                                                  "csrf_token": _csrf(page)})
    where = (headers.get("Location") or "") if headers else ""
    status2, _, page = web.call("/uc1/issue")
    if status not in (302, 303) or status2 != 200:
        reason = "the operator's login needs a second factor" if "webauthn" in where.lower() else \
            "login answered %s, the issue form %s" % (status, status2)
        rep.add("F.issue", "log in as %s and issue one notional credential" % args.operator, "issued",
                reason + ": issue one in the console and run again with --pack and --anchor", "SKIP")
        return None
    serial = "TKN-EVAL-%d" % int(time.time())
    status, headers, body = web.call("/uc1/issue", form={
        "csrf_token": _csrf(page), "legal_name": "Notional Evaluation Holder", "date_of_birth": "1990-04-02",
        "jurisdiction": "US-PA", "issuing_agency_id": str(args.agency), "algorithm_id": "1",
        "biometric_binding_type": "IRIS", "witness_agency_id": str(args.witness_agency), "liveness_check_type": "MULTI_MODAL",
        "token_value": serial, "physical_serial": "SN-" + serial, "hardware_model": "TitanQ-3", "contexts": ["1"]})
    m = re.search(r"/tokens/(\d+)", (headers.get("Location") or "") if headers else "")
    if not m:
        rep.add("F.issue", "issue one notional credential through the console's own form", "issued",
                "the form answered %s without a new credential" % status, "FAIL", re.sub(r"\s+", " ", body)[:300])
        return None
    token_id = int(m.group(1))
    status, _, body = web.call("/api/tokens/%d/authenticity-pack" % token_id)
    pack = _json(body) if status == 200 else None
    if not pack:
        rep.add("F.issue", "fetch the new credential's authenticity pack", "200 and a pack", "HTTP %s" % status, "FAIL")
        return None
    rep.add("F.issue", "issue one notional credential through the console's own form", "issued",
            "credential #%d (%s), %s" % (token_id, serial, pack.get("algorithm")), "PASS")
    return token_id, pack


def notional_revoke(rep, web, args, token_id, token, pack):
    _, _, page = web.call("/uc8/revoke")
    status, _, body = web.call("/uc8/revoke", form={
        "csrf_token": _csrf(page), "token_id": str(token_id), "actor_agency_id": str(args.agency),
        "reason_code": "ADMINISTRATIVE", "published_location": "polaris-evaluate notional run",
        # Co-signed: one authority alone may not revoke past its rate bound (7 percent in 30 days by
        # default), and on a small notional database one revocation already passes it.
        "cosigner_agency_id": str(args.witness_agency)})
    if status not in (302, 303):
        rep.add("F.revoke", "revoke it through the console's own form", "revoked",
                "the form answered %s" % status, "FAIL", re.sub(r"\s+", " ", body)[:300])
        return
    rep.add("F.revoke", "revoke it through the console's own form, co-signed by authority %d" % args.witness_agency,
            "revoked", "revoked", "PASS")
    status, v = online(web, token, pack)
    refused = status == 200 and v.get("decision") not in (None, "accept") and v.get("usable") is False
    rep.add("F.online.after-revoke", "POST /api/v1/verify after the revocation", "an answer: not accepted, not usable",
            "HTTP %s, decision %s, usable %s" % (status, v.get("decision"), v.get("usable")), "PASS" if refused else "FAIL")


def register_rp(rep):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    r = subprocess.run(["bash", os.path.join(ROOT, "scripts", "polaris-rp-register.sh"), "evaluation-" + stamp,
                        "--justification", "the relying party of a notional polaris-evaluate run"],
                       capture_output=True, text=True, timeout=300, env=os.environ)
    cid = re.search(r"^\s*client_id:\s*(\S+)", r.stdout, re.M)
    sec = re.search(r"^\s*client_secret:\s*(\S+)", r.stdout, re.M)
    if r.returncode != 0 or not cid or not sec:
        rep.add("E.relying-party", "register an evaluation relying party (polaris-rp-register.sh)", "registered",
                "it could not (exit %d)" % r.returncode, "FAIL", (r.stderr or r.stdout)[-300:])
        return None, None
    rep.add("E.relying-party", "register an evaluation relying party (polaris-rp-register.sh)", "registered",
            "evaluation-%s" % stamp, "PASS")
    return cid.group(1), sec.group(1)


# --- G: what is running --------------------------------------------------------------------------------
VERSION = r"""
import __version__
print("POLARIS-EVALUATE " + __version__.__version__)
"""


def probe_provenance(rep):
    r = in_app(VERSION)
    line = next((l for l in r.stdout.splitlines() if l.startswith("POLARIS-EVALUATE ")), None)
    version = line.split(" ", 1)[1].strip() if line else "unknown"
    rep.add("G.version", "the version the running app reports", "a version", version, "INFO")
    ps = compose("ps", "--format", "json")
    raw = ps.stdout.strip()
    rows = json.loads(raw) if raw.startswith("[") else [json.loads(l) for l in raw.splitlines() if l.strip()]
    for row in sorted(rows, key=lambda x: x.get("Service", "")):
        image = subprocess.run(["docker", "inspect", "--format", "{{.Image}}", row.get("ID", "")],
                               capture_output=True, text=True).stdout.strip()
        digests = _json(subprocess.run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image],
                                       capture_output=True, text=True).stdout.strip()) or []
        # Under Docker's containerd image store a local build has a digest too ("polaris-app@sha256:..."),
        # so only the release registry's name makes an image a published release.
        release = [d for d in digests if d.startswith(RELEASE_REGISTRY)]
        rep.add("G.image.%s" % row.get("Service"), "the image %s runs" % row.get("Service"),
                "a published release image, by digest, once releases publish images",
                ("the release image %s" % release[0]) if release else "not a published release image (%s)" % image[:19],
                "INFO", ", ".join(digests))
    return version


def host_facts():
    info = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}|{{json .DriverStatus}}"],
                          capture_output=True, text=True).stdout.strip()
    server, _, driver = info.partition("|")
    cv = subprocess.run(["docker", "compose", "version", "--short"], capture_output=True, text=True).stdout.strip()
    return {"os": platform.platform(), "docker": server, "docker_driver_status": driver, "compose": cv,
            "containerd_image_store": "io.containerd.snapshotter" in driver}


def write_report(out, rep, header):
    doc = dict(header, rows=rep.rows, counts=rep.counts(), verdict_digest=rep.digest(),
               does_not_establish=list(DOES_NOT_ESTABLISH))
    with open(os.path.join(out, "report.json"), "w") as fh:
        json.dump(doc, fh, indent=2)
    c = rep.counts()
    lines = ["# Polaris evaluation report", "",
             "| | |", "|---|---|"]
    for k in ("polaris_version", "mode", "started", "finished", "project", "url"):
        lines.append("| %s | %s |" % (k.replace("_", " "), header.get(k, "")))
    for k, v in header["host"].items():
        lines.append("| host %s | %s |" % (k.replace("_", " "), v))
    if header.get("notional_statement"):
        lines += ["", "**The operator's statement:** %s" % header["notional_statement"]]
    lines += ["", "**Result:** %s PASS, %s FAIL, %s WARN, %s SKIP, %s INFO. Verdict digest `%s`."
              % (c["PASS"], c["FAIL"], c["WARN"], c["SKIP"], c["INFO"], doc["verdict_digest"]), "",
              "| Verdict | Probe | Attempted | A sound install | This install |", "|---|---|---|---|---|"]
    for r in rep.rows:
        cell = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
        lines.append("| %s | `%s` | %s | %s | %s |" % (r["verdict"], r["id"], cell(r["attempted"]),
                                                        cell(r["expected"]), cell(r["observed"])))
    lines += ["", "## What this run does not establish", ""] + ["- " + s for s in DOES_NOT_ESTABLISH]
    if header.get("residue"):
        lines += ["", "## What the run left behind", ""] + ["- " + s for s in header["residue"]]
    with open(os.path.join(out, "report.md"), "w") as fh:
        fh.write(rep.scrub("\n".join(lines)) + "\n")
    # Owner-only whatever the umask: a report names hosts, versions and image IDs.
    os.chmod(out, 0o700)
    for name in ("report.json", "report.md"):
        os.chmod(os.path.join(out, name), 0o600)


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    ap.add_argument("--notional", action="store_true",
                    help="also issue, verify, tamper with and revoke one credential (notional data only)")
    ap.add_argument("--operator", help="with --notional: the operator account that issues")
    ap.add_argument("--password-file", help="with --notional: a file holding that operator's password")
    ap.add_argument("--agency", type=int, default=1, help="the issuing authority (default 1)")
    ap.add_argument("--witness-agency", type=int, default=2, help="with --notional: the witnessing authority")
    ap.add_argument("--pack", help="without --notional: an authenticity pack to verify offline and online")
    ap.add_argument("--rp-config", help="without --notional: JSON {client_id, client_secret} of a relying party")
    ap.add_argument("--url", default=os.environ.get("POLARIS_EVALUATE_URL")
                    or "https://%s" % os.environ.get("POLARIS_DOMAIN", "localhost"))
    ap.add_argument("--cacert", help="a CA file the edge's certificate chains to, when it is not a public one")
    ap.add_argument("--out", help="the report directory (default ./polaris-evaluation-<UTC>)")
    args = ap.parse_args(argv)
    if args.notional and not (args.operator and args.password_file):
        ap.error("--notional needs --operator and --password-file")
    if args.notional and args.pack:
        ap.error("--pack is for a run without --notional (a notional run issues its own)")

    started = datetime.datetime.now(datetime.timezone.utc)
    out = os.path.abspath(args.out or "polaris-evaluation-%s" % started.strftime("%Y%m%dT%H%M%SZ"))
    os.umask(0o077)
    os.makedirs(out, exist_ok=True)
    password = open(args.password_file).read().strip() if args.password_file else ""
    rp = json.load(open(args.rp_config)) if args.rp_config else {}
    rep = Report([password, rp.get("client_secret", "")])
    print("polaris-evaluate: %s, %s mode; the report goes to %s"
          % (args.url, "notional" if args.notional else "live-safe", out))

    cafile = args.cacert
    if not cafile and re.match(r"https://(localhost|127\.0\.0\.1)(:\d+)?$", args.url):
        # The edge's own local certificate authority (tls internal): read from the edge, public.
        r = compose("exec", "-T", "caddy", "cat", "/data/caddy/pki/authorities/local/root.crt")
        if r.returncode == 0 and "BEGIN CERTIFICATE" in r.stdout:
            cafile = os.path.join(out, "edge-ca.crt")
            with open(cafile, "w") as fh:
                fh.write(r.stdout)
    env = dict(os.environ, POLARIS_DOCTOR_URL=args.url)
    if cafile:
        env["POLARIS_DOCTOR_CACERT"] = cafile
    web = Http(args.url, cafile)
    residue = ["audit rows for each verification and each self-test run, as every verification leaves",
               "the self-test's refused statements as ERROR lines in the PostgreSQL log "
               "(application_name=polaris-athena-selftest)"]

    print("A. the stack")
    ok, why = guarded(rep, "A.doctor", probe_doctor, rep, env) or (True, "")
    if not ok:
        print("polaris-evaluate: nothing to evaluate: %s" % why, file=sys.stderr)
        return 2
    print("G. what is running")
    version = guarded(rep, "G.version", probe_provenance, rep) or "unknown"
    print("C. published trust")
    anchor = guarded(rep, "C.trust-list", probe_trust, rep, web, args.agency)

    issued = None
    token = None
    if args.notional:
        print("F. a notional credential")
        cid, secret = guarded(rep, "E.relying-party", register_rp, rep) or (None, None)
        rep._secrets.append(secret or "")
        if cid:
            residue.append("one relying party registration, named evaluation-<UTC stamp>")
            token, st = guarded(rep, "E.relying-party.token", rp_token, web, cid, secret) or (None, "no answer")
            if not token:
                rep.add("E.relying-party.token", "POST /api/v1/oauth/token", "an access token", "HTTP %s" % st, "FAIL")
        issued = guarded(rep, "F.issue", notional_issue, rep, web, args, password)
        if issued:
            residue.append("one notional holder and one credential, revoked at the end of the run")
    print("B. the database's rules on this database")
    guarded(rep, "B.selftest", probe_selftest, rep)

    pack = issued[1] if issued else (json.load(open(args.pack)) if args.pack else None)
    if pack is None:
        rep.add("D.offline", "offline verification of a credential", "a credential to verify",
                "none: a live-safe run issues nothing; pass --pack, or run --notional on notional data", "SKIP")
    elif anchor is None:
        rep.add("D.offline", "offline verification of a credential", "the install's published key",
                "no published key to verify against (C.trust-list)", "SKIP")
    else:
        print("D. offline verification")
        guarded(rep, "D.offline", probe_offline, rep, out, pack, anchor)
    if pack is not None and not args.notional and rp.get("client_id"):
        token, st = guarded(rep, "E.relying-party.token", rp_token, web, rp["client_id"], rp["client_secret"]) \
            or (None, "no answer")
        if not token:
            rep.add("E.relying-party.token", "POST /api/v1/oauth/token as the given relying party", "an access token",
                    "HTTP %s" % st, "FAIL")
    if pack is None or not token:
        given = args.notional or (args.pack and args.rp_config)
        rep.add("E.online", "online verification by a relying party", "a credential and a relying party",
                "no relying party token (above)" if given else "none given (pass --pack and --rp-config, or run --notional)",
                "FAIL" if given else "SKIP")
    else:
        print("E. online verification")
        guarded(rep, "E.online", probe_online, rep, web, token, pack)
        if issued:
            guarded(rep, "F.revoke", notional_revoke, rep, web, args, issued[0], token, pack)

    header = {"tool": "scripts/polaris-evaluate.py", "polaris_version": version,
              "mode": "notional" if args.notional else "live-safe",
              "notional_statement": ("the operator ran with --notional, stating this database holds notional data "
                                     "only; nothing here checks that statement") if args.notional else "",
              "started": started.isoformat(timespec="seconds"),
              "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "project": os.environ.get("COMPOSE_PROJECT_NAME", "polaris_web"), "url": args.url,
              "host": host_facts(), "residue": residue}
    write_report(out, rep, header)
    c = rep.counts()
    print("polaris-evaluate: %d PASS, %d FAIL, %d WARN, %d SKIP, %d INFO; verdict digest %s"
          % (c["PASS"], c["FAIL"], c["WARN"], c["SKIP"], c["INFO"], rep.digest()[:16]))
    print("  report: %s" % os.path.join(out, "report.md"))
    failing = [r["id"] for r in rep.rows if r["verdict"] == "FAIL"]
    if failing:
        print("polaris-evaluate: failing: %s" % ", ".join(failing))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
