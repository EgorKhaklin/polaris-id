# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_evaluate.py: the parts of scripts/polaris-evaluate.py that decide a verdict or write the report,
without a stack: the doctor's lines read back, the self-test's statuses mapped, the verdict digest, and a
report that never carries a secret and is readable by its owner only. The probes against a running stack
run in CI's fresh-host job, with negative controls."""
import importlib.util
import json
import os
import stat
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location("polaris_evaluate", os.path.join(_HERE, "polaris-evaluate.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


DOCTOR = """polaris-doctor: project polaris-try, 5 services
  ok    app                Up 3 minutes (healthy)
  ok    caddy              Up 3 minutes
  FAIL  postgres           exited, exit code 1 (Exited (1) 2 seconds ago); its log: docker compose logs --tail 50 postgres
  ok    secrets            every mounted secret file is present and not empty
  WARN  secrets at rest    plaintext files in /opt/polaris/polaris_web/secrets on this disk
  WARN  key register       agency 1 has issued without a registered key
polaris-doctor: failing: postgres
"""


class DoctorLines(unittest.TestCase):
    def test_each_finding_is_read_with_its_component(self):
        ev = _load()
        found = ev.parse_doctor(DOCTOR)
        self.assertEqual([c for _, c, _ in found],
                         ["app", "caddy", "postgres", "secrets", "secrets at rest", "key register"])
        self.assertEqual([s for s, _, _ in found], ["ok", "ok", "FAIL", "ok", "WARN", "WARN"])
        self.assertTrue(found[2][2].startswith("exited, exit code 1"))

    def test_lines_that_are_not_findings_are_ignored(self):
        ev = _load()
        self.assertEqual(ev.parse_doctor("polaris-doctor: project x\nnothing here\n"), [])


class SelfTestVerdicts(unittest.TestCase):
    def rows(self, res):
        ev = _load()
        rep = ev.Report([])
        ev.selftest_rows(rep, res)
        return {r["id"]: r["verdict"] for r in rep.rows}

    def test_each_status_has_the_verdict_it_deserves(self):
        probes = [{"rule": "C1", "attempt": "UPDATE an audit row", "expected": "trigger", "status": "refused",
                   "refused_by": "trigger"},
                  {"rule": "C2", "status": "refused_otherwise", "refused_by": "grant", "expected": "check"},
                  {"rule": "C3", "status": "accepted"},
                  {"rule": "C4", "status": "owner_exempt"},
                  {"rule": "C5", "status": "inconclusive", "message": "there is no row for it to aim at"},
                  {"rule": "C6", "status": "something new"}]
        got = self.rows({"role": "polaris_app", "is_owner": False, "probes": probes})
        self.assertEqual(got, {"B.role": "PASS", "B.C1": "PASS", "B.C2": "WARN", "B.C3": "FAIL",
                               "B.C4": "INFO", "B.C5": "SKIP", "B.C6": "FAIL"})

    def test_the_schema_owner_as_the_application_role_fails(self):
        self.assertEqual(self.rows({"role": "postgres", "is_owner": True, "probes": []})["B.role"], "FAIL")


class Digest(unittest.TestCase):
    def report(self, rows):
        ev = _load()
        rep = ev.Report([])
        for rid, verdict, observed in rows:
            rep.add(rid, "attempted", "expected", observed, verdict)
        return rep

    def test_the_digest_reads_verdicts_only(self):
        a = self.report([("A.x", "PASS", "credential #12"), ("B.y", "FAIL", "image sha256:1")])
        b = self.report([("B.y", "FAIL", "image sha256:2"), ("A.x", "PASS", "credential #13")])
        self.assertEqual(a.digest(), b.digest(), "order, times and numbers must not move the digest")
        c = self.report([("A.x", "PASS", "credential #12"), ("B.y", "PASS", "image sha256:1")])
        self.assertNotEqual(a.digest(), c.digest(), "a changed verdict must move the digest")


class ReportFile(unittest.TestCase):
    def test_no_secret_reaches_the_report_and_only_its_owner_reads_it(self):
        ev = _load()
        secret, password = "rp-secret-9f8e7d", "Try-hunter2-correct-horse"
        rep = ev.Report([password, secret])
        rep.add("E.relying-party", "register", "registered", "client secret %s" % secret, "PASS",
                "password %s" % password)
        out = tempfile.mkdtemp()
        header = {"polaris_version": "1.0.0-rc.70", "mode": "notional", "started": "s", "finished": "f",
                  "project": "p", "url": "https://localhost:8443", "host": {"os": "test"},
                  "notional_statement": "the operator stated it", "residue": ["one relying party"]}
        ev.write_report(out, rep, header)
        for name in ("report.json", "report.md"):
            text = open(os.path.join(out, name)).read()
            self.assertNotIn(secret, text)
            self.assertNotIn(password, text)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(out, name)).st_mode), 0o600, name)
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o700)
        md = open(os.path.join(out, "report.md")).read()
        self.assertIn("## What this run does not establish", md)
        for sentence in ev.DOES_NOT_ESTABLISH:
            self.assertIn(sentence, md)
        doc = json.load(open(os.path.join(out, "report.json")))
        self.assertEqual(doc["verdict_digest"], rep.digest())
        self.assertEqual(doc["counts"]["PASS"], 1)

    def test_a_probe_that_cannot_run_is_a_failure_not_a_lost_report(self):
        ev = _load()
        rep = ev.Report([])

        def broken():
            raise RuntimeError("the stack went away")
        self.assertIsNone(ev.guarded(rep, "C.trust-list", broken))
        self.assertEqual([(r["id"], r["verdict"]) for r in rep.rows], [("C.trust-list", "FAIL")])
        self.assertIn("the stack went away", rep.rows[0]["observed"])

    def test_no_answer_is_status_zero_not_an_exception(self):
        ev = _load()
        status, headers, body = ev.Http("https://127.0.0.1:9", None).call("/api/health")
        self.assertEqual((status, headers), (0, None))
        self.assertIn("no answer", body)

    def test_a_tampered_signature_differs_in_exactly_one_place(self):
        ev = _load()
        sig = "ab" * 40
        flipped = ev._flip(sig)
        self.assertEqual(len(flipped), len(sig))
        self.assertEqual(sum(a != b for a, b in zip(sig, flipped)), 1)


class FakeWeb:
    """Answers the console's routes from a script: path -> (status, headers, body), or a list taken in turn."""

    def __init__(self, routes):
        self.routes = {k: (list(v) if isinstance(v, list) else v) for k, v in routes.items()}
        self.calls = []

    def call(self, path, form=None, body=None, headers=None):
        self.calls.append((path, form is not None))
        answer = self.routes.get(path, (404, {}, "not found"))
        return answer.pop(0) if isinstance(answer, list) else answer


class Args:
    operator, agency, witness_agency = "ci-admin", 1, 2


FORM = '<input type="hidden" name="csrf_token" value="tok">'


class NotionalIssue(unittest.TestCase):
    """Review of #318 (2026-10-09): a notional run with a wrong password skipped issuance and exited 0."""

    def issue(self, login):
        ev = _load()
        rep = ev.Report([])
        web = FakeWeb({"/login": [(200, {}, FORM), login], "/uc1/issue": (200, {}, FORM)})
        self.assertIsNone(ev.notional_issue(rep, web, Args, "pw"))
        return [(r["id"], r["verdict"]) for r in rep.rows]

    def test_a_refused_login_fails_the_run(self):
        self.assertEqual(self.issue((401, {}, "bad credentials")), [("F.issue", "FAIL")])
        self.assertEqual(self.issue((302, {"Location": "/login?next=%2F"}, "")), [("F.issue", "FAIL")])

    def test_a_second_factor_is_the_one_skip(self):
        self.assertEqual(self.issue((302, {"Location": "/webauthn/login"}, "")), [("F.issue", "SKIP")])

    def test_two_runs_in_one_second_issue_different_serials(self):
        ev = _load()
        orig = ev.time.time
        ev.time.time = lambda: 1791500000.0
        try:
            seen = set()
            for _ in range(2):
                sent = {}

                class Capture(FakeWeb):
                    def call(self, path, form=None, body=None, headers=None):
                        if form and "token_value" in form:
                            sent["serial"] = form["token_value"]
                        return super().call(path, form, body, headers)
                web = Capture({"/login": [(200, {}, FORM), (302, {"Location": "/"}, "")],
                               "/uc1/issue": [(200, {}, FORM), (200, {}, "no")]})
                ev.notional_issue(ev.Report([]), web, Args, "pw")
                seen.add(sent["serial"])
            self.assertEqual(len(seen), 2, seen)
        finally:
            ev.time.time = orig


class NotionalRevoke(unittest.TestCase):
    """A revocation counts only when the form lands on that credential's page: a lost session also answers 302,
    to /login, and a refusal answers 200 (review of #318, 2026-10-09: `or` turned to `and` passed both)."""

    def revoke(self, answer):
        ev = _load()
        rep = ev.Report([])
        orig = ev.online
        ev.online = lambda web, token, pack: (200, {"decision": "reject", "usable": False})
        try:
            web = FakeWeb({"/uc8/revoke": [(200, {}, FORM), answer]})
            done = ev.notional_revoke(rep, web, Args, 41, "token", {"token_value": "TKN-X"})
        finally:
            ev.online = orig
        return done, [(r["id"], r["verdict"]) for r in rep.rows]

    def test_only_the_credentials_own_page_counts(self):
        self.assertEqual(self.revoke((302, {"Location": "/login?next=%2Fuc8%2Frevoke"}, "")),
                         (False, [("F.revoke", "FAIL")]))
        self.assertEqual(self.revoke((200, {}, "the authority's rate bound refuses it")), (False, [("F.revoke", "FAIL")]))
        self.assertEqual(self.revoke((302, {"Location": "/tokens/410"}, "")), (False, [("F.revoke", "FAIL")]))
        self.assertEqual(self.revoke((302, {"Location": "/tokens/41"}, "")),
                         (True, [("F.revoke", "PASS"), ("F.online.after-revoke", "PASS")]))


class Verifier(unittest.TestCase):
    """The published wheel is what a stranger runs; a verifier built from the checkout is reported as such."""

    class Done:
        def __init__(self, rc):
            self.returncode, self.stdout, self.stderr = rc, "", "" if rc == 0 else "no matching distribution"

    def install(self, pypi_rc):
        ev = _load()
        calls = []

        def run(cmd, **_kw):
            calls.append(cmd)
            return self.Done(pypi_rc if "--only-binary" in cmd else 0)
        orig = ev.subprocess.run
        ev.subprocess.run = run
        try:
            r, source = ev.install_verifier("pip", "9.9.9")
        finally:
            ev.subprocess.run = orig
        rep = ev.Report([])
        ev.record_verifier(rep, "9.9.9", r, source)
        return len(calls), source, rep.rows[0]["verdict"]

    def test_the_published_wheel_is_an_info(self):
        self.assertEqual(self.install(0), (1, "PyPI", "INFO"))

    def test_one_built_from_the_checkout_is_a_warning(self):
        self.assertEqual(self.install(1), (2, "this checkout", "WARN"))


class IssuedNothing(unittest.TestCase):
    """A notional run that issued nothing says why once, at F.issue, and the rows after it skip with that reason
    rather than fail again (review of #318, 2026-10-09: the branch could be deleted with every test green)."""

    def test_the_rows_after_a_failed_issue_skip_naming_it(self):
        ev = _load()
        tmp = tempfile.mkdtemp()
        pw = os.path.join(tmp, "pw")
        with open(pw, "w") as fh:
            fh.write("pw\n")
        stubs = {
            "probe_doctor": lambda rep, env: (True, ""),
            "probe_provenance": lambda rep: "9.9.9",
            "probe_trust": lambda rep, web, agency: "anchor",
            "register_rp": lambda rep: ("cid", "secret"),
            "rp_token": lambda web, cid, secret: ("token", 200),
            "notional_issue": lambda rep, web, args, password: rep.add(
                "F.issue", "issue", "issued", "login answered 401", "FAIL") and None,
            "probe_selftest": lambda rep: None,
            "host_facts": lambda: {"os": "test"},
        }
        for name in ("probe_offline", "probe_online", "notional_revoke"):
            stubs[name] = lambda *a, _n=name: self.fail("%s ran without a credential" % _n)
        saved = {k: getattr(ev, k) for k in stubs}
        for k, v in stubs.items():
            setattr(ev, k, v)
        try:
            rc = ev.main(["--notional", "--operator", "ci-admin", "--password-file", pw,
                          "--url", "https://evaluate.invalid", "--out", os.path.join(tmp, "report")])
        finally:
            for k, v in saved.items():
                setattr(ev, k, v)
        doc = json.load(open(os.path.join(tmp, "report", "report.json")))
        rows = {r["id"]: r for r in doc["rows"]}
        self.assertEqual(rc, 1)
        self.assertEqual([r["id"] for r in doc["rows"] if r["verdict"] == "FAIL"], ["F.issue"])
        for rid in ("D.offline", "E.online"):
            self.assertEqual(rows[rid]["verdict"], "SKIP", rid)
            self.assertIn("issued none (F.issue)", rows[rid]["observed"], rid)


if __name__ == "__main__":
    unittest.main()
