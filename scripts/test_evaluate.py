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


if __name__ == "__main__":
    unittest.main()
