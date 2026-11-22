#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_agree.py -- agree.py passes a row set both verifiers judged as each row expects, and fails on
each broken row set, OID4VCgo verdict file and exit status made here; agree-gate.sh, the workflow's
step, passes only when agree.py exits 0 and prints its one PASS line and no FAIL line.

The rows and both sides' verdicts, at the instant and at the run date, are made here, with two outside
vector files in a scratch directory; no witness run, no cryptography, no network. main runs here with
this repository's verdicts given as fixed ones. mdoc-witness.yml runs this before the witness.

    python3 -I lab/interop/mdoc/witness-oid4vcgo/test_agree.py
"""
import contextlib
import copy
import datetime
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("witness_agree", os.path.join(HERE, "agree.py"))
agree = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agree)

UTC = datetime.timezone.utc
TODAY = datetime.datetime(2026, 11, 21, 12, 0, 0, tzinfo=UTC)
NS = "org.iso.18013.5.1"
CLAIMS = {NS: {"family_name": "Mustermann", "age_over_21": True}}
VALID, NOT_YET = "MINTED-VALID-AT-INSTANT", "MINTED-DS-NOT-YET-VALID"


def refusal(side, stage):
    code, ours_says, theirs_says = agree.STAGES[stage]
    if side == agree.OURS:
        return {"outcome": "refused", "code": code, "error": "the check %s here" % ours_says}
    return {"outcome": "refused", "error": "mdocdcapi: %s here" % theirs_says}


class AgreeTests(unittest.TestCase):

    def scratch(self):
        """A new scratch directory, removed when the test ends."""
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        return directory

    def setUp(self):
        self.repo = pathlib.Path(self.scratch())
        rows = []
        for name, origin, stage in (("ANNEXC-DETERMINISTIC-001", "https://verifier.example", "document"),
                                    ("ANNEXC-REAL-001", "https://verifier.multipaz.org", "open")):
            vector = {"id": name, "origin": origin, "encryptionInfoB64": "info-" + name,
                      "encryptedResponseB64": "response-" + name, "recipientPrivateKeyHex": "00ab",
                      "expected": {"docType": "org.iso.18013.5.1.mDL", "requestedElement": "age_over_18"}}
            raw = json.dumps(vector).encode()
            rel = "testdata/%s.json" % name
            (self.repo / "testdata").mkdir(exist_ok=True)
            (self.repo / rel).write_bytes(raw)
            rows.append({"id": name, "kind": "outside", "expect": "refused", "refused_at": stage, "session": "Session",
                         "source": {"path": rel, "sha256": hashlib.sha256(raw).hexdigest()},
                         "origin": origin, "doctype": "org.iso.18013.5.1.mDL", "elements": {NS: ["age_over_18"]},
                         "encryption_info": "info-" + name, "recipient_key_hex": "%064x" % 0xab,
                         "response": "response-" + name})
        valid = {"id": VALID, "kind": "window", "expect": "accepted", "session": "Session",
                 "document_signer": {"not_before": "2026-05-31T12:00:00Z", "not_after": "2026-07-01T12:00:00Z"},
                 "mso": {"signed": "2026-06-01T11:00:00Z", "valid_from": "2026-06-01T11:00:00Z",
                         "valid_until": "2049-12-31T00:00:00Z"},
                 "origin": "https://rp.example", "doctype": "org.iso.18013.5.1.mDL",
                 "elements": {NS: ["family_name", "age_over_21"]}, "encryption_info": "info-valid",
                 "recipient_key_hex": "%064x" % 1, "response": "response-valid", "claims": CLAIMS}
        not_yet = dict(valid, id=NOT_YET, expect="refused", refused_at="document_signer_validity",
                       response="response-not-yet",
                       document_signer={"not_before": "2026-06-02T12:00:00Z", "not_after": "2049-12-31T00:00:00Z"},
                       mso={"signed": "2026-06-02T13:00:00Z", "valid_from": "2026-06-02T13:00:00Z",
                            "valid_until": "2049-12-31T00:00:00Z"})
        del not_yet["claims"]
        rows += [valid, not_yet]
        for name, change in (("CONTROL-ANOTHER-ORIGIN", {"origin": "https://other.example"}),
                             ("CONTROL-ANOTHER-KEY", {"session": "fields", "recipient_key_hex": "%064x" % 2}),
                             ("CONTROL-FLIPPED-CIPHERTEXT", {"response": "response-flipped"})):
            control = {k: v for k, v in valid.items() if k not in ("document_signer", "mso", "claims")}
            control.update({"id": name, "kind": "control", "of": valid["id"], "expect": "refused",
                            "refused_at": "open"}, **change)
            rows.append(control)
        self.fixture = {"at": "2026-06-01T12:00:00Z", "max_skew_seconds": 300, "rows": rows}
        self.ours = {row["id"]: self.verdict(row, agree.OURS) for row in rows}
        self.theirs = {row["id"]: self.verdict(row, agree.THEIRS) for row in rows}
        self.ours_later = {VALID: refusal(agree.OURS, "document_signer_validity"),
                           NOT_YET: {"outcome": "accepted", "claims": CLAIMS}}
        self.theirs_later = {VALID: refusal(agree.THEIRS, "document_signer_validity"),
                             NOT_YET: {"outcome": "accepted", "claims": CLAIMS}}

    @staticmethod
    def verdict(row, side):
        if row["expect"] == "accepted":
            return {"outcome": "accepted", "claims": copy.deepcopy(row["claims"])}
        return refusal(side, row["refused_at"])

    def judged(self):
        return agree.judge(self.fixture, self.ours, self.theirs, TODAY, repo=self.repo,
                           our_run_date=self.ours_later, their_run_date=self.theirs_later)

    def row(self, row_id):
        return next(row for row in self.fixture["rows"] if row["id"] == row_id)

    def assertFails(self, needle):
        # The judge reports a broken row set as a problem; raising on one is a failure here, not an error.
        try:
            lines, problems = self.judged()
        except Exception as error:
            self.fail("the judge raised %r where a problem naming %r was expected" % (error, needle))
        self.assertTrue(any(needle in problem for problem in problems), "no problem names %r: %r" % (needle, problems))
        return lines

    def test_both_verifiers_as_each_row_expects_pass(self):
        lines, problems = self.judged()
        self.assertEqual(problems, [])
        self.assertEqual(lines[-1], "ROWS 7  BOTH-AGREE 7  BOTH-AS-EXPECTED 7  WINDOW-ROWS-TURNED-AT-THE-RUN-DATE 2")
        self.assertEqual(sum(line.startswith("ROW ") for line in lines), 7)
        self.assertEqual(sum(line.startswith("RUN-DATE ") for line in lines), 2)

    def test_each_row_line_carries_both_verdicts_and_the_response_digest(self):
        lines, _ = self.judged()
        line = next(line for line in lines if line.startswith("ROW " + VALID))
        self.assertIn("Polaris accepted", line)
        self.assertIn("OID4VCgo accepted", line)
        self.assertIn(hashlib.sha256(b"response-valid").hexdigest(), line)

    def test_a_control_their_verifier_accepts_fails(self):
        self.theirs["CONTROL-FLIPPED-CIPHERTEXT"] = {"outcome": "accepted", "claims": CLAIMS}
        lines = self.assertFails("CONTROL-FLIPPED-CIPHERTEXT: OID4VCgo accepted it")
        self.assertTrue(lines[-1].startswith("ROWS 7  BOTH-AGREE 6  BOTH-AS-EXPECTED 6  "), lines[-1])

    def test_the_valid_row_our_verifier_refuses_fails(self):
        self.ours[VALID] = refusal(agree.OURS, "document_signer_validity")
        self.assertFails(VALID + ": Polaris refused it")

    def test_a_row_both_verifiers_get_wrong_fails(self):
        self.ours[NOT_YET] = self.theirs[NOT_YET] = {"outcome": "accepted", "claims": CLAIMS}
        lines = self.assertFails(NOT_YET + ": OID4VCgo accepted it")
        self.assertTrue(lines[-1].startswith("ROWS 7  BOTH-AGREE 7  BOTH-AS-EXPECTED 6  "), lines[-1])

    def test_other_claims_on_an_accepted_row_fail(self):
        self.theirs[VALID] = {"outcome": "accepted", "claims": {NS: {"family_name": "Other"}}}
        self.assertFails("OID4VCgo accepted it with claims")

    def test_a_refusal_at_another_stage_fails_on_either_side(self):
        self.ours["CONTROL-ANOTHER-ORIGIN"] = refusal(agree.OURS, "document")
        self.assertFails("CONTROL-ANOTHER-ORIGIN: Polaris refused it at malformed")
        self.setUp()
        self.ours["CONTROL-ANOTHER-ORIGIN"] = {"outcome": "refused", "code": "hpke", "error": "something else"}
        self.assertFails("CONTROL-ANOTHER-ORIGIN: Polaris refused it at hpke")
        self.setUp()
        self.ours["CONTROL-ANOTHER-ORIGIN"] = {"outcome": "refused", "code": "malformed",
                                               "error": "the check does not open here"}
        self.assertFails("CONTROL-ANOTHER-ORIGIN: Polaris refused it at malformed")
        self.setUp()
        self.theirs[NOT_YET] = {"outcome": "refused", "error": "mdocdcapi: mdoc: the MSO is not yet valid"}
        self.assertFails(NOT_YET + ": OID4VCgo refused it with")
        self.setUp()
        self.theirs["ANNEXC-DETERMINISTIC-001"] = refusal(agree.THEIRS, "open")
        lines, problems = self.judged()
        self.assertTrue(any(p.startswith("ANNEXC-DETERMINISTIC-001: OID4VCgo refused it with") for p in problems))
        self.assertTrue(lines[-1].startswith("ROWS 7  BOTH-AGREE 7  BOTH-AS-EXPECTED 6  "), lines[-1])

    def test_a_refused_row_naming_no_stage_fails(self):
        del self.row("ANNEXC-REAL-001")["refused_at"]
        self.assertFails("ANNEXC-REAL-001 names no stage it is refused at (None)")

    def test_a_missing_or_unreadable_verdict_fails(self):
        del self.theirs["ANNEXC-REAL-001"]
        self.ours["CONTROL-ANOTHER-KEY"] = {"outcome": "error", "error": "KeyError: 'session'"}
        self.assertFails("ANNEXC-REAL-001: no verdict from OID4VCgo")
        self.assertFails("CONTROL-ANOTHER-KEY: Polaris gave no verdict")

    def test_two_verdicts_that_are_no_outcome_do_not_count_as_agreeing(self):
        self.ours["ANNEXC-REAL-001"] = self.theirs["ANNEXC-REAL-001"] = {"outcome": "error", "error": "a panic"}
        lines = self.assertFails("ANNEXC-REAL-001: OID4VCgo gave no verdict")
        self.assertTrue(lines[-1].startswith("ROWS 7  BOTH-AGREE 6  BOTH-AS-EXPECTED 6  "), lines[-1])

    def test_a_verdict_on_a_row_the_file_does_not_hold_fails(self):
        self.theirs["CONTROL-SOMETHING-ELSE"] = {"outcome": "refused"}
        self.assertFails("OID4VCgo judged CONTROL-SOMETHING-ELSE, which the rows file does not hold")

    def test_an_empty_or_short_row_set_fails(self):
        self.fixture["rows"] = [row for row in self.fixture["rows"] if row["id"] != "CONTROL-ANOTHER-KEY"]
        del self.ours["CONTROL-ANOTHER-KEY"], self.theirs["CONTROL-ANOTHER-KEY"]
        self.assertFails("no row CONTROL-ANOTHER-KEY")
        self.fixture["rows"], self.ours, self.theirs = [], {}, {}
        self.assertFails("the rows file holds no row")

    def test_two_rows_of_one_id_fail(self):
        self.fixture["rows"].append(copy.deepcopy(self.row("CONTROL-ANOTHER-ORIGIN")))
        self.assertFails("two rows are CONTROL-ANOTHER-ORIGIN")

    def test_a_row_set_with_no_instant_fails(self):
        del self.fixture["at"]
        self.assertFails("the rows file names no instant")

    def test_a_row_that_expects_neither_outcome_or_states_no_claims_fails(self):
        self.row("CONTROL-ANOTHER-ORIGIN")["expect"] = "maybe"
        self.assertFails("CONTROL-ANOTHER-ORIGIN expects 'maybe'")
        self.setUp()
        del self.row(VALID)["claims"]
        self.assertFails(VALID + " expects acceptance and states no claims")

    def test_an_outside_row_that_is_not_its_file_fails(self):
        for field, value, needle in (("response", "other", "response is not its file's encryptedResponseB64"),
                                     ("origin", "https://x.example", "origin is not its file's origin"),
                                     ("recipient_key_hex", "%064x" % 0xac, "recipient key is not its file's"),
                                     ("elements", {NS: ["age_over_21"]}, "not its file's requestedElement")):
            with self.subTest(field):
                self.setUp()
                self.row("ANNEXC-REAL-001")[field] = value
                self.assertFails(needle)
        self.setUp()
        self.row("ANNEXC-REAL-001")["source"]["sha256"] = "00" * 32
        self.assertFails("is not the one its SHA-256 names")
        self.row("ANNEXC-REAL-001")["source"]["path"] = "testdata/absent.json"
        self.assertFails("copies no file this tree holds")
        # The same bytes, so the same SHA-256, in a file outside the tree: named by its absolute path and by a
        # path that climbs out of the tree.
        self.setUp()
        source = self.row("ANNEXC-REAL-001")["source"]
        outside = pathlib.Path(self.scratch()) / "vector.json"
        outside.write_bytes((self.repo / source["path"]).read_bytes())
        for path in (str(outside), os.path.relpath(outside, self.repo)):
            with self.subTest(path=path):
                source["path"] = path
                self.assertFails("copies no file this tree holds")

    def test_a_copied_member_absent_from_both_the_row_and_its_file_fails(self):
        # Absent from both, the two compare equal (None == None): the row then copies nothing from its file.
        for field, member in agree.COPIED:
            with self.subTest(field):
                self.setUp()
                row = self.row("ANNEXC-REAL-001")
                path = self.repo / row["source"]["path"]
                vector = json.loads(path.read_bytes())
                parent = vector
                for name in member[:-1]:
                    parent = parent[name]
                del parent[member[-1]]
                raw = json.dumps(vector).encode()
                path.write_bytes(raw)
                row["source"]["sha256"] = hashlib.sha256(raw).hexdigest()
                del row[field]
                self.assertFails("ANNEXC-REAL-001's %s is not its file's %s" % (field, ".".join(member)))

    def test_a_window_row_whose_dates_no_longer_separate_the_instant_from_the_run_date_fails(self):
        apart, unsigned = " no longer separates the instant from the run date", "'s dates are out of order"
        cases = ((VALID, [("document_signer", "not_after", "2027-01-01T00:00:00Z")], VALID + apart),
                 (VALID, [("document_signer", "not_before", "2026-05-01T00:00:00Z"),
                          ("document_signer", "not_after", "2026-05-31T00:00:00Z"),
                          ("mso", "signed", "2026-05-15T00:00:00Z"), ("mso", "valid_from", "2026-05-15T00:00:00Z")],
                  VALID + apart),
                 (NOT_YET, [("document_signer", "not_after", "2026-10-01T00:00:00Z")], NOT_YET + apart),
                 (VALID, [("mso", "signed", "2026-07-02T00:00:00Z"), ("mso", "valid_from", "2026-07-02T00:00:00Z")],
                  VALID + unsigned),
                 (VALID, [("mso", "valid_until", "2026-06-01T11:00:00Z")], VALID + unsigned),
                 (VALID, [("mso", "valid_until", "2026-07-01T12:00:00Z")], VALID + apart),
                 (VALID, [("mso", "valid_from", "2026-06-01T12:30:00Z")], VALID + apart),
                 (NOT_YET, [("document_signer", "not_before", "2026-12-01T00:00:00Z"),
                            ("mso", "signed", "2026-12-01T01:00:00Z"), ("mso", "valid_from", "2026-12-01T01:00:00Z")],
                  NOT_YET + apart),
                 (NOT_YET, [("document_signer", "not_before", "2026-06-01T12:00:00Z")], NOT_YET + apart),
                 (NOT_YET, [("mso", "valid_until", "2026-07-01T12:00:00Z")], NOT_YET + apart),
                 (NOT_YET, [("mso", "signed", "2026-06-01T11:00:00Z")], NOT_YET + unsigned),
                 (VALID, [("mso", "signed", "2026-06-01T12:30:00Z")], VALID + unsigned))
        for row_id, changes, needle in cases:
            with self.subTest(needle, changes=changes):
                self.setUp()
                for part, field, value in changes:
                    self.row(row_id)[part][field] = value
                self.assertFails(needle)
        self.setUp()
        del self.row(VALID)["mso"]
        self.assertFails(VALID + " states no document signer or MSO window")

    def test_a_window_row_that_does_not_turn_at_the_run_date_fails_on_either_side(self):
        self.theirs_later[VALID] = {"outcome": "accepted", "claims": CLAIMS}
        lines = self.assertFails(VALID + " at the run date: OID4VCgo gave accepted, not refused")
        self.assertTrue(lines[-1].endswith("WINDOW-ROWS-TURNED-AT-THE-RUN-DATE 1"), lines[-1])
        self.setUp()
        self.ours_later[NOT_YET] = refusal(agree.OURS, "document_signer_validity")
        self.assertFails(NOT_YET + " at the run date: Polaris gave refused, not accepted")
        self.setUp()
        del self.theirs_later[NOT_YET]
        self.assertFails(NOT_YET + " at the run date: OID4VCgo gave no verdict, not accepted")
        self.setUp()
        self.ours_later = {}
        self.assertFails(VALID + " at the run date: Polaris gave no verdict, not refused")

    def test_the_valid_row_refused_at_the_run_date_for_another_reason_fails(self):
        self.theirs_later[VALID] = {"outcome": "refused", "error": "mdocdcapi: mdoc: the MSO expired"}
        self.assertFails(VALID + " at the run date: OID4VCgo refused it with")
        self.setUp()
        self.ours_later[VALID] = refusal(agree.OURS, "open")
        lines = self.assertFails(VALID + " at the run date: Polaris refused it at hpke")
        self.assertTrue(lines[-1].endswith("WINDOW-ROWS-TURNED-AT-THE-RUN-DATE 1"), lines[-1])

    def test_window_rows_without_both_verdicts_fail(self):
        self.row(NOT_YET)["kind"] = "control"
        self.row(NOT_YET)["of"] = VALID
        self.assertFails("the window rows do not hold one row valid at the instant and one not yet valid there")

    def test_a_control_of_a_row_not_both_accept_or_a_row_of_no_kind_fails(self):
        self.row("CONTROL-ANOTHER-KEY")["of"] = NOT_YET
        self.assertFails("CONTROL-ANOTHER-KEY is a control of %r" % NOT_YET)
        self.row("CONTROL-ANOTHER-KEY")["of"] = "NO-SUCH-ROW"
        self.assertFails("CONTROL-ANOTHER-KEY is a control of 'NO-SUCH-ROW'")
        self.setUp()
        self.row("CONTROL-ANOTHER-KEY")["kind"] = "extra"
        self.assertFails("CONTROL-ANOTHER-KEY is of kind 'extra'")

    def test_read_theirs_refuses_a_file_it_cannot_take_as_one_verdict_per_row_and_time(self):
        path = os.path.join(self.scratch(), "theirs.jsonl")
        cases = (("", "holds no verdict"),
                 ('{"id": "A", "when": "instant", "outcome": "refused"}\n'
                  '{"id": "A", "when": "instant", "outcome": "accepted"}\n', "judged A twice at the instant"),
                 ('{"id": "A", "outcome": "refused"}\n', "line 1 is not a verdict line"),
                 ('{"id": "A", "when": "yesterday", "outcome": "refused"}\n', "line 1 is not a verdict line"),
                 ('{"when": "instant", "outcome": "refused"}\n', "line 1 is not a verdict line"),
                 ("WITNESS-DONE 1\n", "line 1 is not a verdict line"))
        for text, needle in cases:
            with self.subTest(needle):
                with open(path, "w") as handle:
                    handle.write(text)
                _, problems = agree.read_theirs(path)
                self.assertTrue(any(needle in problem for problem in problems), problems)
        with open(path, "w") as handle:
            handle.write('{"id": "A", "when": "instant", "outcome": "refused"}\n'
                         '{"id": "A", "when": "run_date", "outcome": "accepted"}\n')
        self.assertEqual(agree.read_theirs(path), ({"instant": {"A": {"id": "A", "when": "instant", "outcome": "refused"}},
                                                    "run_date": {"A": {"id": "A", "when": "run_date",
                                                                       "outcome": "accepted"}}}, []))

    def test_main_exits_1_and_prints_fail_on_a_wrong_verdict_or_a_broken_verdict_file(self):
        # main as the workflow runs it, over a rows file and OID4VCgo's verdict file, with this repository's
        # verdicts (ours(), which needs the cryptography) given as fixed ones and the outside files in self.repo.
        directory = pathlib.Path(self.scratch())
        rows_path, theirs_path = directory / "rows.json", directory / "annexc.jsonl"
        rows_path.write_text(json.dumps(self.fixture))
        real_judge = agree.judge

        def judge(*args, **kwargs):
            return real_judge(*args, **dict(kwargs, repo=self.repo))

        def ours(fixture, when=None, only=None):
            return copy.deepcopy(self.ours_later if when else self.ours)

        def run(theirs_lines):
            theirs_path.write_text("".join(json.dumps(line) + "\n" for line in theirs_lines))
            out = io.StringIO()
            with mock.patch.object(agree, "ours", ours), mock.patch.object(agree, "judge", judge), \
                    contextlib.redirect_stdout(out):
                status = agree.main(["agree.py", str(theirs_path), str(rows_path)])
            return status, out.getvalue().splitlines()

        clean = ([dict(verdict, id=row_id, when="instant") for row_id, verdict in self.theirs.items()]
                 + [dict(verdict, id=row_id, when="run_date") for row_id, verdict in self.theirs_later.items()])
        status, lines = run(clean)
        self.assertEqual((status, lines[-1]), (0, "AGREEMENT TABLE: PASS"), lines)
        self.assertEqual([line for line in lines if line.startswith("FAIL ")], [])
        accepted = [dict(line, outcome="accepted", claims=CLAIMS) if line["id"] == "ANNEXC-REAL-001" else line
                    for line in clean]
        for name, theirs_lines, needle in (
                ("a row their verifier judges otherwise", accepted, "ANNEXC-REAL-001: OID4VCgo accepted it"),
                ("a verdict file judging a row twice", clean + clean[:1],
                 "judged ANNEXC-DETERMINISTIC-001 twice at the instant"),
                ("a verdict file with a line that is no verdict", clean + [{"WITNESS-DONE": 1}],
                 "line %d is not a verdict line" % (len(clean) + 1))):
            with self.subTest(name):
                status, lines = run(theirs_lines)
                self.assertEqual((status, lines[-1]), (1, "AGREEMENT TABLE: FAIL"), lines)
                self.assertTrue(any(line.startswith("FAIL ") and needle in line for line in lines), lines)

    def test_the_workflow_gate_passes_only_on_exit_0_with_one_pass_line_and_no_fail_line(self):
        # agree-gate.sh, which the workflow step runs, over made-up agree.py outputs: a stand-in agree.py beside a
        # copy of the gate prints each and exits with each status.
        bash, bin_dir = shutil.which("bash"), self.scratch()
        self.assertIsNotNone(bash, "no bash on PATH")
        os.symlink(sys.executable, os.path.join(bin_dir, "python"))
        env = {"PATH": os.pathsep.join((bin_dir, "/usr/bin", "/bin"))}
        cases = (("the table passes", 0, "ROW A\nAGREEMENT TABLE: PASS\n", 0),
                 ("exit 1 under a PASS line", 1, "ROW A\nAGREEMENT TABLE: PASS\n", 1),
                 ("exit 0 with FAIL printed", 0, "ROW A\nFAIL A: OID4VCgo accepted it\nAGREEMENT TABLE: FAIL\n", 1),
                 ("exit 0 with no table line", 0, "ROW A\n", 1),
                 ("exit 0 with nothing printed", 0, "", 1),
                 ("a FAIL line beside a PASS line", 0, "FAIL A: no verdict\nAGREEMENT TABLE: PASS\n", 1),
                 ("a FAIL table line beside a PASS line", 0, "AGREEMENT TABLE: PASS\nAGREEMENT TABLE: FAIL\n", 1),
                 ("two PASS lines", 0, "AGREEMENT TABLE: PASS\nAGREEMENT TABLE: PASS\n", 1),
                 ("a PASS line that is not the whole line", 0, "AGREEMENT TABLE: PASSED\n", 1))
        for name, status, text, want in cases:
            with self.subTest(name):
                directory = self.scratch()
                shutil.copy(os.path.join(HERE, "agree-gate.sh"), directory)
                with open(os.path.join(directory, "agree.py"), "w") as handle:
                    handle.write("import sys\nsys.stdout.write(%r)\nsys.exit(%d)\n" % (text, status))
                run = subprocess.run([str(bash), os.path.join(directory, "agree-gate.sh"), "annexc.jsonl"],
                                     capture_output=True, text=True, env=env)
                self.assertEqual(run.returncode, want, run.stdout + run.stderr)
                self.assertTrue(run.stdout.startswith(text), run.stdout)
                self.assertEqual(run.stdout.rstrip("\n").endswith("agree-gate: PASS"), want == 0, run.stdout)

    def test_a_wrong_argument_count_exits_2(self):
        run = [sys.executable, "-I", os.path.join(HERE, "agree.py")]
        self.assertEqual(subprocess.run(run, capture_output=True).returncode, 2)


if __name__ == "__main__":
    unittest.main()
