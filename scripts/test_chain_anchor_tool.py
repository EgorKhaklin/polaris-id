# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_chain_anchor_tool.py -- scripts/polaris-chain-anchor.py, offline (decision 013).

The decision itself is verify_chain_anchor's and test_verify_refusals drives each of its
refusals. This holds the tool to what an operator and a monitor read from it: the exit code
(0 anchored, 1 pending, 2 refused, 3 a usage or transport error), the file anchor-record
consumes, and `check`'s two findings, an anchor that does not verify and a log that no longer
extends its anchored head. No network: block headers come through --header, as from the
caller's own node, and `check` reads a stand-in instance.

    cd scripts && python3 -m unittest test_chain_anchor_tool
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURE = json.loads((ROOT / "sdk" / "testdata" / "chain-anchor-969876.json").read_text())
_spec = importlib.util.spec_from_file_location("polaris_chain_anchor", HERE / "polaris-chain-anchor.py")
T = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(T)
V = T._load_verifier()


def _run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = T.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class VerifyExitCodes(unittest.TestCase):

    def setUp(self):
        d = tempfile.mkdtemp()
        self.dir = pathlib.Path(d)
        self.checkpoint = self.dir / "checkpoint.json"
        self.checkpoint.write_text(FIXTURE["anchor"]["checkpoint"])
        self.proof = self.dir / "checkpoint.json.ots"
        self.proof.write_bytes(bytes.fromhex(FIXTURE["anchor"]["proof_hex"]))
        self.header = "969876=" + FIXTURE["headers"]["969876"]

    def test_an_anchor_from_the_caller_s_own_node_holds_and_is_written_for_anchor_record(self):
        out_file = self.dir / "anchor.json"
        code, out, _ = _run("verify", str(self.checkpoint), str(self.proof), "--header", self.header,
                            "--out", str(out_file))
        self.assertEqual(code, 0, out)
        self.assertIn("ANCHORED: in Bitcoin block 969876", out)
        doc = json.loads(out_file.read_text())
        self.assertEqual(doc["anchor"]["checkpoint"], FIXTURE["anchor"]["checkpoint"])
        self.assertEqual(doc["min_sources"], 1)
        # What anchor-record decides again, offline, from the file alone.
        self.assertTrue(V.verify_chain_anchor(doc["anchor"], doc["headers"], doc["min_sources"])["anchored"])

    def test_a_node_header_and_one_named_source_need_both_by_default(self):
        with mock.patch.object(T, "_esplora_header", return_value=FIXTURE["headers"]["969876"]):
            code, out, _ = _run("verify", str(self.checkpoint), str(self.proof), "--header", self.header,
                                "--source", "https://esplora.example/api")
        self.assertEqual(code, 0, out)
        self.assertIn("read from 2 source(s)", out)

    def test_the_wrong_block_is_refused_with_exit_2(self):
        code, out, _ = _run("verify", str(self.checkpoint), str(self.proof),
                            "--header", "969876=" + FIXTURE["headers"]["969877"])
        self.assertEqual(code, 2, out)
        self.assertIn("REFUSED", out)

    def test_a_changed_checkpoint_is_refused_with_exit_2(self):
        self.checkpoint.write_text(FIXTURE["anchor"]["checkpoint"].replace('"tree_size":194', '"tree_size":195'))
        code, out, _ = _run("verify", str(self.checkpoint), str(self.proof), "--header", self.header)
        self.assertEqual(code, 2, out)
        self.assertIn("another digest", out)

    def test_a_pending_proof_is_exit_1(self):
        digest = hashlib.sha256(self.checkpoint.read_bytes()).digest()
        pending = b"\x00" + bytes.fromhex("83dfe30d2ef90c8e") + b"\x06\x05https"
        self.proof.write_bytes(V._OTS_MAGIC + b"\x01\x08" + digest + pending)
        code, out, _ = _run("verify", str(self.checkpoint), str(self.proof), "--header", self.header)
        self.assertEqual(code, 1, out)
        self.assertIn("PENDING", out)

    def test_a_malformed_header_flag_or_a_missing_file_is_exit_3(self):
        self.assertEqual(_run("verify", str(self.checkpoint), str(self.proof), "--header", "abc")[0], 3)
        self.assertEqual(_run("verify", str(self.dir / "absent.json"), str(self.proof), "--header", self.header)[0], 3)


class CheckAgainstAnInstance(unittest.TestCase):
    """`check` against a stand-in instance serving the fixture anchor and the three logs."""

    HEADS = {h["log_id"]: h for h in json.loads(FIXTURE["anchor"]["checkpoint"])["heads"]}

    def serve(self, timestamp_head, consistency=None):
        anchor = dict(FIXTURE["anchor"], anchor_id=1)

        def get(url, raw=False):
            if url.endswith("/api/v1/transparency/anchors?start=0"):
                return {"count": 1, "start": 0, "end": 1, "anchors": [anchor]}
            for log_id, path in T._LOGS.items():
                if url.endswith(path + "/sth"):
                    return timestamp_head if log_id == "polaris-timestamp-log" else self.HEADS[log_id]
            if "/timestamps/consistency/" in url:
                return {"proof_hex": consistency or []}
            raise AssertionError("unexpected fetch " + url)
        return mock.patch.object(T, "_get", side_effect=get)

    def headers(self):
        return mock.patch.object(T, "_esplora_header", return_value=FIXTURE["headers"]["969876"])

    def test_logs_that_still_hold_the_anchored_heads_pass(self):
        with self.serve(self.HEADS["polaris-timestamp-log"]), self.headers():
            code, out, _ = _run("check", "--url", "https://polaris.example")
        self.assertEqual(code, 0, out)
        self.assertIn("anchor 1: in Bitcoin block 969876", out)
        self.assertIn("size 194 extends the anchored 194", out)

    def test_a_log_whose_root_moved_at_the_anchored_size_is_exit_2(self):
        moved = dict(self.HEADS["polaris-timestamp-log"], root_hash_hex="00" * 32)
        with self.serve(moved), self.headers():
            code, out, _ = _run("check", "--url", "https://polaris.example")
        self.assertEqual(code, 2, out)
        self.assertIn("does NOT extend the anchored size 194", out)

    def test_a_log_shorter_than_its_anchor_is_exit_2(self):
        shrunk = dict(self.HEADS["polaris-timestamp-log"], tree_size=193)
        with self.serve(shrunk), self.headers():
            code, out, _ = _run("check", "--url", "https://polaris.example")
        self.assertEqual(code, 2, out)
        self.assertIn("fewer than the 194 anchored", out)

    def test_an_anchor_that_does_not_verify_is_exit_2(self):
        with self.serve(self.HEADS["polaris-timestamp-log"]), \
                mock.patch.object(T, "_esplora_header", return_value=FIXTURE["headers"]["969877"]):
            code, out, _ = _run("check", "--url", "https://polaris.example")
        self.assertEqual(code, 2, out)
        self.assertIn("REFUSED anchor 1", out)


if __name__ == "__main__":
    unittest.main()
