# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""test_transparency_tools.py -- the transparency monitor and witness follow the log --log names.

The app serves three logs under /api/v1/transparency (rp_api.py): the audit anchors at the
root, the exchange receipts under /receipts and the anchored timestamps under /timestamps.
Each tool runs offline against a stand-in that serves another head on each log, with a
verifier that accepts every head, so a test reads only which log the tool followed: the head
it recorded and the routes it asked for. What the verifier decides about a head is
test_verify_refusals's, and the drills run both tools against a live log.

    cd scripts && python3 -m unittest test_transparency_tools
"""
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import re
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MONITOR = _load("polaris_transparency_monitor", "polaris-transparency-monitor.py")
WITNESS = _load("polaris_transparency_witness", "polaris-transparency-witness.py")

# --log -> (the routes' prefix, the log_id rp_api.py signs into that log's heads).
LOGS = {"anchors": ("/api/v1/transparency", "polaris-audit-anchor-log"),
        "receipts": ("/api/v1/transparency/receipts", "polaris-exchange-receipt-log"),
        "timestamps": ("/api/v1/transparency/timestamps", "polaris-timestamp-log")}
ANCHOR = "ab" * 32


class StandIn:
    """Three logs at once, each at its own size; records every path asked for."""

    def __init__(self, size):
        self.size, self.paths = size, []

    def get(self, base, path):
        self.paths.append(path)
        prefix, log_id = max(((p, i) for p, i in LOGS.values() if path.startswith(p + "/")), key=lambda t: len(t[0]))
        rest = path[len(prefix):]
        if rest == "/sth":
            return {"format": "polaris-sth", "log_id": log_id, "tree_size": self.size,
                    "root_hash_hex": ("%02x" % self.size) * 32, "timestamp": "2026-10-24T00:00:0%dZ" % self.size}
        if rest.startswith("/consistency/"):
            return {"proof_hex": []}
        if rest == "/entries":
            return {"entries": []}
        raise AssertionError("no such route on the stand-in: %s" % path)


class AcceptAll:
    @staticmethod
    def verify_sth(sth, issuer_key=None):
        return {"sth_authentic": True, "issuer_matches": True, "note": None}

    @staticmethod
    def verify_log_consistency(old, new, proof, issuer_key=None):
        return {"fork": False, "consistent": True, "note": None}

    @staticmethod
    def verify_equivocation(a, b, issuer_key=None):
        return {"proven": False, "note": None}


def _cosign(head, key_file):
    return {"log_id": head["log_id"], "tree_size": head["tree_size"], "public_key_hex": "cd" * 32}


def _run(tool, argv, server):
    out, err = io.StringIO(), io.StringIO()
    patches = [mock.patch.object(tool, "_get", server.get), mock.patch.object(tool, "_load_verifier", AcceptAll)]
    if tool is WITNESS:
        patches.append(mock.patch.object(tool, "cosign", _cosign))
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        stack.enter_context(contextlib.redirect_stdout(out))
        stack.enter_context(contextlib.redirect_stderr(err))
        code = tool.main(argv)
    return code, out.getvalue() + err.getvalue()


class FollowsTheNamedLog(unittest.TestCase):
    def _two_polls(self, tool, log, extra=()):
        prefix, log_id = LOGS[log]
        with tempfile.TemporaryDirectory() as state:
            argv = ["--url", "http://log.invalid", "--anchor", ANCHOR, "--state", state, "--log", log] + list(extra)
            first, second = StandIn(1), StandIn(2)
            code, out = _run(tool, argv, first)
            self.assertEqual(code, 0, out)
            code, out = _run(tool, argv, second)
            self.assertEqual(code, 0, out)
            with open(os.path.join(state, "last_sth.json")) as f:
                recorded = json.load(f)
        self.assertEqual((recorded["log_id"], recorded["tree_size"]), (log_id, 2))
        self.assertIn(prefix + "/consistency/1/2", second.paths)
        for path in first.paths + second.paths:
            self.assertEqual(re.sub(r"/(sth|entries|consistency/\d+/\d+)$", "", path), prefix, path)

    def test_the_monitor_follows_each_log(self):
        for log in LOGS:
            with self.subTest(log=log):
                self._two_polls(MONITOR, log)

    def test_the_witness_follows_each_log(self):
        with tempfile.TemporaryDirectory() as keys:
            key_file = os.path.join(keys, "witness.key.json")
            for log in LOGS:
                with self.subTest(log=log):
                    self._two_polls(WITNESS, log, ("--key", key_file))


if __name__ == "__main__":
    unittest.main()
