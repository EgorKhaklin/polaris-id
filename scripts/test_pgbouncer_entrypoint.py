# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The pooler's entrypoint keeps the operator scope inside one session.

The application puts the operator's authority into the database session and the row-level
policies read it (docs/design/per-authority-isolation.md). A transaction-mode pooler hands a
server connection to the next client with that session unreset, so an unrelated request ran
under the previous operator's authority. These tests run the real entrypoint, with a stand-in
`pgbouncer` on PATH that prints the ini it was handed, and assert what it generates and what it
refuses. They need no database and no pgbouncer install.

    python3 -m unittest test_pgbouncer_entrypoint      (from scripts/)
"""
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "polaris_web" / "pgbouncer-entrypoint.sh"


class PoolerKeepsTheOperatorScopeInOneSession(unittest.TestCase):

    def _run(self, **env):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="pgb-entry-"))
        (tmp / "pw").write_text("a-test-password-only")
        stub = tmp / "bin"
        stub.mkdir()
        # The stand-in pooler: print the generated ini, then exit 0 (exec replaces the shell).
        (stub / "pgbouncer").write_text('#!/bin/sh\ncat "$1"\n')
        (stub / "pgbouncer").chmod(0o755)
        full = {"PATH": "%s:%s" % (stub, os.environ.get("PATH", "")),
                "POLARIS_DB_PASSWORD_FILE": str(tmp / "pw"),
                "PGBOUNCER_CONF_DIR": str(tmp / "conf")}
        full.update(env)
        return subprocess.run(["sh", str(ENTRYPOINT)], env=full, capture_output=True, text=True,
                              timeout=30)

    def test_the_default_is_session_pooling_with_a_reset(self):
        r = self._run()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("pool_mode = session", r.stdout)
        self.assertIn("server_reset_query = DISCARD ALL", r.stdout)

    def test_transaction_and_statement_pooling_are_refused(self):
        for mode in ("transaction", "statement"):
            with self.subTest(mode=mode):
                r = self._run(PGBOUNCER_POOL_MODE=mode)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("is refused", r.stderr)
                self.assertIn("per-authority-isolation.md", r.stderr)
                self.assertNotIn("pool_mode", r.stdout, "no ini may be served in a refused mode")

    def test_session_named_explicitly_is_accepted(self):
        r = self._run(PGBOUNCER_POOL_MODE="session")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("pool_mode = session", r.stdout)

    def test_an_unknown_mode_is_refused(self):
        r = self._run(PGBOUNCER_POOL_MODE="sessions")
        self.assertEqual(r.returncode, 1)
        self.assertIn("must be session", r.stderr)


if __name__ == "__main__":
    unittest.main()
