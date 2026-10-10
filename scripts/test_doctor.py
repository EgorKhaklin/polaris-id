# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The doctor says what a running install still lacks.

pgBackRest keeps its repository on the host unless POLARIS_PGBACKREST_S3_BUCKET names an offsite
one, and a repository on the host is lost with it: the backups and the WAL a point-in-time restore
replays (lab record 017, gate row OP-14). These tests run the real scripts/polaris-doctor.sh under
bash with a stand-in `docker` that answers as the database container would, and read the line the
doctor prints for the backups. No Docker, no database.

    python3 -m unittest test_doctor      (from scripts/)
"""
import pathlib
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCTOR = ROOT / "scripts" / "polaris-doctor.sh"

# The stand-in docker: `info` and `compose config` answer so the doctor examines a stack; the
# database container's environment is STUB_ARCHIVING and STUB_BUCKET; every other call fails, which
# the doctor reports as a failing component and carries on.
STUB = r'''#!%(python)s
import os, sys
line = " ".join(sys.argv[1:])
if sys.argv[1:2] == ["info"]:
    sys.exit(0)
if "config --services" in line:
    print("postgres"); sys.exit(0)
if "ps -a --format json" in line:
    print("[]"); sys.exit(0)
for name, var in (("POLARIS_PGBACKREST_ENABLED", "STUB_ARCHIVING"), ("POLARIS_PGBACKREST_S3_BUCKET", "STUB_BUCKET")):
    if "printenv " + name in line:
        print(os.environ.get(var, "")); sys.exit(0)
sys.exit(1)
'''


def closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]          # released on close: nothing listens there now


class BackupsTests(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-doctor-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        (self.bin / "docker").write_text(STUB % {"python": sys.executable})
        (self.bin / "systemctl").write_text("#!/bin/sh\nexit 0\n")
        for f in self.bin.iterdir():
            f.chmod(0o755)

    def backups_line(self, **env):
        full = {"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % self.bin, "HOME": str(self.tmp),
                "POLARIS_ENV_FILE": "", "POLARIS_DOMAIN": "localhost",
                "POLARIS_DOCTOR_URL": "https://127.0.0.1:%d" % closed_port()}
        full.update(env)
        r = subprocess.run(["bash", str(DOCTOR)], env=full, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=120)
        lines = [ln for ln in r.stdout.splitlines() if ln.split()[1:2] == ["backups"]]
        self.assertEqual(len(lines), 1, r.stdout + r.stderr)
        return lines[0]

    def test_a_repository_on_the_host_is_a_warning(self):
        line = self.backups_line(STUB_ARCHIVING="1", STUB_BUCKET="")
        self.assertTrue(line.lstrip().startswith("WARN"), line)
        self.assertIn("on this host", line)
        self.assertIn("DR.md section 5", line)

    def test_archiving_switched_off_is_a_warning(self):
        line = self.backups_line(STUB_ARCHIVING="0", STUB_BUCKET="polaris-dr")
        self.assertTrue(line.lstrip().startswith("WARN"), line)
        self.assertIn("continuous archiving is off", line)

    def test_an_offsite_repository_is_named(self):
        line = self.backups_line(STUB_ARCHIVING="1", STUB_BUCKET="polaris-dr")
        self.assertTrue(line.lstrip().startswith("ok"), line)
        self.assertIn("s3://polaris-dr", line)


if __name__ == "__main__":
    unittest.main()
