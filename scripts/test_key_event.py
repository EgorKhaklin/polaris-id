# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""An install's last steps are one command each: the signing key, and a relying party.

Under real signing every relying-party route refuses a credential whose key its authority had not
registered when it signed (KEY-CEREMONY.md), and no install path registered one: a fresh install's
relying-party API refused its own credentials. `polaris-key-event.sh register AGENCY --current`
reads the key from the running app's custody, registers an authority's first key, and never rotates. On
the Docker stack the documented `polaris rp-register` could not reach the database as its owner;
`polaris-rp-register.sh` runs the CLI's statements there. These tests run the real scripts under
bash with a stand-in `docker` that answers as the stack would and records every call. No Docker,
no database.

    python3 -m unittest test_key_event      (from scripts/)
"""
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
KEY_EVENT = ROOT / "scripts" / "polaris-key-event.sh"
RP_REGISTER = ROOT / "scripts" / "polaris-rp-register.sh"
KEY = "ab" * 1952                           # an ML-DSA-65 public key's length in hex: 3904
OTHER = "cd" * 1952

# The stand-in docker: `compose ... exec -T app python ...` answers as the app would and
# `compose ... exec -T postgres psql ...` as the database; every call (its argv and its stdin) is
# appended to calls.jsonl, so a test reads exactly what reached the stack.
STUB = r'''#!%(python)s
import json, os, sys
args = sys.argv[1:]
stdin = "" if sys.stdin.isatty() else sys.stdin.read()
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps({"argv": args, "stdin": stdin}) + "\n")
line = " ".join(args)
if "custody.py public-key" in line:
    if not os.environ.get("STUB_PK"):
        sys.stderr.write("custody: no signing key is configured\n"); sys.exit(3)
    if os.environ.get("STUB_BANNER"):
        print("liboqs-python faulthandler is disabled")
    print(os.environ["STUB_PK"]); sys.exit(0)
if "generate_password_hash" in line:
    print("scrypt:32768:8:1$salt$" + "0" * 16); sys.exit(0)
if "psql" in line:
    if "FROM AuthorityKeyCurrent" in stdin:     # --current's read: the key's status|events|active keys
        print(os.environ.get("STUB_STATE", "none|0|")); sys.exit(0)
    if "INSERT INTO RelyingParty" in stdin:
        if os.environ.get("STUB_REFUSE"):
            sys.stderr.write("ERROR:  refused\n"); sys.exit(3)
        print("42"); sys.exit(0)
    if "INSERT INTO AuthorityKeyEvent" in stdin:
        print("recorded key event #7"); sys.exit(0)
sys.stderr.write("stub docker: unexpected call: %%s\n" %% line); sys.exit(99)
'''


class _Base(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="polaris-key-event-"))
        self.log = self.tmp / "calls.jsonl"
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        (self.bin / "docker").write_text(STUB % {"python": sys.executable})
        # The loader asks systemd which configuration the unit runs; this host runs none.
        (self.bin / "systemctl").write_text("#!/bin/sh\nexit 0\n")
        for f in self.bin.iterdir():
            f.chmod(0o755)

    def run_script(self, script, *args, **env):
        full = {"PATH": "%s:/usr/bin:/bin:/usr/sbin:/sbin" % self.bin, "HOME": str(self.tmp),
                "STUB_LOG": str(self.log), "POLARIS_ENV_FILE": ""}       # set and empty: no file
        full.update(env)
        # stdin closed: a call that sends nothing must read nothing, not wait on the runner's own input.
        return subprocess.run(["bash", str(script), *args], env=full, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=60)

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def inserts(self, table):
        return [c for c in self.calls() if ("INSERT INTO %s" % table) in c["stdin"]]

    @staticmethod
    def var(call, name):
        """The value a psql -v NAME=VALUE argument carried."""
        argv = call["argv"]
        for i, a in enumerate(argv):
            if a == "-v" and i + 1 < len(argv) and argv[i + 1].startswith(name + "="):
                return argv[i + 1].split("=", 1)[1]
        return None


class RegisterCurrentTests(_Base):

    def test_the_key_is_read_from_the_app_and_registered(self):
        r = self.run_script(KEY_EVENT, "register", "1", "--current", STUB_PK=KEY)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        [ins] = self.inserts("AuthorityKeyEvent")
        self.assertEqual(self.var(ins, "pk"), KEY)
        self.assertEqual(self.var(ins, "ev"), "registered")
        self.assertEqual(self.var(ins, "agency"), "1")
        self.assertIn("--current", self.var(ins, "note"))
        self.assertEqual(self.var(ins, "first"), "1")
        read = [c for c in self.calls() if "custody.py public-key" in " ".join(c["argv"])]
        self.assertEqual(len(read), 1)
        self.assertIn("--agency 1", " ".join(read[0]["argv"]))

    def test_a_banner_on_stdout_is_not_taken_for_the_key(self):
        r = self.run_script(KEY_EVENT, "register", "1", "--current", STUB_PK=KEY, STUB_BANNER="1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.var(self.inserts("AuthorityKeyEvent")[0], "pk"), KEY)

    def test_a_key_already_active_is_left_alone(self):
        r = self.run_script(KEY_EVENT, "register", "1", "--current", STUB_PK=KEY, STUB_STATE="active|1|" + KEY)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("already registered", r.stdout)
        self.assertEqual(self.inserts("AuthorityKeyEvent"), [])

    def test_another_active_key_is_never_rotated_by_the_script(self):
        r = self.run_script(KEY_EVENT, "register", "1", "--current", STUB_PK=KEY, STUB_STATE="none|1|" + OTHER)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("rotation", r.stderr)
        self.assertEqual(self.inserts("AuthorityKeyEvent"), [])

    def test_an_ended_key_is_never_registered_again(self):
        for status in ("retired", "compromised"):
            with self.subTest(status):
                r = self.run_script(KEY_EVENT, "register", "1", "--current", STUB_PK=KEY, STUB_STATE=status + "|2|")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("never registered again", r.stderr)
                self.assertEqual(self.inserts("AuthorityKeyEvent"), [])

    def test_a_key_after_the_first_is_the_ceremonys(self):
        r = self.run_script(KEY_EVENT, "register", "1", "--current", STUB_PK=KEY, STUB_STATE="none|2|")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("first key", r.stderr)
        self.assertEqual(self.inserts("AuthorityKeyEvent"), [])

    def test_no_key_in_the_app_is_refused(self):
        r = self.run_script(KEY_EVENT, "register", "1", "--current")      # placeholder profile
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual(self.inserts("AuthorityKeyEvent"), [])

    def test_a_key_of_no_accepted_length_is_refused(self):
        r = self.run_script(KEY_EVENT, "register", "1", "--current", STUB_PK="ab" * 100)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual(self.inserts("AuthorityKeyEvent"), [])

    def test_current_is_for_registration_only_and_dates_itself(self):
        for args in (("retire", "1", "--current"), ("compromise", "1", "--current"),
                     ("register", "1", "--current", "--effective-at", "2026-01-01T00:00:00")):
            with self.subTest(args):
                r = self.run_script(KEY_EVENT, *args, STUB_PK=KEY)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertEqual(self.inserts("AuthorityKeyEvent"), [])

    def test_a_key_named_by_its_hex_still_registers_without_asking_the_app(self):
        r = self.run_script(KEY_EVENT, "register", "1", OTHER.upper())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.var(self.inserts("AuthorityKeyEvent")[0], "pk"), OTHER)
        self.assertEqual(self.var(self.inserts("AuthorityKeyEvent")[0], "first"), "0")
        self.assertFalse([c for c in self.calls() if "custody.py" in " ".join(c["argv"])])


class RelyingPartyTests(_Base):

    WHY = "the bank that verifies credentials at account opening"

    def test_a_party_is_registered_with_the_clis_statement(self):
        r = self.run_script(RP_REGISTER, "First Bank", "--justification", self.WHY, "--scope", "verify",
                            "--rate-limit-per-min", "60", "--required-enrollment", "ENROLLED",
                            "--required-context", "3", "--require-zk")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        [ins] = self.inserts("RelyingParty")
        for name, want in (("org", "First Bank"), ("scope", "verify"), ("rate", "60"), ("zk", "true"),
                           ("enroll", "ENROLLED"), ("ctx", "3"), ("why", self.WHY)):
            self.assertEqual(self.var(ins, name), want, name)
        self.assertRegex(self.var(ins, "cid"), r"\Arp_[0-9a-f]{24}\Z")
        self.assertTrue(self.var(ins, "h").startswith("scrypt:"))
        self.assertIn("polaris.actor", ins["stdin"])
        self.assertIn("polaris.justification", ins["stdin"])
        self.assertIn("registered relying party #42: First Bank", r.stdout)

    def test_the_secret_is_shown_once_and_never_on_a_command_line(self):
        r = self.run_script(RP_REGISTER, "First Bank", "--justification", self.WHY)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        secret = re.search(r"client_secret: (\S+)", r.stdout).group(1)
        [hashed] = [c for c in self.calls() if "generate_password_hash" in " ".join(c["argv"])]
        self.assertEqual(hashed["stdin"], secret, "the secret is hashed from stdin")
        for c in self.calls():
            self.assertNotIn(secret, " ".join(c["argv"]))
            if "generate_password_hash" not in " ".join(c["argv"]):
                self.assertNotIn(secret, c["stdin"], "only the hashing call receives the secret")

    def test_a_short_reason_is_refused_before_the_stack_is_asked(self):
        r = self.run_script(RP_REGISTER, "First Bank", "--justification", "   because   ")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual(self.calls(), [])

    def test_an_unknown_scope_or_option_is_usage(self):
        for args in (("First Bank", "--justification", self.WHY, "--scope", "everything"),
                     ("First Bank", "--justification", self.WHY, "--rate-limit-per-min", "fast"),
                     ("--justification", self.WHY)):
            with self.subTest(args):
                r = self.run_script(RP_REGISTER, *args)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertEqual(self.calls(), [])

    def test_a_refusal_by_the_database_is_an_error(self):
        r = self.run_script(RP_REGISTER, "First Bank", "--justification", self.WHY, STUB_REFUSE="1")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertNotIn("client_secret", r.stdout)


if __name__ == "__main__":
    unittest.main()
