# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""scripts/polaris-dev-tunnel.sh hands --once, --vct and --claim to `polaris-oid4vp serve`, and
reuses a PKI directory that already holds one rather than minting new keys over it, unless its
leaf has expired (keygen makes it valid for 90 days), which it refuses with how to remint.

On every exit (the verifier returning, as `--once` does after one presentation; Ctrl-C; a TERM)
it stops the tunnel and the verifier and deletes the tunnel's log, and it exits with the
verifier's status.

Run against stand-ins on PATH: a cloudflared that prints a quick-tunnel origin and a
polaris-oid4vp that records each command line (keygen also writes the five files). With
CF_PIDFILE or SERVE_PIDFILE set, that stand-in writes its PID there and stays up for a minute;
SERVE_EXIT is the status serve returns. No network.
"""
import os
import pathlib
import re
import signal
import subprocess
import tempfile
import time
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "polaris-dev-tunnel.sh"

CLOUDFLARED = """#!/bin/sh
echo "INF |  https://quiet-river-stone-lamp.trycloudflare.com  |"
if [ -n "${CF_PIDFILE:-}" ]; then echo $$ > "$CF_PIDFILE"; exec sleep 60; fi
exec sleep 5
"""

OID4VP = """#!/bin/sh
printf '%s\\n' "$*" >> "$RECORD"
if [ "$1" = serve ]; then
    if [ -n "${SERVE_PIDFILE:-}" ]; then echo $$ > "$SERVE_PIDFILE"; exec sleep 60; fi
    exit "${SERVE_EXIT:-0}"
fi
if [ "$1" = keygen ]; then
    out=""
    while [ $# -gt 0 ]; do
        if [ "$1" = --out ]; then out="$2"; fi
        shift
    done
    mkdir -p "$out"
    for f in anchor.pem client.pem client-key.pem tls.pem tls-key.pem; do
        echo "minted" > "$out/$f"
    done
fi
"""

FILES = ("anchor.pem", "client.pem", "client-key.pem", "tls.pem", "tls-key.pem")


def leaf_pem(days_from_now):
    """A self-signed P-256 certificate whose notAfter is `days_from_now` days away (negative: past)."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dev-tunnel test leaf")])
    now = datetime.datetime.now(datetime.timezone.utc)
    after = now + datetime.timedelta(days=days_from_now)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(after - datetime.timedelta(days=90)).not_valid_after(after)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


class DevTunnel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        bin_dir = self.dir / "bin"
        bin_dir.mkdir()
        for name, body in (("cloudflared", CLOUDFLARED), ("polaris-oid4vp", OID4VP)):
            path = bin_dir / name
            path.write_text(body)
            path.chmod(0o755)
        self.record = self.dir / "record.txt"
        self.env = {"PATH": "%s:/usr/bin:/bin" % bin_dir, "RECORD": str(self.record),
                    "HOME": str(self.dir), "TMPDIR": str(self.dir)}

    def tearDown(self):
        self.tmp.cleanup()

    def run_tunnel(self, *args):
        run = subprocess.run(["bash", str(SCRIPT), *args], env=self.env, capture_output=True,
                             text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        return run, self.record.read_text().splitlines()

    def test_once_vct_and_claim_reach_serve(self):
        pki = self.dir / "pki"
        _, calls = self.run_tunnel("--pki", str(pki), "--once", "--vct", "pbdf.sidn-pbdf.email",
                                   "--claim", '["domain"]', "--claim", "age_over_18=true")
        serve = [c for c in calls if c.startswith("serve ")]
        self.assertEqual(len(serve), 1, calls)
        self.assertIn("--once", serve[0].split())
        self.assertIn("--vct pbdf.sidn-pbdf.email", serve[0])
        self.assertIn('--claim ["domain"] --claim age_over_18=true', serve[0])
        self.assertIn("--public-base-url https://quiet-river-stone-lamp.trycloudflare.com",
                      serve[0])

    def test_a_new_pki_directory_is_minted_once(self):
        pki = self.dir / "pki"
        _, calls = self.run_tunnel("--pki", str(pki))
        self.assertEqual([c for c in calls if c.startswith("keygen ")],
                         ["keygen --out %s --host quiet-river-stone-lamp.trycloudflare.com" % pki])
        for name in FILES:
            self.assertTrue((pki / name).is_file(), name)

    def existing_pki(self, leaf_days):
        pki = self.dir / "pki"
        pki.mkdir()
        for name in FILES:
            (pki / name).write_text("kept " + name)
        (pki / "client.pem").write_text(leaf_pem(leaf_days))
        return pki, {name: (pki / name).read_text() for name in FILES}

    def test_an_existing_pki_is_reused_not_remade(self):
        pki, before = self.existing_pki(30)
        run, calls = self.run_tunnel("--pki", str(pki))
        self.assertEqual([c for c in calls if c.startswith("keygen ")], [], calls)
        self.assertEqual({name: (pki / name).read_text() for name in FILES}, before)
        self.assertIn("reusing the test PKI", run.stdout)
        self.assertIn("serve --pki %s " % pki, calls[-1])

    def test_an_existing_pki_whose_leaf_has_expired_is_refused(self):
        pki, before = self.existing_pki(-1)
        run = subprocess.run(["bash", str(SCRIPT), "--pki", str(pki)], env=self.env,
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        self.assertIn("the test leaf in %s has expired or cannot be read; remove %s to remint (the "
                      "wallet then needs the new anchor)" % (pki, pki), run.stderr)
        self.assertEqual({name: (pki / name).read_text() for name in FILES}, before)
        calls = self.record.read_text().splitlines() if self.record.exists() else []
        self.assertEqual(calls, [], "nothing was minted or served")

    def test_help_prints_the_header_and_no_code(self):
        run = subprocess.run(["bash", str(SCRIPT), "--help"], env=self.env, capture_output=True,
                             text=True, timeout=30)
        self.assertEqual(run.returncode, 0)
        lines = run.stdout.splitlines()
        self.assertTrue(lines and all(line.startswith("#") for line in lines), lines[-3:])
        self.assertIn("NOT tunnelled by this script", lines[-1])

    def test_a_partial_pki_is_minted_again(self):
        pki = self.dir / "pki"
        pki.mkdir()
        (pki / "anchor.pem").write_text("alone")
        _, calls = self.run_tunnel("--pki", str(pki))
        self.assertEqual(len([c for c in calls if c.startswith("keygen ")]), 1, calls)

    def test_an_unknown_argument_is_still_refused(self):
        run = subprocess.run(["bash", str(SCRIPT), "--nope"], env=self.env, capture_output=True,
                             text=True, timeout=30)
        self.assertEqual(run.returncode, 2)
        self.assertIn("unknown argument --nope", run.stderr)

    # The script under `bash -x`, in a session of its own, its output and trace in files. The
    # trace names the tunnel log it made; the session lets the cleanup reach anything it left.
    def start(self, *args):
        out = open(self.dir / "out.txt", "w")
        trace = open(self.dir / "trace.txt", "w")
        self.addCleanup(out.close)
        self.addCleanup(trace.close)
        proc = subprocess.Popen(["bash", "-x", str(SCRIPT), "--pki", str(self.dir / "pki"), *args],
                                env=self.env, stdin=subprocess.DEVNULL, stdout=out, stderr=trace,
                                start_new_session=True)
        self.addCleanup(self.kill_group, proc)
        return proc

    def kill_group(self, proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait(timeout=10)

    def tunnel_log(self):
        trace = (self.dir / "trace.txt").read_text()
        found = re.findall(r"^\+ CF_LOG=(\S+)$", trace, re.M)
        self.assertEqual(len(found), 1, trace[-800:])
        self.assertTrue(pathlib.Path(found[0]).name.startswith("polaris-cf."), found)
        return found[0]

    def pid_in(self, name, within=15.0):
        path = self.dir / name
        end = time.monotonic() + within
        while time.monotonic() < end:
            text = path.read_text().strip() if path.exists() else ""
            if text:
                pid = int(text)
                self.addCleanup(self.kill_pid, pid)
                return pid
            time.sleep(0.05)
        self.fail("%s was not written within %ss: %s" % (name, within,
                                                           (self.dir / "trace.txt").read_text()[-800:]))

    @staticmethod
    def kill_pid(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    @staticmethod
    def stopped(pid, within=5.0):
        end = time.monotonic() + within
        while time.monotonic() < end:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            time.sleep(0.05)
        return False

    def serving(self):
        """The script with the tunnel and the verifier both up, and its tunnel log on disk."""
        self.env["CF_PIDFILE"] = str(self.dir / "cf.pid")
        self.env["SERVE_PIDFILE"] = str(self.dir / "serve.pid")
        proc = self.start()
        tunnel, verifier = self.pid_in("cf.pid"), self.pid_in("serve.pid")
        log = self.tunnel_log()
        self.assertTrue(os.path.exists(log), "the control: the log is there while the tunnel runs")
        return proc, tunnel, verifier, log

    def assert_cleaned_up(self, tunnel, log, verifier=None):
        self.assertTrue(self.stopped(tunnel), "the tunnel process outlived the script")
        if verifier is not None:
            self.assertTrue(self.stopped(verifier), "the verifier outlived the script")
        self.assertFalse(os.path.exists(log), "the tunnel's log was left at %s" % log)

    def test_a_once_run_stops_the_tunnel_and_deletes_its_log(self):
        self.env["CF_PIDFILE"] = str(self.dir / "cf.pid")
        proc = self.start("--once")
        self.assertEqual(proc.wait(timeout=60), 0, (self.dir / "trace.txt").read_text()[-800:])
        self.assert_cleaned_up(self.pid_in("cf.pid"), self.tunnel_log())

    def test_ctrl_c_stops_the_verifier_and_the_tunnel(self):
        # Ctrl-C signals the whole foreground group: the script and both of its children.
        proc, tunnel, verifier, log = self.serving()
        os.killpg(proc.pid, signal.SIGINT)
        self.assertEqual(proc.wait(timeout=30), 130, "exits as a script stopped by SIGINT")
        self.assert_cleaned_up(tunnel, log, verifier)

    def test_term_to_the_script_stops_the_verifier_and_the_tunnel(self):
        proc, tunnel, verifier, log = self.serving()
        os.kill(proc.pid, signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=30), 143, "exits as a script stopped by SIGTERM")
        self.assert_cleaned_up(tunnel, log, verifier)

    def test_the_exit_status_is_the_verifiers(self):
        self.env["CF_PIDFILE"] = str(self.dir / "cf.pid")
        self.env["SERVE_EXIT"] = "3"
        proc = self.start("--once")
        self.assertEqual(proc.wait(timeout=60), 3, (self.dir / "trace.txt").read_text()[-800:])
        self.assert_cleaned_up(self.pid_in("cf.pid"), self.tunnel_log())


if __name__ == "__main__":
    unittest.main()
