# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""scripts/polaris-dev-tunnel.sh hands --once, --vct and --claim to `polaris-oid4vp serve`, and
reuses a PKI directory that already holds one rather than minting new keys over it, unless its
leaf has expired (keygen makes it valid for 90 days), which it refuses with how to remint.

Run against stand-ins on PATH: a cloudflared that prints a quick-tunnel origin and a
polaris-oid4vp that records each command line (keygen also writes the five files). No network.
"""
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "polaris-dev-tunnel.sh"

CLOUDFLARED = """#!/bin/sh
echo "INF |  https://quiet-river-stone-lamp.trycloudflare.com  |"
exec sleep 5
"""

OID4VP = """#!/bin/sh
printf '%s\\n' "$*" >> "$RECORD"
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


if __name__ == "__main__":
    unittest.main()
