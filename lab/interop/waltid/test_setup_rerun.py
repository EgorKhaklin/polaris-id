# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""setup.sh can be run again on the same walt.id: the wallet then trusts the new certificate and
holds only the new credential.

docs/STRANGER-PATH.md step 3 run a second time makes a new CA and TLS certificate. setup.sh
imported the listener's certificate under a fixed alias with its error discarded, and keytool
refuses an alias that exists, so the first certificate stayed and walt.id refused the verifier
("PKIX path validation failed"). Step 4 now deletes the alias first; only its absence, on a
first run, is not an error. And every run's wallet used stores of one fixed name, so a second
wallet held the first run's credential too and presented it, which the verifier refused under
the new issuer key. Step 1 now names the stores for the run.

The tests run setup.sh's own lines under /bin/bash (3.2.57 on macOS, 5.2 on the Linux CI
runners): step 4 against a `docker` whose keytool answers as keytool does (an alias that exists
is refused on import, an absent one on delete), step 1 against a `curl` that records what it is
asked to create.
"""
import json
import pathlib
import subprocess
import tempfile
import unittest

SETUP = pathlib.Path(__file__).resolve().parent / "setup.sh"
STEP1 = ("\nSTORE=$(", "\n\n# 2.")
STEP4 = ('docker cp "$PKI/tls.pem"', '\n"$PY" -c \'')

FAKE_DOCKER = r'''#!/bin/bash
# The container's keystore is a directory, one file per alias.
store="$FAKE_ROOT/cacerts"
case "$1" in
  cp) cp "$2" "$FAKE_ROOT/polaris-tls.pem" ;;
  exec)
    shift 2
    [ "$1" = keytool ] || exit 2
    op=$2; shift 2; alias=""
    while [ $# -gt 0 ]; do [ "$1" = -alias ] && alias=$2; shift; done
    echo "Warning: use -cacerts option to access cacerts keystore" >&2
    # FAKE_BROKEN names the one operation that fails with an error other than the alias's.
    if [ "${FAKE_BROKEN:-}" = "$op" ]; then
      echo "keytool error: java.io.IOException: keystore password was incorrect"; exit 1
    fi
    case "$op" in
      -delete)
        [ -f "$store/$alias" ] || { echo "keytool error: java.lang.Exception: Alias <$alias> does not exist"; exit 1; }
        rm "$store/$alias" ;;
      -importcert)
        [ -f "$store/$alias" ] && { echo "keytool error: java.lang.Exception: Certificate not imported, alias <$alias> already exists"; exit 1; }
        cp "$FAKE_ROOT/polaris-tls.pem" "$store/$alias"; echo "Certificate was added to keystore" >&2 ;;
      *) exit 2 ;;
    esac ;;
  *) exit 2 ;;
esac
'''


# Records each store and wallet it is asked to create; FAKE_FAIL names a URL part it refuses.
FAKE_CURL = r'''#!/bin/bash
url=""; data=""
while [ $# -gt 0 ]; do
  case "$1" in
    -d) data=$2; shift ;;
    -H|-X) shift ;;
    http*) url=$1 ;;
  esac
  shift
done
[ -n "${FAKE_FAIL:-}" ] && case "$url" in *"$FAKE_FAIL"*) exit 22 ;; esac
echo "$url $data" >> "$FAKE_ROOT/curl.log"
case "$url" in */wallet) echo '{"walletId": "w-1"}' ;; esac
'''


def lines(span):
    text = SETUP.read_text()
    start = text.find(span[0])
    end = text.find(span[1], start)
    assert start >= 0 and end > start, "setup.sh's lines from %r were not found" % span[0]
    return text[start:end + 1]


class TrustImport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        for d in ("bin", "cacerts", "pki"):
            (self.root / d).mkdir()
        docker = self.root / "bin" / "docker"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(0o755)
        (self.root / "step4.sh").write_text('set -euo pipefail\nPKI="$1"\nCONTAINER=polaris-waltid\n' + lines(STEP4))

    def tearDown(self):
        self.tmp.cleanup()

    def run_step4(self, cert, **env):
        (self.root / "pki" / "tls.pem").write_text(cert)
        return subprocess.run(
            ["/bin/bash", str(self.root / "step4.sh"), str(self.root / "pki")],
            capture_output=True, text=True, timeout=30,
            env={"PATH": "%s:/usr/bin:/bin" % (self.root / "bin"), "FAKE_ROOT": str(self.root), **env})

    def trusted(self):
        return (self.root / "cacerts" / "polaris-stranger").read_text()

    def test_a_second_run_trusts_the_new_certificate(self):
        first = self.run_step4("first certificate")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(self.trusted(), "first certificate")
        second = self.run_step4("second certificate")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.trusted(), "second certificate",
                         "a second run must leave the wallet trusting the new certificate")
        self.assertEqual(first.stdout + first.stderr + second.stdout + second.stderr, "",
                         "keytool's output is shown only when it fails")

    def test_a_keystore_error_stops_the_run(self):
        # Each operation alone: the delete failing while the import works, and the reverse.
        for op in ("-delete", "-importcert"):
            with self.subTest(failing=op):
                (self.root / "cacerts" / "polaris-stranger").unlink(missing_ok=True)
                r = self.run_step4("a certificate", FAKE_BROKEN=op)
                self.assertNotEqual(r.returncode, 0, "a keytool error other than an absent alias must fail the run")
                self.assertIn("keystore password was incorrect", r.stderr)


class StoresPerRun(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "bin").mkdir()
        curl = self.root / "bin" / "curl"
        curl.write_text(FAKE_CURL)
        curl.chmod(0o755)
        (self.root / "step1.sh").write_text(
            'set -euo pipefail\nWALTID=http://waltid.test\nPY=python3\n' + lines(STEP1) + 'echo "$WID"\n')

    def tearDown(self):
        self.tmp.cleanup()

    def run_step1(self, **env):
        log = self.root / "curl.log"
        log.write_text("")
        r = subprocess.run(
            ["/bin/bash", str(self.root / "step1.sh")], capture_output=True, text=True, timeout=30,
            env={"PATH": "%s:/usr/bin:/bin" % (self.root / "bin"), "FAKE_ROOT": str(self.root), **env})
        return r, log.read_text().splitlines()

    def stores(self, calls):
        made = {}
        for call in calls:
            url, _, data = call.partition(" ")
            if "/stores/" in url:
                kind, name = url.split("/stores/")[1].split("/")
                made[kind] = name
            else:
                wallet = json.loads(data)
        self.assertEqual(sorted(made), ["credentials", "dids", "keys"])
        self.assertEqual(len(set(made.values())), 1, "the three stores share the run's name: %s" % made)
        name = made["keys"]
        self.assertEqual((wallet["keyStoreIds"], wallet["credentialStoreIds"], wallet["didStoreId"]),
                         ([name], [name], name), "the wallet is made on this run's stores")
        return name

    def test_each_run_makes_its_wallet_on_stores_of_its_own(self):
        first, calls1 = self.run_step1()
        second, calls2 = self.run_step1()
        self.assertEqual((first.returncode, second.returncode), (0, 0), first.stderr + second.stderr)
        self.assertEqual(first.stdout, "w-1\n")
        one, two = self.stores(calls1), self.stores(calls2)
        self.assertRegex(one, r"^stranger-[0-9a-f]{16}$")
        self.assertNotEqual(one, two, "a second run must not reuse the first run's stores")

    def test_a_store_walt_id_did_not_create_stops_the_run(self):
        for kind in ("keys", "credentials", "dids"):
            with self.subTest(store=kind):
                r, calls = self.run_step1(FAKE_FAIL="/stores/%s/" % kind)
                self.assertNotEqual(r.returncode, 0, "the run must stop when a store is not created")
                self.assertIn("did not create the %s store" % kind, r.stderr)
                self.assertFalse([c for c in calls if c.startswith("http://waltid.test/wallet ")],
                                 "no wallet is made without its stores")


if __name__ == "__main__":
    unittest.main()
