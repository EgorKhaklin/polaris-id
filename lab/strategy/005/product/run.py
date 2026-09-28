#!/usr/bin/env python3
"""lab/strategy/005/product/run.py: a wallet Polaris did not write receives a wallet copy from the PRODUCT.

005 step S5. Step 2 (../STEP2.md) had two wallets take a credential from the lab issuer; this
has them take one from polaris_web itself, through the OpenID4VCI endpoints and the operator's
offer route, with the record deciding. One run per wallet: an issuer has one identifier, the
leaf certificate names it, and walt.id (in Docker) and Credo (on the host) cannot resolve the
same host name here.

    python3 lab/strategy/005/product/run.py --wallet credo  --out /tmp/s5-credo
    python3 lab/strategy/005/product/run.py --wallet waltid --out /tmp/s5-waltid

Each run, in order, and each step's result goes into outcome.json:
  1. a fresh database (00_load_all.sql, then every up migration), as CI loads one;
  2. a TLS certificate for the issuer host, and a TEST wallet-copy chain for agency 2 whose leaf
     names the issuer URL (scripts/polaris-credential-copy-test-pki.py);
  3. polaris_web under gunicorn over TLS, behind a WSGI shim that appends every request
     (method, path, status, user agent, form or JSON body) to wire.jsonl;
  4. two fresh ACTIVE credentials through uc1_issue_and_activate;
  5. the operator signs in with the seed's development credentials and offers a wallet copy of
     the first (POST /tokens/<id>/wallet-offer);
  6. the wallet redeems the offer through its own public API (C);
  7. the copy is read back from the wallet and checked without polaris_web: its signature from
     x5c[0], the chain to the test anchor, the binding to the wallet's own key, and its status
     through polaris-oid4vp's status decision, which must be VALID;
  8. the first credential is revoked through uc8_revoke_token, and the SAME copy's status must
     now be INVALID (D);
  9. the second credential is offered, revoked before redemption, and the wallet's redemption
     must fail (B).
Exit 0 only if every step behaved as required. LAB CODE: development credentials, a TEST CA,
a scratch database; never a deployment.
"""
import argparse
import base64
import datetime
import http.cookiejar
import importlib.util
import json
import os
import pathlib
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[3]
WEB = ROOT / "polaris_web"
CREDO = ROOT / "lab" / "interop" / "credo"
VENV_PY = os.environ.get("POLARIS_TEST_PYTHON", sys.executable)
AGENCY = 2
WALTID_IMAGE = "waltid/wallet-api2:1.0.0@sha256:d2248288f41ceba029a7fd943fed623ef7f0f846edfee666ac6f7e621c4d739e"
PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

sys.path.insert(0, str(ROOT / "packages" / "polaris-oid4vp"))
from polaris_oid4vp import status as oid4vp_status  # noqa: E402  the verifier's own status reader

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SHIP = _load("polaris_ship", ROOT / "scripts" / "polaris-ship.py")
PKI = _load("copy_test_pki", ROOT / "scripts" / "polaris-credential-copy-test-pki.py")


# ---------------------------------------------------------------- the record's side

def psql(db, sql, *, one=False):
    out = subprocess.run(["psql", "-h", "localhost", "-U", "vanta", "-d", db, "-qAt", "-v", "ON_ERROR_STOP=1",
                          "-c", sql], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("psql: %s" % out.stderr.strip())
    return out.stdout.strip().splitlines()[0] if one else out.stdout


def issue(db, label):
    value = "TKN-S5-%s-%s" % (label, secrets.token_hex(3))
    token_id = psql(db, "SELECT uc1_issue_and_activate('S5 Holder %s', DATE '1990-05-06', 'PA', 2, 1, 'NONE', 2, "
                        "NULL, '%s', 'PHY-%s', 's5', ARRAY[1])" % (label, value, value), one=True)
    return int(token_id), value


def revoke(db, token_id):
    cosigner = psql(db, "SELECT aa.agency_id FROM IdentityToken t JOIN AgencyAlgorithmAuth aa "
                        "ON aa.algorithm_id = t.algorithm_id WHERE t.token_id = %d AND "
                        "aa.authorization_type = 'BOTH' AND aa.agency_id <> t.issuing_agency_id "
                        "ORDER BY aa.agency_id LIMIT 1" % token_id, one=True)
    psql(db, "CALL uc8_revoke_token(%d, %d, 'COMPROMISED', 'lab/strategy/005 S5', %s)"
         % (token_id, AGENCY, cosigner))


# ---------------------------------------------------------------- TLS and the shim

def tls_cert(out, host):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    # The TLS name the wallet uses, and always localhost, where this harness fetches from. The
    # wallet-copy leaf is a different certificate and names ONE issuer; this one only serves TLS.
    import ipaddress
    names = [x509.DNSName(h) for h in dict.fromkeys((host, "localhost"))]
    names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    (out / "tls.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (out / "tls-key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()))
    os.chmod(out / "tls-key.pem", 0o600)


SHIM = '''\
"""A WSGI shim that records what a wallet sent to polaris_web. Lab only."""
import io, json, os, sys, time
sys.path.insert(0, %(web)r)
os.chdir(%(web)r)
from app import app as flask_app

LOG = %(log)r


class Wire:
    def __init__(self, inner):
        self.inner = inner

    def __call__(self, environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = environ["wsgi.input"].read(length) if length else b""
        environ["wsgi.input"] = io.BytesIO(body)
        seen = {}

        def recording_start(status, headers, exc_info=None):
            seen["status"] = int(status.split()[0])
            return start_response(status, headers, exc_info)

        result = self.inner(environ, recording_start)
        if environ.get("PATH_INFO") == "/login":
            body = b""   # the development password is in the seed already; it stays out of the evidence
        entry = {"t": time.time(), "method": environ["REQUEST_METHOD"], "path": environ.get("PATH_INFO"),
                 "query": environ.get("QUERY_STRING"), "status": seen.get("status"),
                 "user_agent": environ.get("HTTP_USER_AGENT"),
                 "body": body.decode("utf-8", "replace")[:4000] if body else None}
        with open(LOG, "a") as fh:
            fh.write(json.dumps(entry) + "\\n")
        return result


flask_app.wsgi_app = Wire(flask_app.wsgi_app)
'''


def serve(out, db, host, port, bind):
    keys = out / "keys"
    PKI.make(keys, AGENCY, "https://%s:%d/api/v1/oid4vci/%d" % (host, port, AGENCY))
    (out / "wire_app.py").write_text(SHIM % {"web": str(WEB), "log": str(out / "wire.jsonl")})
    env = dict(os.environ, POLARIS_DB_HOST="localhost", POLARIS_DB_NAME=db, POLARIS_DB_USER="vanta",
               POLARIS_SECRET_KEY=secrets.token_hex(32), POLARIS_PQC_PROFILE="placeholder",
               POLARIS_STATE_DIR=str(out / "state"), POLARIS_CREDENTIAL_COPY_KEYS_DIR=str(keys),
               PYTHONPATH=str(out))
    (out / "state").mkdir(exist_ok=True)
    log = open(out / "gunicorn.log", "w")
    proc = subprocess.Popen([VENV_PY, "-m", "gunicorn", "-w", "1", "-b", "%s:%d" % (bind, port),
                             "--certfile", str(out / "tls.pem"), "--keyfile", str(out / "tls-key.pem"),
                             "wire_app:flask_app"], cwd=str(out), env=env, stdout=log, stderr=subprocess.STDOUT)
    ctx = ssl.create_default_context(cafile=str(out / "tls.pem"))
    for _ in range(60):
        try:
            urllib.request.urlopen("https://localhost:%d/api/health/live" % port, context=ctx, timeout=2)
            return proc, keys
        except Exception:  # noqa: BLE001  not up yet
            time.sleep(0.5)
    proc.terminate()
    raise RuntimeError("polaris_web did not come up; see %s" % (out / "gunicorn.log"))


# ---------------------------------------------------------------- the operator

class Operator:
    """The operator's browser: a cookie jar, the CSRF token, the offer route."""

    def __init__(self, port, cafile):
        self.base = "https://localhost:%d" % port
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=cafile)))

    def _open(self, path, data=None):
        req = urllib.request.Request(self.base + path, data=urllib.parse.urlencode(data).encode() if data else None)
        return self.opener.open(req, timeout=30)

    def sign_in(self):
        # The seed's development credentials (polaris_sql/10_auth.sql), on a scratch database.
        self._open("/login", {"username": "admin", "password": "Admin@123!"})

    def offer(self, token_id):
        page = self._open("/tokens").read().decode()
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        return json.loads(self._open("/tokens/%d/wallet-offer" % token_id, {"csrf_token": csrf}).read())


# ---------------------------------------------------------------- the verifier's side

def check_copy(compact, anchor_pem, holder_jwk, port, cafile):
    """Verify the copy the way a verifier would, without polaris_web: returns the facts."""
    d64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
    jwt = compact.split("~")[0]
    h64, p64, s64 = jwt.split(".")
    header, payload = json.loads(d64(h64)), json.loads(d64(p64))
    leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
    anchor = x509.load_pem_x509_certificate(pathlib.Path(anchor_pem).read_bytes())
    leaf.verify_directly_issued_by(anchor)
    sig = d64(s64)
    leaf.public_key().verify(utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                             ("%s.%s" % (h64, p64)).encode(), ec.ECDSA(hashes.SHA256()))
    return {"iss": payload["iss"], "vct": payload["vct"], "cnf_matches_wallet_key":
            all(payload["cnf"]["jwk"].get(k) == holder_jwk.get(k) for k in ("kty", "crv", "x", "y")),
            "status": status_of(payload, header, cafile)}


def status_of(payload, header, cafile):
    ref = payload["status"]["status_list"]
    # Fetched through localhost (the wallet's host name may resolve only inside Docker), and
    # judged against the uri the copy names, which the token's `sub` must equal.
    parts = urllib.parse.urlsplit(ref["uri"])
    local = parts._replace(netloc="localhost:%d" % parts.port).geturl()
    token = urllib.request.urlopen(local, context=ssl.create_default_context(cafile=cafile), timeout=30).read()
    leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))

    def same_key(signing_input, signature, _header):
        try:
            leaf.public_key().verify(utils.encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                                                int.from_bytes(signature[32:], "big")),
                                     bytes(signing_input), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:  # noqa: BLE001
            return False
    verdict = oid4vp_status.decide(token, index=ref["idx"], expected_uri=ref["uri"],
                                   authority=oid4vp_status.StatedAuthority(), now=int(time.time()),
                                   credential_issuer=payload["iss"], issuer_key_verify=same_key)
    return verdict["meaning"] if verdict.checked else "UNCHECKED: %s" % dict(verdict)


# ---------------------------------------------------------------- the wallets

def credo_receive(offer_uri, out, cafile, anchor):
    run_out = out / ("credo-%s" % secrets.token_hex(2))
    env = dict(os.environ, OFFER=offer_uri, ISSUER_TLS=cafile, ISSUER_CA=anchor, OUT=str(run_out))
    done = subprocess.run(["node", "receive.ts"], cwd=str(CREDO), env=env, capture_output=True, text=True, timeout=300)
    (run_out / "stdout.log").parent.mkdir(parents=True, exist_ok=True)
    (run_out / "stdout.log").write_text(done.stdout + done.stderr)
    outcome = json.loads((run_out / "outcome.json").read_text()) if (run_out / "outcome.json").exists() else {}
    return outcome.get("compact"), outcome.get("holder_jwk"), outcome


class WaltId:
    """walt.id Wallet API v2 1.0.0, unmodified, at a pinned digest (lab/interop/waltid/README.md)."""

    def __init__(self, out, tls_pem):
        self.name = "polaris-waltid-s5"
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        subprocess.run(["docker", "run", "-d", "--name", self.name, "-p", "7006:7006", WALTID_IMAGE],
                       check=True, capture_output=True)
        # The issuer's TLS certificate is self-signed; trusting it is registration, not a workaround.
        subprocess.run(["docker", "cp", tls_pem, "%s:/tmp/issuer-tls.pem" % self.name], check=True)
        subprocess.run(["docker", "exec", "-u", "0", self.name, "keytool", "-importcert", "-noprompt", "-alias",
                        "polaris-s5", "-file", "/tmp/issuer-tls.pem", "-keystore",
                        "/opt/java/openjdk/lib/security/cacerts", "-storepass", "changeit"], check=True,
                       capture_output=True)
        subprocess.run(["docker", "restart", self.name], check=True, capture_output=True)
        self.base = "http://localhost:7006"
        for _ in range(120):
            try:
                urllib.request.urlopen(self.base + "/livez", timeout=2)
                break
            except Exception:  # noqa: BLE001
                time.sleep(1)
        self.wid, self.kid, self.jwk = self._setup()

    def _call(self, method, path, body=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            text = resp.read().decode()
        return json.loads(text) if text.strip().startswith(("{", "[")) else text

    def _setup(self):
        for store in ("keys", "credentials", "dids"):
            self._call("POST", "/stores/%s/polaris" % store, {})
        wallet = self._call("POST", "/wallet", {"keyStoreIds": ["polaris"], "credentialStoreIds": ["polaris"],
                                               "didStoreId": "polaris", "noDidStore": False})
        wid = wallet["walletId"]
        key = self._call("POST", "/wallet/%s/keys/generate" % wid, {"backend": "jwk", "keyType": "secp256r1"})
        kid = key["keyId"] if isinstance(key, dict) else str(key).strip('"')
        did = self._call("POST", "/wallet/%s/dids/create" % wid, {"method": "jwk", "keyId": kid, "options": {}})
        did = did["did"] if isinstance(did, dict) else str(did).strip('"')
        jwk = json.loads(base64.urlsafe_b64decode(did.split("did:jwk:")[1].split("#")[0] + "=="))
        return wid, kid, jwk

    def receive(self, offer_uri):
        try:
            got = self._call("POST", "/wallet/%s/credentials/receive" % self.wid,
                             {"offerUrl": offer_uri, "keyId": self.kid})
        except urllib.error.HTTPError as exc:
            return None, {"error": "HTTP %d: %s" % (exc.code, exc.read().decode()[:500])}
        ids = (got or {}).get("credentialIds") or []
        if not ids:
            return None, {"receive": got}
        stored = self._call("GET", "/wallet/%s/credentials/%s" % (self.wid, ids[-1]))
        return _sd_jwt_in(stored), {"receive": got, "stored_fields": sorted(stored) if isinstance(stored, dict) else None}

    def close(self):
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)


# ---------------------------------------------------------------- the run

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--wallet", choices=("credo", "waltid"), required=True)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--port", type=int, default=9644)
    ap.add_argument("--db", default=None, help="scratch database name (default polaris_s5_<wallet>)")
    args = ap.parse_args(argv)
    out = args.out.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    db = args.db or "polaris_s5_%s" % args.wallet
    host = "localhost" if args.wallet == "credo" else "host.docker.internal"
    bind = "127.0.0.1" if args.wallet == "credo" else "0.0.0.0"
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(ROOT), capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "--", "polaris_web", "polaris_sql"], cwd=str(ROOT),
                                capture_output=True, text=True).stdout.strip())
    result = {"wallet": args.wallet, "commit": commit, "product_tree_dirty": dirty,
              "issuer": "https://%s:%d/api/v1/oid4vci/%d" % (host, args.port, AGENCY),
              "started": datetime.datetime.now(datetime.timezone.utc).isoformat()}

    env = dict(os.environ, PGUSER="vanta", POLARIS_DB_HOST="localhost")
    SHIP.make_db(db, env)
    tls_cert(out, host)
    server, keys = serve(out, db, host, args.port, bind)
    wallet = None
    try:
        cafile, anchor = str(out / "tls.pem"), str(keys / ("%d.anchor.pem" % AGENCY))
        c_id, _ = issue(db, "C")
        b_id, _ = issue(db, "B")
        op = Operator(args.port, cafile)
        op.sign_in()
        offer_c = op.offer(c_id)
        offer_b = op.offer(b_id)
        if args.wallet == "credo":
            compact, holder_jwk, raw = credo_receive(offer_c["offer_uri"], out, cafile, anchor)
        else:
            wallet = WaltId(out, cafile)
            compact, raw = wallet.receive(offer_c["offer_uri"])
            holder_jwk = wallet.jwk
        result["C_received"] = bool(compact)
        result["C_wallet_said"] = raw if not compact else {k: v for k, v in raw.items() if k != "compact"}
        if compact:
            facts = check_copy(compact, anchor, holder_jwk, args.port, cafile)
            result["C_copy"] = facts
            revoke(db, c_id)
            result["D_status_after_revocation"] = status_of(*_parts(compact), cafile)
        revoke(db, b_id)
        if args.wallet == "credo":
            compact_b, _, raw_b = credo_receive(offer_b["offer_uri"], out, cafile, anchor)
        else:
            compact_b, raw_b = wallet.receive(offer_b["offer_uri"])
        result["B_received"] = bool(compact_b)
        result["B_wallet_said"] = raw_b if not compact_b else "a copy was issued"
    finally:
        if wallet is not None:
            wallet.close()
        server.terminate()
        server.wait(timeout=30)
    wire = [json.loads(line) for line in (out / "wire.jsonl").read_text().splitlines()] if (out / "wire.jsonl").exists() else []
    result["issuer_saw"] = [(w["method"], w["path"], w["status"], (w.get("user_agent") or "")[:40]) for w in wire]
    ok = (result.get("C_received") and result.get("C_copy", {}).get("status") == "VALID"
          and result["C_copy"].get("cnf_matches_wallet_key") and result.get("D_status_after_revocation") == "INVALID"
          and result.get("B_received") is False)
    result["verdict"] = "PASS" if ok else "FAIL"
    (out / "outcome.json").write_text(json.dumps(result, indent=2, default=str))
    print(json.dumps({k: result[k] for k in ("wallet", "issuer", "verdict", "C_received", "B_received")}, indent=1))
    return 0 if ok else 1


def _sd_jwt_in(value):
    """The issued SD-JWT wherever the wallet keeps it: the first string shaped like one."""
    if isinstance(value, str):
        return value if value.startswith("ey") and "~" in value and value.count(".") >= 2 else None
    items = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    for item in items:
        found = _sd_jwt_in(item)
        if found:
            return found
    return None


def _parts(compact):
    d64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
    h64, p64, _ = compact.split("~")[0].split(".")
    return json.loads(d64(p64)), json.loads(d64(h64))


if __name__ == "__main__":
    sys.exit(main())
