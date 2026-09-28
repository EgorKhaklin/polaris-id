#!/usr/bin/env python3
"""lab/strategy/005/product/present.py: the product's wallet copy, presented from the wallet to a verifier that reads its status.

005 step S6. S5 (../STEP5.md) had walt.id receive a copy from polaris_web and checked the copy
itself. Here walt.id presents the copy it holds, through its own public API, to a
polaris-oid4vp Verifier that reads the product's status list:

  1. as in S5: a fresh database, TLS, the TEST wallet-copy chain, polaris_web over TLS, an
     ACTIVE credential, the operator's offer, walt.id's receipt;
  2. a verifier: `polaris-oid4vp keygen` for host.docker.internal, a Verifier that trusts the
     product's TEST anchor for issuers and resolves status from the product's list. It states
     the authority for exactly the list the copy names, under its issuer's own path, and
     accepts a list only from an x5c leaf chaining to that same anchor;
  3. walt.id, configured beforehand to trust the verifier (its TLS certificate, and its
     request-object CA in clientIdTrust), presents the copy: the verdict must be authentic
     with status VALID;
  4. uc8_revoke_token, then walt.id presents the SAME copy to a new request: authentic, and
     status INVALID.

    python3 lab/strategy/005/product/present.py --out /tmp/s6-waltid

Exit 0 only if both verdicts are as required. LAB CODE, as run.py.
"""
import argparse
import base64
import os
import subprocess
import datetime
import importlib.util
import json
import pathlib
import shutil
import ssl
import sys
import time
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("s5run", HERE / "run.py")
S5 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S5)

from polaris_oid4vp import status as tsl  # noqa: E402  (run.py put the package on sys.path)
from polaris_oid4vp.cli import FILES, keygen, verifier_from  # noqa: E402
from polaris_oid4vp.serve import serve  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402

VERIFIER_PORT = 9543


def _read_json(proc, key):
    """The next line on the wallet's stdout that is a JSON object carrying `key`. Other lines,
    such as a library's own log output, are skipped. None when the process ends first."""
    for line in proc.stdout:
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and key in obj:
            return obj
    return None


def status_resolver(anchor, product_port, product_cafile):
    """The relying party's own status policy, stated rather than inferred.

    A list is accepted only for the issuer the credential names, only from under that
    issuer's own path, and only when its x5c leaf chains to the anchor the relying party
    already trusts for that issuer's credentials."""

    def verify(signing_input, signature, header):
        try:
            leaf = x509.load_der_x509_certificate(base64.b64decode((header or {}).get("x5c", [""])[0]))
            leaf.verify_directly_issued_by(anchor)
            der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                             int.from_bytes(signature[32:], "big"))
            leaf.public_key().verify(der, bytes(signing_input), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:  # noqa: BLE001  any failure is "not this authority"
            return False

    def fetch(uri):
        parts = urllib.parse.urlsplit(uri)
        # The verifier runs on the host, where the wallet's host name does not resolve.
        local = parts._replace(netloc="localhost:%d" % product_port).geturl()
        ctx = ssl.create_default_context(cafile=product_cafile)
        return urllib.request.urlopen(local, context=ctx, timeout=15).read()

    def resolver(*, uri, idx, issuer=None):
        if not (isinstance(issuer, str) and isinstance(uri, str) and uri.startswith(issuer + "/status/")):
            return {"checked": False, "state": "unreachable",
                    "reason": "the status list is not under the issuer's own path"}
        authority = tsl.StatedAuthority().state(
            credential_issuer=issuer, status_uri=uri, verify=verify,
            why="the relying party trusts this issuer's anchor for its credentials, and so for "
                "status lists signed under it")
        try:
            token = fetch(uri)
        except Exception as exc:  # noqa: BLE001  no list is no answer, not a negative one
            return {"checked": False, "state": "unreachable",
                    "reason": "fetching the status list raised %s" % type(exc).__name__}
        # Judged at the time the list ARRIVED. decide_by_fetching takes `now` before its fetch,
        # so a list the issuer signs during the request reads as dated in the future
        # (iat_future): observed 2026-09-28 on a copy that was VALID, reported to the
        # polaris-oid4vp maintainers with the repro.
        return tsl.decide(token, index=idx, expected_uri=uri, authority=authority,
                          now=int(time.time()), credential_issuer=issuer)
    return resolver


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--wallet", choices=("waltid", "credo"), default="waltid")
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--port", type=int, default=9644)
    args = ap.parse_args(argv)
    credo = args.wallet == "credo"
    out = args.out.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    # walt.id runs in Docker and reaches the host by this name; Credo runs on the host.
    host = "localhost" if credo else "host.docker.internal"
    bind = "127.0.0.1" if credo else "0.0.0.0"
    db = "polaris_s6_%s" % args.wallet
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(S5.ROOT), capture_output=True, text=True).stdout.strip()
    result = {"wallet": args.wallet, "commit": commit, "issuer": "https://%s:%d/api/v1/oid4vci/%d" % (host, args.port, S5.AGENCY),
              "started": datetime.datetime.now(datetime.timezone.utc).isoformat()}

    S5.SHIP.make_db(db, dict(os.environ, PGUSER="vanta", POLARIS_DB_HOST="localhost"))
    S5.tls_cert(out, host)
    vpki = out / "verifier-pki"
    keygen(vpki, host)
    server, keys = S5.serve(out, db, host, args.port, bind)
    anchor_pem = keys / ("%d.anchor.pem" % S5.AGENCY)
    anchor = x509.load_pem_x509_certificate(anchor_pem.read_bytes())
    verdicts = []
    verifier = verifier_from(vpki, host, VERIFIER_PORT, issuer_trust_anchors=[anchor])
    # An age check: the relying party asks for the wallet copy and for age_over_18 alone, so
    # selective disclosure is exercised too (the verdict must not carry the holder's name).
    verifier.vct_values = ["urn:polaris:wallet-copy:1"]
    verifier.claims = ["age_over_18"]
    verifier.status_resolver = status_resolver(anchor, args.port, str(out / "tls.pem"))
    vserver = serve(verifier, host=bind, port=VERIFIER_PORT, certfile=str(vpki / FILES["tls_cert"]),
                    keyfile=str(vpki / FILES["tls_key"]),
                    on_verdict=lambda status, body, verdict: verdicts.append((status, verdict)))
    wallet = None
    try:
        c_id, _ = S5.issue(db, "C")
        op = S5.Operator(args.port, str(out / "tls.pem"))
        op.sign_in()
        offer = op.offer(c_id)
        if credo:
            bundle = out / "tls-bundle.pem"
            bundle.write_text((out / "tls.pem").read_text() + (vpki / FILES["tls_cert"]).read_text())
            env = dict(os.environ, OFFER=offer["offer_uri"], ISSUER_CA=str(anchor_pem),
                       VERIFIER_CA=str(vpki / FILES["anchor"]), NODE_EXTRA_CA_CERTS=str(bundle))
            wallet = subprocess.Popen(["node", "receive-and-present.ts"], cwd=str(S5.CREDO), env=env,
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=open(out / "credo.log", "w"), text=True, bufsize=1)
            said = _read_json(wallet, "ready") or {"error": "Credo exited before it answered"}
            compact = said.get("stored") or None
        else:
            wallet = S5.WaltId(out, str(out / "tls.pem"), extra_tls=(str(vpki / FILES["tls_cert"]),),
                               request_anchor_pem=str(vpki / FILES["anchor"]))
            compact, said = wallet.receive(offer["offer_uri"])
        result["received"] = bool(compact)
        result["wallet_said"] = said

        def present(label):
            session, _ = verifier.new_request()
            url = "openid4vp://authorize?" + urllib.parse.urlencode(verifier.authorization_request_params(session))
            before = len(verdicts)
            if credo:
                wallet.stdin.write(url + "\n")
                wallet.stdin.flush()
                answer = _read_json(wallet, "presented") or {"error": "Credo exited before it answered"}
            else:
                try:
                    answer = wallet._call("POST", "/wallet/%s/credentials/present" % wallet.wid,
                                          {"requestUrl": url, "keyId": wallet.kid})
                except urllib.error.HTTPError as exc:
                    answer = {"error": "HTTP %d: %s" % (exc.code, exc.read().decode()[:400])}
            for _ in range(20):
                if len(verdicts) > before:
                    break
                time.sleep(0.5)
            got = verdicts[before][1] if len(verdicts) > before else None
            row = {"wallet_answer": answer if isinstance(answer, dict) else str(answer)[:400],
                   "authentic": getattr(got, "authentic", None),
                   "claims": sorted((getattr(got, "claims", None) or {}).keys()),
                   "revocation": getattr(got, "revocation", None)}
            result[label] = row
            return row

        if compact:
            first = present("presented_while_active")
            S5.revoke(db, c_id)
            second = present("presented_after_revocation")
            ok = (first["authentic"] is True and (first["revocation"] or {}).get("meaning") == "VALID"
                  and "age_over_18" in first["claims"] and "legal_name" not in first["claims"]
                  and second["authentic"] is True and (second["revocation"] or {}).get("meaning") == "INVALID")
        else:
            ok = False
    finally:
        if wallet is not None and credo:
            wallet.stdin.close()
            wallet.wait(timeout=60)
        elif wallet is not None:
            wallet.close()
        vserver.shutdown()
        vserver.server_close()
        server.terminate()
        server.wait(timeout=30)
    result["verdict"] = "PASS" if ok else "FAIL"
    (out / "outcome.json").write_text(json.dumps(result, indent=2, default=str))
    print(json.dumps({k: result.get(k) for k in ("wallet", "verdict", "received")}, indent=1))
    for label in ("presented_while_active", "presented_after_revocation"):
        row = result.get(label) or {}
        print(label, "authentic=%s" % row.get("authentic"), "status=%s" % (row.get("revocation") or {}).get("meaning"),
              "state=%s" % (row.get("revocation") or {}).get("state"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
