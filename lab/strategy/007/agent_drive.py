# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""lab/strategy/007/agent_drive.py -- an agent, and the holder who granted it, against the gate and
two routes Pomerium protects: one that needs `read:status`, one that needs `write:config`.

The agent gets a token per action from the gate and calls the routes with it. The controls come
after: a token on the other action's route, an action outside the grant, a replayed proof, no
token, a forged token, and the holder revoking the grant. One line per check; exits 0 only if
every check holds.

    python3 agent_drive.py --dir AGENT_DIR --gate https://localhost:9444 --cafile pki/tls.pem \\
        --audience pomerium --read https://status.localhost.pomerium.io:8443/ \\
        --write https://config.localhost.pomerium.io:8443/

AGENT_DIR is what `grants.py mint` wrote. On the host, add --loopback .localhost.pomerium.io: those
names no longer resolve in public DNS.
"""
import argparse
import json
import pathlib
import socket
import ssl
import sys
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / "packages" / "polaris-oid4vp"))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import grants  # noqa: E402
from polaris_oid4vp.jwe import b64u_decode  # noqa: E402
from polaris_oid4vp.verifier import _sign_es256  # noqa: E402


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a redirect to sign in is an answer, not a path
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="An agent and its holder against the gate and Pomerium (lab).")
    for name in ("--dir", "--gate", "--cafile", "--audience", "--read", "--write"):
        ap.add_argument(name, required=True)
    ap.add_argument("--loopback", metavar="SUFFIX",
                    help="resolve host names ending in SUFFIX to 127.0.0.1 (when run on the host)")
    args = ap.parse_args(argv)
    if args.loopback:
        real = socket.getaddrinfo
        socket.getaddrinfo = lambda host, *a, **k: real(
            "127.0.0.1" if isinstance(host, str) and host.endswith(args.loopback) else host, *a, **k)

    chain = json.loads((pathlib.Path(args.dir) / "chain.json").read_text())
    holder = grants.Key.load(pathlib.Path(args.dir) / "holder.key")
    agent = grants.Key.load(pathlib.Path(args.dir) / "agent.key")
    gate_tls = ssl.create_default_context(cafile=args.cafile)
    gate_tls.check_hostname = False   # its certificate names host.docker.internal; this runs on the host
    proxy_tls = ssl._create_unverified_context()  # Pomerium's own self-signed certificate  # noqa: S323

    def call(url, data=None, headers=None, context=gate_tls):
        opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=context))
        request = urllib.request.Request(url, data=data, headers=headers or {},
                                         method="GET" if data is None else "POST")
        try:
            with opener.open(request, timeout=30) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def gate_json(path, body):
        status, text = call(args.gate + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
        return status, json.loads(text or "{}")

    def token_request(action, proved=None):
        status, body = call(args.gate + "/agent/nonce", ("audience=" + args.audience).encode(),
                            {"Content-Type": "application/x-www-form-urlencoded"})
        if status != 200:
            raise SystemExit("the gate gave no nonce: %s %s" % (status, body))
        proof = grants.proof(agent, chain["grant"], proved or action, json.loads(body)["nonce"])
        return dict(chain, audience=args.audience, action=action, proof=proof)

    def proxied(url, token):
        """(admitted, status, the action claim the upstream saw). Admitted means the upstream
        answered through Pomerium: whoami echoes the request, with Pomerium's assertion in it."""
        status, text = call(url, headers={"Authorization": "Bearer " + token} if token else {},
                            context=proxy_tls)
        seen = {}
        for line in text.splitlines():
            name, sep, value = line.partition(":")
            if sep and name and " " not in name.strip():
                seen[name.strip().lower()] = value.strip()
        admitted = status == 200 and "x-pomerium-jwt-assertion" in seen
        return admitted, status, seen.get("x-pomerium-claim-action")

    results = []

    def check(ok, text):
        results.append(bool(ok))
        print("  %-4s  %s" % ("ok" if ok else "FAIL", text), flush=True)

    read_request = token_request("read:status")
    status, body = gate_json("/agent/token", read_request)
    check(status == 200, "the gate issued a token for read:status (%s)" % status)
    read_token = body.get("token", "")
    claims = json.loads(b64u_decode(read_token.split(".")[1])) if read_token.count(".") == 2 else {}

    admitted, status, action = proxied(args.read, read_token)
    check(admitted and action == "read:status",
          "Pomerium admitted it to the read:status route (%s, action=%s)" % (status, action))
    admitted, status, _ = proxied(args.write, read_token)
    check(not admitted, "and refused it on the write:config route (%s)" % status)

    status, body = gate_json("/agent/token", token_request("write:config"))
    write_token = body.get("token", "")
    admitted, status, action = proxied(args.write, write_token)
    check(admitted and action == "write:config",
          "a write:config token was admitted to its route (%s, action=%s)" % (status, action))
    admitted, status, _ = proxied(args.write, read_token)
    check(not admitted, "the read:status token is still refused there afterwards (%s)" % status)

    status, body = gate_json("/agent/token", read_request)
    check(status == 400, "the gate refused the same proof again, a replay (%s %s)" % (status, body.get("error")))
    status, body = gate_json("/agent/token", token_request("delete:account"))
    check(status == 403, "the gate refused an action outside the grant (%s %s)" % (status, body.get("error")))

    admitted, status, _ = proxied(args.read, None)
    check(not admitted, "Pomerium refused a request with no token (%s)" % status)
    forger = ec.generate_private_key(ec.SECP256R1())
    header = json.loads(b64u_decode(read_token.split(".")[0])) if read_token.count(".") == 2 else {}
    forged = _sign_es256(forger, header, claims)
    admitted, status, _ = proxied(args.read, forged)
    check(not admitted, "Pomerium refused the same claims signed by a key the gate never held (%s)" % status)

    status, body = gate_json("/agent/revoke", dict(chain, revocation=grants.revocation(holder, chain["grant"])))
    check(status == 200, "the holder revoked the grant at the gate (%s)" % status)
    status, body = gate_json("/agent/token", token_request("read:status"))
    check(status == 403 and "revoked" in body.get("error_description", ""),
          "the gate refused the agent from then on (%s: %s)" % (status, body.get("error_description")))

    print(json.dumps({"claims": claims}))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
