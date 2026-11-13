# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""dryrun.py -- the lab verifier and a local stand-in, on loopback, before anyone scans anything.

The stand-in is not a wallet. It is built from the tests' own keys: it fetches the request object by GET,
checks the header, the kid and the client_id against the verifier's DID log, and posts an encrypted response
with a test credential made in this process. The verifier listens on 127.0.0.1 at an ephemeral port and is
stopped before this exits; nothing here reaches any other host.

    python -B lab/interop/swiyu/dryrun.py

Its first and last lines say what it is. Nothing it prints is evidence of anything about a wallet.
"""
import pathlib
import socket
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import swiyu_fixtures as F  # noqa: E402
from polaris_oid4vp.serve import serve  # noqa: E402

BANNER = "DRY RUN: a local stand-in, not a wallet, never evidence"


def main():
    print(BANNER, flush=True)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    world = F.World(public_url="http://127.0.0.1:%d" % port)
    httpd = serve(world.front, host="127.0.0.1", port=port, background=True)
    ok = False
    try:
        print("listening on 127.0.0.1:%d (loopback only)" % port, flush=True)
        session, _ = world.verifier.new_request()
        print("LINK openid4vp %s" % world.verifier.links(session)["openid4vp"], flush=True)
        checks, answer = world.wallet.over_http("%s?state=%s" % (world.verifier.request_uri, session.state), world.log)
        for name in ("header", "kid", "client_id", "signature"):
            print("%s %s" % (name, "ok" if checks.get(name) else "FAILED"), flush=True)
        if answer is not None:
            print("verifier answered %d, %s" % (answer[0], "accepted (200)" if answer[0] == 200 else "refused"), flush=True)
            record = world.last()
            for name, check in sorted(record["checks"].items()):
                print("%s %s" % (name, check["outcome"]), flush=True)
            print("status %s" % (record["status"],), flush=True)
            print("counted: %s" % record["counted"], flush=True)
            ok = answer[0] == 200 and record["counted"] and all(checks.values())
    finally:
        httpd.shutdown()
        httpd.server_close()
    print("listener stopped" if ok else "dry run did not complete", flush=True)
    print(BANNER, flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
