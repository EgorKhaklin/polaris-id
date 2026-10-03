#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-issuance-tunnel-serve.py: serve Polaris on the loopback with ONLY its OpenID4VCI
wallet endpoints reachable (lab/strategy/012-issuance-tunnel.md).

It imports the ordinary application, so every route is the real one, and wraps its WSGI callable in
the issuance-only filter (polaris_issuance_scope.IssuanceOnly) before serving. A request for the
operator console, the relying-party API, sign-in or the offer-minting route is answered 403 before
the application sees it. It ALWAYS filters: there is no switch that would serve the whole
application to a tunnel. The orchestrator scripts/polaris-issuance-tunnel.sh sets the environment
(the notional database, the PQC profile, and POLARIS_CREDENTIAL_COPY_KEYS_DIR pointing at the
certificate minted for the tunnel host) and points a cloudflared tunnel at the port this binds.

    POLARIS_ISSUANCE_TUNNEL_PORT   the loopback port to bind (default 2223)

It binds 127.0.0.1 only, and refuses to run under POLARIS_ENV=production, as the tunnel scripts do.
This is development and evaluation tooling; the application does not import it and it adds no route.
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def main() -> int:
    if os.environ.get("POLARIS_ENV", "").strip().lower() == "production":
        print("polaris-issuance-tunnel-serve: refusing to run under POLARIS_ENV=production; this is "
              "a dev and evaluation tool, not an issuer's ingress.", file=sys.stderr)
        return 2
    try:
        port = int(os.environ.get("POLARIS_ISSUANCE_TUNNEL_PORT", "2223"))
    except ValueError:
        print("polaris-issuance-tunnel-serve: POLARIS_ISSUANCE_TUNNEL_PORT must be a port number.",
              file=sys.stderr)
        return 2

    sys.path.insert(0, _HERE)                                 # polaris_issuance_scope
    sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))    # the application
    import polaris_issuance_scope as scope
    import app as app_module   # noqa: E402 -- runs app.py, which registers every route at its end

    flask_app = app_module.app

    def _log_refusal(method: str, path: str) -> None:
        # The response says only 403; this is where the operator sees what the tunnel kept out.
        print("issuance-tunnel: refused %s %s" % (method, path), file=sys.stderr)

    flask_app.wsgi_app = scope.IssuanceOnly(flask_app.wsgi_app, on_refuse=_log_refusal)

    from werkzeug.serving import run_simple
    print("issuance-tunnel: serving OID4VCI-only on http://127.0.0.1:%d (every other path is 403)"
          % port, file=sys.stderr)
    run_simple("127.0.0.1", port, flask_app, threaded=True, use_reloader=False, use_debugger=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
