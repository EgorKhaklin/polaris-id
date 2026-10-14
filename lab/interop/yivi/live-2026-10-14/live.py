# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Run `polaris-oid4vp serve` unchanged, saving what the wallet posts before the verifier judges it.

argv: <package dir> <capture dir> <serve args...>. No verifier code is changed: the original
handle_direct_post and request_object run as they are; this only writes copies first.
"""
import json
import pathlib
import sys
import time

sys.path.insert(0, sys.argv[1])
CAP = pathlib.Path(sys.argv[2])
CAP.mkdir(parents=True, exist_ok=True)

from polaris_oid4vp import cli, jwe  # noqa: E402
from polaris_oid4vp import verifier as V  # noqa: E402

_orig_post = V.Verifier.handle_direct_post
_orig_req = V.Verifier.request_object


def _write(name, data):
    p = CAP / name
    p.write_text(data if isinstance(data, str) else json.dumps(data, indent=1, default=str))
    p.chmod(0o600)


def request_object(self, state, wallet_nonce=None, wallet_metadata=None):
    jar = _orig_req(self, state, wallet_nonce=wallet_nonce, wallet_metadata=wallet_metadata)
    if jar is not None:
        _write("request-%d.jwt" % int(time.time()), jar if isinstance(jar, str) else jar.decode())
    return jar


def handle_direct_post(self, form):
    t = time.time()
    _write("form-%d.json" % int(t), form)
    token = (form.get("response") or [""])[0] if isinstance(form.get("response"), list) else ""
    with self._lock:
        cands = list(self._sessions.values())
    for c in cands:
        try:
            body = jwe.decrypt_response(token, c.enc_key)
        except Exception:  # noqa: BLE001
            continue
        _write("response-%d.json" % int(t), body)
        _write("session-%d.json" % int(t), {"state": c.state, "nonce": c.nonce, "received_at": t})
        break
    status, rbody, verdict = _orig_post(self, form)
    _write("verdict-%d.json" % int(t), {
        "received_at": t, "status": status,
        "authentic": bool(getattr(verdict, "authentic", False)) if verdict else False,
        "code": getattr(verdict, "code", None), "reason": getattr(verdict, "reason", None),
        "claims": getattr(verdict, "claims", None)})
    return status, rbody, verdict


V.Verifier.handle_direct_post = handle_direct_post
V.Verifier.request_object = request_object
sys.exit(cli.main(sys.argv[3:]))
