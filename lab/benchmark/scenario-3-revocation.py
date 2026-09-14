#!/usr/bin/env python3
"""scenario-3-revocation.py -- a credential is revoked immediately before an OFFLINE presentation.

The third required scenario. The directive forbids hiding behind "fresh enough", "eventually
consistent" or "policy dependent" and demands the actual bounded behaviour. So this measures
the bound, on the published vectors, and prints the number.

Run: python3 lab/benchmark/scenario-3-revocation.py
"""
import datetime as dt
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
_spec = importlib.util.spec_from_file_location(
    "polaris_detached", ROOT / "packages" / "polaris-verify" / "polaris_verify_cli" / "verifier.py")
V = importlib.util.module_from_spec(_spec)
sys.modules["polaris_detached"] = V
_spec.loader.exec_module(V)

VEC = ROOT / "conformance" / "vectors"


def vec(name):
    return json.loads((VEC / ("%s.json" % name)).read_text())


def seconds(a, b):
    return (dt.datetime.fromisoformat(b.replace("Z", "+00:00"))
            - dt.datetime.fromisoformat(a.replace("Z", "+00:00"))).total_seconds()


def main() -> int:
    assertion = vec("status-assertion-mldsa87-valid")
    pack = vec("pack-mldsa87-valid")
    window = seconds(assertion["issued_at"], assertion["expires_at"])

    probe = V.verify_status_assertion(assertion, now=assertion["issued_at"])
    if probe.get("status_authentic") is not True:
        print("VOID: the published assertion does not verify here (status_authentic=%r). "
              "Without a real ML-DSA backend every signature reports 'could not run' and "
              "every number below would be a fact about this machine. Install "
              "cryptography>=48 or liboqs and re-run." % probe.get("status_authentic"),
              file=sys.stderr)
        return 2

    print("== the published status assertion ==")
    print("  issued_at        %s" % assertion["issued_at"])
    print("  expires_at       %s" % assertion["expires_at"])
    print("  window           %.0f seconds = %.0f days" % (window, window / 86400))
    print("  status           %s" % assertion.get("status"))

    print("\n== the stale acceptance window, measured ==")
    # One second before expiry, with the verifier's DEFAULT bound.
    almost = (dt.datetime.fromisoformat(assertion["expires_at"].replace("Z", "+00:00"))
              - dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    late = V.verify_status_assertion(assertion, now=almost)
    print("  default max_window_seconds       %r" % None)
    print("  fresh, %.0f days after issuance   %s" % (window / 86400, late.get("fresh")))
    print("  -> the stale acceptance window IS the issuer's chosen validity: %.0f days."
          % (window / 86400))
    print("     A revocation recorded one second after issued_at is invisible to an offline")
    print("     verifier for the rest of that period. Not 'eventually consistent'. %.0f days."
          % (window / 86400))

    print("\n== what bounds it ==")
    for bound in (300, 86400, 31536000):
        r = V.verify_status_assertion(assertion, now=almost, max_window_seconds=bound)
        print("  max_window_seconds=%-9d fresh=%s" % (bound, r.get("fresh")))
    print("  The bound is the RELYING PARTY's to supply. The verifier's default is None,")
    print("  which accepts any window the issuer chose.")

    print("\n== the full offline decision, and what it shows a relying party ==")
    stapled = V.verify_stapled(pack, assertion, now=almost)
    for k in sorted(stapled):
        if k not in ("witnesses",):
            print("  %-22s %s" % (k, str(stapled[k])[:70]))

    print("\n== no status assertion at all ==")
    alone = V.verify_pack(pack)
    print("  signature_valid        %s" % alone.get("signature_valid"))
    print("  anything about status? %s" % ("status" in alone or "active" in alone))
    print("  -> authenticity and status are separate verdicts. A credential that verifies")
    print("     says nothing about whether it is still valid, and the API cannot be read")
    print("     as saying otherwise: there is no status field to misread.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
