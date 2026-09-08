#!/usr/bin/env python3
"""
polaris-relying-party.py — the other end of the credential (the holder↔verifier flow).

A relying party (a bank, a border kiosk, a service) takes a holder's PRESENTATION
— produced by the wallet's `present` — and decides ACCEPT or REJECT by combining
the two questions Polaris keeps deliberately separate:

  1. AUTHENTICITY (offline, cacheable): is this a genuine credential signed by a
     trusted issuer? Checked with the detached verifier (scripts/polaris-verify.py),
     no server, no database. Optionally against an issuer anchor set.
  2. AUTHORIZATION (online, freshness-critical): is the token authoritative RIGHT
     NOW (ACTIVE, not revoked)? A tiny online call to the issuer's
     GET /api/tokens/<id>/verify.

ACCEPT iff the credential is authentic, from a trusted issuer (when an anchor is
given), and currently authoritative. Without a reachable issuer the verdict is
PROVISIONAL — authentic, but status unverified — never a full accept.

    polaris-relying-party.py verify-presentation --presentation p.json --issuer-url https://issuer.example
    polaris-relying-party.py verify-presentation --presentation p.json --issuer-anchor issuer.json --offline

Standalone: stdlib plus the detached verifier. A holder's duress code, if present,
is carried but never changes this decision — a duress presentation is byte-for-byte
a normal one, and the distress signal is matched silently by the issuer, out of the
relying party's sight (the anti-coercion vocation).

Exit 0 = ACCEPT · 2 = REJECT · 3 = PROVISIONAL (authentic, status unverified) or error.
"""
import argparse
import importlib.util
import json
import os
import sys
import urllib.request

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify_rp", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def verify_presentation(presentation, anchor_keys=None, status_checker=None):
    """Decide ACCEPT/REJECT/PROVISIONAL for a holder's presentation.

    status_checker: a callable token_id -> the issuer's /verify JSON (dict), or None
    to skip the online status check (offline / provisional). Injectable so this is
    testable without a live server; the CLI supplies an HTTP one."""
    cred = presentation.get("credential") or {}
    V = _load_verifier()
    a = V.verify_pack(cred, anchor_keys)
    authentic = bool(a.get("signature_valid"))
    issuer_ok = a.get("issuer_trusted") in (None, True)
    reasons = []
    if not authentic:
        reasons.append("not authentic: %s" % (a.get("note") or "signature invalid"))
    if a.get("issuer_trusted") is False:
        reasons.append("issuer not trusted: the signing key is not in the anchor set")

    status, current = None, None
    if authentic and issuer_ok and status_checker is not None:
        try:
            status = status_checker(cred.get("token_id"))
        except Exception as e:
            status = {"error": str(e)}
        if isinstance(status, dict) and "currently_authoritative" in status:
            current = bool(status["currently_authoritative"])
            if not current:
                reasons.append("not currently authoritative (revoked/inactive): status=%s"
                               % status.get("status"))
        else:
            reasons.append("status could not be read from the issuer")

    if not authentic or not issuer_ok:
        decision = "reject"
    elif status_checker is None:
        decision = "provisional"
        reasons.append("status not checked (offline) — authenticity only, not a full accept")
    elif current is True:
        decision = "accept"
    else:
        decision = "reject"

    return {
        "decision": decision,
        "authentic": authentic,
        "issuer_trusted": a.get("issuer_trusted"),
        "currently_authoritative": current,
        "token_value": cred.get("token_value"),
        # The presence of a presented code is all the relying party sees; whether it
        # is a normal or a duress code is indistinguishable here, by design.
        "presented_code_present": presentation.get("presented_code") is not None,
        "reasons": reasons,
    }


def _http_status_checker(issuer_url):
    base = issuer_url.rstrip("/")

    def check(token_id):
        url = "%s/api/tokens/%s/verify" % (base, token_id)
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.loads(r.read())
    return check


def _oauth_status_checker(issuer_url, client_id, client_secret, credential):
    """Authenticate as a relying-party ORGANIZATION (OAuth2 client-credentials,
    P3.4) and read the token's status from the versioned /api/v1/verify endpoint by
    presenting the credential the holder handed over. This is how a real relying
    party — a bank, a kiosk — reaches the status check: as itself, with its own
    credential, not by borrowing an operator login. It presents the genuine issued
    signature (a possession proof), and the issuer returns the verdict with no
    personal data. Returns the status shape verify_presentation reads."""
    import base64
    base = issuer_url.rstrip("/")
    creds = base64.b64encode(("%s:%s" % (client_id, client_secret)).encode()).decode()
    token_req = urllib.request.Request(
        "%s/api/v1/oauth/token" % base, data=b"grant_type=client_credentials",
        headers={"Authorization": "Basic " + creds,
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(token_req, timeout=30) as r:
        bearer = json.loads(r.read())["access_token"]
    body = json.dumps({"token_value": credential.get("token_value"),
                       "signature_hex": credential.get("signature_hex")}).encode()

    def check(_token_id):
        req = urllib.request.Request(
            "%s/api/v1/verify" % base, data=body,
            headers={"Authorization": "Bearer " + bearer, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            v = json.loads(r.read())
        # Map the v1 verdict onto the status shape verify_presentation consumes.
        return {"currently_authoritative": v.get("currently_authoritative"),
                "status": v.get("status")}
    return check


def main(argv=None):
    ap = argparse.ArgumentParser(description="Polaris relying-party verifier (holder<->verifier flow).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("verify-presentation", help="decide ACCEPT/REJECT for a holder's presentation")
    p.add_argument("--presentation", required=True, help="the wallet's presentation JSON (default: stdin)")
    p.add_argument("--issuer-anchor", help="the issuer's published verification key(s)")
    p.add_argument("--issuer-url", help="the issuer base URL for the online status check")
    p.add_argument("--oauth-client-id",
                   help="authenticate to the issuer's /api/v1 as this relying-party org (P3.4)")
    p.add_argument("--oauth-client-secret", help="the relying-party client secret (with --oauth-client-id)")
    p.add_argument("--offline", action="store_true", help="skip the online status check (provisional at best)")
    p.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        raw = open(args.presentation).read() if args.presentation and args.presentation != "-" else sys.stdin.read()
        presentation = json.loads(raw)
    except Exception as e:
        print("could not read the presentation: %s" % e, file=sys.stderr)
        return 3
    anchor = None
    if args.issuer_anchor:
        V = _load_verifier()
        anchor = V._load_anchor(args.issuer_anchor)
    status_checker = None
    if args.issuer_url and not args.offline:
        if args.oauth_client_id and args.oauth_client_secret:
            # P3.4: authenticate as a relying-party org and use the versioned
            # /api/v1/verify contract, presenting this credential.
            cred = presentation.get("credential") or {}
            status_checker = _oauth_status_checker(
                args.issuer_url, args.oauth_client_id, args.oauth_client_secret, cred)
        else:
            status_checker = _http_status_checker(args.issuer_url)

    verdict = verify_presentation(presentation, anchor_keys=anchor, status_checker=status_checker)
    if args.json:
        print(json.dumps(verdict, indent=2))
    else:
        print("decision:              %s" % verdict["decision"].upper())
        print("authentic:             %s" % verdict["authentic"])
        if verdict["issuer_trusted"] is not None:
            print("issuer_trusted:        %s" % verdict["issuer_trusted"])
        if verdict["currently_authoritative"] is not None:
            print("currently_authoritative: %s" % verdict["currently_authoritative"])
        for r in verdict["reasons"]:
            print("  - %s" % r)
    return {"accept": 0, "reject": 2, "provisional": 3}.get(verdict["decision"], 3)


if __name__ == "__main__":
    sys.exit(main())
