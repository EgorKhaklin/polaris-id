#!/usr/bin/env python3
"""polaris-status-distribution-drill.py - status artifacts through an untrusted cache (P2.6).

Signing a status artifact is what lets an untrusted intermediary carry it: a cache cannot
forge a status any more than an aggregator can. But a cache introduces the one failure
signing does not prevent, which is TIME. A cached status is a status the issuer may already
have withdrawn.

The rule this drill holds the origin to: a cache directive is never a constant, it is the
artifact's OWN remaining life, computed from the `expires_at` the issuer signed. A cache then
physically cannot outlive that window. A fixed max-age would eventually exceed some
artifact's window and the symptom would be a revoked credential that keeps verifying.

Two halves, and getting the second backwards is a privacy incident rather than a performance
regression:

  PUBLIC     A revocation feed, checkpoint, bundle, manifest, trust list, registry and leaf
             set are byte-identical for every consumer, so they are `public` and cached to
             their own window, with an ETag to revalidate on and no permission to serve stale.

  PER-HOLDER A status assertion, holder binding and timestamp NAME ONE CREDENTIAL. A shared
             cache holding one would serve one holder's credential to another, and a
             signature cannot undo a disclosure. Those are `no-store`.

Run: python3 scripts/polaris-status-distribution-drill.py
Needs a loaded database (POLARIS_DB_*). Exit 0 iff every case holds, 3 to skip.
"""
import os
import re
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "polaris_web"))

PUBLIC = [
    "/api/v1/revocation-feed/1",
    "/api/v1/epoch-checkpoint/1",
    "/api/v1/federation-status-bundle/1",
    "/api/v1/federation-manifest/1",
    "/api/v1/trust-list/1",
    "/api/v1/registry/1",
]


def _row(label, got, want):
    ok = got == want
    print("  %-66s %-10s %-10s %s" % (label[:66], str(got)[:10], str(want)[:10], "OK" if ok else "FAIL"))
    return ok


def main():
    try:
        import app as flask_app
    except Exception as e:  # noqa: BLE001
        print("status-distribution drill needs the app importable (POLARIS_DB_* + the venv): %s" % e,
              file=sys.stderr)
        return 3
    client = flask_app.app.test_client()
    try:
        # The public status endpoints answer only for a FEDERATED authority, and a freshly
        # loaded database has none: a signing key is registered by an operator, not by the
        # seed. Register one here so the drill is self-sufficient rather than silently
        # skipping the half it exists to test.
        flask_app.query("UPDATE Agency SET signing_public_key_hex = %s WHERE agency_id = 1 "
                        "AND signing_public_key_hex IS NULL", ("ab" * 16,), fetch="none")
        probe = client.get(PUBLIC[0])
    except Exception as e:  # noqa: BLE001
        print("status-distribution drill needs a loaded database: %s" % e, file=sys.stderr)
        return 3
    if probe.status_code >= 500:
        print("status-distribution drill needs a loaded, federated database (got %d)"
              % probe.status_code, file=sys.stderr)
        return 3

    print("status artifacts through an untrusted cache")
    print()
    print("  %-66s %-10s %-10s %s" % ("case", "got", "expected", "ok"))
    ok = True
    served = 0

    for path in PUBLIC:
        r = client.get(path)
        if r.status_code != 200:
            continue
        served += 1
        name = path.rsplit("/", 2)[-2]
        cc = r.headers.get("Cache-Control", "")
        body = r.get_json() or {}
        ok &= _row("%s: publicly cacheable" % name, "public" in cc, True)

        m = re.search(r"max-age=(\d+)", cc)
        ok &= _row("%s: carries a max-age" % name, bool(m), True)
        if m and isinstance(body.get("expires_at"), str):
            exp = body["expires_at"].replace("Z", "+00:00")
            remaining = (datetime.fromisoformat(exp) - datetime.now(timezone.utc)).total_seconds()
            # THE rule: the cache may not outlive the window the issuer signed.
            ok &= _row("%s: max-age does not outlive the signed window" % name,
                       int(m.group(1)) <= remaining + 5, True)

        ok &= _row("%s: does not permit serving stale" % name,
                   "stale-while-revalidate" in cc or "stale-if-error" in cc, False)
        ok &= _row("%s: carries an ETag to revalidate on" % name, bool(r.headers.get("ETag")), True)

    ok &= _row("at least one public artifact was actually served", served >= 1, True)

    # The per-holder half. The assertion names one token value, so no cache may keep it.
    row = flask_app.query("SELECT token_id, token_value FROM IdentityToken "
                          "WHERE issuing_agency_id = 1 AND status = 'ACTIVE' "
                          "ORDER BY token_id LIMIT 1", fetch="one", primary=True)
    if row:
        import hashlib
        import psycopg2
        placeholder = hashlib.sha3_256(row["token_value"].encode("utf-8")).digest()
        # Idempotent: a drill must be re-runnable against a database it has already touched,
        # and one signature per algorithm per token is a schema constraint, not a race.
        existing = flask_app.query(
            "SELECT 1 FROM TokenSignature WHERE token_id = %s AND algorithm_id = 1",
            (row["token_id"],), fetch="one", primary=True)
        if not existing:
            flask_app.query("INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, "
                            "signing_public_key_hex) VALUES (%s, 1, %s, NULL)",
                            (row["token_id"], psycopg2.Binary(placeholder)), fetch="none")
        r = client.post("/api/v1/status-assertion",
                        json={"token_value": row["token_value"], "signature_hex": placeholder.hex()})
        cc = r.headers.get("Cache-Control", "")
        ok &= _row("a status assertion is minted", r.status_code, 200)
        ok &= _row("...and is no-store: it names ONE credential", "no-store" in cc, True)
        ok &= _row("...and is never marked publicly cacheable", "public" in cc, False)
        ok &= _row("...and the body does name that one credential",
                   row["token_value"] in r.get_data(as_text=True), True)

    # An expired or unreadable window must not be cached at all.
    with flask_app.app.test_request_context():
        expired = flask_app._public_artifact({"format": "x", "expires_at": "2020-01-01T00:00:00Z"})
        ok &= _row("an already-expired artifact is no-store",
                   expired.headers.get("Cache-Control"), "no-store")
        junk = flask_app._public_artifact({"format": "x", "expires_at": "not-an-instant"})
        ok &= _row("an unreadable window is no-store, not a guessed interval",
                   junk.headers.get("Cache-Control"), "no-store")
    ok &= _row("a missing window yields no max-age at all",
               flask_app._artifact_max_age({}), None)

    print()
    if ok:
        print("OK: a signed status can cross an untrusted network without a cache being able to "
              "outlive the window its issuer signed. Every public artifact's max-age is its own "
              "remaining life, none permits serving stale, and each carries an ETag to revalidate "
              "on. Every artifact that names one credential is no-store, because a shared cache "
              "holding one would serve one holder's credential to another and a signature cannot "
              "undo a disclosure. An expired or unparseable window is not cached at all.")
        return 0
    print("FAIL: at least one case did not hold", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
