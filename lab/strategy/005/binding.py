#!/usr/bin/env python3
"""005, section 9 step 3: does the wallet copy obey the Polaris record?

Kill criterion 1 of the record: "If the wallet copy can be issued, or can stay valid, when the
Polaris record would refuse it or has revoked it, the wallet copy is a second issuer beside
Polaris, not Polaris issuing. Kill."

This drives the lab issuer (issuer/issuer.py) in its Polaris-record mode against a real Polaris
database loaded the way CI loads one, and tries to obtain or keep a wallet copy the record
refuses:

  A. offers for credentials the record holds REVOKED, LOST and RESERVE  -> no copy
  B. an offer made while ACTIVE, the credential revoked before redemption -> no copy
  C. a copy issued while ACTIVE and presented: accepted, status VALID      (the control)
  D. the same credential revoked through uc8_revoke_token, the SAME copy presented again
     -> the verifier's verdict carries status INVALID from the issuer's list

Revocation is performed by the Polaris procedure, not by editing a row. The presentation goes
through polaris-oid4vp's `Verifier` with the issuer CA as trust anchor and a status resolver
that accepts a status list only from an x5c leaf chaining to that CA.

    POLARIS_DB=polaris_lab005 python3 binding.py [--out results.json]

The database must be a scratch copy (it revokes a token). Exit 0 when every case behaves as
the criterion requires.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import secrets
import sys
import time
import urllib.parse

import psycopg2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

HERE = pathlib.Path(__file__).resolve().parent
TREE = HERE.parents[2]
sys.path[:0] = [str(HERE / "issuer"), str(TREE / "packages" / "polaris-oid4vp"),
                str(TREE / "lab" / "interop" / "credo" / "adversarial")]
import issuer as lab  # noqa: E402
from adversarial import _throwaway_client_pki  # noqa: E402
from polaris_oid4vp import status as tsl  # noqa: E402
from polaris_oid4vp.jwe import encrypt_compact  # noqa: E402
from polaris_oid4vp.verifier import Verifier  # noqa: E402


class Record:
    """The Polaris record, read-only except through the revocation procedure."""

    def __init__(self, dsn):
        self.conn = psycopg2.connect(dsn)
        self.conn.autocommit = True

    def __call__(self, token_value):
        with self.conn.cursor() as c:
            c.execute("SELECT token_id, status FROM IdentityToken WHERE token_value = %s", (token_value,))
            return c.fetchone()

    def all(self):
        with self.conn.cursor() as c:
            c.execute("SELECT token_id, status FROM IdentityToken")
            return c.fetchall()

    def pick(self, status):
        with self.conn.cursor() as c:
            c.execute("SELECT token_value FROM IdentityToken WHERE status = %s ORDER BY token_id LIMIT 1", (status,))
            row = c.fetchone()
            return row[0] if row else None

    def issue(self, label):
        """A fresh ACTIVE credential through uc1_issue_and_activate, the Polaris issuance
        procedure: agency 2 on algorithm 1, where the seed has another agency authorized to
        co-sign its revocation."""
        tv = "TKN-LAB005-%s-%s" % (label, secrets.token_hex(3))
        with self.conn.cursor() as c:
            c.execute("SELECT uc1_issue_and_activate(%s, DATE '1990-01-01', 'PA', 2, 1, 'NONE', 2, NULL,"
                      " %s, %s, 'lab', ARRAY[1])", ("Lab Holder " + label, tv, "PHY-" + tv))
        return tv

    def pick_revocable(self):
        """An ACTIVE credential whose revocation another agency is authorized to co-sign, so the
        revocation goes through every rule uc8 applies rather than around one."""
        with self.conn.cursor() as c:
            c.execute("SELECT t.token_value FROM IdentityToken t WHERE t.status = 'ACTIVE' AND EXISTS ("
                      " SELECT 1 FROM AgencyAlgorithmAuth aa WHERE aa.algorithm_id = t.algorithm_id"
                      " AND aa.authorization_type = 'BOTH' AND aa.agency_id <> t.issuing_agency_id)"
                      " ORDER BY t.token_id LIMIT 1")
            row = c.fetchone()
            return row[0] if row else None

    def revoke(self, token_value):
        with self.conn.cursor() as c:
            c.execute("SELECT token_id, issuing_agency_id FROM IdentityToken WHERE token_value = %s", (token_value,))
            tid, agency = c.fetchone()
            # The revocation-rate rule asks for a co-signing agency once revocations pass its
            # bound, which a scratch database with a handful of tokens does at once. A second
            # agency co-signs, as an operator would; the rule itself is left alone.
            # The co-signer must be another agency holding BOTH authorization on the
            # credential's algorithm, which is the rule uc8 checks.
            c.execute("SELECT aa.agency_id FROM AgencyAlgorithmAuth aa JOIN IdentityToken t"
                      " ON t.algorithm_id = aa.algorithm_id WHERE t.token_id = %s"
                      " AND aa.authorization_type = 'BOTH' AND aa.agency_id <> %s"
                      " ORDER BY aa.agency_id LIMIT 1", (tid, agency))
            cosigner = c.fetchone()[0]
            c.execute("CALL uc8_revoke_token(%s, %s, %s, %s, %s)",
                      (tid, agency, "COMPROMISED", "lab/strategy/005", cosigner))


def b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Holder:
    """A wallet reduced to what the binding question needs: its own key, the OpenID4VCI
    exchange against the issuer object, and a key-bound presentation."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.jwk = lab.public_jwk(self.key)

    def obtain(self, issuer, offer):
        code = offer["grants"][lab.PRE_AUTH]["pre-authorized_code"]
        st, tok = issuer.token({"grant_type": lab.PRE_AUTH, "pre-authorized_code": code})
        if st != 200:
            return None, "token: %s" % tok
        _, n = issuer.nonce()
        proof = lab.jws(self.key, {"alg": "ES256", "typ": lab.PROOF_TYP, "jwk": self.jwk},
                        {"aud": issuer.base, "iat": int(time.time()), "nonce": n["c_nonce"]})
        st, body = issuer.credential("Bearer " + tok["access_token"],
                                     {"credential_configuration_id": lab.CONFIG_ID, "proofs": {"jwt": [proof]}})
        if st != 200:
            return None, body.get("error_description") or body.get("error")
        return body["credentials"][0]["credential"], None

    def respond(self, jar, credential):
        _, claims = [json.loads(lab.b64d(x)) for x in jar.split(".")[:2]]
        enc = claims["client_metadata"]["jwks"]["keys"][0]
        enc_pub = ec.EllipticCurvePublicNumbers(int.from_bytes(lab.b64d(enc["x"]), "big"),
                                                int.from_bytes(lab.b64d(enc["y"]), "big"),
                                                ec.SECP256R1()).public_key()
        kb = lab.jws(self.key, {"alg": "ES256", "typ": "kb+jwt"},
                     {"iat": int(time.time()), "aud": claims["client_id"], "nonce": claims["nonce"],
                      "sd_hash": b64e(hashlib.sha256(credential.encode("ascii")).digest())})
        body = {"state": claims["state"], "vp_token": {"pid": [credential + kb]}}
        return {"response": [encrypt_compact(json.dumps(body).encode(), enc_pub)]}


def status_resolver_for(issuer, ca):
    """Accept a status list only when its x5c leaf chains to the issuer CA the relying party
    already trusts for credentials, and verify it under that leaf. Stated, not inferred."""

    def verify(signing_input, signature, header):
        try:
            leaf = x509.load_der_x509_certificate(base64.b64decode((header or {}).get("x5c", [""])[0]))
            ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
            der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
            leaf.public_key().verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:  # noqa: BLE001
            return False

    authority = tsl.StatedAuthority().state(
        credential_issuer=issuer.base, status_uri=issuer.base + "/status", verify=verify,
        why="the relying party trusts this issuer's CA for credentials, and so for its status list")

    def resolver(*, uri, idx, issuer=None):
        return tsl.decide_by_fetching(index=idx, expected_uri=uri, authority=authority,
                                      fetch=lambda _u: issuer_obj.status_list_token().encode(),
                                      now=int(time.time()), credential_issuer=issuer)
    issuer_obj = issuer
    return resolver


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    a = ap.parse_args()
    db = os.environ.get("POLARIS_DB")
    if not db or db in ("polaris_test", "polaris"):
        raise SystemExit("POLARIS_DB must name a SCRATCH database: this revokes a credential")
    record = Record("dbname=%s host=%s user=%s" % (db, os.environ.get("POLARIS_DB_HOST", "localhost"),
                                                   os.environ.get("POLARIS_DB_USER", os.environ.get("USER"))))
    issuer = lab.Issuer("https://issuer.lab.test", record=record)
    ca = x509.load_pem_x509_certificate(issuer.ca_pem.encode())
    cert_pem, key_pem = _throwaway_client_pki()
    verifier = Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                        request_uri="https://verifier.lab.test/request.jwt",
                        response_uri="https://verifier.lab.test/response",
                        issuer_trust_anchors=[ca], status_resolver=status_resolver_for(issuer, ca))
    results, bad = [], 0

    def note(case, expect, got, detail):
        nonlocal bad
        ok = expect == got
        bad += not ok
        results.append({"case": case, "expect": expect, "got": got, "detail": detail})
        print("%-4s %-8s %-8s %s   (%s)" % ("ok" if ok else "FAIL", expect, got, case, detail))

    def offer_for(tv):
        uri, _ = issuer.new_offer(tv)
        return json.loads(urllib.parse.unquote(uri.split("credential_offer=", 1)[1]))

    def present(holder, credential):
        _, jar = verifier.new_request()
        status, _, verdict = verifier.handle_direct_post(holder.respond(jar, credential))
        rev = getattr(verdict, "revocation", {}) or {}
        return status, verdict, rev

    # A. the record refuses at the offer's credential
    for st in ("REVOKED", "LOST", "RESERVE"):
        tv = record.pick(st)
        if tv is None:
            note("A: offer for a %s credential" % st, "no copy", "SKIPPED", "no such row in the seed")
            continue
        cred, why = Holder().obtain(issuer, offer_for(tv))
        note("A: offer for a %s credential" % st, "no copy", "copy" if cred else "no copy", why or "issued")

    # B. ACTIVE at offer, revoked before redemption
    tv_b = record.issue("B")
    offer_b = offer_for(tv_b)
    record.revoke(tv_b)
    cred, why = Holder().obtain(issuer, offer_b)
    note("B: offered while ACTIVE, revoked before redemption", "no copy", "copy" if cred else "no copy", why or "issued")

    # C. the control, then D. revoke and present the same copy again
    tv_c = record.issue("C")
    holder = Holder()
    cred, why = holder.obtain(issuer, offer_for(tv_c))
    note("C: offer for an ACTIVE credential", "copy", "copy" if cred else "no copy", why or "issued")
    if cred:
        status, verdict, rev = present(holder, cred)
        got = "accepted/%s" % rev.get("meaning") if status == 200 and rev.get("checked") else \
            "status %d, revocation %s" % (status, rev.get("state"))
        note("C: that copy presented to polaris-oid4vp", "accepted/VALID", got, rev.get("reason") or "")
        record.revoke(tv_c)
        status, verdict, rev = present(holder, cred)
        got = "%s" % rev.get("meaning") if rev.get("checked") else "unchecked (%s)" % rev.get("state")
        note("D: the SAME copy after uc8_revoke_token", "INVALID", got,
             "HTTP %d; the verdict carries the record's revocation" % status)

    print("\n%d cases, %d as the criterion requires, %d not" % (len(results), len(results) - bad, bad))
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps({"database": "a scratch load of polaris_sql (00_load_all + migrations)",
                                                   "results": results}, indent=2) + "\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
