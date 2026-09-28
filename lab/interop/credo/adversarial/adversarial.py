#!/usr/bin/env python3
"""Mutations of one genuine Credo presentation, each put to polaris-oid4vp's full decision path.

Credo 0.6.3 built, signed and encrypted a real presentation (`capture-verifier` recorded it,
together with the session it answered). This script rebuilds that session inside a `Verifier`
that judges against the captured client_id, then posts variants of Credo's output to `handle_direct_post`:
the genuine response first (the positive control, which must be accepted), then each
mutation, which must be refused.

What this measures: whether the verifier refuses altered versions of an independent
implementation's REAL encodings (its base64url, its JSON member order, its JWE header with
`kid`, `apu`, `apv`). What it does not: Credo producing a hostile presentation on its own.
Credo is an honest wallet; every refusal below is Polaris refusing Polaris's edit of Credo's
output. That is internal evidence, stated as such.

    python3 adversarial.py CAPTURE.json [--out results.json] [--wallet NAME]
Exit 0 when the control is accepted and every mutation is refused; 1 otherwise.
"""
import argparse
import base64
import copy
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
TREE = HERE.parents[3]
sys.path.insert(0, str(TREE / "packages" / "polaris-oid4vp"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from polaris_oid4vp import verifier as V  # noqa: E402
from polaris_oid4vp.jwe import encrypt_compact  # noqa: E402
from polaris_oid4vp.sdjwt import verify_presentation  # noqa: E402



def _throwaway_client_pki():
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "adversarial-harness")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def flip(s, i=-3):
    """Change one base64url character without changing the length."""
    c = s[i]
    return s[:i] + ("A" if c != "A" else "B") + s[i + 1:] if i != -1 else s[:-1] + ("A" if s[-1] != "A" else "B")


def rejwt(jws, header=None, payload=None, keep_sig=True):
    h, p, sig = jws.split(".")
    hh = json.loads(b64d(h)) if header is None else header
    pp = json.loads(b64d(p)) if payload is None else payload
    return ".".join([b64e(json.dumps(hh, separators=(",", ":")).encode()),
                     b64e(json.dumps(pp, separators=(",", ":")).encode()), sig if keep_sig else ""])


class Harness:
    def __init__(self, capture):
        self.c = capture
        self.key = serialization.load_pem_private_key(capture["enc_key_pem"].encode(), password=None)
        cert_pem, key_pem = _throwaway_client_pki()
        self.v = V.Verifier(client_cert_pem=cert_pem, client_key_pem=key_pem,
                            request_uri="https://localhost:9543/request",
                            response_uri="https://localhost:9543/response",
                            issuer_jwks=capture["issuer_jwks"],
                            vct_values=tuple(capture["vct_values"]))
        # The only part of the client PKI a RESPONSE is judged against is the client_id, which
        # the KB-JWT's `aud` must equal. Take it from the capture; the throwaway certificate
        # would only sign request objects, and no request object is served here.
        self.v.client_id = capture["client_id"]

    def _session(self):
        s = V.Session(self.key)
        s.nonce, s.state = self.c["nonce"], self.c["state"]
        with self.v._lock:
            self.v._sessions = {s.state: s}
        return s

    def post_token(self, token):
        self._session()
        out = self.v.handle_direct_post({"response": token})
        verdict = out[2] if len(out) > 2 else None
        return out[0], (getattr(verdict, "reason", None) or out[1].get("error_description"))

    def post_body(self, body):
        return self.post_token(encrypt_compact(json.dumps(body).encode(), self.key.public_key()))

    def post_presentation(self, pres):
        body = copy.deepcopy(self.c["body"])
        body["vp_token"] = {"pid": [pres]}
        return self.post_body(body)


def cases(c):
    body = c["body"]
    pres = body["vp_token"]["pid"][0]
    parts = pres.split("~")
    issuer_jwt, disclosures, kb = parts[0], parts[1:-1], parts[-1]
    kb_h = json.loads(b64d(kb.split(".")[0]))
    kb_p = json.loads(b64d(kb.split(".")[1]))
    iss_h = json.loads(b64d(issuer_jwt.split(".")[0]))
    iss_p = json.loads(b64d(issuer_jwt.split(".")[1]))
    join = lambda *xs: "~".join(xs)  # noqa: E731
    fake = b64e(json.dumps(["s9", "age_over_18", True]).encode())
    altered = b64e(json.dumps(["s0", "given_name", "Mallory"]).encode())

    P = "presentation"
    yield ("genuine response, as Credo sent it", "token", c["response_jwe"], "accept")
    yield ("genuine body, re-encrypted to the session key", "body", body, "accept")

    # --- the JWE ----------------------------------------------------------------------
    t = c["response_jwe"].split(".")
    yield ("JWE ciphertext altered", "token", ".".join(t[:3] + [flip(t[3], 5)] + t[4:]), "reject")
    yield ("JWE tag altered", "token", ".".join(t[:4] + [flip(t[4], 5)]), "reject")
    yield ("JWE IV altered", "token", ".".join(t[:2] + [flip(t[2], 3)] + t[3:]), "reject")
    h = json.loads(b64d(t[0]))
    for label, mod in (("enc A256GCM", {"enc": "A256GCM"}), ("alg dir", {"alg": "dir"}),
                       ("alg none", {"alg": "none"}), ("zip DEF", {"zip": "DEF"}),
                       ("apv changed", {"apv": b64e(b"other")})):
        hh = dict(h, **mod)
        yield ("JWE protected header: %s" % label, "token",
               ".".join([b64e(json.dumps(hh, separators=(",", ":")).encode())] + t[1:]), "reject")
    yield ("JWE with an encrypted key segment", "token", ".".join([t[0], b64e(b"x" * 16)] + t[2:]), "reject")
    yield ("JWE with a sixth segment", "token", c["response_jwe"] + ".AAAA", "reject")

    # --- the authorization response body ----------------------------------------------
    yield ("state from another request", "body", dict(body, state="another-state"), "reject")
    yield ("state missing", "body", {k: v for k, v in body.items() if k != "state"}, "reject")
    yield ("vp_token keyed by a query id the request did not ask for", "body",
           dict(body, vp_token={"not-pid": [pres]}), "reject")
    yield ("vp_token with a second, unrequested entry", "body",
           dict(body, vp_token={"pid": [pres], "extra": [pres]}), "reject")
    yield ("vp_token with the presentation twice", "body", dict(body, vp_token={"pid": [pres, pres]}), "reject")
    yield ("vp_token as a bare string", "body", dict(body, vp_token=pres), "reject")
    yield ("vp_token empty", "body", dict(body, vp_token={}), "reject")

    # --- the presentation (Credo's SD-JWT, disclosures and KB-JWT) ---------------------
    yield ("key-binding JWT removed", P, join(issuer_jwt, *disclosures, ""), "reject")
    yield ("key-binding JWT signature removed", P, join(issuer_jwt, *disclosures, kb.rsplit(".", 1)[0] + "."), "reject")
    yield ("key-binding JWT alg none", P, join(issuer_jwt, *disclosures, rejwt(kb, header=dict(kb_h, alg="none"), keep_sig=False)), "reject")
    yield ("key-binding JWT nonce changed", P, join(issuer_jwt, *disclosures, rejwt(kb, payload=dict(kb_p, nonce="x"))), "reject")
    yield ("key-binding JWT aud changed", P, join(issuer_jwt, *disclosures, rejwt(kb, payload=dict(kb_p, aud="x509_hash:other"))), "reject")
    yield ("key-binding JWT typ changed", P, join(issuer_jwt, *disclosures, rejwt(kb, header=dict(kb_h, typ="JWT"))), "reject")
    yield ("key-binding JWT signature altered", P, join(issuer_jwt, *disclosures, flip(kb, -5)), "reject")
    yield ("one disclosure withheld (sd_hash no longer covers the set)", P, join(issuer_jwt, disclosures[0], kb), "reject")
    yield ("disclosures reordered", P, join(issuer_jwt, *reversed(disclosures), kb), "reject")
    yield ("a disclosure repeated", P, join(issuer_jwt, *disclosures, disclosures[0], kb), "reject")
    yield ("a disclosure the issuer never committed to", P, join(issuer_jwt, *disclosures, fake, kb), "reject")
    yield ("a disclosure's value altered", P, join(issuer_jwt, altered, *disclosures[1:], kb), "reject")
    yield ("a disclosure with base64 padding", P, join(issuer_jwt, disclosures[0] + "=", *disclosures[1:], kb), "reject")
    yield ("issuer signature altered", P, join(flip(issuer_jwt, -5), *disclosures, kb), "reject")
    yield ("issuer JWT alg none", P, join(rejwt(issuer_jwt, header=dict(iss_h, alg="none"), keep_sig=False), *disclosures, kb), "reject")
    yield ("issuer JWT vct changed", P, join(rejwt(issuer_jwt, payload=dict(iss_p, vct="urn:other")), *disclosures, kb), "reject")
    yield ("issuer JWT cnf removed", P, join(rejwt(issuer_jwt, payload={k: v for k, v in iss_p.items() if k != "cnf"}), *disclosures, kb), "reject")
    yield ("issuer JWT typ changed", P, join(rejwt(issuer_jwt, header=dict(iss_h, typ="JWT")), *disclosures, kb), "reject")
    yield ("a trailing empty segment after the KB-JWT", P, pres + "~", "reject")
    yield ("whitespace around the presentation", P, " " + pres + "\n", "reject")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("--out")
    ap.add_argument("--wallet", default="Credo 0.6.3 (@credo-ts/openid4vc)")
    a = ap.parse_args()
    capture = json.loads(pathlib.Path(a.capture).read_text())
    hz = Harness(capture)
    results, bad = [], 0
    for label, kind, value, expect in cases(capture):
        try:
            status, reason = {"token": hz.post_token, "body": hz.post_body,
                              "presentation": hz.post_presentation}[kind](value)
            got = "accept" if status == 200 else "reject"
        except Exception as exc:          # a crash is a finding too: the handler promises none
            got, reason = "CRASH", "%s: %s" % (type(exc).__name__, exc)
        ok = got == expect
        bad += not ok
        results.append({"case": label, "layer": kind, "expect": expect, "got": got, "reason": reason})
        print("%-4s %-6s %-6s %s%s" % ("ok" if ok else "FAIL", expect, got, label,
                                       "" if ok else "   <- %s" % reason))

    # KB-JWT freshness can only be moved through `now`, which the Verifier class does not
    # expose; the function underneath does.
    pres = capture["body"]["vp_token"]["pid"][0]
    iat = json.loads(b64d(pres.split("~")[-1].split(".")[1]))["iat"]
    for label, now, expect in (("KB-JWT judged at its own iat", iat, "accept"),
                               ("KB-JWT judged a day after its iat", iat + 86400, "reject"),
                               ("KB-JWT judged a day before its iat", iat - 86400, "reject")):
        v = verify_presentation(pres, expected_nonce=capture["nonce"], expected_audience=capture["client_id"],
                                issuer_jwks=capture["issuer_jwks"], expected_vct=capture["vct_values"],
                                now=now)
        got = "accept" if v.authentic else "reject"
        ok = got == expect
        bad += not ok
        results.append({"case": label, "layer": "presentation (verify_presentation, now)",
                        "expect": expect, "got": got, "reason": v.reason})
        print("%-4s %-6s %-6s %s%s" % ("ok" if ok else "FAIL", expect, got, label, "" if ok else "   <- %s" % v.reason))

    print("\n%d cases, %d as expected, %d not" % (len(results), len(results) - bad, bad))
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps({"wallet": a.wallet,
                                                   "verifier": "polaris-oid4vp (tree)",
                                                   "results": results}, indent=2) + "\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
