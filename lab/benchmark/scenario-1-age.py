#!/usr/bin/env python3
"""scenario-1-age.py -- holder proves AGE >= 21 without revealing date of birth.

The first required benchmark scenario, run rather than described. It measures POLARIS only.
The external column of the table in README.md comes from public documentation, and every
value that could not be measured here is marked UNKNOWN there rather than guessed.

Two things are measured:

  1. Can Polaris return a trustworthy verdict on an age-over-21 presentation, and what does
     the verifier see? Built the way the EUDI/HAIP ecosystem actually does it: the issuer
     mints a selectively-disclosable boolean `age_over_21`, and the holder discloses that
     one claim while withholding `birthdate`. This is NOT a range proof. Whether that
     distinction matters is the question the table answers.

  2. Given transcript A from verifier 1 and transcript B from verifier 2, same holder? The
     adversary pools complete transcripts and looks for any value that is IDENTICAL. A
     different holder is run as the control, so a value that matches for everybody is
     counted as a population constant rather than as a correlation handle.

Run: python3 lab/benchmark/scenario-1-age.py
"""
import base64
import hashlib
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
PKG = ROOT / "packages" / "polaris-oid4vp"
sys.path.insert(0, str(PKG))

from test_sdjwt import Wallet, _disclosure, _jws, _public_jwk  # noqa: E402
from polaris_oid4vp.sdjwt import b64u_encode, verify_presentation  # noqa: E402

NONCE = "vJ3xQ2kZ8fLpN1sT7wRm5bYc0aHdEgUi"


def mint(wallet, claims, salt_prefix="s"):
    """An SD-JWT VC committing to every claim, selectively disclosable."""
    ds = {name: _disclosure("%s%d" % (salt_prefix, i), name, value)
          for i, (name, value) in enumerate(claims)}
    payload = {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
               "iat": int(time.time()),
               "_sd": [b64u_encode(hashlib.sha256(d.encode("ascii")).digest())
                       for d in ds.values()],
               "cnf": {"jwk": _public_jwk(wallet.holder_key)}}
    jwt = _jws(wallet.issuer_key,
               {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "issuer-1"}, payload)
    return jwt, ds


def present(wallet, jwt, disclosures, nonce, audience):
    body = jwt + "~" + "".join(d + "~" for d in disclosures)
    kb = _jws(wallet.holder_key, {"alg": "ES256", "typ": "kb+jwt"},
              {"iat": int(time.time()), "aud": audience, "nonce": nonce,
               "sd_hash": b64u_encode(hashlib.sha256(body.encode("ascii")).digest())})
    return body + kb


def observable(presentation):
    """Every scalar a verifier reads off the wire, flattened, plus transcript length."""
    out = {}

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, "%s.%s" % (path, k) if path else k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, "%s[%d]" % (path, i))
        else:
            out[path] = node

    parts = presentation.split("~")
    for label, token in (("issuer_jwt", parts[0]), ("kb_jwt", parts[-1])):
        header, claims, sig = token.split(".")
        walk(json.loads(base64.urlsafe_b64decode(header + "==")), label + ".hdr")
        walk(json.loads(base64.urlsafe_b64decode(claims + "===")), label + ".claims")
        out[label + ".sig"] = sig
    for i, d in enumerate(parts[1:-1]):
        if d:
            out["disclosure[%d]" % i] = d
    out["_bytes"] = len(presentation)
    return out


def main() -> int:
    audience = "x509_hash:0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
    wallet = Wallet()
    jwt, ds = mint(wallet, [("age_over_21", True), ("birthdate", "1990-04-17"),
                            ("given_name", "Jean")])

    print("== 1. the verdict, and what the verifier sees ==")
    presentation = present(wallet, jwt, [ds["age_over_21"]], NONCE, audience)
    v = verify_presentation(presentation, expected_nonce=NONCE, expected_audience=audience,
                            issuer_jwks=[wallet.issuer_jwk])
    print("  authentic                    %s" % v.authentic)
    print("  claims the verifier sees     %s" % sorted(v.claims))
    print("  age_over_21                  %r" % v.claims.get("age_over_21"))
    print("  birthdate disclosed          %s" % ("birthdate" in v.claims))
    print("  birthdate anywhere on wire   %s" % ("1990-04-17" in presentation))
    print("  presentation bytes           %d" % len(presentation))
    print("  disclosures presented        %d of %d committed" % (1, len(ds)))
    print("  network calls to verify      0 (issuer key configured out of band)")

    print("\n== 2. same holder? two verifiers pool complete transcripts ==")
    # DIFFERENT SALTS PER ISSUANCE, which is what a real issuer does. Reusing one salt makes
    # the disclosure and its digest match for everybody and would be reported as a
    # correlation handle when it is a fixture artifact.
    a = observable(present(wallet, jwt, [ds["age_over_21"]], "nonce-1", "verifier-ONE"))
    b = observable(present(wallet, jwt, [ds["age_over_21"]], "nonce-2", "verifier-TWO"))
    other_wallet = Wallet()
    other_jwt, other_ds = mint(other_wallet, [("age_over_21", True)], salt_prefix="z")
    c = observable(present(other_wallet, other_jwt, [other_ds["age_over_21"]],
                           "nonce-3", "verifier-ONE"))

    same = {k for k in set(a) & set(b) if a[k] == b[k]}
    everyone = {k for k in set(a) & set(c) if a[k] == c[k]}
    handles = sorted(same - everyone)
    print("  observable values per transcript   %d" % len(a))
    print("  identical across the two verifiers %d" % len(same))
    print("  identical for a DIFFERENT holder   %d  (population constants)" % len(everyone))
    print("  correlation handles                %d" % len(handles))
    for k in handles:
        print("      %-34s %s" % (k, str(a[k])[:46]))
    if handles:
        print("\n  A verifier pair matches this holder with ONE string comparison. The handle is"
              "\n  issuer-signed, so the holder cannot vary it per verifier. Unlinkability here"
              "\n  rests on batch issuance (many credentials, one key each), which this"
              "\n  measurement does not exercise and this repository does not implement.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
