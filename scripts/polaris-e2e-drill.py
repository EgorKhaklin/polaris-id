#!/usr/bin/env python3
"""
polaris-e2e-drill.py — the whole holder<->verifier flow, RUN end to end (PE follow-up).

The wallet (PE.7) holds a credential and PRESENTS it; a relying party
(scripts/polaris-relying-party.py) decides ACCEPT or REJECT by combining the two
questions Polaris keeps apart:

  authenticity  — offline, cryptographic: the detached verifier (PE.2) checks a
                  real ML-DSA-65 signature over SHA3-256(token_value), against a
                  published issuer anchor set. No server, no database.
  authorization — online, fresh: is the token authoritative RIGHT NOW? A call to
                  the issuer's GET /api/tokens/<id>/verify.

This drill uses REAL ML-DSA signatures for the authenticity half (so the offline
verification is the genuine article, not a placeholder) and an in-memory stand-in
for the issuer's status service for the authorization half, so the whole decision
matrix RUNS with no database — in the same CI job as the detached verifier and the
federation drill. The status service's real, DB-backed form (GET .../verify and
currently_authoritative) is exercised against Postgres in polaris_web/test_app.py;
this drill proves the relying party correctly COMBINES a real offline authenticity
verdict with a status signal, including the anti-coercion property.

Matrix (FAILS with exit 1 if any decision is wrong):

    presentation             expected
    active, own issuer       ACCEPT       (authentic + trusted + authoritative)
    revoked, own issuer      REJECT       (authentic, but not authoritative now)
    tampered signature       REJECT       (not authentic)
    foreign issuer           REJECT       (authentic, but not a trusted issuer)
    active, offline check    PROVISIONAL  (authentic; status not verified)
    active, under duress     ACCEPT       (indistinguishable from a normal accept)

Needs liboqs + cryptography (the real two-witness issuance path).

    python3 scripts/polaris-e2e-drill.py
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))
_WALLET = os.path.join(_ROOT, "scripts", "polaris-wallet.py")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_ROOT, "scripts", filename))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _issue_pack(pqc, key_file, token_value, token_id):
    """A real authenticity pack: sign SHA3-256(token_value) with this issuer's
    custodied ML-DSA-65 key, through the app's real signing entry point."""
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
    sig, alg, pk = pqc.signature_with_key_for_token(token_value)
    return {"format": "polaris-authenticity-pack/1", "token_value": token_value,
            "token_id": token_id, "algorithm": alg, "signature_hex": sig.hex(),
            "public_key_hex": pk, "real_signature": True}


def _wallet(wallet_dir, *args):
    return subprocess.run([sys.executable, _WALLET, "--wallet", wallet_dir, *args],
                          capture_output=True, text=True)


def _present(tmp, pack, tag, duress=False):
    """Hold a credential in a fresh wallet and present it — the holder's real tool."""
    wdir = os.path.join(tmp, "wallet-%s" % tag)
    pf = os.path.join(tmp, "pack-%s.json" % tag)
    with open(pf, "w") as f:
        json.dump(pack, f)
    _wallet(wdir, "enroll", "--pack", pf, "--duress-code", "please-help-me")
    out = os.path.join(tmp, "present-%s.json" % tag)
    _wallet(wdir, "present", *(["--duress"] if duress else ["--code", "ordinary"]),
            "--out", out)
    with open(out) as f:
        return json.load(f)


def main():
    try:
        import pqc_signing
    except Exception as e:
        print("e2e drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_enabled() and pqc_signing.second_witness_available()):
        print("e2e drill needs real ML-DSA (POLARIS_USE_REAL_PQC=1 + liboqs + cryptography); skipping",
              file=sys.stderr)
        return 3

    verify = _load("polaris_verify", "polaris-verify.py")
    rp = _load("polaris_relying_party", "polaris-relying-party.py")
    # The relying party loads the detached verifier itself; share this one instance.
    rp._load_verifier = lambda: verify

    tmp = tempfile.mkdtemp(prefix="polaris-e2e-")
    # Two roots: the home issuer, and a foreign issuer outside the trust anchors.
    home_kp = pqc_signing.generate_keypair()
    foreign_kp = pqc_signing.generate_keypair()
    home_kf = os.path.join(tmp, "home.key.json")
    foreign_kf = os.path.join(tmp, "foreign.key.json")
    for kf, kp in ((home_kf, home_kp), (foreign_kf, foreign_kp)):
        with open(kf, "w") as f:
            json.dump(kp, f)
    # The relying party trusts only the home issuer.
    anchor = [home_kp["public_key_hex"]]

    # The issuer's status service, stubbed in memory: token_id -> authoritative.
    STATUS = {101: True, 202: False}  # 101 active, 202 revoked

    def status_checker(token_id):
        active = STATUS.get(int(token_id), False)
        return {"currently_authoritative": active,
                "status": "ACTIVE" if active else "REVOKED"}

    home_active = _issue_pack(pqc_signing, home_kf, "E2E-ACTIVE-0001", 101)
    home_revoked = _issue_pack(pqc_signing, home_kf, "E2E-REVOKED-0002", 202)
    foreign_active = _issue_pack(pqc_signing, foreign_kf, "E2E-FOREIGN-0003", 101)

    tampered = dict(home_active)
    b = bytearray.fromhex(tampered["signature_hex"])
    b[0] ^= 0x01
    tampered["signature_hex"] = b.hex()

    cases = []

    def decide(tag, pack, *, online, duress=False):
        presentation = _present(tmp, pack, tag, duress=duress)
        v = rp.verify_presentation(
            presentation, anchor_keys=anchor,
            status_checker=(status_checker if online else None))
        return v

    checks = [
        ("active, own issuer", decide("active", home_active, online=True), "accept"),
        ("revoked, own issuer", decide("revoked", home_revoked, online=True), "reject"),
        ("tampered signature", decide("tampered", tampered, online=True), "reject"),
        ("foreign issuer", decide("foreign", foreign_active, online=True), "reject"),
        ("active, offline check", decide("offline", home_active, online=False), "provisional"),
        ("active, under duress", decide("duress", home_active, online=True, duress=True), "accept"),
    ]

    print("presentation             decision     authentic  authoritative  expected  ok")
    ok_all = True
    for label, v, expected in checks:
        ok = (v["decision"] == expected)
        ok_all = ok_all and ok
        print("  %-22s %-11s  %-9s  %-13s  %-8s  %s"
              % (label, v["decision"].upper(), v["authentic"],
                 v["currently_authoritative"], expected.upper(), "OK" if ok else "WRONG"))
    print()
    # The anti-coercion invariant: a duress presentation is byte-for-byte a normal
    # accept from the relying party's side — it cannot tell the two apart.
    normal = next(v for (l, v, e) in checks if l == "active, own issuer")
    duress = next(v for (l, v, e) in checks if l == "active, under duress")
    indistinguishable = (normal["decision"] == duress["decision"] == "accept"
                         and sorted(normal) == sorted(duress))
    print("duress indistinguishable from a normal accept: %s" % indistinguishable)
    ok_all = ok_all and indistinguishable

    if ok_all:
        print("\nOK: the holder<->verifier flow holds — real offline authenticity combined "
              "with online status, and duress stays silent.")
        return 0
    print("\nFAIL: a holder<->verifier decision was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
