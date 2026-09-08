#!/usr/bin/env python3
"""
polaris-verify.py — a DETACHED authenticity verifier for a Polaris credential.

The engine that runs when the dashboard is unplugged (roadmap P-E1). A relying
party (a bank, a border kiosk, anyone) verifies a Polaris credential OFFLINE,
with NO Polaris backend, NO Postgres, and NO Polaris code on the box — only a
standard ML-DSA-65 library. It reads an "authenticity pack" (the self-contained
credential exported by `GET /api/tokens/<id>/authenticity-pack`) and checks that
the ML-DSA-65 signature is genuine.

This proves AUTHENTICITY (the token was signed by the holder of a given key), not
current AUTHORIZATION (whether the token is ACTIVE right now) — those are two
different questions with two different freshness needs (see
docs/design/verification-scaling.md). Authorization is a tiny online call to
`GET /api/tokens/<id>/verify`; authenticity is this, and it needs no network.

    python3 polaris-verify.py --pack credential.json
    python3 polaris-verify.py --pack credential.json --issuer-anchor issuer.json
    cat credential.json | python3 polaris-verify.py --json

Verifies the SAME thing the server does: the signature over SHA3-256(token_value)
under ML-DSA-65, checked against the public key IN the pack (a self-contained
authenticity proof), and — with --issuer-anchor — that that public key is one the
issuer has published (so it is genuinely the issuer's key, not an attacker's).

Two independent witnesses, exactly like Polaris issuance: liboqs (primary) and
cryptography/OpenSSL (a second, independent implementation). They must AGREE.

Exit code 0 iff the signature is valid (and, when an anchor is given, the key is
trusted). 2 iff invalid. 3 on a usage/dependency error.

Dependencies: `pip install liboqs-python` (primary). Optionally
`cryptography>=48` on OpenSSL 3.5+ for the independent second witness.
"""
import argparse
import hashlib
import json
import os
import sys

_ALG = "ML-DSA-65"
_PLACEHOLDER = "DETERMINISTIC-PLACEHOLDER-SHA3-256"


def _digest(token_value: str) -> bytes:
    # The signer signs SHA3-256(token_value.encode('utf-8')); we reconstruct it.
    return hashlib.sha3_256(token_value.encode("utf-8")).digest()


def _verify_liboqs(digest: bytes, sig: bytes, pk: bytes):
    """Primary witness: liboqs. Returns True/False, or None if liboqs is absent."""
    try:
        import oqs  # type: ignore
    except Exception:
        return None
    try:
        with oqs.Signature(_ALG) as v:
            return bool(v.verify(digest, sig, pk))
    except Exception:
        return False


def _verify_cryptography(digest: bytes, sig: bytes, pk: bytes):
    """Second, independent witness: cryptography/OpenSSL. None if unavailable."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        from cryptography.exceptions import InvalidSignature
    except Exception:
        return None
    if not hasattr(mldsa, "MLDSA65PublicKey"):
        return None
    try:
        key = mldsa.MLDSA65PublicKey.from_public_bytes(pk)
    except Exception:
        return None
    try:
        key.verify(sig, digest)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def verify_pack(pack: dict, anchor_keys=None) -> dict:
    """Verify an authenticity pack. Returns a verdict dict."""
    tok = pack.get("token_value")
    alg = pack.get("algorithm")
    sig_hex = pack.get("signature_hex")
    pk_hex = pack.get("public_key_hex")
    verdict = {
        "algorithm": alg,
        "token_value": tok,
        "signature_valid": False,
        "witnesses": [],
        "authenticity": None,
        "issuer_trusted": None,
        "note": None,
    }
    if not tok or not alg:
        verdict["note"] = "pack is missing token_value or algorithm"
        return verdict

    if alg == _PLACEHOLDER:
        # A dev/CI placeholder is NOT a signature — it is a SHA3 binding with no
        # key. Say so plainly rather than reporting a green check.
        try:
            got = bytes.fromhex(sig_hex or "")
        except ValueError:
            got = b""
        matches = got == _digest(tok)
        verdict["signature_valid"] = False
        verdict["authenticity"] = "none"
        verdict["note"] = ("this pack carries the DEV placeholder (not a real signature); "
                           "the SHA3 binding %s. It cannot be authenticated." %
                           ("matches" if matches else "does NOT match"))
        return verdict

    if alg != _ALG:
        verdict["note"] = "unknown signature algorithm: %r" % alg
        return verdict

    if not sig_hex or not pk_hex:
        verdict["note"] = "pack is missing signature_hex or public_key_hex"
        return verdict
    try:
        sig = bytes.fromhex(sig_hex)
        pk = bytes.fromhex(pk_hex)
    except ValueError:
        verdict["note"] = "signature_hex/public_key_hex are not valid hex"
        return verdict

    digest = _digest(tok)
    primary = _verify_liboqs(digest, sig, pk)
    witness = _verify_cryptography(digest, sig, pk)
    ran = []
    if primary is not None:
        ran.append("liboqs=%s" % ("valid" if primary else "INVALID"))
    if witness is not None:
        ran.append("cryptography=%s" % ("valid" if witness else "INVALID"))
    verdict["witnesses"] = ran

    if primary is None and witness is None:
        verdict["note"] = ("no ML-DSA-65 verifier available: install liboqs-python "
                           "(and optionally cryptography>=48 for the second witness)")
        return verdict
    if primary is not None and witness is not None and primary != witness:
        verdict["signature_valid"] = False
        verdict["authenticity"] = "witness-disagreement"
        verdict["note"] = ("the two witnesses DISAGREE on this signature — treat as invalid "
                           "and investigate the verifier libraries")
        return verdict

    ok = primary if primary is not None else witness
    verdict["signature_valid"] = bool(ok)
    verdict["authenticity"] = "genuine" if ok else "forged-or-tampered"

    if anchor_keys is not None:
        trusted = pk_hex.lower() in {a.lower() for a in anchor_keys}
        verdict["issuer_trusted"] = trusted
        if ok and not trusted:
            verdict["note"] = ("signature is genuine but its public key is NOT in the issuer "
                               "anchor set — it is a valid signature by an UNTRUSTED key")
    return verdict


def verify_dir(dir_path) -> int:
    """Re-verify every published vector in ``dir_path`` against its declared
    expectation (``_vector.expect``: "valid" | "invalid"). This is the offline
    proof a third party runs to confirm this verifier agrees with the published
    packs: a genuine pack verifies, and every tampered pack FAILS. Exit 0 iff all
    match, 2 if any disagree, 3 on a usage error."""
    import glob
    paths = sorted(glob.glob(os.path.join(dir_path, "*.json")))
    if not paths:
        print("no *.json vectors in %s" % dir_path, file=sys.stderr)
        return 3
    all_ok = True
    ran_real = False
    for p in paths:
        try:
            pack = json.load(open(p))
        except Exception as e:
            print("%-34s UNREADABLE (%s)" % (os.path.basename(p), e))
            all_ok = False
            continue
        expect = (pack.get("_vector") or {}).get("expect", "valid")
        verdict = verify_pack(pack)
        got = "valid" if verdict["signature_valid"] else "invalid"
        if verdict["authenticity"] not in ("none", None) and verdict["witnesses"]:
            ran_real = True
        # A vector whose verifier could not run at all (no library, so no witness)
        # is neither pass nor fail here — report it so a bare-Python run is not
        # mistaken for a green check.
        if not verdict["witnesses"] and pack.get("public_key_hex"):
            print("%-34s SKIPPED (no ML-DSA verifier installed)" % os.path.basename(p))
            all_ok = False
            continue
        ok = (got == expect)
        all_ok = all_ok and ok
        print("%-34s expect=%-8s got=%-8s %s"
              % (os.path.basename(p), expect, got, "OK" if ok else "MISMATCH"))
    if ran_real:
        print("(verified with the app's real witnesses)")
    return 0 if all_ok else 2


def selftest() -> int:
    """Prove the whole path end-to-end with REAL ML-DSA-65: generate a keypair,
    sign, build a pack, verify it (must pass), tamper it three ways (each must
    fail), and confirm the placeholder is refused. Requires liboqs; exits 3 if it
    is absent so a CI runner that intends to exercise real crypto fails loudly
    rather than skipping in silence."""
    try:
        import oqs  # type: ignore
    except Exception as e:
        print("selftest needs liboqs-python (the primary witness): %s" % e, file=sys.stderr)
        return 3
    tok = "POLARIS-SELFTEST-TOKEN-0001"
    digest = _digest(tok)
    with oqs.Signature(_ALG) as signer:
        pk = bytes(signer.generate_keypair())
        sig = bytes(signer.sign(digest))

    def pack_for(token_value, signature, public_key):
        return {"format": "polaris-authenticity-pack/1", "token_value": token_value,
                "algorithm": _ALG, "signature_hex": signature.hex(),
                "public_key_hex": public_key.hex()}

    checks = []
    v = verify_pack(pack_for(tok, sig, pk))
    checks.append(("genuine pack verifies", v["signature_valid"] is True))
    checks.append(("both witnesses agree" if len(v["witnesses"]) == 2 else
                   "primary witness ran", len(v["witnesses"]) >= 1))
    bad = bytearray(sig); bad[0] ^= 0x01
    checks.append(("flipped signature fails",
                   verify_pack(pack_for(tok, bytes(bad), pk))["signature_valid"] is False))
    checks.append(("altered token fails",
                   verify_pack(pack_for(tok + "X", sig, pk))["signature_valid"] is False))
    with oqs.Signature(_ALG) as other:
        pk2 = bytes(other.generate_keypair())
    checks.append(("wrong key fails",
                   verify_pack(pack_for(tok, sig, pk2))["signature_valid"] is False))
    placeholder = {"format": "polaris-authenticity-pack/1", "token_value": tok,
                   "algorithm": _PLACEHOLDER, "signature_hex": _digest(tok).hex(),
                   "public_key_hex": None}
    checks.append(("placeholder is refused",
                   verify_pack(placeholder)["signature_valid"] is False))
    ok = True
    for name, passed in checks:
        print("  [%s] %s" % ("PASS" if passed else "FAIL", name))
        ok = ok and passed
    print("selftest: %s (witnesses: %s)"
          % ("PASS" if ok else "FAIL", ", ".join(v["witnesses"]) or "primary only"))
    return 0 if ok else 2


_STATUS_ASSERTION_FORMAT = "polaris-status-assertion/1"


def _status_assertion_canonical(assertion):
    """The canonical bytes the issuer signed — MUST match app.py's
    _status_assertion_statement: sorted-keys compact JSON of exactly five fields."""
    return json.dumps({
        "format": assertion.get("format"),
        "token_value": assertion.get("token_value"),
        "status": assertion.get("status"),
        "issued_at": assertion.get("issued_at"),
        "expires_at": assertion.get("expires_at"),
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_iso(s):
    from datetime import datetime, timezone
    if isinstance(s, str) and s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def verify_status_assertion(assertion, now=None, max_window_seconds=None, anchor_keys=None):
    """Verify a short-lived signed status assertion (P3.6) OFFLINE: the ML-DSA-65
    signature over SHA3-256(canonical statement), and freshness (now within
    [issued_at, expires_at) and the window no longer than max_window_seconds, when a
    bound is given). Reports status and, with anchors, issuer trust. No network."""
    from datetime import datetime, timezone
    v = {"status_authentic": False, "fresh": None, "status": assertion.get("status"),
         "issued_at": assertion.get("issued_at"), "expires_at": assertion.get("expires_at"),
         "issuer_trusted": None, "witnesses": [], "note": None}
    alg = assertion.get("algorithm")
    pk_hex = assertion.get("public_key_hex")
    sig_hex = assertion.get("signature_hex")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder status assertion — not authenticatable offline"
        return v
    if assertion.get("format") != _STATUS_ASSERTION_FORMAT:
        v["note"] = "not a %s" % _STATUS_ASSERTION_FORMAT
        return v
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_status_assertion_canonical(assertion)).digest()
    primary = _verify_liboqs(digest, sig, pk)
    witness = _verify_cryptography(digest, sig, pk)
    ran = []
    if primary is not None:
        ran.append("liboqs=%s" % ("valid" if primary else "INVALID"))
    if witness is not None:
        ran.append("cryptography=%s" % ("valid" if witness else "INVALID"))
    v["witnesses"] = ran
    if primary is None and witness is None:
        v["note"] = "no ML-DSA-65 verifier available"
        return v
    if primary is not None and witness is not None and primary != witness:
        v["note"] = "the two witnesses DISAGREE — treat as invalid"
        return v
    ok = primary if primary is not None else witness
    v["status_authentic"] = bool(ok)
    if not ok:
        v["note"] = "status assertion signature is invalid"
        return v
    now = now or datetime.now(timezone.utc)
    try:
        ia, ea = _parse_iso(assertion["issued_at"]), _parse_iso(assertion["expires_at"])
    except Exception as e:
        v["fresh"] = False
        v["note"] = "unparseable issued_at/expires_at (%s)" % e
        return v
    window = (ea - ia).total_seconds()
    within = ia <= now < ea
    window_ok = True if max_window_seconds is None else (0 < window <= max_window_seconds)
    v["fresh"] = bool(within and window_ok)
    if not within:
        v["note"] = "stale or not-yet-valid: now is not within [issued_at, expires_at)"
    elif not window_ok:
        v["note"] = "window %ds exceeds the accepted maximum %ds" % (int(window), max_window_seconds)
    if anchor_keys is not None:
        v["issuer_trusted"] = pk_hex.lower() in {a.lower() for a in anchor_keys}
    return v


def verify_stapled(pack, assertion, now=None, max_window_seconds=None, anchor_keys=None):
    """The full OFFLINE holder<->verifier decision (P3.6): the credential's
    authenticity AND a fresh, bound, ACTIVE status assertion — with no connectivity.
    accept iff both signatures are genuine (and issuer-trusted, when anchored), the
    assertion is bound to this credential, fresh, and ACTIVE."""
    a = verify_pack(pack, anchor_keys)
    s = verify_status_assertion(assertion, now=now, max_window_seconds=max_window_seconds,
                                anchor_keys=anchor_keys)
    bound = bool(pack.get("token_value")) and pack.get("token_value") == assertion.get("token_value")
    reasons = []
    if not a["signature_valid"]:
        reasons.append("credential is not authentic")
    if a.get("issuer_trusted") is False:
        reasons.append("credential issuer is not trusted")
    if not bound:
        reasons.append("the status assertion is not bound to this credential")
    if not s["status_authentic"]:
        reasons.append("status assertion not authentic: %s" % (s.get("note") or "invalid"))
    elif not s["fresh"]:
        reasons.append("status not fresh: %s" % (s.get("note") or "expired"))
    elif s["status"] != "ACTIVE":
        reasons.append("status is %s, not ACTIVE" % s["status"])
    if s.get("issuer_trusted") is False:
        reasons.append("status assertion issuer is not trusted")
    accept = (a["signature_valid"] and a.get("issuer_trusted") in (None, True)
              and bound and s["status_authentic"] and s.get("issuer_trusted") in (None, True)
              and bool(s["fresh"]) and s["status"] == "ACTIVE")
    return {"decision": "accept" if accept else "reject",
            "authentic": a["signature_valid"], "status": s["status"], "fresh": s["fresh"],
            "bound": bound, "reasons": reasons, "credential": a, "status_assertion": s}


def _load_anchor(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return [str(x) for x in data]
    for key in ("public_keys_hex", "public_key_hex", "anchors", "keys"):
        if key in data:
            v = data[key]
            return [str(x) for x in (v if isinstance(v, list) else [v])]
    raise ValueError("anchor file must be a list of hex keys or carry a "
                     "'public_keys_hex' list")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Detached authenticity verifier for a Polaris credential.")
    ap.add_argument("--pack", help="authenticity pack JSON file (default: stdin)")
    ap.add_argument("--status-assertion",
                    help="a signed status assertion JSON file (P3.6): with --pack, decide "
                         "ACCEPT/REJECT fully OFFLINE (authenticity + fresh, bound, ACTIVE status)")
    ap.add_argument("--max-window", type=int, default=None,
                    help="reject a status assertion whose validity window exceeds this many seconds")
    ap.add_argument("--issuer-anchor", help="JSON file of the issuer's published verification key(s)")
    ap.add_argument("--json", action="store_true", help="machine-readable verdict")
    ap.add_argument("--verify-dir", help="re-verify every published vector in a directory")
    ap.add_argument("--selftest", action="store_true",
                    help="prove the path end-to-end with a live ML-DSA-65 round-trip (needs liboqs)")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if args.verify_dir:
        return verify_dir(args.verify_dir)

    try:
        raw = open(args.pack).read() if args.pack else sys.stdin.read()
        pack = json.loads(raw)
    except Exception as e:
        print("could not read the authenticity pack: %s" % e, file=sys.stderr)
        return 3
    anchor = None
    if args.issuer_anchor:
        try:
            anchor = _load_anchor(args.issuer_anchor)
        except Exception as e:
            print("could not read the issuer anchor: %s" % e, file=sys.stderr)
            return 3

    # P3.6: with a stapled status assertion, decide the whole thing OFFLINE.
    if args.status_assertion:
        try:
            assertion = json.loads(open(args.status_assertion).read())
        except Exception as e:
            print("could not read the status assertion: %s" % e, file=sys.stderr)
            return 3
        verdict = verify_stapled(pack, assertion, max_window_seconds=args.max_window, anchor_keys=anchor)
        if args.json:
            print(json.dumps(verdict, indent=2))
        else:
            print("decision:         %s" % verdict["decision"].upper())
            print("authentic:        %s" % verdict["authentic"])
            print("status:           %s" % verdict["status"])
            print("fresh:            %s" % verdict["fresh"])
            print("bound:            %s" % verdict["bound"])
            for r in verdict["reasons"]:
                print("  - %s" % r)
        return 0 if verdict["decision"] == "accept" else 2

    verdict = verify_pack(pack, anchor)
    if args.json:
        print(json.dumps(verdict, indent=2))
    else:
        print("token:            %s" % verdict["token_value"])
        print("algorithm:        %s" % verdict["algorithm"])
        print("signature_valid:  %s" % verdict["signature_valid"])
        if verdict["witnesses"]:
            print("witnesses:        %s" % ", ".join(verdict["witnesses"]))
        if verdict["issuer_trusted"] is not None:
            print("issuer_trusted:   %s" % verdict["issuer_trusted"])
        if verdict["note"]:
            print("note:             %s" % verdict["note"])
    ok = verdict["signature_valid"] and (verdict["issuer_trusted"] in (None, True))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
