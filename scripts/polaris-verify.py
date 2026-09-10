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

_VERIFIER_VERSION = "9.330"   # P8.8b: pinned copies of this file self-identify to the compatibility suite
_ALG = "ML-DSA-65"          # the default parameter set
# P8.8a: the accepted FIPS 204 parameter sets -> (cryptography witness class, public key
# bytes, signature bytes). ML-DSA-44 is below the floor and is rejected like any unknown
# algorithm; a verifier never guesses a parameter set from a key it was not told about.
_ACCEPTED = {"ML-DSA-65": ("MLDSA65PublicKey", 1952, 3309), "ML-DSA-87": ("MLDSA87PublicKey", 2592, 4627)}


def _accepted_alg(alg):
    """True iff `alg` names an accepted parameter set. Total: a hostile non-string is simply
    not accepted (never a TypeError from an unhashable value)."""
    return isinstance(alg, str) and alg in _ACCEPTED
_PLACEHOLDER = "DETERMINISTIC-PLACEHOLDER-SHA3-256"


def _digest(token_value: str) -> bytes:
    # The signer signs SHA3-256(token_value.encode('utf-8')); we reconstruct it.
    return hashlib.sha3_256(token_value.encode("utf-8")).digest()


def _verify_liboqs(digest: bytes, sig: bytes, pk: bytes, alg=_ALG):
    """Primary witness: liboqs. Returns True/False, or None if liboqs is absent."""
    if not _accepted_alg(alg):
        return False
    try:
        import oqs  # type: ignore
    except Exception:
        return None
    try:
        with oqs.Signature(alg) as v:
            return bool(v.verify(digest, sig, pk))
    except Exception:
        return False


def _verify_cryptography(digest: bytes, sig: bytes, pk: bytes, alg=_ALG):
    """Second, independent witness: cryptography/OpenSSL. None if unavailable."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        from cryptography.exceptions import InvalidSignature
    except Exception:
        return None
    cls_name = _ACCEPTED[alg][0] if _accepted_alg(alg) else None
    if not cls_name or not hasattr(mldsa, cls_name):
        return None
    try:
        key = getattr(mldsa, cls_name).from_public_bytes(pk)
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
    """Verify an authenticity pack. Returns a verdict dict. Total: hostile non-dict input
    fails closed rather than raising."""
    if not isinstance(pack, dict):
        pack = {}
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

    if not _accepted_alg(alg):
        verdict["note"] = "unknown or unaccepted signature algorithm: %r" % alg
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
    primary = _verify_liboqs(digest, sig, pk, alg)
    witness = _verify_cryptography(digest, sig, pk, alg)
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
    # P8.8a: algorithm agility. An ML-DSA-87 pack verifies under its own parameter set; a
    # signature claiming the wrong set fails; a genuine ML-DSA-44 pack is refused (below the floor).
    enabled = set(oqs.get_enabled_sig_mechanisms())
    if "ML-DSA-87" in enabled:
        with oqs.Signature("ML-DSA-87") as s87:
            pk87 = bytes(s87.generate_keypair())
            sig87 = bytes(s87.sign(digest))
        p87 = dict(pack_for(tok, sig87, pk87), algorithm="ML-DSA-87")
        checks.append(("ML-DSA-87 pack verifies (algorithm agility)", verify_pack(p87)["signature_valid"] is True))
        bad87 = bytearray(sig87); bad87[0] ^= 0x01
        checks.append(("flipped ML-DSA-87 signature fails",
                       verify_pack(dict(p87, signature_hex=bytes(bad87).hex()))["signature_valid"] is False))
        checks.append(("an ML-DSA-87 signature claiming ML-DSA-65 fails",
                       verify_pack(dict(p87, algorithm="ML-DSA-65"))["signature_valid"] is False))
    if "ML-DSA-44" in enabled:
        with oqs.Signature("ML-DSA-44") as s44:
            pk44 = bytes(s44.generate_keypair())
            sig44 = bytes(s44.sign(digest))
        checks.append(("a genuine ML-DSA-44 pack is refused (below the floor)",
                       verify_pack(dict(pack_for(tok, sig44, pk44), algorithm="ML-DSA-44"))["signature_valid"] is False))
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


def _instant(now=None):
    """Normalise a caller's `now` into an aware datetime.

    Every freshness gate compares `now` against parsed instants, so a caller who passes an
    ISO-8601 string -- which the conformance contract, the CLI and every docstring invite --
    must get a verdict, not a TypeError and not a silent `fresh: false`. Accepts None (the
    real clock), an ISO-8601 string, or a datetime; a naive datetime is read as UTC. Raises
    ValueError on anything else, which each caller turns into an honest refusal, because a
    verifier told to judge "as of T" must never quietly judge as of some other instant.
    """
    from datetime import datetime, timezone
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, datetime):
        return now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    if isinstance(now, str):
        return _parse_iso(now)
    raise ValueError("`now` must be None, an ISO-8601 string or a datetime, not %s"
                     % type(now).__name__)


def verify_status_assertion(assertion, now=None, max_window_seconds=None, anchor_keys=None):
    """Verify a short-lived signed status assertion (P3.6) OFFLINE: the ML-DSA-65
    signature over SHA3-256(canonical statement), and freshness (now within
    [issued_at, expires_at) and the window no longer than max_window_seconds, when a
    bound is given). Reports status and, with anchors, issuer trust. No network."""
    if not isinstance(assertion, dict):
        assertion = {}
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
    if not _accepted_alg(alg):
        v["note"] = "unknown or unaccepted signature algorithm: %r" % alg
        return v
    primary = _verify_liboqs(digest, sig, pk, alg)
    witness = _verify_cryptography(digest, sig, pk, alg)
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
    try:
        now = _instant(now)
        ia, ea = _parse_iso(assertion["issued_at"]), _parse_iso(assertion["expires_at"])
    except Exception as e:
        v["fresh"] = False
        v["note"] = "unparseable issued_at/expires_at or `now` (%s)" % e
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


_MANIFEST_FORMAT = "polaris-federation-manifest/1"


def _manifest_canonical(manifest):
    """The canonical bytes an authority signs when it publishes a federation manifest.
    Excludes the signature envelope (signature_hex, public_key_hex); everything else
    is signed. MUST match app.py's _manifest_statement."""
    statement = {k: manifest.get(k) for k in
                 ("format", "authority", "anchors", "attestations", "epoch",
                  "revocation", "issued_at", "expires_at", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_manifest(manifest, now=None, max_window_seconds=None, trusted_anchors=None):
    """Verify a federation manifest (P3.2) OFFLINE: an authority's published anchors
    and the attestations it has made, signed by that authority. Checks the signature
    over SHA3-256(canonical), that the signing key is one of the manifest's own
    declared active anchors (self-consistency), freshness, and, with trusted_anchors,
    whether this authority is one the relying party trusts. No network."""
    if not isinstance(manifest, dict):
        manifest = {}
    _anchors = manifest.get("anchors")
    _atts = manifest.get("attestations")
    v = {"manifest_authentic": False, "fresh": None, "issuer_trusted": None,
         "authority": manifest.get("authority"),
         "anchors": _anchors if isinstance(_anchors, list) else [],
         "attestations": _atts if isinstance(_atts, list) else [],
         "witnesses": [], "note": None}
    alg = manifest.get("algorithm")
    pk_hex = manifest.get("public_key_hex")
    sig_hex = manifest.get("signature_hex")
    if manifest.get("format") != _MANIFEST_FORMAT:
        v["note"] = "not a %s" % _MANIFEST_FORMAT
        return v
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder manifest -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    # Self-consistency: the manifest must be signed by one of the ACTIVE anchor keys
    # it declares as its own roots, so a manifest cannot be signed by a stranger key.
    active = {str(a.get("public_key_hex", "")).lower() for a in v["anchors"]
              if isinstance(a, dict) and (a.get("status") or "active") == "active"}
    if pk_hex.lower() not in active:
        v["note"] = "the manifest is not signed by one of its own declared active anchors"
        return v
    digest = hashlib.sha3_256(_manifest_canonical(manifest)).digest()
    if not _accepted_alg(alg):
        v["note"] = "unknown or unaccepted signature algorithm: %r" % alg
        return v
    primary = _verify_liboqs(digest, sig, pk, alg)
    witness = _verify_cryptography(digest, sig, pk, alg)
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
        v["note"] = "the two witnesses DISAGREE -- treat as invalid"
        return v
    ok = primary if primary is not None else witness
    v["manifest_authentic"] = bool(ok)
    if not ok:
        v["note"] = "manifest signature is invalid"
        return v
    try:
        now = _instant(now)
        ia, ea = _parse_iso(manifest["issued_at"]), _parse_iso(manifest["expires_at"])
    except Exception as e:
        v["fresh"] = False
        v["note"] = "unparseable issued_at/expires_at or `now` (%s)" % e
        return v
    window = (ea - ia).total_seconds()
    within = ia <= now < ea
    window_ok = True if max_window_seconds is None else (0 < window <= max_window_seconds)
    v["fresh"] = bool(within and window_ok)
    if not within:
        v["note"] = "manifest is stale or not yet valid"
    elif not window_ok:
        v["note"] = "manifest window %ds exceeds the accepted maximum %ds" % (int(window), max_window_seconds)
    if trusted_anchors is not None:
        trusted = {t.lower() for t in trusted_anchors}
        v["issuer_trusted"] = bool(active & trusted)
    return v


_ATTESTATION_FORMAT = "polaris-trust-attestation/1"   # P9.5 (v9.348)


def _attestation_canonical(att):
    """The bytes an ATTESTING agency signs when it accepts another authority (P9.5). MUST
    match polaris_web/app.py's _attestation_statement; the canonical oracle pins the pair."""
    if not isinstance(att, dict):
        att = {}
    statement = {k: att.get(k) for k in
                 ("format", "attesting_agency_id", "attested_agency_id",
                  "attested_public_key_hex", "context_id", "attested_date",
                  "valid_until", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_attestation(att, attesting_agency_id=None, expected_key=None):
    """Verify OFFLINE that a federation attestation carries the ATTESTING agency's own
    signature over the attested key, the context and the window (P9.5).

    Before v9.348 an attestation was a row an operator recorded, and the manifest that
    published it signed whatever the table held: a row inserted straight into the database
    was indistinguishable from one made through the ceremony. A signed attestation is
    evidence in its own right, independent of the manifest's freshness window.

    An attestation with no signature is not a failure, it is `signed: False` LEGACY: rows
    recorded before v9.348 stay verifiable for one major, and a relying party that requires
    signatures asks for them. Total on hostile input."""
    v = {"signed": False, "attestation_authentic": False, "attester_matches": None,
         "key_matches": None, "witnesses": [], "note": None}
    if not isinstance(att, dict):
        v["note"] = "attestation must be an object"
        return v
    if not att.get("signature_hex") and not att.get("public_key_hex"):
        v["note"] = "unsigned legacy attestation (recorded before v9.348): the trust edge rests on the manifest"
        return v
    v["signed"] = True
    if att.get("format") != _ATTESTATION_FORMAT:
        v["note"] = "not a %s" % _ATTESTATION_FORMAT
        return v
    alg, pk_hex, sig_hex = att.get("algorithm"), att.get("public_key_hex"), att.get("signature_hex")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder attestation signature -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    ok, ran, note = _two_witness_verify(hashlib.sha3_256(_attestation_canonical(att)).digest(), sig, pk, alg)
    v["witnesses"] = ran
    if ok is None:
        v["note"] = note
        return v
    v["attestation_authentic"] = bool(ok)
    if not ok:
        v["note"] = "the attestation signature is invalid"
        return v
    if attesting_agency_id is not None:
        v["attester_matches"] = (att.get("attesting_agency_id") == attesting_agency_id)
        if not v["attester_matches"]:
            v["note"] = "the attestation names a different attesting agency than the manifest that published it"
    if expected_key is not None:
        v["key_matches"] = (str(att.get("attested_public_key_hex") or "").lower() == str(expected_key).lower())
        if not v["key_matches"]:
            v["note"] = "the attestation is signed over a different attested key"
    return v


def verify_cross_authority(pack, context_id, trusted_manifests, now=None,
                           max_window_seconds=None, trusted_anchors=None,
                           revocation_feed=None, trust_list=None,
                           require_signed_attestation=False):
    """Decide whether to accept a credential from ANOTHER authority, OFFLINE, using
    published federation manifests (P3.2). Accept iff the credential's signature is
    genuine AND some manifest the relying party trusts attests to the credential's
    signing key in the presented context. `trusted_anchors` are the anchor keys of the
    authorities the relying party already trusts (whose manifests it will honor).

    P3.2b: if the relying party supplies the issuer's `revocation_feed`, the decision is
    fail-closed on revocation -- a genuine, fresh feed BOUND to the issuer's key must
    also show the credential is not revoked. A missing binding, a forged or stale feed,
    or a listed (revoked) credential all reject. When no feed is supplied the decision is
    the P3.2 attestation decision and `revocation_checked` is False (non-revocation was
    not confirmed offline)."""
    if not isinstance(pack, dict):
        pack = {}
    if not isinstance(trusted_manifests, (list, tuple)):
        trusted_manifests = []
    a = verify_pack(pack)
    if not a["signature_valid"]:
        return {"decision": "reject", "authentic": False,
                "reasons": ["credential is not authentic"], "via": None,
                "revocation_checked": False, "revoked": None}
    token_key = (pack.get("public_key_hex") or "").lower()
    via = None
    attestation_signed = None       # P9.5: None until an edge is found
    for manifest in trusted_manifests:
        mv = verify_manifest(manifest, now=now, max_window_seconds=max_window_seconds,
                             trusted_anchors=trusted_anchors)
        if not (mv["manifest_authentic"] and mv["fresh"]):
            continue
        if trusted_anchors is not None and not mv["issuer_trusted"]:
            continue  # the relying party does not trust the manifest's authority
        for att in mv["attestations"]:
            if not isinstance(att, dict):
                continue
            same_key = str(att.get("attested_public_key_hex") or "").lower() == token_key
            same_ctx = (context_id is None or att.get("context_id") == context_id)
            if same_key and same_ctx:
                # P9.5: is this edge signed by the agency that made it, or is it the
                # operator's word carried by the manifest's signature?
                agency = (mv["authority"] or {}).get("agency_id") if isinstance(mv["authority"], dict) else None
                av = verify_attestation(att, attesting_agency_id=agency, expected_key=token_key)
                if av["signed"] and not (av["attestation_authentic"]
                                         and av["attester_matches"] is not False
                                         and av["key_matches"] is not False):
                    continue   # a present-but-bad signature is worse than none: refuse the edge
                if require_signed_attestation and not av["signed"]:
                    continue
                attestation_signed = bool(av["signed"])
                via = mv["authority"]
                break
        if via:
            break
    if not via:
        return {"decision": "reject", "authentic": True,
                "reasons": ["no trusted authority attests to this credential's issuer in this context"
                            + (" with a signature by the attesting agency" if require_signed_attestation else "")],
                "via": None, "revocation_checked": False, "revoked": None,
                "attestation_signed": None}
    # P8.7b: a trust list the relying party holds decides the issuer KEY's status independently
    # of the issuer's own manifest -- a compromised key rejects the credential outright.
    if trust_list is not None:
        tv = verify_trust_list(trust_list, now=now, max_window_seconds=max_window_seconds, trusted_anchors=trusted_anchors)
        if not (tv["trust_list_authentic"] and tv["fresh"]) or (trusted_anchors is not None and not tv["issuer_trusted"]):
            return {"decision": "reject", "authentic": True,
                    "reasons": ["the supplied trust list is not authentic, fresh and trusted"],
                    "via": via, "revocation_checked": False, "revoked": None, "key_status": None,
                    "attestation_signed": attestation_signed}
        status = key_status_at(trust_list, token_key, now)
        if status == "compromised":
            return {"decision": "reject", "authentic": True,
                    "reasons": ["the issuer key is listed COMPROMISED by a trusted trust list"],
                    "via": via, "revocation_checked": False, "revoked": None, "key_status": status,
                    "attestation_signed": attestation_signed}
    # P3.2b: fail-closed revocation propagation, if the relying party supplies the feed.
    if revocation_feed is not None:
        rv = verify_revocation_feed(revocation_feed, now=now,
                                    max_window_seconds=max_window_seconds, issuer_key=token_key)
        if not (rv["feed_authentic"] and rv["fresh"] and rv["issuer_matches"]):
            return {"decision": "reject", "authentic": True,
                    "reasons": ["the issuer's revocation feed is not authentic, fresh, and bound to "
                                "the issuer key -- non-revocation cannot be confirmed"],
                    "via": via, "revocation_checked": True, "revoked": None,
                    "attestation_signed": attestation_signed}
        if is_revoked(revocation_feed, pack.get("token_value") or ""):
            return {"decision": "reject", "authentic": True,
                    "reasons": ["credential is revoked in the issuer's published revocation feed"],
                    "via": via, "revocation_checked": True, "revoked": True,
                    "attestation_signed": attestation_signed}
        return {"decision": "accept", "authentic": True, "reasons": [], "via": via,
                "revocation_checked": True, "revoked": False,
                "attestation_signed": attestation_signed}
    return {"decision": "accept", "authentic": True, "reasons": [], "via": via,
            "revocation_checked": False, "revoked": None,
            "attestation_signed": attestation_signed}


# ---------------------------------------------------------------------------
# P3.2b: epoch alignment + revocation propagation across authorities.
#
# Two more signed objects an authority publishes, both consumed here OFFLINE and
# both signed by the SAME authority key that signs its manifest and its credentials:
#
#   - polaris-epoch-checkpoint/1: the authority's commitment to a point on its
#     append-only TokenStateEpoch chain -- an epoch number, its Merkle root, and the
#     prior epoch it extends. Two checkpoints from one authority let a consumer prove
#     MONOTONICITY and catch a FORK: two different roots signed at one epoch number is
#     cryptographic proof the authority equivocated about its own history.
#
#   - polaris-revocation-feed/1: the authority's signed revocation state as of an
#     epoch -- the sorted set of revoked-credential leaves (SHA3-256(token_value)) and
#     a commitment over them. Because RevocationList is append-only, a genuine feed is
#     MONOTONE: a newer feed that DROPS a previously-published revocation, or moves its
#     as_of backward, is a ROLLBACK and is rejected. A relying party checks a foreign
#     credential's non-revocation against the issuer's authentic feed with no issuer
#     contact -- revocation propagates through published, signed data, not a callback.
# ---------------------------------------------------------------------------
_EPOCH_CHECKPOINT_FORMAT = "polaris-epoch-checkpoint/1"
_REVOCATION_FEED_FORMAT = "polaris-revocation-feed/1"


def _epoch_checkpoint_canonical(cp):
    """Canonical bytes the authority signs. MUST match app.py _epoch_checkpoint_statement."""
    statement = {k: cp.get(k) for k in
                 ("format", "authority", "epoch", "prev", "as_of",
                  "issued_at", "expires_at", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _revocation_feed_canonical(feed):
    """Canonical bytes the authority signs. MUST match app.py _revocation_feed_statement.
    The revoked-leaf LIST is part of the signed statement, so the commitment can never be
    separated from the members it commits to."""
    statement = {k: feed.get(k) for k in
                 ("format", "authority", "epoch_number", "as_of", "revoked_root_hex",
                  "revoked_count", "revoked_leaves", "issued_at", "expires_at", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def revoked_root(leaves):
    """A deterministic commitment over the revoked-leaf set: SHA3-256 over the sorted,
    de-duplicated, newline-joined lowercase hex leaves. Order-independent, so anyone who
    holds the same set computes the same root. MUST match app.py's builder. Total: a
    non-list `leaves` (hostile input) commits to the empty set rather than raising."""
    if not isinstance(leaves, (list, tuple, set)):
        leaves = []
    uniq = sorted({str(x).lower() for x in leaves})
    return hashlib.sha3_256("\n".join(uniq).encode("utf-8")).hexdigest()


def revocation_leaf(token_value):
    """The published identifier for a revoked credential: SHA3-256(token_value) hex. A
    relying party derives it from the credential it is presented; it does NOT expose the
    active population, because only a holder of a credential can compute its leaf."""
    return hashlib.sha3_256(token_value.encode("utf-8")).hexdigest()


def _two_witness_verify(digest, sig, pk, alg=_ALG):
    """Shared ML-DSA-65 two-witness check (liboqs primary, cryptography second). Returns
    (ok, ran, note): ok is True/False, or None when no verifier is available or the two
    witnesses disagree -- in which case `note` says which."""
    if not _accepted_alg(alg):
        return None, [], "unknown or unaccepted signature algorithm: %r" % alg
    primary = _verify_liboqs(digest, sig, pk, alg)
    witness = _verify_cryptography(digest, sig, pk, alg)
    ran = []
    if primary is not None:
        ran.append("liboqs=%s" % ("valid" if primary else "INVALID"))
    if witness is not None:
        ran.append("cryptography=%s" % ("valid" if witness else "INVALID"))
    if primary is None and witness is None:
        return None, ran, "no ML-DSA-65 verifier available"
    if primary is not None and witness is not None and primary != witness:
        return None, ran, "the two witnesses DISAGREE -- treat as invalid"
    ok = primary if primary is not None else witness
    return bool(ok), ran, None


def _verify_window(obj, v, now, max_window_seconds):
    """Shared freshness gate for a signed, window-bounded object. Sets v['fresh'] and
    v['note']; returns nothing."""
    try:
        now = _instant(now)
        ia, ea = _parse_iso(obj["issued_at"]), _parse_iso(obj["expires_at"])
    except Exception as e:
        v["fresh"] = False
        v["note"] = "unparseable issued_at/expires_at or `now` (%s)" % e
        return
    window = (ea - ia).total_seconds()
    within = ia <= now < ea
    window_ok = True if max_window_seconds is None else (0 < window <= max_window_seconds)
    v["fresh"] = bool(within and window_ok)
    if not within:
        v["note"] = "object is stale or not yet valid"
    elif not window_ok:
        v["note"] = "validity window %ds exceeds the accepted maximum %ds" % (int(window), max_window_seconds)


def verify_epoch_checkpoint(cp, now=None, max_window_seconds=None, issuer_key=None):
    """Verify a signed epoch checkpoint OFFLINE (P3.2b): the signature over
    SHA3-256(canonical) with two witnesses, freshness, and (with issuer_key) that it is
    signed by the expected issuing authority's key. Returns a verdict dict. Chaining and
    fork detection between two checkpoints is check_epoch_chain."""
    if not isinstance(cp, dict):
        cp = {}
    v = {"checkpoint_authentic": False, "fresh": None, "issuer_matches": None,
         "authority": cp.get("authority"), "epoch": cp.get("epoch"), "prev": cp.get("prev"),
         "witnesses": [], "note": None}
    if cp.get("format") != _EPOCH_CHECKPOINT_FORMAT:
        v["note"] = "not a %s" % _EPOCH_CHECKPOINT_FORMAT
        return v
    alg, pk_hex, sig_hex = cp.get("algorithm"), cp.get("public_key_hex"), cp.get("signature_hex")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder checkpoint -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_epoch_checkpoint_canonical(cp)).digest()
    ok, ran, note = _two_witness_verify(digest, sig, pk, alg)
    v["witnesses"] = ran
    if ok is None:
        v["note"] = note
        return v
    v["checkpoint_authentic"] = bool(ok)
    if not ok:
        v["note"] = "checkpoint signature is invalid"
        return v
    _verify_window(cp, v, now, max_window_seconds)
    if issuer_key is not None:
        v["issuer_matches"] = (pk_hex.lower() == issuer_key.lower())
    return v


def check_epoch_chain(cp1, cp2):
    """Given two epoch checkpoints from the SAME authority, decide whether they form a
    consistent, monotonic chain, and detect a FORK. Pure structural check: establish each
    checkpoint's authenticity with verify_epoch_checkpoint first.

    Returns {"consistent": bool, "fork": bool, "note": str}. fork=True means the two
    checkpoints assign DIFFERENT roots to the SAME epoch number, or the later one does not
    extend the earlier one it should -- the equivocation the alignment protocol catches."""
    e1, e2 = (cp1.get("epoch") or {}), (cp2.get("epoch") or {})
    pk1, pk2 = (cp1.get("public_key_hex") or "").lower(), (cp2.get("public_key_hex") or "").lower()
    if pk1 and pk2 and pk1 != pk2:
        return {"consistent": False, "fork": False,
                "note": "checkpoints are signed by different keys; not one authority's chain"}
    n1, n2 = e1.get("number"), e2.get("number")
    if n1 is None or n2 is None:
        return {"consistent": False, "fork": False, "note": "a checkpoint is missing its epoch number"}
    (_, elo), (hi, ehi) = ((cp1, e1), (cp2, e2)) if n1 <= n2 else ((cp2, e2), (cp1, e1))
    nlo, nhi = elo["number"], ehi["number"]
    if nlo == nhi:
        if (elo.get("root_hex") or "").lower() != (ehi.get("root_hex") or "").lower():
            return {"consistent": False, "fork": True,
                    "note": "FORK: two different roots signed at epoch %s" % nlo}
        return {"consistent": True, "fork": False, "note": "identical epoch checkpoint"}
    hp = (hi.get("prev") or {})
    if nhi == nlo + 1:
        if hp.get("number") != nlo or (hp.get("root_hex") or "").lower() != (elo.get("root_hex") or "").lower():
            return {"consistent": False, "fork": True,
                    "note": "FORK: epoch %s does not extend the published epoch %s" % (nhi, nlo)}
        return {"consistent": True, "fork": False, "note": "adjacent checkpoints chain cleanly"}
    return {"consistent": True, "fork": False,
            "note": "monotone but non-adjacent (%s..%s); intervening checkpoints not shown" % (nlo, nhi)}


def epoch_aligned(manifest, checkpoint):
    """The alignment cross-check (P3.2b): True iff a checkpoint's epoch matches the epoch
    the authority's own (separately trusted) manifest commits to -- same number, same
    root. An authority cannot serve a checkpoint that disagrees with the epoch its signed
    manifest published without being caught. Returns None if either side omits the epoch."""
    me, ce = (manifest.get("epoch") or {}), (checkpoint.get("epoch") or {})
    if me.get("number") is None or ce.get("number") is None:
        return None
    return (me.get("number") == ce.get("number")
            and (me.get("root_hex") or "").lower() == (ce.get("root_hex") or "").lower())


def verify_revocation_feed(feed, now=None, max_window_seconds=None, issuer_key=None):
    """Verify a signed revocation feed OFFLINE (P3.2b): the signature over
    SHA3-256(canonical) with two witnesses, freshness, that the published commitment
    matches the listed leaves, and (with issuer_key) that it is signed by the expected
    issuer. Returns a verdict dict. Membership is is_revoked; monotonicity between two
    feeds is check_revocation_progression."""
    if not isinstance(feed, dict):
        feed = {}
    v = {"feed_authentic": False, "fresh": None, "commitment_ok": None, "issuer_matches": None,
         "authority": feed.get("authority"), "as_of": feed.get("as_of"),
         "revoked_count": feed.get("revoked_count"), "witnesses": [], "note": None}
    if feed.get("format") != _REVOCATION_FEED_FORMAT:
        v["note"] = "not a %s" % _REVOCATION_FEED_FORMAT
        return v
    alg, pk_hex, sig_hex = feed.get("algorithm"), feed.get("public_key_hex"), feed.get("signature_hex")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder feed -- not authenticatable offline"
        return v
    # The commitment must match the listed leaves; a feed whose root does not commit to
    # its own members is rejected before its signature is even considered meaningful. A
    # wrong-typed leaf set or root (hostile input) fails the commitment rather than raising.
    leaves = feed.get("revoked_leaves")
    if not isinstance(leaves, (list, tuple, set)):
        leaves = []
    uniq = {str(x).lower() for x in leaves}
    v["commitment_ok"] = (revoked_root(leaves) == str(feed.get("revoked_root_hex") or "").lower()
                          and len(uniq) == (feed.get("revoked_count") or 0))
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_revocation_feed_canonical(feed)).digest()
    ok, ran, note = _two_witness_verify(digest, sig, pk, alg)
    v["witnesses"] = ran
    if ok is None:
        v["note"] = note
        return v
    if not ok:
        v["note"] = "feed signature is invalid"
        return v
    if not v["commitment_ok"]:
        v["note"] = "the revoked-set commitment does not match the listed leaves"
        return v
    v["feed_authentic"] = True
    _verify_window(feed, v, now, max_window_seconds)
    if issuer_key is not None:
        v["issuer_matches"] = (pk_hex.lower() == issuer_key.lower())
    return v


def is_revoked(feed, token_value):
    """True iff the credential's leaf is listed in the feed. Call verify_revocation_feed
    first -- this is a membership test, not an authenticity check. Total: a non-dict feed or
    a non-list leaf set (hostile input) is treated as no-match rather than raising."""
    if not isinstance(feed, dict):
        return False
    leaf = revocation_leaf(str(token_value) if token_value else "").lower()
    leaves = feed.get("revoked_leaves")
    if not isinstance(leaves, (list, tuple, set)):
        return False
    return leaf in {str(x).lower() for x in leaves}


def check_revocation_progression(prev_feed, next_feed):
    """Given two revocation feeds from the SAME issuer, decide whether next_feed is a
    valid FORWARD progression of prev_feed. Revocation is append-only, so the newer feed
    must not move as_of backward and must not DROP any leaf the older feed published. A
    dropped leaf or a regressed as_of is a ROLLBACK (equivocation). Pure structural check.

    Returns {"progresses": bool, "rolled_back": bool, "note": str}."""
    pk1, pk2 = (prev_feed.get("public_key_hex") or "").lower(), (next_feed.get("public_key_hex") or "").lower()
    if pk1 and pk2 and pk1 != pk2:
        return {"progresses": False, "rolled_back": False,
                "note": "feeds are signed by different keys; not one issuer's history"}
    prev_leaves = {str(x).lower() for x in (prev_feed.get("revoked_leaves") or [])}
    next_leaves = {str(x).lower() for x in (next_feed.get("revoked_leaves") or [])}
    dropped = prev_leaves - next_leaves
    if dropped:
        return {"progresses": False, "rolled_back": True,
                "note": "ROLLBACK: %d revocation(s) in the older feed are missing from the newer one"
                        % len(dropped)}
    try:
        if _parse_iso(next_feed["as_of"]) < _parse_iso(prev_feed["as_of"]):
            return {"progresses": False, "rolled_back": True,
                    "note": "ROLLBACK: the newer feed's as_of precedes the older feed's"}
    except Exception:
        pass
    return {"progresses": True, "rolled_back": False,
            "note": "forward progression (%d new revocation(s))" % len(next_leaves - prev_leaves)}


# ---------------------------------------------------------------------------
# P3.2c: the aggregate mirrored status feed (a federation status bundle).
#
# At federation scale a relying party that wants to check foreign credentials from
# many authorities would fetch each authority's revocation feed and epoch checkpoint
# separately -- N round-trips and N points of availability failure. The status bundle
# is ONE short-lived, CDN-distributable artifact that MIRRORS many authorities' feeds:
# the relying party fetches it once and verifies any member's credential OFFLINE.
#
# The publisher (the aggregator) is UNTRUSTED for correctness. The bundle carries each
# member authority's OWN signed revocation feed and epoch checkpoint VERBATIM, so trust
# in a credential's status still roots in the member authority's ML-DSA signature, never
# the aggregator's. The aggregator's own signature is only a freshness + set-integrity
# envelope: it bounds how old the aggregation is, and commits to exactly the member set.
# What an aggregator CANNOT do is forge a member's status (it cannot re-sign as the
# member) or silently omit a member (the verifier fail-closes on an absent issuer). So
# the bundle adds AVAILABILITY, not trust: verify_cross_authority_via_bundle returns the
# same decision the issuer's own feed would, and the aggregator cannot change it.
# ---------------------------------------------------------------------------
_STATUS_BUNDLE_FORMAT = "polaris-federation-status-bundle/1"


def _status_bundle_canonical(bundle):
    """Canonical bytes the publisher signs. MUST match app.py _status_bundle_statement.
    The member set is committed by members_root_hex (recomputed and checked separately in
    verify_status_bundle), so the signed statement stays small and fixed-shape rather than
    canonicalizing a deep list of nested signed objects."""
    statement = {k: bundle.get(k) for k in
                 ("format", "publisher", "members_root_hex", "member_count",
                  "issued_at", "expires_at", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def bundle_members_root(members):
    """A deterministic commitment over the member set: SHA3-256 over the sorted,
    newline-joined per-member digests, each the SHA3-256 of the member entry's canonical
    JSON. Order-independent, so anyone assembling the same members computes the same root;
    binds the bundle to the EXACT feeds it mirrors, so adding, dropping, or swapping a
    member changes the root. MUST match app.py's _bundle_members_root."""
    if not isinstance(members, (list, tuple)):
        members = []
    digs = sorted(hashlib.sha3_256(
        json.dumps(m, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        for m in members)
    return hashlib.sha3_256("\n".join(digs).encode("utf-8")).hexdigest()


def verify_status_bundle(bundle, now=None, max_window_seconds=None, publisher_key=None):
    """Verify an aggregate federation STATUS BUNDLE (P3.2c) OFFLINE. This checks only the
    ENVELOPE: the publisher's signature over SHA3-256(canonical) with two witnesses, that
    the committed members_root matches the embedded members (so the set cannot be tampered),
    freshness, and (with publisher_key) that the expected publisher signed it. It does NOT
    establish any member's status -- each member feed is verified in its own right, bound to
    its own authority key, inside verify_cross_authority_via_bundle. A tampered or swapped
    member changes members_root and is rejected here; a forged or stale member feed is
    rejected there. The publisher is untrusted for correctness; this envelope only makes a
    member's ABSENCE current and attributable."""
    if not isinstance(bundle, dict):
        bundle = {}
    v = {"bundle_authentic": False, "fresh": None, "commitment_ok": None,
         "publisher_matches": None, "publisher": bundle.get("publisher"),
         "member_count": bundle.get("member_count"),
         "members": bundle.get("members") or [], "witnesses": [], "note": None}
    if bundle.get("format") != _STATUS_BUNDLE_FORMAT:
        v["note"] = "not a %s" % _STATUS_BUNDLE_FORMAT
        return v
    alg, pk_hex, sig_hex = bundle.get("algorithm"), bundle.get("public_key_hex"), bundle.get("signature_hex")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder bundle -- not authenticatable offline"
        return v
    members = bundle.get("members")
    if not isinstance(members, list):
        members = []
    v["members"] = members  # a coerced list, so a downstream member iteration is total
    v["commitment_ok"] = (bundle_members_root(members) == str(bundle.get("members_root_hex") or "").lower()
                          and len(members) == (bundle.get("member_count") or 0))
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_status_bundle_canonical(bundle)).digest()
    ok, ran, note = _two_witness_verify(digest, sig, pk, alg)
    v["witnesses"] = ran
    if ok is None:
        v["note"] = note
        return v
    if not ok:
        v["note"] = "bundle signature is invalid"
        return v
    if not v["commitment_ok"]:
        v["note"] = "the members_root does not match the embedded members (the set was tampered)"
        return v
    v["bundle_authentic"] = True
    _verify_window(bundle, v, now, max_window_seconds)
    if publisher_key is not None:
        v["publisher_matches"] = (pk_hex.lower() == publisher_key.lower())
    return v


def verify_cross_authority_via_bundle(pack, context_id, trusted_manifests, bundle,
                                      now=None, max_window_seconds=None,
                                      trusted_anchors=None, publisher_key=None):
    """Decide a FOREIGN credential OFFLINE using an aggregate status bundle (P3.2c) as the
    status transport, instead of the issuer's individually-fetched revocation feed. The
    answer equals what the issuer's own feed would give; the aggregator cannot change it.

    Fail-closed at every step:
      - the bundle must be authentic and fresh (a stale bundle proves nothing about now,
        and if publisher_key is pinned it must be the one that signed it);
      - the credential's issuer must be PRESENT in the bundle, else reject -- an aggregator
        that omits an authority cannot thereby make its credentials verifiable;
      - the trust + revocation decision is the SAME verify_cross_authority decision, run
        against the MEMBER's own signed feed, so a forged or tampered member feed rejects
        exactly as it would if fetched directly.
    On the accept path, `epoch_bound` reports whether the member's embedded epoch checkpoint
    is authentic, fresh, and bound to the same issuer key -- the status tied to a committed
    epoch rather than a bare point in time."""
    if not isinstance(pack, dict):
        pack = {}
    if not isinstance(trusted_manifests, (list, tuple)):
        trusted_manifests = []
    bv = verify_status_bundle(bundle, now=now, max_window_seconds=max_window_seconds,
                              publisher_key=publisher_key)
    base = {"via": None, "revocation_checked": False, "revoked": None, "in_bundle": None,
            "epoch_bound": None, "bundle_ok": bool(bv["bundle_authentic"] and bv["fresh"])}
    if not (bv["bundle_authentic"] and bv["fresh"]):
        return {**base, "decision": "reject", "authentic": None,
                "reasons": ["the status bundle is not authentic or not fresh"]}
    if publisher_key is not None and not bv["publisher_matches"]:
        return {**base, "decision": "reject", "authentic": None,
                "reasons": ["the status bundle is not signed by the pinned publisher key"]}
    token_key = str(pack.get("public_key_hex") or "").lower()
    member = None
    for m in bv["members"]:
        if not isinstance(m, dict):
            continue  # a hostile bundle can commit to a non-dict member entry
        feed = m.get("revocation_feed")
        if not isinstance(feed, dict):
            continue
        if str(feed.get("public_key_hex") or "").lower() == token_key:
            member = m
            break
    if member is None:
        return {**base, "decision": "reject", "authentic": None, "in_bundle": False,
                "reasons": ["the credential's issuer is not present in the status bundle "
                            "(fail-closed: an omitted authority is not verifiable)"]}
    decision = verify_cross_authority(pack, context_id, trusted_manifests, now=now,
                                      max_window_seconds=max_window_seconds,
                                      trusted_anchors=trusted_anchors,
                                      revocation_feed=member.get("revocation_feed"))
    decision["in_bundle"] = True
    decision["bundle_ok"] = True
    cp = member.get("epoch_checkpoint")
    if cp is not None:
        cv = verify_epoch_checkpoint(cp, now=now, max_window_seconds=max_window_seconds,
                                     issuer_key=token_key)
        decision["epoch_bound"] = bool(cv["checkpoint_authentic"] and cv["fresh"] and cv["issuer_matches"])
    else:
        decision["epoch_bound"] = None
    return decision


# ---------------------------------------------------------------------------
# P3.2d: offline cross-authority epoch-bound zero-knowledge presentation.
#
# A holder proves, in ZERO KNOWLEDGE, that its credential is included in an issuing
# authority's epoch tree -- without revealing WHICH credential. The Plonky2 circuit
# already binds the proof to the epoch's Merkle ROOT (a public input, alongside the
# epoch number, a context, and a nonce), and that root is exactly TokenStateEpoch's
# committed root, which an authority also publishes SIGNED in its epoch checkpoint.
#
# This composes the two OFFLINE: a relying party that trusts authority B accepts a
# holder's proof against a FOREIGN authority A's epoch iff (1) A's signed checkpoint is
# authentic, fresh, and attested by B in the presented context -- so the epoch ROOT it
# commits to is trusted, non-transitively; (2) the proof's public inputs BIND to that
# trusted root, epoch number, and context; and (3) the Plonky2 proof verifies.
#
# Steps 1-2 are pure Python here. Step 3 is the one thing this standalone verifier
# cannot do in pure Python -- checking a Plonky2 FRI proof -- so it shells to the
# polaris-zk binary as a LOCAL subprocess: no network, still offline. If the binary is
# absent the decision ABSTAINS (trust and binding established, proof unverifiable here),
# never a false accept. The verdict reveals nothing about the credential.
# ---------------------------------------------------------------------------
_ZK_BINARY_ENV = "POLARIS_ZK_BINARY"


def _zk_binary_path():
    """Locate the standalone polaris-zk verifier binary. POLARIS_ZK_BINARY wins; otherwise
    the default build location beside this repo. Stdlib only."""
    import os
    explicit = os.environ.get(_ZK_BINARY_ENV)
    if explicit:
        return explicit
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "polaris_zk", "target", "release", "polaris-zk")


def _zk_verify_proof(proof_bundle, zk_binary=None):
    """Check a Plonky2 ZK proof by invoking the polaris-zk verifier binary as a LOCAL
    subprocess (no network -- offline). Returns True/False, or None to ABSTAIN when the binary
    is unavailable, so a relying party without it establishes trust but never false-accepts.
    Uses only the standard library; imports no Polaris code."""
    import os
    import subprocess
    binary = zk_binary or _zk_binary_path()
    if not (isinstance(binary, str) and os.path.isfile(binary)):
        return None
    try:
        proc = subprocess.run([binary, "verify"],
                              input=json.dumps(proof_bundle).encode("utf-8"),
                              capture_output=True, timeout=60)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return False
    try:
        return bool(json.loads(proc.stdout.decode("utf-8", errors="replace")).get("verified"))
    except (ValueError, AttributeError):
        return False


def verify_zk_against_root(proof_bundle, expected_root_hex, expected_epoch_id,
                           expected_context_id, expected_nonce=None, zk_binary=None):
    """The ZK half of the cross-authority decision, factored so it is testable WITHOUT ML-DSA:
    a holder's proof is accepted against a TRUSTED epoch root iff its public inputs bind to that
    root, epoch number, and context (and a nonce, if the verifier issued a challenge), AND the
    Plonky2 proof verifies. Returns {bound, proof_verified, note}; proof_verified is None
    (abstain) when the polaris-zk binary is absent. Total on hostile input."""
    v = {"bound": False, "proof_verified": None, "note": None}
    pi = proof_bundle.get("public_inputs") if isinstance(proof_bundle, dict) else None
    if not isinstance(pi, dict):
        v["note"] = "proof bundle has no public inputs"
        return v
    if str(pi.get("epoch_root_hex") or "").lower() != str(expected_root_hex or "").lower():
        v["note"] = "proof is not bound to the trusted epoch root"
        return v
    try:
        if int(pi.get("epoch_id", -1)) != int(expected_epoch_id):
            v["note"] = "proof epoch number does not match the checkpoint"
            return v
        if int(pi.get("context_id", -1)) != int(expected_context_id):
            v["note"] = "proof context does not match the presented context"
            return v
        if expected_nonce is not None and int(pi.get("nonce", -1)) != int(expected_nonce):
            v["note"] = "proof nonce does not match the verifier challenge"
            return v
    except (TypeError, ValueError):
        v["note"] = "proof public inputs are malformed"
        return v
    v["bound"] = True
    v["proof_verified"] = _zk_verify_proof(proof_bundle, zk_binary=zk_binary)
    if v["proof_verified"] is None:
        v["note"] = ("public inputs bind to the trusted epoch, but the ZK proof cannot be checked "
                     "here (no polaris-zk binary)")
    elif not v["proof_verified"]:
        v["note"] = "the ZK proof failed cryptographic verification"
    return v


def verify_cross_authority_zk(proof_bundle, epoch_checkpoint, context_id, trusted_manifests,
                              now=None, max_window_seconds=None, trusted_anchors=None,
                              expected_nonce=None, zk_binary=None):
    """Decide a HOLDER's zero-knowledge inclusion proof against a FOREIGN authority's epoch,
    OFFLINE (P3.2d). Accept iff: (1) the foreign epoch checkpoint is authentic and fresh, and
    signed by an authority a trusted manifest attests IN the presented context -- so the epoch
    ROOT it commits to is trusted, non-transitively; (2) the proof's public inputs bind to that
    trusted root, epoch number, and context (and a nonce, if a challenge was issued); and (3)
    the Plonky2 proof verifies via the local polaris-zk binary. Steps 1-2 pure Python; step 3
    shells to the binary (no network -- still offline). If the binary is absent the decision is
    ABSTAIN, never a false accept. The verdict carries no credential: the proof is
    zero-knowledge and nothing about which credential it is leaks."""
    cv = verify_epoch_checkpoint(epoch_checkpoint, now=now, max_window_seconds=max_window_seconds)
    base = {"decision": "reject",
            "checkpoint_authentic": bool(cv["checkpoint_authentic"] and cv["fresh"]),
            "issuer_trusted": None, "bound": None, "proof_verified": None, "via": None, "reasons": []}
    if not (cv["checkpoint_authentic"] and cv["fresh"]):
        return {**base, "reasons": ["the foreign epoch checkpoint is not authentic or not fresh"]}
    cp_key = str((epoch_checkpoint or {}).get("public_key_hex") or "").lower() if isinstance(epoch_checkpoint, dict) else ""
    if not isinstance(trusted_manifests, (list, tuple)):
        trusted_manifests = []
    via = None
    for manifest in trusted_manifests:
        mv = verify_manifest(manifest, now=now, max_window_seconds=max_window_seconds,
                             trusted_anchors=trusted_anchors)
        if not (mv["manifest_authentic"] and mv["fresh"]):
            continue
        if trusted_anchors is not None and not mv["issuer_trusted"]:
            continue
        for att in mv["attestations"]:
            if not isinstance(att, dict):
                continue
            if (str(att.get("attested_public_key_hex") or "").lower() == cp_key
                    and (context_id is None or att.get("context_id") == context_id)):
                via = mv["authority"]
                break
        if via:
            break
    base["issuer_trusted"] = bool(via)
    if not via:
        return {**base, "reasons": ["no trusted authority attests to the checkpoint's issuer in this context"]}
    epoch = (epoch_checkpoint.get("epoch") if isinstance(epoch_checkpoint, dict) else None) or {}
    zk = verify_zk_against_root(proof_bundle, epoch.get("root_hex"), epoch.get("number"),
                                context_id, expected_nonce=expected_nonce, zk_binary=zk_binary)
    result = {**base, "via": via, "bound": zk["bound"], "proof_verified": zk["proof_verified"]}
    if not zk["bound"]:
        return {**result, "decision": "reject",
                "reasons": ["the ZK proof is not bound to the trusted epoch (%s)" % zk["note"]]}
    if zk["proof_verified"] is None:
        return {**result, "decision": "abstain",
                "reasons": ["trust established and the proof binds to the trusted epoch, but the ZK "
                            "proof cannot be checked here (no polaris-zk binary); fetch it or verify online"]}
    if not zk["proof_verified"]:
        return {**result, "decision": "reject", "reasons": ["the ZK proof failed cryptographic verification"]}
    return {**result, "decision": "accept", "reasons": []}


# ---------------------------------------------------------------------------
# P8.2: the exchange receipt -- evidence of an authorized exchange, without the payload.
#
# The gateway's core primitive, and the anti-surveillance inversion of evidentiary message
# logging. When one institution serves an authenticated, authorized request from another, the
# responder signs a RECEIPT that commits to the SHA3-256 of the request and of the response --
# never the bodies -- alongside who requested, who responded, in what context, and which
# authority's attestation authorized the requester. A third party can later prove, from the
# receipt alone, that the RESPONDER attests an authorized exchange occurred (the requester-signed
# envelope beside it proves the requester's side), WITHOUT ever seeing the personal
# data that passed. A party that holds the bodies can additionally confirm the commitment binds
# to them (request_hash == SHA3-256(request)); a party that does not still gets the proof of
# occurrence and authorization. Evidence without retention.
# ---------------------------------------------------------------------------
_EXCHANGE_RECEIPT_FORMAT = "polaris-exchange-receipt/1"


def _exchange_receipt_canonical(receipt):
    """Canonical bytes the responder signs. MUST match app.py's _exchange_receipt_statement."""
    statement = {k: receipt.get(k) for k in
                 ("format", "requester", "responder", "context_id", "request_hash",
                  "response_hash", "authorized_via", "occurred_at", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


_EXCHANGE_MINT_FORMAT = "polaris-exchange-mint/1"


def _exchange_mint_canonical(m):
    """The bytes a RESPONDER's service signs to mint a receipt with no operator session
    (P8.2b). A client builds exactly these bytes; the instance rebuilds them and verifies
    the signature under the responder agency's registered key. MUST match
    polaris_web/app.py's _exchange_mint_statement (pinned by the canonical oracle)."""
    if not isinstance(m, dict):
        m = {}
    statement = {k: m.get(k) for k in
                 ("format", "requester_public_key_hex", "context_id", "request_hash",
                  "response_hash", "responder_agency_id", "occurred_at")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


_TIMESTAMP_FORMAT = "polaris-timestamp/1"


def _timestamp_canonical(t):
    """The bytes a timestamp authority signs (P8.7a). MUST match polaris_web/app.py's
    _timestamp_statement (pinned by the canonical oracle)."""
    if not isinstance(t, dict):
        t = {}
    statement = {k: t.get(k) for k in
                 ("format", "authority", "digest_hex", "digest_algorithm", "nonce",
                  "issued_at", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_timestamp(ts, now=None, anchor_keys=None):
    """Verify a polaris-timestamp/1 OFFLINE (P8.7a): the authority's ML-DSA-65 signature over
    SHA3-256(canonical) binding a digest to an instant. A timestamp records a past event and
    carries no freshness window; `now` is accepted for interface symmetry and unused. With
    anchor_keys it also reports whether the signing key is a trusted authority. No network."""
    if not isinstance(ts, dict):
        ts = {}
    v = {"timestamp_authentic": False, "issuer_trusted": None, "digest_hex": ts.get("digest_hex"),
         "digest_algorithm": ts.get("digest_algorithm"), "nonce": ts.get("nonce"),
         "issued_at": ts.get("issued_at"), "witnesses": [], "note": None}
    alg, pk_hex, sig_hex = ts.get("algorithm"), ts.get("public_key_hex"), ts.get("signature_hex")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder timestamp -- not authenticatable offline"
        return v
    if ts.get("format") != _TIMESTAMP_FORMAT:
        v["note"] = "not a %s" % _TIMESTAMP_FORMAT
        return v
    try:
        sig, pk = bytes.fromhex(str(sig_hex)), bytes.fromhex(str(pk_hex))
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_timestamp_canonical(ts)).digest()
    if not _accepted_alg(alg):
        v["note"] = "unknown or unaccepted signature algorithm: %r" % alg
        return v
    primary = _verify_liboqs(digest, sig, pk, alg)
    witness = _verify_cryptography(digest, sig, pk, alg)
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
        v["note"] = "the two witnesses DISAGREE -- treat as invalid"
        return v
    ok = primary if primary is not None else witness
    if not ok:
        v["note"] = "timestamp signature is invalid"
        return v
    try:
        _parse_iso(ts.get("issued_at"))
    except Exception:
        v["note"] = "issued_at is not a valid instant"
        return v
    v["timestamp_authentic"] = True
    if anchor_keys is not None:
        try:
            v["issuer_trusted"] = str(pk_hex).lower() in {str(k).lower() for k in anchor_keys}
        except TypeError:
            v["issuer_trusted"] = False
    return v


def timestamp_binds(ts, data):
    """True iff SHA3-256(data) equals the timestamp's digest, i.e. the timestamp binds THIS
    data (an exchange receipt's canonical bytes, a document, anything); False if not; None
    if the input is not a timestamp or names another digest algorithm. Offline, no key."""
    if not isinstance(ts, dict) or not isinstance(data, (bytes, bytearray)):
        return None
    if str(ts.get("digest_algorithm") or "SHA3-256").upper() != "SHA3-256":
        return None
    return hashlib.sha3_256(bytes(data)).hexdigest() == str(ts.get("digest_hex") or "").lower()


_RECEIPT_LOG_ID = "polaris-exchange-receipt-log"
_TIMESTAMP_LOG_ID = "polaris-timestamp-log"   # P8.5b (v9.341)


def receipt_hash(receipt):
    """A receipt's entry in the receipt transparency log: the SHA3-256 hex of its canonical
    statement (the same bytes its signature covers)."""
    return hashlib.sha3_256(_exchange_receipt_canonical(receipt)).hexdigest()


def timestamp_hash(ts):
    """A timestamp's entry in the timestamp transparency log (P8.5b): the SHA3-256 hex of its
    canonical statement (the same bytes its signature covers)."""
    return hashlib.sha3_256(_timestamp_canonical(ts if isinstance(ts, dict) else {})).hexdigest()


def verify_timestamp_anchor(ts, log_key=None, trusted_witnesses=None, threshold=1):
    """Verify OFFLINE (P8.5b) that a timestamp is ANCHORED: its unsigned `anchor` carries an
    RFC-6962 inclusion proof and a Signed Tree Head of the timestamp log, the proof is for this
    timestamp's hash, the head is an authentic head of that log (with log_key: signed by the
    expected authority), and the proof reconstructs the head. With trusted_witnesses the head
    must also be cosigned by `threshold` distinct trusted witnesses (`anchor.cosignatures`):
    a stolen authority key can sign a fresh head over a fabricated log, but it cannot make a
    witness have cosigned that head at the claimed time. Total on hostile input."""
    v = {"anchored": False, "sth_authentic": False, "log_matches": None, "witnessed": None,
         "cosigner_count": 0, "timestamp_hash": None, "index": None, "tree_size": None, "note": None}
    if not isinstance(ts, dict):
        v["note"] = "timestamp must be an object"
        return v
    anchor = ts.get("anchor")
    if not isinstance(anchor, dict):
        v["note"] = "the timestamp carries no anchor (unanchored: the authority kept no record of it)"
        return v
    proof, sth = anchor.get("proof"), anchor.get("sth")
    if not isinstance(proof, dict) or not isinstance(sth, dict):
        v["note"] = "anchor.proof and anchor.sth must be objects"
        return v
    h = timestamp_hash(ts)
    v["timestamp_hash"] = h
    if str(proof.get("entry_hex") or "").lower() != h:
        v["note"] = "the proof is not for this timestamp"
        return v
    sv = verify_sth(sth, issuer_key=log_key)
    v["sth_authentic"] = bool(sv.get("sth_authentic"))
    if log_key is not None:
        v["log_matches"] = sv.get("issuer_matches")
    if sth.get("log_id") != _TIMESTAMP_LOG_ID or proof.get("log_id") not in (None, _TIMESTAMP_LOG_ID):
        v["note"] = "the head is not a %s head" % _TIMESTAMP_LOG_ID
        return v
    try:
        idx, size = int(proof.get("index")), int(proof.get("tree_size"))
        root = bytes.fromhex(str(sth.get("root_hash_hex")))
        path = [bytes.fromhex(str(p)) for p in (proof.get("proof_hex") or [])]
    except (TypeError, ValueError):
        v["note"] = "malformed proof"
        return v
    v["index"], v["tree_size"] = idx, size
    if size != sth.get("tree_size") or \
            str(proof.get("root_hash_hex") or "").lower() != str(sth.get("root_hash_hex") or "").lower():
        v["note"] = "the proof and the head describe different trees"
        return v
    if not v["sth_authentic"]:
        v["note"] = sv.get("note") or "the head is not authentic"
        return v
    if log_key is not None and not v["log_matches"]:
        v["note"] = "the head is not signed by the expected log key"
        return v
    try:
        ok = verify_inclusion(idx, size, _lh(h), root, path)
    except Exception:  # noqa: BLE001 -- a hostile proof shape is a refusal, never a crash
        ok = False
    v["anchored"] = bool(ok)
    if not ok:
        v["note"] = "the inclusion proof does not reconstruct the head"
        return v
    if trusted_witnesses is not None:
        wv = verify_witnessed_checkpoint(sth, anchor.get("cosignatures") or [], trusted_witnesses,
                                         threshold=threshold, issuer_key=log_key)
        v["witnessed"], v["cosigner_count"] = bool(wv.get("witnessed")), int(wv.get("cosigner_count") or 0)
        if not v["witnessed"]:
            v["note"] = wv.get("note")
    return v


def verify_receipt_inclusion(receipt, proof, sth, log_key=None):
    """Verify OFFLINE (P8.2c) that a receipt is in an append-only receipt log: the receipt's
    hash is the proof's entry; the RFC-6962 inclusion proof reconstructs the head; the head
    is an authentic Signed Tree Head of the RECEIPT log (with log_key: signed by the expected
    log); and proof and head describe the same tree. No network."""
    v = {"included": False, "sth_authentic": False, "log_matches": None, "receipt_hash": None,
         "index": None, "tree_size": None, "note": None}
    if not isinstance(receipt, dict) or not isinstance(proof, dict) or not isinstance(sth, dict):
        v["note"] = "receipt, proof and sth must be objects"
        return v
    h = receipt_hash(receipt)
    v["receipt_hash"] = h
    if str(proof.get("entry_hex") or "").lower() != h:
        v["note"] = "the proof is not for this receipt"
        return v
    sv = verify_sth(sth, issuer_key=log_key)
    v["sth_authentic"] = bool(sv.get("sth_authentic"))
    if log_key is not None:
        v["log_matches"] = sv.get("issuer_matches")
    if sth.get("log_id") != _RECEIPT_LOG_ID:
        v["note"] = "the head is not a %s head" % _RECEIPT_LOG_ID
        return v
    try:
        idx, size = int(proof.get("index")), int(proof.get("tree_size"))
        root = bytes.fromhex(str(sth.get("root_hash_hex")))
        path = [bytes.fromhex(str(p)) for p in (proof.get("proof_hex") or [])]
    except (TypeError, ValueError):
        v["note"] = "malformed proof"
        return v
    v["index"], v["tree_size"] = idx, size
    if size != sth.get("tree_size") or \
            str(proof.get("root_hash_hex") or "").lower() != str(sth.get("root_hash_hex") or "").lower():
        v["note"] = "the proof and the head describe different trees"
        return v
    if not v["sth_authentic"]:
        v["note"] = sv.get("note") or "the head is not authentic"
        return v
    if log_key is not None and not v["log_matches"]:
        v["note"] = "the head is not signed by the expected log key"
        return v
    ok = verify_inclusion(idx, size, _lh(h), root, path)
    v["included"] = bool(ok)
    if not ok:
        v["note"] = "the inclusion proof does not reconstruct the head"
    return v


_REGISTRY_FORMAT = "polaris-registry/1"


def _registry_canonical(r):
    """The bytes a publishing authority signs for its registry (P8.3). MUST match
    polaris_web/app.py's _registry_statement (pinned by the canonical oracle)."""
    if not isinstance(r, dict):
        r = {}
    statement = {k: r.get(k) for k in
                 ("format", "publisher", "instance", "authorities", "contexts", "trust",
                  "relying_parties", "issued_at", "expires_at", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _registry_publisher_key(reg):
    """The registered key the registry itself lists for its publisher, or None."""
    pub = reg.get("publisher") if isinstance(reg.get("publisher"), dict) else {}
    for a in (reg.get("authorities") if isinstance(reg.get("authorities"), list) else []):
        if isinstance(a, dict) and a.get("agency_id") == pub.get("agency_id") \
                and (a.get("status") or "active") == "active" and a.get("public_key_hex"):
            return str(a["public_key_hex"]).lower()
    return None


def verify_registry(reg, now=None, max_window_seconds=None, trusted_anchors=None):
    """Verify a signed registry (P8.3) OFFLINE: the publisher's ML-DSA-65 signature over
    SHA3-256(canonical); self-consistency (the signing key is the key the registry itself
    lists for its publisher, so a stranger cannot publish a registry in an authority's name);
    freshness; and, with trusted_anchors, whether the publisher is one the consumer trusts.
    No network. Discovery then reads the verified registry: registry_service,
    registry_authority, registry_trusts."""
    if not isinstance(reg, dict):
        reg = {}
    v = {"registry_authentic": False, "fresh": None, "issuer_trusted": None,
         "publisher": reg.get("publisher"),
         "services": reg.get("instance", {}).get("services") if isinstance(reg.get("instance"), dict) else None,
         "witnesses": [], "note": None}
    alg, pk_hex, sig_hex = reg.get("algorithm"), reg.get("public_key_hex"), reg.get("signature_hex")
    if reg.get("format") != _REGISTRY_FORMAT:
        v["note"] = "not a %s" % _REGISTRY_FORMAT
        return v
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder registry -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(str(sig_hex)), bytes.fromhex(str(pk_hex))
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    listed = _registry_publisher_key(reg)
    if listed is None or listed != str(pk_hex).lower():
        v["note"] = "the registry is not signed by the key it lists for its own publisher"
        return v
    digest = hashlib.sha3_256(_registry_canonical(reg)).digest()
    if not _accepted_alg(alg):
        v["note"] = "unknown or unaccepted signature algorithm: %r" % alg
        return v
    primary = _verify_liboqs(digest, sig, pk, alg)
    witness = _verify_cryptography(digest, sig, pk, alg)
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
        v["note"] = "the two witnesses DISAGREE -- treat as invalid"
        return v
    ok = primary if primary is not None else witness
    v["registry_authentic"] = bool(ok)
    if not ok:
        v["note"] = "registry signature is invalid"
        return v
    try:
        now = _instant(now)
        ia, ea = _parse_iso(reg["issued_at"]), _parse_iso(reg["expires_at"])
        fresh = ia <= now < ea
        if max_window_seconds is not None and (ea - ia).total_seconds() > max_window_seconds:
            fresh = False
        v["fresh"] = fresh
    except Exception:
        v["fresh"] = False
        v["note"] = "issued_at/expires_at or the caller's `now` are not valid instants"
    if trusted_anchors is not None:
        try:
            v["issuer_trusted"] = str(pk_hex).lower() in {str(k).lower() for k in trusted_anchors}
        except TypeError:
            v["issuer_trusted"] = False
    return v


def registry_service(reg, kind):
    """The service entry of the given kind from a (verified) registry, or None."""
    inst = reg.get("instance") if isinstance(reg, dict) and isinstance(reg.get("instance"), dict) else {}
    for s in (inst.get("services") if isinstance(inst.get("services"), list) else []):
        if isinstance(s, dict) and s.get("kind") == kind:
            return s
    return None


def _hexstr(v):
    """A hex string compared case-insensitively; anything else compares to nothing."""
    return v.lower() if isinstance(v, str) else ""


def registry_speaks(reg, format_string):
    """P8.8b negotiation, consumer side: whether a registry advertises `format_string` as
    `name/MAJOR`. A consumer MUST NOT send an instance a format it does not advertise, MUST
    reject an artifact at a major it does not implement, and never needs a minor: minors only
    add what a verifier may ignore (wire spec section 6). Total over hostile input."""
    name, _, major = str(format_string or "").partition("/")
    inst = reg.get("instance") if isinstance(reg, dict) else None
    proto = inst.get("protocol") if isinstance(inst, dict) else None
    formats = proto.get("formats") if isinstance(proto, dict) else None
    return bool(name) and isinstance(formats, dict) and str(formats.get(name)) == major


def registry_key_status(reg, public_key_hex):
    """The status the registry lists for `public_key_hex` ('active', 'retired', 'compromised'),
    wherever the key appears (an authority's `keys` register, else its configured key), or
    None when the registry does not list the key at all."""
    key = _hexstr(public_key_hex)
    for a in (reg.get("authorities") if isinstance(reg, dict) and isinstance(reg.get("authorities"), list) else []):
        if not isinstance(a, dict):
            continue
        for k in (a.get("keys") if isinstance(a.get("keys"), list) else []):
            if isinstance(k, dict) and _hexstr(k.get("public_key_hex")) == key:
                return k.get("status") or "active"
        if _hexstr(a.get("public_key_hex")) == key:
            return a.get("status") or "active"
    return None


def registry_authority(reg, public_key_hex):
    """The authority entry whose active key is `public_key_hex` (its configured key, or any
    key its `keys` register lists as active), or None."""
    want = str(public_key_hex or "").lower()
    for a in (reg.get("authorities") if isinstance(reg, dict) and isinstance(reg.get("authorities"), list) else []):
        if isinstance(a, dict) and str(a.get("public_key_hex") or "").lower() == want \
                and (a.get("status") or "active") == "active":
            return a
        for k in (a.get("keys") if isinstance(a, dict) and isinstance(a.get("keys"), list) else []):
            if isinstance(k, dict) and _hexstr(k.get("public_key_hex")) == _hexstr(public_key_hex) \
                    and (k.get("status") or "active") == "active":
                return a
    return None


def registry_trusts(reg, attested_public_key_hex, context_id):
    """The attesting agency ids that, per the registry's trust graph, attest the given key IN
    the given context (non-transitive, in-context, like every Polaris trust decision)."""
    want = str(attested_public_key_hex or "").lower()
    out = []
    for t in (reg.get("trust") if isinstance(reg, dict) and isinstance(reg.get("trust"), list) else []):
        if isinstance(t, dict) and str(t.get("attested_public_key_hex") or "").lower() == want \
                and t.get("context_id") == context_id:
            out.append(t.get("attesting_agency_id"))
    return sorted(x for x in out if x is not None)


_EXCHANGE_REQUEST_FORMAT = "polaris-exchange-request/1"


def _exchange_request_canonical(e):
    """The bytes a REQUESTER signs for an exchange envelope (P8.2d): the SHA3-256 of its
    request body (canonical JSON), the target, the context, a nonce and the time. A client
    builds exactly these bytes; the gateway rebuilds them and verifies under the requester's
    registered key. MUST match polaris_web/app.py's _exchange_request_statement."""
    if not isinstance(e, dict):
        e = {}
    statement = {k: e.get(k) for k in
                 ("format", "requester", "target", "context_id", "request_hash", "nonce",
                  "issued_at", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_body_hash(obj):
    """SHA3-256 hex of a JSON body in canonical form (sorted keys, compact) -- what an exchange
    envelope's request_hash and a receipt's response_hash bind."""
    return hashlib.sha3_256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def verify_exchange_request(envelope, requester_key=None, trusted_manifests=None, body=None):
    """Verify a requester's signed exchange envelope OFFLINE (P8.2d): the ML-DSA-65 signature
    over SHA3-256(canonical) under the key the envelope names (with requester_key: that it is
    the expected requester); with trusted_manifests, that the requester is attested in the
    envelope's context by an authority the verifier trusts (the section 4 rule); with body,
    that request_hash binds it. A third party holding the envelope and the matching receipt
    (exchange_evidence) proves both sides of an exchange with no access to either body."""
    if not isinstance(envelope, dict):
        envelope = {}
    req = envelope.get("requester") if isinstance(envelope.get("requester"), dict) else {}
    claimed = str(req.get("public_key_hex") or "").lower()
    pk_hex = str(envelope.get("public_key_hex") or "").lower()
    v = {"request_authentic": False, "requester_matches": None, "requester_authorized": None,
         "body_bound": None, "requester": envelope.get("requester"), "target": envelope.get("target"),
         "context_id": envelope.get("context_id"), "request_hash": envelope.get("request_hash"),
         "nonce": envelope.get("nonce"), "issued_at": envelope.get("issued_at"), "witnesses": [], "note": None}
    if envelope.get("format") != _EXCHANGE_REQUEST_FORMAT:
        v["note"] = "not a %s" % _EXCHANGE_REQUEST_FORMAT
        return v
    alg = envelope.get("algorithm")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder envelope -- not authenticatable offline"
        return v
    # The signature envelope's key is the verification key (as for every artifact); it MUST be
    # the key the signed statement claims for the requester, or the envelope lies about itself.
    if pk_hex != claimed:
        v["note"] = "the envelope's public_key_hex does not match the signed requester key"
        return v
    try:
        sig, pk = bytes.fromhex(str(envelope.get("signature_hex"))), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_exchange_request_canonical(envelope)).digest()
    if not _accepted_alg(alg):
        v["note"] = "unknown or unaccepted signature algorithm: %r" % alg
        return v
    primary = _verify_liboqs(digest, sig, pk, alg)
    witness = _verify_cryptography(digest, sig, pk, alg)
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
        v["note"] = "the two witnesses DISAGREE -- treat as invalid"
        return v
    ok = primary if primary is not None else witness
    v["request_authentic"] = bool(ok)
    if not ok:
        v["note"] = "envelope signature is invalid"
        return v
    if requester_key is not None:
        v["requester_matches"] = (pk_hex == str(requester_key).lower())
    if trusted_manifests is not None:
        ctx = envelope.get("context_id")
        authorized = False
        for m in (trusted_manifests if isinstance(trusted_manifests, (list, tuple)) else []):
            mv = verify_manifest(m)
            if not (mv.get("manifest_authentic") and mv.get("fresh")):
                continue
            for att in mv.get("attestations") or []:
                if isinstance(att, dict) and str(att.get("attested_public_key_hex") or "").lower() == pk_hex \
                        and att.get("context_id") == ctx:
                    authorized = True
        v["requester_authorized"] = authorized
    if body is not None:
        v["body_bound"] = (canonical_body_hash(body) == str(envelope.get("request_hash") or "").lower())
    return v


def _alg_for_key_length(pk_hex):
    """The accepted parameter set a public key's length identifies, for an artifact whose
    `algorithm` is not a signed field (the mint statement); None when no accepted set fits."""
    try:
        n = len(bytes.fromhex(pk_hex or ""))
    except (ValueError, TypeError):
        return None
    for name, (_cls, pk_len, _sig_len) in _ACCEPTED.items():
        if n == pk_len:
            return name
    return None


def verify_exchange_mint(mint, responder_key=None):
    """Verify a responder-signed MINT statement OFFLINE (P8.2b): the responder service's
    ML-DSA signature over SHA3-256(canonical) with two witnesses, and (with responder_key)
    that the expected responder agency's registered key signed it. `algorithm` is not a
    signed field of this artifact; the declared value is used when present, else the
    parameter set the key's length identifies. An audit holding the statement a service sent
    to mint a receipt can confirm who asked for it. Total over hostile input."""
    if not isinstance(mint, dict):
        mint = {}
    v = {"mint_authentic": False, "responder_matches": None,
         "responder_agency_id": mint.get("responder_agency_id"), "context_id": mint.get("context_id"),
         "requester_public_key_hex": mint.get("requester_public_key_hex"), "occurred_at": mint.get("occurred_at"),
         "witnesses": [], "note": None}
    if mint.get("format") != _EXCHANGE_MINT_FORMAT:
        v["note"] = "not a %s" % _EXCHANGE_MINT_FORMAT
        return v
    pk_hex, sig_hex = mint.get("public_key_hex"), mint.get("signature_hex")
    alg = mint.get("algorithm") if mint.get("algorithm") is not None else _alg_for_key_length(pk_hex)
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder mint -- not authenticatable offline"
        return v
    if not _accepted_alg(alg):
        v["note"] = "unknown or unaccepted signature algorithm: %r" % alg
        return v
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_exchange_mint_canonical(mint)).digest()
    ok, ran, note = _two_witness_verify(digest, sig, pk, alg)
    v["witnesses"] = ran
    if ok is not True:
        v["note"] = note or "signature INVALID"
        return v
    v["mint_authentic"] = True
    if responder_key is not None:
        v["responder_matches"] = _hexstr(pk_hex) == _hexstr(responder_key)
    return v


def exchange_evidence(envelope, receipt):
    """The evidentiary chain of one exchange (P8.2d): the requester-signed envelope and the
    responder-signed receipt agree on the requester key, the context, the request hash and the
    instant. Neither carries a body. True/False; None on malformed input."""
    if not isinstance(envelope, dict) or not isinstance(receipt, dict):
        return None
    req_e = envelope.get("requester") if isinstance(envelope.get("requester"), dict) else {}
    req_r = receipt.get("requester") if isinstance(receipt.get("requester"), dict) else {}
    return (str(req_e.get("public_key_hex") or "").lower() == str(req_r.get("public_key_hex") or "").lower()
            and envelope.get("context_id") == receipt.get("context_id")
            and str(envelope.get("request_hash") or "").lower() == str(receipt.get("request_hash") or "").lower()
            and envelope.get("issued_at") == receipt.get("occurred_at"))


_SIGNED_DOCUMENT_FORMAT = "polaris-signed-document/1"


def _signed_document_canonical(d):
    """The bytes a signer signs for a document container (P8.5). MUST match
    polaris_web/app.py's _signed_document_statement (pinned by the canonical oracle)."""
    if not isinstance(d, dict):
        d = {}
    statement = {k: d.get(k) for k in
                 ("format", "document", "signer", "on_behalf_of", "purpose", "signed_at",
                  "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def document_signature_material(doc):
    """What a long-term-validation timestamp over a signed document binds: the canonical
    statement AND the signature, so the timestamp proves the SIGNATURE existed at its instant.
    MUST match polaris_web/app.py's _document_signature_material."""
    if not isinstance(doc, dict):
        return b""
    return _signed_document_canonical(doc) + b"\n" + str(doc.get("signature_hex") or "").lower().encode("utf-8")


def is_revoked_leaf(feed, leaf_hex):
    """True iff the given leaf (SHA3-256(token_value) hex -- the same value a signed document
    records as credential_hash) is listed in the feed. Membership only; verify the feed first."""
    if not isinstance(feed, dict):
        return False
    leaves = feed.get("revoked_leaves")
    if not isinstance(leaves, (list, tuple, set)):
        return False
    return str(leaf_hex or "").lower() in {str(x).lower() for x in leaves}


def attach_ltv(doc, timestamp=None, manifest=None, epoch_checkpoint=None, revocation_feed=None, timestamps=None):
    """Attach long-term-validation evidence to a signed document (outside the signed
    statement): a timestamp over document_signature_material(doc) -- from a second authority
    if you want time independent of the signer -- and the signer's manifest, epoch checkpoint
    and revocation feed at that instant. Returns a new container."""
    out = dict(doc) if isinstance(doc, dict) else {}
    ltv = dict(out.get("ltv") or {}) if isinstance(out.get("ltv"), dict) else {}
    if timestamps:   # P8.5b: further timestamps (a quorum of independent authorities) beside ltv.timestamp
        ltv["timestamps"] = list(ltv.get("timestamps") or []) + [t for t in timestamps if isinstance(t, dict)]
    for k, val in (("timestamp", timestamp), ("manifest", manifest),
                   ("epoch_checkpoint", epoch_checkpoint), ("revocation_feed", revocation_feed)):
        if val is not None:
            ltv[k] = val
    out["ltv"] = ltv
    return out


def verify_signed_document(doc, now=None, trusted_anchors=None, document_bytes=None, trust_list=None, timestamp_anchors=None,
                           require_anchored=False, trusted_witnesses=None, witness_threshold=1, timestamp_quorum=1):
    """Verify a signed document OFFLINE (P8.5): the signer's ML-DSA-65 signature over
    SHA3-256(canonical) (two witnesses); with trusted_anchors, signer trust; with
    document_bytes, that the container binds them. Then LONG-TERM VALIDATION from the embedded
    evidence: the timestamp is authentic and binds the statement AND signature (so the
    signature existed at the timestamp's instant); the signer's manifest was authentic and
    fresh AT THAT INSTANT and listed the signing key as active; and, for a holder-authorized
    signature, the signer's revocation feed at that instant did not list the credential.
    P8.5b (v9.341): `timestamp_quorum` demands that many DISTINCT trusted, independent authorities
    among ltv.timestamp and ltv.timestamps; `require_anchored` demands an anchored timestamp
    (inclusion evidence in the authority's append-only timestamp log), cosigned by
    `witness_threshold` of `trusted_witnesses` when those are given; with a trust list the
    timestamp authority's key must have been active at the instant, like the signer's.
    `timestamp_anchors` (v9.334) names the timestamp authorities the verifier trusts, distinct
    from the signer anchors: valid_long_term requires the timestamp trusted AND independent of
    the signing key, so neither a stranger's timestamp nor a signer's own (backdatable) one counts.
    valid_long_term is the conjunction: it holds even after the key is rotated or retired,
    because it is decided at the instant the evidence fixes, not now. No network."""
    if not isinstance(doc, dict):
        doc = {}
    d = doc.get("document") if isinstance(doc.get("document"), dict) else {}
    v = {"document_authentic": False, "signer_trusted": None, "binds": None,
         "signer": doc.get("signer"), "on_behalf_of": doc.get("on_behalf_of"),
         "digest_hex": d.get("digest_hex"), "signed_at": doc.get("signed_at"),
         "ltv": {"present": False, "timestamp_authentic": None, "timestamp_binds": None, "instant": None,
                 "timestamp_authority_trusted": None, "timestamp_independent": None,
                 "timestamps": [], "independent_timestamps": 0, "timestamp_anchored": None, "timestamp_witnessed": None,
                 "timestamp_authority_key_status_per_trust_list": None,
                 "signer_key_active_at_instant": None, "credential_unrevoked_at_instant": None,
                 "signer_key_status_per_trust_list": None},
         "valid_long_term": False, "witnesses": [], "note": None}
    alg, pk_hex, sig_hex = doc.get("algorithm"), doc.get("public_key_hex"), doc.get("signature_hex")
    if doc.get("format") != _SIGNED_DOCUMENT_FORMAT:
        v["note"] = "not a %s" % _SIGNED_DOCUMENT_FORMAT
        return v
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder signature -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(str(sig_hex)), bytes.fromhex(str(pk_hex))
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_signed_document_canonical(doc)).digest()
    if not _accepted_alg(alg):
        v["note"] = "unknown or unaccepted signature algorithm: %r" % alg
        return v
    primary = _verify_liboqs(digest, sig, pk, alg)
    witness = _verify_cryptography(digest, sig, pk, alg)
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
        v["note"] = "the two witnesses DISAGREE -- treat as invalid"
        return v
    ok = primary if primary is not None else witness
    v["document_authentic"] = bool(ok)
    if not ok:
        v["note"] = "document signature is invalid"
        return v
    signer_key = str(pk_hex).lower()
    if trusted_anchors is not None:
        try:
            v["signer_trusted"] = signer_key in {str(k).lower() for k in trusted_anchors}
        except TypeError:
            v["signer_trusted"] = False
    if document_bytes is not None:
        v["binds"] = (isinstance(document_bytes, (bytes, bytearray))
                      and hashlib.sha3_256(bytes(document_bytes)).hexdigest() == str(d.get("digest_hex") or "").lower())
    ltv = doc.get("ltv") if isinstance(doc.get("ltv"), dict) else None
    if not ltv:
        v["note"] = "no long-term-validation evidence attached"
        return v
    L = v["ltv"]
    L["present"] = True
    ts = ltv.get("timestamp")
    # v9.334: a cryptographically authentic timestamp is not yet TRUSTED time evidence. Anyone
    # can mint an ML-DSA key and sign a timestamp, and a signer's own key (or a thief holding
    # it) can backdate one; so long-term validity requires the timestamp authority to be one
    # the verifier trusts (timestamp_anchors, distinct from the signer anchors) AND distinct
    # from the signing key. Without anchors the verdict reports the facts and claims nothing.
    tv = verify_timestamp(ts, anchor_keys=timestamp_anchors)
    L["timestamp_authentic"] = bool(tv.get("timestamp_authentic"))
    L["timestamp_binds"] = bool(timestamp_binds(ts, document_signature_material(doc)))
    L["timestamp_authority_trusted"] = tv.get("issuer_trusted")
    ts_key = str((ts.get("public_key_hex") if isinstance(ts, dict) else "") or "").lower()
    L["timestamp_independent"] = bool(ts_key) and ts_key != signer_key
    L["instant"] = tv.get("issued_at")
    try:
        instant = _parse_iso(tv.get("issued_at"))
    except Exception:
        instant = None
    manifest = ltv.get("manifest")
    if instant is not None and isinstance(manifest, dict):
        mv = verify_manifest(manifest, now=instant)
        active = any(isinstance(a, dict) and str(a.get("public_key_hex") or "").lower() == signer_key
                     and (a.get("status") or "active") == "active" for a in mv.get("anchors") or [])
        L["signer_key_active_at_instant"] = bool(mv.get("manifest_authentic") and mv.get("fresh")
                                                 and str(manifest.get("public_key_hex") or "").lower() == signer_key and active)
    else:
        L["signer_key_active_at_instant"] = False
    obo = doc.get("on_behalf_of") if isinstance(doc.get("on_behalf_of"), dict) else None
    if obo and obo.get("credential_hash"):
        feed = ltv.get("revocation_feed")
        if instant is not None and isinstance(feed, dict):
            fv = verify_revocation_feed(feed, now=instant, issuer_key=signer_key)
            L["credential_unrevoked_at_instant"] = bool(fv.get("feed_authentic") and fv.get("fresh")
                                                        and fv.get("issuer_matches") is not False
                                                        and not is_revoked_leaf(feed, obo["credential_hash"]))
        else:
            L["credential_unrevoked_at_instant"] = False
    # P8.7b: with a trust list the verifier trusts, the signer key's status AT THE INSTANT is
    # decided independently of the signer's own manifest (which a compromised key could forge).
    L["signer_key_status_per_trust_list"] = None
    if trust_list is not None:
        tlv = verify_trust_list(trust_list, now=now, trusted_anchors=trusted_anchors)
        L["signer_key_status_per_trust_list"] = (key_status_at(trust_list, signer_key, instant)
                                                 if (tlv["trust_list_authentic"] and tlv["fresh"] and instant is not None) else None)
    # P8.5b (v9.341): every timestamp the container carries (ltv.timestamp, then ltv.timestamps)
    # is judged the same way; those that are authentic, bound, trusted and independent of the
    # signer count toward a QUORUM of distinct authorities. An anchored timestamp (inclusion
    # evidence in the timestamp log, witnessed when the verifier names witnesses) is what
    # survives the authority's key being stolen later. With a trust list, the authority's key
    # must have been ACTIVE at the instant, exactly as the signer's must.
    material = document_signature_material(doc)
    quorum_keys, tl_ok = set(), None
    if trust_list is not None:
        _tlv = verify_trust_list(trust_list, now=now, trusted_anchors=trusted_anchors)
        tl_ok = bool(_tlv["trust_list_authentic"] and _tlv["fresh"])
    for t in [ts] + [x for x in (ltv.get("timestamps") or []) if isinstance(x, dict)]:
        if not isinstance(t, dict):
            continue
        tv_i = verify_timestamp(t, anchor_keys=timestamp_anchors)
        t_key = str(t.get("public_key_hex") or "").lower()
        entry = {"authority": t.get("authority"), "authentic": bool(tv_i.get("timestamp_authentic")),
                 "binds": bool(timestamp_binds(t, material)), "trusted": tv_i.get("issuer_trusted"),
                 "independent": bool(t_key) and t_key != signer_key, "anchored": None, "witnessed": None,
                 "key_status_per_trust_list": None}
        if tl_ok and instant is not None and t_key:
            entry["key_status_per_trust_list"] = key_status_at(trust_list, t_key, instant)
        if isinstance(t.get("anchor"), dict):
            av = verify_timestamp_anchor(t, log_key=t_key or None, trusted_witnesses=trusted_witnesses, threshold=witness_threshold)
            entry["anchored"] = bool(av.get("anchored"))
            entry["witnessed"] = av.get("witnessed")
        qualifies = (entry["authentic"] and entry["binds"] and entry["trusted"] is True and entry["independent"]
                     and (trust_list is None or entry["key_status_per_trust_list"] == "active"))
        entry["qualifies"] = qualifies
        if qualifies:
            quorum_keys.add(t_key)
            if entry["anchored"]:
                L["timestamp_anchored"] = True
                if trusted_witnesses is not None and entry["witnessed"]:
                    L["timestamp_witnessed"] = True
        L["timestamps"].append(entry)
    L["independent_timestamps"] = len(quorum_keys)
    if L["timestamp_anchored"] is None:
        L["timestamp_anchored"] = False
    if trusted_witnesses is not None and L["timestamp_witnessed"] is None:
        L["timestamp_witnessed"] = False
    if L["timestamps"]:
        L["timestamp_authority_key_status_per_trust_list"] = L["timestamps"][0]["key_status_per_trust_list"]
    quorum = max(1, int(timestamp_quorum or 1))
    anchored_ok = (not require_anchored) or (L["timestamp_anchored"] and (trusted_witnesses is None or L["timestamp_witnessed"]))
    v["valid_long_term"] = bool(v["document_authentic"] and L["timestamp_authentic"] and L["timestamp_binds"]
                                and L["timestamp_authority_trusted"] is True and L["timestamp_independent"]
                                and (trust_list is None or L["timestamp_authority_key_status_per_trust_list"] == "active")
                                and L["independent_timestamps"] >= quorum and anchored_ok
                                and L["signer_key_active_at_instant"]
                                and L["credential_unrevoked_at_instant"] is not False
                                and (trust_list is None or L["signer_key_status_per_trust_list"] == "active"))
    if not v["valid_long_term"]:
        v["note"] = "long-term validation failed: " + ", ".join(
            k for k in ("timestamp_authentic", "timestamp_binds", "timestamp_independent", "signer_key_active_at_instant") if not L[k]
        ) + (", no trusted timestamp-authority anchors given" if L["timestamp_authority_trusted"] is None
             else (", timestamp authority not trusted" if L["timestamp_authority_trusted"] is False else "")
        ) + (", timestamp authority key not active at the instant per the trust list"
             if (trust_list is not None and L["timestamp_authority_key_status_per_trust_list"] != "active") else ""
        ) + (", timestamp quorum not met (%d of %d independent authorities)" % (L["independent_timestamps"], quorum)
             if L["independent_timestamps"] < quorum else ""
        ) + (", no anchored timestamp under an anchored policy" if (require_anchored and not L["timestamp_anchored"])
             else (", the anchor's head is not witnessed by a trusted witness"
                   if (require_anchored and trusted_witnesses is not None and not L["timestamp_witnessed"]) else "")
        ) + (", credential revoked at the instant" if L["credential_unrevoked_at_instant"] is False else "")
    return v


_ID_TOKEN_FORMAT = "polaris-id-token/1"


def _id_token_canonical(t):
    """The bytes an issuing agency signs for an ID token (P8.4). MUST match polaris_web/app.py's
    _id_token_statement (pinned by the canonical oracle)."""
    if not isinstance(t, dict):
        t = {}
    statement = {k: t.get(k) for k in
                 ("format", "iss", "sub", "aud", "nonce", "context_id", "disclosure_level", "acr",
                  "enrollment", "auth_time", "iat", "exp", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_id_token(tok, audience=None, nonce=None, now=None, trusted_anchors=None):
    """Verify a polaris-id-token/1 OFFLINE (P8.4) as a relying party: the issuing agency's
    ML-DSA-65 signature (two witnesses); that it was issued to THIS audience and carries the
    nonce this login started with; freshness (iat <= now < exp); and, with trusted_anchors,
    that the issuer is one the relying party trusts. The subject is a credential hash, never
    a token or a person. No network."""
    if not isinstance(tok, dict):
        tok = {}
    v = {"token_authentic": False, "audience_matches": None, "nonce_matches": None, "fresh": None,
         "issuer_trusted": None, "sub": tok.get("sub"), "acr": tok.get("acr"), "enrollment": tok.get("enrollment"),
         "context_id": tok.get("context_id"), "disclosure_level": tok.get("disclosure_level"),
         "witnesses": [], "note": None}
    alg, pk_hex, sig_hex = tok.get("algorithm"), tok.get("public_key_hex"), tok.get("signature_hex")
    if tok.get("format") != _ID_TOKEN_FORMAT:
        v["note"] = "not a %s" % _ID_TOKEN_FORMAT
        return v
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder token -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(str(sig_hex)), bytes.fromhex(str(pk_hex))
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_id_token_canonical(tok)).digest()
    if not _accepted_alg(alg):
        v["note"] = "unknown or unaccepted signature algorithm: %r" % alg
        return v
    primary = _verify_liboqs(digest, sig, pk, alg)
    witness = _verify_cryptography(digest, sig, pk, alg)
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
        v["note"] = "the two witnesses DISAGREE -- treat as invalid"
        return v
    ok = primary if primary is not None else witness
    v["token_authentic"] = bool(ok)
    if not ok:
        v["note"] = "token signature is invalid"
        return v
    if audience is not None:
        v["audience_matches"] = (tok.get("aud") == audience)
    if nonce is not None:
        v["nonce_matches"] = (tok.get("nonce") == nonce)
    try:
        now = _instant(now)
        v["fresh"] = _parse_iso(tok["iat"]) <= now < _parse_iso(tok["exp"])
    except Exception:
        v["fresh"] = False
        v["note"] = "iat/exp or the caller's `now` are not valid instants"
    if trusted_anchors is not None:
        try:
            v["issuer_trusted"] = str(pk_hex).lower() in {str(k).lower() for k in trusted_anchors}
        except TypeError:
            v["issuer_trusted"] = False
    return v


_TRUST_LIST_FORMAT = "polaris-trust-list/1"


def _trust_list_canonical(t):
    """The bytes a publisher signs for a trust list (P8.7b). MUST match polaris_web/app.py's
    _trust_list_statement (pinned by the canonical oracle)."""
    if not isinstance(t, dict):
        t = {}
    statement = {k: t.get(k) for k in ("format", "publisher", "keys", "issued_at", "expires_at", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _trust_list_publisher_key(tl):
    pub = tl.get("publisher") if isinstance(tl.get("publisher"), dict) else {}
    for k in (tl.get("keys") if isinstance(tl.get("keys"), list) else []):
        if isinstance(k, dict) and k.get("agency_id") == pub.get("agency_id") and k.get("status") == "active" and k.get("public_key_hex"):
            yield str(k["public_key_hex"]).lower()


def verify_trust_list(tl, now=None, max_window_seconds=None, trusted_anchors=None):
    """Verify a signed trust list OFFLINE (P8.7b): the publisher's ML-DSA-65 signature; that it is
    signed by a key the list itself carries as ACTIVE for its publisher (an impostor cannot publish
    a trust list in an authority's name, and a publisher cannot sign one under a key it has
    retired); freshness; and, with trusted_anchors, whether the publisher is trusted."""
    if not isinstance(tl, dict):
        tl = {}
    v = {"trust_list_authentic": False, "fresh": None, "issuer_trusted": None,
         "publisher": tl.get("publisher"), "key_count": len(tl.get("keys")) if isinstance(tl.get("keys"), list) else 0,
         "witnesses": [], "note": None}
    alg, pk_hex, sig_hex = tl.get("algorithm"), tl.get("public_key_hex"), tl.get("signature_hex")
    if tl.get("format") != _TRUST_LIST_FORMAT:
        v["note"] = "not a %s" % _TRUST_LIST_FORMAT
        return v
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder trust list -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(str(sig_hex)), bytes.fromhex(str(pk_hex))
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    if str(pk_hex).lower() not in set(_trust_list_publisher_key(tl)):
        v["note"] = "the trust list is not signed by a key it lists as active for its own publisher"
        return v
    digest = hashlib.sha3_256(_trust_list_canonical(tl)).digest()
    if not _accepted_alg(alg):
        v["note"] = "unknown or unaccepted signature algorithm: %r" % alg
        return v
    primary = _verify_liboqs(digest, sig, pk, alg)
    witness = _verify_cryptography(digest, sig, pk, alg)
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
        v["note"] = "the two witnesses DISAGREE -- treat as invalid"
        return v
    ok = primary if primary is not None else witness
    v["trust_list_authentic"] = bool(ok)
    if not ok:
        v["note"] = "trust list signature is invalid"
        return v
    try:
        now = _instant(now)
        ia, ea = _parse_iso(tl["issued_at"]), _parse_iso(tl["expires_at"])
        fresh = ia <= now < ea
        if max_window_seconds is not None and (ea - ia).total_seconds() > max_window_seconds:
            fresh = False
        v["fresh"] = fresh
    except Exception:
        v["fresh"] = False
        v["note"] = "issued_at/expires_at or the caller's `now` are not valid instants"
    if trusted_anchors is not None:
        try:
            v["issuer_trusted"] = str(pk_hex).lower() in {str(k).lower() for k in trusted_anchors}
        except TypeError:
            v["issuer_trusted"] = False
    return v


def key_status_at(tl, public_key_hex, instant=None):
    """A key's status AT AN INSTANT per a (verified) trust list: 'compromised' from its
    compromised_at (which may predate the discovery), 'retired' from its retired_at, 'active'
    from its registration, None if the list does not carry the key or the instant precedes its
    registration. Decides long-term validity and cross-authority trust independently of the
    signer's own word."""
    from datetime import datetime, timezone
    want = str(public_key_hex or "").lower()
    if not isinstance(tl, dict):
        return None
    if instant is None:
        instant = datetime.now(timezone.utc)
    elif isinstance(instant, str):
        try:
            instant = _parse_iso(instant)
        except Exception:
            return None
    for k in (tl.get("keys") if isinstance(tl.get("keys"), list) else []):
        if not isinstance(k, dict) or str(k.get("public_key_hex") or "").lower() != want:
            continue
        def _at(field):
            val = k.get(field)
            if not val:
                return None
            try:
                return _parse_iso(val if str(val).endswith("Z") or "+" in str(val) else str(val) + "Z")
            except Exception:
                return None
        reg, ret, comp = _at("registered_at"), _at("retired_at"), _at("compromised_at")
        if reg is not None and instant < reg:
            return None
        if k.get("status") == "compromised" and (comp is None or instant >= comp):
            return "compromised"
        if k.get("status") in ("retired", "compromised") and ret is not None and instant >= ret:
            return "retired"
        if k.get("status") == "retired" and ret is None:
            return "retired"
        return "active"
    return None


def verify_exchange_receipt(receipt, now=None, trusted_manifests=None, responder_key=None,
                            request_body=None, response_body=None, max_window_seconds=None):
    """Verify an exchange receipt OFFLINE (P8.2). Establishes, WITHOUT the payload, that an
    exchange occurred and was authorized: the responder's ML-DSA-65 signature over
    SHA3-256(canonical) with two witnesses; (with responder_key) that the expected responder
    signed it; and (with trusted_manifests) that some authority the relying party trusts
    attests the REQUESTER's key in the receipt's context -- the same non-transitive trust as a
    foreign credential. A party that also holds the request and/or response body may pass it to
    confirm the commitment binds (request_hash == SHA3-256(body)); a party that does not still
    obtains the responder's signed attestation of occurrence and authorization; a receipt is signed
    by the responder alone, so the REQUESTER'S participation is proven by the envelope it signed
    (exchange_evidence checks the pair). Returns a verdict dict; reveals nothing
    about the payload."""
    if not isinstance(receipt, dict):
        receipt = {}
    v = {"receipt_authentic": False, "responder_matches": None, "requester_authorized": None,
         "request_bound": None, "response_bound": None, "via": None,
         "requester": receipt.get("requester"), "responder": receipt.get("responder"),
         "context_id": receipt.get("context_id"), "occurred_at": receipt.get("occurred_at"),
         "witnesses": [], "note": None}
    if receipt.get("format") != _EXCHANGE_RECEIPT_FORMAT:
        v["note"] = "not a %s" % _EXCHANGE_RECEIPT_FORMAT
        return v
    alg, pk_hex, sig_hex = receipt.get("algorithm"), receipt.get("public_key_hex"), receipt.get("signature_hex")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder receipt -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_exchange_receipt_canonical(receipt)).digest()
    ok, ran, note = _two_witness_verify(digest, sig, pk, alg)
    v["witnesses"] = ran
    if ok is None:
        v["note"] = note
        return v
    if not ok:
        v["note"] = "receipt signature is invalid"
        return v
    v["receipt_authentic"] = True
    if responder_key is not None:
        v["responder_matches"] = (pk_hex.lower() == responder_key.lower())
    # Payload binding, only for a party that holds the bodies: the commitment must match.
    if request_body is not None:
        h = hashlib.sha3_256(request_body if isinstance(request_body, bytes) else str(request_body).encode("utf-8")).hexdigest()
        v["request_bound"] = (h == str(receipt.get("request_hash") or "").lower())
    if response_body is not None:
        h = hashlib.sha3_256(response_body if isinstance(response_body, bytes) else str(response_body).encode("utf-8")).hexdigest()
        v["response_bound"] = (h == str(receipt.get("response_hash") or "").lower())
    # Authorization: some trusted manifest attests the REQUESTER's key in the receipt's context.
    if trusted_manifests is not None:
        req_key = str((receipt.get("requester") or {}).get("public_key_hex") or "").lower() if isinstance(receipt.get("requester"), dict) else ""
        ctx = receipt.get("context_id")
        via = None
        for manifest in (trusted_manifests if isinstance(trusted_manifests, (list, tuple)) else []):
            mv = verify_manifest(manifest, now=now, max_window_seconds=max_window_seconds)
            if not (mv["manifest_authentic"] and mv["fresh"]):
                continue
            for att in mv["attestations"]:
                if not isinstance(att, dict):
                    continue
                if str(att.get("attested_public_key_hex") or "").lower() == req_key and \
                   (ctx is None or att.get("context_id") == ctx):
                    via = mv["authority"]
                    break
            if via:
                break
        v["requester_authorized"] = bool(via)
        v["via"] = via
    return v


# ---------------------------------------------------------------------------
# P3.3: the transparency log over the audit-anchor roots.
#
# The audit anchor log (AnchorBatch) is append-only at the database. This turns
# its sequence of Merkle roots into a PUBLIC, append-only, independently verifiable
# transparency log in the style of RFC 6962 (Certificate Transparency), using
# SHA3-256 to match the rest of Polaris: a leaf is hashed with a 0x00 prefix, an
# interior node with a 0x01 prefix, so a leaf can never be presented as a node.
#
# The log publishes a SIGNED TREE HEAD (STH: {tree_size, root_hash, timestamp},
# signed by the authority) and, between any two sizes, a CONSISTENCY PROOF: the
# cryptographic evidence that the smaller tree is a prefix of the larger one --
# that the log only ever appended, never rewrote or dropped history. A monitor
# that has cached an old STH verifies each new STH is consistent with it; a fork
# (two different roots at one size) or a rewrite fails the proof. All of this is
# verified here with no Polaris code, no database, and no key but the published one.
# ---------------------------------------------------------------------------
_STH_FORMAT = "polaris-transparency-sth/1"


def _lh(entry):
    """RFC 6962 leaf hash, SHA3-256(0x00 || entry). `entry` is a log entry -- an anchor
    root hex string -- taken as its UTF-8 bytes."""
    return hashlib.sha3_256(b"\x00" + entry.encode("utf-8")).digest()


def _ih(left, right):
    """RFC 6962 interior node hash, SHA3-256(0x01 || left || right), over two digests."""
    return hashlib.sha3_256(b"\x01" + left + right).digest()


def _largest_pow2_below(n):
    k = 1
    while k < n:
        k <<= 1
    return k >> 1


def merkle_tree_head(entries):
    """RFC 6962 Merkle Tree Hash over an ordered list of log entries (anchor root hex
    strings). Returns the tree head digest (bytes)."""
    n = len(entries)
    if n == 0:
        return hashlib.sha3_256(b"").digest()
    if n == 1:
        return _lh(entries[0])
    k = _largest_pow2_below(n)
    return _ih(merkle_tree_head(entries[:k]), merkle_tree_head(entries[k:]))


def consistency_proof(m, entries):
    """RFC 6962 consistency proof that the first `m` entries form a prefix of `entries`.
    Returns a list of digests. (Generator side, for drills and reference.)"""
    def sub(m, ents, b):
        n = len(ents)
        if m == n:
            return [] if b else [merkle_tree_head(ents)]
        k = _largest_pow2_below(n)
        if m <= k:
            return sub(m, ents[:k], b) + [merkle_tree_head(ents[k:])]
        return sub(m - k, ents[k:], False) + [merkle_tree_head(ents[:k])]
    if m <= 0 or m > len(entries):
        return []
    return sub(m, entries, True)


def verify_consistency(m, n, root1, root2, proof):
    """Verify a consistency proof (RFC 6962 §2.1.4): the size-`m` tree with head `root1`
    is a prefix of the size-`n` tree with head `root2`. root1/root2/proof are digests.
    True iff the log only appended between the two heads."""
    if m < 0 or n < m:
        return False
    if m == n:
        return not proof and root1 == root2
    if m == 0:
        return not proof
    if not proof:
        return False
    node, last = m - 1, n - 1
    while node & 1:
        node >>= 1
        last >>= 1
    it = iter(proof)
    if node:
        h1 = h2 = next(it, None)
        if h1 is None:
            return False
    else:
        h1 = h2 = root1
    while node:
        if node & 1:
            s = next(it, None)
            if s is None:
                return False
            h1, h2 = _ih(s, h1), _ih(s, h2)
        elif node < last:
            s = next(it, None)
            if s is None:
                return False
            h2 = _ih(h2, s)
        node >>= 1
        last >>= 1
    while last:
        s = next(it, None)
        if s is None:
            return False
        h2 = _ih(h2, s)
        last >>= 1
    return h1 == root1 and h2 == root2 and next(it, None) is None


def inclusion_proof(idx, entries):
    """RFC 6962 inclusion proof for the entry at `idx`. Returns a list of digests."""
    def sub(i, ents):
        n = len(ents)
        if n <= 1:
            return []
        k = _largest_pow2_below(n)
        if i < k:
            return sub(i, ents[:k]) + [merkle_tree_head(ents[k:])]
        return sub(i - k, ents[k:]) + [merkle_tree_head(ents[:k])]
    if idx < 0 or idx >= len(entries):
        return []
    return sub(idx, entries)


def verify_inclusion(idx, tree_size, leaf, root, proof):
    """Verify (RFC 6962 §2.1.1) that `leaf` (a leaf digest) is the entry at `idx` in a
    tree of `tree_size` with head `root`."""
    if idx < 0 or idx >= tree_size:
        return False
    fn, sn = idx, tree_size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            r = _ih(p, r)
            if not (fn & 1):
                while fn != 0 and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = _ih(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def _sth_canonical(sth):
    """The canonical bytes an authority signs for a Signed Tree Head. MUST match app.py's
    _sth_statement: sorted-keys compact JSON of exactly these fields."""
    statement = {k: sth.get(k) for k in
                 ("format", "log_id", "tree_size", "root_hash_hex", "timestamp")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_sth(sth, issuer_key=None):
    """Verify a Signed Tree Head OFFLINE (P3.3): the signature over SHA3-256(canonical)
    with two witnesses, and (with issuer_key) that it is signed by the expected log key.
    Returns a verdict dict. Append-only consistency between two heads, and timestamp
    monotonicity, are verify_log_consistency and the monitor's concern."""
    if not isinstance(sth, dict):
        sth = {}
    v = {"sth_authentic": False, "tree_size": sth.get("tree_size"),
         "root_hash_hex": sth.get("root_hash_hex"), "issuer_matches": None,
         "witnesses": [], "note": None}
    if sth.get("format") != _STH_FORMAT:
        v["note"] = "not a %s" % _STH_FORMAT
        return v
    alg, pk_hex, sig_hex = sth.get("algorithm"), sth.get("public_key_hex"), sth.get("signature_hex")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder STH -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_sth_canonical(sth)).digest()
    ok, ran, note = _two_witness_verify(digest, sig, pk, alg)
    v["witnesses"] = ran
    if ok is None:
        v["note"] = note
        return v
    v["sth_authentic"] = bool(ok)
    if not ok:
        v["note"] = "STH signature is invalid"
    if issuer_key is not None:
        v["issuer_matches"] = (pk_hex.lower() == issuer_key.lower())
    return v


def verify_log_consistency(old_sth, new_sth, proof, issuer_key=None):
    """Decide whether new_sth is an append-only extension of old_sth (P3.3), using a
    consistency proof. Both STHs must be authentic (and, with issuer_key, from the same
    expected log key); the newer tree must be at least as large; and the proof must show
    the older head is a prefix of the newer. Returns {consistent, fork, note}. fork=True
    means the log rewrote or dropped history -- the tampering a monitor exists to catch."""
    ov = verify_sth(old_sth, issuer_key=issuer_key)
    nv = verify_sth(new_sth, issuer_key=issuer_key)
    if not (ov["sth_authentic"] and nv["sth_authentic"]):
        return {"consistent": False, "fork": False, "note": "an STH is not authentic"}
    if issuer_key is not None and not (ov["issuer_matches"] and nv["issuer_matches"]):
        return {"consistent": False, "fork": False, "note": "an STH is not signed by the expected log key"}
    if (old_sth.get("log_id") != new_sth.get("log_id")):
        return {"consistent": False, "fork": False, "note": "the STHs are from different logs"}
    m, n = old_sth.get("tree_size"), new_sth.get("tree_size")
    if not isinstance(m, int) or not isinstance(n, int) or m < 0 or n < 0:
        return {"consistent": False, "fork": False, "note": "a tree_size is missing or invalid"}
    if n < m:
        return {"consistent": False, "fork": True,
                "note": "the newer STH is SMALLER (tree shrank from %d to %d) -- a rewrite" % (m, n)}
    try:
        root1, root2 = bytes.fromhex(old_sth["root_hash_hex"]), bytes.fromhex(new_sth["root_hash_hex"])
        pf = [bytes.fromhex(h) for h in (proof or [])]
    except (ValueError, TypeError, KeyError):
        return {"consistent": False, "fork": False, "note": "root_hash_hex or proof is not valid hex"}
    if m == n:
        ok = root1 == root2
        return {"consistent": ok, "fork": not ok,
                "note": "same size; heads %s" % ("match" if ok else "DIFFER -- a fork at size %d" % m)}
    if verify_consistency(m, n, root1, root2, pf):
        return {"consistent": True, "fork": False, "note": "append-only from %d to %d" % (m, n)}
    return {"consistent": False, "fork": True,
            "note": "consistency proof FAILED: the size-%d head is not a prefix of the size-%d head "
                    "-- the log rewrote history" % (m, n)}


# ---------------------------------------------------------------------------
# P3.3b: witness cosignatures, and the proof of a split view.
#
# A single monitor catches a log that REWRITES its own history (the old head it cached is
# no longer a prefix of the new one). It cannot, alone, catch a SPLIT VIEW: a log that
# shows one head to one observer and a different head at the same size to another, each
# internally consistent. Two defences, both here and both verified offline:
#
#   - Witness cosignatures. An independent witness cosigns a head with its OWN key only
#     when that head is consistent with the last head it cosigned. A relying party requires
#     a head to carry cosignatures from at least K distinct trusted witnesses, so a split
#     view needs K witnesses to equivocate, not just the log.
#   - The equivocation proof. Two Signed Tree Heads for one log, both validly signed by the
#     log key, at the same size with different roots, ARE a non-repudiable proof the log
#     signed two histories. It is what two gossiping observers produce the moment they
#     compare the heads they were shown.
# ---------------------------------------------------------------------------
_COSIGNATURE_FORMAT = "polaris-transparency-cosignature/1"


def _cosignature_canonical(cosig):
    """The canonical bytes a witness signs to cosign a log head. MUST match the witness's
    signer: sorted-keys compact JSON of exactly these fields."""
    statement = {k: cosig.get(k) for k in ("format", "log_id", "tree_size", "root_hash_hex")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_cosignature(cosig, witness_key=None):
    """Verify a witness cosignature over a log head (P3.3b): the signature over
    SHA3-256(canonical) with two witnesses, and (with witness_key) that it is from the
    expected witness. Returns a verdict dict."""
    v = {"cosignature_authentic": False, "log_id": cosig.get("log_id"),
         "tree_size": cosig.get("tree_size"), "root_hash_hex": cosig.get("root_hash_hex"),
         "witness": cosig.get("public_key_hex"), "witness_matches": None, "witnesses": [], "note": None}
    if cosig.get("format") != _COSIGNATURE_FORMAT:
        v["note"] = "not a %s" % _COSIGNATURE_FORMAT
        return v
    alg, pk_hex, sig_hex = cosig.get("algorithm"), cosig.get("public_key_hex"), cosig.get("signature_hex")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder cosignature -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_cosignature_canonical(cosig)).digest()
    ok, ran, note = _two_witness_verify(digest, sig, pk, alg)
    v["witnesses"] = ran
    if ok is None:
        v["note"] = note
        return v
    v["cosignature_authentic"] = bool(ok)
    if not ok:
        v["note"] = "cosignature signature is invalid"
    if witness_key is not None:
        v["witness_matches"] = (pk_hex.lower() == witness_key.lower())
    return v


def verify_witnessed_checkpoint(sth, cosignatures, trusted_witnesses, threshold=1, issuer_key=None):
    """Decide whether a log head carries enough independent witnessing to resist a split
    view (P3.3b): the STH is log-authentic AND at least `threshold` DISTINCT trusted
    witnesses have cosigned this exact head (same log_id, tree_size, root_hash). Returns
    {witnessed, cosigner_count, note}."""
    sv = verify_sth(sth, issuer_key=issuer_key)
    if not sv["sth_authentic"]:
        return {"witnessed": False, "cosigner_count": 0, "note": "the STH is not log-authentic"}
    if issuer_key is not None and sv["issuer_matches"] is False:
        return {"witnessed": False, "cosigner_count": 0, "note": "the STH is not signed by the expected log key"}
    trusted = {t.lower() for t in (trusted_witnesses or [])}
    seen = set()
    for c in (cosignatures or []):
        cv = verify_cosignature(c)
        if not cv["cosignature_authentic"]:
            continue
        if (c.get("log_id") == sth.get("log_id") and c.get("tree_size") == sth.get("tree_size")
                and (c.get("root_hash_hex") or "").lower() == (sth.get("root_hash_hex") or "").lower()):
            w = (c.get("public_key_hex") or "").lower()
            if w in trusted:
                seen.add(w)
    n = len(seen)
    ok = n >= threshold
    return {"witnessed": ok, "cosigner_count": n,
            "note": ("%d distinct trusted witness cosignature(s) over this head (threshold %d)" % (n, threshold))
                    if ok else ("only %d trusted witness cosignature(s), need %d" % (n, threshold))}


def verify_equivocation(sth_a, sth_b, log_key):
    """Given two Signed Tree Heads for one log, decide whether they are a PROVEN
    equivocation -- non-repudiable evidence the log signed two conflicting histories
    (P3.3b). Proven iff both are validly signed by `log_key`, carry the same log_id, and
    conflict: the same tree_size with a DIFFERENT root_hash. This is the split view a lone
    monitor cannot catch and two gossiping observers can. Returns {proven, note}."""
    a = verify_sth(sth_a, issuer_key=log_key)
    b = verify_sth(sth_b, issuer_key=log_key)
    if not (a["sth_authentic"] and a["issuer_matches"] and b["sth_authentic"] and b["issuer_matches"]):
        return {"proven": False, "note": "both heads must be validly signed by the log key to prove equivocation"}
    if sth_a.get("log_id") != sth_b.get("log_id"):
        return {"proven": False, "note": "the heads are for different logs"}
    if sth_a.get("tree_size") == sth_b.get("tree_size"):
        if (sth_a.get("root_hash_hex") or "").lower() != (sth_b.get("root_hash_hex") or "").lower():
            return {"proven": True,
                    "note": "PROVEN equivocation: the log signed two different roots at tree_size %s"
                            % sth_a.get("tree_size")}
        return {"proven": False, "note": "the two heads are identical (no equivocation)"}
    return {"proven": False,
            "note": "different sizes; consistency between them is decided by verify_log_consistency, "
                    "and equivocation there is a smaller head shown NOT to be a prefix of the larger"}


# ---------------------------------------------------------------------------
# P3.3c: external-ledger publication.
#
# Witnesses attest the heads they were shown; an external LEDGER is the complete, ordered,
# public record. The log publishes each head into an independent append-only ledger -- a
# ledger IS an append-only log, so this reuses the machinery above: publishing a head is
# appending its entry to the ledger, and the receipt is the ledger's own signed head plus
# an inclusion proof. A relying party that requires a publication receipt knows the head is
# recorded in a place the log does not control and cannot later erase, and the full set of
# published heads is publicly enumerable. Where the ledger lives -- a file bulletin, a
# public chain -- is a driver choice; this verifies the receipt whatever the backend.
# ---------------------------------------------------------------------------
_PUBLICATION_FORMAT = "polaris-transparency-publication/1"


def _publication_entry(log_id, tree_size, root_hash_hex):
    """The stable string a ledger records to publish a log head. It binds the head's full
    identity so a receipt cannot be transplanted onto a different head."""
    return "polaris-published-head/1|%s|%s|%s" % (log_id, tree_size, (root_hash_hex or "").lower())


def verify_publication(log_sth, receipt, ledger_key):
    """Verify that a log head was published to an independent append-only ledger (P3.3c).
    The receipt carries the LEDGER's own signed tree head and an inclusion proof; this
    confirms the head's entry is a leaf in the ledger and the ledger head is signed by the
    trusted ledger key. So the log cannot use a head it has not publicly committed, and the
    ledger (being append-only) cannot later drop it. Returns {published, ledger_size, note}."""
    v = {"published": False, "ledger_size": None, "note": None}
    if receipt.get("format") != _PUBLICATION_FORMAT:
        v["note"] = "not a %s" % _PUBLICATION_FORMAT
        return v
    if (receipt.get("log_id") != log_sth.get("log_id")
            or receipt.get("tree_size") != log_sth.get("tree_size")
            or (receipt.get("root_hash_hex") or "").lower() != (log_sth.get("root_hash_hex") or "").lower()):
        v["note"] = "the receipt does not bind to this log head"
        return v
    ledger_sth = receipt.get("ledger_sth") or {}
    lv = verify_sth(ledger_sth, issuer_key=ledger_key)
    if not lv["sth_authentic"]:
        v["note"] = "the ledger's signed head is not authentic (%s)" % lv["note"]
        return v
    if ledger_key is not None and lv["issuer_matches"] is False:
        v["note"] = "the ledger head is not signed by the trusted ledger key"
        return v
    v["ledger_size"] = ledger_sth.get("tree_size")
    entry = _publication_entry(log_sth.get("log_id"), log_sth.get("tree_size"), log_sth.get("root_hash_hex"))
    try:
        idx = int(receipt["leaf_index"])
        root = bytes.fromhex(ledger_sth["root_hash_hex"])
        proof = [bytes.fromhex(h) for h in (receipt.get("inclusion_proof_hex") or [])]
    except (ValueError, TypeError, KeyError):
        v["note"] = "the receipt's leaf_index, proof, or ledger root is malformed"
        return v
    if verify_inclusion(idx, ledger_sth.get("tree_size"), _lh(entry), root, proof):
        v["published"] = True
        v["note"] = ("the head is recorded at index %d in ledger %r (ledger size %s)"
                     % (idx, ledger_sth.get("log_id"), ledger_sth.get("tree_size")))
    else:
        v["note"] = "the inclusion proof does not place this head in the ledger"
    return v


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


# --- P8.6: the wallet protocol surface -- offline presentation and QR/NFC framing ------------
#
# A presentation is the UNSIGNED wrapper a holder hands a verifier: the issuer-signed
# credential (the authenticity pack), optionally a stapled issuer-signed status assertion
# (P3.6) so authorization is decidable OFFLINE, optionally a ZK membership proof, the context
# and disclosure level, and an opaque presentation code. Its authenticity lives in the signed
# objects inside it, never in the wrapper. For QR/NFC transfer the wrapper is compressed,
# base64url-encoded and split into digest-tied frames (polaris-qr/1); a receiver rejects mixed,
# missing or altered frames before it ever parses the payload.
_PRESENTATION_FORMAT = "polaris-presentation/1"
_QR_FORMAT = "polaris-qr/1"
_QR_PREFIX = "PLRS1"
QR_FRAME_BYTES = 1800   # a QR version-40 byte-mode frame holds 2953; 1800 leaves margin for any encoder


def presentation_payload(presentation):
    """The canonical bytes of a presentation for transfer (sorted keys, compact)."""
    return json.dumps(presentation if isinstance(presentation, dict) else {}, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


# v9.335: a decoder that is total on hostile input is also resource-bounded. The largest
# legitimate presentation (an ML-DSA-87 pack, a stapled assertion, a proof bundle) is well
# under 100 KiB; a compressible payload can expand a thousandfold, so the decompressor runs
# with an output limit and every bound is checked before the work it guards.
_QR_MAX_FRAMES = 9999                     # the format's four-digit index
_QR_MAX_COMPRESSED = 512 * 1024           # bytes of compressed payload (base64 adds a third)
_QR_MAX_DECOMPRESSED = 2 * 1024 * 1024    # bytes after inflation


def encode_presentation_frames(presentation, frame_bytes=QR_FRAME_BYTES):
    """Split a presentation into polaris-qr/1 frames: PLRS1/<total>/<index>/<sha3-256 of the
    payload>/<chunk>, where the payload is base64url(zlib(canonical JSON)). Every frame names
    the payload digest, so a receiver ties frames of one transfer together and detects any
    altered chunk after reassembly. No frame exceeds frame_bytes."""
    import base64
    import zlib
    payload = base64.urlsafe_b64encode(zlib.compress(presentation_payload(presentation), 9)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha3_256(payload.encode("ascii")).hexdigest()
    head = len("%s/%d/%d/%s/" % (_QR_PREFIX, 9999, 9999, digest))
    chunk = max(16, int(frame_bytes) - head)
    chunks = [payload[i:i + chunk] for i in range(0, len(payload), chunk)] or [""]
    return ["%s/%d/%d/%s/%s" % (_QR_PREFIX, len(chunks), i, digest, c) for i, c in enumerate(chunks)]


def decode_presentation_frames(frames):
    """Reassemble polaris-qr/1 frames (any order, duplicates tolerated) into a presentation.
    Returns (presentation, None) or (None, reason). Total: hostile input yields a reason,
    never a crash; mixed transfers, a missing frame, and an altered chunk are all refused."""
    import base64
    import zlib
    if not isinstance(frames, (list, tuple)):
        return None, "frames must be a list of strings"
    if len(frames) > 2 * _QR_MAX_FRAMES:
        return None, "too many frames (the format carries at most %d)" % _QR_MAX_FRAMES
    parts, total, digest, size = {}, None, None, 0
    for f in frames:
        if not isinstance(f, str):
            return None, "a frame is not a string"
        size += len(f)
        if size > _QR_MAX_COMPRESSED * 4 // 3 + 128 * _QR_MAX_FRAMES:
            return None, "payload exceeds the compressed-size bound (%d bytes)" % _QR_MAX_COMPRESSED
        bits = f.strip().split("/", 4)
        if len(bits) != 5 or bits[0] != _QR_PREFIX:
            return None, "not a %s frame" % _QR_FORMAT
        try:
            t, i = int(bits[1]), int(bits[2])
        except ValueError:
            return None, "malformed frame header"
        if total is None:
            total, digest = t, bits[3]
        if t != total or bits[3] != digest:
            return None, "frames from different transfers were mixed"
        if not (0 < total <= _QR_MAX_FRAMES and 0 <= i < total):
            return None, "frame index out of range"
        if i in parts and parts[i] != bits[4]:
            return None, "conflicting duplicate frame"
        parts[i] = bits[4]
    if total is None:
        return None, "no frames"
    missing = [i for i in range(total) if i not in parts]
    if missing:
        return None, "missing frame(s) %s" % missing
    payload = "".join(parts[i] for i in range(total))
    if len(payload) > _QR_MAX_COMPRESSED * 4 // 3 + 4:
        return None, "payload exceeds the compressed-size bound (%d bytes)" % _QR_MAX_COMPRESSED
    if hashlib.sha3_256(payload.encode("ascii")).hexdigest() != digest:
        return None, "payload digest mismatch (a frame was altered)"
    try:
        data = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        if len(data) > _QR_MAX_COMPRESSED:
            return None, "payload exceeds the compressed-size bound (%d bytes)" % _QR_MAX_COMPRESSED
        d = zlib.decompressobj()
        raw = d.decompress(data, _QR_MAX_DECOMPRESSED)
        if d.unconsumed_tail or not d.eof:
            return None, "payload exceeds the decompressed-size bound (%d bytes): refused before inflating further" % _QR_MAX_DECOMPRESSED
        obj = json.loads(raw.decode("utf-8"))
    except Exception as e:  # noqa: BLE001 -- any decoding failure (incl. recursion depth) is a clean refusal
        return None, "undecodable payload: %s" % type(e).__name__
    if not isinstance(obj, dict) or obj.get("format") != _PRESENTATION_FORMAT:
        return None, "not a %s" % _PRESENTATION_FORMAT
    return obj, None


_EPOCH_LEAVES_FORMAT = "polaris-epoch-leaves/1"        # P9.2 (v9.350)


def _epoch_leaves_canonical(b):
    """The bytes an authority signs for a published anonymity set (P9.2). MUST match app.py's
    _epoch_leaves_statement; the canonical oracle pins the pair."""
    if not isinstance(b, dict):
        b = {}
    statement = {k: b.get(k) for k in
                 ("format", "authority", "epoch_id", "context_id", "merkle_root",
                  "leaf_count", "leaves_root_hex", "issued_at", "expires_at", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _leaves_root(leaves):
    """The commitment over a leaf set: SHA3-256 of the sorted, newline-joined hexes. The same
    construction the revocation feed uses, so it is checkable with SHA3-256 alone."""
    uniq = sorted({str(x).lower() for x in (leaves or [])})
    return hashlib.sha3_256("\n".join(uniq).encode("utf-8")).hexdigest()


def verify_epoch_leaves(bundle, now=None, max_window_seconds=None, anchor_keys=None,
                        epoch_checkpoint=None):
    """Verify OFFLINE that a published anonymity set is authentic and complete (P9.2).

    A holder needs the epoch's leaf set to prove membership on their OWN device: the set is
    the anonymity set, and a set only its issuer holds is not one. This checks the authority's
    signature over the statement, that the leaves riding beside it match the committed
    leaves_root_hex, that the count agrees, freshness, and, with an epoch checkpoint, that the
    bundle describes the same epoch root the authority published there.

    It deliberately does NOT recompute the Poseidon Merkle root: that needs the proving
    library, and a verifier that required it would not be standalone. The commitment is
    SHA3-256 over the set, so the leaves are tamper-evident in any language."""
    v = {"leaves_authentic": False, "fresh": None, "issuer_trusted": None,
         "commitment_matches": None, "count_matches": None, "epoch_matches": None,
         "leaf_count": None, "witnesses": [], "note": None}
    if not isinstance(bundle, dict) or bundle.get("format") != _EPOCH_LEAVES_FORMAT:
        v["note"] = "not a %s" % _EPOCH_LEAVES_FORMAT
        return v
    alg, pk_hex, sig_hex = bundle.get("algorithm"), bundle.get("public_key_hex"), bundle.get("signature_hex")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder bundle -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    ok, ran, note = _two_witness_verify(hashlib.sha3_256(_epoch_leaves_canonical(bundle)).digest(), sig, pk, alg)
    v["witnesses"] = ran
    if ok is None:
        v["note"] = note
        return v
    if not ok:
        v["note"] = "the bundle signature is invalid"
        return v
    # The commitment must match the published set, and a mismatch is a REFUSAL, not a note.
    # A caller who read `leaves_authentic: true` would take all_leaves_hex as the anonymity
    # set, and member_index would place the holder inside a crowd that does not exist: an
    # attacker who swaps every member but one leaves the signature genuine and the holder
    # believing they are hidden. That is anonymity-set poisoning, and it defeats the entire
    # purpose of the bundle. verify_revocation_feed refuses the same shape of tamper for the
    # same reason, and these two must not disagree about what a broken commitment means.
    leaves = bundle.get("all_leaves_hex")
    leaves = leaves if isinstance(leaves, list) else []
    v["leaf_count"] = len(leaves)
    v["commitment_matches"] = (_leaves_root(leaves) == str(bundle.get("leaves_root_hex") or "").lower())
    v["count_matches"] = (len(leaves) == bundle.get("leaf_count"))
    if not v["commitment_matches"]:
        v["note"] = "the published leaves do not match the committed leaves_root_hex"
        return v
    if not v["count_matches"]:
        v["note"] = "the published leaf count does not match the signed one"
        return v
    v["leaves_authentic"] = True
    _verify_window(bundle, v, now, max_window_seconds)
    if anchor_keys is not None:
        v["issuer_trusted"] = str(pk_hex).lower() in {str(a).lower() for a in anchor_keys}
    if isinstance(epoch_checkpoint, dict):
        v["epoch_matches"] = (
            str(bundle.get("merkle_root") or "").lower()
            == str((epoch_checkpoint.get("epoch") or {}).get("root_hex")
                   or epoch_checkpoint.get("merkle_root") or "").lower())
        if v["epoch_matches"] is False:
            v["note"] = "the bundle names a different epoch root than the published checkpoint"
    return v


def member_index(bundle, leaf_seed_hex):
    """Where is this holder's leaf in the published set (P9.2)? Returns an index or None.

    The holder computes their own leaf seed from data only they hold and looks it up HERE, on
    their own device. The issuer is never asked, so it never learns which member is proving."""
    leaves = bundle.get("all_leaves_hex") if isinstance(bundle, dict) else None
    if not isinstance(leaves, list):
        return None
    target = str(leaf_seed_hex or "").lower()
    for i, x in enumerate(leaves):
        if str(x).lower() == target:
            return i
    return None


_HOLDER_BINDING_FORMAT = "polaris-holder-binding/1"    # P9.1 (v9.349)
_HOLDER_PROOF_FORMAT = "polaris-holder-proof/1"


def _holder_binding_canonical(b):
    """The bytes the ISSUER signs for a holder key binding (P9.1). MUST match app.py's
    _holder_binding_statement; the canonical oracle pins the pair."""
    if not isinstance(b, dict):
        b = {}
    statement = {k: b.get(k) for k in
                 ("format", "token_value", "holder_public_key_hex", "holder_algorithm",
                  "bound_at", "status", "issued_at", "expires_at", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _holder_proof_canonical(pr):
    """The bytes the HOLDER signs to prove they hold the bound key (P9.1).

    Deliberately narrow: the credential it is about, the context it is presented in, the
    verifier's nonce (so a captured proof cannot be replayed to another verifier), and the
    instant. It does NOT cover the presented code, so a duress presentation carrying this
    proof is byte-indistinguishable from a consenting one."""
    if not isinstance(pr, dict):
        pr = {}
    statement = {k: pr.get(k) for k in
                 ("format", "token_value", "context_id", "verifier_nonce", "issued_at", "algorithm")}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_holder_binding(binding, credential=None, now=None, max_window_seconds=None, anchor_keys=None):
    """Verify OFFLINE that an ISSUER bound a holder public key to a credential (P9.1): the
    issuer's signature over the canonical statement, freshness, the binding's status, and
    (with `credential`) that it is about THIS credential and signed by the same issuer key.
    Total on hostile input."""
    v = {"binding_authentic": False, "fresh": None, "issuer_trusted": None, "bound_to_credential": None,
         "status": None, "holder_public_key_hex": None, "holder_algorithm": None,
         "witnesses": [], "note": None}
    if not isinstance(binding, dict) or binding.get("format") != _HOLDER_BINDING_FORMAT:
        v["note"] = "not a %s" % _HOLDER_BINDING_FORMAT
        return v
    v["status"] = binding.get("status")
    v["holder_public_key_hex"] = binding.get("holder_public_key_hex")
    v["holder_algorithm"] = binding.get("holder_algorithm")
    alg, pk_hex, sig_hex = binding.get("algorithm"), binding.get("public_key_hex"), binding.get("signature_hex")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder binding -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    ok, ran, note = _two_witness_verify(hashlib.sha3_256(_holder_binding_canonical(binding)).digest(), sig, pk, alg)
    v["witnesses"] = ran
    if ok is None:
        v["note"] = note
        return v
    v["binding_authentic"] = bool(ok)
    if not ok:
        v["note"] = "the binding signature is invalid"
        return v
    _verify_window(binding, v, now, max_window_seconds)
    if anchor_keys is not None:
        v["issuer_trusted"] = str(pk_hex).lower() in {str(a).lower() for a in anchor_keys}
    if isinstance(credential, dict):
        v["bound_to_credential"] = (
            str(binding.get("token_value")) == str(credential.get("token_value"))
            and str(pk_hex).lower() == str(credential.get("public_key_hex") or "").lower())
        if not v["bound_to_credential"]:
            v["note"] = "the binding is not about this credential, or not signed by its issuer key"
    return v


def verify_holder_proof(proof, binding=None, expected_nonce=None, expected_context=None,
                        now=None, max_age_seconds=300):
    """Verify OFFLINE that the party presenting a credential HOLDS the key its issuer bound
    to it (P9.1): the holder's signature over the canonical statement, and, with `binding`,
    that the signing key is the bound one and the binding is active.

    `expected_nonce` is the value the verifier issued for this presentation; a proof that
    does not name it is a replay of one made for somebody else. `max_age_seconds` bounds how
    old a proof may be. Total on hostile input."""
    v = {"proof_authentic": False, "key_matches_binding": None, "nonce_matches": None,
         "context_matches": None, "fresh": None, "witnesses": [], "note": None}
    if not isinstance(proof, dict) or proof.get("format") != _HOLDER_PROOF_FORMAT:
        v["note"] = "not a %s" % _HOLDER_PROOF_FORMAT
        return v
    alg, pk_hex, sig_hex = proof.get("algorithm"), proof.get("public_key_hex"), proof.get("signature_hex")
    if alg == _PLACEHOLDER or not pk_hex:
        v["note"] = "placeholder holder proof -- not authenticatable offline"
        return v
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    ok, ran, note = _two_witness_verify(hashlib.sha3_256(_holder_proof_canonical(proof)).digest(), sig, pk, alg)
    v["witnesses"] = ran
    if ok is None:
        v["note"] = note
        return v
    v["proof_authentic"] = bool(ok)
    if not ok:
        v["note"] = "the holder proof signature is invalid"
        return v
    if expected_nonce is not None:
        v["nonce_matches"] = (str(proof.get("verifier_nonce")) == str(expected_nonce))
    if expected_context is not None:
        v["context_matches"] = (proof.get("context_id") == expected_context)
    from datetime import timedelta
    try:
        ref = _instant(now)
    except ValueError:  # a caller's bad `now` is a refusal, not a crash
        ref = None
    try:
        issued = _parse_iso(proof.get("issued_at"))
    except Exception:  # noqa: BLE001 -- an unparseable instant is a refusal, never a crash
        issued = None
    if issued is not None and ref is not None:
        # A proof may be a minute ahead of the verifier's clock and no older than max_age.
        v["fresh"] = (issued <= ref + timedelta(seconds=60)) and ((ref - issued).total_seconds() <= int(max_age_seconds or 300))
    else:
        v["fresh"] = False
        v["note"] = "unparseable issued_at"
    if isinstance(binding, dict):
        v["key_matches_binding"] = (
            str(pk_hex).lower() == str(binding.get("holder_public_key_hex") or "").lower()
            and (binding.get("status") or "active") == "active")
        if not v["key_matches_binding"]:
            v["note"] = "the proof is not signed by the key the issuer bound, or the binding is revoked"
    return v


def verify_presentation(presentation, anchor_keys=None, now=None, max_window_seconds=None, expected_context=None,
                        expected_nonce=None, require_holder_proof=False):
    """Decide a presentation OFFLINE (P8.6): the credential's authenticity (and, with anchor
    keys, issuer trust); the stapled status assertion's authenticity, freshness, ACTIVE status
    and BINDING to this credential (same token, same issuer key); the context, if the verifier
    expected one. usable_offline is the conjunction. The presentation code is reported present
    or absent and never interpreted: a duress presentation is indistinguishable here by
    design. A ZK proof is reported present; deciding it needs the epoch root and the polaris-zk
    binary (verify_zk_against_root). Total on hostile input."""
    v = {"credential_authentic": False, "issuer_trusted": None, "token_value": None,
         "status": {"present": False, "authentic": None, "fresh": None, "active": None, "bound": None},
         # P9.1: the holder key chain, issuer anchor -> binding -> holder key -> proof.
         "holder": {"present": False, "binding_authentic": None, "bound_to_credential": None,
                    "binding_fresh": None, "proof_authentic": None, "key_matches_binding": None,
                    "nonce_matches": None, "proved": None},
         "zk_present": False, "presented_code_present": False, "context_matches": None,
         "usable_offline": False, "note": None}
    if not isinstance(presentation, dict) or presentation.get("format") != _PRESENTATION_FORMAT:
        v["note"] = "not a %s" % _PRESENTATION_FORMAT
        return v
    cred = presentation.get("credential") if isinstance(presentation.get("credential"), dict) else {}
    pv = verify_pack(cred, anchor_keys=anchor_keys)
    v["credential_authentic"] = bool(pv.get("signature_valid"))
    v["issuer_trusted"] = pv.get("issuer_trusted")
    v["token_value"] = cred.get("token_value")
    v["presented_code_present"] = presentation.get("presented_code") is not None   # opaque; never interpreted
    v["zk_present"] = isinstance(presentation.get("zk_proof"), dict)
    if expected_context is not None:
        v["context_matches"] = (presentation.get("context_id") == expected_context)
    sa = presentation.get("status_assertion")
    S = v["status"]
    if isinstance(sa, dict):
        S["present"] = True
        sv = verify_status_assertion(sa, now=now, max_window_seconds=max_window_seconds, anchor_keys=anchor_keys)
        S["authentic"] = bool(sv.get("status_authentic"))
        S["fresh"] = sv.get("fresh")
        S["active"] = (sv.get("status") == "ACTIVE")
        S["bound"] = (str(sa.get("token_value")) == str(cred.get("token_value"))
                      and str(sa.get("public_key_hex") or "").lower() == str(cred.get("public_key_hex") or "").lower())
    # P9.1: a holder proof, when present, must chain to a binding the issuer signed. When the
    # verifier requires one (require_holder_proof), a presentation without it is not usable:
    # possession of a file stops being sufficient and possession of a KEY is required.
    H = v["holder"]
    binding, proof = presentation.get("holder_binding"), presentation.get("holder_proof")
    if isinstance(binding, dict) or isinstance(proof, dict):
        H["present"] = True
        bv = verify_holder_binding(binding, credential=cred, now=now,
                                   max_window_seconds=max_window_seconds, anchor_keys=anchor_keys)
        H["binding_authentic"] = bv["binding_authentic"]
        H["bound_to_credential"] = bv["bound_to_credential"]
        H["binding_fresh"] = bv["fresh"]
        pv2 = verify_holder_proof(proof, binding=binding if bv["binding_authentic"] else None,
                                  expected_nonce=expected_nonce, expected_context=expected_context, now=now)
        H["proof_authentic"] = pv2["proof_authentic"]
        H["key_matches_binding"] = pv2["key_matches_binding"]
        H["nonce_matches"] = pv2["nonce_matches"]
        H["proved"] = bool(bv["binding_authentic"] and bv["fresh"] and bv["bound_to_credential"] is not False
                           and pv2["proof_authentic"] and pv2["fresh"]
                           and pv2["key_matches_binding"] and pv2["nonce_matches"] is not False
                           and pv2["context_matches"] is not False)
    v["usable_offline"] = bool(v["credential_authentic"] and v["issuer_trusted"] is not False
                               and S["present"] and S["authentic"] and S["fresh"] and S["active"] and S["bound"]
                               and v["context_matches"] is not False
                               and (H["proved"] if H["present"] else True)
                               and (H["proved"] if require_holder_proof else True))
    if not v["usable_offline"]:
        why = []
        if not v["credential_authentic"]:
            why.append("credential not authentic")
        if v["issuer_trusted"] is False:
            why.append("issuer not trusted")
        if not S["present"]:
            why.append("no status assertion stapled (authorization not decidable offline)")
        else:
            why += [k for k in ("authentic", "fresh", "active", "bound") if not S[k]]
        if v["context_matches"] is False:
            why.append("context mismatch")
        if H["present"] and not H["proved"]:
            why.append("the holder proof does not chain to an issuer-signed binding")
        elif require_holder_proof and not H["present"]:
            why.append("no holder proof (this verifier requires possession of the holder key, not only the file)")
        v["note"] = "; ".join(why)
    return v


def main(argv=None):
    ap = argparse.ArgumentParser(description="Detached authenticity verifier for a Polaris credential.")
    ap.add_argument("--pack", help="authenticity pack JSON file (default: stdin)")
    ap.add_argument("--presentation", help="a polaris-presentation/1 JSON file (P8.6): the credential with a stapled status "
                                           "assertion, decided offline")
    ap.add_argument("--qr-frames", help="a file of polaris-qr/1 frames, one per line, as scanned from a wallet (P8.6)")
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
    ap.add_argument("--zk-proof", help="a holder's ZK inclusion proof bundle JSON (P3.2d): with "
                    "--epoch-checkpoint and --trusted-manifest, decide a cross-authority proof OFFLINE")
    ap.add_argument("--epoch-checkpoint", help="a foreign authority's signed epoch checkpoint JSON")
    ap.add_argument("--trusted-manifest", action="append",
                    help="a federation manifest the relying party trusts (repeatable)")
    ap.add_argument("--trusted-anchor", help="an anchor public key hex the relying party trusts")
    ap.add_argument("--context", type=int, help="the presented context id (for --zk-proof)")
    ap.add_argument("--nonce", type=int, default=None, help="the challenge nonce the proof must carry")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if args.verify_dir:
        return verify_dir(args.verify_dir)

    if args.presentation or args.qr_frames:
        try:
            if args.qr_frames:
                with open(args.qr_frames) as fh:
                    frames = [ln for ln in fh.read().splitlines() if ln.strip()]
                presentation, reason = decode_presentation_frames(frames)
                if presentation is None:
                    print("could not decode the QR frames: %s" % reason, file=sys.stderr)
                    return 1
            else:
                with open(args.presentation) as fh:
                    presentation = json.loads(fh.read())
            anchor = _load_anchor(args.issuer_anchor) if args.issuer_anchor else None
        except (OSError, ValueError) as e:
            print("could not read the presentation / anchor: %s" % e, file=sys.stderr)
            return 3
        verdict = verify_presentation(presentation, anchor_keys=anchor, max_window_seconds=args.max_window,
                                      expected_context=args.context)
        if args.json:
            print(json.dumps(verdict, indent=2))
        else:
            print("usable offline: %s%s" % (verdict["usable_offline"], (" (%s)" % verdict["note"]) if verdict.get("note") else ""))
        return 0 if verdict["usable_offline"] else 1
    if args.zk_proof:
        try:
            proof = json.loads(open(args.zk_proof).read())
            checkpoint = json.loads(open(args.epoch_checkpoint).read()) if args.epoch_checkpoint else {}
            manifests = [json.loads(open(m).read()) for m in (args.trusted_manifest or [])]
        except Exception as e:
            print("could not read the ZK proof / checkpoint / manifest: %s" % e, file=sys.stderr)
            return 3
        verdict = verify_cross_authority_zk(
            proof, checkpoint, args.context, manifests, max_window_seconds=args.max_window,
            trusted_anchors=([args.trusted_anchor] if args.trusted_anchor else None),
            expected_nonce=args.nonce)
        if args.json:
            print(json.dumps(verdict, indent=2))
        else:
            print("decision: %s" % verdict["decision"])
            for r in verdict.get("reasons", []):
                print("  - %s" % r)
        return {"accept": 0, "abstain": 2}.get(verdict["decision"], 1)

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
