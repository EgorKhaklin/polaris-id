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
    from datetime import datetime, timezone
    v = {"manifest_authentic": False, "fresh": None, "issuer_trusted": None,
         "authority": manifest.get("authority"), "anchors": manifest.get("anchors") or [],
         "attestations": manifest.get("attestations") or [], "witnesses": [], "note": None}
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
    active = {a.get("public_key_hex", "").lower() for a in v["anchors"]
              if (a.get("status") or "active") == "active"}
    if pk_hex.lower() not in active:
        v["note"] = "the manifest is not signed by one of its own declared active anchors"
        return v
    digest = hashlib.sha3_256(_manifest_canonical(manifest)).digest()
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
        v["note"] = "the two witnesses DISAGREE -- treat as invalid"
        return v
    ok = primary if primary is not None else witness
    v["manifest_authentic"] = bool(ok)
    if not ok:
        v["note"] = "manifest signature is invalid"
        return v
    now = now or datetime.now(timezone.utc)
    try:
        ia, ea = _parse_iso(manifest["issued_at"]), _parse_iso(manifest["expires_at"])
    except Exception as e:
        v["fresh"] = False
        v["note"] = "unparseable issued_at/expires_at (%s)" % e
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


def verify_cross_authority(pack, context_id, trusted_manifests, now=None,
                           max_window_seconds=None, trusted_anchors=None,
                           revocation_feed=None):
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
    a = verify_pack(pack)
    if not a["signature_valid"]:
        return {"decision": "reject", "authentic": False,
                "reasons": ["credential is not authentic"], "via": None,
                "revocation_checked": False, "revoked": None}
    token_key = (pack.get("public_key_hex") or "").lower()
    via = None
    for manifest in trusted_manifests:
        mv = verify_manifest(manifest, now=now, max_window_seconds=max_window_seconds,
                             trusted_anchors=trusted_anchors)
        if not (mv["manifest_authentic"] and mv["fresh"]):
            continue
        if trusted_anchors is not None and not mv["issuer_trusted"]:
            continue  # the relying party does not trust the manifest's authority
        for att in mv["attestations"]:
            same_key = (att.get("attested_public_key_hex") or "").lower() == token_key
            same_ctx = (context_id is None or att.get("context_id") == context_id)
            if same_key and same_ctx:
                via = mv["authority"]
                break
        if via:
            break
    if not via:
        return {"decision": "reject", "authentic": True,
                "reasons": ["no trusted authority attests to this credential's issuer in this context"],
                "via": None, "revocation_checked": False, "revoked": None}
    # P3.2b: fail-closed revocation propagation, if the relying party supplies the feed.
    if revocation_feed is not None:
        rv = verify_revocation_feed(revocation_feed, now=now,
                                    max_window_seconds=max_window_seconds, issuer_key=token_key)
        if not (rv["feed_authentic"] and rv["fresh"] and rv["issuer_matches"]):
            return {"decision": "reject", "authentic": True,
                    "reasons": ["the issuer's revocation feed is not authentic, fresh, and bound to "
                                "the issuer key -- non-revocation cannot be confirmed"],
                    "via": via, "revocation_checked": True, "revoked": None}
        if is_revoked(revocation_feed, pack.get("token_value") or ""):
            return {"decision": "reject", "authentic": True,
                    "reasons": ["credential is revoked in the issuer's published revocation feed"],
                    "via": via, "revocation_checked": True, "revoked": True}
        return {"decision": "accept", "authentic": True, "reasons": [], "via": via,
                "revocation_checked": True, "revoked": False}
    return {"decision": "accept", "authentic": True, "reasons": [], "via": via,
            "revocation_checked": False, "revoked": None}


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
    holds the same set computes the same root. MUST match app.py's builder."""
    uniq = sorted({str(x).lower() for x in leaves})
    return hashlib.sha3_256("\n".join(uniq).encode("utf-8")).hexdigest()


def revocation_leaf(token_value):
    """The published identifier for a revoked credential: SHA3-256(token_value) hex. A
    relying party derives it from the credential it is presented; it does NOT expose the
    active population, because only a holder of a credential can compute its leaf."""
    return hashlib.sha3_256(token_value.encode("utf-8")).hexdigest()


def _two_witness_verify(digest, sig, pk):
    """Shared ML-DSA-65 two-witness check (liboqs primary, cryptography second). Returns
    (ok, ran, note): ok is True/False, or None when no verifier is available or the two
    witnesses disagree -- in which case `note` says which."""
    primary = _verify_liboqs(digest, sig, pk)
    witness = _verify_cryptography(digest, sig, pk)
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
    from datetime import datetime, timezone
    now = now or datetime.now(timezone.utc)
    try:
        ia, ea = _parse_iso(obj["issued_at"]), _parse_iso(obj["expires_at"])
    except Exception as e:
        v["fresh"] = False
        v["note"] = "unparseable issued_at/expires_at (%s)" % e
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
    ok, ran, note = _two_witness_verify(digest, sig, pk)
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
    # its own members is rejected before its signature is even considered meaningful.
    leaves = feed.get("revoked_leaves") or []
    uniq = {str(x).lower() for x in leaves}
    v["commitment_ok"] = (revoked_root(leaves) == (feed.get("revoked_root_hex") or "").lower()
                          and len(uniq) == (feed.get("revoked_count") or 0))
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_revocation_feed_canonical(feed)).digest()
    ok, ran, note = _two_witness_verify(digest, sig, pk)
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
    first -- this is a membership test, not an authenticity check."""
    leaf = revocation_leaf(token_value or "").lower()
    return leaf in {str(x).lower() for x in (feed.get("revoked_leaves") or [])}


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
    digs = sorted(hashlib.sha3_256(
        json.dumps(m, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        for m in (members or []))
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
    members = bundle.get("members") or []
    v["commitment_ok"] = (bundle_members_root(members) == (bundle.get("members_root_hex") or "").lower()
                          and len(members) == (bundle.get("member_count") or 0))
    try:
        sig, pk = bytes.fromhex(sig_hex), bytes.fromhex(pk_hex)
    except (ValueError, TypeError):
        v["note"] = "signature_hex/public_key_hex are not valid hex"
        return v
    digest = hashlib.sha3_256(_status_bundle_canonical(bundle)).digest()
    ok, ran, note = _two_witness_verify(digest, sig, pk)
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
    token_key = (pack.get("public_key_hex") or "").lower()
    member = None
    for m in bv["members"]:
        feed = (m.get("revocation_feed") or {})
        if (feed.get("public_key_hex") or "").lower() == token_key:
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
    ok, ran, note = _two_witness_verify(digest, sig, pk)
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
    ok, ran, note = _two_witness_verify(digest, sig, pk)
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
