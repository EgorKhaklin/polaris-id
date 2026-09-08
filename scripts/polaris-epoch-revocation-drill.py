#!/usr/bin/env python3
"""
polaris-epoch-revocation-drill.py — epoch alignment + revocation propagation, run (P3.2b).

The inter-authority protocol v1 (P3.2) let two authorities publish their anchors and
attestations and a relying party accept a foreign credential offline. It carried the
epoch and revocation state only as references. P3.2b makes those references consume-able:
two more signed objects an authority publishes, both verified here OFFLINE, both signed
by the SAME authority key that signs its manifest and its credentials.

  1. EPOCH CHECKPOINT  (polaris-epoch-checkpoint/1): the authority's commitment to a point
     on its append-only TokenStateEpoch chain. Two checkpoints prove MONOTONICITY, and two
     different roots signed at one epoch number are a FORK -- cryptographic proof the
     authority equivocated about its own history.

  2. REVOCATION FEED   (polaris-revocation-feed/1): the sorted revoked-credential leaves it
     issued, plus a commitment over them. It is MONOTONE (RevocationList is append-only),
     so a feed that DROPS a revocation or moves its as_of backward is a ROLLBACK. A relying
     party checks a foreign credential's non-revocation against it with NO issuer contact.

This drill stands up two authorities with distinct real ML-DSA-65 roots and drives the
whole accept/reject matrix. It FAILS (exit 1) if any decision is wrong: a fork or a
rollback must be caught, a revoked foreign credential must be rejected offline, an active
one accepted, and a feed that is not authentic, fresh, and bound to the issuer key must
fail closed. Needs liboqs + cryptography.

    python3 scripts/polaris-epoch-revocation-drill.py
"""
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "polaris_web"))


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _iso(dt):
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main():
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    try:
        import pqc_signing
    except Exception as e:
        print("epoch/revocation drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("epoch/revocation drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-epoch-revoc-")
    now = datetime.now(timezone.utc)

    def issuer(name):
        kp = pqc_signing.generate_keypair()
        kf = os.path.join(tmp, "%s.key.json" % name)
        with open(kf, "w") as f:
            json.dump(kp, f)
        return {"name": name, "key_file": kf, "key_hex": kp["public_key_hex"], "agency_id": name}

    def sign_with(key_file, message):
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
        sig, _alg, pk = pqc_signing.signature_over_message(message)
        return sig, pk

    def pack_for(iss, token_value):
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = iss["key_file"]
        sig, alg, pk = pqc_signing.signature_with_key_for_token(token_value)
        return {"format": "polaris-authenticity-pack/1", "token_value": token_value,
                "algorithm": alg, "signature_hex": sig.hex(), "public_key_hex": pk}

    def checkpoint(iss, number, root_hex, prev, ttl_hours=24, issued=None):
        issued = issued or now
        body = {
            "format": "polaris-epoch-checkpoint/1",
            "authority": {"agency_id": iss["agency_id"], "name": iss["name"]},
            "epoch": {"number": number, "root_hex": root_hex, "committed_count": number,
                      "valid_until": _iso(issued + timedelta(days=30))},
            "prev": prev,
            "as_of": _iso(issued),
            "issued_at": _iso(issued),
            "expires_at": _iso(issued + timedelta(hours=ttl_hours)),
            "algorithm": "ML-DSA-65",
        }
        sig, pk = sign_with(iss["key_file"], V._epoch_checkpoint_canonical(body))
        body["signature_hex"], body["public_key_hex"] = sig.hex(), pk
        return body

    def feed(iss, leaves, epoch_number=1, as_of=None, ttl_hours=24, issued=None):
        issued = issued or now
        uniq = sorted({str(x).lower() for x in leaves})
        body = {
            "format": "polaris-revocation-feed/1",
            "authority": {"agency_id": iss["agency_id"], "name": iss["name"]},
            "epoch_number": epoch_number,
            "as_of": _iso(as_of or issued),
            "revoked_root_hex": V.revoked_root(uniq),
            "revoked_count": len(uniq),
            "revoked_leaves": uniq,
            "issued_at": _iso(issued),
            "expires_at": _iso(issued + timedelta(hours=ttl_hours)),
            "algorithm": "ML-DSA-65",
        }
        sig, pk = sign_with(iss["key_file"], V._revocation_feed_canonical(body))
        body["signature_hex"], body["public_key_hex"] = sig.hex(), pk
        return body

    def manifest(iss, attestations, ttl_hours=24, issued=None):
        issued = issued or now
        body = {
            "format": "polaris-federation-manifest/1",
            "authority": {"agency_id": iss["agency_id"], "name": iss["name"]},
            "anchors": [{"public_key_hex": iss["key_hex"], "algorithm": "ML-DSA-65", "status": "active"}],
            "attestations": attestations,
            "epoch": {"number": 2, "root_hex": "bb" * 16},
            "revocation": {"as_of": _iso(issued), "count": 0},
            "issued_at": _iso(issued),
            "expires_at": _iso(issued + timedelta(hours=ttl_hours)),
            "algorithm": "ML-DSA-65",
        }
        sig, pk = sign_with(iss["key_file"], V._manifest_canonical(body))
        body["signature_hex"], body["public_key_hex"] = sig.hex(), pk
        return body

    # Two authorities with distinct real roots, plus a stranger.
    I, B, S = issuer("I"), issuer("B"), issuer("S")

    # --- epoch alignment: a chain, a fork, an aligned/misaligned checkpoint -------------
    cp1 = checkpoint(I, 1, "aa" * 16, None)
    cp2 = checkpoint(I, 2, "bb" * 16, {"number": 1, "root_hex": "aa" * 16})   # extends cp1
    cp2_fork = checkpoint(I, 2, "cc" * 16, {"number": 1, "root_hex": "aa" * 16})  # different root at #2
    cp1_alt = checkpoint(I, 1, "dd" * 16, None)                              # different root at #1
    cp_stranger = checkpoint(S, 1, "aa" * 16, None)                         # signed by the wrong key
    cp_expired = checkpoint(I, 1, "aa" * 16, None, ttl_hours=1, issued=now - timedelta(hours=2))

    # I's manifest commits to epoch {number:2, root "bb"*16}; cp2 matches it, cp2_fork does not.
    I_manifest = manifest(I, [])

    # --- revocation propagation: feeds, membership, monotonicity ------------------------
    revoked_tok = "FED-I-REVOKED-01"
    active_tok = "FED-I-ACTIVE-01"
    leaf_r = V.revocation_leaf(revoked_tok)
    leaf_2 = V.revocation_leaf("FED-I-REVOKED-02")
    feed_v1 = feed(I, [leaf_r], epoch_number=1)
    feed_v2 = feed(I, [leaf_r, leaf_2], epoch_number=2, as_of=now + timedelta(hours=1),
                   issued=now + timedelta(hours=1))
    feed_tampered = dict(feed_v1)
    feed_tampered["revoked_leaves"] = [V.revocation_leaf("SOMETHING-ELSE")]  # leaves no longer match root
    feed_by_stranger = feed(S, [leaf_r])  # a feed for I's token, signed by the wrong key

    # --- cross-authority: B attests to I in context 1; a relying party trusts B ---------
    pack_revoked = pack_for(I, revoked_tok)
    pack_active = pack_for(I, active_tok)
    B_attests_I = manifest(B, [{"attested_agency_id": "I", "attested_public_key_hex": I["key_hex"], "context_id": 1}])
    trust_B = [B["key_hex"]]

    def x(pack, feed_arg):
        return V.verify_cross_authority(pack, 1, [B_attests_I], trusted_anchors=trust_B,
                                        revocation_feed=feed_arg)

    checks = [
        # epoch alignment
        ("checkpoint cp1 is authentic",
         V.verify_epoch_checkpoint(cp1, issuer_key=I["key_hex"])["checkpoint_authentic"] is True, True),
        ("cp1 -> cp2 chains cleanly",
         V.check_epoch_chain(cp1, cp2)["consistent"] and not V.check_epoch_chain(cp1, cp2)["fork"], True),
        ("FORK caught: two roots at epoch 1",
         V.check_epoch_chain(cp1, cp1_alt)["fork"], True),
        ("FORK caught: rival root at epoch 2",
         V.check_epoch_chain(cp2, cp2_fork)["fork"], True),
        ("stranger-signed checkpoint fails issuer bind",
         V.verify_epoch_checkpoint(cp_stranger, issuer_key=I["key_hex"])["issuer_matches"], False),
        ("expired checkpoint is not fresh",
         V.verify_epoch_checkpoint(cp_expired)["fresh"], False),
        ("cp2 is aligned with I's manifest epoch",
         V.epoch_aligned(I_manifest, cp2), True),
        ("cp2_fork is NOT aligned with I's manifest epoch",
         V.epoch_aligned(I_manifest, cp2_fork), False),
        # revocation feed
        ("feed_v1 is authentic + bound to issuer",
         (lambda r: r["feed_authentic"] and r["issuer_matches"])(
             V.verify_revocation_feed(feed_v1, issuer_key=I["key_hex"])), True),
        ("tampered feed (commitment mismatch) rejected",
         V.verify_revocation_feed(feed_tampered)["feed_authentic"], False),
        ("revoked credential is in the feed",
         V.is_revoked(feed_v1, revoked_tok), True),
        ("active credential is not in the feed",
         V.is_revoked(feed_v1, active_tok), False),
        ("feed_v1 -> feed_v2 is a forward progression",
         V.check_revocation_progression(feed_v1, feed_v2)["progresses"], True),
        ("ROLLBACK caught: feed_v2 -> feed_v1 drops a revocation",
         V.check_revocation_progression(feed_v2, feed_v1)["rolled_back"], True),
        # cross-authority decisions (the headline: revocation crosses the boundary offline)
        ("foreign active credential, no feed: ACCEPT",
         x(pack_active, None)["decision"], "accept"),
        ("foreign active credential, with I's feed: ACCEPT",
         x(pack_active, feed_v1)["decision"], "accept"),
        ("foreign REVOKED credential, with I's feed: REJECT",
         x(pack_revoked, feed_v1)["decision"], "reject"),
        ("foreign credential, feed signed by a stranger: REJECT (fail-closed)",
         x(pack_active, feed_by_stranger)["decision"], "reject"),
        ("foreign credential, tampered feed: REJECT (fail-closed)",
         x(pack_active, feed_tampered)["decision"], "reject"),
    ]

    print("case                                                         got        expected   ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-56s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: epoch alignment and revocation propagation hold across two authorities OFFLINE -- "
              "a fork and a rollback are caught, and a revoked foreign credential is rejected with no "
              "issuer contact.")
        return 0
    print("\nFAIL: an epoch-alignment or revocation decision was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
