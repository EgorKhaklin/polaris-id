#!/usr/bin/env python3
"""
polaris-federation-status-bundle-drill.py — the aggregate mirrored status feed, run (P3.2c).

P3.2b let a relying party check a foreign credential's non-revocation against the issuer's
own signed revocation feed, OFFLINE. At federation scale that is one fetch per authority.
P3.2c aggregates them: a publisher mirrors many authorities' revocation feeds and epoch
checkpoints into ONE short-lived, signed STATUS BUNDLE, so a relying party fetches it once
and checks any member's credential offline.

The property this drill exists to prove is that the publisher (the aggregator) is UNTRUSTED
for correctness. It stands up two real authorities (I and B) plus a separate aggregator (P),
all with distinct real ML-DSA-65 roots, and drives the accept/reject matrix. The headline
case: the aggregator, in FULL control of the bundle it signs, drops a revocation from a
member's embedded feed and re-signs the bundle -- and the revoked credential is STILL
rejected, because the member feed carries the MEMBER's own signature, which the aggregator
cannot forge. It FAILS (exit 1) if any decision is wrong. Needs liboqs + cryptography.

    python3 scripts/polaris-federation-status-bundle-drill.py
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
        print("status-bundle drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("status-bundle drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-status-bundle-")
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

    def bundle(publisher, members, ttl_hours=1, issued=None):
        """Assemble a status bundle over `members` (each {authority_id, revocation_feed,
        epoch_checkpoint}) and sign the ENVELOPE with the publisher's key. members_root is
        computed over the members as given, so tampering a member after this call is caught
        unless the caller also recomputes the root (which a real aggregator can do -- and
        which the member-signature defense still defeats)."""
        issued = issued or now
        body = {
            "format": "polaris-federation-status-bundle/1",
            "publisher": {"agency_id": publisher["agency_id"], "name": publisher["name"]},
            "members": members,
            "members_root_hex": V.bundle_members_root(members),
            "member_count": len(members),
            "issued_at": _iso(issued),
            "expires_at": _iso(issued + timedelta(hours=ttl_hours)),
            "algorithm": "ML-DSA-65",
        }
        sig, pk = sign_with(publisher["key_file"], V._status_bundle_canonical(body))
        body["signature_hex"], body["public_key_hex"] = sig.hex(), pk
        return body

    # Two real authorities (I issues the credential, B vouches for I) and a separate
    # aggregator P that publishes the bundle. The relying party trusts B, not P.
    I, B, P, S = issuer("I"), issuer("B"), issuer("P"), issuer("S")

    revoked_tok = "FED-I-REVOKED-01"
    active_tok = "FED-I-ACTIVE-01"
    leaf_r = V.revocation_leaf(revoked_tok)

    pack_revoked = pack_for(I, revoked_tok)
    pack_active = pack_for(I, active_tok)

    cp_I = checkpoint(I, 2, "bb" * 16, {"number": 1, "root_hex": "aa" * 16})
    feed_I_clean = feed(I, [])              # I has revoked nothing yet
    feed_I_revoked = feed(I, [leaf_r])      # I has revoked the credential
    member_I_clean = {"authority_id": I["agency_id"], "revocation_feed": feed_I_clean, "epoch_checkpoint": cp_I}
    member_I_revoked = {"authority_id": I["agency_id"], "revocation_feed": feed_I_revoked, "epoch_checkpoint": cp_I}
    member_B = {"authority_id": B["agency_id"],
                "revocation_feed": feed(B, []), "epoch_checkpoint": checkpoint(B, 1, "cc" * 16, None)}

    # B attests to I in context 1; the relying party trusts B's anchor.
    B_attests_I = manifest(B, [{"attested_agency_id": "I", "attested_public_key_hex": I["key_hex"], "context_id": 1}])
    trust_B = [B["key_hex"]]

    def decide(pack, bnd, publisher_key=None):
        return V.verify_cross_authority_via_bundle(
            pack, 1, [B_attests_I], bnd, trusted_anchors=trust_B, publisher_key=publisher_key)

    # --- honest bundles ---------------------------------------------------------------
    good_bundle = bundle(P, [member_I_clean, member_B])            # I active, mirrored by P
    revoked_bundle = bundle(P, [member_I_revoked, member_B])       # I's credential revoked
    without_I = bundle(P, [member_B])                              # aggregator omits I
    stale_bundle = bundle(P, [member_I_clean, member_B], ttl_hours=1, issued=now - timedelta(hours=3))

    # --- tamper 1: swap a member's feed WITHOUT recomputing members_root (set integrity) --
    tampered_set = json.loads(json.dumps(good_bundle))
    tampered_set["members"][0]["revocation_feed"] = feed_I_revoked  # different member, root now stale
    # (members_root_hex left as the good bundle's -> commitment must fail)

    # --- tamper 2 (headline): the aggregator drops the revocation from I's embedded feed,
    # keeps it internally consistent, recomputes members_root, and RE-SIGNS the bundle with
    # its own key. The envelope is now perfectly valid -- but I's feed signature is over the
    # ORIGINAL (revoking) canonical, so it no longer verifies, and the revoked credential is
    # rejected. The aggregator cannot forge a member's status. --------------------------
    forged_feed = json.loads(json.dumps(feed_I_revoked))
    forged_feed["revoked_leaves"] = []
    forged_feed["revoked_root_hex"] = V.revoked_root([])
    forged_feed["revoked_count"] = 0
    # keep I's original signature_hex/public_key_hex -> invalid over the tampered canonical
    forged_member = {"authority_id": I["agency_id"], "revocation_feed": forged_feed, "epoch_checkpoint": cp_I}
    forged_bundle = bundle(P, [forged_member, member_B])  # bundle() recomputes members_root + re-signs

    checks = [
        # envelope
        ("good bundle envelope is authentic + fresh + committed",
         (lambda r: r["bundle_authentic"] and r["fresh"] and r["commitment_ok"])(
             V.verify_status_bundle(good_bundle, publisher_key=P["key_hex"])), True),
        ("bundle pinned to the wrong publisher fails the pin",
         V.verify_status_bundle(good_bundle, publisher_key=S["key_hex"])["publisher_matches"], False),
        # accept path
        ("active foreign credential via the bundle: ACCEPT",
         decide(pack_active, good_bundle)["decision"], "accept"),
        ("accepted credential is marked in_bundle",
         decide(pack_active, good_bundle)["in_bundle"], True),
        ("accepted credential is epoch-bound to I's checkpoint",
         decide(pack_active, good_bundle)["epoch_bound"], True),
        ("accept still holds when the correct publisher is pinned",
         decide(pack_active, good_bundle, publisher_key=P["key_hex"])["decision"], "accept"),
        # revocation crosses the boundary through the mirror
        ("revoked foreign credential via the revoked bundle: REJECT",
         decide(pack_revoked, revoked_bundle)["decision"], "reject"),
        ("revoked decision is fail-closed on revocation, not trust",
         decide(pack_revoked, revoked_bundle)["revoked"], True),
        # fail-closed omission
        ("credential whose issuer is OMITTED from the bundle: REJECT",
         decide(pack_active, without_I)["decision"], "reject"),
        ("omitted issuer is reported not-in-bundle",
         decide(pack_active, without_I)["in_bundle"], False),
        # stale envelope
        ("stale bundle: REJECT (a stale mirror proves nothing about now)",
         decide(pack_active, stale_bundle)["decision"], "reject"),
        # set integrity
        ("member swapped without recomputing members_root: envelope REJECT",
         V.verify_status_bundle(tampered_set, publisher_key=P["key_hex"])["commitment_ok"], False),
        ("credential decided against a tampered set: REJECT",
         decide(pack_active, tampered_set)["decision"], "reject"),
        # the headline: the aggregator cannot forge a member's status even with a valid envelope
        ("forged bundle envelope itself is authentic (aggregator controls it)",
         (lambda r: r["bundle_authentic"] and r["commitment_ok"])(
             V.verify_status_bundle(forged_bundle, publisher_key=P["key_hex"])), True),
        ("but the forged member feed's OWN signature is invalid",
         V.verify_revocation_feed(forged_member["revocation_feed"], issuer_key=I["key_hex"])["feed_authentic"], False),
        ("so the revoked credential is STILL rejected: the aggregator cannot lie",
         decide(pack_revoked, forged_bundle)["decision"], "reject"),
    ]

    print("case                                                              got        expected   ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-61s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if ok_all:
        print("\nOK: the aggregate status bundle mirrors many authorities OFFLINE, and the publisher is "
              "untrusted for correctness -- an omitted authority is fail-closed, a stale mirror proves "
              "nothing, and an aggregator in full control of the bundle still cannot forge a member's "
              "revocation status, because the member feed carries the member's own signature.")
        return 0
    print("\nFAIL: a status-bundle decision was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
