#!/usr/bin/env python3
"""
polaris-federation-instances-drill.py — two REAL Polaris instances, federation over HTTP (P3.10).

The crypto drills prove the federation protocol in one process. This proves it across the
DEPLOYMENT boundary: two independent instances, each its own database and its own real
ML-DSA-65 root, talking only over HTTP. It boots authority A on one port against one
database and authority B on another, then a relying party decides ACCEPT/REJECT for a
credential A issued using trust data it pulls OVER THE WIRE from the running instances,
and the decision flips as real state changes on those instances:

  - cross-verification: B publishes a manifest attesting to A's key in a context; a relying
    party that trusts B accepts A's credential in that context, from B's manifest alone;
  - attestation revocation: B revokes the attestation; re-fetched over HTTP, the credential
    is no longer accepted;
  - anchor cross-checks: A's signed epoch checkpoint and revocation feed are fetched over
    HTTP and verified; when A revokes the credential, its feed (re-fetched) rejects it;
  - and the adversarial cases (wrong context, forged credential) reject throughout.

It FAILS (exit 1) if any decision is wrong. Preconditions: two loaded Polaris databases
(default `polaris_fa`, `polaris_fb`) reachable via the POLARIS_DB_* environment, and
liboqs + cryptography for real ML-DSA. It launches the two instances itself (gunicorn) and
tears them down. Exit 3 if a precondition is missing (skip).

    POLARIS_DB_HOST=localhost POLARIS_DB_USER=vanta python3 scripts/polaris-federation-instances-drill.py
"""
import contextlib
import importlib.util
import hashlib
import json
from datetime import datetime, timezone, timedelta
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WEB = os.path.join(_ROOT, "polaris_web")
sys.path.insert(0, _WEB)

A_DB = os.environ.get("POLARIS_FED_A_DB", "polaris_fa")
B_DB = os.environ.get("POLARIS_FED_B_DB", "polaris_fb")
DB_HOST = os.environ.get("POLARIS_DB_HOST", "localhost")
DB_USER = os.environ.get("POLARIS_DB_USER", "postgres")
DB_PORT = os.environ.get("POLARIS_DB_PORT", "5432")
CONTEXT_ID = int(os.environ.get("POLARIS_FED_CONTEXT_ID", "1"))


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _conn(dbname):
    import psycopg2
    return psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, dbname=dbname)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect IS a verdict here (the operator route sends a session-less caller to
    /login); do not follow it, report the 3xx."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def _http_post_json(url, obj):
    """POST a JSON body with NO cookie or session; returns (status, parsed json or {}).
    Redirects are not followed and a non-JSON body reads as an empty dict."""
    data = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with _NO_REDIRECT_OPENER.open(req, timeout=10) as r:
            status, raw = r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, raw = e.code, (e.read().decode("utf-8", "replace") if e.fp else "")
    try:
        return status, json.loads(raw or "{}")
    except ValueError:
        return status, {}


def _http_get_soft(url):
    """GET returning (status, json-or-{}) without raising on 4xx."""
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        return e.code, {}


def _http_get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, json.loads(r.read().decode("utf-8"))


def _wait_health(port, log_path, name, tries=60):
    for i in range(tries):
        try:
            code, _ = _http_get("http://127.0.0.1:%d/api/health" % port)
            if code == 200:
                print("  instance %s healthy on :%d (check %d)" % (name, port, i + 1))
                return True
        except (urllib.error.URLError, ConnectionError, socket.timeout):
            pass
        time.sleep(0.5)
    print("  instance %s NEVER became healthy on :%d" % (name, port), file=sys.stderr)
    with contextlib.suppress(Exception):
        with open(log_path) as f:
            print("  --- %s log tail ---\n%s" % (name, "".join(f.readlines()[-25:])), file=sys.stderr)
    return False


def _launch(dbname, port, key_file, log_path):
    env = dict(os.environ)
    env.update({
        "POLARIS_DB_HOST": DB_HOST, "POLARIS_DB_PORT": DB_PORT, "POLARIS_DB_USER": DB_USER,
        "POLARIS_DB_NAME": dbname, "POLARIS_USE_REAL_PQC": "1",
        "POLARIS_PQC_SIGNING_KEY_FILE": key_file,
        "POLARIS_SECRET_KEY": env.get("POLARIS_SECRET_KEY", "fed_drill_secret_" + "0" * 40),
    })
    log = open(log_path, "w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "gunicorn", "-w", "1", "-b", "127.0.0.1:%d" % port,
         "--timeout", "60", "app:app"],
        cwd=_WEB, env=env, stdout=log, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid if hasattr(os, "setsid") else None)
    return proc


def _kill(proc):
    if proc is None:
        return
    with contextlib.suppress(Exception):
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    with contextlib.suppress(Exception):
        proc.wait(timeout=10)


def main():
    os.environ["POLARIS_USE_REAL_PQC"] = "1"
    try:
        import pqc_signing
    except Exception as e:
        print("federation-instances drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("federation-instances drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3
    try:
        import psycopg2  # noqa: F401
        _conn(A_DB).close()
        _conn(B_DB).close()
    except Exception as e:
        print("federation-instances drill needs two loaded databases %r and %r reachable via "
              "POLARIS_DB_* (%s); skipping" % (A_DB, B_DB, e), file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-fed-inst-")

    def keypair(name):
        kp = pqc_signing.generate_keypair()
        f = os.path.join(tmp, "%s.json" % name)
        with open(f, "w") as fh:
            json.dump(kp, fh)
        return f, kp["public_key_hex"]

    key_a, pub_a = keypair("keyA")
    key_b, pub_b = keypair("keyB")

    # Register each instance's authority root, and give B an agency row that carries A's
    # key so B can attest to it. All state changes below are real rows on the instances.
    with _conn(A_DB) as ca, ca.cursor() as cur:
        cur.execute("UPDATE Agency SET signing_public_key_hex=%s WHERE agency_id=1", (pub_a,))
        # Two credentials A issued: an ACTIVE one, and one already in A's RevocationList.
        # The drill only READS A (its feed and checkpoint reflect this state), so it does
        # not need a freshly loaded A database -- it writes only B's attestation, idempotently.
        cur.execute("SELECT token_value FROM IdentityToken "
                    "WHERE issuing_agency_id=1 AND status='ACTIVE' ORDER BY token_id LIMIT 1")
        active_row = cur.fetchone()
        cur.execute("SELECT it.token_value FROM RevocationList rl "
                    "JOIN IdentityToken it ON it.token_id = rl.token_id "
                    "WHERE it.issuing_agency_id=1 ORDER BY it.token_id LIMIT 1")
        revoked_row = cur.fetchone()
        ca.commit()
    if not active_row or not revoked_row:
        print("%s needs an ACTIVE and a REVOKED agency-1 token (load the sample data)" % A_DB, file=sys.stderr)
        return 3
    active_value, revoked_value = active_row[0], revoked_row[0]
    # B attests to A's key in CONTEXT_ID. AgencyTrustAttestation is append-only
    # (federation audit-of-record: no delete, and revocation is one-way), so the drill
    # mutates B's state irreversibly and needs a freshly loaded B database each run -- the
    # same precondition the CI job satisfies. On a fresh load this attestation is new.
    with _conn(B_DB) as cb, cb.cursor() as cur:
        cur.execute("UPDATE Agency SET signing_public_key_hex=%s WHERE agency_id=1", (pub_b,))
        cur.execute("UPDATE Agency SET signing_public_key_hex=%s WHERE agency_id=2", (pub_a,))
        cur.execute("INSERT INTO AgencyTrustAttestation (attesting_agency_id, attested_agency_id, context_id, attested_date, valid_until, signed_by) "
                    "VALUES (1, 2, %s, CURRENT_DATE, CURRENT_DATE + INTERVAL '1 year', 1)", (CONTEXT_ID,))
        cb.commit()

    # The held credentials A issued: A's real signature over each token value.
    os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_a

    def a_pack(tv):
        sig, alg, pk = pqc_signing.signature_with_key_for_token(tv)
        return {"format": "polaris-authenticity-pack/1", "token_value": tv,
                "algorithm": alg, "signature_hex": sig.hex(), "public_key_hex": pk}

    pack = a_pack(active_value)
    pack_revoked = a_pack(revoked_value)
    forged = dict(pack)
    bb = bytearray.fromhex(forged["signature_hex"]); bb[0] ^= 0x01
    forged["signature_hex"] = bb.hex()

    port_a, port_b = _free_port(), _free_port()
    log_a, log_b = os.path.join(tmp, "a.log"), os.path.join(tmp, "b.log")
    proc_a = proc_b = None
    try:
        proc_a = _launch(A_DB, port_a, key_a, log_a)
        proc_b = _launch(B_DB, port_b, key_b, log_b)
        if not (_wait_health(port_a, log_a, "A") and _wait_health(port_b, log_b, "B")):
            return 1
        base_a = "http://127.0.0.1:%d" % port_a
        base_b = "http://127.0.0.1:%d" % port_b

        # Everything a relying party consumes is fetched OVER HTTP from the running instances.
        def b_manifest():
            return _http_get(base_b + "/api/v1/federation-manifest/1")[1]
        def a_checkpoint():
            return _http_get(base_a + "/api/v1/epoch-checkpoint/1")[1]
        def a_feed():
            return _http_get(base_a + "/api/v1/revocation-feed/1")[1]

        def decide(pk_pack, ctx, feed=None):
            return V.verify_cross_authority(pk_pack, ctx, [b_manifest()], trusted_anchors=[pub_b],
                                            revocation_feed=feed)

        checks = []
        # 1. cross-verification over the wire: B attests to A in CONTEXT_ID.
        checks.append(("A credential accepted via B's fetched manifest (right context)",
                       decide(pack, CONTEXT_ID)["decision"], "accept"))
        # 2. wrong context rejects.
        checks.append(("wrong context rejects",
                       decide(pack, CONTEXT_ID + 1000)["decision"], "reject"))
        # 3. forged credential rejects.
        checks.append(("forged credential rejects",
                       decide(forged, CONTEXT_ID)["decision"], "reject"))
        # 4. anchor cross-check: A's epoch checkpoint, fetched over HTTP, is authentic + bound to A.
        cp = a_checkpoint()
        cv = V.verify_epoch_checkpoint(cp, issuer_key=pub_a)
        checks.append(("A's fetched epoch checkpoint is authentic + issuer-bound",
                       bool(cp.get("public_key_hex") == pub_a and cv["checkpoint_authentic"] and cv["issuer_matches"]),
                       True))
        # 5. anchor cross-check: A's revocation feed, fetched over HTTP, is authentic and
        #    reflects A's real revocation state -- it lists the revoked credential, not the
        #    active one.
        feed = a_feed()
        fv = V.verify_revocation_feed(feed, issuer_key=pub_a)
        checks.append(("A's fetched revocation feed is authentic + issuer-bound",
                       bool(fv["feed_authentic"] and fv["issuer_matches"]), True))
        checks.append(("the feed lists A's revoked credential but not the active one",
                       bool(V.is_revoked(feed, revoked_value) and not V.is_revoked(feed, active_value)), True))
        # 6. revocation propagation over HTTP: with A's published feed the active credential
        #    is accepted and the revoked one is rejected, with no contact with A beyond the feed.
        checks.append(("active credential accepted with A's feed",
                       decide(pack, CONTEXT_ID, feed=feed)["decision"], "accept"))
        checks.append(("revoked credential rejected offline via A's feed",
                       decide(pack_revoked, CONTEXT_ID, feed=feed)["decision"], "reject"))

        # 6b. AGGREGATION (P3.2c, the correct architecture): B is a HUB. It FETCHES A's
        #     already-signed feed and checkpoint over HTTP (it holds NO A key), verifies them
        #     against A's public key, and embeds them VERBATIM in a status bundle alongside its
        #     own fetched feed. B signs ONLY the outer envelope, with its own key. A relying
        #     party that trusts B then checks A's credential against the SINGLE bundle, offline.
        #     This is fetch / verify / preserve / sign-the-envelope -- never re-sign a partner.
        b_feed = _http_get(base_b + "/api/v1/revocation-feed/1")[1]
        b_cp = _http_get(base_b + "/api/v1/epoch-checkpoint/1")[1]
        member_a = {"authority_id": 2, "revocation_feed": feed, "epoch_checkpoint": cp}
        member_b = {"authority_id": 1, "revocation_feed": b_feed, "epoch_checkpoint": b_cp}

        def hub_bundle(member_list):
            import datetime as _dt
            n = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
            body = {
                "format": "polaris-federation-status-bundle/1",
                "publisher": {"agency_id": 1, "name": "Instance B (hub)"},
                "members": member_list,
                "members_root_hex": V.bundle_members_root(member_list),
                "member_count": len(member_list),
                "issued_at": n.isoformat().replace("+00:00", "Z"),
                "expires_at": (n + _dt.timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                "algorithm": "ML-DSA-65",
            }
            # B signs ONLY the envelope, with B's own key. A's embedded feed keeps A's signature.
            os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_b
            s, _a, p = pqc_signing.signature_over_message(V._status_bundle_canonical(body))
            body["signature_hex"], body["public_key_hex"] = s.hex(), p
            return body

        def decide_bundle(pk_pack, bundle):
            return V.verify_cross_authority_via_bundle(pk_pack, CONTEXT_ID, [b_manifest()], bundle,
                                                       trusted_anchors=[pub_b], publisher_key=pub_b)

        full_bundle = hub_bundle([member_a, member_b])
        omit_a_bundle = hub_bundle([member_b])
        checks.append(("A's embedded feed is signed by A, not the hub (aggregator holds no A key)",
                       bool((feed.get("public_key_hex") or "").lower() == pub_a.lower()
                            and (feed.get("public_key_hex") or "").lower() != pub_b.lower()), True))
        checks.append(("the hub bundle envelope is signed by B (the aggregator)",
                       (full_bundle["public_key_hex"] or "").lower() == pub_b.lower(), True))
        checks.append(("A's ACTIVE credential accepted via B's fetched-and-bundled status (offline)",
                       decide_bundle(pack, full_bundle)["decision"], "accept"))
        checks.append(("A's REVOKED credential rejected via the same bundle (offline)",
                       decide_bundle(pack_revoked, full_bundle)["decision"], "reject"))
        checks.append(("A omitted from the bundle: A's credential is fail-closed (not verifiable)",
                       decide_bundle(pack, omit_a_bundle)["decision"], "reject"))

        # 6c. SERVICE-TO-SERVICE MINTING (P8.2b): B's OWN service mints an exchange receipt on
        #     instance B with NO session -- it authenticates by SIGNING the mint statement under
        #     B's registered ML-DSA-65 key (agency 1 on B = pub_b). The requester is A's key,
        #     which B attests in CONTEXT_ID, so the receipt is authorized. All over HTTP; the
        #     receipt is then verified OFFLINE against B's fetched manifest.
        def mint_request(requester_key, when, responder_id=1):
            return {"format": "polaris-exchange-mint/1", "requester_public_key_hex": requester_key,
                    "context_id": CONTEXT_ID,
                    "request_hash": hashlib.sha3_256(b"the request body, never sent").hexdigest(),
                    "response_hash": hashlib.sha3_256(b"the response body, never sent").hexdigest(),
                    "responder_agency_id": responder_id, "occurred_at": when}

        def signed_mint(mint, key_file):
            os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file
            sig, _alg, _pk = pqc_signing.signature_over_message(V._exchange_mint_canonical(mint))
            return {"mint": mint, "signature_hex": sig.hex()}

        now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        stale_iso = (datetime.now(timezone.utc) - timedelta(minutes=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        mint_url = base_b + "/api/v1/exchange-receipt/1/signed"
        st, receipt = _http_post_json(mint_url, signed_mint(mint_request(pub_a, now_iso), key_b))
        checks.append(("B's service mints a receipt with NO session, authenticated by its signature (200)", st, 200))
        rv = (V.verify_exchange_receipt(receipt, trusted_manifests=[b_manifest()], responder_key=pub_b)
              if st == 200 else {})
        checks.append(("the minted receipt is authentic, responder-bound, and the requester (A) is authorized, OFFLINE",
                       bool(rv.get("receipt_authentic") and rv.get("responder_matches") and rv.get("requester_authorized")), True))
        checks.append(("the receipt carries the SIGNED occurred_at (a replay can only duplicate, never re-time)",
                       (receipt or {}).get("occurred_at") == now_iso, True))
        st2, _ = _http_post_json(mint_url, signed_mint(mint_request(pub_a, now_iso), key_a))
        checks.append(("signed under the WRONG key (A's, not the responder's registered key) rejects (401)", st2, 401))
        bad = signed_mint(mint_request(pub_a, now_iso), key_b)
        bb2 = bytearray.fromhex(bad["signature_hex"]); bb2[0] ^= 0x01; bad["signature_hex"] = bb2.hex()
        st3, _ = _http_post_json(mint_url, bad)
        checks.append(("a tampered signature rejects (401)", st3, 401))
        st4, _ = _http_post_json(mint_url, signed_mint(mint_request(pub_a, stale_iso), key_b))
        checks.append(("a STALE signed time (30 min) rejects (401): the freshness window bounds replay", st4, 401))
        _kf_s, pub_stranger = keypair("stranger")
        st5, _ = _http_post_json(mint_url, signed_mint(mint_request(pub_stranger, now_iso), key_b))
        checks.append(("an UNATTESTED requester is not authorized: 403 even under a valid responder signature", st5, 403))
        st6, _ = _http_post_json(base_b + "/api/v1/exchange-receipt/1",
                                 {"requester_public_key_hex": pub_a, "context_id": CONTEXT_ID,
                                  "request_hash": "00" * 32, "response_hash": "00" * 32})
        checks.append(("the operator mint route with no session does not mint (not 200)", st6 != 200, True))

        # 6d. TIMESTAMP AUTHORITY over HTTP (P8.7a): B binds a digest to an instant under its
        #     registered key; verified offline, trusted under B's key, bound to the document B
        #     never saw; a non-digest is refused at the door.
        doc = b"a document B never sees"
        st7, tsr = _http_post_json(base_b + "/api/v1/timestamp/1",
                                   {"digest_hex": hashlib.sha3_256(doc).hexdigest(), "nonce": "drill-nonce"})
        checks.append(("B's timestamp authority binds a digest to an instant over HTTP (200)", st7, 200))
        tv = V.verify_timestamp(tsr, anchor_keys=[pub_b]) if st7 == 200 else {}
        checks.append(("the timestamp is authentic, trusted under B's key, and binds to the document (offline)",
                       bool(tv.get("timestamp_authentic") and tv.get("issuer_trusted") and V.timestamp_binds(tsr, doc)), True))
        checks.append(("the nonce is echoed in the signed statement", (tsr or {}).get("nonce") == "drill-nonce", True))
        st8, _ = _http_post_json(base_b + "/api/v1/timestamp/1", {"digest_hex": "not a digest"})
        checks.append(("a non-digest is refused at the door (400): the content itself is never sent", st8, 400))

        # 6e. RECEIPT TRANSPARENCY (P8.2c): the SET of receipts is an append-only log while no
        #     receipt is retained. The minted receipt's hash is in B's receipt log; inclusion is
        #     verified OFFLINE against a head signed by B; a second mint grows the log by one and
        #     the earlier head is a prefix of the later (append-only); a fabricated hash is not in
        #     the log; a tampered proof fails; the independent monitor, pointed at the RECEIPT
        #     log, accepts the head and then its consistent extension.
        rh = V.receipt_hash(receipt) if st == 200 else "00" * 32
        st9, inc = _http_get_soft(base_b + "/api/v1/exchange-receipt/inclusion/" + rh)
        checks.append(("the minted receipt's hash is in B's receipt log: inclusion evidence served (200)", st9, 200))
        iv = (V.verify_receipt_inclusion(receipt, inc.get("proof", {}), inc.get("sth", {}), log_key=pub_b)
              if st9 == 200 else {})
        checks.append(("inclusion verified OFFLINE: the proof reconstructs a head signed by B's key",
                       bool(iv.get("included") and iv.get("sth_authentic") and iv.get("log_matches")), True))
        sth1 = inc.get("sth", {})
        mon_state = os.path.join(tmp, "receipt-monitor")
        mon_cmd = [sys.executable, os.path.join(_ROOT, "scripts", "polaris-transparency-monitor.py"),
                   "--url", base_b, "--anchor", pub_b, "--state", mon_state, "--log", "receipts", "--once"]
        mon1 = subprocess.run(mon_cmd, capture_output=True, text=True)
        checks.append(("the independent monitor, pointed at the RECEIPT log, accepts its head (exit 0)", mon1.returncode, 0))
        second = dict(mint_request(pub_a, now_iso)); second["request_hash"] = hashlib.sha3_256(b"a second request").hexdigest()
        st10, _receipt2 = _http_post_json(mint_url, signed_mint(second, key_b))
        sth2 = _http_get(base_b + "/api/v1/transparency/receipts/sth")[1]
        checks.append(("a second minted receipt grows the receipt log by exactly one",
                       (st10, sth2.get("tree_size")), (200, (sth1.get("tree_size") or 0) + 1)))
        cons = _http_get(base_b + "/api/v1/transparency/receipts/consistency/%d/%d"
                         % (sth1.get("tree_size") or 0, sth2.get("tree_size") or 0))[1]
        try:
            consistent = V.verify_consistency(cons["first_size"], cons["second_size"],
                                              bytes.fromhex(cons["first_root_hex"]), bytes.fromhex(cons["second_root_hex"]),
                                              [bytes.fromhex(p) for p in cons["proof_hex"]]) \
                and cons["second_root_hex"] == sth2.get("root_hash_hex") and cons["first_root_hex"] == sth1.get("root_hash_hex")
        except Exception as e:  # noqa: BLE001 -- a malformed proof is a wrong verdict, not a crash
            consistent = "error: %s" % e
        checks.append(("the earlier head is a prefix of the later one: append-only, verified offline", consistent, True))
        mon2 = subprocess.run(mon_cmd, capture_output=True, text=True)
        checks.append(("the monitor accepts the grown log as a consistent extension (exit 0)", mon2.returncode, 0))
        checks.append(("a fabricated receipt hash is not in the log (404)",
                       _http_get_soft(base_b + "/api/v1/exchange-receipt/inclusion/" + "ab" * 32)[0], 404))
        bad_inc = json.loads(json.dumps(inc)) if st9 == 200 else {"proof": {}, "sth": {}}
        bad_inc["proof"]["index"] = int(bad_inc["proof"].get("index", 0)) + 1
        checks.append(("a tampered inclusion proof does not verify",
                       V.verify_receipt_inclusion(receipt, bad_inc["proof"], bad_inc["sth"], log_key=pub_b)["included"], False))

        # 6f. DISCOVERY (P8.3): B publishes a SIGNED REGISTRY. A consumer fetches it, verifies it
        #     offline under B's key, and drives a call from a path it READ OUT OF THE REGISTRY --
        #     never from hardcoded knowledge -- and reads B's in-context trust graph from it.
        reg = _http_get(base_b + "/api/v1/registry/1")[1]
        rv = V.verify_registry(reg, trusted_anchors=[pub_b])
        checks.append(("B's fetched registry is authentic, fresh, self-consistent, and from a trusted publisher",
                       bool(rv.get("registry_authentic") and rv.get("fresh") and rv.get("issuer_trusted")), True))
        svc = V.registry_service(reg, "timestamp") or {}
        disc_path = str(svc.get("path") or "").replace("{agency_id}", "1")
        st11, _tsd = (_http_post_json(base_b + disc_path, {"digest_hex": hashlib.sha3_256(b"discovered").hexdigest()})
                      if disc_path else (0, {}))
        checks.append(("a service DISCOVERED from the registry (timestamp) answers at the advertised path (200)", st11, 200))
        # (the sample data already has another agency attesting agency 2 in this context, so the
        #  registry rightly reports every attester; the check is membership, not equality)
        checks.append(("the registry's trust graph lists B (agency 1) among those attesting A's key in CONTEXT_ID",
                       1 in V.registry_trusts(reg, pub_a, CONTEXT_ID), True))
        checks.append(("the registry lists A's key as an authority B knows",
                       V.registry_authority(reg, pub_a) is not None, True))
        checks.append(("the registry advertises the protocol formats, including itself",
                       "polaris-registry" in ((reg.get("instance") or {}).get("protocol") or {}).get("formats", {}), True))

        # 7. attestation revocation on B: re-fetched manifest no longer accepts A.
        with _conn(B_DB) as cb, cb.cursor() as cur:
            cur.execute("UPDATE AgencyTrustAttestation SET revocation_date=CURRENT_DATE, "
                        "revocation_reason='drill attestation revocation' "
                        "WHERE attesting_agency_id=1 AND attested_agency_id=2 AND context_id=%s", (CONTEXT_ID,))
            cb.commit()
        checks.append(("attestation revoked on B: re-fetched manifest rejects the credential",
                       decide(pack, CONTEXT_ID)["decision"], "reject"))
        reg2 = _http_get(base_b + "/api/v1/registry/1")[1]
        checks.append(("... and the re-fetched registry's trust graph no longer lists B's attestation",
                       1 in V.registry_trusts(reg2, pub_a, CONTEXT_ID), False))

        print("\ncase                                                                   got        expected   ok")
        ok_all = True
        for label, got, expected in checks:
            ok = got == expected
            ok_all = ok_all and ok
            print("  %-66s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
        if ok_all:
            print("\nOK: two independent instances federate over HTTP -- a foreign credential is accepted from "
                  "trust data pulled over the wire; a hub aggregates a peer's FETCHED, already-signed feed into a "
                  "status bundle it signs with only its OWN key (holding no peer key), B's own service mints an exchange "
                  "receipt with no session by signing under its registered key, and the decision flips as "
                  "attestations and revocations change on the running instances, with real ML-DSA throughout.")
            return 0
        print("\nFAIL: a two-instance federation decision was wrong.", file=sys.stderr)
        return 1
    finally:
        _kill(proc_a)
        _kill(proc_b)


if __name__ == "__main__":
    sys.exit(main())
