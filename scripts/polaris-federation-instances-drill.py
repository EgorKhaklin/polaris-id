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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone, timedelta
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
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
# P8.8a: a MIXED-algorithm federation by default. A signs under ML-DSA-87, B under ML-DSA-65,
# so every cross-instance path is exercised across parameter sets; POLARIS_DRILL_ALGORITHM_A
# = ML-DSA-65 runs the single-algorithm configuration.
ALG_A = os.environ.get("POLARIS_DRILL_ALGORITHM_A", "ML-DSA-87")
ALG_B = "ML-DSA-65"


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


class _EchoUpstream(BaseHTTPRequestHandler):
    """The institution's own service behind B's gateway: echoes the request it was handed and
    names the requester the gateway authenticated. It never sees an envelope or a key."""
    def do_POST(self):  # noqa: N802 -- http.server's naming
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            req = json.loads(raw.decode("utf-8") or "null")
        except ValueError:
            req = None
        out = json.dumps({"echo": req, "served_by": "echo-upstream",
                          "requester": self.headers.get("X-Polaris-Requester")}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):  # quiet
        pass


def _http_post_form(url, data, basic=None):
    """POST a urlencoded form (optionally HTTP Basic), returning (status, json-or-{})."""
    import base64
    from urllib.parse import urlencode
    req = urllib.request.Request(url, data=urlencode(data).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    if basic:
        req.add_header("Authorization", "Basic " + base64.b64encode(("%s:%s" % basic).encode("utf-8")).decode("ascii"))
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


def _launch(dbname, port, key_file, log_path, extra_env=None):
    env = dict(os.environ)
    env.update({
        "POLARIS_DB_HOST": DB_HOST, "POLARIS_DB_PORT": DB_PORT, "POLARIS_DB_USER": DB_USER,
        "POLARIS_DB_NAME": dbname, "POLARIS_USE_REAL_PQC": "1",
        "POLARIS_PQC_SIGNING_KEY_FILE": key_file,
        "POLARIS_SECRET_KEY": env.get("POLARIS_SECRET_KEY", "fed_drill_secret_" + "0" * 40),
    })
    env.update(extra_env or {})
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

    def keypair(name, algorithm=ALG_B):
        kp = pqc_signing.generate_keypair(algorithm=algorithm)
        f = os.path.join(tmp, "%s.json" % name)
        with open(f, "w") as fh:
            json.dump(kp, fh)
        return f, kp["public_key_hex"]

    key_a, pub_a = keypair("keyA", ALG_A)
    key_b, pub_b = keypair("keyB", ALG_B)
    print("  A signs under %s, B under %s (mixed-algorithm federation)" % (ALG_A, ALG_B))

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
        proc_a = _launch(A_DB, port_a, key_a, log_a, extra_env={"POLARIS_PQC_ALGORITHM": ALG_A})
        # P8.2d: B's gateway forwards service kind "echo" to an upstream the DRILL runs (the
        # institution's own service); the mapping is operator configuration, never a request.
        echo_srv = ThreadingHTTPServer(("127.0.0.1", 0), _EchoUpstream)
        threading.Thread(target=echo_srv.serve_forever, daemon=True).start()
        echo_url = "http://127.0.0.1:%d/" % echo_srv.server_address[1]
        proc_b = _launch(B_DB, port_b, key_b, log_b, extra_env={"POLARIS_EXCHANGE_UPSTREAMS": json.dumps({"echo": echo_url})})
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
            os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_b   # select the signer FIRST; the body names its algorithm
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
                "algorithm": pqc_signing.algorithm_name(),
            }
            # B signs ONLY the envelope, with B's own key. A's embedded feed keeps A's signature.
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
        # P8.5b (v9.341): anchoring is the caller's choice. A plain request leaves no row; an anchored
        # one appends exactly one digest and comes back with inclusion evidence a verifier checks
        # offline against B's registered key; the registry lists the timestamp log.
        with _conn(B_DB) as cb, cb.cursor() as cur:
            cur.execute("SELECT count(*) FROM TimestampLog"); rows_before = cur.fetchone()[0]
        st9, tsa_anchored = _http_post_json(base_b + "/api/v1/timestamp/1",
                                            {"digest_hex": hashlib.sha3_256(doc).hexdigest(), "nonce": "drill-anchored", "anchor": True})
        with _conn(B_DB) as cb, cb.cursor() as cur:
            cur.execute("SELECT count(*) FROM TimestampLog"); rows_after = cur.fetchone()[0]
        av = V.verify_timestamp_anchor(tsa_anchored, log_key=pub_b) if st9 == 200 else {}
        checks.append(("an unanchored timestamp left NO row; an ANCHORED one (the caller's choice) appended exactly one digest",
                       (rows_before, rows_after - rows_before), (0, 1)))
        checks.append(("the anchored timestamp's inclusion evidence verifies offline under B's key (proof reconstructs the signed head)",
                       (st9, av.get("anchored"), av.get("sth_authentic"), av.get("log_matches")), (200, True, True, True)))
        st10, incl = _http_get_soft(base_b + "/api/v1/timestamp/inclusion/" + V.timestamp_hash(tsa_anchored)) if st9 == 200 else (0, {})
        checks.append(("B serves the inclusion evidence for that timestamp hash (200), and the registry lists the timestamp log",
                       (st10, "polaris-timestamp-log" in ((_http_get(base_b + "/api/v1/registry/1")[1].get("instance") or {}).get("transparency_logs") or [])), (200, True)))

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

        # 6g. THE GATEWAY (P8.2d): A's service sends a signed exchange envelope + body to B's
        #     gateway for B's "echo" service. B authenticates A by its known key, authorizes it
        #     through the trust graph, consumes the nonce, forwards to the echo upstream, and
        #     returns the response with a signed receipt. The evidence (envelope + receipt)
        #     verifies offline with no body; replay, strangers, mismatched bodies, tampering,
        #     unknown kinds and stale envelopes are all refused; no body is ever stored or logged.
        def envelope(requester_key, key_file, body, nonce, kind="echo", when=None, target_id=1):
            os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_file   # the key decides the algorithm: select it FIRST
            env = {"format": "polaris-exchange-request/1", "requester": {"public_key_hex": requester_key},
                   "target": {"agency_id": target_id, "kind": kind}, "context_id": CONTEXT_ID,
                   "request_hash": V.canonical_body_hash(body), "nonce": nonce,
                   "issued_at": when or now_iso, "algorithm": pqc_signing.algorithm_name()}
            sig, _alg, pk = pqc_signing.signature_over_message(V._exchange_request_canonical(env))
            env["signature_hex"], env["public_key_hex"] = sig.hex(), pk
            return env

        gw = base_b + "/api/v1/exchange/1"
        ask = {"ask": "balance", "account": "notional-42"}
        env1 = envelope(pub_a, key_a, ask, "nonce-1")
        st12, ex = _http_post_json(gw, {"envelope": env1, "body": ask})
        # P8.8b: negotiation. An unadvertised major is refused with the supported list, never
        # guessed at (the format check precedes nonce consumption, so the consumed nonce is moot);
        # the consumer-side rule reads what B speaks from B's registry.
        st_v2, body_v2 = _http_post_json(gw, {"envelope": dict(env1, format="polaris-exchange-request/2"), "body": ask})
        checks.append(("an unadvertised format version is refused as unsupported_format_version (400) listing the supported one",
                       (st_v2, (body_v2 or {}).get("error"), (body_v2 or {}).get("supported")),
                       (400, "unsupported_format_version", ["polaris-exchange-request/1"])))
        checks.append(("B's registry says what B speaks, major.minor per format (registry_speaks: the consumer-side rule)",
                       (V.registry_speaks(reg, "polaris-exchange-request/1"), V.registry_speaks(reg, "polaris-exchange-request/2"),
                        V.registry_speaks(reg, "polaris-nothing/1"), reg["instance"]["protocol"]["versions"]["polaris-registry"].split(".")[0]),
                       (True, False, False, "1")))
        rcpt = (ex or {}).get("receipt") or {}
        resp_body = (ex or {}).get("response_body")
        checks.append(("A's signed exchange is mediated by B's gateway to B's echo service (200)", st12, 200))
        checks.append(("the upstream answered the request and saw the authenticated requester",
                       (resp_body or {}).get("echo") == ask and (resp_body or {}).get("requester") == pub_a, True))
        rv2 = V.verify_exchange_receipt(rcpt, trusted_manifests=[b_manifest()], responder_key=pub_b,
                                        request_body=json.dumps(ask, sort_keys=True, separators=(",", ":")).encode(),
                                        response_body=json.dumps(resp_body, sort_keys=True, separators=(",", ":")).encode())
        checks.append(("the receipt is authentic, B-signed, requester authorized, and binds BOTH bodies",
                       bool(rv2.get("receipt_authentic") and rv2.get("responder_matches") and rv2.get("requester_authorized")
                            and rv2.get("request_bound") and rv2.get("response_bound")), True))
        ev = V.verify_exchange_request(env1, requester_key=pub_a, trusted_manifests=[b_manifest()], body=ask)
        checks.append(("the envelope verifies offline: A-signed, authorized in-context, bound to the body",
                       bool(ev.get("request_authentic") and ev.get("requester_matches") and ev.get("requester_authorized") and ev.get("body_bound")), True))
        checks.append(("envelope + receipt form one consistent evidence chain (same requester, context, hash, instant)",
                       V.exchange_evidence(env1, rcpt), True))
        checks.append(("the receipt's occurred_at is the envelope's SIGNED time", rcpt.get("occurred_at") == env1["issued_at"], True))
        checks.append(("the exchange's receipt is in B's receipt log (inclusion evidence served)",
                       _http_get_soft(base_b + "/api/v1/exchange-receipt/inclusion/" + V.receipt_hash(rcpt))[0] if rcpt else 0, 200))
        st13, _ = _http_post_json(gw, {"envelope": env1, "body": ask})
        checks.append(("the SAME envelope replayed is refused (409): the nonce was consumed", st13, 409))
        st14, _ = _http_post_json(gw, {"envelope": envelope(pub_a, key_a, ask, "nonce-2"), "body": ask})
        checks.append(("the same request with a NEW nonce is a new exchange (200)", st14, 200))
        _kf_x, pub_x = keypair("stranger-x")
        st15, _ = _http_post_json(gw, {"envelope": envelope(pub_x, _kf_x, ask, "nonce-3"), "body": ask})
        checks.append(("a requester whose key B does not know is refused (401)", st15, 401))
        # v9.333: trust is DIRECTIONAL. A third authority (agency 5 on B) attests X in the context
        # (the seed already holds that row for context 1; the insert tolerates it); B (agency 1) does not. X is KNOWN to B (registered as agency 3) but B must refuse, since B
        # holds no attestation of X itself; once B attests X, the same exchange is authorized.
        with _conn(B_DB) as cb, cb.cursor() as cur:
            cur.execute("UPDATE Agency SET signing_public_key_hex=%s WHERE agency_id=3", (pub_x,))
            cur.execute("INSERT INTO AgencyTrustAttestation (attesting_agency_id, attested_agency_id, context_id, attested_date, valid_until, signed_by) "
                        "VALUES (5, 3, %s, CURRENT_DATE, CURRENT_DATE + INTERVAL '1 year', 1) "
                        "ON CONFLICT (attesting_agency_id, attested_agency_id, context_id) WHERE revocation_date IS NULL DO NOTHING", (CONTEXT_ID,))
            cb.commit()
        st15b, body15b = _http_post_json(gw, {"envelope": envelope(pub_x, _kf_x, ask, "nonce-3b"), "body": ask})
        checks.append(("a THIRD authority's attestation of X does not authorize X at B (403): trust is directional, not transitive",
                       (st15b, "directional" in ((body15b or {}).get("error_description") or "")), (403, True)))
        with _conn(B_DB) as cb, cb.cursor() as cur:
            cur.execute("INSERT INTO AgencyTrustAttestation (attesting_agency_id, attested_agency_id, context_id, attested_date, valid_until, signed_by) "
                        "VALUES (1, 3, %s, CURRENT_DATE, CURRENT_DATE + INTERVAL '1 year', 1)", (CONTEXT_ID,))
            cb.commit()
        st15c, ex15c = _http_post_json(gw, {"envelope": envelope(pub_x, _kf_x, ask, "nonce-3c"), "body": ask})
        checks.append(("once B itself attests X, the same exchange is authorized (200) via B's attestation and no other",
                       (st15c, (((ex15c or {}).get("receipt") or {}).get("authorized_via") or {}).get("authority", {}).get("agency_id")), (200, 1)))
        st16, _ = _http_post_json(gw, {"envelope": envelope(pub_a, key_a, ask, "nonce-4"), "body": {"ask": "something else"}})
        checks.append(("a body the envelope does not bind is refused (400)", st16, 400))
        bad_env = envelope(pub_a, key_a, ask, "nonce-5"); bb3 = bytearray.fromhex(bad_env["signature_hex"]); bb3[0] ^= 0x01; bad_env["signature_hex"] = bb3.hex()
        st17, _ = _http_post_json(gw, {"envelope": bad_env, "body": ask})
        checks.append(("a tampered envelope signature is refused (401)", st17, 401))
        st18, _ = _http_post_json(gw, {"envelope": envelope(pub_a, key_a, ask, "nonce-6", kind="teleport"), "body": ask})
        checks.append(("a service kind B does not forward to is refused (404): upstreams are operator configuration", st18, 404))
        st19, _ = _http_post_json(gw, {"envelope": envelope(pub_a, key_a, ask, "nonce-7", when=stale_iso), "body": ask})
        checks.append(("a stale envelope is refused (401): the freshness window", st19, 401))
        reg_g = _http_get(base_b + "/api/v1/registry/1")[1]
        checks.append(("B's registry advertises the gateway and the 'echo' exchange kind",
                       bool(V.registry_service(reg_g, "exchange")) and "echo" in ((reg_g.get("instance") or {}).get("exchange_kinds") or []), True))
        with open(log_b) as fh:
            b_log = fh.read()
        checks.append(("no request or response body appears anywhere in B's process log",
                       "notional-42" not in b_log and "echo-upstream" not in b_log, True))
        with _conn(B_DB) as cb, cb.cursor() as cur:
            cur.execute("SELECT count(*) FROM ExchangeNonce")
            n_nonce = cur.fetchone()[0]
        checks.append(("B's replay register holds exactly the consumed nonces (3 delivered exchanges)", n_nonce, 3))

        # 6h. HOLDER-AUTHORIZED DOCUMENT SIGNING (P8.5c) over HTTP: give one of B's issued
        #     credentials a REAL ML-DSA-65 signature (a new TokenSignature row under key_b), have
        #     the holder prove possession and sign a document via B; verify the container offline
        #     with the evidence B embedded; then do the same through the WALLET's `sign` command.
        import psycopg2
        with _conn(B_DB) as cb, cb.cursor() as cur:
            cur.execute("SELECT token_id, token_value FROM IdentityToken WHERE issuing_agency_id=1 AND status='ACTIVE' ORDER BY token_id LIMIT 1")
            b_tok_id, b_tok_value = cur.fetchone()
            os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = key_b
            b_sig, _alg_b, b_pk = pqc_signing.signature_with_key_for_token(b_tok_value)
            cur.execute("INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, signing_public_key_hex) VALUES (%s, 1, %s, %s)",
                        (b_tok_id, psycopg2.Binary(b_sig), b_pk))
            cb.commit()
        the_doc = b"the holder's document; it never leaves the holder"
        st20, sdoc = _http_post_json(base_b + "/api/v1/sign/1/holder",
                                     {"token_value": b_tok_value, "signature_hex": b_sig.hex(),
                                      "digest_hex": hashlib.sha3_256(the_doc).hexdigest(), "name": "report.txt", "purpose": "drill"})
        checks.append(("a holder who proves possession of B's credential gets a document signed by B (200)", st20, 200))
        sv = V.verify_signed_document(sdoc, trusted_anchors=[pub_b], document_bytes=the_doc) if st20 == 200 else {"ltv": {}}
        checks.append(("the container is B-signed, trusted, binds the document, and records the holder by credential HASH",
                       bool(sv.get("document_authentic") and sv.get("signer_trusted") and sv.get("binds")
                            and (sdoc.get("on_behalf_of") or {}).get("credential_hash") == V.revocation_leaf(b_tok_value)), True))
        # v9.334: B's own embedded timestamp is convenience evidence. Long-term validity needs time
        # evidence from a timestamp authority the verifier trusts AND distinct from the signer, so
        # the container becomes valid long term only once A's timestamp (over HTTP, on the
        # signature material, never the document) is attached and A is trusted for time.
        checks.append(("B's own embedded timestamp is convenience evidence: authentic, but NOT valid long term on its own (v9.334)",
                       (bool((sv.get("ltv") or {}).get("timestamp_authentic")), bool(sv.get("valid_long_term"))), (True, False)))
        material_digest = hashlib.sha3_256(V.document_signature_material(sdoc)).hexdigest() if st20 == 200 else "00" * 32
        st20b, ts_a = _http_post_json(base_a + "/api/v1/timestamp/1", {"digest_hex": material_digest, "nonce": "ltv-b-doc"})
        strong = V.attach_ltv(sdoc, timestamp=ts_a) if st20 == 200 and st20b == 200 else {}
        checks.append(("A timestamps B's signature material over HTTP (200) and, with A trusted for time, the container is VALID LONG TERM",
                       (st20b, bool(V.verify_signed_document(strong, trusted_anchors=[pub_b], document_bytes=the_doc, timestamp_anchors=[pub_a]).get("valid_long_term"))),
                       (200, True)))
        checks.append(("... but not with B as the only trusted timestamp authority: A's timestamp is not B's word, and B's own is not independent",
                       bool(V.verify_signed_document(strong, trusted_anchors=[pub_b], document_bytes=the_doc, timestamp_anchors=[pub_b]).get("valid_long_term")), False))
        st20c, _ = _http_post_json(base_b + "/api/v1/sign/1/holder",
                                   {"token_value": b_tok_value, "signature_hex": b_sig.hex(), "digest_hex": hashlib.sha3_256(the_doc).hexdigest(),
                                    "timestamp_agency_id": 2})
        checks.append(("asking B to timestamp under an agency whose custody on B is B's own key is refused (400): one key gives no independent evidence", st20c, 400))
        checks.append(("the token value appears nowhere in the container", b_tok_value not in json.dumps(sdoc), True))
        st21, _ = _http_post_json(base_b + "/api/v1/sign/1/holder",
                                  {"token_value": b_tok_value, "signature_hex": "00" * 64, "digest_hex": "ab" * 32})
        checks.append(("a wrong presented signature is uniformly 'not verifiable' (400)", st21, 400))
        wdir = os.path.join(tmp, "wallet"); os.makedirs(wdir)
        pack_path = os.path.join(tmp, "b-pack.json")
        with open(pack_path, "w") as fh:
            json.dump({"format": "polaris-authenticity-pack/1", "token_value": b_tok_value, "algorithm": _alg_b,
                       "signature_hex": b_sig.hex(), "public_key_hex": b_pk}, fh)
        doc_path = os.path.join(tmp, "report.txt")
        with open(doc_path, "wb") as fh:
            fh.write(the_doc)
        wallet = [sys.executable, os.path.join(_ROOT, "scripts", "polaris-wallet.py"), "--wallet", wdir]
        enroll = subprocess.run(wallet + ["enroll", "--pack", pack_path], capture_output=True, text=True)
        out_path = os.path.join(tmp, "signed.json")
        signed = subprocess.run(wallet + ["sign", "--document", doc_path, "--instance", base_b, "--agency", "1", "--out", out_path],
                                capture_output=True, text=True)
        wdoc = json.load(open(out_path)) if signed.returncode == 0 and os.path.isfile(out_path) else {}
        checks.append(("the WALLET enrolls the credential and signs the document through B (exit 0)",
                       (enroll.returncode, signed.returncode), (0, 0)))
        wv = V.verify_signed_document(wdoc, trusted_anchors=[pub_b], document_bytes=the_doc)
        w_material = hashlib.sha3_256(V.document_signature_material(wdoc)).hexdigest() if wdoc else "00" * 32
        st_w, ts_w = _http_post_json(base_a + "/api/v1/timestamp/1", {"digest_hex": w_material, "nonce": "ltv-wallet-doc"})
        w_strong = V.attach_ltv(wdoc, timestamp=ts_w) if wdoc and st_w == 200 else {}
        checks.append(("the wallet-signed container verifies offline (B-signed, binds the document); with A's timestamp attached it is valid long term",
                       (bool(wv.get("document_authentic") and wv.get("binds")),
                        bool(V.verify_signed_document(w_strong, trusted_anchors=[pub_b], document_bytes=the_doc, timestamp_anchors=[pub_a]).get("valid_long_term"))),
                       (True, True)))

        # 6i. THE AUTH BROKER (P8.4) over HTTP: a relying party registered on B with the
        #     'authenticate' scope starts a login (nonce + PKCE); the holder of B's real-signed
        #     credential authorizes by possession; the relying party exchanges the code with its
        #     client credentials and receives an ID token signed by B's agency key, which it
        #     verifies OFFLINE. Replay, a wrong verifier, a verify-only relying party, a wrong
        #     presentation and an unmet step-up are all refused.
        import base64
        import security as _sec
        rp_cid, rp_secret = "rp_drill_auth_" + os.urandom(6).hex(), "drill-secret-" + os.urandom(8).hex()
        with _conn(B_DB) as cb, cb.cursor() as cur:
            cur.execute("INSERT INTO RelyingParty (client_id, client_secret_hash, org_name, enabled, rate_limit_per_min, scope) "
                        "VALUES (%s, %s, %s, TRUE, 120, 'verify authenticate')", (rp_cid, _sec.hash_password(rp_secret), "Drill Bank"))
            cur.execute("INSERT INTO RelyingParty (client_id, client_secret_hash, org_name, enabled, rate_limit_per_min, scope) "
                        "VALUES (%s, %s, %s, TRUE, 120, 'verify')", (rp_cid + "v", _sec.hash_password(rp_secret), "Verify-only Bank"))
            cb.commit()
        verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        login_nonce = "login-" + os.urandom(8).hex()

        def authorize(extra=None, cid=rp_cid, sig=None):
            body = {"client_id": cid, "nonce": login_nonce, "code_challenge": challenge, "code_challenge_method": "S256",
                    "context_id": CONTEXT_ID, "disclosure_level": "ZERO_KNOWLEDGE",
                    "token_value": b_tok_value, "signature_hex": sig or b_sig.hex()}
            body.update(extra or {})
            return _http_post_json(base_b + "/api/v1/auth/authorize", body)

        st22, auth = authorize()
        checks.append(("the holder authorizes by possession for the relying party (200, a signed code)", (st22, bool(auth.get("code"))), (200, True)))
        st23, tokr = _http_post_form(base_b + "/api/v1/auth/token",
                                     {"grant_type": "authorization_code", "code": auth.get("code", ""), "code_verifier": verifier},
                                     basic=(rp_cid, rp_secret))
        idt = (tokr or {}).get("id_token") or {}
        checks.append(("the relying party exchanges the code (client credentials + PKCE verifier) for an ID token (200)", st23, 200))
        iv = V.verify_id_token(idt, audience=rp_cid, nonce=login_nonce, trusted_anchors=[pub_b])
        checks.append(("the ID token verifies OFFLINE: B-signed, for this relying party, with its nonce, fresh, trusted",
                       bool(iv.get("token_authentic") and iv.get("audience_matches") and iv.get("nonce_matches") and iv.get("fresh") and iv.get("issuer_trusted")), True))
        checks.append(("the subject is the credential hash and the token value appears nowhere",
                       (idt.get("sub") == V.revocation_leaf(b_tok_value), b_tok_value not in json.dumps(idt)), (True, True)))
        st24, rep = _http_post_form(base_b + "/api/v1/auth/token",
                                    {"grant_type": "authorization_code", "code": auth.get("code", ""), "code_verifier": verifier},
                                    basic=(rp_cid, rp_secret))
        checks.append(("the SAME code exchanged again is refused (invalid_grant): single use", (st24, rep.get("error")), (400, "invalid_grant")))
        st25, _a2 = authorize()
        st26, wrong = _http_post_form(base_b + "/api/v1/auth/token",
                                      {"grant_type": "authorization_code", "code": _a2.get("code", ""), "code_verifier": "w" * 43},
                                      basic=(rp_cid, rp_secret))
        checks.append(("a wrong PKCE verifier is refused (invalid_grant)", (st26, wrong.get("error")), (400, "invalid_grant")))
        st27, _ = authorize(cid=rp_cid + "v")
        checks.append(("a relying party holding only the verify scope cannot use the broker (401)", st27, 401))
        st28, _ = authorize(sig="00" * 64)
        checks.append(("a wrong presentation is uniformly 'not verifiable' (400)", st28, 400))
        st29, _ = authorize(extra={"require_zk": True})
        checks.append(("a step-up the holder cannot meet is refused (403 insufficient_assurance)", st29, 403))
        with _conn(B_DB) as cb, cb.cursor() as cur:
            cur.execute("SELECT count(*) FROM AuthCodeConsumed")
            n_codes = cur.fetchone()[0]
        # a code refused for a wrong verifier is not consumed (refused before the register is
        # touched, so the legitimate party may retry within the window); only the successful
        # exchange left a row, and that row is a code hash and nothing else
        checks.append(("the broker's only record is the consumed code hash of the one successful exchange", n_codes, 1))

        # 6j. THE TRUST LIST (P8.7b) over HTTP: B publishes a signed trust list of every key it
        #     knows (its own, A's as agency 2). B then RECORDS A's key compromised (an append-only
        #     event, effective now); the re-fetched trust list says so, B's registry and manifest
        #     report the real status, and a relying party holding B's trust list REJECTS A's
        #     credential that it accepted a moment ago -- with no change to A at all.
        tl1 = _http_get(base_b + "/api/v1/trust-list/1")[1]
        tlv1 = V.verify_trust_list(tl1, trusted_anchors=[pub_b])
        checks.append(("B's fetched trust list is authentic, fresh, self-consistent and trusted",
                       bool(tlv1.get("trust_list_authentic") and tlv1.get("fresh") and tlv1.get("issuer_trusted")), True))
        checks.append(("it lists A's key (agency 2 on B) as active and B's own key as active",
                       (V.key_status_at(tl1, pub_a), V.key_status_at(tl1, pub_b)), ("active", "active")))
        checks.append(("with that trust list, A's credential is accepted",
                       V.verify_cross_authority(pack, CONTEXT_ID, [b_manifest()], trusted_anchors=[pub_b], trust_list=tl1)["decision"], "accept"))
        with _conn(B_DB) as cb, cb.cursor() as cur:
            cur.execute("INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, algorithm, event, note) VALUES (2, %s, %s, 'registered', 'drill')", (pub_a, ALG_A))
            cur.execute("INSERT INTO AuthorityKeyEvent (agency_id, public_key_hex, algorithm, event, note) VALUES (2, %s, %s, 'compromised', 'drill: A key compromised')", (pub_a, ALG_A))
            cb.commit()
        tl2 = _http_get(base_b + "/api/v1/trust-list/1")[1]
        checks.append(("B records A's key COMPROMISED: the re-fetched trust list says so", V.key_status_at(tl2, pub_a), "compromised"))
        checks.append(("... and A's credential is now REJECTED by a relying party holding B's trust list (A unchanged)",
                       V.verify_cross_authority(pack, CONTEXT_ID, [b_manifest()], trusted_anchors=[pub_b], trust_list=tl2)["decision"], "reject"))
        reg_t = _http_get(base_b + "/api/v1/registry/1")[1]
        checks.append(("B's registry reports A's key status honestly (compromised), no longer a hardcoded active",
                       V.registry_key_status(reg_t, pub_a), "compromised"))
        # P8.8a: the mixed-algorithm federation is reported honestly, key by key.
        checks.append(("A's credential verifies under A's own parameter set (%s)" % ALG_A,
                       V.verify_pack(pack)["signature_valid"] is True and V.verify_pack(pack)["algorithm"] == ALG_A, True))
        checks.append(("B's trust list reports A's key under its real algorithm, B's under its own",
                       sorted({(k["algorithm"]) for k in tl2["keys"] if k["public_key_hex"] in (pub_a, pub_b)}),
                       sorted({ALG_A, ALG_B})))
        checks.append(("B's registry advertises both accepted parameter sets and its own signing one",
                       (sorted(reg_t["instance"]["protocol"]["algorithms"]), reg_t["instance"]["protocol"]["signing_algorithm"]),
                       (["ML-DSA-65", "ML-DSA-87"], ALG_B)))

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
