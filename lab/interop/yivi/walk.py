# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""walk.py -- one presentation from the Yivi app to polaris-oid4vp, captured and judged.

Run by walk.sh, which starts the quick tunnel and hands this the tunnel's https origin. This:
  1. builds the verifier from the persistent PKI (read only) and trusts ONE issuer anchor, the
     pinned Yivi Attestation Providers CA. The Yivi Requestors Root above it also certifies
     relying party certificates, so as an issuer anchor it would let one pass as an issuer; it is
     pinned for the offline comparisons only;
  2. serves the verifier, unchanged, on the loopback and waits until GET <origin>/done answers 200
     through the tunnel, so the 300 s request lifetime starts only once a phone can reach it;
  3. starts one request (DCQL: vct pbdf.sidn-pbdf.email, claim path ["domain"], no value filter),
     writes the request object and the DCQL to the public directory, and shows the launch link
     as a QR code (https://open.yivi.app/-/openid4vp?<query>) and as text;
  4. saves what the wallet posts (the JWE) and its decryption to the PRIVATE directory BEFORE the
     verifier judges it, then lets polaris-oid4vp judge it and records the verdict as it comes;
  5. negative (a): the captured response posted again to the live verifier;
  6. offline, at the recorded instant (`polaris-oid4vp verdict --now`): the configured anchor;
     the Requestors Root alone (a negative); an unrelated root alone (negative (b)); both pinned
     anchors, irmago's own pair (a comparison); and, only when the x5c carries a pinned anchor,
     the pair minus that anchor (HAIP 1.0 6.1.1 keeps the anchor out of x5c).
The public directory gets the request, the verdict with the disclosed value withheld, the x5c
shape (names, usages and DER SHA-256) and the refusals. Before this exits, public_guard checks
it, with the disclosed values (held in memory only) refused as literals. Exit 0 only when the
live verdict is authentic and every negative is refused.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
PACKAGE = HERE.parent.parent.parent / "packages" / "polaris-oid4vp"
sys.path.insert(0, str(PACKAGE))
sys.path.insert(0, str(HERE))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from polaris_oid4vp.cli import parse_claim, verifier_from  # noqa: E402
from polaris_oid4vp.jwe import b64u_decode, decrypt_response  # noqa: E402
from polaris_oid4vp.serve import serve  # noqa: E402

import public_guard  # noqa: E402

#: The two Yivi issuer anchors (Production_Yivi_IssuerTrustAnchor in irmago v1.4.1
#: eudi/trustanchors.go, whose bytes hash to TRUSTANCHORS_GO_SHA256), by the SHA-256 of the DER.
AP_CA = ("yivi-attestation-providers-ca.pem",
         "0c7e79d26737cda146e77bad55f96153604a1445cb5b3417f8ca3b4b9a8cc1bf")
ROOT = ("yivi-requestors-root-ca.pem",
        "7a1576244da5a552df90f27cd4a9d944f6a0d3855a43865f1b195767ef4c1e69")
TRUSTANCHORS_GO_SHA256 = "07d6bc671d4b8bd464f810e1efc47930375b8ca4418965f6d9439fb9f09f00c9"
VCT = "pbdf.sidn-pbdf.email"
CLAIM = '["domain"]'
UNIVERSAL_LINK = "https://open.yivi.app/-/openid4vp"
WITHHELD = "<the presenter's email domain, withheld>"


def say(text):
    print("walk: " + text, flush=True)


def utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def der_sha256(cert):
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def spki(cert):
    return cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)


def load_pinned(name, digest):
    path = HERE / name
    certs = x509.load_pem_x509_certificates(path.read_bytes())
    if len(certs) != 1 or der_sha256(certs[0]) != digest:
        raise SystemExit("walk: %s is not the pinned certificate (DER SHA-256 %s)" % (path, digest))
    return path, certs[0]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def cert_facts(cert):
    """Public facts about a certificate: names, digests and usages, nothing of a holder."""
    facts = {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
             "sha256_der": der_sha256(cert),
             "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
             "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")}
    for name, cls in (("basic_constraints", x509.BasicConstraints), ("key_usage", x509.KeyUsage),
                      ("extended_key_usage", x509.ExtendedKeyUsage),
                      ("subject_alt_name", x509.SubjectAlternativeName)):
        try:
            value = cert.extensions.get_extension_for_class(cls).value
        except x509.ExtensionNotFound:
            facts[name] = None
            continue
        if cls is x509.ExtendedKeyUsage:
            facts[name] = [oid.dotted_string for oid in value]
        elif cls is x509.SubjectAlternativeName:
            facts[name] = ([u for u in value.get_values_for_type(x509.UniformResourceIdentifier)]
                           + ["dns:" + d for d in value.get_values_for_type(x509.DNSName)])
        elif cls is x509.BasicConstraints:
            facts[name] = {"ca": value.ca, "path_length": value.path_length}
        else:
            facts[name] = [k for k in ("digital_signature", "key_cert_sign", "crl_sign")
                           if getattr(value, k)]
    facts["critical_extensions"] = sorted(e.oid.dotted_string for e in cert.extensions if e.critical)
    return facts


def presentation_of(vp_token):
    if not isinstance(vp_token, dict) or len(vp_token) != 1:
        return None
    value = next(iter(vp_token.values()))
    if isinstance(value, list) and value:
        value = value[0]
    return value if isinstance(value, str) else None


def x5c_of(presentation):
    header = json.loads(b64u_decode(presentation.split("~", 1)[0].split(".", 1)[0]))
    chain = header.get("x5c")
    if not isinstance(chain, list):
        return None
    return [x509.load_der_x509_certificate(base64.b64decode(item)) for item in chain]


def unrelated_root(directory):
    """A fresh self-signed CA that has certified nothing: the trust list of negative (b)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "walk unrelated root (negative b)")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    path = directory / "unrelated-root.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path, cert


def offline_verdict(request_path, vp_token_path, anchor_paths, now):
    """`polaris-oid4vp verdict` as a stranger runs it; its verdict fields and exit code only."""
    cmd = [sys.executable, "-m", "polaris_oid4vp.cli", "verdict",
           "--request", str(request_path), "--vp-token", str(vp_token_path), "--now", str(now)]
    for path in anchor_paths:
        cmd += ["--issuer-trust-anchor", str(path)]
    env = dict(os.environ, PYTHONPATH=str(PACKAGE))
    run = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60, cwd=str(PACKAGE))
    try:
        doc = json.loads(run.stdout)
    except ValueError:
        doc = {}
    verdicts = list((doc.get("verdicts") or {}).values())
    verdict = verdicts[0] if len(verdicts) == 1 else {}
    return {"exit": run.returncode, "accepted": doc.get("accepted"),
            "code": verdict.get("code"), "reason": verdict.get("reason")}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pki", required=True, help="the persistent verifier PKI (read only)")
    ap.add_argument("--origin", required=True, help="the tunnel's https origin")
    ap.add_argument("--port", type=int, required=True, help="the loopback port to serve on")
    ap.add_argument("--public-out", required=True)
    ap.add_argument("--private-out", required=True)
    ap.add_argument("--no-open", action="store_true", help="do not open the QR code")
    ap.add_argument("--ready-timeout", type=int, default=240)
    ap.add_argument("--rehearsal-anchor", default=None,
                    help="REHEARSAL ONLY: a stand-in issuer CA added to the trust list")
    ap.add_argument("--rehearsal-wallet", nargs=argparse.REMAINDER, default=None,
                    help="REHEARSAL ONLY: a stand-in wallet command, given the link as its last "
                         "argument in place of the phone")
    args = ap.parse_args()

    public = pathlib.Path(args.public_out)
    private = pathlib.Path(args.private_out)
    public.mkdir(parents=True, exist_ok=True)
    private.mkdir(parents=True, exist_ok=True)
    os.chmod(private, 0o700)

    ap_ca_path, ap_ca = load_pinned(*AP_CA)
    root_path, root = load_pinned(*ROOT)
    configured = [ap_ca_path]
    anchors = [ap_ca]
    if args.rehearsal_anchor is not None:
        configured.append(pathlib.Path(args.rehearsal_anchor))
        anchors += x509.load_pem_x509_certificates(pathlib.Path(args.rehearsal_anchor).read_bytes())
    say("issuer trust: %s" % "; ".join("%s (DER SHA-256 %s)" % (c.subject.rfc4514_string(),
                                                                der_sha256(c)) for c in anchors))

    verifier = verifier_from(pathlib.Path(args.pki), "localhost", args.port,
                             issuer_trust_anchors=anchors, public_base_url=args.origin,
                             claims=[parse_claim(CLAIM)], vct_values=[VCT])
    say("client_id %s" % verifier.client_id)

    state = {"fetches": [], "posts": [], "session": None, "withheld": set()}
    done = threading.Event()
    lock = threading.Lock()
    original_request_object = verifier.request_object
    original_handle = verifier.handle_direct_post

    def request_object(st, wallet_nonce=None, wallet_metadata=None):
        jar = original_request_object(st, wallet_nonce=wallet_nonce,
                                      wallet_metadata=wallet_metadata)
        method = "POST" if wallet_nonce is not None else "GET"
        with lock:
            state["fetches"].append({"at": utc(time.time()), "method": method, "served": bool(jar)})
        say("request object fetched (%s), served=%s" % (method, bool(jar)))
        return jar

    def handle_direct_post(form):
        now = time.time()
        tag = "post%d" % len(state["posts"])
        # The capture first, before the verifier reads a byte of it.
        write_json(private / ("%s-form.json" % tag), dict(form))
        token = (form.get("response") or [""])[0]
        body = None
        if token and state["session"] is not None:
            try:
                body = decrypt_response(token, state["session"].enc_key)
            except Exception as exc:  # noqa: BLE001  recorded; the verifier still judges it
                say("%s: did not decrypt here (%s)" % (tag, type(exc).__name__))
        if body is not None:
            write_json(private / ("%s-decrypted.json" % tag), body)
            if "vp_token" in body:
                write_json(private / ("%s-vp_token.json" % tag), body["vp_token"])
        entry = {"at": utc(now), "at_posix": now, "form_keys": sorted(form),
                 "decrypted": body is not None}
        if form.get("error"):
            entry["wallet_error"] = (form.get("error") or [""])[0]
        if body is not None and body.get("error") is not None:
            entry["wallet_error"] = str(body.get("error"))
        status, out, verdict = original_handle(form)
        entry["status"] = status
        if verdict is not None:
            entry["verdict"] = {"authentic": verdict.authentic, "code": verdict.code,
                                "reason": verdict.reason,
                                "issuer_subject": getattr(verdict, "issuer_subject", None),
                                "issuer_anchor": getattr(verdict, "issuer_anchor", None)}
            claims = verdict.claims if isinstance(verdict.claims, dict) else {}
            disclosed = sorted(getattr(verdict, "disclosed", ()) or (), key=repr)
            if verdict.authentic:
                top = {p[0] for p in disclosed if p}
                entry["verdict"]["selectively_disclosed"] = ["/".join(map(str, p)) for p in disclosed]
                entry["verdict"]["domain"] = WITHHELD if "domain" in claims else None
                entry["verdict"]["values"] = {k: claims[k] for k in ("iss", "vct") if k in claims}
                entry["verdict"]["always_visible"] = sorted(k for k in claims if k not in top)
                with lock:
                    for name in top:
                        if isinstance(claims.get(name), str):
                            state["withheld"].add(claims[name])
        with lock:
            state["posts"].append(entry)
        say("%s: <- %d %s" % (tag, status, "authentic" if verdict is not None and verdict.authentic
                              else "refused: %s: %s" % (getattr(verdict, "code", None),
                                                        getattr(verdict, "reason", None))))
        done.set()
        return status, out, verdict

    verifier.request_object = request_object
    verifier.handle_direct_post = handle_direct_post

    httpd = serve(verifier, host="127.0.0.1", port=args.port, certfile=None, keyfile=None)
    say("serving on 127.0.0.1:%d, advertised as %s" % (args.port, args.origin))
    try:
        return walk(args, verifier, state, done, public, private, configured, ap_ca_path,
                    root_path, (ap_ca, root))
    finally:
        httpd.shutdown()
        httpd.server_close()


def walk(args, verifier, state, done, public, private, configured, ap_ca_path, root_path, pinned):
    # The tunnel must answer before the request's lifetime starts.
    deadline = time.time() + args.ready_timeout
    ready = False
    while time.time() < deadline and not ready:
        try:
            with urllib.request.urlopen(args.origin.rstrip("/") + "/done", timeout=10) as r:
                ready = r.status == 200
        except (urllib.error.URLError, OSError):
            pass
        if not ready:
            time.sleep(2)
    if not ready:
        say("FAILED: %s/done did not answer 200 within %d s" % (args.origin, args.ready_timeout))
        return 1
    say("the tunnel answers: GET %s/done -> 200" % args.origin)

    session, jar = verifier.new_request()
    state["session"] = session
    started = time.time()
    request_path = public / "request-object.jwt"
    request_path.write_text(jar + "\n", encoding="ascii")
    head, payload, _ = jar.split(".")
    request_claims = json.loads(b64u_decode(payload))
    write_json(public / "dcql.json", request_claims["dcql_query"])
    query = urllib.parse.urlencode(verifier.authorization_request_params(session))
    link = "%s?%s" % (UNIVERSAL_LINK, query)
    (public / "launch-link.txt").write_text(link + "\n", encoding="ascii")
    say("request started at %s; it expires at %s (%d s)"
        % (utc(started), utc(started + verifier.request_ttl_seconds), verifier.request_ttl_seconds))
    say("the link (and the QR code):\n\n  %s\n" % link)
    say("the same, as openid4vp://:\n\n  openid4vp://?%s\n" % query)

    if args.rehearsal_wallet:
        say("REHEARSAL: a stand-in wallet answers in place of the phone")
        wallet = subprocess.run(list(args.rehearsal_wallet) + [link], capture_output=True,
                                text=True, timeout=120)
        for line in (wallet.stdout + wallet.stderr).splitlines():
            say("  stand-in: " + line)
    else:
        png = private / "qr.png"
        subprocess.run(["qrencode", "-o", str(png), "-s", "16", "-m", "4", "-l", "M", link],
                       check=True)
        if not args.no_open:
            subprocess.run(["open", str(png)], check=False)
        say("QR code opened: %s" % png)

    remaining = started + verifier.request_ttl_seconds + 5 - time.time()
    say("waiting up to %d s for the presentation" % max(0, int(remaining)))
    result = {"rehearsal": args.rehearsal_wallet is not None, "client_id": verifier.client_id,
              "issuer_trust": [cert_facts(c) for c in x509.load_pem_x509_certificates(
                  b"".join(p.read_bytes() for p in configured))],
              "trustanchors_go_sha256": TRUSTANCHORS_GO_SHA256,
              "request": {"vct_values": [VCT], "claims": [json.loads(CLAIM)],
                          "response_mode": request_claims.get("response_mode"),
                          "lifetime_s": verifier.request_ttl_seconds,
                          "started": utc(started)},
              "fetches": state["fetches"]}
    if not done.wait(timeout=max(1, remaining)):
        say("FAILED: no presentation within the request lifetime")
        result["live_verdict"] = None
        write_json(public / "result.json", result)
        return 1
    time.sleep(0.5)
    live = dict(state["posts"][0])
    at = live.pop("at_posix")
    result["live_verdict"] = dict(live.pop("verdict", None) or {}, status=live["status"],
                                  at=live["at"])
    if "wallet_error" in live:
        result["live_verdict"]["wallet_error"] = live["wallet_error"]

    # Negative (a): the same response again, to the live verifier.
    form = json.loads((private / "post0-form.json").read_text())
    data = urllib.parse.urlencode(form, doseq=True).encode("ascii")
    req = urllib.request.Request("http://127.0.0.1:%d/response" % args.port, data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            replay_status = r.status
    except urllib.error.HTTPError as exc:
        replay_status = exc.code
    time.sleep(0.2)
    replay = (state["posts"][1] if len(state["posts"]) > 1 else {}).get("verdict") or {}
    result["negative_a_replay"] = {"status": replay_status, "authentic": replay.get("authentic"),
                                   "code": replay.get("code"), "reason": replay.get("reason")}
    say("negative (a), the response replayed: <- %d %s: %s"
        % (replay_status, replay.get("code"), replay.get("reason")))

    # What the app sent, and the offline verdicts at the recorded instant.
    vp_token_path = private / "post0-vp_token.json"
    offline = {}
    if vp_token_path.exists():
        pres = presentation_of(json.loads(vp_token_path.read_text()))
        x5c = x5c_of(pres) if pres else None
        result["x5c"] = [cert_facts(c) for c in x5c] if x5c is not None else None
        if x5c is not None:
            say("the x5c: %s" % " <- ".join(c.subject.rfc4514_string() for c in x5c))
            say("leaf extended key usage: %s" % (result["x5c"][0]["extended_key_usage"],))
        unrelated_path, unrelated = unrelated_root(private)
        runs = [("configured", configured),
                ("root_only", [root_path]),
                ("unrelated_root", [unrelated_path]),
                ("irmago_pair", [ap_ca_path, root_path])]
        carried = [c for c in pinned if x5c is not None and spki(c) in {spki(s) for s in x5c}]
        if carried:
            keep = [p for p, c in zip((ap_ca_path, root_path), pinned) if c not in carried]
            runs.append(("irmago_pair_minus_carried", keep))
            offline["dropped_from_pair"] = [c.subject.rfc4514_string() for c in carried]
        for name, paths in runs:
            offline[name] = offline_verdict(request_path, vp_token_path, paths, int(at))
            offline[name]["trust_list"] = [x509.load_pem_x509_certificates(p.read_bytes())[0]
                                           .subject.rfc4514_string() for p in paths]
            say("offline %s: accepted=%s %s: %s" % (name, offline[name]["accepted"],
                                                   offline[name]["code"], offline[name]["reason"]))
        offline["unrelated_root_sha256_der"] = der_sha256(unrelated)
        offline["at"] = utc(int(at))
    else:
        say("no vp_token was captured, so nothing can be judged offline")
        result["x5c"] = None
    result["offline"] = offline
    write_json(public / "result.json", result)

    withheld = sorted(state["withheld"])
    leaks = public_guard.check_dir(public, withheld=withheld)
    if leaks:
        say("FAILED: the public files carry holder data; moved to the private directory: %s"
            % [p.split(":")[0] for p in leaks])
        for path in sorted(public.iterdir()):
            path.rename(private / ("quarantined-" + path.name))
        return 1
    say("public files checked: no disclosure, SD-JWT, KB-JWT, holder key, _sd list, email, or "
        "the %d disclosed value(s)" % len(withheld))

    live_ok = bool(result["live_verdict"].get("authentic"))
    refused = {"negative (a) replay": replay_status >= 400 and not replay.get("authentic"),
               "root only": (offline.get("root_only") or {}).get("accepted") is False,
               "negative (b) unrelated root": (offline.get("unrelated_root") or {}).get("accepted") is False}
    say("live verdict authentic: %s; refused: %s" % (live_ok, ", ".join(
        "%s %s" % (k, v) for k, v in refused.items())))
    return 0 if live_ok and all(refused.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
