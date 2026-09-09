#!/usr/bin/env python3
"""
polaris-presentation-drill.py -- the wallet's presentation and its QR/NFC transfer, run (P8.6).

A holder's presentation -- the issuer-signed credential with a stapled issuer-signed status
assertion -- is decided OFFLINE by a verifier, and it travels as digest-tied polaris-qr/1
frames. This drill builds a real presentation under real ML-DSA-65 keys and drives:

  - the presentation is usable offline (credential authentic, issuer trusted, assertion
    authentic + fresh + ACTIVE + bound to this credential);
  - framing: several frames under the byte budget, reassembled in ANY order; a missing frame,
    a frame from another transfer, and an altered chunk are refused before parsing;
  - a stapled assertion for ANOTHER credential is not bound; an expired one is not fresh; a
    REVOKED status is not active; no assertion means not decidable offline;
  - a presentation code is reported present and never interpreted (duress-indistinguishable);
  - the WALLET round trip: enroll, `present --qr --status-assertion`, decode with the detached
    verifier's `--qr-frames` -- exit 0;
  - hostile input does not crash the verifier.

Red (exit 1) on any wrong verdict. Needs liboqs + cryptography.

    python3 scripts/polaris-presentation-drill.py
"""
import importlib.util
import json
import os
import random
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

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
        print("presentation drill needs the app's pqc_signing (and liboqs): %s" % e, file=sys.stderr)
        return 3
    if not (pqc_signing.is_available() and pqc_signing.second_witness_available()):
        print("presentation drill needs real ML-DSA (liboqs + cryptography); skipping", file=sys.stderr)
        return 3

    V = _load_verifier()
    tmp = tempfile.mkdtemp(prefix="polaris-presentation-")
    now = datetime.now(timezone.utc)

    def issuer(name):
        kp = pqc_signing.generate_keypair()
        kf = os.path.join(tmp, "%s.key.json" % name)
        with open(kf, "w") as f:
            json.dump(kp, f)
        return {"name": name, "key_file": kf, "key_hex": kp["public_key_hex"]}

    ISS, STRANGER = issuer("issuer"), issuer("stranger")

    def pack(tv, who=ISS):
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = who["key_file"]
        sig, alg, pk = pqc_signing.signature_with_key_for_token(tv)
        return {"format": "polaris-authenticity-pack/1", "token_value": tv, "algorithm": alg,
                "signature_hex": sig.hex(), "public_key_hex": pk}

    def assertion(tv, status="ACTIVE", issued=None, ttl_hours=1, who=ISS):
        issued = issued or now
        a = {"format": "polaris-status-assertion/1", "token_value": tv, "status": status,
             "issued_at": _iso(issued), "expires_at": _iso(issued + timedelta(hours=ttl_hours))}
        os.environ["POLARIS_PQC_SIGNING_KEY_FILE"] = who["key_file"]
        sig, alg, pk = pqc_signing.signature_over_message(V._status_assertion_canonical(a))
        a.update({"algorithm": alg, "signature_hex": sig.hex(), "public_key_hex": pk})
        return a

    TV = "TKN-PRESENT-0001"
    cred = pack(TV)
    good = {"format": "polaris-presentation/1", "credential": cred, "presented_code": None,
            "status_assertion": assertion(TV), "context_id": 1, "disclosure_level": "ZERO_KNOWLEDGE"}
    frames = V.encode_presentation_frames(good, frame_bytes=1800)
    shuffled = list(frames); random.Random(7).shuffle(shuffled)
    other = V.encode_presentation_frames(dict(good, presented_code="other-transfer"), frame_bytes=1800)
    altered = list(frames); altered[0] = altered[0][:-2] + ("ab" if not altered[0].endswith("ab") else "cd")
    decoded, _ = V.decode_presentation_frames(shuffled)
    vd = V.verify_presentation(decoded or {}, anchor_keys=[ISS["key_hex"]], expected_context=1)

    def usable(p, **k):
        return V.verify_presentation(p, anchor_keys=[ISS["key_hex"]], **k)["usable_offline"]

    # the wallet round trip
    wdir = os.path.join(tmp, "wallet"); os.makedirs(wdir)
    pack_path, sa_path, frames_path = os.path.join(tmp, "pack.json"), os.path.join(tmp, "status.json"), os.path.join(tmp, "frames.txt")
    json.dump(cred, open(pack_path, "w")); json.dump(assertion(TV), open(sa_path, "w"))
    anchor_path = os.path.join(tmp, "anchor.json"); json.dump({"public_key_hex": ISS["key_hex"]}, open(anchor_path, "w"))
    wallet = [sys.executable, os.path.join(_ROOT, "scripts", "polaris-wallet.py"), "--wallet", wdir]
    enroll = subprocess.run(wallet + ["enroll", "--pack", pack_path], capture_output=True, text=True)
    present = subprocess.run(wallet + ["present", "--status-assertion", sa_path, "--context", "1", "--qr", "--out", frames_path],
                             capture_output=True, text=True)
    decide = subprocess.run([sys.executable, os.path.join(_ROOT, "scripts", "polaris-verify.py"), "--qr-frames", frames_path,
                             "--issuer-anchor", anchor_path, "--context", "1", "--json"], capture_output=True, text=True)
    try:   # the oqs import may print a notice ahead of the JSON verdict; parse from the first brace
        cli_verdict = json.loads(decide.stdout[decide.stdout.find("{"):])
    except ValueError:
        cli_verdict = {}

    # v9.335: resource bounds. Frames are built by hand around hostile payloads: a decompression
    # bomb (64 MiB of zeros compresses to ~64 KiB, inside the compressed bound, so only an
    # output-limited decompressor refuses it), an incompressible oversized payload, and a flood
    # of frames. Each is refused with a bound named, in well under a second.
    import base64
    import hashlib
    import time
    import zlib

    def hand_frames(raw_payload_bytes, chunk=1500):
        payload = base64.urlsafe_b64encode(zlib.compress(raw_payload_bytes, 9)).rstrip(b"=").decode("ascii")
        digest = hashlib.sha3_256(payload.encode("ascii")).hexdigest()
        chunks = [payload[i:i + chunk] for i in range(0, len(payload), chunk)]
        return ["PLRS1/%d/%d/%s/%s" % (len(chunks), i, digest, c) for i, c in enumerate(chunks)]

    t0 = time.monotonic()
    bomb_frames = hand_frames(b"\0" * (64 * 1024 * 1024))
    bomb = V.decode_presentation_frames(bomb_frames)
    bomb_seconds = time.monotonic() - t0
    big = V.decode_presentation_frames(hand_frames(os.urandom(1024 * 1024)))
    flood = V.decode_presentation_frames(["PLRS1/9999/0/00/x"] * 25000)

    checks = [
        ("a DECOMPRESSION BOMB (64 MiB of zeros in %d frames) is refused at the decompressed-size bound" % len(bomb_frames),
         (bomb[0], "decompressed-size bound" in (bomb[1] or "")), (None, True)),
        ("... and refused quickly (under two seconds), the inflater stopping at the limit", bomb_seconds < 2.0, True),
        ("an incompressible 1 MiB payload is refused at the compressed-size bound before hashing",
         (big[0], "compressed-size bound" in (big[1] or "")), (None, True)),
        ("a flood of frames is refused before any parsing", (flood[0], "too many frames" in (flood[1] or "")), (None, True)),
        ("the presentation is USABLE OFFLINE: credential authentic, issuer trusted, assertion bound + fresh + ACTIVE",
         vd["usable_offline"], True),
        ("it travels as several frames, each under the 1800-byte budget",
         (len(frames) >= 2, max(len(f) for f in frames) <= 1800), (True, True)),
        ("the frames reassemble in ANY order to the same presentation", decoded == good, True),
        ("a missing frame is refused before parsing", V.decode_presentation_frames(frames[1:])[0], None),
        ("a frame from ANOTHER transfer mixed in is refused", V.decode_presentation_frames(frames[:-1] + [other[-1]])[0], None),
        ("an altered chunk is refused (payload digest)", V.decode_presentation_frames(altered)[0], None),
        ("a stapled assertion for ANOTHER credential is not bound",
         usable(dict(good, status_assertion=assertion("TKN-OTHER-0002"))), False),
        ("an EXPIRED assertion is not fresh", usable(dict(good, status_assertion=assertion(TV, issued=now - timedelta(days=2)))), False),
        ("a REVOKED status is not active", usable(dict(good, status_assertion=assertion(TV, status="REVOKED"))), False),
        ("an assertion signed by a STRANGER is not bound to this issuer", usable(dict(good, status_assertion=assertion(TV, who=STRANGER))), False),
        ("no assertion: authentic but not decidable offline",
         (V.verify_presentation(dict(good, status_assertion=None))["credential_authentic"], usable(dict(good, status_assertion=None))), (True, False)),
        ("a wrong expected context is refused", usable(good, expected_context=2), False),
        ("a presentation code is reported present and NEVER interpreted (duress-indistinguishable)",
         (V.verify_presentation(dict(good, presented_code="1234"), anchor_keys=[ISS["key_hex"]])["presented_code_present"],
          usable(dict(good, presented_code="1234"))), (True, True)),
        ("WALLET round trip: enroll, present --qr --status-assertion, decide with the detached verifier (exit 0)",
         (enroll.returncode, present.returncode, decide.returncode), (0, 0, 0)),
        ("... and the CLI verdict is usable offline", cli_verdict.get("usable_offline"), True),
        ("hostile input does not crash the verifier",
         (V.verify_presentation("nope")["usable_offline"], V.decode_presentation_frames(["junk"])[0]), (False, None)),
    ]

    print("case                                                                       got        expected   ok")
    ok_all = True
    for label, got, expected in checks:
        ok = got == expected
        ok_all = ok_all and ok
        print("  %-72s %-10s %-10s %s" % (label, str(got), str(expected), "OK" if ok else "WRONG"))
    if not ok_all:
        print("  wallet stderr: %s\n  verify stderr: %s" % (present.stderr[-300:], decide.stderr[-300:]))
    if ok_all:
        print("\nOK: a holder's presentation -- credential plus stapled status assertion -- is decided offline under real "
              "ML-DSA-65, travels as digest-tied QR frames reassembled in any order and refused when mixed, missing or "
              "altered, refuses an unbound, stale, revoked or stranger-signed assertion, never interprets a presentation "
              "code, and round-trips through the wallet and the detached verifier's CLI.")
        return 0
    print("\nFAIL: a presentation verdict was wrong.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
