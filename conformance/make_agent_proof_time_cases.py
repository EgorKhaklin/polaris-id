#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Generate the agent-proof time cases (1.1.0).

An agent proof's issued_at is signed. The detached verifier holds it to the grant's window,
[issued_at, expires_at), and to at most 60 seconds ahead of its clock; until 1.1.0 neither SDK
read it, and no published case asked, because every published proof was made inside its
grant's window. These cases ask, each on a grant that is fresh at the case's clock:

    window-start    made at the instant the grant begins: proves
    skew-limit      dated 60 seconds ahead of the clock: proves
    ahead-of-clock  dated 61 seconds ahead: proves nothing
    before-grant    made one second before the grant: proves nothing
    at-lapse        made at the grant's expires_at: proves nothing

Fresh keys; every expected value is checked against the detached verifier and the Python SDK
before anything is written. Never modifies a published vector: it refuses to run when any of
its files exists, because a rerun signs with new keys.

    python3 conformance/make_agent_proof_time_cases.py
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors"
CASES = ROOT / "conformance" / "cases.json"
VEC = "conformance/vectors/"
SINCE = "1.1.0"
GID = "conformance-proof-time-0001"
NONCE = "svc-proof-time-1"


def main():
    # Before any key is made, and without liboqs: every file this writes is agent-proof-time-*.
    existing = sorted(p.name for p in OUT.glob("agent-proof-time-*.json"))
    if existing:
        print("refusing: %d of these vectors are published (%s); a rerun would re-sign them with new keys"
              % (len(existing), ", ".join(existing)), file=sys.stderr)
        return 2
    try:
        import oqs  # type: ignore
    except Exception as e:  # noqa: BLE001
        print("needs liboqs-python: %s" % e, file=sys.stderr)
        return 3
    spec = importlib.util.spec_from_file_location("polaris_verify_script", ROOT / "scripts" / "polaris-verify.py")
    V = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(V)
    sys.path.insert(0, str(ROOT / "sdk" / "python"))
    import polaris_verify as P  # noqa: E402

    def kp():
        with oqs.Signature("ML-DSA-65") as s:
            return bytes(s.generate_keypair()), bytes(s.export_secret_key())

    def sign(sk, d):
        with oqs.Signature("ML-DSA-65", secret_key=sk) as s:
            return bytes(s.sign(d))

    hol_pk, hol_sk = kp()
    agt_pk, agt_sk = kp()
    grant = {"format": "polaris-agent-grant/1", "grant_id": GID,
             "agent_public_key_hex": agt_pk.hex(), "agent_algorithm": "ML-DSA-65",
             "actions": ["read:status"], "limits": {"max_uses": 3}, "context_id": 1,
             "issued_at": "2026-05-01T00:00:00Z", "expires_at": "2026-05-01T06:00:00Z",
             "algorithm": "ML-DSA-65"}
    grant["signature_hex"] = sign(hol_sk, hashlib.sha3_256(V._agent_grant_canonical(grant)).digest()).hex()
    grant["public_key_hex"] = hol_pk.hex()
    files = {"agent-proof-time-grant.json": grant}
    cases = []

    def case(label, made, now, proved, note):
        p = {"format": "polaris-agent-proof/1", "grant_id": GID, "action": "read:status",
             "service_nonce": NONCE, "issued_at": made, "algorithm": "ML-DSA-65"}
        p["signature_hex"] = sign(agt_sk, hashlib.sha3_256(V._agent_proof_canonical(p)).digest()).hex()
        p["public_key_hex"] = agt_pk.hex()
        files["agent-proof-time-%s.json" % label] = p
        cases.append({"name": "agent-grant-use-proof-" + label, "artifact": "agent-grant-use",
                      "grant_file": VEC + "agent-proof-time-grant.json", "now": now,
                      "proof_file": VEC + "agent-proof-time-%s.json" % label,
                      "requested_action": "read:status", "expected_nonce": NONCE,
                      "expect": {"authentic": True, "fresh": True, "action_in_scope": True, "agent_proved": proved},
                      "since": SINCE, "note": note})

    case("window-start", "2026-05-01T00:00:00Z", "2026-05-01T00:00:30Z", True,
         "The positive control: a proof made at the instant the grant begins. The window includes its start.")
    case("skew-limit", "2026-05-01T00:01:30Z", "2026-05-01T00:00:30Z", True,
         "A proof dated 60 seconds ahead of this verifier's clock, the skew a verifier allows: it proves.")
    case("ahead-of-clock", "2026-05-01T00:01:31Z", "2026-05-01T00:00:30Z", False,
         "A proof dated 61 seconds ahead of this verifier's clock proves nothing. The case's now is "
         "the clock: a verifier reading its own machine's clock instead accepts it.")
    case("before-grant", "2026-04-30T23:59:59Z", "2026-05-01T00:00:30Z", False,
         "A proof made one second before the grant existed proves nothing: a grant authorizes what "
         "the agent does inside its window.")
    case("at-lapse", "2026-05-01T06:00:00Z", "2026-05-01T05:59:30Z", False,
         "A proof made at the grant's expires_at, while the grant is still fresh at this clock. The "
         "window is [issued_at, expires_at), so a proof made at its end proves nothing.")

    # Every expected value, against the detached verifier and the Python SDK, before writing.
    for c in cases:
        g, pr = grant, files[c["proof_file"][len(VEC):]]
        dv = V.verify_agent_grant(g, now=c["now"], requested_action=c["requested_action"], agent_proof=pr,
                                  expected_nonce=c["expected_nonce"])
        sg = P.verify_signed_artifact(g, now=c["now"])
        s = bool(P.verify_signed_artifact(pr, now=c["now"]).authentic
                 and P.agent_proof_proves(pr, g, c["requested_action"], c["expected_nonce"], c["now"]))
        e = c["expect"]
        got = (dv["agent_proved"] is True, s, dv["grant_authentic"] is True, sg.authentic, sg.fresh,
               dv["action_in_scope"] is True)
        want = (e["agent_proved"],) * 2 + (True,) * 4
        if got != want:
            print("a verifier disagrees with %s: %r, expected %r" % (c["name"], got, want), file=sys.stderr)
            return 1

    for name, o in files.items():
        (OUT / name).write_text(json.dumps(o, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    mine = {c["name"] for c in cases}
    doc["cases"] = [c for c in doc["cases"] if c.get("name") not in mine] + cases
    CASES.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote %d vectors and %d cases (total %d)" % (len(files), len(cases), len(doc["cases"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
