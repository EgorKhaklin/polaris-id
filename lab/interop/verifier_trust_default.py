#!/usr/bin/env python3
"""verifier_trust_default.py -- what does an integrator learn when no trust root is given?

RAISED BY AN OUTSIDE REVIEWER, 2026-09-17: the detached verifier computes

    accept = (a["signature_valid"] and a.get("issuer_trusted") in (None, True) and ...)

so `issuer_trusted = None` is ACCEPTED. `None` happens when the caller passes no
`--issuer-anchor`. Is that a deliberate "you did not ask me to judge the issuer", or a
default that fails open?

IT IS DELIBERATE, and defensible. Without a trust root there is no opinion to have: the
verifier can say the signature is genuine against the key shipped beside it, and nothing
about whether that key belongs to anyone you trust. Refusing to answer at all would make the
tool useless for the case where authenticity is the only question.

THE QUESTION IS THEREFORE NOT THE VERDICT BUT ITS LEGIBILITY. `polaris-verify` is a CLI, and
a CLI is integrated through its EXIT CODE far more often than through its JSON. So this runs
the same genuine pack three ways and records what an integrator can actually distinguish.

    no --issuer-anchor          nobody asked about the issuer
    an anchor set WITHOUT it    a genuine signature by an untrusted key
    an anchor set WITH it       the case everyone wants

WHY IT MATTERS HERE RATHER THAN IN GENERAL. The package's own contract already refuses this
shape of silent default one field over: the verifier will not run until the caller names its
cryptography, and the code says why, that "the mode a run uses is something the caller states,
not something the machine's installed packages decide for them." There is no
environment-variable downgrade on that path. The trust root is the same kind of decision and
is optional.

Needs the vectors in this repository, so it runs from a checkout rather than from an install.

Run: python3 lab/interop/verifier_trust_default.py
"""
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "packages" / "polaris-verify" / "polaris_verify_cli" / "verifier.py"
PACK = ROOT / "vectors" / "ml-dsa-65-valid.json"
OTHER = ROOT / "vectors" / "ml-dsa-65-wrong-key.json"


def _run(anchor_path):
    cmd = [sys.executable, str(VERIFIER), "--pack", str(PACK),
           "--pqc-provider", "auto", "--json"]
    if anchor_path:
        cmd += ["--issuer-anchor", str(anchor_path)]
    r = subprocess.run(cmd, capture_output=True)
    out = (r.stdout or b"").decode("utf-8", "replace")
    start = out.find("{")
    if start < 0:
        return None, r.returncode, out.strip().splitlines()[-1:] or [""]
    return json.loads(out[start:]), r.returncode, None


def main():
    for p in (VERIFIER, PACK, OTHER):
        if not p.exists():
            print("missing %s; this runs from a checkout" % p, file=sys.stderr)
            return 3

    signer = json.loads(PACK.read_text())["public_key_hex"]
    stranger = json.loads(OTHER.read_text())["public_key_hex"]

    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "with.json").write_text(json.dumps([signer]))
        (d / "without.json").write_text(json.dumps([stranger]))

        cases = [("no --issuer-anchor", None),
                 ("anchor set WITHOUT the signer", d / "without.json"),
                 ("anchor set WITH the signer", d / "with.json")]
        rows = []
        for label, anchor in cases:
            verdict, code, err = _run(anchor)
            if verdict is None:
                print("== VOID: no JSON verdict for %r (exit %d): %s =="
                      % (label, code, err), file=sys.stderr)
                return 1
            rows.append((label, verdict, code))

    print("the SAME genuine pack, three ways:\n")
    print("%-32s %-8s %-12s %-16s %s"
          % ("case", "sig", "authenticity", "issuer_trusted", "exit"))
    for label, v, code in rows:
        print("%-32s %-8s %-12s %-16s %d"
              % (label, v.get("signature_valid"), v.get("authenticity"),
                 v.get("issuer_trusted"), code))
    print()
    for label, v, _c in rows:
        print("  %-32s note: %s" % (label, v.get("note") or "(none)"))
    print()

    none_row = rows[0]
    untrusted_row = rows[1]
    trusted_row = rows[2]

    # The control. If the verifier did NOT distinguish a genuine-but-untrusted key when it
    # was given a trust root, the finding below would be a much larger one, and this file
    # would be measuring a broken verifier rather than an under-specified default.
    if untrusted_row[1].get("issuer_trusted") is not False or untrusted_row[2] == 0:
        print("== VOID: given an anchor set that excludes the signer, the verifier did not "
              "report issuer_trusted=False with a non-zero exit. The tool is not making the "
              "distinction at all, which is a different and larger finding than this file "
              "was written to measure ==", file=sys.stderr)
        return 1
    print("control: given a trust root that excludes the signer, the verifier reports")
    print("         issuer_trusted=False, says so in `note`, and exits %d. The distinction"
          % untrusted_row[2])
    print("         is made, and made loudly, whenever it is asked for.\n")

    same_exit = none_row[2] == trusted_row[2]
    if not same_exit:
        print("== The no-anchor case exits %d and the trusted case exits %d, so the exit code "
              "already distinguishes them and there is nothing here. =="
              % (none_row[2], trusted_row[2]))
        return 0

    print("== THE VERDICT IS HONEST AND THE EXIT CODE IS NOT. With no trust root the JSON "
          "says `issuer_trusted: null`, which is exactly right and hides nothing. But the "
          "process exits %d, the same as a fully trusted verification, with an empty `note`. "
          "An integrator who shells out and branches on the exit status, which is the usual "
          "way a CLI is integrated, cannot tell 'this key is one I trust' from 'nobody asked "
          "me about the key'. ==" % none_row[2])
    print()
    print("WHAT THIS DOES AND DOES NOT SAY. It is not a claim that the verifier lies: the "
          "field is present and null, and a caller reading the JSON has everything. Nor is it "
          "a claim that accepting without a trust root is wrong, because without one there is "
          "no opinion to have. What it establishes is that the same package makes the "
          "opposite choice one field over, refusing to run until the caller names its "
          "cryptography on the stated grounds that such a mode is 'something the caller "
          "states, not something the machine decides for them', and that the trust root is "
          "the same kind of decision left to a silent default. Whether to require it, or to "
          "give the un-anchored case its own exit code or a `note`, is a change to a "
          "published CLI contract and the owner's call. Nothing here proposes one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
