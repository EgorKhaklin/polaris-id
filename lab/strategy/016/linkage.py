# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""linkage.py: record 016, lab step 1. What can verifiers link: one wallet copy, or a batch?

    python3 lab/strategy/016/linkage.py [--verifiers 8]

Builds real wallet copies with polaris_web/wallet_copy.py and the test PKI, and gives each of N
verifiers one presentation disclosing only age_over_18, the minimal request. For each scenario it
reports which observable values every verifier saw identically (and so links them):

  A. today: one copy, presented to all N verifiers;
  B. a batch: N copies, one per verifier, each with its own holder key, an independent status
     index drawn from the whole list, its own signature, and iat rounded to the day.

Falsifier 1 of record 016 is checked on B.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import pathlib
import secrets
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "polaris_web"))


def b64(data):
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(s):
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def main(argv):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--verifiers", type=int, default=8)
    a = ap.parse_args(argv)
    from cryptography.hazmat.primitives.asymmetric import ec
    import credential_copy_keys
    import wallet_copy as wc

    issuer = "https://issuer.polaris.example"
    tmp = tempfile.TemporaryDirectory()
    spec = importlib.util.spec_from_file_location("pki", ROOT / "scripts" / "polaris-credential-copy-test-pki.py")
    pki = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pki)
    written = pki.make(pathlib.Path(tmp.name), 7, issuer)
    key = credential_copy_keys.load_from_files(7, written["key"], written["chain"])
    claims = wc.claims_for("Ada Test", datetime.date(2001, 3, 4), "US-PA", datetime.date(2026, 10, 5))
    status_uri = issuer + "/status/2026-10-05/0"
    now = int(time.time())

    def holder():
        n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}

    def present(copy):
        """What a verifier keeps from a presentation disclosing age_over_18 only."""
        jws, *disclosures = [p for p in copy.split("~") if p]
        head, body, sig = jws.split(".")
        payload = json.loads(unb64(body))
        shown = [d for d in disclosures if json.loads(unb64(d))[1] == "age_over_18"]
        return {
            "holder key (cnf)": hashlib.sha256(json.dumps(payload["cnf"], sort_keys=True).encode()).hexdigest(),
            "status index": payload["status"]["status_list"]["idx"],
            "signature": sig,
            "iat": payload["iat"],
            "exp": payload["exp"],
            "disclosed value": json.loads(unb64(shown[0]))[2],
            "issuer": payload["iss"],
        }

    def shared(observations):
        return {k for k in observations[0] if len({json.dumps(o[k]) for o in observations}) == 1}

    # A. Today: one copy, every verifier.
    one = wc.build_copy(key, issuer, claims, holder(), now, now + 30 * 86400, secrets.randbelow(wc.STATUS_LIST_SIZE), status_uri)
    a_obs = [present(one) for _ in range(a.verifiers)]
    # B. A batch: one copy per verifier.
    day = now - now % 86400
    b_obs = [present(wc.build_copy(key, issuer, claims, holder(), day, day + 30 * 86400,
                                   secrets.randbelow(wc.STATUS_LIST_SIZE), status_uri))
             for _ in range(a.verifiers)]

    a_shared, b_shared = shared(a_obs), shared(b_obs)
    print("%d verifiers, each shown one presentation disclosing age_over_18 only\n" % a.verifiers)
    print("%-20s %-28s %s" % ("observable", "A: one copy (today)", "B: a batch, one each"))
    for k in a_obs[0]:
        print("%-20s %-28s %s" % (k, "same at every verifier" if k in a_shared else "differs",
                                  "same at every verifier" if k in b_shared else "differs"))
    linking = {"holder key (cnf)", "status index", "signature"}
    fine_time = b_obs[0]["iat"] % 86400 != 0
    ok = not (linking & b_shared) and not fine_time
    print("\nA links the holder by: %s" % ", ".join(sorted(a_shared & (linking | {"iat", "exp"}))))
    print("B shares only: %s (the issuer, the day, and the disclosed value: what every holder of"
          " that day and answer shares)" % ", ".join(sorted(b_shared)))
    print("\nRESULT: falsifier 1 %s" % ("held: no copy in the batch shares a key, an index or a "
                                        "signature, and no timestamp is finer than the day" if ok
                                        else "FAILED"))
    tmp.cleanup()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
