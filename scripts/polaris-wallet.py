#!/usr/bin/env python3
"""
polaris-wallet.py — the holder's wallet (roadmap PE.7). The FIRST non-operator surface.

Everything else in Polaris is operator-facing: an agency issues, an operator
verifies. This is the other side — a tool a PERSON runs to hold their own
credential as a file, verify it offline, present it to a relying party, and prove
membership in zero knowledge. It is deliberately plain: stdlib plus the detached
verifier (scripts/polaris-verify.py) for offline verification, and the polaris-zk
binary for proofs. It imports NO Polaris server code and touches NO database — a
holder runs it on their own machine.

    polaris-wallet.py enroll --pack credential.json
    polaris-wallet.py show
    polaris-wallet.py verify --issuer-anchor issuer.json
    polaris-wallet.py present --out presentation.json
    polaris-wallet.py prove-membership --epoch epoch.json --out proof.json

The wallet is a directory (default ~/.polaris-wallet, override with --wallet). It
holds the credential (an authenticity pack from GET /api/tokens/<id>/authenticity-pack)
and, optionally, a duress code.

Duress and the vocation: a duress code, presented under coercion, signals distress
silently — the server records it and shows the coercer a normal success. The
vocation-preserving default is NOT to store the code on the device (a seized
wallet would reveal it); type it at presentation with `present --duress --code`.
If you do store it (`enroll --duress-code`), `present` and `present --duress`
produce byte-identical structure so an observer cannot tell which you used — the
only difference is the opaque code value the server matches out of sight.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_WALLET = os.path.join(os.path.expanduser("~"), ".polaris-wallet")


def _load_verifier():
    """The detached verifier (a sibling holder tool), for offline self-verification."""
    spec = importlib.util.spec_from_file_location(
        "polaris_verify", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _leaf_seed(token_id, token_value, context_id):
    """The holder's epoch leaf seed — the SAME derivation the issuer uses:
    SHA3-256("{token_id}|{token_value}|{context_id}")."""
    h = hashlib.sha3_256()
    h.update(("%s|%s|%s" % (token_id, token_value, context_id)).encode("utf-8"))
    return h.hexdigest()


def _wallet_dir(args):
    return args.wallet or _DEFAULT_WALLET


def _cred_path(wallet):
    return os.path.join(wallet, "credential.json")


def _duress_path(wallet):
    return os.path.join(wallet, "duress")


def _load_credential(wallet):
    path = _cred_path(wallet)
    if not os.path.isfile(path):
        raise SystemExit("no credential held: run 'enroll --pack <pack.json>' first (%s)" % path)
    with open(path) as f:
        return json.load(f)


def cmd_enroll(args):
    wallet = _wallet_dir(args)
    os.makedirs(wallet, exist_ok=True)
    os.chmod(wallet, stat.S_IRWXU)  # 0700 — the holder's own directory
    with open(args.pack) as f:
        pack = json.load(f)
    if pack.get("format") != "polaris-authenticity-pack/1":
        raise SystemExit("that file is not a polaris-authenticity-pack/1")
    with open(_cred_path(wallet), "w") as f:
        json.dump(pack, f, indent=2)
    os.chmod(_cred_path(wallet), stat.S_IRUSR | stat.S_IWUSR)  # 0600
    print("held credential for token %s (issuer %s) in %s"
          % (pack.get("token_value"), pack.get("issuer"), wallet))
    if args.duress_code:
        dp = _duress_path(wallet)
        with open(dp, "w") as f:
            f.write(args.duress_code)
        os.chmod(dp, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        # Deliberately terse: no celebratory confirmation that would advertise, to
        # someone reading over the holder's shoulder, that a duress code exists.
        sys.stderr.write("(a presentation code is stored locally)\n")
    return 0


def cmd_show(args):
    pack = _load_credential(_wallet_dir(args))
    # Never prints the duress code, and does not advertise whether one is set.
    # Authenticity from the pack itself: the explicit flag if present, else a real
    # signature is one under a real algorithm with a public key to check it against.
    real = pack.get("real_signature")
    if real is None:
        real = pack.get("algorithm") == "ML-DSA-65" and bool(pack.get("public_key_hex"))
    print("token:      %s" % pack.get("token_value"))
    print("issuer:     %s" % pack.get("issuer"))
    print("algorithm:  %s" % pack.get("algorithm"))
    print("authentic:  %s" % ("real ML-DSA-65 signature (run 'verify' to check it)" if real
                              else "development placeholder (not authenticatable)"))
    if pack.get("issued_at"):
        print("issued_at:  %s" % pack.get("issued_at"))
    print("token_id:   %s (needed to prove membership)" % pack.get("token_id"))
    return 0


def cmd_verify(args):
    pack = _load_credential(_wallet_dir(args))
    V = _load_verifier()
    anchor = None
    if args.issuer_anchor:
        anchor = V._load_anchor(args.issuer_anchor)
    verdict = V.verify_pack(pack, anchor)
    print("signature_valid: %s" % verdict["signature_valid"])
    if verdict["witnesses"]:
        print("witnesses:       %s" % ", ".join(verdict["witnesses"]))
    if verdict["issuer_trusted"] is not None:
        print("issuer_trusted:  %s" % verdict["issuer_trusted"])
    if verdict["note"]:
        print("note:            %s" % verdict["note"])
    ok = verdict["signature_valid"] and (verdict["issuer_trusted"] in (None, True))
    return 0 if ok else 2


def cmd_present(args):
    """Emit a presentation for a relying party. The structure is IDENTICAL whether
    or not this is a duress presentation — an observer cannot tell which was used;
    only the opaque code value differs, and the server matches it out of sight."""
    wallet = _wallet_dir(args)
    pack = _load_credential(wallet)
    code = args.code
    if args.duress and code is None:
        dp = _duress_path(wallet)
        if os.path.isfile(dp):
            with open(dp) as f:
                code = f.read().strip()
    presentation = {
        "format": "polaris-presentation/1",
        "credential": pack,
        "presented_code": code,
    }
    out = json.dumps(presentation, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out + "\n")
    else:
        sys.stdout.write(out + "\n")
    return 0


def _zk_binary(args):
    return (args.zk_binary or os.environ.get("POLARIS_ZK_BINARY")
            or os.path.join(_ROOT, "polaris_zk", "target", "release", "polaris-zk"))


def cmd_prove_membership(args):
    """Produce a zero-knowledge proof that the held credential's token is in a
    published epoch, without revealing WHICH member it is. The epoch bundle is
    public (its leaf-seed set is the anonymity set); the proof's public inputs are
    the root and the binding, never the holder's index."""
    wallet = _wallet_dir(args)
    pack = _load_credential(wallet)
    with open(args.epoch) as f:
        epoch = json.load(f)
    all_leaves = epoch.get("all_leaves_hex") or epoch.get("leaves_hex")
    if not all_leaves:
        raise SystemExit("epoch bundle has no all_leaves_hex")
    context_id = args.context if args.context is not None else epoch.get("context_id")
    epoch_id = epoch.get("epoch_id")
    nonce = args.nonce if args.nonce is not None else epoch.get("nonce", 0)
    if context_id is None or epoch_id is None:
        raise SystemExit("need epoch_id and context_id (from the epoch bundle or --context)")
    token_id = pack.get("token_id")
    token_value = pack.get("token_value")
    if token_id is None or token_value is None:
        raise SystemExit("the held credential lacks token_id/token_value; cannot derive the leaf")
    seed = _leaf_seed(token_id, token_value, context_id)
    if seed not in all_leaves:
        raise SystemExit("this credential is not a member of that epoch/context (its leaf seed is "
                         "not in the published set) — nothing to prove")
    leaf_index = all_leaves.index(seed)
    binary = _zk_binary(args)
    if not os.path.exists(binary):
        raise SystemExit("the polaris-zk binary is not built at %s (build it, or set "
                         "POLARIS_ZK_BINARY / --zk-binary)" % binary)
    payload = {"leaf_seed_hex": seed, "leaf_index": leaf_index, "all_leaves_hex": all_leaves,
               "epoch_id": int(epoch_id), "context_id": int(context_id), "nonce": int(nonce)}
    try:
        proc = subprocess.run([binary, "prove"], input=json.dumps(payload),
                              capture_output=True, text=True, timeout=600)
    except Exception as e:
        raise SystemExit("could not run the polaris-zk binary: %s" % e)
    if proc.returncode != 0:
        raise SystemExit("proof generation failed: %s" % (proc.stderr.strip() or proc.returncode))
    bundle = json.loads(proc.stdout)
    out = json.dumps(bundle, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out + "\n")
        print("membership proof written to %s (proves membership without revealing which member)" % args.out)
    else:
        sys.stdout.write(out + "\n")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Polaris holder wallet (PE.7).")
    ap.add_argument("--wallet", help="wallet directory (default: ~/.polaris-wallet)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("enroll", help="hold a credential (and optionally a duress code)")
    p.add_argument("--pack", required=True, help="an authenticity pack JSON file")
    p.add_argument("--duress-code", help="OPTIONAL duress code to store locally (see the deniability note)")
    p.set_defaults(fn=cmd_enroll)

    p = sub.add_parser("show", help="display the held credential (offline)")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("verify", help="self-verify the held credential offline")
    p.add_argument("--issuer-anchor", help="the issuer's published verification key(s)")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("present", help="emit a presentation for a relying party")
    p.add_argument("--duress", action="store_true", help="present under duress (uses the stored/typed code)")
    p.add_argument("--code", help="the presentation code to include")
    p.add_argument("--out", help="write to a file instead of stdout")
    p.set_defaults(fn=cmd_present)

    p = sub.add_parser("prove-membership", help="produce a ZK membership proof for a published epoch")
    p.add_argument("--epoch", required=True, help="the published epoch bundle (all_leaves_hex, epoch_id, context_id)")
    p.add_argument("--context", type=int, help="context id (if not in the epoch bundle)")
    p.add_argument("--nonce", type=int, help="proof nonce (default from the bundle, or 0)")
    p.add_argument("--zk-binary", help="path to the polaris-zk binary")
    p.add_argument("--out", help="write the proof to a file instead of stdout")
    p.set_defaults(fn=cmd_prove_membership)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
