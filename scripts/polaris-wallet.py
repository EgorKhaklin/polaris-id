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
    polaris-wallet.py present --status-assertion status.json --qr --out frames.txt
    polaris-wallet.py prove-membership --epoch epoch.json --out proof.json
    polaris-wallet.py sign --document report.pdf --instance https://issuer.example --agency 1 --out signed.json

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


def _holder_secret(token_id, token_value, context_id):
    """The holder's per-context SECRET — the SAME derivation the issuer uses:
    SHA3-256("{token_id}|{token_value}|{context_id}").

    Since P9.3 this is the secret, not the published leaf. The leaf is its Poseidon
    commitment, which the circuit opens; the secret never leaves this device."""
    h = hashlib.sha3_256()
    h.update(("%s|%s|%s" % (token_id, token_value, context_id)).encode("utf-8"))
    return h.hexdigest()


def _leaf_commitment(binary, secret_hex, context_id):
    """The published epoch leaf: Poseidon(secret || context_id), via the polaris-zk binary.

    Computed rather than looked up, so the holder finds their OWN leaf in the published set
    locally and never has to ask the issuer which member they are."""
    proc = subprocess.run([binary, "leaf"],
                          input=json.dumps({"secret_hex": secret_hex, "context_id": int(context_id)}),
                          capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise SystemExit("could not derive the leaf commitment: %s"
                         % (proc.stderr.strip() or proc.returncode))
    return json.loads(proc.stdout)["leaf_hex"]


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
    # P8.6: staple the issuer-signed status assertion (fetched when connected) so the relying
    # party decides authorization OFFLINE; optionally a ZK membership proof; the context and
    # disclosure level the holder presents under.
    if getattr(args, "status_assertion", None):
        with open(args.status_assertion) as f:
            presentation["status_assertion"] = json.load(f)
    if getattr(args, "zk_proof", None):
        with open(args.zk_proof) as f:
            presentation["zk_proof"] = json.load(f)
    # P9.1: prove possession of the HOLDER KEY, not only of the file. The proof names the
    # verifier's own nonce, so it cannot be replayed to anyone else.
    if getattr(args, "holder_nonce", None):
        binding_path = os.path.join(wallet, "holder_binding.json")
        proof = _holder_proof(wallet, pack["token_value"], getattr(args, "context", None), args.holder_nonce)
        if proof is None:
            sys.stderr.write("no holder key in this wallet; run: polaris-wallet holder-keygen\n")
            return 3
        presentation["holder_proof"] = proof
        if os.path.isfile(binding_path):
            with open(binding_path) as f:
                presentation["holder_binding"] = json.load(f)
    # P9.4: the handle this relying party should key its records by. Emitted only when the
    # holder names the verifier, because a handle without a scope is a global identifier
    # again, which is the thing being removed. The verifier RECOMPUTES it from the binding
    # it verified, so putting it here is a convenience, never something it has to trust.
    if getattr(args, "verifier_scope", None):
        binding_path = os.path.join(wallet, "holder_binding.json")
        holder_key = None
        if os.path.isfile(binding_path):
            with open(binding_path) as f:
                holder_key = (json.load(f) or {}).get("holder_public_key_hex")
        V = _load_verifier()
        handle = V.pairwise_handle(holder_key or pack.get("token_value"), args.verifier_scope)
        if handle:
            presentation["verifier_scope"] = args.verifier_scope
            presentation["pairwise_handle"] = handle
    if getattr(args, "context", None) is not None:
        presentation["context_id"] = args.context
    if getattr(args, "disclosure_level", None):
        presentation["disclosure_level"] = args.disclosure_level
    if getattr(args, "qr", False):
        V = _load_verifier()
        frames = V.encode_presentation_frames(presentation, frame_bytes=args.frame_bytes)
        out = "\n".join(frames)
    else:
        out = json.dumps(presentation, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out + "\n")
    else:
        sys.stdout.write(out + "\n")
    return 0


# --- P9.1 (v9.349): the holder's own key -------------------------------------------------
# Until this version a holder held a credential, not a key pair, so presenting the file was
# the whole of the proof. These two commands give the holder a key that never leaves this
# directory, and a proof that the party presenting the credential holds it.
_HOLDER_KEY_FILE = "holder_key.json"


def _holder_key_path(wallet):
    return os.path.join(wallet, _HOLDER_KEY_FILE)


def cmd_holder_keygen(args):
    """Generate a holder key pair and bind its PUBLIC half to the held credential.

    The private key is written here and goes nowhere else: the binding endpoint is
    authenticated by POSSESSION of the credential, never by handing over a secret. Losing
    this file loses the key, not the credential; bind a new one with --rotate."""
    wallet = _wallet_dir(args)
    pack = _load_credential(wallet)
    try:
        import oqs  # type: ignore
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("holder-keygen needs liboqs-python (pip install liboqs-python): %s\n" % e)
        return 3
    alg = args.algorithm
    with oqs.Signature(alg) as signer:
        pk = bytes(signer.generate_keypair())
        sk = bytes(signer.export_secret_key())
    path = _holder_key_path(wallet)
    with open(path, "w") as f:
        json.dump({"algorithm": alg, "public_key_hex": pk.hex(), "secret_key_hex": sk.hex()}, f, indent=2)
    os.chmod(path, 0o600)
    body = {"token_value": pack["token_value"], "signature_hex": pack["signature_hex"],
            "holder_public_key_hex": pk.hex(), "holder_algorithm": alg,
            "event": ("rotated" if args.rotate else "bound")}
    import urllib.error
    import urllib.request
    req = urllib.request.Request(args.instance.rstrip("/") + "/api/v1/holder-key",
                                 data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            binding = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise SystemExit("binding refused: HTTP %d %s" % (e.code, e.read().decode("utf-8", "replace")[:200]))
    out = os.path.join(wallet, "holder_binding.json")
    with open(out, "w") as f:
        json.dump(binding, f, indent=2)
    sys.stdout.write("holder key %s; the private half stays in %s\nbinding written to %s\n"
                     % ("rotated" if args.rotate else "bound", path, out))
    return 0


def _holder_proof(wallet, token_value, context_id, verifier_nonce):
    """Sign a holder proof with the key held here. Narrow by design: the credential, the
    context, the verifier's nonce and the instant. NOT the presented code, so a coerced
    presentation is byte-indistinguishable from a consenting one."""
    import hashlib as _h
    from datetime import datetime, timezone
    path = _holder_key_path(wallet)
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        key = json.load(f)
    try:
        import oqs  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    V = _load_verifier()
    proof = {"format": "polaris-holder-proof/1", "token_value": token_value,
             "context_id": context_id, "verifier_nonce": verifier_nonce,
             "issued_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
             "algorithm": key["algorithm"]}
    digest = _h.sha3_256(V._holder_proof_canonical(proof)).digest()
    with oqs.Signature(key["algorithm"], secret_key=bytes.fromhex(key["secret_key_hex"])) as signer:
        proof["signature_hex"] = bytes(signer.sign(digest)).hex()
    proof["public_key_hex"] = key["public_key_hex"]
    return proof


# --- P9.8 (v9.354): delegating to an agent, without handing over the credential ----------

_AGENT_KEY_FILE = "agent_key.json"


def _sign_with_holder_key(wallet, statement_bytes, algorithm=None):
    """Sign bytes with the holder key held here. Returns (signature_hex, public_key_hex, alg)
    or None when there is no key or no signer installed.

    The holder key never leaves this device, which is the point: a grant is authorised by
    the person, on their own hardware, and the issuer is not asked and never told."""
    path = _holder_key_path(wallet)
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        key = json.load(f)
    try:
        import oqs  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    alg = algorithm or key["algorithm"]
    with oqs.Signature(alg, secret_key=bytes.fromhex(key["secret_key_hex"])) as signer:
        return bytes(signer.sign(statement_bytes)).hex(), key["public_key_hex"], alg


def cmd_grant(args):
    """Mint an agent grant: named actions, stated limits, an expiry, a revocation handle.

    What this deliberately is NOT is a copy of the credential. Handing an agent the
    credential gives it everything the person can do, forever, revocable only by revoking
    the person. This gives it exactly the listed actions, inside the stated limits, until the
    expiry, and the holder can end it alone."""
    import hashlib as _h
    from datetime import datetime, timedelta, timezone
    wallet = _wallet_dir(args)
    actions = [a.strip() for a in (args.action or []) if a.strip()]
    if not actions:
        raise SystemExit("a grant must name at least one action (--action); an empty grant "
                         "authorises nothing, and is not a way to authorise everything")
    limits = {}
    if args.max_uses is not None:
        limits["max_uses"] = int(args.max_uses)
    if args.max_amount is not None:
        limits["max_amount"] = float(args.max_amount)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    iso = lambda d: d.isoformat().replace("+00:00", "Z")
    V = _load_verifier()
    grant = {"format": "polaris-agent-grant/1",
             "grant_id": args.grant_id or ("grant-" + os.urandom(8).hex()),
             "agent_public_key_hex": args.agent_key, "agent_algorithm": args.agent_algorithm,
             "actions": actions, "limits": limits, "context_id": args.context,
             "issued_at": iso(now), "expires_at": iso(now + timedelta(hours=int(args.hours))),
             "algorithm": "ML-DSA-65"}
    signed = _sign_with_holder_key(wallet, _h.sha3_256(V._agent_grant_canonical(grant)).digest())
    if signed is None:
        raise SystemExit("no holder key in this wallet (run: polaris-wallet holder-keygen), or "
                         "liboqs is not installed")
    grant["signature_hex"], grant["public_key_hex"], grant["algorithm"] = signed
    out = json.dumps(grant, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out + "\n")
        print("grant %s written to %s (revoke it with: polaris-wallet revoke-grant --grant-id %s)"
              % (grant["grant_id"], args.out, grant["grant_id"]))
    else:
        sys.stdout.write(out + "\n")
    return 0


def cmd_revoke_grant(args):
    """End a grant, with the holder's own key. The issuer is not contacted and never learns
    the grant existed; the human's credential is untouched and stays usable.

    The revocation says the grant is over and says nothing about why. A reason field would be
    a place a coercer could demand be filled in or left empty, and either way it would turn a
    revocation into a signal about the person."""
    import hashlib as _h
    from datetime import datetime, timezone
    wallet = _wallet_dir(args)
    V = _load_verifier()
    rev = {"format": "polaris-grant-revocation/1", "grant_id": args.grant_id,
           "revoked_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
           "algorithm": "ML-DSA-65"}
    signed = _sign_with_holder_key(wallet, _h.sha3_256(V._grant_revocation_canonical(rev)).digest())
    if signed is None:
        raise SystemExit("no holder key in this wallet, or liboqs is not installed")
    rev["signature_hex"], rev["public_key_hex"], rev["algorithm"] = signed
    out = json.dumps(rev, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out + "\n")
        print("revocation for %s written to %s (your credential is untouched)"
              % (args.grant_id, args.out))
    else:
        sys.stdout.write(out + "\n")
    return 0


def _zk_binary(args):
    return (args.zk_binary or os.environ.get("POLARIS_ZK_BINARY")
            or os.path.join(_ROOT, "polaris_zk", "target", "release", "polaris-zk"))


def cmd_sign(args):
    """Sign a document on the holder's behalf (P8.5c): hash the file HERE -- the document never
    leaves the wallet -- present the held credential to the issuing authority's instance, and
    receive a portable signed container with long-term-validation evidence attached."""
    import urllib.error
    import urllib.request
    wallet = _wallet_dir(args)
    pack = _load_credential(wallet)
    with open(args.document, "rb") as f:
        data = f.read()
    body = {"token_value": pack.get("token_value"), "signature_hex": pack.get("signature_hex"),
            "digest_hex": hashlib.sha3_256(data).hexdigest(), "digest_algorithm": "SHA3-256",
            "name": os.path.basename(args.document), "purpose": args.purpose}
    req = urllib.request.Request(args.instance.rstrip("/") + "/api/v1/sign/%d/holder" % args.agency,
                                 data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            doc = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise SystemExit("signing refused: HTTP %d %s" % (e.code, e.read().decode("utf-8", "replace")[:200]))
    out = json.dumps(doc, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out + "\n")
    else:
        sys.stdout.write(out + "\n")
    return 0


def cmd_login(args):
    """Authenticate to a relying party through your issuing authority (P8.4): present the held
    credential at the authorize endpoint with the relying party's nonce and PKCE challenge and
    receive the authorization code to hand back to the relying party. Nothing about the login
    is recorded at the authority."""
    import urllib.error
    import urllib.request
    wallet = _wallet_dir(args)
    pack = _load_credential(wallet)
    body = {"client_id": args.client_id, "nonce": args.nonce, "code_challenge": args.code_challenge,
            "code_challenge_method": "S256", "context_id": args.context,
            "disclosure_level": args.disclosure_level, "token_value": pack.get("token_value"),
            "signature_hex": pack.get("signature_hex")}
    if args.code:
        body["presented_code"] = args.code
    req = urllib.request.Request(args.instance.rstrip("/") + "/api/v1/auth/authorize",
                                 data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            out = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise SystemExit("authorization refused: HTTP %d %s" % (e.code, e.read().decode("utf-8", "replace")[:200]))
    sys.stdout.write(json.dumps(out, indent=2) + "\n")
    return 0


def cmd_prove_membership(args):
    """Produce a zero-knowledge proof that the held credential's token is in a
    published epoch, without revealing WHICH member it is. The epoch bundle is
    public (its leaf-seed set is the anonymity set); the proof's public inputs are
    the root and the binding, never the holder's index."""
    wallet = _wallet_dir(args)
    pack = _load_credential(wallet)
    if getattr(args, "from_instance", None):
        import urllib.error
        import urllib.request
        # P9.2: fetch the PUBLISHED anonymity set and verify it before proving. Every holder
        # fetches identical bytes, so the request says nothing about which leaf is theirs;
        # the leaf is found here, on this device, and the proof is built here.
        url = "%s/api/v1/epoch/%d/leaves" % (args.from_instance.rstrip("/"), args.epoch_id)
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                epoch = json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise SystemExit("could not fetch the anonymity set: HTTP %d" % e.code)
        V = _load_verifier()
        v = V.verify_epoch_leaves(epoch)
        if not (v["leaves_authentic"] and v["commitment_matches"] and v["count_matches"]):
            raise SystemExit("the published anonymity set does not verify: %s" % v["note"])
        sys.stderr.write("anonymity set: %d members, signed by the issuing authority\n" % v["leaf_count"])
    else:
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
    binary = _zk_binary(args)
    if not os.path.exists(binary):
        raise SystemExit("the polaris-zk binary is not built at %s (build it, or set "
                         "POLARIS_ZK_BINARY / --zk-binary)" % binary)
    secret = _holder_secret(token_id, token_value, context_id)
    leaf = _leaf_commitment(binary, secret, context_id)
    if leaf not in all_leaves:
        raise SystemExit("this credential is not a member of that epoch/context (its leaf "
                         "commitment is not in the published set) — nothing to prove")
    leaf_index = all_leaves.index(leaf)
    # P9.3: the SECRET goes to the prover, never the leaf. The circuit opens
    # Poseidon(secret || context_id) into the leaf and derives the scoped nullifier from the
    # same secret, which is what makes the nullifier mean anything.
    payload = {"secret_hex": secret, "leaf_index": leaf_index, "all_leaves_hex": all_leaves,
               "epoch_id": int(epoch_id), "context_id": int(context_id), "nonce": int(nonce),
               "scope": int(getattr(args, "scope", None) or 0)}
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
    p.add_argument("--status-assertion", help="staple a fetched polaris-status-assertion/1 (authorization decidable offline)")
    p.add_argument("--zk-proof", help="staple a ZK membership proof bundle")
    p.add_argument("--context", type=int, help="the verification context presented under")
    p.add_argument("--disclosure-level", help="ZERO_KNOWLEDGE, SELECTIVE or FULL")
    p.add_argument("--qr", action="store_true", help="emit polaris-qr/1 frames (one per line) for QR/NFC transfer instead of JSON")
    p.add_argument("--frame-bytes", type=int, default=1800, help="maximum bytes per QR frame (default 1800)")
    p.add_argument("--holder-nonce", help="prove possession of the holder key against this verifier-issued nonce (P9.1)")
    p.add_argument("--verifier-scope", help="the relying party this presentation is for; emits a per-verifier pairwise handle it should key its records by instead of the token value (P9.4)")
    p.add_argument("--out", help="write to a file instead of stdout")
    p.set_defaults(fn=cmd_present)

    p = sub.add_parser("holder-keygen", help="generate a holder key and bind its public half to the credential (P9.1)")
    p.add_argument("--algorithm", default="ML-DSA-65", choices=["ML-DSA-65", "ML-DSA-87"])
    p.add_argument("--rotate", action="store_true", help="replace the bound key rather than binding a first one")
    p.add_argument("--instance", default=os.environ.get("POLARIS_INSTANCE", "http://127.0.0.1:5000"),
                   help="the issuing authority's instance")
    p.set_defaults(fn=cmd_holder_keygen)

    p = sub.add_parser("prove-membership", help="produce a ZK membership proof for a published epoch")
    p.add_argument("--epoch", help="the published epoch bundle (all_leaves_hex, epoch_id, context_id)")
    p.add_argument("--scope", type=int, default=0,
                   help="the relying party's scope (P9.3): the proof carries a nullifier under it, so "
                        "that verifier can refuse a second proof from you without learning who you are, "
                        "and another verifier cannot correlate it with yours")
    p.add_argument("--from-instance", help="fetch the signed anonymity set from an instance and prove locally (P9.2)")
    p.add_argument("--epoch-id", type=int, help="which epoch to fetch with --from-instance")
    p.add_argument("--context", type=int, help="context id (if not in the epoch bundle)")
    p.add_argument("--nonce", type=int, help="proof nonce (default from the bundle, or 0)")
    p.add_argument("--zk-binary", help="path to the polaris-zk binary")
    p.add_argument("--out", help="write the proof to a file instead of stdout")
    p.set_defaults(fn=cmd_prove_membership)

    p = sub.add_parser("grant", help="authorise an agent to act for you, WITHOUT handing over your credential (P9.8)")
    p.add_argument("--agent-key", required=True, help="the agent's PUBLIC key hex; it proves possession of the private half to act")
    p.add_argument("--agent-algorithm", default="ML-DSA-65", help="the agent key's algorithm")
    p.add_argument("--action", action="append", required=True,
                   help="an action the agent may perform (repeatable). A grant with no actions "
                        "authorises nothing; there is no way to say 'everything'")
    p.add_argument("--max-uses", type=int, help="limit: how many times the grant may be used")
    p.add_argument("--max-amount", type=float, help="limit: the largest amount an action may carry")
    p.add_argument("--context", type=int, help="the context this grant is for")
    p.add_argument("--hours", type=int, default=24, help="how long the grant lives (default 24)")
    p.add_argument("--grant-id", help="the revocation handle (default: random)")
    p.add_argument("--out", help="write the grant to a file instead of stdout")
    p.set_defaults(fn=cmd_grant)

    p = sub.add_parser("revoke-grant", help="end a grant with your own key; your credential is untouched and the issuer is not told (P9.8)")
    p.add_argument("--grant-id", required=True, help="the grant to end")
    p.add_argument("--out", help="write the revocation to a file instead of stdout")
    p.set_defaults(fn=cmd_revoke_grant)

    p = sub.add_parser("login", help="authenticate to a relying party through your issuing authority (authorization code + PKCE)")
    p.add_argument("--instance", required=True, help="base URL of the issuing authority's instance")
    p.add_argument("--client-id", required=True, help="the relying party's client id")
    p.add_argument("--nonce", required=True, help="the nonce the relying party's login started with")
    p.add_argument("--code-challenge", required=True, help="the relying party's PKCE S256 challenge")
    p.add_argument("--context", type=int, required=True, help="verification context id")
    p.add_argument("--disclosure-level", default="ZERO_KNOWLEDGE", help="ZERO_KNOWLEDGE (default), SELECTIVE or FULL")
    p.add_argument("--code", help="a presentation code (a duress code is served identically)")
    p.set_defaults(fn=cmd_login)

    p = sub.add_parser("sign", help="sign a document on your behalf via your issuing authority (the document never leaves the wallet)")
    p.add_argument("--document", required=True, help="the file to sign (hashed locally; only its SHA3-256 is sent)")
    p.add_argument("--instance", required=True, help="base URL of the issuing authority's instance")
    p.add_argument("--agency", type=int, required=True, help="the issuing agency id on that instance")
    p.add_argument("--purpose", help="a short statement of purpose recorded in the signed container")
    p.add_argument("--out", help="write the signed container to a file instead of stdout")
    p.set_defaults(fn=cmd_sign)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
