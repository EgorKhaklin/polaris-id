#!/usr/bin/env python3
"""polaris-compat-suite.py -- cross-version compatibility, both directions (P8.8b, v9.330).

  1. IMMUTABILITY.  conformance/frozen/v1/SHA256SUMS is recomputed; a changed frozen file fails.
  2. NEW <- FROZEN. The CURRENT detached verifier (and the current Python SDK, and the current
     TypeScript SDK when node is present) run the FROZEN version-1 cases: every frozen
     expectation must hold. A verifier that stops accepting what version 1 published has
     broken the protocol.
  3. OLD <- CURRENT. A PINNED OLDER detached verifier (the vendored v9.317 by default) runs
     the CURRENT cases under the cross-version rule: it MUST agree on every case at or before
     its own release (`since`), MUST NOT accept anything a later case expects rejected
     (fail-closed across versions), and may only decline (never accept wrongly) what it
     predates. Artifact types it does not implement are reported as predated, not failed.

Exit 0 when every direction holds, 1 on any violation, 3 when the frozen set is missing.
No database, no network. Needs liboqs or cryptography for real ML-DSA verification.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
from datetime import datetime, timezone

sys.dont_write_bytecode = True   # importing the vendored verifier must not write into the frozen set
ROOT = pathlib.Path(__file__).resolve().parents[1]
FROZEN = ROOT / "conformance" / "frozen" / "v1"
CURRENT_CASES = ROOT / "conformance" / "cases.json"
CURRENT_VERIFIER = ROOT / "scripts" / "polaris-verify.py"
OLD_VERIFIER = FROZEN / "verifiers" / "polaris-verify-v9.317.py"

# artifact -> the detached verifier's function and the verdict key that means "authentic"
FUNCTIONS = {
    "epoch-checkpoint": ("verify_epoch_checkpoint", "checkpoint_authentic"),
    "revocation-feed": ("verify_revocation_feed", "feed_authentic"),
    "federation-manifest": ("verify_manifest", "manifest_authentic"),
    "federation-status-bundle": ("verify_status_bundle", "bundle_authentic"),
    "transparency-sth": ("verify_sth", "sth_authentic"),
    "timestamp": ("verify_timestamp", "timestamp_authentic"),
    "registry": ("verify_registry", "registry_authentic"),
    "exchange-request": ("verify_exchange_request", "request_authentic"),
    "signed-document": ("verify_signed_document", "document_authentic"),
    "id-token": ("verify_id_token", "token_authentic"),
    "trust-list": ("verify_trust_list", "trust_list_authentic"),
    "exchange-receipt": ("verify_exchange_receipt", "receipt_authentic"),
    "exchange-mint": ("verify_exchange_mint", "mint_authentic"),
    # P9.5 / P9.1 / P9.2 (v9.348-v9.350): the trust edge, the holder chain, the anonymity set.
    "trust-attestation": ("verify_attestation", "attestation_authentic"),
    "holder-binding": ("verify_holder_binding", "binding_authentic"),
    "holder-proof": ("verify_holder_proof", "proof_authentic"),
    "epoch-leaves": ("verify_epoch_leaves", "leaves_authentic"),
}


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _at(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc) if iso else None


def _vkey(v):
    return tuple(int(x) for x in str(v).split("."))


def _read(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def decide(V, case):
    """The detached verifier's decision for one case, normalized to the expectation keys.
    Returns (got, None) or (None, "predates <artifact>") when V lacks the function."""
    art = case.get("artifact", "authenticity-pack")
    if art == "authenticity-pack":
        pack = _read(case["pack_file"])
        anchors = case.get("anchors")
        anchors = [pack.get("public_key_hex")] if anchors == "self" else anchors
        v = V.verify_pack(pack, anchors)
        return {"authentic": v.get("signature_valid"), "issuer_trusted": v.get("issuer_trusted")}, None
    if art == "status-assertion":
        v = V.verify_status_assertion(_read(case["assertion_file"]), now=_at(case.get("now")))
        return {"authentic": v.get("status_authentic"), "fresh": v.get("fresh"), "active": (v.get("status") == "ACTIVE")}, None
    if art == "cross-authority":
        pack = _read(case["pack_file"])
        ms = [_read(f) for f in case.get("manifest_files", [])]
        anchors = case.get("trusted_anchors")
        if anchors == "manifest":
            anchors = sorted({a["public_key_hex"] for m in ms for a in m.get("anchors", [])
                              if (a.get("status") or "active") == "active" and a.get("public_key_hex")})
        kw = {"now": _at(case.get("now"))}
        if "feed_file" in case:
            kw["revocation_feed"] = _read(case["feed_file"])
        v = V.verify_cross_authority(pack, case.get("context_id"), ms, trusted_anchors=anchors, **kw)
        return {"decision": v.get("decision"), "authentic": v.get("authentic"), "issuer_trusted": v.get("issuer_trusted")}, None
    if art == "timestamp-anchor":
        # P9.6: the composite anchor decision, not a per-artifact authenticity check.
        fn = getattr(V, "verify_timestamp_anchor", None)
        if fn is None:
            return None, "predates %s" % art
        ts = _read(case["timestamp_file"])
        log_key = case.get("log_key")
        if log_key == "sth":
            log_key = ts["anchor"]["sth"]["public_key_hex"]
        tw = case.get("trusted_witnesses")
        if tw == "cosigners":
            tw = sorted({x["public_key_hex"] for x in ts["anchor"].get("cosignatures", [])
                         if isinstance(x, dict) and x.get("public_key_hex")})
        v = fn(ts, log_key=log_key, trusted_witnesses=tw, threshold=int(case.get("threshold") or 1))
        return {"anchored": v.get("anchored"), "witnessed": v.get("witnessed")}, None
    if art == "holder-chain":
        # P9.1: the composite chain decision.
        fn = getattr(V, "verify_holder_proof", None)
        if fn is None:
            return None, "predates %s" % art
        cred, b, pr = _read(case["credential_file"]), _read(case["binding_file"]), _read(case["proof_file"])
        now = _at(case.get("now"))
        bv = V.verify_holder_binding(b, credential=cred, now=now)
        pv = fn(pr, binding=b if bv.get("binding_authentic") else None,
                expected_nonce=case.get("expected_nonce"), expected_context=case.get("expected_context"), now=now)
        proved = bool(bv.get("binding_authentic") and bv.get("fresh") and bv.get("bound_to_credential") is not False
                      and pv.get("proof_authentic") and pv.get("fresh") and pv.get("key_matches_binding")
                      and pv.get("nonce_matches") is not False and pv.get("context_matches") is not False)
        return {"proved": proved}, None
    if art not in FUNCTIONS:
        return None, "predates %s" % art
    fn_name, key = FUNCTIONS[art]
    fn = getattr(V, fn_name, None)
    if fn is None:
        return None, "predates %s" % art
    kw = {"now": _at(case["now"])} if "now" in case else {}
    v = fn(_read(case["object_file"]), **kw)
    return {"authentic": v.get(key), "fresh": v.get("fresh")}, None


def check_sums():
    sums = (FROZEN / "SHA256SUMS").read_text(encoding="utf-8").split("\n")
    bad, n = [], 0
    for line in sums:
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        n += 1
        p = FROZEN / rel
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            bad.append(rel)
    listed = {line.split("  ", 1)[1] for line in sums if line.strip()}
    extra = [f.relative_to(FROZEN).as_posix() for f in FROZEN.rglob("*") if f.is_file() and f.name != "SHA256SUMS"
             and "__pycache__" not in f.parts and f.relative_to(FROZEN).as_posix() not in listed]
    return n, bad, extra


def run_sdk_cli(cmd, env, cases):
    """Drive a stdin->stdout conformance verifier (the SDKs' CLI protocol) over frozen cases."""
    failures = []
    for c in cases:
        art = c.get("artifact", "authenticity-pack")
        payload = {"artifact": art}
        if art == "authenticity-pack":
            pack = _read(c["pack_file"]); payload["pack"] = pack
            anchors = c.get("anchors")
            if anchors == "self":
                anchors = [pack["public_key_hex"]]
            if anchors is not None:
                payload["anchors"] = anchors
        elif art == "status-assertion":
            payload["assertion"] = _read(c["assertion_file"])
            if "now" in c:
                payload["now"] = c["now"]
        elif art == "cross-authority":
            payload["pack"] = _read(c["pack_file"])
            ms = [_read(f) for f in c.get("manifest_files", [])]
            payload["manifests"] = ms
            payload["context_id"] = c.get("context_id")
            anchors = c.get("trusted_anchors")
            if anchors == "manifest":
                anchors = sorted({a["public_key_hex"] for m in ms for a in m.get("anchors", [])
                                  if (a.get("status") or "active") == "active" and a.get("public_key_hex")})
            payload["trusted_anchors"] = anchors
            if "feed_file" in c:
                payload["revocation_feed"] = _read(c["feed_file"])
            if "now" in c:
                payload["now"] = c["now"]
        else:
            payload["object"] = _read(c["object_file"])
            if "now" in c:
                payload["now"] = c["now"]
        try:
            p = subprocess.run(cmd, input=json.dumps(payload), capture_output=True, text=True, timeout=120, env=env, cwd=str(ROOT))
            got = json.loads(p.stdout.strip().splitlines()[-1]) if p.stdout.strip() else {}
        except Exception as e:  # noqa: BLE001 - any failure to answer is a failure to conform
            got = {"error": str(e)}
        mism = {k: (got.get(k), e) for k, e in c["expect"].items() if got.get(k) != e}
        if mism:
            failures.append((c["name"], mism))
    return failures


def main(argv=None):
    ap = argparse.ArgumentParser(description="Polaris cross-version compatibility suite")
    ap.add_argument("--old-verifier", default=str(OLD_VERIFIER), help="a pinned older scripts/polaris-verify.py")
    ap.add_argument("--old-version", default=None, help="its release (default: _VERIFIER_VERSION in the file, else from its filename)")
    ap.add_argument("--skip-sdks", action="store_true", help="only the detached verifiers (no SDK CLIs)")
    ap.add_argument("--typescript-only", action="store_true", help="immutability + the frozen cases under the TypeScript SDK only (no ML-DSA libraries needed in Python)")
    args = ap.parse_args(argv)
    if not (FROZEN / "SHA256SUMS").is_file():
        print("no frozen set at %s" % FROZEN, file=sys.stderr)
        return 3
    failures = []

    n, bad, extra = check_sums()
    print("1. immutability: %d frozen files pinned; %s" % (n, "all match" if not bad and not extra else "CHANGED %s EXTRA %s" % (bad, extra)))
    failures += ["frozen file changed: %s" % b for b in bad] + ["unpinned file in the frozen set: %s" % e for e in extra]

    frozen_cases = json.loads((FROZEN / "cases.json").read_text(encoding="utf-8"))["cases"]
    if args.typescript_only:
        f = run_sdk_cli(["node", "sdk/typescript/src/conformance.ts"], dict(os.environ), frozen_cases)
        print("2. current TypeScript SDK <- frozen v1: %s" % ("all %d cases hold" % len(frozen_cases) if not f else "FAILED %s" % f[:3]))
        failures += ["typescript sdk on frozen %s: %s" % x for x in f]
        if failures:
            print("\nFAILED:")
            for x in failures:
                print("  - " + x)
            return 1
        print("\nOK: the current TypeScript SDK accepts everything version 1 published.")
        return 0
    NEW = _load_module(CURRENT_VERIFIER, "polaris_verify_current")
    n_ok = 0
    for c in frozen_cases:
        got, why = decide(NEW, c)
        mism = {} if got is None else {k: (got.get(k), e) for k, e in c["expect"].items() if got.get(k) != e}
        if why or mism:
            failures.append("current verifier on frozen %s: %s" % (c["name"], why or mism))
        else:
            n_ok += 1
    print("2. current detached verifier (%s) <- frozen v1: %d/%d cases hold" % (getattr(NEW, "_VERIFIER_VERSION", "?"), n_ok, len(frozen_cases)))
    if not args.skip_sdks:
        env = dict(os.environ); env["PYTHONPATH"] = str(ROOT / "sdk" / "python") + os.pathsep + env.get("PYTHONPATH", "")
        f = run_sdk_cli([sys.executable, "-m", "polaris_verify.conformance"], env, frozen_cases)
        print("   current Python SDK <- frozen v1: %s" % ("all %d cases hold" % len(frozen_cases) if not f else "FAILED %s" % f[:3]))
        failures += ["python sdk on frozen %s: %s" % x for x in f]
        if shutil.which("node") and (ROOT / "sdk" / "typescript" / "node_modules").is_dir():
            f = run_sdk_cli(["node", "sdk/typescript/src/conformance.ts"], dict(os.environ), frozen_cases)
            print("   current TypeScript SDK <- frozen v1: %s" % ("all %d cases hold" % len(frozen_cases) if not f else "FAILED %s" % f[:3]))
            failures += ["typescript sdk on frozen %s: %s" % x for x in f]
        else:
            print("   current TypeScript SDK <- frozen v1: skipped (node or node_modules absent)")

    OLD = _load_module(args.old_verifier, "polaris_verify_pinned")
    old_version = args.old_version or getattr(OLD, "_VERIFIER_VERSION", None)
    if old_version is None:
        import re
        m = re.search(r"v?(9\.\d+)", pathlib.Path(args.old_verifier).name)
        old_version = m.group(1) if m else "0.0"
    current_cases = json.loads(CURRENT_CASES.read_text(encoding="utf-8"))["cases"]
    agreed = predated = declined = 0
    for c in current_cases:
        got, why = decide(OLD, c)
        if why:
            predated += 1
            continue
        mism = {k: (got.get(k), e) for k, e in c["expect"].items() if got.get(k) != e}
        if not mism:
            agreed += 1
            continue
        newer = _vkey(c.get("since", "0.0")) > _vkey(old_version)
        # Fail-closed across versions: a wrong ACCEPTANCE is always a violation; on a case newer
        # than the pinned release a wrong rejection is the verifier declining what it predates.
        wrong_accept = any(e in (False, "reject") and g not in (False, None, "reject") for k, (g, e) in mism.items())
        if newer and not wrong_accept:
            declined += 1
        else:
            failures.append("pinned v%s verifier on %s (since %s): %s" % (old_version, c["name"], c.get("since"), mism))
    print("3. pinned v%s verifier <- current cases: %d agreed, %d predated (types it lacks), %d declined (newer than it, fail-closed), %d violations"
          % (old_version, agreed, predated, declined, len([f for f in failures if f.startswith("pinned")])))

    if failures:
        print("\nFAILED:")
        for f in failures:
            print("  - " + f)
        return 1
    print("\nOK: version 1 is compatible in both directions -- the current verifiers accept everything version 1 "
          "published, and the pinned older verifier never accepts what the current suite rejects.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
