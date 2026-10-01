#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-hostile-agreement-drill.py -- do the three verifiers agree on HOSTILE input?

The agreement drill compares this repository's three verifiers (the detached verifier a
relying party installs, and the two reference SDKs) on the published cases as published. A
presenter does not send published cases. This drill takes every published case, replaces each
node of what a PRESENTER supplies (the credential, the artifact, a grant, a proof: never the
relying party's own anchors, clock or expectations) with a value of the wrong JSON type, or
deletes it, and decides every such input with all three.

It fails on:
  - an exception out of any verifier: each promises a verdict on hostile input;
  - a disagreement on the PRIMARY decision (authentic, decision, anchored, proved): the same
    bytes, two answers a relying party acts on;
  - any other disagreement, unless both verifiers refused the artifact (what they then say
    about a refused artifact's window or trust decides nothing), or it is one of the
    conventions ACCOUNTED lists with its reason.

2026-09-30: the sweep this drill makes permanent found an inclusion proof anchored under one
verifier and refused under another, a status bundle whose signed count disagreed with its
members accepted by both SDKs, a grant bound to a credential whose signature did not verify,
and crashes; conformance/make_hostile_shape_vectors.py published the cases that fixed them.

The detached verifier is driven through the adapter its own conformance test uses
(scripts/test_verify_conformance.py), as the agreement drill does, with its file loader
pointed at the mutated objects. An input that adapter cannot express (a manifest set that is
not a list, a missing top-level object) is counted and skipped for that pair, never failed.

NEGATIVE CONTROL: --prove-control inverts the TypeScript SDK's `authentic` on every input of
one artifact and REQUIRES the disagreement to be found. Without it, "0 disagreements" and
"the comparison never ran" read the same.

  python3 scripts/polaris-hostile-agreement-drill.py [--workers N] [--only PREFIX] [--sample K]
  python3 scripts/polaris-hostile-agreement-drill.py --prove-control
"""
import argparse
import copy
import importlib.util
import json
import multiprocessing as mp
import os
import pathlib
import subprocess
import sys
import traceback

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sdk" / "python"))

#: What a presenter supplies, per artifact. The relying party's own inputs (anchors, now,
#: audience, nonce, expected keys, thresholds) are its configuration, not hostile input.
PRESENTER = {
    "authenticity-pack": ["pack"],
    "status-assertion": ["assertion"],
    "trust-attestation": ["object"],
    "id-token": ["object"],
    "agent-grant-use": ["grant", "binding", "credential", "revocation", "agent_proof"],
    "exchange-use": ["object", "body", "request_body", "response_body", "manifests"],
    "holder-chain": ["credential", "binding", "proof"],
    "timestamp-anchor": ["timestamp"],
    "cross-authority": ["pack", "manifests", "revocation_feed"],
}


def _deep(n):
    v = []
    for _ in range(n):
        v = [v]
    return v


#: Every value survives a JSON round trip in both languages unchanged: no NaN or Infinity
#: (JavaScript's JSON has none), no integer beyond 2**53 (JavaScript would round it).
HOSTILE = [None, True, False, 0, 1, -1, 2 ** 31, 1.5, "", "x", "0" * 64, "é", "\x00",
           "2026-02-31T00:00:00Z", [], [None], [1], ["x"], [{}], {}, {"a": 1}, {"": None},
           _deep(60), "A" * 5000]
DELETE = object()

PRIMARY = ("authentic", "decision", "anchored", "proved")

#: Disagreements that are conventions, not defects, each with the reason it is one.
#: (artifact or case-name prefix, mutated path or "*", key or "*") -> reason.
ACCOUNTED = {
    ("exchange-mint", "object/algorithm", "*"):
        "`algorithm` is not a signed field of polaris-exchange-mint/1 (WIRE-SPEC 3.8.1). With it "
        "absent the detached verifier takes the parameter set the key's length identifies, as the "
        "product's mint route does; the SDKs require the label. A design difference, recorded.",
    ("exchange-use-mint", "object/algorithm", "*"):
        "the same mint, decided in use",
    ("cross-authority", "*", "issuer_trusted"):
        "the detached adapter derives issuer_trusted from key_status, a different question "
        "(the agreement drill accounts for it the same way)",
}


def presenter_keys(payload, signed):
    art = payload.get("artifact", "authenticity-pack")
    if art in PRESENTER:
        return PRESENTER[art]
    return ["object"] if art in signed else []


def paths(v, prefix=(), depth=0):
    """Every node below v, as a path; a list's first three items."""
    if depth > 12:
        return
    if isinstance(v, dict):
        for k in list(v):
            yield prefix + (k,)
            yield from paths(v[k], prefix + (k,), depth + 1)
    elif isinstance(v, list):
        for i, x in enumerate(v[:3]):
            yield prefix + (i,)
            yield from paths(x, prefix + (i,), depth + 1)


def mutate(payload, path, value):
    m = copy.deepcopy(payload)
    cur = m
    for p in path[:-1]:
        cur = cur[p]
    if value is DELETE:
        del cur[path[-1]]
    else:
        cur[path[-1]] = value
    return m


# --- the three verifiers ---------------------------------------------------------------

_TS_DRIVER = r"""
import { pathToFileURL } from "node:url";
import * as readline from "node:readline";
const { decide } = await import(pathToFileURL(process.env.POLARIS_TS_ADAPTER).href);
const control = process.env.POLARIS_DRILL_CONTROL || "";
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  let out;
  try {
    const c = JSON.parse(line);
    const v = decide(c);
    if (control && ((c && c.artifact) || "authenticity-pack") === control && "authentic" in v) v.authentic = !v.authentic;
    out = JSON.stringify(v);
  } catch (e) {
    out = JSON.stringify({ __raised: String(e && e.name) + ": " + String(e && e.message).slice(0, 160) });
  }
  process.stdout.write(out + "\n");
}
"""

_state = {}


def _init(control):
    from polaris_verify import conformance as C
    _state["py"] = C
    env = dict(os.environ, POLARIS_TS_ADAPTER=str(ROOT / "sdk" / "typescript" / "src" / "conformance.ts"),
               POLARIS_DRILL_CONTROL=control or "")
    _state["node"] = subprocess.Popen(["node", "--input-type=module", "-e", _TS_DRIVER], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
                                      env=env)
    spec = importlib.util.spec_from_file_location("tvc_hostile", ROOT / "scripts" / "test_verify_conformance.py")
    tvc = importlib.util.module_from_spec(spec)
    sys.modules["tvc_hostile"] = tvc
    spec.loader.exec_module(tvc)
    store = {}
    tvc._load = lambda rel: copy.deepcopy(store[rel])
    _state["tvc"], _state["store"] = tvc, store


def _py(payload):
    try:
        return _state["py"].decide(copy.deepcopy(payload))
    except Exception as e:  # noqa: BLE001 -- a verdict was promised; anything raised is the finding
        return {"__raised": "%s: %s" % (type(e).__name__, str(e)[:160])}


def _ts(payload):
    p = _state["node"]
    p.stdin.write(json.dumps(payload) + "\n")
    p.stdin.flush()
    line = p.stdout.readline()
    try:
        return json.loads(line)
    except ValueError:
        return {"__raised": "the TypeScript driver answered %r" % line[:80]}


_FILES = {"pack": "pack_file", "assertion": "assertion_file", "object": "object_file", "grant": "grant_file",
          "revocation": "revocation_file", "agent_proof": "proof_file", "binding": "binding_file",
          "credential": "credential_file", "timestamp": "timestamp_file", "revocation_feed": "feed_file"}


def _detached(name, payload):
    """The detached verifier's verdict, or None when its adapter cannot express the input."""
    store = _state["store"]
    store.clear()
    art = payload.get("artifact", "authenticity-pack")
    case = {"name": name, "artifact": art}
    for k, v in payload.items():
        if k == "artifact":
            continue
        if k == "proof" and art == "holder-chain":
            store["@proof"] = v
            case["proof_file"] = "@proof"
        elif k in _FILES:
            if art == "agent-grant-use" and k in ("revocation", "agent_proof") and v is None:
                continue
            store["@" + k] = v
            case[_FILES[k]] = "@" + k
        elif k == "manifests":
            if not isinstance(v, list):
                return None
            case["manifest_files"] = []
            for i, m in enumerate(v):
                store["@m%d" % i] = m
                case["manifest_files"].append("@m%d" % i)
        else:
            case[k] = v
    try:
        return _state["tvc"]._verdict_for(case)
    except Exception as e:  # noqa: BLE001
        frames = traceback.extract_tb(e.__traceback__)
        if frames and frames[-1].filename.endswith("test_verify_conformance.py"):
            return None      # the adapter, not the verifier, could not read this shape
        return {"__raised": "%s: %s" % (type(e).__name__, str(e)[:160])}


# --- the comparison ----------------------------------------------------------------------

def _refused(v):
    return any(v.get(k) in (False, "reject") for k in PRIMARY if k in v)


def _accounted(name, art, path, key):
    """The ACCOUNTED rule this difference falls under, or None."""
    for rule in ACCOUNTED:
        who, where, what = rule
        if (name.startswith(who) or art == who) and where in ("*", path) and what in ("*", key):
            return rule
    return None


def compare(name, art, path, a, b, pair):
    """The disagreements between two verdicts: [(kind, key)]."""
    if "__raised" in a or "__raised" in b:
        return [("raised", "%s raised" % ("the first" if "__raised" in a else "the second"))]
    out = []
    for k in sorted(set(a) & set(b)):
        if a[k] == b[k]:
            continue
        rule = _accounted(name, art, path, k)
        if rule:
            out.append(("accounted", rule))
        elif k in PRIMARY:
            out.append(("decision", k))
        elif _refused(a) and _refused(b):
            continue          # what two refusals say about the refused artifact decides nothing
        else:
            out.append(("other", k))
    return out


def run_case(item):
    name, payload, sample, signed = item
    art = payload.get("artifact", "authenticity-pack")
    rows, n, skipped = [], 0, 0
    todo = [((), None)]
    for top in presenter_keys(payload, signed):
        if top in payload:
            for path in [(top,)] + [(top,) + p for p in paths(payload[top])]:
                for val in HOSTILE + [DELETE]:
                    todo.append((path, val))
    for i, (path, val) in enumerate(todo):
        if path and sample > 1 and i % sample:
            continue
        try:
            m = mutate(payload, path, val) if path else payload
        except (KeyError, IndexError, TypeError):
            continue
        n += 1
        where = "/".join(map(str, path)) or "<published>"
        shown = "<deleted>" if val is DELETE else ("" if not path else repr(val)[:40])
        p, t, d = _py(m), _ts(m), _detached(name, m)
        for kind, key in compare(name, art, where, p, t, "typescript"):
            rows.append((kind, "python vs typescript", name, where, shown, key, p, t))
        if d is None:
            skipped += 1
        else:
            for kind, key in compare(name, art, where, p, d, "detached"):
                rows.append((kind, "python vs detached", name, where, shown, key, p, d))
    return name, n, skipped, rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--only", help="run only the cases whose name starts with this")
    ap.add_argument("--sample", type=int, default=1, help="decide every Kth mutation (1: all)")
    ap.add_argument("--prove-control", action="store_true")
    args = ap.parse_args()

    spec = importlib.util.spec_from_file_location("rc", ROOT / "conformance" / "run_conformance.py")
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
    from polaris_verify import conformance as C
    cases = rc._load_cases()
    control = "status-assertion" if args.prove_control else ""
    if args.prove_control:
        cases = [c for c in cases if c[1].get("artifact") == control]
    if args.only:
        cases = [c for c in cases if c[0].startswith(args.only)]
    items = [(name, payload, max(1, args.sample), C._SIGNED_ARTIFACTS) for name, payload, _ in cases]

    total, skipped, rows = 0, 0, []
    with mp.Pool(args.workers, initializer=_init, initargs=(control,)) as pool:
        for name, n, s, r in pool.imap_unordered(run_case, items):
            total += n
            skipped += s
            rows.extend(r)
    failing = [r for r in rows if r[0] != "accounted"]
    accounted = [r for r in rows if r[0] == "accounted"]
    print("hostile agreement: %d published case(s), %d input(s) decided by all three verifiers%s"
          % (len(cases), total, " (every %dth mutation)" % args.sample if args.sample > 1 else ""))
    print("  the detached adapter could not express %d of them; those were compared between the SDKs only" % skipped)
    print("  %d accounted difference(s), each a convention ACCOUNTED names:" % len(accounted))
    for rule, reason in ACCOUNTED.items():
        n = sum(1 for r in accounted if r[5] == rule)
        if n:
            print("    %6d  %s, %s, %s: %s" % (n, rule[0], rule[1], rule[2], reason[:100]))

    if args.prove_control:
        if failing:
            print("control holds: a verifier with `authentic` inverted on every %s input produced %d "
                  "disagreement(s) and this drill found them" % (control, len(failing)))
            return 0
        print("CONTROL FAILED: an inverted verdict produced no disagreement, so the comparison is not running",
              file=sys.stderr)
        return 1

    if not failing:
        print("== the three verifiers agree on every hostile input: no verifier raised, no primary "
              "decision differed, and every other difference is between two refusals or accounted ==")
        return 0
    by = {}
    for r in failing:
        by.setdefault((r[0], r[1]), 0)
        by[(r[0], r[1])] += 1
    print("== FAILED: %d disagreement(s): %s ==" % (
        len(failing), ", ".join("%d %s (%s)" % (v, k[0], k[1]) for k, v in sorted(by.items()))))
    for kind, pair, name, where, shown, key, a, b in sorted(failing, key=lambda r: (r[0] != "raised", r[0], r[2], r[3]))[:25]:
        print("  %-8s %-22s case=%s path=%s value=%s key=%s\n      %s\n      %s"
              % (kind, pair, name, where, shown, key, json.dumps(a)[:160], json.dumps(b)[:160]))
    return 1


if __name__ == "__main__":
    sys.exit(main())
