#!/usr/bin/env python3
"""
polaris-transparency-monitor.py — an independent transparency-log monitor (P3.3).

Anyone can run this against a Polaris transparency log. It is the auditor's side of an
append-only log: it fetches the log's Signed Tree Head, verifies the signature against a
trust anchor it was given out of band, and -- holding a previously seen head in its own
state -- fetches a consistency proof and confirms the log only appended, never rewrote or
dropped history. A fork (two different roots at one size), a shrunk tree, a rewritten
entry, an STH signed by the wrong key, or a timestamp that goes backwards all make it
ALERT: it prints the finding and exits non-zero, so cron or a monitoring system picks up
the signal. It is read-only and standalone -- only the Python standard library and the
detached verifier, no Polaris application code, no database.

    polaris-transparency-monitor.py --url https://log.example --anchor <pubkey-hex|file> \\
        --state ~/.polaris-monitor [--once]

Exit codes: 0 = verified (append-only confirmed, or first observation recorded);
2 = ALERT (a violation was detected); 3 = a usage or transport error.
"""
import argparse
import importlib.util
import json
import os
import sys
import urllib.error
import urllib.request

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "polaris_verify", os.path.join(_ROOT, "scripts", "polaris-verify.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _get(base, path):
    with urllib.request.urlopen(base.rstrip("/") + path, timeout=15) as r:
        return json.loads(r.read().decode("utf-8"))


def _read_anchor(value):
    """The trust anchor is a public key hex, given directly or as a file (a bare hex
    string, or JSON with a public_key_hex/anchor field)."""
    if os.path.isfile(value):
        raw = open(value).read().strip()
        try:
            data = json.loads(raw)
        except ValueError:
            return raw.split()[0]
        if isinstance(data, str):
            return data
        for k in ("public_key_hex", "anchor", "public_key"):
            if isinstance(data, dict) and data.get(k):
                return data[k]
        raise ValueError("anchor file has no public_key_hex")
    return value


def _alert(msg):
    print("ALERT: %s" % msg, file=sys.stderr)
    return 2


def poll(base, anchor, state_dir, verifier, log="anchors"):
    """One monitor cycle over the chosen log (anchors, or the P8.2c receipt log). Returns an exit code."""
    prefix = "/api/v1/transparency" + ("/receipts" if log == "receipts" else "")
    """One monitor cycle. Returns an exit code."""
    try:
        sth = _get(base, prefix + "/sth")
    except (urllib.error.URLError, ValueError, OSError) as e:
        print("could not fetch the STH: %s" % e, file=sys.stderr)
        return 3
    sv = verifier.verify_sth(sth, issuer_key=anchor)
    if not sv["sth_authentic"]:
        return _alert("the STH signature did not verify (%s)" % sv["note"])
    if sv["issuer_matches"] is False:
        return _alert("the STH is not signed by the trusted log key")

    state_file = os.path.join(state_dir, "last_sth.json")
    old = None
    if os.path.isfile(state_file):
        with open(state_file) as f:
            old = json.load(f)

    if old is not None:
        if old.get("log_id") != sth.get("log_id"):
            return _alert("the log_id changed from %r to %r" % (old.get("log_id"), sth.get("log_id")))
        m, n = old["tree_size"], sth["tree_size"]
        try:
            cons = _get(base, prefix + "/consistency/%d/%d" % (m, n))
        except (urllib.error.URLError, ValueError, OSError) as e:
            print("could not fetch the consistency proof: %s" % e, file=sys.stderr)
            return 3
        cv = verifier.verify_log_consistency(old, sth, cons.get("proof_hex", []), issuer_key=anchor)
        if cv["fork"]:
            return _alert(cv["note"])
        if not cv["consistent"]:
            return _alert("could not confirm append-only consistency (%s)" % cv["note"])
        if str(sth.get("timestamp")) < str(old.get("timestamp")):
            return _alert("the STH timestamp went backwards (%s -> %s)" % (old.get("timestamp"), sth.get("timestamp")))

    # Verified. Mirror the entries and record this head as the new baseline.
    os.makedirs(state_dir, exist_ok=True)
    try:
        entries = _get(base, prefix + "/entries")
        with open(os.path.join(state_dir, "entries.json"), "w") as f:
            json.dump(entries, f)
    except (urllib.error.URLError, ValueError, OSError):
        pass  # mirroring is best-effort; the STH + consistency are the guarantee
    with open(state_file, "w") as f:
        json.dump(sth, f)
    if old is None:
        print("OK: STH verified and recorded (first observation), log_id=%s tree_size=%d"
              % (sth.get("log_id"), sth.get("tree_size")))
    else:
        print("OK: append-only confirmed from tree_size=%d to tree_size=%d (log_id=%s)"
              % (old["tree_size"], sth["tree_size"], sth.get("log_id")))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Independent monitor for a Polaris transparency log.")
    ap.add_argument("--url", required=True, help="base URL of the log server")
    ap.add_argument("--anchor", required=True, help="the log's trusted public key (hex, or a file)")
    ap.add_argument("--state", required=True, help="directory for the monitor's cached STH and mirror")
    ap.add_argument("--once", action="store_true", help="poll once and exit (the default and only mode in v1)")
    ap.add_argument("--log", choices=("anchors", "receipts"), default="anchors",
                    help="which log to monitor: the audit-anchor log (default) or the P8.2c receipt log")
    args = ap.parse_args(argv)
    try:
        anchor = _read_anchor(args.anchor)
    except Exception as e:
        print("could not read the trust anchor: %s" % e, file=sys.stderr)
        return 3
    return poll(args.url, anchor, args.state, _load_verifier(), log=args.log)


if __name__ == "__main__":
    sys.exit(main())
