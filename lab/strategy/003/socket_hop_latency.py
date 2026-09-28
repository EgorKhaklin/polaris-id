#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""socket_hop_latency.py - the added latency of ONE local IPC round trip, measured
(lab/strategy/003-signing-custody-compartment.md, section 10, kill criterion 3).

LAB ONLY, stdlib only. This does NOT sign anything and holds no key. It measures only the cost
of the extra hop a separate signer process would add: a parent sends the request bytes to a
child over a UNIX socket, the child echoes back a signature-sized reply (a 3309-byte ML-DSA-65
signature plus a small JSON envelope), and the parent times the round trip. Signing itself is
0.12 ms of liboqs (lab/evaluation) whether it runs in-process or in the child, so it is not the
variable under test; the hop is.

Reports p50/p99 over N round trips against the 17.8 ms end-to-end verification request measured
in lab/evaluation/README.md.

    ~/.local/share/polaris-venv312/bin/python lab/strategy/003/socket_hop_latency.py --n 5000
"""
import argparse
import json
import os
import socket
import struct
import tempfile
import threading
import time

SIG_BYTES = 3309  # ML-DSA-65 signature size; the child returns this much, as a real signer would


def _recv_exactly(conn, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _serve(path, ready):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    ready.set()
    conn, _ = srv.accept()
    reply = json.dumps({"ok": True, "alg": "ML-DSA-65",
                        "sig_hex": "00" * SIG_BYTES}).encode("utf-8")
    header = struct.pack(">I", len(reply))
    try:
        while True:
            raw_len = _recv_exactly(conn, 4)
            if len(raw_len) < 4:
                break
            (mlen,) = struct.unpack(">I", raw_len)
            msg = _recv_exactly(conn, mlen)
            if not msg:
                break
            conn.sendall(header + reply)   # child would parse+policy+sign here (~0.12 ms extra)
    finally:
        conn.close()
        srv.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--warmup", type=int, default=500)
    args = ap.parse_args()

    d = tempfile.mkdtemp(prefix="polaris-signer-hop-")
    path = os.path.join(d, "sock")
    ready = threading.Event()
    t = threading.Thread(target=_serve, args=(path, ready), daemon=True)
    t.start()
    ready.wait(5)

    cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    cli.connect(path)
    cli.setsockopt(socket.IPPROTO_TCP if False else socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # A representative request body: a canonical status-assertion statement (~200 bytes).
    req = json.dumps({"caller": "rp", "agency_id": 1, "message_hex": "ab" * 180}).encode("utf-8")
    framed = struct.pack(">I", len(req)) + req

    def one():
        cli.sendall(framed)
        raw_len = _recv_exactly(cli, 4)
        (mlen,) = struct.unpack(">I", raw_len)
        _recv_exactly(cli, mlen)

    for _ in range(args.warmup):
        one()

    samples = []
    for _ in range(args.n):
        t0 = time.perf_counter()
        one()
        samples.append((time.perf_counter() - t0) * 1e3)  # ms

    cli.close()
    samples.sort()

    def pct(p):
        return samples[min(len(samples) - 1, int(round(p / 100 * len(samples))))]

    out = {
        "n": args.n,
        "reply_bytes": SIG_BYTES,
        "hop_ms": {"p50": pct(50), "p90": pct(90), "p99": pct(99),
                   "min": samples[0], "max": samples[-1],
                   "mean": sum(samples) / len(samples)},
        "reference_ms": {"end_to_end_verification_p50": 17.8, "in_process_sign": 0.12},
    }
    os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"), exist_ok=True)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "out",
                           "socket_hop_latency.json"), "w") as f:
        json.dump(out, f, indent=1)
    print("UNIX-socket round trip over %d calls (reply %d bytes):" % (args.n, SIG_BYTES))
    print("  p50 %.3f ms  p90 %.3f ms  p99 %.3f ms  (min %.3f, max %.3f, mean %.3f)"
          % (out["hop_ms"]["p50"], out["hop_ms"]["p90"], out["hop_ms"]["p99"],
             out["hop_ms"]["min"], out["hop_ms"]["max"], out["hop_ms"]["mean"]))
    print("  reference: 17.8 ms end-to-end verification, 0.12 ms in-process sign")


if __name__ == "__main__":
    main()
