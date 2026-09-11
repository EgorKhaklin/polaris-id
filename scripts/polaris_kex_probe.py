#!/usr/bin/env python3
"""polaris_kex_probe.py - what TLS group did this hop actually negotiate?

v9.404. PQC-POSTURE used to state the internal hops' key exchange by reading
base-image OpenSSL versions out of the Dockerfiles. That is an inference, and
it was wrong in both directions at once: the app's database client does not use
the base image's OpenSSL at all (psycopg2-binary vendors its own), and the
pgbouncer image had moved two Alpine releases since the posture was written.

So measure it. This probe speaks the PostgreSQL SSLRequest preamble, then hands
the socket to the SAME OpenSSL the driver links - located by walking psycopg2's
own vendored library directory, not by asking the system - and reads the group
back out of the finished handshake with SSL_get0_group_name().

  python3 polaris_kex_probe.py HOST PORT [GROUPS]

GROUPS, when given, is an OpenSSL group list (e.g. X25519MLKEM768) forced onto
the client. Forcing separates "the server would accept the hybrid" from "the
server happens to prefer it", which are different claims.

Prints one RESULT line and exits 0 on a completed handshake, non-zero otherwise.
"""
from __future__ import annotations

import ctypes
import glob
import os
import socket
import struct
import sys

#: The postgres wire protocol's SSLRequest: an 8-byte packet whose body is the
#: magic version code. The server answers with a single byte, 'S' to proceed
#: with TLS or 'N' to refuse. TLS does not start until that byte arrives, which
#: is why a plain s_client cannot probe a postgres port without -starttls.
SSL_REQUEST_CODE = 80877103

#: SSL_CTRL_SET_GROUPS_LIST from openssl/ssl.h. ctypes cannot read the header,
#: and the numeric value is part of the stable ABI.
SSL_CTRL_SET_GROUPS_LIST = 92


def _vendored_libs() -> tuple[str, str]:
    """Find the libcrypto/libssl the DRIVER uses, not the system's.

    psycopg2-binary ships a manylinux wheel whose libpq is statically bound to
    its own OpenSSL, dropped in a sibling `.libs` directory with a hashed
    filename. That library is what every database connection this app makes
    actually speaks TLS with, so it is the only one worth measuring.
    """
    import psycopg2  # noqa: F401  (imported for its package location)

    site = os.path.dirname(os.path.dirname(psycopg2.__file__))
    roots = [os.path.join(site, "psycopg2_binary.libs"),
             os.path.join(site, "psycopg2", ".libs")]
    for root in roots:
        crypto = sorted(glob.glob(os.path.join(root, "libcrypto-*.so*")))
        libssl = sorted(glob.glob(os.path.join(root, "libssl-*.so*")))
        # A wheel may also carry a 1.1.1 libcrypto for krb5; take the 3.x pair,
        # which is the one libpq is linked against.
        crypto = [p for p in crypto if ".so.3" in p] or crypto
        if crypto and libssl:
            return crypto[-1], libssl[-1]
    raise SystemExit("polaris_kex_probe: no vendored OpenSSL found beside psycopg2")


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        return 64
    host, port = argv[1], int(argv[2])
    groups = argv[3].encode() if len(argv) > 3 and argv[3] else None

    crypto_path, ssl_path = _vendored_libs()
    crypto = ctypes.CDLL(crypto_path, mode=ctypes.RTLD_GLOBAL)
    libssl = ctypes.CDLL(ssl_path, mode=ctypes.RTLD_GLOBAL)

    crypto.OpenSSL_version.argtypes = [ctypes.c_int]
    crypto.OpenSSL_version.restype = ctypes.c_char_p
    crypto.ERR_get_error.restype = ctypes.c_ulong
    crypto.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]
    libssl.TLS_client_method.restype = ctypes.c_void_p
    libssl.SSL_CTX_new.argtypes = [ctypes.c_void_p]
    libssl.SSL_CTX_new.restype = ctypes.c_void_p
    libssl.SSL_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
    libssl.SSL_CTX_ctrl.restype = ctypes.c_long
    libssl.SSL_new.argtypes = [ctypes.c_void_p]
    libssl.SSL_new.restype = ctypes.c_void_p
    libssl.SSL_set_fd.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libssl.SSL_connect.argtypes = [ctypes.c_void_p]
    libssl.SSL_get0_group_name.argtypes = [ctypes.c_void_p]
    libssl.SSL_get0_group_name.restype = ctypes.c_char_p
    libssl.SSL_get_version.argtypes = [ctypes.c_void_p]
    libssl.SSL_get_version.restype = ctypes.c_char_p

    def errors() -> str:
        buf = ctypes.create_string_buffer(256)
        out = []
        while True:
            code = crypto.ERR_get_error()
            if not code:
                break
            crypto.ERR_error_string_n(code, buf, 256)
            out.append(buf.value.decode())
        return "; ".join(out) or "(no queued error)"

    print("CLIENT", crypto.OpenSSL_version(0).decode(), "from", os.path.basename(crypto_path))

    sock = socket.create_connection((host, port), timeout=20)
    sock.sendall(struct.pack("!ii", 8, SSL_REQUEST_CODE))
    answer = sock.recv(1)
    if answer != b"S":
        print(f"RESULT refused-tls {answer!r}")
        return 2

    # create_connection's timeout leaves the socket non-blocking, which turns
    # every SSL_connect into WANT_READ. OpenSSL owns the fd from here.
    sock.settimeout(None)

    ctx = libssl.SSL_CTX_new(libssl.TLS_client_method())
    if not ctx:
        print("RESULT no-context ::", errors())
        return 3
    if groups and libssl.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST, 0, ctypes.c_char_p(groups)) != 1:
        print(f"RESULT client-cannot-offer {groups.decode()} ::", errors())
        return 4
    con = libssl.SSL_new(ctx)
    libssl.SSL_set_fd(con, sock.fileno())
    if libssl.SSL_connect(con) != 1:
        forced = f" forced={groups.decode()}" if groups else ""
        print(f"RESULT handshake-failed{forced} ::", errors())
        return 5
    group = libssl.SSL_get0_group_name(con)
    print("RESULT", libssl.SSL_get_version(con).decode(), (group or b"unknown").decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
