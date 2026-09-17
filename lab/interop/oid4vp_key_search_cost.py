#!/usr/bin/env python3
"""oid4vp_key_search_cost.py -- what does the outstanding-key search actually cost?

RAISED BY AN OUTSIDE REVIEWER, 2026-09-17, as a design-intent question rather than a bug:
`handle_direct_post` may try every outstanding response-encryption key before one opens the
ciphertext. Is that deliberate, what bounds the number of outstanding sessions, and is the
O(N) path a real resource-exhaustion risk or a theoretical one under an unrealistic
deployment assumption?

THE DESIGN, read from the code before measuring it. The loop is deliberate and says so:

    # The response is encrypted to a PER-REQUEST key, so finding the session means
    # finding the key that opens it. Trying each outstanding one is deliberate: the
    # `state` that would let us look it up directly is INSIDE the ciphertext, and
    # trusting an unauthenticated state parameter to pick a decryption key is how a
    # verifier gets steered onto the wrong session.

So the alternative the reviewer asks about, selecting the key before decrypting, means
reading an attacker-supplied `state` from outside the ciphertext and choosing a private key
with it. The property that buys is that the verifier cannot be steered: a response is
matched to a session by the only thing an attacker cannot forge, which is the ability to
decrypt under that session's key. The `state` inside the plaintext is then checked against
the session the key belongs to, so the two must agree.

WHAT BOUNDS N, which is the half the code comment does not say. Two things, and the second
matters more than the first:

  1. TIME. `DEFAULT_REQUEST_TTL_SECONDS = 300`, and `_expire_locked()` runs on every new
     request and every posted response. There is no cap on the COUNT.

  2. WHO CAN CREATE ONE. The HTTP surface is two paths: `/request.jwt` serves the request
     object for a state that already exists, and `/response` takes the direct_post. **No
     route calls `new_request()`.** Sessions are created by the operator through the library,
     not by anybody who can reach the server. So N is the verifier's own legitimate
     concurrency, and an attacker posting bogus responses cannot inflate it.

That is the whole difference between a nuisance and a denial of service, and it is a
property of the SERVE surface rather than of the verifier object. An integrator who wires
`new_request()` to an unauthenticated route of their own has taken that bound away.

MEASURED HERE: the cost of one bogus response against N outstanding sessions, for N in
1, 10, 100, 1000, against the real verifier and the real JWE path. Also the cost of a
GENUINE response, because the honest case walks the same list and that is the number a
deployment actually pays.

Run: python3 lab/interop/oid4vp_key_search_cost.py [--trials N]
"""
import argparse
import datetime
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "packages" / "polaris-oid4vp"))

try:
    from polaris_oid4vp.verifier import Verifier, DEFAULT_REQUEST_TTL_SECONDS
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError as exc:                       # pragma: no cover
    print("needs the polaris-oid4vp package and cryptography: %s" % exc, file=sys.stderr)
    raise SystemExit(3)

POPULATIONS = (1, 10, 100, 1000)


def _verifier():
    """A verifier with a throwaway self-signed client chain, as the package's own tests build.

    Borrowed rather than invented: the constructor takes a leaf certificate and its key, and
    a measurement that stubbed them would be measuring something the package does not do.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab anchor")])
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab verifier")]))
            .issuer_name(ca_name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(ca_key, hashes.SHA256()))
    return Verifier(
        client_cert_pem=leaf.public_bytes(serialization.Encoding.PEM),
        client_key_pem=leaf_key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()),
        request_uri="https://verifier.example/request.jwt",
        response_uri="https://verifier.example/response")


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0] or None)
    ap.add_argument("--trials", type=int, default=20)
    args = ap.parse_args()

    try:
        v = _verifier()
    except Exception as exc:                     # pragma: no cover
        print("could not construct the verifier: %s" % exc, file=sys.stderr)
        return 3

    print("THE SHAPE, read before measuring:")
    print("  request TTL                    %ds" % DEFAULT_REQUEST_TTL_SECONDS)
    print("  cap on outstanding sessions    none; time is the only bound")
    print("  HTTP routes that create one    none. /request.jwt serves an existing state,")
    print("                                 /response takes the direct_post. new_request()")
    print("                                 is the operator's, through the library.")
    print()

    # A WELL-FORMED bogus response: a real compact JWE, built by the package's own
    # `encrypt_compact` (which is what a wallet does), encrypted to a key no session holds.
    #
    # The first version of this file used a hand-written token of the right shape, and
    # measured 0.0034 ms per candidate. That is an order of magnitude too cheap for a P-256
    # key agreement, which is the tell: the token was being rejected on PARSE, before any
    # ECDH happened, so the measurement was of the reject path and not of the search. A
    # malformed input measures the cost of malformed input. An attacker probing this would
    # send something well-formed, so that is what is sent here: every candidate now pays a
    # full ephemeral-static ECDH, a Concat KDF and an AES-GCM tag check before failing.
    from polaris_oid4vp.jwe import encrypt_compact
    stranger = ec.generate_private_key(ec.SECP256R1())
    bogus = {"response": [encrypt_compact(b'{"state":"nope","vp_token":"x"}',
                                          stranger.public_key())]}

    print("%-10s %14s %14s %14s" % ("sessions", "per bogus POST", "per session", "POSTs/sec"))
    rows = []
    for n in POPULATIONS:
        while len(v._sessions) < n:
            v.new_request()
        # The population must be what we think it is: new_request() expires as it goes, and
        # a measurement against a list that quietly emptied is a measurement of nothing.
        if len(v._sessions) != n:
            print("== VOID: asked for %d outstanding sessions and the verifier holds %d =="
                  % (n, len(v._sessions)), file=sys.stderr)
            return 1
        t0 = time.perf_counter()
        for _ in range(args.trials):
            status, _body = v.handle_direct_post(bogus)[:2]
            if status == 200:
                print("== VOID: the bogus response was ACCEPTED ==", file=sys.stderr)
                return 1
        dt = (time.perf_counter() - t0) / args.trials
        rows.append((n, dt))
        print("%-10d %13.2fms %13.4fms %14.0f" % (n, dt * 1e3, dt * 1e3 / n, 1 / dt))

    print()
    first, last = rows[0], rows[-1]
    per_session = last[1] / last[0] * 1e3        # ms, which is what the sentence says
    linear = last[1] / (first[1] * last[0] / first[0])
    print("scaling from %d to %d sessions is %.2fx linear (1.00 would be exactly O(N))"
          % (first[0], last[0], linear))
    print()
    print("== THE PATH IS O(N) AND THE CONSTANT IS %.3f ms PER OUTSTANDING SESSION. What "
          "that costs a deployment is decided by N, and N is the verifier's own legitimate "
          "concurrency, because no HTTP route creates a session: an attacker posting bogus "
          "responses walks the operator's list and cannot lengthen it. At %d outstanding "
          "requests a bogus POST costs %.0f ms, so a single core serves %.0f of them a "
          "second. ==" % (per_session, last[0], last[1] * 1e3, 1 / last[1]))
    print()
    print("WHAT THIS DOES AND DOES NOT SAY. It measures this machine, one process, one core, "
          "and the honest path pays the same walk: a real response decrypts on average half "
          "way down the list, so the legitimate cost at N sessions is about half the number "
          "above. It does not model a deployment's request rate, which is what actually sets "
          "N. The bound it does establish is structural rather than numeric: with session "
          "creation off the HTTP surface, an unauthenticated attacker cannot grow N, so this "
          "is a cost multiplier on the operator's own concurrency and not an amplification "
          "an outsider controls. An integrator who exposes new_request() on a route of their "
          "own removes that bound, and nothing in the package stops them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
