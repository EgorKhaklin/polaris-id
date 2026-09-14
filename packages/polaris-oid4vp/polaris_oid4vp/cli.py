"""cli.py -- `polaris-oid4vp keygen` and `polaris-oid4vp serve`.

Installing this package used to leave you with a library and no way to run a verifier.
Standing one up meant writing the PKI, constructing a `Verifier` and calling `serve()`
yourself, and the only worked example was a 200-line drill inside the repository, which is
the thing a product boundary exists to make unnecessary.

**`keygen` is the half that is not obvious.** The High Assurance profile pins
`client_id_prefix=x509_hash`, and the conformance suite refuses two shapes of certificate
that look perfectly reasonable:

  * a SELF-SIGNED leaf. "Leaf certificate in x5c chain must not be self-signed."
  * the registered TRUST ANCHOR included in the chain. "Trust anchor certificate must not be
    included in x5c chain."

So the leaf needs an issuer, the issuer is registered out of band, and the chain carries the
leaf alone. Each of those cost a failed conformance run to discover, and a command that
produces the right shape is worth more than a paragraph saying what the right shape is.

    polaris-oid4vp keygen --out ./pki --host verifier.example
    polaris-oid4vp serve --pki ./pki --port 9443

`keygen` prints the `client_id` it produced and the path to the anchor a conformance suite
wants registered. `serve` prints the two URLs a wallet is pointed at.

THE KEYS IT MAKES ARE FOR TESTING. A deployment's request-signing certificate comes from
whatever authority its ecosystem trusts, not from a subcommand.
"""
import argparse
import datetime
import json
import pathlib
import sys
import time

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

from .serve import REQUEST_PATH, RESPONSE_PATH, serve
from .verifier import Verifier

#: What `keygen` writes and `serve` reads. Four files, named for what they are rather than
#: for the order somebody happened to generate them in.
FILES = {
    "anchor": "anchor.pem",          # register THIS with the conformance suite
    "client_cert": "client.pem",     # the leaf, and the only thing that goes in x5c
    "client_key": "client-key.pem",
    "tls_cert": "tls.pem",           # the listener's certificate; may be self-signed
    "tls_key": "tls-key.pem",
}


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def keygen(out: pathlib.Path, host: str) -> dict:
    """A CA, a leaf it signs, and a self-signed certificate for the listener."""
    if not _HAVE_CRYPTO:
        raise RuntimeError("polaris-oid4vp requires the cryptography package")
    out.mkdir(parents=True, exist_ok=True)
    now = _now()

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "polaris-oid4vp test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True,
                                       False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(ca_key, hashes.SHA256()))

    tls_key = ec.generate_private_key(ec.SECP256R1())
    tls_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    tls = (x509.CertificateBuilder().subject_name(tls_name).issuer_name(tls_name)
           .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(now - datetime.timedelta(days=1))
           .not_valid_after(now + datetime.timedelta(days=90))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
           .sign(tls_key, hashes.SHA256()))

    def write(name, data, mode=0o644):
        path = out / FILES[name]
        path.write_bytes(data)
        path.chmod(mode)
        return path

    write("anchor", ca.public_bytes(serialization.Encoding.PEM))
    write("client_cert", leaf.public_bytes(serialization.Encoding.PEM))
    write("client_key", leaf_key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()), 0o600)
    write("tls_cert", tls.public_bytes(serialization.Encoding.PEM))
    write("tls_key", tls_key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()), 0o600)
    return {"out": out, "host": host}


def verifier_from(pki: pathlib.Path, host: str, port: int, issuer_jwks=None) -> Verifier:
    base = "https://%s:%d" % (host, port)
    return Verifier(
        client_cert_pem=(pki / FILES["client_cert"]).read_bytes(),
        client_key_pem=(pki / FILES["client_key"]).read_bytes(),
        request_uri=base + REQUEST_PATH,
        response_uri=base + RESPONSE_PATH,
        issuer_jwks=issuer_jwks or [])


def _cmd_keygen(args) -> int:
    out = pathlib.Path(args.out)
    keygen(out, args.host)
    verifier = verifier_from(out, args.host, args.port)
    print("wrote %d files to %s" % (len(FILES), out))
    print("  client_id     %s" % verifier.client_id)
    print("  trust anchor  %s" % (out / FILES["anchor"]))
    print()
    print("Register the anchor with the verifier under test, NOT the leaf: the conformance")
    print("suite refuses a chain that carries its own trust anchor, and refuses a leaf that")
    print("signed itself. These keys are for testing.")
    return 0


def _cmd_serve(args) -> int:
    pki = pathlib.Path(args.pki)
    missing = [name for name in FILES.values() if not (pki / name).is_file()]
    if missing:
        print("polaris-oid4vp: %s is missing %s. Run `polaris-oid4vp keygen --out %s` first."
              % (pki, ", ".join(missing), pki), file=sys.stderr)
        return 2
    issuer_jwks = json.loads(pathlib.Path(args.issuer_jwks).read_text()) if args.issuer_jwks \
        else []
    if isinstance(issuer_jwks, dict):
        issuer_jwks = issuer_jwks.get("keys", [issuer_jwks])

    verifier = verifier_from(pki, args.host, args.port, issuer_jwks)
    if not issuer_jwks:
        print("polaris-oid4vp: no --issuer-jwks given, so no credential can be verified: "
              "every presentation will be refused with `issuer_key`. That is the correct "
              "answer to an unconfigured verifier, and it is probably not what you wanted.",
              file=sys.stderr)

    httpd = serve(verifier, host=args.bind, port=args.port,
                  certfile=str(pki / FILES["tls_cert"]), keyfile=str(pki / FILES["tls_key"]),
                  verbose=args.verbose,
                  # The operator sees the reason; the wallet never does. body carries the
                  # same constant refusal whatever went wrong.
                  on_verdict=lambda status, body, verdict: print(
                      "  <- %d %s" % (status,
                                      "authentic, claims %s" % sorted(verdict.claims)
                                      if verdict and verdict.authentic
                                      else "refused: %s: %s" % (verdict.code, verdict.reason)
                                      if verdict else "refused")))
    print("polaris-oid4vp serving on https://%s:%d" % (args.host, args.port))
    print("  client_id     %s" % verifier.client_id)
    print("  request_uri   %s%s" % (verifier.request_uri, ""))
    print("  response_uri  %s" % verifier.response_uri)
    print("  anchor to register: %s" % (pki / FILES["anchor"]))
    print("\nStart a request with --once to print the parameters a wallet is launched with.")
    if args.once:
        session, _ = verifier.new_request()
        params = verifier.authorization_request_params(session)
        print("\nauthorization request parameters:")
        for key, value in params.items():
            print("  %-18s %s" % (key, value))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        httpd.shutdown()
        httpd.server_close()
    return 0


def main(argv=None) -> int:
    # NOT the module docstring's first line. That reads "cli.py -- ..." and put a source
    # filename on the first screen a stranger sees after installing the command, which is
    # the sort of thing every drill in this tree does harmlessly and a shipped binary
    # must not.
    ap = argparse.ArgumentParser(
        prog="polaris-oid4vp",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="An OpenID4VP 1.0 verifier under the High Assurance Interoperability "
                    "Profile: ask a wallet for a presentation and check what comes back.",
        epilog="""two commands, in this order:

  polaris-oid4vp keygen --out ./pki --host verifier.example
      The certificates the profile requires. It pins client_id_prefix=x509_hash, and the
      conformance suite refuses both a self-signed leaf and a chain carrying its own trust
      anchor, so this makes a CA, a leaf it signs, and a certificate for the listener.
      Prints the client_id and the anchor a counterparty registers. THESE KEYS ARE FOR
      TESTING.

  polaris-oid4vp serve --pki ./pki --port 9443 --issuer-jwks issuers.json
      Serves the signed request object and the response endpoint. With no --issuer-jwks it
      trusts no issuer and refuses every presentation, which is correct and is a trap, so
      it says so on stderr.""")
    sub = ap.add_subparsers(dest="command", required=True)

    g = sub.add_parser("keygen", help="make the certificates the HAIP profile requires")
    g.add_argument("--out", default="./pki")
    g.add_argument("--host", default="localhost")
    g.add_argument("--port", type=int, default=9443)
    g.set_defaults(func=_cmd_keygen)

    s = sub.add_parser("serve", help="run a verifier")
    s.add_argument("--pki", default="./pki")
    s.add_argument("--host", default="localhost", help="the name a wallet reaches this by")
    s.add_argument("--bind", default="0.0.0.0")
    s.add_argument("--port", type=int, default=9443)
    s.add_argument("--issuer-jwks", default=None,
                   help="a JSON file of issuer public JWKs to trust")
    s.add_argument("--once", action="store_true",
                   help="print one authorization request's parameters at startup")
    s.add_argument("--verbose", action="store_true")
    s.set_defaults(func=_cmd_serve)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
