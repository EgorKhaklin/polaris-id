# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
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
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

from .sdjwt import _es256_public_key, _not_an_es256_verification_key
from .serve import REQUEST_PATH, RESPONSE_PATH, serve
from .verifier import Verifier, claim_query, verifier_info_entries

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
          # Key identifiers, which RFC 5280 (4.2.1.1, 4.2.1.2) has every conforming CA put on
          # its own certificate and on each one it signs. Multipaz's trust manager finds a CA by
          # them and skipped this one without ("Skipping certificate without SKI"), so it refused
          # the request (lab/interop/multipaz, 2026-10-04).
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                         critical=False)
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
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            # digitalSignature, because this leaf's ONLY job is signing the request
            # object. Omitted until v9.465 and nothing here noticed: the OpenID
            # Foundation conformance suite ran eleven modules clean against a leaf
            # carrying no KeyUsage at all. An unmodified walt.id Wallet API v2 refused
            # it on sight -- "Certificate does not contain client Key Usage
            # 'digitalSignature'" -- which is the first thing this package has been
            # told by an implementation that did not come from this repository.

            .sign(ca_key, hashes.SHA256()))

    tls_key = ec.generate_private_key(ec.SECP256R1())
    tls_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    tls = (x509.CertificateBuilder().subject_name(tls_name).issuer_name(tls_name)
           .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(now - datetime.timedelta(days=1))
           .not_valid_after(now + datetime.timedelta(days=90))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
           # serverAuth, because Apple's TLS policy refuses a server certificate without it, even
           # one the client trusts explicitly: the EU iOS OpenID4VP library's wallet could fetch
           # the request object only by pinning this certificate around the policy
           # (lab/interop/eudi-ios, 2026-10-04).
           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
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


def parse_claim(text):
    """`--claim`: a name (`given_name`), a dotted path of object keys (`age_equal_or_over.18`)
    or a JSON array of keys (`["address","locality"]`), optionally `=VALUE` (JSON: `=true`,
    `=18`, `="DE"`; anything else is taken as a string) for the value the request accepts."""
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise ValueError("--claim %s: a JSON path needs its closing ]" % text)
        path_text, rest = text[:end + 1], text[end + 1:]
        try:
            path = json.loads(path_text)
        except ValueError as exc:
            raise ValueError("--claim %s: the path is not JSON (%s)" % (text, exc)) from None
        if rest and not rest.startswith("="):
            raise ValueError("--claim %s: after the JSON path only =VALUE may follow" % text)
        value_text, has_value = rest[1:], bool(rest)
    else:
        path_text, sep, value_text = text.partition("=")
        path, has_value = path_text.split("."), bool(sep)
    claim = {"path": path}
    if has_value:
        try:
            value = json.loads(value_text)
        except ValueError:
            value = value_text
        claim["values"] = [value]
    try:
        claim_query(claim)      # refuses here what the verifier would refuse at startup
    except ValueError as exc:
        raise ValueError("--claim %s: %s" % (text, exc)) from None
    return claim


def verifier_from(pki: pathlib.Path, host: str, port: int, issuer_jwks=None,
                  issuer_trust_anchors=None, public_base_url=None, claims=None,
                  vct_values=None, verifier_info=None) -> Verifier:
    # A verifier behind a reverse proxy or a tunnel reaches wallets at a public origin that is
    # not its own host:port; the HAIP request_uri and response_uri must advertise that origin.
    base = public_base_url.rstrip("/") if public_base_url else "https://%s:%d" % (host, port)
    return Verifier(
        client_cert_pem=(pki / FILES["client_cert"]).read_bytes(),
        client_key_pem=(pki / FILES["client_key"]).read_bytes(),
        request_uri=base + REQUEST_PATH,
        response_uri=base + RESPONSE_PATH,
        issuer_jwks=issuer_jwks or [],
        issuer_trust_anchors=issuer_trust_anchors or [],
        **({"claims": claims} if claims else {}),
        **({"vct_values": vct_values} if vct_values else {}),
        **({"verifier_info": verifier_info} if verifier_info is not None else {}))


def _load_trust_anchors(paths):
    """Each file holds one or more PEM certificates, every one an issuer trust anchor.

    HAIP 1.0 has an SD-JWT VC issuer sign with its certificate in `x5c`, and the library has
    verified such chains against configured anchors since it was written; until 2026-09-27
    this command could not configure one, so no HAIP issuer's credential could be verified
    by `serve` (found issuing into walt.id and Credo, lab/strategy/005/)."""
    from cryptography.x509 import load_pem_x509_certificates
    anchors = []
    for path in paths or []:
        try:
            anchors.extend(load_pem_x509_certificates(pathlib.Path(path).read_bytes()))
        except (OSError, ValueError) as exc:
            raise SystemExit("polaris-oid4vp: --issuer-trust-anchor %s is not a readable PEM "
                             "certificate file: %s" % (path, exc))
    return anchors


def _load_issuer_jwks(path):
    """The keys of --issuer-jwks: a JWK Set ({"keys": [...]}), a list of JWKs, or one JWK.
    Anything else is refused before the listener starts (2026-10-01): a file that did not parse
    was a traceback, and a `keys` that is not a list was read one character at a time, so the
    verifier started with no key and said nothing."""
    try:
        doc = json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise SystemExit("polaris-oid4vp: --issuer-jwks %s is not a readable JSON file: %s" % (path, exc))
    keys = doc.get("keys", [doc]) if isinstance(doc, dict) else doc
    if not (isinstance(keys, list) and all(isinstance(k, dict) for k in keys)):
        raise SystemExit("polaris-oid4vp: --issuer-jwks %s is not a JWK Set, a list of JWKs or "
                         "one JWK" % path)
    return keys


def _verifies_es256(jwk):
    """Whether the verifier would check an issuer signature under this configured JWK."""
    if _not_an_es256_verification_key(jwk):
        return False
    try:
        _es256_public_key(jwk)
    except ValueError:
        return False
    return True


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
    try:
        issuer_jwks = _load_issuer_jwks(args.issuer_jwks) if args.issuer_jwks else []
        anchors = _load_trust_anchors(args.issuer_trust_anchor)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 2
    try:
        claims = [parse_claim(c) for c in args.claim]
    except ValueError as exc:
        print("polaris-oid4vp: %s" % exc, file=sys.stderr)
        return 2
    verifier_info = None
    if args.verifier_info:
        try:
            with open(args.verifier_info, encoding="utf-8") as fh:
                verifier_info = verifier_info_entries(json.load(fh), (Verifier.DCQL_QUERY_ID,))
        except (OSError, ValueError) as exc:
            print("polaris-oid4vp: --verifier-info %s: %s" % (args.verifier_info, exc),
                  file=sys.stderr)
            return 2
    # Keys named and none usable is a configuration that cannot be what was meant: every
    # credential from those issuers would be refused, with no word at startup (2026-10-01).
    if args.issuer_jwks and not any(_verifies_es256(k) for k in issuer_jwks):
        why = ("none of the %d keys in --issuer-jwks %s can verify an ES256 issuer signature: each "
               "is not a P-256 key, or its use, key_ops or alg says it is for something else"
               % (len(issuer_jwks), args.issuer_jwks))
        if not anchors:
            print("polaris-oid4vp: %s. Refusing to start a verifier that could verify nothing." % why,
                  file=sys.stderr)
            return 2
        print("polaris-oid4vp: %s; only issuers whose x5c chains to --issuer-trust-anchor can be "
              "verified." % why, file=sys.stderr)
    verifier = verifier_from(pki, args.host, args.port, issuer_jwks, anchors,
                             public_base_url=args.public_base_url, claims=claims,
                             vct_values=args.vct, verifier_info=verifier_info)
    if not issuer_jwks and not anchors:
        print("polaris-oid4vp: no --issuer-jwks or --issuer-trust-anchor given, so no "
              "credential can be verified: "
              "every presentation will be refused with `issuer_key`. That is the correct "
              "answer to an unconfigured verifier, and it is probably not what you wanted.",
              file=sys.stderr)

    httpd = serve(verifier, host=args.bind, port=args.port,
                  certfile=None if args.no_local_tls else str(pki / FILES["tls_cert"]),
                  keyfile=None if args.no_local_tls else str(pki / FILES["tls_key"]),
                  verbose=args.verbose,
                  # The operator sees the reason; the wallet never does. body carries the
                  # same constant refusal whatever went wrong.
                  on_verdict=lambda status, body, verdict: print(
                      "  <- %d %s" % (status,
                                      "authentic, claims %s" % sorted(verdict.claims)
                                      if verdict and verdict.authentic
                                      else "refused: %s: %s" % (verdict.code, verdict.reason)
                                      if verdict else "refused")))
    print("polaris-oid4vp serving on %s (listening on %s:%d)"
          % (verifier.request_uri[:-len(REQUEST_PATH)], args.bind, args.port))
    if args.no_local_tls:
        print("  the local listener is plain HTTP; a proxy or tunnel must provide the public HTTPS")
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
    s.add_argument("--public-base-url", default=None, metavar="URL",
                   help="the HTTPS origin a wallet reaches this verifier by when it is behind a "
                        "reverse proxy or tunnel (e.g. https://verifier.example); used for the "
                        "request_uri and response_uri in place of https://host:port")
    s.add_argument("--no-local-tls", action="store_true",
                   help="serve the local listener over plain HTTP, for when a reverse proxy or "
                        "tunnel terminates TLS and provides the public HTTPS (pair with "
                        "--public-base-url); the listener still binds --bind")
    s.add_argument("--issuer-jwks", default=None,
                   help="a JSON file of issuer public JWKs to trust")
    s.add_argument("--issuer-trust-anchor", action="append", default=[], metavar="PEM",
                   help="a PEM file of CA certificates an issuer's x5c leaf must chain to "
                        "(repeatable); the HAIP way to trust an issuer")
    s.add_argument("--claim", action="append", default=[], metavar="PATH[=VALUE]",
                   help="a claim to ask for (repeatable; default given_name and family_name): a "
                        "name, a dotted path of object keys such as age_equal_or_over.18, or a "
                        "JSON array of keys; =VALUE (e.g. =true) is the value it must have")
    s.add_argument("--vct", action="append", default=[], metavar="TYPE",
                   help="a credential type to accept (repeatable; default urn:eudi:pid:1)")
    s.add_argument("--verifier-info", default=None, metavar="FILE",
                   help="verifier attestations to put in the request object: a JSON array "
                        "(OpenID4VP 1.0 section 5.1) or one object (as the German EUDI wallet "
                        "guide shows), e.g. {\"format\": \"registration_cert\", \"data\": \"<JWT>\"}")
    s.add_argument("--once", action="store_true",
                   help="print one authorization request's parameters at startup")
    s.add_argument("--verbose", action="store_true")
    s.set_defaults(func=_cmd_serve)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
