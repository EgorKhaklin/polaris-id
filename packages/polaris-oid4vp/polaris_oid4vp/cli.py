# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""cli.py -- `polaris-oid4vp keygen`, `polaris-oid4vp serve` and `polaris-oid4vp verdict`.

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
import os
import pathlib
import sys
import tempfile
import threading
import time
import urllib.parse

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

from .jwe import _loads_depth_bounded
from .sdjwt import (TRANSACTION_DATA_SCOPES, _es256_public_key, _not_an_es256_verification_key,
                    b64u_decode)
from .serve import REQUEST_PATH, RESPONSE_PATH, serve
from .verifier import (VERIFIER_INFO_PROFILES, Verifier, claim_query, transaction_data_entries,
                       verifier_info_entries, verify_response)

#: What `keygen` writes and `serve` reads. Four files, named for what they are rather than
#: for the order somebody happened to generate them in.
FILES = {
    "anchor": "anchor.pem",          # register THIS with the conformance suite
    "client_cert": "client.pem",     # the leaf, and the only thing that goes in x5c
    "client_key": "client-key.pem",
    "tls_cert": "tls.pem",           # the listener's certificate; may be self-signed
    "tls_key": "tls-key.pem",
}

#: The schemes `serve --once` prints a launch link for, the same query behind each. `openid4vp://`
#: is OpenID4VP 1.0's own (section 9); `haip-vp://` is HAIP 1.0's (section 5.1, which leaves it a
#: MAY); `eu-eaap://` is the one ETSI TS 119 472-2 mandates (clause 6.4.1, requirement
#: OIDFVP-HAIP-REDIRECTS-03), and WE BUILD CS-02 v1.2 has a verifier support it beside
#: `openid4vp://`.
LAUNCH_SCHEMES = ("openid4vp", "haip-vp", "eu-eaap")


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
                  vct_values=None, verifier_info=None, credential_query_id=None,
                  verifier_info_profile=None) -> Verifier:
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
        **({"verifier_info": verifier_info} if verifier_info is not None else {}),
        **({"credential_query_id": credential_query_id} if credential_query_id is not None else {}),
        **({"verifier_info_profile": verifier_info_profile}
           if verifier_info_profile is not None else {}))


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


def _operator_line(verdict):
    """What `serve` prints after `<- STATUS` for one answer at the response URI. Only an
    authentic presentation reads `authentic`: the lab walks grep `<- 200 authentic` for an
    acceptance, and a wallet's error response is answered 200 too (OpenID4VP 1.0 section 8.2)."""
    if verdict is None:
        return "refused"
    if verdict.authentic:
        return "authentic, claims %s" % sorted(verdict.claims)
    if getattr(verdict, "wallet_error", None) is not None:
        return "wallet error: %s" % verdict.reason
    return "refused: %s: %s" % (verdict.code, verdict.reason)


def _result_of(status, verdict):
    """The members `--result` writes for one answer at the response URI, decided as
    `_operator_line` decides: the HTTP status the wallet was answered, and for anything but an
    acceptance the check that refused (the verdict's code) and its reason. Claim names only, as
    the line prints them; never the response_code a redirect carries, which redeems the result."""
    out = {"response": {"status_code": status}}
    if verdict is None:
        out.update(outcome="refused", check=None, reason=None)
    elif verdict.authentic:
        out.update(outcome="accepted", claims=sorted(verdict.claims))
    elif getattr(verdict, "wallet_error", None) is not None:
        out.update(outcome="wallet_error", check=verdict.code, reason=verdict.reason)
    else:
        out.update(outcome="refused", check=verdict.code, reason=verdict.reason)
    return out


class _ResultFile:
    """`serve --once --result FILE`: what became of the request --once started, as one JSON
    object in its own file, so it never mixes with the log on stdout.

    Written whole at startup and again before each answer at either URI goes out, through a
    temporary file renamed over it, so a reader finds the last complete document and finds it
    by the time the wallet has its answer. The process is usually stopped by a signal, so
    nothing waits for an exit to write. Until a response arrives the outcome is
    `nothing_received`, which a refusal never reads as. Then it is the latest response's:
    `accepted`, `refused` or `wallet_error`, until the request closes, on its acceptance or at
    the end of its lifetime. Then it stays: a later response is counted and changes nothing
    else, so a stranger's POST after the close cannot overwrite what became of the request.

    A file that cannot be written at startup stops the command before it listens. One that
    cannot be rewritten later is removed and the failure said on stderr: a document left saying
    what it said before an answer would be read as the result, and the wallet still gets its
    answer.
    """

    def __init__(self, path):
        self.path = pathlib.Path(path)
        self._lock = threading.Lock()
        self._state = None
        self._fetches = {"served": 0, "refused": 0}
        self._responses = 0
        self._latest = {"outcome": "nothing_received"}
        self._open = lambda: True
        self._write()

    def request(self, state, is_open):
        with self._lock:
            self._state = state
            self._open = is_open
            self._rewrite()

    def request_object(self, status):
        with self._lock:
            self._fetches["served" if status == 200 else "refused"] += 1
            self._rewrite()

    def verdict(self, status, verdict):
        with self._lock:
            self._responses += 1
            # An acceptance is never judged after the close (the verifier refuses it), so one is
            # recorded even when the lifetime ends before this line runs.
            accepted = verdict is not None and verdict.authentic
            if self._latest["outcome"] != "accepted" and (accepted or self._open()):
                self._latest = _result_of(status, verdict)
            self._rewrite()

    def _rewrite(self):
        try:
            self._write()
        except OSError as exc:
            try:
                os.unlink(str(self.path))
            except OSError:
                pass
            print("polaris-oid4vp: --result %s could not be rewritten (%s); it was removed rather "
                  "than left stale" % (self.path, exc), file=sys.stderr, flush=True)

    def _write(self):
        doc = dict(self._latest, state=self._state, request_object=dict(self._fetches),
                   responses=self._responses)
        fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
                fh.write("\n")
            os.replace(tmp, str(self.path))
        except BaseException:
            os.unlink(tmp)
            raise


def _cmd_serve(args) -> int:
    # An empty address binds every interface, which only an address that names it may do.
    if not args.bind:
        print("polaris-oid4vp: --bind is empty, which would listen on every interface; name the "
              "address: 127.0.0.1 for this machine only, 0.0.0.0 for every interface",
              file=sys.stderr)
        return 2
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
    query_id = (Verifier.DCQL_QUERY_ID if args.credential_query_id is None
                else args.credential_query_id)
    verifier_info = None
    if args.verifier_info:
        try:
            with open(args.verifier_info, encoding="utf-8") as fh:
                verifier_info = json.load(fh)
            # Under a profile the verifier holds it to the profile first, below, so a refusal
            # names the requirement it fails; without one it is checked here, as before.
            if args.verifier_info_profile is None:
                verifier_info = verifier_info_entries(verifier_info, (query_id,))
        except (OSError, ValueError) as exc:
            print("polaris-oid4vp: --verifier-info %s: %s" % (args.verifier_info, exc),
                  file=sys.stderr)
            return 2
    if args.result and not args.once:
        print("polaris-oid4vp: --result reports on the request --once starts; add --once",
              file=sys.stderr)
        return 2
    # The entries of the request --once starts, checked now so that one a wallet would refuse
    # stops the command before it listens, as a bad --verifier-info does.
    transaction_data = None
    if args.transaction_data:
        if not args.once:
            print("polaris-oid4vp: --transaction-data is carried by the request --once starts; "
                  "add --once", file=sys.stderr)
            return 2
        try:
            with open(args.transaction_data, encoding="utf-8") as fh:
                transaction_data = json.load(fh)
            transaction_data_entries(transaction_data, (query_id,))
        except (OSError, ValueError) as exc:
            print("polaris-oid4vp: --transaction-data %s: %s" % (args.transaction_data, exc),
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
    try:
        verifier = verifier_from(pki, args.host, args.port, issuer_jwks, anchors,
                                 public_base_url=args.public_base_url, claims=claims,
                                 vct_values=args.vct, verifier_info=verifier_info,
                                 credential_query_id=args.credential_query_id,
                                 verifier_info_profile=args.verifier_info_profile)
    except ValueError as exc:
        print("polaris-oid4vp: %s" % exc, file=sys.stderr)
        return 2
    if not issuer_jwks and not anchors:
        print("polaris-oid4vp: no --issuer-jwks or --issuer-trust-anchor given, so no "
              "credential can be verified: "
              "every presentation will be refused with `issuer_key`. That is the correct "
              "answer to an unconfigured verifier, and it is probably not what you wanted.",
              file=sys.stderr)

    result = None
    if args.result:
        try:
            result = _ResultFile(args.result)
        except OSError as exc:
            print("polaris-oid4vp: --result %s: %s" % (args.result, exc), file=sys.stderr)
            return 2

    def on_verdict(status, body, verdict):
        if result is not None:
            result.verdict(status, verdict)
        # The operator sees the reason; the wallet never does. body carries the same constant
        # refusal whatever went wrong.
        print("  <- %d %s" % (status, _operator_line(verdict)), flush=True)

    httpd = serve(verifier, host=args.bind, port=args.port,
                  certfile=None if args.no_local_tls else str(pki / FILES["tls_cert"]),
                  keyfile=None if args.no_local_tls else str(pki / FILES["tls_key"]),
                  verbose=args.verbose, on_verdict=on_verdict,
                  on_request_object=result.request_object if result is not None else None)
    print("polaris-oid4vp serving on %s (listening on %s:%d)"
          % (verifier.request_uri[:-len(REQUEST_PATH)], args.bind, args.port))
    if args.no_local_tls:
        print("  the local listener is plain HTTP; a proxy or tunnel must provide the public HTTPS")
    print("  client_id     %s" % verifier.client_id)
    print("  request_uri   %s%s" % (verifier.request_uri, ""))
    print("  response_uri  %s" % verifier.response_uri)
    print("  anchor to register: %s" % (pki / FILES["anchor"]))
    if verifier.verifier_info_profile:
        print("  verifier_info meets %s: ETSI TS 119 472-2 V1.2.1 RO-01 to RO-16, shape and labels "
              "only (the registration certificate's signature, chain and registry are not "
              "checked)" % verifier.verifier_info_profile)
        # Claimed only when it ran: with no certificate carried there was nothing to hold to.
        print("  %s" % ("the request asks for no more than its registration certificate registers"
                        if verifier.over_asking_checked else
                        "no registration certificate carried; the over-asking check did not run"))
    print("\nStart a request with --once to print the parameters a wallet is launched with.")
    if args.once:
        session, _ = verifier.new_request(transaction_data=transaction_data)
        if result is not None:
            # Open while inside its lifetime, the verifier's own test (Verifier._expire_locked).
            result.request(session.state, lambda: time.time() - session.created
                           <= verifier.request_ttl_seconds)
        params = verifier.authorization_request_params(session)
        print("\nauthorization request parameters:")
        for key, value in params.items():
            print("  %-18s %s" % (key, value))
        if session.transaction_data:
            print("  the request object carries %d transaction_data entr%s, which the key "
                  "binding JWT must bind" % (len(session.transaction_data),
                                             "y" if len(session.transaction_data) == 1 else "ies"))
        # After the parameters, which the lab walks read: the three lines under the heading, the
        # first `x509_hash:` and the last `state=` in the log. A link's values are
        # percent-encoded, so it carries neither, and those reads find what they found before.
        print("\nlaunch links, the same request behind each scheme:")
        query = urllib.parse.urlencode(params)
        for scheme in LAUNCH_SCHEMES:
            print("  %s://?%s" % (scheme, query))
    # Read while it serves, and stdout is often not a terminal (a pipe, a file, a container log
    # without -t), where Python holds what was printed until the buffer fills or the process
    # exits. So the lines above go out now, and each verdict line as it is printed (2026-10-15).
    sys.stdout.flush()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        httpd.shutdown()
        httpd.server_close()
    return 0


def _read_request(path):
    """The authorization request's claims: a JSON object, or the compact request object JWS as
    served, whose payload is read as it stands. Its signature is not checked here: this is the
    caller's own request, given to say what the wallet was asked."""
    text = pathlib.Path(path).read_text(encoding="utf-8").strip()
    if text.startswith("{"):
        return _loads_depth_bounded(text, "request")
    parts = text.split(".")
    if len(parts) != 3:
        raise ValueError("%s is neither a JSON object nor a compact JWS" % path)
    return _loads_depth_bounded(b64u_decode(parts[1]), "request object payload")


def _verdict_json(verdict):
    out = {"authentic": verdict.authentic, "code": verdict.code, "reason": verdict.reason,
           "claims": sorted(verdict.claims)}
    if verdict.transaction_data is not None:
        out["transaction_data"] = verdict.transaction_data
    return out


def _cmd_verdict(args) -> int:
    try:
        request = _read_request(args.request)
        token = _loads_depth_bounded(pathlib.Path(args.vp_token).read_text(encoding="utf-8"),
                                     "vp_token")
        if isinstance(token, dict) and "vp_token" in token:   # a whole direct_post body
            token = token["vp_token"]
        issuer_jwks = _load_issuer_jwks(args.issuer_jwks) if args.issuer_jwks else []
        anchors = _load_trust_anchors(args.issuer_trust_anchor)
        result = verify_response(request, token, transaction_data_scope=args.transaction_data_scope,
                                 issuer_jwks=issuer_jwks, trust_anchors=anchors, now=args.now)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print("polaris-oid4vp: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps({
        "accepted": result["accepted"], "scope": result["scope"], "problem": result["problem"],
        "expected": result["expected"], "either": result["either"],
        "verdicts": {qid: _verdict_json(v) for qid, v in result["verdicts"].items()},
        "readings": {scope: {qid: _verdict_json(v) for qid, v in verdicts.items()}
                     for scope, verdicts in result["readings"].items()},
        "response_refusals": result["response_refusals"],
    }, indent=2))
    if result["accepted"] is None:
        print("polaris-oid4vp: %s" % result["problem"], file=sys.stderr)
        return 2
    return 0 if result["accepted"] else 1


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
      it says so on stderr.

and one that judges a response already captured:

  polaris-oid4vp verdict --request request.json --vp-token vp_token.json --issuer-jwks i.json
      Checks every presentation in the vp_token against the request, its transaction_data
      under both readings of which entries each key binding JWT binds; with more than one
      credential, --transaction-data-scope names the reading that decides. Exit 0 accepted,
      1 refused, 2 when it cannot decide.""")
    sub = ap.add_subparsers(dest="command", required=True)

    g = sub.add_parser("keygen", help="make the certificates the HAIP profile requires")
    g.add_argument("--out", default="./pki")
    g.add_argument("--host", default="localhost")
    g.add_argument("--port", type=int, default=9443)
    g.set_defaults(func=_cmd_keygen)

    s = sub.add_parser("serve", help="run a verifier")
    s.add_argument("--pki", default="./pki")
    s.add_argument("--host", default="localhost", help="the name a wallet reaches this by")
    s.add_argument("--bind", default="127.0.0.1",
                   help="the address to listen on: 127.0.0.1, this machine only, by default; "
                        "0.0.0.0 for every interface, as a wallet or suite elsewhere needs; "
                        "an empty one is refused")
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
                        "guide shows), e.g. [{\"format\": \"registration_cert\", \"data\": "
                        "\"<the base64url encoding of the serialized RP registration certificate>\"}] "
                        "(ETSI TS 119 472-2 V1.3.1 RO-16's words)")
    s.add_argument("--verifier-info-profile", default=None, choices=VERIFIER_INFO_PROFILES,
                   help="hold --verifier-info to a profile before listening, and exit 2 naming the "
                        "requirement it fails: etsi-119472-2, ETSI TS 119 472-2 V1.2.1's RO-01 to "
                        "RO-16 (shape and labels only; the registration certificate's signature, "
                        "chain and registry are not checked), and, when a registration "
                        "certificate is carried, a request asking for no more than it registers")
    s.add_argument("--credential-query-id", default=None, metavar="ID",
                   help="the id of the request's DCQL credential query (default pid), which "
                        "transaction_data entries name in credential_ids")
    s.add_argument("--transaction-data", default=None, metavar="FILE",
                   help="a JSON array of transaction_data entries (OpenID4VP 1.0 section 8.4) for "
                        "the request --once starts: each a base64url string, sent exactly as "
                        "given, or a JSON object, encoded here. The key binding JWT must bind "
                        "every one; a TS12 payment must satisfy TS12's schema")
    s.add_argument("--once", action="store_true",
                   help="start one authorization request at startup and print its parameters "
                        "and its launch links (openid4vp://, haip-vp://, eu-eaap://)")
    s.add_argument("--result", default=None, metavar="FILE",
                   help="with --once: keep FILE a JSON object saying what became of that "
                        "request, rewritten whole at startup and before each answer goes out: "
                        "outcome (nothing_received until a response arrives, then accepted, "
                        "refused or wallet_error), response.status_code (the HTTP status the "
                        "wallet was answered), check and reason (what refused it, as the <- "
                        "line says), claims (the names accepted), state, request_object (the "
                        "fetches served and refused) and responses (how many arrived)")
    s.add_argument("--verbose", action="store_true")
    s.set_defaults(func=_cmd_serve)

    d = sub.add_parser("verdict", help="judge a captured response against its request")
    d.add_argument("--request", required=True, metavar="FILE",
                   help="the authorization request: its claims as a JSON object, or the request "
                        "object JWS as served (its signature is not checked here)")
    d.add_argument("--vp-token", required=True, metavar="FILE",
                   help="the vp_token as a JSON object, or the decrypted response carrying one")
    d.add_argument("--issuer-jwks", default=None,
                   help="a JSON file of issuer public JWKs to trust")
    d.add_argument("--issuer-trust-anchor", action="append", default=[], metavar="PEM",
                   help="a PEM file of CA certificates an issuer's x5c leaf must chain to")
    d.add_argument("--transaction-data-scope", choices=TRANSACTION_DATA_SCOPES, default=None,
                   help="which entries each key binding JWT must bind: per_credential, those "
                        "naming its credential query; all_entries, every one. Needed when the "
                        "two differ")
    d.add_argument("--now", type=float, default=None, metavar="SECONDS",
                   help="judge as of this POSIX time, such as when the response was captured")
    d.set_defaults(func=_cmd_verdict)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
