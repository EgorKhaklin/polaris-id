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
from .serve import (CONTROL_PATH, REQUEST_PATH, RESPONSE_PATH, control_token_problem,
                    cors_origins_of, serve)
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

#: How many requests may be outstanding at once when `--control-token-file` lets a caller start them:
#: the 65th is answered 429 until one is answered or expires. Whoever holds the token cannot make
#: the verifier hold more.
CONTROL_OUTSTANDING_LIMIT = 64


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

    With `--rearm` or `--control-token-file` (`numbered`, 2026-11-17) the file describes the
    newest request started, and says which: `request` is 1, 2, 3 ... in start order, 0 and a
    `state` of null before the first. `state` is what it always was, the request's OAuth state
    value. A new request rewrites the whole file to its own pending form, so nothing about an
    older one is left in it; under `--rearm` the request that closed is kept, whole, as
    `previous`, in the same rename, and `previous` is absent for request 1. Plain `--once` is
    one request and its document is as it was, with no `request` and no `previous`.
    """

    def __init__(self, path, numbered=False):
        self.path = pathlib.Path(path)
        self._lock = threading.Lock()
        self._numbered = numbered
        self._number = 0
        self._previous = None
        self._state = None
        self._fetches = {"served": 0, "refused": 0}
        self._responses = 0
        self._latest = {"outcome": "nothing_received"}
        self._open = lambda: True
        self._write()

    def request(self, state, is_open, number=None, keep_previous=False):
        with self._lock:
            # The closed request's document, taken as it stands (the answer that closed it is in it)
            # and rewritten away in the same rename that writes this one's pending form.
            self._previous = self._document() if keep_previous and self._number else None
            self._state = state
            self._open = is_open
            self._fetches = {"served": 0, "refused": 0}
            self._responses = 0
            self._latest = {"outcome": "nothing_received"}
            if number is not None:
                self._number = number
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

    def _document(self):
        doc = dict(self._latest, state=self._state, request_object=dict(self._fetches),
                   responses=self._responses)
        if self._numbered:
            doc["request"] = self._number
        return doc

    def _write(self):
        doc = self._document()
        if self._previous is not None:
            doc["previous"] = self._previous
        fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
                fh.write("\n")
            os.replace(tmp, str(self.path))
        except BaseException:
            os.unlink(tmp)
            raise


class _Started:
    """One request `_Requests.start` made: its number, its session and the launch parameters."""

    __slots__ = ("number", "session", "params", "launch")

    def __init__(self, number, session, params):
        self.number, self.session, self.params = number, session, params
        # The same query behind each scheme. The one place a launch link is made: what `--once`
        # prints, what a `--rearm` successor prints and what the control endpoint answers.
        query = urllib.parse.urlencode(params)
        self.launch = {scheme: "%s://?%s" % (scheme, query) for scheme in LAUNCH_SCHEMES}


def _announce(started):
    """What `--once` prints for a request, and what each `--rearm` successor prints: its
    authorization request parameters, then the launch links. Written in one piece, so two
    requests' lines do not interleave."""
    session = started.session
    lines = ["", "authorization request parameters:"]
    lines += ["  %-18s %s" % (key, value) for key, value in started.params.items()]
    if session.transaction_data:
        lines.append("  the request object carries %d transaction_data entr%s, which the key "
                     "binding JWT must bind" % (len(session.transaction_data),
                                                "y" if len(session.transaction_data) == 1
                                                else "ies"))
    # After the parameters, which the lab walks read: the three lines under the heading, the
    # first `x509_hash:` and the last `state=` in the log. A link's values are percent-encoded,
    # so it carries neither, and those reads find what they found before.
    lines += ["", "launch links, the same request behind each scheme:"]
    lines += ["  " + started.launch[scheme] for scheme in LAUNCH_SCHEMES]
    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.flush()


def _control_specification(spec):
    """What a control request body asks for: (claims, vct), each None for the serve command's own.
    Each claim is a string in `--claim` syntax and goes through `parse_claim`, the function that
    validates `--claim`; `--vct` is validated by nothing but its being a string, and so is this.
    Anything else raises ValueError saying which member."""
    unknown = sorted(set(spec) - {"claims", "vct"})
    if unknown:
        raise ValueError("%s is not a member of a control request; it has claims and vct only"
                         % json.dumps(unknown[0][:64]))
    claims = vct = None
    if "claims" in spec:
        texts = spec["claims"]
        if not isinstance(texts, list) or not texts:
            raise ValueError("claims is a non-empty list of strings, each as --claim takes it")
        claims = []
        for n, text in enumerate(texts):
            if not isinstance(text, str):
                raise ValueError("claims[%d] is not a string; write it as --claim takes it" % n)
            try:
                claims.append(parse_claim(text))
            except ValueError as exc:
                raise ValueError("claims[%d]: %s" % (n, exc)) from None
    if "vct" in spec:
        vct = spec["vct"]
        if not isinstance(vct, list) or not vct or not all(isinstance(v, str) and v for v in vct):
            raise ValueError("vct is a non-empty list of non-empty strings, each as --vct takes it")
    return claims, vct


class _Requests:
    """Starts the requests of one `serve` command and follows the current one.

    `start` is the one function that makes a request, tells the result file about it and
    prepares what is printed or answered: `--once` calls it, each `--rearm` successor and each
    answer of the control endpoint, so the three cannot drift apart.

    `--rearm` (2026-11-17). A request ends in one of two ways, and each calls `close` or
    `expired` with the state of the request it is about; both go through one lock and one test,
    that the request is still the current one, so a closing answer and the expiry arriving
    together start one successor and not two. The successor has the same specification, and
    `announce` prints its parameters as `--once` printed the first. The expiry is a timer
    thread started with each request, so an idle server starts and prints a new request each time
    one expires, and no wallet has to ask for it to be noticed. An answer for a request that is no
    longer the current one (the verifier no longer has it, so it is about none) is neither
    recorded nor does it end anything.

    The control endpoint (`control`) starts requests of its own, each independent of the others
    and of the current one, and each ended by an answer at the response URI, accepted,
    refused or a wallet's error response, the rule `--rearm` has for the current request, or by
    its own expiry. So a refusal frees the request's place among the 64 outstanding, and a
    second presentation to it is refused as one to a request that has closed. The request `--once`
    starts beside the endpoint is not one of these: it keeps the plain rule, that a refusal leaves
    it open. `--result` follows the newest request.
    """

    def __init__(self, verifier, result, transaction_data=None, *, rearm=False, announce=None):
        self.verifier, self.result, self.transaction_data = verifier, result, transaction_data
        self.rearm, self.announce = rearm, announce
        self._lock = threading.Lock()
        self._number = 0
        self._current = None
        self._timer = None
        self._stopped = False
        # The states of the outstanding requests the control endpoint started: each ends at an
        # answer. Pruned of the expired at each start, so it holds at most the 64 bound.
        self._ends_on_answer = set()

    def current_state(self):
        with self._lock:
            return self._current

    def start(self, claims=None, vct_values=None):
        """Make a request, with this command's own specification or the claims and credential
        types given, and return it. Raises ValueError, making none, for one a wallet would refuse."""
        with self._lock:
            return self._start_locked(claims, vct_values)

    def _start_locked(self, claims=None, vct_values=None, ends_on_answer=False):
        verifier = self.verifier
        session, _ = verifier.new_request(transaction_data=self.transaction_data, claims=claims,
                                          vct_values=vct_values)
        self._number += 1
        self._current = session.state
        self._ends_on_answer = {s for s in self._ends_on_answer if verifier.is_outstanding(s)}
        if ends_on_answer:
            self._ends_on_answer.add(session.state)
        if self.result is not None:
            # Open while inside its lifetime, the verifier's own test (Verifier._expire_locked).
            self.result.request(session.state,
                                lambda: time.time() - session.created <= verifier.request_ttl_seconds,
                                self._number, keep_previous=self.rearm)
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if self.rearm and not self._stopped:
            self._timer = threading.Timer(verifier.request_ttl_seconds, self.expired,
                                          args=(session.state,))
            self._timer.daemon = True
            self._timer.start()
        return _Started(self._number, session, verifier.authorization_request_params(session))

    def close(self, state):
        """An answer ended the request `state`. A request the control endpoint started is closed.
        Under `--rearm`, and if it is still the current request, it is closed and its successor
        starts and is announced. Returns whether it did either."""
        return self._end(state)

    def expired(self, state):
        """The timer of the request `state` ran out: the same as `close`."""
        return self._end(state)

    def _end(self, state):
        with self._lock:
            if state in self._ends_on_answer:
                self._ends_on_answer.discard(state)
                self.verifier.close_request(state)
                return True
            if not self.rearm or self._stopped or state != self._current:
                return False
            try:
                self.verifier.close_request(state)
                started = self._start_locked()
                if self.announce is not None:
                    self.announce(started)
            except Exception as exc:  # noqa: BLE001
                print("polaris-oid4vp: --rearm could not start the next request: %s: %s"
                      % (type(exc).__name__, exc), file=sys.stderr, flush=True)
                return False
            return True

    def stop(self):
        with self._lock:
            self._stopped = True
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    # What the listener's hooks call when the result file or `--rearm` follows the newest request.
    # The verifier says which request an answer or a fetch was about (`attributed_request`), on
    # the thread that answered, and only the current request's are recorded.

    def answered(self, status, verdict):
        """An answer at the response URI. Recorded in the result file when it is about the
        current request. Returns the state of the request it is about when that answer ends the
        request (the current one under `--rearm`, one the control endpoint started), else None."""
        state = self.verifier.attributed_request()
        with self._lock:
            if state is None:
                return None
            current = state == self._current
            if current and self.result is not None:
                self.result.verdict(status, verdict)
            if state in self._ends_on_answer or (current and self.rearm):
                return state
            return None

    def fetched(self, status):
        """An answer at the request URI, counted for the current request only."""
        state = self.verifier.attributed_request()
        with self._lock:
            if self.result is not None and state is not None and state == self._current:
                self.result.request_object(status)

    def control(self, spec):
        """POST /control/request: (status, document). 201 with the launch parameters; 400 for a
        body or a specification refused; 429 at CONTROL_OUTSTANDING_LIMIT outstanding requests.
        The count and the request are made under one lock, so no number of callers at once makes
        more than the limit."""
        try:
            claims, vct = _control_specification(spec)
        except ValueError as exc:
            return 400, {"error": "invalid_request", "error_description": str(exc)}
        with self._lock:
            if self.verifier.outstanding() >= CONTROL_OUTSTANDING_LIMIT:
                return 429, {"error": "too_many_requests",
                             "error_description": "%d requests are outstanding; one must be "
                                                  "answered or expire first"
                                                  % CONTROL_OUTSTANDING_LIMIT}
            try:
                started = self._start_locked(claims, vct, ends_on_answer=True)
            except ValueError as exc:
                return 400, {"error": "invalid_request", "error_description": str(exc)}
        return 201, {"request": started.number, "state": started.session.state,
                     "launch": started.launch, "request_uri": started.params["request_uri"],
                     "client_id": started.params["client_id"]}


def _read_control_token(path):
    """The token in `--control-token-file`, stripped. ValueError says why it cannot be used, and
    never what it held."""
    try:
        raw = pathlib.Path(path).read_bytes()
    except OSError as exc:
        raise ValueError("--control-token-file %s: %s" % (path, exc.strerror or "unreadable"))
    try:
        token = raw.decode("ascii").strip()
    except ValueError:
        raise ValueError("--control-token-file %s: the token is ASCII text" % path) from None
    if not token:
        raise ValueError("--control-token-file %s: the file holds no token" % path)
    problem = control_token_problem(token)
    if problem:
        raise ValueError("--control-token-file %s: %s" % (path, problem))
    return token


def _cmd_serve(args) -> int:
    # An empty address binds every interface, which only an address that names it may do.
    if not args.bind:
        print("polaris-oid4vp: --bind is empty, which would listen on every interface; name the "
              "address: 127.0.0.1 for this machine only, 0.0.0.0 for every interface",
              file=sys.stderr)
        return 2
    try:
        cors_origins = cors_origins_of(args.cors_origin)
    except ValueError as exc:
        print("polaris-oid4vp: --cors-origin %s" % exc, file=sys.stderr)
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
    if args.rearm and not args.once:
        print("polaris-oid4vp: --rearm starts the next request when the one --once starts ends; "
              "add --once", file=sys.stderr)
        return 2
    if args.rearm and args.control_token_file:
        print("polaris-oid4vp: --rearm and --control-token-file are not combined: under --rearm "
              "the command owns which request is the current one, and the control endpoint "
              "starts requests of its own; use one", file=sys.stderr)
        return 2
    control_token = None
    if args.control_token_file:
        try:
            control_token = _read_control_token(args.control_token_file)
        except ValueError as exc:
            print("polaris-oid4vp: %s" % exc, file=sys.stderr)
            return 2
    if args.result and not (args.once or control_token):
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

    # With --rearm or the control endpoint there is more than one request over the command's life,
    # so each answer and fetch is held to the request it was about and the file is numbered.
    several = bool(args.rearm or control_token)
    result = None
    if args.result:
        try:
            result = _ResultFile(args.result, numbered=several)
        except OSError as exc:
            print("polaris-oid4vp: --result %s: %s" % (args.result, exc), file=sys.stderr)
            return 2
    requests = _Requests(verifier, result, transaction_data, rearm=args.rearm, announce=_announce)

    def on_verdict(status, body, verdict):
        about = None
        if several:
            about = requests.answered(status, verdict)
        elif result is not None:
            result.verdict(status, verdict)
        # The operator sees the reason; the wallet never does. body carries the same constant
        # refusal whatever went wrong.
        print("  <- %d %s" % (status, _operator_line(verdict)), flush=True)
        # Under --rearm any answer about the current request ends it, accepted, refused or a
        # wallet's error response, and the next starts before the wallet has its answer; a request
        # the control endpoint started ends at an answer the same way. With neither, a
        # refusal still leaves the request open.
        if about is not None:
            requests.close(about)

    on_request_object = None
    if result is not None:
        on_request_object = requests.fetched if several else result.request_object
    httpd = serve(verifier, host=args.bind, port=args.port,
                  certfile=None if args.no_local_tls else str(pki / FILES["tls_cert"]),
                  keyfile=None if args.no_local_tls else str(pki / FILES["tls_key"]),
                  verbose=args.verbose, on_verdict=on_verdict,
                  on_request_object=on_request_object,
                  cors_origins=cors_origins, control_token=control_token,
                  on_control=requests.control if control_token else None)
    print("polaris-oid4vp serving on %s (listening on %s:%d)"
          % (verifier.request_uri[:-len(REQUEST_PATH)], args.bind, args.port))
    if args.no_local_tls:
        print("  the local listener is plain HTTP; a proxy or tunnel must provide the public HTTPS")
    print("  client_id     %s" % verifier.client_id)
    print("  request_uri   %s%s" % (verifier.request_uri, ""))
    print("  response_uri  %s" % verifier.response_uri)
    print("  anchor to register: %s" % (pki / FILES["anchor"]))
    if cors_origins:
        print("  cors origins  %s" % " ".join(cors_origins))
    if control_token:
        print("  control       POST %s, bearer token from %s, at most %d outstanding requests"
              % (CONTROL_PATH, args.control_token_file, CONTROL_OUTSTANDING_LIMIT))
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
        _announce(requests.start())
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
        requests.stop()
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
    s.add_argument("--cors-origin", action="append", default=[], metavar="ORIGIN",
                   help="for a wallet that runs in a browser page: answer requests from ORIGIN "
                        "(e.g. https://wallet.example, repeatable, or * alone for every origin) "
                        "to /request.jwt and /response with Access-Control-Allow-Origin and "
                        "Vary: Origin, and their preflight OPTIONS; off by default")
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
    s.add_argument("--rearm", action="store_true",
                   help="with --once: when the request ends, start the next with the same "
                        "specification and print its parameters and launch links as --once "
                        "does. Under --rearm any answer at the response URI about the current "
                        "request ends it (accepted, refused, or a wallet's error response; "
                        "with neither --rearm nor --control-token-file a refusal leaves the "
                        "request open), and so does the "
                        "end of its lifetime, which a timer notices with no wallet asking: an "
                        "idle server starts and prints a new request each time one expires. "
                        "--result then describes the current request and keeps the one that "
                        "ended as previous; refused with --control-token-file")
    s.add_argument("--control-token-file", default=None, metavar="FILE",
                   help="turn on POST /control/request on this listener, same TLS mode: FILE "
                        "holds the bearer token (read at startup, never from the command line; "
                        "at least 32 printable ASCII characters). A call with "
                        "`Authorization: Bearer TOKEN` starts a request and is answered 201 "
                        "with its request number, state, launch links, request_uri and "
                        "client_id; an optional JSON body names claims (each as --claim takes "
                        "it) and vct for that request alone. A request started here ends at an "
                        "answer, accepted, refused or a wallet's error response, as under "
                        "--rearm, or when it expires. Without the header, or with a "
                        "wrong token, 401 and nothing else; at most 64 requests outstanding "
                        "(429 beyond). The path never carries CORS headers. --result follows "
                        "the newest request; refused with --rearm")
    s.add_argument("--result", default=None, metavar="FILE",
                   help="with --once (or --control-token-file): keep FILE a JSON object saying "
                        "what became of that request, rewritten whole at startup and before "
                        "each answer goes out: outcome (nothing_received until a response "
                        "arrives, then accepted, refused or wallet_error), response.status_code "
                        "(the HTTP status the wallet was answered), check and reason (what "
                        "refused it, as the <- line says), claims (the names accepted), state, "
                        "request_object (the fetches served and refused) and responses (how "
                        "many arrived). With --rearm or --control-token-file it describes the "
                        "newest request and adds request (1, 2, 3 ... in start order, 0 before "
                        "the first), and under --rearm previous (the request that ended, whole)")
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
