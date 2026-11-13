# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""swiyu_verifier.py -- polaris-oid4vp's verifier, asking the way the swiyu wallet reads a request.

`SwiyuVerifier` subclasses the package's `Verifier` and changes the REQUEST SIDE only: the client
identifier is `decentralized_identifier:` plus the verifier's did:webvh DID, the request object is signed
under that DID's key and names it by `kid`, the header carries the Swiss profile version, `client_metadata`
is the two members the profile lists, the link carries `client_id` and `request_uri` and nothing else, and
with a verification query statement the request carries `scope` in place of `dcql_query`. The session, the
nonce, the per-request encryption key and the DCQL query builder are the package's.

The RESPONSE SIDE is the package's. `handle_direct_post` is not overridden (a test holds that), and three
lab checks sit beside it that can only refuse:

    L7   in `Front`, in front of it: a response whose JWE says an `enc` other than A256GCM is refused
         before the package decrypts it
    L10  in the `_single_presentation` override, which calls the package's first: the credential's header
         must carry a `kid`, an absolute DID URL of the pinned issuer DID
    L13  in the `status_resolver` the package already calls: the list is fetched only from the registry
         host, within 200 KB, without redirects, and only a token under the credential's DID and a key of
         the pin decides

A lab check may refuse what the package would accept and never accepts what the package refuses
(`test_lab_checks_only_refuse`). Every response the listener hands to the verifier leaves a record (the package's listener
refuses some POSTs before they reach it, and a record that cannot be written raises, `write_record`): `verdict` is the answer
`handle_direct_post` gave as run (the lab checks inside it) or, when L7 refused before the package ran, the lab's own
refusal; each check's outcome carries `parent`, the package's own answer at the place that check sits,
"not judged" where the package did not run; a check that did not run is "not judged"; and the record
says whether the presentation COUNTS (the package accepted it, all three checks ran and said ok, and the
issuer's status list says VALID and is not stale). It names the package that judged: version, file (relative to
the repository root), commit, and whether its folder held uncommitted changes.

The issuer's key is a pin, not a resolution: a file written by the pin step from a DID log checked offline.
Nothing here resolves a DID or follows a name in a token to a host.
"""
import argparse
import datetime
import functools
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from typing import Callable, Optional

# The tree's copy of the package is put first on sys.path before the import below, so it is the one imported unless the
# caller imported polaris_oid4vp already (then that module stays in use; the record names the file of the one that judged).
_PACKAGE_DIR = pathlib.Path(__file__).resolve().parents[3] / "packages" / "polaris-oid4vp"
_REPO_ROOT = _PACKAGE_DIR.parents[1]
sys.path.insert(0, str(_PACKAGE_DIR))

import polaris_oid4vp  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from polaris_oid4vp import sdjwt, status  # noqa: E402
from polaris_oid4vp.jwe import MAX_PROTECTED_HEADER_BYTES, _loads_depth_bounded, b64u_decode, b64u_encode  # noqa: E402
from polaris_oid4vp.sdjwt import Verdict  # noqa: E402
from polaris_oid4vp.serve import serve  # noqa: E402
from polaris_oid4vp.verifier import RESPONSE_MODE, WALLET_AUDIENCE, Verifier, _sign_es256  # noqa: E402

QUERY_ID = "betaid"
VCT_VALUES = ("betaid-sdjwt", "urn:vct:ch.admin.bcs.betaid")
CLAIM = "age_over_18"
TYP_IDENTITY = "swiyu-identity-trust-statement+jwt"
TYP_QUERY = "swiyu-verification-query-public-statement+jwt"
TYP_PROTECTED = "swiyu-protected-verification-authorization-trust-statement+jwt"
STATEMENT_TYPS = (TYP_IDENTITY, TYP_QUERY, TYP_PROTECTED)

PROFILE_VERSION = "swiss-profile-verification:1.0.0"
REQUEST_TYP = "oauth-authz-req+jwt"
CLIENT_ID_PREFIX = "decentralized_identifier:"
ENC = "A256GCM"
SCHEMES = ("openid4vp", "swiyu-verify")
PIN_MAX_AGE_SECONDS = 24 * 3600
PIN_FUTURE_SECONDS = 300
STATUS_MAX_BYTES = 200 * 1024
STATUS_TIMEOUT_SECONDS = 10
NOT_JUDGED = "not judged"
FILE_MODE = 0o600
FREE_NUMBER_TRIES = 100
RECORD_FILE = re.compile(r"(?:record|capture)-([0-9]+)\.json")


class StartRefused(ValueError):
    """The verifier will not start on these inputs."""


def _only_caches(listed):
    """True when every path `git status --porcelain` listed is a Python cache: a `__pycache__` folder, a file inside one,
    or a `.pyc` file."""
    for line in listed.splitlines():
        for path in line[3:].split(" -> "):  # "XY path", or "XY old -> new" for a rename
            path = path.strip('"')
            if "__pycache__" not in path.split("/") and not path.endswith(".pyc"):
                return False
    return True


@functools.lru_cache(maxsize=None)
def _identity(directory, root):
    here = pathlib.Path(directory)
    version = getattr(polaris_oid4vp, "__version__", None) if here == pathlib.Path(str(polaris_oid4vp.__file__)).parent else None
    if not version:
        try:
            found = re.search(r'^version\s*=\s*"([^"]+)"', (here.parent / "pyproject.toml").read_text(), re.M)
        except OSError:
            found = None
        version = found.group(1) if found else "unknown"
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}

    def ask(*args):
        try:
            done = subprocess.run(["git", "--no-optional-locks", "-C", str(here), *args], capture_output=True, text=True, timeout=10, env=env)
        except (OSError, subprocess.SubprocessError):
            return None
        return done.stdout if done.returncode == 0 else None

    commit = (ask("rev-parse", "HEAD") or "").strip()
    commit = commit if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit) else "unknown"
    # every listed path counts (untracked ones singly, ignored ones too) except a Python cache
    listed = ask("status", "--porcelain", "--untracked-files=all", "--ignored=matching", "--", ".")
    try:  # relative to the repository root (the folder holding packages/): no path of this machine is recorded
        shown = (here / "__init__.py").relative_to(root).as_posix()
    except ValueError:
        shown = "outside the tree: %s/__init__.py" % here.name
    return {"name": "polaris_oid4vp", "version": str(version), "path": shown, "commit": commit,
            "dirty": "unknown" if commit == "unknown" or listed is None else not _only_caches(listed)}


def package_identity(directory=None, root=None):
    """The package that judges: its version, its file (relative to the repository root) and, when git answers for its
    folder, the commit and whether the folder held uncommitted changes (else "unknown"; never a guess). `directory` is the
    package folder, the one holding `__init__.py`; `root` is the repository root (the folder holding packages/)."""
    here = pathlib.Path(str(polaris_oid4vp.__file__)).parent if directory is None else pathlib.Path(directory)
    return dict(_identity(str(here), str(_REPO_ROOT if root is None else root)))


def lab_query():
    """The one DCQL query: one `dc+sd-jwt` credential query, both type names of the Beta-ID, one claim."""
    return {"credentials": [{"id": QUERY_ID, "format": "dc+sd-jwt", "meta": {"vct_values": list(VCT_VALUES)},
                             "claims": [{"path": [CLAIM]}]}]}


def self_signed_pem(key):
    """A throwaway certificate over `key`: the package's constructor wants one, and this verifier never
    sends it (the request names its key by `kid`)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab")])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256())
            ).public_bytes(serialization.Encoding.PEM)


# ------------------------------------------------------------------------------ what it starts on (L3, L4, L11, L8, L9)

def _check_public_url(url):
    split = urllib.parse.urlsplit(url)
    loopback = split.scheme == "http" and split.hostname in ("127.0.0.1", "localhost")
    if (split.scheme != "https" and not loopback) or not split.netloc or split.path not in ("", "/") or split.query:
        raise StartRefused("the public URL %r is not an https origin" % (url,))


def _check_did(did, registry_host):
    parts = did.split(":") if isinstance(did, str) else []
    if (len(parts) < 5 or parts[:2] != ["did", "webvh"] or not parts[2] or parts[3] != registry_host
            or not all(parts[4:])):
        raise StartRefused("the DID %r is not a did:webvh DID on the registry host %s "
                           "(did:webvh:<scid>:<host>:<path>)" % (did, registry_host))


def _split_kid(kid):
    base, mark, fragment = kid.partition("#") if isinstance(kid, str) else ("", "", "")
    return (base, fragment) if mark and fragment else (None, None)


def _check_kid(did, kid):
    base, _ = _split_kid(kid)
    if base != did:
        raise StartRefused("the kid %r is not an absolute URL of %s with a fragment" % (kid, did))


def _check_log_key(did_log, did, kid, key):
    """The DID log's newest entry names `kid` with a public key, and a signature made under `key` the way a
    request is signed verifies under it."""
    lines = [line for line in did_log.splitlines() if line.strip()] if isinstance(did_log, str) else []
    if not lines:
        raise StartRefused("the DID log is empty")
    try:
        state = json.loads(lines[-1])["state"]
        methods = state["verificationMethod"]
    except (ValueError, KeyError, TypeError):
        raise StartRefused("the last line of the DID log is not a did:webvh entry with a state") from None
    if state.get("id") != did:
        raise StartRefused("the DID log is for %r, not %s" % (state.get("id"), did))
    for method in methods if isinstance(methods, list) else []:
        mid = method.get("id", "") if isinstance(method, dict) else ""
        if (did + mid if mid.startswith("#") else mid) != kid:
            continue
        try:
            logged = sdjwt._es256_public_key(method.get("publicKeyJwk"))
        except ValueError as exc:
            raise StartRefused("the DID log names %s without a P-256 publicKeyJwk: %s" % (kid, exc)) from None
        token = _sign_es256(key, {"alg": "ES256"}, {"probe": 1})
        signing_input, _, signature = token.rpartition(".")
        if not sdjwt._verify_es256(logged, signing_input.encode("ascii"), b64u_decode(signature)):
            raise StartRefused("the key given for %s is not the key the DID log names for it" % kid)
        return
    raise StartRefused("the DID log has no verification method %s" % kid)


class Pin:
    """The issuer's DID, the sha256 of the log it was read from, the resolver and time of the reading, and
    the keys the log names (kid, a DID URL, to a P-256 JWK)."""

    def __init__(self, did, log_sha256, resolver, resolved_at, keys):
        self.did, self.log_sha256, self.resolver, self.resolved_at, self.keys = did, log_sha256, resolver, resolved_at, keys

    def jwks(self):
        return [dict(jwk, use="sig", alg="ES256") for jwk in self.keys.values()]


def load_pin(raw, now=None):
    now = time.time() if now is None else now
    if isinstance(raw, (str, bytes)):
        try:
            raw = json.loads(raw)
        except ValueError:
            raise StartRefused("the pin file is not JSON") from None
    if not isinstance(raw, dict):
        raise StartRefused("the pin file is not a JSON object")
    for member in ("did", "log_sha256", "resolver", "resolved_at"):
        if not isinstance(raw.get(member), str) or not raw[member]:
            raise StartRefused("the pin file has no %s" % member)
    if not re.fullmatch(r"[0-9a-f]{64}", raw["log_sha256"]):
        raise StartRefused("the pin's log_sha256 is not a lowercase hex SHA-256")
    try:
        stamped = datetime.datetime.strptime(raw["resolved_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc).timestamp()
    except ValueError:
        raise StartRefused("the pin's resolved_at is not a UTC time like 2026-11-13T02:00:00Z") from None
    if now - stamped > PIN_MAX_AGE_SECONDS:
        raise StartRefused("the pin was resolved %.1f hours ago; a pin older than %d hours is not used: "
                           "make a new one" % ((now - stamped) / 3600, PIN_MAX_AGE_SECONDS // 3600))
    if stamped - now > PIN_FUTURE_SECONDS:
        raise StartRefused("the pin's resolved_at is in the future")
    if not isinstance(raw.get("keys"), list) or not raw["keys"]:
        raise StartRefused("the pin names no keys")
    keys = {}
    for jwk in raw["keys"]:
        kid = jwk.get("kid") if isinstance(jwk, dict) else None
        if _split_kid(kid)[0] != raw["did"]:
            raise StartRefused("the pin holds a key whose kid %r is not a DID URL of %s" % (kid, raw["did"]))
        try:
            sdjwt._es256_public_key(jwk)
        except ValueError as exc:
            raise StartRefused("the pin's key %s is not a P-256 key: %s" % (kid, exc)) from None
        keys[kid] = {m: jwk[m] for m in ("kty", "crv", "x", "y", "kid")}
    return Pin(raw["did"], raw["log_sha256"], raw["resolver"], raw["resolved_at"], keys)


def check_statements(verifier_info, did, scope, query):
    """L8, L9: the entries are `{"format": "jwt", "data": <compact JWS>}` and nothing else, at most one
    statement of each typ, each for this DID; a verification query statement carries the scope and the very
    query the response is judged by. Returns the entries as given."""
    if verifier_info is None:
        if scope is not None:
            raise StartRefused("a scope is given without a verification query statement to carry it")
        return None
    if not isinstance(verifier_info, list) or not verifier_info:
        raise StartRefused("verifier_info is a non-empty list of {format, data} entries")
    seen, has_query = set(), False
    for entry in verifier_info:
        if not isinstance(entry, dict):
            raise StartRefused("a verifier_info entry is not an object")
        if "credential_ids" in entry:
            raise StartRefused("a verifier_info entry carries credential_ids, which the trust protocol forbids")
        if set(entry) != {"format", "data"} or entry["format"] != "jwt":
            raise StartRefused("verifier_info entries are {format: jwt, data: <compact JWS>} and nothing else")
        try:
            header, payload, _, _ = sdjwt._parse_jws(entry["data"])
        except ValueError:
            raise StartRefused("a statement does not parse as a JWS") from None
        typ = header.get("typ")
        if typ not in STATEMENT_TYPS:
            raise StartRefused("a statement has typ %r; the lab carries %s" % (typ, ", ".join(STATEMENT_TYPS)))
        if typ in seen:
            raise StartRefused("two statements have typ %s; the trust protocol takes one" % typ)
        seen.add(typ)
        if payload.get("sub") != did:
            raise StartRefused("the statement of typ %s is for sub %r, not %s" % (typ, payload.get("sub"), did))
        if typ == TYP_QUERY:
            has_query = True
            request = payload.get("request")
            if not isinstance(request, dict) or request.get("type") != "DCQL":
                raise StartRefused("the verification query statement has no DCQL request")
            if request.get("query") != query:
                raise StartRefused("the statement's query is not the query the response is judged by")
            if scope is None or request.get("scope") != scope:
                raise StartRefused("the scope %r is not the statement's request.scope %r" % (scope, request.get("scope")))
    if scope is not None and not has_query:
        raise StartRefused("a scope is given without a verification query statement to carry it")
    return verifier_info


# -------------------------------------------------------------------------------------------- the status fetch (L13)

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def bounded_fetch(url, *, max_bytes=STATUS_MAX_BYTES, timeout=STATUS_TIMEOUT_SECONDS, schemes=("https",)):
    """One GET, no redirect, no proxy, at most `max_bytes` of body. Raises for anything else."""
    if urllib.parse.urlsplit(url).scheme not in schemes:
        raise ValueError("the scheme of %s is not one of %s" % (url, ", ".join(schemes)))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    request = urllib.request.Request(url, headers={"Accept": "application/statuslist+jwt, application/jwt"})
    with opener.open(request, timeout=timeout) as answer:
        if answer.status != 200:
            raise ValueError("the status list answered %d" % answer.status)
        body = answer.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError("the status list is over %d bytes" % max_bytes)
    return body


# ----------------------------------------------------------------------------------------------- the verifier

def _text(value):
    return value if isinstance(value, str) else None


class SwiyuVerifier(Verifier):
    def __init__(self, *, did, kid, key_pem, did_log, issuer_pin, registry_host, public_url, status_host=None,
                 verifier_info=None, scope=None, fetch=None, status_schemes=("https",), request_ttl_seconds=600,
                 clock=None, runs_dir=None, wallet_version=None):
        self._clock = clock or time.time
        _check_public_url(public_url)
        _check_did(did, registry_host)
        _check_kid(did, kid)
        try:
            key = serialization.load_pem_private_key(key_pem, password=None)
        except (ValueError, TypeError):
            raise StartRefused("the key is not an unencrypted PEM private key") from None
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise StartRefused("the key is not a P-256 key")
        _check_log_key(did_log, did, kid, key)
        self.pin = load_pin(issuer_pin, self._clock())
        info = check_statements(verifier_info, did, scope, lab_query())
        super().__init__(client_cert_pem=self_signed_pem(key),
                         client_key_pem=key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()),
                         request_uri=public_url.rstrip("/") + "/request.jwt", response_uri=public_url.rstrip("/") + "/response",
                         redirect=False, issuer_jwks=self.pin.jwks(), vct_values=list(VCT_VALUES), claims=[CLAIM],
                         credential_query_id=QUERY_ID, request_ttl_seconds=request_ttl_seconds, verifier_info=info,
                         status_resolver=self._status_resolver)
        self.did, self.kid, self.scope = did, kid, scope
        self.client_id = CLIENT_ID_PREFIX + did
        self.x5c = None
        self.variant = "C" if scope is not None else "B" if info else "A"
        self.wallet_version = wallet_version
        self.runs_dir = runs_dir
        self.on_record: Optional[Callable] = None
        self.package = package_identity()
        self._last_n = 0
        self.records, self.request_jars = [], []
        self._status_host = status_host.lower() if status_host else None
        self._status_schemes = tuple(status_schemes)
        self._fetch = fetch or (lambda uri: bounded_fetch(uri, schemes=self._status_schemes))
        self._local = threading.local()
        self._records_lock = threading.Lock()

    # ------------------------------------------------------------------------------------------ the request

    def new_request(self, transaction_data=None):
        if transaction_data is not None:
            raise ValueError("the Swiss profile does not support transaction data (swiss-profile-verification 8.4)")
        session, jar = super().new_request()
        self.request_jars = (self.request_jars + [jar])[-100:]
        return session, jar

    def _request_object(self, session, wallet_nonce=None):
        numbers = session.enc_key.public_key().public_numbers()
        enc_jwk = {"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES", "kid": "enc-" + session.state,
                   "x": b64u_encode(numbers.x.to_bytes(32, "big")), "y": b64u_encode(numbers.y.to_bytes(32, "big"))}
        now = int(time.time())
        claims = {"iss": self.client_id, "aud": WALLET_AUDIENCE, "client_id": self.client_id,
                  "response_type": "vp_token", "response_mode": RESPONSE_MODE, "response_uri": self.response_uri,
                  "nonce": session.nonce, "state": session.state, "iat": now, "exp": now + self.request_ttl_seconds,
                  "client_metadata": {"jwks": {"keys": [enc_jwk]}, "encrypted_response_enc_values_supported": [ENC]}}
        if self.scope is not None:
            claims["scope"] = self.scope
        else:
            claims["dcql_query"] = self._dcql_query()
        if wallet_nonce is not None:
            claims["wallet_nonce"] = wallet_nonce
        if self.verifier_info:
            claims["verifier_info"] = self.verifier_info
        header = {"alg": "ES256", "typ": REQUEST_TYP, "kid": self.kid, "profile_version": PROFILE_VERSION}
        return _sign_es256(self.key, header, claims)

    def authorization_request_params(self, session):
        return {"client_id": self.client_id, "request_uri": "%s?state=%s" % (self.request_uri, session.state)}

    def links(self, session):
        query = urllib.parse.urlencode(self.authorization_request_params(session), quote_via=urllib.parse.quote, safe="")
        return {scheme: "%s://?%s" % (scheme, query) for scheme in SCHEMES}

    # ------------------------------------------------------------------------- L10: the credential's kid

    def reset_local(self):
        self._local.vp_token = None
        self._local.credential = None
        self._local.l10 = None
        self._local.l10_parent = None
        self._local.l13 = None
        self._local.l13_parent = None
        self._local.l13_answer = None

    def _single_presentation(self, vp_token):
        self._local.vp_token = vp_token
        presentation = super()._single_presentation(vp_token)
        if presentation is None:
            self._local.l10_parent = "refused"
            return None
        self._local.l10_parent = "passed"
        credential: dict[str, Optional[str]] = {"typ": None, "kid": None, "vct": None, "iss_claim": None, "issuer_did": None}
        self._local.credential = credential
        try:
            header, payload, _, _ = sdjwt._parse_jws(presentation.split("~")[0])
        except ValueError as exc:
            self._local.l10 = {"outcome": "refused", "detail": "the credential does not parse: %s" % exc}
            return None
        kid = header.get("kid")
        credential.update(typ=_text(header.get("typ")), kid=_text(kid), vct=_text(payload.get("vct")),
                          iss_claim=_text(payload.get("iss")))
        base, _ = _split_kid(kid)
        if base != self.pin.did:
            self._local.l10 = {"outcome": "refused", "detail": "the credential's kid %r is not an absolute DID URL "
                                                               "of the pinned issuer %s" % (kid, self.pin.did)}
            return None
        credential["issuer_did"] = base
        self._local.l10 = {"outcome": "ok", "detail": "kid under %s" % base}
        return presentation

    # ------------------------------------------------------------------------------- L13: the status list

    def _status_resolver(self, *, uri, idx, issuer):
        answer = self._resolve_status(uri=uri, idx=idx, issuer=issuer)
        self._local.l13_answer = answer  # what L13 itself concluded: the record reads it when the verdict carries none
        return answer

    def _resolve_status(self, *, uri, idx, issuer):
        credential = getattr(self._local, "credential", None) or {}
        did = credential.get("issuer_did")

        def refuse(code, reason):
            self._local.l13 = {"outcome": "refused", "detail": reason}
            return {"checked": False, "code": code, "reason": reason}

        if did is None:
            return refuse("no_authority", "the credential was not judged under a pinned DID, so no status list is read for it")
        try:
            split = urllib.parse.urlsplit(uri)
        except ValueError:
            return refuse("no_authority", "the status uri does not parse")
        if (self._status_host is None or split.scheme not in self._status_schemes
                or split.netloc.lower() != self._status_host):
            return refuse("no_authority", "the status list at %s is not on the registry host %s: not fetched"
                          % (uri, self._status_host))

        def verify(signing_input, signature, header):
            jwk = self.pin.keys.get(header.get("kid")) if isinstance(header, dict) else None
            return jwk is not None and sdjwt._verify_es256(sdjwt._es256_public_key(jwk), signing_input, signature)

        def authority(*, credential_issuer, status_uri, header, issuer_key_verify=None):
            # before the fetch (header None) the registry host rule above has already been applied; once the
            # token is in hand its kid must be a pinned key of the credential's own DID
            if header is not None:
                kid = header.get("kid")
                if _split_kid(kid)[0] != did:
                    return None
            return verify, status.STATED, "the pin names the key of %s" % did

        answer = status.decide_by_fetching(index=idx, expected_uri=uri, authority=authority, fetch=self._fetch,
                                           credential_issuer=did)
        self._local.l13_parent = dict(answer)
        self._local.l13 = {"outcome": "ok" if answer["checked"] else "refused",
                           "detail": "status %s" % answer.get("status") if answer["checked"] else answer.get("reason")}
        return answer

    # --------------------------------------------------------------------------------------------- the record

    def _highest_in_folder(self):
        """The largest N of any record-N.json or capture-N.json already in the runs folder (0 for none)."""
        try:
            names = os.listdir(self.runs_dir)
        except FileNotFoundError:
            return 0
        return max([int(found.group(1)) for found in map(RECORD_FILE.fullmatch, names) if found] or [0])

    def _open_pair(self, n):
        """Create record-N.json and capture-N.json, neither of which may exist. If the second is taken, the first
        that was made is removed again and the error goes up."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        folder = str(self.runs_dir)
        record_path = os.path.join(folder, "record-%d.json" % n)
        first = os.open(record_path, flags, FILE_MODE)
        try:
            second = os.open(os.path.join(folder, "capture-%d.json" % n), flags, FILE_MODE)
        except BaseException:
            os.close(first)
            os.unlink(record_path)
            raise
        return os.fdopen(first, "w"), os.fdopen(second, "w")

    def write_record(self, record, capture):
        with self._records_lock:
            handles = None
            if self.runs_dir:
                os.makedirs(self.runs_dir, mode=0o700, exist_ok=True)
                os.chmod(self.runs_dir, 0o700)
            # one past the largest number the folder holds (an earlier process may have used it) and past this
            # process's own; a number taken between the scan and the open moves on to the next, a bounded number of times
            n = max(self._last_n, self._highest_in_folder() if self.runs_dir else 0) + 1
            for _ in range(FREE_NUMBER_TRIES if self.runs_dir else 0):
                try:
                    handles = self._open_pair(n)
                    break
                except FileExistsError:
                    n += 1
            if self.runs_dir and handles is None:
                raise FileExistsError("no free record number in %s after %d tries" % (self.runs_dir, FREE_NUMBER_TRIES))
            record["n"] = self._last_n = n
            self.records.append(record)
            for handle, body in zip(handles or (), (record, capture)):
                with handle:
                    json.dump(body, handle, indent=1)
                    handle.write("\n")
        if self.on_record:
            self.on_record(record)


def _response_token(form):
    value = form.get("response") if isinstance(form, dict) else None
    return (value or [""])[0] if isinstance(value, list) else value or ""


def check_enc(token):
    """L7: the `enc` in a posted JWE's protected header. Not judged when there is no readable header."""
    # read as the package reads it: jwe.decrypt_compact strips the token before it splits it
    parts = token.strip().split(".") if isinstance(token, str) else []
    if len(parts) != 5:
        return {"outcome": NOT_JUDGED, "detail": "no compact JWE was posted"}
    try:
        header = _loads_depth_bounded(b64u_decode(parts[0]), "protected header", limit=MAX_PROTECTED_HEADER_BYTES, finite=True)
    except (ValueError, UnicodeError):
        return {"outcome": NOT_JUDGED, "detail": "the protected header does not read"}
    if not isinstance(header, dict):
        return {"outcome": NOT_JUDGED, "detail": "the protected header is not an object"}
    if header.get("enc") != ENC:
        return {"outcome": "refused", "detail": "the response is encrypted with enc=%r; the Swiss profile allows %s only"
                                                % (header.get("enc"), ENC)}
    return {"outcome": "ok", "detail": "enc=" + ENC}


def _revocation_of(answer):
    """The status a record shows for one status answer (the verdict's revocation, or the resolver's own answer)."""
    if not isinstance(answer, dict):
        return NOT_JUDGED
    state = answer.get("state")
    if state is None:  # the package names a resolver's answer's state the same way (sdjwt._revocation_state)
        code = answer.get("code")
        state = (sdjwt.CHECKED if answer.get("checked") else sdjwt.NO_AUTHORITY if code == sdjwt.NO_AUTHORITY
                 else sdjwt.UNREACHABLE if code in (None, sdjwt.UNREACHABLE) else sdjwt.LIST_REFUSED)
    return {"state": state, "status": answer.get("status"), "code": answer.get("code"), "stale": answer.get("stale")}


class Front:
    """What the listener holds. L7 sits here; everything else goes straight to the verifier."""

    def __init__(self, verifier):
        self.verifier = verifier
        self.request_threads = []  # the threads that answered, for main() to wait on before it stops the listener

    def request_object(self, state, wallet_nonce=None, wallet_metadata=None):
        return self.verifier.request_object(state, wallet_nonce=wallet_nonce, wallet_metadata=wallet_metadata)

    def redeem(self, response_code, state=None):
        return self.verifier.redeem(response_code, state)

    def handle_direct_post(self, form):
        v = self.verifier
        v.reset_local()
        self.request_threads = (self.request_threads + [threading.current_thread()])[-100:]
        token = _response_token(form)
        l7: dict = check_enc(token)
        stopped_by_l7 = l7["outcome"] == "refused"
        if stopped_by_l7:
            result = 400, dict(Verifier.REFUSAL_BODY), Verdict(False, "enc", l7["detail"])
        else:
            result = v.handle_direct_post(form)
        verdict = result[2]
        answer = {"status": result[0], "authentic": bool(getattr(verdict, "authentic", False)),
                  "code": getattr(verdict, "code", ""), "reason": getattr(verdict, "reason", "")}
        local = v._local
        # beside each check, the package's own answer at the place that check sits
        l7["parent"] = NOT_JUDGED if stopped_by_l7 else {"status": answer["status"], "code": answer["code"]}
        l10: dict = dict(local.l10 or {"outcome": NOT_JUDGED, "detail": "the check did not run"})
        l10["parent"] = (NOT_JUDGED if stopped_by_l7 or local.l10_parent is None else "passed" if local.l10_parent == "passed"
                         else {"code": answer["code"], "reason": answer["reason"]})
        l13: dict = dict(local.l13 or {"outcome": NOT_JUDGED, "detail": "the check did not run"})
        l13["parent"] = local.l13_parent if local.l13_parent is not None else NOT_JUDGED
        checks = {"L7": l7, "L10": l10, "L13": l13}
        revocation = getattr(verdict, "revocation", None)
        state = _revocation_of(revocation if isinstance(revocation, dict) else local.l13_answer)
        # counted: the package accepted it, L7, L10 and L13 each ran and said ok, and the issuer's list says VALID (0)
        # and is not stale. A check that did not run never counts, and neither does an answer that does not say fresh.
        counted = bool(
            all(c["outcome"] == "ok" for c in checks.values())
            and answer["authentic"]
            and state != NOT_JUDGED
            and state["state"] == sdjwt.CHECKED
            and state["status"] == 0
            and state["stale"] is False
        )
        record = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "wallet_version": v.wallet_version,
                  "variant": v.variant, "package": v.package, "checks": checks, "verdict": answer,
                  "credential": local.credential if local.credential is not None else NOT_JUDGED,
                  "status": state, "counted": counted,
                  "request_sha256": [hashlib.sha256(jar.encode("ascii")).hexdigest() for jar in v.request_jars],
                  "response_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest() if token else None}
        v.write_record(record, {"request_objects": list(v.request_jars), "response": token or None,
                                "vp_token": local.vp_token})
        return result


# ---------------------------------------------------------------------------------------------------------- CLI

def _arguments():
    p = argparse.ArgumentParser(description="the swiyu lab verifier (loopback listener; the tunnel is run.sh's)")
    required = ("did", "kid", "key", "did-log", "issuer-pin", "registry-host", "public-url")
    for name in required:
        p.add_argument("--" + name, required=True)
    p.add_argument("--status-host")
    p.add_argument("--statement", action="append", default=[])
    p.add_argument("--scope")
    p.add_argument("--port", type=int, default=9444)
    p.add_argument("--runs")
    p.add_argument("--wallet-version")
    p.add_argument("--attempts", type=int, default=2)
    p.add_argument("--wait-seconds", type=float, default=1800)
    return p


def _read(path, what):
    try:
        return pathlib.Path(path).read_bytes()
    except OSError as exc:
        raise StartRefused("cannot read the %s %s: %s" % (what, path, exc.strerror)) from None


def _summary(record):
    c = record["checks"]
    cred = record["credential"] if isinstance(record["credential"], dict) else {}
    verdict = record["verdict"]
    return ("RESULT n=%d counted=%s authentic=%s code=%s L7=%s L10=%s L13=%s status=%s typ=%s kid=%s vct=%s"
            % (record["n"], record["counted"], verdict["authentic"], verdict["code"], c["L7"]["outcome"], c["L10"]["outcome"],
               c["L13"]["outcome"], record["status"], cred.get("typ"), cred.get("kid"), cred.get("vct")))


class Tally:
    """What main() keeps across the records of one run: whether any counted, and the attempts used."""

    def __init__(self, attempts):
        self.attempts, self.used, self.counted = attempts, 1, False

    def add(self, record):
        """Take one record. Returns True when the run is over: a record counted, or the attempts are used."""
        self.counted = self.counted or record["counted"]  # a later record never unsets a counted run
        if record["counted"] or self.used >= self.attempts:
            return True
        self.used += 1
        return False


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--print-query" in argv:
        print(json.dumps(lab_query()))
        return 0
    args = _arguments().parse_args(argv)
    try:
        info = [{"format": "jwt", "data": _read(path, "statement").decode("utf-8").strip()} for path in args.statement]
        verifier = SwiyuVerifier(
            did=args.did, kid=args.kid, key_pem=_read(args.key, "key"), did_log=_read(args.did_log, "DID log").decode("utf-8"),
            issuer_pin=_read(args.issuer_pin, "pin file").decode("utf-8"), registry_host=args.registry_host,
            public_url=args.public_url, status_host=args.status_host, verifier_info=info or None, scope=args.scope,
            runs_dir=args.runs, wallet_version=args.wallet_version)
    except (StartRefused, UnicodeError) as exc:
        print("swiyu_verifier: refused to start: %s" % exc, file=sys.stderr)
        return 2
    done, tally, front = threading.Event(), Tally(args.attempts), Front(verifier)

    def announce():
        session, _ = verifier.new_request()
        for scheme, link in verifier.links(session).items():
            print("LINK %s %s" % (scheme, link), flush=True)
            if shutil.which("qrencode"):
                subprocess.run(["qrencode", "-t", "ANSIUTF8", link], check=False)

    def on_record(record):
        print(_summary(record), flush=True)
        if args.runs:
            print("record: %s" % os.path.join(args.runs, "record-%d.json" % record["n"]), flush=True)
        if tally.add(record):
            done.set()
        else:
            announce()

    verifier.on_record = on_record
    if args.runs:
        os.makedirs(args.runs, mode=0o700, exist_ok=True)
        os.chmod(args.runs, 0o700)
    httpd = serve(front, host="127.0.0.1", port=args.port, background=True, verbose=True)
    print("listening 127.0.0.1:%d (loopback only); public %s; variant %s, %d statement(s); wallet %s; status host %s"
          % (httpd.server_port, args.public_url, verifier.variant, len(info), args.wallet_version, args.status_host), flush=True)
    announce()
    arrived = done.wait(args.wait_seconds)
    if arrived:  # the answer to the last response is written before the listener goes (bounded: 10 s in all)
        end = time.time() + 10
        for thread in list(front.request_threads):
            if thread is not threading.current_thread():
                thread.join(max(0.0, end - time.time()))
    httpd.shutdown()
    httpd.server_close()
    if not arrived:
        print("swiyu_verifier: no response arrived in %.0f s" % args.wait_seconds, file=sys.stderr)
        return 3
    return 0 if tally.counted else 1


if __name__ == "__main__":
    sys.exit(main())
